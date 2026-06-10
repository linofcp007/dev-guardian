import { GuardianDatabase as Database } from '../../../src/storage/db.js';
import { beforeEach, describe, expect, it } from 'vitest';
import { runMigrations } from '../../../src/storage/migrations/runner.js';
import { ScansRepo } from '../../../src/storage/scansRepo.js';

function freshRepo() {
  const db = new Database(':memory:');
  runMigrations(db);
  return { db, repo: new ScansRepo(db) };
}

describe('ScansRepo', () => {
  it('inserts a scan with status=running and returns the record', () => {
    const { repo } = freshRepo();
    const record = repo.insert({
      scan_id: 'scan-1',
      scan_type: 'security_full',
      project_path: '/tmp/proj',
      tree_hash: 'hash-1',
    });
    expect(record.status).toBe('running');
    expect(record.tools_run).toEqual([]);
    expect(record.missing_tools).toEqual([]);
    expect(record.finished_at).toBeNull();
  });

  it('finalizes a scan to completed and persists tools_run / missing_tools', () => {
    const { repo } = freshRepo();
    repo.insert({
      scan_id: 'scan-2',
      scan_type: 'sast',
      project_path: '/tmp/proj',
      tree_hash: 'h2',
    });
    repo.finalize({
      scan_id: 'scan-2',
      status: 'completed',
      tools_run: [{ name: 'semgrep', version: '1.0', status: 'ok' }],
      missing_tools: ['bandit'],
    });
    const got = repo.getById('scan-2');
    expect(got?.status).toBe('completed');
    expect(got?.tools_run).toEqual([{ name: 'semgrep', version: '1.0', status: 'ok' }]);
    expect(got?.missing_tools).toEqual(['bandit']);
    expect(got?.finished_at).not.toBeNull();
  });

  it('markCancelled only affects running scans', () => {
    const { repo } = freshRepo();
    repo.insert({ scan_id: 's-a', scan_type: 'sast', project_path: '/p', tree_hash: 'h' });
    repo.finalize({
      scan_id: 's-a',
      status: 'completed',
      tools_run: [],
      missing_tools: [],
    });
    repo.markCancelled('s-a');
    expect(repo.getById('s-a')?.status).toBe('completed');

    repo.insert({ scan_id: 's-b', scan_type: 'sast', project_path: '/p', tree_hash: 'h' });
    repo.markCancelled('s-b');
    expect(repo.getById('s-b')?.status).toBe('cancelled');
  });

  it('reapRunning flips orphans to failed and returns the count', () => {
    const { repo } = freshRepo();
    repo.insert({ scan_id: 'orphan-1', scan_type: 'sast', project_path: '/p', tree_hash: 'h' });
    repo.insert({ scan_id: 'orphan-2', scan_type: 'sast', project_path: '/p', tree_hash: 'h' });
    repo.insert({ scan_id: 'clean', scan_type: 'sast', project_path: '/p', tree_hash: 'h' });
    repo.finalize({ scan_id: 'clean', status: 'completed', tools_run: [], missing_tools: [] });

    const reaped = repo.reapRunning();
    expect(reaped).toBe(2);
    expect(repo.getById('orphan-1')?.status).toBe('failed');
    expect(repo.getById('clean')?.status).toBe('completed');
  });

  it('findCacheHit returns the most recent matching completed scan within the freshness window', () => {
    const { repo } = freshRepo();
    repo.insert({ scan_id: 'old', scan_type: 'sast', project_path: '/p', tree_hash: 'same' });
    repo.finalize({ scan_id: 'old', status: 'completed', tools_run: [], missing_tools: [] });

    repo.insert({ scan_id: 'newer', scan_type: 'sast', project_path: '/p', tree_hash: 'same' });
    repo.finalize({ scan_id: 'newer', status: 'completed', tools_run: [], missing_tools: [] });

    // Freshness threshold in the past — both qualify; newest wins.
    const hit = repo.findCacheHit({
      tree_hash: 'same',
      scan_type: 'sast',
      freshThreshold: '1970-01-01T00:00:00.000Z',
    });
    expect(hit?.scan_id).toBe('newer');

    // Threshold in the future — nothing fresh enough.
    const miss = repo.findCacheHit({
      tree_hash: 'same',
      scan_type: 'sast',
      freshThreshold: '2999-01-01T00:00:00.000Z',
    });
    expect(miss).toBeNull();

    // Different scan_type or different tree_hash means no hit either.
    expect(
      repo.findCacheHit({
        tree_hash: 'same',
        scan_type: 'security_full',
        freshThreshold: '1970-01-01T00:00:00.000Z',
      }),
    ).toBeNull();
    expect(
      repo.findCacheHit({
        tree_hash: 'other',
        scan_type: 'sast',
        freshThreshold: '1970-01-01T00:00:00.000Z',
      }),
    ).toBeNull();
  });

  it('listHistory returns scans in start-time descending order, capped by limit', () => {
    const { repo } = freshRepo();
    for (let i = 0; i < 5; i++) {
      repo.insert({
        scan_id: `s-${i}`,
        scan_type: 'sast',
        project_path: '/p',
        tree_hash: `h-${i}`,
      });
    }
    const history = repo.listHistory(3);
    expect(history).toHaveLength(3);
    // Descending order — s-4, s-3, s-2 (newest first).
    expect(history.map((s) => s.scan_id)).toEqual(['s-4', 's-3', 's-2']);
  });
});
