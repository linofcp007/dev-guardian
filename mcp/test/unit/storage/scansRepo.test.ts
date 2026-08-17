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

  it('getLatestForProject ignores a newer completed scan belonging to another project', () => {
    // getLatest() picks the latest completed scan across the WHOLE database,
    // no project filter — correct for a caller with no project in scope,
    // wrong for one that resolved a specific projectPath and must not read
    // another project's scan just because that project's scan happened to
    // complete more recently. Mirrors surfaceRepo.ts's getLatestForProject
    // and findingsRepo.ts's listOpenForProject siblings.
    const { repo } = freshRepo();
    repo.insert({ scan_id: 'a1', scan_type: 'sast', project_path: '/project-a', tree_hash: 'ha' });
    repo.finalize({ scan_id: 'a1', status: 'completed', tools_run: [], missing_tools: [] });

    // Inserted second, so it wins the unscoped `started_at DESC, rowid DESC`
    // ordering even if both rows land in the same millisecond: `id` is a TEXT
    // PRIMARY KEY (001_initial.sql), not `INTEGER PRIMARY KEY`, so it is not
    // a rowid alias — SQLite still assigns this table its own implicit,
    // strictly-increasing rowid, and `rowid DESC` is the statement's explicit
    // tiebreaker. Insertion order, not wall-clock resolution, decides ties.
    repo.insert({ scan_id: 'b1', scan_type: 'sast', project_path: '/project-b', tree_hash: 'hb' });
    repo.finalize({ scan_id: 'b1', status: 'completed', tools_run: [], missing_tools: [] });

    // getLatest() answers with the OTHER project's scan — kept, and
    // asserted, because callers with no project in scope still depend on it.
    expect(repo.getLatest()?.scan_id).toBe('b1');

    expect(repo.getLatestForProject('/project-a')?.scan_id).toBe('a1');
    expect(repo.getLatestForProject('/project-b')?.scan_id).toBe('b1');
  });

  it('getLatest ignores a create_fix_pr worktree re-scan, even though it completed more recently (task-7-review.md I3)', () => {
    // create_fix_pr re-runs a scanner inside a disposable worktree
    // (project_path starting with 'guardian-fixpr-wt-') to verify a fix. A
    // wrong implementation lets that real, completed scan win getLatest()'s
    // unscoped ordering the moment it finishes — every unscoped consumer
    // (guardian://findings/open, risk_score, triage_findings, …) then reports
    // on a directory that no longer exists instead of the real project.
    const { repo } = freshRepo();
    repo.insert({ scan_id: 'real', scan_type: 'sast', project_path: '/real-project', tree_hash: 'h1' });
    repo.finalize({ scan_id: 'real', status: 'completed', tools_run: [], missing_tools: [] });

    // Inserted (and completed) SECOND, so it would win the unscoped
    // `started_at DESC, rowid DESC` ordering if not excluded by name.
    repo.insert({
      scan_id: 'verify',
      scan_type: 'sast',
      project_path: '/tmp/guardian-fixpr-wt-AbC123',
      tree_hash: 'h2',
    });
    repo.finalize({ scan_id: 'verify', status: 'completed', tools_run: [], missing_tools: [] });

    expect(repo.getLatest()?.scan_id).toBe('real');
    // The worktree scan is still readable by id — this excludes it only
    // from the UNSCOPED "latest" surface, not from storage entirely.
    expect(repo.getById('verify')?.scan_id).toBe('verify');
  });

  it('getLatestForProject returns null for a project with no scan of its own', () => {
    const { repo } = freshRepo();
    repo.insert({ scan_id: 's1', scan_type: 'sast', project_path: '/project-a', tree_hash: 'h' });
    repo.finalize({ scan_id: 's1', status: 'completed', tools_run: [], missing_tools: [] });

    expect(repo.getLatestForProject('/project-c')).toBeNull();
  });

  it('listHistoryForProject returns scans in start-time descending order, capped by limit', () => {
    const { repo } = freshRepo();
    for (let i = 0; i < 5; i++) {
      repo.insert({
        scan_id: `s-${i}`,
        scan_type: 'sast',
        project_path: '/p',
        tree_hash: `h-${i}`,
      });
    }
    const history = repo.listHistoryForProject('/p', 3);
    expect(history).toHaveLength(3);
    // Descending order — s-4, s-3, s-2 (newest first) — same ordering as
    // the equivalent listHistory test above, over the scoped variant.
    expect(history.map((s) => s.scan_id)).toEqual(['s-4', 's-3', 's-2']);
  });

  it('listHistoryForProject excludes another project entirely, even a scan inserted later', () => {
    // The listHistory hazard for a history LIST rather than a single latest
    // row: a naive implementation that fetches listHistory(N) and filters by
    // project_path in JS would silently drop this project's older entries
    // whenever another project's scans push them past N. Scoping in SQL, as
    // implemented, cannot do that — a match is either in the WHERE clause's
    // result set or it isn't, regardless of how much other-project traffic
    // exists.
    const { repo } = freshRepo();
    repo.insert({ scan_id: 'a1', scan_type: 'sast', project_path: '/project-a', tree_hash: 'ha' });
    repo.finalize({ scan_id: 'a1', status: 'completed', tools_run: [], missing_tools: [] });

    // Inserted second — later start time and higher rowid — so it would sort
    // first in an unscoped history list.
    repo.insert({ scan_id: 'b1', scan_type: 'sast', project_path: '/project-b', tree_hash: 'hb' });
    repo.finalize({ scan_id: 'b1', status: 'completed', tools_run: [], missing_tools: [] });

    expect(repo.listHistory(50).map((s) => s.scan_id)).toEqual(['b1', 'a1']);
    expect(repo.listHistoryForProject('/project-a', 50).map((s) => s.scan_id)).toEqual(['a1']);
    expect(repo.listHistoryForProject('/project-b', 50).map((s) => s.scan_id)).toEqual(['b1']);
  });

  it('listHistoryForProject includes non-completed scans, matching listHistory\'s own contract', () => {
    const { repo } = freshRepo();
    repo.insert({ scan_id: 'running-1', scan_type: 'sast', project_path: '/p', tree_hash: 'h' });
    // Left running — never finalized.

    const history = repo.listHistoryForProject('/p');
    expect(history).toHaveLength(1);
    expect(history[0]?.status).toBe('running');
  });
});
