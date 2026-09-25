import { spawnSync } from 'node:child_process';
import { hostname } from 'node:os';
import { describe, expect, it } from 'vitest';
import { GuardianDatabase as Database } from '../../../src/storage/db.js';
import { runMigrations } from '../../../src/storage/migrations/runner.js';
import { ScansRepo } from '../../../src/storage/scansRepo.js';

const HOUR = 60 * 60 * 1000;

function freshRepo() {
  const db = new Database(':memory:');
  runMigrations(db);
  return { db, repo: new ScansRepo(db) };
}

/** The pid of a process that has already exited. */
function deadPid(): number {
  const r = spawnSync(process.execPath, ['-e', '']);
  if (typeof r.pid !== 'number') throw new Error('could not spawn a short-lived child');
  return r.pid;
}

function insertRunning(
  db: Database,
  repo: ScansRepo,
  id: string,
  owner: { pid: number | null; host: string | null },
  ageMs = 0,
): void {
  repo.insert({ scan_id: id, scan_type: 'sast', project_path: '/p', tree_hash: 'h' });
  db.prepare('UPDATE scans SET owner_pid = ?, owner_host = ?, started_at = ? WHERE id = ?').run(
    owner.pid,
    owner.host,
    new Date(Date.now() - ageMs).toISOString(),
    id,
  );
}

describe('ScansRepo.insert records its owner', () => {
  it('stores this process id and host on the new scan', () => {
    const { db, repo } = freshRepo();
    repo.insert({ scan_id: 's', scan_type: 'sast', project_path: '/p', tree_hash: 'h' });
    const row = db
      .prepare<[], { owner_pid: number; owner_host: string }>("SELECT owner_pid, owner_host FROM scans WHERE id = 's'")
      .get();
    expect(row).toEqual({ owner_pid: process.pid, owner_host: hostname() });
  });
});

describe('reapRunning (startup reaper)', () => {
  it("leaves alone a running scan whose owner process is alive — another server's scan", () => {
    const { repo } = freshRepo();
    repo.insert({ scan_id: 'live', scan_type: 'sast', project_path: '/p', tree_hash: 'h' });
    expect(repo.reapRunning()).toBe(0);
    expect(repo.getById('live')?.status).toBe('running');
  });

  it('reaps a running scan whose owner on this host has exited', () => {
    const { db, repo } = freshRepo();
    insertRunning(db, repo, 'orphan', { pid: deadPid(), host: hostname() });
    expect(repo.reapRunning()).toBe(1);
    const reaped = db
      .prepare<[], { status: string; error: string; finished_at: string | null }>(
        "SELECT status, error, finished_at FROM scans WHERE id = 'orphan'",
      )
      .get();
    expect(reaped?.status).toBe('failed');
    expect(reaped?.error).toMatch(/^reaped on startup/);
    expect(reaped?.finished_at).not.toBeNull();
  });

  it("never reaps a live owner's scan, however old it is", () => {
    const { db, repo } = freshRepo();
    insertRunning(db, repo, 'long', { pid: process.pid, host: hostname() }, 7 * HOUR);
    expect(repo.reapRunning()).toBe(0);
    expect(repo.getById('long')?.status).toBe('running');
  });

  it('reaps a scan with no recorded owner (written before owners existed) only once it is 6 h old', () => {
    const { db, repo } = freshRepo();
    insertRunning(db, repo, 'legacy-young', { pid: null, host: null }, 1 * HOUR);
    insertRunning(db, repo, 'legacy-old', { pid: null, host: null }, 7 * HOUR);
    expect(repo.reapRunning()).toBe(1);
    expect(repo.getById('legacy-young')?.status).toBe('running');
    expect(repo.getById('legacy-old')?.status).toBe('failed');
  });

  it("treats another host's scan as an unknown owner: its pid means nothing here", () => {
    const { db, repo } = freshRepo();
    insertRunning(db, repo, 'remote-young', { pid: deadPid(), host: 'some-other-host' }, 1 * HOUR);
    insertRunning(db, repo, 'remote-old', { pid: process.pid, host: 'some-other-host' }, 7 * HOUR);
    expect(repo.reapRunning()).toBe(1);
    expect(repo.getById('remote-young')?.status).toBe('running');
    expect(repo.getById('remote-old')?.status).toBe('failed');
  });

  it('asks the injected liveness check about the recorded pid, and nothing else', () => {
    const { db, repo } = freshRepo();
    insertRunning(db, repo, 'a', { pid: 4242, host: 'box' });
    const asked: number[] = [];
    const reaped = repo.reapRunning({
      host: 'box',
      isAlive: (pid) => {
        asked.push(pid);
        return false;
      },
    });
    expect(asked).toEqual([4242]);
    expect(reaped).toBe(1);
  });

  it('never touches finished scans', () => {
    const { db, repo } = freshRepo();
    insertRunning(db, repo, 'done', { pid: deadPid(), host: hostname() }, 7 * HOUR);
    repo.finalize({ scan_id: 'done', status: 'completed', tools_run: [], missing_tools: [] });
    expect(repo.reapRunning()).toBe(0);
    expect(repo.getById('done')?.status).toBe('completed');
  });
});
