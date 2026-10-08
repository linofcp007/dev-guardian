import { spawn, type ChildProcess } from 'node:child_process';
import { hostname } from 'node:os';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { deadPid } from '../../helpers/deadPid.js';
import { GuardianDatabase as Database } from '../../../src/storage/db.js';
import { runMigrations } from '../../../src/storage/migrations/runner.js';
import { ScansRepo } from '../../../src/storage/scansRepo.js';

const HOUR = 60 * 60 * 1000;

function freshRepo() {
  const db = new Database(':memory:');
  runMigrations(db);
  return { db, repo: new ScansRepo(db) };
}

/**
 * A process that is alive for the whole file and is NOT this one. The reaper
 * runs once, at startup, before its own process has started any scan — so
 * this process's own pid can never be "another live server".
 */
let otherServer: ChildProcess | undefined;
let otherServerPid = 0;
beforeAll(() => {
  otherServer = spawn(process.execPath, ['-e', 'setInterval(() => {}, 60000);'], { stdio: 'ignore' });
  if (typeof otherServer.pid !== 'number') throw new Error('could not spawn a long-lived child');
  otherServerPid = otherServer.pid;
});
afterAll(() => {
  otherServer?.kill();
});

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
    const { db, repo } = freshRepo();
    insertRunning(db, repo, 'live', { pid: otherServerPid, host: hostname() }, 1 * HOUR);
    expect(repo.reapRunning()).toBe(0);
    expect(repo.getById('live')?.status).toBe('running');
  });

  // A container restarted with the same hostname is pid 1 again, and Windows
  // hands out a dead process's pid again quickly. The reaper runs at startup,
  // before this process has started any scan, so a running row carrying OUR
  // pid was written by an earlier process that happened to have it.
  it("reaps a running scan recorded under this process's own pid: an earlier process that had it", () => {
    const { db, repo } = freshRepo();
    repo.insert({ scan_id: 'same-pid', scan_type: 'sast', project_path: '/p', tree_hash: 'h' });
    expect(repo.reapRunning()).toBe(1);
    const row = db
      .prepare<[], { status: string; error: string }>("SELECT status, error FROM scans WHERE id = 'same-pid'")
      .get();
    expect(row?.status).toBe('failed');
    expect(row?.error).toMatch(/this process's own pid/);
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

  it("leaves a live owner's scan alone for longer than an unknown owner's (7 h)", () => {
    const { db, repo } = freshRepo();
    insertRunning(db, repo, 'long', { pid: otherServerPid, host: hostname() }, 7 * HOUR);
    expect(repo.reapRunning()).toBe(0);
    expect(repo.getById('long')?.status).toBe('running');
  });

  // Every scanner run is capped (10 min by default), so no real scan is
  // still going a day later: an owner that still looks alive then is a
  // reused pid, not the process that started the scan.
  it('reaps a scan whose owner still looks alive once it is more than 24 h old', () => {
    const { db, repo } = freshRepo();
    insertRunning(db, repo, 'reused-pid', { pid: otherServerPid, host: hostname() }, 25 * HOUR);
    expect(repo.reapRunning()).toBe(1);
    const row = db
      .prepare<[], { status: string; error: string }>("SELECT status, error FROM scans WHERE id = 'reused-pid'")
      .get();
    expect(row?.status).toBe('failed');
    expect(row?.error).toMatch(/24 h/);
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
    insertRunning(db, repo, 'remote-old', { pid: otherServerPid, host: 'some-other-host' }, 7 * HOUR);
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
