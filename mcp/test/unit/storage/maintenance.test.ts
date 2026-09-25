import { describe, expect, it } from 'vitest';
import { GuardianDatabase } from '../../../src/storage/db.js';
import { Storage } from '../../../src/storage/index.js';
import {
  DEFAULT_RETENTION_SCANS,
  PRUNE_BATCH,
  RETENTION_START_DELAY_MS,
  deleteScans,
  listPrunableScans,
  pruneScans,
  reapOrphanedScans,
  resolveRetentionLimit,
  scheduleRetention,
  type Defer,
} from '../../../src/storage/maintenance.js';
import { runMigrations } from '../../../src/storage/migrations/runner.js';
import type { ScanType } from '../../../src/types.js';

function fresh(): { db: GuardianDatabase; storage: Storage } {
  const db = new GuardianDatabase(':memory:');
  db.pragma('foreign_keys = ON');
  runMigrations(db);
  return { db, storage: new Storage(db) };
}

let clock = 0;
/** A completed scan with one finding, one CVE and a tree-cache row. */
function seedScan(storage: Storage, id: string, project: string, type: ScanType = 'sast'): void {
  storage.scans.insert({ scan_id: id, scan_type: type, project_path: project, tree_hash: `h-${id}` });
  storage.scans.finalize({ scan_id: id, status: 'completed', tools_run: [], missing_tools: [] });
  // Distinct, increasing start times: retention ranks by recency.
  clock += 1;
  storage
    .rawHandle()
    .prepare('UPDATE scans SET started_at = ? WHERE id = ?')
    .run(new Date(Date.UTC(2026, 0, 1, 0, 0, 0, clock)).toISOString(), id);
  storage.findings.bulkInsert([
    {
      fingerprint: `fp-${id}`,
      scan_id: id,
      tool: 'semgrep',
      severity: 'high',
      category: 'security',
      title: 'x',
      fix_available: false,
    },
  ]);
  storage.cves.bulkUpsert([{ cve_id: `CVE-${id}`, package_name: 'p', severity: 'high', scan_id: id }]);
  storage.scans.attachTreeCache({ tree_hash: `h-${id}`, scan_id: id, scan_type: type });
}

/** `n` scans of one project and type, oldest first: s0 … s(n-1). */
function seedMany(storage: Storage, n: number): string[] {
  const ids = Array.from({ length: n }, (_, i) => `s${i}`);
  for (const id of ids) seedScan(storage, id, '/p1');
  return ids;
}

function scanIds(db: GuardianDatabase): string[] {
  return db
    .prepare<[], { id: string }>('SELECT id FROM scans ORDER BY started_at, rowid')
    .all()
    .map((r) => r.id);
}

function count(db: GuardianDatabase, table: string): number {
  return db.prepare<[], { n: number }>(`SELECT COUNT(*) AS n FROM ${table}`).get()?.n ?? -1;
}

/** A clock that advances `step` ms every time it is read. */
function steppingClock(step: number): () => number {
  let t = 0;
  return () => (t += step);
}

describe('pruneScans', () => {
  it('keeps the newest N scans per (project, scan type) and deletes the rest with their child rows', () => {
    const { db, storage } = fresh();
    for (const id of ['a1', 'a2', 'a3', 'a4']) seedScan(storage, id, '/p1', 'sast');
    for (const id of ['d1', 'd2', 'd3']) seedScan(storage, id, '/p1', 'deps');
    for (const id of ['b1', 'b2']) seedScan(storage, id, '/p2', 'sast');

    const result = pruneScans(db, 2);

    expect(result).toEqual({ deleted: 3, remaining: 0, complete: true });
    expect(scanIds(db)).toEqual(['a3', 'a4', 'd2', 'd3', 'b1', 'b2']);
    expect(count(db, 'findings')).toBe(6);
    expect(count(db, 'scan_cves')).toBe(6);
    expect(count(db, 'tree_cache')).toBe(6);
    expect(storage.findings.listByScan('a1')).toEqual([]);
    expect(storage.cves.listActive('a1')).toEqual([]);
  });

  it('never deletes a scan a baseline points at, however old', () => {
    const { db, storage } = fresh();
    for (const id of ['s1', 's2', 's3']) seedScan(storage, id, '/p1');
    storage.baselines.set({ scan_id: 's1' });

    pruneScans(db, 1);

    expect(scanIds(db)).toEqual(['s1', 's3']);
    expect(storage.baselines.getActive()?.scan_id).toBe('s1');
    expect(storage.findings.listByScan('s1')).toHaveLength(1);
  });

  it('never deletes a scan that is still running', () => {
    const { db, storage } = fresh();
    seedScan(storage, 'r1', '/p1');
    db.prepare("UPDATE scans SET status = 'running' WHERE id = 'r1'").run();
    for (const id of ['s2', 's3']) seedScan(storage, id, '/p1');

    pruneScans(db, 1);

    expect(scanIds(db)).toEqual(['r1', 's3']);
  });

  it('removes legacy `cves` rows that point at a pruned scan, instead of failing on the foreign key', () => {
    const { db, storage } = fresh();
    for (const id of ['s1', 's2']) seedScan(storage, id, '/p1');
    db.exec(`INSERT INTO cves VALUES ('CVE-LEGACY', 'p', NULL, NULL, 'high', 's1', 's2')`);

    expect(pruneScans(db, 1).deleted).toBe(1);
    expect(scanIds(db)).toEqual(['s2']);
    expect(count(db, 'cves')).toBe(0);
  });

  it('deletes nothing when retention is disabled (0)', () => {
    const { db, storage } = fresh();
    for (const id of ['s1', 's2', 's3']) seedScan(storage, id, '/p1');
    expect(pruneScans(db, 0)).toEqual({ deleted: 0, remaining: 0, complete: true });
    expect(scanIds(db)).toHaveLength(3);
  });

  it(`works through more than one batch (${PRUNE_BATCH} scans per write transaction) to the end`, () => {
    const { db, storage } = fresh();
    const ids = seedMany(storage, 2 * PRUNE_BATCH + 7 + 3);

    const result = pruneScans(db, 3);

    expect(result).toEqual({ deleted: 2 * PRUNE_BATCH + 7, remaining: 0, complete: true });
    expect(scanIds(db)).toEqual(ids.slice(-3));
    expect(count(db, 'findings')).toBe(3);
  });

  it('stops after the last batch when the backlog is an exact multiple of the batch size', () => {
    const { db, storage } = fresh();
    seedMany(storage, 2 * PRUNE_BATCH + 1);
    expect(pruneScans(db, 1, { maxBatches: 2 })).toEqual({
      deleted: 2 * PRUNE_BATCH,
      remaining: 0,
      complete: true,
    });
  });

  it('stops at the batch budget and leaves the rest for the next run', () => {
    const { db, storage } = fresh();
    const ids = seedMany(storage, 2 * PRUNE_BATCH + 7 + 3);

    const first = pruneScans(db, 3, { maxBatches: 1 });
    expect(first).toEqual({ deleted: PRUNE_BATCH, remaining: PRUNE_BATCH + 7, complete: false });
    // Oldest first: what is left is the newer part of the backlog, plus the kept three.
    expect(scanIds(db)).toEqual(ids.slice(PRUNE_BATCH));

    const second = pruneScans(db, 3);
    expect(second).toEqual({ deleted: PRUNE_BATCH + 7, remaining: 0, complete: true });
    expect(scanIds(db)).toEqual(ids.slice(-3));
  });

  it('stops at the time budget', () => {
    const { db, storage } = fresh();
    seedMany(storage, 3 * PRUNE_BATCH + 1);
    // Every clock read is 10 ms later: the budget check before batch 1 reads
    // 10 ms, before batch 2 20 ms, and 30 ms >= 25 stops the third.
    const result = pruneScans(db, 1, { budgetMs: 25, now: steppingClock(10) });
    expect(result).toEqual({ deleted: 2 * PRUNE_BATCH, remaining: PRUNE_BATCH, complete: false });
  });
});

describe('every column that references a scan is indexed', () => {
  // Retention deletes a scan with every row pointing at it, and SQLite's own
  // foreign-key check looks each of these columns up again. An unindexed one
  // costs a full table scan per deleted scan: 21.5 s under one write lock for
  // 2950 scans over 60k legacy `cves` rows, before these indexes existed.
  // (`baselines.scan_id` is exempt: a handful of rows, and never deleted from.)
  it.each([
    ['findings', 'scan_id'],
    ['scan_cves', 'scan_id'],
    ['tree_cache', 'scan_id'],
    ['cves', 'first_seen_scan_id'],
    ['cves', 'last_seen_scan_id'],
  ])('%s.%s', (table, column) => {
    const { db } = fresh();
    const plan = db
      .prepare<[string], { detail: string }>(`EXPLAIN QUERY PLAN SELECT 1 FROM ${table} WHERE ${column} = ?`)
      .all('x')
      .map((r) => r.detail)
      .join(' | ');
    expect(plan).toMatch(/USING (COVERING )?INDEX/);
  });
});

describe('deleteScans', () => {
  it('honours a baseline set after the scan was listed as prunable', () => {
    const { db, storage } = fresh();
    for (const id of ['s1', 's2', 's3']) seedScan(storage, id, '/p1');
    const listed = listPrunableScans(db, 1);
    expect(listed).toEqual(['s1', 's2']);

    storage.baselines.set({ scan_id: 's1' }); // another process, in between

    expect(deleteScans(db, listed)).toBe(1);
    expect(scanIds(db)).toEqual(['s1', 's3']);
  });
});

describe('resolveRetentionLimit', () => {
  it('defaults to 50', () => {
    expect(DEFAULT_RETENTION_SCANS).toBe(50);
    expect(resolveRetentionLimit(undefined)).toEqual({ keep: 50 });
    expect(resolveRetentionLimit('')).toEqual({ keep: 50 });
  });

  it('honours a positive integer and 0 (disabled)', () => {
    expect(resolveRetentionLimit('10')).toEqual({ keep: 10 });
    expect(resolveRetentionLimit(' 7 ')).toEqual({ keep: 7 });
    expect(resolveRetentionLimit('0')).toEqual({ keep: 0 });
  });

  it('falls back to the default, with a warning, for anything else', () => {
    for (const raw of ['abc', '-3', '2.5', '1e3']) {
      const r = resolveRetentionLimit(raw);
      expect(r.keep).toBe(50);
      expect(r.warning).toMatch(/GUARDIAN_RETENTION_SCANS/);
    }
  });
});

/** A `Defer` that queues callbacks for the test to run by hand. */
function manualTimers(): { defer: Defer; delays: number[]; runNext(): boolean; pending(): number } {
  const queue: Array<{ fn: () => void; cancelled: boolean }> = [];
  const delays: number[] = [];
  return {
    delays,
    defer: (fn, ms) => {
      const entry = { fn, cancelled: false };
      queue.push(entry);
      delays.push(ms);
      return () => {
        entry.cancelled = true;
      };
    },
    runNext: () => {
      const next = queue.shift();
      if (next === undefined) return false;
      if (!next.cancelled) next.fn();
      return true;
    },
    pending: () => queue.filter((e) => !e.cancelled).length,
  };
}

describe('scheduleRetention', () => {
  it('does nothing until its timer fires — the server connects first', () => {
    const { db, storage } = fresh();
    seedMany(storage, 5);
    const timers = manualTimers();

    scheduleRetention(storage, () => {}, { env: { GUARDIAN_RETENTION_SCANS: '1' }, defer: timers.defer });

    expect(scanIds(db)).toHaveLength(5);
    expect(timers.delays).toEqual([RETENTION_START_DELAY_MS]);
  });

  it('deletes one batch per timer tick until the backlog is gone, then logs once', () => {
    const { db, storage } = fresh();
    const ids = seedMany(storage, 2 * PRUNE_BATCH + 7 + 1);
    const timers = manualTimers();
    const lines: string[] = [];

    scheduleRetention(storage, (l) => lines.push(l), {
      env: { GUARDIAN_RETENTION_SCANS: '1' },
      defer: timers.defer,
    });

    timers.runNext();
    expect(scanIds(db)).toHaveLength(PRUNE_BATCH + 7 + 1);
    timers.runNext();
    expect(scanIds(db)).toHaveLength(7 + 1);
    expect(lines).toEqual([]);
    timers.runNext();
    expect(scanIds(db)).toEqual(ids.slice(-1));
    expect(timers.pending()).toBe(0);
    expect(lines).toEqual([`pruned ${2 * PRUNE_BATCH + 7} scan(s) beyond the newest 1 per project and scan type`]);
  });

  it('stops when its work budget is spent, and says how many are left for the next start', () => {
    const { db, storage } = fresh();
    seedMany(storage, 3 * PRUNE_BATCH + 1);
    const timers = manualTimers();
    const lines: string[] = [];

    scheduleRetention(storage, (l) => lines.push(l), {
      env: { GUARDIAN_RETENTION_SCANS: '1' },
      defer: timers.defer,
      // Each tick reads the clock twice, 10 ms apart: 10 ms of work per batch.
      now: steppingClock(10),
      budgetMs: 15,
    });
    while (timers.runNext()) {
      /* drain */
    }

    expect(scanIds(db)).toHaveLength(PRUNE_BATCH + 1);
    expect(lines).toEqual([
      `pruned ${2 * PRUNE_BATCH} scan(s) beyond the newest 1 per project and scan type; ` +
        `${PRUNE_BATCH} left for the next start (retention budget 15 ms)`,
    ]);
  });

  it('stops when cancelled (the server is shutting down)', () => {
    const { db, storage } = fresh();
    seedMany(storage, 2 * PRUNE_BATCH + 2);
    const timers = manualTimers();

    const cancel = scheduleRetention(storage, () => {}, {
      env: { GUARDIAN_RETENTION_SCANS: '1' },
      defer: timers.defer,
    });
    timers.runNext();
    cancel();
    while (timers.runNext()) {
      /* drain */
    }

    expect(scanIds(db)).toHaveLength(PRUNE_BATCH + 2);
  });

  it('logs a failure and stops, never throws', () => {
    const { storage } = fresh();
    seedMany(storage, 3);
    storage.close();
    const timers = manualTimers();
    const lines: string[] = [];

    scheduleRetention(storage, (l) => lines.push(l), {
      env: { GUARDIAN_RETENTION_SCANS: '1' },
      defer: timers.defer,
    });
    expect(() => timers.runNext()).not.toThrow();
    expect(lines.join('\n')).toMatch(/retention failed \(continuing\)/);
    expect(timers.pending()).toBe(0);
  });

  it('schedules nothing when GUARDIAN_RETENTION_SCANS=0', () => {
    const { storage } = fresh();
    const timers = manualTimers();
    scheduleRetention(storage, () => {}, { env: { GUARDIAN_RETENTION_SCANS: '0' }, defer: timers.defer });
    expect(timers.delays).toEqual([]);
  });

  it('logs an unusable GUARDIAN_RETENTION_SCANS and uses the default', () => {
    const { storage } = fresh();
    const timers = manualTimers();
    const lines: string[] = [];
    scheduleRetention(storage, (l) => lines.push(l), { env: { GUARDIAN_RETENTION_SCANS: 'lots' }, defer: timers.defer });
    expect(lines.join('\n')).toMatch(/GUARDIAN_RETENTION_SCANS='lots'/);
    expect(timers.delays).toHaveLength(1);
  });
});

describe('reapOrphanedScans', () => {
  it('logs how many scans it reaped', () => {
    const { storage } = fresh();
    const lines: string[] = [];
    reapOrphanedScans({ scans: { reapRunning: () => 2 }, rawHandle: () => storage.rawHandle() }, (l) =>
      lines.push(l),
    );
    expect(lines).toEqual(['reaped 2 orphaned scan(s)']);
  });

  it('logs a failure instead of throwing it', () => {
    const { storage } = fresh();
    const lines: string[] = [];
    const failing = {
      scans: {
        reapRunning: (): number => {
          throw new Error('database is locked');
        },
      },
      rawHandle: () => storage.rawHandle(),
    };
    expect(() => reapOrphanedScans(failing, (l) => lines.push(l))).not.toThrow();
    expect(lines.join('\n')).toMatch(/reaper failed \(continuing\): database is locked/);
  });
});
