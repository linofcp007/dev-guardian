import { describe, expect, it } from 'vitest';
import { GuardianDatabase } from '../../../src/storage/db.js';
import { Storage } from '../../../src/storage/index.js';
import {
  DEFAULT_RETENTION_SCANS,
  PRUNE_BATCH,
  RETENTION_START_DELAY_MS,
  deletePrunableScans,
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
function seedScan(
  storage: Storage,
  id: string,
  project: string,
  type: ScanType = 'sast',
  meta?: Record<string, unknown>,
): void {
  storage.scans.insert({
    scan_id: id,
    scan_type: type,
    project_path: project,
    tree_hash: `h-${id}`,
    ...(meta !== undefined ? { meta } : {}),
  });
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

/** A scoped run's `meta` — the shape `scanToolFactory` writes at insert (Task 13). */
const SCOPED = { scope: { mode: 'staged', files: 1 } };

describe('scoped and whole-project scans are ranked apart (I1)', () => {
  // A scoped scan (`meta.scope`: `--staged`, `--unpushed`, a file list) is a
  // `sast` row like any other, but it never describes the project's state
  // (history/scanRoles.ts#isScopedScan). Ranked together, fifty pre-commit
  // runs pushed the last whole-project `scan_sast` out, and the open set
  // lost every SAST finding with nothing to say so.
  it('three scoped sast scans never push out the one whole-project sast scan (keep 3)', () => {
    const { db, storage } = fresh();
    seedScan(storage, 'full-sast', '/p1', 'sast');
    for (const id of ['sc1', 'sc2', 'sc3']) seedScan(storage, id, '/p1', 'sast', SCOPED);

    expect(listPrunableScans(db, 3)).toEqual([]);
    pruneScans(db, 3);

    expect(scanIds(db)).toEqual(['full-sast', 'sc1', 'sc2', 'sc3']);
  });

  it('keeps the newest N of each kind: old scoped and old whole-project scans are both still pruned', () => {
    const { db, storage } = fresh();
    seedScan(storage, 'w1', '/p1', 'sast');
    seedScan(storage, 'sc1', '/p1', 'sast', SCOPED);
    seedScan(storage, 'w2', '/p1', 'sast');
    seedScan(storage, 'sc2', '/p1', 'sast', SCOPED);
    seedScan(storage, 'sc3', '/p1', 'sast', SCOPED);
    seedScan(storage, 'w3', '/p1', 'sast');

    expect(pruneScans(db, 2)).toEqual({ deleted: 2, remaining: 0, complete: true });
    expect(scanIds(db)).toEqual(['w2', 'sc2', 'sc3', 'w3']);
  });

  it('a single-plugin wp_vuln_check (meta.slug) is scoped too, as isScopedScan says', () => {
    const { db, storage } = fresh();
    seedScan(storage, 'wp-full', '/p1', 'wp_vuln_check');
    for (const id of ['wp-a', 'wp-b']) seedScan(storage, id, '/p1', 'wp_vuln_check', { slug: 'akismet' });

    pruneScans(db, 1);

    expect(scanIds(db)).toEqual(['wp-full', 'wp-b']);
  });

  it('a row with malformed meta is ranked as whole-project and never breaks the prune', () => {
    const { db, storage } = fresh();
    for (const id of ['s1', 's2', 's3']) seedScan(storage, id, '/p1');
    db.prepare("UPDATE scans SET meta = '{not json' WHERE id = 's2'").run();

    expect(pruneScans(db, 1).deleted).toBe(2);
    expect(scanIds(db)).toEqual(['s3']);
  });

  it('deletePrunableScans re-ranks under the lock: a row no longer beyond the newest N is kept', () => {
    const { db, storage } = fresh();
    seedScan(storage, 'w1', '/p1', 'sast');
    seedScan(storage, 'w2', '/p1', 'sast');
    const listed = listPrunableScans(db, 1);
    expect(listed).toEqual(['w1']);

    // In between, the newer row goes (another process, another keep): w1 is
    // the newest whole-project sast scan again.
    db.prepare("DELETE FROM findings WHERE scan_id = 'w2'").run();
    db.prepare("DELETE FROM scan_cves WHERE scan_id = 'w2'").run();
    db.prepare("DELETE FROM tree_cache WHERE scan_id = 'w2'").run();
    db.prepare("DELETE FROM cves WHERE first_seen_scan_id = 'w2' OR last_seen_scan_id = 'w2'").run();
    db.prepare("DELETE FROM scans WHERE id = 'w2'").run();

    expect(deletePrunableScans(db, listed, 1)).toBe(0);
    expect(scanIds(db)).toEqual(['w1']);
  });
});

describe('an orchestrated run is kept whole around a baseline (I2)', () => {
  /**
   * Task 9's shape: the `security_full` parent first, holding
   * `meta.child_scans`, then one child per type with `meta.parent_scan_id`.
   */
  function seedRun(storage: Storage, id: string, project = '/p1'): void {
    const types: ScanType[] = ['sast', 'secrets', 'deps', 'iac'];
    seedScan(storage, id, project, 'security_full', {
      child_scans: types.map((t) => ({ tool: `scan_${t}`, scan_id: `${id}-${t}`, status: 'completed' })),
    });
    for (const t of types) seedScan(storage, `${id}-${t}`, project, t, { parent_scan_id: id });
  }

  it('never prunes a child of a baselined parent, however far beyond the newest N it is', () => {
    const { db, storage } = fresh();
    seedRun(storage, 'run1');
    storage.baselines.set({ scan_id: 'run1' });
    for (const id of ['sa', 'sb', 'sc']) seedScan(storage, id, '/p1', 'sast');

    expect(listPrunableScans(db, 3)).not.toContain('run1-sast');
    pruneScans(db, 3);

    expect(scanIds(db)).toContain('run1-sast');
    expect(storage.findings.listByScan('run1-sast')).toHaveLength(1);
  });

  it('never prunes the parent of a baselined child', () => {
    const { db, storage } = fresh();
    seedRun(storage, 'run1');
    storage.baselines.set({ scan_id: 'run1-sast' });
    seedRun(storage, 'run2');
    seedRun(storage, 'run3');

    pruneScans(db, 1);

    // run1 is beyond the newest security_full, but its sast child is the
    // baseline, so the run it belongs to stays. Its other children do not
    // stand under a baseline and go like any other row.
    expect(scanIds(db)).toEqual(expect.arrayContaining(['run1', 'run1-sast']));
    expect(scanIds(db)).not.toContain('run1-deps');
    expect(scanIds(db)).not.toContain('run2');
  });

  it("follows the parent's child_scans list too — the link runCompare reads", () => {
    const { db, storage } = fresh();
    seedScan(storage, 'run1', '/p1', 'security_full', {
      child_scans: [{ tool: 'scan_sast', scan_id: 'old-child', status: 'completed' }],
    });
    seedScan(storage, 'old-child', '/p1', 'sast'); // no parent_scan_id of its own
    storage.baselines.set({ scan_id: 'run1' });
    for (const id of ['sa', 'sb']) seedScan(storage, id, '/p1', 'sast');

    pruneScans(db, 1);

    expect(scanIds(db)).toEqual(['run1', 'old-child', 'sb']);
  });

  it('tolerates child_scans entries that are not objects, and malformed baseline meta', () => {
    const { db, storage } = fresh();
    seedScan(storage, 'run1', '/p1', 'security_full', { child_scans: ['x', 3, null, { scan_id: 7 }] });
    storage.baselines.set({ scan_id: 'run1' });
    seedScan(storage, 'run0', '/p1', 'security_full');
    db.prepare("UPDATE scans SET meta = '{broken' WHERE id = 'run0'").run();
    storage.baselines.set({ scan_id: 'run0' });
    for (const id of ['s1', 's2', 's3']) seedScan(storage, id, '/p1', 'sast');

    expect(pruneScans(db, 1).deleted).toBe(2);
    expect(scanIds(db)).toEqual(['run1', 'run0', 's3']);
  });

  // Follow-up X2: an audit_executive row links its sub-scans by
  // `meta.sub_scan_ids` ({ tool: scan_id | null }), and `runCompare.ts`
  // reads each sub-scan's bookkeeping through it. A baselined audit keeps
  // them the way a baselined security_full parent keeps its children.
  it("never prunes a baselined audit's sub_scan_ids, however far beyond the newest N they are", () => {
    const { db, storage } = fresh();
    seedScan(storage, 'sub-full', '/p1', 'security_full');
    seedScan(storage, 'sub-quality', '/p1', 'quality');
    seedScan(storage, 'audit1', '/p1', 'audit', {
      sub_scan_ids: { security_scan_full: 'sub-full', quality_check: 'sub-quality', deps_audit: null },
    });
    storage.baselines.set({ scan_id: 'audit1' });
    for (const id of ['f1', 'f2']) seedScan(storage, id, '/p1', 'security_full');
    for (const id of ['q1', 'q2']) seedScan(storage, id, '/p1', 'quality');

    expect(listPrunableScans(db, 1)).not.toContain('sub-full');
    pruneScans(db, 1);

    expect(scanIds(db)).toEqual(['sub-full', 'sub-quality', 'audit1', 'f2', 'q2']);
    expect(storage.findings.listByScan('sub-full')).toHaveLength(1);
  });

  it("an audit that is not the baseline protects nothing, and malformed sub_scan_ids are tolerated", () => {
    const { db, storage } = fresh();
    seedScan(storage, 'sub-old', '/p1', 'quality');
    seedScan(storage, 'audit0', '/p1', 'audit', { sub_scan_ids: { quality_check: 'sub-old' } });
    seedScan(storage, 'audit1', '/p1', 'audit', { sub_scan_ids: ['sub-old', 7, null] });
    storage.baselines.set({ scan_id: 'audit1' });
    seedScan(storage, 'audit2', '/p1', 'audit', { sub_scan_ids: 'sub-old' });
    storage.baselines.set({ scan_id: 'audit2' });
    for (const id of ['q1', 'q2']) seedScan(storage, id, '/p1', 'quality');

    pruneScans(db, 1);

    // audit0 is beyond the newest audit and not a baseline; its sub-scan is
    // an ordinary quality row, and the two baselined audits' malformed lists
    // name nothing that could keep it.
    expect(scanIds(db)).toEqual(['audit1', 'audit2', 'q2']);
  });

  it('deletePrunableScans honours a baseline set on the parent after its children were listed', () => {
    const { db, storage } = fresh();
    seedRun(storage, 'run1');
    for (const id of ['sa', 'sb']) seedScan(storage, id, '/p1', 'sast');
    const listed = listPrunableScans(db, 1);
    expect(listed).toContain('run1-sast');

    storage.baselines.set({ scan_id: 'run1' }); // another process, in between

    deletePrunableScans(db, listed, 1);
    expect(scanIds(db)).toContain('run1-sast');
    expect(scanIds(db)).not.toContain('sa');
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

describe('deletePrunableScans', () => {
  it('honours a baseline set after the scan was listed as prunable', () => {
    const { db, storage } = fresh();
    for (const id of ['s1', 's2', 's3']) seedScan(storage, id, '/p1');
    const listed = listPrunableScans(db, 1);
    expect(listed).toEqual(['s1', 's2']);

    storage.baselines.set({ scan_id: 's1' }); // another process, in between

    expect(deletePrunableScans(db, listed, 1)).toBe(1);
    expect(scanIds(db)).toEqual(['s1', 's3']);
  });
});

describe('deleteScans (a caller removing a scan it wrote, whatever its rank)', () => {
  it('deletes the newest scan with its rows', () => {
    const { db, storage } = fresh();
    for (const id of ['s1', 's2']) seedScan(storage, id, '/p1');
    expect(deleteScans(db, ['s2'])).toBe(1);
    expect(scanIds(db)).toEqual(['s1']);
    expect(count(db, 'findings')).toBe(1);
  });

  it('never deletes a baseline, a running scan, or a child of a baselined orchestrated run', () => {
    const { db, storage } = fresh();
    seedScan(storage, 'base', '/p1');
    storage.baselines.set({ scan_id: 'base' });
    seedScan(storage, 'run', '/p1');
    db.prepare("UPDATE scans SET status = 'running' WHERE id = 'run'").run();
    seedScan(storage, 'parent', '/p1', 'security_full', { child_scans: [] });
    storage.baselines.set({ scan_id: 'parent' });
    seedScan(storage, 'child', '/p1', 'sast', { parent_scan_id: 'parent' });

    expect(deleteScans(db, ['base', 'run', 'child'])).toBe(0);
    expect(scanIds(db)).toEqual(['base', 'run', 'parent', 'child']);
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
