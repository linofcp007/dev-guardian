import { describe, expect, it } from 'vitest';
import { GuardianDatabase } from '../../../src/storage/db.js';
import { Storage } from '../../../src/storage/index.js';
import {
  DEFAULT_RETENTION_SCANS,
  pruneScans,
  resolveRetentionLimit,
  runStartupMaintenance,
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
    .run(new Date(Date.UTC(2026, 0, 1, 0, 0, clock)).toISOString(), id);
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

function scanIds(db: GuardianDatabase): string[] {
  return db
    .prepare<[], { id: string }>('SELECT id FROM scans ORDER BY started_at, rowid')
    .all()
    .map((r) => r.id);
}

function count(db: GuardianDatabase, table: string): number {
  return db.prepare<[], { n: number }>(`SELECT COUNT(*) AS n FROM ${table}`).get()?.n ?? -1;
}

describe('pruneScans', () => {
  it('keeps the newest N scans per (project, scan type) and deletes the rest with their child rows', () => {
    const { db, storage } = fresh();
    for (const id of ['a1', 'a2', 'a3', 'a4']) seedScan(storage, id, '/p1', 'sast');
    for (const id of ['d1', 'd2', 'd3']) seedScan(storage, id, '/p1', 'deps');
    for (const id of ['b1', 'b2']) seedScan(storage, id, '/p2', 'sast');

    const result = pruneScans(db, 2);

    expect(result.deleted).toBe(3);
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
    expect(pruneScans(db, 0).deleted).toBe(0);
    expect(scanIds(db)).toHaveLength(3);
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

describe('runStartupMaintenance', () => {
  it('prunes to GUARDIAN_RETENTION_SCANS and logs what it did', () => {
    const { db, storage } = fresh();
    for (const id of ['s1', 's2', 's3']) seedScan(storage, id, '/p1');
    const lines: string[] = [];

    runStartupMaintenance(storage, (l) => lines.push(l), { GUARDIAN_RETENTION_SCANS: '1' });

    expect(scanIds(db)).toEqual(['s3']);
    expect(lines.join('\n')).toMatch(/pruned 2 scan/);
  });

  it('keeps going when the reaper throws: logs it, and retention still runs', () => {
    const { db, storage } = fresh();
    for (const id of ['s1', 's2']) seedScan(storage, id, '/p1');
    const failingReaper = {
      scans: {
        reapRunning: (): number => {
          throw new Error('database is locked');
        },
      },
      rawHandle: () => storage.rawHandle(),
    };
    const lines: string[] = [];

    expect(() =>
      runStartupMaintenance(failingReaper, (l) => lines.push(l), { GUARDIAN_RETENTION_SCANS: '1' }),
    ).not.toThrow();

    expect(lines.join('\n')).toMatch(/reaper failed.*database is locked/);
    expect(scanIds(db)).toEqual(['s2']);
  });

  it('keeps going when retention throws', () => {
    const { storage } = fresh();
    storage.close();
    const lines: string[] = [];
    expect(() =>
      runStartupMaintenance(storage, (l) => lines.push(l), { GUARDIAN_RETENTION_SCANS: '1' }),
    ).not.toThrow();
    expect(lines.join('\n')).toMatch(/retention failed/);
  });
});
