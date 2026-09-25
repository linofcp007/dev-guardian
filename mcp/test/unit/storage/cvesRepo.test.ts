import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { CvesRepo, type UpsertCveInput } from '../../../src/storage/cvesRepo.js';
import { GuardianDatabase } from '../../../src/storage/db.js';
import { listMigrations, runMigrations } from '../../../src/storage/migrations/runner.js';
import { ScansRepo } from '../../../src/storage/scansRepo.js';

function fresh() {
  const db = new GuardianDatabase(':memory:');
  db.pragma('foreign_keys = ON');
  runMigrations(db);
  return { db, scans: new ScansRepo(db), cves: new CvesRepo(db) };
}

function scan(scans: ScansRepo, id: string, project: string): void {
  scans.insert({ scan_id: id, scan_type: 'deps', project_path: project, tree_hash: `h-${id}` });
}

function cve(scanId: string, id: string, extra: Partial<UpsertCveInput> = {}): UpsertCveInput {
  return { cve_id: id, package_name: 'lodash', installed_version: '4.17.20', severity: 'high', scan_id: scanId, ...extra };
}

describe('CvesRepo.listActive', () => {
  it("keeps a scan's CVEs after a later scan of ANOTHER project sees the same CVE", () => {
    const { scans, cves } = fresh();
    scan(scans, 'scan-a', '/p1');
    scan(scans, 'scan-b', '/p2');
    cves.bulkUpsert([cve('scan-a', 'CVE-2021-1')]);
    cves.bulkUpsert([cve('scan-b', 'CVE-2021-1')]);

    expect(cves.listActive('scan-a').map((c) => c.cve_id)).toEqual(['CVE-2021-1']);
    expect(cves.listActive('scan-b').map((c) => c.cve_id)).toEqual(['CVE-2021-1']);
  });

  it('returns exactly the CVEs of the scan asked about', () => {
    const { scans, cves } = fresh();
    scan(scans, 'scan-a', '/p1');
    scan(scans, 'scan-b', '/p2');
    cves.bulkUpsert([cve('scan-a', 'CVE-X'), cve('scan-a', 'CVE-Y')]);
    cves.bulkUpsert([cve('scan-b', 'CVE-Y'), cve('scan-b', 'CVE-Z')]);

    expect(cves.listActive('scan-a').map((c) => c.cve_id)).toEqual(['CVE-X', 'CVE-Y']);
    expect(cves.listActive('scan-b').map((c) => c.cve_id)).toEqual(['CVE-Y', 'CVE-Z']);
  });

  it('dedupes a CVE whose installed version is unknown instead of adding a row per report', () => {
    const { scans, cves } = fresh();
    scan(scans, 'scan-a', '/p1');
    const noVersion = cve('scan-a', 'CVE-NOVER', { installed_version: undefined });
    cves.bulkUpsert([noVersion, noVersion]);
    cves.upsert(noVersion);

    const listed = cves.listActive('scan-a');
    expect(listed).toHaveLength(1);
    expect(listed[0]).not.toHaveProperty('installed_version');
  });

  it('keeps one row per distinct installed version of the same package', () => {
    const { scans, cves } = fresh();
    scan(scans, 'scan-a', '/p1');
    cves.bulkUpsert([
      cve('scan-a', 'CVE-V', { installed_version: '1.0.0' }),
      cve('scan-a', 'CVE-V', { installed_version: '2.0.0' }),
    ]);
    expect(cves.listActive('scan-a').map((c) => c.installed_version)).toEqual(['1.0.0', '2.0.0']);
  });

  it('orders by severity, most severe first', () => {
    const { scans, cves } = fresh();
    scan(scans, 'scan-a', '/p1');
    cves.bulkUpsert([
      cve('scan-a', 'CVE-LOW', { severity: 'low' }),
      cve('scan-a', 'CVE-CRIT', { severity: 'critical' }),
      cve('scan-a', 'CVE-MED', { severity: 'medium' }),
    ]);
    expect(cves.listActive('scan-a').map((c) => c.cve_id)).toEqual(['CVE-CRIT', 'CVE-MED', 'CVE-LOW']);
  });

  it("reports first/last seen within the scan's own project, never another project's scans", () => {
    const { scans, cves } = fresh();
    scan(scans, 'p1-old', '/p1');
    scan(scans, 'other', '/p2');
    scan(scans, 'p1-new', '/p1');
    for (const id of ['p1-old', 'other', 'p1-new']) cves.bulkUpsert([cve(id, 'CVE-SEEN')]);

    const [latest] = cves.listActive('p1-new');
    expect(latest?.first_seen_scan_id).toBe('p1-old');
    expect(latest?.last_seen_scan_id).toBe('p1-new');
    const [older] = cves.listActive('p1-old');
    expect(older?.first_seen_scan_id).toBe('p1-old');
    expect(older?.last_seen_scan_id).toBe('p1-new');
    const [elsewhere] = cves.listActive('other');
    expect(elsewhere?.first_seen_scan_id).toBe('other');
    expect(elsewhere?.last_seen_scan_id).toBe('other');
  });
});

describe('the per-scan CVE migration on a database written by 2.0.0', () => {
  /** Applies the shipped migrations up to and including `version` only. */
  function databaseAtVersion(version: number): GuardianDatabase {
    const db = new GuardianDatabase(':memory:');
    for (const m of listMigrations()) {
      if (m.version > version) break;
      db.exec(readFileSync(m.filePath, 'utf8'));
    }
    db.exec(`INSERT INTO schema_meta (key, value) VALUES ('version', '${version}')`);
    return db;
  }

  it('carries legacy rows over, collapsing NULL-version duplicates, so each scan keeps its list', () => {
    const db = databaseAtVersion(3);
    for (const [id, project] of [['old-a', '/p1'], ['new-a', '/p1'], ['b', '/p2']] as const) {
      db.exec(
        `INSERT INTO scans (id, scan_type, project_path, tree_hash, started_at, status)
         VALUES ('${id}', 'deps', '${project}', 'h', '2026-01-0${id === 'old-a' ? 1 : 2}T00:00:00.000Z', 'completed')`,
      );
    }
    db.exec(`
      INSERT INTO cves VALUES ('CVE-1', 'lodash', '4.17.20', '4.17.21', 'high', 'old-a', 'new-a');
      INSERT INTO cves VALUES ('CVE-2', 'left-pad', NULL, NULL, 'low', 'new-a', 'new-a');
      INSERT INTO cves VALUES ('CVE-2', 'left-pad', NULL, NULL, 'low', 'new-a', 'new-a');
      INSERT INTO cves VALUES ('CVE-3', 'minimist', '1.2.0', NULL, 'critical', 'b', 'b');
    `);

    runMigrations(db);
    const cves = new CvesRepo(db);

    expect(cves.listActive('new-a').map((c) => c.cve_id)).toEqual(['CVE-1', 'CVE-2']);
    expect(cves.listActive('old-a').map((c) => c.cve_id)).toEqual(['CVE-1']);
    expect(cves.listActive('b').map((c) => c.cve_id)).toEqual(['CVE-3']);
    const [cve1] = cves.listActive('new-a');
    expect(cve1).toMatchObject({ installed_version: '4.17.20', fixed_version: '4.17.21', first_seen_scan_id: 'old-a' });
  });
});
