/**
 * 2.0.0 stored a project as `resolve(input)` — `c:\Users\…` with the drive
 * letter as the host typed it. Migration 011 scoped every legacy suppression
 * to the path of the scan that reported it, i.e. to that spelling, and 3.0.0
 * stores scans under the canonical `C:\Users\…` (`platform/projectPath.ts
 * #canonicalPath`). The open set compares a suppression's project exactly
 * (`history/openSet.ts#suppressionMatcher`, `findingsRepo.ts
 * #SUPPRESSION_MATCHES_F`), so after the upgrade every such suppression
 * stopped applying, and every baseline was looked up under a spelling no new
 * scan uses. Reproduced by seeding the database with the v2.0.0 tag's own
 * storage code.
 *
 * The startup step rewrites a stored `suppressions.project_path` /
 * `baselines.project_path` to its canonical spelling when it names an
 * existing directory and differs ONLY in spelling — never through a symbolic
 * link or junction, whose target can have been repointed at a different
 * project since the row was written.
 */

import { readFileSync, symlinkSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { openSetForProject } from '../../../src/history/openSet.js';
import { canonicalPath } from '../../../src/platform/projectPath.js';
import { GuardianDatabase as Database } from '../../../src/storage/db.js';
import { Storage } from '../../../src/storage/index.js';
import { canonicalizeStoredProjectPaths } from '../../../src/storage/maintenance.js';
import { listMigrations, runMigrations } from '../../../src/storage/migrations/runner.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

const isWindows = process.platform === 'win32';

/**
 * A database as 2.0.0 left it (migrations 001–003, version 3): one completed
 * SAST scan of `storedPath` with one finding, a suppression of it (2.0.0's
 * suppressions had no project column) and a baseline on the scan. Then
 * migrated to this build, which backfills the suppression's project from
 * the scan: `storedPath`.
 */
function upgradedFrom200(storedPath: string): Database {
  const db = new Database(':memory:');
  for (const m of listMigrations().filter((x) => x.version <= 3)) db.exec(readFileSync(m.filePath, 'utf8'));
  db.exec(`INSERT INTO schema_meta(key, value) VALUES('version', '3')`);
  db.prepare(
    `INSERT INTO scans (id, scan_type, project_path, tree_hash, started_at, finished_at, status, tools_run)
     VALUES ('old', 'sast', ?, 'h', '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:01.000Z', 'completed',
             '[{"name":"semgrep","status":"ok"}]')`,
  ).run(storedPath);
  db.exec(
    `INSERT INTO findings (fingerprint, scan_id, tool, rule_id, severity, category, title, file_path, line_start)
     VALUES ('fp-1', 'old', 'semgrep', 'r', 'high', 'security', 't', 'a.js', 3)`,
  );
  db.exec(
    `INSERT INTO suppressions (finding_fingerprint, reason, created_at)
     VALUES ('fp-1', 'reviewed in 2.0.0', '2026-01-01T00:00:02.000Z')`,
  );
  db.exec(`INSERT INTO baselines (scan_id, set_at, note) VALUES ('old', '2026-01-01T00:00:03.000Z', 'v2 baseline')`);
  runMigrations(db);
  return db;
}

/** A 3.0 scan of the same project, stored under the canonical spelling, re-finding fp-1. */
function rescanCanonical(storage: Storage, canonical: string): void {
  storage.scans.insert({ scan_id: 'new', scan_type: 'sast', project_path: canonical, tree_hash: 'h2' });
  storage.findings.bulkInsert([
    {
      scan_id: 'new',
      fingerprint: 'fp-1',
      tool: 'semgrep',
      rule_id: 'r',
      severity: 'high',
      category: 'security',
      title: 't',
      file_path: 'a.js',
      line_start: 3,
      fix_available: false,
      fix_applied: false,
    },
  ]);
  storage.scans.finalize({
    scan_id: 'new',
    status: 'completed',
    tools_run: [{ name: 'semgrep', status: 'ok' }],
    missing_tools: [],
  });
}

/** The project's 2.0.0 spelling: the drive letter in lower case on Windows. */
function legacySpelling(canonical: string): string {
  return isWindows ? canonical.charAt(0).toLowerCase() + canonical.slice(1) : `${canonical}/`;
}

describe('stored project paths from 2.0.0', () => {
  it('a suppression and a baseline written under the 2.0.0 spelling apply again', () => {
    const canonical = canonicalPath(makeTempDir('guardian-spelling-'));
    const stored = legacySpelling(canonical);
    expect(stored).not.toBe(canonical);
    const db = upgradedFrom200(stored);
    const storage = new Storage(db);
    rescanCanonical(storage, canonical);

    // Before the step: the suppression lapsed, and there is no baseline.
    expect(openSetForProject(storage, canonical).findings.map((f) => f.fingerprint)).toEqual(['fp-1']);
    expect(storage.baselines.getActiveForProject(canonical)).toBeNull();

    expect(canonicalizeStoredProjectPaths(db)).toBe(2);

    expect(openSetForProject(storage, canonical).findings).toEqual([]);
    expect(storage.baselines.getActiveForProject(canonical)?.note).toBe('v2 baseline');
    expect(storage.suppressions.listAll()[0]?.project_path).toBe(canonical);
  });

  it('is idempotent: a second run rewrites nothing', () => {
    const canonical = canonicalPath(makeTempDir('guardian-spelling-'));
    const db = upgradedFrom200(legacySpelling(canonical));
    expect(canonicalizeStoredProjectPaths(db)).toBe(2);
    expect(canonicalizeStoredProjectPaths(db)).toBe(0);
  });

  it('leaves a path that no longer exists as it is', () => {
    const gone = join(canonicalPath(makeTempDir('guardian-spelling-')), 'deleted-project');
    const stored = legacySpelling(gone);
    const db = upgradedFrom200(stored);
    expect(canonicalizeStoredProjectPaths(db)).toBe(0);
    expect(db.prepare<[], { p: string }>(`SELECT project_path AS p FROM suppressions`).get()?.p).toBe(stored);
  });

  it('never follows a link: its target may be another project by now', () => {
    const base = canonicalPath(makeTempDir('guardian-spelling-'));
    const target = canonicalPath(makeTempDir('guardian-spelling-target-'));
    const link = join(base, 'current');
    symlinkSync(target, link, isWindows ? 'junction' : 'dir');
    const db = upgradedFrom200(link);
    expect(canonicalizeStoredProjectPaths(db)).toBe(0);
    expect(db.prepare<[], { p: string }>(`SELECT project_path AS p FROM baselines`).get()?.p).toBe(link);
  });

  it('never merges one project into another: an already-canonical path is untouched', () => {
    const canonical = canonicalPath(makeTempDir('guardian-spelling-'));
    const db = upgradedFrom200(canonical);
    expect(canonicalizeStoredProjectPaths(db)).toBe(0);
  });
});
