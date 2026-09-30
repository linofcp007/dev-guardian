/**
 * `dev-guardian db adopt` — since round 6, the ONLY way an existing database
 * comes to be trusted: a database from before 3.1.0, a copy of a registered
 * one, another machine's. Nothing is adopted automatically (round 6 of the
 * 3.0 review defeated every rule that tried), so this is the upgrade path
 * from 3.0.0 as well.
 *
 * It prints what the database holds — first what to weigh (suppressions
 * with no project, which apply to every project; scans dated in the future),
 * then projects, scans, dates, and every project path its rows are filed
 * under with where each leads now — and registers it only with `--yes`.
 * `--rehome` also moves the rows filed under another path that leads to this
 * project (a link, macOS /var) to its canonical path, so `status` reads them.
 * Refused even with `--yes`: a database git tracks, one reached through a
 * link, a schema holding what the migrations never create, scans dated in
 * the future. A real subprocess against the built `mcp/dist`, as the other
 * CLI end-to-end tests run it; it is a CLI command and never an MCP tool
 * (`toolSurface.test.ts` pins the tool list).
 */

import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, symlinkSync } from 'node:fs';
import { createRequire } from 'node:module';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it, vi } from 'vitest';
import { canonicalPath } from '../../src/platform/projectPath.js';
import { expectedSchema, openDatabase, resolveFallbackDbPath } from '../../src/storage/db.js';
import { PROJECT_KEYED_TABLES } from '../../src/storage/dbProvenance.js';
import { listMigrations } from '../../src/storage/migrations/runner.js';
import { cleanupTempDirs, makeTempDir, rmDir } from '../helpers/tempDir.js';

const { DatabaseSync } = createRequire(import.meta.url)('node:sqlite') as typeof import('node:sqlite');

// Each case runs the CLI (and git) as real processes, several times: the
// 10 s default was measured too short in Docker (12-18 s per case).
vi.setConfig({ testTimeout: 90_000 });

const REPO_ROOT = resolve(fileURLToPath(new URL('../../..', import.meta.url)));
const CLI = resolve(REPO_ROOT, 'cli', 'dev-guardian.mjs');
const isWindows = process.platform === 'win32';

const cleanups: string[] = [];
afterAll(() => {
  for (const dir of cleanups) rmDir(dir);
  cleanupTempDirs();
});

function runCli(args: string[]): { status: number | null; stdout: string; stderr: string } {
  const r = spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    env: { ...process.env, NO_COLOR: '1' },
    timeout: 60_000,
  });
  return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

function git(cwd: string, ...args: string[]): void {
  const r = spawnSync('git', args, { cwd, encoding: 'utf8' });
  if (r.status !== 0) throw new Error(`git ${args.join(' ')}: ${r.stderr}`);
}

function project(): string {
  const dir = makeTempDir('guardian-db-adopt-');
  cleanups.push(resolveFallbackDbPath(dir).replace(/[\\/]guardian\.db$/, ''));
  return dir;
}

/** A 3.0.0-shaped database (every migration, no id) holding `extra`. */
function legacyDatabase(dir: string, extra: string): string {
  mkdirSync(join(dir, '.guardian'), { recursive: true });
  const path = join(dir, '.guardian', 'guardian.db');
  const raw = new DatabaseSync(path);
  for (const m of listMigrations()) raw.exec(readFileSync(m.filePath, 'utf8'));
  raw.exec(extra);
  raw.close();
  return path;
}

const sql = (s: string): string => s.replace(/'/g, "''");

function scan(id: string, projectPath: string, status: string, at = new Date()): string {
  const iso = at.toISOString();
  return (
    `INSERT INTO scans (id, scan_type, project_path, tree_hash, started_at, finished_at, status, tools_run) ` +
    `VALUES ('${id}', 'sast', '${sql(projectPath)}', 'h', '${iso}', '${iso}', '${status}', '[{"name":"semgrep","status":"ok"}]');`
  );
}

function finding(scanId: string, fp: string): string {
  return (
    `INSERT INTO findings (fingerprint, scan_id, tool, rule_id, severity, category, title, fix_available, fix_applied) ` +
    `VALUES ('${fp}', '${scanId}', 'semgrep', 'r', 'critical', 'security', 'SQL injection', 0, 0);`
  );
}

function sha256(path: string): string {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

function dbIdOf(path: string): string | undefined {
  const raw = new DatabaseSync(path, { readOnly: true });
  try {
    return (raw.prepare(`SELECT value FROM schema_meta WHERE key = 'db_id'`).get() as { value: string } | undefined)
      ?.value;
  } finally {
    raw.close();
  }
}

function projectPathsIn(path: string): string[] {
  const raw = new DatabaseSync(path, { readOnly: true });
  try {
    return (raw.prepare('SELECT DISTINCT project_path AS p FROM scans ORDER BY p').all() as Array<{ p: string }>).map((r) => r.p);
  } finally {
    raw.close();
  }
}

describe('dev-guardian db adopt', () => {
  it('the upgrade from 3.0.0: the warning names the command; it shows, registers only with --yes, and the server then uses it', () => {
    const dir = project();
    git(dir, 'init', '-q');
    const primary = legacyDatabase(
      dir,
      `${scan('a', canonicalPath(dir), 'completed')}
       INSERT INTO suppressions (finding_fingerprint, reason, created_at, project_path) VALUES
         ('fp-1', 'accepted', '2026-01-01T00:00:00.000Z', NULL),
         ('fp-2', 'accepted', '2026-01-01T00:00:00.000Z', NULL),
         ('fp-3', 'accepted', '2026-01-01T00:00:00.000Z', '${sql(canonicalPath(dir))}');`,
    );

    const before = openDatabase({ projectPath: dir });
    try {
      expect(before.path).toBe(resolveFallbackDbPath(dir));
      expect(before.warning).toMatch(/created before dev-guardian 3\.1\.0 and is not trusted automatically/);
      expect(before.warning).toContain(`db adopt --project "${dir}" --yes`);
    } finally {
      before.db.close();
    }
    const untouched = sha256(primary);

    const shown = runCli(['db', 'adopt', '--project', dir]);
    expect(shown.stderr).toBe('');
    expect(shown.status).toBe(0);
    // What to weigh comes first, flagged.
    expect(shown.stdout.split('\n')[0]).toMatch(/^!! 2 suppression\(s\) have no project: they apply to EVERY project/);
    expect(shown.stdout).toContain(`Database      ${primary}`);
    expect(shown.stdout).toMatch(/Status\s+not used: created before dev-guardian 3\.1\.0/);
    expect(shown.stdout).toMatch(/Scans\s+1 \(1 completed\)/);
    expect(shown.stdout).toMatch(/Suppressions\s+3, of which 2 have no project and apply to EVERY project/);
    expect(shown.stdout).toMatch(/Not registered\. .*--yes yourself/);
    expect(sha256(primary)).toBe(untouched);
    expect(dbIdOf(primary)).toBeUndefined();

    const adopted = runCli(['db', 'adopt', '--project', dir, '--yes']);
    expect(adopted.stderr).toBe('');
    expect(adopted.status).toBe(0);
    expect(adopted.stdout).toMatch(/Registered '.*' as this user's database \(id [0-9a-f]{32}\)/);

    const after = openDatabase({ projectPath: dir });
    try {
      expect(after.path).toBe(primary);
      expect(after.warning).toBeUndefined();
    } finally {
      after.db.close();
    }
    const again = runCli(['db', 'adopt', '--project', dir, '--yes']);
    expect(again.status).toBe(0);
    expect(again.stdout).toMatch(/Already registered: nothing to do/);
  });

  it('--rehome: scans filed under a link to the project are moved to its canonical path, and status reads them', () => {
    const dir = project();
    const link = `${dir}-link`;
    symlinkSync(dir, link, isWindows ? 'junction' : 'dir');
    cleanups.push(link);
    const other = project();
    const unc = isWindows ? '\\\\192.0.2.10\\share\\proj' : '//192.0.2.10/share/proj';
    const primary = legacyDatabase(
      dir,
      `${scan('mine', link, 'completed')} ${finding('mine', 'fp-mine')}
       ${scan('theirs', canonicalPath(other), 'completed')}
       ${scan('share', unc, 'completed')}
       INSERT INTO suppressions (finding_fingerprint, reason, created_at, project_path) VALUES
         ('fp-x', 'accepted', '2026-01-01T00:00:00.000Z', '${sql(link)}');`,
    );

    // Before: "No scan yet" — the scans are filed under the link.
    runCli(['db', 'adopt', '--project', dir, '--yes']);
    expect(runCli(['status', '--project', dir]).stdout).toMatch(/No scan yet|no scan/i);

    const started = performance.now();
    const shown = runCli(['db', 'adopt', '--project', dir, '--rehome']);
    // The network path is listed, never looked up.
    expect(performance.now() - started).toBeLessThan(20_000);
    expect(shown.status).toBe(0);
    expect(shown.stdout).toContain(`this project is ${canonicalPath(dir)}`);
    expect(shown.stdout).toMatch(new RegExp(`${escape(link)}\\n\\s+2 row\\(s\\): leads to this project: --rehome moves`));
    expect(shown.stdout).toMatch(new RegExp(`${escape(canonicalPath(other))}\\n\\s+1 row\\(s\\): another directory: never touched`));
    expect(shown.stdout).toMatch(new RegExp(`${escape(unc)}\\n\\s+1 row\\(s\\): not looked at`));
    expect(shown.stdout).toContain(`--rehome would move 2 row(s) under 1 path(s) to ${canonicalPath(dir)}, and nothing else.`);
    expect(shown.stdout).toMatch(/Nothing changed: add --yes to --rehome/);
    expect(projectPathsIn(primary)).toContain(link);

    const moved = runCli(['db', 'adopt', '--project', dir, '--yes', '--rehome']);
    expect(moved.stderr).toBe('');
    expect(moved.status).toBe(0);
    expect(moved.stdout).toMatch(/Rehomed 2 row\(s\) from 1 path\(s\)/);
    // Only this project's rows moved; another project's and the share's did not.
    expect(projectPathsIn(primary).sort()).toEqual([canonicalPath(dir), canonicalPath(other), unc].sort());

    const status = runCli(['status', '--project', dir]);
    expect(status.status).toBe(0);
    expect(status.stdout).not.toMatch(/No scan yet/i);
    expect(status.stdout).toMatch(/OPEN\s+1 crit/);
  });

  it('scans dated in the future: flagged first, and refused even with --yes — no override', () => {
    const dir = project();
    const primary = legacyDatabase(
      dir,
      `${scan('real', canonicalPath(dir), 'completed')}
       ${scan('ahead', canonicalPath(dir), 'completed', new Date(Date.now() + 2 * 86_400_000))}`,
    );
    const r = runCli(['db', 'adopt', '--project', dir, '--yes']);
    expect(r.status).toBe(1);
    expect(r.stdout.split('\n')[0]).toMatch(/^!! 1 scan\(s\) are dated in the future \(the furthest: /);
    expect(r.stdout).toMatch(/It cannot be registered:\n {2}- 1 scan\(s\) are dated in the future/);
    expect(r.stdout).toMatch(/will not register a database that holds any/);
    expect(dbIdOf(primary)).toBeUndefined();
  });

  it('a database git tracks cannot be registered, even with --yes', () => {
    const dir = project();
    git(dir, 'init', '-q');
    const primary = legacyDatabase(dir, scan('a', canonicalPath(dir), 'completed'));
    git(dir, 'add', '-f', '.guardian/guardian.db');
    const r = runCli(['db', 'adopt', '--project', dir, '--yes']);
    expect(r.status).toBe(1);
    expect(r.stdout).toMatch(/It cannot be registered:\n {2}- git tracks \.guardian\/guardian\.db/);
    expect(dbIdOf(primary)).toBeUndefined();
  });

  it('a database whose schema holds a trigger cannot be registered', () => {
    const dir = project();
    const primary = legacyDatabase(
      dir,
      `CREATE TRIGGER hide AFTER INSERT ON findings BEGIN DELETE FROM findings WHERE rowid = NEW.rowid; END;`,
    );
    const r = runCli(['db', 'adopt', '--project', dir, '--yes']);
    expect(r.status).toBe(1);
    expect(r.stdout).toMatch(/its schema holds what dev-guardian's migrations never create \(trigger hide/);
    expect(dbIdOf(primary)).toBeUndefined();
  });

  it('no database: exit 1; an unknown subcommand or flag: a usage error', () => {
    const dir = project();
    const none = runCli(['db', 'adopt', '--project', dir]);
    expect(none.status).toBe(1);
    expect(none.stderr).toMatch(/there is no database at/);
    expect(runCli(['db']).status).toBe(3);
    expect(runCli(['db', 'trust']).status).toBe(3);
    expect(runCli(['db', 'adopt', '--project', dir, '--force']).status).toBe(3);
  });

  it('--rehome covers every table that keys rows by project', () => {
    const keyed = [...expectedSchema().columns.entries()]
      .filter(([, cols]) => cols.has('project_path'))
      .map(([table]) => table)
      .sort();
    expect([...PROJECT_KEYED_TABLES].sort()).toEqual(keyed);
  });
});

function escape(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
