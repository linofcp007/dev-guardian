/**
 * `dev-guardian db adopt` — the way back for a legitimate database the
 * adoption rules cannot tell from a copy.
 *
 * Round 5: a legacy database whose scans are filed under a link to the
 * project (macOS `/var` -> `/private/var`, `~/lnk`), or that holds only
 * failed scans, is foreign for good, and the warning's only advice was to
 * delete it. `db adopt` prints what it holds and registers it only with
 * `--yes`; the checks every trusted database must pass (no link, not tracked
 * by git, a clean schema) still apply. A real subprocess against the built
 * `mcp/dist`, as the other CLI end-to-end tests run it. It is a CLI command
 * and never an MCP tool: `toolSurface.test.ts` pins the tool list.
 */

import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, symlinkSync } from 'node:fs';
import { createRequire } from 'node:module';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';
import { canonicalPath } from '../../src/platform/projectPath.js';
import { openDatabase, resolveFallbackDbPath } from '../../src/storage/db.js';
import { listMigrations } from '../../src/storage/migrations/runner.js';
import { cleanupTempDirs, makeTempDir, rmDir } from '../helpers/tempDir.js';

const { DatabaseSync } = createRequire(import.meta.url)('node:sqlite') as typeof import('node:sqlite');

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
    timeout: 30_000,
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

function scan(id: string, projectPath: string, status: string): string {
  const now = new Date().toISOString();
  return (
    `INSERT INTO scans (id, scan_type, project_path, tree_hash, started_at, finished_at, status) ` +
    `VALUES ('${id}', 'sast', '${sql(projectPath)}', 'h', '${now}', '${now}', '${status}');`
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

describe('dev-guardian db adopt', () => {
  it("a database stranded by a link: shows what it holds, registers only with --yes, and the server then uses it", () => {
    const dir = project();
    git(dir, 'init', '-q');
    const link = `${dir}-link`;
    symlinkSync(dir, link, isWindows ? 'junction' : 'dir');
    cleanups.push(link);
    const primary = legacyDatabase(
      dir,
      `${scan('a', link, 'completed')}
       ${scan('b', link, 'failed')}
       INSERT INTO suppressions (finding_fingerprint, reason, created_at, project_path) VALUES
         ('fp-1', 'accepted', '2026-01-01T00:00:00.000Z', NULL),
         ('fp-2', 'accepted', '2026-01-01T00:00:00.000Z', NULL),
         ('fp-3', 'accepted', '2026-01-01T00:00:00.000Z', '${sql(link)}');`,
    );

    // The server's warning names the way back.
    const before = openDatabase({ projectPath: dir });
    try {
      expect(before.path).toBe(resolveFallbackDbPath(dir));
      expect(before.warning).toMatch(/db adopt --project/);
    } finally {
      before.db.close();
    }
    const untouched = sha256(primary);

    const shown = runCli(['db', 'adopt', '--project', dir]);
    expect(shown.stderr).toBe('');
    expect(shown.status).toBe(0);
    expect(shown.stdout).toContain(`Database      ${primary}`);
    expect(shown.stdout).toMatch(/Status\s+not used: .*no completed scan of this project/);
    expect(shown.stdout).toMatch(/Scans\s+2 \(1 completed\)/);
    expect(shown.stdout).toContain(link);
    expect(shown.stdout).toMatch(/Suppressions\s+3, of which 2 have no project and apply to EVERY project/);
    expect(shown.stdout).toMatch(/Not registered\. .*--yes/);
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
    const again = runCli(['db', 'adopt', '--project', dir]);
    expect(again.status).toBe(0);
    expect(again.stdout).toMatch(/Already registered: nothing to do/);
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
});
