/**
 * A `.guardian/guardian.db` is data the project brought, not something
 * dev-guardian can take on faith.
 *
 * The self-security review reproduced it: a committed database carrying
 * `AFTER INSERT ON findings BEGIN DELETE FROM findings WHERE rowid =
 * NEW.rowid; END` (and the same on scan_cves) took a project from risk 55 to
 * 8 and from 7 open findings to 0 at coverage `full`, in risk_score, every
 * report, the open set and create_fix_pr — the server opens
 * `<cwd>/.guardian/guardian.db` at startup, whatever it holds.
 *
 * So a database git tracks is refused, and so is one holding any schema
 * object the migrations never create; a refused database gives way to the
 * per-user fallback, with a warning that says why. The fallback itself moved
 * out of the shared temp directory, where its path was predictable
 * (`tmpdir()/dev-guardian/<sha1(path)>`) and nothing checked who made it.
 */

import { spawnSync } from 'node:child_process';
import { lstatSync, mkdirSync, readFileSync, symlinkSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { homedir, tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { afterAll, afterEach, describe, expect, it, vi } from 'vitest';
import {
  GuardianDbError,
  openDatabase,
  openDatabaseAtPath,
  resolveFallbackDbPath,
  userDataDir,
} from '../../../src/storage/db.js';
import { gitTracksDatabase } from '../../../src/storage/dbTrust.js';
import { Storage } from '../../../src/storage/index.js';
import { listMigrations } from '../../../src/storage/migrations/runner.js';
import { cleanupTempDirs, makeTempDir, rmDir } from '../../helpers/tempDir.js';

const { DatabaseSync } = createRequire(import.meta.url)('node:sqlite') as typeof import('node:sqlite');

// Every open of an existing project database asks git (a process spawn, up
// to 3 s by design) and most tests here make several; on a loaded machine
// the 10 s unit default was measured too short (a Docker run beside the
// full Windows suite).
vi.setConfig({ testTimeout: 30_000 });

const undo: Array<() => void> = [];
afterEach(() => {
  vi.unstubAllEnvs();
  for (const fn of undo.splice(0).reverse()) {
    try {
      fn();
    } catch {
      /* best-effort cleanup */
    }
  }
});
afterAll(cleanupTempDirs);

const isWindows = process.platform === 'win32';

function project(): string {
  const dir = makeTempDir('guardian-trust-');
  undo.push(() => rmDir(dirname(resolveFallbackDbPath(dir))));
  return dir;
}

function primaryOf(dir: string): string {
  return join(dir, '.guardian', 'guardian.db');
}

/** A primary database that opens and migrates normally, then closes. */
function existingDatabase(dir: string): string {
  const { db, path } = openDatabase({ projectPath: dir });
  db.close();
  return path;
}

/** Runs `sql` on `path` through a raw connection — the way a hostile file is made. */
function tamper(path: string, sql: string): void {
  const raw = new DatabaseSync(path);
  try {
    raw.exec(sql);
  } finally {
    raw.close();
  }
}

function git(cwd: string, ...args: string[]): void {
  const r = spawnSync('git', args, { cwd, encoding: 'utf8' });
  if (r.status !== 0) throw new Error(`git ${args.join(' ')}: ${r.stderr}`);
}

/** Stores one scan with one finding through the storage layer, returns what reads back. */
function storeAndReadBack(storage: Storage, projectPath: string): number {
  storage.scans.insert({ scan_id: 's1', scan_type: 'sast', project_path: projectPath, tree_hash: 'h' });
  storage.findings.bulkInsert([
    {
      scan_id: 's1',
      fingerprint: 'fp-1',
      tool: 'semgrep',
      rule_id: 'r',
      severity: 'critical',
      category: 'security',
      title: 'SQL injection',
      fix_available: false,
      fix_applied: false,
    },
  ]);
  storage.scans.finalize({ scan_id: 's1', status: 'completed', tools_run: [], missing_tools: [] });
  return storage.findings.listByScan('s1').length;
}

const HIDE_FINDINGS = `
  CREATE TRIGGER hide_findings AFTER INSERT ON findings
  BEGIN DELETE FROM findings WHERE rowid = NEW.rowid; END;
`;

describe('a database holding objects the migrations never create', () => {
  it('is refused: a trigger that deletes every finding no longer hides them', () => {
    const dir = project();
    const primary = existingDatabase(dir);
    tamper(primary, HIDE_FINDINGS);

    const opened = openDatabase({ projectPath: dir });
    try {
      expect(opened.path).toBe(resolveFallbackDbPath(dir));
      expect(opened.warning).toContain('trigger hide_findings');
      expect(opened.warning).toContain(primary);
      expect(storeAndReadBack(new Storage(opened.db), dir)).toBe(1);
    } finally {
      opened.db.close();
    }
  });

  it('is refused: a CHECK constraint that INSERT OR IGNORE would silently obey', () => {
    // Every repo inserts with INSERT OR IGNORE, which skips a row that
    // violates a CHECK — the same hiding as the trigger, under the table's
    // own name and type.
    const dir = project();
    const primary = existingDatabase(dir);
    const raw = new DatabaseSync(primary);
    const row = raw.prepare(`SELECT sql FROM sqlite_master WHERE name = 'findings'`).get() as { sql: string };
    const hostile = row.sql.replace(/\)\s*$/, `, CHECK (severity <> 'critical'))`);
    raw.exec(`DROP TABLE findings; ${hostile};`);
    raw.close();

    const opened = openDatabase({ projectPath: dir });
    try {
      expect(opened.path).toBe(resolveFallbackDbPath(dir));
      expect(opened.warning).toMatch(/table findings: check\(severity <> 'critical'\)/);
      expect(storeAndReadBack(new Storage(opened.db), dir)).toBe(1);
    } finally {
      opened.db.close();
    }
  });

  it('is refused: a view, an unknown table, a known index redefined as UNIQUE', () => {
    const dir = project();
    const primary = existingDatabase(dir);
    tamper(
      primary,
      `CREATE VIEW open_findings AS SELECT * FROM findings WHERE 0;
       CREATE TABLE extra (x TEXT);
       DROP INDEX idx_findings_scan_id;
       CREATE UNIQUE INDEX idx_findings_scan_id ON findings(scan_id);`,
    );

    const opened = openDatabase({ projectPath: dir });
    try {
      expect(opened.path).toBe(resolveFallbackDbPath(dir));
      expect(opened.warning).toContain('view open_findings');
      expect(opened.warning).toContain('table extra');
      expect(opened.warning).toContain('index idx_findings_scan_id');
    } finally {
      opened.db.close();
    }
  });

  it('trusts a database 3.0.0 migrated, file by file, and a 2.0.0 one', () => {
    // The definitions a legacy database holds were written by exec'ing each
    // file whole (comments inside CREATE TABLE included) and by ALTER TABLE
    // appending columns in whatever order the migrations ran.
    for (const upTo of [3, 14]) {
      const dir = project();
      const primary = primaryOf(dir);
      mkdirSync(dirname(primary), { recursive: true });
      const raw = new DatabaseSync(primary);
      for (const m of listMigrations().filter((x) => x.version <= upTo)) raw.exec(readFileSync(m.filePath, 'utf8'));
      raw.exec(`INSERT INTO schema_meta(key, value) VALUES('version', '${upTo}')`);
      raw.close();

      const opened = openDatabase({ projectPath: dir });
      try {
        expect(opened.path, `version ${upTo}`).toBe(primary);
        expect(opened.warning, `version ${upTo}`).toBeUndefined();
      } finally {
        opened.db.close();
      }
    }
  });

  it('trusts a 3.0 development database whose migrations ran out of order', () => {
    // 014 before 013: findings' columns were appended in the other order.
    const dir = project();
    const primary = primaryOf(dir);
    mkdirSync(dirname(primary), { recursive: true });
    const raw = new DatabaseSync(primary);
    const all = listMigrations();
    for (const m of [...all.filter((x) => x.version <= 12), ...all.filter((x) => x.version === 14 || x.version === 13)]) {
      raw.exec(readFileSync(m.filePath, 'utf8'));
    }
    raw.exec(`INSERT INTO schema_meta(key, value) VALUES('version', '14')`);
    raw.close();

    const opened = openDatabase({ projectPath: dir });
    try {
      expect(opened.path).toBe(primary);
      expect(opened.warning).toBeUndefined();
    } finally {
      opened.db.close();
    }
  });

  it('the per-user fallback itself is refused with an error naming it, not used', () => {
    const dir = project();
    const fallback = resolveFallbackDbPath(dir);
    openDatabaseAtPath(ensureParent(fallback)).close();
    tamper(fallback, HIDE_FINDINGS);
    expect(() => openDatabaseAtPath(fallback)).toThrow(GuardianDbError);
    expect(() => openDatabaseAtPath(fallback)).toThrow(/trigger hide_findings/);
  });
});

describe('a database a newer build migrated (downgrade)', () => {
  // 3.0.0 served a database a later build had migrated (the review measured
  // 2.0.0 serving a v14 one), and a downgrade must keep doing so — without
  // reopening the hiding attack. A later build's migrations can only ADD:
  // tables, columns, indexes. What cannot hide a row is accepted; what can
  // (a trigger, a view, a UNIQUE index or constraint on a table this build
  // writes, a CHECK, a NOT NULL a default does not satisfy) is refused
  // whatever schema_migrations says.
  function futureDatabase(extra = ''): { dir: string; primary: string } {
    const dir = project();
    const primary = existingDatabase(dir);
    tamper(
      primary,
      `INSERT INTO schema_migrations (version, name, applied_at) VALUES (999, 'from_the_future', '2027-01-01T00:00:00.000Z');
       UPDATE schema_meta SET value = '999' WHERE key = 'version';
       CREATE TABLE future_things (id INTEGER PRIMARY KEY, label TEXT NOT NULL, UNIQUE (label));
       CREATE UNIQUE INDEX idx_future_things_label ON future_things(label);
       ALTER TABLE findings ADD COLUMN future_note TEXT;
       ALTER TABLE findings ADD COLUMN future_flag INTEGER NOT NULL DEFAULT 0;
       CREATE INDEX idx_findings_future_note ON findings(future_note);
       ${extra}`,
    );
    return { dir, primary };
  }

  it('is accepted: an unknown table, extra columns and a non-unique index — and findings read back', () => {
    const { dir, primary } = futureDatabase();
    const opened = openDatabase({ projectPath: dir });
    try {
      expect(opened.path).toBe(primary);
      expect(opened.warning).toBeUndefined();
      expect(storeAndReadBack(new Storage(opened.db), dir)).toBe(1);
    } finally {
      opened.db.close();
    }
  });

  it.each([
    ['a UNIQUE index on findings', 'CREATE UNIQUE INDEX idx_findings_one_per_scan ON findings(scan_id);', /index idx_findings_one_per_scan: a UNIQUE index on findings/],
    ['a trigger', HIDE_FINDINGS, /trigger hide_findings/],
    ['a view', 'CREATE VIEW recent AS SELECT * FROM findings;', /view recent/],
  ])('is refused with %s, whatever schema_migrations says', (_what, sql, expected) => {
    const { dir } = futureDatabase(sql);
    const opened = openDatabase({ projectPath: dir });
    try {
      expect(opened.path).toBe(resolveFallbackDbPath(dir));
      expect(opened.warning).toMatch(expected);
      expect(opened.warning).toMatch(/newer dev-guardian/);
      expect(storeAndReadBack(new Storage(opened.db), dir)).toBe(1);
    } finally {
      opened.db.close();
    }
  });

  // A table constraint goes after the columns; a column before them (a fresh
  // CREATE TABLE accepts no column after a table constraint).
  it.each([
    ['a UNIQUE table constraint', { constraint: 'UNIQUE (scan_id)' }, /table findings: unique\(scan_id\)/],
    ['a CHECK constraint', { constraint: "CHECK (severity <> 'critical')" }, /table findings: check\(severity <> 'critical'\)/],
    ['a column NOT NULL with no default (INSERT OR IGNORE skips every row)', { column: 'gate TEXT NOT NULL' }, /table findings: gate text not null/],
    ['a column NOT NULL DEFAULT NULL', { column: 'gate TEXT NOT NULL DEFAULT NULL' }, /table findings: gate text not null default null/],
    ['a UNIQUE column', { column: 'token TEXT UNIQUE' }, /table findings: token text unique/],
    ['a changed known column', {}, /table findings: severity text not null check/],
  ])('is refused with %s on a known table', (what, add: { constraint?: string; column?: string }, expected) => {
    const { dir, primary } = futureDatabase();
    const raw = new DatabaseSync(primary);
    const row = raw.prepare(`SELECT sql FROM sqlite_master WHERE name = 'findings'`).get() as { sql: string };
    let hostile = row.sql;
    if (add.constraint !== undefined) hostile = hostile.replace(/\)\s*$/, `, ${add.constraint})`);
    if (add.column !== undefined) hostile = hostile.replace('(', `(${add.column}, `);
    if (what === 'a changed known column') {
      hostile = hostile.replace(/severity\s+TEXT NOT NULL/, "severity TEXT NOT NULL CHECK (severity <> 'critical')");
    }
    raw.exec(`DROP TABLE findings; ${hostile};`);
    raw.close();

    const opened = openDatabase({ projectPath: dir });
    try {
      expect(opened.path).toBe(resolveFallbackDbPath(dir));
      expect(opened.warning).toMatch(expected);
    } finally {
      opened.db.close();
    }
  });

  it('without a newer schema_migrations entry, an unknown table is still refused', () => {
    const dir = project();
    const primary = existingDatabase(dir);
    tamper(primary, 'CREATE TABLE future_things (id INTEGER PRIMARY KEY);');
    const opened = openDatabase({ projectPath: dir });
    try {
      expect(opened.path).toBe(resolveFallbackDbPath(dir));
      expect(opened.warning).toContain('table future_things');
    } finally {
      opened.db.close();
    }
  });
});

function ensureParent(path: string): string {
  mkdirSync(dirname(path), { recursive: true });
  return path;
}

describe('a database git tracks', () => {
  it('is refused, and the per-user fallback is used with a warning saying why', () => {
    const dir = project();
    git(dir, 'init', '-q');
    const primary = existingDatabase(dir);
    git(dir, 'add', '-f', '.guardian/guardian.db');

    const opened = openDatabase({ projectPath: dir });
    try {
      expect(opened.path).toBe(resolveFallbackDbPath(dir));
      expect(opened.warning).toContain(primary);
      expect(opened.warning).toMatch(/tracked by git/);
    } finally {
      opened.db.close();
    }
  });

  it('is refused when only its WAL is tracked', () => {
    const dir = project();
    git(dir, 'init', '-q');
    existingDatabase(dir);
    writeFileSync(join(dir, '.guardian', 'guardian.db-wal'), '');
    git(dir, 'add', '-f', '.guardian/guardian.db-wal');
    expect(gitTracksDatabase(dir).state).toBe('tracked');
  });

  it('an untracked database in a git repository is used as before, with no warning', () => {
    const dir = project();
    git(dir, 'init', '-q');
    const primary = existingDatabase(dir);
    const opened = openDatabase({ projectPath: dir });
    try {
      expect(opened.path).toBe(primary);
      expect(opened.warning).toBeUndefined();
    } finally {
      opened.db.close();
    }
  });
});

describe('when git cannot answer', () => {
  const NO_GIT = { git: join(tmpdir(), 'no-such-git-binary-for-dev-guardian') };

  it('outside any repository: untracked, since nothing can be tracked — and nothing to warn about', () => {
    const dir = project();
    const verdict = gitTracksDatabase(dir, NO_GIT);
    expect(verdict.state).toBe('untracked');
    expect(verdict.inferred).toBe(true);

    // A machine with no git and a project with no .git: there is nothing to
    // ask, so no warning on every start.
    const primary = existingDatabase(dir);
    vi.stubEnv('PATH', '');
    const opened = openDatabase({ projectPath: dir });
    try {
      expect(opened.path).toBe(primary);
      expect(opened.warning).toBeUndefined();
    } finally {
      opened.db.close();
    }
  });

  it('reads the index: a database it lists is tracked', () => {
    const dir = project();
    git(dir, 'init', '-q');
    existingDatabase(dir);
    git(dir, 'add', '-f', '.guardian/guardian.db');
    const verdict = gitTracksDatabase(dir, NO_GIT);
    expect(verdict.state).toBe('tracked');
  });

  it('reads the index: a database it does not list is untracked, inferred (used with a warning)', () => {
    const dir = project();
    git(dir, 'init', '-q');
    writeFileSync(join(dir, 'a.txt'), 'a');
    git(dir, 'add', 'a.txt');
    existingDatabase(dir);
    const verdict = gitTracksDatabase(dir, NO_GIT);
    expect(verdict.state).toBe('untracked');
    expect(verdict.inferred).toBe(true);

    // Through openDatabase, with no git on PATH at all.
    vi.stubEnv('PATH', '');
    const opened = openDatabase({ projectPath: dir });
    try {
      expect(opened.path).toBe(primaryOf(dir));
      expect(opened.warning).toMatch(/could not ask git/);
    } finally {
      opened.db.close();
    }
  });

  it('an index it cannot read is "cannot tell", and the database is refused', () => {
    const dir = project();
    mkdirSync(join(dir, '.git'));
    writeFileSync(join(dir, '.git', 'index'), 'not an index');
    existingDatabase(dir);
    expect(gitTracksDatabase(dir, NO_GIT).state).toBe('unknown');

    vi.stubEnv('PATH', '');
    const opened = openDatabase({ projectPath: dir });
    try {
      expect(opened.path).toBe(resolveFallbackDbPath(dir));
      expect(opened.warning).toMatch(/could not confirm/);
    } finally {
      opened.db.close();
    }
  });
});

/** A project whose database git tracks — the simplest way to reach the fallback. */
function trackedProject(): string {
  const dir = project();
  git(dir, 'init', '-q');
  existingDatabase(dir);
  git(dir, 'add', '-f', '.guardian/guardian.db');
  return dir;
}

describe('connection pragmas', () => {
  it('opens with trusted_schema OFF, cell_size_check ON and no memory map', () => {
    const dir = project();
    const opened = openDatabase({ projectPath: dir });
    try {
      const read = (pragma: string): unknown =>
        Object.values(opened.db.prepare<[], Record<string, unknown>>(`PRAGMA ${pragma}`).get() ?? {})[0];
      expect(read('trusted_schema')).toBe(0);
      expect(read('cell_size_check')).toBe(1);
      expect(read('mmap_size')).toBe(0);
    } finally {
      opened.db.close();
    }
  });
});

describe('the per-user fallback location', () => {
  it('is in the user data directory, never the shared temp directory', () => {
    vi.stubEnv('GUARDIAN_DATA_DIR', '');
    const base = makeTempDir('guardian-userdata-');
    if (isWindows) vi.stubEnv('LOCALAPPDATA', base);
    else vi.stubEnv('XDG_DATA_HOME', base);
    expect(userDataDir()).toBe(join(base, 'dev-guardian'));
    const path = resolveFallbackDbPath('/some/project');
    expect(path.startsWith(join(base, 'dev-guardian'))).toBe(true);
    expect(path.startsWith(join(tmpdir(), 'dev-guardian'))).toBe(false);
  });

  it.runIf(!isWindows)('defaults to ~/.local/share/dev-guardian without XDG_DATA_HOME', () => {
    vi.stubEnv('GUARDIAN_DATA_DIR', '');
    vi.stubEnv('XDG_DATA_HOME', '');
    expect(userDataDir()).toBe(join(homedir(), '.local', 'share', 'dev-guardian'));
  });

  it.runIf(isWindows)('defaults to %LOCALAPPDATA%\\dev-guardian', () => {
    vi.stubEnv('GUARDIAN_DATA_DIR', '');
    const local = process.env['LOCALAPPDATA'] ?? join(homedir(), 'AppData', 'Local');
    expect(userDataDir()).toBe(join(local, 'dev-guardian'));
  });

  it.runIf(!isWindows)('creates its directories 0700', () => {
    const base = makeTempDir('guardian-userdata-');
    vi.stubEnv('GUARDIAN_DATA_DIR', join(base, 'dg'));
    const dir = trackedProject();
    const opened = openDatabase({ projectPath: dir });
    try {
      expect(opened.path.startsWith(join(base, 'dg'))).toBe(true);
      expect(lstatSync(join(base, 'dg')).mode & 0o777).toBe(0o700);
      expect(lstatSync(dirname(opened.path)).mode & 0o777).toBe(0o700);
    } finally {
      opened.db.close();
    }
  });

  it.runIf(!isWindows)("refuses a project directory under it that is a symbolic link (someone else's file)", () => {
    const base = makeTempDir('guardian-userdata-');
    vi.stubEnv('GUARDIAN_DATA_DIR', join(base, 'dg'));
    const dir = trackedProject();
    const elsewhere = join(base, 'elsewhere');
    mkdirSync(elsewhere);
    mkdirSync(join(base, 'dg'), { recursive: true });
    symlinkSync(elsewhere, dirname(resolveFallbackDbPath(dir)));
    expect(() => openDatabase({ projectPath: dir })).toThrow(GuardianDbError);
    expect(() => openDatabase({ projectPath: dir })).toThrow(/symbolic link|not a directory/);
  });
});

describe('a corrupt database file', () => {
  it('fails with one line naming the file and telling the user to move it aside', () => {
    const dir = project();
    const primary = primaryOf(dir);
    mkdirSync(dirname(primary), { recursive: true });
    writeFileSync(primary, 'this is not a SQLite database, just some bytes '.repeat(200));

    let caught: unknown;
    try {
      openDatabase({ projectPath: dir }).db.close();
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(GuardianDbError);
    const message = caught instanceof Error ? caught.message : '';
    expect(message).toContain(primary);
    expect(message).toMatch(/move it aside/i);
  });
});
