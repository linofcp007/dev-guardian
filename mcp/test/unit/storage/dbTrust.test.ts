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
import { createHash, randomBytes } from 'node:crypto';
import {
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  renameSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { createRequire } from 'node:module';
import { homedir, tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { afterAll, afterEach, describe, expect, it, vi } from 'vitest';
import {
  GuardianDbError,
  openDatabase,
  openDatabaseAtPath,
  registerProjectDatabase,
  resolveFallbackDbPath,
  userDataDir,
} from '../../../src/storage/db.js';
import { openSetForProject } from '../../../src/history/openSet.js';
import { canonicalPath } from '../../../src/platform/projectPath.js';
import { gitIndexAt } from '../../../src/storage/dbProvenance.js';
import { registerDbId, registryDir } from '../../../src/storage/dbRegistry.js';
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

  it('trusts, once registered, a database 3.0.0 migrated file by file, and a 2.0.0 one', () => {
    // The definitions a legacy database holds were written by exec'ing each
    // file whole (comments inside CREATE TABLE included) and by ALTER TABLE
    // appending columns in whatever order the migrations ran. It has no id:
    // the user registers it (`db adopt --yes`), which migrates it.
    for (const upTo of [3, 14]) {
      const dir = project();
      git(dir, 'init', '-q');
      const primary = primaryOf(dir);
      mkdirSync(dirname(primary), { recursive: true });
      const raw = new DatabaseSync(primary);
      for (const m of listMigrations().filter((x) => x.version <= upTo)) raw.exec(readFileSync(m.filePath, 'utf8'));
      raw.exec(`INSERT INTO schema_meta(key, value) VALUES('version', '${upTo}')`);
      raw.close();

      registerProjectDatabase(dir);
      const opened = openDatabase({ projectPath: dir });
      try {
        expect(opened.path, `version ${upTo}`).toBe(primary);
        expect(opened.warning, `version ${upTo}`).toBeUndefined();
      } finally {
        opened.db.close();
      }
    }
  });

  it('trusts, once registered, a 3.0 development database whose migrations ran out of order', () => {
    // 014 before 013: findings' columns were appended in the other order.
    const dir = project();
    git(dir, 'init', '-q');
    const primary = primaryOf(dir);
    mkdirSync(dirname(primary), { recursive: true });
    const raw = new DatabaseSync(primary);
    const all = listMigrations();
    for (const m of [...all.filter((x) => x.version <= 12), ...all.filter((x) => x.version === 14 || x.version === 13)]) {
      raw.exec(readFileSync(m.filePath, 'utf8'));
    }
    raw.exec(`INSERT INTO schema_meta(key, value) VALUES('version', '14')`);
    raw.close();

    registerProjectDatabase(dir);
    const opened = openDatabase({ projectPath: dir });
    try {
      expect(opened.path).toBe(primary);
      expect(opened.warning).toBeUndefined();
    } finally {
      opened.db.close();
    }
  });

  it('the per-user fallback holding one is not used: an in-memory database, and a warning naming it', () => {
    const dir = trackedProject();
    const fallback = resolveFallbackDbPath(dir);
    openDatabaseAtPath(ensureParent(fallback)).close();
    tamper(fallback, HIDE_FINDINGS);
    const opened = openDatabase({ projectPath: dir });
    try {
      expect(opened.path).toBe(':memory:');
      expect(opened.warning).toContain('trigger hide_findings');
      expect(opened.warning).toContain(fallback);
      expect(opened.warning).toMatch(/per-user database for this project: move it aside/);
    } finally {
      opened.db.close();
    }
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
    ['a column NOT NULL with no default (INSERT OR IGNORE skips every row)', { column: 'gate TEXT NOT NULL' }, /column gate is NOT NULL with no non-NULL default/],
    ['a column NOT NULL DEFAULT NULL', { column: 'gate TEXT NOT NULL DEFAULT NULL' }, /column gate is NOT NULL with no non-NULL default/],
    ['a generated column', { column: 'shadow TEXT GENERATED ALWAYS AS (title) VIRTUAL' }, /table findings: shadow text generated/],
    ['a UNIQUE column', { column: 'token TEXT UNIQUE' }, /table findings: token text unique/],
    // The re-review's bypass: a quoted TYPE name that reads like a default.
    // SQLite records notnull=1 with no default; judged on pragma_table_xinfo.
    ['a NOT NULL column whose quoted type name reads like a default', { column: "gate 'default 1' NOT NULL" }, /column gate is NOT NULL with no non-NULL default/],
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
      expect(opened.warning).toMatch(/git tracks \.guardian\/guardian\.db/);
      expect(opened.warning).toMatch(/git rm --cached/);
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
    expect(gitIndexAt(dir).tracked).toEqual(['.guardian/guardian.db-wal']);
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

/** A database as 3.0.0 wrote it — every migration, no db_id — plus `extra`. */
function legacyDatabase(dir: string, extra = ''): string {
  const primary = primaryOf(dir);
  mkdirSync(dirname(primary), { recursive: true });
  const raw = new DatabaseSync(primary);
  for (const m of listMigrations()) raw.exec(readFileSync(m.filePath, 'utf8'));
  raw.exec(`INSERT INTO schema_meta(key, value) VALUES('version', '${Math.max(...listMigrations().map((m) => m.version))}')`);
  if (extra !== '') raw.exec(extra);
  raw.close();
  return primary;
}

/** SQL for one completed scan filed under `projectPath`, finished at `finishedAt` (default: now). */
function scanOf(projectPath: string, id = 'legacy-1', finishedAt = new Date()): string {
  const started = new Date(finishedAt.getTime() - 1000).toISOString();
  return (
    `INSERT INTO scans (id, scan_type, project_path, tree_hash, started_at, finished_at, status) ` +
    `VALUES ('${id}', 'sast', '${projectPath.replace(/'/g, "''")}', 'h', '${started}', '${finishedAt.toISOString()}', 'completed');`
  );
}

function dbIdOf(path: string): string | undefined {
  const raw = new DatabaseSync(path, { readOnly: true });
  try {
    return (raw.prepare(`SELECT value FROM schema_meta WHERE key = 'db_id'`).get() as { value: string } | undefined)?.value;
  } finally {
    raw.close();
  }
}

function sha256(path: string): string {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

/** Opens `dir`: the fallback, with a warning matching `why`, and a database that works. */
function expectForeign(dir: string, why: RegExp): string {
  const opened = openDatabase({ projectPath: dir });
  try {
    expect(opened.path).toBe(resolveFallbackDbPath(dir));
    expect(opened.warning).toMatch(why);
    expect(opened.warning).toMatch(/Meanwhile this project's scans are kept in '.+' \(not merged back later\)/);
    expect(storeAndReadBack(new Storage(opened.db), dir)).toBe(1);
    return opened.warning ?? '';
  } finally {
    opened.db.close();
  }
}

describe('provenance: only a database registered for its own path is trusted', () => {
  // The re-review of round 2 reproduced open_findings 7 -> 0 with
  // storage_warning null through four routes the tracked check called
  // untracked, and through DATA alone: seven suppressions with no project
  // (NULL matches every project) in a database whose schema is exactly the
  // migrations'. The rule: trusted only when THIS user's dev-guardian
  // created it, or the user registered it (`db adopt --yes`), for the very
  // path it is opened at; anything else is foreign.

  it('a database this build creates carries a registered id and is trusted, with or without git', () => {
    const dir = project();
    const primary = existingDatabase(dir);
    const id = dbIdOf(primary) ?? '';
    expect(id).toMatch(/^[0-9a-f]{32}$/);
    expect(existsSync(join(registryDir(), `${id}.json`))).toBe(true);
    vi.stubEnv('PATH', '');
    const opened = openDatabase({ projectPath: dir });
    try {
      expect(opened.path).toBe(primary);
      expect(opened.warning).toBeUndefined();
    } finally {
      opened.db.close();
    }
  });

  it('a project reached through an alias (a link or junction above it) creates and keeps its own database', () => {
    // The first cut resolved the not-yet-created database lexically and the
    // project really, and called every such new database "outside the
    // project" — on every Windows 8.3 path and macOS /var path.
    const base = makeTempDir('guardian-alias-');
    mkdirSync(join(base, 'real', 'proj'), { recursive: true });
    symlinkSync(join(base, 'real'), join(base, 'alias'), isWindows ? 'junction' : 'dir');
    const viaAlias = join(base, 'alias', 'proj');
    undo.push(() => rmDir(dirname(resolveFallbackDbPath(viaAlias))));
    for (let i = 0; i < 2; i++) {
      const opened = openDatabase({ projectPath: viaAlias });
      try {
        expect(opened.path).toBe(primaryOf(viaAlias));
        expect(opened.warning).toBeUndefined();
      } finally {
        opened.db.close();
      }
    }
  });

  // Round 5: a registered id is trusted only where it was registered. The id
  // travels with the file, so on its own it is a bearer token: a ZIP layout
  // of a project carrying its registered database read storage_warning null
  // and 0 open findings, while the registry named another directory.
  it('a registered database copied elsewhere (an archive, a Docker COPY) is foreign, and says where it was registered', () => {
    const original = project();
    const registeredAt = canonicalPath(existingDatabase(original));
    const copy = project();
    mkdirSync(join(copy, '.guardian'));
    copyFileSync(primaryOf(original), primaryOf(copy));
    const suppressions = Array.from(
      { length: 7 },
      (_, i) => `('fp-${i}', 'hidden', '2026-01-01T00:00:00.000Z', NULL)`,
    ).join(', ');
    tamper(
      primaryOf(copy),
      `INSERT INTO suppressions (finding_fingerprint, reason, created_at, project_path) VALUES ${suppressions}`,
    );
    const warning = expectForeign(copy, /was registered at '.+', not here: it is a copy/);
    expect(warning).toContain(`registered at '${registeredAt}'`);
    const opened = openDatabase({ projectPath: copy });
    try {
      const storage = new Storage(opened.db);
      expect(openSetForProject(storage, copy).findings.map((f) => f.fingerprint)).toEqual(['fp-1']);
    } finally {
      opened.db.close();
    }
  });

  it('a registered database whose repository was moved is not trusted at the new path; the warning names the old one', () => {
    const dir = project();
    const registeredAt = canonicalPath(existingDatabase(dir));
    const moved = `${dir}-moved`;
    renameSync(dir, moved);
    undo.push(() => rmDir(moved));
    undo.push(() => rmDir(dirname(resolveFallbackDbPath(moved))));
    const warning = expectForeign(moved, /was registered at/);
    expect(warning).toContain(`registered at '${registeredAt}'`);
    expect(warning).toMatch(/db adopt --project/);
  });

  // Round 6: automatic adoption cannot be made safe. Extractors restore a
  // directory's creation time (Windows' own tar.exe with its defaults; 7-Zip
  // for an archive built with -mtc=on), and a dense series of future-dated
  // scans always has one near "now" — it was adopted, open 7 -> 0. So a
  // database from before 3.0.1 is never trusted automatically; the warning
  // is the upgrade path, and `db adopt --yes` the one way in.
  it('a database from before 3.0.1 is never adopted automatically: the warning says what to run, once', () => {
    const dir = project();
    git(dir, 'init', '-q');
    const primary = legacyDatabase(dir, scanOf(canonicalPath(dir)));
    const before = sha256(primary);
    const warning = expectForeign(dir, /was created before dev-guardian 3\.0\.1 and is not trusted automatically/);
    expect(warning).toContain(primary);
    expect(warning).toMatch(/If it is yours, run `node ".+" db adopt --project ".+" --yes` once, yourself, in a terminal/);
    expect(warning).toMatch(/an assistant must not run it for you/);
    expect(sha256(primary)).toBe(before);
    expect(dbIdOf(primary)).toBeUndefined();
  });

  it('every shape rounds 3 to 5 adopted stays foreign: no git, a linked worktree, and the future-dated series', () => {
    const plain = project();
    legacyDatabase(plain, scanOf(canonicalPath(plain)));
    expectForeign(plain, /created before dev-guardian 3\.0\.1/);

    const base = makeTempDir('guardian-worktree-');
    const main = join(base, 'main');
    mkdirSync(main);
    git(main, 'init', '-q');
    writeFileSync(join(main, 'README'), 'x');
    git(main, 'add', 'README');
    git(main, '-c', 'user.email=t@example.invalid', '-c', 'user.name=t', 'commit', '-q', '-m', 'init');
    const wt = join(base, 'wt');
    git(main, 'worktree', 'add', '-q', wt);
    undo.push(() => rmDir(dirname(resolveFallbackDbPath(wt))));
    legacyDatabase(wt, scanOf(canonicalPath(wt)));
    expectForeign(wt, /created before dev-guardian 3\.0\.1/);

    // The reviewer's series: every 9 minutes from now - 2 h to now + 2 days.
    const series = project();
    git(series, 'init', '-q');
    const now = Date.now();
    const rows: string[] = [];
    for (let t = now - 2 * 3600_000, i = 0; t <= now + 2 * 86_400_000; t += 9 * 60_000, i++) {
      rows.push(scanOf(canonicalPath(series), `planted-${i}`, new Date(t)));
    }
    // One transaction: 334 autocommitted inserts took 70 s on Docker's overlay file system.
    legacyDatabase(series, `BEGIN; ${rows.join('\n')} COMMIT;`);
    expectForeign(series, /created before dev-guardian 3\.0\.1/);
  });

  it('once the user registers it (`db adopt --yes`), it is trusted — and stays so', () => {
    const dir = project();
    git(dir, 'init', '-q');
    const primary = legacyDatabase(dir, scanOf(canonicalPath(dir)));
    const done = registerProjectDatabase(dir);
    expect(done).toMatchObject({ db_path: primary, already: false });
    expect(dbIdOf(primary)).toBe(done.db_id);
    for (let i = 0; i < 2; i++) {
      const opened = openDatabase({ projectPath: dir });
      try {
        expect(opened.path).toBe(primary);
        expect(opened.warning).toBeUndefined();
      } finally {
        opened.db.close();
      }
    }
  });

  it('data alone: suppressions with no project, in an exact-schema database, are not trusted', () => {
    const dir = project();
    const suppressions = Array.from(
      { length: 7 },
      (_, i) => `('fp-${i}', 'hidden', '2026-01-01T00:00:00.000Z', NULL)`,
    ).join(', ');
    legacyDatabase(
      dir,
      `INSERT INTO suppressions (finding_fingerprint, reason, created_at, project_path) VALUES ${suppressions};
       INSERT INTO suppressions (finding_fingerprint, reason, created_at, project_path) VALUES ('fp-1', 'hidden', '2026-01-01T00:00:00.000Z', NULL);`,
    );
    const opened = openDatabase({ projectPath: dir });
    try {
      expect(opened.path).toBe(resolveFallbackDbPath(dir));
      const storage = new Storage(opened.db);
      storeAndReadBack(storage, dir);
      expect(openSetForProject(storage, dir).findings.map((f) => f.fingerprint)).toEqual(['fp-1']);
    } finally {
      opened.db.close();
    }
  });

  it('an id this user never registered is foreign', () => {
    const dir = project();
    legacyDatabase(dir, `INSERT INTO schema_meta(key, value) VALUES('db_id', '${'ab'.repeat(16)}')`);
    expectForeign(dir, /carries a dev-guardian id this user never registered/);
  });

  it('a committed database spelled .Guardian (case-insensitive index match) is tracked', () => {
    // The index names `.Guardian/guardian.db`; the file system serves the
    // database as `.guardian/guardian.db` on Windows and macOS. `git
    // ls-files -- .guardian/guardian.db` prints nothing for it under
    // core.ignorecase — the miss the re-review reproduced.
    const dir = project();
    git(dir, 'init', '-q');
    git(dir, 'config', 'core.ignorecase', 'true');
    const primary = legacyDatabase(dir);
    const blob = spawnSync('git', ['hash-object', '-w', primary], { cwd: dir, encoding: 'utf8' }).stdout.trim();
    git(dir, 'update-index', '--add', '--cacheinfo', `100644,${blob},.Guardian/guardian.db`);
    expect(spawnSync('git', ['ls-files', '--', '.guardian/guardian.db'], { cwd: dir, encoding: 'utf8' }).stdout).toBe('');
    expectForeign(dir, /git tracks \.Guardian\/guardian\.db/);
  });

  it.runIf(isWindows)('a committed .Guardian directory, served as .guardian by NTFS, is tracked', () => {
    const dir = project();
    git(dir, 'init', '-q');
    mkdirSync(join(dir, '.Guardian'));
    const raw = new DatabaseSync(join(dir, '.Guardian', 'guardian.db'));
    for (const m of listMigrations()) raw.exec(readFileSync(m.filePath, 'utf8'));
    raw.close();
    git(dir, 'add', '-f', '.Guardian/guardian.db');
    expectForeign(dir, /git tracks \.Guardian\/guardian\.db/);
  });

  it('.guardian as a link (a junction on Windows) to a committed database elsewhere is foreign', () => {
    const dir = project();
    git(dir, 'init', '-q');
    mkdirSync(join(dir, 'data'));
    const raw = new DatabaseSync(join(dir, 'data', 'guardian.db'));
    for (const m of listMigrations()) raw.exec(readFileSync(m.filePath, 'utf8'));
    raw.close();
    git(dir, 'add', '-f', 'data/guardian.db');
    symlinkSync(join(dir, 'data'), join(dir, '.guardian'), isWindows ? 'junction' : 'dir');
    expectForeign(dir, /`\.guardian` is a link/);
  });

  it('.guardian as a submodule is foreign', () => {
    const dir = project();
    git(dir, 'init', '-q');
    legacyDatabase(dir);
    const sub = join(dir, '.guardian');
    git(sub, 'init', '-q');
    git(sub, 'add', '-f', 'guardian.db');
    git(sub, '-c', 'user.email=t@example.invalid', '-c', 'user.name=t', 'commit', '-q', '-m', 'db');
    const head = spawnSync('git', ['rev-parse', 'HEAD'], { cwd: sub, encoding: 'utf8' }).stdout.trim();
    git(dir, 'update-index', '--add', '--cacheinfo', `160000,${head},.guardian`);
    expectForeign(dir, /submodule/);
  });

  it("the ownership check runs before anything is created under GUARDIAN_DATA_DIR", () => {
    const base = makeTempDir('guardian-userdata-');
    const notADirectory = join(base, 'data-file');
    writeFileSync(notADirectory, 'x');
    vi.stubEnv('GUARDIAN_DATA_DIR', notADirectory);
    const dir = project();
    expect(() => registerDbId({ db_id: 'cd'.repeat(16), db_path: 'x', project_path: dir, created_at: 'now' })).toThrow(
      GuardianDbError,
    );
    expect(() => registerDbId({ db_id: 'cd'.repeat(16), db_path: 'x', project_path: dir, created_at: 'now' })).toThrow(
      /is not a directory/,
    );
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

  it.runIf(!isWindows)("refuses a project directory under it that is a symbolic link (someone else's file): in memory, never used", () => {
    const base = makeTempDir('guardian-userdata-');
    vi.stubEnv('GUARDIAN_DATA_DIR', join(base, 'dg'));
    const dir = trackedProject();
    const elsewhere = join(base, 'elsewhere');
    mkdirSync(elsewhere);
    mkdirSync(join(base, 'dg'), { recursive: true });
    symlinkSync(elsewhere, dirname(resolveFallbackDbPath(dir)));
    const opened = openDatabase({ projectPath: dir });
    try {
      expect(opened.path).toBe(':memory:');
      expect(opened.warning).toMatch(/history will not persist: '[^']+' is a symbolic link; set GUARDIAN_DATA_DIR/);
    } finally {
      opened.db.close();
    }
    expect(existsSync(join(elsewhere, 'guardian.db'))).toBe(false);
  });
});

// Round 5: a per-user data directory that cannot be created was FATAL — in
// Docker node:22 as uid 4242 with no passwd entry (HOME=/), `fatal: Error:
// EACCES: permission denied, mkdir '/.local/share/dev-guardian'`, where 3.0.0
// opened the project database. Never exit for it; never fall back to trusting
// the project database unregistered either: an in-memory database for the
// session, and a warning saying history will not persist and what to set.
describe('a per-user data directory that cannot be used', () => {
  /** A GUARDIAN_DATA_DIR under a regular file: mkdir fails on every platform. */
  function uncreatableDataDir(): string {
    const blocker = join(makeTempDir('guardian-blocker-'), 'not-a-directory');
    writeFileSync(blocker, 'x');
    return join(blocker, 'dev-guardian');
  }

  const NOT_PERSISTED = /history will not persist: .+; set GUARDIAN_DATA_DIR to a writable directory/;

  it('a new project runs on an in-memory database, and nothing is written to the project', () => {
    vi.stubEnv('GUARDIAN_DATA_DIR', uncreatableDataDir());
    const dir = project();
    const opened = openDatabase({ projectPath: dir });
    try {
      expect(opened.path).toBe(':memory:');
      expect(opened.warning).toMatch(NOT_PERSISTED);
      expect(opened.warning).toMatch(/cannot be created/);
      expect(storeAndReadBack(new Storage(opened.db), dir)).toBe(1);
    } finally {
      opened.db.close();
    }
    expect(existsSync(primaryOf(dir))).toBe(false);
  });

  it('a foreign project database: its refusal, then that the fallback cannot be used either', () => {
    const dir = trackedProject();
    vi.stubEnv('GUARDIAN_DATA_DIR', uncreatableDataDir());
    const opened = openDatabase({ projectPath: dir });
    try {
      expect(opened.path).toBe(':memory:');
      expect(opened.warning).toMatch(/git tracks \.guardian\/guardian\.db/);
      expect(opened.warning).toMatch(NOT_PERSISTED);
    } finally {
      opened.db.close();
    }
  });

  it('a registry that is not a directory is named, and the user is never told to delete the project database', () => {
    // It read "…and restart.. The file is left as it is; delete it or move
    // it aside…": the registry's problem, blamed on the project's file.
    const base = makeTempDir('guardian-userdata-');
    vi.stubEnv('GUARDIAN_DATA_DIR', base);
    writeFileSync(join(base, 'registry'), 'x');
    const dir = project();
    const opened = openDatabase({ projectPath: dir });
    try {
      expect(opened.path).toBe(':memory:');
      expect(opened.warning).toContain(`'${join(base, 'registry')}' is not a directory`);
      expect(opened.warning).toMatch(NOT_PERSISTED);
      expect(opened.warning).not.toMatch(/delete it|move it aside|left as it is|restart\.\./);
    } finally {
      opened.db.close();
    }
    expect(existsSync(primaryOf(dir))).toBe(false);
  });

  it.runIf(!isWindows && process.getuid?.() !== 0)("a data directory another user owns: in memory, naming the owner", () => {
    vi.stubEnv('GUARDIAN_DATA_DIR', '/');
    const dir = project();
    const opened = openDatabase({ projectPath: dir });
    try {
      expect(opened.path).toBe(':memory:');
      expect(opened.warning).toMatch(/'\/' belongs to uid 0, not to this user/);
      expect(opened.warning).toMatch(NOT_PERSISTED);
      expect(opened.warning).not.toMatch(/delete it|move it aside|left as it is/);
    } finally {
      opened.db.close();
    }
  });
});

// Round 6: a database SQLite cannot read never stops the server (it used to
// exit 1). Where it lives and whether git tracks it are asked BEFORE its
// bytes are read; one that is not the user's registered database is
// foreign, the user's own gives way to an in-memory database.
describe('a database SQLite cannot read', () => {
  const shapes: Array<[string, () => Buffer]> = [
    ['8 KB of random bytes', () => randomBytes(8 * 1024)],
    [
      'a 16-byte SQLite header, then zeros',
      () => Buffer.concat([Buffer.from('SQLite format 3\0', 'latin1'), Buffer.alloc(8 * 1024 - 16)]),
    ],
  ];

  function unreadable(dir: string, bytes: Buffer): string {
    const primary = primaryOf(dir);
    mkdirSync(dirname(primary), { recursive: true });
    writeFileSync(primary, bytes);
    return primary;
  }

  it.each(shapes)('%s, not registered: foreign — the fallback, and the file left as it is', (_label, bytes) => {
    const dir = project();
    const primary = unreadable(dir, bytes());
    const before = sha256(primary);
    const warning = expectForeign(dir, /cannot be read \(.*\) and is not a database this user registered/);
    expect(warning).toContain(primary);
    expect(sha256(primary)).toBe(before);
  });

  it.each(shapes)('%s, committed: git decides before the file is read — foreign', (_label, bytes) => {
    const dir = project();
    git(dir, 'init', '-q');
    unreadable(dir, bytes());
    git(dir, 'add', '-f', '.guardian/guardian.db');
    expectForeign(dir, /git tracks \.guardian\/guardian\.db/);
  });

  it.each(shapes)('%s, in a clone of a repository that committed it: foreign', (_label, bytes) => {
    const origin = project();
    git(origin, 'init', '-q');
    unreadable(origin, bytes());
    git(origin, 'add', '-f', '.guardian/guardian.db');
    git(origin, '-c', 'user.email=t@example.invalid', '-c', 'user.name=t', 'commit', '-q', '-m', 'db');
    const clone = `${origin}-clone`;
    git(dirname(origin), 'clone', '-q', origin, clone);
    undo.push(() => rmDir(clone));
    undo.push(() => rmDir(dirname(resolveFallbackDbPath(clone))));
    expectForeign(clone, /git tracks \.guardian\/guardian\.db/);
  });

  it.each(shapes)("%s, the user's own registered database: in memory, and the warning says to move it aside", (_label, bytes) => {
    const dir = project();
    const primary = existingDatabase(dir);
    for (const side of ['-wal', '-shm']) rmDir(`${primary}${side}`);
    writeFileSync(primary, bytes());
    const opened = openDatabase({ projectPath: dir });
    try {
      expect(opened.path).toBe(':memory:');
      expect(opened.warning).toContain(`the database '${primary}' cannot be read`);
      expect(opened.warning).toMatch(/Move it aside .* and restart/);
      expect(opened.warning).toMatch(/in-memory database: history will not persist/);
      expect(storeAndReadBack(new Storage(opened.db), dir)).toBe(1);
    } finally {
      opened.db.close();
    }
  });
});