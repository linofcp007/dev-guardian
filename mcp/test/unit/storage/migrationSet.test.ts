/**
 * Applied migrations are a SET, not a high-water mark.
 *
 * 012, 013 and 014 were written on parallel branches, each of which reserved
 * its number and skipped the others'. A database used on one of those
 * branches reached `schema_meta.version` 14 without some of the others'
 * objects, and the old runner — "apply every number above the stored
 * version" — then skipped them forever: `new Storage()` prepares every
 * statement up front, so one missing table or column stopped the server (and
 * the CLI's status / dashboard) at startup. 014 was also edited in place to
 * add `findings.vuln_aliases`, so a database that ran its first cut lacks
 * that column while claiming 014. Each shape below was reproduced against
 * 3.0.0's runner: `no such table: mcp_tool_pins`, `table findings has no
 * column named cwe`, `… no column named vuln_aliases`.
 */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it, vi } from 'vitest';
import { GuardianDatabase as Database, GuardianDbError, openDatabaseAtPath } from '../../../src/storage/db.js';
import { Storage } from '../../../src/storage/index.js';
import { listMigrations, objectsOf, runMigrations, splitStatements } from '../../../src/storage/migrations/runner.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

// Two tests build file-backed databases and migrate them twice; one timed
// out at the 10 s unit default in a Docker run beside the full Windows suite.
vi.setConfig({ testTimeout: 30_000 });

const LATEST = String(Math.max(...listMigrations().map((m) => m.version)));
const ALL_VERSIONS = listMigrations().map((m) => m.version);

/** The migrations up to `upTo`, executed as SQL, minus the versions in `skip`. */
function legacyDatabase(opts: {
  upTo: number;
  skip?: number[];
  storedVersion: number;
  early014?: boolean;
  path?: string;
}): Database {
  const db = new Database(opts.path ?? ':memory:');
  for (const m of listMigrations().filter((x) => x.version <= opts.upTo)) {
    if (opts.skip?.includes(m.version)) continue;
    let sql = readFileSync(m.filePath, 'utf8');
    // 014's first cut (f2d69b3): the three suppression columns, no vuln_aliases.
    if (m.version === 14 && opts.early014 === true) {
      sql = sql.replace(/ALTER TABLE findings ADD COLUMN vuln_aliases TEXT;/, '');
    }
    db.exec(sql);
  }
  db.prepare(`INSERT INTO schema_meta(key, value) VALUES('version', ?)`).run(String(opts.storedVersion));
  return db;
}

function tableNames(db: Database): string[] {
  return db
    .prepare<[], { name: string }>(`SELECT name FROM sqlite_master WHERE type = 'table'`)
    .all()
    .map((r) => r.name);
}

function columnsOf(db: Database, table: string): string[] {
  return db
    .prepare<[], { name: string }>(`PRAGMA table_info(${table})`)
    .all()
    .map((c) => c.name);
}

function recordedVersions(db: Database): number[] {
  return db
    .prepare<[], { version: number }>(`SELECT version FROM schema_migrations ORDER BY version`)
    .all()
    .map((r) => r.version);
}

describe('3.0 development databases', () => {
  it('creates mcp_tool_pins on a version-14 database whose branch never ran 012', () => {
    const db = legacyDatabase({ upTo: 14, skip: [12, 13], storedVersion: 14 });
    db.exec(
      `INSERT INTO scans (id, scan_type, project_path, tree_hash, started_at, finished_at, status)
       VALUES ('s1', 'sast', '/p', 'h', '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:01.000Z', 'completed')`,
    );
    expect(tableNames(db)).not.toContain('mcp_tool_pins');

    runMigrations(db);

    expect(tableNames(db)).toEqual(expect.arrayContaining(['mcp_tool_pins', 'mcp_server_pins']));
    expect(columnsOf(db, 'findings')).toEqual(expect.arrayContaining(['cwe', 'owasp', 'vuln_aliases']));
    const storage = new Storage(db);
    expect(storage.scans.getById('s1')?.scan_id).toBe('s1');
    expect(storage.mcpToolPins.getServerPins('/p', 'k')).toEqual(new Map());
    expect(recordedVersions(db)).toEqual(ALL_VERSIONS);
  });

  it('adds findings.cwe / owasp on a version-14 database whose branch never ran 013', () => {
    const db = legacyDatabase({ upTo: 14, skip: [13], storedVersion: 14 });
    expect(columnsOf(db, 'findings')).not.toContain('cwe');

    runMigrations(db);

    expect(columnsOf(db, 'findings')).toEqual(expect.arrayContaining(['cwe', 'owasp']));
    expect(() => new Storage(db)).not.toThrow();
    expect(recordedVersions(db)).toEqual(ALL_VERSIONS);
  });

  it('adds findings.vuln_aliases on a database that ran 014 before it was edited in place', () => {
    const db = legacyDatabase({ upTo: 14, storedVersion: 14, early014: true });
    expect(columnsOf(db, 'findings')).not.toContain('vuln_aliases');
    expect(columnsOf(db, 'suppressions')).toContain('vex_status');

    runMigrations(db);

    // The three VEX columns already there are left alone — no "duplicate
    // column name" — and the one that is missing is added.
    expect(columnsOf(db, 'findings')).toContain('vuln_aliases');
    expect(columnsOf(db, 'suppressions').filter((c) => c.startsWith('vex_'))).toHaveLength(3);
    expect(() => new Storage(db)).not.toThrow();
    expect(recordedVersions(db)).toEqual(ALL_VERSIONS);
  });

  it('upgrades a clean 2.0.0 database (version 3) and records every migration once', () => {
    const db = legacyDatabase({ upTo: 3, storedVersion: 3 });
    db.exec(
      `INSERT INTO scans (id, scan_type, project_path, tree_hash, started_at, finished_at, status)
       VALUES ('old', 'sast', '/p', 'h', '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:01.000Z', 'completed')`,
    );
    db.exec(
      `INSERT INTO findings (fingerprint, scan_id, tool, severity, category, title, file_path, line_start)
       VALUES ('fp-1', 'old', 'semgrep', 'high', 'security', 't', 'a.js', 3)`,
    );

    runMigrations(db);

    expect(recordedVersions(db)).toEqual(ALL_VERSIONS);
    const version = db.prepare<[], { value: string }>(`SELECT value FROM schema_meta WHERE key = 'version'`).get();
    expect(version?.value).toBe(LATEST);
    expect(new Storage(db).findings.listByScan('old').map((f) => f.fingerprint)).toEqual(['fp-1']);
  });

  it('records every migration on a fresh database, and a second run applies nothing', () => {
    const db = new Database(':memory:');
    runMigrations(db);
    expect(recordedVersions(db)).toEqual(ALL_VERSIONS);
    const before = db.prepare(`SELECT version, name, applied_at FROM schema_migrations ORDER BY version`).all();
    runMigrations(db);
    expect(db.prepare(`SELECT version, name, applied_at FROM schema_migrations ORDER BY version`).all()).toEqual(
      before,
    );
  });

  it('trusts the stored version for migrations up to 011: their data steps are not re-run', () => {
    // 011's backfill is a data step. Re-running it would re-scope a
    // suppression the database deliberately left global (NULL).
    const db = legacyDatabase({ upTo: 14, storedVersion: 14 });
    db.exec(
      `INSERT INTO scans (id, scan_type, project_path, tree_hash, started_at, finished_at, status)
       VALUES ('s1', 'sast', '/p', 'h', '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:01.000Z', 'completed')`,
    );
    db.exec(
      `INSERT INTO findings (fingerprint, scan_id, tool, severity, category, title)
       VALUES ('fp-global', 's1', 'semgrep', 'high', 'security', 't')`,
    );
    db.exec(
      `INSERT INTO suppressions (finding_fingerprint, reason, created_at, project_path)
       VALUES ('fp-global', 'kept global', '2026-01-01T00:00:00.000Z', NULL)`,
    );

    runMigrations(db);

    const row = db
      .prepare<[], { project_path: string | null }>(
        `SELECT project_path FROM suppressions WHERE finding_fingerprint = 'fp-global'`,
      )
      .get();
    expect(row?.project_path).toBeNull();
    expect(recordedVersions(db)).toEqual(ALL_VERSIONS);
  });
});

describe('statement by statement', () => {
  function schemaOf(db: Database): unknown[] {
    return db.prepare(`SELECT type, name, tbl_name FROM sqlite_master ORDER BY type, name`).all();
  }

  it('builds the same schema as executing each shipped file whole', () => {
    const whole = new Database(':memory:');
    for (const m of listMigrations()) whole.exec(readFileSync(m.filePath, 'utf8'));
    const split = new Database(':memory:');
    runMigrations(split);
    const withoutBookkeeping = (rows: unknown[]): unknown[] =>
      rows.filter((r) => (r as { name: string }).name !== 'schema_migrations');
    expect(withoutBookkeeping(schemaOf(split))).toEqual(withoutBookkeeping(schemaOf(whole)));
  });

  it('every CREATE in a shipped migration says IF NOT EXISTS, so a re-run is harmless', () => {
    for (const m of listMigrations()) {
      for (const statement of splitStatements(readFileSync(m.filePath, 'utf8'), m.filePath)) {
        if (/^CREATE\b/i.test(statement)) expect(statement, m.filePath).toMatch(/^CREATE\s+(UNIQUE\s+)?(TABLE|INDEX)\s+IF\s+NOT\s+EXISTS\b/i);
      }
    }
  });

  it('no migration creates a trigger or a view — the open refuses every one, whatever schema_migrations says', () => {
    for (const m of listMigrations()) {
      const sql = readFileSync(m.filePath, 'utf8');
      // The splitter refuses a trigger outright; a view it would split fine.
      for (const statement of splitStatements(sql, m.filePath)) {
        expect(statement, m.filePath).not.toMatch(/^CREATE\s+(?:TEMP\s+|TEMPORARY\s+)?(?:TRIGGER|VIEW)\b/i);
      }
    }
    const built = new Database(':memory:');
    runMigrations(built);
    expect(
      built.prepare(`SELECT type, name FROM sqlite_master WHERE type IN ('trigger', 'view')`).all(),
    ).toEqual([]);
  });

  it('splits on semicolons outside comments, strings and quoted identifiers only', () => {
    const sql = [
      "-- a comment; with a semicolon and an apostrophe's",
      "INSERT INTO t VALUES ('a;b', 'it''s; fine');",
      '/* block; comment */ CREATE TABLE IF NOT EXISTS "x;y" (a TEXT);',
      'SELECT [c;d] FROM t',
    ].join('\n');
    expect(splitStatements(sql)).toEqual([
      "INSERT INTO t VALUES ('a;b', 'it''s; fine')",
      'CREATE TABLE IF NOT EXISTS "x;y" (a TEXT)',
      'SELECT [c;d] FROM t',
    ]);
  });

  it('refuses a trigger, whose body it cannot split', () => {
    expect(() => splitStatements('CREATE TRIGGER t AFTER INSERT ON x BEGIN DELETE FROM x; END;', 'f.sql')).toThrow(
      /f\.sql: CREATE TRIGGER/,
    );
  });

  it('reads what a probed migration creates from its own SQL', () => {
    const byVersion = new Map(listMigrations().map((m) => [m.version, m]));
    const m12 = byVersion.get(12);
    const m14 = byVersion.get(14);
    if (m12 === undefined || m14 === undefined) throw new Error('012 and 014 ship');
    expect(objectsOf(m12).tables).toEqual(['mcp_tool_pins', 'mcp_server_pins']);
    expect(objectsOf(m14).columns).toContainEqual({ table: 'findings', column: 'vuln_aliases' });
  });
});

describe('an index a development database never got', () => {
  it('is recreated at open instead of stopping the server (005 first cut)', () => {
    // 005's first cut (2532683) had no indexes on the legacy cves table or on
    // tree_cache; ae80f56 added three. A database that ran the first cut has
    // 005 recorded, so nothing re-runs it.
    const path = join(makeTempDir('guardian-index-'), 'guardian.db');
    const setup = legacyDatabase({ upTo: 14, storedVersion: 14, path });
    for (const name of ['idx_cves_first_seen_scan_id', 'idx_cves_last_seen_scan_id', 'idx_tree_cache_scan_id']) {
      setup.exec(`DROP INDEX ${name}`);
    }
    setup.close();

    const db = openDatabaseAtPath(path);
    try {
      const names = db
        .prepare<[], { name: string }>(`SELECT name FROM sqlite_master WHERE type = 'index'`)
        .all()
        .map((r) => r.name);
      expect(names).toEqual(
        expect.arrayContaining(['idx_cves_first_seen_scan_id', 'idx_cves_last_seen_scan_id', 'idx_tree_cache_scan_id']),
      );
    } finally {
      db.close();
    }
  });
});

describe('a schema the runner cannot repair', () => {
  it('names the missing object and the database file instead of a bare prepare error', () => {
    // Every migration is recorded as applied, and a column is gone anyway
    // (hand-edited, restored from a partial copy): nothing is left to run,
    // and `new Storage()` would have died on `no such column`.
    const path = join(makeTempDir('guardian-schema-'), 'guardian.db');
    const setup = new Database(path);
    runMigrations(setup);
    setup.exec('ALTER TABLE findings DROP COLUMN cwe');
    setup.close();

    let caught: unknown;
    try {
      openDatabaseAtPath(path).close();
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(GuardianDbError);
    const message = caught instanceof Error ? caught.message : '';
    expect(message).toContain(path);
    expect(message).toContain('findings.cwe');
    expect(message).not.toMatch(/\n\s+at /);
  });
});
