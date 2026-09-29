/**
 * Forward-only SQL migration runner.
 *
 * Migrations live next to this file as `NNN_name.sql`. Which of them a
 * database has applied is recorded as a SET, one row per migration, in
 * `schema_migrations` (version, name, applied_at). On startup every shipped
 * migration that is not in the set is applied, in numeric order, each in its
 * own transaction. `schema_meta.version` is still written — as the highest
 * number applied — so an older build sharing the file keeps reading what it
 * expects; it is no longer what decides what runs.
 *
 * ---- Why a set, not a high-water mark ------------------------------------
 *
 * The runner used to apply every number above `schema_meta.version`. 012,
 * 013 and 014 were then written on parallel branches, each reserving its own
 * number: a database used on one of those branches reached version 14
 * without the others' objects, and every later start skipped them — while
 * `new Storage()` prepares every statement up front, so one missing table or
 * column (`no such table: mcp_tool_pins`, `table findings has no column
 * named cwe`, `… vuln_aliases`: 014 was edited in place after it had run)
 * stopped the server and the CLI's status / dashboard at startup.
 *
 * A database that predates the set (`schema_migrations` empty, a stored
 * version above 0) is backfilled once, under the write lock: every migration
 * up to the stored version is recorded as applied — EXCEPT those in
 * {@link PROBED_ON_BACKFILL}, whose objects are looked for instead (their
 * tables, indexes and columns, read from their own SQL), and whichever is
 * missing anything stays unrecorded and runs next. Migrations up to 011
 * shipped in order on one branch, so the stored version is trusted for them:
 * 011 carries a data step (its suppression backfill) that must not run twice.
 *
 * ---- Idempotent statements ------------------------------------------------
 *
 * A probed migration can be partly applied (014's first cut added three of
 * its four columns), so every migration runs statement by statement and
 * each `ALTER TABLE … ADD COLUMN` is skipped when `PRAGMA table_info` already
 * lists the column; SQLite has no `ADD COLUMN IF NOT EXISTS`. Every `CREATE`
 * in a migration says `IF NOT EXISTS` (enforced by a test). The splitter
 * understands comments and quoted text, and refuses `CREATE TRIGGER`, whose
 * body holds semicolons of its own — no migration creates one, and a
 * database holding one is refused at open (`storage/db.ts`).
 *
 * Migrations are SQL only (no JS hooks): keep the surface area small and the
 * audit trail trivial — what you read in the .sql file is what runs. The one
 * data step SQL cannot express runs after them, in `runMigrations`:
 * re-keying stored plugin-pack findings to the rule's own id
 * (`../localRuleIds.ts` — it needs sha256 and the plugin's packs). It changes
 * values, never the schema, commits in batches, and records how far it got in
 * `schema_meta`, so every start carries on from there.
 *
 * ---- Numbering convention ------------------------------------------------
 *
 *   - `NNN` is three digits, zero-padded (`004_scan_owner.sql`); `name` is
 *     free text.
 *   - Take the next unused number. Numbers are unique — two files with the
 *     same number make {@link listMigrations} throw. Branches written in
 *     parallel that both took the same number must be renumbered when they
 *     meet; that is a merge-time job, never a runtime one.
 *   - A number that has shipped is never reused, renumbered or edited: a
 *     database that recorded it will not run the file again. Change a shipped
 *     schema with a NEW migration.
 *   - Each file is additive (new tables, new nullable/defaulted columns,
 *     backfills) so a database written by an older build keeps working, and
 *     so does an older build still sharing the file with a newer one.
 *   - Never a trigger or a view: a database holding either is refused at open
 *     whatever it records (`../schemaCheck.ts` — SQL stored in a committed
 *     database hid every finding), and a test holds every file to it.
 *   - An older build opens a database a newer one migrated only when the
 *     newer objects cannot hide a row: new tables, new non-UNIQUE indexes,
 *     and new columns an insert that does not name them always satisfies
 *     (nullable, or NOT NULL with a non-NULL DEFAULT; no CHECK, UNIQUE,
 *     REFERENCES or GENERATED). A UNIQUE index, or any such constraint, added
 *     to an EXISTING table makes every older build refuse the database and
 *     fall back to its per-user copy, with a warning that says why — add one
 *     only when that downgrade cost is worth it.
 *
 * ---- Concurrency -----------------------------------------------------------
 *
 * Several processes open one database at once (the plugin's MCP server, a
 * project-level one, the CLI). The backfill and each migration therefore run
 * inside `BEGIN IMMEDIATE` and RE-READ the set once they hold the write
 * lock: the read before taking the lock is only a fast path, and another
 * process may have done the same work in the meantime.
 */

import type { DB } from '../db.js';
import { rekeyStoredLocalRuleIds } from '../localRuleIds.js';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * Where the `NNN_name.sql` files live at runtime. Resolved by probing, because
 * the path differs across the three ways this module runs:
 *   - tsc output / tsx tests → this module sits beside the .sql files;
 *   - esbuild bundle (dist/server.js) → `import.meta.url` collapses to `dist/`,
 *     so the assets are one level down in `dist/storage/migrations/` (where
 *     `scripts/copy-assets.mjs` mirrors them).
 */
function resolveMigrationsDir(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  const candidates = [here, join(here, 'storage', 'migrations'), join(here, 'migrations')];
  for (const dir of candidates) {
    try {
      if (existsSync(dir) && readdirSync(dir).some((f) => MIGRATION_FILE.test(f))) return dir;
    } catch {
      /* unreadable candidate — try the next one */
    }
  }
  return here;
}

const MIGRATION_FILE = /^(\d+)_(.+)\.sql$/;

const MIGRATIONS_DIR = resolveMigrationsDir();

/**
 * The migrations a 3.0 development database may have recorded (by number,
 * through the old high-water mark) without running — see the module header.
 * The one-time backfill probes their objects instead of trusting the number.
 */
export const PROBED_ON_BACKFILL: ReadonlySet<number> = new Set([12, 13, 14]);

export interface Migration {
  version: number;
  name: string;
  filePath: string;
}

export function runMigrations(db: DB): void {
  const migrations = listMigrations();
  ensureBookkeeping(db);
  backfillFromHighWaterMark(db, migrations);
  // Unlocked fast path: an up-to-date database — every open after the
  // first — never takes the write lock here at all.
  const applied = appliedVersions(db);
  for (const migration of migrations) {
    if (applied.has(migration.version)) continue;
    applyMigration(db, migration);
  }
  // Fails open: a database this step could not re-key keeps working exactly
  // as before (the old ids simply stay), and the next start tries again.
  try {
    rekeyStoredLocalRuleIds(db);
  } catch {
    /* see above */
  }
}

function ensureBookkeeping(db: DB): void {
  // schema_meta is also created by 001_initial.sql, but we need it to exist
  // BEFORE we read the stored version on a brand-new DB.
  db.exec(`
    CREATE TABLE IF NOT EXISTS schema_meta (
      key   TEXT PRIMARY KEY,
      value TEXT NOT NULL
    )
  `);
  db.exec(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version    INTEGER PRIMARY KEY,
      name       TEXT NOT NULL,
      applied_at TEXT NOT NULL
    )
  `);
}

/** `schema_meta.version`: the highest migration number applied, 0 on a new database. */
function storedHighWaterMark(db: DB): number {
  const row = db
    .prepare<[], { value: string }>("SELECT value FROM schema_meta WHERE key = 'version'")
    .get();
  if (!row) return 0;
  const n = Number.parseInt(row.value, 10);
  return Number.isFinite(n) ? n : 0;
}

function raiseHighWaterMark(db: DB, version: number): void {
  if (storedHighWaterMark(db) >= version) return;
  db.prepare(
    `INSERT INTO schema_meta(key, value) VALUES('version', ?)
     ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
  ).run(String(version));
}

function appliedVersions(db: DB): Set<number> {
  return new Set(
    db
      .prepare<[], { version: number }>('SELECT version FROM schema_migrations')
      .all()
      .map((r) => Number(r.version)),
  );
}

function isRecorded(db: DB, version: number): boolean {
  return db.prepare<[number], { one: number }>('SELECT 1 AS one FROM schema_migrations WHERE version = ?').get(version) !== undefined;
}

function hasAnyRecorded(db: DB): boolean {
  return db.prepare<[], { one: number }>('SELECT 1 AS one FROM schema_migrations LIMIT 1').get() !== undefined;
}

function record(db: DB, migration: Migration, appliedAt: string): void {
  db.prepare<[number, string, string]>(
    'INSERT OR IGNORE INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)',
  ).run(migration.version, migration.name, appliedAt);
}

/**
 * The one-time conversion of a database that predates `schema_migrations`:
 * see the module header. A no-op on a new database (stored version 0) and
 * on every database that already has a set.
 */
function backfillFromHighWaterMark(db: DB, migrations: readonly Migration[]): void {
  if (storedHighWaterMark(db) === 0 || hasAnyRecorded(db)) return;
  db.transaction(() => {
    const stored = storedHighWaterMark(db);
    if (stored === 0 || hasAnyRecorded(db)) return; // another process did it
    const now = new Date().toISOString();
    for (const migration of migrations) {
      if (migration.version > stored) continue;
      if (PROBED_ON_BACKFILL.has(migration.version) && !objectsPresent(db, migration)) continue;
      record(db, migration, now);
    }
  })();
}

function applyMigration(db: DB, migration: Migration): void {
  const statements = splitStatements(readFileSync(migration.filePath, 'utf8'), migration.filePath);
  db.transaction(() => {
    // Re-read under the write lock — see "Concurrency" in the module header.
    if (isRecorded(db, migration.version)) return;
    for (const statement of statements) runIdempotent(db, statement);
    record(db, migration, new Date().toISOString());
    raiseHighWaterMark(db, migration.version);
  })();
}

const ADD_COLUMN = /^ALTER\s+TABLE\s+["`[]?(\w+)["`\]]?\s+ADD\s+(?:COLUMN\s+)?["`[]?(\w+)["`\]]?/i;
const CREATE_TABLE = /^CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?["`[]?(\w+)["`\]]?/i;
const CREATE_INDEX = /^CREATE\s+(?:UNIQUE\s+)?INDEX\s+(?:IF\s+NOT\s+EXISTS\s+)?["`[]?(\w+)["`\]]?/i;

function runIdempotent(db: DB, statement: string): void {
  const add = ADD_COLUMN.exec(statement);
  if (add !== null) {
    const [, table, column] = add;
    if (table !== undefined && column !== undefined && columnExists(db, table, column)) return;
  }
  db.exec(statement);
}

function columnExists(db: DB, table: string, column: string): boolean {
  return db
    .prepare<[string, string], { one: number }>('SELECT 1 AS one FROM pragma_table_info(?) WHERE name = ?')
    .get(table, column) !== undefined;
}

function objectExists(db: DB, type: 'table' | 'index', name: string): boolean {
  return db
    .prepare<[string, string], { one: number }>('SELECT 1 AS one FROM sqlite_master WHERE type = ? AND name = ?')
    .get(type, name) !== undefined;
}

/**
 * What a migration creates, read from its own SQL: the tables and indexes it
 * creates and the columns it adds. Data statements create nothing to look for.
 */
export interface MigrationObjects {
  tables: string[];
  indexes: string[];
  columns: Array<{ table: string; column: string }>;
}

export function objectsOf(migration: Migration): MigrationObjects {
  const out: MigrationObjects = { tables: [], indexes: [], columns: [] };
  for (const statement of splitStatements(readFileSync(migration.filePath, 'utf8'), migration.filePath)) {
    const table = CREATE_TABLE.exec(statement)?.[1];
    if (table !== undefined) {
      out.tables.push(table);
      continue;
    }
    const index = CREATE_INDEX.exec(statement)?.[1];
    if (index !== undefined) {
      out.indexes.push(index);
      continue;
    }
    const add = ADD_COLUMN.exec(statement);
    if (add?.[1] !== undefined && add[2] !== undefined) out.columns.push({ table: add[1], column: add[2] });
  }
  return out;
}

/** Whether every table, index and column `migration` creates is in `db`. */
function objectsPresent(db: DB, migration: Migration): boolean {
  const objects = objectsOf(migration);
  return (
    objects.tables.every((t) => objectExists(db, 'table', t)) &&
    objects.indexes.every((i) => objectExists(db, 'index', i)) &&
    objects.columns.every((c) => columnExists(db, c.table, c.column))
  );
}

/**
 * `sql` as the statements SQLite would run, comments dropped, in order.
 * Understands `--` and `/* … *\/` comments, '…' strings (with '' escapes),
 * "…" / `…` / […] identifiers. Throws on `CREATE TRIGGER`, whose body holds
 * semicolons of its own (see the module header); `source` names the file.
 */
export function splitStatements(sql: string, source = 'migration'): string[] {
  const statements: string[] = [];
  let current = '';
  let i = 0;
  const push = (): void => {
    const text = current.trim();
    current = '';
    if (text === '') return;
    if (/^CREATE\s+(?:TEMP\s+|TEMPORARY\s+)?TRIGGER\b/i.test(text)) {
      throw new Error(`${source}: CREATE TRIGGER is not supported in a migration (see migrations/runner.ts)`);
    }
    statements.push(text);
  };
  const closers: Record<string, string> = { "'": "'", '"': '"', '`': '`', '[': ']' };
  while (i < sql.length) {
    const ch = sql[i] ?? '';
    const next = sql[i + 1] ?? '';
    if (ch === '-' && next === '-') {
      const end = sql.indexOf('\n', i);
      i = end < 0 ? sql.length : end + 1;
      current += ' ';
      continue;
    }
    if (ch === '/' && next === '*') {
      const end = sql.indexOf('*/', i + 2);
      i = end < 0 ? sql.length : end + 2;
      current += ' ';
      continue;
    }
    const closer = closers[ch];
    if (closer !== undefined) {
      let j = i + 1;
      for (;;) {
        const end = sql.indexOf(closer, j);
        if (end < 0) {
          j = sql.length;
          break;
        }
        // '' inside a string (and "" inside an identifier) is an escaped quote.
        if (closer !== ']' && sql[end + 1] === closer) {
          j = end + 2;
          continue;
        }
        j = end + 1;
        break;
      }
      current += sql.slice(i, j);
      i = j;
      continue;
    }
    if (ch === ';') {
      push();
      i += 1;
      continue;
    }
    current += ch;
    i += 1;
  }
  push();
  return statements;
}

/**
 * Every `NNN_name.sql` in `dir`, in version order. Throws on a duplicated
 * number — see the numbering convention in this module's header.
 */
export function listMigrations(dir: string = MIGRATIONS_DIR): Migration[] {
  const migrations: Migration[] = [];
  for (const f of readdirSync(dir)) {
    const match = MIGRATION_FILE.exec(f);
    if (!match) continue;
    const versionPart = match[1];
    const namePart = match[2];
    if (versionPart === undefined || namePart === undefined) continue;
    migrations.push({
      version: Number.parseInt(versionPart, 10),
      name: namePart,
      filePath: join(dir, f),
    });
  }
  migrations.sort((a, b) => a.version - b.version);

  for (let i = 1; i < migrations.length; i++) {
    const prev = migrations[i - 1];
    const cur = migrations[i];
    if (prev !== undefined && cur !== undefined && prev.version === cur.version) {
      throw new Error(
        `Duplicate migration number ${cur.version}: '${prev.name}' and '${cur.name}' in ${dir}. ` +
          'Renumber one of them to the next unused number.',
      );
    }
  }
  return migrations;
}
