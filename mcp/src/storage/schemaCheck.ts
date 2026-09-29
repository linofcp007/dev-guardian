/**
 * What a guardian database's schema must, and may, hold — compared against
 * the schema the shipped migrations build on an empty database (the
 * REFERENCE, `db.ts#expectedSchema`).
 *
 * Two questions, asked by `db.ts` at every file-backed open:
 *
 *   - {@link untrustedObjects}, BEFORE the migrations run: does the file hold
 *     a schema object the migrations never create? A trigger or a view (no
 *     migration creates either), a table or index of another name, a known
 *     name of the wrong type (a view called `findings`), or a known table or
 *     index whose DEFINITION the migrations never wrote. Such a database is
 *     not trusted. The attack is measured, not hypothetical: `AFTER INSERT ON
 *     findings BEGIN DELETE FROM findings WHERE rowid = NEW.rowid; END` in a
 *     committed `.guardian/guardian.db` took a project from risk 55 to 8 and
 *     from 7 open findings to 0 at coverage `full` — in risk_score, every
 *     report, the open set and create_fix_pr. The definition check closes
 *     the same hole one level down: every repo inserts with `INSERT OR
 *     IGNORE`, which silently skips a row that violates a CHECK or UNIQUE
 *     constraint, so `CHECK (severity <> 'critical')` or `UNIQUE (scan_id)`
 *     written into `findings` would hide rows exactly as the trigger did,
 *     under every name and type the migrations use. Asked before migrating
 *     because the migrations and the plugin-pack re-key WRITE to findings,
 *     suppressions and baselines, and a trigger fires on those writes too.
 *   - {@link missingObjects}, AFTER they run: is every table, column and
 *     index the code relies on really there? A database the runner could not
 *     bring there (a column dropped by hand, a file restored from a partial
 *     copy) otherwise died inside `new Storage()` on a bare `no such column`,
 *     naming neither the object nor the file. A missing index is recreated
 *     from the reference instead ({@link missingIndexSql}) — a 3.0
 *     development database that ran 005's first cut lacks three of them, and
 *     an index is never worth refusing to start over.
 *
 * A table's definition is compared as a SET of its top-level parts (column
 * definitions and table constraints), normalised: comments dropped,
 * whitespace collapsed, case folded. A set, because `ALTER TABLE … ADD
 * COLUMN` appends to the stored text in the order migrations ran, and
 * migrations written on parallel branches ran in either order. Before the
 * migrations run a table may lack parts (an older database), never hold one
 * the reference does not.
 *
 * SQLite's own objects are allowed: `sqlite_sequence` (AUTOINCREMENT),
 * `sqlite_stat1`–`sqlite_stat4` (ANALYZE) and a PRIMARY KEY / UNIQUE
 * constraint's `sqlite_autoindex_*` (the constraint itself is a part of the
 * table's definition, checked above).
 *
 * A database a NEWER build has migrated holds objects this build's reference
 * does not; what a later additive migration can create without being able to
 * hide a row is accepted — see {@link untrustedObjects}.
 */

import type { DB } from './db.js';

export type SchemaObjectType = 'table' | 'index' | 'view' | 'trigger';

export interface SchemaSnapshot {
  /** Every sqlite_master object by name. */
  objects: Map<string, SchemaObjectType>;
  /** Every table's columns. */
  columns: Map<string, Set<string>>;
  /** Every index's table. */
  indexTables: Map<string, string>;
  /** Every object's CREATE text as SQLite stores it (null for an autoindex). */
  sql: Map<string, string | null>;
  /**
   * Every table's UNIQUE keys as SQLite enforces them — PRIMARY KEY and
   * UNIQUE constraints and UNIQUE indexes alike (`pragma_index_list`), each
   * as its column list (`<expr>` for an expression), plus ` where` for a
   * partial one.
   */
  uniqueKeys: Map<string, Set<string>>;
}

interface MasterRow {
  type: string;
  name: string;
  tbl_name: string;
  sql: string | null;
}

function masterRows(db: DB): MasterRow[] {
  return db.prepare<[], MasterRow>('SELECT type, name, tbl_name, sql FROM sqlite_master').all();
}

/** Reads `db`'s schema: every sqlite_master object, and every table's columns. */
export function readSchema(db: DB): SchemaSnapshot {
  const objects = new Map<string, SchemaObjectType>();
  const columns = new Map<string, Set<string>>();
  const indexTables = new Map<string, string>();
  const sql = new Map<string, string | null>();
  const uniqueKeys = new Map<string, Set<string>>();
  for (const row of masterRows(db)) {
    const type = asObjectType(row.type);
    if (type === null) continue;
    objects.set(row.name, type);
    sql.set(row.name, row.sql);
    if (type === 'index') indexTables.set(row.name, row.tbl_name);
    if (type === 'table') {
      const cols = db
        .prepare<[string], { name: string }>('SELECT name FROM pragma_table_info(?)')
        .all(row.name)
        .map((c) => c.name);
      columns.set(row.name, new Set(cols));
      uniqueKeys.set(row.name, uniqueKeysOf(db, row.name));
    }
  }
  return { objects, columns, indexTables, sql, uniqueKeys };
}

/** `table`'s UNIQUE keys, as {@link SchemaSnapshot.uniqueKeys} spells them. */
function uniqueKeysOf(db: DB, table: string): Set<string> {
  const keys = new Set<string>();
  const indexes = db
    .prepare<[string], { name: string; unique: number; partial: number }>(
      'SELECT name, "unique" AS "unique", partial FROM pragma_index_list(?)',
    )
    .all(table);
  for (const index of indexes) {
    if (Number(index.unique) !== 1) continue;
    const cols = db
      .prepare<[string], { name: string | null }>('SELECT name FROM pragma_index_info(?) ORDER BY seqno')
      .all(index.name)
      .map((c) => c.name ?? '<expr>');
    keys.add(`(${cols.join(', ')})${Number(index.partial) === 1 ? ' where' : ''}`);
  }
  return keys;
}

interface ColumnInfo {
  name: string;
  notnull: number;
  dflt_value: string | null;
  pk: number;
  hidden: number;
}

/**
 * Why a column this build does not know can make an insert fail — judged on
 * what SQLite RECORDED (`pragma_table_xinfo`), not on the CREATE text: a
 * quoted type name such as `gate 'default 1' NOT NULL` reads like a column
 * with a default and is stored as NOT NULL with none. Null when an insert
 * that does not name the column always satisfies it.
 */
function newColumnProblem(column: ColumnInfo): string | null {
  if (Number(column.pk) !== 0) return 'part of the PRIMARY KEY';
  if (Number(column.hidden) !== 0) return 'a generated or hidden column';
  if (Number(column.notnull) !== 0 && !isNonNullLiteral(column.dflt_value)) {
    return 'NOT NULL with no non-NULL default (INSERT OR IGNORE would skip every row)';
  }
  return null;
}

/** A default SQLite stores as a plain non-NULL literal: a number, a string, a blob, TRUE or FALSE. */
function isNonNullLiteral(dflt: string | null): boolean {
  if (dflt === null) return false;
  const v = dflt.trim();
  return (
    /^[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:e[+-]?\d+)?$/i.test(v) ||
    /^'(?:[^']|'')*'$/.test(v) ||
    /^x'(?:[0-9a-f]{2})*'$/i.test(v) ||
    /^(?:true|false)$/i.test(v)
  );
}

/**
 * The structural half of the check on a known table (`pragma_table_xinfo`,
 * `pragma_index_list`): a column the reference does not have that an insert
 * can violate, and a UNIQUE key the reference does not have. Each problem as
 * `table findings: …`.
 */
function structuralProblems(db: DB, table: string, reference: SchemaSnapshot): string[] {
  const out: string[] = [];
  const known = new Set([...(reference.columns.get(table) ?? [])].map((c) => c.toLowerCase()));
  const columns = db
    .prepare<[string], ColumnInfo>('SELECT name, "notnull" AS "notnull", dflt_value, pk, hidden FROM pragma_table_xinfo(?)')
    .all(table);
  for (const column of columns) {
    if (known.has(column.name.toLowerCase())) continue;
    const problem = newColumnProblem(column);
    if (problem !== null) out.push(`table ${table}: column ${column.name} is ${problem}`);
  }
  const allowedKeys = reference.uniqueKeys.get(table) ?? new Set<string>();
  for (const key of uniqueKeysOf(db, table)) {
    if (!allowedKeys.has(key)) out.push(`table ${table}: a UNIQUE key on ${key} (INSERT OR IGNORE would skip rows)`);
  }
  return out;
}

function asObjectType(type: string): SchemaObjectType | null {
  return type === 'table' || type === 'index' || type === 'view' || type === 'trigger' ? type : null;
}

/** SQLite's own bookkeeping objects, allowed whatever the reference holds. */
function isSqliteInternal(row: MasterRow): boolean {
  if (row.type === 'table' && (row.name === 'sqlite_sequence' || /^sqlite_stat[1-4]$/.test(row.name))) return true;
  return row.type === 'index' && row.sql === null && row.name.startsWith('sqlite_autoindex_');
}

export interface TrustOptions {
  /**
   * The database records migrations this build does not ship
   * ({@link recordsNewerMigrations}): a later build migrated it. What a later
   * ADDITIVE migration can create, and cannot hide a row with, is then
   * accepted — see {@link untrustedObjects}.
   */
  newerBuild?: boolean;
}

/**
 * Every object in `db` the migrations did not create, one short phrase each
 * (`trigger findings_hide`, `table findings: check(severity<>'critical')`) —
 * empty when there is none. Reads sqlite_master only; runs nothing the file
 * defines.
 *
 * ---- A database a newer build migrated (a downgrade) --------------------
 *
 * 3.0.0 served a database a later build had migrated, and a downgrade must
 * keep doing so. With `newerBuild`, what a later additive migration can
 * create and no row can be hidden by is accepted:
 *   - a table of another name (this build never writes to it, and a table
 *     cannot act on another one without a trigger);
 *   - an extra column on a known table, when every insert this build makes
 *     still succeeds with it — no CHECK, UNIQUE, PRIMARY KEY, REFERENCES or
 *     GENERATED, and a NOT NULL only beside a non-NULL DEFAULT. `INSERT OR
 *     IGNORE` silently skips a row that violates NOT NULL, CHECK or UNIQUE,
 *     so a column like `gate TEXT NOT NULL` hides every finding;
 *   - an index of another name that is not UNIQUE; a UNIQUE one only on a
 *     table this build does not know (it is that table's own business, like
 *     the UNIQUE constraints its CREATE TABLE may declare).
 * Whatever schema_migrations says, still refused: every trigger and every
 * view (no migration creates either — `migrations/runner.ts`, held by a
 * test); a UNIQUE index, or any change of definition, on a table this build
 * writes to — a UNIQUE index on `findings` makes `INSERT OR IGNORE` drop
 * rows, the same hiding the trigger did; and a CHECK, UNIQUE or other
 * constraint added to a known table. So a future migration that adds a
 * UNIQUE index or constraint to an existing table costs an older build a
 * fallback, with a warning that says why — the migrations' own rules say so.
 *
 * `newerBuild` comes from the file itself, so an attacker can claim it — and
 * gains only what is accepted above, none of which can hide a row.
 */
export function untrustedObjects(db: DB, reference: SchemaSnapshot, opts: TrustOptions = {}): string[] {
  const newer = opts.newerBuild === true;
  const out: string[] = [];
  for (const row of masterRows(db)) {
    if (isSqliteInternal(row)) continue;
    // Never created by a migration: refused whatever the reference holds.
    if (row.type === 'trigger' || row.type === 'view') {
      out.push(`${row.type} ${row.name}`);
      continue;
    }
    const expected = reference.objects.get(row.name);
    if (expected === undefined) {
      const why = newer ? unknownObjectProblem(row, reference) : null;
      if (!newer) out.push(`${row.type} ${row.name}`);
      else if (why !== null) out.push(`${row.type} ${row.name}: ${why}`);
      continue;
    }
    if (expected !== row.type) {
      out.push(`${row.type} ${row.name}`);
      continue;
    }
    const referenceSql = reference.sql.get(row.name) ?? null;
    if (row.type === 'table') {
      const actual = tableDefinition(row.sql ?? '');
      const allowed = tableDefinition(referenceSql ?? '');
      if (actual === null || allowed === null || actual.tail !== allowed.tail) {
        out.push(`table ${row.name}: a definition the migrations never wrote`);
        continue;
      }
      const allowedParts = new Set(allowed.parts);
      const knownColumns = reference.columns.get(row.name) ?? new Set<string>();
      for (const part of actual.parts) {
        if (allowedParts.has(part)) continue;
        if (newer && harmlessNewColumn(part, knownColumns)) continue;
        out.push(`table ${row.name}: ${shorten(part)}`);
      }
      // What SQLite recorded, whatever the text says (a quoted type name hides
      // a NOT NULL from a reading of the text).
      out.push(...structuralProblems(db, row.name, reference));
    } else if (row.type === 'index') {
      if (normaliseSql(row.sql ?? '') !== normaliseSql(referenceSql ?? '')) {
        out.push(`index ${row.name}: a definition the migrations never wrote`);
      }
    }
  }
  return out.sort();
}

/**
 * Why an object of a name the reference does not know, in a database a newer
 * build migrated, can hide a row — or null when it cannot (see
 * {@link untrustedObjects}).
 */
function unknownObjectProblem(row: MasterRow, reference: SchemaSnapshot): string | null {
  if (row.type === 'table') return null;
  if (row.type !== 'index') return 'not something a migration creates';
  const unique = /^create\s+unique\s+index\b/.test(normaliseSql(row.sql ?? ''));
  if (!unique) return null;
  return reference.objects.get(row.tbl_name) === 'table' ? `a UNIQUE index on ${row.tbl_name}` : null;
}

const TABLE_CONSTRAINT = /^(?:constraint|primary\s+key|unique|check|foreign\s+key)\b/;
const COLUMN_CONSTRAINT = /\b(?:primary\s+key|unique|check|references|generated)\b|\bas\s*\(/;

/**
 * The TEXT half of judging a part of a known table's definition that the
 * reference does not have, in a database a newer build migrated: a column
 * (not a table constraint) of a name the reference does not have, with none
 * of CHECK, UNIQUE, PRIMARY KEY, REFERENCES or GENERATED written anywhere in
 * it — a keyword inside a quoted name only refuses more. NOT NULL, a default,
 * PRIMARY KEY and generated columns are judged on what SQLite recorded
 * ({@link structuralProblems}), never on this text.
 */
function harmlessNewColumn(part: string, knownColumns: ReadonlySet<string>): boolean {
  if (TABLE_CONSTRAINT.test(part)) return false;
  const name = /^(?:"([^"]+)"|`([^`]+)`|\[([^\]]+)\]|([^\s(]+))/.exec(part);
  const column = name?.[1] ?? name?.[2] ?? name?.[3] ?? name?.[4];
  if (column === undefined) return false;
  const known = [...knownColumns].some((c) => c.toLowerCase() === column.toLowerCase());
  if (known) return false;
  return !COLUMN_CONSTRAINT.test(part);
}

/**
 * Whether `db` records a migration newer than `latestKnown` — in
 * `schema_migrations`, or as `schema_meta.version` — so a later build
 * migrated it. Reads each only when it is a real table, never through a view.
 */
export function recordsNewerMigrations(db: DB, latestKnown: number): boolean {
  const isTable = (name: string): boolean =>
    db.prepare<[string], { type: string }>('SELECT type FROM sqlite_master WHERE name = ?').get(name)?.type === 'table';
  const numbers: number[] = [];
  if (isTable('schema_migrations')) {
    const max = db.prepare<[], { v: number | null }>('SELECT MAX(version) AS v FROM schema_migrations').get()?.v;
    if (typeof max === 'number') numbers.push(max);
  }
  if (isTable('schema_meta')) {
    const raw = db.prepare<[], { value: string }>("SELECT value FROM schema_meta WHERE key = 'version'").get()?.value;
    const n = raw === undefined ? Number.NaN : Number.parseInt(raw, 10);
    if (Number.isFinite(n)) numbers.push(n);
  }
  return numbers.some((n) => n > latestKnown);
}

/**
 * Every table and column of the reference that `db` lacks, as `table
 * mcp_tool_pins` or `column findings.cwe` — tables first — then every index
 * whose table is there but which is not (an index of a missing table is not
 * listed again). Empty when the schema is complete.
 */
export function missingObjects(db: DB, reference: SchemaSnapshot): string[] {
  const actual = readSchema(db);
  const tables: string[] = [];
  const columns: string[] = [];
  const indexes: string[] = [];
  for (const [name, type] of reference.objects) {
    // SQLite's own objects come and go with its own rules (ANALYZE, a table
    // rebuilt by ALTER): never something the code prepares a statement on.
    if (name.startsWith('sqlite_')) continue;
    if (type === 'index') {
      const table = reference.indexTables.get(name);
      const tableMissing = table !== undefined && actual.objects.get(table) !== 'table';
      if (!tableMissing && actual.objects.get(name) !== 'index') indexes.push(`index ${name}`);
      continue;
    }
    if (actual.objects.get(name) !== type) {
      tables.push(`${type} ${name}`);
      continue;
    }
    if (type !== 'table') continue;
    const have = actual.columns.get(name) ?? new Set<string>();
    for (const column of reference.columns.get(name) ?? []) {
      if (!have.has(column)) columns.push(`column ${name}.${column}`);
    }
  }
  return [...tables.sort(), ...columns.sort(), ...indexes.sort()];
}

/** The reference's CREATE INDEX text for every index `db` lacks on a table it has. */
export function missingIndexSql(db: DB, reference: SchemaSnapshot): string[] {
  const actual = readSchema(db);
  const out: string[] = [];
  for (const [name, type] of reference.objects) {
    if (type !== 'index' || name.startsWith('sqlite_')) continue;
    if (actual.objects.get(name) === 'index') continue;
    const table = reference.indexTables.get(name);
    if (table === undefined || actual.objects.get(table) !== 'table') continue;
    const sql = reference.sql.get(name);
    if (typeof sql === 'string') out.push(sql);
  }
  return out;
}

function shorten(text: string): string {
  return text.length > 80 ? `${text.slice(0, 77)}...` : text;
}

/** `sql` without comments, with whitespace collapsed and case folded. */
export function normaliseSql(sql: string): string {
  let out = '';
  let i = 0;
  while (i < sql.length) {
    const ch = sql[i] ?? '';
    const next = sql[i + 1] ?? '';
    if (ch === '-' && next === '-') {
      const end = sql.indexOf('\n', i);
      i = end < 0 ? sql.length : end + 1;
      out += ' ';
      continue;
    }
    if (ch === '/' && next === '*') {
      const end = sql.indexOf('*/', i + 2);
      i = end < 0 ? sql.length : end + 2;
      out += ' ';
      continue;
    }
    if (ch === "'" || ch === '"' || ch === '`' || ch === '[') {
      const closer = ch === '[' ? ']' : ch;
      let j = i + 1;
      for (;;) {
        const end = sql.indexOf(closer, j);
        if (end < 0) {
          j = sql.length;
          break;
        }
        if (closer !== ']' && sql[end + 1] === closer) {
          j = end + 2;
          continue;
        }
        j = end + 1;
        break;
      }
      out += sql.slice(i, j);
      i = j;
      continue;
    }
    out += ch;
    i += 1;
  }
  return out
    .toLowerCase()
    .replace(/\s+/g, ' ')
    .replace(/\s*([(),])\s*/g, '$1')
    .replace(/\bif not exists\b\s*/g, '')
    .trim();
}

/**
 * A CREATE TABLE text as its top-level parts (column definitions and table
 * constraints), normalised, plus whatever follows the closing parenthesis
 * (`without rowid`, `strict`). Null when the text has no parenthesised body.
 */
export function tableDefinition(sql: string): { parts: string[]; tail: string } | null {
  const text = normaliseSql(sql);
  const open = text.indexOf('(');
  if (open < 0) return null;
  const parts: string[] = [];
  let depth = 0;
  let current = '';
  let i = open + 1;
  for (; i < text.length; i++) {
    const ch = text[i] ?? '';
    if (ch === "'" || ch === '"' || ch === '`' || ch === '[') {
      const closer = ch === '[' ? ']' : ch;
      let end = text.indexOf(closer, i + 1);
      while (end >= 0 && closer !== ']' && text[end + 1] === closer) end = text.indexOf(closer, end + 2);
      const stop = end < 0 ? text.length - 1 : end;
      current += text.slice(i, stop + 1);
      i = stop;
      continue;
    }
    if (ch === '(') depth += 1;
    if (ch === ')') {
      if (depth === 0) break;
      depth -= 1;
    }
    if (ch === ',' && depth === 0) {
      parts.push(current.trim());
      current = '';
      continue;
    }
    current += ch;
  }
  if (current.trim() !== '') parts.push(current.trim());
  return { parts, tail: text.slice(i + 1).trim() };
}
