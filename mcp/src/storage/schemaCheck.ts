/**
 * What a guardian database's schema must, and may, hold — compared against
 * the schema the shipped migrations build on an empty database.
 *
 * Two questions, asked by `db.ts` at every file-backed open:
 *
 *   - {@link unexpectedObjects}, BEFORE the migrations run: does the file
 *     hold a schema object the migrations never create — a trigger, a view,
 *     a table or index of another name, or a known name of the wrong type (a
 *     view called `findings`)? Such a database is not trusted. The attack is
 *     measured, not hypothetical: `AFTER INSERT ON findings BEGIN DELETE FROM
 *     findings WHERE rowid = NEW.rowid; END` in a committed
 *     `.guardian/guardian.db` took a project from risk 55 to 8 and from 7
 *     open findings to 0 at coverage `full`, in risk_score, every report, the
 *     open set and create_fix_pr. Asked before migrating because the
 *     migrations and the plugin-pack re-key WRITE to findings, suppressions
 *     and baselines, and a trigger fires on those writes too.
 *   - {@link missingObjects}, AFTER they run: is every table, column and
 *     index the code prepares statements against really there? A database
 *     the runner could not bring there (a column dropped by hand, a file
 *     restored from a partial copy) otherwise died inside `new Storage()` on
 *     a bare `no such column`, naming neither the object nor the file.
 *
 * SQLite's own objects are allowed: `sqlite_sequence` (AUTOINCREMENT),
 * `sqlite_stat1`–`sqlite_stat4` (ANALYZE) and a UNIQUE / PRIMARY KEY
 * constraint's `sqlite_autoindex_*` (an index with no SQL text). Nothing
 * else outside the reference is — the reference is a SUPERSET of every
 * older database's schema, because migrations only ever add.
 */

import type { DB } from './db.js';

export type SchemaObjectType = 'table' | 'index' | 'view' | 'trigger';

export interface SchemaSnapshot {
  /** `type:name` of every object in sqlite_master. */
  objects: Map<string, SchemaObjectType>;
  /** Every table's columns. */
  columns: Map<string, Set<string>>;
  /** Every index's table. */
  indexTables: Map<string, string>;
}

interface MasterRow {
  type: string;
  name: string;
  tbl_name: string;
  sql: string | null;
}

/** Reads `db`'s schema: every sqlite_master object, and every table's columns. */
export function readSchema(db: DB): SchemaSnapshot {
  const objects = new Map<string, SchemaObjectType>();
  const columns = new Map<string, Set<string>>();
  const indexTables = new Map<string, string>();
  const rows = db.prepare<[], MasterRow>('SELECT type, name, tbl_name, sql FROM sqlite_master').all();
  for (const row of rows) {
    const type = asObjectType(row.type);
    if (type === null) continue;
    objects.set(row.name, type);
    if (type === 'index') indexTables.set(row.name, row.tbl_name);
    if (type === 'table') {
      const cols = db
        .prepare<[string], { name: string }>('SELECT name FROM pragma_table_info(?)')
        .all(row.name)
        .map((c) => c.name);
      columns.set(row.name, new Set(cols));
    }
  }
  return { objects, columns, indexTables };
}

function asObjectType(type: string): SchemaObjectType | null {
  return type === 'table' || type === 'index' || type === 'view' || type === 'trigger' ? type : null;
}

/** SQLite's own bookkeeping objects, allowed whatever the reference holds. */
function isSqliteInternal(row: MasterRow): boolean {
  if (row.type === 'table' && (row.name === 'sqlite_sequence' || /^sqlite_stat[1-4]$/.test(row.name))) return true;
  return row.type === 'index' && row.sql === null && row.name.startsWith('sqlite_autoindex_');
}

/**
 * Every object in `db` the reference does not hold under the same name and
 * type, as `trigger findings_hide` — empty when there is none. Reads
 * sqlite_master only; runs nothing the file defines.
 */
export function unexpectedObjects(db: DB, reference: SchemaSnapshot): string[] {
  const out: string[] = [];
  const rows = db.prepare<[], MasterRow>('SELECT type, name, tbl_name, sql FROM sqlite_master').all();
  for (const row of rows) {
    if (isSqliteInternal(row)) continue;
    const expected = reference.objects.get(row.name);
    if (expected !== undefined && expected === row.type) continue;
    out.push(`${row.type} ${row.name}`);
  }
  return out.sort();
}

/**
 * Every table, column and index of the reference that `db` lacks, as
 * `table mcp_tool_pins`, `column findings.cwe`, `index idx_x` — tables
 * first, then columns, then indexes; an index of a missing table is not
 * listed again. Empty when the schema is complete.
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
