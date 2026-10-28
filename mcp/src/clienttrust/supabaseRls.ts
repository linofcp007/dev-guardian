/**
 * Supabase migrations without row-level security, or with policies that let
 * anyone write — read over `supabase/migrations/*.sql`, in file-name order
 * (the timestamp the Supabase CLI gives them), as one database.
 *
 * Why it matters: every table of an exposed schema (`public` and
 * `graphql_public` by default; `[api] schemas` in `supabase/config.toml`) is
 * served by the Data API to anyone holding the anon key — and the anon key is
 * in the browser by design. Without RLS on, such a table is readable and
 * writable by every visitor. With RLS on, its policies decide, and a write
 * policy whose check is `true`, or one granted to `anon`, decides nothing.
 *
 *   | rule                          | severity | when                                      |
 *   | ----------------------------- | -------- | ----------------------------------------- |
 *   | supabase-rls-disabled         | critical | a table of an exposed schema no migration  |
 *   |                               |          | enables RLS on (or one disables it again)  |
 *   | supabase-policy-open-write    | high     | an insert / update / delete / all policy   |
 *   |                               |          | whose `using` or `with check` is `true`    |
 *   | supabase-policy-anon-write    | high     | a write policy granted `to anon`           |
 *   | supabase-policy-no-auth-check | low      | a write policy that never reads            |
 *   |                               |          | `auth.uid()`, `auth.jwt()` or `auth.role()`|
 *
 * A heuristic over statements, never a SQL parser — bounded and robust by
 * construction: comments, single-quoted strings and dollar-quoted bodies are
 * blanked out first (a function body that builds a table is no table, a
 * `-- enable row level security` comment enables nothing), statements are
 * split on the `;` left, and each is matched by its first words. Names are
 * read as Postgres reads them: unquoted folded to lower case, `"Quoted"`
 * kept, `schema.table` qualified (an unqualified table is `public`'s — the
 * Supabase default search path). What it follows across migrations: `create
 * table`, `alter table … enable / disable row level security`, `… rename
 * to`, `… set schema`, `drop table`, `create / alter / drop policy`, and a
 * `revoke … from anon` plus `from authenticated` (a table neither role can
 * reach is not served). Not followed (known gaps): `alter default
 * privileges`, a schema-wide `revoke … on all tables in schema`, a table
 * created by `create table … as` under another name through a function, a
 * view (`security_invoker`), and a `security definer` function that reads a
 * table for the caller.
 */

import { makeFinding } from '../runners/scannerParsers/index.js';
import type { Finding, Severity } from '../types.js';
import { CLIENT_TRUST_TOOL } from './publicEnv.js';

export interface MigrationFile {
  /** Project-relative, `/`-separated. */
  path: string;
  text: string;
}

/** The schemas Supabase's Data API serves when `config.toml` says nothing. */
export const DEFAULT_EXPOSED_SCHEMAS: readonly string[] = ['public', 'graphql_public'];

/** Roles that bypass RLS anyway, or no visitor holds: a policy for them only opens nothing. */
const PRIVILEGED_ROLES: ReadonlySet<string> = new Set([
  'service_role',
  'postgres',
  'supabase_admin',
  'supabase_auth_admin',
  'supabase_storage_admin',
  'dashboard_user',
]);

/**
 * `[api] schemas = [...]` of a `supabase/config.toml`, or the default when
 * the file or the key is absent — and none at all with `[api] enabled =
 * false`: no Data API, nothing served. A minimal reading — the section, then
 * the keys — never a TOML parser.
 */
export function exposedSchemasFrom(configToml: string | undefined): string[] {
  if (configToml === undefined) return [...DEFAULT_EXPOSED_SCHEMAS];
  const lines = configToml.split(/\r?\n/);
  let inApi = false;
  const body: string[] = [];
  for (const line of lines) {
    const header = /^\s*\[([^\]]+)\]\s*(?:#.*)?$/.exec(line);
    if (header !== null) {
      inApi = (header[1] ?? '').trim() === 'api';
      continue;
    }
    if (inApi) body.push(line.replace(/(^|\s)#.*$/, ''));
  }
  if (body.some((line) => /^\s*enabled\s*=\s*false\s*$/.test(line))) return [];
  const m = /(?:^|\n)\s*schemas\s*=\s*\[([^\]]*)\]/.exec(body.join('\n'));
  if (m === null) return [...DEFAULT_EXPOSED_SCHEMAS];
  const schemas = [...(m[1] ?? '').matchAll(/"([^"]*)"|'([^']*)'/g)].map((s) => s[1] ?? s[2] ?? '').filter((s) => s.length > 0);
  return schemas;
}

// ---- reading the SQL ---------------------------------------------------

interface Statement {
  /** The statement with comments and string bodies blanked, whitespace collapsed. */
  sql: string;
  file: string;
  line: number;
}

/**
 * `text` with every comment, single-quoted string body and dollar-quoted
 * body replaced by spaces (newlines kept, so offsets and lines still match).
 * Double-quoted identifiers are kept: they are the names this reads.
 */
export function blankSqlNoise(text: string): string {
  const out: string[] = [];
  const n = text.length;
  let i = 0;
  const blank = (from: number, to: number): void => {
    for (let k = from; k < to; k += 1) out.push(text[k] === '\n' ? '\n' : ' ');
  };
  while (i < n) {
    const c = text[i];
    const next = text[i + 1];
    if (c === '-' && next === '-') {
      const end = text.indexOf('\n', i);
      const stop = end < 0 ? n : end;
      blank(i, stop);
      i = stop;
    } else if (c === '/' && next === '*') {
      const end = text.indexOf('*/', i + 2);
      const stop = end < 0 ? n : end + 2;
      blank(i, stop);
      i = stop;
    } else if (c === "'") {
      // '' is an escaped quote inside the string; E'' strings' \' likewise.
      let k = i + 1;
      while (k < n) {
        if (text[k] === '\\' && text[i - 1] === 'E') {
          k += 2;
          continue;
        }
        if (text[k] === "'") {
          if (text[k + 1] === "'") {
            k += 2;
            continue;
          }
          break;
        }
        k += 1;
      }
      const stop = Math.min(n, k + 1);
      out.push("'");
      blank(i + 1, stop - 1);
      if (stop - 1 > i) out.push("'");
      i = stop;
    } else if (c === '"') {
      const end = text.indexOf('"', i + 1);
      const stop = end < 0 ? n : end + 1;
      out.push(text.slice(i, stop));
      i = stop;
    } else if (c === '$') {
      const tag = /^\$(?:[A-Za-z_][A-Za-z0-9_]*)?\$/.exec(text.slice(i, i + 64));
      if (tag === null) {
        out.push(c);
        i += 1;
        continue;
      }
      const end = text.indexOf(tag[0], i + tag[0].length);
      const stop = end < 0 ? n : end + tag[0].length;
      blank(i, stop);
      i = stop;
    } else {
      out.push(c ?? '');
      i += 1;
    }
  }
  return out.join('');
}

/** The statements of one migration, each with the line it starts on. */
function statementsOf(file: MigrationFile): Statement[] {
  const blanked = blankSqlNoise(file.text);
  const out: Statement[] = [];
  let start = 0;
  let line = 1;
  let startLine = 1;
  let seenText = false;
  for (let i = 0; i <= blanked.length; i += 1) {
    const c = blanked[i];
    if (i === blanked.length || c === ';') {
      const sql = blanked.slice(start, i).replace(/\s+/g, ' ').trim();
      if (sql.length > 0) out.push({ sql, file: file.path, line: startLine });
      start = i + 1;
      seenText = false;
      continue;
    }
    if (c === '\n') line += 1;
    else if (!seenText && c !== undefined && !/\s/.test(c)) {
      seenText = true;
      startLine = line;
    }
  }
  return out;
}

const IDENT = String.raw`(?:"(?:[^"]|"")+"|[A-Za-z_][A-Za-z0-9_$]*)`;
const QNAME = String.raw`${IDENT}(?:\s*\.\s*${IDENT})?`;

/** A name as Postgres reads it: unquoted folded to lower case, quoted kept. */
function identName(raw: string): string {
  const t = raw.trim();
  if (t.startsWith('"') && t.endsWith('"') && t.length >= 2) return t.slice(1, -1).replace(/""/g, '"');
  return t.toLowerCase();
}

/** `schema.table` (or `table`, in `public`) as `{ schema, name }`. */
function qualified(raw: string): { schema: string; name: string } {
  const parts = [...raw.matchAll(new RegExp(IDENT, 'g'))].map((m) => identName(m[0]));
  if (parts.length >= 2) return { schema: parts[0] ?? 'public', name: parts[1] ?? '' };
  return { schema: 'public', name: parts[0] ?? '' };
}

const keyOf = (t: { schema: string; name: string }): string => `${t.schema}\u0000${t.name}`;
const display = (t: { schema: string; name: string }): string => `${t.schema}.${t.name}`;

/**
 * The parenthesised expression that starts at `open` (an index of `(` in
 * `sql`), without its outer parentheses — or null when it never closes.
 */
function balanced(sql: string, open: number): string | null {
  let depth = 0;
  for (let i = open; i < sql.length; i += 1) {
    const c = sql[i];
    if (c === '(') depth += 1;
    else if (c === ')') {
      depth -= 1;
      if (depth === 0) return sql.slice(open + 1, i).trim();
    }
  }
  return null;
}

/** The expression after `keyword (` in `sql`, or undefined when the clause is absent. */
function clause(sql: string, keyword: RegExp): string | undefined {
  const m = keyword.exec(sql);
  if (m === null) return undefined;
  const open = m.index + m[0].length - 1;
  return balanced(sql, open) ?? undefined;
}

interface TableState {
  schema: string;
  name: string;
  file: string;
  line: number;
  rls: boolean;
  /** Where RLS was disabled again, if it was. */
  disabled?: { file: string; line: number };
  revokedAnon: boolean;
  revokedAuthenticated: boolean;
}

interface PolicyState {
  table: { schema: string; name: string };
  name: string;
  command: string;
  roles: string[];
  using?: string;
  check?: string;
  file: string;
  line: number;
}

const CREATE_TABLE = new RegExp(
  String.raw`^create\s+(?:or\s+replace\s+)?(?:(?:global|local)\s+)?(?:(temp|temporary)\s+)?(?:unlogged\s+)?table\s+(?:if\s+not\s+exists\s+)?(${QNAME})`,
  'i',
);
const ALTER_TABLE = new RegExp(String.raw`^alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?(${QNAME})\s+(.*)$`, 'i');
const DROP_TABLE = new RegExp(String.raw`^drop\s+table\s+(?:if\s+exists\s+)?((?:${QNAME})(?:\s*,\s*${QNAME})*)`, 'i');
const CREATE_POLICY = new RegExp(String.raw`^create\s+policy\s+(${IDENT})\s+on\s+(?:table\s+)?(${QNAME})(.*)$`, 'i');
const ALTER_POLICY = new RegExp(String.raw`^alter\s+policy\s+(${IDENT})\s+on\s+(?:table\s+)?(${QNAME})(.*)$`, 'i');
const DROP_POLICY = new RegExp(String.raw`^drop\s+policy\s+(?:if\s+exists\s+)?(${IDENT})\s+on\s+(?:table\s+)?(${QNAME})`, 'i');
const REVOKE = new RegExp(
  String.raw`^revoke\s+(?:grant\s+option\s+for\s+)?(.+?)\s+on\s+(?:table\s+)?((?:${QNAME})(?:\s*,\s*${QNAME})*)\s+from\s+(.+)$`,
  'i',
);

/** The roles of a `to …` clause, read before `using (` / `with check (` (never inside their expressions). */
function rolesOf(rest: string): string[] | undefined {
  const head = rest.split(/\busing\s*\(|\bwith\s+check\s*\(/i)[0] ?? '';
  const m = /\bto\s+(.+)$/i.exec(head.trim());
  if (m === null) return undefined;
  return (m[1] ?? '')
    .split(',')
    .map((r) => identName(r.trim()))
    .filter((r) => r.length > 0);
}

const isTrue = (expr: string | undefined): boolean => expr !== undefined && /^\(*\s*true\s*\)*$/i.test(expr.trim());
const isFalse = (expr: string | undefined): boolean => expr !== undefined && /^\(*\s*false\s*\)*$/i.test(expr.trim());
const readsAuth = (expr: string | undefined): boolean =>
  expr !== undefined && /\bauth\s*\.\s*(?:uid|jwt|role|email)\s*\(|\bcurrent_user\b|\bcurrent_setting\s*\(/i.test(expr);

/**
 * The findings of one Supabase project's migrations — `files` in any order
 * (sorted here by path, which is the CLI's timestamp order), `exposedSchemas`
 * from its `config.toml`.
 */
export function checkSupabaseMigrations(
  files: readonly MigrationFile[],
  exposedSchemas: readonly string[] = DEFAULT_EXPOSED_SCHEMAS,
): Finding[] {
  const tables = new Map<string, TableState>();
  const policies = new Map<string, PolicyState>();
  const policyKey = (t: { schema: string; name: string }, name: string): string => `${keyOf(t)}\u0000${name}`;

  for (const file of [...files].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0))) {
    for (const st of statementsOf(file)) {
      const sql = st.sql;
      let m: RegExpExecArray | null;
      if ((m = CREATE_TABLE.exec(sql)) !== null) {
        if (m[1] !== undefined) continue; // a temporary table lives in its session only
        const t = qualified(m[2] ?? '');
        const existing = tables.get(keyOf(t));
        if (existing !== undefined && /\bif\s+not\s+exists\b/i.test(sql)) continue;
        tables.set(keyOf(t), { ...t, file: st.file, line: st.line, rls: false, revokedAnon: false, revokedAuthenticated: false });
      } else if ((m = ALTER_TABLE.exec(sql)) !== null) {
        const t = qualified(m[1] ?? '');
        const rest = m[2] ?? '';
        const state = tables.get(keyOf(t));
        if (state === undefined) continue;
        if (/\benable\s+row\s+level\s+security\b/i.test(rest)) {
          state.rls = true;
          delete state.disabled;
        }
        if (/\bdisable\s+row\s+level\s+security\b/i.test(rest)) {
          state.rls = false;
          state.disabled = { file: st.file, line: st.line };
        }
        const renamed = new RegExp(String.raw`\brename\s+to\s+(${IDENT})`, 'i').exec(rest);
        const moved = new RegExp(String.raw`\bset\s+schema\s+(${IDENT})`, 'i').exec(rest);
        if (renamed !== null || moved !== null) {
          const next = {
            schema: moved !== null ? identName(moved[1] ?? '') : state.schema,
            name: renamed !== null ? identName(renamed[1] ?? '') : state.name,
          };
          tables.delete(keyOf(t));
          tables.set(keyOf(next), { ...state, ...next });
          for (const [k, p] of [...policies]) {
            if (keyOf(p.table) !== keyOf(t)) continue;
            policies.delete(k);
            policies.set(policyKey(next, p.name), { ...p, table: next });
          }
        }
      } else if ((m = DROP_TABLE.exec(sql)) !== null) {
        for (const part of (m[1] ?? '').split(',')) {
          const t = qualified(part);
          tables.delete(keyOf(t));
          for (const [k, p] of [...policies]) if (keyOf(p.table) === keyOf(t)) policies.delete(k);
        }
      } else if ((m = CREATE_POLICY.exec(sql)) !== null) {
        const name = identName(m[1] ?? '');
        const table = qualified(m[2] ?? '');
        const rest = m[3] ?? '';
        const command = (/\bfor\s+(all|select|insert|update|delete)\b/i.exec(rest)?.[1] ?? 'all').toLowerCase();
        const using = clause(rest, /\busing\s*\(/i);
        const check = clause(rest, /\bwith\s+check\s*\(/i);
        policies.set(policyKey(table, name), {
          table,
          name,
          command,
          roles: rolesOf(rest) ?? ['public'],
          ...(using !== undefined ? { using } : {}),
          ...(check !== undefined ? { check } : {}),
          file: st.file,
          line: st.line,
        });
      } else if ((m = ALTER_POLICY.exec(sql)) !== null) {
        const name = identName(m[1] ?? '');
        const table = qualified(m[2] ?? '');
        const rest = m[3] ?? '';
        const p = policies.get(policyKey(table, name));
        if (p === undefined) continue;
        const renamed = new RegExp(String.raw`^\s*rename\s+to\s+(${IDENT})`, 'i').exec(rest);
        if (renamed !== null) {
          policies.delete(policyKey(table, name));
          const next = identName(renamed[1] ?? '');
          policies.set(policyKey(table, next), { ...p, name: next });
          continue;
        }
        const roles = rolesOf(rest);
        const using = clause(rest, /\busing\s*\(/i);
        const check = clause(rest, /\bwith\s+check\s*\(/i);
        if (roles !== undefined) p.roles = roles;
        if (using !== undefined) p.using = using;
        if (check !== undefined) p.check = check;
        p.file = st.file;
        p.line = st.line;
      } else if ((m = DROP_POLICY.exec(sql)) !== null) {
        policies.delete(policyKey(qualified(m[2] ?? ''), identName(m[1] ?? '')));
      } else if ((m = REVOKE.exec(sql)) !== null) {
        const privileges = (m[1] ?? '').toLowerCase();
        if (!/\ball\b|\bselect\b/.test(privileges)) continue;
        const grantees = (m[3] ?? '').split(',').map((g) => identName(g.replace(/\b(?:cascade|restrict)\b/gi, '').trim()));
        for (const part of (m[2] ?? '').split(',')) {
          const state = tables.get(keyOf(qualified(part)));
          if (state === undefined) continue;
          if (grantees.includes('anon')) state.revokedAnon = true;
          if (grantees.includes('authenticated')) state.revokedAuthenticated = true;
        }
      }
    }
  }

  const exposed = new Set(exposedSchemas.map((s) => s.toLowerCase()));
  const isExposed = (schema: string): boolean => exposed.has(schema.toLowerCase());
  const findings: Finding[] = [];

  for (const t of tables.values()) {
    if (!isExposed(t.schema) || t.rls) continue;
    if (t.revokedAnon && t.revokedAuthenticated) continue;
    const at = t.disabled ?? { file: t.file, line: t.line };
    const how =
      t.disabled !== undefined
        ? `Row-level security is disabled on ${display(t)} again here`
        : `The table ${display(t)} is created here and no migration enables row-level security on it`;
    findings.push(
      finding('supabase-rls-disabled', 'critical', at, {
        title: `${display(t)} has no row-level security`,
        message:
          `${how}. The ${t.schema} schema is served by Supabase's Data API to anyone holding the anon key — which ` +
          'is in the browser by design — so every visitor can read and write every row (CWE-284). Add ' +
          `\`alter table ${display(t)} enable row level security;\` in a migration, then a policy per operation ` +
          'that compares the row with `auth.uid()`; for a table the API must never serve, revoke it from anon and ' +
          'authenticated or move it to an unexposed schema.',
      }),
    );
  }

  for (const p of policies.values()) {
    if (!isExposed(p.table.schema)) continue;
    if (p.command === 'select') continue;
    if (p.roles.length > 0 && p.roles.every((r) => PRIVILEGED_ROLES.has(r))) continue;
    const exprs = p.command === 'insert' ? [p.check] : p.command === 'delete' ? [p.using] : [p.using, p.check];
    const open = exprs.some(isTrue);
    const anon = p.roles.includes('anon');
    const where = { file: p.file, line: p.line };
    const label = `policy "${p.name}" on ${display(p.table)} (for ${p.command}, to ${p.roles.join(', ')})`;
    if (open) {
      findings.push(
        finding('supabase-policy-open-write', 'high', where, {
          title: `${display(p.table)}: a ${p.command} policy whose check is \`true\``,
          message:
            `The ${label} lets ${anon || p.roles.includes('public') ? 'anyone, logged in or not,' : 'every user it names'} ` +
            `${p.command === 'all' ? 'write' : p.command} any row: a condition of \`true\` checks nothing (CWE-284). ` +
            'Compare the row with the caller — `using ((select auth.uid()) = user_id)` and the same `with check` — ' +
            'or keep writes to server code holding the service-role key.',
        }),
      );
    } else if (anon) {
      findings.push(
        finding('supabase-policy-anon-write', 'high', where, {
          title: `${display(p.table)}: a ${p.command} policy granted to anon`,
          message:
            `The ${label} grants writes to anon — every visitor, with no account (CWE-284). A visitor has no ` +
            '`auth.uid()`, so whatever the condition allows, it allows to anyone holding the public anon key. Grant ' +
            'writes `to authenticated` with a condition on `auth.uid()`, or keep them in server code.',
        }),
      );
    } else if (!exprs.some(readsAuth) && !exprs.every((e) => e === undefined || isFalse(e))) {
      findings.push(
        finding('supabase-policy-no-auth-check', 'low', where, {
          title: `${display(p.table)}: a ${p.command} policy that never reads the caller`,
          message:
            `The ${label} decides without \`auth.uid()\`, \`auth.jwt()\` or \`auth.role()\`: whoever its roles ` +
            'include may write the rows its condition allows, whose they are. That can be right (a helper ' +
            'function that reads the caller itself); if not, compare the row with `auth.uid()`.',
        }),
      );
    }
  }
  return findings;
}

function finding(
  ruleId: string,
  severity: Severity,
  at: { file: string; line: number },
  text: { title: string; message: string },
): Finding {
  return makeFinding({
    tool: CLIENT_TRUST_TOOL,
    rule_id: ruleId,
    severity,
    category: 'security',
    subcategory: 'client-trust',
    title: text.title,
    message: text.message,
    file_path: at.file,
    line_start: at.line,
    line_end: at.line,
    taxonomy: { cwe: ['CWE-284'] },
  });
}
