/**
 * Supabase migrations without RLS, or with policies that let anyone write
 * (`clienttrust/supabaseRls.ts`). Pure: migrations in, findings out — read
 * across files in name order, with quoting, casing and schema-qualified names,
 * and with comments, strings and dollar-quoted bodies never read as SQL.
 */

import { describe, expect, it } from 'vitest';
import {
  blankSqlNoise,
  checkSupabaseMigrations,
  DEFAULT_EXPOSED_SCHEMAS,
  exposedSchemasFrom,
  type MigrationFile,
} from '../../../src/clienttrust/supabaseRls.js';

const DIR = 'supabase/migrations';
const m = (name: string, text: string): MigrationFile => ({ path: `${DIR}/${name}`, text });

/** `rule file:line` of every finding, sorted. */
function rows(files: MigrationFile[], schemas?: string[]): string[] {
  return checkSupabaseMigrations(files, schemas)
    .map((f) => `${f.rule_id} ${f.file_path}:${f.line_start} ${f.severity}`)
    .sort();
}

describe('supabase-rls-disabled', () => {
  it('a public table no migration enables RLS on: critical, on its create line', () => {
    const files = [
      m('20240101000000_init.sql', ['-- profiles', 'create table public.profiles (', '  id uuid primary key', ');', '', 'create table todos (id int);'].join('\n')),
    ];
    expect(rows(files)).toEqual([
      `supabase-rls-disabled ${DIR}/20240101000000_init.sql:2 critical`,
      `supabase-rls-disabled ${DIR}/20240101000000_init.sql:6 critical`,
    ]);
    const f = checkSupabaseMigrations(files)[0];
    expect(f?.tool).toBe('guardian-client-trust');
    expect(f?.title).toBe('public.profiles has no row-level security');
    expect(f?.message).toMatch(/alter table public\.profiles enable row level security/);
    expect(f?.cwe).toEqual(['CWE-284']);
  });

  it('RLS enabled in a LATER migration, in any spelling of the name, clears it', () => {
    const files = [
      m('20240101_a.sql', 'CREATE TABLE IF NOT EXISTS "public"."Orders" (id int);\ncreate table public.items (id int);\ncreate table Notes (id int);'),
      m('20240102_b.sql', 'alter table "public"."Orders" enable row level security;\nALTER TABLE ONLY public.ITEMS ENABLE ROW LEVEL SECURITY;\nalter table if exists notes enable row level security, force row level security;'),
    ];
    expect(rows(files)).toEqual([]);
  });

  it('a quoted name keeps its case: enabling "Orders" does not enable orders', () => {
    const files = [m('1.sql', 'create table "Orders" (id int);\ncreate table orders (id int);\nalter table "Orders" enable row level security;')];
    expect(rows(files)).toEqual([`supabase-rls-disabled ${DIR}/1.sql:2 critical`]);
  });

  it('disabled again later: reported on the disabling line; then dropped: nothing', () => {
    const base = m('1.sql', 'create table t (id int);\nalter table t enable row level security;');
    const disable = m('2.sql', '\n\nalter table public.t disable row level security;');
    expect(rows([base, disable])).toEqual([`supabase-rls-disabled ${DIR}/2.sql:3 critical`]);
    expect(rows([base, disable, m('3.sql', 'drop table if exists other, public.t cascade;')])).toEqual([]);
  });

  it('files are read in name (timestamp) order, whatever order they are given in', () => {
    const files = [m('20240102_enable.sql', 'alter table t enable row level security;'), m('20240101_create.sql', 'create table t (id int);')];
    expect(rows(files)).toEqual([]);
  });

  it('a rename carries the state; a move to an unexposed schema takes the table out of the API', () => {
    expect(rows([m('1.sql', 'create table a (id int);\nalter table a rename to b;\nalter table b enable row level security;')])).toEqual([]);
    expect(rows([m('1.sql', 'create table a (id int);\nalter table a set schema private;')])).toEqual([]);
  });

  it('only exposed schemas: a table in private / auth / extensions, and a temporary table, are not served', () => {
    const files = [m('1.sql', 'create table private.secrets (id int);\ncreate temp table scratch (id int);\ncreate table extensions.x (id int);')];
    expect(rows(files)).toEqual([]);
    // config.toml can expose another schema
    expect(rows(files, ['public', 'private'])).toEqual([`supabase-rls-disabled ${DIR}/1.sql:1 critical`]);
  });

  it('a table revoked from anon AND authenticated is not served; from anon alone it still is', () => {
    const both = m('1.sql', 'create table jobs (id int);\nrevoke all on table public.jobs from anon, authenticated;');
    expect(rows([both])).toEqual([]);
    const anonOnly = m('1.sql', 'create table jobs (id int);\nrevoke select, insert on jobs from anon;');
    expect(rows([anonOnly])).toEqual([`supabase-rls-disabled ${DIR}/1.sql:1 critical`]);
  });

  it('never reads SQL inside a comment, a string or a dollar-quoted function body', () => {
    const files = [
      m(
        '1.sql',
        [
          'create table t (id int);',
          '-- alter table t enable row level security;',
          '/* alter table t enable row level security; */',
          "select 'alter table t enable row level security;';",
          'create function f() returns void as $$ begin create table inner_table (id int); end; $$ language plpgsql;',
          'create function g() returns void as $body$ alter table t enable row level security; $body$ language sql;',
        ].join('\n'),
      ),
    ];
    expect(rows(files)).toEqual([`supabase-rls-disabled ${DIR}/1.sql:1 critical`]);
  });

  it('blankSqlNoise keeps lines and offsets, and quoted identifiers', () => {
    const text = "a -- c\n'x;y' \"Q;\" $$z;$$ b";
    const out = blankSqlNoise(text);
    expect(out.length).toBe(text.length);
    expect(out.split('\n').length).toBe(2);
    expect(out).toContain('"Q;"');
    expect(out).not.toContain('x;y');
    expect(out).not.toContain('z;');
  });
});

describe('write policies', () => {
  const rls = 'create table posts (id int, user_id uuid);\nalter table posts enable row level security;\n';

  it('using (true) / with check (true) for a write: high; for select: nothing', () => {
    const files = [
      m(
        '1.sql',
        rls +
          [
            'create policy "read all" on posts for select using (true);',
            'create policy "insert any" on posts for insert with check (true);',
            'create policy "update any" on public.posts for update to authenticated using ( TRUE );',
            'create policy "delete own" on posts for delete using (auth.uid() = user_id);',
          ].join('\n'),
      ),
    ];
    expect(rows(files)).toEqual([`supabase-policy-open-write ${DIR}/1.sql:4 high`, `supabase-policy-open-write ${DIR}/1.sql:5 high`]);
    const open = checkSupabaseMigrations(files).find((f) => f.line_start === 4);
    expect(open?.message).toMatch(/anyone, logged in or not/);
  });

  it('a write policy granted to anon: high, even with a condition', () => {
    const files = [m('1.sql', `${rls}create policy p on posts as permissive for insert to anon with check (char_length(title) > 0);`)];
    expect(rows(files)).toEqual([`supabase-policy-anon-write ${DIR}/1.sql:3 high`]);
  });

  it('a write policy that never reads the caller: low; one for service_role only, or reading auth.uid(): nothing', () => {
    const files = [
      m(
        '1.sql',
        rls +
          [
            'create policy "by org" on posts for update using (org_id = 7);',
            'create policy "svc" on posts for all to service_role using (true) with check (true);',
            'create policy "own" on posts for all to authenticated using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);',
            'create policy "jwt" on posts for insert with check ((auth.jwt() ->> \'role\') = \'admin\');',
          ].join('\n'),
      ),
    ];
    expect(rows(files)).toEqual([`supabase-policy-no-auth-check ${DIR}/1.sql:3 low`]);
  });

  it('a dropped policy, or one altered to read the caller, is judged as it ends', () => {
    const files = [
      m('1.sql', `${rls}create policy "w" on posts for insert with check (true);\ncreate policy "u" on posts for update using (true);`),
      m('2.sql', 'drop policy if exists "w" on public.posts;\nalter policy "u" on posts using (auth.uid() = user_id) with check (auth.uid() = user_id);'),
    ];
    expect(rows(files)).toEqual([]);
  });
});

describe('exposedSchemasFrom', () => {
  it('reads [api] schemas, and defaults without the file or the key', () => {
    expect(exposedSchemasFrom(undefined)).toEqual(DEFAULT_EXPOSED_SCHEMAS);
    expect(exposedSchemasFrom('[db]\nport = 54322\n')).toEqual(DEFAULT_EXPOSED_SCHEMAS);
    expect(exposedSchemasFrom('[api]\nenabled = true\n# Schemas to expose\nschemas = ["public", "api"]\n[db]\nschemas = ["x"]\n')).toEqual([
      'public',
      'api',
    ]);
    expect(exposedSchemasFrom('[api]\nschemas = [\n  "public",\n  \'storage\',\n]\n')).toEqual(['public', 'storage']);
  });

  it('[api] enabled = false: no Data API, nothing exposed, no RLS finding', () => {
    const config = '[api]\nenabled = false # no REST\nschemas = ["public"]\n[db]\nenabled = true\n';
    expect(exposedSchemasFrom(config)).toEqual([]);
    expect(rows([m('1.sql', 'create table public.t (id int);')], exposedSchemasFrom(config))).toEqual([]);
    // [db] enabled = false says nothing about the API.
    expect(exposedSchemasFrom('[db]\nenabled = false\n')).toEqual(DEFAULT_EXPOSED_SCHEMAS);
  });
});
