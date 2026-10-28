/**
 * The client-trust pass (`clienttrust/clientTrustPass.ts`) on real projects:
 * the `.env*` files git IGNORES are read (`.env.local` is where a
 * browser-exposed secret usually lives, and gitleaks' files pass never reads
 * it), a git-ignored dependency folder is not walked, the migrations of each
 * Supabase directory are read as one database — and scan_sast runs the pass
 * and records its findings without the value ever reaching the database.
 *
 * Secret-shaped values are built at run time: the repository's own secret
 * scan must not find them.
 */

import { spawnSync } from 'node:child_process';
import { mkdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

vi.setConfig({ testTimeout: 120_000 });

vi.mock('../../src/tools/scanHelpers.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/tools/scanHelpers.js')>();
  return { ...actual, scannerAvailable: vi.fn() };
});

import { envFilesState, listEnvFiles, runClientTrustChecks } from '../../src/clienttrust/clientTrustPass.js';
import type { PluginContext } from '../../src/context.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';
import { scannerAvailable } from '../../src/tools/scanHelpers.js';
import type { ToolRun } from '../../src/types.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

afterAll(cleanupTempDirs);
beforeAll(async () => {
  await import('../../src/tools/scanSast.js');
});
beforeEach(() => {
  // No scanner installed: Semgrep and the rest are skipped, the in-process pass still runs.
  vi.mocked(scannerAvailable).mockReset();
  vi.mocked(scannerAvailable).mockResolvedValue(null);
});

const b64 = (o: unknown): string => Buffer.from(JSON.stringify(o)).toString('base64url');
const SERVICE_ROLE = `${b64({ alg: 'HS256', typ: 'JWT' })}.${b64({ iss: 'supabase', role: 'service_role', iat: 1 })}.${'Qw9Z'.repeat(10)}`;
const STRIPE_LIVE = ['sk', 'live', 'Zx9Qw3Er5Ty7Ui9OpAs1Df3Gh5Jk7L'].join('_');

function write(dir: string, rel: string, text: string): void {
  const abs = join(dir, ...rel.split('/'));
  mkdirSync(join(abs, '..'), { recursive: true });
  writeFileSync(abs, text);
}

function git(cwd: string, ...args: string[]): void {
  const r = spawnSync('git', ['-c', 'user.email=t@t', '-c', 'user.name=t', '-c', 'commit.gpgsign=false', ...args], { cwd, encoding: 'utf8' });
  if (r.status !== 0) throw new Error(`git ${args.join(' ')}: ${r.stderr}`);
}

/** A Next.js monorepo: secrets in git-ignored env files, a Supabase project with one table left open. */
function project(): string {
  const dir = makeTempDir('client-trust-');
  git(dir, 'init', '-q');
  write(dir, '.gitignore', '.env*.local\nnode_modules/\n');
  write(dir, '.env.example', 'NEXT_PUBLIC_SUPABASE_URL=\nNEXT_PUBLIC_SUPABASE_ANON_KEY=\n');
  write(dir, '.env.local', `NEXT_PUBLIC_SUPABASE_URL=https://abcd.supabase.co\nNEXT_PUBLIC_SUPABASE_ANON_KEY=${SERVICE_ROLE}\n`);
  write(dir, 'apps/web/.env.production.local', `STRIPE_SECRET_KEY=${STRIPE_LIVE}\nNEXT_PUBLIC_STRIPE_SECRET_KEY=${STRIPE_LIVE}\n`);
  // An ignored dependency folder is one entry of git's listing, never walked.
  write(dir, 'node_modules/pkg/.env', `NEXT_PUBLIC_STRIPE_SECRET_KEY=${STRIPE_LIVE}\n`);
  write(dir, 'supabase/config.toml', '[api]\nschemas = ["public"]\n');
  write(dir, 'supabase/migrations/20240101000000_init.sql', 'create table public.profiles (id uuid primary key);\ncreate table public.notes (id int);\n');
  write(dir, 'supabase/migrations/20240102000000_rls.sql', 'alter table public.profiles enable row level security;\n');
  write(dir, 'src/app.ts', 'export const x = 1;\n');
  git(dir, 'add', '-A');
  git(dir, 'commit', '-qm', 'base');
  return dir;
}

describe('the env files the pass reads', () => {
  it('lists tracked, untracked and git-ignored env files, never inside an ignored dependency folder', async () => {
    const dir = project();
    const listing = await listEnvFiles(dir);
    expect(listing.files).toEqual(['.env.example', '.env.local', 'apps/web/.env.production.local']);
    expect([...listing.ignored].sort()).toEqual(['.env.local', 'apps/web/.env.production.local']);
  });

  it('outside git, walks the directory (bounded) and finds the same files', async () => {
    const dir = makeTempDir('client-trust-nogit-');
    write(dir, '.env.local', `VITE_STRIPE_SECRET=${STRIPE_LIVE}\n`);
    write(dir, 'deep/a/b/.env', 'X=1\n');
    write(dir, 'node_modules/p/.env', 'X=1\n');
    const listing = await listEnvFiles(dir);
    expect(listing.files).toEqual(['.env.local', 'deep/a/b/.env']);
    const r = await runClientTrustChecks(dir);
    expect(r?.findings.map((f) => `${f.file_path}:${f.line_start} ${f.severity}`)).toEqual(['.env.local:1 critical']);
  });

  it('the cache state moves when a git-ignored env file changes', async () => {
    const dir = project();
    const before = await envFilesState(dir);
    write(dir, '.env.local', 'NEXT_PUBLIC_SUPABASE_URL=https://abcd.supabase.co\n');
    expect(await envFilesState(dir)).not.toBe(before);
  });
});

describe('runClientTrustChecks', () => {
  it('whole project: the ignored env files and the open table, each on its line', async () => {
    const dir = project();
    const r = await runClientTrustChecks(dir);
    expect(r).not.toBeNull();
    expect(r?.toolRun).toEqual({
      name: 'guardian-client-trust',
      status: 'ok',
      reason: 'read 3 env file(s) (2 ignored by git, read all the same) and 2 Supabase migration(s)',
    });
    expect(r?.missing).toEqual([]);
    expect(r?.findings.map((f) => `${f.rule_id} ${f.file_path}:${f.line_start} ${f.severity}`).sort()).toEqual([
      'client-env-public-secret .env.local:2 critical',
      'client-env-public-secret apps/web/.env.production.local:2 critical',
      'supabase-rls-disabled supabase/migrations/20240101000000_init.sql:2 critical',
    ]);
  });

  it('with files (a diff): only those env files, every migration of a touched directory, findings kept to the files', async () => {
    const dir = project();
    const onlyRls = await runClientTrustChecks(dir, { files: ['supabase/migrations/20240102000000_rls.sql', 'src/app.ts'] });
    // The open table was created in the other migration: read, but not this diff's file.
    expect(onlyRls?.findings).toEqual([]);
    expect(onlyRls?.toolRun.reason).toBe('read 0 env file(s) and 2 Supabase migration(s)');
    const both = await runClientTrustChecks(dir, { files: ['supabase/migrations/20240101000000_init.sql', '.env.local'] });
    expect(both?.findings.map((f) => f.file_path).sort()).toEqual(['.env.local', 'supabase/migrations/20240101000000_init.sql']);
    expect(await runClientTrustChecks(dir, { files: ['src/app.ts'] })).toBeNull();
  });

  it('.guardianignore keeps a file unread; nothing to check is no entry', async () => {
    const dir = project();
    const r = await runClientTrustChecks(dir, { ignores: (rel) => rel.endsWith('.local') || rel.startsWith('supabase/') });
    expect(r?.findings).toEqual([]);
    expect(r?.toolRun.reason).toBe('read 1 env file(s) and 0 Supabase migration(s)');
    const empty = makeTempDir('client-trust-empty-');
    write(empty, 'index.js', '1;\n');
    expect(await runClientTrustChecks(empty)).toBeNull();
  });
});

describe('scan_sast runs the pass', () => {
  it('records the findings with no value anywhere, and the pass in tools_run', async () => {
    const dir = project();
    const db = new Database(':memory:');
    runMigrations(db);
    const plugin: PluginContext = { storage: new Storage(db), shell: null, scriptsDir: dir, progressNotifier: { send: () => {} } };
    const tool = TOOLS.find((t) => t.name === 'scan_sast');
    if (tool === undefined) throw new Error('scan_sast not registered');
    const r = (await tool.handler({ project_path: dir, force: true }, plugin)) as unknown as {
      ok: boolean;
      scan_id: string;
      tools_run: ToolRun[];
    };
    expect(r.ok).toBe(true);
    expect(r.tools_run.find((t) => t.name === 'guardian-client-trust')?.status).toBe('ok');
    const stored = plugin.storage.findings.listByScan(r.scan_id).filter((f) => f.tool === 'guardian-client-trust');
    expect(stored.map((f) => f.rule_id).sort()).toEqual(['client-env-public-secret', 'client-env-public-secret', 'supabase-rls-disabled']);
    const everything = JSON.stringify(plugin.storage.findings.listByScan(r.scan_id)) + JSON.stringify(r);
    expect(everything.includes(SERVICE_ROLE)).toBe(false);
    expect(everything.includes(STRIPE_LIVE)).toBe(false);
    expect(everything.includes(STRIPE_LIVE.slice(0, 14))).toBe(false);
  });
});

// Fix round 1, item 4: an env file that is no regular file of the project is
// skipped with a note — never read (a FIFO would block), never a gap (a gap
// held every scan, and dev-spec-driven's finish, at exit 2).
describe('an env file the pass must not read', () => {
  it('one over the cap: skipped with a note, no gap, and not counted as read', async () => {
    const dir = project();
    write(dir, '.env.local', `X=${'y'.repeat(300 * 1024)}\n`);
    const r = await runClientTrustChecks(dir);
    expect(r?.missing).toEqual([]);
    expect(r?.toolRun.reason).toMatch(/^read 2 env file\(s\) \(1 ignored by git, read all the same\) and 2 Supabase migration\(s\); \.env\.local skipped: it is larger than the size cap/);
  });

  it('a link out of the project (a worktree linked to the main checkout): skipped, no gap', async () => {
    const dir = project();
    const outside = makeTempDir('client-trust-outside-');
    write(outside, 'real.env', `NEXT_PUBLIC_STRIPE_SECRET_KEY=${STRIPE_LIVE}\n`);
    rmSync(join(dir, '.env.local'));
    try {
      symlinkSync(join(outside, 'real.env'), join(dir, '.env.local'), 'file');
    } catch (e) {
      // Windows without the symlink privilege: nothing to test here.
      if ((e as NodeJS.ErrnoException).code === 'EPERM') return;
      throw e;
    }
    const r = await runClientTrustChecks(dir);
    expect(r?.missing).toEqual([]);
    expect(r?.toolRun.reason).toMatch(/\.env\.local skipped: it resolves outside the project/);
    expect(r?.findings.some((f) => f.file_path === '.env.local')).toBe(false);
  });

  it.skipIf(process.platform === 'win32')('a FIFO (a secrets manager mount): never opened for a blocking read, no gap', async () => {
    const dir = project();
    rmSync(join(dir, '.env.local'));
    const made = spawnSync('mkfifo', [join(dir, '.env.local')]);
    if (made.status !== 0) return;
    const r = await runClientTrustChecks(dir);
    expect(r?.missing).toEqual([]);
    expect(r?.toolRun.reason).toMatch(/\.env\.local skipped: it is not a regular file/);
  });
});
