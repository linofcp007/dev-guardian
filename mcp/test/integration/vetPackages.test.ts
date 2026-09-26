/**
 * `vet_packages` through its registered tool handler. The network is a stub
 * (`vi.stubGlobal('fetch', …)`) that throws on any URL it was not given, and
 * the user-level config locations point at an empty temp home, so neither
 * the real registries nor this machine's own `.npmrc` / `nuget.config` can
 * leak into a result.
 */

import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import type { PluginContext } from '../../src/context.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { TOOLS } from '../../src/tools/index.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

beforeAll(async () => {
  await import('../../src/tools/vetPackages.js');
});
afterAll(cleanupTempDirs);

let home: string;
let project: string;
beforeEach(() => {
  home = makeTempDir('vetpkg-home-');
  project = makeTempDir('vetpkg-project-');
  for (const k of ['HOME', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA', 'ProgramData', 'XDG_CONFIG_HOME', 'COMPOSER_HOME']) {
    vi.stubEnv(k, home);
  }
  for (const k of [
    'npm_config_registry',
    'NPM_CONFIG_REGISTRY',
    'npm_config_userconfig',
    'NPM_CONFIG_USERCONFIG',
    'PIP_INDEX_URL',
    'PIP_EXTRA_INDEX_URL',
    'PIP_CONFIG_FILE',
    'UV_INDEX_URL',
    'UV_EXTRA_INDEX_URL',
    'UV_INDEX',
    'UV_DEFAULT_INDEX',
    'VIRTUAL_ENV',
    'npm_config_globalconfig',
    'NPM_CONFIG_GLOBALCONFIG',
    'UV_CONFIG_FILE',
    'XDG_CONFIG_DIRS',
  ]) {
    vi.stubEnv(k, '');
  }
});
afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

function plugin(): PluginContext {
  const db = new Database(':memory:');
  runMigrations(db);
  return { storage: new Storage(db), shell: null, scriptsDir: process.cwd(), progressNotifier: { send: () => {} } };
}

function tool() {
  const t = TOOLS.find((x) => x.name === 'vet_packages');
  if (t === undefined) throw new Error('vet_packages not registered');
  return t;
}

interface PkgOut {
  name: string;
  verdict: string;
  version?: string;
  reasons: string[];
  checks: Record<string, { status: string }>;
}
interface VetOk {
  ok: true;
  ecosystem: string;
  verdict: string;
  summary: Record<string, number>;
  packages: PkgOut[];
  skipped: Array<{ raw: string; reason: string }>;
  network: string;
}
interface VetErr {
  ok: false;
  error: { code: string; message: string };
}

async function run(input: Record<string, unknown>): Promise<VetOk | VetErr> {
  return (await tool().handler({ project_path: project, ...input }, plugin())) as unknown as VetOk | VetErr;
}

function expectOk(r: VetOk | VetErr): VetOk {
  if (!r.ok) throw new Error(`expected ok, got ${r.error.code}: ${r.error.message}`);
  return r;
}

type Answer = { status: number; body?: unknown };

function stubNetwork(routes: Record<string, Answer | ((body: unknown) => Answer)>): string[] {
  const calls: string[] = [];
  vi.stubGlobal('fetch', async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const url = String(input);
    calls.push(url);
    const route = routes[url];
    if (route === undefined) throw new Error(`unexpected network call: ${url}`);
    const a = typeof route === 'function' ? route(typeof init?.body === 'string' ? JSON.parse(init.body) : undefined) : route;
    return new Response(a.body === undefined ? '' : JSON.stringify(a.body), { status: a.status });
  });
  return calls;
}

const OSV_CLEAN = (body: unknown): Answer => ({
  status: 200,
  body: { results: ((body as { queries: unknown[] }).queries ?? []).map(() => ({})) },
});

const OLD = '2020-01-01T00:00:00.000Z';

describe('vet_packages tool', () => {
  it('is offline under the suite default (GUARDIAN_OFFLINE=1): no request, nothing claimed as ok', async () => {
    const calls = stubNetwork({});
    const r = expectOk(await run({ ecosystem: 'npm', packages: ['left-pad', 'lodahs'] }));
    expect(calls).toEqual([]);
    expect(r.network).toMatch(/GUARDIAN_OFFLINE/);
    expect(r.packages.map((p) => p.verdict)).toEqual(['unknown', 'warn']);
    expect(r.verdict).toBe('warn');
  });

  it('online: blocks a nonexistent name and passes an established one', async () => {
    vi.stubEnv('GUARDIAN_OFFLINE', '0');
    stubNetwork({
      'https://registry.npmjs.org/left-pad': {
        status: 200,
        body: { 'dist-tags': { latest: '1.3.0' }, modified: OLD, versions: { '1.3.0': {} } },
      },
      'https://registry.npmjs.org/left-pad-ultra-ai-helper': { status: 404 },
      'https://api.osv.dev/v1/querybatch': OSV_CLEAN,
    });
    const r = expectOk(await run({ ecosystem: 'npm', packages: ['left-pad', 'left-pad-ultra-ai-helper'] }));
    expect(r.packages.map((p) => [p.name, p.verdict])).toEqual([
      ['left-pad', 'ok'],
      ['left-pad-ultra-ai-helper', 'block'],
    ]);
    expect(r.verdict).toBe('block');
    expect(r.summary).toEqual({ block: 1, warn: 0, unknown: 0, ok: 1 });
  });

  it('uses the project_path registry configuration: a private scope is unknown, not block', async () => {
    vi.stubEnv('GUARDIAN_OFFLINE', '0');
    writeFileSync(join(project, '.npmrc'), '@acme:registry=https://npm.acme.local/\n');
    stubNetwork({
      'https://registry.npmjs.org/@acme%2Finternal': { status: 404 },
      'https://api.osv.dev/v1/querybatch': OSV_CLEAN,
    });
    const r = expectOk(await run({ ecosystem: 'npm', packages: ['@acme/internal'] }));
    expect(r.packages[0]?.verdict).toBe('unknown');
  });

  it('accepts ecosystem aliases (composer -> packagist) and name:constraint', async () => {
    vi.stubEnv('GUARDIAN_OFFLINE', '0');
    stubNetwork({
      'https://repo.packagist.org/p2/monolog/monolog.json': {
        status: 200,
        body: { packages: { 'monolog/monolog': [{ version: '3.5.0', time: OLD }] } },
      },
      'https://api.osv.dev/v1/querybatch': OSV_CLEAN,
    });
    const r = expectOk(await run({ ecosystem: 'composer', packages: ['monolog/monolog:^3'] }));
    expect(r.ecosystem).toBe('packagist');
    expect(r.packages[0]).toMatchObject({ name: 'monolog/monolog', version: '3.5.0', verdict: 'ok' });
  });

  it('a spec that is not a package name is skipped with a reason, and nothing vetted is not ok', async () => {
    const r = expectOk(await run({ ecosystem: 'npm', packages: ['./local-dir'] }));
    expect(r.packages).toEqual([]);
    expect(r.skipped).toEqual([{ raw: './local-dir', reason: expect.stringMatching(/local path/) }]);
    expect(r.verdict).toBe('unknown');
  });

  it('refuses a project_path that is not a directory', async () => {
    const r = await run({ ecosystem: 'npm', packages: ['left-pad'], project_path: join(project, 'nope') });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe('target_not_found');
  });

  it('a private nuget.config source under project_path makes a missing id unknown', async () => {
    vi.stubEnv('GUARDIAN_OFFLINE', '0');
    mkdirSync(join(project, 'src'), { recursive: true });
    writeFileSync(
      join(project, 'NuGet.Config'),
      '<configuration><packageSources><add key="acme" value="https://nuget.acme.local/v3/index.json" /></packageSources></configuration>',
    );
    stubNetwork({
      'https://api.nuget.org/v3-flatcontainer/acme.internal/index.json': { status: 404 },
      'https://api.osv.dev/v1/querybatch': OSV_CLEAN,
    });
    const r = expectOk(await run({ ecosystem: 'nuget', packages: ['Acme.Internal'], project_path: join(project, 'src') }));
    expect(r.packages[0]?.verdict).toBe('unknown');
  });
});
