import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { decideInstallCommand, type HookVetOptions } from '../../../src/pkgvet/hookDecision.js';

const NOW = Date.parse('2026-09-25T12:00:00Z');
const OSV = 'https://api.osv.dev/v1/querybatch';

type Answer = { status?: number; body?: unknown; hang?: boolean };

function fakeFetch(routes: Record<string, Answer | ((body: unknown) => Answer)>): { fetchImpl: typeof fetch; calls: string[] } {
  const calls: string[] = [];
  const fetchImpl = (async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const url = String(input);
    calls.push(url);
    const route = routes[url];
    if (route === undefined) throw new Error(`unexpected network call: ${url}`);
    const a = typeof route === 'function' ? route(typeof init?.body === 'string' ? JSON.parse(init.body) : undefined) : route;
    if (a.hang === true) {
      return new Promise<Response>((_res, reject) => {
        // Like the real fetch: an already-aborted signal rejects at once.
        if (init?.signal?.aborted === true) reject(new DOMException('aborted', 'AbortError'));
        init?.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')));
      });
    }
    return new Response(a.body === undefined ? '' : JSON.stringify(a.body), { status: a.status ?? 200 });
  }) as typeof fetch;
  return { fetchImpl, calls };
}

const osvClean = (body: unknown): Answer => ({ body: { results: (body as { queries: unknown[] }).queries.map(() => ({})) } });
const npmDoc = (v: string, extra: Record<string, unknown> = {}): Answer => ({
  body: { 'dist-tags': { latest: v }, modified: '2020-01-01T00:00:00.000Z', versions: { [v]: extra } },
});

let project: string;
let home: string;
beforeEach(() => {
  project = mkdtempSync(join(tmpdir(), 'pkgvet-hook-'));
  home = mkdtempSync(join(tmpdir(), 'pkgvet-hookhome-'));
});
afterEach(() => {
  rmSync(project, { recursive: true, force: true });
  rmSync(home, { recursive: true, force: true });
});

function opts(fetchImpl: typeof fetch, extra: Partial<HookVetOptions> = {}): HookVetOptions {
  return {
    cwd: project,
    homeDir: home,
    env: { GUARDIAN_OFFLINE: '0' },
    etcDir: join(home, 'no-etc'),
    nodeExecPath: join(home, 'no-node', 'bin', 'node'),
    fetchImpl,
    now: NOW,
    popular: { npm: ['lodash', 'express'], pypi: ['requests'] },
    ...extra,
  };
}

describe('decideInstallCommand', () => {
  it('a command that installs nothing makes no request and returns null', async () => {
    const f = fakeFetch({});
    expect(await decideInstallCommand('git status && npm run build', opts(f.fetchImpl))).toBeNull();
    expect(await decideInstallCommand('npm install', opts(f.fetchImpl))).toBeNull();
    expect(await decideInstallCommand('pip install -r requirements.txt', opts(f.fetchImpl))).toBeNull();
    expect(f.calls).toEqual([]);
  });

  it('DENIES a hallucinated (nonexistent) package, naming it and the reason', async () => {
    const f = fakeFetch({ 'https://registry.npmjs.org/react-magic-form-helperz': { status: 404 }, [OSV]: osvClean });
    const d = await decideInstallCommand('npm install react-magic-form-helperz', opts(f.fetchImpl));
    expect(d?.deny).toMatch(/react-magic-form-helperz/);
    expect(d?.deny).toMatch(/does not exist/);
    // Round 2 ruling: the deny carries its own escape hatch.
    expect(d?.deny).toContain(
      'If this package is private or local, re-run the install with an explicit --registry / --index-url / --source, or set GUARDIAN_PKG_VET=0.',
    );
  });

  it('DENIES a malicious version', async () => {
    const f = fakeFetch({
      'https://registry.npmjs.org/evil-pkg': npmDoc('1.0.0'),
      [OSV]: (body) => ({
        body: { results: (body as { queries: unknown[] }).queries.map(() => ({ vulns: [{ id: 'MAL-2026-1' }] })) },
      }),
    });
    const d = await decideInstallCommand('npm i evil-pkg', opts(f.fetchImpl));
    expect(d?.deny).toMatch(/MAL-2026-1/);
  });

  it('WARNS (does not deny) on typosquat suspicion', async () => {
    const f = fakeFetch({ 'https://registry.npmjs.org/lodahs': npmDoc('1.0.0'), [OSV]: osvClean });
    const d = await decideInstallCommand('npm install lodahs', opts(f.fetchImpl));
    expect(d?.deny).toBeUndefined();
    expect(d?.context).toMatch(/lodahs/);
    expect(d?.context).toMatch(/lodash/);
  });

  it('WARNS on install scripts', async () => {
    const f = fakeFetch({
      'https://registry.npmjs.org/native-thing': npmDoc('2.0.0', { hasInstallScript: true }),
      'https://registry.npmjs.org/native-thing/2.0.0': { body: { scripts: { install: 'node-gyp rebuild' } } },
      [OSV]: osvClean,
    });
    const d = await decideInstallCommand('pnpm add native-thing', opts(f.fetchImpl));
    expect(d?.deny).toBeUndefined();
    expect(d?.context).toMatch(/install scripts/);
  });

  it('an established, clean package is silent', async () => {
    const f = fakeFetch({ 'https://registry.npmjs.org/express': npmDoc('4.21.2'), [OSV]: osvClean });
    expect(await decideInstallCommand('npm install express', opts(f.fetchImpl))).toBeNull();
  });

  it('a private registry configured for the name: no deny — the ruling\'s "not found … ignore this" warning', async () => {
    writeFileSync(join(project, '.npmrc'), 'registry=https://npm.acme.local/\n');
    const f = fakeFetch({ 'https://registry.npmjs.org/acme-private': { status: 404 }, [OSV]: osvClean });
    const d = await decideInstallCommand('npm install acme-private', opts(f.fetchImpl));
    expect(d?.deny).toBeUndefined();
    expect(d?.context).toMatch(/acme-private.*not found on the public registry — if it is private or local, ignore this/s);
    expect(d?.context).toMatch(/custom registry/);
  });

  it('a --registry on the command line also stops a deny', async () => {
    const f = fakeFetch({ 'https://registry.npmjs.org/acme-private': { status: 404 }, [OSV]: osvClean });
    const d = await decideInstallCommand('npm install --registry https://npm.acme.local acme-private', opts(f.fetchImpl));
    expect(d?.deny).toBeUndefined();
    expect(d?.context).toMatch(/not found on the public registry/);
  });

  describe('controller ruling — a missing name is DENIED only under a confident parse', () => {
    const missing = (): ReturnType<typeof fakeFetch> =>
      fakeFetch({
        'https://registry.npmjs.org/react-magic-form-helperz': { status: 404 },
        'https://pypi.org/pypi/react-magic-form-helperz/json': { status: 404 },
        [OSV]: osvClean,
      });

    it.each([
      ['(a) an unknown flag', 'npm install --brand-new-flag x react-magic-form-helperz', /unknown flag --brand-new-flag/],
      ['(b) an inline env assignment', 'NPM_CONFIG_REGISTRY=https://npm.acme.local npm install react-magic-form-helperz', /environment/],
      ['(b) PowerShell $env:', '$env:NPM_CONFIG_REGISTRY="https://npm.acme.local"; npm install react-magic-form-helperz', /environment/],
      ['(c) a cd first', 'cd packages/web && npm install react-magic-form-helperz', /directory/],
      ['(c) --prefix', 'npm install --prefix ./web react-magic-form-helperz', /--prefix/],
      ['(f) yarn workspace', 'yarn workspace web add react-magic-form-helperz', /workspace/],
    ])('%s: warns, does not deny', async (_label, command, why) => {
      const f = missing();
      const d = await decideInstallCommand(command, opts(f.fetchImpl));
      expect(d?.deny).toBeUndefined();
      expect(d?.context).toMatch(/react-magic-form-helperz.*not found on the public registry — if it is private or local, ignore this/s);
      expect(d?.context).toMatch(why);
    });

    it('C1: `pip install -qr req.txt` vets nothing and never looks the file name up', async () => {
      const f = fakeFetch({});
      expect(await decideInstallCommand('pip install -qr req.txt', opts(f.fetchImpl))).toBeNull();
      expect(await decideInstallCommand('pip install -Ur requirements.txt', opts(f.fetchImpl))).toBeNull();
      expect(f.calls).toEqual([]);
    });

    it('a MALICIOUS package is still denied under an uncertain parse', async () => {
      const f = fakeFetch({
        'https://registry.npmjs.org/evil-pkg': npmDoc('1.0.0'),
        [OSV]: (body) => ({ body: { results: (body as { queries: unknown[] }).queries.map(() => ({ vulns: [{ id: 'MAL-2026-2' }] })) } }),
      });
      const d = await decideInstallCommand('cd web && npm i evil-pkg', opts(f.fetchImpl));
      expect(d?.deny).toMatch(/MAL-2026-2/);
    });
  });

  describe('M4 — known vulnerabilities warn in the hook only for an exact pin', () => {
    const vulnerable = (): ReturnType<typeof fakeFetch> =>
      fakeFetch({
        'https://registry.npmjs.org/lodash': {
          body: { 'dist-tags': { latest: '4.17.21' }, modified: '2020-01-01T00:00:00.000Z', versions: { '4.17.20': {}, '4.17.21': {} } },
        },
        [OSV]: (body) => ({
          body: {
            results: (body as { queries: Array<{ version?: string }> }).queries.map(() => ({ vulns: [{ id: 'GHSA-35jh-r3h4-6jhm' }] })),
          },
        }),
      });

    it('unpinned: silent', async () => {
      expect(await decideInstallCommand('npm install lodash', opts(vulnerable().fetchImpl))).toBeNull();
    });

    it('a range: silent', async () => {
      expect(await decideInstallCommand('npm install lodash@^4', opts(vulnerable().fetchImpl))).toBeNull();
    });

    it('an exact pin: warns', async () => {
      const d = await decideInstallCommand('npm install lodash@4.17.20', opts(vulnerable().fetchImpl));
      expect(d?.context).toMatch(/GHSA-35jh-r3h4-6jhm/);
    });
  });

  it('fails open inside the budget when the network hangs: a note, never a claim of vetting', async () => {
    const f = fakeFetch({ 'https://registry.npmjs.org/express': { hang: true }, [OSV]: { hang: true } });
    const t0 = Date.now();
    const d = await decideInstallCommand('npm install express', opts(f.fetchImpl, { budgetMs: 200 }));
    expect(Date.now() - t0).toBeLessThan(2000);
    expect(d?.deny).toBeUndefined();
    expect(d?.context).toMatch(/could not vet/i);
    expect(d?.context).not.toMatch(/\bok\b|vetted and clean/i);
  });

  it('GUARDIAN_OFFLINE=1: no request; a note, and typosquat suspicion still warns', async () => {
    const f = fakeFetch({});
    const d = await decideInstallCommand('npm install lodahs express', opts(f.fetchImpl, { env: { GUARDIAN_OFFLINE: '1' } }));
    expect(f.calls).toEqual([]);
    expect(d?.deny).toBeUndefined();
    expect(d?.context).toMatch(/lodash/);
    expect(d?.context).toMatch(/could not vet/i);
  });

  it('vets every install command in a compound line, across ecosystems', async () => {
    const f = fakeFetch({
      'https://registry.npmjs.org/express': npmDoc('4.21.2'),
      'https://pypi.org/pypi/reqeusts/json': { status: 404 },
      [OSV]: osvClean,
    });
    const d = await decideInstallCommand('npm i express && pip install reqeusts', opts(f.fetchImpl));
    // Round 2: a compound line is never deny-eligible for a missing name — it warns.
    expect(d?.deny).toBeUndefined();
    expect(d?.context).toMatch(/reqeusts.*not found on the public registry/s);
    expect(d?.context).toMatch(/requests/); // did-you-mean
  });
});

// ─────────────────────────────── fix round 2 — the reviewer's probe table

/**
 * A fake public registry: every name in EXISTS is published (old, clean);
 * every other name answers 404; OSV is clean; nuget.org search is down.
 * Built from URL shapes, so any name the parse vets can be answered — and
 * the list of calls shows exactly which names were looked up.
 */
function fakeRegistry(): { fetchImpl: typeof fetch; calls: string[] } {
  const EXISTS = new Set(['npm:express', 'npm:lodash', 'pypi:requests', 'packagist:monolog/monolog', 'nuget:newtonsoft.json']);
  const calls: string[] = [];
  const json = (body: unknown, status = 200): Response => new Response(JSON.stringify(body), { status });
  const fetchImpl = (async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const url = String(input);
    calls.push(url);
    if (url === OSV) return json(osvClean(JSON.parse(String(init?.body))).body);
    let m = /^https:\/\/registry\.npmjs\.org\/([^/]+)$/.exec(url);
    if (m !== null) {
      const name = decodeURIComponent(m[1] ?? '');
      return EXISTS.has(`npm:${name}`) ? json(npmDoc('1.0.0').body) : json({ error: 'Not found' }, 404);
    }
    m = /^https:\/\/pypi\.org\/pypi\/([^/]+)\/json$/.exec(url);
    if (m !== null) {
      return EXISTS.has(`pypi:${decodeURIComponent(m[1] ?? '')}`)
        ? json({ info: { version: '1.0.0' }, releases: { '1.0.0': [{ upload_time_iso_8601: '2020-01-01T00:00:00Z' }] } })
        : json({}, 404);
    }
    m = /^https:\/\/repo\.packagist\.org\/p2\/(.+)\.json$/.exec(url);
    if (m !== null) {
      const name = m[1] ?? '';
      return EXISTS.has(`packagist:${name}`)
        ? json({ packages: { [name]: [{ version: '1.0.0', time: '2020-01-01T00:00:00+00:00' }] } })
        : json({}, 404);
    }
    m = /^https:\/\/api\.nuget\.org\/v3-flatcontainer\/([^/]+)\/index\.json$/.exec(url);
    if (m !== null) return EXISTS.has(`nuget:${m[1] ?? ''}`) ? json({ versions: ['1.0.0'] }) : json({}, 404);
    if (url.startsWith('https://api.nuget.org/v3/registration5-gz-semver2/')) return json({ published: '2020-01-01T00:00:00Z' });
    if (url.startsWith('https://azuresearch-usnc.nuget.org/')) return json({}, 503);
    throw new Error(`unexpected network call: ${url}`);
  }) as typeof fetch;
  return { fetchImpl, calls };
}

describe('round 2 — every probe the reviewer reproduced is a WARN (or silent), never a DENY', () => {
  it.each([
    ['comment', 'pip install requests  # for http calls'],
    ['PowerShell block comment', 'pip install requests <# for http calls #>'],
    ['two dotnet sources, public last', 'dotnet add package Corp.Lib -s https://nuget.corp.local/v3/index.json -s https://api.nuget.org/v3/index.json'],
    ['pip: corp extra index, public -i last', 'pip install --extra-index-url https://pypi.corp.local/simple -i https://pypi.org/simple corp-lib'],
    ['uv pip: corp extra index, public --index-url last', 'uv pip install --extra-index-url https://pypi.corp.local/simple --index-url https://pypi.org/simple corp-lib'],
    ['npm config set, then install', 'npm config set @org:registry https://npm.corp.local && npm i @org/x'],
    ['.npmrc appended, then install', 'echo "@org:registry=https://npm.corp.local" >> .npmrc && npm i @org/x'],
    ['composer config repositories, then require', 'composer config repositories.wpackagist composer https://wpackagist.org && composer require wpackagist-plugin/akismet'],
    ['poetry source add, then add', 'poetry source add corp https://pypi.corp.local/simple && poetry add corp-lib'],
    ['pip config set, then install', 'pip config set global.index-url https://pypi.corp.local/simple && pip install corp-lib'],
    ['dotnet nuget add source, then add', 'dotnet nuget add source https://nuget.corp.local/v3/index.json -n corp && dotnet add package Corp.Lib'],
    ['npm --userconfig', 'npm --userconfig ./corp.npmrc install corp-lib'],
    ['npm --globalconfig', 'npm install --globalconfig ./corp.npmrc corp-lib'],
    ['uv --config-file', 'uv add --config-file ./uv.toml corp-lib'],
    ['bun -c', 'bun add -c ./bunfig.toml corp-lib'],
    ['bun --config', 'bun add --config ./bunfig.toml corp-lib'],
    ['a venv pip by path', '.venv/bin/pip install corp-lib'],
    ['activate, then pip', 'source .venv/bin/activate && pip install corp-lib'],
    ['set -a && source .env', 'set -a && source .env && npm i corp-lib'],
  ])('%s: %s', async (_label, command) => {
    const f = fakeRegistry();
    const d = await decideInstallCommand(command, opts(f.fetchImpl, { popular: {} }));
    expect(d?.deny).toBeUndefined();
    for (const word of ['for', 'http', 'calls']) {
      expect(f.calls.some((u) => u.endsWith(`/pypi/${word}/json`))).toBe(false);
    }
  });

  it.each([
    ['YARN_NPM_REGISTRY_SERVER', 'yarn add corp-lib'],
    ['YARN_REGISTRY', 'yarn add corp-lib'],
    ['BUN_CONFIG_REGISTRY', 'bun add corp-lib'],
    ['npm_config_@corp:registry', 'npm i @corp/lib'],
    ['PIP_INDEX_URL', 'pip install corp-lib'],
    ['UV_DEFAULT_INDEX', 'uv add corp-lib'],
    ['NUGET_PACKAGES', 'dotnet add package Corp.Lib'],
  ])('hook env var %s: %s warns', async (name, command) => {
    const f = fakeRegistry();
    const d = await decideInstallCommand(
      command,
      opts(f.fetchImpl, { popular: {}, env: { GUARDIAN_OFFLINE: '0', [name]: 'https://corp.local/registry' } }),
    );
    expect(d?.deny).toBeUndefined();
    expect(d?.context).toMatch(/not found on the public registry/);
  });

  it('npm default global npmrc (<node prefix>/etc/npmrc) warns', async () => {
    const prefix = join(home, 'node-prefix');
    mkdirSync(join(prefix, 'etc'), { recursive: true });
    writeFileSync(join(prefix, 'etc', 'npmrc'), 'registry=https://npm.corp.local/\n');
    const f = fakeRegistry();
    const d = await decideInstallCommand(
      'npm i corp-lib',
      opts(f.fetchImpl, { popular: {}, platform: 'linux', nodeExecPath: join(prefix, 'bin', 'node') }),
    );
    expect(d?.deny).toBeUndefined();
  });

  it('a nuget.config above the repository root warns', async () => {
    const repo = join(project, 'repo');
    mkdirSync(join(repo, '.git'), { recursive: true });
    writeFileSync(
      join(project, 'nuget.config'),
      '<configuration><packageSources><add key="corp" value="https://nuget.corp.local/v3/index.json" /></packageSources></configuration>',
    );
    const f = fakeRegistry();
    const d = await decideInstallCommand('dotnet add package Corp.Lib', opts(f.fetchImpl, { popular: {}, cwd: repo }));
    expect(d?.deny).toBeUndefined();
  });
});

describe('round 2 — the controls stay DENY (one plain statement, allowlisted flags only)', () => {
  it.each([
    'npm i react-super-hallucinated-utils-zz',
    'pip install reqeusts',
    'composer require zzvendor/notapkg',
    'dotnet add package Acme.Totally.Missing.Pkg',
    'npm i -D hallucinated-zz-pkg',
    'pnpm add -E hallucinated-zz-pkg',
    'yarn add --dev hallucinated-zz-pkg',
    'bun add -d hallucinated-zz-pkg',
    'pip install -U --user hallucinated-zz-pkg',
    'python -m pip install -q hallucinated-zz-pkg',
    'uv add --dev hallucinated-zz-pkg',
    'poetry add --group dev hallucinated-zz-pkg',
    'composer require --dev zzvendor/notapkg',
    'dotnet add package Acme.Totally.Missing.Pkg --version 1.0.0',
    'npm i react-super-hallucinated-utils-zz  # the form helper',
  ])('%s', async (command) => {
    const f = fakeRegistry();
    const d = await decideInstallCommand(command, opts(f.fetchImpl, { popular: { pypi: ['requests'] } }));
    expect(d?.deny).toMatch(/does not exist/);
    expect(d?.deny).toContain('re-run the install with an explicit --registry / --index-url / --source, or set GUARDIAN_PKG_VET=0');
  });

  it('`pip install reqeusts` names the popular package it is close to', async () => {
    const f = fakeRegistry();
    const d = await decideInstallCommand('pip install reqeusts', opts(f.fetchImpl, { popular: { pypi: ['requests'] } }));
    expect(d?.deny).toMatch(/Did you mean 'requests'/);
  });

  it('a MALICIOUS deny carries no escape hatch', async () => {
    const f = fakeFetch({
      'https://registry.npmjs.org/evil-pkg': npmDoc('1.0.0'),
      [OSV]: (body) => ({ body: { results: (body as { queries: unknown[] }).queries.map(() => ({ vulns: [{ id: 'MAL-2026-3' }] })) } }),
    });
    const d = await decideInstallCommand('npm i evil-pkg', opts(f.fetchImpl));
    expect(d?.deny).toMatch(/MAL-2026-3/);
    expect(d?.deny).not.toMatch(/GUARDIAN_PKG_VET/);
  });
});
