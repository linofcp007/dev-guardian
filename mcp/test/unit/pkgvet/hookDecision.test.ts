import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
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
    // Never tells the model how to switch the guard off.
    expect(d?.deny).not.toMatch(/GUARDIAN_PKG_VET/);
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
    expect(d?.deny).toMatch(/reqeusts/);
    expect(d?.deny).toMatch(/requests/); // did-you-mean
  });
});
