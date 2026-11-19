/**
 * `vetPackages` over a fully mocked network. Every request goes through
 * `fakeFetch`, which throws on any URL it was not given a route for — so no
 * test in this file can reach a real registry.
 */

import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { nugetSearchUrl } from '../../../src/pkgvet/registry.js';
import type { PackageSpec, PackageVetResult, PkgEcosystem } from '../../../src/pkgvet/types.js';
import { TOOL_BUDGET_MS, vetPackages, type VetOptions } from '../../../src/pkgvet/vet.js';
import { hangBound, PERF_STRICT } from '../../helpers/timing.js';

const NOW = Date.parse('2026-09-25T12:00:00Z');
const DAY = 24 * 3600 * 1000;
const iso = (msAgo: number): string => new Date(NOW - msAgo).toISOString();

type Route = { status?: number; body?: unknown; hang?: boolean } | ((init: RequestInit | undefined) => { status?: number; body?: unknown });

interface Fake {
  fetchImpl: typeof fetch;
  calls: Array<{ url: string; body?: unknown }>;
}

function fakeFetch(routes: Record<string, Route>): Fake {
  const calls: Fake['calls'] = [];
  const fetchImpl = (async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const url = String(input);
    const body = typeof init?.body === 'string' ? (JSON.parse(init.body) as unknown) : undefined;
    calls.push({ url, body });
    const route = routes[url];
    if (route === undefined) throw new Error(`unexpected network call: ${url}`);
    const r = typeof route === 'function' ? route(init) : route;
    if ('hang' in r && r.hang === true) {
      return new Promise<Response>((_resolve, reject) => {
        const signal = init?.signal;
        if (signal?.aborted) reject(new DOMException('aborted', 'AbortError'));
        signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')));
      });
    }
    return new Response(r.body === undefined ? '' : JSON.stringify(r.body), { status: r.status ?? 200 });
  }) as typeof fetch;
  return { fetchImpl, calls };
}

const OSV = 'https://api.osv.dev/v1/querybatch';

/** An OSV route answering each query by `name@version` from `vulns`. */
function osvRoute(vulns: Record<string, string[]> = {}): Route {
  return (init) => {
    const body = JSON.parse(String(init?.body)) as { queries: Array<{ package: { name: string }; version?: string }> };
    return {
      body: {
        results: body.queries.map((q) => {
          const ids = vulns[`${q.package.name}@${q.version ?? ''}`] ?? [];
          return ids.length > 0 ? { vulns: ids.map((id) => ({ id, modified: '2026-01-01T00:00:00Z' })) } : {};
        }),
      },
    };
  };
}

function npmAbbrev(name: string, opts: { versions: string[]; latest: string; modifiedAgo?: number; installScript?: string[] }): unknown {
  return {
    name,
    'dist-tags': { latest: opts.latest },
    modified: iso(opts.modifiedAgo ?? 400 * DAY),
    versions: Object.fromEntries(
      opts.versions.map((v) => [v, { name, version: v, ...(opts.installScript?.includes(v) ? { hasInstallScript: true } : {}) }]),
    ),
  };
}

const spec = (ecosystem: PkgEcosystem, name: string, range?: string): PackageSpec =>
  range === undefined ? { ecosystem, name, raw: name } : { ecosystem, name, range, raw: `${name}@${range}` };

let project: string;
let home: string;
beforeEach(() => {
  project = mkdtempSync(join(tmpdir(), 'pkgvet-vet-'));
  home = mkdtempSync(join(tmpdir(), 'pkgvet-home-'));
});
afterEach(() => {
  rmSync(project, { recursive: true, force: true });
  rmSync(home, { recursive: true, force: true });
});

function opts(fake: Fake, extra: Partial<VetOptions> = {}): VetOptions {
  return {
    fetchImpl: fake.fetchImpl,
    now: NOW,
    offline: false,
    budgetMs: 2000,
    popular: { npm: ['express', 'lodash', 'react'], pypi: ['requests'], packagist: ['monolog/monolog'], nuget: ['Newtonsoft.Json'] },
    registry: { projectDir: project, homeDir: home, env: {}, etcDir: join(home, 'no-etc'), nodeExecPath: join(home, 'no-node', 'bin', 'node') },
    ...extra,
  };
}

describe('vetPackages — npm', () => {
  it('an established package with nothing wrong is ok, and every check says pass', async () => {
    const fake = fakeFetch({
      'https://registry.npmjs.org/left-pad': { body: npmAbbrev('left-pad', { versions: ['1.3.0'], latest: '1.3.0' }) },
      [OSV]: osvRoute(),
    });
    const [r] = await vetPackages([spec('npm', 'left-pad')], opts(fake));
    expect(r).toMatchObject({ name: 'left-pad', version: '1.3.0', verdict: 'ok' });
    expect(r?.checks.exists.status).toBe('pass');
    expect(r?.checks.malicious.status).toBe('pass');
    expect(r?.checks.vulnerabilities.status).toBe('pass');
    expect(r?.checks.publish_age.status).toBe('pass');
    expect(r?.checks.install_scripts.status).toBe('pass');
    expect(r?.checks.typosquat.status).toBe('pass');
    // OSV was asked about the RESOLVED version, not the package in general.
    const osvCall = fake.calls.find((c) => c.url === OSV);
    expect(osvCall?.body).toEqual({ queries: [{ package: { name: 'left-pad', ecosystem: 'npm' }, version: '1.3.0' }] });
  });

  it('a name the registry has never heard of is BLOCKED as likely hallucinated', async () => {
    const fake = fakeFetch({
      'https://registry.npmjs.org/expresss-validator-pro': { status: 404, body: { error: 'Not found' } },
      [OSV]: osvRoute(),
    });
    const [r] = await vetPackages([spec('npm', 'expresss-validator-pro')], opts(fake));
    expect(r?.verdict).toBe('block');
    expect(r?.checks.exists.status).toBe('fail');
    expect(r?.reasons[0]).toMatch(/does not exist|hallucinated/i);
  });

  it('a missing name with a custom registry configured is UNKNOWN, never block (private package)', async () => {
    writeFileSync(join(project, '.npmrc'), 'registry=https://npm.acme.local/\n');
    const fake = fakeFetch({
      'https://registry.npmjs.org/acme-internal-lib': { status: 404 },
      [OSV]: osvRoute(),
    });
    const [r] = await vetPackages([spec('npm', 'acme-internal-lib')], opts(fake));
    expect(r?.verdict).toBe('unknown');
    expect(r?.checks.exists.status).toBe('unknown');
    expect(r?.reasons.join(' ')).toMatch(/custom registry/i);
    expect(r?.reasons.join(' ')).toContain('.npmrc');
  });

  it('ruling (e): a scoped 404 with an npmjs auth token configured is UNKNOWN (private scoped package)', async () => {
    writeFileSync(join(project, '.npmrc'), '//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n');
    const fake = fakeFetch({ 'https://registry.npmjs.org/@acme%2Fprivate': { status: 404 }, [OSV]: osvRoute() });
    const [r] = await vetPackages([spec('npm', '@acme/private')], opts(fake));
    expect(r?.verdict).toBe('unknown');
    expect(r?.not_on_public_registry).toBe(true);
    expect(r?.reasons.join(' ')).toMatch(/auth token/i);
  });

  it('ruling (f): a local workspace package that 404s is UNKNOWN, naming the manifest', async () => {
    writeFileSync(join(project, 'package.json'), JSON.stringify({ workspaces: ['packages/*'] }));
    mkdirSync(join(project, 'packages', 'ui'), { recursive: true });
    writeFileSync(join(project, 'packages', 'ui', 'package.json'), JSON.stringify({ name: 'acme-ui-kit' }));
    const fake = fakeFetch({ 'https://registry.npmjs.org/acme-ui-kit': { status: 404 }, [OSV]: osvRoute() });
    const [r] = await vetPackages([spec('npm', 'acme-ui-kit')], opts(fake));
    expect(r?.verdict).toBe('unknown');
    expect(r?.reasons.join(' ')).toMatch(/workspace package/i);
  });

  it('a confident 404 is marked not_on_public_registry as well as blocked', async () => {
    const fake = fakeFetch({ 'https://registry.npmjs.org/zz-nope-zz': { status: 404 }, [OSV]: osvRoute() });
    const [r] = await vetPackages([spec('npm', 'zz-nope-zz')], opts(fake));
    expect(r).toMatchObject({ verdict: 'block', not_on_public_registry: true });
  });

  it('a registry named on the command line counts as a custom registry too', async () => {
    const fake = fakeFetch({ 'https://registry.npmjs.org/acme-internal-lib': { status: 404 }, [OSV]: osvRoute() });
    const [r] = await vetPackages([spec('npm', 'acme-internal-lib')], opts(fake, { commandRegistries: ['https://npm.acme.local'] }));
    expect(r?.verdict).toBe('unknown');
  });

  it('naming the PUBLIC registry on the command line is not a custom registry', async () => {
    const fake = fakeFetch({ 'https://registry.npmjs.org/acme-internal-lib': { status: 404 }, [OSV]: osvRoute() });
    const [r] = await vetPackages([spec('npm', 'acme-internal-lib')], opts(fake, { commandRegistries: ['https://registry.npmjs.org/'] }));
    expect(r?.verdict).toBe('block');
  });

  it('round 2: several registries on the command line — ANY non-public one counts', async () => {
    const fake = fakeFetch({ 'https://registry.npmjs.org/acme-internal-lib': { status: 404 }, [OSV]: osvRoute() });
    const [r] = await vetPackages(
      [spec('npm', 'acme-internal-lib')],
      opts(fake, { commandRegistries: ['https://npm.acme.local', 'https://registry.npmjs.org/'] }),
    );
    expect(r?.verdict).toBe('unknown');
  });

  it('round 2: publish age is not rounded up — ~60 h is "60 h", 100 h is "4.2 days"', async () => {
    const fake = fakeFetch({
      'https://pypi.org/pypi/fresh-lib/json': {
        body: { info: { version: '2.0.0' }, releases: { '1.0.0': [{ upload_time_iso_8601: iso(100 * 3600 * 1000) }], '2.0.0': [{ upload_time_iso_8601: iso(60 * 3600 * 1000) }] } },
      },
      [OSV]: osvRoute(),
    });
    const [fresh, older] = await vetPackages([spec('pypi', 'fresh-lib'), spec('pypi', 'fresh-lib', '==1.0.0')], opts(fake));
    expect(fresh?.checks.publish_age.detail).toMatch(/published 60 h ago/);
    expect(older?.checks.publish_age.detail).toBe('published 4.2 days ago');
  });

  it('a MAL- advisory on the version that would install is BLOCKED', async () => {
    const fake = fakeFetch({
      'https://registry.npmjs.org/chalk': { body: npmAbbrev('chalk', { versions: ['5.6.0', '5.6.1'], latest: '5.6.1' }) },
      [OSV]: osvRoute({ 'chalk@5.6.1': ['MAL-2025-46969', 'GHSA-xxxx'] }),
    });
    const [r] = await vetPackages([spec('npm', 'chalk')], opts(fake));
    expect(r?.verdict).toBe('block');
    expect(r?.checks.malicious.status).toBe('fail');
    expect(r?.malicious_ids).toEqual(['MAL-2025-46969']);
  });

  it('asks OSV about the version the RANGE resolves to', async () => {
    const fake = fakeFetch({
      'https://registry.npmjs.org/chalk': { body: npmAbbrev('chalk', { versions: ['4.1.2', '5.6.0', '5.6.1'], latest: '5.6.1' }) },
      [OSV]: osvRoute({ 'chalk@5.6.1': ['MAL-2025-46969'] }),
    });
    const [r] = await vetPackages([spec('npm', 'chalk', '^4')], opts(fake));
    expect(r?.version).toBe('4.1.2');
    expect(r?.verdict).toBe('ok');
  });

  it('npm security placeholder (0.0.1-security) is BLOCKED: npm took the package down as malicious', async () => {
    const fake = fakeFetch({
      'https://registry.npmjs.org/crossenv': { body: npmAbbrev('crossenv', { versions: ['0.0.1-security'], latest: '0.0.1-security' }) },
      [OSV]: osvRoute(),
    });
    const [r] = await vetPackages([spec('npm', 'crossenv')], opts(fake));
    expect(r?.verdict).toBe('block');
    expect(r?.reasons.join(' ')).toMatch(/security placeholder/i);
  });

  it('the placeholder is sometimes 0.0.2-security (measured live on crossenv) — also BLOCKED', async () => {
    const fake = fakeFetch({
      'https://registry.npmjs.org/crossenv': { body: npmAbbrev('crossenv', { versions: ['0.0.2-security'], latest: '0.0.2-security' }) },
      [OSV]: osvRoute(),
    });
    const [r] = await vetPackages([spec('npm', 'crossenv')], opts(fake));
    expect(r?.verdict).toBe('block');
  });

  it('known (non-malicious) vulnerabilities on the version WARN', async () => {
    const fake = fakeFetch({
      'https://registry.npmjs.org/lodash': { body: npmAbbrev('lodash', { versions: ['4.17.20', '4.17.21'], latest: '4.17.21' }) },
      [OSV]: osvRoute({ 'lodash@4.17.20': ['GHSA-35jh-r3h4-6jhm'] }),
    });
    const [r] = await vetPackages([spec('npm', 'lodash', '4.17.20')], opts(fake));
    expect(r?.verdict).toBe('warn');
    expect(r?.checks.vulnerabilities.status).toBe('warn');
    expect(r?.vulnerability_ids).toEqual(['GHSA-35jh-r3h4-6jhm']);
  });

  it('a version published less than 72 h ago WARNS (fetches the full document only then)', async () => {
    const fake = fakeFetch({
      'https://registry.npmjs.org/fresh-pkg': (init) => {
        const accept = new Headers(init?.headers).get('accept') ?? '';
        return accept.includes('install-v1')
          ? { body: npmAbbrev('fresh-pkg', { versions: ['1.0.0', '1.0.1'], latest: '1.0.1', modifiedAgo: 5 * 3600 * 1000 }) }
          : { body: { name: 'fresh-pkg', time: { '1.0.0': iso(90 * DAY), '1.0.1': iso(5 * 3600 * 1000) }, versions: { '1.0.1': { scripts: {} } } } };
      },
      [OSV]: osvRoute(),
    });
    const [r] = await vetPackages([spec('npm', 'fresh-pkg')], opts(fake));
    expect(r?.verdict).toBe('warn');
    expect(r?.checks.publish_age.status).toBe('warn');
    expect(r?.reasons.join(' ')).toMatch(/5 h ago|72 h/);
    expect(r?.published_at).toBe(iso(5 * 3600 * 1000));
  });

  it('does NOT fetch the full document when the package has not changed in 72 h', async () => {
    const fake = fakeFetch({
      'https://registry.npmjs.org/old-pkg': { body: npmAbbrev('old-pkg', { versions: ['1.0.0'], latest: '1.0.0', modifiedAgo: 30 * DAY }) },
      [OSV]: osvRoute(),
    });
    const [r] = await vetPackages([spec('npm', 'old-pkg')], opts(fake));
    expect(r?.checks.publish_age.status).toBe('pass');
    expect(fake.calls.filter((c) => c.url === 'https://registry.npmjs.org/old-pkg')).toHaveLength(1);
  });

  it('install scripts WARN, naming them', async () => {
    const fake = fakeFetch({
      'https://registry.npmjs.org/esbuild': { body: npmAbbrev('esbuild', { versions: ['0.28.2'], latest: '0.28.2', installScript: ['0.28.2'] }) },
      'https://registry.npmjs.org/esbuild/0.28.2': { body: { name: 'esbuild', version: '0.28.2', scripts: { postinstall: 'node install.js', test: 'x' } } },
      [OSV]: osvRoute(),
    });
    const [r] = await vetPackages([spec('npm', 'esbuild')], opts(fake));
    expect(r?.verdict).toBe('warn');
    expect(r?.checks.install_scripts.status).toBe('warn');
    expect(r?.install_scripts).toEqual(['postinstall']);
  });

  it('a near-miss of a popular name WARNS as typosquat suspicion', async () => {
    const fake = fakeFetch({
      'https://registry.npmjs.org/lodahs': { body: npmAbbrev('lodahs', { versions: ['1.0.0'], latest: '1.0.0' }) },
      [OSV]: osvRoute(),
    });
    const [r] = await vetPackages([spec('npm', 'lodahs')], opts(fake));
    expect(r?.verdict).toBe('warn');
    expect(r?.similar_to).toBe('lodash');
  });

  it('an exact version that is not published WARNS', async () => {
    const fake = fakeFetch({
      'https://registry.npmjs.org/left-pad': { body: npmAbbrev('left-pad', { versions: ['1.3.0'], latest: '1.3.0' }) },
      [OSV]: osvRoute(),
    });
    const [r] = await vetPackages([spec('npm', 'left-pad', '9.9.9')], opts(fake));
    expect(r?.verdict).toBe('warn');
    expect(r?.reasons.join(' ')).toMatch(/9\.9\.9.*not published/);
    expect(r?.requested_version_unpublished).toBe(true);
  });
});

describe('vetPackages — unknown is never ok', () => {
  it('a registry that never answers inside the budget is UNKNOWN, and the budget is enforced', async () => {
    const fake = fakeFetch({ 'https://registry.npmjs.org/left-pad': { hang: true }, [OSV]: { hang: true } });
    const t0 = Date.now();
    const [r] = await vetPackages([spec('npm', 'left-pad')], opts(fake, { budgetMs: 150 }));
    expect(Date.now() - t0).toBeLessThan(hangBound(2000));
    expect(r?.verdict).toBe('unknown');
    expect(r?.checks.exists.status).toBe('unknown');
    expect(r?.reasons.join(' ')).toMatch(/budget|timed out/i);
  });

  it('HTTP 429 is UNKNOWN with the rate limit as the reason', async () => {
    const fake = fakeFetch({ 'https://registry.npmjs.org/left-pad': { status: 429 }, [OSV]: osvRoute() });
    const [r] = await vetPackages([spec('npm', 'left-pad')], opts(fake));
    expect(r?.verdict).toBe('unknown');
    expect(r?.reasons.join(' ')).toMatch(/rate limited/i);
  });

  it('registry down, OSV up: OSV is asked about the NAME, and a clean answer is a real malware pass', async () => {
    const fake = fakeFetch({ 'https://registry.npmjs.org/left-pad': { status: 503 }, [OSV]: osvRoute() });
    const [r] = await vetPackages([spec('npm', 'left-pad')], opts(fake));
    expect(r?.checks.malicious.status).toBe('pass');
    expect(r?.verdict).toBe('unknown');
    const osvCall = fake.calls.find((c) => c.url === OSV);
    expect(osvCall?.body).toEqual({ queries: [{ package: { name: 'left-pad', ecosystem: 'npm' } }] });
  });

  it('registry down, OSV lists a MAL- advisory on some version: a warning, not a block', async () => {
    const fake = fakeFetch({ 'https://registry.npmjs.org/left-pad': { status: 503 }, [OSV]: osvRoute({ 'left-pad@': ['MAL-2026-9'] }) });
    const [r] = await vetPackages([spec('npm', 'left-pad')], opts(fake));
    expect(r?.checks.malicious.status).toBe('warn');
    expect(r?.verdict).toBe('warn');
  });

  it('OSV being down makes the malware check UNKNOWN, so the verdict cannot be ok', async () => {
    const fake = fakeFetch({
      'https://registry.npmjs.org/left-pad': { body: npmAbbrev('left-pad', { versions: ['1.3.0'], latest: '1.3.0' }) },
      [OSV]: { status: 503 },
    });
    const [r] = await vetPackages([spec('npm', 'left-pad')], opts(fake));
    expect(r?.checks.malicious.status).toBe('unknown');
    expect(r?.verdict).toBe('unknown');
  });

  it('offline: no request at all, network checks UNKNOWN, typosquat still runs', async () => {
    const fake = fakeFetch({});
    const [r, s] = await vetPackages([spec('npm', 'left-pad'), spec('npm', 'lodahs')], opts(fake, { offline: true }));
    expect(fake.calls).toHaveLength(0);
    expect(r?.verdict).toBe('unknown');
    expect(r?.reasons.join(' ')).toMatch(/GUARDIAN_OFFLINE|offline/i);
    expect(s?.verdict).toBe('warn');
    expect(s?.checks.typosquat.status).toBe('warn');
  });

  it('a missing popular list makes the typosquat check UNKNOWN rather than a pass', async () => {
    const fake = fakeFetch({
      'https://registry.npmjs.org/left-pad': { body: npmAbbrev('left-pad', { versions: ['1.3.0'], latest: '1.3.0' }) },
      [OSV]: osvRoute(),
    });
    const [r] = await vetPackages([spec('npm', 'left-pad')], opts(fake, { popular: { npm: null } }));
    expect(r?.checks.typosquat.status).toBe('unknown');
    expect(r?.verdict).toBe('unknown');
  });
});

describe('vetPackages — PyPI, Packagist, NuGet', () => {
  it('PyPI: resolves the specifier, reads upload times, warns on a fresh release', async () => {
    const fake = fakeFetch({
      'https://pypi.org/pypi/requests/json': {
        body: {
          info: { version: '2.32.0' },
          releases: {
            '2.31.0': [{ upload_time_iso_8601: iso(400 * DAY) }],
            '2.32.0': [{ upload_time_iso_8601: iso(2 * 3600 * 1000) }],
            '3.0.0rc1': [{ upload_time_iso_8601: iso(3600 * 1000) }],
          },
        },
      },
      [OSV]: osvRoute(),
    });
    const [pinned, latest] = await vetPackages([spec('pypi', 'requests', '==2.31.0'), spec('pypi', 'requests')], opts(fake));
    expect(pinned).toMatchObject({ version: '2.31.0', verdict: 'ok' });
    expect(latest).toMatchObject({ version: '2.32.0', verdict: 'warn' });
    expect(latest?.checks.install_scripts.status).toBe('not_applicable');
    const osvCall = fake.calls.find((c) => c.url === OSV);
    expect(JSON.stringify(osvCall?.body)).toContain('"ecosystem":"PyPI"');
  });

  it('PyPI: a nonexistent name is blocked', async () => {
    const fake = fakeFetch({ 'https://pypi.org/pypi/reqeusts-toolbelt-ai/json': { status: 404 }, [OSV]: osvRoute() });
    const [r] = await vetPackages([spec('pypi', 'reqeusts-toolbelt-ai')], opts(fake));
    expect(r?.verdict).toBe('block');
  });

  it('PyPI: a nonexistent name with PIP_INDEX_URL set is unknown', async () => {
    const fake = fakeFetch({ 'https://pypi.org/pypi/acme-internal/json': { status: 404 }, [OSV]: osvRoute() });
    const [r] = await vetPackages(
      [spec('pypi', 'acme-internal')],
      opts(fake, { registry: { projectDir: project, homeDir: home, env: { PIP_INDEX_URL: 'https://pypi.acme.local/simple' } } }),
    );
    expect(r?.verdict).toBe('unknown');
    expect(r?.reasons.join(' ')).toContain('PIP_INDEX_URL');
  });

  it('Packagist: expands the minified p2 format and reads per-version times', async () => {
    const fake = fakeFetch({
      'https://repo.packagist.org/p2/monolog/monolog.json': {
        body: {
          minified: 'composer/2.0',
          packages: {
            'monolog/monolog': [
              { name: 'monolog/monolog', version: '3.5.0', time: iso(200 * DAY), license: ['MIT'] },
              { version: '3.4.0', time: iso(300 * DAY) },
            ],
          },
        },
      },
      [OSV]: osvRoute(),
    });
    const [r] = await vetPackages([spec('packagist', 'monolog/monolog', '^3.4')], opts(fake));
    expect(r).toMatchObject({ version: '3.5.0', verdict: 'ok' });
    expect(r?.published_at).toBe(iso(200 * DAY));
  });

  it('NuGet: flat container for versions, registration leaf for the publish time', async () => {
    const fake = fakeFetch({
      'https://api.nuget.org/v3-flatcontainer/newtonsoft.json/index.json': { body: { versions: ['13.0.1', '13.0.3'] } },
      'https://api.nuget.org/v3/registration5-gz-semver2/newtonsoft.json/13.0.3.json': { body: { published: iso(900 * DAY) } },
      [OSV]: osvRoute(),
    });
    const [r] = await vetPackages([spec('nuget', 'Newtonsoft.Json')], opts(fake));
    expect(r).toMatchObject({ version: '13.0.3', verdict: 'ok' });
    expect(r?.checks.publish_age.status).toBe('pass');
  });

  it('I3 — NuGet: OSV is asked with the canonical id from the registry, not the typed casing', async () => {
    const fake = fakeFetch({
      'https://api.nuget.org/v3-flatcontainer/newtonsoft.json/index.json': { body: { versions: ['13.0.1'] } },
      [nugetSearchUrl('newtonsoft.json')]: { body: { data: [{ id: 'Newtonsoft.Json', version: '13.0.1' }] } },
      'https://api.nuget.org/v3/registration5-gz-semver2/newtonsoft.json/13.0.1.json': { body: { published: iso(900 * DAY) } },
      [OSV]: osvRoute({ 'Newtonsoft.Json@13.0.1': ['GHSA-5crp-9r3c-p9vr'] }),
    });
    const [r] = await vetPackages([spec('nuget', 'newtonsoft.json')], opts(fake));
    const osvCall = fake.calls.find((c) => c.url === OSV);
    expect(osvCall?.body).toEqual({ queries: [{ package: { name: 'Newtonsoft.Json', ecosystem: 'NuGet' }, version: '13.0.1' }] });
    expect(r?.vulnerability_ids).toEqual(['GHSA-5crp-9r3c-p9vr']);
  });

  it('I3 — NuGet: when the canonical id is unavailable, OSV gets the id as typed', async () => {
    const fake = fakeFetch({
      'https://api.nuget.org/v3-flatcontainer/newtonsoft.json/index.json': { body: { versions: ['13.0.1'] } },
      [nugetSearchUrl('Newtonsoft.Json')]: { status: 503 },
      'https://api.nuget.org/v3/registration5-gz-semver2/newtonsoft.json/13.0.1.json': { body: { published: iso(900 * DAY) } },
      [OSV]: osvRoute(),
    });
    await vetPackages([spec('nuget', 'Newtonsoft.Json')], opts(fake));
    const osvCall = fake.calls.find((c) => c.url === OSV);
    expect(JSON.stringify(osvCall?.body)).toContain('"name":"Newtonsoft.Json"');
  });

  it('I3 — Packagist: registry and OSV both get the lower-cased name', async () => {
    const fake = fakeFetch({
      'https://repo.packagist.org/p2/laravel/framework.json': {
        body: { packages: { 'laravel/framework': [{ version: 'v10.0.0', time: iso(700 * DAY) }] } },
      },
      [OSV]: osvRoute({ 'laravel/framework@v10.0.0': ['GHSA-3p32-j457-pg5x'] }),
    });
    const [r] = await vetPackages([spec('packagist', 'Laravel/Framework')], opts(fake));
    const osvCall = fake.calls.find((c) => c.url === OSV);
    expect(JSON.stringify(osvCall?.body)).toContain('"name":"laravel/framework"');
    expect(r?.vulnerability_ids).toEqual(['GHSA-3p32-j457-pg5x']);
  });

  it('NuGet: a nonexistent id is blocked; with a nuget.config private source it is unknown', async () => {
    const fake = fakeFetch({ 'https://api.nuget.org/v3-flatcontainer/acme.internal/index.json': { status: 404 }, [OSV]: osvRoute() });
    const [r] = await vetPackages([spec('nuget', 'Acme.Internal')], opts(fake));
    expect(r?.verdict).toBe('block');
    writeFileSync(
      join(project, 'nuget.config'),
      '<configuration><packageSources><add key="acme" value="https://nuget.acme.local/v3/index.json" /></packageSources></configuration>',
    );
    const [s] = await vetPackages([spec('nuget', 'Acme.Internal')], opts(fake));
    expect(s?.verdict).toBe('unknown');
  });
});

// ───────────────── install-vet-manifest-unreported-lookups — checks the caller will not report are not fetched for

describe('vetPackages — checks the caller does not report (install-vet-manifest-unreported-lookups)', () => {
  const NPM = 'https://registry.npmjs.org/fresh-pkg';
  const hourAgo = iso(3600 * 1000);
  /** Abbreviated when asked with npm's install-v1 Accept, the full document otherwise; `asked` says which. */
  const routes = (asked: string[]): Record<string, Route> => ({
    [NPM]: (init) => {
      const abbreviated = (new Headers(init?.headers).get('accept') ?? '').includes('install-v1');
      asked.push(abbreviated ? 'abbreviated' : 'full');
      return abbreviated
        ? { body: { 'dist-tags': { latest: '2.0.0' }, modified: hourAgo, versions: { '2.0.0': { hasInstallScript: true } } } }
        : { body: { time: { '2.0.0': hourAgo }, versions: { '2.0.0': { scripts: { postinstall: 'node build.js' } } } } };
    },
    [OSV]: osvRoute(),
  });
  const fresh = spec('npm', 'fresh-pkg');

  it('T-03 with both checks named as unreported: the abbreviated document and OSV only, each check not_applicable with its reason, and the verdict is not unknown for them', async () => {
    const asked: string[] = [];
    const f = fakeFetch(routes(asked));
    const [r] = await vetPackages([fresh], opts(f, { unreported: new Set(['publish_age', 'install_scripts'] as const) }));
    expect(asked).toEqual(['abbreviated']);
    expect(f.calls.map((c) => c.url)).toEqual([NPM, OSV]);
    expect(r?.checks.publish_age).toEqual({ status: 'not_applicable', detail: expect.stringMatching(/not checked/) });
    expect(r?.checks.install_scripts).toEqual({ status: 'not_applicable', detail: expect.stringMatching(/not checked/) });
    expect(r?.checks.exists.status).toBe('pass');
    expect(r?.checks.malicious.status).toBe('pass');
    expect(r?.verdict).toBe('ok');
    expect(r?.version).toBe('2.0.0');
  });

  it('T-03 without the option the result is the one of before: the full document is asked, and the fresh version and its install scripts warn', async () => {
    const asked: string[] = [];
    const f = fakeFetch(routes(asked));
    const [r] = await vetPackages([fresh], opts(f));
    expect(asked).toEqual(['abbreviated', 'full']);
    expect(r?.checks.publish_age.status).toBe('warn');
    expect(r?.checks.install_scripts).toEqual({ status: 'warn', detail: expect.stringMatching(/runs install scripts on install: postinstall/) });
    expect(r?.verdict).toBe('warn');
  });

  it('T-03 with only one of the two named, what the other needs is still asked, and only the named one is not_applicable', async () => {
    const asked: string[] = [];
    const f = fakeFetch(routes(asked));
    const [r] = await vetPackages([fresh], opts(f, { unreported: new Set(['publish_age'] as const) }));
    expect(asked).toEqual(['abbreviated', 'full']);
    expect(r?.checks.publish_age.status).toBe('not_applicable');
    expect(r?.checks.install_scripts.status).toBe('warn');
  });
});

// ───────────────── install-vet-lockfile-pins — a malicious advisory that arrived decides, whatever else OSV did not answer

describe('install-vet-lockfile-pins', () => {
  const doc = (name: string): Route => ({ body: npmAbbrev(name, { versions: ['1.0.0'], latest: '1.0.0' }) });

  it('T-15 a MAL- advisory in a result OSV cut short (next_page_token) still blocks its package: the query is unanswered, the hit that arrived is not lost', async () => {
    const fake = fakeFetch({
      'https://registry.npmjs.org/left-pad': { body: npmAbbrev('left-pad', { versions: ['1.3.0'], latest: '1.3.0' }) },
      [OSV]: { body: { results: [{ vulns: [{ id: 'MAL-2026-1' }], next_page_token: 'more' }] } },
    });
    const [r] = await vetPackages([spec('npm', 'left-pad')], opts(fake));
    expect(r?.checks.malicious.status).toBe('fail');
    expect(r?.checks.malicious.detail).toMatch(/MAL-2026-1/);
    expect(r?.malicious_ids).toEqual(['MAL-2026-1']);
    expect(r?.verdict).toBe('block');
    // What OSV did not finish saying about the other checks stays unknown.
    expect(r?.checks.vulnerabilities.status).toBe('unknown');
  });

  it('T-15 a package OSV gave no hit for, in the same incomplete answer, stays unknown — never pass', async () => {
    const fake = fakeFetch({
      'https://registry.npmjs.org/left-pad': { body: npmAbbrev('left-pad', { versions: ['1.3.0'], latest: '1.3.0' }) },
      'https://registry.npmjs.org/ms': { body: npmAbbrev('ms', { versions: ['2.1.3'], latest: '2.1.3' }) },
      [OSV]: { body: { results: [{ vulns: [{ id: 'MAL-2026-1' }], next_page_token: 'more' }, { next_page_token: 'more' }] } },
    });
    const [bad, other] = await vetPackages([spec('npm', 'left-pad'), spec('npm', 'ms')], opts(fake));
    expect(bad?.checks.malicious.status).toBe('fail');
    expect(other?.checks.malicious.status).toBe('unknown');
    expect(other?.verdict).toBe('unknown');
  });

  it('T-15 more than 100 packages, the second OSV batch failing: the hit of the batch that answered blocks, and the packages of the failed one are unknown', async () => {
    const names = Array.from({ length: 101 }, (_, i) => `pkg-${String(i).padStart(3, '0')}`);
    const routes: Record<string, Route> = Object.fromEntries(names.map((n) => [`https://registry.npmjs.org/${n}`, doc(n)]));
    routes[OSV] = (init) => {
      const { queries } = JSON.parse(String(init?.body)) as { queries: Array<{ package: { name: string } }> };
      if (queries.some((q) => q.package.name === 'pkg-100')) return { status: 500, body: {} };
      return { body: { results: queries.map((q) => (q.package.name === 'pkg-000' ? { vulns: [{ id: 'MAL-2026-2' }] } : {})) } };
    };
    const results = await vetPackages(names.map((n) => spec('npm', n)), opts(fakeFetch(routes)));
    expect(results[0]?.checks.malicious.status).toBe('fail');
    expect(results[0]?.verdict).toBe('block');
    expect(results[100]?.checks.malicious.status).toBe('unknown');
    // A package of the batch that answered is vetted: only the failed batch's packages are left unverified (US-1.AC-9).
    expect(results[50]?.checks.malicious.status).toBe('pass');
  });

  it('T-15 the registry failing, a MAL- hit that arrived by name still warns (the version is unknown)', async () => {
    const fake = fakeFetch({
      'https://registry.npmjs.org/left-pad': { status: 503 },
      [OSV]: { body: { results: [{ vulns: [{ id: 'MAL-2026-9' }], next_page_token: 'more' }] } },
    });
    const [r] = await vetPackages([spec('npm', 'left-pad')], opts(fake));
    expect(r?.checks.malicious.status).toBe('warn');
    expect(r?.checks.malicious.detail).toMatch(/MAL-2026-9/);
  });
});

// ───────────────── install-vet-slow-first-round — OSV is asked at half the budget, whatever the registry still owes

describe('install-vet-slow-first-round', () => {
  const REGISTRY = 'https://registry.npmjs.org/';
  /**
   * The network budget of the calls below: half of it is 500 ms from either end. No test sets a timer of its own
   * against it — a document is held until the first OSV request has LEFT, or until its own request is aborted — so
   * what a test reads is an order of requests, never which of two timers fired first.
   */
  const BUDGET = 1000;
  /** A timer may fire a millisecond or two before its time as `performance.now()` reads it; load only ever makes it late. */
  const TIMER_EARLY_MS = 25;
  /** The trial's positive control: OSV has `MAL-2025-6022` for these four versions of the name, and for no other. */
  const PRETTIER = 'eslint-config-prettier';
  const PRETTIER_ADVISORIES = Object.fromEntries(['8.10.1', '9.1.1', '10.1.6', '10.1.7'].map((v) => [`${PRETTIER}@${v}`, ['MAL-2025-6022']]));

  /** What the registry has for a name, and when it hands it over. */
  interface Published {
    /** The version `latest` names, the one a bare name installs; `null`: the registry does not have the name (HTTP 404). */
    latest: string | null;
    /**
     * Absent: answered when asked. `late`: held until the first OSV request has left, and answered then — a document
     * that arrives after OSV was asked, at any speed of the machine. `never`: held until its request is aborted.
     * `on release`: held until the test calls `release()`.
     */
    arrives?: 'late' | 'never' | 'on release';
  }

  interface SlowNet extends Fake {
    /** The names whose document was asked of the registry, in order. */
    registry: string[];
    /** Each OSV request, in order: its queries as `name@version` — the bare name, for a query with no version — sorted. */
    osv: string[][];
    /** When each OSV request left, on `performance.now()`. */
    osvAt: number[];
    /** Whether each OSV request left before its signal aborted: inside the budget. */
    osvInTime: boolean[];
    /** Hands over the documents held `on release`. */
    release: () => void;
  }

  /** Pending until `gate` opens — for ever, with no gate — and rejected, as the real fetch is, when the request's signal aborts first. */
  const held = (gate: Promise<void> | undefined, signal: AbortSignal | null | undefined): Promise<void> =>
    new Promise<void>((resolve, reject) => {
      const aborted = (): void => reject(new DOMException('aborted', 'AbortError'));
      if (signal?.aborted === true) {
        aborted();
        return;
      }
      signal?.addEventListener('abort', aborted, { once: true });
      void gate?.then(resolve);
    });

  /**
   * The network of these tests; like `fakeFetch`, any URL it has nothing for throws. The registry publishes
   * `registry`, each document handed over when its {@link Published.arrives} says. OSV answers a query that names a
   * version with the `advisories` of that `name@version`, and a query with no version with those of every version of
   * the name — unless `osvAnswer` says that request hangs (until aborted) or fails with an HTTP status.
   */
  function slowNet(net: {
    registry: Readonly<Record<string, Published>>;
    advisories?: Readonly<Record<string, readonly string[]>>;
    osvAnswer?: (request: number, pairs: readonly string[]) => 'hangs' | number | undefined;
  }): SlowNet {
    const seen: Omit<SlowNet, 'fetchImpl' | 'release'> = { calls: [], registry: [], osv: [], osvAt: [], osvInTime: [] };
    let osvWasAsked = (): void => undefined;
    const afterOsv = new Promise<void>((resolve) => {
      osvWasAsked = resolve;
    });
    let release = (): void => undefined;
    const onRelease = new Promise<void>((resolve) => {
      release = resolve;
    });
    const json = (body: unknown, status = 200): Response => new Response(JSON.stringify(body), { status });
    const advisories = net.advisories ?? {};
    const idsFor = (name: string, version: string | undefined): string[] =>
      version !== undefined
        ? [...(advisories[`${name}@${version}`] ?? [])]
        : [...new Set(Object.entries(advisories).flatMap(([pair, ids]) => (pair.startsWith(`${name}@`) ? ids : [])))];
    const fetchImpl = (async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
      const url = String(input);
      const body = typeof init?.body === 'string' ? (JSON.parse(init.body) as unknown) : undefined;
      seen.calls.push({ url, body });
      if (url === OSV) {
        const { queries } = body as { queries: Array<{ package: { name: string }; version?: string }> };
        const pairs = queries.map((q) => (q.version === undefined ? q.package.name : `${q.package.name}@${q.version}`));
        seen.osv.push([...pairs].sort());
        seen.osvAt.push(performance.now());
        seen.osvInTime.push(init?.signal?.aborted !== true);
        // The request has left: the documents held for that moment arrive now, and not a moment sooner.
        osvWasAsked();
        const how = net.osvAnswer?.(seen.osv.length, pairs);
        if (how === 'hangs') await held(undefined, init?.signal);
        if (typeof how === 'number') return json({ error: 'unavailable' }, how);
        return json({
          results: queries.map((q) => {
            const ids = idsFor(q.package.name, q.version);
            return ids.length > 0 ? { vulns: ids.map((id) => ({ id })) } : {};
          }),
        });
      }
      const name = url.startsWith(REGISTRY) ? decodeURIComponent(url.slice(REGISTRY.length)) : '';
      const published = net.registry[name];
      if (published === undefined) throw new Error(`unexpected network call: ${url}`);
      seen.registry.push(name);
      if (published.arrives === 'late') await held(afterOsv, init?.signal);
      else if (published.arrives === 'never') await held(undefined, init?.signal);
      else if (published.arrives === 'on release') await held(onRelease, init?.signal);
      if (published.latest === null) return json({ error: 'Not found' }, 404);
      return json(npmAbbrev(name, { versions: [published.latest], latest: published.latest }));
    }) as typeof fetch;
    return { fetchImpl, release: () => release(), ...seen };
  }

  /** The status of each check of a result, in the order of `PackageChecks`. */
  const statuses = (r: PackageVetResult | undefined): string[] =>
    r === undefined
      ? []
      : [r.checks.exists, r.checks.malicious, r.checks.vulnerabilities, r.checks.publish_age, r.checks.install_scripts, r.checks.typosquat].map((c) => c.status);
  const ALL_PASS = ['pass', 'pass', 'pass', 'pass', 'pass', 'pass'];

  // `next` is one of the documents that were slow in the measurement (megabytes); here its document never arrives.
  const TWO_AND_A_SLOW_ONE: Readonly<Record<string, Published>> = {
    express: { latest: '4.21.2' },
    lodash: { latest: '4.17.20' },
    next: { latest: '15.0.3', arrives: 'never' },
  };
  const THREE = [spec('npm', 'express'), spec('npm', 'lodash'), spec('npm', 'next')];

  it('T-01 the registry answers for two packages and never for a third: at half the budget ONE OSV request leaves, with the version of the two and the bare name of the third — the two have their whole result, the third an unknown existence and a malware check passed by name', async () => {
    const net = slowNet({ registry: TWO_AND_A_SLOW_ONE, advisories: { 'lodash@4.17.20': ['GHSA-35jh-r3h4-6jhm'] } });
    const t0 = performance.now();
    const [express, lodash, next] = await vetPackages(THREE, opts(net, { budgetMs: BUDGET }));

    // One request, inside the budget, and mixed: the version where the registry had answered, the name where it had not.
    expect(net.osv).toEqual([['express@4.21.2', 'lodash@4.17.20', 'next']]);
    expect(net.osvInTime).toEqual([true]);
    // At half the budget and not from the start: a timer is never early, so load cannot fail this.
    expect((net.osvAt[0] ?? 0) - t0).toBeGreaterThanOrEqual(BUDGET / 2 - TIMER_EARLY_MS);
    // One document per package, the slow one included: none is asked twice.
    expect([...net.registry].sort()).toEqual(['express', 'lodash', 'next']);

    // The two the registry answered for: everything, at the version — the advisory of that version among it.
    expect(express).toMatchObject({ version: '4.21.2', verdict: 'ok' });
    expect(statuses(express)).toEqual(ALL_PASS);
    expect(lodash).toMatchObject({ version: '4.17.20', verdict: 'warn', vulnerability_ids: ['GHSA-35jh-r3h4-6jhm'] });
    expect(lodash?.checks.vulnerabilities.detail).toMatch(/1 known vulnerability in 4\.17\.20/);
    expect(lodash?.checks.malicious.status).toBe('pass');

    // The one whose document did not arrive: not verified, alone, with the reason — and the answer OSV gave for its name stands.
    expect(next?.checks.exists.status).toBe('unknown');
    expect(next?.checks.exists.detail).toMatch(/budget|timed out/i);
    expect(next?.checks.malicious).toEqual({ status: 'pass', detail: expect.stringMatching(/for any version/) });
    expect(next?.checks.vulnerabilities.status).toBe('unknown');
    expect(next?.version).toBeUndefined();
    expect(next?.verdict).toBe('unknown');
  });

  it('T-01 (EC-2) OSV failing when it is asked at half the budget: everything that depended on it is unknown, with the reason, and it is not asked again', async () => {
    const net = slowNet({ registry: TWO_AND_A_SLOW_ONE, osvAnswer: () => 503 });
    const results = await vetPackages(THREE, opts(net, { budgetMs: BUDGET }));

    expect(net.osv).toEqual([['express@4.21.2', 'lodash@4.17.20', 'next']]);
    expect(net.osvInTime).toEqual([true]);
    expect(results.map((r) => r.checks.exists.status)).toEqual(['pass', 'pass', 'unknown']);
    for (const r of results) {
      expect(r.checks.malicious).toEqual({ status: 'unknown', detail: expect.stringMatching(/OSV lookup failed.*503/) });
      expect(r.verdict).toBe('unknown');
    }
    expect(results[1]?.checks.vulnerabilities.status).toBe('unknown');
  });

  it(
    'T-02 protection — the registry answering for every package before half the budget: ONE OSV request, with every version, right after the last answer; no request more; the results of before',
    async () => {
      // Half of this budget is half as far again as the bound below, on a loaded machine and on a quiet one: a call
      // that waited for half the budget before asking OSV is past the bound by seconds.
      const soon = hangBound(1000);
      const budgetMs = 3 * soon;
      const net = slowNet({
        registry: { 'left-pad': { latest: '1.3.0' }, ms: { latest: '2.1.3' }, lodash: { latest: '4.17.20', arrives: 'on release' } },
        advisories: { 'lodash@4.17.20': ['GHSA-35jh-r3h4-6jhm'] },
      });
      const vetting = vetPackages([spec('npm', 'left-pad'), spec('npm', 'ms'), spec('npm', 'lodash')], opts(net, { budgetMs }));
      // The last document is handed over a few turns of the event loop later: long before half the budget.
      await new Promise((resolve) => setTimeout(resolve, 20));
      const askedWhileADocumentWasOwed = net.osv.length;
      const releasedAt = performance.now();
      net.release();
      const [leftPad, ms, lodash] = await vetting;

      // Nothing by name from the start, then one request with every version — and it left when the last document came.
      expect(askedWhileADocumentWasOwed).toBe(0);
      expect(net.osv).toEqual([['left-pad@1.3.0', 'lodash@4.17.20', 'ms@2.1.3']]);
      expect((net.osvAt[0] ?? Number.POSITIVE_INFINITY) - releasedAt).toBeLessThan(soon);
      // One document per package and the one batch: nothing else left.
      expect([...net.registry].sort()).toEqual(['left-pad', 'lodash', 'ms']);
      expect(net.calls).toHaveLength(4);

      expect(leftPad).toMatchObject({ version: '1.3.0', verdict: 'ok' });
      expect(statuses(leftPad)).toEqual(ALL_PASS);
      expect(ms).toMatchObject({ version: '2.1.3', verdict: 'ok' });
      expect(statuses(ms)).toEqual(ALL_PASS);
      expect(lodash).toMatchObject({ version: '4.17.20', verdict: 'warn', vulnerability_ids: ['GHSA-35jh-r3h4-6jhm'] });
      expect(lodash?.checks.vulnerabilities.status).toBe('warn');
    },
    120_000,
  );

  it('T-03 a document that arrives after OSV was asked by name, and no MAL- advisory for the name: the malware check passes ("for any version"), the vulnerabilities stay undetermined, and OSV is not asked a second time', async () => {
    const net = slowNet({
      registry: { 'left-pad': { latest: '1.3.0' }, prisma: { latest: '6.1.0', arrives: 'late' }, sharp: { latest: '0.33.5', arrives: 'late' } },
      // `prisma`: an advisory that is not a malicious-package one, on a version that is not the one that installs. `sharp`: none at all.
      advisories: { 'prisma@5.0.0': ['GHSA-aaaa-bbbb-cccc'] },
    });
    const [fast, ...late] = await vetPackages([spec('npm', 'left-pad'), spec('npm', 'prisma'), spec('npm', 'sharp')], opts(net, { budgetMs: BUDGET }));

    expect(net.osv).toEqual([['left-pad@1.3.0', 'prisma', 'sharp']]);
    expect([...net.registry].sort()).toEqual(['left-pad', 'prisma', 'sharp']);
    expect(fast).toMatchObject({ version: '1.3.0', verdict: 'ok' });
    expect(statuses(fast)).toEqual(ALL_PASS);

    expect(late.map((r) => r.name)).toEqual(['prisma', 'sharp']);
    // What came late still counts: the package exists, and at which version.
    expect(late.map((r) => [r.checks.exists.status, r.version])).toEqual([
      ['pass', '6.1.0'],
      ['pass', '0.33.5'],
    ]);
    for (const r of late) {
      expect(r.checks.malicious).toEqual({ status: 'pass', detail: expect.stringMatching(/for any version/) });
      // The version was never asked of OSV: nothing is said of its vulnerabilities but that they are not known — no
      // warning from the advisories of other versions, and no pass either, with or without any.
      expect(r.checks.vulnerabilities.status).toBe('unknown');
      expect(r.verdict).toBe('unknown');
    }
  });

  it.each([
    ['10.1.7', 'has the advisory: DENIED', 'fail'],
    ['10.1.8', 'has none: passed', 'pass'],
  ] as const)(
    'T-04 a document arriving late for a name with MAL- advisories on some versions: a second OSV request, of that package and its version alone, and never a third — %s %s',
    async (latest, _outcome, status) => {
      const net = slowNet({
        registry: { 'left-pad': { latest: '1.3.0' }, [PRETTIER]: { latest, arrives: 'late' } },
        advisories: PRETTIER_ADVISORIES,
      });
      const [fast, late] = await vetPackages([spec('npm', 'left-pad'), spec('npm', PRETTIER)], opts(net, { budgetMs: BUDGET }));

      // The first request as in T-01; the second is the late name alone, at the version its document resolved to.
      expect(net.osv).toEqual([[PRETTIER, 'left-pad@1.3.0'], [`${PRETTIER}@${latest}`]]);
      expect(net.osvInTime).toEqual([true, true]);
      // And nothing more is asked of the registry for it.
      expect([...net.registry].sort()).toEqual([PRETTIER, 'left-pad']);
      expect(fast).toMatchObject({ version: '1.3.0', verdict: 'ok' });

      expect(late?.checks.exists.status).toBe('pass');
      expect(late?.version).toBe(latest);
      expect(late?.checks.malicious.status).toBe(status);
      if (status === 'fail') {
        expect(late?.checks.malicious.detail).toMatch(/MAL-2025-6022/);
        expect(late?.malicious_ids).toEqual(['MAL-2025-6022']);
        expect(late?.verdict).toBe('block');
      } else {
        // The advisories of the other versions are not this version's.
        expect(late?.malicious_ids).toBeUndefined();
        expect(['ok', 'unknown']).toContain(late?.verdict);
      }
    },
  );

  it.each([
    ['its result cut by next_page_token, no MAL- id in the page that came', 'page'],
    ['the whole first request answering HTTP 503', '503'],
  ] as const)(
    'T-03 a document arriving late and the by-name OSV answer INCOMPLETE — %s: the malware check is unknown with a reason, never a pass; the existence and the version still come from the document; no second request is sent (today: it is asked only for a late name whose first answer holds a MAL- id)',
    async (_how, mode) => {
      const net = slowNet({
        registry: { 'left-pad': { latest: '1.3.0' }, prisma: { latest: '6.1.0', arrives: 'late' } },
        ...(mode === '503' ? { osvAnswer: () => 503 } : {}),
      });
      // `next_page_token` on the result of the late name: the stand-in's OSV answers in full, this cuts that one result.
      const fetchImpl = (async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
        const res = await net.fetchImpl(input, init);
        if (mode !== 'page' || String(input) !== OSV) return res;
        const { queries } = JSON.parse(String(init?.body)) as { queries: Array<{ package: { name: string } }> };
        const json = (await res.json()) as { results: Array<Record<string, unknown>> };
        const cut = json.results.map((r, i) => (queries[i]?.package.name === 'prisma' ? { ...r, next_page_token: 'more' } : r));
        return new Response(JSON.stringify({ results: cut }), { status: 200 });
      }) as typeof fetch;
      const [, late] = await vetPackages([spec('npm', 'left-pad'), spec('npm', 'prisma')], opts({ fetchImpl, calls: net.calls }, { budgetMs: BUDGET }));

      expect(net.osv[0]).toEqual(['left-pad@1.3.0', 'prisma']);
      // The choice as it is: no MAL- id came, so no second question — a change of that is to be deliberate.
      expect(net.osv).toHaveLength(1);
      expect(late?.checks.exists.status).toBe('pass');
      expect(late?.version).toBe('6.1.0');
      expect(late?.checks.malicious.status).toBe('unknown');
      expect(late?.checks.malicious.detail).toMatch(/OSV lookup failed/);
      expect(late?.checks.malicious.detail).not.toMatch(/for any version/);
      expect(late?.checks.vulnerabilities.status).toBe('unknown');
      expect(late?.verdict).not.toBe('ok');
      expect(late?.verdict).toBe('unknown');
    },
  );

  it('T-05 the same, and the budget ending before the second request is answered: a warning that some versions have advisories and that this one was not determined in time — neither passed nor denied', async () => {
    const net = slowNet({
      // The version that installs IS one of the malicious ones: nothing but the answer that did not come could say so.
      registry: { 'left-pad': { latest: '1.3.0' }, [PRETTIER]: { latest: '10.1.7', arrives: 'late' } },
      advisories: PRETTIER_ADVISORIES,
      osvAnswer: (request) => (request > 1 ? 'hangs' : undefined),
    });
    const [fast, late] = await vetPackages([spec('npm', 'left-pad'), spec('npm', PRETTIER)], opts(net, { budgetMs: BUDGET }));

    expect(net.osv[0]).toEqual([PRETTIER, 'left-pad@1.3.0']);
    // The second request WAS sent, to OSV, holding that package alone with its version — and no third (it hangs until the budget aborts it).
    expect(net.osv).toEqual([[PRETTIER, 'left-pad@1.3.0'], [`${PRETTIER}@10.1.7`]]);
    expect(net.calls.filter((c) => c.url === OSV)).toHaveLength(2);
    expect(fast).toMatchObject({ version: '1.3.0', verdict: 'ok' });

    expect(late?.checks.exists.status).toBe('pass');
    expect(late?.checks.malicious.status).toBe('warn');
    expect(late?.checks.malicious.detail).toMatch(/MAL-2025-6022/);
    expect(late?.checks.malicious.detail).toMatch(/version.*determined|determined.*version/is);
    expect(late?.verdict).toBe('warn');
  });

  it('T-06 the npm security placeholder in a document that arrives late is DENIED', async () => {
    const net = slowNet({ registry: { 'left-pad': { latest: '1.3.0' }, crossenv: { latest: '0.0.1-security', arrives: 'late' } } });
    const [fast, late] = await vetPackages([spec('npm', 'left-pad'), spec('npm', 'crossenv')], opts(net, { budgetMs: BUDGET }));

    // OSV has nothing for the name: one request, and the document that came after it decides.
    expect(net.osv).toEqual([['crossenv', 'left-pad@1.3.0']]);
    expect(fast).toMatchObject({ version: '1.3.0', verdict: 'ok' });
    expect(late?.checks.malicious).toEqual({ status: 'fail', detail: expect.stringMatching(/security placeholder/) });
    expect(late?.verdict).toBe('block');
  });

  it('T-06 (EC-3) a name the registry does not have, its 404 arriving late, with a MAL- advisory by name: DENIED, and the existence check is the one of before', async () => {
    const net = slowNet({
      registry: { 'left-pad': { latest: '1.3.0' }, 'gone-evil': { latest: null, arrives: 'late' } },
      advisories: { 'gone-evil@1.0.0': ['MAL-2026-5'] },
    });
    const [fast, late] = await vetPackages([spec('npm', 'left-pad'), spec('npm', 'gone-evil')], opts(net, { budgetMs: BUDGET }));

    // There is no version to ask a second time with.
    expect(net.osv).toEqual([['gone-evil', 'left-pad@1.3.0']]);
    expect(fast).toMatchObject({ version: '1.3.0', verdict: 'ok' });
    expect(late?.not_on_public_registry).toBe(true);
    expect(late?.checks.exists).toEqual({ status: 'fail', detail: expect.stringMatching(/does not exist/) });
    expect(late?.checks.malicious).toEqual({ status: 'fail', detail: expect.stringMatching(/MAL-2026-5/) });
    expect(late?.verdict).toBe('block');
  });

  it(
    'T-09 with the budget of the vet_packages tool, OSV is asked at half of THAT budget: 5 s, not the 1.5 s of the hook',
    async () => {
      const net = slowNet({ registry: { 'left-pad': { latest: '1.3.0' }, prisma: { latest: '6.1.0', arrives: 'late' } } });
      const t0 = performance.now();
      // The budget `tools/vetPackages.ts` passes.
      const [fast, late] = await vetPackages([spec('npm', 'left-pad'), spec('npm', 'prisma')], opts(net, { budgetMs: TOOL_BUDGET_MS }));
      const askedAfter = (net.osvAt[0] ?? 0) - t0;

      expect(net.osv).toEqual([['left-pad@1.3.0', 'prisma']]);
      expect(net.osvInTime).toEqual([true]);
      // Not sooner than half of it (a timer is never early; load only delays it) …
      expect(askedAfter).toBeGreaterThanOrEqual(TOOL_BUDGET_MS / 2 - TIMER_EARLY_MS);
      // … and, where a number of milliseconds means something, not much later.
      if (PERF_STRICT) expect(askedAfter).toBeLessThan(TOOL_BUDGET_MS / 2 + 1000);
      // The answer was used, and so was the document that came after the question.
      expect(fast).toMatchObject({ version: '1.3.0', verdict: 'ok' });
      expect(late?.checks.exists.status).toBe('pass');
      expect(late?.checks.malicious.status).toBe('pass');
    },
    // Half the budget is 5 s; and a call that never asks OSV waits the whole of it out, 10 s, before this test can fail.
    4 * TOOL_BUDGET_MS,
  );

  // More than one OSV batch: 101 packages, every document arriving at once.
  const MANY = Array.from({ length: 101 }, (_, i) => `pkg-${String(i).padStart(3, '0')}`);
  /** The batch that holds the last package fails (HTTP 500); the other answers, with a `MAL-` advisory for the first package. */
  async function twoBatches(): Promise<{ net: SlowNet; results: PackageVetResult[]; failed: string[] }> {
    const net = slowNet({
      registry: Object.fromEntries(MANY.map((name) => [name, { latest: '1.0.0' }])),
      advisories: { 'pkg-000@1.0.0': ['MAL-2026-2'] },
      osvAnswer: (_request, pairs) => (pairs.includes('pkg-100@1.0.0') ? 500 : undefined),
    });
    const results = await vetPackages(MANY.map((name) => spec('npm', name)), opts(net));
    const failed = (net.osv.find((pairs) => pairs.includes('pkg-100@1.0.0')) ?? []).map((pair) => pair.slice(0, pair.indexOf('@')));
    return { net, results, failed };
  }

  it('T-10 more than 100 packages, two OSV batches, one answering with a MAL- advisory and the other failing: the package with the advisory is DENIED', async () => {
    const { net, results, failed } = await twoBatches();
    expect(net.osv).toHaveLength(2);
    expect(failed.length).toBeGreaterThan(0);
    expect(failed).not.toContain('pkg-000');
    expect(results[0]?.checks.malicious).toEqual({ status: 'fail', detail: expect.stringMatching(/MAL-2026-2/) });
    expect(results[0]?.malicious_ids).toEqual(['MAL-2026-2']);
    expect(results[0]?.verdict).toBe('block');
  });

  it('T-10 … and only the packages of the batch that failed are left unverified, with the reason: the others of the batch that answered are vetted', async () => {
    const { results, failed } = await twoBatches();
    expect(failed.length).toBeGreaterThan(0);
    const unverified = results.filter((r) => r.verdict === 'unknown');
    expect(unverified.length, 'packages left unverified, against those of the batch that failed').toBe(failed.length);
    expect(unverified.map((r) => r.name).sort()).toEqual([...failed].sort());
    for (const r of unverified) expect(r.checks.malicious).toEqual({ status: 'unknown', detail: expect.stringMatching(/OSV lookup failed/) });
    // Every other package but the denied one: asked, answered, clean.
    const answered = results.filter((r) => r.name !== 'pkg-000' && !failed.includes(r.name));
    expect(answered).toHaveLength(MANY.length - 1 - failed.length);
    expect(answered.filter((r) => r.verdict !== 'ok' || r.checks.malicious.status !== 'pass').map((r) => r.name)).toEqual([]);
  });

  it('T-10 the same NAME twice in a call of more than 100 packages, in two OSV batches, one answering and one failing: each spec is judged by its OWN query — the answered one is vetted (a MAL- advisory for its version denies it), the failed one is not verified', async () => {
    const fillers = Array.from({ length: 99 }, (_, i) => `filler-${String(i).padStart(3, '0')}`);
    const names = ['dup', ...fillers];
    const net = slowNet({
      registry: Object.fromEntries([...names, 'dup'].map((name) => [name, { latest: '1.0.0' }])),
      advisories: { 'dup@1.0.0': ['MAL-2026-7'] },
      // The first batch holds the first 100 queries, the second the 101st alone.
      osvAnswer: (_request, pairs) => (pairs.length === 1 ? 500 : undefined),
    });
    // The two specs of `dup` ask different things of the registry's one document: 1.0.0 is published, 2.0.0 is not,
    // so the second is asked of OSV by name — in the batch that fails.
    const specs = [spec('npm', 'dup', '1.0.0'), ...fillers.map((n) => spec('npm', n)), spec('npm', 'dup', '2.0.0')];
    const results = await vetPackages(specs, opts(net));

    expect(net.osv).toHaveLength(2);
    expect(net.osv.map((pairs) => pairs.length).sort((a, b) => a - b)).toEqual([1, 100]);
    const [answeredSpec, failedSpec] = [results[0], results[100]];
    expect(answeredSpec?.checks.malicious).toEqual({ status: 'fail', detail: expect.stringMatching(/MAL-2026-7/) });
    expect(answeredSpec?.verdict).toBe('block');
    // The failed batch's own spec: nothing about it was answered, and the other spec's advisory is not read as its own.
    expect(failedSpec?.checks.malicious).toEqual({ status: 'unknown', detail: expect.stringMatching(/OSV lookup failed/) });
    expect(failedSpec?.malicious_ids).toBeUndefined();
    expect(failedSpec?.verdict).not.toBe('ok');
    // And the fillers of the answered batch are vetted.
    expect(results.slice(1, 100).filter((r) => r.verdict !== 'ok').map((r) => r.name)).toEqual([]);
  });
});

// ───────────────── pkgvet-registry-credentials-said — a configured registry is named by scheme and host, never by its URL

describe('pkgvet-registry-credentials-said', () => {
  const MARK = 'dgsecret-zzq7731';
  const USER = 'dguser-zzq7731';
  const HOST = 'npm.company.example';
  const HOST_URL = `https://${HOST}`;
  const SENTENCE_START = 'a custom registry is configured (';
  const SENTENCE_END = ' — possibly a private or local package';

  /** A registry URL with credentials, a path and a query, built from pieces so no literal secret stands in the source. */
  const credentialUrl = (tail: string): string => ['https://', USER, ':', MARK, '@', HOST, tail].join('');
  const SECRET_URL = credentialUrl(`/caminho/?t=${MARK}#${MARK}`);

  const missing = (name: string): Fake => fakeFetch({ [`https://registry.npmjs.org/${name}`]: { status: 404 }, [OSV]: osvRoute() });

  /** Everything the check writes about a name: the `exists` detail and the reasons. */
  const said = (r: PackageVetResult | undefined): string => `${r?.checks.exists.detail ?? ''}\n${(r?.reasons ?? []).join('\n')}`;

  /** What the custom-registry sentence shows of the registry: the part in parentheses after the source, without the source. */
  function shownOfRegistry(text: string, source: string): string {
    const from = text.indexOf(SENTENCE_START);
    expect(from, `the custom-registry sentence in: ${text}`).toBeGreaterThan(-1);
    const to = text.indexOf(SENTENCE_END, from);
    expect(to, `the end of the custom-registry sentence in: ${text}`).toBeGreaterThan(from);
    const inner = text.slice(from + SENTENCE_START.length, to - 1);
    expect(inner.startsWith(source), `the sentence names its source ${source}: ${inner}`).toBe(true);
    return inner.slice(source.length).replace(/^[\s:,-]+/, '');
  }

  it('T-01 a registry URL with credentials, a path and a query is named by its source and https://host only — from the command line and from a .npmrc', async () => {
    const fromCommandLine = await vetPackages([spec('npm', 'acme-internal-lib')], opts(missing('acme-internal-lib'), { commandRegistries: [SECRET_URL] }));
    writeFileSync(join(project, '.npmrc'), `registry=${SECRET_URL}\n`);
    const fromNpmrc = await vetPackages([spec('npm', 'acme-internal-lib')], opts(missing('acme-internal-lib')));

    for (const [where, source, r] of [
      ['the command line', 'the command line', fromCommandLine[0]],
      ['a project .npmrc', join(project, '.npmrc'), fromNpmrc[0]],
    ] as const) {
      expect(r?.verdict, where).toBe('unknown');
      const text = said(r);
      for (const leaked of [MARK, USER, '/caminho', '?t=', '#']) {
        expect(text.includes(leaked), `${where}: "${leaked}" must not be in: ${text}`).toBe(false);
      }
      expect(text, where).toContain(source);
      expect(shownOfRegistry(text, source), where).toBe(HOST_URL);
    }
  });

  // [label, config value, what the sentence may show of it]: the exact scheme://host, or '' when nothing of the value may be shown.
  const HOSTILE: Array<[label: string, value: string, shown: string]> = [
    ['a password with @', ['https://', USER, ':p@ss-', MARK, '@', HOST, '/'].join(''), HOST_URL],
    ['a password with a colon', ['https://', USER, ':p:ss-', MARK, '@', HOST, '/'].join(''), HOST_URL],
    ['a password with a slash (not a URL the parser reads)', ['https://', USER, ':p/ss-', MARK, '@', HOST, '/'].join(''), ''],
    ['a password with %40', ['https://', USER, ':p%40ss-', MARK, '@', HOST, '/'].join(''), HOST_URL],
    ['several URLs separated by spaces', [credentialUrl(`/p/${MARK}`), ' ', ['https://', USER, ':', MARK, '@other.example/y'].join('')].join(''), HOST_URL],
    ['name=URL', `corp=${credentialUrl(`/p/${MARK}`)}`, HOST_URL],
    ['a token in the path and the query', `https://${HOST}/${MARK}/account/?token=${MARK}&x=1`, HOST_URL],
    ['a user without a password', ['https://', MARK, '@', HOST, '/'].join(''), HOST_URL],
    // The parser reads the user name as the host and the digits as a port: the value is ambiguous, so nothing of it is shown.
    ['a password of digits, then a slash', ['https://', USER, ':8080/ss-', MARK, '@', HOST, '/'].join(''), ''],
    ['a password of digits, then a #', ['https://', USER, ':2024#x-', MARK, '@', HOST, '/'].join(''), ''],
    ['a password of digits, then a ?', ['https://', USER, ':2024?x-', MARK, '@', HOST, '/'].join(''), ''],
    ['a password of digits, then a space', ['https://', USER, ':80 ', MARK, '@', HOST, '/'].join(''), ''],
    ['a port', ['https://', USER, ':', MARK, '@', HOST, ':8443/simple'].join(''), HOST_URL],
    ['text that is not a URL', `not a url ${MARK}`, ''],
    ['a local folder', `/srv/${MARK}/feed`, ''],
    ['a Windows folder', `C:\\Users\\${MARK}\\feeds`, ''],
    ['a UNC share', `\\\\${MARK}-server\\share`, ''],
    ['a file: URL', `file:///srv/${MARK}/feed`, ''],
  ];

  it.each(HOSTILE)('T-02 hostile value, %s: the sentence shows exactly the scheme and host, or nothing of the value', async (_label, value, shown) => {
    for (const [source, extra] of [
      ['the command line', { commandRegistries: [value] }],
      ['NPM_CONFIG_REGISTRY', { registry: { projectDir: project, homeDir: home, env: { NPM_CONFIG_REGISTRY: value } } }],
    ] as const) {
      const [r] = await vetPackages([spec('npm', 'acme-internal-lib')], opts(missing('acme-internal-lib'), extra));
      const text = said(r);
      expect(text.includes(MARK), `${source}: the marker must not be in: ${text}`).toBe(false);
      expect(text.includes(USER), `${source}: the user name must not be in: ${text}`).toBe(false);
      expect(shownOfRegistry(text, source), `${source}: ${value.length} chars of config value`).toBe(shown);
    }
  });

  it('T-02 an environment value with several URLs, the public one first: the sentence shows the host of the first that is not public', async () => {
    const value = ['https://registry.npmjs.org/ ', credentialUrl(`/p/?t=${MARK}`), ' https://other.example/x'].join('');
    const [r] = await vetPackages(
      [spec('npm', 'acme-internal-lib')],
      opts(missing('acme-internal-lib'), { registry: { projectDir: project, homeDir: home, env: { NPM_CONFIG_REGISTRY: value } } }),
    );
    const text = said(r);
    expect(text.includes(MARK), `the marker must not be in: ${text}`).toBe(false);
    expect(shownOfRegistry(text, 'NPM_CONFIG_REGISTRY')).toBe(HOST_URL);
  });

  it('T-02 several clean URLs with credentials: the first that is not public is named, none of the credentials', async () => {
    const value = [credentialUrl('/simple'), ' ', ['https://', USER, ':', MARK, '@other.example/simple'].join('')].join('');
    const [r] = await vetPackages(
      [spec('npm', 'acme-internal-lib')],
      opts(missing('acme-internal-lib'), { registry: { projectDir: project, homeDir: home, env: { NPM_CONFIG_REGISTRY: value } } }),
    );
    const text = said(r);
    expect(text.includes(MARK) || text.includes(USER), `no credential may be in: ${text}`).toBe(false);
    expect(shownOfRegistry(text, 'NPM_CONFIG_REGISTRY')).toBe(HOST_URL);
  });

  // User information that is only a token (no colon) and is cut by a separator the parser reads as the end of the
  // authority: it takes the token's prefix for the host, lowercased. Nothing of the token may be shown.
  const TOKEN = ['gh', 'p_ZzQ', '7731', 'Tok'].join('');
  it.each([
    ['a slash', '/'],
    ['a question mark', '?'],
    ['a hash', '#'],
    ['a backslash', '\\'],
  ])('T-02 a token as user information, cut by %s: no part of the token is shown, in any letter case, and nothing of the value', async (_label, separator) => {
    const value = ['https://', TOKEN, separator, 'rest-', MARK, '@', HOST, '/'].join('');
    for (const [source, extra] of [
      ['the command line', { commandRegistries: [value] }],
      ['NPM_CONFIG_REGISTRY', { registry: { projectDir: project, homeDir: home, env: { NPM_CONFIG_REGISTRY: value } } }],
    ] as const) {
      const [r] = await vetPackages([spec('npm', 'acme-internal-lib')], opts(missing('acme-internal-lib'), extra));
      const text = said(r);
      const lower = text.toLowerCase();
      for (const part of [TOKEN, 'rest-', MARK]) {
        expect(lower.includes(part.toLowerCase()), `${source}: "${part}" must not be in: ${text}`).toBe(false);
      }
      expect(shownOfRegistry(text, source), source).toBe('');
    }
  });

  it('T-02 a host with strange characters is shown as the parser reads it (punycode), without the credentials', async () => {
    const value = ['https://', USER, ':', MARK, '@npm.compány.example/x'].join('');
    const [r] = await vetPackages([spec('npm', 'acme-internal-lib')], opts(missing('acme-internal-lib'), { commandRegistries: [value] }));
    const text = said(r);
    expect(text.includes(MARK) || text.includes(USER), `no credential may be in: ${text}`).toBe(false);
    expect(shownOfRegistry(text, 'the command line')).toBe('https://npm.xn--compny-sta.example');
  });

  it('T-05 protection: an unremarkable registry still makes the name unknown and names the source; the other sentences read as before', async () => {
    writeFileSync(join(project, '.npmrc'), 'registry=https://npm.acme.local/\n');
    const [plain] = await vetPackages([spec('npm', 'acme-internal-lib')], opts(missing('acme-internal-lib')));
    expect(plain?.verdict).toBe('unknown');
    expect(plain?.checks.exists.status).toBe('unknown');
    expect(plain?.reasons.join(' ')).toContain(join(project, '.npmrc'));
    expect(plain?.checks.exists.detail).toContain(`${SENTENCE_START}${join(project, '.npmrc')}`);
    rmSync(join(project, '.npmrc'));

    // An npmjs auth token: the sentence of before, with the file only.
    writeFileSync(join(project, '.npmrc'), '//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n');
    const [auth] = await vetPackages([spec('npm', '@acme/private')], opts(fakeFetch({ 'https://registry.npmjs.org/@acme%2Fprivate': { status: 404 }, [OSV]: osvRoute() })));
    expect(auth?.verdict).toBe('unknown');
    expect(auth?.checks.exists.detail).toContain(
      `but an npmjs auth token is configured (${join(project, '.npmrc')}) and a private scoped package answers 404 to an anonymous lookup — possibly a private or local package; not vetted.`,
    );
    rmSync(join(project, '.npmrc'));

    // A local workspace package.
    writeFileSync(join(project, 'package.json'), JSON.stringify({ workspaces: ['packages/*'] }));
    mkdirSync(join(project, 'packages', 'ui'), { recursive: true });
    writeFileSync(join(project, 'packages', 'ui', 'package.json'), JSON.stringify({ name: 'acme-ui-kit' }));
    const [workspace] = await vetPackages([spec('npm', 'acme-ui-kit')], opts(missing('acme-ui-kit')));
    expect(workspace?.verdict).toBe('unknown');
    expect(workspace?.checks.exists.detail).toMatch(/but it is a local workspace package \([^)]+\) — possibly a private or local package; not vetted\.$/);
    rmSync(join(project, 'package.json'));
    rmSync(join(project, 'packages'), { recursive: true, force: true });

    // A configuration that could not be read (a directory where `.npmrc` belongs).
    mkdirSync(join(project, '.npmrc'));
    const [unreadable] = await vetPackages([spec('npm', 'acme-internal-lib')], opts(missing('acme-internal-lib')));
    expect(unreadable?.verdict).toBe('unknown');
    expect(unreadable?.checks.exists.detail).toContain(
      `registry configuration at ${join(project, '.npmrc')} could not be read — possibly a private registry — possibly a private or local package; not vetted.`,
    );
  });
});
