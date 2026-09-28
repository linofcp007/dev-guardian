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
import type { PackageSpec, PkgEcosystem } from '../../../src/pkgvet/types.js';
import { vetPackages, type VetOptions } from '../../../src/pkgvet/vet.js';

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
    expect(Date.now() - t0).toBeLessThan(2000);
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
