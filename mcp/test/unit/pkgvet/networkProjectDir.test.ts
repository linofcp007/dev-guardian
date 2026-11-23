/**
 * install-vet-network-project-dir-probe: the paths install-vet asks the disk for.
 *
 * `privateRegistry.ts`, `configFile.ts` and `hookDecision.ts` import `node:fs` directly, so `opts.diskImpl` sees none of
 * their calls. A recording `node:fs` does: a path with the documentation host `198.51.100.7` in it is listed and fails
 * at once with ENOENT, never touching the disk or the network; every other path goes to the real `node:fs`.
 *
 * T-02 is the protection (green before and after the fix): a local project still reads up to its repository root, a
 * local installed copy is still looked for, and a `cd` into a network path still reaches no network path.
 */

import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const NETWORK_HOST = '198.51.100.7';
// `owners[i]` is the source module (`hookDecision`, `configFile`, `privateRegistry`, `folderSpelling`) that asked for `paths[i]` (from the stack), or '' for any other.
const seen = vi.hoisted(() => ({ paths: [] as string[], owners: [] as string[] }));

vi.mock('node:fs', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs')>();
  type P = import('node:fs').PathLike;
  type Any = (p: P, ...rest: unknown[]) => unknown;
  const ownerOf = (): string => /(hookDecision|configFile|privateRegistry|folderSpelling)\.ts/.exec(new Error('stack').stack ?? '')?.[1] ?? '';
  const record = (p: P): void => {
    const text = String(p);
    seen.paths.push(text);
    seen.owners.push(ownerOf());
    if (text.includes('198.51.100.7')) {
      throw Object.assign(new Error(`ENOENT: no such file or directory, '${text}'`), { code: 'ENOENT', path: text });
    }
  };
  // The first argument is the path in every wrapped call; the rest goes to the real function untouched.
  const wrap =
    (fn: Any) =>
    (p: P, ...rest: unknown[]): unknown => {
      record(p);
      return fn(p, ...rest);
    };
  const lstatSync = wrap(actual.lstatSync as Any) as typeof actual.lstatSync;
  const statSync = wrap(actual.statSync as Any) as typeof actual.statSync;
  const existsSync = (p: P): boolean => {
    seen.paths.push(String(p));
    seen.owners.push(ownerOf());
    return String(p).includes('198.51.100.7') ? false : actual.existsSync(p);
  };
  const native = wrap(actual.realpathSync.native as Any) as typeof actual.realpathSync.native;
  const realpathSync = Object.assign(wrap(actual.realpathSync as Any), { native }) as typeof actual.realpathSync;
  const readdirSync = wrap(actual.readdirSync as Any) as typeof actual.readdirSync;
  const openSync = wrap(actual.openSync as Any) as typeof actual.openSync;
  const readFileSync = ((p: P | number, ...rest: unknown[]) => {
    if (typeof p !== 'number') record(p);
    return (actual.readFileSync as (p: P | number, ...rest: unknown[]) => unknown)(p, ...rest);
  }) as typeof actual.readFileSync;
  const wrapped = { lstatSync, statSync, existsSync, realpathSync, readdirSync, openSync, readFileSync };
  return { ...actual, ...wrapped, default: { ...actual, ...wrapped } };
});

import { decideInstallCommand, type HookVetOptions } from '../../../src/pkgvet/hookDecision.js';

const NOW = Date.parse('2026-09-25T12:00:00Z');
const OSV = 'https://api.osv.dev/v1/querybatch';
const EVIL = 'dgprobe-zzq7731-evil';
const TOOL = 'dgprobe-zzq7731-tool';
const NET = '\\\\198.51.100.7\\share\\proj';

/**
 * The registries and OSV, mocked: EVIL and TOOL exist on npm and PyPI, EVIL has a MAL advisory, every other name
 * (`dgprobe-zzq7731-missing` included) is a 404. Any other URL throws.
 */
function registries(): { fetchImpl: typeof fetch; calls: string[] } {
  const calls: string[] = [];
  const known = [EVIL, TOOL];
  const json = (body: unknown, status = 200): Response => new Response(JSON.stringify(body), { status });
  const fetchImpl = (async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const url = String(input);
    calls.push(url);
    if (url === OSV) {
      const body = JSON.parse(String(init?.body)) as { queries: { package?: { name?: string } }[] };
      return json({ results: body.queries.map((q) => (q.package?.name === EVIL ? { vulns: [{ id: 'MAL-2026-77' }] } : {})) });
    }
    const pypi = /^https:\/\/pypi\.org\/pypi\/([^/]+)\/json$/.exec(url);
    if (pypi !== null) {
      return known.includes(decodeURIComponent(pypi[1] ?? ''))
        ? json({ info: { version: '1.0.0' }, releases: { '1.0.0': [{ upload_time_iso_8601: '2020-01-01T00:00:00Z' }] } })
        : json({}, 404);
    }
    const npm = /^https:\/\/registry\.npmjs\.org\/([^/]+)$/.exec(url);
    if (npm !== null) {
      return known.includes(decodeURIComponent(npm[1] ?? ''))
        ? json({ 'dist-tags': { latest: '1.0.0' }, modified: '2020-01-01T00:00:00.000Z', versions: { '1.0.0': {} } })
        : json({}, 404);
    }
    throw new Error(`unexpected network call: ${url}`);
  }) as typeof fetch;
  return { fetchImpl, calls };
}

const made: string[] = [];
let home: string;

function tempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  made.push(dir);
  return dir;
}

function put(root: string, rel: string, text: string): void {
  const file = join(root, rel);
  mkdirSync(join(file, '..'), { recursive: true });
  writeFileSync(file, text);
}

beforeEach(() => {
  seen.paths.length = 0;
  seen.owners.length = 0;
  home = tempDir('dg-netdir-home-');
});
afterEach(() => {
  for (const dir of made.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function opts(fetchImpl: typeof fetch, cwd: string, extra: Partial<HookVetOptions> = {}): HookVetOptions {
  return {
    cwd,
    projectDir: cwd,
    homeDir: home,
    env: { GUARDIAN_OFFLINE: '0' },
    etcDir: join(home, 'no-etc'),
    nodeExecPath: join(home, 'no-node', 'bin', 'node'),
    systemLibraryDir: join(home, 'no-library'),
    fetchImpl,
    now: NOW,
    popular: {},
    ...extra,
  };
}

const norm = (p: string): string => p.replaceAll('\\', '/');
/** True when `owner` asked the disk for exactly `path` (compared with forward slashes). */
const askedBy = (owner: string, path: string): boolean => seen.paths.some((p, i) => seen.owners[i] === owner && norm(p) === norm(path));

describe('install-vet-network-project-dir-probe', () => {
  it('T-02 (a) a local repository: the manifest is read up to the repository root, and the mock sees privateRegistry.ts', async () => {
    const root = tempDir('dg-netdir-repo-');
    mkdirSync(join(root, '.git'));
    mkdirSync(join(root, 'app'));
    put(root, 'package.json', JSON.stringify({ name: 'proj', dependencies: { [EVIL]: '1.0.0' } }));
    const f = registries();
    const d = await decideInstallCommand('npm install', opts(f.fetchImpl, join(root, 'app')));
    // Today's refusal names the repository root's manifest: the climb from `app` reaches the root.
    expect(d?.deny).toBe(
      "dev-guardian blocked this install: ../package.json names 'dgprobe-zzq7731-evil@1.0.0': OSV malicious-package advisory for 1.0.0: MAL-2026-77. Installing it or removing the dependency is the user's decision: tell them which file names it, and install nothing from that manifest until they have decided.",
    );
    // The recording sees privateRegistry.ts's `.git` lstat, so a fix that stopped it would turn this red.
    expect(askedBy('privateRegistry', join(root, 'app', '.git')) || askedBy('privateRegistry', join(root, '.git'))).toBe(true);
  });

  it('T-02 (b) an npx in a local folder with the installed copy: no request for the name, and the mock sees hookDecision.ts and configFile.ts', async () => {
    const dir = tempDir('dg-netdir-copy-');
    put(dir, 'package.json', JSON.stringify({ name: 'proj' }));
    put(dir, `node_modules/${TOOL}/package.json`, JSON.stringify({ name: TOOL, version: '1.0.0' }));
    put(dir, `node_modules/.bin/${TOOL}`, '#!/usr/bin/env node\n');
    const f = registries();
    const d = await decideInstallCommand(`npx ${TOOL}`, opts(f.fetchImpl, dir));
    // Today's decision: none (null), and no request for the name: the installed copy is found on disk.
    expect(d).toBeNull();
    expect(f.calls.filter((u) => u.includes(TOOL))).toEqual([]);
    // The recording sees the two modules that look for the installed copy.
    expect(askedBy('hookDecision', join(dir, 'package.json'))).toBe(true);
    expect(askedBy('configFile', join(dir, 'node_modules', TOOL, 'package.json'))).toBe(true);
  });

  it.skipIf(process.platform !== 'win32')(
    "T-02 (c) a cd into a network path with local cwd and projectDir (Windows; skipped otherwise): today's decision, no network path",
    async () => {
      const dir = tempDir('dg-netdir-local-');
      const f = registries();
      const d = await decideInstallCommand(`cd '${NET}' && npm install ${TOOL}`, opts(f.fetchImpl, dir));
      // Today's decision: a warning (no deny, no ask) that the manifest was not read; the name itself is vetted and clean.
      expect(d).toEqual({
        context: 'dev-guardian: package.json was not read (where the command runs could not be determined) — its packages were not vetted.',
      });
      expect(f.calls).toContain(`https://registry.npmjs.org/${TOOL}`);
      expect(seen.paths.filter((p) => p.includes(NETWORK_HOST))).toEqual([]);
    },
  );
});
