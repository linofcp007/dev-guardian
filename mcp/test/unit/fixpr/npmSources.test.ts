/**
 * `create_fix_pr`'s npm network-path check fails CLOSED (review of 3.0, W2E
 * round 3, I1).
 *
 * The reviewer's repro: a `package-lock.json` with
 * `resolved: file://192.0.2.1/share/p-1.0.0.tgz` was found — and the same
 * lock padded past the 2 000 000-value parse bound read as "nothing found",
 * so the install went ahead and npm, which parses it anyway, opened the share
 * (on Windows, authenticating to the host). So did a lock over the size cap,
 * one that did not parse, an entry deeper than six levels, and every
 * workspace member's `package.json`, which was never read. Now any file npm
 * reads that could not be fully read and checked refuses the install, named.
 */
import { spawnSync } from 'node:child_process';
import { mkdirSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { checkNpmSources, installRefusal, npmSourcesRefusal } from '../../../src/fixpr/repoPackageConfig.js';
import { CAN_SYMLINK, POSIX } from '../../helpers/fsCapabilities.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

const SHARE = 'file://192.0.2.1/share/p-1.0.0.tgz';
/** How a network path's host is named: `\\192.0.2.1`, a UNC host, whatever spelling reached it. */
const HOST = '\\\\192.0.2.1';

function project(files: Record<string, string>): string {
  const dir = makeTempDir('npm-sources-');
  for (const [rel, body] of Object.entries(files)) {
    mkdirSync(join(dir, ...rel.split('/').slice(0, -1)), { recursive: true });
    writeFileSync(join(dir, ...rel.split('/')), body);
  }
  return dir;
}

const PKG = JSON.stringify({ name: 'x', version: '1.0.0', dependencies: { p: '1.0.0' } });
const lock = (padding: number): string =>
  JSON.stringify({
    name: 'x',
    lockfileVersion: 3,
    packages: { '': { dependencies: { p: '1.0.0' } }, 'node_modules/p': { version: '1.0.0', resolved: SHARE } },
    padding: new Array(padding).fill(0),
  });

describe("the reviewer's lock", () => {
  it('unpadded: the network path is named by its host', () => {
    const check = checkNpmSources(project({ 'package.json': PKG, 'package-lock.json': lock(0) }));
    expect(check).toEqual({ network: [`package-lock.json: packages.node_modules/p.resolved (${HOST})`], unchecked: [] });
  });

  it('padded past the parse bound: unchecked, and the install is refused — never "nothing found"', () => {
    const dir = project({ 'package.json': PKG, 'package-lock.json': lock(2_100_000) });
    const check = checkNpmSources(dir);
    expect(check.network).toEqual([]);
    expect(check.unchecked).toEqual([expect.stringMatching(/^package-lock\.json \(it holds more than 2000000 JSON values/)]);
    expect(installRefusal({ projectDir: dir, stepEcosystems: ['npm'], stepFiles: [], rescanTools: [] })).toMatch(
      /^npm reads files dev-guardian could not check for a network path \(package-lock\.json \(it holds more than 2000000 JSON values.*dev-guardian doesn't install what it has not checked$/,
    );
  });
});

describe('every file npm reads, at any depth', () => {
  it.each([
    ['a lock that is not JSON', { 'package-lock.json': '{"packages": {' }, 'package-lock.json (it is not valid JSON)'],
    ['a shrinkwrap that is an array', { 'npm-shrinkwrap.json': '[1]' }, 'npm-shrinkwrap.json (it is not a JSON object)'],
    ['a package.json whose workspaces are not a list', { 'package.json': '{"workspaces": 5}' }, 'package.json (its "workspaces" is not a list of patterns)'],
  ])('%s is unchecked, named', (_label, files, named) => {
    expect(checkNpmSources(project({ 'package.json': PKG, ...files })).unchecked).toEqual([named]);
  });

  it('a lockfile v1 entry twelve levels down the dependency tree is found (the walk stopped at six)', () => {
    let deps: Record<string, unknown> = { leaf: { version: SHARE } };
    for (let i = 0; i < 12; i++) deps = { [`d${i}`]: { version: '1.0.0', dependencies: deps } };
    const check = checkNpmSources(project({ 'package.json': PKG, 'package-lock.json': JSON.stringify({ lockfileVersion: 1, dependencies: deps }) }));
    expect(check.network).toHaveLength(1);
    expect(check.network[0]?.endsWith(`.dependencies.leaf.version (${HOST})`)).toBe(true);
  });

  it('a nested override is found', () => {
    const pkg = JSON.stringify({ name: 'x', overrides: { a: { b: { c: { d: { e: { f: { g: SHARE } } } } } } } });
    expect(checkNpmSources(project({ 'package.json': pkg })).network).toEqual([`package.json: overrides.a.b.c.d.e.f.g (${HOST})`]);
  });

  it("a workspace member's package.json is read, and a network path in it named", () => {
    const pkg = JSON.stringify({ name: 'root', private: true, workspaces: ['packages/*'] });
    const member = JSON.stringify({ name: 'm', dependencies: { q: 'file:\\\\192.0.2.1\\share\\q' } });
    const check = checkNpmSources(project({ 'package.json': pkg, 'packages/m/package.json': member, 'packages/n/package.json': '{"name":"n"}' }));
    expect(check).toEqual({ network: [`packages/m/package.json: dependencies.q (${HOST})`], unchecked: [] });
  });

  it('the object form `workspaces: { packages: [...] }` and a `**` pattern are followed', () => {
    const pkg = JSON.stringify({ name: 'root', workspaces: { packages: ['apps/**'] } });
    const member = JSON.stringify({ name: 'deep', devDependencies: { q: SHARE } });
    expect(checkNpmSources(project({ 'package.json': pkg, 'apps/web/ui/package.json': member })).network).toEqual([
      `apps/web/ui/package.json: devDependencies.q (${HOST})`,
    ]);
  });

  it.skipIf(!CAN_SYMLINK)('a workspace member linked out of the project is unchecked, named', () => {
    const outside = makeTempDir('npm-out-');
    writeFileSync(join(outside, 'package.json'), '{"name":"o"}');
    const dir = project({ 'package.json': JSON.stringify({ name: 'root', workspaces: ['packages/*'] }) });
    mkdirSync(join(dir, 'packages'));
    symlinkSync(outside, join(dir, 'packages', 'o'), process.platform === 'win32' ? 'junction' : 'dir');
    expect(checkNpmSources(dir).unchecked).toEqual(['packages/o (a link a workspace pattern matches, not followed)']);
  });

  it.skipIf(!POSIX)('a FIFO lock is unchecked at once, never waited on (POSIX)', () => {
    const dir = project({ 'package.json': PKG });
    expect(spawnSync('mkfifo', [join(dir, 'package-lock.json')]).status).toBe(0);
    const t0 = Date.now();
    expect(checkNpmSources(dir).unchecked).toEqual([expect.stringMatching(/^package-lock\.json \(/)]);
    expect(Date.now() - t0).toBeLessThan(3_000);
  });

  it("yarn.lock's text: a file: URL to a host is named, the registry's https URLs are not", () => {
    const yarn = [
      '# yarn lockfile v1',
      '',
      'p@1.0.0:',
      '  version "1.0.0"',
      '  resolved "https://registry.yarnpkg.com/p/-/p-1.0.0.tgz#abc"',
      '',
      'q@file://192.0.2.1/share/q.tgz:',
      '  version "1.0.0"',
      `  resolved "${SHARE}"`,
      '',
    ].join('\n');
    expect(checkNpmSources(project({ 'package.json': PKG, 'yarn.lock': yarn })).network).toEqual([
      `yarn.lock:7 (${HOST})`,
      `yarn.lock:9 (${HOST})`,
    ]);
  });

  it('a clean project passes: registry URLs, local file: specs, localhost', () => {
    const pkg = JSON.stringify({ name: 'x', dependencies: { a: '^1.0.0', b: 'file:../b', c: 'file:///opt/c.tgz', d: 'file://localhost/opt/d.tgz' } });
    const lockText = JSON.stringify({ lockfileVersion: 3, packages: { 'node_modules/a': { resolved: 'https://registry.npmjs.org/a/-/a-1.0.0.tgz' } } });
    const check = checkNpmSources(project({ 'package.json': pkg, 'package-lock.json': lockText }));
    expect(check).toEqual({ network: [], unchecked: [] });
    expect(npmSourcesRefusal(check)).toBeNull();
  });
});
