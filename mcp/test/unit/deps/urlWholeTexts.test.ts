/**
 * deps-tools-host-other-texts, task 2, T-05 (red until the fix): the places that say a URL, a network path or a JSON key
 * of a project file WHOLE, with no rule in front of it: the `.npmrc` registry, the key of an `overrides` /
 * `resolutions` entry, a ProjectReference or a solution entry on a network path, and the restore error line. A URL
 * with a user part is said as the parser writes it without that part; a URL with an `@` outside its user part, or an
 * `@` in the part a reader cut off, is said `(host not shown)`; a text with an `@` that is not a host is said
 * `(unparseable URL)`.
 *
 * The `planDotnetRestore` rows assert on the absolute path (EC-13): the backslash form only where a backslash path is a
 * network path (Windows), the `//` form on every platform. Every credential-looking value is MADE UP and built from
 * parts.
 */

import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { classifyRestoreFailure, planDotnetRestore } from '../../../src/deps/dotnetRestore.js';
import { checkNpmSources } from '../../../src/fixpr/repoPackageConfig.js';
import { projectNpmRegistry } from '../../../src/tools/depsAudit.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

const FEATURE = 'deps-tools-host-other-texts';
const WIN = process.platform === 'win32';
const T = ['tok', 'ZzQ', '7731'].join('');
const K = ['ken', 'Qq', '88'].join('');
const U = ['dg', 'user', 'zq'].join('');
const W = ['pw', 'ZzQ', '55'].join('');
const H = 'host.example';
const DIGITS = ['44', '55'].join('');
const BS = String.fromCharCode(92);
const TAB = String.fromCharCode(9);

const partsIn = (text: string): string[] => [T, K, U, W].filter((p) => text.toLowerCase().includes(p.toLowerCase()));
const expectNoPart = (said: unknown): void => {
  const text = typeof said === 'string' ? said : JSON.stringify(said);
  expect(partsIn(text), text).toEqual([]);
};

function project(files: Record<string, string>): string {
  const dir = makeTempDir('dg-urlwhole-');
  for (const [name, text] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, name)), { recursive: true });
    writeFileSync(join(dir, name), text);
  }
  return dir;
}

// ── the project's .npmrc ─────────────────────────────────────────────────────────────────────────────────────────
const registry = (value: string): string | null => projectNpmRegistry(project({ '.npmrc': `registry=${value}\n` }));

/** `said`: what the registry is said as; undefined when the plan only asks for no part. */
const REGISTRIES: Array<{ id: string; value: string; said?: string }> = [
  { id: 'https://T/K@H/', value: `https://${T}/${K}@${H}/` },
  { id: 'https://U:4455/K@H/', value: `https://${U}:${DIGITS}/${K}@${H}/` },
  { id: 'https://U:pw/K@H/', value: `https://${U}:${W}/${K}@${H}/`, said: '(unparseable URL)' },
  { id: 'https://T/@H/', value: `https://${T}/@${H}/` },
  { id: 'https://U:T@K@H/', value: `https://${U}:${T}@${K}@${H}/`, said: `https://${H}/` },
  { id: 'quoted https://T/K@H/', value: `"https://${T}/${K}@${H}/"` },
  { id: '//T/K@H/ (no scheme)', value: `//${T}/${K}@${H}/` },
  { id: 'https:U:T@H/', value: `https:${U}:${T}@${H}/`, said: `https://${H}/` },
  { id: 'https:/U:T@H/', value: `https:/${U}:${T}@${H}/`, said: `https://${H}/` },
  { id: 'http:\\U:T@H/', value: `http:${BS}${U}:${T}@${H}/`, said: `http://${H}/` },
  { id: 'ht<TAB>tps://U:T@H/', value: `ht${TAB}tps://${U}:${T}@${H}/`, said: `https://${H}/` },
  { id: 'U:T@H:path', value: `${U}:${T}@${H}:path`, said: '(unparseable URL)' },
  { id: 'npm:https://U:T@H/x@1.0.0', value: `npm:https://${U}:${T}@${H}/x@1.0.0` },
];

describe(`${FEATURE} T-05 the project .npmrc registry`, () => {
  it.each(REGISTRIES)('T-05 projectNpmRegistry, $id: no part of the credentials', ({ value, said }) => {
    const r = registry(value);
    expectNoPart(String(r));
    if (said !== undefined) expect(r).toBe(said);
  });
});

// ── a JSON key in the path of the npm refusal ────────────────────────────────────────────────────────────────────
const SHARE = `//files.${H}/share/x.tgz`;
const KEYS: Array<{ id: string; key: string; said?: string }> = [
  { id: 'dgdep@https://T/K@H/x.tgz', key: `dgdep@https://${T}/${K}@${H}/x.tgz` },
  { id: 'dgdep@https://U:T@H/x.tgz', key: `dgdep@https://${U}:${T}@${H}/x.tgz`, said: `dgdep@https://${H}/x.tgz` },
  { id: 'dgdep@https://T K@H/x.tgz', key: `dgdep@https://${T} ${K}@${H}/x.tgz`, said: 'dgdep@https://(host not shown)' },
];

describe(`${FEATURE} T-05 a JSON key in the npm network-path refusal`, () => {
  describe.each(['overrides', 'resolutions'])('%s', (field) => {
    it.each(KEYS)('T-05 checkNpmSources, key $id: no part of the credentials', ({ key, said }) => {
      const manifest = `${JSON.stringify({ name: 'dgproj', version: '1.0.0', dependencies: { dgdep: '^1.0.0' }, [field]: { [key]: SHARE } }, null, 2)}\n`;
      const check = checkNpmSources(project({ 'package.json': manifest }));
      expect(check.network.length, JSON.stringify(check)).toBe(1);
      expectNoPart(check.network);
      if (said !== undefined) expect(check.network[0]).toContain(`${field}.${said} (`);
    });
  });
});

// ── a ProjectReference or a solution entry on a network path ─────────────────────────────────────────────────────
const LIB = '<Project Sdk="Microsoft.NET.Sdk"></Project>\n';
const csproj = (include: string): string => `<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><ProjectReference Include="${include}" /></ItemGroup></Project>\n`;
const sln = (entry: string): string =>
  `Microsoft Visual Studio Solution File, Format Version 12.00\nProject("{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}") = "Lib", "${entry}", "{11111111-1111-1111-1111-111111111111}"\nEndProject\n`;
const ALL_NETWORK_PATHS: Array<{ id: string; path: string; windowsOnly: boolean }> = [
  { id: `${BS}${BS}T${BS}K@H${BS}share${BS}Lib.csproj`, path: `${BS}${BS}${T}${BS}${K}@${H}${BS}share${BS}Lib.csproj`, windowsOnly: true },
  { id: '//T/K@H/share/Lib.csproj', path: `//${T}/${K}@${H}/share/Lib.csproj`, windowsOnly: true },
];

// A network path is one only where Windows reads it: `isNetworkPath` of `platform/projectPath.ts` is never true on POSIX,
// where `//x` and `\\x` are local paths (the 3.16.0 release run on Linux, 2026-11-23).
const NETWORK_PATHS = ALL_NETWORK_PATHS.filter((p) => WIN || !p.windowsOnly);

describe(`${FEATURE} T-05 a ProjectReference or a solution entry on a network path`, () => {
  describe.each([
    { kind: 'a ProjectReference', files: (p: string) => ({ 'App.csproj': csproj(p), 'Lib.csproj': LIB }), target: 'App.csproj' },
    { kind: 'a .sln entry', files: (p: string) => ({ 'App.sln': sln(p), 'Lib.csproj': LIB }), target: 'App.sln' },
  ])('$kind', ({ files, target }) => {
    it.each(NETWORK_PATHS)('T-05 planDotnetRestore, $id: refused as a network path, the host not shown', ({ path }) => {
      const dir = project(files(path));
      const plan = planDotnetRestore(dir, join(dir, target));
      expect(plan.blocked?.code, JSON.stringify(plan.blocked)).toBe('network_path_reference');
      expectNoPart(plan.blocked?.reason ?? '');
      expect(plan.blocked?.reason).toContain('(host not shown)');
    });
  });
});

// ── the restore error line ───────────────────────────────────────────────────────────────────────────────────────
const FEED_ERROR = (source: string): string => `error NU1301: Unable to load the service index for source ${source}.`;
const SOURCES: Array<{ id: string; text: string; said?: string }> = [
  { id: 'https://T/K@H/v3/index.json', text: `https://${T}/${K}@${H}/v3/index.json` },
  { id: 'https://U:T@H/v3/index.json', text: `https://${U}:${T}@${H}/v3/index.json`, said: `https://${H}/v3/index.json` },
  { id: 'https:U:T@H/v3/index.json', text: `https:${U}:${T}@${H}/v3/index.json`, said: `https://${H}/v3/index.json` },
  { id: ' https://U:T@H/v3/index.json (a space too many)', text: ` https://${U}:${T}@${H}/v3/index.json`, said: `https://${H}/v3/index.json` },
  { id: 'ht<TAB>tps://U:T@H/v3/index.json', text: `ht${TAB}tps://${U}:${T}@${H}/v3/index.json`, said: `https://${H}/v3/index.json` },
  { id: 'https://T K@H/v3/index.json (criterion 3)', text: `https://${T} ${K}@${H}/v3/index.json`, said: 'source https://(host not shown)' },
  { id: 'the @ after character 240', text: `https://${T}/${'a'.repeat(240)}${K}@${H}/v3/index.json` },
];

describe(`${FEATURE} T-05 the restore error line`, () => {
  it.each(SOURCES)('T-05 classifyRestoreFailure, source $id: no part of the credentials', ({ text, said }) => {
    const failure = classifyRestoreFailure('', FEED_ERROR(text));
    expect(failure.code).toBe('NU1301');
    expect(failure.kind).toBe('feed_unreachable');
    expectNoPart(failure.reason);
    if (said !== undefined) expect(failure.reason).toContain(said);
    else expect(failure.reason).toContain('(host not shown)');
  });
});
