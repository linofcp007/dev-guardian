/**
 * deps-tools-host-other-texts, task 2, T-04 (red until the fix): the cuts the dependency readers make before the rule
 * sees the value. A reader cuts a yarn.lock value at a space, a quote, a comma or 2 048 characters; a requirement at
 * its `;`; a line at its comment; an option at its space or `=`; a setup.cfg line at its `;` or `#`. The URL that is left
 * reads as a host that is the START of a credential (`https://T;K@H/…` is read as `https://T`), and an `@` after the cut
 * is never seen. The rule must see the text before the cut: an `@` in what was cut says the host is not said.
 *
 * Each assertion is that no made-up part of a credential is in what the reader says, and that the host is said
 * `(host not shown)`. Every credential-looking value is MADE UP and built from parts.
 */

import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { checkRequirements } from '../../../src/deps/pipRequirements.js';
import { checkPyproject, checkSetupCfg } from '../../../src/deps/pythonProject.js';
import { checkNpmSources } from '../../../src/fixpr/repoPackageConfig.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

const FEATURE = 'deps-tools-host-other-texts';
const T = ['tok', 'ZzQ', '7731'].join('');
const K = ['ken', 'Qq', '88'].join('');
const U = ['dg', 'user', 'zq'].join('');
const H = 'host.example';
const P = ['dgprobe', 'zzq7731', 'p'].join('-');
const PAD = 'p'.repeat(2100); // puts the `@` more than 2048 characters after the start of the path

const partsIn = (text: string): string[] => [T, K, U].filter((p) => text.toLowerCase().includes(p.toLowerCase()));
/** What the reader says: no part of the credentials in it, and the host not shown. */
function expectHostNotShown(said: unknown): void {
  const text = JSON.stringify(said);
  expect(partsIn(text), text).toEqual([]);
  expect(text, 'the host is said as not shown').toContain('(host not shown)');
}

function project(files: Record<string, string>): string {
  const dir = makeTempDir('dg-urlcut-');
  for (const [name, text] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, name)), { recursive: true });
    writeFileSync(join(dir, name), text);
  }
  return dir;
}

// ── yarn.lock ────────────────────────────────────────────────────────────────────────────────────────────────────
const MANIFEST = `${JSON.stringify({ name: 'dgproj', version: '1.0.0', dependencies: { dgdep: '^1.0.0' } }, null, 2)}\n`;
/** A yarn.lock quoted string: yarn writes a `"` inside one as `\"`. */
const yq = (v: string): string => `"${v.replace(/"/g, '\\"')}"`;
const YARN_PLACES: Array<{ id: string; lock: (v: string) => string }> = [
  { id: 'resolved "V"', lock: (v) => `# yarn lockfile v1\n\n\ndgdep@^1.0.0:\n  version "1.0.0"\n  resolved ${yq(v)}\n` },
  { id: 'resolved V (not quoted)', lock: (v) => `# yarn lockfile v1\n\n\ndgdep@^1.0.0:\n  version "1.0.0"\n  resolved ${v}\n` },
  { id: 'the key of the entry', lock: (v) => `# yarn lockfile v1\n\n\n${yq(`dgdep@${v}`)}:\n  version "1.0.0"\n` },
  { id: 'resolution of Berry', lock: (v) => `__metadata:\n  version: 8\n\n${yq(`dgdep@${v}`)}:\n  version: 1.0.0\n  resolution: ${yq(`dgdep@${v}`)}\n` },
];
const YARN_PATHS: Array<{ id: string; value: string }> = [
  { id: 'a comma', value: `//${T}/a,${K}@${H}/x.tgz` },
  { id: 'an apostrophe', value: `//${T}/a'${K}@${H}/x.tgz` },
  { id: 'a space', value: `//${T}/a ${K}@${H}/x.tgz` },
  { id: 'a double quote', value: `//${T}/a"${K}@${H}/x.tgz` },
  { id: 'the @ after 2048 characters', value: `//${T}/${PAD}/${K}@${H}/x.tgz` },
];

describe(`${FEATURE} T-04 yarn.lock: a network path cut by the reader`, () => {
  describe.each(YARN_PLACES)('$id', ({ lock }) => {
    it.each(YARN_PATHS)('T-04 checkNpmSources, $id: the host is not shown, no part of the credentials', ({ value }) => {
      const dir = project({ 'package.json': MANIFEST, 'yarn.lock': lock(value) });
      const check = checkNpmSources(dir);
      expect(check.network.length, JSON.stringify(check)).toBeGreaterThan(0);
      expectHostNotShown(check.network);
    });
  });
});

// ── requirements.txt ─────────────────────────────────────────────────────────────────────────────────────────────
const requirements = (line: string): unknown => {
  const dir = project({ 'requirements.txt': `${line}\n` });
  return checkRequirements(dir, ['requirements.txt']).refusals;
};
const SEMICOLONS = [`${T};${K}@`, `${T} ;${K}@`];
const REQUIREMENT_LINES: Array<{ id: string; line: string }> = [
  ...SEMICOLONS.flatMap((c, i) => {
    const mark = i === 0 ? ';' : ' ;';
    return [
      { id: `name @ URL, ${mark} in the credentials`, line: `${P} @ https://${c}${H}/x.tar.gz` },
      { id: `name @ git+URL, ${mark} in the credentials`, line: `${P} @ git+https://${c}${H}/r.git` },
      { id: `only the URL, ${mark} in the credentials`, line: `https://${c}${H}/x.tar.gz` },
      { id: `//…, ${mark} in the credentials`, line: `//${c}${H}/share` },
      { id: `file://…, ${mark} in the credentials`, line: `file://${c}${H}/x.tgz` },
    ];
  }),
  { id: '--index-url, a comment with an @ after', line: `--index-url https://${H}/simple # ${K}@x` },
  { id: 'a requirement, a comment with an @ after', line: `${P} @ https://${H}/x.tar.gz # ${K}@x` },
  { id: '-r URL, a comment with an @ after', line: `-r https://${H}/more.txt # ${K}@x` },
  { id: '--find-links //T/a=K@H', line: `--find-links //${T}/a=${K}@${H}/share` },
  { id: '-r //T/a=K@H', line: `-r //${T}/a=${K}@${H}/more.txt` },
  { id: '--find-links "//T/a K@H"', line: `--find-links "//${T}/a ${K}@${H}/share"` },
  { id: '//T/a;K@H as a requirement', line: `//${T}/a;${K}@${H}/share` },
];

describe(`${FEATURE} T-04 requirements.txt: a line cut before its host is read`, () => {
  it.each(REQUIREMENT_LINES)('T-04 checkRequirements, $id: the host is not shown, no part of the credentials', ({ line }) => {
    const refusals = requirements(line);
    expect(JSON.stringify(refusals)).not.toBe('[]');
    expectHostNotShown(refusals);
  });
});

// ── pyproject.toml and setup.cfg ─────────────────────────────────────────────────────────────────────────────────
const CUTS = [
  { id: ';', item: `${P} @ https://${T};${K}@${H}/x.tar.gz` },
  { id: ' ;', item: `${P} @ https://${T} ;${K}@${H}/x.tar.gz` },
  { id: ' #', item: `${P} @ https://${T} #${K}@${H}/x.tar.gz` },
];
const toml = (item: string): string => JSON.stringify(item);
const PYPROJECT_TABLES: Array<{ id: string; file: (item: string) => string }> = [
  { id: '[project].dependencies', file: (i) => `[project]\nname = "x"\nversion = "0"\ndependencies = [${toml(i)}]\n` },
  { id: '[project.optional-dependencies]', file: (i) => `[project]\nname = "x"\nversion = "0"\n\n[project.optional-dependencies]\nextra = [${toml(i)}]\n` },
  { id: '[dependency-groups]', file: (i) => `[project]\nname = "x"\nversion = "0"\n\n[dependency-groups]\ndev = [${toml(i)}]\n` },
  { id: '[build-system].requires', file: (i) => `[build-system]\nrequires = [${toml(i)}]\n` },
];
const SETUP_PLACES: Array<{ id: string; file: (item: string) => string }> = [
  { id: 'install_requires on the same line', file: (i) => `[options]\ninstall_requires = ${i}\n` },
  { id: 'install_requires, continued', file: (i) => `[options]\ninstall_requires =\n    ${i}\n` },
  { id: '[options.extras_require]', file: (i) => `[options.extras_require]\nextra =\n    ${i}\n` },
];

describe(`${FEATURE} T-04 pyproject.toml and setup.cfg: a requirement cut by the reader`, () => {
  describe.each(PYPROJECT_TABLES)('$id', ({ file }) => {
    it.each(CUTS)('T-04 checkPyproject, $id in the credentials: the host is not shown, no part of the credentials', ({ item }) => {
      const dir = project({ 'pyproject.toml': file(item) });
      const refusals = checkPyproject(dir, dir, false);
      expect(refusals.length, JSON.stringify(refusals)).toBeGreaterThan(0);
      expectHostNotShown(refusals);
    });
  });
  describe.each(SETUP_PLACES)('$id', ({ file }) => {
    it.each(CUTS)('T-04 checkSetupCfg, $id in the credentials: the host is not shown, no part of the credentials', ({ item }) => {
      const dir = project({ 'setup.cfg': file(item) });
      const refusals = checkSetupCfg(dir, dir);
      expect(refusals.length, JSON.stringify(refusals)).toBeGreaterThan(0);
      expectHostNotShown(refusals);
    });
  });
});
