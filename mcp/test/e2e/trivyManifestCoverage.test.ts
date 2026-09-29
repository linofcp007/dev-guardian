/**
 * `assessManifestCoverage` against the REAL Trivy (fix round 1 of the
 * integration fix, I1). The coverage check reads Trivy's report and decides
 * which root manifests Trivy said nothing about. The "declares nothing"
 * exclusion (`trivy.ts`, `npmManifestDeclaresNothing`) takes a manifest out
 * of that check, so it rests on facts about Trivy that no mock can show.
 * This file pins those facts on the Trivy on PATH (measured on 0.69.3):
 *
 *   - a `package.json` that declares nothing produces no `Results` key,
 *     WITH a lock file that locks nothing as much as without one. That is
 *     why it is excluded: the report is identical to a real gap, and no lock
 *     file a user could add would change it;
 *   - a lock file that still locks packages (a stale one, left behind when a
 *     dependency was deleted from package.json) IS reported: Trivy reads the
 *     lock file, not package.json. The exclusion does not apply there, and
 *     the check finds npm covered.
 *
 * If a future Trivy stops reporting a stale lock file, the second test fails
 * here, and the unit tests in `test/unit/runners/scannerParsers/trivy.test.ts`
 * show the check would then report the npm gap rather than hide it.
 *
 * Gated on Trivy being on PATH (`it.skipIf`): a skip reports as a skip, and
 * `GUARDIAN_REQUIRE_SEMGREP=1` turns a missing Trivy into a hard failure, as
 * in `ciCliFixture.test.ts`. The same arguments as `scan_deps` / `deps_audit`,
 * so this is the report the product actually reads.
 */

import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { assessManifestCoverage } from '../../src/runners/scannerParsers/trivy.js';
import { isInstalled } from '../helpers/toolchain.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

afterAll(cleanupTempDirs);

const TRIVY_INSTALLED = await isInstalled('trivy');
const REQUIRE_TOOLCHAIN = process.env['GUARDIAN_REQUIRE_SEMGREP'] === '1';

/** Trivy may download its vulnerability DB on a first run: far past a warm run's few seconds. */
const TRIVY_TIMEOUT_MS = 300_000;

const EMPTY_MANIFEST = { name: 'x', version: '1.0.0', private: true };
const LODASH = { version: '4.17.4', resolved: 'https://registry.npmjs.org/lodash/-/lodash-4.17.4.tgz' };

/** `trivy fs --scanners vuln,license --format json`, exactly as scanDeps.ts runs it; the raw report. */
function trivyFs(project: string): string {
  const out = join(makeTempDir('trivy-manifest-e2e-out-'), 'deps.json');
  execFileSync('trivy', ['fs', '--scanners', 'vuln,license', '--format', 'json', '--output', out, '--quiet', project], {
    timeout: TRIVY_TIMEOUT_MS,
    stdio: 'ignore',
  });
  return readFileSync(out, 'utf8');
}

function resultsOf(raw: string): Array<{ Target?: string; Type?: string }> | undefined {
  return (JSON.parse(raw) as { Results?: Array<{ Target?: string; Type?: string }> }).Results;
}

function project(files: Record<string, unknown>): string {
  const dir = makeTempDir('trivy-manifest-e2e-');
  for (const [name, body] of Object.entries(files)) writeFileSync(join(dir, name), JSON.stringify(body, null, 2), 'utf8');
  return dir;
}

describe('assessManifestCoverage on a real Trivy report (npm "declares nothing")', () => {
  it.skipIf(!TRIVY_INSTALLED)(
    'a declares-nothing package.json beside a lock file that locks nothing: no Results, and no gap',
    () => {
      const dir = project({
        'package.json': EMPTY_MANIFEST,
        'package-lock.json': { name: 'x', version: '1.0.0', lockfileVersion: 3, requires: true, packages: { '': EMPTY_MANIFEST } },
      });
      const raw = trivyFs(dir);
      expect(resultsOf(raw)).toBeUndefined();
      expect(assessManifestCoverage(dir, raw)).toEqual({ gaps: [], sawAnyResults: false });
    },
    TRIVY_TIMEOUT_MS,
  );

  it.skipIf(!TRIVY_INSTALLED)(
    'a declares-nothing package.json beside a STALE package-lock.json that still locks lodash: Trivy reports it, npm is covered',
    () => {
      const dir = project({
        'package.json': EMPTY_MANIFEST,
        'package-lock.json': {
          name: 'x',
          version: '1.0.0',
          lockfileVersion: 3,
          requires: true,
          packages: { '': { ...EMPTY_MANIFEST, dependencies: { lodash: '4.17.4' } }, 'node_modules/lodash': LODASH },
        },
      });
      const raw = trivyFs(dir);
      expect(resultsOf(raw)).toEqual(
        expect.arrayContaining([expect.objectContaining({ Target: 'package-lock.json', Type: 'npm' })]),
      );
      expect(assessManifestCoverage(dir, raw)).toEqual({ gaps: [], sawAnyResults: true });
    },
    TRIVY_TIMEOUT_MS,
  );

  // Review 3.0, wave 2 (c): Trivy skips devDependencies by default, so a
  // lock holding only dev packages gets no Result — measured on 0.69.3, and
  // `--include-dev-deps` (which dev-guardian does not pass) brings it back.
  // Still a gap, but the lock file is there: marked dev_only, so the advice
  // is not "commit the lock file".
  it.skipIf(!TRIVY_INSTALLED)(
    'a package.json with only devDependencies beside its lock: no Results, a gap marked dev_only',
    () => {
      const manifest = { name: 'x', version: '1.0.0', devDependencies: { lodash: '4.17.4' } };
      const dir = project({
        'package.json': manifest,
        'package-lock.json': {
          name: 'x',
          version: '1.0.0',
          lockfileVersion: 3,
          requires: true,
          packages: { '': manifest, 'node_modules/lodash': { ...LODASH, dev: true } },
        },
      });
      const raw = trivyFs(dir);
      expect(resultsOf(raw)).toBeUndefined();
      expect(assessManifestCoverage(dir, raw)).toEqual({
        gaps: [{ ecosystem: 'npm', files: ['package.json'], dev_only: ['package.json'] }],
        sawAnyResults: false,
      });
    },
    TRIVY_TIMEOUT_MS,
  );

  it.runIf(REQUIRE_TOOLCHAIN)('GUARDIAN_REQUIRE_SEMGREP=1 — Trivy must be on PATH for this file to mean anything', () => {
    expect(TRIVY_INSTALLED, 'GUARDIAN_REQUIRE_SEMGREP=1 but trivy is not on PATH.').toBe(true);
  });
});

/** Files written as given — Gradle and TOML are not JSON. */
function textProject(files: Record<string, string>): string {
  const dir = makeTempDir('trivy-manifest-e2e-');
  for (const [name, body] of Object.entries(files)) writeFileSync(join(dir, name), body, 'utf8');
  return dir;
}

const GRADLE = "plugins { id 'java' }\ndependencies { implementation 'org.apache.logging.log4j:log4j-core:2.14.1' }\n";
const GRADLE_LOCK =
  '# This is a Gradle generated file for dependency locking.\n' +
  'org.apache.logging.log4j:log4j-core:2.14.1=compileClasspath,runtimeClasspath\nempty=\n';
const PEP621 = '[project]\nname = "x"\nversion = "0.1.0"\ndependencies = ["django==3.2.0"]\n';

/**
 * Final review I4, measured on 0.69.3: Trivy reads Gradle only from
 * `gradle.lockfile`, and Python only from a pinned `requirements.txt` or a
 * lock file. Before these ecosystems were in the table, both bare shapes
 * read `trivy ok`, coverage `full`, 0 findings. If a future Trivy starts
 * reading a bare manifest, the first or third test fails here — the gap
 * would then be a false alarm, and the table entry must be revisited.
 */
describe('assessManifestCoverage on a real Trivy report (Gradle and Python)', () => {
  it.skipIf(!TRIVY_INSTALLED)(
    'a build.gradle without gradle.lockfile: no Results, a gradle gap',
    () => {
      const dir = textProject({ 'build.gradle': GRADLE });
      const raw = trivyFs(dir);
      expect(resultsOf(raw) ?? []).toEqual([]);
      expect(assessManifestCoverage(dir, raw)).toEqual({
        gaps: [{ ecosystem: 'gradle', files: ['build.gradle'] }],
        sawAnyResults: false,
      });
    },
    TRIVY_TIMEOUT_MS,
  );

  it.skipIf(!TRIVY_INSTALLED)(
    'a build.gradle with gradle.lockfile: a gradle Result, covered',
    () => {
      const dir = textProject({ 'build.gradle': GRADLE, 'gradle.lockfile': GRADLE_LOCK });
      const raw = trivyFs(dir);
      expect(resultsOf(raw)).toEqual(
        expect.arrayContaining([expect.objectContaining({ Target: 'gradle.lockfile', Type: 'gradle' })]),
      );
      expect(assessManifestCoverage(dir, raw)).toEqual({ gaps: [], sawAnyResults: true });
    },
    TRIVY_TIMEOUT_MS,
  );

  it.skipIf(!TRIVY_INSTALLED)(
    'a PEP 621 pyproject.toml alone: no Results, a python gap',
    () => {
      const dir = textProject({ 'pyproject.toml': PEP621 });
      const raw = trivyFs(dir);
      expect(resultsOf(raw) ?? []).toEqual([]);
      expect(assessManifestCoverage(dir, raw)).toEqual({
        gaps: [{ ecosystem: 'python', files: ['pyproject.toml'] }],
        sawAnyResults: false,
      });
    },
    TRIVY_TIMEOUT_MS,
  );

  it.skipIf(!TRIVY_INSTALLED)(
    'a setuptools project (setup.py install_requires + a build-system-only pyproject.toml): no Results, a python gap on setup.py',
    () => {
      const dir = textProject({
        'setup.py': 'from setuptools import setup\nsetup(name="x", install_requires=["django==3.2.0"])\n',
        'pyproject.toml': '[build-system]\nrequires = ["setuptools"]\nbuild-backend = "setuptools.build_meta"\n',
      });
      const raw = trivyFs(dir);
      expect(resultsOf(raw) ?? []).toEqual([]);
      expect(assessManifestCoverage(dir, raw)).toEqual({
        gaps: [{ ecosystem: 'python', files: ['setup.py'] }],
        sawAnyResults: false,
      });
    },
    TRIVY_TIMEOUT_MS,
  );

  it.skipIf(!TRIVY_INSTALLED)(
    'a pinned requirements.txt beside the pyproject.toml: a pip Result, python covered',
    () => {
      const dir = textProject({ 'pyproject.toml': PEP621, 'requirements.txt': 'django==3.2.0\n' });
      const raw = trivyFs(dir);
      expect(resultsOf(raw)).toEqual(
        expect.arrayContaining([expect.objectContaining({ Target: 'requirements.txt', Type: 'pip' })]),
      );
      expect(assessManifestCoverage(dir, raw)).toEqual({ gaps: [], sawAnyResults: true });
    },
    TRIVY_TIMEOUT_MS,
  );
});
