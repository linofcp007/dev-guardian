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

  it.runIf(REQUIRE_TOOLCHAIN)('GUARDIAN_REQUIRE_SEMGREP=1 — Trivy must be on PATH for this file to mean anything', () => {
    expect(TRIVY_INSTALLED, 'GUARDIAN_REQUIRE_SEMGREP=1 but trivy is not on PATH.').toBe(true);
  });
});
