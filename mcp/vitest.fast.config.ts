import { configDefaults, defineConfig } from 'vitest/config';
import base from './vitest.config.js';

/**
 * The fast lane (`npm run test:fast`, review 8, finding 6): the unit and docs
 * tests, minus the few unit files that take most of their time — the inner
 * loop while you work. `npm test`, the full suite, is still the gate: run it
 * before you commit.
 *
 * Out of this lane: `test/integration/` and `test/e2e/` (real scanners, real
 * subprocesses, real repositories), and the unit files below, each over 8 s
 * in a full run with 4 workers (measured 2026-10-13; together 590 of the 753
 * seconds the unit and docs files took): timing shapes, fuzz corpora, real git
 * and real databases. What is left — 287 files — took 134 s of file time,
 * about 40 s of wall time on 4 workers.
 */
const SLOW_UNIT_FILES = [
  'test/unit/hooks/bashGuard.test.ts',
  'test/unit/platform/yamlBounds.test.ts',
  'test/unit/ci/refConfig.test.ts',
  'test/unit/platform/gitSafety.test.ts',
  'test/unit/history/openSetCarryForward.test.ts',
  'test/unit/platform/scope.test.ts',
  'test/unit/storage/dbTrust.test.ts',
  'test/unit/ci/appRunner.test.ts',
  'test/unit/pluginSurface/distSync.test.ts',
  'test/unit/hooks/secretScan.test.ts',
  'test/unit/pkgvet/hookDecision.test.ts',
  'test/unit/runners/processRunner.test.ts',
  'test/unit/testHelpers/timing.test.ts',
  'test/unit/sarif/importSarif.test.ts',
  'test/unit/fixpr/semgrepFix.test.ts',
];

export default defineConfig({
  ...base,
  test: {
    ...base.test,
    include: ['test/unit/**/*.test.ts', 'test/docs/**/*.test.ts'],
    exclude: [...configDefaults.exclude, ...SLOW_UNIT_FILES],
  },
});
