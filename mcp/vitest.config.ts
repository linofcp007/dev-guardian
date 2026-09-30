import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    environment: 'node',
    // Item 8's first fix (2026-09-25 full review) raised this GLOBALLY to
    // 180_000 to work around a handful of slow, real-Semgrep-invoking
    // integration/e2e tests — fix round 1, item 4 (Important, review round
    // 1) reverted that: a 180s ceiling for all 141 files hides a genuine
    // hang in any of the other, fast, unit-level tests for three whole
    // minutes instead of ten seconds. The unit default stays 10_000; the
    // handful of files that genuinely need longer (real `semgrep`
    // subprocess calls across a whole rule pack / every hit fixture) set
    // their OWN, file-scoped override via `vi.setConfig({ testTimeout })`
    // at the top of the file — see each one's own comment for why. That
    // override is why those files can run long without needing this default
    // raised for everything else.
    testTimeout: 10_000,
    // Hooks, unlike tests, get 30 s (review 3.0, R7). Sixty files load the
    // tool under test in a `beforeAll(async () => { await import(...) })`,
    // and in the first wave of a coverage run — every worker starting at
    // once, each import transforming and instrumenting the tool's whole
    // module graph — two such hooks measured 10.2 s and 10.3 s and failed
    // their files (55 tests skipped) with nothing wrong. A hook that is
    // genuinely hung is still reported, 20 s later.
    hookTimeout: 30_000,
    // Task 19 (EPSS/KEV intel): `intel/enrich.ts` calls the network for any
    // CVE it has not cached in the last 24h, and several PRE-EXISTING tests
    // exercise real trivy-sourced CVEs (e.g. `test/integration/createFixPr.test.ts`'s
    // risk_score check) without mocking `fetch` — they were written before
    // this feature existed and must not suddenly start dialing out. Default
    // network off for the whole suite; a test that specifically exercises the
    // online path clears it with `vi.stubEnv('GUARDIAN_OFFLINE', '0')` (and
    // `vi.unstubAllEnvs()` after) and supplies its own mocked `fetch` — see
    // `test/unit/intel/*.test.ts`. The one test allowed to hit the real APIs
    // is gated behind its own env var instead (`test/e2e/cveIntelLive.test.ts`).
    env: { GUARDIAN_OFFLINE: '1' },
    // Runs in every worker before its test files. Gives each worker its own
    // Semgrep settings file so concurrent Semgrep invocations — within one
    // run, or across two agents running this suite at once — stop racing on
    // the single global `~/.semgrep/settings.yml`. That race is not
    // theoretical: it crashes Semgrep with an uncaught PermissionError and
    // the failure reads as a broken rule pack. See the file's own comment for
    // the mechanism and the measurements.
    // canonicalTmpdir.ts: os.tmpdir() in its canonical spelling — see the file.
    // userDataDir.ts: the per-user database fallback goes to a temp directory.
    setupFiles: ['./test/setup/canonicalTmpdir.ts', './test/setup/semgrepSettings.ts', './test/setup/userDataDir.ts'],
    // tempLeftovers: removes, before and after the run, the temp directories
    // a test's cleanup could not (a timed-out test's process still held
    // them) — see `LEFTOVERS_FILE` in test/helpers/tempDir.ts.
    // semgrepHome: the run's own directory, Semgrep's log and version cache
    // pointed into it (never the home directory), and a check at the end that
    // nothing wrote the real ones — see the file.
    globalSetup: ['./test/setup/tempLeftovers.ts', './test/setup/semgrepHome.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html'],
      include: ['src/**/*.ts'],
      // server.ts = bootstrap, registerAll.ts = side-effect import list only.
      exclude: ['src/**/*.d.ts', 'src/server.ts', 'src/registerAll.ts'],
      // Floors a few points below what `npm run test:coverage` measured on
      // Windows at the end of review 3.0 (R7): 91.89 / 82.61 / 96.03 / 94.59
      // (statements / branches / functions / lines). They were 70/62/72/70
      // against a suite measuring ~91/82/96/94 — a floor 20 points down lets
      // a fifth of the tested code go untested before anything notices. The
      // margin absorbs what differs between machines (the POSIX-only and
      // Windows-only tests each skip on the other). Raise them as the suite
      // grows; `npm run test:coverage` fails below them.
      thresholds: {
        statements: 89,
        branches: 80,
        functions: 93,
        lines: 92,
      },
    },
  },
});
