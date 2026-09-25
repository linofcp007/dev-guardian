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
    // Runs in every worker before its test files. Gives each worker its own
    // Semgrep settings file so concurrent Semgrep invocations — within one
    // run, or across two agents running this suite at once — stop racing on
    // the single global `~/.semgrep/settings.yml`. That race is not
    // theoretical: it crashes Semgrep with an uncaught PermissionError and
    // the failure reads as a broken rule pack. See the file's own comment for
    // the mechanism and the measurements.
    // canonicalTmpdir.ts: os.tmpdir() in its canonical spelling — see the file.
    setupFiles: ['./test/setup/canonicalTmpdir.ts', './test/setup/semgrepSettings.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html'],
      include: ['src/**/*.ts'],
      // server.ts = bootstrap, registerAll.ts = side-effect import list only.
      exclude: ['src/**/*.d.ts', 'src/server.ts', 'src/registerAll.ts'],
      // Floors set just below current (73/68/79/73). Raise as the suite grows;
      // CI fails if coverage regresses below these.
      thresholds: {
        statements: 70,
        branches: 62,
        functions: 72,
        lines: 70,
      },
    },
  },
});
