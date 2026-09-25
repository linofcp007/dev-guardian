import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    environment: 'node',
    // Item 8 (2026-09-25 full review, Task 5 — packaging/deps): raised from
    // 10_000 as an unavoidable, minimal consequence of the vitest 2 -> 5
    // dependency bump (mcp/package.json is this task's own file; the
    // several semgrep-heavy integration test files this actually affects
    // are not — see the task report for the full reasoning; this is the
    // one shared, out-of-lane touch that fix required).
    //
    // Several `test/integration/*Rules*.test.ts` / `semgrepPacks.test.ts`
    // tests invoke real `semgrep` SYNCHRONOUSLY (execSync/spawnSync, no
    // await) across every rule pack / every hit fixture — genuinely slow
    // (measured 41-90s for ONE such call under heavy concurrent machine
    // load) and, it turns out, was NEVER actually bounded by this 10s
    // config value: vitest's timeout is enforced via a timer on the event
    // loop, which cannot fire while a SYNCHRONOUS call blocks the thread —
    // confirmed directly, re-running the identical test unmodified on
    // vitest 2.1.9 under the SAME load that failed it on 5.0.1: it took
    // 63s and PASSED, because the timeout timer never got a chance to run
    // until the call had already returned. vitest 5 evidently measures and
    // reports the overrun differently, surfacing a gap that was always
    // real but never enforced. The fix is a genuinely longer budget, not a
    // narrower one already exceeded in practice.
    testTimeout: 180_000,
    // Runs in every worker before its test files. Gives each worker its own
    // Semgrep settings file so concurrent Semgrep invocations — within one
    // run, or across two agents running this suite at once — stop racing on
    // the single global `~/.semgrep/settings.yml`. That race is not
    // theoretical: it crashes Semgrep with an uncaught PermissionError and
    // the failure reads as a broken rule pack. See the file's own comment for
    // the mechanism and the measurements.
    setupFiles: ['./test/setup/semgrepSettings.ts'],
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
