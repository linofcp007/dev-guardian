/**
 * Every Semgrep spawn in this codebase — one helper, so none can forget
 * Python's UTF-8 mode (review M3).
 *
 * Semgrep's CLI is Python and, without `PYTHONUTF8=1`, reads rule files and
 * writes `--output` in the locale's encoding (`semgrepReport.ts#pythonUtf8Env`
 * has the measurements). scan_sast, the RGPD pack, create_fix_pr and the
 * surface scan set it; bug_hunt and scan_wordpress did not — so with
 * PYTHONUTF8 unset, a project holding a file named `日本.py` made Semgrep
 * 1.176.1 exit 2 without a report on Windows (cp1252): bug_hunt read "report
 * is not valid JSON (exit 2)" and advised installing Semgrep.
 *
 * `test/unit/runners/semgrepRun.test.ts` fails when any file in `src/` names
 * Semgrep as a command outside this one. The toolchain probe
 * (`semgrep --version`, `runners/installCatalog.ts`) is the one exception:
 * it reads no project.
 *
 * Semgrep's own version check asks Semgrep's servers for a newer release on
 * every run — `--metrics=off` and `local_only` included, and
 * `semgrep --version` too — unless `SEMGREP_ENABLE_VERSION_CHECK=0` (review
 * 3.0, wave 2). {@link SEMGREP_NO_VERSION_CHECK_ENV} goes into every spawn
 * here, into the Docker fallback's container (`dockerScanner.ts`, `-e`) and
 * into check_toolchain's probe (`installCatalog.ts`); `init_project`'s status
 * script sets it as well.
 */
import { runProcess } from './processRunner.js';
import { pythonUtf8Env } from './semgrepReport.js';
/** The command itself, for callers that describe a Semgrep spawn as data (`scanFileBatches`, `batchArgs`). */
export const SEMGREP_COMMAND = 'semgrep';
/** Semgrep's version check off — whatever the caller's environment says. */
export const SEMGREP_NO_VERSION_CHECK_ENV = { SEMGREP_ENABLE_VERSION_CHECK: '0' };
/**
 * The command and environment of a Semgrep spawn: the caller's environment
 * (or the server's) plus `PYTHONUTF8=1` and {@link SEMGREP_NO_VERSION_CHECK_ENV}.
 */
export function semgrepSpawn(env) {
    return { command: SEMGREP_COMMAND, env: { ...pythonUtf8Env(env), ...SEMGREP_NO_VERSION_CHECK_ENV } };
}
/** Run Semgrep — through `run` when the caller injects one (create_fix_pr's worktree runner). */
export function runSemgrep(opts, run = runProcess) {
    return run({ ...opts, ...semgrepSpawn(opts.env) });
}
//# sourceMappingURL=semgrepRun.js.map