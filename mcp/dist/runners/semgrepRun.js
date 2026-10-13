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
import { DEFAULT_SEMGREP_TIMEOUT_S, DEFAULT_SEMGREP_TIMEOUT_THRESHOLD, loadScanSettings, semgrepTimeoutArgs, } from '../platform/scanSettings.js';
import { runProcess } from './processRunner.js';
import { pythonUtf8Env } from './semgrepReport.js';
/** The command itself, for callers that describe a Semgrep spawn as data (`scanFileBatches`, `batchArgs`). */
export const SEMGREP_COMMAND = 'semgrep';
/**
 * `.guardian/` is dev-guardian's own state — reports of earlier scans
 * (`sast.json`, `surface.json`: 1.5 MB a run on a mid-size tree), the
 * baseline, the database — and never a scan target: a project whose
 * `.gitignore` lacks the lines (every CLI-only and CI project) had Semgrep
 * read its old reports (review 8, finding 14). Unanchored: a sub-project's
 * `.guardian/` too.
 */
export const SEMGREP_EXCLUDE_GUARDIAN_DIR = '--exclude=.guardian';
/**
 * The flags every Semgrep scan of a project takes besides its rules: the
 * per-file timeout and threshold from `.guardian/scan.yml` under `configRoot`
 * (the project, or the CI gate's `--rules-ref` copy — `platform/scanSettings.ts`)
 * and {@link SEMGREP_EXCLUDE_GUARDIAN_DIR}. `warning`: the settings file was
 * there but not applied, and why — the caller says so on the run.
 */
export function semgrepScanFlags(configRoot) {
    const loaded = loadScanSettings(configRoot);
    return {
        args: [...semgrepTimeoutArgs(loaded.settings), SEMGREP_EXCLUDE_GUARDIAN_DIR],
        warning: loaded.kind === 'invalid'
            ? `${loaded.path} was not applied (${loaded.error}) — Semgrep ran with dev-guardian's defaults ` +
                `(--timeout ${DEFAULT_SEMGREP_TIMEOUT_S} --timeout-threshold ${DEFAULT_SEMGREP_TIMEOUT_THRESHOLD})`
            : null,
    };
}
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