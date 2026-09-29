/**
 * Every Trivy spawn in this codebase — one helper, so that no pass can be
 * steered by the configuration of the repository it is scanning.
 *
 * ---- The defect ------------------------------------------------------------
 *
 * Trivy reads `trivy.yaml` from its WORKING DIRECTORY whenever `--config` is
 * not given, and every pass used to run with `cwd` set to the project. So a
 * repository could commit its own `trivy.yaml` and decide what its scan
 * reports. Reproduced with the CLI gate against a project pinning lodash
 * 4.17.15: without the file, exit 1, coverage full, 7 findings; with a
 * committed `trivy.yaml` of `severity: [UNKNOWN]`, exit 0, coverage full,
 * no gap, 0 findings. The same file can set `db.repository` or `server.addr`,
 * which would send the project's package list to a host of the file's
 * choosing and trust whatever it answers.
 *
 * ---- What this does --------------------------------------------------------
 *
 *   - Trivy runs in `workDir` — a report directory this scan created, never
 *     the project — and is handed its target as an explicit path.
 *   - It is always given `--config <an empty file this helper writes>`, so no
 *     `trivy.yaml` is looked up anywhere at all.
 *   - The project's `.trivyignore` (the one file Trivy used to pick up from
 *     the project on its own that a project legitimately owns: accepted
 *     risks) is honoured only EXPLICITLY — `--ignorefile <project>/.trivyignore`
 *     when it exists — and returned in `honoured`, so the caller names it in
 *     the result. A suppression file that decides what a scan reports is
 *     never applied in silence. Trivy's other cwd lookups (`trivy-secret.yaml`,
 *     a default `.trivyignore`) find nothing in a report directory.
 *
 * Measured on Trivy 0.69.3: the project's `trivy.yaml` above takes the scan
 * from 7 findings to 0 when Trivy runs in the project; run from a report
 * directory with `--config` pointing at an empty file, the same project
 * reports all 7. `--skip-dirs` / `--skip-files` stay anchored at the target
 * (not the working directory), so `.guardianignore`'s native flags keep
 * working. `test/unit/runners/trivyRun.test.ts` fails when any spawn in
 * `src/` names Trivy outside this file.
 */
import { existsSync, lstatSync, mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { runProcess } from './processRunner.js';
import { assessManifestCoverage } from './scannerParsers/trivy.js';
/** The project's own Trivy suppression file, honoured explicitly. */
export const PROJECT_TRIVYIGNORE = '.trivyignore';
/** The empty configuration file written into the working directory. */
export const NEUTRAL_TRIVY_CONFIG = 'trivy-neutral-config.yaml';
const NEUTRAL_CONFIG_TEXT = "# Written by dev-guardian: an empty Trivy configuration, passed as --config so that the\n" +
    "# scanned repository's own trivy.yaml is never read.\n";
/** The project's `.trivyignore`, when it is a regular file; else null. */
export function projectTrivyIgnore(projectPath) {
    const path = join(projectPath, PROJECT_TRIVYIGNORE);
    try {
        return existsSync(path) && lstatSync(path).isFile() ? path : null;
    }
    catch {
        return null;
    }
}
/** The argv of one run — pure, for the tests. */
export function trivyArgv(inv, configPath, ignoreFile) {
    return [...inv.args, '--config', configPath, ...(ignoreFile !== null ? ['--ignorefile', ignoreFile] : []), inv.target];
}
/** Run Trivy — see the module comment. A config that cannot be written is a failed run, never one without it. */
export async function runTrivy(inv) {
    const configPath = join(inv.workDir, NEUTRAL_TRIVY_CONFIG);
    try {
        mkdirSync(inv.workDir, { recursive: true });
        writeFileSync(configPath, NEUTRAL_CONFIG_TEXT, 'utf8');
    }
    catch (e) {
        const why = e instanceof Error ? e.message : String(e);
        return {
            outcome: 'failed',
            exitCode: null,
            stdout: '',
            stderr: `could not write the neutral Trivy configuration ${configPath}: ${why}`,
            truncated: false,
            honoured: [],
        };
    }
    const ignoreFile = inv.ignoreFrom !== undefined ? projectTrivyIgnore(inv.ignoreFrom) : null;
    const run = await runProcess({
        command: 'trivy',
        args: trivyArgv(inv, configPath, ignoreFile),
        cwd: inv.workDir,
        ...(inv.env !== undefined ? { env: inv.env } : {}),
        ...(inv.signal !== undefined ? { signal: inv.signal } : {}),
        ...(inv.onLog !== undefined ? { onLog: inv.onLog } : {}),
        ...(inv.timeoutMs !== undefined ? { timeoutMs: inv.timeoutMs } : {}),
    });
    return { ...run, honoured: ignoreFile !== null ? [PROJECT_TRIVYIGNORE] : [] };
}
/** The words a `tools_run` reason carries for what a run honoured, or null. */
export function honouredNote(honoured) {
    if (honoured.length === 0)
        return null;
    return `honoured the project's ${honoured.join(', ')} (repository configuration: its entries are not reported)`;
}
/**
 * `run` naming what it honoured: the note appended to its reason, and the
 * files in `honoured_config`. Unchanged when nothing was.
 */
export function withHonoured(run, honoured) {
    const note = honouredNote(honoured);
    if (note === null)
        return run;
    const reason = run.reason !== undefined && run.reason.length > 0 ? `${run.reason}; ${note}` : note;
    return { ...run, reason, honoured_config: [...honoured] };
}
/**
 * The `trivy` entry of a dependency pass (`trivy fs --scanners vuln[,license]`)
 * — the ONE judgement scan_deps, deps_audit and scan_wordpress share (review
 * I2: scan_wordpress had none, so a plugin whose composer.json has no lock
 * read `ok`, full, where scan_deps on the same tree read none):
 *
 *   - the process did not complete → `failed`;
 *   - every manifest the walk found was read → `ok`;
 *   - some were not, and Trivy reported other Results → `ok`, reason
 *     `no_supported_manifest`, each gap listed missing as `trivy:<ecosystem>`
 *     — never the bare `trivy`: `create_fix_pr`'s verification reads a
 *     literal `trivy` in `missing_tools` as "Trivy did not run", which would
 *     block every Trivy-sourced fix over one uncovered ecosystem;
 *   - none were, and Trivy reported nothing at all → `skipped`,
 *     `no_supported_manifest`, `trivy` missing.
 *
 * `trivy.ts#assessManifestCoverage` walks the tree (review I1); a walk that
 * stopped early says so in the reason.
 */
export function judgeTrivyFs(args) {
    const { projectPath, raw, run, exclusions } = args;
    if (run.outcome !== 'completed') {
        return {
            toolRun: withHonoured({ name: 'trivy', status: 'failed', reason: run.outcome }, run.honoured),
            missing: [],
            gaps: [],
        };
    }
    const coverage = assessManifestCoverage(projectPath, raw ?? '', {
        ignores: exclusions === null ? null : (rel, isDir) => exclusions.ignores(rel, isDir),
    });
    const note = coverage.walkIncomplete !== undefined ? `${coverage.walkIncomplete} — manifests below were not checked` : null;
    const withNote = (r) => withHonoured(note === null ? r : { ...r, reason: r.reason !== undefined ? `${r.reason}; ${note}` : note }, run.honoured);
    if (coverage.gaps.length > 0 && coverage.sawAnyResults) {
        return {
            toolRun: withNote({ name: 'trivy', status: 'ok', reason: 'no_supported_manifest' }),
            missing: coverage.gaps.map((g) => `trivy:${g.ecosystem}`),
            gaps: coverage.gaps,
        };
    }
    if (coverage.gaps.length > 0) {
        return {
            toolRun: withNote({ name: 'trivy', status: 'skipped', reason: 'no_supported_manifest' }),
            missing: ['trivy'],
            gaps: coverage.gaps,
        };
    }
    return { toolRun: withNote({ name: 'trivy', status: 'ok' }), missing: [], gaps: [] };
}
//# sourceMappingURL=trivyRun.js.map