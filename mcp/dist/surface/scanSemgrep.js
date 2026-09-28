import { copyFileSync, existsSync, lstatSync } from 'node:fs';
import { join } from 'node:path';
import { buildSemgrepDockerArgs, DEFAULT_SEMGREP_IMAGE, toContainerPath, } from '../runners/dockerScanner.js';
import { git, splitNul } from '../runners/git.js';
import { runProcess } from '../runners/processRunner.js';
import { countFilesWithExtension, PROJECT_WALK_EXCLUDE } from '../runners/projectFiles.js';
import { checkSemgrepReport, describePartialParse, pythonUtf8Env } from '../runners/semgrepReport.js';
import { scannerAvailable } from '../tools/scanHelpers.js';
import { ROUTE_PACK_EXTENSIONS } from './extract.js';
/**
 * Run Semgrep against the routes rule pack, natively if it's on PATH,
 * otherwise via Docker. Returns null only when neither is available — the
 * caller treats that as "cannot run at all" and persists nothing.
 *
 * Mirrors scan_sast's Docker fallback: probe `docker`, bind the project at
 * `/src`, run the container, and check for real output. The argv comes from
 * the shared `buildSemgrepDockerArgs` — this tool only differs in
 * `--config`, which the builder takes as an option, so the mount shape, the
 * output rewriting and anything added there later apply here too. The rule
 * pack lives outside the project tree (in the dev-guardian install), so we
 * stage a copy inside the report dir — already inside the project, already
 * inside the bind mount — instead of adding a second `--mount`.
 */
export async function invokeSemgrep(options) {
    const { projectPath, rulesPath, outFile, reportDir } = options;
    const semgrepBin = await scannerAvailable('semgrep');
    if (semgrepBin !== null) {
        const run = await runProcess({
            command: 'semgrep',
            args: ['--config', rulesPath, '--json', '--output', outFile, '--quiet', projectPath],
            cwd: projectPath,
            // UTF-8 mode, like every other Semgrep call site: otherwise the locale
            // codec reads the rule pack and writes `--output`
            // (runners/semgrepReport.ts#pythonUtf8Env).
            env: pythonUtf8Env(process.env),
        });
        return { toolRun: buildToolRun(run), run, via: null };
    }
    const dockerBin = await scannerAvailable('docker');
    if (dockerBin === null)
        return null;
    const image = process.env['GUARDIAN_SEMGREP_IMAGE'] || DEFAULT_SEMGREP_IMAGE;
    const via = `docker (${image})`;
    let containerRules;
    try {
        const stagedRules = join(reportDir, 'routes.yml');
        copyFileSync(rulesPath, stagedRules);
        containerRules = toContainerPath(projectPath, stagedRules);
    }
    catch (e) {
        return {
            toolRun: {
                name: 'semgrep',
                status: 'failed',
                reason: `docker: could not stage rule pack: ${e.message}`,
            },
            run: null,
            via,
        };
    }
    const run = await runProcess({
        command: 'docker',
        args: buildSemgrepDockerArgs({
            projectPath,
            outFileHost: outFile,
            image,
            configs: [containerRules],
        }),
        cwd: projectPath,
    });
    return { toolRun: buildToolRun(run, via), run, via };
}
/**
 * The PROCESS half of the verdict. Semgrep exits 1 when it *finds* matches —
 * that is success, not failure; scan_sast, bug_hunt and scan_wordpress all
 * treat `outcome === 'completed' || exitCode === 1` as a clean exit. Reading
 * the raw outcome alone (as an earlier version of this tool did) reported
 * every successful route-finding run as `failed`.
 *
 * A clean exit is necessary and never sufficient: {@link judgeSurfaceReport}
 * decides whether the run actually scanned.
 */
export function buildToolRun(run, via) {
    const ok = run.outcome === 'completed' || run.exitCode === 1;
    if (ok) {
        return via ? { name: 'semgrep', status: 'ok', reason: `ran via ${via}` } : { name: 'semgrep', status: 'ok' };
    }
    const firstLine = run.stderr.split(/\r?\n/).find((l) => l.trim().length > 0);
    const reason = via ? `${via}: ${firstLine ?? 'fallback failed'}` : (firstLine ?? 'unknown');
    return { name: 'semgrep', status: 'failed', reason };
}
/**
 * Semgrep's built-in default ignore, applied when the scan root has NO
 * `.semgrepignore` of its own. Source: Semgrep's documentation, "Ignore
 * files, folders, and code" → "Define ignored files and folders in
 * .semgrepignore" (https://semgrep.dev/docs/ignoring-files-folders-code): the
 * default file lists `node_modules/`, `build/`, `dist/`, `vendor/`, `.env/`,
 * `.venv/`, `.tox/`, `*.min.js`, `.npm/`, `.yarn/`, `test/`, `tests/`,
 * `*_test.go`, `.semgrep` and `.semgrep_logs/` (plus `:include .gitignore` —
 * inside a git work tree `.gitignore` applies either way, and
 * {@link countRouteTargets} reads it through git; outside one Semgrep did not
 * honour it, measured). Measured on 1.176.1 with the routes pack: without
 * a `.semgrepignore` it skipped test/, tests/ and deep/test/ at any depth,
 * foo_test.go, build/, dist/, vendor/ and *.min.js, and scanned testdata/,
 * spec/ and __tests__/; with an empty `.semgrepignore` it skipped none of
 * them. Hidden directories (`.env/`, `.venv/`, …) are skipped by the walk
 * already.
 */
const SEMGREP_DEFAULT_IGNORED_DIRS = [
    'node_modules', 'build', 'dist', 'vendor', 'test', 'tests',
];
const SEMGREP_DEFAULT_IGNORED_SUFFIXES = ['.min.js', '_test.go'];
/**
 * How many files in a routes-pack language Semgrep would actually be handed
 * in `projectPath` — the `targets` {@link judgeSurfaceReport} judges
 * "scanned 0" against, and 0 means not applicable.
 *
 * With no `.semgrepignore`, Semgrep's own default ignore applies, so its
 * paths are not targets: a Terraform module whose only Go code is its
 * Terratest suite under `test/` has nothing Semgrep would scan, and counting
 * it read as "scanned 0 of 1" — a gap and an exit 2 on every CI run. With a
 * `.semgrepignore`, Semgrep ignores nothing by default, and the user's own
 * ignore excluding every route file IS a real gap, so those files count.
 *
 * Inside a git work tree Semgrep lists its targets through git — tracked
 * files plus untracked ones `.gitignore` does not exclude — whether or not
 * there is a `.semgrepignore` (measured on 1.176.1: gitignored `gen/` and
 * `deep/gen/` were never scanned, a force-added tracked file was; a
 * gitignored directory given as the target itself scanned nothing). So there
 * the count is `git ls-files --cached --others --exclude-standard`: a route
 * file excluded only by `.gitignore` is not applicable, never a gap. Outside
 * git — or when git cannot answer — Semgrep did not honour `.gitignore`
 * (measured: `gen/` was scanned), and the walk stays. Both keep
 * {@link PROJECT_WALK_EXCLUDE} (dependencies, build output) and skip hidden
 * directories, as the walk always has.
 */
export async function countRouteTargets(projectPath) {
    const ownIgnore = existsSync(join(projectPath, '.semgrepignore'));
    const listed = await gitListedFiles(projectPath);
    if (listed !== null)
        return countListedRouteTargets(projectPath, listed, ownIgnore);
    if (ownIgnore) {
        return countFilesWithExtension(projectPath, ROUTE_PACK_EXTENSIONS);
    }
    return countFilesWithExtension(projectPath, ROUTE_PACK_EXTENSIONS, new Set([...PROJECT_WALK_EXCLUDE, ...SEMGREP_DEFAULT_IGNORED_DIRS]), (name) => SEMGREP_DEFAULT_IGNORED_SUFFIXES.some((suffix) => name.endsWith(suffix)));
}
/**
 * The files git lists under `projectPath` (relative to it, `/`-separated):
 * tracked, plus untracked ones no `.gitignore` excludes — or null outside a
 * git work tree, or when git cannot answer (not installed, an unsafe
 * repository), which falls back to the walk.
 */
async function gitListedFiles(projectPath) {
    const r = await git(projectPath, ['ls-files', '-z', '--cached', '--others', '--exclude-standard']);
    return r.exitCode === 0 ? splitNul(r.stdout) : null;
}
/**
 * The route targets among git's listing: a routes-pack extension, no
 * directory the walk skips ({@link PROJECT_WALK_EXCLUDE}, hidden ones), and —
 * with no `.semgrepignore` — none of Semgrep's default-ignored directories or
 * suffixes. A tracked file deleted from the work tree is listed by
 * `--cached` and scanned by nobody: only regular files on disk count.
 */
function countListedRouteTargets(projectPath, files, ownIgnore) {
    const skipDirs = ownIgnore
        ? PROJECT_WALK_EXCLUDE
        : new Set([...PROJECT_WALK_EXCLUDE, ...SEMGREP_DEFAULT_IGNORED_DIRS]);
    let count = 0;
    for (const file of new Set(files)) {
        const segments = file.split('/');
        const name = (segments.pop() ?? '').toLowerCase();
        if (!ROUTE_PACK_EXTENSIONS.some((ext) => name.endsWith(ext)))
            continue;
        if (segments.some((dir) => skipDirs.has(dir) || dir.startsWith('.')))
            continue;
        if (!ownIgnore && SEMGREP_DEFAULT_IGNORED_SUFFIXES.some((suffix) => name.endsWith(suffix)))
            continue;
        try {
            if (!lstatSync(join(projectPath, file)).isFile())
                continue;
        }
        catch {
            continue;
        }
        count += 1;
    }
    return count;
}
/**
 * Global Constraint 3 for the surface scan, as the controller ruled it for
 * I3: the report is judged by the one Semgrep judge every other call site
 * uses (`runners/semgrepReport.ts` — exit code, `paths.scanned`, `errors[]`),
 * never by the exit code alone, and a per-file parse problem is partial
 * coverage rather than a failure. `raw` is the report text (the caller has
 * already refused a missing or unparseable one); `targets` is how many files
 * in a routes-pack language the project holds, so "scanned 0" is judged
 * against what there was to scan. With `projectPath`, the partly parsed files
 * are named relative to it.
 */
export function judgeSurfaceReport(args) {
    const { run, raw, via, targets, projectPath } = args;
    const check = checkSemgrepReport({
        raw,
        exitCode: run.exitCode,
        outcome: run.outcome,
        targets,
        ...(projectPath !== undefined ? { projectPath } : {}),
    });
    if (check.verdict === 'ok')
        return { verdict: 'ok', toolRun: buildToolRun(run, via ?? undefined) };
    const prefix = via !== null ? `${via}: ` : '';
    if (check.verdict === 'scanned_nothing') {
        return {
            verdict: 'scanned_nothing',
            toolRun: {
                name: 'semgrep',
                status: 'skipped',
                reason: `${prefix}semgrep scanned 0 of ${targets} file(s) in a routes-pack language — every one is ` +
                    'excluded (.semgrepignore) or the rule file loaded nothing',
            },
        };
    }
    if (check.verdict === 'partial' && check.partial !== undefined) {
        const partial = check.partial;
        return {
            verdict: 'partial',
            partial,
            toolRun: {
                name: 'semgrep',
                status: 'ok',
                reason: `${via !== null ? `ran via ${via}; ` : ''}` +
                    describePartialParse(partial, 'routes in the unparsed spans may be missing'),
                partially_parsed: partial,
            },
        };
    }
    const stderr = run.stderr.split(/\r?\n/).find((l) => l.trim().length > 0);
    const detail = [check.reason ?? 'semgrep failed', ...(stderr !== undefined ? [stderr] : [])].join('; ');
    return { verdict: 'failed', toolRun: { name: 'semgrep', status: 'failed', reason: `${prefix}${detail}` } };
}
//# sourceMappingURL=scanSemgrep.js.map