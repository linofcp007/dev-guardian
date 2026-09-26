import { copyFileSync } from 'node:fs';
import { join } from 'node:path';
import { buildSemgrepDockerArgs, DEFAULT_SEMGREP_IMAGE, toContainerPath, } from '../runners/dockerScanner.js';
import { runProcess } from '../runners/processRunner.js';
import { checkSemgrepReport, pythonUtf8Env } from '../runners/semgrepReport.js';
import { scannerAvailable } from '../tools/scanHelpers.js';
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
 * Global Constraint 3 for the surface scan: the report is judged by the one
 * Semgrep judge every other call site uses (`runners/semgrepReport.ts` —
 * exit code, `paths.scanned`, `errors[]`), never by the exit code alone.
 * `raw` is the report text; the caller has already refused a missing or
 * unparseable one.
 */
export function judgeSurfaceReport(args) {
    const { run, raw, via } = args;
    const check = checkSemgrepReport({ raw, exitCode: run.exitCode, outcome: run.outcome, targets: 1 });
    if (check.ok)
        return { verdict: 'ok', toolRun: buildToolRun(run, via ?? undefined) };
    const prefix = via !== null ? `${via}: ` : '';
    const exitClean = run.outcome === 'completed' || run.exitCode === 1;
    if (exitClean && check.scanned === 0 && check.errors === 0) {
        return {
            verdict: 'scanned_nothing',
            toolRun: {
                name: 'semgrep',
                status: 'skipped',
                reason: `${prefix}semgrep scanned 0 files — no file here is in a language the routes rules ` +
                    'cover, or every source file is excluded (.semgrepignore)',
            },
        };
    }
    const stderr = run.stderr.split(/\r?\n/).find((l) => l.trim().length > 0);
    const detail = [check.reason ?? 'semgrep failed', ...(stderr !== undefined ? [stderr] : [])].join('; ');
    return { verdict: 'failed', toolRun: { name: 'semgrep', status: 'failed', reason: `${prefix}${detail}` } };
}
//# sourceMappingURL=scanSemgrep.js.map