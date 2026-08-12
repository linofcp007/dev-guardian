import { copyFileSync } from 'node:fs';
import { join } from 'node:path';
import { buildSemgrepDockerArgs, DEFAULT_SEMGREP_IMAGE, toContainerPath, } from '../runners/dockerScanner.js';
import { runProcess } from '../runners/processRunner.js';
import { scannerAvailable } from '../tools/scanHelpers.js';
/**
 * Run Semgrep against the routes rule pack, natively if it's on PATH,
 * otherwise via Docker. Returns null only when neither is available — the
 * caller treats that as "cannot run at all" and persists nothing.
 *
 * Mirrors scan_sast's Docker fallback (scanSast.ts:95-130): probe `docker`,
 * bind the project at `/src`, run the container, and check for real output.
 * The argv comes from the shared `buildSemgrepDockerArgs` — this tool only
 * differs in `--config`, which the builder now takes as an option, so the
 * mount shape, the output rewriting and anything added there later apply
 * here too. The rule pack lives outside the project tree (in the
 * dev-guardian install), so we stage a copy inside the report dir — already
 * inside the project, already inside the bind mount — instead of adding a
 * second `--mount`.
 */
export async function invokeSemgrep(options) {
    const { projectPath, rulesPath, outFile, reportDir } = options;
    const semgrepBin = await scannerAvailable('semgrep');
    if (semgrepBin !== null) {
        const run = await runProcess({
            command: 'semgrep',
            args: ['--config', rulesPath, '--json', '--output', outFile, '--quiet', projectPath],
            cwd: projectPath,
        });
        return { toolRun: buildToolRun(run) };
    }
    const dockerBin = await scannerAvailable('docker');
    if (dockerBin === null)
        return null;
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
        };
    }
    const image = process.env['GUARDIAN_SEMGREP_IMAGE'] || DEFAULT_SEMGREP_IMAGE;
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
    return { toolRun: buildToolRun(run, `docker (${image})`) };
}
/**
 * Semgrep exits 1 when it *finds* matches — that is success, not failure.
 * Repo convention: scanSast.ts:87-94, bugHunt.ts:158, scanWordpress.ts
 * (semgrep-wp/gitleaks/etc.) all treat `outcome === 'completed' ||
 * exitCode === 1` as ok. Reading the raw outcome alone (as an earlier
 * version of this tool did) reports every successful route-finding run as
 * `failed`.
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
//# sourceMappingURL=scanSemgrep.js.map