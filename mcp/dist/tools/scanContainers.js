/**
 * `scan_containers` — Trivy on Dockerfile and/or container images, hadolint
 * on a Dockerfile, and hardening checks on a compose file.
 *
 * Strategy:
 *   - If `dockerfile_path` is given (or a `Dockerfile` exists at project
 *     root), run `trivy config --format json --output … <dockerfile>` AND,
 *     when hadolint is installed, `hadolint --format json <dockerfile>` —
 *     the two catch different things (Trivy: Dockerfile misconfigurations by
 *     its own rule engine; hadolint: a dedicated Dockerfile linter, DL/SC
 *     codes) and both are cheap next to an image pull.
 *   - If `image` is given, run `trivy image --format json --output … <image>`
 *     with `--scanners vuln,secret,misconfig` — vuln alone used to leave
 *     secrets baked into an image layer and image-level misconfigurations
 *     both unreported.
 *   - Independently of either of the above, a compose file at the project
 *     root (`docker-compose.yml`, `compose.yml`, `docker-compose.yaml`) is
 *     checked for `privileged: true`, `network_mode: host`, a mounted
 *     `/var/run/docker.sock`, and an unpinned/`:latest` image tag — see
 *     `runners/composeChecks.ts`. This never depends on Trivy being
 *     installed: it is a pure text check.
 *   - All of the above can fire in the same call; outputs land in
 *     `.guardian/reports/containers-<scan>/`.
 *
 * Returns `tools_run` with one entry per pass (trivy-dockerfile / trivy-image
 * / hadolint / docker-compose). Trivy's own gap is only counted (added to
 * `missing_tools`) when there was something for it to scan — a project with
 * no Dockerfile, no `image`, and no compose file is "nothing to scan"
 * (coverage `full`), not "trivy is missing" (coverage `none`), the same
 * distinction `computeCoverage`'s own doc comment already draws.
 *
 * Both inputs are validated before any scan row is written or any process
 * starts: `image` is handed to trivy as a positional argument, so a value
 * starting with `-` would be parsed as an option and one with whitespace is
 * no image reference at all; `dockerfile_path` must resolve INSIDE the
 * project (symlinks included), because the tool scans the project and
 * nothing else.
 */
import { existsSync, readFileSync, realpathSync } from 'node:fs';
import { isAbsolute, join, relative, resolve, sep } from 'node:path';
import { z } from 'zod';
import { InvalidProjectPathError, resolveProjectPath } from '../platform/projectPath.js';
import { checkCompose } from '../runners/composeChecks.js';
import { hadolintParser } from '../runners/scannerParsers/hadolint.js';
import { trivyParser } from '../runners/scannerParsers/trivy.js';
import { runProcess } from '../runners/processRunner.js';
import { Force, ProjectPath, SeverityMin } from '../schemas.js';
import { registerToolModule } from './index.js';
import { ensureReportDir, readJsonSafe, scannerAvailable, } from './scanHelpers.js';
import { makeScanTool, } from './scanToolFactory.js';
/** The three canonical compose file names, in the order stackDetect.ts's own `hasComposeFile` checks them. */
const COMPOSE_FILE_NAMES = ['docker-compose.yml', 'compose.yml', 'docker-compose.yaml'];
/** Wraps `checkCompose` (pure text -> Finding[]) as a `ScannerParser` so it flows through the same `parser_inputs` pipeline as every other scanner. */
const composeParser = {
    name: 'docker-compose',
    parse(input) {
        const { text, filePath } = input;
        return { findings: checkCompose(text, filePath), cves: [] };
    },
};
/** An image reference: non-empty, no whitespace, not starting with `-`. */
const IMAGE_REF = /^(?!-)\S+$/;
const scanContainers = makeScanTool({
    name: 'scan_containers',
    title: 'Container scan (Dockerfile + image + compose)',
    description: 'Run Trivy against a Dockerfile (config check) and/or a container image (vuln + secret + ' +
        'misconfig). If neither dockerfile_path nor image is provided, scans ./Dockerfile when present. ' +
        'Also, independent of both: hadolint lints the Dockerfile when installed, and a compose file ' +
        '(docker-compose.yml / compose.yml / docker-compose.yaml) at the project root is checked for ' +
        'privileged containers, host networking, a mounted docker.sock, and unpinned/:latest image tags.',
    scan_type: 'containers',
    category: 'security',
    supportsAutoFix: false,
    inputSchema: {
        project_path: ProjectPath,
        severity_min: SeverityMin,
        dockerfile_path: z
            .string()
            .optional()
            .describe('Path to a Dockerfile to scan with `trivy config`.'),
        image: z
            .string()
            .regex(IMAGE_REF, 'image must be an image reference: no whitespace, not starting with "-"')
            .optional()
            .describe('Container image reference to scan with `trivy image`.'),
        force: Force,
    },
    invoke: async (input, ctx) => {
        const reportDir = ensureReportDir(ctx.projectPath, ctx.scanId, 'containers');
        const tools_run = [];
        const missing_tools = [];
        const parser_inputs = [];
        let anyOutcome = 'completed';
        const inp = input;
        // Validated by the handler below before this runs; re-checked here so
        // no other caller of `invoke` can bypass it.
        const invalid = invalidInput(ctx.projectPath, inp);
        if (invalid)
            throw new Error(invalid);
        const dockerfile = inp.dockerfile_path !== undefined
            ? resolve(ctx.projectPath, inp.dockerfile_path)
            : existsSync(join(ctx.projectPath, 'Dockerfile'))
                ? join(ctx.projectPath, 'Dockerfile')
                : undefined;
        // Trivy's own gap is only a gap when there was something for it to
        // scan — see the module doc comment for why this must not be a bare
        // early return any more: hadolint and the compose checks below are
        // independent of Trivy being installed at all.
        if (dockerfile !== undefined || inp.image !== undefined) {
            const trivyBin = await scannerAvailable('trivy');
            if (!trivyBin) {
                tools_run.push({ name: 'trivy', status: 'skipped', reason: 'not_installed' });
                missing_tools.push('trivy');
            }
            else {
                if (dockerfile !== undefined) {
                    const outFile = join(reportDir, 'dockerfile.json');
                    const result = await runProcess({
                        command: 'trivy',
                        args: ['config', '--format', 'json', '--output', outFile, '--quiet', dockerfile],
                        cwd: ctx.projectPath,
                        env: ctx.scriptEnv,
                        signal: ctx.signal,
                        onLog: ctx.onLog,
                    });
                    const raw = readJsonSafe(outFile);
                    if (raw)
                        parser_inputs.push({ parser: trivyParser, input: raw });
                    tools_run.push({
                        name: 'trivy-dockerfile',
                        status: result.outcome === 'completed' ? 'ok' : 'failed',
                    });
                    if (result.outcome !== 'completed')
                        anyOutcome = result.outcome;
                }
                if (inp.image) {
                    const outFile = join(reportDir, 'image.json');
                    const result = await runProcess({
                        command: 'trivy',
                        args: [
                            'image',
                            '--format',
                            'json',
                            '--output',
                            outFile,
                            '--quiet',
                            '--scanners',
                            // vuln alone used to leave secrets baked into an image
                            // layer, and image-level misconfigurations, unreported;
                            // trivyParser already handles all three result shapes.
                            'vuln,secret,misconfig',
                            inp.image,
                        ],
                        cwd: ctx.projectPath,
                        env: ctx.scriptEnv,
                        signal: ctx.signal,
                        onLog: ctx.onLog,
                    });
                    const raw = readJsonSafe(outFile);
                    if (raw)
                        parser_inputs.push({ parser: trivyParser, input: raw });
                    tools_run.push({
                        name: 'trivy-image',
                        status: result.outcome === 'completed' ? 'ok' : 'failed',
                    });
                    if (result.outcome !== 'completed')
                        anyOutcome = result.outcome;
                }
            }
        }
        else {
            // No Dockerfile, no image — nothing for Trivy to scan. Not a gap:
            // computeCoverage's own doc comment says this must read 'full', not
            // 'none', so this is never added to `missing_tools`.
            tools_run.push({ name: 'trivy', status: 'skipped', reason: 'no_dockerfile_or_image' });
        }
        if (dockerfile !== undefined) {
            const hadolintBin = await scannerAvailable('hadolint');
            if (!hadolintBin) {
                tools_run.push({ name: 'hadolint', status: 'skipped', reason: 'not_installed' });
                missing_tools.push('hadolint');
            }
            else {
                const result = await runProcess({
                    command: 'hadolint',
                    args: ['--format', 'json', dockerfile],
                    cwd: ctx.projectPath,
                    env: ctx.scriptEnv,
                    signal: ctx.signal,
                    onLog: ctx.onLog,
                });
                // hadolint exits 1 when it found anything at/above its failure
                // threshold (default: any finding) — a result, not a failure; same
                // convention as jscpd/ruff/bandit/staticcheck elsewhere here.
                const finished = result.outcome !== 'cancelled' &&
                    result.outcome !== 'timed_out' &&
                    result.outcome !== 'output_too_large';
                if (finished && (result.exitCode === 0 || result.exitCode === 1)) {
                    parser_inputs.push({ parser: hadolintParser, input: result.stdout });
                    tools_run.push({ name: 'hadolint', status: 'ok' });
                }
                else {
                    tools_run.push({ name: 'hadolint', status: 'failed' });
                    if (result.outcome !== 'completed')
                        anyOutcome = result.outcome;
                }
            }
        }
        const composeFile = findComposeFile(ctx.projectPath);
        if (composeFile) {
            const text = readComposeFileSafe(composeFile);
            if (text !== null) {
                parser_inputs.push({
                    parser: composeParser,
                    input: { text, filePath: relative(ctx.projectPath, composeFile) },
                });
                tools_run.push({ name: 'docker-compose', status: 'ok' });
            }
            else {
                tools_run.push({ name: 'docker-compose', status: 'failed', reason: 'could not read the compose file' });
            }
        }
        return {
            outcome: anyOutcome,
            tools_run,
            missing_tools,
            parser_inputs,
            report_paths: [reportDir],
        };
    },
});
/**
 * The scan pipeline, behind the argument checks: a rejected input returns a
 * domain error before the factory writes a scan row or starts a process. The
 * MCP layer already rejects a bad `image` through the schema's pattern; this
 * also covers in-process callers, and `dockerfile_path` needs the project
 * path, which no schema knows.
 */
const tool = {
    ...scanContainers,
    handler: async (input, plugin, callMeta) => {
        const inp = input;
        let projectPath = null;
        try {
            projectPath = resolveProjectPath(inp.project_path).path;
        }
        catch (e) {
            // The pipeline reports an invalid project_path itself.
            if (!(e instanceof InvalidProjectPathError))
                throw e;
        }
        const invalid = projectPath !== null ? invalidInput(projectPath, inp) : null;
        if (invalid)
            return { ok: false, error: { code: 'unsupported_target', message: invalid } };
        return scanContainers.handler(input, plugin, callMeta);
    },
};
registerToolModule(tool);
/** The first of `COMPOSE_FILE_NAMES` present at the project root, or null. */
function findComposeFile(projectPath) {
    for (const name of COMPOSE_FILE_NAMES) {
        const candidate = join(projectPath, name);
        if (existsSync(candidate))
            return candidate;
    }
    return null;
}
function readComposeFileSafe(path) {
    try {
        return readFileSync(path, 'utf8');
    }
    catch {
        return null;
    }
}
/** Why the input cannot be scanned, or null when it can. */
function invalidInput(projectPath, inp) {
    if (inp.image !== undefined && !IMAGE_REF.test(inp.image)) {
        return `image ${JSON.stringify(inp.image)} is not an image reference: it must not contain whitespace or start with "-".`;
    }
    if (inp.dockerfile_path !== undefined && !isInside(projectPath, inp.dockerfile_path)) {
        return `dockerfile_path ${JSON.stringify(inp.dockerfile_path)} resolves outside the project (${projectPath}); scan_containers only reads files inside it.`;
    }
    return null;
}
/**
 * Whether `candidate` (relative to `root`, or absolute) names a path inside
 * `root`. Checked lexically, and — when the file exists — again on the real
 * paths, so a symlink inside the project pointing out of it is refused too.
 */
function isInside(root, candidate) {
    const within = (base, target) => {
        const rel = relative(base, target);
        return rel !== '' && rel !== '..' && !rel.startsWith(`..${sep}`) && !isAbsolute(rel);
    };
    const abs = resolve(root, candidate);
    if (!within(root, abs))
        return false;
    if (!existsSync(abs))
        return true;
    try {
        return within(realpathSync.native(root), realpathSync.native(abs));
    }
    catch {
        return false;
    }
}
//# sourceMappingURL=scanContainers.js.map