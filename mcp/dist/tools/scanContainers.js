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
 *   - For the `image`, when cosign is installed and `GUARDIAN_OFFLINE` is not
 *     `1`, its Sigstore signature (`runners/cosignCheck.ts`): with a signer
 *     identity and issuer, a real `cosign verify` (a rejection is a high
 *     finding); without them, only whether a signature and signed SLSA
 *     provenance exist (low / info findings when absent), and the response's
 *     `image_signature` says a signature that exists was NOT verified.
 *     cosign absent or offline: `cosign` skipped, in `missing_tools` — the
 *     image's signature was not looked at, which is a gap, not a pass.
 *   - All of the above can fire in the same call; outputs land in
 *     `.guardian/reports/containers-<scan>/`.
 *
 * Returns `tools_run` with one entry per pass (trivy-dockerfile / trivy-image
 * / hadolint / docker-compose / cosign-verify or cosign-tree; the
 * trivy-image and cosign entries name their image in `target`). Trivy's own
 * gap is only counted (added to
 * `missing_tools`) when there was something for it to scan — a project with
 * no Dockerfile, no `image`, and no compose file is "nothing to scan"
 * (coverage `full`), not "trivy is missing" (coverage `none`), the same
 * distinction `computeCoverage`'s own doc comment already draws.
 *
 * Every input is validated before any scan row is written or any process
 * starts: `image` is handed to trivy as a positional argument, so a value
 * starting with `-` would be parsed as an option and one with whitespace is
 * no image reference at all; `dockerfile_path` must resolve INSIDE the
 * project (symlinks included), because the tool scans the project and
 * nothing else; a signer needs an image, exactly one identity form and one
 * issuer form, and no control characters.
 */
import { existsSync, readFileSync, realpathSync } from 'node:fs';
import { isAbsolute, join, relative, resolve, sep } from 'node:path';
import { z } from 'zod';
import { InvalidProjectPathError, resolveProjectPath } from '../platform/projectPath.js';
import { checkCompose } from '../runners/composeChecks.js';
import { detectImageSupplyChain, skippedSummary, verifyImage, } from '../runners/cosignCheck.js';
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
/** Hands the cosign check's findings (already built) to the same `parser_inputs` pipeline. */
const cosignParser = {
    name: 'cosign',
    parse(input) {
        return { findings: input, cves: [] };
    },
};
/** An image reference: non-empty, no whitespace, not starting with `-`. */
const IMAGE_REF = /^(?!-)\S+$/;
/** A signer value: an e-mail, a workflow URL or an RE2 regexp — never a control character. */
const SignerValue = z.string().min(1).max(1024);
const scanContainers = makeScanTool({
    name: 'scan_containers',
    title: 'Container scan (Dockerfile + image + compose)',
    description: 'Run Trivy against a Dockerfile (config check) and/or a container image (vuln + secret + ' +
        'misconfig). If neither dockerfile_path nor image is provided, scans ./Dockerfile when present. ' +
        'Also, independent of both: hadolint lints the Dockerfile when installed, and a compose file ' +
        '(docker-compose.yml / compose.yml / docker-compose.yaml) at the project root is checked for ' +
        'privileged containers, host networking, a mounted docker.sock, and unpinned/:latest image tags. ' +
        "For the image, cosign checks its Sigstore signature (unless GUARDIAN_OFFLINE=1): with signer_identity " +
        '(or signer_identity_regexp) AND signer_issuer (or signer_issuer_regexp), a real cosign verify — a ' +
        'rejection is a high finding; without them, only whether a signature and a signed SLSA provenance ' +
        'attestation exist (low / info findings when absent), and image_signature says an existing signature ' +
        'was NOT verified. cosign missing or offline: skipped and in missing_tools, never a pass.',
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
        signer_identity: SignerValue.optional().describe("The identity `image` must be signed by: the signing certificate's subject — a workflow URL such as " +
            'https://github.com/org/repo/.github/workflows/release.yml@refs/heads/main, or an e-mail. Needs ' +
            'signer_issuer (or signer_issuer_regexp); runs cosign verify.'),
        signer_identity_regexp: SignerValue.optional().describe('signer_identity as a regular expression (Go RE2 syntax; anchor it with ^ and $), e.g. to accept every ' +
            'release workflow of one repository. Not with signer_identity.'),
        signer_issuer: SignerValue.optional().describe('The OIDC issuer of that identity, e.g. https://token.actions.githubusercontent.com (GitHub Actions) ' +
            'or https://accounts.google.com.'),
        signer_issuer_regexp: SignerValue.optional().describe('signer_issuer as a regular expression (Go RE2 syntax). Not with signer_issuer.'),
        force: Force,
    },
    invoke: async (input, ctx) => {
        const reportDir = ensureReportDir(ctx.projectPath, ctx.scanId, 'containers');
        const tools_run = [];
        const missing_tools = [];
        const parser_inputs = [];
        let anyOutcome = 'completed';
        const inp = input;
        let imageSignature;
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
                    // `target`: which image this pass looked at. A comparison
                    // re-measures an image's findings only by a scan of the SAME
                    // image (history/runCompare.ts) — image B's scan never resolves
                    // image A's.
                    tools_run.push({
                        name: 'trivy-image',
                        status: result.outcome === 'completed' ? 'ok' : 'failed',
                        reason: `image ${inp.image}`,
                        target: inp.image,
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
        // The image's signature — independent of Trivy: a missing Trivy does
        // not make the signature any less checkable, nor the reverse.
        if (inp.image !== undefined) {
            const policy = signerPolicy(inp);
            if (ctx.scriptEnv['GUARDIAN_OFFLINE'] === '1') {
                const reason = 'network disabled (GUARDIAN_OFFLINE=1)';
                tools_run.push({ name: 'cosign', status: 'skipped', reason });
                missing_tools.push('cosign');
                imageSignature = skippedSummary(inp.image, reason);
            }
            else if ((await scannerAvailable('cosign')) === null) {
                tools_run.push({ name: 'cosign', status: 'skipped', reason: 'not_installed' });
                missing_tools.push('cosign');
                imageSignature = skippedSummary(inp.image, 'cosign is not installed');
            }
            else {
                const cosignCtx = {
                    cwd: ctx.projectPath,
                    env: ctx.scriptEnv,
                    ...(ctx.signal !== undefined ? { signal: ctx.signal } : {}),
                    onLog: ctx.onLog,
                };
                const check = policy !== null
                    ? await verifyImage(inp.image, policy, cosignCtx)
                    : await detectImageSupplyChain(inp.image, cosignCtx);
                tools_run.push(check.run);
                parser_inputs.push({ parser: cosignParser, input: check.findings });
                imageSignature = check.summary;
                // A cosign failure is this check's gap (its tools_run entry says
                // so); only a cancellation is the whole scan's outcome.
                if (check.cancelled)
                    anyOutcome = 'cancelled';
            }
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
            ...(imageSignature !== undefined ? { extras: { image_signature: imageSignature } } : {}),
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
const SIGNER_FIELDS = ['signer_identity', 'signer_identity_regexp', 'signer_issuer', 'signer_issuer_regexp'];
/** The signer `image` must be signed by, or null when none was named (existence check only). */
function signerPolicy(inp) {
    const policy = {};
    if (inp.signer_identity !== undefined)
        policy.identity = inp.signer_identity;
    if (inp.signer_identity_regexp !== undefined)
        policy.identityRegexp = inp.signer_identity_regexp;
    if (inp.signer_issuer !== undefined)
        policy.issuer = inp.signer_issuer;
    if (inp.signer_issuer_regexp !== undefined)
        policy.issuerRegexp = inp.signer_issuer_regexp;
    return Object.keys(policy).length > 0 ? policy : null;
}
/** Why the input cannot be scanned, or null when it can. */
function invalidInput(projectPath, inp) {
    if (inp.image !== undefined && !IMAGE_REF.test(inp.image)) {
        return `image ${JSON.stringify(inp.image)} is not an image reference: it must not contain whitespace or start with "-".`;
    }
    if (inp.dockerfile_path !== undefined && !isInside(projectPath, inp.dockerfile_path)) {
        return `dockerfile_path ${JSON.stringify(inp.dockerfile_path)} resolves outside the project (${projectPath}); scan_containers only reads files inside it.`;
    }
    return invalidSigner(inp);
}
/**
 * Why the signer cannot be verified, or null. cosign's keyless `verify`
 * needs one identity form AND one issuer form: an identity alone would let
 * any issuer vouch for it — the same address minted by another OIDC
 * provider — so half a signer is refused rather than half-checked.
 */
function invalidSigner(inp) {
    const given = SIGNER_FIELDS.filter((f) => inp[f] !== undefined);
    if (given.length === 0)
        return null;
    if (inp.image === undefined) {
        return `${given.join(', ')} name(s) who must have signed an image, but no image was given — pass image.`;
    }
    for (const field of given) {
        // A line break could smuggle a second line into a log or a report; no
        // identity, issuer or regexp has a reason to hold one.
        if (/[\u0000-\u001f\u007f]/.test(inp[field] ?? '')) {
            return `${field} contains a control character; an identity, issuer or regexp never needs one.`;
        }
    }
    if (inp.signer_identity !== undefined && inp.signer_identity_regexp !== undefined) {
        return 'Pass signer_identity OR signer_identity_regexp, not both.';
    }
    if (inp.signer_issuer !== undefined && inp.signer_issuer_regexp !== undefined) {
        return 'Pass signer_issuer OR signer_issuer_regexp, not both.';
    }
    const identity = inp.signer_identity !== undefined || inp.signer_identity_regexp !== undefined;
    const issuer = inp.signer_issuer !== undefined || inp.signer_issuer_regexp !== undefined;
    if (identity && !issuer) {
        return 'A signer identity needs its OIDC issuer too — pass signer_issuer (or signer_issuer_regexp); an identity alone would accept it from any issuer.';
    }
    if (issuer && !identity) {
        return 'An OIDC issuer needs the identity it vouches for — pass signer_identity (or signer_identity_regexp) too.';
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