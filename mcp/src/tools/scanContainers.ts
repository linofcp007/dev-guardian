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
 *   - For the `image`, when cosign ≥ 3.0 is installed and `GUARDIAN_OFFLINE`
 *     is not `1`, its Sigstore signature (`runners/cosignCheck.ts`), on the
 *     digest the tag is pinned to first: with a signer identity and issuer,
 *     a real `cosign verify` (a confirmed rejection is a high finding);
 *     without them, only whether a signature and signed SLSA provenance
 *     exist (low / info findings when absent — checked against the
 *     registry's own referrers index and answers in cosign's request log,
 *     since cosign swallows some registry errors), and the response's
 *     `image_signature` says a signature that exists was NOT verified. All
 *     of one image's cosign calls share one deadline, the tool's timeout.
 *     cosign absent, older than 3.0 or offline: `cosign` skipped, in
 *     `missing_tools` — the image's signature was not looked at, which is a
 *     gap, not a pass. An unanchored signer regexp is verified as asked, with
 *     a warning.
 *   - All of the above can fire in the same call; outputs land in
 *     `.guardian/reports/containers-<scan>/`.
 *
 * Returns `tools_run` with one entry per pass (trivy-dockerfile / trivy-image
 * / hadolint / docker-compose / cosign-verify or cosign-referrers; the
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
import {
  UNSAFE_CHARS,
  UNSAFE_CHAR_CLASS,
  cosignReadiness,
  escapeUnsafe,
  detectImageSupplyChain,
  skippedSummary,
  unanchoredSignerRegexps,
  verifyImage,
  type ImageSignatureSummary,
  type SignerPolicy,
} from '../runners/cosignCheck.js';
import { hadolintParser } from '../runners/scannerParsers/hadolint.js';
import { trivyParser } from '../runners/scannerParsers/trivy.js';
import type { ParserOutput, ScannerParser } from '../runners/scannerParsers/index.js';
import { runProcess } from '../runners/processRunner.js';
import { judgeTrivyConfig } from '../runners/trivyConfig.js';
import { runTrivy, withHonoured } from '../runners/trivyRun.js';
import { Force, ProjectPath, SeverityMin } from '../schemas.js';
import type { Finding, ToolResult, ToolRun } from '../types.js';
import { registerToolModule, type ToolModule } from './index.js';
import {
  ensureReportDir,
  readJsonSafe,
  scannerAvailable,
} from './scanHelpers.js';
import {
  makeScanTool,
  type ScannerInvocation,
} from './scanToolFactory.js';

/** The three canonical compose file names, in the order stackDetect.ts's own `hasComposeFile` checks them. */
const COMPOSE_FILE_NAMES: readonly string[] = ['docker-compose.yml', 'compose.yml', 'docker-compose.yaml'];

/** Wraps `checkCompose` (pure text -> Finding[]) as a `ScannerParser` so it flows through the same `parser_inputs` pipeline as every other scanner. */
const composeParser: ScannerParser = {
  name: 'docker-compose',
  parse(input: unknown): ParserOutput {
    const { text, filePath } = input as { text: string; filePath: string };
    return { findings: checkCompose(text, filePath), cves: [] };
  },
};

/** Hands the cosign check's findings (already built) to the same `parser_inputs` pipeline. */
const cosignParser: ScannerParser = {
  name: 'cosign',
  parse(input: unknown): ParserOutput {
    return { findings: input as Finding[], cves: [] };
  },
};

/**
 * An image reference: non-empty, no whitespace, not starting with `-`, and
 * none of `UNSAFE_CHARS` (`runners/cosignCheck.ts`: control, zero-width,
 * line-separator and bidi characters) — JavaScript's `\S` lets ESC, U+0085
 * and the zero-width characters through, and the reference flows into
 * cosign's reasons, notes and findings.
 */
const IMAGE_REF = new RegExp(`^(?!-)[^\\s${UNSAFE_CHAR_CLASS}]+$`);

/** A signer value: an e-mail, a workflow URL or an RE2 regexp — never a control character. */
const SignerValue = z.string().min(1).max(1024);

const scanContainers = makeScanTool({
    name: 'scan_containers',
    title: 'Container scan (Dockerfile + image + compose)',
    description:
      'Run Trivy against a Dockerfile (config check) and/or a container image (vuln + secret + ' +
      'misconfig). If neither dockerfile_path nor image is provided, scans ./Dockerfile when present. ' +
      'Also, independent of both: hadolint lints the Dockerfile when installed, and a compose file ' +
      '(docker-compose.yml / compose.yml / docker-compose.yaml) at the project root is checked for ' +
      'privileged containers, host networking, a mounted docker.sock, and unpinned/:latest image tags. ' +
      'For the image, cosign (3.0+) checks its Sigstore signature on the digest it pins the tag to (unless ' +
      'GUARDIAN_OFFLINE=1): with signer_identity (or signer_identity_regexp) AND signer_issuer (or ' +
      'signer_issuer_regexp), a real cosign verify — a confirmed rejection is a high finding; without them, only ' +
      'whether a signature and a signed SLSA provenance attestation exist (low / info findings when absent), and ' +
      'image_signature says an existing signature was NOT verified. Only a network or registry failure withholds a ' +
      'verdict: a junk, unparseable or non-Sigstore artifact is no signature. A registry failure, even one cosign ' +
      'skips in silence, is unknown, never absent — except a referrers API answering with no index at all (400, ' +
      '406, HTML): see SECURITY.md. cosign missing, older than 3.0 or offline: skipped and in missing_tools, never a pass.',
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
        .regex(IMAGE_REF, 'image must be an image reference: no whitespace or control characters, not starting with "-"')
        .optional()
        .describe('Container image reference to scan with `trivy image`.'),
      signer_identity: SignerValue.optional().describe(
        "The identity `image` must be signed by: the signing certificate's subject — a workflow URL such as " +
          'https://github.com/org/repo/.github/workflows/release.yml@refs/heads/main, or an e-mail. Needs ' +
          'signer_issuer (or signer_issuer_regexp); runs cosign verify.',
      ),
      signer_identity_regexp: SignerValue.optional().describe(
        'signer_identity as a regular expression (Go RE2 syntax; anchor it with ^ and $), e.g. to accept every ' +
          'release workflow of one repository. Not with signer_identity.',
      ),
      signer_issuer: SignerValue.optional().describe(
        'The OIDC issuer of that identity, e.g. https://token.actions.githubusercontent.com (GitHub Actions) ' +
          'or https://accounts.google.com.',
      ),
      signer_issuer_regexp: SignerValue.optional().describe(
        'signer_issuer as a regular expression (Go RE2 syntax). Not with signer_issuer.',
      ),
      force: Force,
    },
    invoke: async (input, ctx): Promise<ScannerInvocation> => {
      const reportDir = ensureReportDir(ctx.projectPath, ctx.scanId, 'containers');
      const tools_run: ToolRun[] = [];
      const missing_tools: string[] = [];
      const warnings: string[] = [];
      const parser_inputs: ScannerInvocation['parser_inputs'] = [];
      let anyOutcome: ScannerInvocation['outcome'] = 'completed';

      const inp = input as ContainersInput;
      let imageSignature: ImageSignatureSummary | undefined;
      // Validated by the handler below before this runs; re-checked here so
      // no other caller of `invoke` can bypass it.
      const invalid = invalidInput(ctx.projectPath, inp);
      if (invalid) throw new Error(invalid);
      const dockerfile =
        inp.dockerfile_path !== undefined
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
        } else {
          if (dockerfile !== undefined) {
            const outFile = join(reportDir, 'dockerfile.json');
            // Never in the project, never its trivy.yaml (runners/trivyRun.ts).
            // No --quiet: a Dockerfile Trivy cannot parse is one ERROR line
            // in its log, and --quiet hides it (runners/trivyConfig.ts).
            const result = await runTrivy({
              args: ['config', '--format', 'json', '--output', outFile],
              target: dockerfile,
              workDir: reportDir,
              ignoreFrom: ctx.projectPath,
              env: ctx.scriptEnv,
              signal: ctx.signal,
              onLog: ctx.onLog,
            });
            const raw = readJsonSafe(outFile);
            if (raw) parser_inputs.push({ parser: trivyParser, input: raw });
            // The file it was given is the one that must be recognised.
            const judged = judgeTrivyConfig({
              name: 'trivy-dockerfile',
              run: result,
              raw,
              iacFiles: [relative(ctx.projectPath, dockerfile).split(sep).join('/')],
            });
            tools_run.push(judged.toolRun);
            missing_tools.push(...judged.missing);
            if (result.outcome !== 'completed') anyOutcome = result.outcome;
          }

          if (inp.image) {
            const outFile = join(reportDir, 'image.json');
            // The project's .trivyignore applied to its image as it always
            // was, now explicitly and named; its trivy.yaml never.
            const result = await runTrivy({
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
              ],
              target: inp.image,
              workDir: reportDir,
              ignoreFrom: ctx.projectPath,
              env: ctx.scriptEnv,
              signal: ctx.signal,
              onLog: ctx.onLog,
            });
            const raw = readJsonSafe(outFile);
            if (raw) parser_inputs.push({ parser: trivyParser, input: raw });
            // `target`: which image this pass looked at. A comparison
            // re-measures an image's findings only by a scan of the SAME
            // image (history/runCompare.ts) — image B's scan never resolves
            // image A's.
            tools_run.push(
              withHonoured(
                {
                  name: 'trivy-image',
                  status: result.outcome === 'completed' ? 'ok' : 'failed',
                  reason: `image ${inp.image}`,
                  target: inp.image,
                },
                result.honoured,
              ),
            );
            if (result.outcome !== 'completed') anyOutcome = result.outcome;
          }
        }
      } else {
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
        } else if ((await scannerAvailable('cosign')) === null) {
          tools_run.push({ name: 'cosign', status: 'skipped', reason: 'not_installed' });
          missing_tools.push('cosign');
          imageSignature = skippedSummary(inp.image, 'cosign is not installed');
        } else {
          const cosignCtx = {
            cwd: ctx.projectPath,
            env: ctx.scriptEnv,
            ...(ctx.signal !== undefined ? { signal: ctx.signal } : {}),
            onLog: ctx.onLog,
          };
          // cosign 2.x cannot see OCI referrers in `tree`: it would read a
          // signed image as unsigned, so it is not used at all.
          const ready = await cosignReadiness(cosignCtx);
          if (!ready.ok) {
            tools_run.push({ name: 'cosign', status: ready.status, reason: ready.reason });
            missing_tools.push('cosign');
            imageSignature = skippedSummary(inp.image, ready.reason);
          } else {
            const check =
              policy !== null
                ? await verifyImage(inp.image, policy, cosignCtx)
                : await detectImageSupplyChain(inp.image, cosignCtx);
            tools_run.push(check.run);
            parser_inputs.push({ parser: cosignParser, input: check.findings });
            imageSignature = check.summary;
            // A cosign failure is this check's gap (its tools_run entry says
            // so); only a cancellation is the whole scan's outcome.
            if (check.cancelled) anyOutcome = 'cancelled';
          }
        }
        // Said whether or not cosign ran: the policy itself is too loose.
        if (policy !== null) warnings.push(...unanchoredSignerRegexps(policy));
      }

      if (dockerfile !== undefined) {
        const hadolintBin = await scannerAvailable('hadolint');
        if (!hadolintBin) {
          tools_run.push({ name: 'hadolint', status: 'skipped', reason: 'not_installed' });
          missing_tools.push('hadolint');
        } else {
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
          const finished =
            result.outcome !== 'cancelled' &&
            result.outcome !== 'timed_out' &&
            result.outcome !== 'output_too_large';
          if (finished && (result.exitCode === 0 || result.exitCode === 1)) {
            parser_inputs.push({ parser: hadolintParser, input: result.stdout });
            tools_run.push({ name: 'hadolint', status: 'ok' });
          } else {
            tools_run.push({ name: 'hadolint', status: 'failed' });
            if (result.outcome !== 'completed') anyOutcome = result.outcome;
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
        } else {
          tools_run.push({ name: 'docker-compose', status: 'failed', reason: 'could not read the compose file' });
        }
      }

      return {
        outcome: anyOutcome,
        tools_run,
        missing_tools,
        parser_inputs,
        report_paths: [reportDir],
        ...(warnings.length > 0 ? { warnings } : {}),
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
const tool: ToolModule = {
  ...scanContainers,
  handler: async (input, plugin, callMeta): Promise<ToolResult<Record<string, unknown>>> => {
    const inp = input as ContainersInput & { project_path?: string };
    let projectPath: string | null = null;
    try {
      projectPath = resolveProjectPath(inp.project_path).path;
    } catch (e) {
      // The pipeline reports an invalid project_path itself.
      if (!(e instanceof InvalidProjectPathError)) throw e;
    }
    const invalid = projectPath !== null ? invalidInput(projectPath, inp) : null;
    if (invalid) return { ok: false, error: { code: 'unsupported_target', message: invalid } };
    return scanContainers.handler(input, plugin, callMeta);
  },
};

registerToolModule(tool);

/** The first of `COMPOSE_FILE_NAMES` present at the project root, or null. */
function findComposeFile(projectPath: string): string | null {
  for (const name of COMPOSE_FILE_NAMES) {
    const candidate = join(projectPath, name);
    if (existsSync(candidate)) return candidate;
  }
  return null;
}

function readComposeFileSafe(path: string): string | null {
  try {
    return readFileSync(path, 'utf8');
  } catch {
    return null;
  }
}

interface ContainersInput {
  dockerfile_path?: string;
  image?: string;
  signer_identity?: string;
  signer_identity_regexp?: string;
  signer_issuer?: string;
  signer_issuer_regexp?: string;
}

const SIGNER_FIELDS = ['signer_identity', 'signer_identity_regexp', 'signer_issuer', 'signer_issuer_regexp'] as const;

/** The signer `image` must be signed by, or null when none was named (existence check only). */
function signerPolicy(inp: ContainersInput): SignerPolicy | null {
  const policy: SignerPolicy = {};
  if (inp.signer_identity !== undefined) policy.identity = inp.signer_identity;
  if (inp.signer_identity_regexp !== undefined) policy.identityRegexp = inp.signer_identity_regexp;
  if (inp.signer_issuer !== undefined) policy.issuer = inp.signer_issuer;
  if (inp.signer_issuer_regexp !== undefined) policy.issuerRegexp = inp.signer_issuer_regexp;
  return Object.keys(policy).length > 0 ? policy : null;
}

/** Why the input cannot be scanned, or null when it can. */
function invalidInput(projectPath: string, inp: ContainersInput): string | null {
  if (inp.image !== undefined && !IMAGE_REF.test(inp.image)) {
    return `image ${escapeUnsafe(JSON.stringify(inp.image))} is not an image reference: it must not contain whitespace, control, zero-width or bidi characters, or start with "-".`;
  }
  if (inp.dockerfile_path !== undefined && !isInside(projectPath, inp.dockerfile_path)) {
    return `dockerfile_path ${escapeUnsafe(JSON.stringify(inp.dockerfile_path))} resolves outside the project (${projectPath}); scan_containers only reads files inside it.`;
  }
  return invalidSigner(inp);
}

/**
 * Why the signer cannot be verified, or null. cosign's keyless `verify`
 * needs one identity form AND one issuer form: an identity alone would let
 * any issuer vouch for it — the same address minted by another OIDC
 * provider — so half a signer is refused rather than half-checked.
 */
function invalidSigner(inp: ContainersInput): string | null {
  const given = SIGNER_FIELDS.filter((f) => inp[f] !== undefined);
  if (given.length === 0) return null;
  if (inp.image === undefined) {
    return `${given.join(', ')} name(s) who must have signed an image, but no image was given — pass image.`;
  }
  for (const field of given) {
    // A line break could smuggle a second line into a log or a report; no
    // identity, issuer or regexp has a reason to hold one.
    if (UNSAFE_CHARS.test(inp[field] ?? '')) {
      return `${field} contains a control character (or a zero-width, line-separator or bidi character); an identity, issuer or regexp never needs one.`;
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
function isInside(root: string, candidate: string): boolean {
  const within = (base: string, target: string): boolean => {
    const rel = relative(base, target);
    return rel !== '' && rel !== '..' && !rel.startsWith(`..${sep}`) && !isAbsolute(rel);
  };
  const abs = resolve(root, candidate);
  if (!within(root, abs)) return false;
  if (!existsSync(abs)) return true;
  try {
    return within(realpathSync.native(root), realpathSync.native(abs));
  } catch {
    return false;
  }
}
