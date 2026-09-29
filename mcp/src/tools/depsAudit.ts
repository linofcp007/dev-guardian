/**
 * `deps_audit` — dependency audit (Trivy + bot detection + stack-specific
 * auditors).
 *
 * Builds on `scan_deps` (same Trivy invocation, plus a manifest-coverage
 * check — see `trivy.ts`'s own module comment for the bare-`.csproj` /
 * bare-`package.json` silent gap it closes) and adds:
 *
 *   - `bot_configured` flag — whether the project already has renovate.json
 *     or .github/dependabot.yml in place;
 *   - `npm audit --json` (npm 7+/6 both supported) parsed into Findings via
 *     `npmAuditParser` — npm's GitHub-advisory coverage is complementary to
 *     Trivy's, so its vulnerabilities are counted rather than merely
 *     captured. To avoid double-counting, an npm finding for a package Trivy
 *     already reported as a CVE is dropped (Trivy is canonical); npm findings
 *     for packages Trivy missed are kept;
 *   - `pip-audit --format json`, run per `requirements*.txt` file (`-r`) when
 *     any exist, else against the project directory for a `pyproject.toml`
 *     project — NEVER bare, which audits whatever Python is on PATH (the MCP
 *     host's own interpreter, not this project's dependencies). Parsed via
 *     `pipAuditParser`;
 *   - `dotnet list <target> package --vulnerable --include-transitive
 *     --format json --no-restore`, one call per root `.sln`/`.slnx`
 *     (preferred) or `.csproj`, when the .NET SDK is on PATH. **Each one is
 *     preceded by `dotnet restore <target> --locked-mode`**, which evaluates
 *     and runs the project's own MSBuild and reaches its NuGet feeds — the
 *     same trust boundary `deps_update_plan`'s own dotnet branch crosses.
 *     `../deps/dotnetRestore.ts` has the measured rules that keep that
 *     restore from creating or rewriting a lock file. Parsed via
 *     `dotnetScaParser`. Trivy cannot cover this stack at all without a
 *     `packages.lock.json` (see `trivy.ts`), so this is NuGet's only source
 *     of CVE-adjacent findings, not a complementary one like npm's.
 *
 * pip-audit resolves `-r` requirements by building a temporary virtualenv
 * and installing them into it from PyPI — network access, and an sdist's own
 * build step runs there. The tool description says so, next to the restore.
 *
 * All raw outputs are persisted under `.guardian/reports/depsaudit-<scan>/`.
 */

import { existsSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import {
  classifyRestoreFailure,
  findDotnetTargets,
  planDotnetRestore,
  removeCreatedLockFiles,
} from '../deps/dotnetRestore.js';
import { dotnetScaParser } from '../runners/scannerParsers/dotnetSca.js';
import { NPM_AUDIT_TOOL_NAME, npmAuditParser } from '../runners/scannerParsers/npmAudit.js';
import { pipAuditParser } from '../runners/scannerParsers/pipAudit.js';
import { TRIVY_TOOL_NAME, trivyParser } from '../runners/scannerParsers/trivy.js';
import { runProcess } from '../runners/processRunner.js';
import { honouredHandedFiles, honouredRootFiles, nameRepoConfig, withProjectConfig } from '../runners/repoConfig.js';
import { judgeTrivyFs, runTrivy, type TrivyFsJudgement } from '../runners/trivyRun.js';
import { trivySkipArgs } from '../platform/guardianIgnore.js';
import { Force, ProjectPath, SeverityMin } from '../schemas.js';
import type { Finding, ToolRun } from '../types.js';
import { registerToolModule } from './index.js';
import {
  ensureReportDir,
  readJsonSafe,
  scannerAvailable,
} from './scanHelpers.js';
import {
  makeScanTool,
  type ScannerInvocation,
} from './scanToolFactory.js';

interface BotConfigured {
  renovate: boolean;
  dependabot: boolean;
}

/**
 * The package name a scanner encoded in a finding's snippet. Both parsers write
 * `${pkg}@${version…}` (Trivy: `pkg@installed->fixed`; npm: `pkg@range`), so the
 * name is everything before the LAST `@` — which keeps scoped names like
 * `@babel/core` intact. Returns null when no package can be recovered.
 */
function packageFromSnippet(snippet: string | undefined): string | null {
  if (!snippet) return null;
  const at = snippet.lastIndexOf('@');
  if (at <= 0) return null; // no version marker, or a leading '@' with empty name
  return snippet.slice(0, at).trim().toLowerCase() || null;
}

/**
 * Trivy is the canonical CVE source across stacks; npm audit is here for the
 * GitHub advisories Trivy misses. When both flag the SAME package they are
 * (almost always) the same vulnerability seen twice — Trivy by CVE, npm by
 * GHSA — and npm's finding would otherwise inflate the counts. So we drop each
 * npm-audit finding whose package Trivy already reported as a CVE. npm findings
 * for packages Trivy did NOT flag (its complementary value) are kept.
 */
function dropNpmDuplicatesOfTrivy(findings: Finding[]): Finding[] {
  const trivyPackages = new Set<string>();
  for (const f of findings) {
    if (f.tool === TRIVY_TOOL_NAME && f.subcategory === 'cve') {
      const pkg = packageFromSnippet(f.snippet);
      if (pkg) trivyPackages.add(pkg);
    }
  }
  if (trivyPackages.size === 0) return findings;
  return findings.filter((f) => {
    if (f.tool !== NPM_AUDIT_TOOL_NAME) return true;
    const pkg = packageFromSnippet(f.snippet);
    return !(pkg !== null && trivyPackages.has(pkg));
  });
}

function detectBots(projectPath: string): BotConfigured {
  return {
    renovate:
      existsSync(join(projectPath, 'renovate.json')) ||
      existsSync(join(projectPath, '.renovaterc')) ||
      existsSync(join(projectPath, '.renovaterc.json')),
    dependabot: existsSync(join(projectPath, '.github', 'dependabot.yml')),
  };
}

registerToolModule(
  makeScanTool({
    name: 'deps_audit',
    title: 'Dependency audit (Trivy + native auditors + bot detection)',
    description:
      'Run Trivy fs (vuln+license) plus stack-specific auditors when applicable: npm audit; ' +
      'pip-audit, once per requirements*.txt (or the project dir for pyproject.toml), never the ' +
      'host Python — it builds a TEMPORARY virtualenv and installs those requirements into it ' +
      'from PyPI, or from an index the requirements file names (named in tools_run) — network ' +
      'access; an sdist\'s build step runs there; and for any .sln/.csproj, ' +
      '`dotnet restore --locked-mode` then `dotnet list package --vulnerable --include-transitive ' +
      '--no-restore`. That restore EXECUTES the project\'s own MSBuild (targets, imported .props) ' +
      'and contacts its NuGet feeds; it never rewrites or creates a packages.lock.json (an ' +
      'out-of-sync lock, or one a restore would create, is reported as a gap). Returns Findings, ' +
      'indexed CVEs, and a `bot_configured` flag indicating whether Renovate or Dependabot is set ' +
      'up in this repo.',
    // Its own type, not scan_deps' 'deps': the two shared cache entries and
    // answered for each other. Readers that want "the latest deps_audit" use
    // `isDepsAuditScan`, which also recognises the 2.0.x rows typed 'deps'.
    scan_type: 'deps_audit',
    category: 'security',
    supportsAutoFix: false,
    inputSchema: {
      project_path: ProjectPath,
      severity_min: SeverityMin,
      force: Force,
    },
    invoke: async (_input, ctx): Promise<ScannerInvocation> => {
      const reportDir = ensureReportDir(ctx.projectPath, ctx.scanId, 'depsaudit');
      const tools_run: ToolRun[] = [];
      const missing_tools: string[] = [];
      const parser_inputs: ScannerInvocation['parser_inputs'] = [];

      // --- Trivy fs (canonical CVE source for all stacks) ---------------
      let manifestCoverageGaps: TrivyFsJudgement['gaps'] = [];
      const trivyBin = await scannerAvailable('trivy');
      if (trivyBin) {
        const outFile = join(reportDir, 'deps.json');
        // Never in the project, never its trivy.yaml (runners/trivyRun.ts).
        const result = await runTrivy({
          args: ['fs', '--scanners', 'vuln,license', '--format', 'json', '--output', outFile, '--quiet', ...trivySkipArgs(ctx.exclusions)],
          target: ctx.projectPath,
          workDir: reportDir,
          ignoreFrom: ctx.projectPath,
          env: ctx.scriptEnv,
          signal: ctx.signal,
          onLog: ctx.onLog,
        });
        const raw = readJsonSafe(outFile);
        if (raw) parser_inputs.push({ parser: trivyParser, input: raw });
        // The one judgement scan_deps, deps_audit and scan_wordpress share
        // (runners/trivyRun.ts#judgeTrivyFs): a manifest anywhere in the
        // tree that Trivy read nothing for (e.g. a bare .csproj with no
        // packages.lock.json) must never read as a clean scan.
        const judged = judgeTrivyFs({ projectPath: ctx.projectPath, raw, run: result, exclusions: ctx.exclusions });
        tools_run.push(judged.toolRun);
        missing_tools.push(...judged.missing);
        manifestCoverageGaps = judged.gaps;
      } else {
        tools_run.push({ name: 'trivy', status: 'skipped', reason: 'not_installed' });
        missing_tools.push('trivy');
      }

      // --- Native auditors ----------------------------------------------
      // npm audit is parsed into Findings; so is pip-audit, now that it is
      // pointed at this project's own manifests instead of the host Python.
      if (existsSync(join(ctx.projectPath, 'package.json'))) {
        await tryNativeAudit({
          command: 'npm',
          args: ['audit', '--json', '--audit-level=info'],
          outFile: join(reportDir, 'npm-audit.json'),
          ctx,
          tools_run,
          missing_tools,
          parser_inputs,
          parser: npmAuditParser,
        });
      }

      // pip-audit: NEVER invoked bare — a bare `pip-audit` audits whatever
      // Python is on PATH (the MCP host's own interpreter), not this
      // project's dependencies. One invocation PER requirements file (so
      // each finding is attributed to its REAL source file, fix round 1
      // item 9 — pip-audit's own JSON output never says which file a
      // dependency came from when several are combined into one call), or
      // the project directory for a pyproject.toml-only project.
      await runPipAudit({ ctx, reportDir, tools_run, missing_tools, parser_inputs });

      // .NET SCA: Trivy cannot cover NuGet at all without a
      // packages.lock.json (trivy.ts's own module comment), so this is the
      // stack's only source of dependency findings, run whenever a
      // .sln/.csproj exists and the SDK is on PATH.
      const dotnetFailures = await runDotnetSca({ ctx, reportDir, tools_run, missing_tools, parser_inputs });

      const bot_configured = detectBots(ctx.projectPath);

      return {
        outcome: 'completed',
        tools_run,
        missing_tools,
        parser_inputs,
        dedupeFindings: dropNpmDuplicatesOfTrivy,
        report_paths: [reportDir],
        extras: {
          bot_configured,
          ...(manifestCoverageGaps.length > 0 ? { manifest_coverage_gaps: manifestCoverageGaps } : {}),
          ...(dotnetFailures.length > 0 ? { dotnet_restore_failures: dotnetFailures } : {}),
        },
      };
    },
  }),
);

interface NativeAuditOptions {
  command: string;
  args: string[];
  outFile: string;
  ctx: Parameters<NonNullable<Parameters<typeof makeScanTool>[0]['invoke']>>[1];
  tools_run: ToolRun[];
  /**
   * Accumulator for auditors that were expected here (the manifest exists) but
   * could not run — not installed, or ran but produced no usable report. A
   * missing auditor is a real coverage gap, so it must be surfaced rather than
   * silently swallowed (otherwise a "0 findings" reads as a clean bill).
   */
  missing_tools?: string[];
  /** When set, the captured JSON is fed to this parser and counted as Findings. */
  parser?: ScannerInvocation['parser_inputs'][number]['parser'];
  /** Accumulator the parsed input is pushed onto (required with `parser`). */
  parser_inputs?: ScannerInvocation['parser_inputs'];
}

/**
 * A real `npm audit --json` report has a `vulnerabilities` (npm 7+) or
 * `advisories` (npm 6) object. When npm cannot audit (no lockfile, config
 * error) it exits non-zero — often with the *same* code 1 it uses for
 * "vulnerabilities found" — and prints an `{ error: … }` object instead. We
 * must not mistake that error for a clean scan, so success is gated on the
 * output actually being a report.
 */
function looksLikeNpmAuditReport(raw: string): boolean {
  try {
    const j = JSON.parse(raw) as Record<string, unknown>;
    if (!j || typeof j !== 'object' || 'error' in j) return false;
    const isObj = (v: unknown): boolean => typeof v === 'object' && v !== null;
    return isObj(j['vulnerabilities']) || isObj(j['advisories']);
  } catch {
    return false;
  }
}

/** The public npm registry: npm audit answered by it is not worth a note. */
const NPM_PUBLIC_REGISTRY = /^https?:\/\/registry\.npmjs\.org\/?$/i;

/**
 * The registry the project's own `.npmrc` sends `npm audit` to, when it is
 * not the public one — credentials in the URL removed — or null.
 *
 * `npm audit` runs in the project, so the project's `.npmrc` decides which
 * server answers it: a private registry is legitimate and stays honoured, but
 * the answer is that server's, and a repository could equally point it at a
 * server of its own that answers "no vulnerabilities". Named in the result,
 * never silent. Only the unscoped `registry` key: a `@scope:registry` line
 * does not move the audit endpoint. The user's own `~/.npmrc` and
 * `npm_config_registry` are the user's choice, not the project's, and are
 * not read here.
 */
export function projectNpmRegistry(projectPath: string): string | null {
  let text: string;
  try {
    text = readFileSync(join(projectPath, '.npmrc'), 'utf8');
  } catch {
    return null;
  }
  let registry: string | null = null;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (line === '' || line.startsWith('#') || line.startsWith(';')) continue;
    const m = /^registry\s*=\s*(.*)$/i.exec(line);
    if (m?.[1] === undefined) continue;
    // The last one wins, as in npm's own ini reader.
    registry = m[1].trim().replace(/^["']|["']$/g, '');
  }
  if (registry === null || registry === '' || NPM_PUBLIC_REGISTRY.test(registry)) return null;
  // Never echo a credential written into the URL.
  return registry.replace(/^([a-z][a-z0-9+.-]*:\/\/)[^/@]*@/i, '$1');
}

async function tryNativeAudit(opts: NativeAuditOptions): Promise<void> {
  const bin = await scannerAvailable(opts.command);
  if (!bin) {
    opts.tools_run.push({
      name: opts.command,
      status: 'skipped',
      reason: 'not_installed',
    });
    // The manifest exists but its auditor is absent — a real coverage gap.
    opts.missing_tools?.push(opts.command);
    return;
  }
  const isNpmStdout = opts.command === 'npm';
  const result = await runProcess({
    command: opts.command,
    args: opts.args,
    cwd: opts.ctx.projectPath,
    env: opts.ctx.scriptEnv,
    signal: opts.ctx.signal,
    onLog: opts.ctx.onLog,
  });
  // npm audit writes to stdout; redirect ourselves.
  if (isNpmStdout && result.stdout.length > 0) {
    try {
      writeFileSync(opts.outFile, result.stdout, 'utf8');
    } catch {
      /* swallow */
    }
  }
  // Exit code 0/1 (or `completed`) is a run that produced output — npm and
  // pip-audit both exit 1 when vulnerabilities are present, which is
  // information, not failure. But npm ALSO exits 1 on a hard error (no
  // lockfile), so for npm we additionally require the output to be a real
  // audit report. An error masquerading as exit 1 must count as a gap, not a
  // clean "0 findings".
  const exitOk =
    result.outcome === 'completed' || result.exitCode === 0 || result.exitCode === 1;
  const ok = isNpmStdout ? exitOk && looksLikeNpmAuditReport(result.stdout) : exitOk;

  // Feed the captured JSON to its parser so the findings are counted. npm
  // prints to stdout; file-output tools (pip-audit) are read back from disk.
  let parsed = false;
  if (ok && opts.parser && opts.parser_inputs) {
    const rawText = isNpmStdout ? result.stdout : readJsonSafe(opts.outFile);
    if (rawText && rawText.length > 0) {
      opts.parser_inputs.push({ parser: opts.parser, input: rawText });
      parsed = true;
    }
  }

  // The project's .npmrc is named whenever npm audit read one (round 5, item
  // 2: `runners/repoConfig.ts`) — its registry, `omit=dev`, `audit-level`
  // decide what is audited — and whoever answered, when the project chose a
  // registry other than npm's (see `projectNpmRegistry`).
  const registry = isNpmStdout ? projectNpmRegistry(opts.ctx.projectPath) : null;
  const npmrc = isNpmStdout ? honouredRootFiles(opts.ctx.projectPath, 'npm') : [];
  const registryNote = (run: ToolRun): ToolRun => {
    const named = withProjectConfig(run, npmrc);
    if (registry === null) return named;
    const note = `npm audit answered by ${registry} (from the project's .npmrc)`;
    return {
      ...named,
      reason: named.reason !== undefined && named.reason.length > 0 ? `${named.reason}; ${note}` : note,
      honoured_config: [...new Set([...(named.honoured_config ?? []), '.npmrc'])],
    };
  };
  if (ok) {
    opts.tools_run.push(
      registryNote({
        name: opts.command,
        status: 'ok',
        reason: parsed ? 'parsed into findings' : 'captured (evidence only)',
      }),
    );
  } else {
    const reason =
      isNpmStdout && exitOk
        ? 'ran but produced no audit report (missing lockfile?)'
        : 'failed to run';
    opts.tools_run.push(registryNote({ name: opts.command, status: 'failed', reason }));
    // A failed auditor is a coverage gap — surface it so the roll-up and the
    // executive summary do not read the result as fully covered.
    opts.missing_tools?.push(opts.command);
  }
}

// --------------------------------------------------------------- pip-audit

/**
 * `requirements*.txt` at the project root, plus one level into a
 * `requirements/` directory (the common `requirements/base.txt` +
 * `requirements/dev.txt` split) — never a recursive walk, matching this
 * file's other manifest checks (`package.json`, `pyproject.toml`), which are
 * root-level existence checks too.
 */
function findRequirementsFiles(projectPath: string): string[] {
  const out: string[] = [];
  let entries: string[] = [];
  try {
    entries = readdirSync(projectPath);
  } catch {
    return out;
  }
  for (const name of entries) {
    if (/^requirements.*\.txt$/i.test(name)) out.push(join(projectPath, name));
  }
  const reqDir = join(projectPath, 'requirements');
  if (existsSync(reqDir)) {
    try {
      for (const name of readdirSync(reqDir)) {
        if (name.toLowerCase().endsWith('.txt')) out.push(join(reqDir, name));
      }
    } catch {
      /* ignore — best-effort */
    }
  }
  return out;
}

/**
 * A real `pip-audit --format json` report has a `dependencies` array — even
 * an empty one on a clean project. pip-audit exits 1 on a resolution
 * failure (a Poetry-only `pyproject.toml` it cannot read, a broken
 * requirements file, a network error reaching PyPI) the SAME way it exits 1
 * when vulnerabilities are found, and on that failure path the `-o` file is
 * either never written or contains something that is not this shape (fix
 * round 1, item 3 / Global Constraint 3: "a scanner that failed is never
 * reported as ok"). Mirrors `looksLikeNpmAuditReport` above for the same
 * reason: exit code alone cannot tell a real report apart from a masked
 * error.
 */
function looksLikePipAuditReport(raw: string): boolean {
  try {
    const j = JSON.parse(raw) as Record<string, unknown>;
    return !!j && typeof j === 'object' && Array.isArray(j['dependencies']);
  } catch {
    return false;
  }
}

/**
 * Runs `pip-audit --format json` once PER requirements file (never bare —
 * see this file's own module comment), or once against the project
 * directory for a `pyproject.toml`-only project. One call per file, not one
 * call with several `-r` flags, so `pipAuditParser` can attribute every
 * finding to the REAL file it came from (fix round 1, item 9) — pip-audit's
 * own JSON says nothing about which requirements file a dependency was
 * read from, so a combined call cannot be attributed at all. The captured
 * JSON is annotated with `__source_file` before being handed to the parser
 * (`scanToolFactory.ts` builds one shared `ParserContext` for a whole scan,
 * so a per-call override cannot go through `ctx` — see `pipAuditParser`'s
 * own doc comment).
 *
 * Aggregated into ONE `tools_run` entry across every file (`ok` if at least
 * one call produced a real report, `failed` only if every call did not) —
 * `create_fix_pr` and every other consumer of `tools_run` expect one entry
 * per named tool, the same pattern `runDotnetSca` already uses for multiple
 * `.csproj` targets.
 */
async function runPipAudit(opts: {
  ctx: Parameters<NonNullable<Parameters<typeof makeScanTool>[0]['invoke']>>[1];
  reportDir: string;
  tools_run: ToolRun[];
  missing_tools: string[];
  parser_inputs: ScannerInvocation['parser_inputs'];
}): Promise<void> {
  const { ctx, reportDir, tools_run, missing_tools, parser_inputs } = opts;
  const requirementsFiles = findRequirementsFiles(ctx.projectPath);
  const hasPyproject = existsSync(join(ctx.projectPath, 'pyproject.toml'));
  if (requirementsFiles.length === 0 && !hasPyproject) return; // nothing to audit — not a gap

  const bin = await scannerAvailable('pip-audit');
  if (!bin) {
    tools_run.push({ name: 'pip-audit', status: 'skipped', reason: 'not_installed' });
    missing_tools.push('pip-audit');
    return;
  }

  // One "target" per invocation: each requirements file individually, or
  // the project directory itself when there is no requirements file at all.
  const targets: Array<{ arg: string; sourceFile: string }> =
    requirementsFiles.length > 0
      ? requirementsFiles.map((f) => ({ arg: f, sourceFile: relative(ctx.projectPath, f) || f }))
      : [{ arg: ctx.projectPath, sourceFile: 'pyproject.toml' }];

  let anyOk = false;
  let anyFailed = false;
  for (const [i, target] of targets.entries()) {
    const outFile = join(reportDir, `pip-audit-${i}.json`);
    const args =
      requirementsFiles.length > 0
        ? ['-r', target.arg, '--format', 'json', '-o', outFile]
        : ['--format', 'json', '-o', outFile, target.arg];
    const result = await runProcess({
      command: 'pip-audit',
      args,
      cwd: ctx.projectPath,
      env: ctx.scriptEnv,
      signal: ctx.signal,
      onLog: ctx.onLog,
    });
    // Exit 0/1 alone is not success — pip-audit exits 1 on a genuine
    // failure the same way it does on "vulnerabilities found" (item 3).
    const exitOk = result.outcome === 'completed' || result.exitCode === 0 || result.exitCode === 1;
    const raw = exitOk ? readJsonSafe(outFile) : null;
    if (raw && looksLikePipAuditReport(raw)) {
      anyOk = true;
      let annotated = raw;
      try {
        const parsed = JSON.parse(raw) as Record<string, unknown>;
        parsed['__source_file'] = target.sourceFile;
        annotated = JSON.stringify(parsed);
      } catch {
        /* raw already passed looksLikePipAuditReport, so this is unreachable
         * in practice; fall back to the unannotated text rather than drop it */
      }
      parser_inputs.push({ parser: pipAuditParser, input: annotated });
    } else {
      anyFailed = true;
    }
  }

  // The requirements files it read whose index options steered the
  // resolution, named (`runners/repoConfig.ts`): honoured — a private index
  // is legitimate — never silently.
  const steering = honouredHandedFiles(
    ctx.projectPath,
    'pip-audit',
    requirementsFilesRead(ctx.projectPath, requirementsFiles),
  );
  if (anyOk) {
    tools_run.push(
      withProjectConfig(
        {
          name: 'pip-audit',
          status: 'ok',
          reason: anyFailed ? 'parsed into findings (failed for at least one target)' : 'parsed into findings',
        },
        steering,
      ),
    );
    if (anyFailed) missing_tools.push('pip-audit');
  } else {
    tools_run.push(
      withProjectConfig(
        {
          name: 'pip-audit',
          status: 'failed',
          reason: 'ran but produced no audit report for any target (resolution failure or unsupported project?)',
        },
        steering,
      ),
    );
    missing_tools.push('pip-audit');
  }
}

/** pip's includes: another requirements (`-r`) or constraints (`-c`) file, read with the same options. */
const PIP_INCLUDE = /^[ \t]*(?:--requirement|--constraint|-r|-c)(?:[ \t]*=[ \t]*|[ \t]+|(?=[^\s=]))(\S+)/;
/** Most requirements files {@link requirementsFilesRead} reads. */
const MAX_REQUIREMENTS_FILES = 50;
/** A requirements file is read up to this size. */
const MAX_REQUIREMENTS_BYTES = 1024 * 1024;

/**
 * The requirements files pip reads when pip-audit is handed `handed`: those,
 * and every file they include (`-r` / `-c`, relative to the including file,
 * as pip resolves them), transitively and bounded — project-relative,
 * `/`-separated. An include that is a URL, holds an environment variable or
 * leaves the project is not read (the server reads within the project), so
 * an index option there is not named.
 */
function requirementsFilesRead(projectPath: string, handed: readonly string[]): string[] {
  const inProject = (abs: string): string | null => {
    const rel = relative(projectPath, abs);
    if (rel === '' || isAbsolute(rel) || rel === '..' || rel.startsWith(`..${sep}`)) return null;
    return rel.split(sep).join('/');
  };
  const seen = new Set<string>();
  const out: string[] = [];
  const queue = [...handed];
  while (queue.length > 0 && out.length < MAX_REQUIREMENTS_FILES) {
    const abs = queue.shift();
    if (abs === undefined) break;
    const rel = inProject(abs);
    if (rel === null || seen.has(rel)) continue;
    seen.add(rel);
    let text: string;
    try {
      const st = statSync(abs);
      if (!st.isFile() || st.size > MAX_REQUIREMENTS_BYTES) continue;
      text = readFileSync(abs, 'utf8');
    } catch {
      continue;
    }
    out.push(rel);
    // pip joins a line that ends in a backslash with the next.
    for (const line of text.replace(/\\\r?\n/g, ' ').split(/\r?\n/)) {
      const target = PIP_INCLUDE.exec(line)?.[1]?.replace(/^["']|["']$/g, '');
      if (target === undefined || target === '' || /^[a-z][a-z0-9+.-]*:\/\//i.test(target) || target.includes('$')) continue;
      queue.push(resolve(dirname(abs), target));
    }
  }
  return out;
}


// --------------------------------------------------------------- .NET SCA

/** One target's restore/list failure, surfaced structurally in the scan's
 *  extras (`dotnet_restore_failures`) as well as in the tool's reason. */
interface DotnetTargetFailure {
  target: string;
  code: string;
  reason: string;
}

/**
 * Runs `dotnet list <target> package --vulnerable --include-transitive
 * --format json --no-restore` for every target `findDotnetTargets` finds,
 * each one preceded by an explicit `dotnet restore` planned by
 * `planDotnetRestore` (`../deps/dotnetRestore.ts` — its module comment has
 * the measured rules): `--locked-mode` on every restore, lock files found from
 * the solution/project list rather than a depth-limited walk, and a restore
 * that would create a lock file is either prevented
 * (`-p:RestorePackagesWithLockFile=false`) or not run at all. `dotnet list`
 * never restores on its own (`--no-restore`), so the listing is always built
 * from the restore this call just ran — which is also why no
 * `requestedVersion`/`resolvedVersion` comparison is made any more: after a
 * fresh restore the two legitimately differ for every floating (`12.*`),
 * range (`[12.0.1,13.0)`), two-part (`12.0`) or not-on-the-feed (`12.0.0`
 * resolving to `12.0.1`) reference, and treating that as staleness threw real
 * findings away.
 *
 * A failed target is one coverage gap, not a whole-scan failure — the other
 * targets still run — and its reason carries NuGet's own code, so an
 * out-of-sync lock (`NU1004`) reads differently from a missing package
 * (`NU1101`) or an unreachable feed (`NU1301`).
 */
async function runDotnetSca(opts: {
  ctx: Parameters<NonNullable<Parameters<typeof makeScanTool>[0]['invoke']>>[1];
  reportDir: string;
  tools_run: ToolRun[];
  missing_tools: string[];
  parser_inputs: ScannerInvocation['parser_inputs'];
}): Promise<DotnetTargetFailure[]> {
  const { ctx, reportDir, tools_run, missing_tools, parser_inputs } = opts;
  const targets = findDotnetTargets(ctx.projectPath);
  if (targets.length === 0) return []; // no .sln/.csproj — nothing to do, not a gap

  const dotnetBin = await scannerAvailable('dotnet');
  if (!dotnetBin) {
    tools_run.push({ name: 'dotnet', status: 'skipped', reason: 'not_installed' });
    missing_tools.push('dotnet');
    return [];
  }

  let anyOk = false;
  const failures: DotnetTargetFailure[] = [];
  for (const [i, target] of targets.entries()) {
    const rel = relative(ctx.projectPath, target) || target;
    const plan = planDotnetRestore(ctx.projectPath, target);
    if (plan.blocked) {
      failures.push({ target: rel, code: plan.blocked.code, reason: plan.blocked.reason });
      continue;
    }
    const restore = await runProcess({
      command: 'dotnet',
      args: plan.args,
      cwd: ctx.projectPath,
      env: ctx.scriptEnv,
      signal: ctx.signal,
      onLog: ctx.onLog,
    });
    const created = removeCreatedLockFiles(plan);
    if (created.length > 0) {
      failures.push({
        target: rel,
        code: 'lock_file_would_be_created',
        reason:
          `restore created ${created.map((c) => relative(ctx.projectPath, c) || c).join(', ')} ` +
          '(a RestorePackagesWithLockFile opt-in this scan could not see) — deleted again; results not used',
      });
      continue;
    }
    if (restore.outcome !== 'completed') {
      // Never retried without --locked-mode: that retry would be exactly the
      // lock rewrite this whole sequence exists to prevent.
      const failure = classifyRestoreFailure(restore.stdout, restore.stderr);
      failures.push({ target: rel, code: failure.code, reason: failure.reason });
      continue;
    }

    const list = await runProcess({
      command: 'dotnet',
      args: ['list', target, 'package', '--vulnerable', '--include-transitive', '--format', 'json', '--no-restore'],
      cwd: ctx.projectPath,
      env: ctx.scriptEnv,
      signal: ctx.signal,
      onLog: ctx.onLog,
    });
    if (list.outcome !== 'completed' || list.stdout.trim().length === 0) {
      failures.push({ target: rel, code: 'list_failed', reason: 'restored, but `dotnet list package --vulnerable` failed' });
      continue;
    }
    anyOk = true;
    parser_inputs.push({ parser: dotnetScaParser, input: list.stdout });
    try {
      writeFileSync(join(reportDir, `dotnet-list-${i}.json`), list.stdout, 'utf8');
    } catch {
      /* best-effort evidence copy */
    }
  }

  const gapReason = failures.map((f) => `${f.target}: ${f.reason}`).join('; ');
  // The project's NuGet.config files answer the lookup: named (`runners/repoConfig.ts`).
  if (anyOk) {
    tools_run.push(
      await nameRepoConfig(
        {
          name: 'dotnet',
          status: 'ok',
          reason: failures.length > 0 ? `parsed into findings (gap — ${gapReason})` : 'parsed into findings',
        },
        ctx.projectPath,
        'dotnet',
      ),
    );
    if (failures.length > 0) missing_tools.push('dotnet');
  } else {
    tools_run.push(
      await nameRepoConfig({ name: 'dotnet', status: 'failed', reason: gapReason || 'no target could be listed' }, ctx.projectPath, 'dotnet'),
    );
    missing_tools.push('dotnet');
  }
  return failures;
}
