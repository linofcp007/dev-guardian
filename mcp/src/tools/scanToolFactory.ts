/**
 * Generic scan-tool factory.
 *
 * Most of our scan tools share the same lifecycle:
 *
 *   1. Validate input (zod)
 *   2. Resolve project_path
 *   3. (Optional) Check working-tree is clean for auto_fix
 *   4. Compute tree_hash
 *   5. Cache hit? → return existing scan_id flagged as cached
 *   6. Insert scans(running)
 *   7. Invoke the scanner (the tool-specific bit)
 *   8. Apply parsers, filter by severity_min, persist findings/CVEs
 *   9. Finalize scans → completed / failed / cancelled / output_too_large
 *  10. Build and return ScanResult
 *
 * Steps 1–6 and 8–10 are common — this factory implements them. Only step
 * 7 (and the bits inside `config.invoke`) is tool-specific.
 *
 * The factory is single-tenant per process: concurrent calls for the same
 * tree_hash are serialised by SQLite's transactions, but the runtime
 * doesn't attempt to coalesce two in-flight calls into a single run.
 */

import { randomUUID } from 'node:crypto';
import type { ZodRawShape } from 'zod';
import { buildDriftAdvisory } from '../configdrift/advisory.js';
import { detectConfigDrift } from '../configdrift/detect.js';
import type { PluginContext, ToolContext } from '../context.js';
import { configsDirFromScriptsDir } from '../platform/configsDir.js';
import { resolveVersion } from '../platform/version.js';
import { makeProgressEmitter } from '../progress/progressEmitter.js';
import {
  type ParserContext,
  type ParserCveInput,
  type ScannerParser,
} from '../runners/scannerParsers/index.js';
import { getScanLimiter } from '../runners/concurrencyLimiter.js';
import { runShellScript, type ShellRunResult } from '../runners/shellRunner.js';
import { filterFindings } from '../severity/filter.js';
import { SEVERITY_ORDER } from '../types.js';
import type {
  Category,
  DomainError,
  Finding,
  FindingsCountBySeverity,
  ScanResult,
  ScanType,
  Severity,
  ToolResult,
  ToolRun,
} from '../types.js';
import { computeTreeHash } from '../treeHash/computeTreeHash.js';
import {
  InvalidProjectPathError,
  resolveProjectPath,
} from '../platform/projectPath.js';
import { isWorkingTreeClean } from './gitState.js';
import { assessCoverage } from './scanCoverage.js';
import type { ToolModule } from './index.js';

/**
 * What `config.invoke` returns to the factory. Either a direct shell run
 * (most tools) plus the parser tasks for it, or a fully synthesised
 * outcome for tools that don't shell out at all (e.g. an internal
 * sequencer).
 */
export interface ScannerInvocation {
  /** The runner outcome ('completed', 'failed', 'cancelled', etc.). */
  outcome: ShellRunResult['outcome'];
  /** Status per scanner (semgrep ok, bandit skipped, …). */
  tools_run: ToolRun[];
  /** Scanners that were expected to run but were not installed. */
  missing_tools: string[];
  /** Inputs to feed parsers. Parsers run sequentially in array order. */
  parser_inputs: Array<{ parser: ScannerParser; input: unknown }>;
  /**
   * Optional cross-parser reconciliation applied once, after every parser has
   * run, over the combined findings. Used when one scanner's output overlaps
   * another's (e.g. `deps_audit` dropping npm-audit findings for packages Trivy
   * already reported by CVE) so the same vulnerability is not counted twice.
   */
  dedupeFindings?: (findings: Finding[]) => Finding[];
  /** Absolute paths to scanner report files written under .guardian/reports. */
  report_paths: string[];
  /** Optional error string surfaced when outcome !== 'completed'. */
  error?: string;
  /**
   * Additional keys merged into the ToolResult payload alongside the
   * canonical ScanResult fields. Used by tools that need to surface extra
   * structured data (e.g. `deps_audit` returning `bot_configured`).
   */
  extras?: Record<string, unknown>;
}

export interface InvokeContext extends ToolContext {
  /** Convenience: the env file scripts expect (PROJECT_PATH etc.). */
  scriptEnv: NodeJS.ProcessEnv;
}

export interface ScanToolBaseInput {
  project_path?: string;
  severity_min?: Severity;
  force?: boolean;
  auto_fix?: boolean;
  allow_dirty?: boolean;
}

export interface ScanToolConfig<TInput extends ScanToolBaseInput> {
  name: string;
  description: string;
  title?: string;
  scan_type: ScanType;
  category: Category;
  inputSchema: ZodRawShape;
  /**
   * How long a freshly completed scan of this type is considered "still
   * valid" for cache reuse. Defaults to 5 minutes per US-8 AC-2.
   */
  cacheTtlMs?: number;
  /**
   * Whether `auto_fix` is meaningful for this tool. When false (e.g.
   * `scan_secrets`), the factory skips the working-tree-clean check.
   */
  supportsAutoFix?: boolean;
  /**
   * The tool-specific bit: actually run the scanner(s) and return the
   * parser inputs. Throw to signal a true failure; return outcome='failed'
   * + an error string to signal a soft failure that should still finalize
   * the scan row.
   */
  invoke: (input: TInput, ctx: InvokeContext) => Promise<ScannerInvocation>;
}

const FIVE_MINUTES_MS = 5 * 60 * 1000;

export function makeScanTool<TInput extends ScanToolBaseInput>(
  config: ScanToolConfig<TInput>,
): ToolModule {
  return {
    name: config.name,
    description: config.description,
    ...(config.title ? { title: config.title } : {}),
    inputSchema: config.inputSchema,
    handler: (rawInput, plugin, callMeta) =>
      runScanPipeline(config, rawInput as TInput, plugin, callMeta),
  };
}

async function runScanPipeline<TInput extends ScanToolBaseInput>(
  config: ScanToolConfig<TInput>,
  input: TInput,
  plugin: PluginContext,
  callMeta?: import('./index.js').ToolCallMeta,
): Promise<ToolResult<Record<string, unknown>>> {
  if (config.supportsAutoFix !== false && input.auto_fix === true) {
    if (input.allow_dirty !== true) {
      try {
        const resolved = resolveProjectPath(input.project_path);
        if (!(await isWorkingTreeClean(resolved.path))) {
          return failDomain('working_tree_dirty', `auto_fix=true requires a clean working tree.`, {
            allow_dirty: true,
          });
        }
      } catch (e) {
        if (e instanceof InvalidProjectPathError) {
          return failDomain('not_a_git_repo', e.message);
        }
        throw e;
      }
    }
  }

  let resolvedProject: ReturnType<typeof resolveProjectPath>;
  try {
    resolvedProject = resolveProjectPath(input.project_path);
  } catch (e) {
    if (e instanceof InvalidProjectPathError) {
      return failDomain('not_a_git_repo', e.message);
    }
    throw e;
  }
  const projectPath = resolvedProject.path;
  const warnings: string[] = [];
  if (resolvedProject.warning) warnings.push(resolvedProject.warning);
  if (plugin.storageWarning) warnings.push(plugin.storageWarning);
  const driftAdvisory = configDriftAdvisory(plugin, projectPath);
  if (driftAdvisory) warnings.push(driftAdvisory);

  if (plugin.shell === null) {
    return failDomain(
      'no_bash_shell',
      'No usable bash shell was found on this host. Run `install_toolchain` or install Git Bash / WSL.',
    );
  }

  const treeHash = await computeTreeHash(projectPath);

  // Cache check.
  const ttl = config.cacheTtlMs ?? FIVE_MINUTES_MS;
  const fresh = new Date(Date.now() - ttl).toISOString();
  if (input.force !== true) {
    const cached = plugin.storage.scans.findCacheHit({
      tree_hash: treeHash,
      scan_type: config.scan_type,
      freshThreshold: fresh,
    });
    if (cached) {
      return cachedResult(plugin, cached.scan_id, warnings);
    }
  }

  // Insert running scan.
  const scanId = randomUUID();
  plugin.storage.scans.insert({
    scan_id: scanId,
    scan_type: config.scan_type,
    project_path: projectPath,
    tree_hash: treeHash,
  });
  plugin.storage.scans.attachTreeCache({
    tree_hash: treeHash,
    scan_id: scanId,
    scan_type: config.scan_type,
  });

  // Set up per-call context.
  // Use the host's AbortSignal if provided; otherwise build a fresh one so
  // child runners always have a signal to listen to. The host signal is
  // what propagates `notifications/cancelled` from the MCP client down to
  // SIGTERM on the child process tree.
  const controller = new AbortController();
  const externalSignal = callMeta?.signal;
  if (externalSignal) {
    if (externalSignal.aborted) {
      controller.abort();
    } else {
      externalSignal.addEventListener(
        'abort',
        () => {
          controller.abort();
        },
        { once: true },
      );
    }
  }
  const progress = makeProgressEmitter({
    token: callMeta?.progressToken,
    notifier: plugin.progressNotifier,
  });
  const ctx: InvokeContext = {
    plugin,
    scanId,
    projectPath,
    signal: controller.signal,
    progress,
    scriptEnv: {
      ...process.env,
      PROJECT_PATH: projectPath,
      GUARDIAN_SCAN_ID: scanId,
    },
  };

  // Acquire a slot from the global concurrency limiter so 50 parallel
  // calls from the host don't fork 50 scanner processes. Default cap is 2.
  const limiter = getScanLimiter();
  await limiter.acquire();
  let invocation: ScannerInvocation;
  try {
    invocation = await config.invoke(input, ctx);
  } catch (e) {
    plugin.storage.scans.finalize({
      scan_id: scanId,
      status: 'failed',
      tools_run: [],
      missing_tools: [],
      error: e instanceof Error ? e.message : String(e),
    });
    progress.dispose();
    limiter.release();
    return failDomain(
      'scanner_failed',
      e instanceof Error ? e.message : 'Scanner failed with an unknown error',
    );
  } finally {
    progress.dispose();
  }
  limiter.release();

  // Apply parsers.
  let findings: Finding[] = [];
  const cves: ParserCveInput[] = [];
  const parserCtx: ParserContext = { project_path: projectPath };
  for (const task of invocation.parser_inputs) {
    const out = task.parser.parse(task.input, parserCtx);
    findings.push(...out.findings);
    cves.push(...out.cves);
  }

  // Cross-parser reconciliation (e.g. drop npm-audit dupes of Trivy CVEs)
  // before anything counts, persists, or filters the findings.
  if (invocation.dedupeFindings) findings = invocation.dedupeFindings(findings);

  // Severity floor.
  findings = filterFindings(findings, input.severity_min);

  // Persist findings + CVEs (best-effort; one transaction per repo).
  if (findings.length > 0) {
    plugin.storage.findings.bulkInsert(
      findings.map((f) => ({ ...f, scan_id: scanId })),
    );
  }
  if (cves.length > 0) {
    plugin.storage.cves.bulkUpsert(cves.map((c) => ({ ...c, scan_id: scanId })));
  }

  const status =
    invocation.outcome === 'completed'
      ? 'completed'
      : invocation.outcome === 'cancelled'
        ? 'cancelled'
        : 'failed';

  const finalize: Parameters<typeof plugin.storage.scans.finalize>[0] = {
    scan_id: scanId,
    status,
    tools_run: invocation.tools_run,
    missing_tools: invocation.missing_tools,
  };
  if (invocation.report_paths[0] !== undefined) finalize.report_dir = invocation.report_paths[0];
  if (invocation.error !== undefined) finalize.error = invocation.error;
  // Persist extras into scans.meta so resources (compliance/status, etc.)
  // can read them without forcing a re-run.
  if (invocation.extras !== undefined) finalize.meta = invocation.extras;
  plugin.storage.scans.finalize(finalize);

  if (status === 'cancelled') {
    return failDomain('cancelled', 'Scan was cancelled by the host.');
  }

  if (invocation.outcome === 'output_too_large') {
    return failDomain(
      'output_too_large',
      'Scanner output exceeded 5 MB. Read full report from report_paths instead.',
      { report_paths: invocation.report_paths },
    );
  }

  // Build the ScanResult response.
  const counts = countBySeverity(findings);
  const top = topFindings(findings, 10);

  // Coverage: did the scanners that were supposed to run actually run? A
  // "0 findings" result is only trustworthy at coverage 'full'. When a primary
  // scanner was missing/failed we push a loud warning so the count is never
  // mistaken for a clean bill of health.
  const { coverage, warning: coverageWarning } = assessCoverage(
    config.scan_type,
    invocation.tools_run,
    invocation.missing_tools,
  );
  if (coverageWarning) warnings.unshift(coverageWarning);

  const result: ScanResult = {
    scan_id: scanId,
    scan_type: config.scan_type,
    project_path: projectPath,
    tree_hash: treeHash,
    started_at: new Date().toISOString(), // best-effort; real value lives in DB
    finished_at: new Date().toISOString(),
    status,
    tools_run: invocation.tools_run,
    missing_tools: invocation.missing_tools,
    report_paths: invocation.report_paths,
    findings_count_by_severity: counts,
    top_findings: top,
    warnings,
    coverage,
  };

  const payload: Record<string, unknown> = {
    ...(result as unknown as Record<string, unknown>),
    ...(invocation.extras ?? {}),
  };
  return { ok: true, ...payload };
}

/**
 * The config-drift advisory, or `null` when there is nothing to say.
 *
 * ---- Why it hangs off the scan pipeline ------------------------------
 *
 * `init_project` copies four baseline configs into a project and then never
 * looks at them again, so a fix to a shipped config — `base.yml`'s
 * `wp-unescaped-output`, which could not match anything until b51a2dc — never
 * reaches a project that already ran init. A check only helps if it runs
 * somewhere people actually go, and every scan tool in this codebase comes
 * through here, including the cached path.
 *
 * ---- Why it checks all four, not "the one this scan reads" -----------
 *
 * The narrower design was tried first and does not survive contact: `scan_sast`
 * runs Semgrep with `--config=auto` plus registered custom rules and never
 * reads `.semgrep.yml` at all; `deps_audit` only existence-checks
 * `renovate.json`; `.pre-commit-config.yaml` is consumed by git hooks, not by
 * any scan. Mapping scan types to files would encode four claims about who
 * reads what, three of which are already false. What is true is simpler: these
 * are the baselines this project installed, and the scan is when the user is
 * looking. Reading four small files and hashing them costs nothing next to a
 * Semgrep run.
 *
 * Never throws, and cannot alter the scan: the return value's only
 * destination is the `warnings` string array.
 */
function configDriftAdvisory(plugin: PluginContext, projectPath: string): string | null {
  try {
    return buildDriftAdvisory(
      detectConfigDrift({
        projectPath,
        configsDir: configsDirFromScriptsDir(plugin.scriptsDir),
        currentVersion: resolveVersion(),
      }),
    );
  } catch {
    return null;
  }
}

function cachedResult(
  plugin: PluginContext,
  scanId: string,
  warnings: string[],
): ToolResult<Record<string, unknown>> {
  const record = plugin.storage.scans.getById(scanId);
  if (!record) {
    return failDomain('unknown_scan_id', `Cached scan ${scanId} could not be loaded.`);
  }
  const findings = plugin.storage.findings.listByScan(scanId);
  const counts = countBySeverity(findings);
  const top = topFindings(findings, 10);

  // Re-derive coverage from the persisted tools_run/missing_tools so a cached
  // scan carries the same honest signal as a fresh one.
  const { coverage, warning: coverageWarning } = assessCoverage(
    record.scan_type,
    record.tools_run,
    record.missing_tools,
  );
  const allWarnings = coverageWarning ? [coverageWarning, ...warnings] : warnings;

  const payload: ScanResult = {
    ...record,
    cached: true,
    cached_from: scanId,
    findings_count_by_severity: counts,
    top_findings: top,
    warnings: allWarnings,
    coverage,
  };
  return { ok: true, ...(payload as unknown as Record<string, unknown>) };
}

function countBySeverity(findings: Finding[]): FindingsCountBySeverity {
  const out: FindingsCountBySeverity = {
    info: 0,
    low: 0,
    medium: 0,
    high: 0,
    critical: 0,
  };
  for (const f of findings) out[f.severity] += 1;
  return out;
}

function topFindings(findings: Finding[], limit: number): Finding[] {
  return [...findings]
    .sort(
      (a, b) =>
        SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity] ||
        a.fingerprint.localeCompare(b.fingerprint),
    )
    .slice(0, limit);
}

function failDomain(
  code: DomainError['code'],
  message: string,
  retry_with?: Record<string, unknown>,
): ToolResult<Record<string, unknown>> {
  const error: DomainError = { code, message };
  if (retry_with !== undefined) error.retry_with = retry_with;
  return { ok: false, error };
}

// Re-export for tools to build their `parser_inputs` ergonomically.
export { runShellScript };
