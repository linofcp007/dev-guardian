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
 *   8. Apply parsers, give each finding its line-independent identity,
 *      persist findings/CVEs
 *   9. Finalize scans → completed / failed / cancelled / output_too_large
 *  10. Filter by severity_min, then build and return ScanResult
 *
 * Steps 1–6 and 8–10 are common — this factory implements them. Only step
 * 7 (and the bits inside `config.invoke`) is tool-specific.
 *
 * **`severity_min` filters the response, never the history.** Step 8 stores
 * everything the scan found and step 10 shows the caller the slice they
 * asked for; the order used to be the other way round, which threw the rest
 * away. See the comment above `bulkInsert` for what that cost. A tool's own
 * `responseView` (bug_hunt's `categories`) follows the same rule.
 *
 * ---- The cache key: every input field, except the response-only ones ----
 *
 * A scan is served from the cache only under exactly the same key
 * (`treeHash/cacheKey.ts#scanCacheKey`): the canonical project path, the tool
 * name and scan type, the tree hash, the plugin version, the content of every
 * rule pack the tool declares in `rulePacks`, and a hash of the NORMALISED
 * input. The rule for the input is deliberately blunt, because every
 * exception to it was a reproduced wrong answer (see cacheKey.ts): EVERY
 * input field takes part, after the tool's own zod schema has applied its
 * defaults, EXCEPT
 *
 *   - `project_path` — keyed separately, in canonical form, so `.` and the
 *     absolute path of the same directory agree;
 *   - `severity_min` and `force` — they shape the response or the lookup,
 *     never the scan;
 *   - whatever the tool lists in `responseOnlyInputs`.
 *
 * A new input field is therefore part of the key the moment it is added to a
 * tool's schema, with no change here — which is what keeps, say, a scoped scan
 * from ever sharing a cache entry with an unscoped one. A field may be listed
 * in `responseOnlyInputs` only if it is applied by `responseView` (or later,
 * on the response) and changes nothing about what is scanned or stored.
 *
 * The factory is single-tenant per process: concurrent calls for the same
 * key are serialised by SQLite's transactions, but the runtime doesn't
 * attempt to coalesce two in-flight calls into a single run.
 *
 * ---- Scoped scans and `.guardianignore` ------------------------------
 *
 * A tool with `supportsScope` takes a `scope` input (`platform/scope.ts`):
 * the factory resolves it to a file set BEFORE any scan row exists (a scope
 * that names nothing is a domain error, never an empty scan), hands it to
 * `invoke` as `ctx.scope`, keeps only the findings inside it, and records the
 * row with `meta.scope` — which keeps it out of the open set, the baselines
 * and every "latest"/"previous" comparison (`history/scanRoles.ts`). The
 * resolved file set and refs join the cache key, so a moved branch is a new
 * scan; `scope` itself is an input like any other, so a scoped call never
 * shares an entry with an unscoped one.
 *
 * Every tool honours the project's `.guardianignore`
 * (`platform/guardianIgnore.ts`): `ctx.exclusions` for the native flags a
 * scanner has, and a result filter here for all of them. What it excluded —
 * files and findings — is in every response (`exclusions`), fresh or cached.
 */

import { randomUUID } from 'node:crypto';
import { z, type ZodRawShape } from 'zod';
import { buildDriftAdvisory } from '../configdrift/advisory.js';
import { detectConfigDrift } from '../configdrift/detect.js';
import type { PluginContext, ToolContext } from '../context.js';
import { assignIdentities, dependencyCoordinates, makeSourceReader } from '../fingerprint/findingIdentity.js';
import { configsDirFromScriptsDir } from '../platform/configsDir.js';
import {
  GUARDIAN_IGNORE_FILE,
  isProjectPath,
  loadProjectExclusions,
  type ProjectExclusions,
} from '../platform/guardianIgnore.js';
import {
  resolveScope,
  ScanScopeInput,
  ScopeError,
  suggestScopeForFile,
  type ResolvedScope,
  type ScanScope,
} from '../platform/scope.js';
import { resolveVersion } from '../platform/version.js';
import { makeProgressEmitter, type ProgressEmitter } from '../progress/progressEmitter.js';
import {
  type ParserContext,
  type ParserCveInput,
  type ScannerParser,
} from '../runners/scannerParsers/index.js';
import { getScanLimiter } from '../runners/concurrencyLimiter.js';
import type { ProcessOutcome } from '../runners/processRunner.js';
import { describeShortfallTiers, severityShortfall } from '../severity/breakdown.js';
import { filterFindings } from '../severity/filter.js';
import { SEVERITY_ORDER } from '../types.js';
import type {
  Category,
  DomainError,
  Finding,
  FindingsCountBySeverity,
  ScanCoverage,
  ScanResult,
  ScanType,
  Severity,
  SeverityFilterDisclosure,
  ToolResult,
  ToolRun,
} from '../types.js';
import { hashInput, hashRulePacks, scanCacheKey } from '../treeHash/cacheKey.js';
import { computeTreeHash } from '../treeHash/computeTreeHash.js';
import {
  InvalidProjectPathError,
  resolveProjectPath,
} from '../platform/projectPath.js';
import { workingTreeState } from './gitState.js';
import { assessCoverage, computeCoverage } from './scanCoverage.js';
import type { ToolCallMeta, ToolModule } from './index.js';

/**
 * What `config.invoke` returns to the factory: how the scanner run(s) ended,
 * plus the parser tasks for their output — or a fully synthesised outcome for
 * a tool that runs other tools (`security_scan_full`).
 */
export interface ScannerInvocation {
  /** The runner outcome ('completed', 'failed', 'cancelled', etc.). */
  outcome: ProcessOutcome;
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
   * Warnings about THIS run (e.g. review_pr: the diff edits
   * `.guardianignore`), added to the response and kept on the row, so a cache
   * hit says them too.
   */
  warnings?: string[];
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
  /**
   * What an orchestrator passes to each child tool it runs: this call's
   * signal (so cancelling the parent stops every child's scanner), the host's
   * progress token, and this scan's id as `parentScanId`, which the child
   * records in its own row's `meta.parent_scan_id`.
   */
  childCallMeta: ToolCallMeta;
  /**
   * The project whose rule configuration this scan uses — `projectPath`
   * itself, unless `create_fix_pr` is re-scanning a worktree of another
   * project (`ToolCallMeta.originProjectPath`).
   */
  rulesProjectPath: string;
  /**
   * The resolved `scope` of a scoped call (`supportsScope` tools only), or
   * null for a whole-project scan. The tool scans `scope.files` as explicit
   * targets; the factory drops every finding outside `scope.member`.
   */
  scope: ResolvedScope | null;
  /** The project's `.guardianignore`, or null when it has none. */
  exclusions: ProjectExclusions | null;
}

export interface ScanToolBaseInput {
  project_path?: string;
  severity_min?: Severity;
  force?: boolean;
  auto_fix?: boolean;
  allow_dirty?: boolean;
  /** Read only for tools with `supportsScope` (see `platform/scope.ts`). */
  scope?: ScanScope;
}

/** What `rulePacks` gets to decide which packs a call would load. */
export interface RulePackContext {
  /** Canonical project path. */
  projectPath: string;
  plugin: PluginContext;
  /** See `InvokeContext.rulesProjectPath`. */
  rulesProjectPath: string;
}

/**
 * A response-only view over a scan's stored findings, applied before
 * `severity_min`. Everything the scan found is still persisted; the view
 * decides what this one response shows, and says what it withheld.
 */
export interface ResponseView {
  /** The findings this response shows (before `severity_min`). */
  visible: Finding[];
  /** Merged into the payload, e.g. `{ category_filter: {...} }`. */
  disclosure: Record<string, unknown>;
  /** Added to `warnings` when the view withheld something, else null. */
  warning: string | null;
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
   * Input fields, beyond `severity_min` and `force`, that shape only the
   * response and so stay out of the cache key — see the module comment for
   * the rule a field must meet to be listed here.
   */
  responseOnlyInputs?: readonly string[];
  /**
   * Every rule pack this call would load: local files and directories are
   * keyed by content, anything else (a registry pack such as `p/php`) by
   * name. Must name the same packs `invoke` passes to the scanner, or an
   * edited pack is served from a stale cache entry.
   */
  rulePacks?: (input: TInput, ctx: RulePackContext) => readonly string[];
  /**
   * Warnings about the tool's CONFIGURATION rather than about one run — e.g.
   * custom rules registered in 2.0.x that no longer apply — added to every
   * response, fresh or served from the cache. A throw adds nothing.
   */
  configWarnings?: (input: TInput, ctx: RulePackContext) => readonly string[];
  /**
   * State outside the working tree that the scan reads, joined to the cache
   * key — e.g. HEAD and every ref for a git-history scan, which a fetch or an
   * empty-diff merge moves without changing one file. A throw makes the call
   * uncacheable rather than failing it.
   */
  cacheState?: (input: TInput, ctx: RulePackContext) => Promise<Record<string, string>>;
  /** See {@link ResponseView}. Applied to fresh runs and cache hits alike. */
  responseView?: (input: TInput, findings: readonly Finding[], scanId: string) => ResponseView | null;
  /**
   * The tool runs other scan tools (`security_scan_full`) rather than a
   * scanner. It takes no slot from the scan limiter itself: each child takes
   * its own, and a parent holding one while its children wait for the rest
   * deadlocks as soon as two parents run at the default limit of 2.
   */
  orchestrator?: boolean;
  /**
   * The tool takes a `scope` input (its schema must declare
   * `scope: ScanScopeInput`) and scans `ctx.scope.files` when one is given.
   * A `project_path` naming a file is then answered with the call to make
   * instead.
   */
  supportsScope?: boolean;
  /**
   * The tool-specific bit: actually run the scanner(s) and return the
   * parser inputs. Throw to signal a true failure; return outcome='failed'
   * + an error string to signal a soft failure that should still finalize
   * the scan row.
   */
  invoke: (input: TInput, ctx: InvokeContext) => Promise<ScannerInvocation>;
}

const FIVE_MINUTES_MS = 5 * 60 * 1000;

/** Inputs that never enter the cache key — see the module comment. */
const KEYLESS_INPUTS: readonly string[] = ['project_path', 'severity_min', 'force'];

/**
 * Keys the factory itself writes into `scans.meta`, as opposed to a tool's
 * `extras`. A cache hit re-emits every OTHER meta key as an extra, so a key
 * added to `meta` here must be added to this set too — unless, like `scope`
 * and `exclusions`, the factory writes it precisely so that a cache hit
 * answers with it, exactly as the fresh run did.
 */
const FACTORY_META_KEYS: ReadonlySet<string> = new Set(['severity_min', 'parent_scan_id', 'run_warnings']);

/** Longest scanner stderr line forwarded into a progress message. */
const MAX_LOG_LINE = 200;

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
  callMeta?: ToolCallMeta,
): Promise<ToolResult<Record<string, unknown>>> {
  if (config.supportsAutoFix !== false && input.auto_fix === true) {
    if (input.allow_dirty !== true) {
      try {
        const resolved = resolveProjectPath(input.project_path);
        // Only a tree git POSITIVELY confirms clean may be rewritten without
        // `allow_dirty` — see gitState.ts: "not a repo" and "git failed" are
        // not clean, they are unknown.
        const tree = await workingTreeState(resolved.path);
        if (tree.state === 'dirty') {
          return failDomain('working_tree_dirty', `auto_fix=true requires a clean working tree.`, {
            allow_dirty: true,
          });
        }
        if (tree.state === 'unknown') {
          return failDomain(
            'not_a_git_repo',
            `auto_fix=true requires a working tree git confirms is clean, and git could not ` +
              `(${tree.reason}). Autofix would rewrite files nothing can restore; pass ` +
              `allow_dirty=true to accept that.`,
            { allow_dirty: true },
          );
        }
      } catch (e) {
        if (e instanceof InvalidProjectPathError) return invalidProjectPath(config, e);
        throw e;
      }
    }
  }

  let resolvedProject: ReturnType<typeof resolveProjectPath>;
  try {
    resolvedProject = resolveProjectPath(input.project_path);
  } catch (e) {
    if (e instanceof InvalidProjectPathError) return invalidProjectPath(config, e);
    throw e;
  }
  const projectPath = resolvedProject.path;
  const warnings: string[] = [];
  if (resolvedProject.warning) warnings.push(resolvedProject.warning);
  if (plugin.storageWarning) warnings.push(plugin.storageWarning);
  const driftAdvisory = configDriftAdvisory(plugin, projectPath);
  if (driftAdvisory) warnings.push(driftAdvisory);

  // `.guardianignore`, then the scope (which it narrows) — both before any
  // scan row exists, so a scope that names nothing is an error, not a scan.
  let exclusions: ProjectExclusions | null = null;
  const loadedExclusions = await loadProjectExclusions(projectPath);
  if (loadedExclusions !== null) {
    if ('error' in loadedExclusions) {
      warnings.push(
        `${GUARDIAN_IGNORE_FILE} could not be read (${loadedExclusions.error}) — NOTHING was excluded from ` +
          'this scan.',
      );
    } else {
      exclusions = loadedExclusions;
    }
  }
  let scope: ResolvedScope | null = null;
  if (config.supportsScope === true && input.scope !== undefined && input.scope !== null) {
    // The MCP layer validated it; an in-process caller may not have.
    const parsed = ScanScopeInput.safeParse(input.scope);
    if (!parsed.success) {
      const issues = parsed.error.issues.map((i) => `${['scope', ...i.path].join('.')}: ${i.message}`);
      return failDomain('unsupported_target', `scope is not valid: ${issues.join('; ')}`);
    }
    if (parsed.data !== undefined) {
      try {
        scope = await resolveScope(projectPath, parsed.data, { exclusions });
      } catch (e) {
        if (e instanceof ScopeError) return failDomain(e.code, e.message);
        throw e;
      }
    }
  }

  // No bash check here: no scan tool built on this factory runs a shell
  // script any more — each invokes its scanners directly — so a host without
  // Git Bash or WSL can still scan.

  // A child of an orchestrator reuses the hash its parent just computed for
  // the same tree (see ToolCallMeta.treeHash) — five hashes of one tree per
  // security_scan_full otherwise.
  const treeHash =
    callMeta?.parentScanId !== undefined && callMeta.treeHash !== undefined
      ? callMeta.treeHash
      : await computeTreeHash(projectPath);
  const rulesProjectPath = callMeta?.originProjectPath ?? projectPath;
  let cacheState: Record<string, string> = {};
  if (config.cacheState) {
    try {
      cacheState = await config.cacheState(input, { projectPath, plugin, rulesProjectPath });
    } catch {
      cacheState = { uncacheable: randomUUID() };
    }
  }
  // The resolved scope (its files and refs) and the ignore file's content
  // shape what is scanned and kept, so both are keyed; absent, the key is
  // exactly what it was before either existed.
  if (scope !== null) cacheState = { ...cacheState, scope: scope.cacheState['scope'] ?? '' };
  if (exclusions !== null) cacheState = { ...cacheState, guardianignore: exclusions.hash };
  const cacheKey = buildCacheKey(config, input, { projectPath, plugin, rulesProjectPath }, treeHash, cacheState);
  if (config.configWarnings) {
    try {
      warnings.push(...config.configWarnings(input, { projectPath, plugin, rulesProjectPath }));
    } catch {
      /* a warning about configuration never fails the scan */
    }
  }

  // Cache check. Only a run whose every scanner ran is served again: one
  // with a scanner missing or failed is `completed` at coverage none or
  // partial, and its own warning tells the caller to install the scanner and
  // re-run. That re-run, inside the window, used to get the same gap back —
  // after `install_toolchain` had already made the scanner visible.
  const ttl = config.cacheTtlMs ?? FIVE_MINUTES_MS;
  const fresh = new Date(Date.now() - ttl).toISOString();
  if (input.force !== true) {
    const cached = plugin.storage.scans.findCacheHit({
      cache_key: cacheKey,
      freshThreshold: fresh,
    });
    // A scope that held nothing to scan is coverage none, whatever its
    // bookkeeping (every scanner merely `skipped`) computes to.
    if (
      cached &&
      computeCoverage(cached.tools_run, cached.missing_tools) === 'full' &&
      !scannedNothing(cached.meta?.['scope'])
    ) {
      return cachedResult(config, input, plugin, cached.scan_id, warnings);
    }
  }

  // Insert running scan. A child of an orchestrator records its parent from
  // the start, so even a row that later fails or is reaped says whose it was.
  const scanId = randomUUID();
  const parentScanId = callMeta?.parentScanId;
  // A scoped row says so from the start: a run that fails or is reaped is
  // still never mistaken for a whole-project scan.
  const insertMeta: Record<string, unknown> = {
    ...(parentScanId !== undefined ? { parent_scan_id: parentScanId } : {}),
    ...(scope !== null ? { scope: scope.meta } : {}),
  };
  const inserted = plugin.storage.scans.insert({
    scan_id: scanId,
    scan_type: config.scan_type,
    project_path: projectPath,
    tree_hash: treeHash,
    cache_key: cacheKey,
    ...(Object.keys(insertMeta).length > 0 ? { meta: insertMeta } : {}),
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
  try {
    return await runScanBody({
      config,
      input,
      plugin,
      projectPath,
      treeHash,
      scanId,
      startedAt: inserted.started_at,
      warnings,
      signal: controller.signal,
      progress,
      childCallMeta: {
        signal: controller.signal,
        parentScanId: scanId,
        treeHash,
        ...(callMeta?.progressToken !== undefined ? { progressToken: callMeta.progressToken } : {}),
        ...(callMeta?.originProjectPath !== undefined ? { originProjectPath: callMeta.originProjectPath } : {}),
      },
      rulesProjectPath,
      scope,
      exclusions,
      ...(parentScanId !== undefined ? { parentScanId } : {}),
    });
  } finally {
    progress.dispose();
  }
}

/**
 * An unusable `project_path`. A FILE, for a tool that can scope, is answered
 * with the call to make instead — `scope.paths` — in `retry_with`.
 */
function invalidProjectPath<TInput extends ScanToolBaseInput>(
  config: ScanToolConfig<TInput>,
  e: InvalidProjectPathError,
): ToolResult<Record<string, unknown>> {
  if (e.reason === 'not_a_directory' && config.supportsScope === true) {
    const retry = suggestScopeForFile(e.path);
    return failDomain(
      'unsupported_target',
      `project_path ${e.path} is a file, and project_path must be a directory. To scan just that file, ` +
        `pass project_path "${retry.project_path}" with scope: { paths: ["${retry.scope.paths.join('", "')}"] }.`,
      retry,
    );
  }
  return failDomain('not_a_git_repo', e.message);
}

/** A run's own warnings (`ScannerInvocation.warnings`) as its row keeps them. */
function runWarnings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((w): w is string => typeof w === 'string') : [];
}

/** `meta.scope` of a scoped scan in which no scanner ran (see `nothingInScope`). */
function scannedNothing(scopeMeta: unknown): boolean {
  return typeof scopeMeta === 'object' && scopeMeta !== null && (scopeMeta as { nothing_in_scope?: unknown }).nothing_in_scope === true;
}

/** The warnings a scoped scan's response carries, from its `meta.scope`. */
function scopeWarnings(scopeMeta: unknown): string[] {
  if (typeof scopeMeta !== 'object' || scopeMeta === null) return [];
  const block = scopeMeta as Record<string, unknown>;
  const files = typeof block['files'] === 'number' ? block['files'] : 0;
  const outside = typeof block['findings_outside_scope'] === 'number' ? block['findings_outside_scope'] : 0;
  const ignored =
    typeof block['files_excluded_by_guardianignore'] === 'number' ? block['files_excluded_by_guardianignore'] : 0;
  const warnings = [
    `Scoped scan (${describeScope(block)}, ${files} file(s)): findings outside the scope are not reported` +
      `${outside > 0 ? ` (${outside} dropped)` : ''}. It is recorded as scoped — never a baseline, and never ` +
      "counted as the project's current findings.",
  ];
  // Keyed on what RAN (`nothing_in_scope`), never on the file count alone.
  if (scannedNothing(block)) {
    warnings.push(
      `The scope held nothing to scan${ignored > 0 ? ` once ${GUARDIAN_IGNORE_FILE} is applied` : ''} — no ` +
        'scanner ran, nothing was scanned, and 0 findings here says nothing about the project.',
    );
  }
  if (ignored > 0) {
    warnings.push(`${ignored} file(s) in the scope are excluded by ${GUARDIAN_IGNORE_FILE} and were not scanned.`);
  }
  return warnings;
}

function describeScope(block: Record<string, unknown>): string {
  const diff = block['diff'];
  if (block['kind'] === 'diff' && typeof diff === 'object' && diff !== null) {
    const d = diff as Record<string, unknown>;
    if (typeof d['base'] === 'string') return `diff ${d['base']}...${typeof d['head'] === 'string' ? d['head'] : 'HEAD'}`;
    return d['staged'] === true ? 'staged changes' : 'uncommitted changes';
  }
  if (block['kind'] === 'since' && typeof block['since'] === 'string') return `since ${block['since']}`;
  return 'paths';
}

interface ExclusionReport {
  file: string;
  patterns: number;
  excluded_files: number;
  findings_excluded: number;
}

function exclusionWarning(value: unknown): string | null {
  if (typeof value !== 'object' || value === null) return null;
  const r = value as Partial<ExclusionReport>;
  return (
    `${GUARDIAN_IGNORE_FILE} excluded ${r.excluded_files ?? 0} file(s) (${r.patterns ?? 0} pattern(s)) and ` +
    `${r.findings_excluded ?? 0} finding(s) from this scan.`
  );
}

/** The `.guardianignore` findings an orchestrator's children (`extras.child_scans`) dropped. */
function childFindingsExcluded(plugin: PluginContext, extras: Record<string, unknown> | undefined): number {
  const children = extras?.['child_scans'];
  if (!Array.isArray(children)) return 0;
  let total = 0;
  for (const child of children as unknown[]) {
    const id = typeof child === 'object' && child !== null ? (child as { scan_id?: unknown }).scan_id : undefined;
    if (typeof id !== 'string') continue;
    const report = plugin.storage.scans.getById(id)?.meta?.['exclusions'];
    const n = typeof report === 'object' && report !== null ? (report as { findings_excluded?: unknown }).findings_excluded : undefined;
    if (typeof n === 'number') total += n;
  }
  return total;
}

/**
 * The CVE rows a scan still supports once findings were filtered out: a CVE
 * found ONLY in an excluded (or out-of-scope) manifest must not reach the
 * `cves` table and `guardian://cves/active` either. A row is dropped only
 * when a dropped finding names it and no kept finding does — a CVE row whose
 * findings this cannot read the package of is left alone.
 */
function cvesStillFound(
  cves: readonly ParserCveInput[],
  kept: readonly Finding[],
  dropped: readonly Finding[],
): ParserCveInput[] {
  const keys = (list: readonly Finding[]): Set<string> => {
    const out = new Set<string>();
    for (const f of list) {
      const coords = dependencyCoordinates(f);
      if (coords !== null && f.rule_id !== undefined) out.add(`${f.rule_id}\0${coords.name}`);
    }
    return out;
  };
  const keptKeys = keys(kept);
  const droppedKeys = keys(dropped);
  return cves.filter((c) => {
    const key = `${c.cve_id}\0${c.package_name}`;
    return keptKeys.has(key) || !droppedKeys.has(key);
  });
}

/** Everything after the scan row exists: run, persist, finalize, respond. */
async function runScanBody<TInput extends ScanToolBaseInput>(args: {
  config: ScanToolConfig<TInput>;
  input: TInput;
  plugin: PluginContext;
  projectPath: string;
  treeHash: string;
  scanId: string;
  startedAt: string;
  warnings: string[];
  signal: AbortSignal;
  progress: ProgressEmitter;
  childCallMeta: ToolCallMeta;
  rulesProjectPath: string;
  scope: ResolvedScope | null;
  exclusions: ProjectExclusions | null;
  /** Set when an orchestrator runs this scan as one of its children. */
  parentScanId?: string;
}): Promise<ToolResult<Record<string, unknown>>> {
  const { config, input, plugin, projectPath, treeHash, scanId, startedAt, warnings, progress } =
    args;

  // Boundary events, each with a higher step than the last; the emitter
  // heartbeats in between (every 10 s) for as long as the scanner runs, with
  // the scanner's latest stderr line in its message — see `onLog` below.
  let step = 0;
  const report = (message: string): void => {
    step += 1;
    progress.emit({ step, message: `${config.name}: ${message}` });
  };

  const ctx: InvokeContext = {
    plugin,
    scanId,
    projectPath,
    signal: args.signal,
    progress,
    // Every runner forwards stderr here line by line. A line becomes the
    // message of the next heartbeat, never a notification of its own: a
    // chatty scanner would otherwise send hundreds per second.
    onLog: (line: string) => {
      const trimmed = line.trim();
      if (trimmed.length === 0) return;
      const clipped =
        trimmed.length > MAX_LOG_LINE ? `${trimmed.slice(0, MAX_LOG_LINE - 1)}…` : trimmed;
      progress.note(`${config.name}: ${clipped}`);
    },
    scriptEnv: {
      ...process.env,
      PROJECT_PATH: projectPath,
      GUARDIAN_SCAN_ID: scanId,
    },
    childCallMeta: args.childCallMeta,
    rulesProjectPath: args.rulesProjectPath,
    scope: args.scope,
    exclusions: args.exclusions,
  };

  // Acquire a slot from the global concurrency limiter so 50 parallel
  // calls from the host don't fork 50 scanner processes. Default cap is 2.
  // An orchestrator takes none — see `ScanToolConfig.orchestrator`.
  const limiter = config.orchestrator === true ? null : getScanLimiter();
  if (limiter) {
    report('waiting for a scanner slot');
    await limiter.acquire();
  }
  let invocation: ScannerInvocation;
  try {
    report(`scanning ${projectPath}`);
    invocation = await config.invoke(input, ctx);
  } catch (e) {
    plugin.storage.scans.finalize({
      scan_id: scanId,
      status: 'failed',
      tools_run: [],
      missing_tools: [],
      error: e instanceof Error ? e.message : String(e),
    });
    return failDomain(
      'scanner_failed',
      e instanceof Error ? e.message : 'Scanner failed with an unknown error',
    );
  } finally {
    limiter?.release();
  }
  report('recording results');

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

  // `.guardianignore`, then the scope: what either leaves out is not this
  // scan's result and is never stored — only counted, in the response and
  // in `meta`. A finding with no path cannot be placed, and is kept.
  // Unlike `severity_min`, these are properties of the SCAN (what the
  // project declared, what the caller asked to scan), not of one response.
  const placed = (f: Finding): string | null =>
    f.file_path === undefined || f.file_path === '' ? null : f.file_path;
  const { exclusions, scope } = args;
  const dropped: Finding[] = [];
  const keepIf = (test: (path: string) => boolean): number => {
    const before = findings.length;
    findings = findings.filter((f) => {
      const p = placed(f);
      if (p === null || test(p)) return true;
      dropped.push(f);
      return false;
    });
    return before - findings.length;
  };
  // Only paths IN the project: an image target that happens to match a
  // pattern is not a file the project declared (`isProjectPath`).
  const findingsExcluded =
    exclusions === null ? 0 : keepIf((p) => !(isProjectPath(projectPath, p) && exclusions.ignores(p)));
  const outsideScope = scope === null ? 0 : keepIf((p) => scope.member(p));
  if (dropped.length > 0 && cves.length > 0) {
    const still = cvesStillFound(cves, findings, dropped);
    cves.length = 0;
    cves.push(...still);
  }

  // Line-independent identity, over the scan's whole, final finding set —
  // the occurrence it carries is counted across that set, so this runs once,
  // after the dedupe and before anything persists. Source lines are read from
  // the project on disk (Semgrep without login reports "requires login" in
  // place of the text) and only ever hashed: nothing read here is stored or
  // returned, which is what keeps a secret finding's line out of the database.
  findings = assignIdentities(findings, {
    projectPath,
    readSource: makeSourceReader(projectPath),
  });

  // Persist findings + CVEs (best-effort; one transaction per repo).
  //
  // ---- Why the severity floor is NOT applied before this ---------------
  //
  // It used to be, and the filtered findings were therefore never written.
  // A caller passing `severity_min: 'high'` did not merely fail to SEE the
  // medium findings: they did not exist in the history. So a `set_baseline`
  // captured from that scan silently omitted them, `diff_scans` compared
  // against data that was never recorded, the next UNFILTERED scan reported
  // them as `new` — the opposite of true, they had been there all along —
  // and the trend showed an improvement that never happened.
  //
  // `cves` on the very next line was already upserted unfiltered, so the two
  // halves of a `deps` scan disagreed with each other about the same
  // vulnerability: a medium CVE below the floor kept its `cves` row (and its
  // place in `guardian://cves/active`) while its Finding was dropped.
  //
  // The floor is a property of the REQUEST. History records the TREE. The
  // filtering now happens once, below, on the response only. The same holds
  // for a tool's `responseView` (bug_hunt's `categories`, which used to
  // filter inside the parser and so never stored what it dropped).
  if (findings.length > 0) {
    plugin.storage.findings.bulkInsert(
      findings.map((f) => ({ ...f, scan_id: scanId })),
    );
    // A suppression that predates identities follows its finding from now on.
    plugin.storage.suppressions.adoptIdentities(scanId);
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
  // can read them without forcing a re-run, and so a cache hit can re-emit
  // them (`cachedResult`).
  //
  // `severity_min` rides along in the same object. Now that the floor no
  // longer touches what is stored, a later reader of this scan row needs it
  // to answer a question the findings alone cannot: "this scan found nothing
  // above high" and "this scan was FILTERED at high" produce the same reply
  // count and are otherwise indistinguishable. It goes in `meta` — the
  // existing `TEXT NOT NULL DEFAULT '{}'` JSON column from schema v1 — and
  // not a new column: every reader of `meta` (riskScore, sbomDiff,
  // licenseCompatibility, the dotnet/wp resources, the dashboard snapshot)
  // picks named keys out of it, so an extra key is inert for all of them and
  // no migration is needed. No tool puts `severity_min` in `extras`, so
  // there is nothing to collide with. It is listed in FACTORY_META_KEYS, which
  // is what keeps a cache hit from re-emitting it as an extra.
  const meta: Record<string, unknown> = { ...(invocation.extras ?? {}) };
  if (input.severity_min !== undefined) meta['severity_min'] = input.severity_min;
  // `finalize` replaces the whole blob, so the parent written at insert time
  // has to be written again — and so does the scope.
  if (args.parentScanId !== undefined) meta['parent_scan_id'] = args.parentScanId;
  // A scope in which no scanner ran — every one `skipped` because the scope
  // held nothing for it, none missing or failed — computes to coverage
  // `full` from its bookkeeping. It measured nothing (Global Constraint 3):
  // it is coverage `none` and `nothing_in_scope`, decided by what RAN, not by
  // the file count — a commit range whose files are all deleted still had its
  // history read.
  const nothingInScope =
    scope !== null &&
    !invocation.tools_run.some((t) => t.status === 'ok') &&
    computeCoverage(invocation.tools_run, invocation.missing_tools) === 'full';
  const scopeMeta =
    scope !== null
      ? { ...scope.meta, findings_outside_scope: outsideScope, ...(nothingInScope ? { nothing_in_scope: true } : {}) }
      : null;
  if (scopeMeta !== null) meta['scope'] = scopeMeta;
  // An orchestrator's findings are its children's, already filtered there:
  // what it excluded is what they did.
  const excludedHere =
    config.orchestrator === true ? findingsExcluded + childFindingsExcluded(plugin, invocation.extras) : findingsExcluded;
  const exclusionReport: ExclusionReport | null =
    exclusions !== null
      ? {
          file: GUARDIAN_IGNORE_FILE,
          patterns: exclusions.patterns,
          excluded_files: exclusions.excludedFileCount,
          findings_excluded: excludedHere,
        }
      : null;
  if (exclusionReport !== null) meta['exclusions'] = exclusionReport;
  if (invocation.warnings !== undefined && invocation.warnings.length > 0) meta['run_warnings'] = invocation.warnings;
  if (Object.keys(meta).length > 0) finalize.meta = meta;
  const finishedAt = plugin.storage.scans.finalize(finalize);

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

  // Build the ScanResult response. THIS is where the response-only filters
  // land: the tool's own view first, then the severity floor, on the view.
  const view = applyResponseView(config, input, findings, scanId);
  const visible = filterFindings(view.visible, input.severity_min);
  const counts = countBySeverity(visible);
  const top = topFindings(visible, 10);
  const floor = severityFloorNotice(view.visible, input.severity_min, scanId);
  warnings.push(...scopeWarnings(scopeMeta));
  const excludedNote = exclusionWarning(exclusionReport);
  if (excludedNote !== null) warnings.push(excludedNote);
  warnings.push(...(invocation.warnings ?? []));
  if (view.warning) warnings.push(view.warning);
  if (floor?.warning) warnings.push(floor.warning);

  // Coverage: did the scanners that were supposed to run actually run? A
  // "0 findings" result is only trustworthy at coverage 'full'. When a primary
  // scanner was missing/failed we push a loud warning so the count is never
  // mistaken for a clean bill of health.
  const assessed = assessCoverage(config.scan_type, invocation.tools_run, invocation.missing_tools);
  // See `nothingInScope` above: the bookkeeping says `full`, the scan measured nothing.
  const coverage: ScanCoverage = nothingInScope ? 'none' : assessed.coverage;
  const coverageWarning = nothingInScope
    ? `⚠️ ${config.scan_type}: coverage none — no scanner ran on this scope, so its "0 findings" is not a clean result.`
    : assessed.warning;
  if (coverageWarning) warnings.unshift(coverageWarning);

  // The row's own times: `started_at` as `insert` wrote it, `finished_at` as
  // `finalize` wrote it. Both used to be `new Date()` taken here, twice, a
  // microsecond apart — every scan reported that it took no time at all.
  const result: ScanResult = {
    scan_id: scanId,
    scan_type: config.scan_type,
    project_path: projectPath,
    tree_hash: treeHash,
    started_at: startedAt,
    finished_at: finishedAt,
    duration_ms: durationMs(startedAt, finishedAt),
    status,
    tools_run: invocation.tools_run,
    missing_tools: invocation.missing_tools,
    report_paths: invocation.report_paths,
    findings_count_by_severity: counts,
    top_findings: top,
    warnings,
    coverage,
    ...(floor ? { severity_filter: floor.disclosure } : {}),
  };

  report('done');
  const payload: Record<string, unknown> = {
    ...(result as unknown as Record<string, unknown>),
    ...view.disclosure,
    ...(invocation.extras ?? {}),
    ...(scopeMeta !== null ? { scope: scopeMeta } : {}),
    ...(nothingInScope ? { nothing_in_scope: true } : {}),
    ...(exclusionReport !== null ? { exclusions: exclusionReport } : {}),
  };
  return { ok: true, ...payload };
}

/**
 * The cache key for this call — see the module comment for what it covers
 * and why. A `rulePacks` that throws leaves the call uncacheable (a key no
 * other call can produce) rather than failing the scan.
 */
function buildCacheKey<TInput extends ScanToolBaseInput>(
  config: ScanToolConfig<TInput>,
  input: TInput,
  packCtx: RulePackContext,
  treeHash: string,
  /** `config.cacheState`'s answer; empty leaves the key exactly as before it existed. */
  cacheState: Record<string, string>,
): string {
  const { projectPath } = packCtx;
  let rulePacksHash: string;
  try {
    rulePacksHash = hashRulePacks(config.rulePacks ? config.rulePacks(input, packCtx) : []);
  } catch {
    rulePacksHash = `uncacheable:${randomUUID()}`;
  }
  const keyed = normaliseInput(config, input);
  // `__`-prefixed: no schema field is spelt that way, so it cannot collide.
  if (Object.keys(cacheState).length > 0) keyed['__cache_state'] = cacheState;
  return scanCacheKey({
    projectPath,
    tool: config.name,
    scanType: config.scan_type,
    treeHash,
    inputHash: hashInput(keyed),
    pluginVersion: resolveVersion(),
    rulePacksHash,
  });
}

/**
 * The input as the tool's schema reads it — defaults applied, unknown keys
 * dropped — minus the fields that never enter the key. Falls back to the raw
 * input when it does not parse (an in-process caller the MCP layer never
 * validated); `undefined` members are dropped either way.
 */
function normaliseInput<TInput extends ScanToolBaseInput>(
  config: ScanToolConfig<TInput>,
  input: TInput,
): Record<string, unknown> {
  const parsed = z.object(config.inputSchema).safeParse(input);
  const source: Record<string, unknown> = parsed.success
    ? (parsed.data as Record<string, unknown>)
    : { ...(input as Record<string, unknown>) };
  const excluded = new Set([...KEYLESS_INPUTS, ...(config.responseOnlyInputs ?? [])]);
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(source)) {
    if (excluded.has(key) || value === undefined) continue;
    out[key] = value;
  }
  return out;
}

/** The tool's `responseView`, or the identity view when it has none. */
function applyResponseView<TInput extends ScanToolBaseInput>(
  config: ScanToolConfig<TInput>,
  input: TInput,
  findings: readonly Finding[],
  scanId: string,
): ResponseView {
  const view = config.responseView?.(input, findings, scanId) ?? null;
  return view ?? { visible: [...findings], disclosure: {}, warning: null };
}

/** `finished - started` in ms, or null when either is missing or unparseable. */
function durationMs(startedAt: string, finishedAt: string | null): number | null {
  if (finishedAt === null) return null;
  const ms = Date.parse(finishedAt) - Date.parse(startedAt);
  return Number.isFinite(ms) ? ms : null;
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

/**
 * A cache hit, shaped exactly like a fresh run of the same call.
 *
 * `severityMin` is THIS call's floor, not the cached scan's: the stored
 * findings are the whole tree (see the persistence comment above), so the
 * view is re-derived per caller. Without that, a cache hit ignored the floor
 * the caller had just passed and answered with everything.
 *
 * The same goes for the tool's `responseView` (bug_hunt's `categories`),
 * which is why such a field is response-only and out of the cache key.
 *
 * The run's `extras` come back too: they are persisted in `meta`, and every
 * meta key the factory did not write itself (FACTORY_META_KEYS) is one. A hit
 * used to drop them, so `deps_audit` lost `bot_configured`, `compliance_check`
 * its `policy_documents_found`, `scan_wordpress` its
 * `wordpress_layout_detected` — on every call inside the cache window. The
 * raw `meta` blob itself is not part of a result: a fresh run never has one.
 *
 * `started_at`, `finished_at` and `duration_ms` are the ORIGINAL run's, which
 * is what produced these findings; `cached_from` says so. Only a run at
 * coverage `full` gets here (see the lookup); coverage is still re-derived
 * below rather than assumed, so the two can never drift apart silently.
 *
 * One case it cannot repair: a scan row written by a version of this file
 * that filtered before persisting holds only the above-floor subset, and
 * nothing here can tell that apart from a tree with nothing else in it.
 * Those rows have no cache key (migration 006), so they are never served
 * from the cache; they persist in history.
 */
function cachedResult<TInput extends ScanToolBaseInput>(
  config: ScanToolConfig<TInput>,
  input: TInput,
  plugin: PluginContext,
  scanId: string,
  warnings: string[],
): ToolResult<Record<string, unknown>> {
  const record = plugin.storage.scans.getById(scanId);
  if (!record) {
    return failDomain('unknown_scan_id', `Cached scan ${scanId} could not be loaded.`);
  }
  const stored = plugin.storage.findings.listByScan(scanId);
  const view = applyResponseView(config, input, stored, scanId);
  const visible = filterFindings(view.visible, input.severity_min);
  const counts = countBySeverity(visible);
  const top = topFindings(visible, 10);
  const floor = severityFloorNotice(view.visible, input.severity_min, scanId);

  // Re-derive coverage from the persisted tools_run/missing_tools so a cached
  // scan carries the same honest signal as a fresh one.
  const { coverage, warning: coverageWarning } = assessCoverage(
    record.scan_type,
    record.tools_run,
    record.missing_tools,
  );
  const allWarnings = coverageWarning ? [coverageWarning, ...warnings] : [...warnings];
  const { meta, ...row } = record;
  // The scope and the exclusions were written by the run that produced these
  // findings; they come back below as extras, and their warnings with them.
  allWarnings.push(...scopeWarnings(meta?.['scope']));
  const excludedNote = exclusionWarning(meta?.['exclusions']);
  if (excludedNote !== null) allWarnings.push(excludedNote);
  allWarnings.push(...runWarnings(meta?.['run_warnings']));
  if (view.warning) allWarnings.push(view.warning);
  if (floor?.warning) allWarnings.push(floor.warning);

  const extras: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(meta ?? {})) {
    if (!FACTORY_META_KEYS.has(key)) extras[key] = value;
  }

  const result: ScanResult = {
    ...row,
    duration_ms: durationMs(record.started_at, record.finished_at),
    cached: true,
    cached_from: scanId,
    findings_count_by_severity: counts,
    top_findings: top,
    warnings: allWarnings,
    coverage,
    ...(floor ? { severity_filter: floor.disclosure } : {}),
  };
  return {
    ok: true,
    ...(result as unknown as Record<string, unknown>),
    ...view.disclosure,
    ...extras,
  };
}

/**
 * The `severity_filter` block for a response, plus the warning that goes
 * with it — or `null` when no floor was passed and there is nothing to say.
 *
 * `warning` is null when the floor withheld nothing: a caller who passes
 * `severity_min: 'high'` against a project with only criticals should not be
 * told anything happened, because nothing did.
 *
 * `all` must be the UNFILTERED findings of the scan; the whole point is to
 * describe the gap between those and what the response carries.
 */
function severityFloorNotice(
  all: readonly Finding[],
  min: Severity | undefined,
  scanId: string,
): { disclosure: SeverityFilterDisclosure; warning: string | null } | null {
  if (min === undefined) return null;
  const shortfall = severityShortfall(all, min);
  const disclosure: SeverityFilterDisclosure = {
    severity_min: min,
    withheld: shortfall.total,
    withheld_by_severity: shortfall.by_severity,
    suggested_severity_min: shortfall.suggested_severity_min,
    recovered_by_suggestion: shortfall.recovered_by_suggestion,
  };
  if (shortfall.total === 0) return { disclosure, warning: null };

  const suggestion =
    shortfall.suggested_severity_min === null
      ? ''
      : ` Pass severity_min "${shortfall.suggested_severity_min}" to see ` +
        `${shortfall.recovered_by_suggestion} of them.`;
  return {
    disclosure,
    warning:
      `severity_min "${min}" filtered this response only: ${shortfall.total} finding(s) ` +
      `(${describeShortfallTiers(shortfall)}) are recorded in scan ${scanId} and are not ` +
      `shown here. Baselines and diffs against this scan include them.${suggestion}`,
  };
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
