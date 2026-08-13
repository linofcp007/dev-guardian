/**
 * `map_attack_surface` — static inventory of what the application exposes.
 *
 * Standalone (no scan-tool factory): the output is structured metadata, not
 * Findings, and it must not create a row in `scans`. Same shape as
 * `detect_stack`.
 *
 * Failure policy: if Semgrep cannot run — natively or via Docker — NOTHING
 * is persisted. A zero-route snapshot written by a failed run would later be
 * read by scan_dast and risk_score as "this application exposes nothing" —
 * the inverse of the truth. "Zero because the scan failed" and "zero because
 * there are none" must stay distinguishable. The same guarantee extends to a
 * Semgrep run that "succeeded" but produced no readable/parseable JSON: we
 * never let a parse exception escape uncaught (there is no try/catch at the
 * MCP dispatch site), and we never treat garbage output as zero routes.
 *
 * The one case where a non-zero Semgrep exit DOES get persisted: Semgrep
 * exits 1 when it *finds* matches (see `buildToolRun` in `surface/scanSemgrep.ts`) — that is
 * success, not failure. A genuine failure (crash, bad config, timeout) still
 * blocks persistence only when it also failed to leave parseable JSON behind;
 * if it left partial-but-parseable JSON, that partial data is persisted with
 * a `failed` tools_run entry carrying the diagnostic.
 *
 * The same guarantee covers a fourth failure mode: Semgrep reporting matches
 * whose content we cannot read. Current versions redact `extra.metavars`
 * unless the user has run `semgrep login`, so the captures are rebuilt from
 * the matched byte range (see `surface/recoverMetavars.ts`). If Semgrep
 * reported matches and not one could be recovered, that is a broken
 * toolchain, not a project without routes — nothing is persisted.
 */

import { readFileSync } from 'node:fs';
import { isAbsolute, join, resolve } from 'node:path';
import { z } from 'zod';
import type { PluginContext } from '../context.js';
import { resolveProjectPath } from '../platform/projectPath.js';
import { Force, ProjectPath } from '../schemas.js';
import { collectEnvVars } from '../surface/collectors/envVars.js';
import { collectPorts } from '../surface/collectors/ports.js';
import { extractSurface, languageFromPath } from '../surface/extract.js';
import {
  extractModuleEdges,
  resolveModuleEdges,
  type ModuleEdge,
} from '../surface/moduleEdges.js';
import {
  recoverMetavars,
  type RecoveryOutcome,
  type SourceMap,
} from '../surface/recoverMetavars.js';
import { resolveNodeMounts, type ImportRecord } from '../surface/resolvers/node.js';
import { resolveWordpressRoutes } from '../surface/resolvers/wordpress.js';
import { invokeSemgrep } from '../surface/scanSemgrep.js';
import {
  dedupeResolved,
  discoverSpecs,
  MAX_SPEC_BYTES,
  MAX_SPEC_FILES,
} from '../surface/specDiscover.js';
import { diffSpecRoutes } from '../surface/specDiff.js';
import { importSpec } from '../surface/specImport.js';
import { toRelativeIfPossible } from '../runners/scannerParsers/index.js';
import { computeTreeHash } from '../treeHash/computeTreeHash.js';
import type {
  AttackSurfaceSnapshot,
  CoverageEntry,
  RouteRecord,
  SpecDiff,
  SpecFileReport,
  ToolResult,
  ToolRun,
} from '../types.js';
import { registerToolModule, type ToolModule } from './index.js';
import { ensureReportDir, readJsonSafe } from './scanHelpers.js';

const SAMPLE_SIZE = 20;
const WEBHOOK_PATTERN = /webhook|callback|hook/i;

/** Languages the rule pack covers, for honest `no_rules` reporting. */
const COVERED_LANGUAGES = new Set([
  'javascript', 'typescript', 'python', 'php', 'go', 'rust', 'ruby', 'java', 'csharp',
]);

const IncludeEnvVars = z
  .boolean()
  .optional()
  .default(true)
  .describe('Collect environment-variable names the code reads. Default: true.');

const SpecPaths = z
  // `.min(1)` on the array itself, not just on each element: an empty array
  // is "explicit was supplied" to this tool's own cache-bypass and
  // no-persist gates (both test `spec_paths !== undefined`), but
  // `discoverSpecs` treats an empty array as "nothing explicit" and falls
  // back to auto-discovery (`explicit && explicit.length > 0`). Left
  // unconstrained, `spec_paths: []` would silently produce an
  // auto-discovered result that is never cached and never persisted —
  // contradicting this field's own "replaces automatic discovery entirely"
  // description below, and leaving `snapshot_id: null` ambiguous between a
  // degraded run and a successful-but-unpersisted one. Rejecting `[]`
  // outright closes both at the one place every caller passes through.
  .array(z.string().min(1))
  .min(1)
  .optional()
  .describe(
    'Explicit OpenAPI/Swagger document paths. Replaces automatic discovery entirely when ' +
      'supplied — must be non-empty; omit the field to use automatic discovery instead. ' +
      'Relative paths resolve against project_path, not the current working ' +
      'directory. Bypasses the tree-hash cache (always computes a fresh snapshot) and is ' +
      'never persisted as the project\'s cached surface, so a later plain call cannot ' +
      'inherit these paths. Any named path that cannot be read is reported in spec_files, ' +
      'not silently dropped.',
  );

const tool: ToolModule = {
  name: 'map_attack_surface',
  title: 'Map the application attack surface',
  // No "auth hint" in this description on purpose, for code-extracted routes:
  // `auth_hint` exists on every RouteRecord, but no Semgrep rule populates it
  // for a route extracted from source, so it is always 'unknown' there (see
  // normalizeAuth in surface/extract.ts). Spec-imported routes are the one
  // real source: an operation's (or document's) `security` declaration
  // yields 'none' (an affirmative "this route is public") or 'required' (see
  // authHint in surface/specImport.ts). That is a property of spec import
  // specifically, not something this tool can promise in general — a
  // project with no importable spec still gets 'unknown' on every route —
  // so the description below still does not advertise "auth hint" as a
  // general feature. Advertising a mostly-constant field as a feature is how
  // an agent ends up reasoning from it.
  description:
    'Statically extract the externally reachable surface of the project — HTTP routes ' +
    '(method, path, params), referenced environment variables, and declared ' +
    'container ports — across all supported stacks. Also discovers OpenAPI 3.x / ' +
    'Swagger 2.0 documents (or reads exactly the paths given as spec_paths) and diffs ' +
    'them against the code-extracted routes, reporting shadow endpoints (routes the code ' +
    'registers that no spec documents) and dead documentation (spec paths no code ' +
    'implements). Persists a snapshot readable via guardian://surface/latest. Returns a ' +
    'summary plus a 20-route code sample and a spec sample; read the resource for the ' +
    'full route list and the full spec diff. Follow up with scan_dast to actively probe an ' +
    'already-running instance of the application against this inventory.',
  inputSchema: {
    project_path: ProjectPath,
    force: Force,
    include_env_vars: IncludeEnvVars,
    spec_paths: SpecPaths,
  },
  handler: async (input, ctx) => handler(input, ctx),
};

registerToolModule(tool);

async function handler(
  input: Record<string, unknown>,
  ctx: PluginContext,
): Promise<ToolResult<Record<string, unknown>>> {
  const inp = input as {
    project_path?: string;
    force?: boolean;
    include_env_vars?: boolean;
    spec_paths?: string[];
  };

  let projectPath: string;
  try {
    projectPath = resolveProjectPath(inp.project_path).path;
  } catch (e) {
    // `not_a_git_repo` is what detect_stack returns for an unusable
    // project_path (detectStack.ts:45-49), even though resolveProjectPath
    // actually rejects missing / non-directory / root-or-home paths. Keeping
    // the same code here means hosts and skills handle one failure, not two.
    // Do not "fix" this in isolation — it would desync the two tools.
    return { ok: false, error: { code: 'not_a_git_repo', message: (e as Error).message } };
  }

  const treeHash = await computeTreeHash(projectPath);

  // The cache key is the project's tree hash, which says nothing about which
  // document an explicit `spec_paths` argument names — an out-of-tree spec
  // path in particular can change without the tree hash moving at all.
  // Serving a cached snapshot in that case would silently diff against the
  // wrong document (or the auto-discovered one) and misattribute shadow
  // endpoints / dead documentation. So `spec_paths` bypasses the cache read
  // exactly like `force` does. (`include_env_vars` has an analogous,
  // narrower gap — a cache hit can return env_vars collected under a
  // different value of that flag — but that only omits data, never
  // misattributes a finding, so it is left as-is here.)
  if (inp.force !== true && inp.spec_paths === undefined) {
    const cached = ctx.storage.surface.getByTreeHash(treeHash);
    if (cached) {
      return summarize(cached.snapshot, cached.id, cachedToolsRun(cached.snapshot), ctx);
    }
  }

  const includeEnvVars = inp.include_env_vars !== false;
  const reportDir = ensureReportDir(projectPath, treeHash, 'surface');
  const outFile = join(reportDir, 'surface.json');
  const rulesPath = join(ctx.scriptsDir, '..', 'configs', 'semgrep', 'routes.yml');

  const invocation = await invokeSemgrep({ projectPath, rulesPath, outFile, reportDir });
  if (invocation === null) {
    return degradedResult(
      [
        {
          name: 'semgrep',
          status: 'skipped',
          reason: 'not_installed (no docker fallback available)',
        },
      ],
      ['semgrep'],
      'Semgrep is not installed and no Docker fallback is available, so no surface was ' +
        'mapped and nothing was persisted. Run install_toolchain, then retry.',
      ctx,
    );
  }

  const { toolRun } = invocation;

  // `readJsonSafe` returns null only for a missing/unreadable file (see
  // scanHelpers.ts) — never for unparseable content. A file that exists but
  // holds truncated/garbage JSON (mid-write timeout, stale partial file from
  // a previous crash) reaches the JSON.parse below, which is guarded
  // separately.
  const raw = readJsonSafe(outFile);
  if (raw === null) {
    const failedToolRun: ToolRun = {
      ...toolRun,
      status: 'failed',
      reason: toolRun.reason ?? 'no_output',
    };
    return degradedResult(
      [failedToolRun],
      [],
      'Semgrep produced no readable output file; nothing was persisted.',
      ctx,
    );
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    // Precedent: detectStack.ts:73-79 catches JSON.parse the same way and
    // returns a degraded result instead of letting the SyntaxError escape.
    // There is no try/catch at the tool-dispatch site (tools/index.ts), so
    // an uncaught throw here would surface as an opaque MCP protocol error
    // and bypass this tool's documented "persist nothing" contract entirely.
    const failedToolRun: ToolRun = {
      name: 'semgrep',
      status: 'failed',
      reason: `unparseable output: ${(e as Error).message}`,
    };
    return degradedResult(
      [failedToolRun],
      [],
      'Semgrep output was not valid JSON; nothing was persisted.',
      ctx,
    );
  }

  // Rebuild the captures modern Semgrep redacts, before anything downstream
  // looks for them. Reading the files is the impure half and belongs here;
  // `recoverMetavars` itself is pure and takes the text.
  const recovery = recoverMetavars(parsed, readSources(parsed, projectPath));
  if (recovery.intact === 0 && recovery.recovered === 0 && recovery.unrecoverable > 0) {
    return degradedResult(
      [toolRun, unreadableMatchesToolRun(recovery)],
      [],
      unreadableMatchesNote(recovery),
      ctx,
    );
  }

  const toolsRun = [toolRun, ...recoveryToolRun(recovery)];
  const snapshot = buildSnapshot(
    recovery.json,
    projectPath,
    ctx,
    toolsRun,
    includeEnvVars,
    recovery.unreadableRouteFiles,
    inp.spec_paths,
  );

  // An explicit `spec_paths` snapshot must never become "latest for this
  // tree hash": it answers the caller's one-off question about a document
  // THEY named, not a claim about what this project's own spec layout is. If
  // it were persisted, a later PLAIN call (no spec_paths) on the same
  // unchanged tree would read it back from the tree-hash cache and report
  // the explicitly-named document as if auto-discovery had found it —
  // exactly the "silently attributed to the wrong document" failure the
  // spec_paths-bypasses-cache-read fix above exists to prevent, just
  // triggered from the write side instead of the read side. Skipping the
  // insert closes it at the source: nothing is ever there to be inherited.
  if (inp.spec_paths !== undefined) {
    return summarize(snapshot, null, toolsRun, ctx);
  }

  const persisted = ctx.storage.surface.insert({
    project_path: projectPath,
    tree_hash: treeHash,
    snapshot,
  });

  return summarize(snapshot, persisted.id, toolsRun, ctx);
}

/** Name used for the recovery step in `tools_run`; it is not a real binary. */
const RECOVERY_STEP = 'semgrep-metavar-recovery';

/**
 * Source text of every file Semgrep reported a match in, keyed by the `path`
 * value verbatim so `recoverMetavars` can look it up without re-deriving it.
 *
 * Semgrep reports absolute paths when handed an absolute target (which this
 * tool does) and relative ones when handed a relative target, so both are
 * resolved. A file that cannot be read is simply absent from the map — the
 * recovery counts it `unrecoverable` rather than guessing.
 */
function readSources(parsed: unknown, projectPath: string): SourceMap {
  const sources = new Map<string, string>();
  for (const path of collectAllFiles(parsed)) {
    try {
      const buffer = readFileSync(isAbsolute(path) ? path : join(projectPath, path));
      const text = buffer.toString('utf8');
      // Offsets are byte offsets into the file as it sits on disk. Bytes that
      // are not valid UTF-8 decode to U+FFFD, which re-encodes to a different
      // length and shifts every later offset — so a file that does not
      // round-trip is dropped rather than sliced at the wrong place.
      if (Buffer.byteLength(text, 'utf8') !== buffer.length) continue;
      sources.set(path, text);
    } catch {
      // Unreadable / deleted since the scan: absent from the map, by design.
    }
  }
  return sources;
}

/**
 * Make a recovered run visible instead of silent — including the partial case,
 * where some routes are real and some matches were lost. Persisted with the
 * snapshot, so `cachedToolsRun` keeps reporting it on later cache hits.
 * Emitted only when there was something to recover: a run against an older
 * (or logged-in) Semgrep is `intact` throughout and says nothing new.
 */
/**
 * How to get the unreadable matches back. Named wherever a loss is reported,
 * because the fix is not obvious and the obvious guess — "this tool needs a
 * Semgrep account" — is wrong: all thirteen route families are rebuilt from
 * byte offsets and work on any version, logged in or not.
 *
 * A loss therefore no longer means "this rule family cannot be read". It means
 * the source could not be read at the offsets Semgrep reported — the file was
 * deleted or rewritten mid-scan, is not valid UTF-8, or the span carried no
 * capture. Logging in still fixes it, by making the captures arrive directly so
 * the file never has to be re-read; that is why the remedy is still named.
 */
const REDACTION_REMEDY =
  'this Semgrep version redacts match content unless you run `semgrep login`, so the ' +
  'captures are rebuilt by re-reading the source at the reported byte offsets, and that ' +
  'read failed for these matches. Either log in, or use a Semgrep older than ~1.100, and ' +
  'the captures arrive directly. dev-guardian does not require an account — every route ' +
  'family is rebuilt from byte offsets either way';

function recoveryToolRun(recovery: RecoveryOutcome): ToolRun[] {
  if (recovery.recovered === 0 && recovery.unrecoverable === 0) return [];
  const base =
    `recovered ${recovery.recovered} redacted match(es) from byte offsets` +
    (recovery.intact > 0 ? `; ${recovery.intact} already carried metavariables` : '');
  if (recovery.unrecoverable === 0) {
    return [{ name: RECOVERY_STEP, status: 'ok', reason: base }];
  }
  return [
    {
      name: RECOVERY_STEP,
      status: 'failed',
      reason:
        `${base}; ${recovery.unrecoverable} match(es) could not be read and are MISSING ` +
        `from the surface (see coverage[].unreadable_matches for which languages) — ` +
        `${REDACTION_REMEDY}`,
    },
  ];
}

function unreadableMatchesToolRun(recovery: RecoveryOutcome): ToolRun {
  return {
    name: RECOVERY_STEP,
    status: 'failed',
    reason:
      `no match content: all ${recovery.unrecoverable} match(es) lacked metavariables ` +
      'and none could be recovered from the reported byte offsets',
  };
}

function unreadableMatchesNote(recovery: RecoveryOutcome): string {
  return (
    `Semgrep reported ${recovery.unrecoverable} match(es) and not one could be read, so no ` +
    'surface was mapped and nothing was persisted — a zero-route snapshot here would read as ' +
    '"this application exposes nothing", the inverse of what was measured. Cause: ' +
    `${REDACTION_REMEDY}. Every match failing this way at once usually means the working ` +
    'tree changed under the scan, or the files are not valid UTF-8 — check that the project ' +
    'was not being written to while the scan ran, then re-run.'
  );
}

/**
 * What a cache hit reports as `tools_run`.
 *
 * The cache marker must not erase the run that produced the snapshot. There
 * is exactly one case where a failing run still persists — Semgrep exited
 * non-zero but left parseable JSON, persisted with a `failed` entry carrying
 * the diagnostic. Reporting a bare `{semgrep, skipped, cached}` on every
 * later call for the same tree hash would let that warning survive one call
 * and then vanish, so a snapshot that is empty *because the scan died* would
 * read as "this application exposes nothing" — verbatim the falsehood this
 * tool exists to prevent (see the module doc comment).
 */
function cachedToolsRun(snapshot: AttackSurfaceSnapshot): ToolRun[] {
  const marker: ToolRun = { name: 'semgrep', status: 'skipped', reason: 'cached' };
  const persisted = snapshot.tools_run.map((run) => ({
    ...run,
    reason:
      run.reason === undefined ? 'from the cached run' : `${run.reason} (from the cached run)`,
  }));
  return [marker, ...persisted];
}

function buildSnapshot(
  parsed: unknown,
  projectPath: string,
  ctx: PluginContext,
  toolsRun: ToolRun[],
  includeEnvVars: boolean,
  unreadableRouteFiles: readonly string[],
  specPaths: string[] | undefined,
): AttackSurfaceSnapshot {
  const { routes, mounts } = extractSurface(parsed);
  const knownFiles = collectAllFiles(parsed);
  const imports = extractImports(parsed, knownFiles);

  const resolved = resolveWordpressRoutes(resolveNodeMounts(routes, mounts, imports));

  // Task 3b: a second, WIDER extraction over the same `guardian_kind:
  // import` matches, feeding the validate_finding import graph rather than
  // mount resolution — see moduleEdges.ts's own doc comment for why this
  // does not reuse (and must not replace) extractImports/resolveModuleFile
  // above. `projectFiles` unions `paths.scanned` (every file Semgrep
  // actually scanned, matches or not — the closer reading of "the scanned
  // tree") with `knownFiles` (match-bearing files) as a belt-and-suspenders
  // measure: both are Semgrep's own report of this same run, so the union
  // can only add legitimate candidates, never fabricate one.
  //
  // RELATIVIZED BEFORE RESOLUTION, not after. Semgrep reports absolute,
  // native-separator paths for an absolute target (which this tool always
  // passes — see readSources' doc comment above), but an import specifier is
  // written relative to the project root: `resolvePython('app.helpers')` can
  // only ever produce the candidate `app/helpers.py`, and `resolveGo` can
  // only ever match a project-relative package directory. Handing those
  // resolvers an ABSOLUTE project-file set means their candidates match
  // nothing — silently, for Python, Go and Rust, on every platform — and
  // `validate_finding` then reports every file in those three languages as
  // imported by no route. Relativizing afterwards (where this used to
  // happen, on the resolver's OUTPUT) is far too late: there is nothing left
  // to relativize, because nothing resolved. Both sides move into the same
  // project-relative POSIX space here, which is the space `ModuleEdge.file`
  // documents, the one the unit tests exercise, and the one
  // `AttackSurfaceSnapshot.imports` promises its consumers.
  const moduleEdges = extractModuleEdges(resultsArrayOf(parsed)).map((edge) => ({
    ...edge,
    file: toRelativeIfPossible(edge.file, projectPath),
  }));
  const projectFiles = new Set<string>(
    [...scannedFiles(parsed), ...knownFiles].map((file) => toRelativeIfPossible(file, projectPath)),
  );
  const { resolved: resolvedEdges, unresolved: unresolvedEdges } = resolveModuleEdges(
    moduleEdges,
    projectFiles,
  );

  const { specRoutes, specFiles, specsParsed } = importSpecs(projectPath, specPaths);
  const specDiff = diffSpecRoutes(resolved, specRoutes, specsParsed);

  return {
    routes: [...resolved, ...specRoutes],
    env_vars: includeEnvVars ? collectEnvVars(parsed) : [],
    ports: collectPorts(projectPath),
    webhooks: resolved.filter((r) => WEBHOOK_PATTERN.test(r.path_resolved)),
    coverage: buildCoverage(resolved, ctx, unreadableRouteFiles, unresolvedEdges),
    tools_run: toolsRun,
    missing_tools: [],
    spec_files: specFiles,
    spec_diff: specDiff,
    // Already project-relative POSIX, both sides: the relativization happens
    // above, on the resolver's INPUT (see that comment). `module_file` is
    // returned verbatim from `projectFiles`, which was relativized in the
    // same expression as the edge's own `file`, so the two sides of an edge
    // cannot drift into different spaces. This matches
    // `Finding.file_path`'s established convention (toRelativeIfPossible,
    // used by every scan_sast parser — see runners/scannerParsers/index.ts),
    // which is the convention validate_finding's later cross-reference
    // against a finding's file needs and the one this field's own doc
    // comment in types.ts promises. RouteRecord.file/ImportRecord.file stay
    // absolute and native-separator — a separate, pre-existing mismatch that
    // `validate/staticProvider.ts` relativizes on its own side.
    imports: resolvedEdges,
  };
}

/**
 * Discover, import and report every OpenAPI/Swagger document for the
 * project. `specsParsed` counts reports whose status is `'ok'` or
 * `'no_paths'` — a valid document that declares nothing is still a
 * successfully parsed spec, and must not disable the diff the way "no spec
 * was found at all" does (see `diffSpecRoutes`'s doc comment).
 *
 * Discovery's own caps (`truncated`, `oversized`) are folded into
 * `specFiles` as `parse_error` reports rather than dropped, so a capped
 * result is visible in the same place a reader already looks instead of
 * silently reading as "there were only 20 documents".
 *
 * Explicit `specPaths` get two more guarantees discovery alone does not
 * provide: relative entries resolve against `projectPath` (every other path
 * in this tool's contract derives from `project_path`, so a relative
 * argument is the likely default of a calling agent — resolving it against
 * `process.cwd()` instead would silently read the wrong file or nothing at
 * all), and any named path `discoverSpecs` had to drop (missing, unreadable,
 * removed after discovery) is reported rather than vanishing. A caller that
 * *names* a document has made a claim this tool must be able to contradict —
 * "that document could not be read" must stay distinguishable from "this
 * project has no spec", the exact conflation the rest of this feature exists
 * to avoid. Auto-discovered candidates get no such treatment: nothing named
 * them, so one dropped during a directory walk is not a broken promise.
 */
function importSpecs(
  projectPath: string,
  specPaths: string[] | undefined,
): { specRoutes: RouteRecord[]; specFiles: SpecFileReport[]; specsParsed: number } {
  // Deduped HERE, not just inside `discoverSpecs`, so the "which named paths
  // were not read" accounting below applies the file cap to the same list
  // discovery did. See `dedupeResolved`'s doc comment for what slides
  // otherwise.
  const resolvedSpecPaths =
    specPaths === undefined
      ? undefined
      : dedupeResolved(specPaths.map((p) => resolveExplicitSpecPath(projectPath, p)));
  const discovery = discoverSpecs(projectPath, resolvedSpecPaths);

  const specRoutes: RouteRecord[] = [];
  const specFiles: SpecFileReport[] = [];
  let specsParsed = 0;

  for (const { file, text } of discovery.specs) {
    const { routes, report } = importSpec(file, text);
    specRoutes.push(...routes);
    specFiles.push(report);
    if (report.status === 'ok' || report.status === 'no_paths') specsParsed += 1;
  }

  if (discovery.truncated) {
    specFiles.push({
      file: '(spec discovery)',
      format: 'unknown',
      status: 'parse_error',
      routes_found: 0,
      reason:
        `More than ${MAX_SPEC_FILES} candidate spec documents were found; only the first ` +
        `${MAX_SPEC_FILES} were read.`,
      unresolved_refs: 0,
    });
  }

  for (const file of discovery.oversized) {
    specFiles.push({
      file,
      format: 'unknown',
      status: 'parse_error',
      routes_found: 0,
      reason: `File exceeds the ${MAX_SPEC_BYTES}-byte size cap and was not read.`,
      unresolved_refs: 0,
    });
  }

  if (resolvedSpecPaths !== undefined) {
    // Mirrors discoverSpecs' own file-count cap (candidates.slice(0,
    // MAX_SPEC_FILES)) so a path beyond the cap is not double-reported here
    // AND in the `truncated` block above. `resolvedSpecPaths` is already
    // deduped, so this window is byte-for-byte the one discovery selected.
    const attempted = resolvedSpecPaths.slice(0, MAX_SPEC_FILES);
    const accountedFor = new Set<string>([
      ...discovery.specs.map((s) => s.file),
      ...discovery.oversized,
    ]);
    for (const path of attempted) {
      if (accountedFor.has(path)) continue;
      specFiles.push({
        file: path,
        format: 'unknown',
        status: 'parse_error',
        routes_found: 0,
        reason: 'Explicit spec path could not be read (missing, not a file, or unreadable).',
        unresolved_refs: 0,
      });
    }
  }

  return { specRoutes, specFiles, specsParsed };
}

/**
 * Resolve one `spec_paths` entry against `projectPath` when it is relative.
 * An absolute path is used verbatim (modulo `resolve()`'s normalisation) —
 * it may legitimately point outside the project (a spec vendored elsewhere,
 * a shared team document).
 *
 * Always run through `resolve()`, not just `join()`, so a redundant `.`/`..`
 * segment inside an already-absolute input is canonicalised the same way
 * `discoverSpecs`' own dedupe canonicalises its candidates — the "not
 * accounted for" loop below compares this function's output against
 * `discoverSpecs`' output by plain string equality, so the two must agree on
 * one canonical spelling for the same file, or a deduped-away duplicate here
 * would misreport as "could not be read".
 */
function resolveExplicitSpecPath(projectPath: string, path: string): string {
  return resolve(isAbsolute(path) ? path : join(projectPath, path));
}

/** `parsed.results`, or `[]` when absent/malformed — shared by every reader
 *  below that only needs the match array, not the whole Semgrep JSON shape. */
function resultsArrayOf(parsed: unknown): unknown[] {
  const results = (parsed as { results?: unknown }).results;
  return Array.isArray(results) ? results : [];
}

/** Every file path Semgrep reported a match in, across all `guardian_kind`s. */
function collectAllFiles(parsed: unknown): Set<string> {
  const out = new Set<string>();
  for (const raw of resultsArrayOf(parsed)) {
    const path = (raw as { path?: unknown }).path;
    if (typeof path === 'string') out.add(path);
  }
  return out;
}

/**
 * Every file Semgrep actually scanned this run, matched or not — Semgrep's
 * own `paths.scanned` in its `--json` output (confirmed present on both
 * 1.86.0 and 1.164.0). Wider than `collectAllFiles`: a leaf file with an
 * import but no route/mount/env-var match of its own — exactly the kind of
 * file `validate_finding` cares about reaching — would never appear there,
 * only here. Same raw, native-separator convention as `results[].path`
 * (both come from the same Semgrep run), which is what lets
 * `moduleEdges.ts` compare them without any conversion of its own.
 */
function scannedFiles(parsed: unknown): Set<string> {
  const paths = (parsed as { paths?: unknown }).paths;
  const scanned = (paths as { scanned?: unknown } | undefined)?.scanned;
  const out = new Set<string>();
  if (!Array.isArray(scanned)) return out;
  for (const path of scanned) {
    if (typeof path === 'string') out.add(path);
  }
  return out;
}

/** `guardian_kind: 'import'` matches, needed by the Node mount resolver. */
function extractImports(parsed: unknown, knownFiles: Set<string>): ImportRecord[] {
  const results = (parsed as { results?: unknown }).results;
  if (!Array.isArray(results)) return [];

  const out: ImportRecord[] = [];
  for (const raw of results) {
    const record = raw as {
      path?: string;
      extra?: {
        metadata?: { guardian_kind?: string };
        metavars?: Record<string, { abstract_content?: string }>;
      };
    };
    if (record.extra?.metadata?.guardian_kind !== 'import') continue;
    // Semgrep's abstract_content keeps the source quoting (`'./routes/users'`,
    // not `./routes/users`) — same as $PATH/$PREFIX in extract.ts and $NAME
    // in envVars.ts. Without stripping it, `specifier.startsWith('.')` in
    // resolveModuleFile below never matches and mount resolution silently
    // never fires against real Semgrep output.
    const symbol = stripQuotes(record.extra.metavars?.['$SYMBOL']?.abstract_content);
    const modulePath = stripQuotes(record.extra.metavars?.['$MODULE']?.abstract_content);
    const file = record.path;
    if (symbol === undefined || modulePath === undefined || file === undefined) continue;
    out.push({ symbol, module_file: resolveModuleFile(file, modulePath, knownFiles), file });
  }
  return out;
}

function stripQuotes(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  return value.replace(/^['"`]|['"`]$/g, '');
}

function stripKnownExtension(path: string): string {
  return path.replace(/\.[cm]?[jt]sx?$/, '');
}

/**
 * Semgrep reports paths in the host's native separator: on Windows a match in
 * `node-express/routes/users.js` comes back as
 * `C:\project\node-express\routes\users.js`. An import specifier is always
 * POSIX-ish (`./routes/users.js`), so the two are only comparable once the
 * reported path is normalised. Without this, `resolveModuleFile` below split a
 * Windows path into a single segment, matched no known file, and every mounted
 * router silently degraded to `path_partial` — mount resolution was dead on
 * Windows while looking healthy everywhere else.
 */
function toPosixPath(path: string): string {
  return path.replace(/\\/g, '/');
}

/**
 * Turn a specifier like `./routes/users` (imported from `src/app.ts`) into
 * the project-relative file the route was actually matched in, e.g.
 * `src/routes/users.ts`.
 *
 * We do NOT guess a single extension: a plain-JS project imports
 * `./routes/users` and the real file is `.js`; a TypeScript project under
 * this repo's own NodeNext convention imports `./routes/users.js` and the
 * real source file is `.ts`. Neither case is knowable from the specifier
 * text alone, and we have no filesystem access here. Instead we compare,
 * extension-insensitively, against the file paths Semgrep actually reported
 * matches in during this same run (`knownFiles`) and take the one whose
 * extension-stripped path matches. When nothing matches, we return the
 * normalised specifier path as our best-effort guess rather than fabricate
 * an extension.
 *
 * The comparison is separator-insensitive, but the value returned on a hit is
 * the known file *verbatim*: it is later looked up against `RouteRecord.file`,
 * which carries Semgrep's spelling unchanged.
 */
function resolveModuleFile(importingFile: string, specifier: string, knownFiles: Set<string>): string {
  if (!specifier.startsWith('.')) return specifier;
  const posixImporting = toPosixPath(importingFile);
  // An absolute POSIX path's leading `/` is an empty first segment, and
  // dropping empty segments ate it: `/srv/app/src/app.js` + `./routes/users`
  // normalised to `src/routes/users`, which matches no known file on Linux,
  // macOS, or any Docker-Semgrep run (Semgrep reports absolute paths for the
  // absolute target this tool always passes). Node mount resolution then
  // silently fell back to the specifier text on every POSIX host.
  //
  // Absoluteness is read from the DIRECTORY, never from the joined string:
  // the join always contributes a separator, so a directory-less importing
  // file (`app.js`, whose directory is '') would look absolute and resolve
  // to `/routes/users` — matching nothing, and turning the root-level
  // `app.js` + `./routes/users.js` shape into an unresolved mount. That
  // requires keeping '' (no directory) distinct from '/' (the filesystem
  // root), which is why the fallback below is not simply ''.
  // `moduleEdges.ts`'s `joinAndNormalize`/`dirOf` pair, which this mirrors,
  // carries the same guard and the same reasoning.
  const parts = posixImporting.split('/');
  parts.pop();
  const dir = parts.join('/') === '' && posixImporting.startsWith('/') ? '/' : parts.join('/');
  const absolute = dir.startsWith('/');
  const stack: string[] = [];
  for (const part of `${dir}/${specifier}`.split('/')) {
    if (part === '.' || part === '') continue;
    if (part === '..') stack.pop();
    else stack.push(part);
  }
  const joined = `${absolute ? '/' : ''}${stack.join('/')}`;
  const base = stripKnownExtension(joined);

  for (const file of knownFiles) {
    if (stripKnownExtension(toPosixPath(file)) === base) return file;
  }
  return joined;
}

/**
 * Per-language coverage.
 *
 * `unreadable` exists so that a language whose routes Semgrep matched but we
 * could not read never reports `no_matches`. The two are opposite facts — "we
 * looked and there is nothing" versus "there is something and we could not read
 * it" — and collapsing them is the "this application exposes nothing" falsehood
 * this tool is built to avoid.
 *
 * No rule family is refused any more (surface/recoverMetavars.ts), so this is
 * now the genuinely-unreadable case only: source that changed under the scan,
 * is not valid UTF-8, or offsets that land past end-of-file. Rare, and still
 * not something to round down to zero.
 */
function buildCoverage(
  routes: RouteRecord[],
  ctx: PluginContext,
  unreadableRouteFiles: readonly string[],
  unresolvedEdges: readonly ModuleEdge[],
): CoverageEntry[] {
  // `coverage[]` is a per-language report about source code. Spec routes carry
  // `language: 'spec'`, which is not a language the rule pack could ever cover —
  // including them would create a phantom entry reading `status: 'no_rules'`,
  // literally true and completely meaningless.
  const codeRoutes = routes.filter((r) => r.provenance === 'code');
  const detected = ctx.storage.stack.getLatest()?.snapshot.languages ?? [];

  // One entry per lost route, so the count is routes-not-shown, not files.
  const unreadableByLanguage = new Map<string, number>();
  for (const file of unreadableRouteFiles) {
    const language = languageFromPath(file);
    if (language === 'unknown') continue;
    unreadableByLanguage.set(language, (unreadableByLanguage.get(language) ?? 0) + 1);
  }

  // One entry per import edge moduleEdges.ts could not resolve to a project
  // file — see CoverageEntry.unresolved_imports' doc comment in types.ts for
  // why this is reported rather than folded silently into the graph.
  const unresolvedByLanguage = new Map<string, number>();
  for (const edge of unresolvedEdges) {
    unresolvedByLanguage.set(edge.language, (unresolvedByLanguage.get(edge.language) ?? 0) + 1);
  }

  const languages = new Set<string>([
    ...detected,
    ...codeRoutes.map((r) => r.language),
    ...unreadableByLanguage.keys(),
    ...unresolvedByLanguage.keys(),
  ]);
  languages.delete('unknown');

  const entries: CoverageEntry[] = [];
  for (const language of [...languages].sort()) {
    const found = codeRoutes.filter((r) => r.language === language).length;
    const unreadable = unreadableByLanguage.get(language) ?? 0;
    const hasRules = COVERED_LANGUAGES.has(language);
    entries.push({
      language,
      detected: detected.includes(language),
      routes_found: found,
      unreadable_matches: unreadable,
      unresolved_imports: unresolvedByLanguage.get(language) ?? 0,
      // `unreadable` outranks `ok`: a language with some routes read and some
      // lost is not fully covered, and saying `ok` would hide the gap. Import
      // resolution is a separate dimension (see the field's own doc comment)
      // and deliberately does not affect this status.
      status: unreadable > 0 ? 'unreadable' : !hasRules ? 'no_rules' : found > 0 ? 'ok' : 'no_matches',
    });
  }
  return entries;
}

const NO_STACK_NOTE =
  'No stack snapshot found for this project — run detect_stack first for fuller coverage context.';

function summarize(
  snapshot: AttackSurfaceSnapshot,
  // `null` for an explicit-`spec_paths` run that was deliberately not
  // persisted (see the call site in `handler`) — there is no row to point
  // to, the same reason `degradedResult` uses `null` for "nothing written".
  snapshotId: number | null,
  toolsRun: ToolRun[],
  ctx: PluginContext,
): ToolResult<Record<string, unknown>> {
  // `by_language` is a report about source code, same reasoning as
  // `buildCoverage`'s `codeRoutes` filter above: spec routes all carry
  // `language: 'spec'`, which is not a language the rule pack could ever
  // report on. Including them would add a phantom `{ language: 'spec', ... }`
  // entry to a breakdown that otherwise only ever names real languages.
  const codeRoutes = snapshot.routes.filter((r) => r.provenance === 'code');

  const byLanguage = new Map<string, number>();
  for (const route of codeRoutes) {
    byLanguage.set(route.language, (byLanguage.get(route.language) ?? 0) + 1);
  }

  // `sample` is code routes only, same reasoning as `routes_total` right
  // below: it is the field a reading agent looks at first, and it must stay
  // consistent with that count. Sorting `snapshot.routes` (code + spec mixed)
  // by language first let spec routes — all `language: 'spec'` — evict every
  // code route from the 20 slots whenever the project's spec declared more
  // paths than the code had routes, and which language 'spec' happened to
  // sort next to (before 'typescript', after 'javascript'/'php'/'python')
  // made the eviction inconsistent across otherwise-identical projects. Spec
  // routes get their own sample below instead of competing for these slots.
  const sample = [...codeRoutes]
    .sort(
      (a, b) =>
        a.language.localeCompare(b.language) || a.path_resolved.localeCompare(b.path_resolved),
    )
    .slice(0, SAMPLE_SIZE);

  const specRoutesList = snapshot.routes.filter((r) => r.provenance === 'spec');
  const specSample = [...specRoutesList]
    .sort((a, b) => a.path_resolved.localeCompare(b.path_resolved))
    .slice(0, SAMPLE_SIZE);

  const stackDetected = ctx.storage.stack.getLatest() !== null;

  return {
    ok: true,
    // Code routes only — a consumer reading `routes_total` today must get the
    // same number tomorrow now that spec-declared routes share `routes[]`.
    // Spec routes are counted separately in `spec_routes_total`.
    routes_total: codeRoutes.length,
    by_language: [...byLanguage].map(([language, routes]) => ({ language, routes })),
    coverage: snapshot.coverage,
    snapshot_id: snapshotId,
    sample,
    env_vars_total: snapshot.env_vars.length,
    ports: snapshot.ports,
    webhooks_total: snapshot.webhooks.length,
    tools_run: toolsRun,
    missing_tools: snapshot.missing_tools,
    stack_detected: stackDetected,
    spec_routes_total: snapshot.routes.length - codeRoutes.length,
    spec_files: snapshot.spec_files,
    spec_sample: specSample,
    spec_diff_summary: specDiffSummary(snapshot.spec_diff),
    shadow_sample: shadowSample(snapshot.spec_diff),
    ...(stackDetected ? {} : { note: NO_STACK_NOTE }),
  };
}

/** Counts only — the full entry lists stay out of the tool result and are
 *  served by the surface resources, for the same reason the full route list
 *  already is. `null` mirrors `snapshot.spec_diff`: "no spec was found" must
 *  stay distinguishable from "the spec documents nothing". */
function specDiffSummary(diff: SpecDiff | null): Record<string, number> | null {
  if (diff === null) return null;
  return {
    matched: diff.matched.length,
    code_only: diff.code_only.length,
    spec_only: diff.spec_only.length,
    unmatchable: diff.unmatchable.length,
    code_only_withheld: diff.code_only_withheld,
    spec_only_withheld: diff.spec_only_withheld,
  };
}

/** First 20 shadow endpoints — code routes no spec documents — ordered
 *  deterministically the same way `sample` above is. */
function shadowSample(diff: SpecDiff | null): SpecDiff['code_only'] {
  if (diff === null) return [];
  return [...diff.code_only].sort((a, b) => a.path.localeCompare(b.path)).slice(0, SAMPLE_SIZE);
}

/**
 * Shared shape for every "Semgrep could not produce a usable result" exit —
 * unavailable, no output, unparseable output. All three must persist
 * nothing (see the module doc comment) and must return the same field set
 * as `summarize` so a consumer never sees `undefined` on the fields it reads
 * hardest (e.g. `webhooks_total`) just because this run happened to degrade.
 */
function degradedResult(
  toolsRun: ToolRun[],
  missingTools: string[],
  note: string,
  ctx: PluginContext,
): ToolResult<Record<string, unknown>> {
  return {
    ok: true,
    routes_total: 0,
    by_language: [],
    coverage: [],
    snapshot_id: null,
    sample: [],
    env_vars_total: 0,
    ports: [],
    webhooks_total: 0,
    tools_run: toolsRun,
    missing_tools: missingTools,
    stack_detected: ctx.storage.stack.getLatest() !== null,
    spec_routes_total: 0,
    spec_files: [],
    spec_sample: [],
    spec_diff_summary: null,
    shadow_sample: [],
    note,
  };
}
