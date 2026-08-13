/**
 * `validate_finding` — can anything outside the process reach the file this
 * finding lives in?
 *
 * This module is WIRING ONLY. Every rule that decides a verdict lives in
 * `../validate/staticProvider.ts` (the six gates on the negative verdict) and
 * `../validate/importGraph.ts` (hop counting). Nothing here inspects a
 * language, a hop count, a coverage status or a gate; if such a conditional
 * ever appears in this file, it is in the wrong file. What lives here is the
 * impure half the provider deliberately refuses to own: reading storage,
 * resolving the project path, hashing the working tree, minting the one
 * timestamp the batch shares, persisting the result, and reporting what the
 * run could not see.
 *
 * Report-only, by design and without an opt-out: no suppression is ever
 * written and no `Finding.severity` is ever touched (design §1 non-goals). A
 * verdict is a judgment ABOUT a finding, so it lands in its own table
 * (`finding_validations`), never on the finding itself.
 *
 * Four refusals, four different facts — never one empty batch standing in for
 * all of them, because an empty result reads as "nothing to worry about":
 *
 *   1. `not_a_git_repo`        — the project path is unusable.
 *   2. `no_surface_snapshot`   — nothing to root a graph at; names the tool
 *                                that fixes it.
 *   3. `target_not_found`      — the named fingerprint is not open.
 *   4. no open findings        — an `ok` result carrying an explicit note,
 *                                since a project with nothing open is a
 *                                correct state and not a failure. It still
 *                                must not read as "everything is fine".
 *
 * Staleness (design §8): the verdict's `tree_hash` is the SNAPSHOT's, not the
 * working tree's. A verdict derived from a snapshot of tree N describes tree
 * N no matter when it was computed; stamping the current hash instead would
 * make a verdict built on stale route data read as fresh forever — the
 * failure class this project spent three features removing. The `stale` flag
 * on each returned validation is derived at read time by comparing that
 * stored hash against the working tree's current one, and is deliberately not
 * a column: staleness is relative to now, so freezing it would be wrong the
 * moment it was written.
 */

import { z } from 'zod';
import type { PluginContext } from '../context.js';
import { resolveProjectPath } from '../platform/projectPath.js';
import { ProjectPath } from '../schemas.js';
import { languageFromPath } from '../surface/extract.js';
import { computeTreeHash } from '../treeHash/computeTreeHash.js';
import type { DomainErrorCode, ScanRecord, ToolResult } from '../types.js';
import { buildImportGraph } from '../validate/importGraph.js';
import { validateStatically } from '../validate/staticProvider.js';
import { buildSummary, type DastCrossReference } from '../validate/summary.js';
import { registerToolModule, type ToolModule } from './index.js';

/**
 * `scans.listHistory` is the only project-scoped window onto past runs, so the
 * DAST cross-reference searches a bounded slice of it. The bound is reported
 * (`summary.dast.scans_searched`) rather than applied silently: "no DAST scan
 * in the last 200 runs" and "no DAST scan ever" are different statements, and
 * neither is "nothing is exposed".
 */
const DAST_SCAN_SEARCH_LIMIT = 200;

/** The one `scan_dast` check whose finding is evidence of live, anonymous
 *  reachability — see `dast/analyze.ts`'s `checkAnonymousExposure`. */
const ANONYMOUS_EXPOSURE = 'anonymous_exposure';

const Fingerprint = z
  .string()
  .min(1)
  .optional()
  .describe(
    'Validate exactly this finding. Omitted (the default) validates EVERY open finding — batch ' +
      'is the point, since validating one finding at a time saves nobody any triage effort. A ' +
      'fingerprint that matches no open finding is an error, never an empty result.',
  );

const Providers = z
  // `.min(1)`: an empty array would mean "run no providers", whose only
  // possible output is the empty batch every refusal here exists to avoid.
  // Omit the field to get every provider this version has.
  .array(z.enum(['static']))
  .min(1)
  .optional()
  .describe(
    "Evidence providers to run. This version implements only 'static' (import graph + surface " +
      "snapshot); 'runtime' and 'dependency' are planned and will widen this enum. Omit the " +
      'field to run every provider available in this version, so a caller written today keeps ' +
      'working when the others land. Must be non-empty when supplied.',
  );

const tool: ToolModule = {
  name: 'validate_finding',
  title: 'Qualify findings by reachability',
  // An agent's only discovery surface. It must carry the preconditions and
  // the honest limits, not just the capability: the ways a caller misuses
  // this tool are trusting `unreachable` in a stack where it cannot be
  // earned, and expecting it to close findings.
  description:
    'Answers, per finding, whether anything outside the process can reach the FILE the finding ' +
    'lives in. Builds a file-level import graph from the latest map_attack_surface snapshot, ' +
    'roots it at the route-declaring files, and returns one verdict per finding — reachable / ' +
    'unreachable / unknown — with concrete evidence (nearest route and its hop count, how many ' +
    'routes reach the file, any live-confirmed anonymous exposure) plus the coverage gaps behind ' +
    'it. REQUIRES a prior map_attack_surface run and refuses with no_surface_snapshot when there ' +
    'is none. Validates every open finding by default; pass a fingerprint for one, and an ' +
    'unknown fingerprint is an error rather than an empty result. REPORT ONLY: it never ' +
    'suppresses a finding, never writes a suppression, and never changes a severity — closing a ' +
    'finding stays a human decision. Honest limits, every one of them load-bearing: granularity ' +
    'is the file, not the function, so "reachable" means a route imports the file and NOT that ' +
    'the vulnerable line is called; "unreachable" is never emitted for Ruby, Java, C# or PHP, ' +
    'which resolve code at runtime (autoload, annotation injection, DI/service container) rather ' +
    'than by import; reachability is measured from HTTP route entry points only, so a file ' +
    'reached solely by a CLI, a cron job or a queue consumer reads as unreachable-by-route, ' +
    'which is not a claim that the code never runs; and NOTHING here detects dynamic imports — ' +
    'import(expr), require(variable), reflection, plugin registries — so IN A CODEBASE USING ' +
    'THEM "unreachable" CAN BE WRONG AND THIS TOOL CANNOT TELL YOU WHEN. Verdicts persist ' +
    'against the snapshot id and tree hash they were computed from and come back flagged stale ' +
    'once the working tree moves. Read summary.coverage_gaps beside the counts: a verdict count ' +
    'without them is not an answer.',
  inputSchema: {
    project_path: ProjectPath,
    fingerprint: Fingerprint,
    providers: Providers,
  },
  handler: async (input, ctx) => handler(input, ctx),
};

registerToolModule(tool);

/** Every way this tool refuses. Narrowed from `DomainErrorCode` so the
 *  contract is readable in one glance. */
type RefusalCode = Extract<
  DomainErrorCode,
  'not_a_git_repo' | 'no_surface_snapshot' | 'target_not_found'
>;

function fail(
  code: RefusalCode,
  message: string,
  retryWith?: Record<string, unknown>,
): ToolResult<Record<string, unknown>> {
  return {
    ok: false,
    error: { code, message, ...(retryWith === undefined ? {} : { retry_with: retryWith }) },
  };
}

const NO_OPEN_FINDINGS_NOTE =
  'No open findings to validate, so nothing was computed and nothing was persisted. This is NOT ' +
  'a statement that the project is clean — it means the latest completed scan recorded no ' +
  'unsuppressed findings. Run security_scan_full (or scan_sast) first, then re-run ' +
  'validate_finding.';

async function handler(
  input: Record<string, unknown>,
  ctx: PluginContext,
): Promise<ToolResult<Record<string, unknown>>> {
  // `providers` is validated by the schema and deliberately not read here.
  // `z.enum(['static'])` makes `['static']` the only value that can arrive,
  // so reading it could not change what runs; and `summary.providers_run`
  // reports what actually ran rather than what was asked for, so echoing the
  // argument would start lying the moment the enum widens and a caller asks
  // for a provider this version cannot execute.
  const inp = input as { project_path?: string; fingerprint?: string };

  let projectPath: string;
  try {
    projectPath = resolveProjectPath(inp.project_path).path;
  } catch (e) {
    // Same code map_attack_surface, scan_dast and detect_stack return for an
    // unusable project_path, so hosts and skills handle one failure, not four.
    return fail('not_a_git_repo', (e as Error).message);
  }

  // PROJECT-SCOPED, deliberately. Everything downstream is keyed to
  // `projectPath`: routes and findings are relativized against it, verdicts
  // are persisted under it, and the DAST cross-reference below filters on it.
  // Reading "the newest snapshot in the database" instead would hand this run
  // a map of a DIFFERENT tree whenever another project was mapped more
  // recently — every route file would relativize into a foreign key space,
  // match no graph node, and, because the graph is non-empty, produce
  // `unreachable` for every finding rather than an error. Same failure the
  // path-convention gaps in this feature produced twice: silent, universal,
  // and in the direction that hides real findings.
  const persisted = ctx.storage.surface.getLatestForProject(projectPath);
  if (persisted === null) {
    return fail(
      'no_surface_snapshot',
      'No attack-surface snapshot exists for this project, so there are no route files to root a ' +
        'reachability graph at. Run map_attack_surface first, then re-run validate_finding. This ' +
        'is a refusal and not a batch of "unknown" verdicts on purpose: a verdict nobody computed ' +
        'must not occupy the same slot as one that was. A snapshot mapped under a DIFFERENT ' +
        'project_path does not count: it describes another tree, and every verdict computed ' +
        'against it would be silently wrong rather than absent.',
      { run_first: 'map_attack_surface', project_path: projectPath },
    );
  }

  // PROJECT-SCOPED, same reasoning as the surface-snapshot read above:
  // listOpen() answers with the latest completed scan in the WHOLE
  // database, from any project, which would validate a different project's
  // findings under this run whenever that project's scan happened to
  // complete more recently.
  const open = ctx.storage.findings.listOpenForProject(projectPath);
  const selected =
    inp.fingerprint === undefined ? open : open.filter((f) => f.fingerprint === inp.fingerprint);
  if (inp.fingerprint !== undefined && selected.length === 0) {
    return fail(
      'target_not_found',
      `No OPEN finding carries the fingerprint '${inp.fingerprint}'. It may never have existed, ` +
        'it may belong to an older scan, or it may be suppressed — this tool only reads the open ' +
        'list and cannot tell those apart. Read guardian://findings/open for the fingerprints ' +
        'that are actually validatable, or omit the argument to validate all of them.',
    );
  }

  const workingTreeHash = await computeTreeHash(projectPath);
  const graph = buildImportGraph(persisted.snapshot.imports);
  const dast = collectAnonymousExposures(ctx, projectPath);

  const validations = validateStatically({
    snapshot: persisted.snapshot,
    snapshotId: persisted.id,
    // The snapshot's tree, not the working tree — see the module doc comment.
    treeHash: persisted.tree_hash,
    graph,
    findings: selected,
    anonymouslyExposedRouteFiles: dast.files,
    // Injected so the provider stays pure, and minted once so a whole batch
    // carries one timestamp rather than N that drift across a long run.
    computedAt: new Date().toISOString(),
    languageOf: languageOfPath,
    projectPath,
  });

  ctx.storage.validations.upsert(projectPath, validations);

  return {
    ok: true,
    validations: validations.map((v) => ({ ...v, stale: v.tree_hash !== workingTreeHash })),
    summary: buildSummary({
      persisted,
      graph,
      validations,
      dast,
      // The scan `listOpenForProject()` drew from — see `sourceScanOf`.
      sourceScan: sourceScanOf(ctx, projectPath),
      workingTreeHash,
      now: Date.now(),
    }),
    ...(selected.length === 0 ? { note: NO_OPEN_FINDINGS_NOTE } : {}),
  };
}

/**
 * `StaticProviderInput.languageOf`, implemented over the established
 * extension table (`languageFromPath`, `surface/extract.ts`) — the same one
 * `map_attack_surface` builds `coverage[].language` from, so a finding's
 * language and the coverage entry gating its verdict can never disagree about
 * what "typescript" means.
 *
 * PATH CONVENTION: project-relative POSIX (`src/db.ts`), the form the provider
 * relativizes a finding's `file_path` into before calling this. The lookup is
 * extension-only, so an absolute or native-separator path would in practice
 * yield the same answer; the convention is stated because the next provider's
 * implementation should not have to rediscover it, and because a
 * path-convention mismatch is the defect class this feature has already hit
 * twice.
 *
 * `languageFromPath` returns the string `'unknown'` for an unrecognised
 * extension; `languageOf` is contracted to return `null` there ("files whose
 * language could not be determined"). Translating the sentinel is this
 * adapter's whole job — a raw `'unknown'` would be looked up as a language
 * name, match no coverage entry, and read as a coverage gap about a language
 * that does not exist.
 */
function languageOfPath(filePath: string): string | null {
  const language = languageFromPath(filePath);
  return language === 'unknown' ? null : language;
}

/**
 * The scan whose findings this batch validated.
 *
 * `findings.listOpenForProject(projectPath)` selects from the latest
 * COMPLETED scan FOR THIS PROJECT, and `scans.getLatestForProject(
 * projectPath)` returns that same row — identical predicate (`status =
 * 'completed' AND project_path = ?`, identical `ORDER BY started_at DESC,
 * rowid DESC LIMIT 1`), both scoped to the same project. The two must stay in
 * lockstep: if one ever changes its ordering or its project filter, this
 * summary starts naming a scan the findings did not come from, which is worse
 * than naming none — including naming another project's scan entirely, which
 * `getLatest()` (no project filter) could do silently. Kept as a lookup
 * rather than derived from the selected findings because a finding carries no
 * scan id in its domain type, and because the answer must exist even when
 * zero findings were selected — the case where a reader most needs to know
 * WHICH scan came back empty.
 *
 * This is what makes the documented hazard detectable: `validate_finding`
 * validates whatever the latest completed scan left open FOR THIS PROJECT, so
 * running it immediately after `scan_dast` validates the DAST findings rather
 * than the SAST ones. The tool cannot know which the caller meant — it can,
 * and now does, say which it used.
 */
function sourceScanOf(ctx: PluginContext, projectPath: string): ScanRecord | null {
  return ctx.storage.scans.getLatestForProject(projectPath);
}

/**
 * The liveness cross-reference (design §7): a persisted `scan_dast` finding
 * whose subcategory is `anonymous_exposure` fires only on a route the spec
 * declared auth-required and the live server served anonymously, so it is
 * evidence rather than inference.
 *
 * `file_path` is passed through VERBATIM. `dast/analyze.ts` sets it to
 * `route.file` unchanged — absolute, native separators — and the provider
 * relativizes the set itself against the same project root it relativizes
 * routes with, so the two agree by construction. Pre-relativizing here would
 * merely duplicate that; mangling it any other way would silently break the
 * one evidence clause the design calls out by name.
 */
function collectAnonymousExposures(ctx: PluginContext, projectPath: string): DastCrossReference {
  const history = ctx.storage.scans.listHistory(DAST_SCAN_SEARCH_LIMIT);
  const scan =
    history.find(
      (s) => s.scan_type === 'dast' && s.status === 'completed' && s.project_path === projectPath,
    ) ?? null;
  if (scan === null) return { scan: null, files: new Set(), scansSearched: history.length };

  const files = new Set<string>();
  for (const f of ctx.storage.findings.listByScan(scan.scan_id)) {
    if (f.subcategory !== ANONYMOUS_EXPOSURE || f.file_path === undefined) continue;
    files.add(f.file_path);
  }
  return { scan, files, scansSearched: history.length };
}
