/**
 * `validate_finding` — can anything outside the process reach the file this
 * finding lives in?
 *
 * This module is WIRING ONLY. Every rule that decides a verdict lives in
 * `../validate/staticProvider.ts` (the six gates on the negative verdict),
 * `../validate/dependencyProvider.ts` (is a dependency finding's package
 * imported, and by a routed file) and `../validate/importGraph.ts` (hop
 * counting). Nothing here inspects a
 * language, a hop count, a coverage status or a gate; if such a conditional
 * ever appears in this file, it is in the wrong file. What lives here is the
 * impure half the provider deliberately refuses to own: reading storage,
 * resolving the project path, hashing the working tree, minting the one
 * timestamp the batch shares, persisting the result, and reporting what the
 * run could not see.
 *
 * Report-only, by design and without an opt-out: no suppression is ever
 * written and no `Finding.severity` is ever touched (the design of record's non-goals). A
 * verdict is a judgment ABOUT a finding, so it lands in its own table
 * (`finding_validations`), never on the finding itself.
 *
 * Four refusals, four different facts — never one empty batch standing in for
 * all of them, because an empty result reads as "nothing to worry about":
 *
 *   1. `target_not_found` / `unsupported_target` — the project path is
 *                                unusable (`projectPathErrorCode`).
 *   2. `no_surface_snapshot`   — nothing to root a graph at; names the tool
 *                                that fixes it.
 *   3. `target_not_found`      — the named fingerprint is not open.
 *   4. no open findings        — an `ok` result carrying an explicit note,
 *                                since a project with nothing open is a
 *                                correct state and not a failure. It still
 *                                must not read as "everything is fine".
 *
 * Staleness (the design of record): the verdict's `tree_hash` is the SNAPSHOT's, not the
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
import { dependencyCoordinates } from '../fingerprint/findingIdentity.js';
import { openSetForProject } from '../history/openSet.js';
import { findingVulnIds } from '../intel/vulnIds.js';
import { projectPathErrorCode, resolveProjectPath } from '../platform/projectPath.js';
import { ProjectPath } from '../schemas.js';
import { languageFromPath } from '../surface/extract.js';
import { computeTreeHash } from '../treeHash/computeTreeHash.js';
import type { DomainErrorCode, ToolResult } from '../types.js';
import { validateDependencies } from '../validate/dependencyProvider.js';
import { buildImportGraph } from '../validate/importGraph.js';
import { makeNpmResolver } from '../validate/npmResolve.js';
import { makePypiPinResolver } from '../validate/pypiPins.js';
import { validateStatically } from '../validate/staticProvider.js';
import { buildSummary, type DastCrossReference } from '../validate/summary.js';
import { IMPLEMENTED_PROVIDERS, type FindingValidation } from '../validate/types.js';
import { registerToolModule, type ToolModule } from './index.js';

/** The one `scan_dast` check whose finding is evidence of live, anonymous
 *  reachability — see `dast/analyze.ts`'s `checkAnonymousExposure`. */
const ANONYMOUS_EXPOSURE = 'anonymous_exposure';

const Fingerprint = z
  .string()
  .min(1)
  .optional()
  .describe(
    'Validate only this finding. Default: every open finding.',
  );

// Review 3.0 I1: suppress_finding and suggest_fix name the same thing
// `finding_fingerprint`. Passed here before the schemas were strict, the key
// was stripped and EVERY open finding was validated instead of the one named.
const FindingFingerprint = z
  .string()
  .min(1)
  .optional()
  .describe(
    'Same as fingerprint (the name other tools use); pass one.',
  );

const Providers = z
  // `.min(1)`: an empty array would mean "run no providers", whose only
  // possible output is the empty batch every refusal here exists to avoid.
  // Omit the field to get every provider this version has.
  .array(z.enum(IMPLEMENTED_PROVIDERS))
  .min(1)
  .optional()
  .describe(
    "static (the finding's file) and/or dependency (a CVE's package). Default: both.",
  );

const tool: ToolModule = {
  name: 'validate_finding',
  title: 'Qualify findings by reachability',
  // An agent's only discovery surface. It must carry the preconditions and
  // the honest limits, not just the capability: the ways a caller misuses
  // this tool are trusting `unreachable` in a stack where it cannot be
  // earned, and expecting it to close findings.
  //
  // At most 1500 characters (descriptionLimits.test.ts). Shortened from 1809
  // by tightening wording only: every limit below survived, each one tested
  // in validateFinding.test.ts.
  description:
    'Per open finding: does a file an HTTP route reaches import its file (static) or, for a dependency ' +
    'CVE, its package (dependency)? reachable, unreachable or unknown, with evidence. Needs ' +
    'map_attack_surface. Report only: it never suppresses a finding or changes a severity. The unit is ' +
    'the file; Ruby, Java, C# and PHP never get unreachable; nothing detects a dynamic import, so where ' +
    'one is used unreachable can be wrong and this tool cannot tell you when.',
  inputSchema: {
    project_path: ProjectPath,
    fingerprint: Fingerprint,
    finding_fingerprint: FindingFingerprint,
    providers: Providers,
  },
  handler: async (input, ctx) => handler(input, ctx),
};

registerToolModule(tool);

/** Every way this tool refuses. Narrowed from `DomainErrorCode` so the
 *  contract is readable in one glance. */
type RefusalCode = Extract<
  DomainErrorCode,
  'no_surface_snapshot' | 'target_not_found' | 'unsupported_target'
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
  "a statement that the project is clean — it means no usable scan of this project's " +
  'finding-producing types left an unsuppressed finding open. Run security_scan_full (or ' +
  'scan_sast) first, then re-run validate_finding.';

async function handler(
  input: Record<string, unknown>,
  ctx: PluginContext,
): Promise<ToolResult<Record<string, unknown>>> {
  // `summary.providers_run` reports what actually ran, in the fixed order of
  // IMPLEMENTED_PROVIDERS — never the argument echoed back.
  const inp = input as {
    project_path?: string;
    fingerprint?: string;
    finding_fingerprint?: string;
    providers?: string[];
  };
  if (
    inp.fingerprint !== undefined &&
    inp.finding_fingerprint !== undefined &&
    inp.fingerprint !== inp.finding_fingerprint
  ) {
    return fail(
      'unsupported_target',
      `fingerprint ('${inp.fingerprint}') and finding_fingerprint ('${inp.finding_fingerprint}') are ` +
        'the same parameter and name different findings. Pass one of them.',
    );
  }
  const fingerprint = inp.fingerprint ?? inp.finding_fingerprint;
  const requested = new Set(inp.providers ?? IMPLEMENTED_PROVIDERS);
  const providersRun = IMPLEMENTED_PROVIDERS.filter((p) => requested.has(p));

  let projectPath: string;
  try {
    projectPath = resolveProjectPath(inp.project_path).path;
  } catch (e) {
    // The code every tool answers an unusable project_path with
    // (`projectPathErrorCode`), so hosts and skills handle one failure.
    return fail(projectPathErrorCode(e), (e as Error).message);
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
  // complete more recently. And the project's OPEN SET, not its single
  // latest scan: that one could be an SBOM, or a DAST run standing in for
  // the SAST findings the caller meant (`history/openSet.ts`).
  const openSet = openSetForProject(ctx.storage, projectPath);
  const open = openSet.findings;
  const selected = fingerprint === undefined ? open : open.filter((f) => f.fingerprint === fingerprint);
  if (fingerprint !== undefined && selected.length === 0) {
    return fail(
      'target_not_found',
      `No OPEN finding carries the fingerprint '${fingerprint}'. It may never have existed, ` +
        'it may belong to an older scan, or it may be suppressed — this tool only reads the open ' +
        'list and cannot tell those apart. Read guardian://findings/open for the fingerprints ' +
        'that are actually validatable, or omit the argument to validate all of them.',
    );
  }

  const workingTreeHash = await computeTreeHash(projectPath);
  const graph = buildImportGraph(persisted.snapshot.imports);
  const dast = collectAnonymousExposures(ctx, projectPath);

  // Injected so the providers stay pure, and minted once so a whole batch
  // carries one timestamp rather than N that drift across a long run.
  const computedAt = new Date().toISOString();
  const validations: FindingValidation[] = [];
  if (providersRun.includes('static')) {
    validations.push(
      ...validateStatically({
        snapshot: persisted.snapshot,
        snapshotId: persisted.id,
        // The snapshot's tree, not the working tree — see the module doc comment.
        treeHash: persisted.tree_hash,
        graph,
        findings: selected,
        anonymouslyExposedRouteFiles: dast.files,
        computedAt,
        languageOf: languageOfPath,
        projectPath,
      }),
    );
  }
  if (providersRun.includes('dependency')) {
    // Only the dependency findings get a verdict from it — see
    // `validateDependencies`. Same snapshot, graph, tree and timestamp.
    validations.push(
      ...validateDependencies({
        snapshot: persisted.snapshot,
        snapshotId: persisted.id,
        treeHash: persisted.tree_hash,
        graph,
        findings: selected,
        computedAt,
        projectPath,
        npmResolver: makeNpmResolver(projectPath),
        pypiPins: makePypiPinResolver(projectPath),
      }),
    );
  }

  ctx.storage.validations.upsert(projectPath, validations);

  return {
    ok: true,
    validations: validations.map((v) => ({ ...v, stale: v.tree_hash !== workingTreeHash })),
    summary: buildSummary({
      persisted,
      graph,
      validations,
      dast,
      // The newest scan the open set read findings from, taken from the set
      // itself so it cannot drift from it (each finding also carries its
      // own `scan_id`). Present even when nothing was selected — the case
      // where a reader most needs to know which scans came back empty.
      sourceScan: openSet.newestSource,
      workingTreeHash,
      now: Date.now(),
      providersRun,
      findingsSelected: selected.length,
      withoutCoordinates: selected.flatMap((f) => {
        const ids = findingVulnIds(f);
        return ids.length > 0 && dependencyCoordinates(f) === null ? [{ fingerprint: f.fingerprint, ids }] : [];
      }),
    }),
    ...(selected.length === 0 ? { note: NO_OPEN_FINDINGS_NOTE } : {}),
    // Newer scans the open set passed over because their scanners did not
    // run: the findings validated come from the scan before each of them.
    ...(openSet.skipped.count > 0 ? { skipped_scans: openSet.skipped } : {}),
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
 * The liveness cross-reference (the design of record): a persisted `scan_dast` finding
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
  // A project-scoped SQL query over ALL of this project's scans — it
  // searched the 200 newest scans of the whole database, so enough scans of
  // other projects hid this project's DAST run.
  const scan = ctx.storage.scans.listCompletedOfTypes(projectPath, ['dast'], { limit: 1 })[0] ?? null;
  const scansSearched = ctx.storage.scans.countForProject(projectPath);
  if (scan === null) return { scan: null, files: new Set(), scansSearched };

  const files = new Set<string>();
  for (const f of ctx.storage.findings.listByScan(scan.scan_id)) {
    if (f.subcategory !== ANONYMOUS_EXPOSURE || f.file_path === undefined) continue;
    files.add(f.file_path);
  }
  return { scan, files, scansSearched };
}
