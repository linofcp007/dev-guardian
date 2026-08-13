/**
 * The batch-level report that accompanies a set of verdicts.
 *
 * Pure: no I/O, no storage, no clock — `now` is injected, exactly as
 * `computedAt` is on `StaticProviderInput`, and for the same reason. Extracted
 * from `tools/validateFinding.ts` so the orchestrator stays wiring; a sibling
 * tool in this repo had its scanner invocation extracted for the same reason.
 *
 * It holds no verdict logic either. Nothing here inspects a language, a hop
 * count, a coverage status or a gate: it counts what the provider already
 * decided and reports what the run could not see. The one judgment-shaped
 * thing it does is decide WHICH gaps to name, and every one of those is a fact
 * about the inputs (the snapshot aged, the graph was cut, no DAST scan
 * existed), never about a finding.
 *
 * Design §9: "a verdict count without its `coverage_gaps` beside it is not an
 * answer." That is why the counts and the gaps are built in one place and
 * returned together, rather than left for a caller to remember to pair.
 */

import { toRelativeIfPossible } from '../runners/scannerParsers/index.js';
import type { PersistedSurfaceSnapshot } from '../storage/surfaceRepo.js';
import type { ScanRecord } from '../types.js';
import { MAX_GRAPH_EDGES, type ImportGraph } from './importGraph.js';
import { VERDICTS, type FindingValidation, type Verdict } from './types.js';

export interface DastCrossReference {
  /** The completed `scan_dast` run consulted, or `null` when none was found. */
  scan: ScanRecord | null;
  /** `file_path` of every `anonymous_exposure` finding in it, verbatim. */
  files: ReadonlySet<string>;
  /** How many scan records the bounded search window actually held. */
  scansSearched: number;
}

export interface SummaryInput {
  persisted: PersistedSurfaceSnapshot;
  graph: ImportGraph;
  validations: readonly FindingValidation[];
  dast: DastCrossReference;
  /**
   * The completed scan the validated findings were drawn from, or `null`
   * when none could be identified. `validate_finding` validates whatever the
   * latest completed scan left open — which is a documented hazard: run it
   * straight after `scan_dast` and it validates the DAST findings, not the
   * SAST ones the caller had in mind. Reporting the scan makes that
   * detectable instead of merely documented.
   */
  sourceScan: ScanRecord | null;
  /** Hash of the working tree as it is right now, for the staleness check. */
  workingTreeHash: string;
  /** Injected epoch millis — keeps this module free of a clock. */
  now: number;
}

export function buildSummary(input: SummaryInput): Record<string, unknown> {
  const { persisted, graph, validations, dast } = input;
  const stale = persisted.tree_hash !== input.workingTreeHash;
  // Code routes only, and their deduplicated files — the roots the provider
  // actually traverses from. See `routeRoots`.
  const codeRoutes = persisted.snapshot.routes.filter((r) => r.provenance === 'code');

  return {
    findings_selected: validations.length,
    counts_by_verdict: countByVerdict(validations),
    coverage_gaps: collectGaps(input, stale),
    snapshot: {
      id: persisted.id,
      tree_hash: persisted.tree_hash,
      captured_at: persisted.captured_at,
      /**
       * The routes that were ROOTS, not every route in the snapshot.
       * `groupRoutesByRelFile` (staticProvider.ts) excludes spec-provenance
       * routes — a spec route's `file` is the OpenAPI document, which no code
       * import graph contains — so counting them here put a number beside a
       * batch of verdicts that nothing in it was computed from: a project
       * whose routes came only from an imported spec read `routes_total: 40`
       * next to `unreachable` verdicts produced from ZERO roots. It also
       * disagreed with `map_attack_surface`'s own `routes_total`, which is
       * code-only by explicit decision, and with the per-finding evidence
       * sentence ("reached by X of Y known route(s)"), which counts the same
       * code routes.
       */
      routes_total: codeRoutes.length,
      /**
       * Deduplicated root FILES — what `reachFrom` is actually rooted at.
       * Deduplicated through the SAME `toRelativeIfPossible` the provider
       * groups by, not on `route.file` verbatim: the raw value is absolute
       * and native-separator, and two spellings of one file would count as
       * two roots where the provider sees one.
       */
      root_files: new Set(
        codeRoutes.map((r) => toRelativeIfPossible(r.file, persisted.project_path)),
      ).size,
      /** Reported, never silently dropped: the difference is the point. */
      spec_routes_excluded: persisted.snapshot.routes.length - codeRoutes.length,
      import_records: persisted.snapshot.imports.length,
    },
    findings_from_scan: describeSourceScan(input),
    working_tree_hash: input.workingTreeHash,
    snapshot_stale: stale,
    graph: { files: graph.files.size, edges: edgeCount(graph), truncated: graph.truncated },
    // Verbatim and unfiltered. This is where "the languages with no rules"
    // (design §9) is answered. Filtering it to the ones that look interesting
    // would be a coverage-status decision, which belongs to the provider and
    // only ever for the language a finding is actually in.
    snapshot_coverage: persisted.snapshot.coverage,
    dast: {
      available: dast.scan !== null,
      scan_id: dast.scan?.scan_id ?? null,
      finished_at: dast.scan?.finished_at ?? null,
      age_hours: dast.scan === null ? null : ageHours(dast.scan, input.now),
      anonymous_exposure_files: dast.files.size,
      scans_searched: dast.scansSearched,
    },
    providers_run: ['static'],
  };
}

/**
 * Which scan the validated findings came from — design §9's "a verdict count
 * without its `coverage_gaps` beside it is not an answer", applied to the
 * batch's INPUT rather than its coverage.
 *
 * `null` rather than an omitted key when no scan could be identified: an
 * absent field reads as "not measured", the same distinction
 * `countByVerdict` seeds itself with zeros for.
 *
 * `matches_snapshot_tree` is the one derived fact, and it is the one a reader
 * would otherwise have to compute by eye: findings from a different tree than
 * the snapshot's are being placed on a map of a different codebase. It is
 * stated, never acted on — nothing here suppresses or downgrades a verdict.
 */
function describeSourceScan(input: SummaryInput): Record<string, unknown> | null {
  const scan = input.sourceScan;
  if (scan === null) return null;
  return {
    scan_id: scan.scan_id,
    scan_type: scan.scan_type,
    tree_hash: scan.tree_hash,
    finished_at: scan.finished_at,
    matches_snapshot_tree: scan.tree_hash === input.persisted.tree_hash,
  };
}

function countByVerdict(validations: readonly FindingValidation[]): Record<Verdict, number> {
  // Seeded with every verdict at zero, so `confirmed: 0` is PRESENT rather
  // than absent. A missing key reads as "not measured"; this one means "not
  // producible by the provider that ran".
  const counts = Object.fromEntries(VERDICTS.map((v) => [v, 0])) as Record<Verdict, number>;
  for (const v of validations) counts[v.verdict] += 1;
  return counts;
}

function edgeCount(graph: ImportGraph): number {
  let total = 0;
  for (const targets of graph.edges.values()) total += targets.size;
  return total;
}

/**
 * Age of the consulted DAST run in hours (design §11: "the liveness
 * cross-reference is only as fresh as the last scan_dast run, and its age is
 * reported alongside it"). `null` rather than a fabricated number when the
 * stored timestamp cannot be parsed — an unparseable date is not an age of
 * zero, which would read as "this ran just now".
 */
function ageHours(scan: ScanRecord, now: number): number | null {
  const stamp = Date.parse(scan.finished_at ?? scan.started_at);
  if (Number.isNaN(stamp)) return null;
  return Math.round(((now - stamp) / 3_600_000) * 100) / 100;
}

/**
 * The union of every gap the provider reported per finding, plus the ones
 * only the orchestrator's inputs can reveal. Both halves are needed: a
 * per-finding gap only ever names a language some finding is in, so a
 * language with no rules and no findings would go unmentioned; and the
 * provider has no clock, no filesystem and no storage, so it cannot know the
 * snapshot has aged or that no DAST scan exists.
 */
function collectGaps(input: SummaryInput, stale: boolean): string[] {
  const gaps = new Set<string>();
  for (const validation of input.validations) {
    for (const gap of validation.coverage_gaps) gaps.add(gap);
  }

  if (stale) {
    gaps.add(
      `the surface snapshot describes tree ${input.persisted.tree_hash} but the working tree is ` +
        `now ${input.workingTreeHash} — every verdict here was computed against the snapshot's ` +
        'tree, not the current one; re-run map_attack_surface to refresh it',
    );
  }
  if (input.graph.truncated) {
    gaps.add(
      `the import graph was truncated at its ${MAX_GRAPH_EDGES}-edge cap, so it cannot certify ` +
        'the absence of any path',
    );
  }
  if (input.persisted.snapshot.imports.length === 0) {
    // The provider's gate 1 already refuses `unreachable` for every finding
    // here and says so per finding, so this is not the safety net — it is the
    // batch-level statement of the same fact, which the per-finding gaps
    // cannot make when zero findings were selected, and which a reader
    // scanning the summary alone would otherwise have to infer from
    // `graph.edges: 0`.
    gaps.add(
      'the surface snapshot carries 0 resolved import edges, so the import graph has no paths at ' +
        'all: no finding in this batch can earn the `unreachable` verdict, and every file outside ' +
        'a route-declaring file reads `unknown` — re-run map_attack_surface (a snapshot captured ' +
        'before import edges were persisted carries none)',
    );
  }
  if (input.dast.scan === null) {
    gaps.add(
      `no completed scan_dast run was found for this project among the ${input.dast.scansSearched} ` +
        'most recent scans, so no reaching route could be cross-referenced as confirmed ' +
        'anonymously exposed — that is a missing input, not evidence that nothing is exposed',
    );
  }
  gaps.add(
    "only the 'static' provider exists in this version — 'runtime' (live confirmation) and " +
      "'dependency' are not implemented, so no verdict here can be 'confirmed'",
  );
  return [...gaps];
}
