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
import { MAX_GRAPH_EDGES } from './importGraph.js';
import { VERDICTS } from './types.js';
export function buildSummary(input) {
    const { persisted, graph, validations, dast } = input;
    const stale = persisted.tree_hash !== input.workingTreeHash;
    return {
        findings_selected: validations.length,
        counts_by_verdict: countByVerdict(validations),
        coverage_gaps: collectGaps(input, stale),
        snapshot: {
            id: persisted.id,
            tree_hash: persisted.tree_hash,
            captured_at: persisted.captured_at,
            routes_total: persisted.snapshot.routes.length,
            import_records: persisted.snapshot.imports.length,
        },
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
function countByVerdict(validations) {
    // Seeded with every verdict at zero, so `confirmed: 0` is PRESENT rather
    // than absent. A missing key reads as "not measured"; this one means "not
    // producible by the provider that ran".
    const counts = Object.fromEntries(VERDICTS.map((v) => [v, 0]));
    for (const v of validations)
        counts[v.verdict] += 1;
    return counts;
}
function edgeCount(graph) {
    let total = 0;
    for (const targets of graph.edges.values())
        total += targets.size;
    return total;
}
/**
 * Age of the consulted DAST run in hours (design §11: "the liveness
 * cross-reference is only as fresh as the last scan_dast run, and its age is
 * reported alongside it"). `null` rather than a fabricated number when the
 * stored timestamp cannot be parsed — an unparseable date is not an age of
 * zero, which would read as "this ran just now".
 */
function ageHours(scan, now) {
    const stamp = Date.parse(scan.finished_at ?? scan.started_at);
    if (Number.isNaN(stamp))
        return null;
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
function collectGaps(input, stale) {
    const gaps = new Set();
    for (const validation of input.validations) {
        for (const gap of validation.coverage_gaps)
            gaps.add(gap);
    }
    if (stale) {
        gaps.add(`the surface snapshot describes tree ${input.persisted.tree_hash} but the working tree is ` +
            `now ${input.workingTreeHash} — every verdict here was computed against the snapshot's ` +
            'tree, not the current one; re-run map_attack_surface to refresh it');
    }
    if (input.graph.truncated) {
        gaps.add(`the import graph was truncated at its ${MAX_GRAPH_EDGES}-edge cap, so it cannot certify ` +
            'the absence of any path');
    }
    if (input.persisted.snapshot.imports.length === 0) {
        // The one hole none of the provider's four gates covers: with no edges,
        // every file outside a route file is unreached BY CONSTRUCTION, not by
        // evidence, and the negative verdict is still available. Loudest gap in
        // the list, deliberately.
        gaps.add('the surface snapshot carries 0 resolved import edges, so the import graph has no paths at ' +
            'all and every file outside a route-declaring file is unreached by construction, not by ' +
            'evidence — re-run map_attack_surface (a snapshot captured before import edges were ' +
            'persisted carries none)');
    }
    if (input.dast.scan === null) {
        gaps.add(`no completed scan_dast run was found for this project among the ${input.dast.scansSearched} ` +
            'most recent scans, so no reaching route could be cross-referenced as confirmed ' +
            'anonymously exposed — that is a missing input, not evidence that nothing is exposed');
    }
    gaps.add("only the 'static' provider exists in this version — 'runtime' (live confirmation) and " +
        "'dependency' are not implemented, so no verdict here can be 'confirmed'");
    return [...gaps];
}
//# sourceMappingURL=summary.js.map