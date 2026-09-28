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
 * The design of record: "a verdict count without its `coverage_gaps` beside it is not an
 * answer." That is why the counts and the gaps are built in one place and
 * returned together, rather than left for a caller to remember to pair.
 */
import { toRelativeIfPossible } from '../runners/scannerParsers/index.js';
import { MAX_GRAPH_EDGES } from './importGraph.js';
import { IMPLEMENTED_PROVIDERS, VERDICTS, } from './types.js';
export function buildSummary(input) {
    const { persisted, graph, validations, dast } = input;
    const stale = persisted.tree_hash !== input.workingTreeHash;
    const providersRun = input.providersRun ?? ['static'];
    // Code routes only, and their deduplicated files — the roots the provider
    // actually traverses from. See `routeRoots`.
    const codeRoutes = persisted.snapshot.routes.filter((r) => r.provenance === 'code');
    return {
        findings_selected: input.findingsSelected ?? new Set(validations.map((v) => v.fingerprint)).size,
        // Per provider, keyed by provider (review of the 3.0 additions, M4): a
        // dependency finding carries a verdict from each, so one flat count
        // counted it twice and mixed two different questions.
        counts_by_verdict: Object.fromEntries(providersRun.map((p) => [p, countByVerdict(validations.filter((v) => v.provider === p))])),
        coverage_gaps: collectGaps(input, stale, providersRun),
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
            root_files: new Set(codeRoutes.map((r) => toRelativeIfPossible(r.file, persisted.project_path))).size,
            /** Reported, never silently dropped: the difference is the point. */
            spec_routes_excluded: persisted.snapshot.routes.length - codeRoutes.length,
            import_records: persisted.snapshot.imports.length,
        },
        findings_from_scan: describeSourceScan(input),
        working_tree_hash: input.workingTreeHash,
        snapshot_stale: stale,
        graph: { files: graph.files.size, edges: edgeCount(graph), truncated: graph.truncated },
        // Verbatim and unfiltered. This is where "the languages with no rules"
        // (the design of record) is answered. Filtering it to the ones that look interesting
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
        providers_run: [...providersRun],
    };
}
/**
 * Which scan the validated findings came from — the design of record's "a verdict count
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
function describeSourceScan(input) {
    const scan = input.sourceScan;
    if (scan === null)
        return null;
    return {
        scan_id: scan.scan_id,
        scan_type: scan.scan_type,
        tree_hash: scan.tree_hash,
        finished_at: scan.finished_at,
        matches_snapshot_tree: scan.tree_hash === input.persisted.tree_hash,
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
 * Age of the consulted DAST run in hours (the design of record: "the liveness
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
/**
 * The per-finding gaps, one line per KIND (review of the 3.0 additions, M4:
 * 30 packages made 34 entries, 10 KB). Two gaps are one kind when they differ
 * only in what they quote (`'src/a.x'` vs `'src/b.y'`): a kind seen once is
 * kept verbatim — which is also why a per-finding gap still appears in the
 * summary exactly as the finding carries it — and one seen with several
 * values becomes one line naming how many findings and the first values.
 */
function aggregateByKind(validations) {
    const kinds = new Map();
    for (const validation of validations) {
        for (const gap of validation.coverage_gaps) {
            const kind = gap.replace(/'[^']*'/g, "'…'");
            const entry = kinds.get(kind) ?? { variants: new Set(), findings: new Set(), values: [] };
            if (!entry.variants.has(gap)) {
                entry.variants.add(gap);
                entry.values.push(...(gap.match(/'[^']*'/g) ?? []).slice(0, 1));
            }
            entry.findings.add(validation.fingerprint);
            kinds.set(kind, entry);
        }
    }
    return [...kinds].map(([kind, entry]) => {
        const [only] = entry.variants;
        if (entry.variants.size === 1 && only !== undefined)
            return only;
        const shown = entry.values.slice(0, 3).join(', ');
        const more = entry.values.length > 3 ? `, … ${entry.values.length - 3} more` : '';
        return `${kind} — ${entry.findings.size} findings (${shown}${more})`;
    });
}
function collectGaps(input, stale, providersRun) {
    const gaps = new Set(aggregateByKind(input.validations));
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
        // The provider's gate 1 already refuses `unreachable` for every finding
        // here and says so per finding, so this is not the safety net — it is the
        // batch-level statement of the same fact, which the per-finding gaps
        // cannot make when zero findings were selected, and which a reader
        // scanning the summary alone would otherwise have to infer from
        // `graph.edges: 0`.
        gaps.add('the surface snapshot carries 0 resolved import edges, so the import graph has no paths at ' +
            'all: no finding in this batch can earn the `unreachable` verdict, and every file outside ' +
            'a route-declaring file reads `unknown` — re-run map_attack_surface (a snapshot captured ' +
            'before import edges were persisted carries none)');
    }
    if (input.dast.scan === null) {
        gaps.add(`no completed scan_dast run was found for this project among the ${input.dast.scansSearched} ` +
            'most recent scans, so no reaching route could be cross-referenced as confirmed ' +
            'anonymously exposed — that is a missing input, not evidence that nothing is exposed');
    }
    if (providersRun.includes('dependency') && input.persisted.snapshot.external_imports === undefined) {
        gaps.add('the surface snapshot was mapped before third-party imports were recorded, so the ' +
            "'dependency' provider could match no package — re-run map_attack_surface with force: true");
    }
    for (const provider of IMPLEMENTED_PROVIDERS) {
        if (providersRun.includes(provider))
            continue;
        gaps.add(provider === 'dependency'
            ? "'dependency' was not requested, so no dependency finding was checked for an import of its package"
            : "'static' was not requested, so no finding's own file was checked for a path from a route");
    }
    gaps.add("'runtime' (live confirmation) is not implemented in this version, so no verdict here can be " +
        "'confirmed'");
    return [...gaps];
}
//# sourceMappingURL=summary.js.map