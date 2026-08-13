/**
 * The `static` evidence provider — the only one of the three
 * (`static`/`runtime`/`dependency`) this cycle builds. Turns a surface
 * snapshot, its import graph, and a batch of findings into one
 * `FindingValidation` per finding: does anything outside the process reach
 * the file this finding lives in?
 *
 * The governing asymmetry, inherited from `importGraph.ts` and restated here
 * because every decision below follows from it: an import graph is far
 * better at DISPROVING reachability than proving it. "No externally
 * reachable route imports this file, directly or transitively" is a strong
 * claim — no path exists from any root, under any path, full stop. "It is
 * imported, therefore the vulnerability is reachable" is weak, because
 * importing is not calling. `unreachable` is this module's strongest output
 * and its most dangerous: emitting it wrongly deprioritises an exploitable
 * finding, and nobody looks again. So `reachable` is cheap to earn — any
 * discovered path is reported, gates or no gates — while `unreachable` is
 * gated on six independent conditions, ALL of which must hold, checked in
 * order, the first failure deciding `unknown` and naming itself in
 * `coverage_gaps` (design doc §5, plus gates 1 and 6 below, ruled in during
 * Task 5 and the final whole-branch review respectively):
 *
 *   1. The import graph holds at least one edge. An empty graph is evidence
 *      of missing DATA, not of missing reachability: nothing is reached from
 *      anywhere by construction, so "no route imports this file" would be
 *      true of every file in the project and would mean nothing. This is not
 *      a hypothetical shape — `surfaceRepo`'s `EMPTY_SNAPSHOT` backfills
 *      `imports: []` onto every snapshot persisted before import edges
 *      existed, so without this gate anyone who ran `map_attack_surface`
 *      before that and `validate_finding` after it is told, confidently,
 *      that nothing in their codebase is reachable. Checked FIRST because it
 *      is the most fundamental and its remedy is the most actionable. It
 *      does not touch the positive direction either: a finding in a file
 *      that itself declares a route still reads `reachable` at 0 hops, which
 *      needs no edge at all.
 *   2. The finding has a `file_path` and its language is determinable. No
 *      file, no query — that half is checked before even gate 1, since with
 *      no file there is nothing to query in the first place. An unrecognised
 *      extension means there is nothing to trust a per-language coverage
 *      entry (gate 3), a runtime-resolution flag (gate 4) or a per-language
 *      edge count (gate 6) against — but it
 *      does NOT block the positive direction: reachability is computed from
 *      the file path alone, before language is even consulted, so a
 *      discovered path still reads `reachable`.
 *   3. The snapshot's per-language `CoverageEntry.status` is `ok` or
 *      `no_matches`. `unreachable` is a claim about the WHOLE route list for
 *      that language, so it is unsound when that list is known to be
 *      partial (`no_rules`, `unreadable`) — or entirely absent, which is
 *      treated the same as partial, not as permissive. `no_matches` is
 *      deliberately included: the rules ran and this language genuinely
 *      declares no routes, so no route in it can reach anything. Excluding
 *      it would answer `unknown` for every file in any language with no HTTP
 *      surface, which is most of them in most repositories.
 *   4. The language is not one of `RUNTIME_RESOLUTION_LANGUAGES` (Ruby,
 *      Java, C#, PHP). Those four resolve code at runtime — autoload,
 *      annotation-driven injection, a DI container — not by import, so
 *      "nothing imports this file" is true of nearly every file in them and
 *      proves nothing. The positive direction still applies: a discovered
 *      import edge is evidence regardless of the language's resolution
 *      story, so these four stacks can still read `reachable`, only never
 *      `unreachable`.
 *   5. The graph was not truncated (`ImportGraph.truncated`). A cut graph
 *      has unknown missing edges; asserting an absence from it would be
 *      indistinguishable from asserting an absence because nobody looked.
 *   6. The finding's language contributed at least one RESOLVED edge to the
 *      graph, whenever `CoverageEntry.unresolved_imports` for it is non-zero.
 *      Gate 1's reasoning, one language down, and it is not hypothetical
 *      either: `map_attack_surface` shipped handing the module-edge resolvers
 *      absolute paths while every candidate they build from an import
 *      specifier is project-relative, so Python, Go and Rust resolved
 *      nothing — and every finding in those three languages read
 *      `unreachable` against a graph that had never held one of their edges.
 *      Gate 1 could not see it (JS/TS resolved, so the graph was non-empty)
 *      and gate 3 could not either (route extraction was fine, so coverage
 *      said `ok`). Zero resolved edges alongside imports that DID fail to
 *      resolve means the graph has no coverage of the language, and a broken
 *      resolver is indistinguishable from a genuinely unreferenced file.
 *      Both halves are required: gating on `unresolved_imports > 0` alone
 *      would delete the negative verdict in every project with dependencies
 *      (see the note below), and gating on "no edges in this language" alone
 *      would delete it for every language whose files genuinely import
 *      nothing — where zero resolved AND zero unresolved is a complete
 *      picture, not a hole. Checked last of the six; see
 *      `negativeVerdictBlockedBy` for why.
 *
 * `CoverageEntry.unresolved_imports` is reported whenever it is non-zero for
 * the finding's language — on every verdict, including `reachable` — but
 * does NOT gate `unreachable`. That count is dominated by ordinary, harmless
 * cases (third-party and stdlib specifiers such as 'express' or 'os' — see
 * that field's own doc comment in ../types.ts), so most real files in most
 * real languages would show a non-zero value; gating on it would make the
 * negative verdict practically unreachable in any project with real
 * dependencies, defeating the point of building it. Reporting it
 * unconditionally instead keeps the design's promise — "every cap,
 * truncation and uncovered language is reported, never silently applied" —
 * without over-blocking.
 *
 * Purity: no I/O, no clock, no randomness. `computedAt` is injected by the
 * caller; this module never calls `Date.now()`.
 *
 * Path conventions: `snapshot.imports` and every `ImportGraph` node are
 * project-relative POSIX (Task 3b relativizes them before they ever reach
 * this module). `snapshot.routes[].file` is NOT — `toRoute()`
 * (surface/extract.ts) assigns Semgrep's absolute, native-separator path
 * verbatim, and nothing upstream fixes it, because the previous consumer
 * (Node mount resolution) never needed to compare it against anything else.
 * This module is the first thing that roots a graph traversal at a route
 * file, so it is the first thing that breaks if the two sides disagree: an
 * unrelativized root never string-equals any graph key, `reachFrom` finds no
 * path from ANY root, and every verdict comes back `unreachable` or
 * `unknown` — universally, silently, no error anywhere, regardless of what
 * the code actually imports. `projectPath` exists on `StaticProviderInput` so
 * this module can run every route file — and, defensively, every finding's
 * `file_path` — through the identical `toRelativeIfPossible` helper Task 3b
 * already uses for `imports`, so the two sides agree by construction rather
 * than by two implementations happening to concur today.
 *
 * `anonymouslyExposedRouteFiles` carries the SAME disease as `route.file`,
 * one field narrower, and it is not hypothetical: `dast/analyze.ts` builds a
 * `scan_dast` finding's `file_path` as `route.file` verbatim (no
 * `toRelativeIfPossible` anywhere in that path), so a real
 * `anonymouslyExposedRouteFiles` set — built from persisted findings whose
 * `file_path` traces back to a route — is absolute, native-separator, the
 * same convention `route.file` has and NOT the "established convention"
 * every `scan_sast` parser follows for an ordinary `Finding.file_path`. This
 * module relativizes it too, for the same reason and with the same
 * `projectPath`, before ever comparing it against `reachingRoots`.
 */
import { toRelativeIfPossible } from '../runners/scannerParsers/index.js';
import { reachFrom } from './importGraph.js';
/**
 * Languages whose code is resolved at runtime — autoload convention (Ruby),
 * annotation-driven injection (Java/Spring), a DI container (C#/ASP.NET), or
 * a service container (PHP/Laravel) — not by static import. Design doc §5.3:
 * in each of these, "nothing imports this file" is true of nearly every file
 * and proves nothing, so `unreachable` is never emitted for a file in one of
 * them. The positive direction is unaffected — see the module doc comment.
 */
export const RUNTIME_RESOLUTION_LANGUAGES = new Set([
    'ruby',
    'java',
    'csharp',
    'php',
]);
export function validateStatically(input) {
    const routesByFile = groupRoutesByRelFile(input.snapshot.routes, input.projectPath);
    const roots = [...routesByFile.keys()];
    const exposedFiles = relativizeSet(input.anonymouslyExposedRouteFiles, input.projectPath);
    const reachCache = new Map();
    const languagesWithEdges = languagesWithResolvedEdges(input);
    const context = { roots, routesByFile, exposedFiles, reachCache, languagesWithEdges };
    return input.findings.map((finding) => validateOne(finding, input, context));
}
/**
 * The languages the graph can actually say anything about: those with at
 * least one resolved edge leaving a file of that language.
 *
 * Keyed on the edge's SOURCE file, matching how `buildCoverage`
 * (mapAttackSurface.ts) buckets `unresolved_imports` — an edge is attributed
 * to the language of the file that WROTE the import, so the resolved and
 * unresolved counts gate 6 compares are counts of the same population.
 *
 * Read from the graph rather than from `snapshot.imports`, because the graph
 * is what an absent path is measured against: an edge dropped at the
 * truncation cap is missing from the traversal whether or not the snapshot
 * still lists it.
 */
function languagesWithResolvedEdges(input) {
    const languages = new Set();
    for (const [file, targets] of input.graph.edges) {
        if (targets.size === 0)
            continue;
        const language = input.languageOf(file);
        if (language !== null)
            languages.add(language);
    }
    return languages;
}
/**
 * `anonymouslyExposedRouteFiles` carries the same absolute, native-separator
 * convention `route.file` does (see `StaticProviderInput`'s doc comment) —
 * relativized HERE, once per call, rather than per finding, and with the
 * identical `toRelativeIfPossible`/`projectPath` pair `groupRoutesByRelFile`
 * uses for routes, so a route's file and its exposure record agree on the
 * same key by construction.
 */
function relativizeSet(files, projectPath) {
    return new Set([...files].map((file) => toRelativeIfPossible(file, projectPath)));
}
/**
 * Groups CODE-provenance routes by their project-relative POSIX file — the
 * map's keys double as the deduplicated reachability root set, which is also
 * an amortization: several routes registered in the same file (or the same
 * router file re-mounted) cost `reachFrom` one root, not several.
 *
 * Spec-provenance routes are excluded: a spec route's `file` is the spec
 * document, which never participates in a code import graph, so treating it
 * as a root would be a category error — the same routes-vs-specs distinction
 * `buildCoverage` in mapAttackSurface.ts already makes, for the adjacent
 * reason that spec routes carry no language the rule pack could ever cover.
 */
function groupRoutesByRelFile(routes, projectPath) {
    const byFile = new Map();
    for (const route of routes) {
        if (route.provenance !== 'code')
            continue;
        const relFile = toRelativeIfPossible(route.file, projectPath);
        const existing = byFile.get(relFile);
        if (existing === undefined)
            byFile.set(relFile, [route]);
        else
            existing.push(route);
    }
    return byFile;
}
function makeEnvelope(finding, input) {
    return {
        fingerprint: finding.fingerprint,
        provider: 'static',
        snapshot_id: input.snapshotId,
        tree_hash: input.treeHash,
        computed_at: input.computedAt,
    };
}
function validateOne(finding, input, context) {
    const envelope = makeEnvelope(finding, input);
    if (finding.file_path === undefined) {
        return unknownVerdict(envelope, ['finding has no file_path; nothing to evaluate']);
    }
    const relFile = toRelativeIfPossible(finding.file_path, input.projectPath);
    const { language, entry, gaps } = resolveLanguageContext(relFile, input);
    const reach = cachedReachFrom(input.graph, context.roots, relFile, context.reachCache);
    if (reach.hops !== null) {
        return reachableVerdict(envelope, reach.hops, reach.reachingRoots, context.routesByFile, context.exposedFiles, gaps);
    }
    // Gate 1, checked before everything else that could block the negative
    // verdict — including the language, whose absence is a fact about one file
    // while this is a fact about the whole run. Deliberately "no edges AT ALL",
    // never "no edge reaching this file": the latter is the definition of an
    // orphan, so gating on it would make `unreachable` unobtainable and delete
    // the strongest output this provider has.
    if (hasNoEdges(input.graph)) {
        return unknownVerdict(envelope, [EMPTY_GRAPH_GAP, ...gaps]);
    }
    if (language === null) {
        return unknownVerdict(envelope, [`could not determine the language of '${relFile}'`, ...gaps]);
    }
    const blocked = negativeVerdictBlockedBy(language, entry, input.graph.truncated, context.languagesWithEdges.has(language));
    if (blocked !== null)
        return unknownVerdict(envelope, [blocked, ...gaps]);
    return unreachableVerdict(envelope, relFile, gaps);
}
/**
 * Gate 1's message. Names both causes because they need different actions:
 * the first is fixed by re-running one tool, the second is a property of the
 * project (or a hole in the rule pack) that no re-run will change.
 */
const EMPTY_GRAPH_GAP = 'the import graph holds no import edges at all, so it is evidence of missing DATA rather than ' +
    'of missing reachability — every file would be unreached by construction. Either the surface ' +
    'snapshot predates the persistence of import edges (re-run map_attack_surface) or no import ' +
    'rule in the pack matched this project.';
/**
 * True when the graph contains no edge whatsoever.
 *
 * Counts members rather than testing `edges.size === 0`. `buildImportGraph`
 * never stores an empty target set, so today the two agree — but this is the
 * guard against a project-wide false negative, and it must not stop firing
 * because some future producer of an `ImportGraph` (or a hand-built one in a
 * test) records a key with no targets.
 */
function hasNoEdges(graph) {
    for (const targets of graph.edges.values()) {
        if (targets.size > 0)
            return false;
    }
    return true;
}
/** Looks up the finding's language and, when known, its coverage entry and
 *  the (always-reported, never-blocking) unresolved-imports note. */
function resolveLanguageContext(relFile, input) {
    const language = input.languageOf(relFile);
    if (language === null)
        return { language: null, entry: undefined, gaps: [] };
    const entry = input.snapshot.coverage.find((c) => c.language === language);
    const gaps = entry === undefined ? [] : unresolvedImportsGap(language, entry);
    return { language, entry, gaps };
}
/** Non-blocking transparency note — see the module doc comment for why this
 *  is reported rather than gating `unreachable`. */
function unresolvedImportsGap(language, entry) {
    if (entry.unresolved_imports === 0)
        return [];
    return [
        `${entry.unresolved_imports} import(s) for '${language}' could not be resolved to a project ` +
            'file (third-party/stdlib specifiers or an unresolvable dynamic import) and are absent from the graph',
    ];
}
/**
 * The first of gates 3–6 (see the module doc comment) that blocks
 * `unreachable` for `language`, or `null` when all four hold. Gates 1 (a
 * non-empty graph) and 2 (a file_path with a determinable language) are
 * handled by the caller before this is ever invoked.
 *
 * ORDER. Gate 6 is checked LAST, even though its reasoning is the broadest,
 * because it overlaps with gates 3 and 4 and its message is the least
 * specific of the three. Java, C#, Ruby and PHP resolve zero imports BY
 * DESIGN, so gate 6 fires for every finding in them — and would replace gate
 * 4's permanent, accurate cause ("this stack resolves code at runtime") with
 * one that reads like a fixable coverage hole no re-run can close.
 */
function negativeVerdictBlockedBy(language, entry, graphTruncated, languageHasResolvedEdges) {
    if (entry === undefined) {
        return `no coverage entry was recorded for language '${language}'`;
    }
    if (entry.status !== 'ok' && entry.status !== 'no_matches') {
        return `coverage for '${language}' is '${entry.status}', so its route list cannot be trusted as complete`;
    }
    if (RUNTIME_RESOLUTION_LANGUAGES.has(language)) {
        return `'${language}' resolves code at runtime (autoload/DI container/injection), not by static import — an absent path proves nothing here`;
    }
    if (graphTruncated) {
        return 'the import graph was truncated at its edge cap, so it cannot certify the absence of any path';
    }
    if (!languageHasResolvedEdges && entry.unresolved_imports > 0) {
        return (`no import edge in '${language}' resolved to a project file, while ` +
            `${entry.unresolved_imports} did not — the graph holds no coverage of this language at all, ` +
            'so an absent path here is missing DATA rather than evidence of missing reachability. ' +
            'Every file in this language would read as imported by nothing, which is what a broken ' +
            'resolver and a genuinely unreferenced file look like alike.');
    }
    return null;
}
/**
 * `reachFrom` costs O(roots × graph) per call — cheap once, expensive across
 * a whole findings batch if invoked per finding without amortizing: N
 * findings over the same root set would cost O(findings × roots × graph)
 * (flagged in Task 2's review). Several findings sharing a file — the norm,
 * not the exception — then need only one BFS pass between them, so this
 * caches by target file rather than changing `reachFrom` itself.
 */
function cachedReachFrom(graph, roots, target, cache) {
    const cached = cache.get(target);
    if (cached !== undefined)
        return cached;
    const result = reachFrom(graph, roots, target);
    cache.set(target, result);
    return result;
}
function unreachableVerdict(envelope, relFile, gaps) {
    return {
        ...envelope,
        verdict: 'unreachable',
        confidence: 'medium', // a claim about an over-approximating graph, never 'high'
        evidence: [{ detail: `no route imports '${relFile}', directly or transitively` }],
        coverage_gaps: [...gaps],
    };
}
function unknownVerdict(envelope, gaps) {
    return { ...envelope, verdict: 'unknown', confidence: 'low', evidence: [], coverage_gaps: gaps };
}
function reachableVerdict(envelope, hops, reachingRoots, routesByFile, exposedFiles, gaps) {
    const nearestFile = reachingRoots[0];
    if (nearestFile === undefined) {
        // reachFrom only returns a non-null hop count alongside a non-empty
        // reachingRoots (see importGraph.ts's reachFrom) — unreachable in
        // practice, guarded rather than asserted with `!` per house style.
        return unknownVerdict(envelope, [...gaps, 'reachability result was inconsistent: hops without a reaching root']);
    }
    return {
        ...envelope,
        verdict: 'reachable',
        confidence: hops === 0 ? 'high' : 'medium',
        evidence: buildReachableEvidence(hops, nearestFile, reachingRoots, routesByFile, exposedFiles),
        coverage_gaps: [...gaps],
    };
}
/** Design §7: the nearest reaching route with its method, resolved path and
 *  hop count; how many routes reach the file in total; and — only when the
 *  input actually supplied one — a confirmed anonymous exposure. Concrete
 *  facts, never a score. */
function buildReachableEvidence(hops, nearestFile, reachingRoots, routesByFile, exposedFiles) {
    const evidence = [];
    const nearestRoute = routesByFile.get(nearestFile)?.[0];
    if (nearestRoute !== undefined) {
        evidence.push({
            detail: `reachable in ${hopWord(hops)} via ${nearestRoute.method} ${nearestRoute.path_resolved} (${nearestFile})`,
        });
    }
    const totalReaching = reachingRoots.reduce((sum, root) => sum + (routesByFile.get(root)?.length ?? 0), 0);
    const totalRoutes = [...routesByFile.values()].reduce((sum, rs) => sum + rs.length, 0);
    evidence.push({ detail: `reached by ${totalReaching} of ${totalRoutes} known route(s)` });
    const exposed = exposedEvidence(reachingRoots, routesByFile, exposedFiles);
    if (exposed !== null)
        evidence.push(exposed);
    return evidence;
}
/**
 * Never states a route is NOT anonymously exposed — that would assert the
 * inverse of "the input did not say". Absent a match, this contributes
 * nothing to the evidence list at all.
 */
function exposedEvidence(reachingRoots, routesByFile, exposedFiles) {
    const exposedFile = reachingRoots.find((root) => exposedFiles.has(root));
    if (exposedFile === undefined)
        return null;
    const route = routesByFile.get(exposedFile)?.[0];
    const label = route === undefined ? exposedFile : `${route.method} ${route.path_resolved} (${exposedFile})`;
    return { detail: `${label} is confirmed anonymously exposed by a live scan` };
}
function hopWord(hops) {
    return hops === 1 ? '1 hop' : `${hops} hops`;
}
//# sourceMappingURL=staticProvider.js.map