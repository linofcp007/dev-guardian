/**
 * Turn import records into a directed file graph, and measure hops from a
 * root set to a target file.
 *
 * This module knows nothing about findings, verdicts, routes or languages —
 * it turns `ImportRecord[]` into adjacency and answers "how many hops, from
 * which roots". A later stage applies judgment to that measurement; this one
 * only supplies it.
 *
 * The graph is file-level, not call-level, because that is the ceiling of
 * what an import record can honestly claim: `a.ts` imports `b.ts` says
 * nothing about whether anything in `a.ts` actually calls into `b.ts`, or
 * whether the call is behind a branch that never fires. That is the
 * asymmetry the rest of the `validate_finding` feature is built on: an
 * import graph is far better at DISPROVING reachability than proving it.
 * "Nothing imports this file, transitively" is a strong claim — no edge
 * exists from any root, under any path, full stop. "It is imported,
 * therefore the vulnerability is reachable" is weak, because importing is
 * not calling. Callers must only spend this module's answer on the negative
 * direction; the positive direction is evidence, never proof.
 */
/**
 * Upper bound on distinct edges an `ImportGraph` will hold. A repository
 * large enough to hit this is rare, but silently dropping the overflow would
 * let `reachFrom` report "unreached" from a graph that is quietly
 * incomplete — the one wrong answer this feature exists to prevent. Callers
 * see the cut via `ImportGraph.truncated` instead of guessing at it.
 */
export const MAX_GRAPH_EDGES = 20000;
/**
 * Builds directed edges importer → imported. Duplicate records — the same
 * file importing the same module under two different bound symbols — collapse
 * to one edge and do not consume the cap: `MAX_GRAPH_EDGES` bounds the shape
 * of the graph, not the volume of records fed into it.
 */
export function buildImportGraph(records) {
    const edges = new Map();
    const files = new Set();
    let edgeCount = 0;
    let truncated = false;
    for (const record of records) {
        files.add(record.file);
        files.add(record.module_file);
        const existing = edges.get(record.file);
        if (existing !== undefined && existing.has(record.module_file))
            continue;
        if (edgeCount >= MAX_GRAPH_EDGES) {
            truncated = true;
            continue;
        }
        if (existing === undefined) {
            edges.set(record.file, new Set([record.module_file]));
        }
        else {
            existing.add(record.module_file);
        }
        edgeCount += 1;
    }
    return { edges, files, truncated };
}
/**
 * Shortest directed hop count from `root` to `target`, or `null` when no
 * path exists. Breadth-first, one level (`frontier`) at a time, with a
 * `visited` set recording every file the instant it is first discovered:
 * without `visited`, a cycle (`a` imports `b`, `b` imports `a`) walks
 * forever; with one but walked depth-first, a real but longer path can be
 * reported before the true shortest one. Level-synchronous BFS cannot make
 * that mistake — every file in `frontier` at the top of a pass is already at
 * exactly `hops` edges from `root`, so the first time `target` turns up
 * among a frontier's neighbours, that hop count is the minimum by
 * construction, not by luck.
 */
function shortestDistance(graph, root, target) {
    if (root === target)
        return 0;
    const visited = new Set([root]);
    let frontier = [root];
    let hops = 0;
    while (frontier.length > 0) {
        hops += 1;
        const next = [];
        for (const file of frontier) {
            const imported = graph.edges.get(file);
            if (imported === undefined)
                continue;
            for (const candidate of imported) {
                if (candidate === target)
                    return hops;
                if (visited.has(candidate))
                    continue;
                visited.add(candidate);
                next.push(candidate);
            }
        }
        frontier = next;
    }
    return null;
}
/**
 * How many hops separate the nearest root from `target`, and which roots
 * reach it at all, nearest first. Each root is walked independently: `hops`
 * and `reachingRoots` answer two different questions ("how close is the
 * closest one" and "who reaches it, in what order"), and a root that is
 * merely farther than another must not be dropped from the list — a later
 * stage reports "reached by 3 of 40 routes, nearest at 2 hops" from exactly
 * this, and a dropped far root would undercount it.
 */
export function reachFrom(graph, roots, target) {
    const found = [];
    for (const root of roots) {
        const hops = shortestDistance(graph, root, target);
        if (hops !== null)
            found.push({ root, hops });
    }
    if (found.length === 0)
        return { hops: null, reachingRoots: [] };
    // Nearest first, name as the tie-break so two equally-near roots come out
    // in the same order every time — a later task persists this order, and an
    // unstable one would churn a stored verdict for code that never changed.
    found.sort((a, b) => a.hops - b.hops || a.root.localeCompare(b.root));
    return {
        hops: Math.min(...found.map((f) => f.hops)),
        reachingRoots: found.map((f) => f.root),
    };
}
//# sourceMappingURL=importGraph.js.map