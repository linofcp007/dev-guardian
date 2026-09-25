/**
 * Merging findings from several scans into one list — the one place that
 * decides when two findings are "the same".
 *
 * Today that is the fingerprint (tool, rule, path, lines, snippet). A
 * line-independent identity is being introduced alongside it; when a finding
 * carries one, change {@link findingMergeKey} and every merge follows.
 */
/** What two findings must share to be one finding in a merged list. */
export function findingMergeKey(f) {
    return f.fingerprint;
}
/** `findings` in order, keeping the first of each {@link findingMergeKey}. */
export function dedupeFindings(findings) {
    const seen = new Set();
    const out = [];
    for (const f of findings) {
        const key = findingMergeKey(f);
        if (seen.has(key))
            continue;
        seen.add(key);
        out.push(f);
    }
    return out;
}
//# sourceMappingURL=findingMerge.js.map