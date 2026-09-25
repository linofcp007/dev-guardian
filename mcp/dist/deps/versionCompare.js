/**
 * Shared, pure version-comparison helpers for the dependency pipeline
 * (`deps_update_plan`'s CVE-merge/npm/pip branches, `pipAudit.ts`'s own
 * fix-version selection). Extracted so both places pick a fix version the
 * same, correct way rather than maintaining two copies that can drift.
 *
 * Fix round 1, CRITICAL item 1: a scanner's "fixed_version" is not always
 * an upgrade. pip-audit lists ONE fix per still-maintained release branch
 * (installed `2.0.1`, `fix_versions: ["1.11.27","2.2.9","3.0.1"]` — `1.11.27`
 * is an OLDER branch's backport, not a fix FOR a 2.0.1 install), and a CVE
 * row can simply be stale (recorded against an older installed version than
 * what is on disk now). Naively taking `fix_versions[0]`, or trusting a
 * stored `fixed_version` without comparing it to the CURRENT installed
 * version, can propose `npm install pkg@<older>` / `pip==<older>` labelled
 * `security` — a downgrade presented as a fix.
 */
/** `1.2.3`, `1.2`, or `1` — optionally `v`-prefixed — and nothing else. The
 *  only shape this module trusts as an installable, comparable version;
 *  anything else (an open range, a comma-separated list of branches, free
 *  text) is treated as "no usable version" by every function below. */
export function isCleanVersion(v) {
    return v !== undefined && /^v?\d+(\.\d+)*$/i.test(v.trim());
}
/**
 * Numeric dotted-segment comparison. Both inputs SHOULD already be clean
 * (`isCleanVersion`) — a non-clean input degrades to a string comparison
 * rather than throwing, so a caller that forgets to gate still gets an
 * answer, just not a numerically meaningful one.
 */
export function compareVersions(a, b) {
    const pa = a.replace(/^v/i, '').split('.').map((n) => parseInt(n, 10));
    const pb = b.replace(/^v/i, '').split('.').map((n) => parseInt(n, 10));
    if (pa.some(Number.isNaN) || pb.some(Number.isNaN))
        return a.localeCompare(b);
    for (let i = 0; i < Math.max(pa.length, pb.length); i += 1) {
        const diff = (pa[i] ?? 0) - (pb[i] ?? 0);
        if (diff !== 0)
            return diff;
    }
    return 0;
}
/**
 * The smallest candidate that is STRICTLY GREATER than `installed` — never
 * equal (a "fix" equal to what is already installed fixes nothing) and
 * never lower (a downgrade). Returns `undefined` when `installed` is not a
 * clean version, no candidate is a clean version above it, or the candidate
 * list is empty: "no safe minimum could be determined" is the caller's cue
 * to skip and report the package as unplanned, never to guess.
 */
export function minCleanVersionAbove(installed, candidates) {
    if (!isCleanVersion(installed))
        return undefined;
    let best;
    for (const c of candidates) {
        if (!isCleanVersion(c))
            continue;
        if (compareVersions(c, installed) <= 0)
            continue; // downgrade or no-op — excluded
        if (best === undefined || compareVersions(c, best) < 0)
            best = c;
    }
    return best;
}
//# sourceMappingURL=versionCompare.js.map