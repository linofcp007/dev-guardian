/**
 * Pure exploitability ranking — no storage, no network, no I/O. Used
 * directly by `tools/prioritizeFindings.ts` and `dashboard/risk.ts` (via
 * `tools/riskScore.ts`). `rankByExploitability` is also exported for
 * `create_fix_pr` (Task 11 owns `tools/createFixPr.ts` and `fixpr/*.ts`
 * while this task is in flight — see this module's own header note below
 * for where it should be called once that lands).
 *
 * ---- Where `create_fix_pr` should call this ----------------------------
 *
 * `fixpr/candidates.ts#selectGroups` orders `FixGroup[]` by severity alone
 * before slicing to `max_prs`:
 *
 *   const ordered = [...groups].sort(
 *     (a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity],
 *   );
 *
 * The integrator should call `rankByExploitability(ordered, cveIdsOf, intel)`
 * right after that sort (KEV/EPSS as a tie-break WITHIN each severity band,
 * exactly like `prioritizeFindings.ts` uses it below) — `rankByExploitability`
 * is a stable sort over whatever order it is given, so composing it after the
 * severity sort keeps severity as the primary key and only re-orders equal-
 * severity groups. `cveIdsOf` for a `FixGroup` is the union of `findingCveIds`
 * over the `Finding[]` its candidates target (`createFixPr.ts`'s own
 * `findingsForGroup(allFindings, group)` already computes that finding list).
 * `intel` is this task's `intel/enrich.ts#enrichCveIntel`, called once over
 * every open finding's correlated CVE ids before `selectGroups` runs.
 */
const CVE_ID_RE = /CVE-\d{4}-\d+/gi;
const CVE_ID_ONLY_RE = /^CVE-\d{4}-\d+$/i;
/**
 * The CVE id(s) a `Finding` is about, best-effort given the existing data
 * model — there is no stored `finding -> cve_id` foreign key (a `Finding`
 * and its `scan_cves` rows are correlated only by scan + package, not by
 * fingerprint; see `runners/scannerParsers/*.ts`'s own comments). Reliable
 * for `tool: 'trivy'` (`rule_id` IS the CVE id, always) and for `wpscan`
 * when the vulnerability has one (`rule_id` is the first CVE, else the
 * title). Falls back to scanning `title`/`message` for an embedded
 * `CVE-YYYY-NNNN`, which additionally covers npm-audit v1 and pip-audit
 * advisories that mention one in prose.
 *
 * KNOWN GAP: npm-audit's v2 parser (`mapV2Advisory`) records no CVE at all
 * for a finding, even when the underlying advisory has one — its `cves[]`
 * output is only ever populated on the v1 path
 * (`runners/scannerParsers/npmAudit.ts`). Those findings are simply never
 * correlated here and never gain an exploitability boost; fixing that needs
 * a stored finding-CVE link, out of this task's scope.
 */
export function findingCveIds(finding) {
    const ids = new Set();
    if (finding.rule_id !== undefined && CVE_ID_ONLY_RE.test(finding.rule_id)) {
        ids.add(finding.rule_id.toUpperCase());
    }
    for (const text of [finding.title, finding.message]) {
        if (text === undefined)
            continue;
        for (const match of text.matchAll(CVE_ID_RE))
            ids.add(match[0].toUpperCase());
    }
    return [...ids];
}
/**
 * Tools whose findings are vulnerability-shaped and may legitimately carry a
 * CVE — the same set `fixpr/candidates.ts#DEP_SCANNER_TOOLS` treats as
 * "dependency-upgrade-fixable", plus `pip-audit` (whose parser records a
 * `cve_id` on `cves[]` the same way, per `runners/scannerParsers/pipAudit.ts`).
 * Used only to decide whether a finding with NO extracted CVE (see
 * `isUncorrelatedFinding`) is a real coverage gap or an ordinary
 * code-quality finding that was never expected to have one.
 */
export const CVE_CAPABLE_TOOLS = ['trivy', 'npm-audit', 'wpscan', 'pip-audit'];
/**
 * True for a finding from a {@link CVE_CAPABLE_TOOLS} scanner that
 * {@link findingCveIds} could not extract a CVE id from at all — a real
 * advisory dev-guardian cannot yet weigh by KEV/EPSS (review round 1,
 * Important #2), not an ordinary finding that was never expected to have
 * one. The main source today: npm-audit's v2 parser (`mapV2Advisory`,
 * `runners/scannerParsers/npmAudit.ts`) records no CVE at all for a
 * finding even when the underlying advisory has one — `rule_id` is a
 * GHSA id or advisory URL instead. `prioritize_findings` and `risk_score`
 * both surface a COUNT of these (never silently drop them from the
 * boost — a finding that cannot be weighted is reported as such, not
 * left unexplained).
 */
export function isUncorrelatedFinding(finding) {
    return CVE_CAPABLE_TOOLS.includes(finding.tool) && findingCveIds(finding).length === 0;
}
/** Combines every correlated CVE's intel into one signal for ranking. */
export function exploitabilitySignal(cveIds, intel) {
    let kev = false;
    let maxEpss = null;
    const contributed = [];
    for (const id of cveIds) {
        const entry = intel.get(id);
        if (entry === undefined || entry.status !== 'ok')
            continue;
        let matters = false;
        if (entry.kev) {
            kev = true;
            matters = true;
        }
        if (entry.epss_score !== undefined) {
            if (maxEpss === null || entry.epss_score > maxEpss)
                maxEpss = entry.epss_score;
            matters = true;
        }
        if (matters)
            contributed.push(id);
    }
    return { kev, max_epss: maxEpss, cve_ids: contributed };
}
/**
 * A stable re-sort of `items` by exploitability alone: KEV-backed items
 * first, then descending EPSS, ties (including "no signal at all") keeping
 * their relative order from `items` — so composing this after an existing
 * severity sort refines each severity band without disturbing it. Never
 * mutates `items`.
 */
export function rankByExploitability(items, cveIdsOf, intel) {
    const signals = items.map((item) => exploitabilitySignal(cveIdsOf(item), intel));
    return items
        .map((item, index) => ({ item, index }))
        .sort((a, b) => {
        const sa = signals[a.index];
        const sb = signals[b.index];
        /* istanbul ignore next -- signals has one entry per item; both indices are always in range */
        if (sa === undefined || sb === undefined)
            return 0;
        if (sa.kev !== sb.kev)
            return sa.kev ? -1 : 1;
        const ea = sa.max_epss ?? -1;
        const eb = sb.max_epss ?? -1;
        if (ea !== eb)
            return eb - ea;
        return a.index - b.index;
    })
        .map((x) => x.item);
}
//# sourceMappingURL=rank.js.map