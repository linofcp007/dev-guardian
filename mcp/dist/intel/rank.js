/**
 * Pure exploitability ranking — no storage, no network, no I/O. Used
 * directly by `tools/prioritizeFindings.ts` and `dashboard/risk.ts` (via
 * `tools/riskScore.ts`), and by `create_fix_pr`.
 *
 * ---- Where `create_fix_pr` calls this (Task 24, item 5) ---------------
 *
 * `fixpr/candidates.ts#selectGroups` (which groups the `max_prs` cap keeps)
 * and `#rankCandidates` (the order a group's fixes are applied in) order by
 * severity, then KEV, then EPSS. `cveIdsOf` is the union of `findingCveIds`
 * over the findings a group or candidate targets; `intel` is
 * `intel/enrich.ts#enrichCveIntel`, called once per run over those ids.
 *
 * The composition order matters, and the note this replaces had it
 * backwards: `rankByExploitability` is a stable sort by exploitability
 * ALONE, so calling it AFTER a severity sort makes exploitability the
 * primary key (an exploited high jumps every ordinary critical). To keep
 * KEV/EPSS a tie-break within each severity band, it runs FIRST and the
 * stable severity sort after it (`candidates.ts#bySeverityThenExploitability`).
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
 * their relative order from `items`. To refine each severity band without
 * disturbing it, run this FIRST and a stable severity sort after it — run
 * after a severity sort, it re-orders across bands (see the module
 * comment). Never mutates `items`.
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