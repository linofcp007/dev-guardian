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
import { findingVulnIds, isCveId } from './vulnIds.js';
/**
 * The CVE id(s) a `Finding` is about: the CVEs among its OWN vulnerability
 * ids — its rule id and the aliases its scanner recorded
 * (`intel/vulnIds.ts#findingVulnIds`). Trivy: the rule id (a CVE whenever
 * one is assigned); pip-audit: the CVE among its OSV aliases; npm audit v1:
 * the advisory's `cves`; WPScan: every CVE of the vulnerability.
 *
 * It used to scan the title and message for any `CVE-YYYY-NNNN` as well,
 * which tied a finding to every CVE its description MENTIONS — and gave it
 * that CVE's KEV/EPSS boost, SSVC exploitation and VEX statements (review of
 * the 3.0 additions, C1). Only own ids now.
 *
 * A CVE id with no package behind it — a nuclei template or a DAST check
 * named by its CVE, which `dependencyCoordinates` cannot place — still gets
 * its KEV/EPSS boost here. That is pre-existing and kept on purpose (final
 * review, M-b): KEV weighs the vulnerability, which such a finding is about.
 * Only VEX needs a package version, so `suppress_finding` and
 * `validate_finding` say such a finding is "not exportable to VEX (no
 * package coordinates)" rather than this module ignoring it.
 *
 * KNOWN GAP: a row stored before migration 014 carries no aliases, so a
 * pip-audit PYSEC finding or an npm-audit advisory from an older scan has no
 * CVE here until the next scan records them — counted by
 * `isUncorrelatedFinding`, never guessed from its text.
 */
export function findingCveIds(finding) {
    return findingVulnIds(finding).filter(isCveId).map((id) => id.toUpperCase());
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
 * `runners/scannerParsers/npmAudit.ts`) — npm's report gives the advisory's
 * GHSA id and never its CVE — and every dependency finding stored before
 * migration 014 recorded aliases. `prioritize_findings` and `risk_score`
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