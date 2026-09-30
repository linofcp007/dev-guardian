/**
 * `risk_score` — single 0–100 number summarising ONE project's current risk
 * posture, plus a breakdown.
 *
 * The weights, caps, bands and recommendation strings live in the pure
 * `scoreRisk` (`dashboard/risk.ts`), shared with the local dashboard. This
 * handler's job is only to gather this tool's inputs for `project_path`
 * (default: the server's working directory) and hand them off:
 *   - the project's open set (`history/openSet.ts`) — every state scan
 *     type's newest usable scan, deduplicated, suppressions removed. It used
 *     to read the single latest completed scan in the WHOLE database, so an
 *     SBOM generated after a SAST scan scored the project as clean, and any
 *     other project's scan answered for this one;
 *   - the newest usable deps-flavoured scan's active CVEs, weighted by CISA
 *     KEV / FIRST EPSS (Task 19, `intel/enrich.ts`) — cached 24h, timeout-
 *     bounded, `GUARDIAN_OFFLINE=1` skips it. A CVE the network could not
 *     measure this call contributes NO exploitability bonus (never a
 *     fabricated "not exploited"); `coverage.cve_intel` below reports how
 *     many of `active_cves` that was true for, so a caller can tell "no KEV
 *     CVEs" apart from "KEV status unmeasured for every CVE";
 *   - compliance signals (missing policy docs, missing dependency bots);
 *   - the project's active baseline's age;
 *   - the REAL coverage of all of the above: `coverage_caveat` is true when
 *     the open set is partial or empty, or no CVE source exists. It was a
 *     literal `false`.
 *
 * Every "latest scan of type X" is a project-scoped SQL query; none searches
 * a window of the 50 newest rows in the database any more.
 *
 * Read-only over scan/finding/CVE history — the one network dependency is
 * the CVE intel refresh above, itself best-effort and never scan-blocking.
 */
import { scoreRisk } from '../dashboard/risk.js';
import { findLatestUsable, openSetForProject } from '../history/openSet.js';
import { enrichCveIntel } from '../intel/enrich.js';
import { isUncorrelatedFinding } from '../intel/rank.js';
import { resolveProjectPath } from '../platform/projectPath.js';
import { ProjectPath } from '../schemas.js';
import { CVE_SOURCE_SCAN_TYPES, isDepsAuditScan } from '../types.js';
import { registerToolModule } from './index.js';
const tool = {
    name: 'risk_score',
    title: 'Risk score (0-100)',
    description: 'Compute a single 0-100 risk score for one project (project_path, default: the server\'s ' +
        'working directory) from its persisted scans/findings/CVEs/baseline. Open findings are the ' +
        'union of the newest usable scan of every finding-producing type, suppressions removed. CVEs ' +
        'are weighted up when CISA KEV-listed or high FIRST EPSS (cached 24h, offline-safe). Returns ' +
        'the score, a band (low/medium/high/critical), per-component breakdown, the next action to ' +
        'recommend, and `coverage` — which scans it read, which newer scans it skipped because they ' +
        'measured nothing, `coverage.cve_intel` (KEV/EPSS measured vs unavailable, plus `uncorrelated`: ' +
        'findings from a CVE-capable scanner with no extractable CVE id, e.g. npm-audit v2), and ' +
        '`coverage_caveat` when the numbers are incomplete. `suppressed_count`: findings an active ' +
        'suppression took out of the score — a mass suppression shows here, never as a clean project. ' +
        '`future_dated_note` when scans dated in the future were ignored.',
    inputSchema: { project_path: ProjectPath },
    handler: async (input, ctx) => handler(input, ctx),
};
registerToolModule(tool);
async function handler(input, ctx) {
    const inp = input;
    let projectPath;
    try {
        projectPath = resolveProjectPath(inp.project_path).path;
    }
    catch (e) {
        return { ok: false, error: { code: 'not_a_git_repo', message: e.message } };
    }
    const now = Date.now();
    const storage = ctx.storage;
    const open = openSetForProject(storage, projectPath, { now });
    // CVEs — the newest deps-flavoured scan that actually measured dependencies
    // (a security_full run is judged on its trivy half only).
    const cveSource = findLatestUsable(storage, projectPath, CVE_SOURCE_SCAN_TYPES, { slot: 'deps' });
    const cves = cveSource.scan ? storage.cves.listActive(cveSource.scan.scan_id) : [];
    const cveIntel = await enrichCveIntel(storage, cves.map((c) => c.cve_id));
    const cveIntelCoverage = summariseCveIntel(cves, cveIntel, open.findings);
    // Compliance signals — missing policy docs and CI dependency bots. Both are
    // read from files, not scanner output, so a run's scanner coverage does
    // not disqualify them.
    const latestCompliance = findLatestUsable(storage, projectPath, ['compliance'], {
        skipCoverageNone: false,
    }).scan;
    let policiesMissing = 0;
    if (latestCompliance?.meta) {
        const m = latestCompliance.meta;
        const docs = m.policy_documents_found ?? {};
        for (const key of ['privacy_policy', 'terms_of_service', 'security_policy']) {
            if (docs[key] === false)
                policiesMissing += 1;
        }
    }
    // No deps-audit scan yet ⇒ no signal ⇒ no penalty, matching this tool's
    // pre-extraction behaviour (it used to skip the whole bot check in that case).
    let dependencyBotConfigured = true;
    const latestDepsAudit = findLatestUsable(storage, projectPath, ['deps_audit', 'deps'], {
        skipCoverageNone: false,
        predicate: isDepsAuditScan,
    }).scan;
    if (latestDepsAudit?.meta) {
        const m = latestDepsAudit.meta;
        const bot = m.bot_configured ?? {};
        dependencyBotConfigured = Boolean(bot.renovate || bot.dependabot);
    }
    // Baseline freshness — this project's own.
    const baseline = storage.baselines.getActiveForProject(projectPath);
    const coveragePartial = open.coverage !== 'full' || cveSource.scan === null;
    const result = scoreRisk({
        findings: open.findings,
        cves,
        cve_intel: cveIntel,
        policies_missing: policiesMissing,
        dependency_bot_configured: dependencyBotConfigured,
        baseline_set_at: baseline ? baseline.set_at : null,
        coverage_partial: coveragePartial,
        now,
    });
    return {
        ok: true,
        score: result.score,
        band: result.band,
        components: result.components,
        recommended_next_action: result.next_action,
        coverage_caveat: result.coverage_caveat,
        project_path: projectPath,
        // Findings the scans hold that an active suppression takes out of the
        // score — a mass suppression shows here, never as a clean project.
        suppressed_count: open.suppressed,
        // Scans dated in the future, which every reader ignored (storage/scanClock.ts).
        ...(open.future_dated_note !== undefined ? { future_dated_note: open.future_dated_note } : {}),
        coverage: {
            level: open.coverage,
            sources: open.sources,
            skipped: open.skipped,
            cve_source_scan_id: cveSource.scan?.scan_id ?? null,
            ...(cveSource.scan === null
                ? { cve_gap: 'no dependency scan has measured this project: CVEs are unmeasured, not zero' }
                : {}),
            cve_source_skipped: cveSource.skipped,
            cve_intel: cveIntelCoverage,
        },
    };
}
/** `intel` keyed by `cve_id`, same as `enrichCveIntel` returns — a `cve_id`
 *  absent from it (should not happen; `enrichCveIntel` answers for every id
 *  it is asked about) is treated the same as `status: 'unavailable'`. */
function summariseCveIntel(cves, intel, findings) {
    let kevCount = 0;
    let epssMeasured = 0;
    let unavailable = 0;
    for (const cve of cves) {
        const entry = intel.get(cve.cve_id);
        if (entry === undefined || entry.status !== 'ok') {
            unavailable += 1;
            continue;
        }
        if (entry.kev)
            kevCount += 1;
        if (entry.epss_score !== undefined)
            epssMeasured += 1;
    }
    const uncorrelated = findings.filter(isUncorrelatedFinding).length;
    return {
        active_cves: cves.length,
        kev_count: kevCount,
        epss_measured: epssMeasured,
        unavailable,
        uncorrelated,
        ...(uncorrelated > 0
            ? {
                note: `${uncorrelated} finding(s) come from a CVE-capable scanner but carry no extractable CVE id, ` +
                    'so they cannot be weighted by KEV/EPSS yet.',
            }
            : {}),
    };
}
//# sourceMappingURL=riskScore.js.map