/**
 * `risk_score` — single 0–100 number summarising the project's current risk
 * posture, plus a breakdown.
 *
 * The weights, caps, bands and recommendation strings live in the pure
 * `scoreRisk` (`dashboard/risk.ts`), shared with the local dashboard. This
 * handler's job is only to gather this tool's inputs and hand them off:
 *   - `findings.listOpen()` — the latest completed scan in the WHOLE
 *     database, from ANY project. That is deliberate here: this tool takes
 *     no `project_path`, so "whatever this server last scanned" is its
 *     contract, the same one `scans.getLatest()` documents. A caller that HAS
 *     resolved a project path (the dashboard) must use the `ForProject`
 *     repository variants instead — see `findingsRepo.ts`'s doc comment.
 *   - the latest deps-flavoured scan's active CVEs.
 *   - compliance signals (missing policy docs, missing dependency bots).
 *   - the active baseline's age.
 *
 * Output is a JSON `{ score, band, components, recommended_next_action }`.
 * Read-only — does not spawn scanners.
 */
import { scoreRisk } from '../dashboard/risk.js';
import { registerToolModule } from './index.js';
const tool = {
    name: 'risk_score',
    title: 'Risk score (0-100)',
    description: 'Compute a single 0-100 risk score from the project\'s persisted scans/findings/CVEs/baseline. ' +
        'Returns the score, a band (low/medium/high/critical), per-component breakdown, and the next ' +
        'action the model should recommend. Pure read.',
    inputSchema: {},
    handler: async (_input, ctx) => handler(ctx),
};
registerToolModule(tool);
async function handler(ctx) {
    const open = ctx.storage.findings.listOpen();
    // CVEs — use the latest deps-flavoured scan as the source.
    const latestDeps = findLatestOfType(ctx, ['deps', 'security_full']);
    const cves = latestDeps ? ctx.storage.cves.listActive(latestDeps.scan_id) : [];
    // Compliance signals — missing policy docs and CI dependency bots.
    const latestCompliance = findLatestOfType(ctx, ['compliance']);
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
    const latestDepsAudit = findLatestOfType(ctx, ['deps']);
    if (latestDepsAudit?.meta) {
        const m = latestDepsAudit.meta;
        const bot = m.bot_configured ?? {};
        dependencyBotConfigured = Boolean(bot.renovate || bot.dependabot);
    }
    // Baseline freshness.
    const baseline = ctx.storage.baselines.getActive();
    const result = scoreRisk({
        findings: open,
        cves,
        policies_missing: policiesMissing,
        dependency_bot_configured: dependencyBotConfigured,
        baseline_set_at: baseline ? baseline.set_at : null,
        coverage_partial: false,
        now: Date.now(),
    });
    return {
        ok: true,
        score: result.score,
        band: result.band,
        components: result.components,
        recommended_next_action: result.next_action,
    };
}
function findLatestOfType(ctx, types) {
    const history = ctx.storage.scans.listHistory(50);
    const found = history.find((s) => s.status === 'completed' && types.includes(s.scan_type));
    return found ? ctx.storage.scans.getById(found.scan_id) : null;
}
//# sourceMappingURL=riskScore.js.map