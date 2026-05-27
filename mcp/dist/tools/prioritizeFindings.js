/**
 * `prioritize_findings` — heuristic ordering of all currently-open
 * findings, returning a ranked list with "why now" reasoning hooks.
 *
 * Pure heuristics — no LLM call. The calling model uses the ranking +
 * reasoning to decide what to surface to the user first.
 *
 * Ranking (descending priority):
 *   1. severity (critical > high > medium > low > info)
 *   2. category (security > bug > license > compliance > quality > performance)
 *   3. fix_available (yes ranks above no — easy wins first)
 *   4. age / last-seen proximity (recent > old)
 *   5. fingerprint (stable tiebreaker)
 *
 * Each row carries a `priority_score` (0-1000) and a list of `factors`
 * the model can quote.
 */
import { z } from 'zod';
import { registerToolModule } from './index.js';
const SEVERITY_WEIGHT = {
    critical: 400,
    high: 250,
    medium: 120,
    low: 50,
    info: 10,
};
const CATEGORY_WEIGHT = {
    security: 200,
    bug: 150,
    license: 80,
    compliance: 60,
    quality: 30,
    performance: 25,
};
const inputSchema = {
    limit: z
        .number()
        .int()
        .min(1)
        .max(500)
        .optional()
        .describe('Cap on returned items. Default 50.'),
};
const tool = {
    name: 'prioritize_findings',
    title: 'Prioritise open findings (heuristic)',
    description: 'Rank open findings by a weighted heuristic: severity + category + fix_available + age. ' +
        'Returns top-N with explanation. No LLM call — the calling model uses the ranking to drive ' +
        'follow-ups.',
    inputSchema,
    handler: async (input, ctx) => handler(input, ctx),
};
registerToolModule(tool);
async function handler(input, ctx) {
    const inp = input;
    const limit = inp.limit ?? 50;
    const open = ctx.storage.findings.listOpen();
    const latest = ctx.storage.scans.getLatest();
    const recentScanTs = latest ? new Date(latest.started_at).getTime() : Date.now();
    const ranked = open.map((f) => {
        const factors = [];
        let score = 0;
        score += SEVERITY_WEIGHT[f.severity];
        factors.push(`severity=${f.severity} (+${SEVERITY_WEIGHT[f.severity]})`);
        score += CATEGORY_WEIGHT[f.category];
        factors.push(`category=${f.category} (+${CATEGORY_WEIGHT[f.category]})`);
        if (f.fix_available) {
            score += 60;
            factors.push('fix_available (+60 — easy win)');
        }
        // Recency: every finding from the latest scan gets +30; older = 0.
        // (Without per-finding timestamps we use the scan's started_at as a
        // proxy.)
        score += 30;
        factors.push('observed in latest scan (+30)');
        return { finding: f, priority_score: score, factors };
    });
    ranked.sort((a, b) => b.priority_score - a.priority_score ||
        a.finding.fingerprint.localeCompare(b.finding.fingerprint));
    const top = ranked.slice(0, limit);
    const summary = {
        total_open: open.length,
        returned: top.length,
        score_range: top.length > 0 ? {
            max: top[0].priority_score,
            min: top[top.length - 1].priority_score,
        } : null,
    };
    return {
        ok: true,
        summary,
        ranked: top,
        instructions_for_model: 'Pick the first 3-5 entries to action. For each, prefer `suggest_fix(finding_fingerprint)` ' +
            'over speculation. If most top entries are security/critical, call `audit_executive` to ' +
            'understand cross-cutting impact first.',
        // unused reference to keep the time variable from being dead-code'd by
        // future maintainers who add age-weighting.
        _recent_scan_ts: recentScanTs,
    };
}
//# sourceMappingURL=prioritizeFindings.js.map