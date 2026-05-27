/**
 * `wp_describe_setup` — single read that gathers everything the calling
 * model might want to know about the current WordPress posture.
 *
 * Pure read of accumulated dev-guardian state — no scanner spawns.
 * Useful as a "what's the state of this WP project?" one-shot so the
 * model doesn't need to fan out across guardian://wp/audit/latest,
 * guardian://findings/open, etc.
 */
import { registerToolModule } from './index.js';
const tool = {
    name: 'wp_describe_setup',
    title: 'WordPress posture summary',
    description: 'Aggregate read of accumulated WP state: latest wp_audit (versions, checksum mismatches, ' +
        'admins, config flags), latest wp_cron_audit (flagged events), latest wp_rest_audit, open ' +
        'WP-related findings, and active CVEs on wp packages. No scanner spawn.',
    inputSchema: {},
    handler: async (_input, ctx) => handler(ctx),
};
registerToolModule(tool);
async function handler(ctx) {
    const wpAudit = findLatest(ctx, 'wp_audit');
    const wpCron = findLatest(ctx, 'wp_cron_audit');
    const wpRest = findLatest(ctx, 'wp_rest_audit');
    const wpVuln = findLatest(ctx, 'wp_vuln_check');
    const wpCodeScan = findLatest(ctx, 'wordpress');
    const open = ctx.storage.findings
        .listOpen()
        .filter((f) => f.tool === 'wpscan' || f.tool === 'phpcs' || f.category === 'security');
    const cves = wpVuln ? ctx.storage.cves.listActive(wpVuln.scan_id) : [];
    return {
        ok: true,
        audits: {
            wp_audit: wpAudit
                ? {
                    scan_id: wpAudit.scan_id,
                    captured_at: wpAudit.started_at,
                    wp_version: wpAudit.meta?.wp_version ?? null,
                    admins_count: (wpAudit.meta?.admins ?? [])
                        .length,
                    checksum_mismatches_count: countChecksumIssues(wpAudit.meta),
                    warnings: wpAudit.meta?.warnings ?? [],
                }
                : null,
            wp_cron_audit: wpCron
                ? {
                    scan_id: wpCron.scan_id,
                    flagged_count: wpCron.meta?.flagged_count ?? 0,
                }
                : null,
            wp_rest_audit: wpRest
                ? {
                    scan_id: wpRest.scan_id,
                    exposed_count: wpRest.meta?.exposed_count ?? 0,
                }
                : null,
            wp_vuln_check: wpVuln
                ? {
                    scan_id: wpVuln.scan_id,
                    cves_count: cves.length,
                }
                : null,
            scan_wordpress: wpCodeScan
                ? {
                    scan_id: wpCodeScan.scan_id,
                    captured_at: wpCodeScan.started_at,
                }
                : null,
        },
        open_findings_count: open.length,
        open_critical: open.filter((f) => f.severity === 'critical').length,
        open_high: open.filter((f) => f.severity === 'high').length,
        active_cves: cves,
        recommended_next: !wpAudit ? 'Run `wp_audit` first to capture baseline state.'
            : !wpVuln ? 'Run `wp_vuln_check` to map CVEs to your installed plugins/themes.'
                : !wpCron ? 'Run `wp_cron_audit` to detect persistent backdoors.'
                    : open.length > 0 ? 'Open findings exist. Try `triage_findings` + `wp_recommend_hardening`.'
                        : 'Posture looks clean. Consider `audit_executive` for a full cross-stack pass.',
    };
}
function findLatest(ctx, type) {
    const history = ctx.storage.scans.listHistory(50);
    const row = history.find((s) => s.scan_type === type && s.status === 'completed');
    return row ? ctx.storage.scans.getById(row.scan_id) : null;
}
function countChecksumIssues(meta) {
    const cm = meta?.checksum_mismatches ?? {};
    return ((cm.core?.length ?? 0) +
        Object.values(cm.plugins ?? {}).reduce((a, b) => a + (b?.length ?? 0), 0) +
        Object.values(cm.themes ?? {}).reduce((a, b) => a + (b?.length ?? 0), 0));
}
//# sourceMappingURL=wpDescribeSetup.js.map