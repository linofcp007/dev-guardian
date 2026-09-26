/**
 * `wp_describe_setup` — single read that gathers everything the calling
 * model might want to know about ONE WordPress project's posture.
 *
 * Pure read of accumulated dev-guardian state — no scanner spawns.
 * Useful as a "what's the state of this WP project?" one-shot so the
 * model doesn't need to fan out across guardian://wp/audit/latest,
 * guardian://findings/open, etc.
 *
 * **Whose state (Task 24).** Every read used to be "the latest scan of type
 * X" among the 50 newest rows of the whole database, and the findings were
 * `findings.listOpen()` — the single newest completed scan of any project —
 * so another install's audit answered for this one. The WordPress tools key
 * their rows by what they looked at, and this reads each where it lives:
 *   - `project_path` (default: the server's working directory) — the install
 *     root `wp_audit`, `wp_cron_audit`, `wp_vuln_check_source`,
 *     `scan_wordpress` and a path-given `wp_vuln_check` file under;
 *   - `target_url`, when given — the site URL `wp_rest_audit` and a
 *     URL-only `wp_vuln_check` file under. Without it no REST probe is
 *     reported: a probe of some other site is not this project's.
 * `wp_plugin_check`'s single-plugin lookup (a `wp_vuln_check` row that is
 * scoped, `history/scanRoles.ts#isScopedScan`) is never "the latest
 * wp_vuln_check": it holds no CVEs of its own.
 *
 * Each is looked up under every spelling an earlier build may have filed it
 * with (`wordpress/siteKeys.ts`, fix round 1 I3), the newest row across them
 * answering. Only the audits that report through `meta` (`wp_audit`,
 * `wp_cron_audit`, `wp_rest_audit`) are read whatever their scanner
 * coverage; a finding scan that measured nothing is passed over (M3).
 */
import { z } from 'zod';
import { indexFindings } from '../fingerprint/findingIdentity.js';
import { openSetForProject } from '../history/openSet.js';
import { resolveProjectPath } from '../platform/projectPath.js';
import { ProjectPath } from '../schemas.js';
import { latestUnderKeys, wpInstallKeys, wpSiteKey, wpSiteKeys } from '../wordpress/siteKeys.js';
import { registerToolModule } from './index.js';
const tool = {
    name: 'wp_describe_setup',
    title: 'WordPress posture summary',
    description: "Aggregate read of one WordPress project's accumulated state (project_path = the install " +
        "root, default: the server's working directory; target_url = the live site, for the scans " +
        'keyed by URL): latest wp_audit (versions, checksum mismatches, admins, config flags), latest ' +
        'wp_cron_audit (flagged events), latest wp_rest_audit (needs target_url), open WP-related ' +
        'findings, and active CVEs on wp packages. No scanner spawn.',
    inputSchema: {
        project_path: ProjectPath,
        target_url: z
            .string()
            .url()
            .optional()
            .describe('The live site URL wp_rest_audit / wp_vuln_check were run against, to include those rows.'),
    },
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
    const siteKey = inp.target_url !== undefined ? wpSiteKey(inp.target_url) : null;
    const installKeys = wpInstallKeys(projectPath, inp.project_path);
    const siteKeys = inp.target_url !== undefined ? wpSiteKeys(inp.target_url) : [];
    const keys = [...installKeys, ...siteKeys];
    const wpAudit = findLatest(ctx, installKeys, 'wp_audit', META_REPORT);
    const wpCron = findLatest(ctx, installKeys, 'wp_cron_audit', META_REPORT);
    const wpRest = siteKeys.length > 0 ? findLatest(ctx, siteKeys, 'wp_rest_audit', META_REPORT) : null;
    const wpVuln = findLatest(ctx, keys, 'wp_vuln_check', FINDING_SCAN);
    // wp_vuln_check_source (Task 18): the source/offline match against the
    // Wordfence feed + wp.org, alongside wp_vuln_check's live-URL/WPScan
    // lookup. Both can legitimately exist for the same project (one needs no
    // live URL, the other needs no API key), so their CVEs are merged below
    // rather than one shadowing the other.
    const wpVulnSource = findLatest(ctx, installKeys, 'wp_vuln_check_source', FINDING_SCAN);
    const wpCodeScan = findLatest(ctx, installKeys, 'wordpress', FINDING_SCAN);
    const open = openFindings(ctx, keys).filter((f) => f.tool === 'wpscan' || f.tool === 'phpcs' || f.category === 'security');
    const cvesFromLive = wpVuln ? ctx.storage.cves.listActive(wpVuln.scan_id) : [];
    const cvesFromSource = wpVulnSource ? ctx.storage.cves.listActive(wpVulnSource.scan_id) : [];
    const cveById = new Map();
    for (const c of [...cvesFromLive, ...cvesFromSource])
        cveById.set(c.cve_id, c);
    const cves = [...cveById.values()];
    return {
        ok: true,
        project_path: projectPath,
        ...(siteKey !== null ? { target_url: siteKey } : {}),
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
                    cves_count: cvesFromLive.length,
                }
                : null,
            wp_vuln_check_source: wpVulnSource
                ? {
                    scan_id: wpVulnSource.scan_id,
                    cves_count: cvesFromSource.length,
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
            : !wpVuln && !wpVulnSource
                ? 'Run `wp_vuln_check` (live URL) or `wp_vuln_check_source` (no live URL needed) to map CVEs to your installed plugins/themes.'
                : !wpCron ? 'Run `wp_cron_audit` to detect persistent backdoors.'
                    : open.length > 0 ? 'Open findings exist. Try `triage_findings` + `wp_recommend_hardening`.'
                        : 'Posture looks clean. Consider `audit_executive` for a full cross-stack pass.',
    };
}
/**
 * An audit that reports through `meta`: read whatever its scanner coverage
 * (the resources in `resources/wp.ts` read them the same way).
 */
const META_REPORT = { skipCoverageNone: false };
/** A finding scan: one that measured nothing is passed over, the one before it answers. */
const FINDING_SCAN = {};
/** The newest unscoped completed scan of `type` under any of `keys`. */
function findLatest(ctx, keys, type, opts) {
    return latestUnderKeys(ctx.storage, keys, [type], opts);
}
/** The open set of every key, deduplicated — a finding under two keys counts once. */
function openFindings(ctx, keys) {
    const out = [];
    for (const key of new Set(keys)) {
        const seen = indexFindings(out);
        for (const f of openSetForProject(ctx.storage, key).findings)
            if (!seen.has(f))
                out.push(f);
    }
    return out;
}
function countChecksumIssues(meta) {
    const cm = meta?.checksum_mismatches ?? {};
    return ((cm.core?.length ?? 0) +
        Object.values(cm.plugins ?? {}).reduce((a, b) => a + (b?.length ?? 0), 0) +
        Object.values(cm.themes ?? {}).reduce((a, b) => a + (b?.length ?? 0), 0));
}
//# sourceMappingURL=wpDescribeSetup.js.map