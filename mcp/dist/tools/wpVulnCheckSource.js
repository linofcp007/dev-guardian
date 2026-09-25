/**
 * `wp_vuln_check_source` — WordPress vulnerabilities from source: no live
 * URL, no WP-CLI, no WPScan. Reads a local WordPress install directly
 * (`project_path` must be the install root: it contains `wp-includes/` and
 * `wp-content/`), matches what it finds against the Wordfence Intelligence
 * v3 feed and wp.org's plugin directory, and persists Findings + CVEs the
 * same way `wp_vuln_check` (WPScan, live URL) does.
 *
 * ---- Why a new tool rather than extending `scan_wordpress` ------------
 *
 * `scan_wordpress` runs Semgrep/Trivy/gitleaks/PHPCS — static analysis of
 * the PHP source for bugs it can see in the code. This tool does none of
 * that: it is SCA-style KNOWN-vulnerability matching by version number
 * against two external feeds, exactly the axis `deps_audit` sits on beside
 * `scan_sast` for every other ecosystem. It is also the one WP tool in this
 * family that needs neither a live URL (`wp_vuln_check`) nor WP-CLI
 * (`wp_audit`, `wp_cron_audit`) — folding it into either would have made
 * "source, no live site" an exception inside a tool whose whole premise is
 * a live install, or a mismatched extra pass inside a static-analysis
 * aggregator whose `ScannerInvocation.parser_inputs` model assumes a
 * subprocess's JSON, not a two-feed network lookup.
 *
 * ---- The two passes -----------------------------------------------------
 *
 * 1. `wordfence-feed`: `wordpress/vulnFeed.ts`'s cached, version-range match
 *    against the Wordfence Intelligence v3 production feed. No API key (or
 *    `GUARDIAN_OFFLINE=1`) is a real coverage gap — `skipped` +
 *    `missing_tools`, per Global Constraint 3 — not a silent "0
 *    vulnerabilities". A cache hit that is merely stale still counts as
 *    `ok` (real, if possibly outdated, data — Task 19's
 *    `intel/enrich.ts` established this "stale is not a gap" reading and
 *    this tool follows it), surfaced instead as a `warnings` entry.
 * 2. `wp-plugin-api`: `wordpress/wpOrgHealth.ts`'s per-plugin wp.org lookup
 *    — closed/removed, or not updated in over two years. Needs no key, so
 *    it runs independently of whether the Wordfence pass could: "no key ->
 *    coverage partial; wp.org checks still run" (design brief, point 4).
 *    `GUARDIAN_OFFLINE=1` is the one condition that suppresses BOTH passes
 *    — it is a blanket "no network" switch throughout this codebase
 *    (`intel/kev.ts`, `intel/epss.ts`), and an exception for wp.org here
 *    would be the only one.
 */
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { makeFinding } from '../runners/scannerParsers/index.js';
import { Force, ProjectPath, SeverityMin } from '../schemas.js';
import { inventoryWordPressSource } from '../wordpress/sourceInventory.js';
import { getWordfenceFeed, matchInventoryAgainstFeed, wordfenceMatchToFindingAndCve, } from '../wordpress/vulnFeed.js';
import { checkWpOrgPlugin, isStalePlugin, WP_ORG_TOOL_NAME, } from '../wordpress/wpOrgHealth.js';
import { registerToolModule } from './index.js';
import { makeScanTool } from './scanToolFactory.js';
/** Wordfence's own feed is ~100+ MB over the wire; wp.org's per-plugin
 *  lookups are tiny. Different budgets for different reasons. */
const WORDFENCE_TIMEOUT_MS = 60_000;
const WP_ORG_TIMEOUT_MS = 8_000;
registerToolModule(makeScanTool({
    name: 'wp_vuln_check_source',
    title: 'WordPress vulnerabilities from source (no live URL)',
    description: 'Reads a local WordPress install (project_path = the install root: wp-includes/, ' +
        'wp-content/ — not a single plugin/theme directory) and matches core/plugin/theme ' +
        'versions against the Wordfence Intelligence v3 feed (needs WORDFENCE_API_KEY; ' +
        'cached 24h) plus wp.org\'s plugin directory (closed/removed, or stale > 2 years; no ' +
        'key needed). No key or GUARDIAN_OFFLINE=1 -> coverage partial with a stated reason, ' +
        'never a clean result; wp.org checks still run without a Wordfence key. Complements ' +
        'wp_vuln_check (WPScan, needs a live URL) for offline/CI-only WordPress projects.',
    scan_type: 'wp_vuln_check_source',
    category: 'security',
    supportsAutoFix: false,
    // The Wordfence feed's own cache is 24h and wp.org's is 24h too; a
    // shorter factory cache would just re-parse the same ~100 MB feed for
    // an identical answer. An hour balances "don't re-parse for nothing"
    // against "force=true still gets a real re-check within the same day".
    cacheTtlMs: 60 * 60 * 1000,
    inputSchema: {
        project_path: ProjectPath,
        severity_min: SeverityMin,
        force: Force,
    },
    invoke: async (_input, ctx) => {
        const tools_run = [];
        const missing_tools = [];
        const warnings = [];
        const findings = [];
        const cves = [];
        const looksLikeWpRoot = existsSync(join(ctx.projectPath, 'wp-includes')) || existsSync(join(ctx.projectPath, 'wp-content'));
        if (!looksLikeWpRoot) {
            warnings.push('not_a_wordpress_install_root: no wp-includes/ or wp-content/ at project_path — ' +
                'this tool expects the WordPress install root, not a single plugin/theme directory.');
        }
        const inventory = inventoryWordPressSource(ctx.projectPath);
        warnings.push(...inventory.warnings);
        const offline = ctx.scriptEnv['GUARDIAN_OFFLINE'] === '1';
        const apiKey = ctx.scriptEnv['WORDFENCE_API_KEY'];
        // ---- Pass 1: Wordfence Intelligence v3 --------------------------
        let matches = [];
        const wf = await getWordfenceFeed({
            ...(apiKey !== undefined ? { apiKey } : {}),
            env: ctx.scriptEnv,
            timeoutMs: WORDFENCE_TIMEOUT_MS,
            signal: ctx.signal,
        });
        if (wf.ok) {
            matches = matchInventoryAgainstFeed(inventory, wf.feed);
            const entry = { name: 'wordfence-feed', status: 'ok' };
            if (wf.stale) {
                entry.reason = `serving a cached feed from ${wf.fetched_at}`;
                warnings.push(`Wordfence feed: serving a cached copy from ${wf.fetched_at} (a refresh could not be ` +
                    'completed this run) — results may be outdated.');
            }
            tools_run.push(entry);
            for (const match of matches) {
                const { finding, cve } = wordfenceMatchToFindingAndCve(match);
                findings.push(finding);
                if (cve !== null)
                    cves.push(cve);
            }
        }
        else {
            const configGap = offline || apiKey === undefined || apiKey.length === 0;
            tools_run.push({ name: 'wordfence-feed', status: configGap ? 'skipped' : 'failed', reason: wf.reason });
            if (configGap)
                missing_tools.push('wordfence-feed');
        }
        // ---- Pass 2: wp.org plugin directory health ----------------------
        const wpOrgResults = [];
        for (const plugin of inventory.plugins) {
            wpOrgResults.push(await checkWpOrgPlugin(ctx.plugin.storage, plugin.slug, {
                env: ctx.scriptEnv,
                timeoutMs: WP_ORG_TIMEOUT_MS,
                signal: ctx.signal,
            }));
        }
        const unavailable = wpOrgResults.filter((r) => r.status === 'unavailable');
        if (inventory.plugins.length === 0) {
            tools_run.push({ name: 'wp-plugin-api', status: 'skipped', reason: 'no plugins to check' });
        }
        else if (unavailable.length === inventory.plugins.length) {
            tools_run.push({
                name: 'wp-plugin-api',
                status: offline ? 'skipped' : 'failed',
                reason: unavailable[0]?.reason ?? 'unavailable',
            });
            if (offline)
                missing_tools.push('wp-plugin-api');
        }
        else {
            tools_run.push({ name: 'wp-plugin-api', status: 'ok' });
            if (unavailable.length > 0) {
                const names = unavailable.slice(0, 5).map((r) => r.slug);
                const suffix = unavailable.length > 5 ? ', ...' : '';
                warnings.push(`wp.org plugin lookup failed for ${unavailable.length} of ${inventory.plugins.length} ` +
                    `plugin(s): ${names.join(', ')}${suffix}`);
            }
            const staleServed = wpOrgResults.filter((r) => r.stale === true);
            if (staleServed.length > 0) {
                warnings.push(`wp.org: serving cached data for ${staleServed.length} plugin(s) (a refresh could not be ` +
                    'completed this run) — results may be outdated.');
            }
        }
        const now = Date.now();
        let closedCount = 0;
        let staleCount = 0;
        for (const r of wpOrgResults) {
            if (r.status !== 'ok')
                continue;
            const installed = inventory.plugins.find((p) => p.slug === r.slug);
            const componentLabel = `${r.slug}@${installed?.version ?? 'unknown'}`;
            if (r.plugin_status === 'closed') {
                closedCount += 1;
                const severity = r.closure_reason === 'security-issue' ? 'high' : 'medium';
                const finding = makeFinding({
                    tool: WP_ORG_TOOL_NAME,
                    severity,
                    category: 'security',
                    subcategory: 'wordpress-plugin-closed',
                    title: `Plugin "${r.slug}" is closed on wp.org` +
                        (r.closure_reason_text !== undefined ? `: ${r.closure_reason_text}` : ''),
                    fix_available: false,
                    file_path: componentLabel,
                    snippet: `component:${componentLabel}`,
                });
                if (r.closed_date !== undefined)
                    finding.message = `Closed ${r.closed_date}.`;
                findings.push(finding);
            }
            else if (r.plugin_status === 'found' && r.last_updated !== undefined && isStalePlugin(r.last_updated, now)) {
                staleCount += 1;
                findings.push(makeFinding({
                    tool: WP_ORG_TOOL_NAME,
                    severity: 'low',
                    category: 'security',
                    subcategory: 'wordpress-plugin-stale',
                    title: `Plugin "${r.slug}" has not been updated on wp.org since ${r.last_updated.slice(0, 10)}`,
                    fix_available: false,
                    file_path: componentLabel,
                    snippet: `component:${componentLabel}`,
                }));
            }
        }
        const parser_inputs = [];
        if (findings.length > 0 || cves.length > 0) {
            const passthrough = { name: 'wp_vuln_check_source', parse: () => ({ findings, cves }) };
            parser_inputs.push({ parser: passthrough, input: null });
        }
        const extras = {
            inventory: {
                core_version: inventory.core.version,
                plugins_count: inventory.plugins.length,
                themes_count: inventory.themes.length,
            },
            wordfence: wf.ok
                ? { status: 'ok', stale: wf.stale, fetched_at: wf.fetched_at, matched_count: matches.length }
                : { status: 'unavailable', reason: wf.reason },
            wp_org: {
                checked: inventory.plugins.length,
                found: wpOrgResults.filter((r) => r.plugin_status === 'found').length,
                closed: closedCount,
                stale: staleCount,
                not_found: wpOrgResults.filter((r) => r.plugin_status === 'not_found').length,
                unavailable: unavailable.length,
            },
        };
        if (warnings.length > 0)
            extras['warnings_extra'] = warnings;
        return {
            outcome: 'completed',
            tools_run,
            missing_tools,
            parser_inputs,
            report_paths: [],
            extras,
        };
    },
}));
//# sourceMappingURL=wpVulnCheckSource.js.map