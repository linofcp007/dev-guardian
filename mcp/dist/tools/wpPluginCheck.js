/**
 * `wp_plugin_check` — what dev-guardian has already recorded about one
 * WordPress plugin slug: its known CVEs, and — with a local install — the
 * version WP-CLI reports installed there.
 *
 * It makes NO network call. It used to be described as returning the
 * "latest known" version and doing "a fresh WPScan lookup" with target_url;
 * it never did either (review 3.0 I2). target_url only adds the
 * `wp_vuln_check` recorded under that site URL to the rows read.
 *
 * **A version probe that did not answer is a gap, not "not installed".**
 * WP-CLI missing, failing, timing out, printing nothing or printing
 * something that is not JSON used to leave `installed_version: null`,
 * `warnings: []` and a tools_run entry of `ok` — the same answer as a plugin
 * that is not installed. Each is now a warning, a `wp-cli` tools_run entry
 * that is `skipped` (with `wp-cli` in missing_tools) or `failed` with the
 * reason, and coverage `partial`; `installed` is `null` (unknown), `false`
 * only when WP-CLI listed the install's plugins and this one was not there.
 *
 * **Whose CVEs (Task 24).** The project's own (`project_path`, else
 * `wp_install_path`, else the server's working directory — the install root
 * the WordPress scans file their rows under; plus `target_url` for a
 * URL-only `wp_vuln_check`): the newest usable dependency scan, the newest
 * `wp_vuln_check` and the newest `wp_vuln_check_source`. It used to union the
 * CVEs of every such scan among the 50 newest rows of the whole database —
 * any project's, and stale ones beside current ones. Each is looked up under
 * every spelling an earlier build may have filed it with
 * (`wordpress/siteKeys.ts`, fix round 1 I3).
 *
 * **It never refuses for want of a local project** (fix round 1, M4): the
 * lookup reads the database, so with no `project_path` it answers for
 * `wp_install_path` even when that install is not on this machine (an
 * absolute path is its own exact key), else for the server's working
 * directory — even a home directory, as `health_status` does. Refused: an
 * explicit `project_path` that does not resolve, and — when it is the key —
 * a RELATIVE `wp_install_path` that does not exist here (fix round 2): it
 * names no single install (`wordpress/siteKeys.ts#wpInstallPathProblem`).
 * Beside a valid `project_path`, which keys the lookup, such a path only
 * feeds the WP-CLI version probe: the probe is skipped with a warning.
 *
 * **The lookup row is scoped.** It is filed as a `wp_vuln_check` of the
 * project with `meta.scope` = `{ kind: 'plugin', slug }`: one plugin's
 * lookup, with no findings, whose silence about everything else is not
 * evidence — `history/scanRoles.ts#isScopedScan` keeps it out of the open
 * set, the baselines and every comparison.
 */
import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import { canonicalPath, resolveProjectPath } from '../platform/projectPath.js';
import { serverProjectPath } from '../resources/paging.js';
import { runProcess } from '../runners/processRunner.js';
import { ProjectPath } from '../schemas.js';
import { scannerAvailable } from './scanHelpers.js';
import { CVE_SOURCE_SCAN_TYPES } from '../types.js';
import { computeCoverage } from './scanCoverage.js';
import { latestUnderKeys, wpInstallKeys, wpInstallPathProblem, wpSiteKeys } from '../wordpress/siteKeys.js';
import { registerToolModule } from './index.js';
const inputSchema = {
    slug: z.string().min(1).describe('Plugin slug as known by wp.org (e.g. "contact-form-7").'),
    wp_install_path: z
        .string()
        .optional()
        .describe('Path to the WordPress install. On this machine, WP-CLI (`wp plugin list`) reads the installed version and ' +
        'active state from it; it also keys the CVE lookup when project_path is omitted. Absolute, or existing on this machine.'),
    target_url: z
        .string()
        .url()
        .optional()
        .describe('Site URL a wp_vuln_check was recorded under: its CVEs are read too. Nothing is sent to the site — for a ' +
        'live WPScan lookup run wp_vuln_check.'),
    project_path: ProjectPath.describe("The WordPress project whose recorded CVEs are searched. Default: wp_install_path when given, else the server's working directory."),
};
const tool = {
    name: 'wp_plugin_check',
    title: 'WordPress plugin check (1 plugin)',
    description: 'What dev-guardian has already recorded about one WordPress plugin slug: the active CVEs from this ' +
        "project's newest dependency scan, newest wp_vuln_check and newest wp_vuln_check_source. It makes no " +
        'network call — no WPScan query, no latest-version lookup; for fresh data run wp_vuln_check (live site) ' +
        'or wp_vuln_check_source (plugin sources) first. With a local wp_install_path, WP-CLI reports the ' +
        'installed version and whether the plugin is active; WP-CLI missing, failing or printing nothing is a ' +
        'warning and coverage "partial" (installed: null), never a silent null. target_url sends nothing to the ' +
        'site: it adds the wp_vuln_check recorded under that URL. Writes one scoped scan row, no findings.',
    inputSchema,
    handler: async (input, ctx) => handler(input, ctx),
};
registerToolModule(tool);
async function handler(input, ctx) {
    const inp = input;
    if (!inp.slug)
        return failDomain('unknown_scan_id', 'slug is required.');
    // See the module comment: an explicit project_path must exist, and a
    // wp_install_path that keys the lookup must be absolute or exist here (fix
    // round 2) — a relative one that does not would be resolved against the
    // server's cwd and share one record with every other install passed the
    // same way. Beside a project_path it only feeds the version probe.
    const hasProject = inp.project_path !== undefined && inp.project_path.length > 0;
    const installProblem = inp.wp_install_path !== undefined && inp.wp_install_path.length > 0
        ? wpInstallPathProblem(inp.wp_install_path)
        : null;
    if (installProblem !== null && !hasProject)
        return failDomain('unsupported_target', installProblem);
    const warnings = [];
    const toolsRun = [{ name: 'wp_plugin_check', status: 'ok' }];
    const missingTools = [];
    if (installProblem !== null) {
        warnings.push(`${installProblem} The installed version was not detected (the WP-CLI probe was skipped); ` +
            'the CVE lookup used project_path.');
        toolsRun.push({ name: 'wp-cli', status: 'skipped', reason: 'wp_install_path names no install on this machine' });
    }
    const probePath = installProblem === null ? inp.wp_install_path : undefined;
    let projectPath;
    const rawProject = inp.project_path ?? inp.wp_install_path;
    if (inp.project_path !== undefined && hasProject) {
        try {
            projectPath = resolveProjectPath(inp.project_path).path;
        }
        catch (e) {
            return failDomain('not_a_git_repo', e.message);
        }
    }
    else if (inp.wp_install_path !== undefined && inp.wp_install_path.length > 0) {
        projectPath = canonicalPath(inp.wp_install_path);
    }
    else {
        projectPath = serverProjectPath();
    }
    let installed = null;
    let installedVersion = null;
    let active = null;
    if (probePath !== undefined && probePath.length > 0) {
        const probe = await probeInstalled(probePath, inp.slug);
        toolsRun.push(probe.run);
        if (probe.run.status === 'skipped')
            missingTools.push('wp-cli');
        if (probe.warning !== null)
            warnings.push(probe.warning);
        installed = probe.installed;
        installedVersion = probe.version;
        active = probe.active;
    }
    const coverage = computeCoverage(toolsRun, missingTools);
    // CVE lookup from local DB (no network call). Match by package_name == slug.
    // CVEs are normalised lowercased in our DB.
    const slugLower = inp.slug.toLowerCase();
    const allActive = cveSources(ctx, wpInstallKeys(projectPath, rawProject), inp.target_url)
        .flatMap((s) => ctx.storage.cves.listActive(s.scan_id))
        .filter((c) => c.package_name.toLowerCase() === slugLower);
    // De-dup by cve_id
    const cveMap = new Map();
    for (const c of allActive) {
        if (!cveMap.has(c.cve_id))
            cveMap.set(c.cve_id, c);
    }
    const knownCves = [...cveMap.values()];
    // Persist a scan row so this lookup is queryable later — scoped to this
    // one plugin (see the module comment).
    const scanId = randomUUID();
    ctx.storage.scans.insert({
        scan_id: scanId,
        scan_type: 'wp_vuln_check',
        project_path: projectPath,
        tree_hash: '',
        meta: { scope: { kind: 'plugin', slug: inp.slug } },
    });
    ctx.storage.scans.finalize({
        scan_id: scanId,
        status: 'completed',
        tools_run: toolsRun,
        missing_tools: missingTools,
        meta: {
            scope: { kind: 'plugin', slug: inp.slug },
            slug: inp.slug,
            installed,
            installed_version: installedVersion,
            active,
            known_cves: knownCves,
        },
    });
    return {
        ok: true,
        project_path: projectPath,
        scan_id: scanId,
        slug: inp.slug,
        installed,
        installed_version: installedVersion,
        active,
        known_cves: knownCves,
        cve_count: knownCves.length,
        coverage,
        tools_run: toolsRun,
        missing_tools: missingTools,
        warnings,
        hint: knownCves.length > 0
            ? `Run wp_vuln_check or deps_audit for a fresh DB lookup before relying on this.`
            : 'No CVEs for this slug in the local DB. Run wp_vuln_check for a fresh online lookup.',
    };
}
/** `wp plugin list` for one slug, with every way it can fail to answer named. */
async function probeInstalled(probePath, slug) {
    const unknown = (run, warning) => ({
        run,
        installed: null,
        version: null,
        active: null,
        warning: `${warning} The installed version and active state of ${slug} are unknown, not absent.`,
    });
    if (!(await scannerAvailable('wp'))) {
        return unknown({ name: 'wp-cli', status: 'skipped', reason: 'WP-CLI (wp) is not installed' }, 'WP-CLI (`wp`) is not installed, so the install was not probed (install_toolchain with tools=["wp-cli"]).');
    }
    const r = await runProcess({
        command: 'wp',
        args: ['plugin', 'list', `--path=${probePath}`, `--name=${slug}`, '--fields=name,status,version', '--format=json'],
        cwd: probePath,
        timeoutMs: 30_000,
    });
    const failed = (reason) => unknown({ name: 'wp-cli', status: 'failed', reason }, `The WP-CLI probe of ${probePath} failed: ${reason}.`);
    if (r.outcome !== 'completed') {
        const stderr = r.stderr.split(/\r?\n/).find((l) => l.trim() !== '') ?? '';
        return failed(`${r.outcome}, exit ${r.exitCode ?? '?'}${stderr ? `: ${stderr.trim().slice(0, 300)}` : ''}`);
    }
    if (r.stdout.trim() === '')
        return failed('WP-CLI printed nothing');
    let rows;
    try {
        rows = JSON.parse(r.stdout);
    }
    catch {
        return failed(`WP-CLI output is not JSON: ${r.stdout.trim().slice(0, 120)}`);
    }
    if (!Array.isArray(rows))
        return failed('WP-CLI output is not a JSON list');
    const match = rows.find((p) => p?.name === slug);
    if (!match)
        return { run: { name: 'wp-cli', status: 'ok' }, installed: false, version: null, active: null, warning: null };
    return {
        run: { name: 'wp-cli', status: 'ok' },
        installed: true,
        version: typeof match.version === 'string' ? match.version : null,
        active: typeof match.status === 'string' ? match.status.toLowerCase() === 'active' : null,
        warning: null,
    };
}
/**
 * The scans whose CVEs speak for the project now: the newest usable
 * dependency scan (a security_full row judged on its Trivy half), the
 * newest `wp_vuln_check` — under the install root or, when given, the site
 * URL — and the newest `wp_vuln_check_source`. Each is a project-scoped
 * query; a scoped row (another plugin lookup) is never one of them.
 */
function cveSources(ctx, installKeys, targetUrl) {
    const siteKeys = targetUrl !== undefined ? wpSiteKeys(targetUrl) : [];
    const found = [
        latestUnderKeys(ctx.storage, installKeys, CVE_SOURCE_SCAN_TYPES, { slot: 'deps' }),
        // Filed under the install root, or — URL-only — under the site.
        latestUnderKeys(ctx.storage, [...installKeys, ...siteKeys], ['wp_vuln_check']),
        // wp_vuln_check_source (Task 18): source-based match against the
        // Wordfence feed, no live URL — same `cves` shape, same slug key.
        latestUnderKeys(ctx.storage, installKeys, ['wp_vuln_check_source']),
    ];
    return found.filter((s) => s !== null);
}
function failDomain(code, message) {
    return { ok: false, error: { code, message } };
}
//# sourceMappingURL=wpPluginCheck.js.map