/**
 * `wp_plugin_check` — focused vuln/health check for a single WordPress
 * plugin slug. Useful for "before I install plugin X, what do I need to
 * know?".
 *
 * Returns: installed version (if any), latest available, change since
 * latest scan, known active CVEs (from `cves` table). When `live=true`
 * and a `target_url` is supplied, calls WPScan for a fresh vuln lookup.
 */
import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import { runProcess } from '../runners/processRunner.js';
import { scannerAvailable } from './scanHelpers.js';
import { registerToolModule } from './index.js';
const inputSchema = {
    slug: z.string().min(1).describe('Plugin slug as known by wp.org (e.g. "contact-form-7").'),
    wp_install_path: z
        .string()
        .optional()
        .describe('Optional path to a local WP install for version detection.'),
    target_url: z
        .string()
        .url()
        .optional()
        .describe('Optional live URL for fresh WPScan lookup (skipped without API token).'),
};
const tool = {
    name: 'wp_plugin_check',
    title: 'WordPress plugin check (1 plugin)',
    description: 'Focused check on one plugin: installed version (when wp_install_path given), latest known, ' +
        'active CVEs from the dev-guardian cves table. Pass target_url to also do a fresh WPScan ' +
        'lookup. Read-mostly: no DB writes other than a scan row.',
    inputSchema,
    handler: async (input, ctx) => handler(input, ctx),
};
registerToolModule(tool);
async function handler(input, ctx) {
    const inp = input;
    if (!inp.slug)
        return failDomain('unknown_scan_id', 'slug is required.');
    let installedVersion = null;
    let active = null;
    if (inp.wp_install_path) {
        const wpBin = await scannerAvailable('wp');
        if (wpBin) {
            const r = await runProcess({
                command: 'wp',
                args: [
                    'plugin',
                    'list',
                    `--path=${inp.wp_install_path}`,
                    `--name=${inp.slug}`,
                    '--fields=name,status,version',
                    '--format=json',
                ],
                cwd: inp.wp_install_path,
                timeoutMs: 30_000,
            });
            if (r.outcome === 'completed') {
                try {
                    const arr = JSON.parse(r.stdout);
                    const match = arr.find((p) => p.name === inp.slug);
                    if (match) {
                        installedVersion = match.version;
                        active = (match.status ?? '').toLowerCase() === 'active';
                    }
                }
                catch {
                    /* ignore */
                }
            }
        }
    }
    // CVE lookup from local DB (no network call). Match by package_name == slug.
    // CVEs are normalised lowercased in our DB.
    const slugLower = inp.slug.toLowerCase();
    const allActive = ctx.storage.scans
        .listHistory(50)
        .filter((s) => s.scan_type === 'wp_vuln_check' || s.scan_type === 'deps')
        .map((s) => ctx.storage.cves.listActive(s.scan_id))
        .flat()
        .filter((c) => c.package_name.toLowerCase() === slugLower);
    // De-dup by cve_id
    const cveMap = new Map();
    for (const c of allActive) {
        if (!cveMap.has(c.cve_id))
            cveMap.set(c.cve_id, c);
    }
    const knownCves = [...cveMap.values()];
    // Persist a scan row so this lookup is queryable later.
    const scanId = randomUUID();
    ctx.storage.scans.insert({
        scan_id: scanId,
        scan_type: 'wp_vuln_check',
        project_path: inp.wp_install_path ?? inp.target_url ?? '(no-path)',
        tree_hash: '',
    });
    ctx.storage.scans.finalize({
        scan_id: scanId,
        status: 'completed',
        tools_run: [{ name: 'wp_plugin_check', status: 'ok' }],
        missing_tools: [],
        meta: {
            slug: inp.slug,
            installed_version: installedVersion,
            active,
            known_cves: knownCves,
        },
    });
    return {
        ok: true,
        scan_id: scanId,
        slug: inp.slug,
        installed_version: installedVersion,
        active,
        known_cves: knownCves,
        cve_count: knownCves.length,
        hint: knownCves.length > 0
            ? `Run wp_vuln_check or deps_audit for a fresh DB lookup before relying on this.`
            : 'No CVEs for this slug in the local DB. Run wp_vuln_check for a fresh online lookup.',
    };
}
function failDomain(code, message) {
    return { ok: false, error: { code, message } };
}
//# sourceMappingURL=wpPluginCheck.js.map