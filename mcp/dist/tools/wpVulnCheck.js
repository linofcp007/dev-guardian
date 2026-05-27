/**
 * `wp_vuln_check` — query the WPScan public DB for known vulns affecting
 * the installed WP core, plugins, and themes.
 *
 * Standalone. Either pass a `target_url` (preferred — WPScan scans the
 * live site) or `wp_install_path` (we infer versions via WP-CLI then
 * pass `--url` pointing at the bundled wp-config home_url).
 *
 * API token: read from `api_token` input or `WPSCAN_API_TOKEN` env. When
 * absent, surface a warning about rate limits but proceed.
 */
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { join } from 'node:path';
import { z } from 'zod';
import { runProcess } from '../runners/processRunner.js';
import { wpscanParser } from '../runners/scannerParsers/wpscan.js';
import { scannerAvailable } from './scanHelpers.js';
import { registerToolModule } from './index.js';
const inputSchema = {
    wp_install_path: z
        .string()
        .optional()
        .describe('Local path to a WP install (must contain wp-config.php).'),
    target_url: z
        .string()
        .url()
        .optional()
        .describe('Live URL of the WordPress site to scan. Preferred when both inputs are present.'),
    api_token: z
        .string()
        .optional()
        .describe('WPScan API token. Falls back to WPSCAN_API_TOKEN env var.'),
};
const tool = {
    name: 'wp_vuln_check',
    title: 'WordPress vuln-DB lookup (WPScan)',
    description: 'Run WPScan against a target URL (or against the URL inferred from a local install_path) and ' +
        'return vulnerabilities affecting core / plugins / themes. Token optional; without one, you ' +
        'are rate-limited by the public DB.',
    inputSchema,
    handler: async (input, ctx) => handler(input, ctx),
};
registerToolModule(tool);
async function handler(input, ctx) {
    const inp = input;
    if (!inp.target_url && !inp.wp_install_path) {
        return failDomain('unknown_scan_id', 'Provide either target_url or wp_install_path.');
    }
    const wpscanBin = await scannerAvailable('wpscan');
    if (!wpscanBin) {
        return failDomain('missing_scanner', 'wpscan CLI is not installed. Run install_toolchain with tools=["wpscan"].');
    }
    // Resolve URL. When only the install path is given, ask WP-CLI for the home_url.
    let url = inp.target_url;
    const warnings = [];
    if (!url && inp.wp_install_path) {
        const wpBin = await scannerAvailable('wp');
        if (!wpBin) {
            return failDomain('missing_scanner', 'wp_install_path was provided but WP-CLI is missing to read the URL. Install wp-cli or provide target_url.');
        }
        const r = await runProcess({
            command: 'wp',
            args: ['option', 'get', 'home', `--path=${inp.wp_install_path}`],
            cwd: inp.wp_install_path,
            timeoutMs: 30_000,
        });
        if (r.outcome === 'completed') {
            url = r.stdout.trim();
        }
        else {
            return failDomain('scanner_failed', `wp option get home failed: ${r.stderr.split(/\r?\n/)[0] ?? r.outcome}`);
        }
    }
    const token = inp.api_token ?? process.env['WPSCAN_API_TOKEN'] ?? '';
    if (!token)
        warnings.push('No WPSCAN_API_TOKEN — public-no-token rate limit applies.');
    // Persist scan row first so we can attach findings/CVEs to it.
    const scanId = randomUUID();
    const reportDir = join(inp.wp_install_path ?? process.cwd(), '.guardian', 'reports', `wpvuln-${scanId.slice(0, 8)}`);
    mkdirSync(reportDir, { recursive: true });
    const outFile = join(reportDir, 'wpscan.json');
    ctx.storage.scans.insert({
        scan_id: scanId,
        scan_type: 'wp_vuln_check',
        project_path: inp.wp_install_path ?? url,
        tree_hash: '',
        report_dir: reportDir,
    });
    const args = [
        '--no-update',
        '--no-banner',
        '--format',
        'json',
        '--output',
        outFile,
        '--enumerate',
        'vp,vt',
        '--url',
        url,
    ];
    if (token)
        args.push('--api-token', token);
    const r = await runProcess({
        command: 'wpscan',
        args,
        cwd: inp.wp_install_path ?? process.cwd(),
        timeoutMs: 5 * 60_000,
    });
    // Rate-limit signature
    const rateLimited = r.exitCode === 50 ||
        /rate limit|throttled/i.test(r.stderr) ||
        /rate limit|throttled/i.test(r.stdout);
    if (rateLimited) {
        warnings.push('WPScan rate-limited — results are partial. Try again later or set WPSCAN_API_TOKEN.');
    }
    let raw = null;
    if (existsSync(outFile)) {
        try {
            raw = require('node:fs').readFileSync(outFile, 'utf8');
        }
        catch {
            raw = null;
        }
    }
    // Fallback: wpscan stdout
    if (!raw && r.stdout && r.stdout.trim().startsWith('{')) {
        raw = r.stdout;
        try {
            writeFileSync(outFile, raw, 'utf8');
        }
        catch {
            /* ignore */
        }
    }
    let findingsCount = 0;
    let cvesCount = 0;
    if (raw) {
        const parsed = wpscanParser.parse(raw);
        if (parsed.findings.length > 0) {
            ctx.storage.findings.bulkInsert(parsed.findings.map((f) => ({ ...f, scan_id: scanId })));
            findingsCount = parsed.findings.length;
        }
        if (parsed.cves.length > 0) {
            ctx.storage.cves.bulkUpsert(parsed.cves.map((c) => ({ ...c, scan_id: scanId })));
            cvesCount = parsed.cves.length;
        }
    }
    else {
        warnings.push('WPScan produced no parseable JSON output.');
    }
    ctx.storage.scans.finalize({
        scan_id: scanId,
        status: r.outcome === 'completed' || rateLimited ? 'completed' : 'failed',
        tools_run: [{ name: 'wpscan', status: r.outcome === 'completed' ? 'ok' : 'failed' }],
        missing_tools: [],
        report_dir: reportDir,
        meta: { url, rate_limited: rateLimited, has_token: token.length > 0 },
    });
    return {
        ok: true,
        scan_id: scanId,
        url,
        has_token: token.length > 0,
        rate_limited: rateLimited,
        findings_count: findingsCount,
        cves_count: cvesCount,
        report_path: outFile,
        warnings,
    };
}
function failDomain(code, message) {
    return { ok: false, error: { code, message } };
}
//# sourceMappingURL=wpVulnCheck.js.map