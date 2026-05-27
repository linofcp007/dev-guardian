/**
 * `wp_audit` — audit a live WordPress install via WP-CLI.
 *
 * Standalone tool (no factory). Requires `wp` (WP-CLI) on PATH and a
 * directory containing `wp-config.php`. All WP-CLI invocations are
 * read-only.
 *
 * Per-subsection retry: each WP-CLI call is retried up to 3 times with
 * exponential backoff (1s, 3s, 9s) before being skipped. A failing
 * subsection puts a warning in `warnings[]` but never fails the whole
 * audit — partial data is preferable to no data.
 */
import { existsSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { join } from 'node:path';
import { z } from 'zod';
import { resolveProjectPath } from '../platform/projectPath.js';
import { runProcess } from '../runners/processRunner.js';
import { scannerAvailable } from './scanHelpers.js';
import { registerToolModule } from './index.js';
const RETRY_DELAYS_MS = [1000, 3000, 9000];
const DEFAULT_RISKY_LOGINS = ['admin', 'administrator', 'root', 'wpadmin'];
const inputSchema = {
    wp_install_path: z
        .string()
        .min(1)
        .describe('Path to the directory containing wp-config.php.'),
    include_users: z.boolean().optional(),
    include_options: z.boolean().optional(),
    risky_login_names: z.array(z.string()).optional(),
};
const tool = {
    name: 'wp_audit',
    title: 'Live WordPress install audit',
    description: 'Audit a running WordPress install via WP-CLI (read-only): core/plugin/theme file checksums, ' +
        'admin user list, dangerous config flags, plugins with auto_update on. Persists a scan row of ' +
        'type wp_audit so guardian://scans/{id} returns the structured audit.',
    inputSchema,
    handler: async (input, ctx) => handler(input, ctx),
};
registerToolModule(tool);
async function handler(input, ctx) {
    const inp = input;
    if (!inp.wp_install_path) {
        return failDomain('not_a_wordpress_install', 'wp_install_path is required.');
    }
    let installPath;
    try {
        installPath = resolveProjectPath(inp.wp_install_path).path;
    }
    catch (e) {
        return failDomain('not_a_wordpress_install', e.message);
    }
    if (!existsSync(join(installPath, 'wp-config.php'))) {
        return failDomain('not_a_wordpress_install', `No wp-config.php in ${installPath}`);
    }
    const wpBin = await scannerAvailable('wp');
    if (!wpBin) {
        return failDomain('missing_scanner', 'WP-CLI (`wp`) is not installed. Run install_toolchain with tools=["wp-cli"].');
    }
    const includeUsers = inp.include_users ?? true;
    const includeOptions = inp.include_options ?? true;
    const riskyLogins = new Set((inp.risky_login_names ?? DEFAULT_RISKY_LOGINS).map((s) => s.toLowerCase()));
    const meta = {
        wp_version: null,
        checksum_mismatches: { core: [], plugins: {}, themes: {} },
        config_flags: {
            DISALLOW_FILE_EDIT: null,
            WP_DEBUG: null,
            WP_DEBUG_LOG: null,
            FORCE_SSL_ADMIN: null,
        },
        admins: [],
        plugins_with_auto_update: [],
        warnings: [],
    };
    // Parallelise the independent WP-CLI subcommands. Each call goes through
    // the same retry policy (3 attempts, exp. backoff). Worst case improves
    // from 9 × ~10s sequential to ~10s wall-clock when ALL of them retry.
    const configFlags = includeOptions
        ? ['DISALLOW_FILE_EDIT', 'WP_DEBUG', 'WP_DEBUG_LOG', 'FORCE_SSL_ADMIN']
        : [];
    const [versionResult, coreVerify, pluginVerify, themeVerify, adminResult, pluginListResult, ...configResults] = await Promise.all([
        retry(() => wpCall(['core', 'version', `--path=${installPath}`], installPath, ctx)),
        retry(() => wpCall(['core', 'verify-checksums', `--path=${installPath}`, '--format=json'], installPath, ctx)),
        retry(() => wpCall(['plugin', 'verify-checksums', '--all', `--path=${installPath}`, '--format=json'], installPath, ctx)),
        retry(() => wpCall(['theme', 'verify-checksums', '--all', `--path=${installPath}`, '--format=json'], installPath, ctx)),
        includeUsers
            ? retry(() => wpCall([
                'user',
                'list',
                '--role=administrator',
                `--path=${installPath}`,
                '--fields=user_login,user_email',
                '--format=json',
            ], installPath, ctx))
            : Promise.resolve({ ok: true, stdout: '[]', stderr: '', reason: '' }),
        retry(() => wpCall([
            'plugin',
            'list',
            `--path=${installPath}`,
            '--fields=name,auto_update',
            '--format=json',
        ], installPath, ctx)),
        ...configFlags.map((flag) => retry(() => wpCall(['config', 'get', flag, `--path=${installPath}`], installPath, ctx))),
    ]);
    // -------- Apply results
    if (versionResult.ok) {
        meta.wp_version = versionResult.stdout.trim() || null;
    }
    else {
        meta.warnings.push(`core version: ${versionResult.reason}`);
    }
    meta.checksum_mismatches.core = parseChecksumOutput(coreVerify);
    if (!coreVerify.ok)
        meta.warnings.push(`core verify-checksums: ${coreVerify.reason}`);
    meta.checksum_mismatches.plugins = groupByComponent(pluginVerify);
    if (!pluginVerify.ok)
        meta.warnings.push(`plugin verify-checksums: ${pluginVerify.reason}`);
    meta.checksum_mismatches.themes = groupByComponent(themeVerify);
    if (!themeVerify.ok)
        meta.warnings.push(`theme verify-checksums: ${themeVerify.reason}`);
    if (includeUsers) {
        if (adminResult.ok) {
            try {
                const arr = JSON.parse(adminResult.stdout);
                meta.admins = arr.map((u) => ({
                    user_login: u.user_login,
                    user_email: u.user_email,
                    risky: riskyLogins.has((u.user_login ?? '').toLowerCase()),
                }));
            }
            catch {
                meta.warnings.push('user list: stdout not JSON');
            }
        }
        else {
            meta.warnings.push(`user list: ${adminResult.reason}`);
        }
    }
    if (pluginListResult.ok) {
        try {
            const arr = JSON.parse(pluginListResult.stdout);
            meta.plugins_with_auto_update = arr
                .filter((p) => (p.auto_update ?? '').toLowerCase() === 'on')
                .map((p) => p.name);
        }
        catch {
            meta.warnings.push('plugin list: stdout not JSON');
        }
    }
    else {
        meta.warnings.push(`plugin list: ${pluginListResult.reason}`);
    }
    configFlags.forEach((flag, i) => {
        const r = configResults[i];
        if (!r)
            return;
        if (r.ok) {
            const val = r.stdout.trim().toLowerCase();
            meta.config_flags[flag] = val === 'true' || val === '1';
        }
        else {
            meta.warnings.push(`config get ${flag}: ${r.reason}`);
        }
    });
    // -------- Persist scan row with meta
    const scanId = randomUUID();
    ctx.storage.scans.insert({
        scan_id: scanId,
        scan_type: 'wp_audit',
        project_path: installPath,
        tree_hash: '',
    });
    ctx.storage.scans.finalize({
        scan_id: scanId,
        status: 'completed',
        tools_run: [{ name: 'wp-cli', status: 'ok' }],
        missing_tools: [],
        meta: meta,
    });
    return {
        ok: true,
        scan_id: scanId,
        ...meta,
    };
}
async function wpCall(args, cwd, ctx) {
    const r = await runProcess({
        command: 'wp',
        args,
        cwd,
        env: process.env,
        timeoutMs: 60_000,
    });
    const ok = r.outcome === 'completed';
    return {
        ok,
        stdout: r.stdout,
        stderr: r.stderr,
        reason: ok ? '' : `exit ${r.exitCode ?? '?'} (${r.outcome}); ${r.stderr.split(/\r?\n/)[0] ?? ''}`,
    };
    void ctx;
}
async function retry(call) {
    let last = await call();
    for (let i = 0; i < RETRY_DELAYS_MS.length && !last.ok; i += 1) {
        await new Promise((res) => setTimeout(res, RETRY_DELAYS_MS[i]));
        last = await call();
    }
    return last;
}
function parseChecksumOutput(r) {
    if (!r.ok || r.stdout.trim().length === 0)
        return [];
    try {
        const arr = JSON.parse(r.stdout);
        return arr.map((x) => ({
            file: x.file ?? '(unknown)',
            status: normaliseStatus(x.status ?? x.message),
        }));
    }
    catch {
        return [];
    }
}
function groupByComponent(r) {
    // WP-CLI emits one row per file with a `plugin_name` (or `theme_name`)
    // field. Group by that to produce { slug: [files] }.
    if (!r.ok || r.stdout.trim().length === 0)
        return {};
    try {
        const arr = JSON.parse(r.stdout);
        const out = {};
        for (const row of arr) {
            const slug = row['plugin_name'] ?? row['theme_name'] ?? '(unknown)';
            const f = {
                file: row['file'] ?? '(unknown)',
                status: normaliseStatus(row['status'] ?? row['message']),
            };
            if (!out[slug])
                out[slug] = [];
            out[slug].push(f);
        }
        return out;
    }
    catch {
        return {};
    }
}
function normaliseStatus(raw) {
    const s = (raw ?? '').toLowerCase();
    if (s.includes('modified') || s.includes('changed'))
        return 'modified';
    if (s.includes('missing'))
        return 'missing';
    if (s.includes('added') || s.includes('extra') || s.includes('not in'))
        return 'added';
    return 'unknown';
}
function failDomain(code, message) {
    return { ok: false, error: { code, message } };
}
//# sourceMappingURL=wpAudit.js.map