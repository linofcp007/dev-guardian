/**
 * `wp_rest_audit` — probe a live WordPress site's REST API for the
 * common "too-much-exposed" endpoints.
 *
 * Read-only HTTP GETs. Specifically checks:
 *   - GET /wp-json/wp/v2/users  (anonymous user enumeration — default ON)
 *   - GET /wp-json/wp/v2/comments
 *   - GET /wp-json/wp/v2/pages?status=draft  (drafts visible?)
 *   - GET /wp-json/  (route listing; flags plugins exposing internals)
 *   - GET /xmlrpc.php  (legacy attack surface)
 *
 * We never POST and never log in. Output is purely "exposed: yes/no" plus
 * the count of items returned.
 */
import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import { registerToolModule } from './index.js';
const inputSchema = {
    target_url: z
        .string()
        .url()
        .describe('Base URL of the WordPress site (e.g. https://example.com).'),
    timeout_ms: z.number().int().min(1000).max(60_000).optional(),
};
const tool = {
    name: 'wp_rest_audit',
    title: 'WordPress REST API exposure audit',
    description: 'Probe (read-only HTTP GET) the live WP REST API for endpoints that commonly leak data: users ' +
        'enumeration, draft posts, comments, xmlrpc.php. No POSTs, no auth. Returns one row per ' +
        'endpoint with `exposed: yes/no`.',
    inputSchema,
    handler: async (input, ctx) => handler(input, ctx),
};
registerToolModule(tool);
async function handler(input, ctx) {
    const inp = input;
    const url = inp.target_url.replace(/\/$/, '');
    const timeoutMs = inp.timeout_ms ?? 15_000;
    const endpoints = [
        { path: '/wp-json/wp/v2/users', label: 'users (enumeration)', expectListing: true },
        { path: '/wp-json/wp/v2/comments', label: 'comments', expectListing: true },
        {
            path: '/wp-json/wp/v2/pages?status=draft',
            label: 'draft pages',
            expectListing: true,
        },
        { path: '/wp-json/', label: 'route discovery', expectListing: false },
        { path: '/xmlrpc.php', label: 'xmlrpc.php', expectListing: false },
    ];
    const results = [];
    for (const ep of endpoints) {
        results.push(await probe(`${url}${ep.path}`, ep.label, ep.expectListing, timeoutMs));
    }
    const exposed = results.filter((r) => r.exposed);
    const scanId = randomUUID();
    ctx.storage.scans.insert({
        scan_id: scanId,
        scan_type: 'wp_rest_audit',
        project_path: url,
        tree_hash: '',
    });
    ctx.storage.scans.finalize({
        scan_id: scanId,
        status: 'completed',
        tools_run: [{ name: 'http-probe', status: 'ok' }],
        missing_tools: [],
        meta: { target_url: url, results, exposed_count: exposed.length },
    });
    return {
        ok: true,
        scan_id: scanId,
        target_url: url,
        results,
        exposed_count: exposed.length,
        hint: exposed.length > 0
            ? 'Block / restrict the exposed endpoints. Common fix: WP plugin "Disable REST API" or filter ' +
                'via `rest_endpoints` hook in functions.php.'
            : 'No exposed endpoints from this probe set.',
    };
}
async function probe(fullUrl, _label, expectListing, timeoutMs) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);
    try {
        const res = await fetch(fullUrl, {
            method: 'GET',
            signal: controller.signal,
            headers: { 'User-Agent': 'dev-guardian/wp_rest_audit' },
        });
        let detail = '';
        let exposed = false;
        if (expectListing) {
            try {
                const text = await res.text();
                const parsed = JSON.parse(text);
                const count = Array.isArray(parsed) ? parsed.length : 0;
                exposed = res.status === 200 && count > 0;
                detail = `status=${res.status}, items=${count}`;
            }
            catch {
                exposed = res.status === 200;
                detail = `status=${res.status}, non-JSON body`;
            }
        }
        else {
            // For xmlrpc.php and /wp-json/ root: 200 OK means it's accessible
            exposed = res.status === 200 || res.status === 405; // 405 on xmlrpc.php = method not allowed but reachable
            detail = `status=${res.status}`;
        }
        return { endpoint: fullUrl, status: res.status, exposed, detail };
    }
    catch (e) {
        return {
            endpoint: fullUrl,
            status: 0,
            exposed: false,
            detail: `unreachable: ${e.message}`,
        };
    }
    finally {
        clearTimeout(timeout);
    }
}
//# sourceMappingURL=wpRestAudit.js.map