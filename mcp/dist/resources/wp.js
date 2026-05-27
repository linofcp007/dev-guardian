/**
 * WordPress-specific resources.
 *
 * - guardian://wp/audit/latest      — most recent wp_audit (meta JSON)
 * - guardian://wp/audit/{scan_id}   — specific wp_audit by id
 *
 * These read the structured wp_audit data persisted by `wp_audit` into
 * `scans.meta`. Returning them as a dedicated resource gives the model a
 * cleaner shape than reading the generic `guardian://scans/{id}` blob.
 */
import { registerResourceModule } from './index.js';
registerResourceModule({
    name: 'guardian-wp-audit-latest',
    uri: 'guardian://wp/audit/latest',
    description: 'Most recent wp_audit result: WP version, file checksum mismatches, config flags, admin ' +
        'users, plugins with auto_update. Returns `{ last_run: null }` when no audit exists.',
    handler: async (_uri, _params, ctx) => {
        const audit = findLatestWpAudit(ctx);
        if (!audit)
            return { json: { last_run: null } };
        return {
            json: {
                scan_id: audit.scan_id,
                captured_at: audit.started_at,
                ...(audit.meta ?? {}),
            },
        };
    },
});
registerResourceModule({
    name: 'guardian-wp-audit-by-id',
    uri: 'guardian://wp/audit/{scan_id}',
    isTemplate: true,
    description: 'wp_audit result for a specific scan_id. Errors -32602 when the id is unknown or is not a ' +
        'wp_audit scan.',
    handler: async (_uri, params, ctx) => {
        const raw = params['scan_id'];
        const scanId = Array.isArray(raw) ? raw[0] : raw;
        if (!scanId)
            throw mcpInvalidParams('scan_id is required');
        const scan = ctx.storage.scans.getById(scanId);
        if (!scan)
            throw mcpInvalidParams(`unknown scan_id '${scanId}'`);
        if (scan.scan_type !== 'wp_audit') {
            throw mcpInvalidParams(`scan '${scanId}' is not a wp_audit (type='${scan.scan_type}')`);
        }
        return {
            json: {
                scan_id: scanId,
                captured_at: scan.started_at,
                ...(scan.meta ?? {}),
            },
        };
    },
});
registerResourceModule({
    name: 'guardian-wp-cron',
    uri: 'guardian://wp/cron',
    description: 'Latest wp_cron_audit result: total scheduled events + flagged ones (suspicious hooks, ' +
        'base64-looking args, hooks from inactive plugins).',
    handler: async (_uri, _params, ctx) => {
        const scan = findLatestOfType(ctx, 'wp_cron_audit');
        if (!scan)
            return { json: { last_run: null } };
        return {
            json: {
                scan_id: scan.scan_id,
                captured_at: scan.started_at,
                ...(scan.meta ?? {}),
            },
        };
    },
});
function findLatestWpAudit(ctx) {
    return findLatestOfType(ctx, 'wp_audit');
}
function findLatestOfType(ctx, type) {
    const history = ctx.storage.scans.listHistory(50);
    const row = history.find((s) => s.scan_type === type && s.status === 'completed');
    return row ? ctx.storage.scans.getById(row.scan_id) : null;
}
function mcpInvalidParams(message) {
    const err = new Error(message);
    err.code = -32602;
    return err;
}
//# sourceMappingURL=wp.js.map