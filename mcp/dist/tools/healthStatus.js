/**
 * `health_status` — server diagnostics. Useful when something feels off
 * and the model wants to introspect.
 *
 * Reports:
 *   - uptime (process)
 *   - last scan + how long ago
 *   - DB file path + size
 *   - chosen shell label
 *   - concurrency limiter state
 *   - count of registered tools / resources
 */
import { existsSync, statSync } from 'node:fs';
import { getScanLimiter } from '../runners/concurrencyLimiter.js';
import { RESOURCES } from '../resources/index.js';
import { registerToolModule, TOOLS } from './index.js';
const startedAt = Date.now();
const tool = {
    name: 'health_status',
    title: 'Server health',
    description: 'Return server uptime, DB info, last scan, shell choice, in-flight scan count, and tool/resource ' +
        'counts. Read-only.',
    inputSchema: {},
    handler: async (_input, ctx) => handler(ctx),
};
registerToolModule(tool);
async function handler(ctx) {
    const latest = ctx.storage.scans.getLatest();
    const limiter = getScanLimiter();
    const dbPath = ctx.storage
        .rawHandle()
        .name;
    let dbSizeBytes = null;
    if (dbPath && dbPath !== ':memory:' && existsSync(dbPath)) {
        try {
            dbSizeBytes = statSync(dbPath).size;
        }
        catch {
            /* ignore */
        }
    }
    return {
        ok: true,
        server: {
            name: 'dev-guardian',
            version: '0.1.0',
            uptime_seconds: Math.floor((Date.now() - startedAt) / 1000),
            node_version: process.version,
            platform: process.platform,
        },
        storage: {
            db_path: dbPath,
            db_size_bytes: dbSizeBytes,
            total_scans: ctx.storage.scans.listHistory(1000).length,
            ...(ctx.storage.runtimeMeta.get('shell_choice') !== null
                ? { shell_label: ctx.shell?.label ?? 'unknown' }
                : {}),
        },
        last_scan: latest
            ? {
                scan_id: latest.scan_id,
                scan_type: latest.scan_type,
                started_at: latest.started_at,
                age_seconds: Math.floor((Date.now() - new Date(latest.started_at).getTime()) / 1000),
                status: latest.status,
            }
            : null,
        concurrency: {
            in_flight: limiter.inFlight,
            queued: limiter.queued,
        },
        registry: {
            tools: TOOLS.length,
            resources: RESOURCES.length,
        },
        storage_warning: ctx.storageWarning ?? null,
    };
}
//# sourceMappingURL=healthStatus.js.map