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
import type { PluginContext } from '../context.js';
import { resolveVersion } from '../platform/version.js';
import { getScanLimiter } from '../runners/concurrencyLimiter.js';
import { RESOURCES } from '../resources/index.js';
import type { ToolResult } from '../types.js';
import { registerToolModule, TOOLS, type ToolModule } from './index.js';

const startedAt = Date.now();

// Same shared resolver server.ts and report/sarif.ts already use — was a
// second hardcoded '0.1.0' here, independent of (and just as stale as) the
// one report/sarif.ts carried; resolved once, not per call, same "read
// once, reuse many times" shape as those two.
const SERVER_VERSION = resolveVersion();

const tool: ToolModule = {
  name: 'health_status',
  title: 'Server health',
  description:
    'Return server uptime, DB info, last scan, shell choice, in-flight scan count, and tool/resource ' +
    'counts. Read-only.',
  inputSchema: {},
  handler: async (_input, ctx) => handler(ctx),
};

registerToolModule(tool);

async function handler(ctx: PluginContext): Promise<ToolResult<Record<string, unknown>>> {
  const latest = ctx.storage.scans.getLatest();
  const limiter = getScanLimiter();
  const dbPath = (ctx.storage as unknown as { rawHandle: () => { name: string } })
    .rawHandle()
    .name;
  let dbSizeBytes: number | null = null;
  if (dbPath && dbPath !== ':memory:' && existsSync(dbPath)) {
    try {
      dbSizeBytes = statSync(dbPath).size;
    } catch {
      /* ignore */
    }
  }

  return {
    ok: true,
    server: {
      name: 'dev-guardian',
      version: SERVER_VERSION,
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
