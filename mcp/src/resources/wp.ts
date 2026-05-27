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

import type { PluginContext } from '../context.js';
import { registerResourceModule } from './index.js';

registerResourceModule({
  name: 'guardian-wp-audit-latest',
  uri: 'guardian://wp/audit/latest',
  description:
    'Most recent wp_audit result: WP version, file checksum mismatches, config flags, admin ' +
    'users, plugins with auto_update. Returns `{ last_run: null }` when no audit exists.',
  handler: async (_uri, _params, ctx) => {
    const audit = findLatestWpAudit(ctx);
    if (!audit) return { json: { last_run: null } };
    return {
      json: {
        scan_id: audit.scan_id,
        captured_at: audit.started_at,
        ...((audit.meta ?? {}) as Record<string, unknown>),
      },
    };
  },
});

registerResourceModule({
  name: 'guardian-wp-audit-by-id',
  uri: 'guardian://wp/audit/{scan_id}',
  isTemplate: true,
  description:
    'wp_audit result for a specific scan_id. Errors -32602 when the id is unknown or is not a ' +
    'wp_audit scan.',
  handler: async (_uri, params, ctx) => {
    const raw = params['scan_id'];
    const scanId = Array.isArray(raw) ? raw[0] : raw;
    if (!scanId) throw mcpInvalidParams('scan_id is required');
    const scan = ctx.storage.scans.getById(scanId);
    if (!scan) throw mcpInvalidParams(`unknown scan_id '${scanId}'`);
    // wp_audit is persisted under scan_type='audit' with a `meta.checksum_mismatches`
    // marker — we shape the resource around that to avoid creating a new
    // scan_type purely for this.
    const meta = scan.meta ?? {};
    if (!('checksum_mismatches' in (meta as Record<string, unknown>))) {
      throw mcpInvalidParams(`scan '${scanId}' is not a wp_audit`);
    }
    return {
      json: {
        scan_id: scanId,
        captured_at: scan.started_at,
        ...(meta as Record<string, unknown>),
      },
    };
  },
});

function findLatestWpAudit(ctx: PluginContext): ReturnType<typeof ctx.storage.scans.getById> {
  // wp_audit rows live as scan_type='audit' carrying a `meta.checksum_mismatches`
  // marker. Filter for that marker.
  const history = ctx.storage.scans.listHistory(50);
  for (const row of history) {
    if (row.status !== 'completed' || row.scan_type !== 'audit') continue;
    const full = ctx.storage.scans.getById(row.scan_id);
    if (full?.meta && 'checksum_mismatches' in (full.meta as Record<string, unknown>)) {
      return full;
    }
  }
  return null;
}

interface JsonRpcError extends Error {
  code: number;
}

function mcpInvalidParams(message: string): JsonRpcError {
  const err = new Error(message) as JsonRpcError;
  err.code = -32602;
  return err;
}
