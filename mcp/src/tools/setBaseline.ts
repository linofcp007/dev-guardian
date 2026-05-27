/**
 * `set_baseline` — mark a scan as the regression baseline.
 *
 * Pure SQL: inserts a new row in `baselines` whose `scan_id` is either the
 * argument (validated to exist) or the latest completed scan. The most
 * recently inserted row is always the active baseline — older rows are kept
 * for audit/history but ignored by `diff_scans from='baseline'`.
 */

import { z } from 'zod';
import type { PluginContext } from '../context.js';
import type { DomainError, ToolResult } from '../types.js';
import { registerToolModule, type ToolModule } from './index.js';

const inputSchema = {
  scan_id: z
    .string()
    .uuid()
    .optional()
    .describe('Scan to mark as the baseline. Defaults to the latest completed scan.'),
  note: z.string().max(500).optional().describe('Free-form note attached to the baseline row.'),
};

const tool: ToolModule = {
  name: 'set_baseline',
  title: 'Set regression baseline',
  description:
    'Mark a scan as the active regression baseline. Future `diff_scans from=baseline` queries ' +
    'use this row as the reference. Older baselines are kept for history but inactive.',
  inputSchema,
  handler: async (input, ctx) => handler(input, ctx),
};

registerToolModule(tool);

async function handler(
  input: Record<string, unknown>,
  ctx: PluginContext,
): Promise<ToolResult<Record<string, unknown>>> {
  const inp = input as { scan_id?: string; note?: string };

  let targetScanId: string;
  if (inp.scan_id) {
    const scan = ctx.storage.scans.getById(inp.scan_id);
    if (!scan) {
      return failDomain('unknown_scan_id', `No scan with id '${inp.scan_id}'.`);
    }
    if (scan.status !== 'completed') {
      return failDomain(
        'unknown_scan_id',
        `Scan '${inp.scan_id}' is status='${scan.status}'. Baselines require completed scans.`,
      );
    }
    targetScanId = inp.scan_id;
  } else {
    const latest = ctx.storage.scans.getLatest();
    if (!latest) {
      return failDomain(
        'unknown_scan_id',
        'No completed scan exists yet; run a scan tool before setting a baseline.',
      );
    }
    targetScanId = latest.scan_id;
  }

  const baseline = ctx.storage.baselines.set({
    scan_id: targetScanId,
    ...(inp.note !== undefined ? { note: inp.note } : {}),
  });

  return {
    ok: true,
    baseline_id: baseline.id,
    scan_id: baseline.scan_id,
    set_at: baseline.set_at,
    ...(baseline.note !== undefined ? { note: baseline.note } : {}),
  };
}

function failDomain(
  code: DomainError['code'],
  message: string,
): ToolResult<Record<string, unknown>> {
  return { ok: false, error: { code, message } };
}
