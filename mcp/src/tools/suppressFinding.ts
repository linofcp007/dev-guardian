/**
 * `suppress_finding` — mark a finding fingerprint as a false positive.
 *
 * Pure SQL: inserts a row in `suppressions`. While the row is active
 * (NULL `expires_at`, or `expires_at` in the future), the matching
 * finding is hidden from `findings/open` and `findings/by-severity/*`
 * resources. Historical scan records are untouched.
 */

import { z } from 'zod';
import type { PluginContext } from '../context.js';
import type { DomainError, ToolResult } from '../types.js';
import { registerToolModule, type ToolModule } from './index.js';

const inputSchema = {
  finding_fingerprint: z
    .string()
    .regex(/^[0-9a-f]{64}$/)
    .describe('SHA-256 fingerprint of the finding to suppress (from a previous scan response).'),
  reason: z
    .string()
    .min(1)
    .max(1000)
    .describe('Why this finding is being suppressed. Required.'),
  expires_at: z
    .string()
    .datetime()
    .optional()
    .describe('ISO-8601 expiry. When omitted, the suppression never expires.'),
};

const tool: ToolModule = {
  name: 'suppress_finding',
  title: 'Suppress finding',
  description:
    'Mark a finding fingerprint as a false positive. Resources that surface open findings exclude ' +
    'matches while the suppression is active. Pass expires_at for a temporary snooze.',
  inputSchema,
  handler: async (input, ctx) => handler(input, ctx),
};

registerToolModule(tool);

async function handler(
  input: Record<string, unknown>,
  ctx: PluginContext,
): Promise<ToolResult<Record<string, unknown>>> {
  const inp = input as { finding_fingerprint: string; reason: string; expires_at?: string };

  if (!inp.finding_fingerprint || !inp.reason) {
    return failDomain(
      'unknown_scan_id',
      'finding_fingerprint and reason are required.',
    );
  }

  const id = ctx.storage.suppressions.insert({
    finding_fingerprint: inp.finding_fingerprint,
    reason: inp.reason,
    ...(inp.expires_at !== undefined ? { expires_at: inp.expires_at } : {}),
    created_by: 'user',
  });

  return {
    ok: true,
    suppression_id: id,
    finding_fingerprint: inp.finding_fingerprint,
    expires_at: inp.expires_at ?? null,
  };
}

function failDomain(
  code: DomainError['code'],
  message: string,
): ToolResult<Record<string, unknown>> {
  return { ok: false, error: { code, message } };
}
