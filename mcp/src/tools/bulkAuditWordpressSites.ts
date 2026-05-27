/**
 * `bulk_audit_wordpress_sites` — run `wp_audit` against a list of WP
 * installs in parallel and return a consolidated summary.
 *
 * Useful for agencies / freelancers maintaining many WP sites at once.
 * Each site uses its own DB row (per the wp_audit semantics) — no
 * cross-pollination of meta.
 */

import { z } from 'zod';
import type { PluginContext } from '../context.js';
import type { ToolResult } from '../types.js';
import { registerToolModule, TOOLS, type ToolModule } from './index.js';

const inputSchema = {
  wp_install_paths: z
    .array(z.string().min(1))
    .min(1)
    .max(50)
    .describe('Up to 50 WP install paths to audit in parallel.'),
  concurrency: z
    .number()
    .int()
    .min(1)
    .max(10)
    .optional()
    .describe('Max sites audited at once. Default 4.'),
};

interface SiteSummary {
  wp_install_path: string;
  ok: boolean;
  scan_id?: string;
  wp_version?: string | null;
  flagged_count?: number;
  error?: { code: string; message: string };
}

const tool: ToolModule = {
  name: 'bulk_audit_wordpress_sites',
  title: 'Bulk wp_audit across many sites',
  description:
    'Run wp_audit on N WP installs in parallel (default concurrency 4). Returns one row per site ' +
    'with the wp_version, audit scan_id, and a flagged_count (anything in checksum_mismatches.core + ' +
    'modified plugins + modified themes).',
  inputSchema,
  handler: async (input, ctx) => handler(input, ctx),
};

registerToolModule(tool);

async function handler(
  input: Record<string, unknown>,
  ctx: PluginContext,
): Promise<ToolResult<Record<string, unknown>>> {
  const inp = input as { wp_install_paths: string[]; concurrency?: number };
  const limit = Math.max(1, Math.min(inp.concurrency ?? 4, 10));

  const wpAudit = TOOLS.find((t) => t.name === 'wp_audit');
  if (!wpAudit) {
    return {
      ok: false,
      error: { code: 'scanner_failed', message: 'wp_audit tool is not registered' },
    };
  }

  // Simple semaphore loop.
  const queue = [...inp.wp_install_paths];
  const results: SiteSummary[] = [];
  const workers: Promise<void>[] = [];

  for (let i = 0; i < limit; i += 1) {
    workers.push(
      (async () => {
        while (queue.length > 0) {
          const next = queue.shift();
          if (!next) break;
          const result = await wpAudit.handler({ wp_install_path: next }, ctx);
          results.push(summarise(next, result));
        }
      })(),
    );
  }
  await Promise.all(workers);

  // Sort results by wp_install_path so output is deterministic.
  results.sort((a, b) => a.wp_install_path.localeCompare(b.wp_install_path));

  const sitesWithIssues = results.filter((s) => (s.flagged_count ?? 0) > 0 || !s.ok);

  return {
    ok: true,
    total_sites: inp.wp_install_paths.length,
    successful: results.filter((s) => s.ok).length,
    failed: results.filter((s) => !s.ok).length,
    sites_with_issues: sitesWithIssues.length,
    sites: results,
  };
}

function summarise(path: string, result: ToolResult<Record<string, unknown>>): SiteSummary {
  if (!result.ok) {
    return {
      wp_install_path: path,
      ok: false,
      error: result.error,
    };
  }
  const r = result as unknown as {
    ok: true;
    scan_id?: string;
    wp_version?: string | null;
    checksum_mismatches?: {
      core?: unknown[];
      plugins?: Record<string, unknown[]>;
      themes?: Record<string, unknown[]>;
    };
  };
  const cm = r.checksum_mismatches ?? {};
  const flagged =
    (cm.core?.length ?? 0) +
    Object.values(cm.plugins ?? {}).reduce((a, b) => a + (b?.length ?? 0), 0) +
    Object.values(cm.themes ?? {}).reduce((a, b) => a + (b?.length ?? 0), 0);
  const summary: SiteSummary = {
    wp_install_path: path,
    ok: true,
    flagged_count: flagged,
  };
  if (r.scan_id !== undefined) summary.scan_id = r.scan_id;
  if (r.wp_version !== undefined) summary.wp_version = r.wp_version;
  return summary;
}
