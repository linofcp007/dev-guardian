/**
 * `bulk_audit_wordpress_sites` — run `wp_audit` against a list of WP
 * installs in parallel and return a consolidated summary.
 *
 * Useful for agencies / freelancers maintaining many WP sites at once.
 * Each site uses its own DB row (per the wp_audit semantics) — no
 * cross-pollination of meta.
 *
 * **A site's gaps travel with it** (review 3.6.1, finding 2). A wp_audit whose
 * checksum calls failed is `ok: true` with `missing_tools: ['wp-cli']` and
 * coverage partial; the summary kept only the mismatches it found, so that
 * site read `flagged_count: 0`, counted as successful and stayed out of
 * `sites_with_issues` — an unverified site shown as a clean one. Each row now
 * carries the site's `coverage`, `missing_tools` and what was `not_checked`;
 * a partial site is `partial`, not `successful`, and is one of the sites with
 * issues; the totals carry a `coverage` (full only when every site's is,
 * none when no site was audited at all) and the union of `missing_tools`.
 */

import { z } from 'zod';
import type { PluginContext } from '../context.js';
import type { ScanCoverage, ToolResult, ToolRun } from '../types.js';
import { defineTool, registerToolModule, type ToolInput, TOOLS } from './index.js';

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
  /** The site's audit coverage: `none` when it was not audited at all. */
  coverage: ScanCoverage;
  missing_tools: string[];
  /** What the site's audit did not answer (its `tools_run` reason), when coverage is not full. */
  not_checked?: string;
  error?: { code: string; message: string };
}

const tool = defineTool({
  name: 'bulk_audit_wordpress_sites',
  title: 'Bulk wp_audit across many sites',
  description:
    'Run wp_audit on N WP installs in parallel (default concurrency 4). Returns one row per site ' +
    'with the wp_version, audit scan_id, and a flagged_count (checksum_mismatches.core + plugins; theme ' +
    'files are not checked: WP-CLI has no theme checksums), plus its coverage, missing_tools and what was ' +
    'not_checked: a partially audited site is partial and an issue, never a clean success.',
  inputSchema,
  handler: async (input, ctx) => handler(input, ctx),
});

registerToolModule(tool);

async function handler(
  inp: ToolInput<typeof inputSchema>,
  ctx: PluginContext,
): Promise<ToolResult<Record<string, unknown>>> {
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

  const full = (s: SiteSummary): boolean => s.ok && s.coverage === 'full';
  const sitesWithIssues = results.filter((s) => (s.flagged_count ?? 0) > 0 || !full(s));
  const coverage: ScanCoverage = results.every(full)
    ? 'full'
    : results.some((s) => s.ok && s.coverage !== 'none')
      ? 'partial'
      : 'none';

  return {
    ok: true,
    total_sites: inp.wp_install_paths.length,
    coverage,
    missing_tools: [...new Set(results.flatMap((s) => s.missing_tools))].sort(),
    successful: results.filter(full).length,
    partial: results.filter((s) => s.ok && !full(s)).length,
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
      coverage: 'none',
      missing_tools: result.error.code === 'missing_scanner' ? ['wp-cli'] : [],
      error: result.error,
    };
  }
  const r = result as unknown as {
    ok: true;
    scan_id?: string;
    wp_version?: string | null;
    coverage?: ScanCoverage;
    missing_tools?: string[];
    tools_run?: ToolRun[];
    checksum_mismatches?: {
      core?: unknown[];
      plugins?: Record<string, unknown[]>;
    };
  };
  const cm = r.checksum_mismatches ?? {};
  const flagged =
    (cm.core?.length ?? 0) +
    Object.values(cm.plugins ?? {}).reduce((a, b) => a + (b?.length ?? 0), 0);
  // A result that does not say its coverage cannot be shown complete.
  const coverage = r.coverage ?? 'partial';
  const summary: SiteSummary = {
    wp_install_path: path,
    ok: true,
    flagged_count: flagged,
    coverage,
    missing_tools: r.missing_tools ?? [],
  };
  if (coverage !== 'full') {
    const why = (r.tools_run ?? []).map((t) => t.reason).filter((x): x is string => x !== undefined && x !== '');
    summary.not_checked = why.length > 0 ? why.join('; ') : 'the audit did not say what it left out';
  }
  if (r.scan_id !== undefined) summary.scan_id = r.scan_id;
  if (r.wp_version !== undefined) summary.wp_version = r.wp_version;
  return summary;
}
