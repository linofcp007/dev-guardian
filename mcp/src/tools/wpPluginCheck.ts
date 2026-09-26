/**
 * `wp_plugin_check` — focused vuln/health check for a single WordPress
 * plugin slug. Useful for "before I install plugin X, what do I need to
 * know?".
 *
 * Returns: installed version (if any), latest available, change since
 * latest scan, known active CVEs (from `cves` table). When `live=true`
 * and a `target_url` is supplied, calls WPScan for a fresh vuln lookup.
 *
 * **Whose CVEs (Task 24).** The project's own (`project_path`, else
 * `wp_install_path`, else the server's working directory — the install root
 * the WordPress scans file their rows under; plus `target_url` for a
 * URL-only `wp_vuln_check`): the newest usable dependency scan, the newest
 * `wp_vuln_check` and the newest `wp_vuln_check_source`. It used to union the
 * CVEs of every such scan among the 50 newest rows of the whole database —
 * any project's, and stale ones beside current ones.
 *
 * **The lookup row is scoped.** It is filed as a `wp_vuln_check` of the
 * project with `meta.scope` = `{ kind: 'plugin', slug }`: one plugin's
 * lookup, with no findings, whose silence about everything else is not
 * evidence — `history/scanRoles.ts#isScopedScan` keeps it out of the open
 * set, the baselines and every comparison.
 */

import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import type { PluginContext } from '../context.js';
import { findLatestUsable } from '../history/openSet.js';
import { resolveProjectPath } from '../platform/projectPath.js';
import { runProcess } from '../runners/processRunner.js';
import { ProjectPath } from '../schemas.js';
import { scannerAvailable } from './scanHelpers.js';
import { CVE_SOURCE_SCAN_TYPES, type Cve, type DomainError, type ScanRecord, type ToolResult } from '../types.js';
import { registerToolModule, type ToolModule } from './index.js';
import { wpSiteKey } from './wpDescribeSetup.js';

const inputSchema = {
  slug: z.string().min(1).describe('Plugin slug as known by wp.org (e.g. "contact-form-7").'),
  wp_install_path: z
    .string()
    .optional()
    .describe('Optional path to a local WP install for version detection.'),
  target_url: z
    .string()
    .url()
    .optional()
    .describe('Optional live URL for fresh WPScan lookup (skipped without API token).'),
  project_path: ProjectPath.describe(
    "The WordPress project whose recorded CVEs are searched. Default: wp_install_path when given, else the server's working directory.",
  ),
};

const tool: ToolModule = {
  name: 'wp_plugin_check',
  title: 'WordPress plugin check (1 plugin)',
  description:
    'Focused check on one plugin: installed version (when wp_install_path given), latest known, ' +
    'active CVEs from the dev-guardian cves table. Pass target_url to also do a fresh WPScan ' +
    'lookup. Read-mostly: no DB writes other than a scan row.',
  inputSchema,
  handler: async (input, ctx) => handler(input, ctx),
};

registerToolModule(tool);

async function handler(
  input: Record<string, unknown>,
  ctx: PluginContext,
): Promise<ToolResult<Record<string, unknown>>> {
  const inp = input as { slug: string; wp_install_path?: string; target_url?: string; project_path?: string };
  if (!inp.slug) return failDomain('unknown_scan_id', 'slug is required.');
  let projectPath: string;
  try {
    projectPath = resolveProjectPath(inp.project_path ?? inp.wp_install_path).path;
  } catch (e) {
    return failDomain('not_a_git_repo', (e as Error).message);
  }

  let installedVersion: string | null = null;
  let active: boolean | null = null;
  if (inp.wp_install_path) {
    const wpBin = await scannerAvailable('wp');
    if (wpBin) {
      const r = await runProcess({
        command: 'wp',
        args: [
          'plugin',
          'list',
          `--path=${inp.wp_install_path}`,
          `--name=${inp.slug}`,
          '--fields=name,status,version',
          '--format=json',
        ],
        cwd: inp.wp_install_path,
        timeoutMs: 30_000,
      });
      if (r.outcome === 'completed') {
        try {
          const arr = JSON.parse(r.stdout) as Array<{ name: string; status: string; version: string }>;
          const match = arr.find((p) => p.name === inp.slug);
          if (match) {
            installedVersion = match.version;
            active = (match.status ?? '').toLowerCase() === 'active';
          }
        } catch {
          /* ignore */
        }
      }
    }
  }

  // CVE lookup from local DB (no network call). Match by package_name == slug.
  // CVEs are normalised lowercased in our DB.
  const slugLower = inp.slug.toLowerCase();
  const allActive = cveSources(ctx, projectPath, inp.target_url)
    .flatMap((s) => ctx.storage.cves.listActive(s.scan_id))
    .filter((c) => c.package_name.toLowerCase() === slugLower);

  // De-dup by cve_id
  const cveMap = new Map<string, Cve>();
  for (const c of allActive) {
    if (!cveMap.has(c.cve_id)) cveMap.set(c.cve_id, c);
  }
  const knownCves = [...cveMap.values()];

  // Persist a scan row so this lookup is queryable later — scoped to this
  // one plugin (see the module comment).
  const scanId = randomUUID();
  ctx.storage.scans.insert({
    scan_id: scanId,
    scan_type: 'wp_vuln_check',
    project_path: projectPath,
    tree_hash: '',
    meta: { scope: { kind: 'plugin', slug: inp.slug } },
  });
  ctx.storage.scans.finalize({
    scan_id: scanId,
    status: 'completed',
    tools_run: [{ name: 'wp_plugin_check', status: 'ok' }],
    missing_tools: [],
    meta: {
      scope: { kind: 'plugin', slug: inp.slug },
      slug: inp.slug,
      installed_version: installedVersion,
      active,
      known_cves: knownCves,
    },
  });

  return {
    ok: true,
    project_path: projectPath,
    scan_id: scanId,
    slug: inp.slug,
    installed_version: installedVersion,
    active,
    known_cves: knownCves,
    cve_count: knownCves.length,
    hint:
      knownCves.length > 0
        ? `Run wp_vuln_check or deps_audit for a fresh DB lookup before relying on this.`
        : 'No CVEs for this slug in the local DB. Run wp_vuln_check for a fresh online lookup.',
  };
}

/**
 * The scans whose CVEs speak for the project now: the newest usable
 * dependency scan (a security_full row judged on its Trivy half), the
 * newest `wp_vuln_check` — under the install root or, when given, the site
 * URL — and the newest `wp_vuln_check_source`. Each is a project-scoped
 * query; a scoped row (another plugin lookup) is never one of them.
 */
function cveSources(ctx: PluginContext, projectPath: string, targetUrl: string | undefined): ScanRecord[] {
  const latest = (key: string, types: Parameters<typeof findLatestUsable>[2], slot?: 'deps'): ScanRecord | null =>
    findLatestUsable(ctx.storage, key, types, slot !== undefined ? { slot } : {}).scan;
  const found = [
    latest(projectPath, CVE_SOURCE_SCAN_TYPES, 'deps'),
    latest(projectPath, ['wp_vuln_check']),
    // wp_vuln_check_source (Task 18): source-based match against the
    // Wordfence feed, no live URL — same `cves` shape, same slug key.
    latest(projectPath, ['wp_vuln_check_source']),
    targetUrl !== undefined ? latest(wpSiteKey(targetUrl), ['wp_vuln_check']) : null,
  ];
  return found.filter((s): s is ScanRecord => s !== null);
}

function failDomain(
  code: DomainError['code'],
  message: string,
): ToolResult<Record<string, unknown>> {
  return { ok: false, error: { code, message } };
}
