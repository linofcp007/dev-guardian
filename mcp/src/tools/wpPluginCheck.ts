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
 * any project's, and stale ones beside current ones. Each is looked up under
 * every spelling an earlier build may have filed it with
 * (`wordpress/siteKeys.ts`, fix round 1 I3).
 *
 * **It never refuses for want of a local project** (fix round 1, M4): the
 * lookup reads the database, so with no `project_path` it answers for
 * `wp_install_path` even when that install is not on this machine (its
 * canonical spelling), else for the server's working directory — even a
 * home directory, as `health_status` does. Only an explicit `project_path`
 * that does not resolve is refused.
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
import { canonicalPath, resolveProjectPath } from '../platform/projectPath.js';
import { serverProjectPath } from '../resources/paging.js';
import { runProcess } from '../runners/processRunner.js';
import { ProjectPath } from '../schemas.js';
import { scannerAvailable } from './scanHelpers.js';
import { CVE_SOURCE_SCAN_TYPES, type Cve, type DomainError, type ScanRecord, type ToolResult } from '../types.js';
import { latestUnderKeys, wpInstallKeys, wpSiteKeys } from '../wordpress/siteKeys.js';
import { registerToolModule, type ToolModule } from './index.js';

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
  // See the module comment: only an explicit project_path is validated.
  let projectPath: string;
  const rawProject = inp.project_path ?? inp.wp_install_path;
  if (inp.project_path !== undefined && inp.project_path.length > 0) {
    try {
      projectPath = resolveProjectPath(inp.project_path).path;
    } catch (e) {
      return failDomain('not_a_git_repo', (e as Error).message);
    }
  } else if (inp.wp_install_path !== undefined && inp.wp_install_path.length > 0) {
    projectPath = canonicalPath(inp.wp_install_path);
  } else {
    projectPath = serverProjectPath();
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
  const allActive = cveSources(ctx, wpInstallKeys(projectPath, rawProject), inp.target_url)
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
function cveSources(ctx: PluginContext, installKeys: readonly string[], targetUrl: string | undefined): ScanRecord[] {
  const siteKeys = targetUrl !== undefined ? wpSiteKeys(targetUrl) : [];
  const found = [
    latestUnderKeys(ctx.storage, installKeys, CVE_SOURCE_SCAN_TYPES, { slot: 'deps' }),
    // Filed under the install root, or — URL-only — under the site.
    latestUnderKeys(ctx.storage, [...installKeys, ...siteKeys], ['wp_vuln_check']),
    // wp_vuln_check_source (Task 18): source-based match against the
    // Wordfence feed, no live URL — same `cves` shape, same slug key.
    latestUnderKeys(ctx.storage, installKeys, ['wp_vuln_check_source']),
  ];
  return found.filter((s): s is ScanRecord => s !== null);
}

function failDomain(
  code: DomainError['code'],
  message: string,
): ToolResult<Record<string, unknown>> {
  return { ok: false, error: { code, message } };
}
