/**
 * `wp_recommend_hardening` — read the latest `wp_audit` from storage and
 * produce a prioritised hardening checklist (Markdown).
 *
 * Pure read — no scanners. The calling model uses the checklist to drive
 * follow-up actions (suggesting plugin installs, config changes, etc).
 *
 * The audit is ONE install's (`project_path`, the install root `wp_audit`
 * files its row under; default: the server's working directory). It used to
 * be the newest wp_audit among the 50 newest scans of the whole database —
 * another install's admins and config flags, whenever it was audited last
 * (Task 24).
 */

import type { PluginContext } from '../context.js';
import { findLatestUsable } from '../history/openSet.js';
import { resolveProjectPath } from '../platform/projectPath.js';
import { ProjectPath } from '../schemas.js';
import type { ScanRecord, ToolResult } from '../types.js';
import { registerToolModule, type ToolModule } from './index.js';

interface ChecklistItem {
  priority: 'critical' | 'high' | 'medium' | 'low';
  category: 'config' | 'users' | 'integrity' | 'plugins' | 'meta';
  recommendation: string;
  rationale: string;
}

const tool: ToolModule = {
  name: 'wp_recommend_hardening',
  title: 'WordPress hardening checklist',
  description:
    "Generate a prioritised hardening checklist (Markdown) from one install's latest wp_audit " +
    "(project_path = the install root, default: the server's working directory). Pure read — " +
    'inspects scans.meta of that wp_audit, applies heuristics, returns recommendations.',
  inputSchema: { project_path: ProjectPath },
  handler: async (input, ctx) => handler(input, ctx),
};

registerToolModule(tool);

async function handler(
  input: Record<string, unknown>,
  ctx: PluginContext,
): Promise<ToolResult<Record<string, unknown>>> {
  const inp = input as { project_path?: string };
  let projectPath: string;
  try {
    projectPath = resolveProjectPath(inp.project_path).path;
  } catch (e) {
    return { ok: false, error: { code: 'not_a_git_repo', message: (e as Error).message } };
  }
  const audit = findLatestWpAudit(ctx, projectPath);
  if (!audit) {
    return {
      ok: true,
      project_path: projectPath,
      audit_found: false,
      message: 'No wp_audit on file. Run `wp_audit` first.',
      markdown: '## No data\n\nRun `wp_audit` against a WordPress install first.',
    };
  }
  const meta = (audit.meta ?? {}) as Record<string, unknown>;
  const items: ChecklistItem[] = [];

  // Config flags
  const flags = (meta['config_flags'] ?? {}) as Record<string, boolean | null>;
  if (flags['DISALLOW_FILE_EDIT'] !== true) {
    items.push({
      priority: 'high',
      category: 'config',
      recommendation: "Set DISALLOW_FILE_EDIT=true in wp-config.php",
      rationale:
        'Stops admins from editing PHP files via the WP dashboard. Standard hardening step — ' +
        'an attacker who gets admin access cannot drop a webshell directly via the UI.',
    });
  }
  if (flags['WP_DEBUG'] === true) {
    items.push({
      priority: 'high',
      category: 'config',
      recommendation: 'Disable WP_DEBUG in production',
      rationale:
        'WP_DEBUG can leak stack traces, file paths, and DB errors to attackers. Should never be on in prod.',
    });
  }
  if (flags['FORCE_SSL_ADMIN'] !== true) {
    items.push({
      priority: 'medium',
      category: 'config',
      recommendation: 'Set FORCE_SSL_ADMIN=true in wp-config.php',
      rationale: 'Ensures /wp-admin and login always use HTTPS even if the site has mixed content.',
    });
  }

  // Admin users
  const admins = (meta['admins'] ?? []) as Array<{
    user_login: string;
    user_email: string;
    risky: boolean;
  }>;
  const riskyAdmins = admins.filter((a) => a.risky);
  if (riskyAdmins.length > 0) {
    items.push({
      priority: 'critical',
      category: 'users',
      recommendation: `Rename / replace admin user(s): ${riskyAdmins.map((a) => a.user_login).join(', ')}`,
      rationale:
        'Standard credential-stuffing / brute-force attacks target the literal logins `admin`, ' +
        '`administrator`, `root`. Renaming to an arbitrary value kills the simplest attack surface.',
    });
  }
  if (admins.length > 3) {
    items.push({
      priority: 'medium',
      category: 'users',
      recommendation: `Review whether all ${admins.length} administrators still need that role`,
      rationale:
        'Each admin is a credential that can be phished / stolen. Move ex-staff to Editor or remove.',
    });
  }

  // Checksum integrity
  const checksum = (meta['checksum_mismatches'] ?? {}) as {
    core?: Array<{ file: string; status: string }>;
    plugins?: Record<string, unknown[]>;
    themes?: Record<string, unknown[]>;
  };
  if (checksum.core && checksum.core.length > 0) {
    items.push({
      priority: 'critical',
      category: 'integrity',
      recommendation: `${checksum.core.length} core file(s) differ from the WordPress.org checksum`,
      rationale:
        'Core files MUST match the published checksum. Differences = possible compromise. Reinstall ' +
        'core (`wp core download --force`) or restore from a clean backup.',
    });
  }
  const pluginMismatchCount = checksum.plugins
    ? Object.values(checksum.plugins).reduce((a, b) => a + (b?.length ?? 0), 0)
    : 0;
  if (pluginMismatchCount > 0) {
    items.push({
      priority: 'high',
      category: 'integrity',
      recommendation: `${pluginMismatchCount} plugin file(s) differ from the wp.org checksum`,
      rationale:
        'Modified plugin files are a backdoor vector. Re-install affected plugins from a clean source; ' +
        'inspect each modified file before deleting/replacing.',
    });
  }

  // Auto-update plugins
  const autoUpdate = (meta['plugins_with_auto_update'] ?? []) as string[];
  if (autoUpdate.length === 0) {
    items.push({
      priority: 'medium',
      category: 'plugins',
      recommendation: 'Enable auto-updates for at least the high-trust plugins',
      rationale:
        'CVEs in popular plugins (Elementor, Yoast, WPForms) are exploited within hours of disclosure. ' +
        'Auto-update closes the window.',
    });
  }

  // Warnings from wp_audit itself
  const auditWarnings = (meta['warnings'] ?? []) as string[];
  if (auditWarnings.length > 0) {
    items.push({
      priority: 'low',
      category: 'meta',
      recommendation: 'Re-run wp_audit — some subsections failed and were skipped',
      rationale: auditWarnings.slice(0, 3).join('; '),
    });
  }

  // Always-recommend baseline items
  items.push({
    priority: 'high',
    category: 'plugins',
    recommendation: 'Install a 2FA plugin (Wordfence, Two Factor, Sucuri)',
    rationale:
      "Stolen admin credentials are the #1 WP compromise vector. 2FA defeats the entire class.",
  });
  items.push({
    priority: 'medium',
    category: 'plugins',
    recommendation: 'Install a security plugin with login attempt limiting',
    rationale:
      'Wordfence / Sucuri / iThemes Security cap login attempts and block IPs — stops brute-force at the door.',
  });

  // Sort by priority
  const order = { critical: 0, high: 1, medium: 2, low: 3 };
  items.sort((a, b) => order[a.priority] - order[b.priority]);

  return {
    ok: true,
    project_path: projectPath,
    audit_found: true,
    audit_scan_id: audit.scan_id,
    items,
    summary: {
      total: items.length,
      critical: items.filter((i) => i.priority === 'critical').length,
      high: items.filter((i) => i.priority === 'high').length,
    },
    markdown: toMarkdown(items, audit.scan_id),
  };
}

function toMarkdown(items: ChecklistItem[], scanId: string): string {
  const out: string[] = [];
  out.push('# WordPress hardening checklist');
  out.push('');
  out.push(`Based on wp_audit scan \`${scanId}\``);
  out.push('');
  const groups: Array<['critical' | 'high' | 'medium' | 'low', string]> = [
    ['critical', '🔴 Critical'],
    ['high', '🟠 High'],
    ['medium', '🟡 Medium'],
    ['low', '🔵 Low'],
  ];
  for (const [prio, header] of groups) {
    const slice = items.filter((i) => i.priority === prio);
    if (slice.length === 0) continue;
    out.push(`## ${header}`);
    out.push('');
    for (const item of slice) {
      out.push(`- **${item.recommendation}**`);
      out.push(`  - _Why:_ ${item.rationale}`);
    }
    out.push('');
  }
  return out.join('\n');
}

/**
 * The install's newest completed wp_audit — a project-scoped query. The
 * audit reports through `meta`, so its scanner coverage does not disqualify
 * it (`resources/wp.ts` reads it the same way).
 */
function findLatestWpAudit(ctx: PluginContext, projectPath: string): ScanRecord | null {
  return findLatestUsable(ctx.storage, projectPath, ['wp_audit'], { skipCoverageNone: false }).scan;
}
