/**
 * `wp_recommend_hardening` — read the latest `wp_audit` from storage and
 * produce a prioritised hardening checklist (Markdown).
 *
 * Pure read — no scanners. The calling model uses the checklist to drive
 * follow-up actions (suggesting plugin installs, config changes, etc).
 */

import type { PluginContext } from '../context.js';
import type { ToolResult } from '../types.js';
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
    'Generate a prioritised hardening checklist (Markdown) from the latest wp_audit. Pure read — ' +
    'inspects scans.meta of the most recent wp_audit, applies heuristics, returns recommendations.',
  inputSchema: {},
  handler: async (_input, ctx) => handler(ctx),
};

registerToolModule(tool);

async function handler(ctx: PluginContext): Promise<ToolResult<Record<string, unknown>>> {
  const audit = findLatestWpAudit(ctx);
  if (!audit) {
    return {
      ok: true,
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

function findLatestWpAudit(ctx: PluginContext): ReturnType<typeof ctx.storage.scans.getById> {
  const history = ctx.storage.scans.listHistory(50);
  const row = history.find((s) => s.scan_type === 'wp_audit' && s.status === 'completed');
  return row ? ctx.storage.scans.getById(row.scan_id) : null;
}
