/**
 * `wp_cron_audit` — list WP scheduled events and flag suspicious ones.
 *
 * Persistent backdoors on compromised WP sites almost always set up
 * recurring cron events (curl to attacker IP, dump options, etc.). WP-CLI
 * exposes the cron table via `wp cron event list` — we parse it and:
 *   - flag events whose `hook` name doesn't follow a recognised pattern
 *     (most legit events live under `wp_*`, `action_scheduler_*`, or a
 *     plugin slug prefix).
 *   - flag events scheduled with a base64-looking argument.
 *   - flag events from inactive plugins (we cross-reference `wp plugin
 *     list`).
 */

import { existsSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { join } from 'node:path';
import { z } from 'zod';
import type { PluginContext } from '../context.js';
import { resolveProjectPath } from '../platform/projectPath.js';
import { runProcess } from '../runners/processRunner.js';
import { scannerAvailable } from './scanHelpers.js';
import type { DomainError, ToolResult } from '../types.js';
import { registerToolModule, type ToolModule } from './index.js';

const inputSchema = {
  wp_install_path: z
    .string()
    .min(1)
    .describe('Path to the directory containing wp-config.php.'),
};

interface CronEvent {
  hook: string;
  next_run_relative: string;
  schedule: string;
  args?: string[];
}

interface FlaggedEvent extends CronEvent {
  reasons: string[];
}

const KNOWN_PREFIXES = [
  'wp_',
  'do_pings',
  'action_scheduler_',
  'jetpack_',
  'woocommerce_',
  'wc_',
  'wpforms_',
  'rest_post_revisions_cleanup',
  'recovery_mode_clean_expired_keys',
  'delete_expired_transients',
  'update_network_counts',
  'wp_privacy_delete_old_export_files',
  'wp_scheduled_auto_draft_delete',
  'wp_scheduled_delete',
  'wp_site_health_scheduled_check',
  'wp_update_plugins',
  'wp_update_themes',
  'wp_version_check',
];

const BASE64_RE = /^[A-Za-z0-9+/]{40,}={0,2}$/;

const tool: ToolModule = {
  name: 'wp_cron_audit',
  title: 'WordPress cron audit (suspicious scheduled events)',
  description:
    'List WP scheduled cron events and flag suspicious ones: unknown hook namespaces, ' +
    'base64-looking args, events from inactive plugins. Persistent backdoors on compromised WP ' +
    'sites almost always live here.',
  inputSchema,
  handler: async (input, ctx) => handler(input, ctx),
};

registerToolModule(tool);

async function handler(
  input: Record<string, unknown>,
  ctx: PluginContext,
): Promise<ToolResult<Record<string, unknown>>> {
  const inp = input as { wp_install_path: string };
  let installPath: string;
  try {
    installPath = resolveProjectPath(inp.wp_install_path).path;
  } catch (e) {
    return failDomain('not_a_wordpress_install', (e as Error).message);
  }
  if (!existsSync(join(installPath, 'wp-config.php'))) {
    return failDomain('not_a_wordpress_install', `No wp-config.php in ${installPath}`);
  }

  const wpBin = await scannerAvailable('wp');
  if (!wpBin) {
    return failDomain(
      'missing_scanner',
      'WP-CLI (`wp`) is required for wp_cron_audit. Run install_toolchain with tools=["wp-cli"].',
    );
  }

  // Cron events
  const cronResult = await runProcess({
    command: 'wp',
    args: ['cron', 'event', 'list', `--path=${installPath}`, '--format=json'],
    cwd: installPath,
    timeoutMs: 60_000,
  });
  if (cronResult.outcome !== 'completed') {
    return failDomain(
      'scanner_failed',
      `wp cron event list failed: ${cronResult.stderr.split(/\r?\n/)[0] ?? cronResult.outcome}`,
    );
  }
  let events: CronEvent[] = [];
  try {
    events = JSON.parse(cronResult.stdout) as CronEvent[];
  } catch {
    /* leave events empty */
  }

  // Plugin slugs for matching (best-effort; if it fails, we still proceed
  // with prefix-only matching).
  const pluginList = await runProcess({
    command: 'wp',
    args: ['plugin', 'list', `--path=${installPath}`, '--fields=name,status', '--format=json'],
    cwd: installPath,
    timeoutMs: 30_000,
  });
  const activePlugins = new Set<string>();
  const inactivePlugins = new Set<string>();
  if (pluginList.outcome === 'completed') {
    try {
      const parsed = JSON.parse(pluginList.stdout) as Array<{ name: string; status: string }>;
      for (const p of parsed) {
        if ((p.status ?? '').toLowerCase() === 'active') activePlugins.add(p.name);
        else inactivePlugins.add(p.name);
      }
    } catch {
      /* ignore */
    }
  }

  const flagged: FlaggedEvent[] = [];
  for (const ev of events) {
    const reasons: string[] = [];
    const hook = ev.hook ?? '';
    if (!matchesKnownPrefix(hook, activePlugins)) {
      reasons.push('hook does not match any known WP / plugin namespace');
    }
    if (matchesInactivePlugin(hook, inactivePlugins)) {
      reasons.push('hook belongs to an inactive plugin (possible orphaned backdoor)');
    }
    if (Array.isArray(ev.args)) {
      for (const a of ev.args) {
        if (typeof a === 'string' && BASE64_RE.test(a)) {
          reasons.push('argument looks base64-encoded — common obfuscation pattern');
          break;
        }
      }
    }
    if (reasons.length > 0) flagged.push({ ...ev, reasons });
  }

  // Persist
  const scanId = randomUUID();
  ctx.storage.scans.insert({
    scan_id: scanId,
    scan_type: 'wp_cron_audit',
    project_path: installPath,
    tree_hash: '',
  });
  ctx.storage.scans.finalize({
    scan_id: scanId,
    status: 'completed',
    tools_run: [{ name: 'wp-cli', status: 'ok' }],
    missing_tools: [],
    meta: {
      total_events: events.length,
      flagged_count: flagged.length,
      events_flagged: flagged,
    },
  });

  return {
    ok: true,
    scan_id: scanId,
    total_events: events.length,
    flagged_count: flagged.length,
    events_flagged: flagged,
    suggestion:
      flagged.length > 0
        ? 'Review each flagged hook. Use `wp cron event delete <hook>` to remove. Confirm by ' +
          'reading the source PHP for the hook handler before deleting.'
        : 'No obviously-suspicious cron events. This is not a guarantee — manual review is still wise.',
  };
}

function matchesKnownPrefix(hook: string, activePlugins: Set<string>): boolean {
  if (KNOWN_PREFIXES.some((p) => hook.startsWith(p))) return true;
  for (const plugin of activePlugins) {
    const slug = plugin.split('/')[0]?.replace(/\.php$/, '');
    if (slug && hook.toLowerCase().includes(slug.toLowerCase())) return true;
  }
  return false;
}

function matchesInactivePlugin(hook: string, inactivePlugins: Set<string>): boolean {
  for (const plugin of inactivePlugins) {
    const slug = plugin.split('/')[0]?.replace(/\.php$/, '');
    if (slug && hook.toLowerCase().includes(slug.toLowerCase())) return true;
  }
  return false;
}

function failDomain(
  code: DomainError['code'],
  message: string,
): ToolResult<Record<string, unknown>> {
  return { ok: false, error: { code, message } };
}
