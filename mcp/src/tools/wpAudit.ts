/**
 * `wp_audit` — audit a live WordPress install via WP-CLI.
 *
 * Standalone tool (no factory). Requires `wp` (WP-CLI) on PATH and a
 * directory containing `wp-config.php`. All WP-CLI invocations are
 * read-only.
 *
 * Per-subsection retry: each WP-CLI call that FAILED is retried up to 3
 * times with exponential backoff (1s, 3s, 9s) before being skipped. A
 * failing subsection puts a warning in `warnings[]` and is a named gap
 * (`wp-cli` in `missing_tools`, coverage partial) but never fails the whole
 * audit — partial data is preferable to no data.
 *
 * ---- Checksums: exit 1 is the answer, not a failure (review I5) -----------
 *
 * `wp core verify-checksums --format=json` and `wp plugin verify-checksums`
 * print their mismatches as JSON rows on stdout and THEN `Error: …` on
 * stderr, exiting 1 (wp-cli/checksum-command: `Checksum_Core_Command`
 * ends with `display_items( $this->errors )` then `WP_CLI::error(
 * "WordPress installation doesn't verify against checksums." )`; the plugin
 * command reports through `Utils\report_batch_operation_results`, which is a
 * `WP_CLI::error` on any failure). The exit 1 used to read as a failed call:
 * the rows were dropped (a tampered install showed NO mismatches, wp-cli
 * ok, completed) and the call retried three times (~13 s). An exit 1 whose
 * stdout parses as those rows is now the report, taken as is and never
 * retried. A plugin WP-CLI skipped (no checksums for its version on
 * wordpress.org, or no version: a warning, not an error) was not verified
 * and is named in `checksums_not_checked.plugins`. There is no `wp theme
 * verify-checksums` (checksum-command registers core and plugin only), so
 * themes are never asked for and read "not checked", never "no
 * mismatches".
 */

import { existsSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { join } from 'node:path';
import { z } from 'zod';
import type { PluginContext } from '../context.js';
import { resolveProjectPath } from '../platform/projectPath.js';
import { runProcess, type ProcessRunResult } from '../runners/processRunner.js';
import { computeCoverage } from './scanCoverage.js';
import { scannerAvailable } from './scanHelpers.js';
import type { DomainError, ToolResult, ToolRun } from '../types.js';
import { registerToolModule, type ToolModule } from './index.js';

const RETRY_DELAYS_MS = [1000, 3000, 9000] as const;
const DEFAULT_RISKY_LOGINS = ['admin', 'administrator', 'root', 'wpadmin'];

/** What `checksums_not_checked.themes` says, always: WP-CLI cannot check them. */
export const THEMES_NOT_CHECKED = 'not checked (WP-CLI has no theme checksums)';

const inputSchema = {
  wp_install_path: z
    .string()
    .min(1)
    .describe('Path to the directory containing wp-config.php.'),
  include_users: z.boolean().optional(),
  include_options: z.boolean().optional(),
  risky_login_names: z.array(z.string()).optional(),
};

interface ChecksumFile {
  file: string;
  status: 'modified' | 'missing' | 'added' | 'unknown';
}

interface AuditMeta {
  wp_version: string | null;
  checksum_mismatches: {
    core: ChecksumFile[];
    plugins: Record<string, ChecksumFile[]>;
  };
  /** What WP-CLI did not verify: themes (it cannot), and the plugins it skipped. */
  checksums_not_checked: {
    themes: string;
    plugins: Array<{ plugin: string; reason: string }>;
  };
  config_flags: Record<string, boolean | null>;
  admins: Array<{ user_login: string; user_email: string; risky: boolean }>;
  plugins_with_auto_update: string[];
  warnings: string[];
}

const tool: ToolModule = {
  name: 'wp_audit',
  title: 'Live WordPress install audit',
  description:
    'Audit a running WordPress install via WP-CLI (read-only): core/plugin file checksums (WP-CLI has none ' +
    'for themes: reported not checked), admin user list, dangerous config flags, plugins with auto_update ' +
    'on. Persists a scan row of type wp_audit so guardian://scans/{id} returns the structured audit.',
  inputSchema,
  handler: async (input, ctx) => handler(input, ctx),
};

registerToolModule(tool);

async function handler(
  input: Record<string, unknown>,
  ctx: PluginContext,
): Promise<ToolResult<Record<string, unknown>>> {
  const inp = input as {
    wp_install_path: string;
    include_users?: boolean;
    include_options?: boolean;
    risky_login_names?: string[];
  };
  if (!inp.wp_install_path) {
    return failDomain('not_a_wordpress_install', 'wp_install_path is required.');
  }
  let installPath: string;
  try {
    installPath = resolveProjectPath(inp.wp_install_path).path;
  } catch (e) {
    return failDomain('not_a_wordpress_install', (e as Error).message);
  }
  if (!existsSync(join(installPath, 'wp-config.php'))) {
    return failDomain(
      'not_a_wordpress_install',
      `No wp-config.php in ${installPath}`,
    );
  }

  const wpBin = await scannerAvailable('wp');
  if (!wpBin) {
    return failDomain(
      'missing_scanner',
      'WP-CLI (`wp`) is not installed. Run install_toolchain with tools=["wp-cli"].',
    );
  }

  const includeUsers = inp.include_users ?? true;
  const includeOptions = inp.include_options ?? true;
  const riskyLogins = new Set(
    (inp.risky_login_names ?? DEFAULT_RISKY_LOGINS).map((s) => s.toLowerCase()),
  );

  const meta: AuditMeta = {
    wp_version: null,
    checksum_mismatches: { core: [], plugins: {} },
    checksums_not_checked: { themes: THEMES_NOT_CHECKED, plugins: [] },
    config_flags: {
      DISALLOW_FILE_EDIT: null,
      WP_DEBUG: null,
      WP_DEBUG_LOG: null,
      FORCE_SSL_ADMIN: null,
    },
    admins: [],
    plugins_with_auto_update: [],
    warnings: [],
  };
  /** Subsections that did not answer: each a named gap. */
  const gaps: string[] = [];

  // Parallelise the independent WP-CLI subcommands. Each call goes through
  // the same retry policy (3 attempts, exp. backoff). Worst case improves
  // from 9 × ~10s sequential to ~10s wall-clock when ALL of them retry.
  const configFlags = includeOptions
    ? ['DISALLOW_FILE_EDIT', 'WP_DEBUG', 'WP_DEBUG_LOG', 'FORCE_SSL_ADMIN']
    : [];

  const [
    versionResult,
    coreVerify,
    pluginVerify,
    adminResult,
    pluginListResult,
    ...configResults
  ] = await Promise.all([
    retry(() => wpCall(['core', 'version', `--path=${installPath}`], installPath, ctx)),
    retry(() =>
      wpCall(
        ['core', 'verify-checksums', `--path=${installPath}`, '--format=json'],
        installPath,
        ctx,
        { rowsOnExit1: true },
      ),
    ),
    retry(() =>
      wpCall(
        ['plugin', 'verify-checksums', '--all', `--path=${installPath}`, '--format=json'],
        installPath,
        ctx,
        { rowsOnExit1: true },
      ),
    ),
    includeUsers
      ? retry(() =>
          wpCall(
            [
              'user',
              'list',
              '--role=administrator',
              `--path=${installPath}`,
              '--fields=user_login,user_email',
              '--format=json',
            ],
            installPath,
            ctx,
          ),
        )
      : Promise.resolve({ ok: true, stdout: '[]', stderr: '', reason: '' } as WpResult),
    retry(() =>
      wpCall(
        [
          'plugin',
          'list',
          `--path=${installPath}`,
          '--fields=name,auto_update',
          '--format=json',
        ],
        installPath,
        ctx,
      ),
    ),
    ...configFlags.map((flag) =>
      retry(() => wpCall(['config', 'get', flag, `--path=${installPath}`], installPath, ctx)),
    ),
  ]);

  // -------- Apply results
  if (versionResult.ok) {
    meta.wp_version = versionResult.stdout.trim() || null;
  } else {
    meta.warnings.push(`core version: ${versionResult.reason}`);
    gaps.push('core version not read');
  }

  if (coreVerify.ok) {
    meta.checksum_mismatches.core = parseChecksumOutput(coreVerify);
  } else {
    meta.warnings.push(`core verify-checksums: ${coreVerify.reason}`);
    gaps.push('core checksums not verified');
  }

  if (pluginVerify.ok) {
    meta.checksum_mismatches.plugins = groupByComponent(pluginVerify);
    meta.checksums_not_checked.plugins = skippedPlugins(pluginVerify.stderr);
    if (meta.checksums_not_checked.plugins.length > 0) {
      gaps.push(
        `${meta.checksums_not_checked.plugins.length} plugin(s) not verified: ` +
          meta.checksums_not_checked.plugins.map((p) => p.plugin).join(', '),
      );
    }
  } else {
    meta.warnings.push(`plugin verify-checksums: ${pluginVerify.reason}`);
    gaps.push('plugin checksums not verified');
  }
  meta.warnings.push(`theme checksums: ${THEMES_NOT_CHECKED} — theme files were not verified`);

  if (includeUsers) {
    if (adminResult.ok) {
      try {
        const arr = JSON.parse(adminResult.stdout) as Array<{
          user_login: string;
          user_email: string;
        }>;
        meta.admins = arr.map((u) => ({
          user_login: u.user_login,
          user_email: u.user_email,
          risky: riskyLogins.has((u.user_login ?? '').toLowerCase()),
        }));
      } catch {
        meta.warnings.push('user list: stdout not JSON');
        gaps.push('admin users not read');
      }
    } else {
      meta.warnings.push(`user list: ${adminResult.reason}`);
      gaps.push('admin users not read');
    }
  }

  if (pluginListResult.ok) {
    try {
      const arr = JSON.parse(pluginListResult.stdout) as Array<{
        name: string;
        auto_update: string;
      }>;
      meta.plugins_with_auto_update = arr
        .filter((p) => (p.auto_update ?? '').toLowerCase() === 'on')
        .map((p) => p.name);
    } catch {
      meta.warnings.push('plugin list: stdout not JSON');
      gaps.push('plugin list not read');
    }
  } else {
    meta.warnings.push(`plugin list: ${pluginListResult.reason}`);
    gaps.push('plugin list not read');
  }

  configFlags.forEach((flag, i) => {
    const r = configResults[i];
    if (!r) return;
    if (r.ok) {
      const val = r.stdout.trim().toLowerCase();
      meta.config_flags[flag] = val === 'true' || val === '1';
    } else {
      meta.warnings.push(`config get ${flag}: ${r.reason}`);
      gaps.push(`config ${flag} not read`);
    }
  });

  // -------- Bookkeeping: what did not answer is named, never `ok` in silence.
  const answered = [versionResult, coreVerify, pluginVerify, pluginListResult, ...configResults].some((r) => r.ok);
  const toolRun: ToolRun =
    gaps.length === 0
      ? { name: 'wp-cli', status: 'ok' }
      : { name: 'wp-cli', status: answered ? 'ok' : 'failed', reason: gaps.join('; ') };
  const tools_run = [toolRun];
  const missing_tools = gaps.length > 0 ? ['wp-cli'] : [];
  const coverage = computeCoverage(tools_run, missing_tools);

  // -------- Persist scan row with meta
  const scanId = randomUUID();
  ctx.storage.scans.insert({
    scan_id: scanId,
    scan_type: 'wp_audit',
    project_path: installPath,
    tree_hash: '',
  });
  ctx.storage.scans.finalize({
    scan_id: scanId,
    status: answered ? 'completed' : 'failed',
    tools_run,
    missing_tools,
    meta: meta as unknown as Record<string, unknown>,
  });

  return {
    ok: true,
    scan_id: scanId,
    coverage,
    tools_run,
    missing_tools,
    ...meta,
  };
}

interface WpResult {
  ok: boolean;
  stdout: string;
  stderr: string;
  reason: string;
}

/**
 * `rowsOnExit1`: the verify-checksums commands exit 1 AFTER printing their
 * mismatch rows (see the module comment) — that exit with rows on stdout is
 * the answer. Exit 1 without rows (checksums unavailable, no install) is
 * still a failure.
 */
async function wpCall(
  args: string[],
  cwd: string,
  ctx: PluginContext,
  opts: { rowsOnExit1?: boolean } = {},
): Promise<WpResult> {
  const r: ProcessRunResult = await runProcess({
    command: 'wp',
    args,
    cwd,
    env: process.env,
    timeoutMs: 60_000,
  });
  const reported = opts.rowsOnExit1 === true && r.exitCode === 1 && checksumRows(r.stdout) !== null;
  const ok = r.outcome === 'completed' || reported;
  return {
    ok,
    stdout: r.stdout,
    stderr: r.stderr,
    reason: ok ? '' : `exit ${r.exitCode ?? '?'} (${r.outcome}); ${r.stderr.split(/\r?\n/)[0] ?? ''}`,
  };
  void ctx;
}

async function retry(call: () => Promise<WpResult>): Promise<WpResult> {
  let last = await call();
  for (let i = 0; i < RETRY_DELAYS_MS.length && !last.ok; i += 1) {
    await new Promise((res) => setTimeout(res, RETRY_DELAYS_MS[i]));
    last = await call();
  }
  return last;
}

/** The JSON rows a verify-checksums command printed — objects naming a `file` — or null. */
function checksumRows(stdout: string): Array<Record<string, unknown>> | null {
  const text = stdout.trim();
  if (!text.startsWith('[')) return null;
  try {
    const arr = JSON.parse(text) as unknown;
    if (!Array.isArray(arr) || arr.length === 0) return null;
    const rows = arr.filter((x): x is Record<string, unknown> => typeof x === 'object' && x !== null && !Array.isArray(x));
    return rows.length === arr.length && rows.every((x) => typeof x['file'] === 'string') ? rows : null;
  } catch {
    return null;
  }
}

const str = (v: unknown): string | undefined => (typeof v === 'string' ? v : undefined);

function parseChecksumOutput(r: WpResult): ChecksumFile[] {
  const rows = checksumRows(r.stdout);
  if (rows === null) return [];
  return rows.map((x) => ({
    file: str(x['file']) ?? '(unknown)',
    status: normaliseStatus(str(x['status']) ?? str(x['message'])),
  }));
}

function groupByComponent(r: WpResult): Record<string, ChecksumFile[]> {
  // WP-CLI emits one row per file with a `plugin_name` field. Group by it
  // to produce { slug: [files] }.
  const rows = checksumRows(r.stdout);
  if (rows === null) return {};
  const out: Record<string, ChecksumFile[]> = {};
  for (const row of rows) {
    const slug = str(row['plugin_name']) ?? '(unknown)';
    const f: ChecksumFile = {
      file: str(row['file']) ?? '(unknown)',
      status: normaliseStatus(str(row['status']) ?? str(row['message'])),
    };
    let bucket = out[slug];
    if (!bucket) {
      bucket = [];
      out[slug] = bucket;
    }
    bucket.push(f);
  }
  return out;
}

/**
 * The plugins `wp plugin verify-checksums` skipped, from its warnings
 * (Checksum_Plugin_Command: "Could not retrieve the checksums for version
 * {$version} of plugin {$name}, skipping.", "Could not retrieve the version
 * for plugin {$name}, skipping.", and the must-use variants), sorted.
 */
export function skippedPlugins(stderr: string): Array<{ plugin: string; reason: string }> {
  const out = new Map<string, string>();
  for (const raw of stderr.split(/\r?\n/)) {
    const line = raw.replace(/^Warning:\s*/, '').trim();
    const skip = /^(Could not retrieve the (?:checksums for version \S+ of|version for) (?:must-use )?plugin) (.+?), skipping\.$/.exec(line);
    if (skip?.[1] !== undefined && skip[2] !== undefined) {
      out.set(skip[2], skip[1].replace(/^Could not retrieve/, 'WP-CLI could not retrieve'));
      continue;
    }
    const mu = /^Must-use plugin '([^']+)' appears to be a custom file or loader plugin and cannot be verified\.$/.exec(line);
    if (mu?.[1] !== undefined) out.set(mu[1], 'a custom must-use file WP-CLI cannot verify');
  }
  return [...out.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([plugin, reason]) => ({ plugin, reason }));
}

function normaliseStatus(raw: string | undefined): ChecksumFile['status'] {
  const s = (raw ?? '').toLowerCase();
  // "File doesn't verify against checksum", "Checksum does not match".
  if (s.includes('modified') || s.includes('changed') || s.includes('verify against') || s.includes('does not match')) {
    return 'modified';
  }
  // "File doesn't exist".
  if (s.includes('missing') || s.includes("doesn't exist") || s.includes('does not exist')) return 'missing';
  // "File should not exist", "File was added".
  if (s.includes('added') || s.includes('extra') || s.includes('not in') || s.includes('should not exist')) {
    return 'added';
  }
  return 'unknown';
}

function failDomain(
  code: DomainError['code'],
  message: string,
): ToolResult<Record<string, unknown>> {
  return { ok: false, error: { code, message } };
}
