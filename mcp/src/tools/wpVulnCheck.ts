/**
 * `wp_vuln_check` — query the WPScan public DB for known vulns affecting
 * the installed WP core, plugins, and themes.
 *
 * Standalone. Either pass a `target_url` (preferred — WPScan scans the
 * live site) or `wp_install_path` (we infer versions via WP-CLI then
 * pass `--url` pointing at the bundled wp-config home_url).
 *
 * API token: read from `api_token` input or `WPSCAN_API_TOKEN` env.
 *
 * ---- Judged by WPScan's report, never its exit code alone (review C1) --
 *
 * It used to pass `--no-update` and never update, count any non-`completed`
 * outcome as failed, and answer `ok: true` with no status, tools_run or
 * coverage. With no database WPScan writes `{"scan_aborted": "Update
 * required, …"}` and exits 4 — reproduced on 4.1.0 as `findings_count: 0`
 * and a "rate limit" warning; exit 5 (VULNERABLE) was stored as failed; and
 * without a token WPScan outputs NO vulnerability data at all
 * (`vuln_api.error`), which read as a clean site. Now:
 *
 *   - exits 0 and 5 finish a scan; any other exit, or `scan_aborted`, is
 *     `failed`;
 *   - a missing database is downloaded once (`wpscan --update`, egress to
 *     data.wpscan.org — SECURITY.md), then the scan runs again; with
 *     GUARDIAN_OFFLINE=1 the scan is `failed` with that instruction instead;
 *   - vulnerabilities were checked only when `vuln_api` answered (or the
 *     report holds some): without a token the `wpscan` entry is `skipped`,
 *     an API error `failed` — coverage none, `vulnerabilities_checked:
 *     false`, never a clean 0;
 *   - the response carries status / tools_run / missing_tools / coverage like
 *     every other scan tool;
 *   - the report goes under the install, or the per-user cache for a URL —
 *     never the server's working directory.
 */

import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { join } from 'node:path';
import { z } from 'zod';
import type { PluginContext } from '../context.js';
import { canonicalPath } from '../platform/projectPath.js';
import { runProcess, type ProcessRunResult } from '../runners/processRunner.js';
import { wpscanParser } from '../runners/scannerParsers/wpscan.js';
import { computeCoverage } from './scanCoverage.js';
import { scannerAvailable } from './scanHelpers.js';
import type { DomainError, ToolResult, ToolRun } from '../types.js';
import { wpInstallPathProblem, wpSiteKey } from '../wordpress/siteKeys.js';
import { defaultWordfenceCacheDir } from '../wordpress/vulnFeed.js';
import { registerToolModule, type ToolModule } from './index.js';

const inputSchema = {
  wp_install_path: z
    .string()
    .optional()
    .describe(
      'Path to the WP install (must contain wp-config.php to infer the URL). Absolute, or existing on this machine.',
    ),
  target_url: z
    .string()
    .url()
    .optional()
    .describe('Live URL of the WordPress site to scan. Preferred when both inputs are present.'),
  api_token: z
    .string()
    .optional()
    .describe('WPScan API token. Falls back to WPSCAN_API_TOKEN env var.'),
};

const tool: ToolModule = {
  name: 'wp_vuln_check',
  title: 'WordPress vuln-DB lookup (WPScan)',
  description:
    'Run WPScan against a target URL (or against the URL inferred from a local install_path) and ' +
    'return vulnerabilities affecting core / plugins / themes. Without an API token WPScan returns no ' +
    'vulnerability data: the scan then reads not checked (coverage none), never clean. A missing WPScan ' +
    'database is downloaded once (wpscan --update) unless GUARDIAN_OFFLINE=1.',
  inputSchema,
  handler: async (input, ctx) => handler(input, ctx),
};

registerToolModule(tool);

async function handler(
  input: Record<string, unknown>,
  ctx: PluginContext,
): Promise<ToolResult<Record<string, unknown>>> {
  const inp = input as {
    wp_install_path?: string;
    target_url?: string;
    api_token?: string;
  };

  if (!inp.target_url && !inp.wp_install_path) {
    return failDomain(
      'unknown_scan_id',
      'Provide either target_url or wp_install_path.',
    );
  }
  // The row is filed under the install path (below): it must name ONE
  // install — absolute, or existing here (Task 24 fix round 2). A relative
  // path that does not exist would be resolved against the server's cwd and
  // share one record with every other install passed the same way.
  const installProblem = inp.wp_install_path ? wpInstallPathProblem(inp.wp_install_path) : null;
  if (installProblem !== null) return failDomain('unsupported_target', installProblem);
  // Only an install that is on this machine is a place to run in and to
  // write the report under; an absolute path of a remote install is a key.
  const localInstall = inp.wp_install_path && existsSync(inp.wp_install_path) ? inp.wp_install_path : undefined;

  const wpscanBin = await scannerAvailable('wpscan');
  if (!wpscanBin) {
    return failDomain(
      'missing_scanner',
      'wpscan CLI is not installed. Run install_toolchain with tools=["wpscan"].',
    );
  }

  // Resolve URL. When only the install path is given, ask WP-CLI for the home_url.
  let url = inp.target_url;
  if (!url && inp.wp_install_path) {
    const wpBin = await scannerAvailable('wp');
    if (!wpBin) {
      return failDomain(
        'missing_scanner',
        'wp_install_path was provided but WP-CLI is missing to read the URL. Install wp-cli or provide target_url.',
      );
    }
    const r = await runProcess({
      command: 'wp',
      args: ['option', 'get', 'home', `--path=${inp.wp_install_path}`],
      cwd: localInstall ?? process.cwd(),
      timeoutMs: 30_000,
    });
    if (r.outcome === 'completed') {
      url = r.stdout.trim();
    } else {
      return failDomain(
        'scanner_failed',
        `wp option get home failed: ${r.stderr.split(/\r?\n/)[0] ?? r.outcome}`,
      );
    }
  }

  // WP-CLI can succeed and still print nothing, which left `url` undefined
  // while two later call sites asserted it was not. Checked once, here.
  if (!url) {
    return failDomain('scanner_failed', 'Could not resolve a target URL for WPScan.');
  }

  const token = inp.api_token ?? process.env['WPSCAN_API_TOKEN'] ?? '';

  // The report goes under the install when it is on this machine, else the
  // per-user dev-guardian cache — never the server's working directory,
  // which is nobody's project (review C1). WPScan runs in that directory
  // too: it reads `./.wpscan/scan.yml` from where it starts.
  const scanId = randomUUID();
  const reportDir =
    localInstall !== undefined
      ? join(localInstall, '.guardian', 'reports', `wpvuln-${scanId.slice(0, 8)}`)
      : join(defaultWordfenceCacheDir(), 'wp-vuln-check', `wpvuln-${scanId.slice(0, 8)}`);
  mkdirSync(reportDir, { recursive: true });
  const outFile = join(reportDir, 'wpscan.json');

  ctx.storage.scans.insert({
    scan_id: scanId,
    scan_type: 'wp_vuln_check',
    // Filed under the key the project-scoped readers look it up by
    // (`wp_describe_setup`, `wp_plugin_check`): the install root in its
    // canonical spelling, or the site URL the way wp_rest_audit files it.
    project_path: inp.wp_install_path !== undefined ? canonicalPath(inp.wp_install_path) : wpSiteKey(url),
    tree_hash: '',
    report_dir: reportDir,
  });

  const args = ['--no-update', '--no-banner', '--format', 'json', '--output', outFile, '--enumerate', 'vp,vt', '--url', url];
  if (token) args.push('--api-token', token);
  const scan = async (): Promise<WpscanAttempt> => {
    rmSync(outFile, { force: true });
    const run = await runProcess({ command: 'wpscan', args, cwd: reportDir, timeoutMs: 5 * 60_000 });
    const raw = readReport(outFile, run.stdout);
    return { run, raw, report: readWpscanReport(raw) };
  };

  let attempt = await scan();
  let failure: string | null = null;
  let dbNote: string | null = null;
  if (attempt.report.aborted !== null && MISSING_DB.test(attempt.report.aborted)) {
    if (process.env['GUARDIAN_OFFLINE'] === '1') {
      failure =
        'WPScan has no local database, and GUARDIAN_OFFLINE=1 forbids downloading one: run `wpscan --update` ' +
        'once (it downloads the database from data.wpscan.org), or unset GUARDIAN_OFFLINE, and re-run — nothing was scanned';
    } else {
      // Once. The update is its own run: no target, no token.
      const update = await runProcess({
        command: 'wpscan',
        args: ['--update', '--no-banner'],
        cwd: reportDir,
        timeoutMs: 10 * 60_000,
      });
      if (update.outcome !== 'completed') {
        failure =
          `WPScan has no local database and \`wpscan --update\` failed (${firstLine(update) ?? `${update.outcome}, exit ${String(update.exitCode)}`}) ` +
          '— nothing was scanned; run `wpscan --update` by hand and re-run';
      } else {
        dbNote = 'database downloaded (wpscan --update)';
        attempt = await scan();
      }
    }
  }

  // Findings the report holds are real whatever the verdict.
  let findingsCount = 0;
  let cvesCount = 0;
  if (attempt.raw !== null) {
    const parsed = wpscanParser.parse(attempt.raw);
    if (parsed.findings.length > 0) {
      ctx.storage.findings.bulkInsert(parsed.findings.map((f) => ({ ...f, scan_id: scanId })));
      findingsCount = parsed.findings.length;
    }
    if (parsed.cves.length > 0) {
      ctx.storage.cves.bulkUpsert(parsed.cves.map((c) => ({ ...c, scan_id: scanId })));
      cvesCount = parsed.cves.length;
    }
  }

  const verdict = failure !== null ? { status: 'failed' as const, reason: failure, checked: false } : judgeWpscan(attempt, token.length > 0);
  const toolRun: ToolRun = {
    name: 'wpscan',
    status: verdict.status,
    reason: [verdict.reason, ...(dbNote !== null ? [dbNote] : [])].join('; '),
  };
  const tools_run = [toolRun];
  const missing_tools = verdict.status === 'ok' ? [] : ['wpscan'];
  const coverage = computeCoverage(tools_run, missing_tools);
  const status = verdict.status === 'failed' ? 'failed' : 'completed';
  const rateLimited = /limit/i.test(`${attempt.report.aborted ?? ''} ${attempt.report.vulnApiMessage ?? ''}`);

  const warnings: string[] = [];
  if (!verdict.checked) {
    warnings.push(
      verdict.status === 'failed'
        ? `⚠️ wp_vuln_check: the scan did not complete (${verdict.reason}). A "0 findings" result is NOT a clean bill of health.`
        : `⚠️ wp_vuln_check: ${verdict.reason}. A "0 findings" result is NOT a clean bill of health — ` +
            'set WPSCAN_API_TOKEN (or pass api_token) and re-run.',
    );
  }

  ctx.storage.scans.finalize({
    scan_id: scanId,
    status,
    tools_run,
    missing_tools,
    report_dir: reportDir,
    meta: { url, rate_limited: rateLimited, has_token: token.length > 0, vulnerabilities_checked: verdict.checked },
  });

  return {
    ok: true,
    scan_id: scanId,
    status,
    url,
    has_token: token.length > 0,
    rate_limited: rateLimited,
    vulnerabilities_checked: verdict.checked,
    coverage,
    tools_run,
    missing_tools,
    findings_count: findingsCount,
    cves_count: cvesCount,
    report_path: outFile,
    warnings,
  };
}

/** WPScan's own words for a scan it refused without a database (`lib/wpscan/errors/update.rb`). */
const MISSING_DB = /update required|database file is missing/i;

interface WpscanReport {
  /** `scan_aborted`: why WPScan did not scan (`app/views/json/scan_aborted.erb`). */
  aborted: string | null;
  /**
   * `vuln_api` (`app/views/json/vuln_api/status.erb`): `answered` (a plan and
   * request counts), `no_token` (its `error`: "No WPScan API Token given, as
   * a result vulnerability data has not been output"), `failed` (its
   * `http_error` / `parse_error`), or `absent`.
   */
  vulnApi: 'answered' | 'no_token' | 'failed' | 'absent';
  vulnApiMessage: string | null;
  /** Vulnerabilities in the report: proof the API answered, whatever `vuln_api` says. */
  vulnerabilities: number;
}

interface WpscanAttempt {
  run: ProcessRunResult;
  raw: string | null;
  report: WpscanReport;
}

function readReport(outFile: string, stdout: string): string | null {
  if (existsSync(outFile)) {
    try {
      const text = readFileSync(outFile, 'utf8');
      if (text.trim().startsWith('{')) return text;
    } catch {
      /* fall through to stdout */
    }
  }
  if (stdout.trim().startsWith('{')) {
    try {
      writeFileSync(outFile, stdout, 'utf8');
    } catch {
      /* the report path is best-effort; the verdict is not */
    }
    return stdout;
  }
  return null;
}

export function readWpscanReport(raw: string | null): WpscanReport {
  const none: WpscanReport = { aborted: null, vulnApi: 'absent', vulnApiMessage: null, vulnerabilities: 0 };
  if (raw === null) return none;
  let json: unknown;
  try {
    json = JSON.parse(raw);
  } catch {
    return none;
  }
  if (typeof json !== 'object' || json === null) return none;
  const root = json as Record<string, unknown>;
  const aborted = typeof root['scan_aborted'] === 'string' ? root['scan_aborted'] : null;
  const api = root['vuln_api'];
  let vulnApi: WpscanReport['vulnApi'] = 'absent';
  let vulnApiMessage: string | null = null;
  if (typeof api === 'object' && api !== null) {
    const a = api as Record<string, unknown>;
    const text = (v: unknown): string | null => (typeof v === 'string' ? v : v === undefined ? null : JSON.stringify(v));
    if (a['http_error'] !== undefined || a['parse_error'] !== undefined) {
      vulnApi = 'failed';
      vulnApiMessage = text(a['http_error'] ?? a['parse_error']);
    } else if (a['error'] !== undefined) {
      vulnApi = 'no_token';
      vulnApiMessage = text(a['error']);
    } else if (a['plan'] !== undefined || a['requests_remaining'] !== undefined) {
      vulnApi = 'answered';
    }
  }
  return { aborted, vulnApi, vulnApiMessage, vulnerabilities: wpscanParser.parse(raw).findings.length };
}

/**
 * The `wpscan` entry: exits 0 (OK) and 5 (VULNERABLE) are a finished scan,
 * anything else is not (`lib/wpscan/exit_code.rb`: 1 option error, 2
 * interrupted, 3 exception, 4 "scan did not finish"); a `scan_aborted`
 * report is not either. A finished scan checked vulnerabilities only when
 * the API answered — WPScan outputs no vulnerability data at all without a
 * token — so it is `ok` only then: `skipped` without a token, `failed` when
 * the API erred. `checked` says whether vulnerabilities were looked up.
 */
function judgeWpscan(
  attempt: WpscanAttempt,
  hasToken: boolean,
): { status: ToolRun['status']; reason: string; checked: boolean } {
  const { run, raw, report } = attempt;
  if (report.aborted !== null) {
    return { status: 'failed', reason: `WPScan aborted the scan: ${report.aborted}`, checked: false };
  }
  const exit = run.exitCode;
  const finished = (run.outcome === 'completed' || run.outcome === 'failed') && (exit === 0 || exit === 5);
  if (!finished) {
    const why = firstLine(run);
    return {
      status: 'failed',
      reason: `wpscan did not finish (${run.outcome}, exit ${String(exit)})${why !== null ? `: ${why}` : ''}`,
      checked: false,
    };
  }
  if (raw === null) return { status: 'failed', reason: `wpscan exit ${String(exit)} but wrote no JSON report`, checked: false };
  const exitText = exit === 5 ? 'exit 5 (vulnerable)' : `exit ${String(exit)}`;
  if (report.vulnApi === 'answered' || report.vulnerabilities > 0) return { status: 'ok', reason: exitText, checked: true };
  if (report.vulnApi === 'failed') {
    return {
      status: 'failed',
      reason: `the WPScan vulnerability API failed (${report.vulnApiMessage ?? 'no detail'}) — vulnerabilities were not checked`,
      checked: false,
    };
  }
  if (report.vulnApi === 'no_token' || !hasToken) {
    return {
      status: 'skipped',
      reason:
        'WPScan enumerated the site, but no WPScan API token was given, so it fetched no vulnerability data — ' +
        'vulnerabilities were not checked',
      checked: false,
    };
  }
  return {
    status: 'skipped',
    reason: "WPScan's report says nothing of its vulnerability API — vulnerabilities cannot be shown to have been checked",
    checked: false,
  };
}

function firstLine(r: Pick<ProcessRunResult, 'stderr' | 'stdout'>): string | null {
  const line = `${r.stderr}\n${r.stdout}`.split(/\r?\n/).find((l) => l.trim().length > 0);
  return line === undefined ? null : line.trim().slice(0, 300);
}

function failDomain(
  code: DomainError['code'],
  message: string,
): ToolResult<Record<string, unknown>> {
  return { ok: false, error: { code, message } };
}
