/**
 * `wp_vuln_check` judged by WPScan's own report (review C1), with canned
 * WPScan output — `test/e2e/wpscanNoDatabase.test.ts` runs the real WPScan
 * for the one shape reachable without a network (no database).
 *
 * The shapes, from WPScan 4.1.0's own source:
 *   - exit codes (`lib/wpscan/exit_code.rb`): 0 OK, 1 CLI option error,
 *     2 interrupted, 3 exception, 4 ERROR "scan did not finish",
 *     5 VULNERABLE "the target has at least one vulnerability";
 *   - `app/views/json/scan_aborted.erb`: `"scan_aborted": <reason>` — with
 *     no database, `Update required, you can not run a scan if a database
 *     file is missing.` (`lib/wpscan/errors/update.rb`), exit 4;
 *   - `app/views/json/vuln_api/status.erb`: `"vuln_api": { "error": "No
 *     WPScan API Token given, as a result vulnerability data has not been
 *     output. …" }` without a token; `{ "http_error": … }` or
 *     `{ "parse_error": … }` when the API failed; `{ "plan", "requests_done_
 *     during_scan", "requests_remaining" }` when it answered.
 */

import { existsSync, readdirSync, writeFileSync } from 'node:fs';
import { basename, dirname, join, resolve, sep } from 'node:path';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../src/runners/processRunner.js', () => ({ runProcess: vi.fn() }));
vi.mock('../../src/tools/scanHelpers.js', async () => {
  const actual = await vi.importActual<typeof import('../../src/tools/scanHelpers.js')>('../../src/tools/scanHelpers.js');
  return { ...actual, scannerAvailable: vi.fn() };
});

import { runProcess, type ProcessRunOptions, type ProcessRunResult } from '../../src/runners/processRunner.js';
import { scannerAvailable } from '../../src/tools/scanHelpers.js';
import type { PluginContext } from '../../src/context.js';
import { resolveProjectPath } from '../../src/platform/projectPath.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';
import type { ToolRun } from '../../src/types.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

afterAll(cleanupTempDirs);
beforeAll(async () => {
  await import('../../src/tools/wpVulnCheck.js');
});

let cacheDir: string;
beforeEach(() => {
  vi.mocked(runProcess).mockReset();
  vi.mocked(scannerAvailable).mockReset();
  vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/wpscan');
  cacheDir = makeTempDir('wpvuln-cache-');
  vi.stubEnv('GUARDIAN_CACHE_DIR', cacheDir);
  vi.stubEnv('WPSCAN_API_TOKEN', '');
});
afterEach(() => {
  vi.unstubAllEnvs();
});

function plugin(): PluginContext {
  const db = new Database(':memory:');
  runMigrations(db);
  return { storage: new Storage(db), shell: null, scriptsDir: process.cwd(), progressNotifier: { send: () => {} } };
}

interface Out {
  ok: true;
  scan_id: string;
  status: string;
  coverage: string;
  tools_run: ToolRun[];
  missing_tools: string[];
  findings_count: number;
  vulnerabilities_checked: boolean;
  report_path: string;
  warnings: string[];
}

async function check(input: Record<string, unknown>, p = plugin()): Promise<{ out: Out; p: PluginContext }> {
  const tool = TOOLS.find((t) => t.name === 'wp_vuln_check');
  if (!tool) throw new Error('wp_vuln_check not registered');
  const r = await tool.handler(input, p);
  if (!r.ok) throw new Error(JSON.stringify(r.error));
  return { out: r as unknown as Out, p };
}

const done = (exitCode: number, stdout = ''): ProcessRunResult => ({
  outcome: exitCode === 0 ? 'completed' : 'failed',
  exitCode,
  stdout,
  stderr: '',
  truncated: false,
});

/** Writes `report` to the run's --output file (as WPScan does) and exits `exitCode`. */
function wpscanWrites(report: unknown, exitCode: number): (opts: ProcessRunOptions) => ProcessRunResult {
  return (opts) => {
    const args = opts.args ?? [];
    const i = args.indexOf('--output');
    const out = i >= 0 ? args[i + 1] : undefined;
    if (out !== undefined) writeFileSync(out, JSON.stringify(report), 'utf8');
    return done(exitCode);
  };
}

const VULNERABLE = {
  plugins: {
    'contact-form-7': {
      version: { number: '5.0' },
      vulnerabilities: [{ title: 'Stored XSS', references: { cve: ['2099-4242'] }, fixed_in: '5.1' }],
    },
  },
  vuln_api: { plan: 'free', requests_done_during_scan: 3, requests_remaining: 22 },
};
const NO_TOKEN = {
  plugins: { 'contact-form-7': { version: { number: '5.0' } } },
  vuln_api: {
    error:
      'No WPScan API Token given, as a result vulnerability data has not been output.\nYou can get a free API token with 25 daily requests by registering at https://wpscan.com/register',
  },
};
const MISSING_DB = {
  scan_aborted: 'Update required, you can not run a scan if a database file is missing.',
  target_url: 'https://site.example/',
};

describe('wp_vuln_check — judged by WPScan’s report (review C1)', () => {
  it('exit 5 (VULNERABLE) is a completed scan with its findings, full coverage', async () => {
    vi.mocked(runProcess).mockImplementation(async (o) => wpscanWrites(VULNERABLE, 5)(o));
    const { out, p } = await check({ target_url: 'https://site.example/', api_token: 't' });
    expect(out.status).toBe('completed');
    expect(out.tools_run).toEqual([{ name: 'wpscan', status: 'ok', reason: expect.stringMatching(/exit 5/) }]);
    expect(out.missing_tools).toEqual([]);
    expect(out.coverage).toBe('full');
    expect(out.vulnerabilities_checked).toBe(true);
    expect(out.findings_count).toBe(1);
    expect(p.storage.scans.getById(out.scan_id)?.status).toBe('completed');
  });

  it('no API token: WPScan returned no vulnerability data — said so, coverage none, never a clean 0', async () => {
    vi.mocked(runProcess).mockImplementation(async (o) => wpscanWrites(NO_TOKEN, 0)(o));
    const { out, p } = await check({ target_url: 'https://site.example/' });
    expect(out.vulnerabilities_checked).toBe(false);
    expect(out.coverage).toBe('none');
    expect(out.missing_tools).toEqual(['wpscan']);
    expect(out.tools_run[0]?.status).toBe('skipped');
    expect(out.tools_run[0]?.reason).toMatch(/no WPScan API token.*vulnerabilities were not checked/i);
    expect(out.warnings.join(' ')).toMatch(/not a clean/i);
    // The stored row reads the same: a reader of "the latest scan" passes it over.
    const row = p.storage.scans.getById(out.scan_id);
    expect(row?.missing_tools).toEqual(['wpscan']);
  });

  it.each([
    ['http_error', { http_error: 'Couldn’t resolve host name' }],
    ['parse_error', { parse_error: 'WPScan DB API returned an invalid response.' }],
  ])('the vulnerability API failing (%s) is a failed check, not a clean one', async (_label, vulnApi) => {
    vi.mocked(runProcess).mockImplementation(async (o) => wpscanWrites({ plugins: {}, vuln_api: vulnApi }, 0)(o));
    const { out } = await check({ target_url: 'https://site.example/', api_token: 't' });
    expect(out.tools_run[0]?.status).toBe('failed');
    expect(out.coverage).toBe('none');
    expect(out.vulnerabilities_checked).toBe(false);
  });

  it.each([1, 2, 3, 4])('exit %i is a failed scan', async (code) => {
    vi.mocked(runProcess).mockImplementation(async (o) => wpscanWrites({ plugins: {} }, code)(o));
    const { out, p } = await check({ target_url: 'https://site.example/', api_token: 't' });
    expect(out.status).toBe('failed');
    expect(out.tools_run[0]?.status).toBe('failed');
    expect(out.coverage).toBe('none');
    expect(p.storage.scans.getById(out.scan_id)?.status).toBe('failed');
  });

  it('a missing database, offline: failed with the instruction, and nothing downloaded', async () => {
    vi.stubEnv('GUARDIAN_OFFLINE', '1');
    vi.mocked(runProcess).mockImplementation(async (o) => wpscanWrites(MISSING_DB, 4)(o));
    const { out } = await check({ target_url: 'https://site.example/', api_token: 't' });
    expect(out.status).toBe('failed');
    expect(out.tools_run[0]?.reason).toMatch(/no local database.*GUARDIAN_OFFLINE=1.*wpscan --update/i);
    const calls = vi.mocked(runProcess).mock.calls.map((c) => c[0].args ?? []);
    expect(calls.some((a) => a.includes('--update'))).toBe(false);
    expect(calls).toHaveLength(1);
  });

  it('a missing database, online: `wpscan --update` once, then the scan again', async () => {
    vi.stubEnv('GUARDIAN_OFFLINE', '0');
    let scans = 0;
    vi.mocked(runProcess).mockImplementation(async (o) => {
      const args = o.args ?? [];
      if (args.includes('--update')) return done(0, '{"db_update_finished":true}');
      scans += 1;
      return wpscanWrites(scans === 1 ? MISSING_DB : VULNERABLE, scans === 1 ? 4 : 5)(o);
    });
    const { out } = await check({ target_url: 'https://site.example/', api_token: 't' });
    const calls = vi.mocked(runProcess).mock.calls.map((c) => c[0].args ?? []);
    expect(calls.filter((a) => a.includes('--update'))).toHaveLength(1);
    // The update is its own run: no target, no token.
    const update = calls.find((a) => a.includes('--update')) ?? [];
    expect(update).not.toContain('--url');
    expect(update).not.toContain('--api-token');
    expect(scans).toBe(2);
    expect(out.status).toBe('completed');
    expect(out.tools_run[0]?.reason).toMatch(/database downloaded \(wpscan --update\)/);
    expect(out.findings_count).toBe(1);
  });

  it('a failed database update is a failed scan, said so, and not retried in a loop', async () => {
    vi.stubEnv('GUARDIAN_OFFLINE', '0');
    vi.mocked(runProcess).mockImplementation(async (o) => {
      if ((o.args ?? []).includes('--update')) return { ...done(4), stderr: 'Could not download metadata.json' };
      return wpscanWrites(MISSING_DB, 4)(o);
    });
    const { out } = await check({ target_url: 'https://site.example/', api_token: 't' });
    expect(out.status).toBe('failed');
    expect(out.tools_run[0]?.reason).toMatch(/`wpscan --update` failed \(Could not download metadata\.json\)/);
    expect(vi.mocked(runProcess).mock.calls).toHaveLength(2);
  });

  it('never writes into the server’s working directory: a URL-only report goes to the user cache', async () => {
    vi.mocked(runProcess).mockImplementation(async (o) => wpscanWrites(VULNERABLE, 5)(o));
    const reports = join(process.cwd(), '.guardian', 'reports');
    const wpvulnDirs = (): string[] => (existsSync(reports) ? readdirSync(reports).filter((n) => n.startsWith('wpvuln-')) : []);
    const before = wpvulnDirs();
    const { out } = await check({ target_url: 'https://site.example/', api_token: 't' });
    expect(resolve(out.report_path).startsWith(resolve(cacheDir) + sep)).toBe(true);
    expect(wpvulnDirs()).toEqual(before);
    // Nor is WPScan started there (it reads ./.wpscan/scan.yml from its working directory).
    for (const c of vi.mocked(runProcess).mock.calls) expect(resolve(c[0].cwd)).not.toBe(resolve(process.cwd()));
  });

  /**
   * Round 2, item 5: URL-only reports go to the user cache, which nothing
   * pruned. They keep the newest N per URL — N being the scan retention's own
   * (`GUARDIAN_RETENTION_SCANS`, default 50, 0 keeps everything), which is
   * how many scan rows per (URL, scan type) the database keeps.
   */
  it('keeps the newest N reports per URL in the user cache, N the scan retention', async () => {
    vi.stubEnv('GUARDIAN_RETENTION_SCANS', '2');
    vi.mocked(runProcess).mockImplementation(async (o) => wpscanWrites(VULNERABLE, 5)(o));
    const paths: string[] = [];
    for (let i = 0; i < 3; i++) {
      paths.push((await check({ target_url: 'https://site.example/', api_token: 't' })).out.report_path);
    }
    const other = (await check({ target_url: 'https://other.example', api_token: 't' })).out.report_path;
    const siteDir = dirname(dirname(paths[2] ?? ''));
    expect(dirname(dirname(paths[0] ?? ''))).toBe(siteDir);
    expect(readdirSync(siteDir).sort()).toEqual([basename(dirname(paths[1] ?? '')), basename(dirname(paths[2] ?? ''))].sort());
    expect(existsSync(paths[2] ?? '')).toBe(true);
    expect(existsSync(other)).toBe(true);
    expect(dirname(dirname(other))).not.toBe(siteDir);
  });

  it('GUARDIAN_RETENTION_SCANS=0 keeps every report', async () => {
    vi.stubEnv('GUARDIAN_RETENTION_SCANS', '0');
    vi.mocked(runProcess).mockImplementation(async (o) => wpscanWrites(VULNERABLE, 5)(o));
    const paths: string[] = [];
    for (let i = 0; i < 3; i++) paths.push((await check({ target_url: 'https://keep.example/', api_token: 't' })).out.report_path);
    for (const p of paths) expect(existsSync(p)).toBe(true);
  });

  it('a local install gets its report under the install, and WPScan runs in the report directory', async () => {
    const install = resolveProjectPath(makeTempDir('wpvuln-install-')).path;
    writeFileSync(join(install, 'wp-config.php'), '<?php\n');
    vi.mocked(runProcess).mockImplementation(async (o) => wpscanWrites(VULNERABLE, 5)(o));
    const { out } = await check({ wp_install_path: install, target_url: 'https://site.example/', api_token: 't' });
    expect(resolve(out.report_path).startsWith(join(install, '.guardian', 'reports') + sep)).toBe(true);
    const cwd = vi.mocked(runProcess).mock.calls[0]?.[0].cwd ?? '';
    expect(resolve(cwd).startsWith(join(install, '.guardian', 'reports'))).toBe(true);
  });
});
