/**
 * Smoke + integration tests for the 11 Phase-16 tools and the 2 new
 * resources. Most tools are read-only over storage — we seed in-memory
 * state and assert the response shape.
 *
 * The execa-based tools (wp_cron_audit, wp_plugin_check, wp_rest_audit,
 * bulk_audit_wordpress_sites) get mocks for runProcess/scannerAvailable
 * to keep tests offline and deterministic.
 */

import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, relative } from 'node:path';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../src/runners/processRunner.js', () => ({
  runProcess: vi.fn(),
}));
vi.mock('../../src/tools/scanHelpers.js', async () => {
  const actual =
    await vi.importActual<typeof import('../../src/tools/scanHelpers.js')>(
      '../../src/tools/scanHelpers.js',
    );
  return { ...actual, scannerAvailable: vi.fn() };
});

import { runProcess } from '../../src/runners/processRunner.js';
import { scannerAvailable } from '../../src/tools/scanHelpers.js';
import type { PluginContext } from '../../src/context.js';
import { canonicalPath, resolveProjectPath } from '../../src/platform/projectPath.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';
import { RESOURCES } from '../../src/resources/index.js';
import { makeFinding } from '../../src/runners/scannerParsers/index.js';
import { makeTempDir, cleanupTempDirs } from '../helpers/tempDir.js';

afterAll(cleanupTempDirs);

beforeAll(async () => {
  await import('../../src/tools/wpCronAudit.js');
  await import('../../src/tools/wpRecommendHardening.js');
  await import('../../src/tools/wpPluginCheck.js');
  await import('../../src/tools/wpVulnCheck.js');
  await import('../../src/tools/wpRestAudit.js');
  await import('../../src/tools/bulkAuditWordpressSites.js');
  await import('../../src/tools/wpDescribeSetup.js');
  await import('../../src/tools/scanDotnetSecrets.js');
  await import('../../src/tools/dotnetTargetFrameworkCheck.js');
  await import('../../src/tools/dotnetEfcoreAudit.js');
  await import('../../src/tools/dotnetDescribeSetup.js');
  await import('../../src/tools/prioritizeFindings.js');
  await import('../../src/resources/wp.js');
  await import('../../src/resources/dotnet.js');
});

function tempProject(): string {
  return makeTempDir('phase16-');
}

/** A real project directory, in the spelling every scan persists. */
function projectPath(): string {
  return resolveProjectPath(tempProject()).path;
}

function getTool(name: string) {
  const t = TOOLS.find((x) => x.name === name);
  if (!t) throw new Error(`Tool '${name}' not registered`);
  return t;
}

function getResource(name: string) {
  const r = RESOURCES.find((x) => x.name === name);
  if (!r) throw new Error(`Resource '${name}' not registered`);
  return r;
}

function makePlugin(): PluginContext {
  const db = new Database(':memory:');
  runMigrations(db);
  return {
    storage: new Storage(db),
    shell: null,
    scriptsDir: '',
    progressNotifier: { send: () => {} },
  };
}

beforeEach(() => {
  vi.mocked(runProcess).mockReset();
  vi.mocked(scannerAvailable).mockReset();
});

afterEach(() => {
  vi.mocked(runProcess).mockReset();
  vi.mocked(scannerAvailable).mockReset();
});

describe('Phase 16 — registry', () => {
  it('all 11 new tools are registered', () => {
    const names = TOOLS.map((t) => t.name);
    for (const n of [
      'wp_cron_audit',
      'wp_recommend_hardening',
      'wp_plugin_check',
      'wp_rest_audit',
      'bulk_audit_wordpress_sites',
      'wp_describe_setup',
      'scan_dotnet_secrets',
      'dotnet_target_framework_check',
      'dotnet_efcore_audit',
      'dotnet_describe_setup',
      'prioritize_findings',
    ]) {
      expect(names).toContain(n);
    }
  });
});

describe('wp_plugin_check', () => {
  // Every read is one project's since Task 24: rows are seeded under a real
  // project and the call names it. They were seeded under '/p' and read from
  // the server's cwd — found only because the read searched every project.
  it('finds a plugin CVE recorded by a deps_audit scan, which has its own scan type', async () => {
    const plugin = makePlugin();
    const P = projectPath();
    plugin.storage.scans.insert({ scan_id: 'da', scan_type: 'deps_audit', project_path: P, tree_hash: 'h' });
    plugin.storage.cves.upsert({
      cve_id: 'CVE-2024-WP', package_name: 'contact-form-7', severity: 'high', scan_id: 'da',
    });
    plugin.storage.scans.finalize({ scan_id: 'da', status: 'completed', tools_run: [], missing_tools: [] });

    const r = (await getTool('wp_plugin_check').handler({ slug: 'contact-form-7', project_path: P }, plugin)) as {
      ok: true;
      known_cves: Array<{ cve_id: string }>;
    };
    expect(r.known_cves.map((c) => c.cve_id)).toEqual(['CVE-2024-WP']);
  });

  it('also finds a plugin CVE recorded by wp_vuln_check_source (Task 18, source-based)', async () => {
    const plugin = makePlugin();
    const P = projectPath();
    plugin.storage.scans.insert({ scan_id: 'wvs', scan_type: 'wp_vuln_check_source', project_path: P, tree_hash: 'h' });
    plugin.storage.cves.upsert({
      cve_id: 'CVE-2024-SRC', package_name: 'contact-form-7', severity: 'critical', scan_id: 'wvs',
    });
    plugin.storage.scans.finalize({ scan_id: 'wvs', status: 'completed', tools_run: [], missing_tools: [] });

    const r = (await getTool('wp_plugin_check').handler({ slug: 'contact-form-7', project_path: P }, plugin)) as {
      ok: true;
      known_cves: Array<{ cve_id: string }>;
    };
    expect(r.known_cves.map((c) => c.cve_id)).toEqual(['CVE-2024-SRC']);
  });
});

/**
 * Fix round 1, M4: `wp_plugin_check { slug }` is a lookup, not a scan of a
 * directory — it must answer when the server runs in a home directory, and
 * when `wp_install_path` names an install that is not on this machine.
 */
describe('wp_plugin_check never refuses for want of a local project', () => {
  it('answers from the home directory (no project_path, no wp_install_path)', async () => {
    const plugin = makePlugin();
    const cwd = vi.spyOn(process, 'cwd').mockReturnValue(homedir());
    try {
      const r = await getTool('wp_plugin_check').handler({ slug: 'akismet' }, plugin);
      expect(r.ok).toBe(true);
    } finally {
      cwd.mockRestore();
    }
  });

  it('answers when wp_install_path does not exist locally, and files the lookup under it', async () => {
    const plugin = makePlugin();
    const remote = join(tempProject(), 'not', 'here');
    const r = await getTool('wp_plugin_check').handler({ slug: 'akismet', wp_install_path: remote }, plugin);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(plugin.storage.scans.getById(String(r['scan_id']))?.project_path).toBe(canonicalPath(remote));
  });

  /**
   * Fix round 2 (controller ruling): a relative `wp_install_path` that does
   * not exist here names no install — resolved against the server's cwd, two
   * remote installs both passed as the same relative name shared one key, and
   * one's CVEs were reported as the other's. It is rejected, never merged.
   */
  it('rejects a relative wp_install_path that does not exist, rather than merging it with another install', async () => {
    const plugin = makePlugin();
    const rel = 'guardian-remote-wp-install';
    // What another remote install "wp" filed under the old cwd-resolved key.
    plugin.storage.scans.insert({ scan_id: 'other', scan_type: 'wp_vuln_check', project_path: canonicalPath(rel), tree_hash: '' });
    plugin.storage.cves.upsert({ cve_id: 'CVE-OTHER-INSTALL', package_name: 'akismet', severity: 'critical', scan_id: 'other' });
    plugin.storage.scans.finalize({ scan_id: 'other', status: 'completed', tools_run: [{ name: 'wpscan', status: 'ok' }], missing_tools: [] });

    const r = await getTool('wp_plugin_check').handler({ slug: 'akismet', wp_install_path: rel }, plugin);
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.error.code).toBe('unsupported_target');
    expect(r.error.message).toMatch(/absolute path/);
    expect(r.error.message).toMatch(/target_url/);
  });

  it('an existing relative wp_install_path resolves to its install', async () => {
    const plugin = makePlugin();
    const P = projectPath();
    plugin.storage.scans.insert({ scan_id: 'v', scan_type: 'wp_vuln_check', project_path: P, tree_hash: '' });
    plugin.storage.cves.upsert({ cve_id: 'CVE-HERE', package_name: 'akismet', severity: 'high', scan_id: 'v' });
    plugin.storage.scans.finalize({ scan_id: 'v', status: 'completed', tools_run: [{ name: 'wpscan', status: 'ok' }], missing_tools: [] });

    const r = (await getTool('wp_plugin_check').handler(
      { slug: 'akismet', wp_install_path: relative(process.cwd(), P) },
      plugin,
    )) as { ok: true; project_path: string; known_cves: Array<{ cve_id: string }> };
    expect(r.project_path).toBe(P);
    expect(r.known_cves.map((c) => c.cve_id)).toEqual(['CVE-HERE']);
  });

  it('still refuses an explicit project_path that does not exist', async () => {
    const plugin = makePlugin();
    const r = await getTool('wp_plugin_check').handler(
      { slug: 'akismet', project_path: join(tempProject(), 'missing') },
      plugin,
    );
    expect(r.ok).toBe(false);
  });
});

/**
 * Fix round 1, I4: `wp_vuln_check` files its row under the key the scoped
 * readers look it up by — a site URL without its trailing slash, an install
 * path in its canonical spelling — and `wp_describe_setup` /
 * `wp_plugin_check` then find it.
 */
describe('wp_vuln_check files its row where the project-scoped readers look', () => {
  const WPSCAN_OUT = {
    plugins: {
      'contact-form-7': {
        version: { number: '5.0' },
        vulnerabilities: [{ title: 'Stored XSS', references: { cve: ['2099-4242'] }, fixed_in: '5.1' }],
      },
    },
  };

  function mockScanners(homeUrl = 'https://installed.example/'): void {
    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/tool');
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      if (opts.command === 'wp') {
        return { outcome: 'completed', exitCode: 0, stdout: `${homeUrl}\n`, stderr: '', truncated: false };
      }
      const args = opts.args ?? [];
      const out = args[args.indexOf('--output') + 1];
      if (out !== undefined) writeFileSync(out, JSON.stringify(WPSCAN_OUT), 'utf8');
      return { outcome: 'completed', exitCode: 0, stdout: '', stderr: '', truncated: false };
    });
  }

  it('a trailing-slash target_url is filed without the slash, and both readers find it', async () => {
    mockScanners();
    const plugin = makePlugin();
    const P = projectPath();
    // No install path: the report directory goes under the working directory.
    const cwd = vi.spyOn(process, 'cwd').mockReturnValue(P);
    try {
      const r = await getTool('wp_vuln_check').handler({ target_url: 'https://site.example/' }, plugin);
      if (!r.ok) throw new Error(JSON.stringify(r.error));
      expect(plugin.storage.scans.getById(String(r['scan_id']))?.project_path).toBe('https://site.example');

      const d = (await getTool('wp_describe_setup').handler(
        { project_path: P, target_url: 'https://site.example/' },
        plugin,
      )) as { ok: true; audits: { wp_vuln_check: { scan_id: string } | null }; active_cves: Array<{ cve_id: string }> };
      expect(d.audits.wp_vuln_check?.scan_id).toBe(r['scan_id']);
      expect(d.active_cves.map((c) => c.cve_id)).toEqual(['CVE-2099-4242']);

      const p = (await getTool('wp_plugin_check').handler(
        { slug: 'contact-form-7', project_path: P, target_url: 'https://site.example' },
        plugin,
      )) as { ok: true; known_cves: Array<{ cve_id: string }> };
      expect(p.known_cves.map((c) => c.cve_id)).toEqual(['CVE-2099-4242']);
    } finally {
      cwd.mockRestore();
    }
  });

  it('rejects a relative wp_install_path that does not exist before running anything (fix round 2)', async () => {
    mockScanners();
    const plugin = makePlugin();
    const r = await getTool('wp_vuln_check').handler(
      { wp_install_path: 'guardian-remote-wp-install', target_url: 'https://site.example' },
      plugin,
    );
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.error.code).toBe('unsupported_target');
    expect(r.error.message).toMatch(/target_url/);
    expect(vi.mocked(runProcess)).not.toHaveBeenCalled();
  });

  it('an absolute install path that is not on this machine is filed under its exact key, and writes nothing there', async () => {
    mockScanners();
    const plugin = makePlugin();
    const P = projectPath();
    const remote = join(P, 'remote', 'var', 'www', 'html');
    const cwd = vi.spyOn(process, 'cwd').mockReturnValue(P);
    try {
      const r = await getTool('wp_vuln_check').handler(
        { wp_install_path: remote, target_url: 'https://site.example' },
        plugin,
      );
      if (!r.ok) throw new Error(JSON.stringify(r.error));
      expect(plugin.storage.scans.getById(String(r['scan_id']))?.project_path).toBe(canonicalPath(remote));
      // Its report went under the working directory: no directory was
      // created at the remote install's path on this machine.
      expect(existsSync(join(P, 'remote'))).toBe(false);

      const p = (await getTool('wp_plugin_check').handler(
        { slug: 'contact-form-7', wp_install_path: remote },
        plugin,
      )) as { ok: true; known_cves: Array<{ cve_id: string }> };
      expect(p.known_cves.map((c) => c.cve_id)).toEqual(['CVE-2099-4242']);
    } finally {
      cwd.mockRestore();
    }
  });

  it('a relative wp_install_path is filed in its canonical spelling, and both readers find it', async () => {
    mockScanners();
    const plugin = makePlugin();
    const P = projectPath();
    const rel = relative(process.cwd(), P);
    const r = await getTool('wp_vuln_check').handler({ wp_install_path: rel }, plugin);
    if (!r.ok) throw new Error(JSON.stringify(r.error));
    expect(plugin.storage.scans.getById(String(r['scan_id']))?.project_path).toBe(P);

    const d = (await getTool('wp_describe_setup').handler({ project_path: P }, plugin)) as {
      ok: true;
      audits: { wp_vuln_check: { scan_id: string } | null };
    };
    expect(d.audits.wp_vuln_check?.scan_id).toBe(r['scan_id']);

    const p = (await getTool('wp_plugin_check').handler({ slug: 'contact-form-7', project_path: P }, plugin)) as {
      ok: true;
      known_cves: Array<{ cve_id: string }>;
    };
    expect(p.known_cves.map((c) => c.cve_id)).toEqual(['CVE-2099-4242']);
  });
});

describe('wp_recommend_hardening', () => {
  it('returns audit_found=false when no wp_audit exists', async () => {
    const plugin = makePlugin();
    const r = (await getTool('wp_recommend_hardening').handler({}, plugin)) as {
      ok: true;
      audit_found: boolean;
    };
    expect(r.audit_found).toBe(false);
  });

  it('produces a checklist from wp_audit meta', async () => {
    const plugin = makePlugin();
    const P = projectPath();
    plugin.storage.scans.insert({
      scan_id: 'wpa',
      scan_type: 'wp_audit',
      project_path: P,
      tree_hash: '',
    });
    plugin.storage.scans.finalize({
      scan_id: 'wpa',
      status: 'completed',
      tools_run: [],
      missing_tools: [],
      meta: {
        wp_version: '6.4.1',
        config_flags: { DISALLOW_FILE_EDIT: false, WP_DEBUG: true, FORCE_SSL_ADMIN: false },
        admins: [
          { user_login: 'admin', user_email: 'a@a.com', risky: true },
          { user_login: 'jane', user_email: 'j@j.com', risky: false },
        ],
        checksum_mismatches: { core: [{ file: 'x', status: 'modified' }], plugins: {}, themes: {} },
        plugins_with_auto_update: [],
        warnings: [],
      },
    });

    const r = (await getTool('wp_recommend_hardening').handler({ project_path: P }, plugin)) as {
      ok: true;
      audit_found: boolean;
      summary: { total: number; critical: number };
      markdown: string;
    };
    expect(r.audit_found).toBe(true);
    expect(r.summary.critical).toBeGreaterThan(0);
    expect(r.markdown).toContain('Critical');
    expect(r.markdown).toContain('admin');
  });
});

describe('wp_cron_audit', () => {
  it('flags suspicious hooks and base64 args', async () => {
    const project = tempProject();
    writeFileSync(join(project, 'wp-config.php'), '<?php', 'utf8');
    const plugin = makePlugin();

    vi.mocked(scannerAvailable).mockResolvedValue('/fake/wp');
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      const args = opts.args ?? [];
      if (args.includes('event') && args.includes('list')) {
        return {
          outcome: 'completed',
          exitCode: 0,
          stdout: JSON.stringify([
            { hook: 'wp_update_plugins', next_run_relative: '1h', schedule: 'twicedaily' },
            { hook: 'mystery_backdoor_hook', next_run_relative: '5m', schedule: 'hourly', args: ['QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo='] },
          ]),
          stderr: '',
          truncated: false,
        };
      }
      if (args.includes('plugin') && args.includes('list')) {
        return {
          outcome: 'completed',
          exitCode: 0,
          stdout: JSON.stringify([{ name: 'jetpack', status: 'active' }]),
          stderr: '',
          truncated: false,
        };
      }
      return { outcome: 'completed', exitCode: 0, stdout: '[]', stderr: '', truncated: false };
    });

    const r = (await getTool('wp_cron_audit').handler(
      { wp_install_path: project },
      plugin,
    )) as { ok: true; total_events: number; flagged_count: number };
    expect(r.total_events).toBe(2);
    expect(r.flagged_count).toBe(1);
  });
});

describe('scan_dotnet_secrets', () => {
  it('detects Azure Storage AccountKey and SQL Server password', async () => {
    const project = tempProject();
    writeFileSync(
      join(project, 'appsettings.json'),
      `{
        "ConnectionStrings": {
          "Default": "Server=foo;Database=bar;User Id=sa;Password=Sup3rSecret123"
        },
        "Storage": "DefaultEndpointsProtocol=https;AccountName=x;AccountKey=abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123=="
      }`,
      'utf8',
    );
    const plugin = makePlugin();
    const r = (await getTool('scan_dotnet_secrets').handler(
      { project_path: project },
      plugin,
    )) as { ok: true; findings_count: number; findings: Array<{ rule_id: string }> };
    expect(r.findings_count).toBeGreaterThanOrEqual(2);
    const ruleIds = new Set(r.findings.map((f) => f.rule_id));
    expect(ruleIds.has('dotnet-sql-server-conn')).toBe(true);
    expect(ruleIds.has('dotnet-azure-storage-key')).toBe(true);
  });
});

describe('dotnet_target_framework_check', () => {
  it('flags net6.0 as EOL and net8.0 as LTS', async () => {
    const project = tempProject();
    writeFileSync(
      join(project, 'App.csproj'),
      `<Project Sdk="Microsoft.NET.Sdk">
         <PropertyGroup>
           <TargetFramework>net6.0</TargetFramework>
         </PropertyGroup>
       </Project>`,
      'utf8',
    );
    mkdirSync(join(project, 'sub'));
    writeFileSync(
      join(project, 'sub', 'Other.csproj'),
      `<Project Sdk="Microsoft.NET.Sdk">
         <PropertyGroup>
           <TargetFrameworks>net8.0;net9.0</TargetFrameworks>
         </PropertyGroup>
       </Project>`,
      'utf8',
    );
    const plugin = makePlugin();
    const r = (await getTool('dotnet_target_framework_check').handler(
      { project_path: project },
      plugin,
    )) as {
      ok: true;
      project_count: number;
      eol_count: number;
      projects: Array<{
        file: string;
        target_frameworks: string[];
        statuses: Array<{ status: string }>;
      }>;
    };
    expect(r.project_count).toBe(2);
    expect(r.eol_count).toBe(1);
    const net6 = r.projects.find((p) => p.target_frameworks.includes('net6.0'));
    expect(net6?.statuses[0]?.status).toBe('eol');
  });
});

describe('dotnet_efcore_audit', () => {
  it('flags DropTable + AlterColumn nullable=false without defaultValue', async () => {
    const project = tempProject();
    mkdirSync(join(project, 'Migrations'));
    writeFileSync(
      join(project, 'Migrations', '20240101_Initial.cs'),
      `public partial class Initial : Migration {
        protected override void Up(MigrationBuilder migrationBuilder) {
          migrationBuilder.DropTable("OldTable");
          migrationBuilder.AlterColumn<string>("Name", "Users", nullable: false);
        }
      }`,
      'utf8',
    );
    const plugin = makePlugin();
    const r = (await getTool('dotnet_efcore_audit').handler(
      { project_path: project },
      plugin,
    )) as { ok: true; findings_count: number; findings: Array<{ rule_id: string }> };
    expect(r.findings_count).toBeGreaterThanOrEqual(2);
    const ids = new Set(r.findings.map((f) => f.rule_id));
    expect(ids.has('efcore-drop-table')).toBe(true);
    expect(ids.has('efcore-alter-not-null')).toBe(true);
  });
});

describe('prioritize_findings', () => {
  it('ranks critical security above low quality', async () => {
    const plugin = makePlugin();
    // prioritize_findings answers for one project, so the scan must belong
    // to a real one and the call must name it.
    const project = resolveProjectPath(makeTempDir('phase16-prio-')).path;
    plugin.storage.scans.insert({
      scan_id: 's1',
      scan_type: 'sast',
      project_path: project,
      tree_hash: 'h',
    });
    const fLow = makeFinding({
      tool: 't',
      severity: 'low',
      category: 'quality',
      title: 'cosmetic',
      file_path: 'a.ts',
      line_start: 1,
    });
    const fCrit = makeFinding({
      tool: 't',
      severity: 'critical',
      category: 'security',
      title: 'sqli',
      file_path: 'b.ts',
      line_start: 1,
    });
    plugin.storage.findings.bulkInsert([
      { scan_id: 's1', ...fLow },
      { scan_id: 's1', ...fCrit },
    ]);
    plugin.storage.scans.finalize({
      scan_id: 's1',
      status: 'completed',
      tools_run: [],
      missing_tools: [],
    });

    const r = (await getTool('prioritize_findings').handler({ project_path: project }, plugin)) as {
      ok: true;
      ranked: Array<{ finding: { severity: string; title: string }; priority_score: number }>;
    };
    const [first, second] = r.ranked;
    if (!first || !second) throw new Error(`expected 2+ ranked findings, got ${r.ranked.length}`);
    expect(first.finding.title).toBe('sqli');
    expect(second.finding.title).toBe('cosmetic');
    expect(first.priority_score).toBeGreaterThan(second.priority_score);
  });
});

describe('wp_describe_setup + dotnet_describe_setup', () => {
  it('return well-formed posture summaries even with no data', async () => {
    const plugin = makePlugin();
    const wp = (await getTool('wp_describe_setup').handler({}, plugin)) as {
      ok: true;
      recommended_next: string;
    };
    expect(wp.ok).toBe(true);
    expect(wp.recommended_next).toMatch(/wp_audit/i);

    const dn = (await getTool('dotnet_describe_setup').handler({}, plugin)) as {
      ok: true;
      recommended_next: string;
    };
    expect(dn.ok).toBe(true);
    expect(dn.recommended_next).toMatch(/target_framework/i);
  });

  it('merges CVEs from wp_vuln_check (live) and wp_vuln_check_source (Task 18) without double-counting a shared id', async () => {
    const plugin = makePlugin();
    const P = projectPath();
    plugin.storage.scans.insert({ scan_id: 'live', scan_type: 'wp_vuln_check', project_path: P, tree_hash: 'h' });
    plugin.storage.cves.upsert({ cve_id: 'CVE-SHARED', package_name: 'a', severity: 'high', scan_id: 'live' });
    plugin.storage.cves.upsert({ cve_id: 'CVE-LIVE-ONLY', package_name: 'b', severity: 'medium', scan_id: 'live' });
    plugin.storage.scans.finalize({ scan_id: 'live', status: 'completed', tools_run: [], missing_tools: [] });

    plugin.storage.scans.insert({ scan_id: 'src', scan_type: 'wp_vuln_check_source', project_path: P, tree_hash: 'h' });
    plugin.storage.cves.upsert({ cve_id: 'CVE-SHARED', package_name: 'a', severity: 'high', scan_id: 'src' });
    plugin.storage.cves.upsert({ cve_id: 'CVE-SOURCE-ONLY', package_name: 'c', severity: 'low', scan_id: 'src' });
    plugin.storage.scans.finalize({ scan_id: 'src', status: 'completed', tools_run: [], missing_tools: [] });

    const wp = (await getTool('wp_describe_setup').handler({ project_path: P }, plugin)) as {
      ok: true;
      audits: {
        wp_vuln_check: { cves_count: number } | null;
        wp_vuln_check_source: { cves_count: number } | null;
      };
      active_cves: Array<{ cve_id: string }>;
    };

    expect(wp.audits.wp_vuln_check?.cves_count).toBe(2);
    expect(wp.audits.wp_vuln_check_source?.cves_count).toBe(2);
    expect(wp.active_cves.map((c) => c.cve_id).sort()).toEqual(['CVE-LIVE-ONLY', 'CVE-SHARED', 'CVE-SOURCE-ONLY']);
  });
});

describe('new resources', () => {
  it('guardian://wp/cron returns last_run=null when empty', async () => {
    const plugin = makePlugin();
    const r = await getResource('guardian-wp-cron').handler(
      new URL('guardian://wp/cron'),
      {},
      plugin,
    );
    expect((r.json as { last_run: null }).last_run).toBeNull();
  });

  it('guardian://dotnet/target-frameworks returns last_run=null when empty', async () => {
    const plugin = makePlugin();
    const r = await getResource('guardian-dotnet-target-frameworks').handler(
      new URL('guardian://dotnet/target-frameworks'),
      {},
      plugin,
    );
    expect((r.json as { last_run: null }).last_run).toBeNull();
  });
});
