/**
 * Smoke + integration tests for the 12 Phase-14 tools.
 *
 * Each test exercises one tool, asserting it registers correctly and
 * returns a well-shaped response for the most common scenario. The tools
 * are mostly read-only (no scanner spawn), so this is fast.
 */

import Database from 'better-sqlite3';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

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
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';
import { makeFinding } from '../../src/runners/scannerParsers/index.js';

beforeAll(async () => {
  // Import everything once so TOOLS is populated.
  await import('../../src/tools/securityScanFull.js');
  await import('../../src/tools/scanSast.js');
  await import('../../src/tools/scanDeps.js');
  await import('../../src/tools/scanSecrets.js');
  await import('../../src/tools/scanContainers.js');
  await import('../../src/tools/scanIac.js');
  await import('../../src/tools/bugHunt.js');
  await import('../../src/tools/qualityCheck.js');
  await import('../../src/tools/reviewPr.js');
  await import('../../src/tools/depsAudit.js');
  await import('../../src/tools/depsUpdatePlan.js');
  await import('../../src/tools/complianceCheck.js');
  await import('../../src/tools/generateSbom.js');
  await import('../../src/tools/detectStack.js');
  await import('../../src/tools/initProject.js');
  await import('../../src/tools/observabilitySetup.js');
  await import('../../src/tools/perfCheck.js');
  await import('../../src/tools/setBaseline.js');
  await import('../../src/tools/suppressFinding.js');
  await import('../../src/tools/diffScans.js');
  await import('../../src/tools/auditExecutive.js');
  await import('../../src/tools/checkToolchain.js');
  await import('../../src/tools/installToolchain.js');
  // Phase 14:
  await import('../../src/tools/licenseCompatibility.js');
  await import('../../src/tools/riskScore.js');
  await import('../../src/tools/sbomDiff.js');
  await import('../../src/tools/regressionAlert.js');
  await import('../../src/tools/suggestFix.js');
  await import('../../src/tools/triageFindings.js');
  await import('../../src/tools/precommitInstall.js');
  await import('../../src/tools/registerCustomRules.js');
  await import('../../src/tools/healthStatus.js');
  await import('../../src/tools/reportExport.js');
  await import('../../src/tools/complianceEvidence.js');
  await import('../../src/tools/createGithubIssues.js');
});

function tempProject(): string {
  return mkdtempSync(join(tmpdir(), 'phase14-'));
}

function getTool(name: string) {
  const t = TOOLS.find((x) => x.name === name);
  if (!t) throw new Error(`Tool '${name}' not registered`);
  return t;
}

function makePlugin(projectPath?: string): PluginContext {
  const db = new Database(':memory:');
  runMigrations(db);
  const storage = new Storage(db);
  return {
    storage,
    shell: {
      command: 'bash',
      args_prefix: [],
      needs_wsl_path_translate: false,
      label: 'fake',
    },
    scriptsDir: projectPath ?? '',
    progressNotifier: { send: () => {} },
  };
}

function seedFindings(plugin: PluginContext, scanId: string, n: number): void {
  plugin.storage.scans.insert({
    scan_id: scanId,
    scan_type: 'sast',
    project_path: '/p',
    tree_hash: 'h',
  });
  plugin.storage.findings.bulkInsert(
    Array.from({ length: n }).map((_, i) => ({
      scan_id: scanId,
      ...makeFinding({
        tool: 'mock',
        severity: i === 0 ? 'critical' : 'high',
        category: 'security',
        title: `f${i}`,
        file_path: `src/file${i}.ts`,
        line_start: i + 1,
      }),
    })),
  );
  plugin.storage.scans.finalize({
    scan_id: scanId,
    status: 'completed',
    tools_run: [],
    missing_tools: [],
  });
}

beforeEach(() => {
  vi.mocked(runProcess).mockReset();
  vi.mocked(scannerAvailable).mockReset();
});

afterEach(() => {
  vi.mocked(runProcess).mockReset();
  vi.mocked(scannerAvailable).mockReset();
});

describe('phase 14 — registry', () => {
  it('all 12 new tools are registered', () => {
    const names = TOOLS.map((t) => t.name);
    for (const n of [
      'license_compatibility',
      'risk_score',
      'sbom_diff',
      'regression_alert',
      'suggest_fix',
      'triage_findings',
      'precommit_install',
      'register_custom_rules',
      'health_status',
      'report_export',
      'compliance_evidence',
      'create_github_issues',
    ]) {
      expect(names).toContain(n);
    }
  });
});

describe('risk_score', () => {
  it('returns a low score for an empty project', async () => {
    const plugin = makePlugin();
    const r = (await getTool('risk_score').handler({}, plugin)) as {
      ok: true;
      score: number;
      band: string;
    };
    expect(r.ok).toBe(true);
    expect(r.score).toBeGreaterThanOrEqual(0);
    expect(r.score).toBeLessThan(50);
    expect(['low', 'medium', 'high', 'critical']).toContain(r.band);
  });

  it('scales with severity weighted findings', async () => {
    const plugin = makePlugin();
    seedFindings(plugin, 'A', 5);
    const r = (await getTool('risk_score').handler({}, plugin)) as {
      ok: true;
      score: number;
    };
    expect(r.score).toBeGreaterThan(0);
  });
});

describe('triage_findings', () => {
  it('buckets test files as likely_false_positive', async () => {
    const plugin = makePlugin();
    plugin.storage.scans.insert({
      scan_id: 'A',
      scan_type: 'sast',
      project_path: '/p',
      tree_hash: 'h',
    });
    plugin.storage.findings.bulkInsert([
      {
        scan_id: 'A',
        ...makeFinding({
          tool: 'semgrep',
          severity: 'high',
          category: 'security',
          title: 'test thing',
          file_path: 'src/__tests__/foo.test.ts',
          line_start: 1,
        }),
      },
      {
        scan_id: 'A',
        ...makeFinding({
          tool: 'semgrep',
          severity: 'high',
          category: 'security',
          title: 'real thing',
          file_path: 'src/billing.ts',
          line_start: 5,
        }),
      },
    ]);
    plugin.storage.scans.finalize({
      scan_id: 'A',
      status: 'completed',
      tools_run: [],
      missing_tools: [],
    });

    const r = (await getTool('triage_findings').handler({}, plugin)) as {
      ok: true;
      likely_false_positive: unknown[];
      keep_sample: unknown[];
    };
    expect(r.likely_false_positive).toHaveLength(1);
    expect(r.keep_sample).toHaveLength(1);
  });
});

describe('suggest_fix', () => {
  it('packs surrounding source + finding context', async () => {
    const project = tempProject();
    writeFileSync(
      join(project, 'app.js'),
      'line1\nline2\nvulnerable line\nline4\nline5\n',
      'utf8',
    );
    const plugin = makePlugin(project);
    plugin.storage.scans.insert({
      scan_id: 'A',
      scan_type: 'sast',
      project_path: project,
      tree_hash: 'h',
    });
    const f = makeFinding({
      tool: 'semgrep',
      severity: 'high',
      category: 'security',
      title: 'eval used',
      file_path: 'app.js',
      line_start: 3,
      line_end: 3,
    });
    plugin.storage.findings.bulkInsert([{ scan_id: 'A', ...f }]);
    plugin.storage.scans.finalize({
      scan_id: 'A',
      status: 'completed',
      tools_run: [],
      missing_tools: [],
    });

    const r = (await getTool('suggest_fix').handler(
      { project_path: project, finding_fingerprint: f.fingerprint },
      plugin,
    )) as { ok: true; surrounding_source: string };
    expect(r.ok).toBe(true);
    expect(r.surrounding_source).toContain('>>     3');
  });
});

describe('health_status', () => {
  it('returns server + storage diagnostics', async () => {
    const plugin = makePlugin();
    const r = (await getTool('health_status').handler({}, plugin)) as {
      ok: true;
      server: { uptime_seconds: number };
      registry: { tools: number; resources: number };
    };
    expect(r.ok).toBe(true);
    expect(r.server.uptime_seconds).toBeGreaterThanOrEqual(0);
    expect(r.registry.tools).toBeGreaterThan(20);
  });
});

describe('regression_alert', () => {
  it('flags regression when a previous scan exists with fewer critical findings', async () => {
    const plugin = makePlugin();
    plugin.storage.scans.insert({
      scan_id: 'old',
      scan_type: 'sast',
      project_path: '/p',
      tree_hash: 'h1',
    });
    plugin.storage.scans.finalize({
      scan_id: 'old',
      status: 'completed',
      tools_run: [],
      missing_tools: [],
    });
    seedFindings(plugin, 'new', 3);

    const r = (await getTool('regression_alert').handler(
      { threshold: 0.5 },
      plugin,
    )) as { ok: true; regressed: boolean; score_delta: number };
    expect(r.ok).toBe(true);
    expect(r.regressed).toBe(true);
    expect(r.score_delta).toBeGreaterThan(0);
  });
});

describe('register_custom_rules', () => {
  it('auto-discovers .semgrep/ when present and persists the path', async () => {
    const project = tempProject();
    const semDir = join(project, '.semgrep');
    require('node:fs').mkdirSync(semDir, { recursive: true });
    writeFileSync(join(semDir, 'rules.yml'), 'rules: []\n', 'utf8');
    const plugin = makePlugin();

    const r = (await getTool('register_custom_rules').handler(
      { project_path: project },
      plugin,
    )) as { ok: true; registered: string[] };
    expect(r.registered).toHaveLength(1);
    expect(plugin.storage.runtimeMeta.getJson('custom_semgrep_configs')).toBeDefined();
  });
});

describe('sbom_diff', () => {
  it('detects added / removed / changed components', async () => {
    const plugin = makePlugin();
    plugin.storage.scans.insert({
      scan_id: 'sbom1',
      scan_type: 'sbom',
      project_path: '/p',
      tree_hash: '',
    });
    plugin.storage.scans.finalize({
      scan_id: 'sbom1',
      status: 'completed',
      tools_run: [],
      missing_tools: [],
      meta: { top_packages: [{ name: 'a', version: '1' }, { name: 'b', version: '1' }] },
    });
    plugin.storage.scans.insert({
      scan_id: 'sbom2',
      scan_type: 'sbom',
      project_path: '/p',
      tree_hash: '',
    });
    plugin.storage.scans.finalize({
      scan_id: 'sbom2',
      status: 'completed',
      tools_run: [],
      missing_tools: [],
      meta: { top_packages: [{ name: 'a', version: '2' }, { name: 'c', version: '1' }] },
    });

    const r = (await getTool('sbom_diff').handler({}, plugin)) as {
      ok: true;
      summary: { added: number; removed: number; changed: number };
    };
    expect(r.summary).toEqual({ added: 1, removed: 1, changed: 1, unchanged: 0 });
  });
});

describe('license_compatibility', () => {
  it('flags MIT project + AGPL dep as incompatible', async () => {
    const project = tempProject();
    writeFileSync(join(project, 'package.json'), '{"name":"x","license":"MIT"}', 'utf8');
    const plugin = makePlugin(project);
    plugin.storage.scans.insert({
      scan_id: 'c',
      scan_type: 'compliance',
      project_path: project,
      tree_hash: 'h',
    });
    plugin.storage.scans.finalize({
      scan_id: 'c',
      status: 'completed',
      tools_run: [],
      missing_tools: [],
      meta: {
        licenses_summary: [{ license: 'AGPL-3.0', packages: ['risky-pkg'], risk: 'high' }],
      },
    });

    const r = (await getTool('license_compatibility').handler(
      { project_path: project },
      plugin,
    )) as { ok: true; incompatibilities: Array<{ dep_license: string }> };
    expect(r.incompatibilities).toHaveLength(1);
    expect(r.incompatibilities[0]?.dep_license).toBe('AGPL-3.0');
  });
});

describe('report_export', () => {
  it('writes an HTML file with severity counts and findings table', async () => {
    const project = tempProject();
    const plugin = makePlugin(project);
    seedFindings(plugin, 'A', 2);

    const r = (await getTool('report_export').handler(
      { project_path: project, scan_id: 'A' },
      plugin,
    )) as { ok: true; file_path: string; bytes: number; findings_count: number };
    expect(r.ok).toBe(true);
    expect(r.findings_count).toBe(2);
    expect(r.file_path).toMatch(/report\.html$/);
    expect(r.bytes).toBeGreaterThan(500);
  });
});

describe('compliance_evidence', () => {
  it('produces a Markdown evidence pack even with no scans yet', async () => {
    const plugin = makePlugin();
    const r = (await getTool('compliance_evidence').handler(
      { framework: 'gdpr' },
      plugin,
    )) as { ok: true; markdown: string; framework: string };
    expect(r.framework).toBe('gdpr');
    expect(r.markdown).toContain('# Compliance evidence — GDPR');
    expect(r.markdown).toContain('(no data — run');
  });
});

describe('create_github_issues', () => {
  it('returns dry_run plan without invoking gh', async () => {
    const project = tempProject();
    const plugin = makePlugin(project);
    seedFindings(plugin, 'A', 3);
    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/gh');

    const r = (await getTool('create_github_issues').handler(
      { project_path: project, dry_run: true, max_issues: 2 },
      plugin,
    )) as { ok: true; applied: boolean; plans: Array<{ status: string }> };
    expect(r.applied).toBe(false);
    expect(r.plans.length).toBeGreaterThan(0);
    expect(r.plans.every((p) => p.status === 'would_create')).toBe(true);
    expect(vi.mocked(runProcess)).not.toHaveBeenCalled();
  });

  it('returns missing_scanner when gh is absent', async () => {
    const plugin = makePlugin();
    vi.mocked(scannerAvailable).mockResolvedValue(null);

    const r = (await getTool('create_github_issues').handler({}, plugin)) as
      | { ok: true }
      | { ok: false; error: { code: string } };
    expect(r.ok).toBe(false);
  });
});
