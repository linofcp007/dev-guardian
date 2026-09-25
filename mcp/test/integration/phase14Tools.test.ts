/**
 * Smoke + integration tests for the 12 Phase-14 tools.
 *
 * Each test exercises one tool, asserting it registers correctly and
 * returns a well-shaped response for the most common scenario. The tools
 * are mostly read-only (no scanner spawn), so this is fast.
 */

import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { readFileSync, unlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
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
import type { Severity } from '../../src/types.js';
import { resolveVersion } from '../../src/platform/version.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';
import { makeFinding } from '../../src/runners/scannerParsers/index.js';
import { resolveProjectPath } from '../../src/platform/projectPath.js';
import { makeTempDir, cleanupTempDirs } from '../helpers/tempDir.js';

afterAll(cleanupTempDirs);

/**
 * The project the shared seed helpers file scans under. The history readers
 * answer for one project (`project_path`, default the working directory), so
 * a test that seeds scans must name the same, real, project when it reads.
 */
const P = resolveProjectPath(makeTempDir('phase14-p-')).path;

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
  return resolveProjectPath(makeTempDir('phase14-')).path;
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

function seedFindings(plugin: PluginContext, scanId: string, n: number, project = P): void {
  plugin.storage.scans.insert({
    scan_id: scanId,
    scan_type: 'sast',
    project_path: project,
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

/** Like `seedFindings`, but the caller names each finding's severity — for
 *  the tools whose whole behaviour under test is a severity floor. */
function seedSeverities(plugin: PluginContext, scanId: string, severities: Severity[], project = P): void {
  plugin.storage.scans.insert({
    scan_id: scanId,
    scan_type: 'sast',
    project_path: project,
    tree_hash: 'h',
  });
  plugin.storage.findings.bulkInsert(
    severities.map((severity, i) => ({
      scan_id: scanId,
      ...makeFinding({
        tool: 'mock',
        severity,
        category: 'security',
        title: `sev${i}`,
        file_path: `src/sev${i}.ts`,
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
    const r = (await getTool('risk_score').handler({ project_path: P }, plugin)) as {
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
    const r = (await getTool('risk_score').handler({ project_path: P }, plugin)) as {
      ok: true;
      score: number;
      components: { findings: { open_findings: number } };
    };
    expect(r.score).toBeGreaterThan(0);
    expect(r.components.findings.open_findings).toBe(5);
  });
});

describe('triage_findings', () => {
  it('buckets test files as likely_false_positive', async () => {
    const plugin = makePlugin();
    plugin.storage.scans.insert({
      scan_id: 'A',
      scan_type: 'sast',
      project_path: P,
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

    const r = (await getTool('triage_findings').handler({ project_path: P }, plugin)) as {
      ok: true;
      likely_false_positive: unknown[];
      keep: unknown[];
    };
    expect(r.likely_false_positive).toHaveLength(1);
    expect(r.keep).toHaveLength(1);
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

  it('reports the real release version, not a hardcoded literal', async () => {
    // Regression guard: this field used to be a hardcoded '0.1.0',
    // independent of (and just as stale as) the one report/sarif.ts carried
    // before both were pointed at the shared resolveVersion()
    // (platform/version.ts, itself pinned against plugin.json directly in
    // platform/version.test.ts). Reusing the resolver here — rather than a
    // second independent plugin.json read — tests the WIRING: that this
    // handler actually calls the shared source of truth rather than a fresh
    // hardcoded string that could just as easily go stale again.
    const plugin = makePlugin();
    const r = (await getTool('health_status').handler({}, plugin)) as {
      ok: true;
      server: { version: string };
    };
    expect(r.server.version).toBe(resolveVersion());
    expect(r.server.version).not.toBe('0.1.0');
  });
});

describe('regression_alert', () => {
  it('flags regression when a previous scan exists with fewer critical findings', async () => {
    const plugin = makePlugin();
    plugin.storage.scans.insert({
      scan_id: 'old',
      scan_type: 'sast',
      project_path: P,
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
      { threshold: 0.5, project_path: P },
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
  function seedSbomScan(
    plugin: PluginContext,
    project: string,
    scanId: string,
    components: Array<{ name: string; version: string; purl?: string }>,
  ): void {
    const filePath = join(project, `${scanId}.cdx.json`);
    writeFileSync(
      filePath,
      JSON.stringify({
        bomFormat: 'CycloneDX',
        specVersion: '1.5',
        components: components.map((c) => ({
          type: 'library',
          name: c.name,
          version: c.version,
          ...(c.purl ? { purl: c.purl } : {}),
        })),
      }),
      'utf8',
    );
    plugin.storage.scans.insert({ scan_id: scanId, scan_type: 'sbom', project_path: project, tree_hash: '' });
    plugin.storage.scans.finalize({
      scan_id: scanId,
      status: 'completed',
      tools_run: [],
      missing_tools: [],
      report_dir: filePath,
      meta: {
        file_path: filePath,
        top_packages: components.slice(0, 25).map((c) => ({ name: c.name, version: c.version })),
      },
    });
  }

  it('detects added / removed / changed components from the full SBOM file, not just the first 25', async () => {
    const project = tempProject();
    const plugin = makePlugin(project);
    // 30 unchanged components (beyond the old top-25 cap) plus one changed,
    // one added and one removed — all outside the first 25 in document order.
    const bulk = Array.from({ length: 30 }, (_, i) => ({ name: `pkg-${i}`, version: '1.0.0' }));
    seedSbomScan(plugin, project, 'sbom1', [...bulk, { name: 'a', version: '1' }, { name: 'b', version: '1' }]);
    seedSbomScan(plugin, project, 'sbom2', [...bulk, { name: 'a', version: '2' }, { name: 'c', version: '1' }]);

    const r = (await getTool('sbom_diff').handler({ project_path: project }, plugin)) as {
      ok: true;
      summary: { added: number; removed: number; changed: number; unchanged: number };
    };
    expect(r.summary).toEqual({ added: 1, removed: 1, changed: 1, unchanged: 30 });
  });

  it('keys components by (ecosystem, name) — same name in two ecosystems never collapses into one row', async () => {
    const project = tempProject();
    const plugin = makePlugin(project);
    seedSbomScan(plugin, project, 'sbom1', [
      { name: 'requests', version: '2.28.0', purl: 'pkg:pypi/requests@2.28.0' },
    ]);
    seedSbomScan(plugin, project, 'sbom2', [
      { name: 'requests', version: '2.28.0', purl: 'pkg:pypi/requests@2.28.0' },
      // A DIFFERENT ecosystem's package that happens to share the name —
      // must show up as ADDED, never merged into the pypi one above.
      { name: 'requests', version: '0.1.0', purl: 'pkg:npm/requests@0.1.0' },
    ]);

    const r = (await getTool('sbom_diff').handler({ project_path: project }, plugin)) as {
      ok: true;
      summary: { added: number; changed: number; unchanged: number };
      added: Array<{ name: string; ecosystem: string }>;
    };
    expect(r.summary).toEqual({ added: 1, removed: 0, changed: 0, unchanged: 1 });
    expect(r.added).toEqual([{ name: 'requests', version: '0.1.0', ecosystem: 'npm' }]);
  });

  it('the default pair is scoped to project_path — another project\'s SBOM scans never leak in', async () => {
    const projectA = tempProject();
    const projectB = tempProject();
    const plugin = makePlugin(projectB);
    // Two SBOM scans of project A only.
    seedSbomScan(plugin, projectA, 'a1', [{ name: 'left-pkg', version: '1' }]);
    seedSbomScan(plugin, projectA, 'a2', [{ name: 'left-pkg', version: '2' }]);
    // One SBOM scan of project B — not enough, on its own, for a default pair.
    seedSbomScan(plugin, projectB, 'b1', [{ name: 'right-pkg', version: '1' }]);

    const r = await getTool('sbom_diff').handler({ project_path: projectB }, plugin);
    expect(r.ok).toBe(false);
    if (r.ok) throw new Error('expected failure');
    expect(r.error.message).toContain(projectB);
  });

  it('caps the response arrays but reports true, uncapped totals in summary', async () => {
    const project = tempProject();
    const plugin = makePlugin(project);
    const manyAdded = Array.from({ length: 60 }, (_, i) => ({ name: `new-${i}`, version: '1.0.0' }));
    seedSbomScan(plugin, project, 'sbom1', []);
    seedSbomScan(plugin, project, 'sbom2', manyAdded);

    const r = (await getTool('sbom_diff').handler({ project_path: project }, plugin)) as {
      ok: true;
      summary: { added: number };
      added: unknown[];
      truncated: boolean;
    };
    expect(r.summary.added).toBe(60);
    expect(r.added.length).toBeLessThan(60);
    expect(r.truncated).toBe(true);
  });

  // ------------------------------------------------------------ fix round 1

  it("item 6: TWO versions of the same package in the SAME ecosystem coexisting is reported per-version, not collapsed", async () => {
    // The brief's own worked example: lodash@3 and lodash@4 present AT THE
    // SAME TIME (a routine nested-duplicate-install shape), not a version
    // bump from one to the other.
    const project = tempProject();
    const plugin = makePlugin(project);
    seedSbomScan(plugin, project, 'sbom1', [
      { name: 'lodash', version: '3.10.1', purl: 'pkg:npm/lodash@3.10.1' },
      { name: 'lodash', version: '4.17.20', purl: 'pkg:npm/lodash@4.17.20' },
    ]);
    seedSbomScan(plugin, project, 'sbom2', [
      { name: 'lodash', version: '3.10.1', purl: 'pkg:npm/lodash@3.10.1' },
      { name: 'lodash', version: '4.17.21', purl: 'pkg:npm/lodash@4.17.21' },
    ]);

    const r = (await getTool('sbom_diff').handler({ project_path: project }, plugin)) as {
      ok: true;
      summary: { added: number; removed: number; changed: number; unchanged: number };
      added: Array<{ name: string; version?: string; ecosystem: string }>;
      removed: Array<{ name: string; version?: string; ecosystem: string }>;
    };
    // 4.17.20 removed, 4.17.21 added, 3.10.1 unchanged — reported as TWO
    // per-version events, not as a spurious "changed 3.10.1 -> 4.17.21"
    // (which would misreport the still-present 3.10.1 as gone) nor
    // collapsed away entirely.
    expect(r.summary).toEqual({ added: 1, removed: 1, changed: 0, unchanged: 1 });
    expect(r.added).toEqual([{ name: 'lodash', version: '4.17.21', ecosystem: 'npm' }]);
    expect(r.removed).toEqual([{ name: 'lodash', version: '4.17.20', ecosystem: 'npm' }]);
  });

  it('item 6: a simple single-version bump is still reported as one "changed" entry', async () => {
    const project = tempProject();
    const plugin = makePlugin(project);
    seedSbomScan(plugin, project, 'sbom1', [{ name: 'lodash', version: '3.10.1', purl: 'pkg:npm/lodash@3.10.1' }]);
    seedSbomScan(plugin, project, 'sbom2', [{ name: 'lodash', version: '4.17.21', purl: 'pkg:npm/lodash@4.17.21' }]);

    const r = (await getTool('sbom_diff').handler({ project_path: project }, plugin)) as {
      ok: true;
      summary: { added: number; removed: number; changed: number };
      changed: Array<{ name: string; from_version: string; to_version: string }>;
    };
    expect(r.summary).toEqual({ added: 0, removed: 0, changed: 1, unchanged: 0 });
    expect(r.changed).toEqual([{ name: 'lodash', ecosystem: 'npm', from_version: '3.10.1', to_version: '4.17.21' }]);
  });

  it('item 6: refuses a comparison that would mix a full SBOM file against a capped-summary fallback', async () => {
    const project = tempProject();
    const plugin = makePlugin(project);
    seedSbomScan(plugin, project, 'sbom1', [{ name: 'lodash', version: '3.10.1' }]);
    seedSbomScan(plugin, project, 'sbom2', [{ name: 'lodash', version: '4.17.21' }]);
    // sbom2's SBOM file is gone — only sbom1's is still on disk.
    unlinkSync(join(project, 'sbom2.cdx.json'));

    const r = await getTool('sbom_diff').handler({ project_path: project }, plugin);
    expect(r.ok).toBe(false);
    if (r.ok) throw new Error('expected failure');
    expect(r.error.message).toMatch(/full SBOM file/i);
    expect(r.error.message).toMatch(/capped summary/i);
  });

  it('item 6: a both-files-gone comparison still runs, but is clearly flagged and never claims uncapped totals', async () => {
    const project = tempProject();
    const plugin = makePlugin(project);
    seedSbomScan(plugin, project, 'sbom1', [{ name: 'lodash', version: '3.10.1' }]);
    seedSbomScan(plugin, project, 'sbom2', [{ name: 'lodash', version: '4.17.21' }]);
    unlinkSync(join(project, 'sbom1.cdx.json'));
    unlinkSync(join(project, 'sbom2.cdx.json'));

    const r = (await getTool('sbom_diff').handler({ project_path: project }, plugin)) as {
      ok: true;
      component_source: string;
      summary_caveat: string | null;
      changed: Array<{ ecosystem: string }>;
    };
    expect(r.ok).toBe(true);
    expect(r.component_source).toBe('capped_summary_fallback');
    expect(r.summary_caveat).toMatch(/not the true, uncapped/i);
    // Both sides fell back uniformly to 'unknown' — no spurious mismatch.
    expect(r.changed[0]?.ecosystem).toBe('unknown');
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

  function seedComplianceLicenses(
    plugin: PluginContext,
    project: string,
    licenses: Array<{ license: string; packages: string[] }>,
  ): void {
    plugin.storage.scans.insert({ scan_id: 'c', scan_type: 'compliance', project_path: project, tree_hash: 'h' });
    plugin.storage.scans.finalize({
      scan_id: 'c',
      status: 'completed',
      tools_run: [],
      missing_tools: [],
      meta: { licenses_summary: licenses.map((l) => ({ ...l, risk: 'high' })) },
    });
  }

  it('no declared license (the normal proprietary case) still flags a copyleft dependency, instead of returning zero issues', async () => {
    const project = tempProject(); // no package.json, no LICENSE — nothing declared
    const plugin = makePlugin(project);
    seedComplianceLicenses(plugin, project, [{ license: 'GPL-3.0', packages: ['risky-pkg'] }]);

    const r = (await getTool('license_compatibility').handler(
      { project_path: project },
      plugin,
    )) as { ok: true; project_license: string | null; treated_as_proprietary: boolean; incompatibilities: Array<{ dep_license: string }> };

    expect(r.project_license).toBeNull();
    expect(r.treated_as_proprietary).toBe(true);
    expect(r.incompatibilities).toHaveLength(1);
    expect(r.incompatibilities[0]?.dep_license).toBe('GPL-3.0');
  });

  it('npm UNLICENSED is treated the same as no declared license — copyleft deps are still flagged', async () => {
    const project = tempProject();
    writeFileSync(join(project, 'package.json'), '{"name":"x","license":"UNLICENSED"}', 'utf8');
    const plugin = makePlugin(project);
    seedComplianceLicenses(plugin, project, [{ license: 'AGPL-3.0', packages: ['risky-pkg'] }]);

    const r = (await getTool('license_compatibility').handler(
      { project_path: project },
      plugin,
    )) as { ok: true; project_license: string | null; treated_as_proprietary: boolean; incompatibilities: Array<{ dep_license: string }> };

    expect(r.project_license).toBe('UNLICENSED');
    expect(r.treated_as_proprietary).toBe(true);
    expect(r.incompatibilities).toHaveLength(1);
  });

  it('a permissive-licensed dependency raises no issue for a proprietary (no-license) project', async () => {
    const project = tempProject();
    const plugin = makePlugin(project);
    seedComplianceLicenses(plugin, project, [{ license: 'MIT', packages: ['fine-pkg'] }]);

    const r = (await getTool('license_compatibility').handler(
      { project_path: project },
      plugin,
    )) as { ok: true; incompatibilities: unknown[] };
    expect(r.incompatibilities).toEqual([]);
  });

  it('reads PackageLicenseExpression from a .csproj when no package.json/composer.json exists', async () => {
    const project = tempProject();
    writeFileSync(
      join(project, 'Lib.csproj'),
      '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><PackageLicenseExpression>MIT</PackageLicenseExpression></PropertyGroup></Project>',
      'utf8',
    );
    const plugin = makePlugin(project);
    seedComplianceLicenses(plugin, project, [{ license: 'AGPL-3.0', packages: ['risky-pkg'] }]);

    const r = (await getTool('license_compatibility').handler(
      { project_path: project },
      plugin,
    )) as { ok: true; project_license: string | null; incompatibilities: Array<{ dep_license: string }> };
    expect(r.project_license).toBe('MIT');
    expect(r.incompatibilities).toHaveLength(1);
  });

  it('reads the license field from composer.json', async () => {
    const project = tempProject();
    writeFileSync(join(project, 'composer.json'), '{"name":"x/y","license":"MIT"}', 'utf8');
    const plugin = makePlugin(project);
    seedComplianceLicenses(plugin, project, [{ license: 'GPL-2.0', packages: ['risky-pkg'] }]);

    const r = (await getTool('license_compatibility').handler(
      { project_path: project },
      plugin,
    )) as { ok: true; project_license: string | null; incompatibilities: Array<{ dep_license: string }> };
    expect(r.project_license).toBe('MIT');
    expect(r.incompatibilities).toHaveLength(1);
  });

  it('models GPL-2.0-only vs Apache-2.0 as an incompatibility (SPDX "-only" suffix)', async () => {
    const project = tempProject();
    writeFileSync(join(project, 'package.json'), '{"name":"x","license":"GPL-2.0-only"}', 'utf8');
    const plugin = makePlugin(project);
    seedComplianceLicenses(plugin, project, [{ license: 'Apache-2.0', packages: ['dep'] }]);

    const r = (await getTool('license_compatibility').handler(
      { project_path: project },
      plugin,
    )) as { ok: true; incompatibilities: Array<{ reason: string }> };
    expect(r.incompatibilities).toHaveLength(1);
    expect(r.incompatibilities[0]?.reason).toMatch(/patent termination/i);
  });

  it("models AGPL's network clause distinctly from ordinary viral copyleft", async () => {
    const project = tempProject();
    writeFileSync(join(project, 'package.json'), '{"name":"x","license":"MIT"}', 'utf8');
    const plugin = makePlugin(project);
    seedComplianceLicenses(plugin, project, [{ license: 'AGPL-3.0', packages: ['risky-pkg'] }]);

    const r = (await getTool('license_compatibility').handler(
      { project_path: project },
      plugin,
    )) as { ok: true; incompatibilities: Array<{ reason: string }> };
    expect(r.incompatibilities[0]?.reason).toMatch(/network/i);
  });

  // ------------------------------------------------------------ fix round 1

  it('item 5: composer\'s documented "proprietary" / "Proprietary" / "SEE LICENSE IN …" are treated as proprietary, not left uncompatible-checked', async () => {
    for (const label of ['proprietary', 'Proprietary', 'SEE LICENSE IN LICENSE.txt']) {
      const project = tempProject();
      writeFileSync(join(project, 'composer.json'), JSON.stringify({ name: 'x/y', license: label }), 'utf8');
      const plugin = makePlugin(project);
      seedComplianceLicenses(plugin, project, [{ license: 'AGPL-3.0', packages: ['risky-pkg'] }]);

      const r = (await getTool('license_compatibility').handler(
        { project_path: project },
        plugin,
      )) as { ok: true; treated_as_proprietary: boolean; incompatibilities: unknown[] };
      expect(r.treated_as_proprietary, `label=${label}`).toBe(true);
      expect(r.incompatibilities, `label=${label}`).toHaveLength(1);
    }
  });

  it("item 5: an SPDX 'A OR B' dependency license is evaluated, not silently read as compatible", async () => {
    const project = tempProject();
    writeFileSync(join(project, 'package.json'), '{"name":"x","license":"MIT"}', 'utf8');
    const plugin = makePlugin(project);
    // Every option risky — the licensee cannot pick a safe one.
    seedComplianceLicenses(plugin, project, [{ license: 'AGPL-3.0 OR SSPL-1.0', packages: ['dual-risky'] }]);

    const r = (await getTool('license_compatibility').handler(
      { project_path: project },
      plugin,
    )) as { ok: true; incompatibilities: Array<{ dep_license: string }> };
    expect(r.incompatibilities).toHaveLength(1);
    expect(r.incompatibilities[0]?.dep_license).toBe('AGPL-3.0 OR SSPL-1.0');
  });

  it("item 5: an SPDX 'A OR B' dependency license is compatible when EITHER option is safe", async () => {
    const project = tempProject();
    writeFileSync(join(project, 'package.json'), '{"name":"x","license":"MIT"}', 'utf8');
    const plugin = makePlugin(project);
    seedComplianceLicenses(plugin, project, [{ license: 'MIT OR Apache-2.0', packages: ['dual-fine'] }]);

    const r = (await getTool('license_compatibility').handler(
      { project_path: project },
      plugin,
    )) as { ok: true; incompatibilities: unknown[]; undetermined: unknown[] };
    expect(r.incompatibilities).toEqual([]);
    expect(r.undetermined).toEqual([]);
  });

  it('item 5: an unrecognised dependency license is reported as undetermined, never silently compatible', async () => {
    const project = tempProject();
    writeFileSync(join(project, 'package.json'), '{"name":"x","license":"MIT"}', 'utf8');
    const plugin = makePlugin(project);
    seedComplianceLicenses(plugin, project, [{ license: 'Some-Custom-EULA-1.0', packages: ['mystery-pkg'] }]);

    const r = (await getTool('license_compatibility').handler(
      { project_path: project },
      plugin,
    )) as {
      ok: true;
      incompatibilities: unknown[];
      undetermined: Array<{ dep_license: string; packages: string[]; reason: string }>;
      summary: { undetermined_total: number };
    };
    expect(r.incompatibilities).toEqual([]);
    expect(r.undetermined).toHaveLength(1);
    expect(r.undetermined[0]).toMatchObject({ dep_license: 'Some-Custom-EULA-1.0', packages: ['mystery-pkg'] });
    expect(r.summary.undetermined_total).toBe(1);
  });

  it('item 5: findLatestCompliance is scoped to THIS project — another project\'s compliance scan never leaks in', async () => {
    const projectA = tempProject();
    const projectB = tempProject();
    writeFileSync(join(projectB, 'package.json'), '{"name":"x","license":"MIT"}', 'utf8');
    const plugin = makePlugin(projectB);
    // Compliance scan recorded against project A only, with an AGPL dep.
    seedComplianceLicenses(plugin, projectA, [{ license: 'AGPL-3.0', packages: ['a-only-pkg'] }]);

    const r = (await getTool('license_compatibility').handler(
      { project_path: projectB },
      plugin,
    )) as { ok: true; last_compliance_scan_id: string | null; dependencies_audited: number };
    expect(r.last_compliance_scan_id).toBeNull();
    expect(r.dependencies_audited).toBe(0);
  });

  // ------------------------------------------------------------ fix round 2

  it('item 5 (round 2): an SPDX "A OR B" PROJECT license is parsed — every alternative risky against an AGPL dep is incompatible, not silently compatible', async () => {
    const project = tempProject();
    writeFileSync(join(project, 'package.json'), '{"name":"x","license":"MIT OR Apache-2.0"}', 'utf8');
    const plugin = makePlugin(project);
    seedComplianceLicenses(plugin, project, [{ license: 'AGPL-3.0', packages: ['risky-pkg'] }]);

    const r = (await getTool('license_compatibility').handler({ project_path: project }, plugin)) as {
      ok: true;
      incompatibilities: Array<{ dep_license: string }>;
      undetermined: unknown[];
    };
    // Reproduces the coordinator's own probe: the OLD normaliseLicense
    // whitespace-collapsed "MIT OR Apache-2.0" into "MITORApache-2.0",
    // matching no rule for ANY dependency — 0 incompatibilities, 0
    // undetermined, for a project license that is, in fact, two known
    // permissive alternatives, BOTH of which conflict with AGPL.
    expect(r.incompatibilities).toHaveLength(1);
    expect(r.incompatibilities[0]?.dep_license).toBe('AGPL-3.0');
    expect(r.undetermined).toEqual([]);
  });

  it('item 5 (round 2): the same "A OR B" project-license parsing applies when the license comes from composer.json — GPL-2.0-only dep is incompatible', async () => {
    const project = tempProject();
    writeFileSync(join(project, 'composer.json'), JSON.stringify({ name: 'x/y', license: 'MIT OR Apache-2.0' }), 'utf8');
    const plugin = makePlugin(project);
    seedComplianceLicenses(plugin, project, [{ license: 'GPL-2.0-only', packages: ['risky-pkg'] }]);

    const r = (await getTool('license_compatibility').handler({ project_path: project }, plugin)) as {
      ok: true;
      incompatibilities: Array<{ dep_license: string }>;
    };
    expect(r.incompatibilities).toHaveLength(1);
    expect(r.incompatibilities[0]?.dep_license).toBe('GPL-2.0-only');
  });

  it('item 5 (round 2): a parenthesised "(A OR B)" PROJECT license still parses — parens are stripped, not left as stray characters that match nothing', async () => {
    const project = tempProject();
    writeFileSync(join(project, 'package.json'), '{"name":"x","license":"(MIT OR Apache-2.0)"}', 'utf8');
    const plugin = makePlugin(project);
    seedComplianceLicenses(plugin, project, [{ license: 'AGPL-3.0', packages: ['risky-pkg'] }]);

    const r = (await getTool('license_compatibility').handler({ project_path: project }, plugin)) as {
      ok: true;
      incompatibilities: Array<{ dep_license: string }>;
    };
    expect(r.incompatibilities).toHaveLength(1);
  });

  it('item 5 (round 2): a parenthesised "(A OR B)" DEPENDENCY license also parses — stripped parens, not undetermined', async () => {
    const project = tempProject();
    writeFileSync(join(project, 'package.json'), '{"name":"x","license":"MIT"}', 'utf8');
    const plugin = makePlugin(project);
    seedComplianceLicenses(plugin, project, [{ license: '(MIT OR Apache-2.0)', packages: ['dual-fine'] }]);

    const r = (await getTool('license_compatibility').handler({ project_path: project }, plugin)) as {
      ok: true;
      incompatibilities: unknown[];
      undetermined: unknown[];
    };
    expect(r.incompatibilities).toEqual([]);
    expect(r.undetermined).toEqual([]);
  });

  it('item 5 (round 2): an UNMODELLED single project license (MPL-2.0) reports undetermined for a copyleft dep, never silently compatible', async () => {
    const project = tempProject();
    writeFileSync(join(project, 'package.json'), '{"name":"x","license":"MPL-2.0"}', 'utf8');
    const plugin = makePlugin(project);
    seedComplianceLicenses(plugin, project, [
      { license: 'AGPL-3.0', packages: ['agpl-pkg'] },
      { license: 'GPL-2.0-only', packages: ['gpl2-pkg'] },
    ]);

    const r = (await getTool('license_compatibility').handler({ project_path: project }, plugin)) as {
      ok: true;
      incompatibilities: unknown[];
      undetermined: Array<{ dep_license: string }>;
    };
    // This table has no pairwise rule at all for an MPL-2.0 PROJECT license
    // — it is not "fine", it is genuinely not checked, and must read that
    // way rather than as a silent pass.
    expect(r.undetermined).toHaveLength(2);
    const depLicenses = r.undetermined.map((u) => u.dep_license).sort();
    expect(depLicenses).toEqual(['AGPL-3.0', 'GPL-2.0-only']);
  });

  it('item 5 (round 2): a GPL-3.0-only project is never silently compatible — AGPL-3.0 undetermined, GPL-2.0-only (round 4: no common GPL version) incompatible', async () => {
    const project = tempProject();
    writeFileSync(join(project, 'package.json'), '{"name":"x","license":"GPL-3.0-only"}', 'utf8');
    const plugin = makePlugin(project);
    seedComplianceLicenses(plugin, project, [
      { license: 'AGPL-3.0', packages: ['agpl-pkg'] },
      { license: 'GPL-2.0-only', packages: ['gpl2-pkg'] },
    ]);

    const r = (await getTool('license_compatibility').handler({ project_path: project }, plugin)) as {
      ok: true;
      incompatibilities: Array<{ dep_license: string }>;
      undetermined: Array<{ dep_license: string }>;
    };
    expect(r.undetermined.map((u) => u.dep_license)).toEqual(['AGPL-3.0']);
    expect(r.incompatibilities.map((i) => i.dep_license)).toEqual(['GPL-2.0-only']);
  });

  it('item 5 (round 2): an unmodelled project license still reads a PERMISSIVE dependency as compatible (no false undetermined)', async () => {
    const project = tempProject();
    writeFileSync(join(project, 'package.json'), '{"name":"x","license":"MPL-2.0"}', 'utf8');
    const plugin = makePlugin(project);
    seedComplianceLicenses(plugin, project, [{ license: 'MIT', packages: ['fine-pkg'] }]);

    const r = (await getTool('license_compatibility').handler({ project_path: project }, plugin)) as {
      ok: true;
      incompatibilities: unknown[];
      undetermined: unknown[];
    };
    expect(r.incompatibilities).toEqual([]);
    expect(r.undetermined).toEqual([]);
  });

  // ------------------------------------------------------------ fix round 3

  it('N4 (round 3): a dependency license mixing AND/OR with a non-wrapping paren is undetermined, never silently compatible', async () => {
    // The coordinator's own probe, reproduced exactly: a naive OR-first
    // split on "(MIT OR Apache-2.0) AND GPL-3.0-only" reads it as OR with
    // parts "(MIT" and "Apache-2.0) AND GPL-3.0-only" — the FIRST part
    // alone (a recognised permissive license once its stray paren strips)
    // made the WHOLE expression read compatible, silently dropping the
    // "AND GPL-3.0-only" term for a proprietary (no license) project.
    const project = tempProject(); // no package.json — proprietary
    const plugin = makePlugin(project);
    seedComplianceLicenses(plugin, project, [
      { license: '(MIT OR Apache-2.0) AND GPL-3.0-only', packages: ['pkg-a'] },
      { license: 'GPL-3.0-only AND (MIT OR Apache-2.0)', packages: ['pkg-b'] },
    ]);

    const r = (await getTool('license_compatibility').handler({ project_path: project }, plugin)) as {
      ok: true;
      incompatibilities: unknown[];
      undetermined: Array<{ dep_license: string }>;
    };
    expect(r.incompatibilities).toEqual([]);
    expect(r.undetermined).toHaveLength(2);
    const depLicenses = r.undetermined.map((u) => u.dep_license).sort();
    expect(depLicenses).toEqual([
      '(MIT OR Apache-2.0) AND GPL-3.0-only',
      'GPL-3.0-only AND (MIT OR Apache-2.0)',
    ]);
  });

  it('N4 (round 3): the same mixed AND/OR/paren expression is undetermined against a real (MIT) project too, not just proprietary', async () => {
    const project = tempProject();
    writeFileSync(join(project, 'package.json'), '{"name":"x","license":"MIT"}', 'utf8');
    const plugin = makePlugin(project);
    seedComplianceLicenses(plugin, project, [
      { license: '(MIT OR Apache-2.0) AND GPL-3.0-only', packages: ['pkg-a'] },
    ]);

    const r = (await getTool('license_compatibility').handler({ project_path: project }, plugin)) as {
      ok: true;
      incompatibilities: unknown[];
      undetermined: Array<{ dep_license: string }>;
    };
    expect(r.incompatibilities).toEqual([]);
    expect(r.undetermined).toHaveLength(1);
  });

  it('N4 (round 3): a single fully-wrapped OR expression on the DEPENDENCY side still parses correctly (no regression)', async () => {
    const project = tempProject();
    writeFileSync(join(project, 'package.json'), '{"name":"x","license":"MIT"}', 'utf8');
    const plugin = makePlugin(project);
    seedComplianceLicenses(plugin, project, [{ license: '(MIT OR Apache-2.0)', packages: ['pkg-a'] }]);

    const r = (await getTool('license_compatibility').handler({ project_path: project }, plugin)) as {
      ok: true;
      incompatibilities: unknown[];
      undetermined: unknown[];
    };
    expect(r.incompatibilities).toEqual([]);
    expect(r.undetermined).toEqual([]);
  });

  it('N5 (round 3): GPL-2.0-only project vs GPL-3.0-only / AGPL-3.0 deps are a real incompatibility, not silently compatible', async () => {
    // The fix round 2 shape's `isModeledProjectLicense` treated the WHOLE
    // GPL-2.0 family as "understood", so a dependency category the rule
    // table had no actual rule for (anything except Apache-2.0) fell
    // through to "ok" purely because the project side was recognised.
    const project = tempProject();
    writeFileSync(join(project, 'package.json'), '{"name":"x","license":"GPL-2.0-only"}', 'utf8');
    const plugin = makePlugin(project);
    seedComplianceLicenses(plugin, project, [
      { license: 'GPL-3.0-only', packages: ['gpl3-pkg'] },
      { license: 'AGPL-3.0', packages: ['agpl-pkg'] },
    ]);

    const r = (await getTool('license_compatibility').handler({ project_path: project }, plugin)) as {
      ok: true;
      incompatibilities: Array<{ dep_license: string; reason: string }>;
    };
    expect(r.incompatibilities).toHaveLength(2);
    const byDep = Object.fromEntries(r.incompatibilities.map((i) => [i.dep_license, i.reason]));
    expect(byDep['GPL-3.0-only']).toMatch(/GPL-3\.0/);
    expect(byDep['AGPL-3.0']).toMatch(/AGPL/);
  });

  it('N5 (round 3): GPL-2.0-only project vs SSPL-1.0 / BUSL-1.1 deps — no explicit rule for THIS pair — reads undetermined, not compatible', async () => {
    const project = tempProject();
    writeFileSync(join(project, 'package.json'), '{"name":"x","license":"GPL-2.0-only"}', 'utf8');
    const plugin = makePlugin(project);
    seedComplianceLicenses(plugin, project, [
      { license: 'SSPL-1.0', packages: ['sspl-pkg'] },
      { license: 'BUSL-1.1', packages: ['busl-pkg'] },
    ]);

    const r = (await getTool('license_compatibility').handler({ project_path: project }, plugin)) as {
      ok: true;
      incompatibilities: unknown[];
      undetermined: Array<{ dep_license: string }>;
    };
    expect(r.incompatibilities).toEqual([]);
    expect(r.undetermined).toHaveLength(2);
  });

  it('N5 (round 3): GPL-2.0-or-later project vs GPL-3.0 dep IS compatible — the -or-later escape the -only form lacks', async () => {
    const project = tempProject();
    writeFileSync(join(project, 'package.json'), '{"name":"x","license":"GPL-2.0-or-later"}', 'utf8');
    const plugin = makePlugin(project);
    seedComplianceLicenses(plugin, project, [{ license: 'GPL-3.0', packages: ['gpl3-pkg'] }]);

    const r = (await getTool('license_compatibility').handler({ project_path: project }, plugin)) as {
      ok: true;
      incompatibilities: unknown[];
      undetermined: unknown[];
    };
    expect(r.incompatibilities).toEqual([]);
    expect(r.undetermined).toEqual([]);
  });

  it('N5 (round 3): AGPL-3.0-only project vs GPL-2.0-only / SSPL-1.0 deps — no explicit rule — undetermined, not compatible', async () => {
    const project = tempProject();
    writeFileSync(join(project, 'package.json'), '{"name":"x","license":"AGPL-3.0-only"}', 'utf8');
    const plugin = makePlugin(project);
    seedComplianceLicenses(plugin, project, [
      { license: 'GPL-2.0-only', packages: ['gpl2-pkg'] },
      { license: 'SSPL-1.0', packages: ['sspl-pkg'] },
    ]);

    const r = (await getTool('license_compatibility').handler({ project_path: project }, plugin)) as {
      ok: true;
      incompatibilities: unknown[];
      undetermined: Array<{ dep_license: string }>;
    };
    expect(r.incompatibilities).toEqual([]);
    expect(r.undetermined).toHaveLength(2);
  });

  it('N5 (round 3): AGPL-3.0-only project vs Apache-2.0 dep stays compatible (permissive is fine against anything — no regression)', async () => {
    const project = tempProject();
    writeFileSync(join(project, 'package.json'), '{"name":"x","license":"AGPL-3.0-only"}', 'utf8');
    const plugin = makePlugin(project);
    seedComplianceLicenses(plugin, project, [{ license: 'Apache-2.0', packages: ['dep'] }]);

    const r = (await getTool('license_compatibility').handler({ project_path: project }, plugin)) as {
      ok: true;
      incompatibilities: unknown[];
      undetermined: unknown[];
    };
    expect(r.incompatibilities).toEqual([]);
    expect(r.undetermined).toEqual([]);
  });

  // ------------------------------------------------------------ fix round 4

  async function verdict(projectLicense: string, depLicense: string) {
    const project = tempProject();
    writeFileSync(join(project, 'package.json'), JSON.stringify({ name: 'x', license: projectLicense }), 'utf8');
    const plugin = makePlugin(project);
    seedComplianceLicenses(plugin, project, [{ license: depLicense, packages: ['dep'] }]);
    const r = (await getTool('license_compatibility').handler({ project_path: project }, plugin)) as {
      ok: true;
      incompatibilities: Array<{ reason: string }>;
      undetermined: Array<{ reason: string }>;
    };
    if (r.incompatibilities.length > 0) return { kind: 'incompatible', reason: r.incompatibilities[0]?.reason ?? '' };
    if (r.undetermined.length > 0) return { kind: 'undetermined', reason: r.undetermined[0]?.reason ?? '' };
    return { kind: 'ok', reason: '' };
  }

  it('F (round 4): the SAME license on both sides is compatible, never undetermined', async () => {
    const pairs: Array<[string, string]> = [
      ['GPL-2.0-only', 'GPL-2.0-only'],
      ['GPL-2.0', 'GPL-2.0-only'], // the bare SPDX id IS -only
      ['GPL-3.0-only', 'GPL-3.0-only'],
      ['GPL-3.0-or-later', 'GPL-3.0-or-later'],
      ['AGPL-3.0-only', 'AGPL-3.0'],
      ['LGPL-2.1-only', 'LGPL-2.1-only'],
      ['MPL-2.0', 'MPL-2.0'],
      ['SSPL-1.0', 'SSPL-1.0'],
    ];
    for (const [proj, dep] of pairs) {
      expect((await verdict(proj, dep)).kind, `${proj} + ${dep}`).toBe('ok');
    }
  });

  it('F (round 4): "or later" is decided by version — the same answer for an Apache-2.0 and a GPL-3.0 dependency', async () => {
    // A GPL-2.0-or-later project can elect GPL-3.0, which is compatible with
    // both. Round 3 flagged the Apache-2.0 case and passed the GPL-3.0 one.
    expect((await verdict('GPL-2.0-or-later', 'Apache-2.0')).kind).toBe('ok');
    expect((await verdict('GPL-2.0-or-later', 'GPL-3.0')).kind).toBe('ok');
    expect((await verdict('GPL-2.0+', 'GPL-3.0-only')).kind).toBe('ok'); // deprecated spelling of -or-later
    expect((await verdict('GPL-2.0-only', 'GPL-2.0-or-later')).kind).toBe('ok');
    expect((await verdict('GPL-3.0-only', 'GPL-2.0-or-later')).kind).toBe('ok');
    // …and -only has no such route.
    expect((await verdict('GPL-2.0-only', 'Apache-2.0')).kind).toBe('incompatible');
    expect((await verdict('GPL-2.0-only', 'GPL-3.0-only')).kind).toBe('incompatible');
    expect((await verdict('GPL-3.0-only', 'GPL-2.0-only')).kind).toBe('incompatible');
  });

  it('F (round 4): an LGPL dependency in a GPL project is judged by the GPL versions it may become', async () => {
    expect((await verdict('GPL-2.0-only', 'LGPL-2.1-only')).kind).toBe('ok');
    expect((await verdict('GPL-3.0-only', 'LGPL-2.1-or-later')).kind).toBe('ok');
    expect((await verdict('GPL-3.0-only', 'LGPL-3.0-only')).kind).toBe('ok');
    const lgpl3 = await verdict('GPL-2.0-only', 'LGPL-3.0-only');
    expect(lgpl3.kind).toBe('incompatible');
    expect(lgpl3.reason).toMatch(/no GPL version both allow/);
  });

  it('F (round 4): AGPL-1.0 gets its own reason — it is GPL-2.0-based, not "GPL-3.0-compatible licensing"', async () => {
    const inGpl2 = await verdict('GPL-2.0-only', 'AGPL-1.0-only');
    expect(inGpl2.kind).toBe('incompatible');
    expect(inGpl2.reason).toMatch(/section 2\(d\)/);
    expect(inGpl2.reason).not.toMatch(/GPL-3\.0/);
    const inMit = await verdict('MIT', 'AGPL-1.0-only');
    expect(inMit.kind).toBe('incompatible');
    expect(inMit.reason).toMatch(/AGPL-1\.0/);
    expect(inMit.reason).not.toMatch(/section 13/);
    // AGPL-3.0 keeps the section-13 wording and the GPL-3.0 explanation.
    expect((await verdict('MIT', 'AGPL-3.0-only')).reason).toMatch(/section 13/);
    expect((await verdict('GPL-2.0-only', 'AGPL-3.0-only')).reason).toMatch(/built on GPL-3\.0/);
  });
});

describe('report_export', () => {
  it('writes a branded HTML file with severity counts and findings table', async () => {
    const project = tempProject();
    const plugin = makePlugin(project);
    seedFindings(plugin, 'A', 2, project);

    const r = (await getTool('report_export').handler(
      { project_path: project, scan_id: 'A', format: 'html' },
      plugin,
    )) as { ok: true; file_path: string; bytes: number; findings_count: number };
    expect(r.ok).toBe(true);
    expect(r.findings_count).toBe(2);
    expect(r.file_path).toMatch(/report\.html$/);
    expect(r.bytes).toBeGreaterThan(500);
    const html = readFileSync(r.file_path, 'utf8');
    expect(html).toContain('pdk-report-theme'); // branded Pro Digital Key shell
    expect(html).toContain('Pro Digital Key');
  });

  it('defaults to markdown when no format is given', async () => {
    const project = tempProject();
    const plugin = makePlugin(project);
    seedFindings(plugin, 'A', 1, project);

    const r = (await getTool('report_export').handler(
      { project_path: project, scan_id: 'A' },
      plugin,
    )) as { ok: true; format: string; file_path: string };
    expect(r.format).toBe('markdown');
    expect(r.file_path).toMatch(/report\.md$/);
  });

  it('includes the CVEs of a deps_audit scan, which has its own scan type', async () => {
    const project = tempProject();
    const plugin = makePlugin(project);
    seedDepsAuditWithCve(plugin, 'DA', project);

    const r = (await getTool('report_export').handler(
      { project_path: project, scan_id: 'DA' },
      plugin,
    )) as { ok: true; cves_count: number; file_path: string };
    expect(r.cves_count).toBe(1);
    expect(readFileSync(r.file_path, 'utf8')).toContain('CVE-2024-DA');
  });
});

/** A completed `deps_audit` scan (its own scan type) that saw one CVE. */
function seedDepsAuditWithCve(plugin: PluginContext, scanId: string, project = P): void {
  plugin.storage.scans.insert({ scan_id: scanId, scan_type: 'deps_audit', project_path: project, tree_hash: 'h' });
  plugin.storage.cves.upsert({
    cve_id: `CVE-2024-${scanId}`, package_name: 'lodash', severity: 'high', scan_id: scanId,
  });
  plugin.storage.scans.finalize({ scan_id: scanId, status: 'completed', tools_run: [], missing_tools: [] });
}

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

  it('reads the dependency section from a deps_audit scan', async () => {
    const plugin = makePlugin();
    seedDepsAuditWithCve(plugin, 'EV');
    const r = (await getTool('compliance_evidence').handler({}, plugin)) as {
      ok: true;
      markdown: string;
    };
    expect(r.markdown).toContain('`EV`');
    expect(r.markdown).not.toContain('run `scan_deps` or `deps_audit` first');
  });
});

describe('create_github_issues', () => {
  it('returns dry_run plan without invoking gh', async () => {
    const project = tempProject();
    const plugin = makePlugin(project);
    seedFindings(plugin, 'A', 3, project);
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

  it('says what severity_min and max_issues filtered out, instead of an unexplained short plan', async () => {
    // Same defect as create_fix_pr's: severity_min defaults to `high` (and
    // the default was not even stated in the schema), max_issues to 10, and
    // the result reported only the survivors. A caller whose findings are
    // all `medium` got `candidates: 0` and no way to tell that from a clean
    // project.
    const project = tempProject();
    const plugin = makePlugin(project);
    seedSeverities(plugin, 'S1', ['critical', 'high', 'medium', 'medium', 'low'], project);
    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/gh');

    const r = (await getTool('create_github_issues').handler(
      { project_path: project, dry_run: true, max_issues: 1 },
      plugin,
    )) as {
      ok: true;
      candidates: number;
      filtered: {
        considered: number;
        candidates: number;
        excluded: number;
        by_reason: { below_severity_min: number; over_max_issues: number };
        below_severity_min: { suggested_severity_min: string | null };
      };
      filtered_reason: string | null;
    };

    expect(r.candidates).toBe(1);
    expect(r.filtered).toMatchObject({
      considered: 5,
      candidates: 1,
      excluded: 4,
      by_reason: { below_severity_min: 3, over_max_issues: 1 },
    });
    expect(r.filtered.below_severity_min.suggested_severity_min).toBe('medium');
    expect(String(r.filtered_reason)).toContain('2 medium, 1 low');
    expect(String(r.filtered_reason)).toContain('max_issues');
  });

  it('leaves filtered_reason null when nothing was filtered at all', async () => {
    const project = tempProject();
    const plugin = makePlugin(project);
    seedSeverities(plugin, 'S2', ['critical', 'high'], project);
    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/gh');

    const r = (await getTool('create_github_issues').handler(
      { project_path: project, dry_run: true },
      plugin,
    )) as { ok: true; filtered: { excluded: number }; filtered_reason: string | null };
    expect(r.filtered.excluded).toBe(0);
    expect(r.filtered_reason).toBeNull();
  });
});
