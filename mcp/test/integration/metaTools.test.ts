/**
 * Integration tests for set_baseline, suppress_finding, diff_scans,
 * audit_executive.
 *
 * The three SQL-only tools are tested end-to-end against in-memory storage.
 * audit_executive exercises the in-process TOOLS registry — we mock
 * runShellScript / runProcess / scannerAvailable so the sub-tools see
 * canned scanner output.
 */

import { GuardianDatabase as Database } from '../../src/storage/db.js';
import {
  mkdirSync,
  readFileSync,
  writeFileSync,
} from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from 'vitest';

vi.mock('../../src/runners/processRunner.js', () => ({
  runProcess: vi.fn(),
}));
vi.mock('../../src/runners/shellRunner.js', () => ({
  runShellScript: vi.fn(),
}));
vi.mock('../../src/tools/scanHelpers.js', async () => {
  const actual =
    await vi.importActual<typeof import('../../src/tools/scanHelpers.js')>(
      '../../src/tools/scanHelpers.js',
    );
  return { ...actual, scannerAvailable: vi.fn() };
});

import { runProcess } from '../../src/runners/processRunner.js';
import { runShellScript } from '../../src/runners/shellRunner.js';
import { scannerAvailable } from '../../src/tools/scanHelpers.js';

import type { PluginContext } from '../../src/context.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';
import {
  makeFinding,
} from '../../src/runners/scannerParsers/index.js';
import { makeTempDir, cleanupTempDirs } from '../helpers/tempDir.js';

afterAll(cleanupTempDirs);

beforeAll(async () => {
  await import('../../src/tools/securityScanFull.js');
  await import('../../src/tools/scanSast.js');
  await import('../../src/tools/scanSecrets.js');
  await import('../../src/tools/scanDeps.js');
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
});

const here = dirname(fileURLToPath(import.meta.url));
const FIX = resolve(here, '..', 'fixtures', 'scanners');

function tempProject(): string {
  return makeTempDir('meta-tools-');
}

function getTool(name: string) {
  const t = TOOLS.find((x) => x.name === name);
  if (!t) throw new Error(`Tool '${name}' not registered`);
  return t;
}

function makePlugin(projectPath: string): PluginContext {
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
    scriptsDir: projectPath,
    progressNotifier: { send: () => {} },
  };
}

const semgrepFx = () => readFileSync(join(FIX, 'semgrep.json'), 'utf8');
const trivyFsFx = () => readFileSync(join(FIX, 'trivy-fs.json'), 'utf8');
const gitleaksFx = () => readFileSync(join(FIX, 'gitleaks.json'), 'utf8');
const banditFx = () => readFileSync(join(FIX, 'bandit.json'), 'utf8');

beforeEach(() => {
  vi.mocked(runProcess).mockReset();
  vi.mocked(runShellScript).mockReset();
  vi.mocked(scannerAvailable).mockReset();
});

afterEach(() => {
  vi.mocked(runProcess).mockReset();
  vi.mocked(runShellScript).mockReset();
  vi.mocked(scannerAvailable).mockReset();
});

// ---------------------------------------------------------------------- set_baseline

describe('set_baseline', () => {
  it('defaults to the latest completed scan when scan_id is omitted', async () => {
    const plugin = makePlugin(tempProject());
    plugin.storage.scans.insert({
      scan_id: 'scan-A',
      scan_type: 'sast',
      project_path: '/p',
      tree_hash: 'h',
    });
    plugin.storage.scans.finalize({
      scan_id: 'scan-A',
      status: 'completed',
      tools_run: [],
      missing_tools: [],
    });

    const r = (await getTool('set_baseline').handler({}, plugin)) as {
      ok: true;
      scan_id: string;
    };
    expect(r.ok).toBe(true);
    expect(r.scan_id).toBe('scan-A');
    expect(plugin.storage.baselines.getActive()?.scan_id).toBe('scan-A');
  });

  it('errors when no completed scan exists yet', async () => {
    const plugin = makePlugin(tempProject());
    const r = (await getTool('set_baseline').handler({}, plugin)) as
      | { ok: true }
      | { ok: false; error: { code: string } };
    expect(r.ok).toBe(false);
  });
});

// ---------------------------------------------------------------------- suppress_finding

describe('suppress_finding', () => {
  it('inserts a suppression and hides the finding from listOpen', async () => {
    const plugin = makePlugin(tempProject());
    plugin.storage.scans.insert({
      scan_id: 's1',
      scan_type: 'sast',
      project_path: '/p',
      tree_hash: 'h',
    });
    const finding = makeFinding({
      tool: 'mock',
      severity: 'high',
      category: 'security',
      title: 't',
      file_path: 'a.ts',
    });
    plugin.storage.findings.bulkInsert([{ ...finding, scan_id: 's1' }]);
    plugin.storage.scans.finalize({
      scan_id: 's1',
      status: 'completed',
      tools_run: [],
      missing_tools: [],
    });

    const r = (await getTool('suppress_finding').handler(
      { finding_fingerprint: finding.fingerprint, reason: 'fp' },
      plugin,
    )) as { ok: true; suppression_id: number };
    expect(r.ok).toBe(true);
    expect(r.suppression_id).toBeGreaterThan(0);
    expect(plugin.storage.findings.listOpen()).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------- diff_scans

describe('diff_scans', () => {
  it('classifies findings as new / resolved / unchanged', async () => {
    const plugin = makePlugin(tempProject());

    // Seed two scans of the same type with overlapping fingerprints.
    plugin.storage.scans.insert({
      scan_id: 'older',
      scan_type: 'sast',
      project_path: '/p',
      tree_hash: 'h1',
    });
    const fOld = makeFinding({
      tool: 't',
      severity: 'high',
      category: 'security',
      title: 'will resolve',
      file_path: 'a.ts',
      line_start: 1,
    });
    const fShared = makeFinding({
      tool: 't',
      severity: 'high',
      category: 'security',
      title: 'unchanged',
      file_path: 'b.ts',
      line_start: 1,
    });
    plugin.storage.findings.bulkInsert([
      { ...fOld, scan_id: 'older' },
      { ...fShared, scan_id: 'older' },
    ]);
    plugin.storage.scans.finalize({
      scan_id: 'older',
      status: 'completed',
      tools_run: [],
      missing_tools: [],
    });

    plugin.storage.scans.insert({
      scan_id: 'newer',
      scan_type: 'sast',
      project_path: '/p',
      tree_hash: 'h2',
    });
    const fNew = makeFinding({
      tool: 't',
      severity: 'medium',
      category: 'security',
      title: 'brand new',
      file_path: 'c.ts',
      line_start: 1,
    });
    plugin.storage.findings.bulkInsert([
      { ...fShared, scan_id: 'newer' },
      { ...fNew, scan_id: 'newer' },
    ]);
    plugin.storage.scans.finalize({
      scan_id: 'newer',
      status: 'completed',
      tools_run: [],
      missing_tools: [],
    });

    const r = (await getTool('diff_scans').handler(
      { from_scan_id: 'older', to_scan_id: 'newer' },
      plugin,
    )) as {
      ok: true;
      summary: { new: number; resolved: number; unchanged: number };
      new_findings: Array<{ fingerprint: string }>;
      resolved_findings: Array<{ fingerprint: string }>;
    };
    expect(r.ok).toBe(true);
    expect(r.summary).toEqual({ new: 1, resolved: 1, unchanged: 1 });
    expect(r.new_findings[0]?.fingerprint).toBe(fNew.fingerprint);
    expect(r.resolved_findings[0]?.fingerprint).toBe(fOld.fingerprint);
  });

  it('uses the active baseline when from=baseline', async () => {
    const plugin = makePlugin(tempProject());
    plugin.storage.scans.insert({
      scan_id: 'base',
      scan_type: 'sast',
      project_path: '/p',
      tree_hash: 'h',
    });
    plugin.storage.scans.finalize({
      scan_id: 'base',
      status: 'completed',
      tools_run: [],
      missing_tools: [],
    });
    plugin.storage.scans.insert({
      scan_id: 'latest',
      scan_type: 'sast',
      project_path: '/p',
      tree_hash: 'h2',
    });
    plugin.storage.scans.finalize({
      scan_id: 'latest',
      status: 'completed',
      tools_run: [],
      missing_tools: [],
    });
    plugin.storage.baselines.set({ scan_id: 'base' });

    const r = (await getTool('diff_scans').handler(
      { from: 'baseline', to_scan_id: 'latest' },
      plugin,
    )) as { ok: true; from_scan_id: string };
    expect(r.ok).toBe(true);
    expect(r.from_scan_id).toBe('base');
  });

  it('errors when from=previous has no matching prior scan_type', async () => {
    const plugin = makePlugin(tempProject());
    plugin.storage.scans.insert({
      scan_id: 'only-one',
      scan_type: 'sast',
      project_path: '/p',
      tree_hash: 'h',
    });
    plugin.storage.scans.finalize({
      scan_id: 'only-one',
      status: 'completed',
      tools_run: [],
      missing_tools: [],
    });

    const r = (await getTool('diff_scans').handler(
      { from: 'previous', to_scan_id: 'only-one' },
      plugin,
    )) as { ok: true } | { ok: false; error: { code: string } };
    expect(r.ok).toBe(false);
  });
});

// ---------------------------------------------------------------------- audit_executive

describe('audit_executive', () => {
  it('sequences the 4 sub-tools and aggregates counts', async () => {
    const project = tempProject();
    const plugin = makePlugin(project);

    // Mock scannerAvailable so deps_audit / compliance_check see Trivy.
    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/trivy');

    // security_scan_full uses runShellScript with full-security-scan.sh and
    // drops a reports directory containing 5 JSON files. We also handle
    // quality_check (the same mock fires) by detecting its scriptPath via
    // the args.
    vi.mocked(runShellScript).mockImplementation(async (opts) => {
      if (opts.scriptPath.endsWith('full-security-scan.sh')) {
        const reportDir = join(
          project,
          '.guardian',
          'reports',
          `security-${Date.now()}`,
        );
        mkdirSync(reportDir, { recursive: true });
        writeFileSync(join(reportDir, 'sast.json'), semgrepFx(), 'utf8');
        writeFileSync(join(reportDir, 'secrets.json'), gitleaksFx(), 'utf8');
        writeFileSync(join(reportDir, 'deps.json'), trivyFsFx(), 'utf8');
        writeFileSync(join(reportDir, 'bandit.json'), banditFx(), 'utf8');
      } else if (opts.scriptPath.endsWith('quality-scan.sh')) {
        const reportDir = join(
          project,
          '.guardian',
          'reports',
          `quality-${Date.now()}`,
        );
        mkdirSync(reportDir, { recursive: true });
        // No reports → quality_check surfaces tools as missing.
      }
      return {
        outcome: 'completed' as const,
        exitCode: 0,
        stdout: '',
        stderr: '',
        truncated: false,
      };
    });

    // deps_audit + compliance_check both spawn `trivy fs ...` via runProcess.
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      const outIdx = opts.args?.findIndex((a) => a === '--output');
      const path = outIdx !== undefined && outIdx >= 0 ? opts.args?.[outIdx + 1] : undefined;
      if (path) writeFileSync(path, trivyFsFx(), 'utf8');
      return {
        outcome: 'completed' as const,
        exitCode: 0,
        stdout: '',
        stderr: '',
        truncated: false,
      };
    });

    const r = (await getTool('audit_executive').handler(
      { project_path: project },
      plugin,
    )) as {
      ok: true;
      scan_id: string;
      sub_scans: Record<string, { ok: boolean; scan_id?: string }>;
      aggregate_counts: Record<string, number>;
      top_findings: Array<{ fingerprint: string }>;
    };

    expect(r.ok).toBe(true);
    // All 4 sub-tools should have run.
    expect(Object.keys(r.sub_scans).sort()).toEqual([
      'compliance_check',
      'deps_audit',
      'quality_check',
      'security_scan_full',
    ]);
    expect(r.sub_scans['security_scan_full']?.ok).toBe(true);
    // Aggregate counts should be non-trivial (security + deps fixtures
    // both produce findings).
    const total = Object.values(r.aggregate_counts).reduce((a, b) => a + b, 0);
    expect(total).toBeGreaterThan(0);

    // The audit scan row exists and is completed.
    expect(plugin.storage.scans.getById(r.scan_id)?.status).toBe('completed');
  });

  it('emits deltas on the second consecutive audit', async () => {
    const project = tempProject();
    const plugin = makePlugin(project);
    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/trivy');

    let semgrepFindings = semgrepFx();

    vi.mocked(runShellScript).mockImplementation(async (opts) => {
      if (opts.scriptPath.endsWith('full-security-scan.sh')) {
        const reportDir = join(
          project,
          '.guardian',
          'reports',
          `security-${Date.now()}-${Math.random()}`,
        );
        mkdirSync(reportDir, { recursive: true });
        writeFileSync(join(reportDir, 'sast.json'), semgrepFindings, 'utf8');
      }
      return {
        outcome: 'completed' as const,
        exitCode: 0,
        stdout: '',
        stderr: '',
        truncated: false,
      };
    });
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      const outIdx = opts.args?.findIndex((a) => a === '--output');
      const path = outIdx !== undefined && outIdx >= 0 ? opts.args?.[outIdx + 1] : undefined;
      if (path) writeFileSync(path, '{}', 'utf8');
      return {
        outcome: 'completed' as const,
        exitCode: 0,
        stdout: '',
        stderr: '',
        truncated: false,
      };
    });

    const r1 = (await getTool('audit_executive').handler(
      { project_path: project },
      plugin,
    )) as { ok: true; scan_id: string };
    expect(r1.ok).toBe(true);

    // Change scanner output so the second audit sees different findings.
    semgrepFindings = JSON.stringify({ results: [] });

    // Mutate the working tree so the sub-tool cache misses on the second
    // audit (cache key is tree_hash + scan_type).
    writeFileSync(join(project, '__delta_trigger__.txt'), 'modified', 'utf8');

    const r2 = (await getTool('audit_executive').handler(
      { project_path: project },
      plugin,
    )) as {
      ok: true;
      scan_id: string;
      deltas?: { since_audit_scan_id: string; new_findings: number; resolved_findings: number };
    };
    expect(r2.ok).toBe(true);
    expect(r2.deltas).toBeDefined();
    expect(r2.deltas?.since_audit_scan_id).toBe(r1.scan_id);
    expect(r2.deltas?.resolved_findings).toBeGreaterThan(0);
  });
});
