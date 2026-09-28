/**
 * Integration tests for compliance_check and generate_sbom.
 *
 * compliance_check goes through the scan-tool factory → mock runProcess +
 * scannerAvailable. generate_sbom is standalone and also uses runProcess +
 * scannerAvailable. The Syft summariser is exercised against fixture data.
 */

import { GuardianDatabase as Database } from '../../src/storage/db.js';
import {
  existsSync,
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
vi.mock('../../src/tools/scanHelpers.js', async () => {
  const actual =
    await vi.importActual<typeof import('../../src/tools/scanHelpers.js')>(
      '../../src/tools/scanHelpers.js',
    );
  return { ...actual, scannerAvailable: vi.fn() };
});

import { runProcess } from '../../src/runners/processRunner.js';
import { scannerAvailable } from '../../src/tools/scanHelpers.js';
import { evaluateGate } from '../../src/ci/gate.js';
import { buildSnapshot } from '../../src/dashboard/snapshot.js';
import { renderStatus } from '../../src/dashboard/renderStatus.js';

import type { PluginContext } from '../../src/context.js';
import type { ToolRun } from '../../src/types.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';
import { computeTreeHash } from '../../src/treeHash/computeTreeHash.js';
import { makeTempDir, cleanupTempDirs } from '../helpers/tempDir.js';
import { okResult } from '../helpers/toolResult.js';

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
});

const here = dirname(fileURLToPath(import.meta.url));
const FIX = resolve(here, '..', 'fixtures', 'scanners');

function tempProject(): string {
  return makeTempDir('compliance-tools-');
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

beforeEach(() => {
  vi.mocked(runProcess).mockReset();
  vi.mocked(scannerAvailable).mockReset();
});

afterEach(() => {
  vi.mocked(runProcess).mockReset();
  vi.mocked(scannerAvailable).mockReset();
});

describe('compliance_check', () => {
  it('summarises licenses by risk and surfaces risky_licenses', async () => {
    const project = tempProject();
    const plugin = makePlugin(project);

    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/trivy');
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      const outIdx = opts.args?.findIndex((a) => a === '--output');
      const path = outIdx !== undefined && outIdx >= 0 ? opts.args?.[outIdx + 1] : undefined;
      if (path) {
        const fxRaw = readFileSync(join(FIX, 'trivy-fs.json'), 'utf8');
        writeFileSync(path, fxRaw, 'utf8');
      }
      return {
        outcome: 'completed' as const,
        exitCode: 0,
        stdout: '',
        stderr: '',
        truncated: false,
      };
    });

    const tool = getTool('compliance_check');
    const r = (await tool.handler({ project_path: project }, plugin)) as {
      ok: true;
      licenses_summary: { license: string; risk: string }[];
      risky_licenses: { license: string }[];
    };
    expect(r.ok).toBe(true);
    // Trivy fixture has AGPL-3.0-or-later → should be flagged as high risk.
    expect(r.risky_licenses.some((e) => /AGPL/i.test(e.license))).toBe(true);
  });

  it('detects PRIVACY.md, TERMS.md, and SECURITY.md at the project root', async () => {
    const project = tempProject();
    writeFileSync(join(project, 'PRIVACY.md'), '# Privacy', 'utf8');
    writeFileSync(join(project, 'TERMS.md'), '# Terms', 'utf8');
    writeFileSync(join(project, 'SECURITY.md'), '# Security', 'utf8');
    const plugin = makePlugin(project);

    vi.mocked(scannerAvailable).mockResolvedValue(null);

    const tool = getTool('compliance_check');
    const r = (await tool.handler({ project_path: project }, plugin)) as {
      ok: true;
      policy_documents_found: {
        privacy_policy: boolean;
        terms_of_service: boolean;
        security_policy: boolean;
        cookie_policy: boolean;
        paths: string[];
      };
    };
    expect(r.ok).toBe(true);
    expect(r.policy_documents_found.privacy_policy).toBe(true);
    expect(r.policy_documents_found.terms_of_service).toBe(true);
    expect(r.policy_documents_found.security_policy).toBe(true);
    expect(r.policy_documents_found.cookie_policy).toBe(false);
    expect(r.policy_documents_found.paths.sort()).toEqual(['PRIVACY.md', 'SECURITY.md', 'TERMS.md']);
  });
});

/**
 * compliance_check runs the RGPD Semgrep pack (configs/semgrep/rgpd.yml) —
 * and, per Global Constraint 3, a Semgrep that is absent, failed, or scanned
 * nothing is never reported as a clean RGPD result. The pack's own matching
 * is tested against real Semgrep in rgpdRules.test.ts and
 * complianceCheckRgpd.test.ts; here Semgrep's REPORT is scripted, to pin what
 * the tool makes of each shape of it.
 */
describe('compliance_check: the RGPD Semgrep pack', () => {
  interface SemgrepReport {
    results?: unknown[];
    errors?: unknown[];
    paths?: { scanned?: string[] };
    time?: { rules?: unknown[] };
  }

  interface ComplianceResult {
    ok: true;
    project_path: string;
    tools_run: ToolRun[];
    missing_tools: string[];
    coverage: string;
    top_findings: { rule_id?: string; category: string; subcategory?: string; severity: string; file_path?: string }[];
  }

  /** Scripts both scanners: Trivy writes its fixture, Semgrep writes `report`. */
  function scriptScanners(report: SemgrepReport | null, semgrepExit = 0): string[][] {
    const semgrepCalls: string[][] = [];
    vi.mocked(scannerAvailable).mockImplementation(async (name) => `/fake/bin/${name}`);
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      const args = opts.args ?? [];
      const outIdx = args.findIndex((a) => a === '--output');
      const out = outIdx >= 0 ? args[outIdx + 1] : undefined;
      if (opts.command === 'semgrep') {
        semgrepCalls.push([...args]);
        if (out !== undefined && report !== null) writeFileSync(out, JSON.stringify(report), 'utf8');
        return { outcome: semgrepExit === 0 || semgrepExit === 1 ? ('completed' as const) : ('failed' as const), exitCode: semgrepExit, stdout: '', stderr: '', truncated: false };
      }
      if (out !== undefined) writeFileSync(out, readFileSync(join(FIX, 'trivy-fs.json'), 'utf8'), 'utf8');
      return { outcome: 'completed' as const, exitCode: 0, stdout: '', stderr: '', truncated: false };
    });
    return semgrepCalls;
  }

  const HIT = {
    check_id: 'configs.semgrep.rgpd-pii-in-log-js',
    path: 'src/login.js',
    start: { line: 3, col: 15 },
    end: { line: 3, col: 20 },
    extra: { severity: 'WARNING', message: 'Dado pessoal num log (NIF, NISS, ...).', lines: 'requires login' },
  };
  const TRACKER = {
    check_id: 'configs.semgrep.rgpd-tracker-ga4-without-consent',
    path: 'index.html',
    start: { line: 5, col: 3 },
    end: { line: 5, col: 70 },
    extra: { severity: 'WARNING', message: 'Google Analytics (gtag.js) carregado antes do consentimento.', lines: 'requires login' },
  };

  it('runs the shipped pack, offline, over the project, and reports its findings as compliance findings', async () => {
    const project = tempProject();
    const calls = scriptScanners({ results: [HIT, TRACKER], errors: [], paths: { scanned: ['src/login.js', 'index.html'] } });
    const r = (await getTool('compliance_check').handler({ project_path: project }, makePlugin(project))) as unknown as ComplianceResult;
    expect(r.ok).toBe(true);

    expect(calls).toHaveLength(1);
    const args = calls[0] ?? [];
    const config = args.find((a) => a.startsWith('--config='))?.slice('--config='.length) ?? '';
    // The REAL pack, resolved independently of ctx.plugin.scriptsDir (which
    // this test points at a throwaway directory).
    expect(config.replace(/\\/g, '/')).toMatch(/\/configs\/semgrep\/rgpd\.yml$/);
    expect(existsSync(config)).toBe(true);
    expect(args).toContain('--metrics=off');
    // `--time` makes the report list the rules that LOADED, which is what
    // tells "nothing here to scan" from "the pack loaded nothing".
    expect(args).toContain('--time');
    expect(args.at(-1)).toBe(project);

    const rgpd = r.top_findings.filter((f) => f.rule_id?.startsWith('configs.semgrep.rgpd-'));
    expect(rgpd.map((f) => [f.category, f.subcategory, f.severity]).sort()).toEqual([
      ['compliance', 'rgpd-pii-in-logs', 'medium'],
      ['compliance', 'rgpd-tracker-without-consent', 'medium'],
    ]);
    expect(r.tools_run).toContainEqual({ name: 'semgrep-rgpd', status: 'ok' });
    expect(r.coverage).toBe('full');
  });

  it('says the RGPD rules did not run when Semgrep is not installed — never a clean result', async () => {
    const project = tempProject();
    vi.mocked(scannerAvailable).mockImplementation(async (name) => (name === 'trivy' ? '/fake/bin/trivy' : null));
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      const args = opts.args ?? [];
      const out = args[args.findIndex((a) => a === '--output') + 1];
      if (out !== undefined) writeFileSync(out, readFileSync(join(FIX, 'trivy-fs.json'), 'utf8'), 'utf8');
      return { outcome: 'completed' as const, exitCode: 0, stdout: '', stderr: '', truncated: false };
    });
    const r = (await getTool('compliance_check').handler({ project_path: project }, makePlugin(project))) as unknown as ComplianceResult;
    expect(r.tools_run).toContainEqual({ name: 'semgrep-rgpd', status: 'skipped', reason: 'not_installed' });
    expect(r.missing_tools).toContain('semgrep');
    expect(r.coverage).toBe('partial');
    expect(vi.mocked(runProcess).mock.calls.some(([o]) => o.command === 'semgrep')).toBe(false);
  });

  /**
   * Fix round 1, item 5. A Go-only project has no file the pack reads:
   * Semgrep loads the rules (`time.rules` lists them) and scans nothing. That
   * is NOT APPLICABLE, not a missing scanner: listing `semgrep` in
   * missing_tools made the status dashboard print "MISSING semgrep —
   * static-analysis findings are NOT in these numbers" beside a scan_sast
   * that ran fine, and the CI gate print "semgrep not installed".
   */
  it('reports a project with no file the pack reads as not applicable — not missing, on every surface', async () => {
    const project = tempProject();
    const plugin = makePlugin(project);
    scriptScanners({ results: [], errors: [], paths: { scanned: [] }, time: { rules: ['rgpd-tracker-ga4-without-consent'] } });
    const r = (await getTool('compliance_check').handler({ project_path: project }, plugin)) as unknown as ComplianceResult;
    const run = r.tools_run.find((t) => t.name === 'semgrep-rgpd');
    expect(run?.status).toBe('skipped');
    expect(run?.reason).toMatch(/^not applicable/);
    expect(r.missing_tools).toEqual([]);
    expect(r.coverage).toBe('full');

    // The status dashboard reads the stored scan.
    const snapshot = buildSnapshot(plugin.storage, r.project_path, Date.now());
    expect(snapshot.coverage.missing_tools).toEqual([]);
    const status = renderStatus(snapshot, { color: false });
    // The only gap left is the unrelated CVE-source one (no dependency scan
    // in this history) — nothing about Semgrep or static analysis.
    expect(status).not.toMatch(/semgrep/i);
    expect(status).not.toMatch(/static-analysis/);

    // The CI gate reads the step's bookkeeping.
    const gate = evaluateGate({
      findings: [],
      baseline: null,
      failOn: 'high',
      steps: [{ tool: 'compliance_check', ran: true, tools_run: r.tools_run, missing_tools: r.missing_tools }],
      droppedBaselineEntries: 0,
    });
    expect(gate.coverage).toBe('full');
    expect(gate.coverageGaps).toEqual([]);
  });

  it('fails a run that scanned nothing when the pack did not load a single rule — the silent-failure shape', async () => {
    const project = tempProject();
    scriptScanners({ results: [], errors: [], paths: { scanned: [] }, time: { rules: [] } });
    const r = (await getTool('compliance_check').handler({ project_path: project }, makePlugin(project))) as unknown as ComplianceResult;
    const run = r.tools_run.find((t) => t.name === 'semgrep-rgpd');
    expect(run?.status).toBe('failed');
    expect(run?.reason).toMatch(/loaded no rule/);
    expect(r.missing_tools).not.toContain('semgrep');
    expect(r.coverage).toBe('partial');
  });

  it('keeps `semgrep` in missing_tools only when it is not installed, so the gate says exactly that', async () => {
    const project = tempProject();
    vi.mocked(scannerAvailable).mockImplementation(async (name) => (name === 'trivy' ? '/fake/bin/trivy' : null));
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      const args = opts.args ?? [];
      const out = args[args.findIndex((a) => a === '--output') + 1];
      if (out !== undefined) writeFileSync(out, readFileSync(join(FIX, 'trivy-fs.json'), 'utf8'), 'utf8');
      return { outcome: 'completed' as const, exitCode: 0, stdout: '', stderr: '', truncated: false };
    });
    const r = (await getTool('compliance_check').handler({ project_path: project }, makePlugin(project))) as unknown as ComplianceResult;
    const gate = evaluateGate({
      findings: [],
      baseline: null,
      failOn: 'high',
      steps: [{ tool: 'compliance_check', ran: true, tools_run: r.tools_run, missing_tools: r.missing_tools }],
      droppedBaselineEntries: 0,
    });
    expect(gate.coverageGaps).toEqual(['compliance_check: semgrep not installed']);
  });

  it('reports Semgrep errors as a failed run, and still keeps the findings it did produce', async () => {
    const project = tempProject();
    scriptScanners({
      results: [HIT],
      errors: [{ type: 'Timeout', message: 'Timeout when running rgpd-pii-in-log-js on src/big.js', path: 'src/big.js' }],
      paths: { scanned: ['src/login.js', 'src/big.js'] },
    });
    const r = (await getTool('compliance_check').handler({ project_path: project }, makePlugin(project))) as unknown as ComplianceResult;
    const run = r.tools_run.find((t) => t.name === 'semgrep-rgpd');
    expect(run?.status).toBe('failed');
    expect(run?.reason).toMatch(/Timeout/);
    expect(r.coverage).toBe('partial');
    expect(r.top_findings.some((f) => f.rule_id === HIT.check_id)).toBe(true);
  });

  it('fails the run when Semgrep wrote no report at all', async () => {
    const project = tempProject();
    scriptScanners(null, 2);
    const r = (await getTool('compliance_check').handler({ project_path: project }, makePlugin(project))) as unknown as ComplianceResult;
    const run = r.tools_run.find((t) => t.name === 'semgrep-rgpd');
    expect(run?.status).toBe('failed');
    expect(run?.reason).toMatch(/no JSON report/);
  });

  it('keeps the tool description within the 1500-character budget', () => {
    const description = getTool('compliance_check').description;
    expect(description.length).toBeLessThanOrEqual(1500);
    expect(description).toMatch(/rgpd\.yml/);
    // Fix round 1: the accepted guards are a legal judgement, and a project
    // the pack has nothing to read in is not applicable rather than missing.
    expect(description).toMatch(/legal judgement/);
    expect(description).toMatch(/not applicable/);
  });
});

describe('generate_sbom', () => {
  it('inlines the SBOM when below inline_max_kb (default 256)', async () => {
    const project = tempProject();
    const plugin = makePlugin(project);

    vi.mocked(scannerAvailable).mockImplementation(async (name) =>
      name === 'syft' ? '/fake/bin/syft' : null,
    );
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      // Syft is invoked with `-o cyclonedx-json=<outFile>`.
      const oFlag = opts.args?.find((a) => a.startsWith('cyclonedx-json='));
      if (oFlag) {
        const outFile = oFlag.replace('cyclonedx-json=', '');
        const fxRaw = readFileSync(join(FIX, 'syft-cyclonedx.json'), 'utf8');
        writeFileSync(outFile, fxRaw, 'utf8');
      }
      return {
        outcome: 'completed' as const,
        exitCode: 0,
        stdout: '',
        stderr: '',
        truncated: false,
      };
    });

    const tool = getTool('generate_sbom');
    const r = (await tool.handler({ project_path: project }, plugin)) as {
      ok: true;
      format: string;
      produced_by: string;
      components_count: number;
      inline?: unknown;
      file_path: string;
    };
    expect(r.ok).toBe(true);
    expect(r.format).toBe('cyclonedx-json');
    expect(r.produced_by).toBe('syft');
    expect(r.components_count).toBe(3);
    expect(r.inline).toBeDefined();
  });

  it('records the tree it described, so export_vex can tell an SBOM of another tree', async () => {
    const project = tempProject();
    const plugin = makePlugin(project);
    vi.mocked(scannerAvailable).mockImplementation(async (name) => (name === 'syft' ? '/fake/bin/syft' : null));
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      const oFlag = opts.args?.find((a) => a.startsWith('cyclonedx-json='));
      if (oFlag) writeFileSync(oFlag.replace('cyclonedx-json=', ''), readFileSync(join(FIX, 'syft-cyclonedx.json'), 'utf8'), 'utf8');
      return { outcome: 'completed' as const, exitCode: 0, stdout: '', stderr: '', truncated: false };
    });

    const r = okResult<{ scan_id: string }>(await getTool('generate_sbom').handler({ project_path: project }, plugin));
    const row = plugin.storage.scans.getById(r.scan_id);
    expect(row?.tree_hash).toBe(await computeTreeHash(project));
    expect(row?.tree_hash).not.toBe('');
  });

  it('omits inline when inline_max_kb is below the SBOM size', async () => {
    const project = tempProject();
    const plugin = makePlugin(project);

    vi.mocked(scannerAvailable).mockImplementation(async (name) =>
      name === 'syft' ? '/fake/bin/syft' : null,
    );
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      const oFlag = opts.args?.find((a) => a.startsWith('cyclonedx-json='));
      if (oFlag) {
        const outFile = oFlag.replace('cyclonedx-json=', '');
        writeFileSync(outFile, readFileSync(join(FIX, 'syft-cyclonedx.json'), 'utf8'), 'utf8');
      }
      return {
        outcome: 'completed' as const,
        exitCode: 0,
        stdout: '',
        stderr: '',
        truncated: false,
      };
    });

    const tool = getTool('generate_sbom');
    const r = (await tool.handler({ project_path: project, inline_max_kb: 0 }, plugin)) as {
      ok: true;
      inline?: unknown;
    };
    expect(r.ok).toBe(true);
    expect(r.inline).toBeUndefined();
  });

  it('falls back to Trivy when Syft is missing', async () => {
    const project = tempProject();
    const plugin = makePlugin(project);

    vi.mocked(scannerAvailable).mockImplementation(async (name) =>
      name === 'trivy' ? '/fake/bin/trivy' : null,
    );
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      // Trivy is invoked with `--output <outFile>`.
      const oIdx = opts.args?.findIndex((a) => a === '--output');
      const outFile = oIdx !== undefined && oIdx >= 0 ? opts.args?.[oIdx + 1] : undefined;
      if (outFile) {
        writeFileSync(outFile, readFileSync(join(FIX, 'syft-cyclonedx.json'), 'utf8'), 'utf8');
      }
      return {
        outcome: 'completed' as const,
        exitCode: 0,
        stdout: '',
        stderr: '',
        truncated: false,
      };
    });

    const tool = getTool('generate_sbom');
    const r = (await tool.handler({ project_path: project }, plugin)) as {
      ok: true;
      produced_by: string;
    };
    expect(r.ok).toBe(true);
    expect(r.produced_by).toBe('trivy');
  });

  it('returns missing_scanner when neither Syft nor Trivy is available', async () => {
    const project = tempProject();
    const plugin = makePlugin(project);
    vi.mocked(scannerAvailable).mockResolvedValue(null);

    const tool = getTool('generate_sbom');
    const r = (await tool.handler({ project_path: project }, plugin)) as
      | { ok: true }
      | { ok: false; error: { code: string } };
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe('missing_scanner');
  });
});

// Suppress unused-import warning if some helpers aren't used.
void mkdirSync;
