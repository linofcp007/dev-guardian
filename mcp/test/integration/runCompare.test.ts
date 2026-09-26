/**
 * Comparing two orchestrated `security_scan_full` runs when a child of the
 * newer run measured nothing (Task 8 fix round 2).
 *
 * The comparing readers take a run as a whole: the parent row holds every
 * child's findings merged. When the newer run's scan_sast child failed
 * (Semgrep exit 7), its findings are simply absent from that parent — and a
 * parent-vs-parent diff read every one of them as "resolved": the dashboard's
 * since_previous, diff_scans' default, regression_alert (the false resolution
 * cancelled a real new high) and set_baseline all took it. A finding whose
 * type the newer run did not re-measure is neither resolved nor unchanged:
 * it is `not_remeasured`, and every reader says so.
 */

import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { buildSnapshot } from '../../src/dashboard/snapshot.js';
import { openSetForProject } from '../../src/history/openSet.js';
import { TOOLS } from '../../src/tools/index.js';
import { okResult } from '../helpers/toolResult.js';
import { cleanupTempDirs } from '../helpers/tempDir.js';
import type { ToolRun } from '../../src/types.js';
import { freshPlugin, projectDir, seedOrchestratedRun, seedScan, type SeedFinding, type Seeded } from '../helpers/historySeed.js';

afterAll(cleanupTempDirs);

beforeAll(async () => {
  await import('../../src/tools/diffScans.js');
  await import('../../src/tools/regressionAlert.js');
  await import('../../src/tools/setBaseline.js');
});

function tool(name: string) {
  const t = TOOLS.find((x) => x.name === name);
  if (!t) throw new Error(`tool ${name} not registered`);
  return t;
}

const S = 's'.repeat(64);
const D = 'd'.repeat(64);

/** run1 measured everything (one SAST finding); run2's Semgrep failed and Trivy found one new high. */
function failedSastChild(): { s: Seeded; p: string } {
  const s = freshPlugin();
  const p = projectDir('runcmp-');
  seedOrchestratedRun(s, 'run1', p, {
    sast: { findings: [{ fp: S, tool: 'semgrep', identity: 'I-S', severity: 'high' }] },
  });
  seedOrchestratedRun(s, 'run2', p, {
    sast: { failed: true },
    deps: { findings: [{ fp: D, tool: 'trivy', subcategory: 'cve', identity: 'I-D', severity: 'high' }] },
  });
  return { s, p };
}

describe('reading the open set after orchestrated runs', () => {
  it("guardian://findings/open's scan_id names a scan that is actually in sources", async () => {
    await import('../../src/resources/findings.js');
    const { RESOURCES } = await import('../../src/resources/index.js');
    const r = RESOURCES.find((x) => x.name === 'guardian-findings-open');
    if (!r) throw new Error('guardian-findings-open not registered');
    const { s, p } = failedSastChild();
    const cwd = vi.spyOn(process, 'cwd').mockReturnValue(p);
    try {
      const json = (await r.handler(new URL('guardian://findings/open'), {}, s.plugin)).json as {
        scan_id: string;
        sources: Array<{ scan_id: string }>;
      };
      expect(json.sources.map((x) => x.scan_id)).toContain(json.scan_id);
    } finally {
      cwd.mockRestore();
    }
  });

  it('does not page through every orchestrated parent looking for a script-era row', () => {
    const s = freshPlugin();
    const p = projectDir('runcmp-');
    for (let i = 0; i < 40; i++) {
      seedOrchestratedRun(s, `run${i}`, p, { sast: { findings: [{ fp: String(i % 10).repeat(64), tool: 'semgrep' }] } });
    }
    const spy = vi.spyOn(s.storage.scans, 'listCompletedOfTypes');
    openSetForProject(s.storage, p);
    const fullRowsRead = spy.mock.calls.reduce((n, call, i) => {
      const types = call[1];
      const result = spy.mock.results[i]?.value as unknown[] | undefined;
      return types.length === 1 && types[0] === 'security_full' ? n + (result?.length ?? 0) : n;
    }, 0);
    spy.mockRestore();
    expect(fullRowsRead).toBe(0);
  });
});

describe('a newer run whose scan_sast child failed', () => {
  it('dashboard since_previous: the SAST finding is not re-measured, never resolved', () => {
    const { s, p } = failedSastChild();
    const snap = buildSnapshot(s.storage, p, Date.parse('2026-06-01T00:00:00.000Z'));
    expect(snap.findings.items.map((f) => f.fingerprint).sort()).toEqual([D, S]);
    expect(snap.deltas.since_previous).toMatchObject({
      from_scan_id: 'run1',
      to_scan_id: 'run2',
      new_count: 1,
      resolved_count: 0,
      not_remeasured_count: 1,
    });
  });

  it('diff_scans (default): not_remeasured, not resolved', async () => {
    const { s, p } = failedSastChild();
    const r = okResult<{
      from_scan_id: string;
      to_scan_id: string;
      summary: { new: number; resolved: number; unchanged: number; not_remeasured: number };
      resolved_findings: Array<{ fingerprint: string }>;
      not_remeasured_findings: Array<{ fingerprint: string }>;
      not_measured: string[];
    }>(await tool('diff_scans').handler({ project_path: p }, s.plugin));
    expect([r.from_scan_id, r.to_scan_id]).toEqual(['run1', 'run2']);
    expect(r.summary).toEqual({ new: 1, resolved: 0, unchanged: 0, not_remeasured: 1, not_previously_measured: 0 });
    expect(r.resolved_findings).toEqual([]);
    expect(r.not_remeasured_findings.map((f) => f.fingerprint)).toEqual([S]);
    expect(r.not_measured).toEqual(['sast']);
  });

  it('regression_alert: the new high is not cancelled by a false resolution', async () => {
    const { s, p } = failedSastChild();
    const r = okResult<{
      regressed: boolean;
      score_delta: number;
      resolved_findings_by_severity: Record<string, number>;
      not_remeasured_by_severity: Record<string, number>;
    }>(await tool('regression_alert').handler({ project_path: p, threshold: 0 }, s.plugin));
    expect(r.score_delta).toBe(5);
    expect(r.regressed).toBe(true);
    expect(r.resolved_findings_by_severity['high']).toBe(0);
    expect(r.not_remeasured_by_severity['high']).toBe(1);
  });

  it('set_baseline (default): flags that the run did not measure sast', async () => {
    const { s, p } = failedSastChild();
    const r = okResult<{ scan_id: string; not_measured: string[]; warning: string }>(
      await tool('set_baseline').handler({ project_path: p }, s.plugin),
    );
    expect(r.scan_id).toBe('run2');
    expect(r.not_measured).toEqual(['sast']);
    expect(r.warning).toMatch(/sast/);
  });

  it('a run that measured everything compares as before: a real fix is resolved', async () => {
    const s = freshPlugin();
    const p = projectDir('runcmp-');
    seedOrchestratedRun(s, 'run1', p, { sast: { findings: [{ fp: S, tool: 'semgrep', identity: 'I-S' }] } });
    seedOrchestratedRun(s, 'run2', p, {});
    const r = okResult<{ summary: { resolved: number; not_remeasured: number } }>(
      await tool('diff_scans').handler({ project_path: p }, s.plugin),
    );
    expect(r.summary).toMatchObject({ resolved: 1, not_remeasured: 0 });
    const b = okResult<Record<string, unknown>>(await tool('set_baseline').handler({ project_path: p }, s.plugin));
    expect(b['not_measured']).toBeUndefined();
  });
});

/**
 * Fix round 3: a PARTIAL child. A Python project with Bandit installed:
 * Semgrep exit 7 leaves the sast child [semgrep failed, bandit ok] —
 * coverage partial, status completed. "Did the child measure?" is yes; "did
 * it measure Semgrep's findings?" is no. The check is per TOOL.
 */
const PARTIAL_SAST = {
  runs: [
    { name: 'semgrep', status: 'failed', reason: 'exit 7' },
    { name: 'bandit', status: 'ok' },
  ] satisfies ToolRun[],
  missing: [],
};

function partialSastChild(): { s: Seeded; p: string } {
  const s = freshPlugin();
  const p = projectDir('runcmp-partial-');
  seedOrchestratedRun(s, 'run1', p, {
    sast: {
      runs: [{ name: 'semgrep', status: 'ok' }, { name: 'bandit', status: 'ok' }],
      findings: [{ fp: S, tool: 'semgrep', identity: 'I-S', severity: 'high' }],
    },
  });
  seedOrchestratedRun(s, 'run2', p, {
    sast: PARTIAL_SAST,
    deps: { findings: [{ fp: D, tool: 'trivy', subcategory: 'cve', identity: 'I-D', severity: 'high' }] },
  });
  return { s, p };
}

describe("a newer run whose sast child is partial: Semgrep failed, Bandit ran", () => {
  it('dashboard since_previous: not re-measured, never resolved; coverage is not full', () => {
    const { s, p } = partialSastChild();
    const snap = buildSnapshot(s.storage, p, Date.parse('2026-06-01T00:00:00.000Z'));
    expect(snap.deltas.since_previous).toMatchObject({ new_count: 1, resolved_count: 0, not_remeasured_count: 1 });
    // A 'failed' scanner is a gap even when missing_tools does not name it.
    expect(snap.coverage.level).not.toBe('full');
    expect(snap.coverage.missing_tools).toContain('semgrep');
  });

  it('diff_scans (default): not_remeasured, not resolved', async () => {
    const { s, p } = partialSastChild();
    const r = okResult<{ summary: Record<string, number>; not_measured: string[] }>(
      await tool('diff_scans').handler({ project_path: p }, s.plugin),
    );
    expect(r.summary).toMatchObject({ new: 1, resolved: 0, not_remeasured: 1 });
    expect(r.not_measured).toEqual(['semgrep']);
  });

  it('regression_alert: the new high still regresses', async () => {
    const { s, p } = partialSastChild();
    const r = okResult<{ regressed: boolean; score_delta: number }>(
      await tool('regression_alert').handler({ project_path: p, threshold: 0 }, s.plugin),
    );
    expect(r.score_delta).toBe(5);
    expect(r.regressed).toBe(true);
  });

  it('set_baseline (default): flags Semgrep as not measured', async () => {
    const { s, p } = partialSastChild();
    const r = okResult<{ not_measured: string[]; warning: string }>(
      await tool('set_baseline').handler({ project_path: p }, s.plugin),
    );
    expect(r.not_measured).toEqual(['semgrep']);
    expect(r.warning).toMatch(/semgrep/);
  });

  it('a script-era row whose Semgrep was missing but gitleaks ran does not resolve the Semgrep findings', async () => {
    const s = freshPlugin();
    const p = projectDir('runcmp-script-');
    seedScan(s, {
      id: 'old', type: 'security_full', project: p,
      tools_run: [{ name: 'semgrep', status: 'ok' }, { name: 'gitleaks', status: 'ok' }],
      findings: [{ fp: S, tool: 'semgrep', severity: 'high' }],
    });
    seedScan(s, {
      id: 'new', type: 'security_full', project: p,
      tools_run: [{ name: 'semgrep', status: 'skipped', reason: 'not_installed' }, { name: 'gitleaks', status: 'ok' }],
      missing_tools: ['semgrep'],
      findings: [{ fp: D, tool: 'gitleaks', subcategory: 'secret', severity: 'high' }],
    });
    const diff = okResult<{ from_scan_id: string; to_scan_id: string; summary: Record<string, number> }>(
      await tool('diff_scans').handler({ project_path: p }, s.plugin),
    );
    expect([diff.from_scan_id, diff.to_scan_id]).toEqual(['old', 'new']);
    expect(diff.summary).toMatchObject({ new: 1, resolved: 0, not_remeasured: 1 });
    const alert = okResult<{ score_delta: number }>(
      await tool('regression_alert').handler({ project_path: p, threshold: 0 }, s.plugin),
    );
    expect(alert.score_delta).toBe(5);
  });
});

describe('a reference that did not measure a tool: its findings in the newer run are not "new"', () => {
  function partialBaseline(): { s: Seeded; p: string } {
    const s = freshPlugin();
    const p = projectDir('runcmp-mirror-');
    seedOrchestratedRun(s, 'run1', p, { sast: PARTIAL_SAST });
    s.storage.baselines.set({ scan_id: 'run1' });
    seedOrchestratedRun(s, 'run2', p, {
      sast: {
        runs: [{ name: 'semgrep', status: 'ok' }, { name: 'bandit', status: 'ok' }],
        findings: [{ fp: S, tool: 'semgrep', identity: 'I-S', severity: 'high' }],
      },
    });
    return { s, p };
  }

  it('regression_alert: no false alarm from a finding the baseline never looked for', async () => {
    const { s, p } = partialBaseline();
    const r = okResult<{
      reference: string;
      score_delta: number;
      regressed: boolean;
      not_previously_measured_by_severity: Record<string, number>;
    }>(await tool('regression_alert').handler({ project_path: p, threshold: 0 }, s.plugin));
    expect(r.reference).toBe('baseline');
    expect(r.score_delta).toBe(0);
    expect(r.regressed).toBe(false);
    expect(r.not_previously_measured_by_severity['high']).toBe(1);
  });

  it('diff_scans from=baseline and the dashboard deltas label it, instead of counting it new', async () => {
    const { s, p } = partialBaseline();
    const diff = okResult<{ summary: Record<string, number>; not_previously_measured_findings: Array<{ fingerprint: string }> }>(
      await tool('diff_scans').handler({ project_path: p, from: 'baseline' }, s.plugin),
    );
    expect(diff.summary).toMatchObject({ new: 0, not_previously_measured: 1 });
    expect(diff.not_previously_measured_findings.map((f) => f.fingerprint)).toEqual([S]);

    const snap = buildSnapshot(s.storage, p, Date.parse('2026-06-01T00:00:00.000Z'));
    expect(snap.deltas.since_baseline).toMatchObject({ new_count: 0, not_previously_measured_count: 1 });
    expect(snap.deltas.since_previous).toMatchObject({ new_count: 0, not_previously_measured_count: 1 });
  });
});

/**
 * Fix round 4: scanners whose bookkeeping name is not their findings' tool.
 * deps_audit records its native auditor by COMMAND (`npm`) while its
 * findings say `npm-audit`; scan_dast records its engine as `guardian-dast`
 * while its findings say `dast`. Round 3 fell back to the scan's overall
 * coverage for a tool the bookkeeping never named — `partial` counted as
 * measured — so a failed `npm` resolved every npm-audit finding, and a
 * baseline whose npm failed raised a false alarm on the first npm finding.
 */
const N = 'n'.repeat(64);
const A = 'a'.repeat(64);
const T = 't'.repeat(64);
const NOW = Date.parse('2026-06-01T00:00:00.000Z');

interface DiffOut {
  summary: Record<string, number>;
  not_remeasured_findings: Array<{ fingerprint: string }>;
  not_previously_measured_findings: Array<{ fingerprint: string }>;
  not_measured?: string[];
  reference_not_measured?: string[];
  note?: string;
}
interface AlertOut {
  reference: string;
  score_delta: number;
  regressed: boolean;
  resolved_findings_by_severity: Record<string, number>;
  not_remeasured_by_severity: Record<string, number>;
  not_previously_measured_by_severity: Record<string, number>;
}

describe('deps_audit: the npm auditor is recorded as `npm`, its findings say `npm-audit`', () => {
  function npmFailedAfterOk(): { s: Seeded; p: string } {
    const s = freshPlugin();
    const p = projectDir('runcmp-npm-');
    seedScan(s, {
      id: 'a', type: 'deps_audit', project: p,
      tools_run: [{ name: 'trivy', status: 'ok' }, { name: 'npm', status: 'ok', reason: 'parsed into findings' }],
      findings: [{ fp: N, tool: 'npm-audit', subcategory: 'cve', severity: 'high' }],
    });
    seedScan(s, {
      id: 'b', type: 'deps_audit', project: p,
      tools_run: [
        { name: 'trivy', status: 'ok' },
        { name: 'npm', status: 'failed', reason: 'ran but produced no audit report (missing lockfile?)' },
      ],
      missing_tools: ['npm'],
      findings: [{ fp: D, tool: 'trivy', subcategory: 'cve', severity: 'high' }],
    });
    return { s, p };
  }

  it('diff_scans: the npm-audit finding is not re-measured, never resolved', async () => {
    const { s, p } = npmFailedAfterOk();
    const r = okResult<DiffOut>(await tool('diff_scans').handler({ project_path: p, scan_type: 'deps_audit' }, s.plugin));
    expect(r.summary).toMatchObject({ new: 1, resolved: 0, not_remeasured: 1 });
    expect(r.not_remeasured_findings.map((f) => f.fingerprint)).toEqual([N]);
    expect(r.not_measured).toEqual(['npm']);
  });

  it('regression_alert: the new Trivy high is not cancelled by a false npm resolution', async () => {
    const { s, p } = npmFailedAfterOk();
    const r = okResult<AlertOut>(
      await tool('regression_alert').handler({ project_path: p, scan_type: 'deps_audit', threshold: 0 }, s.plugin),
    );
    expect(r.resolved_findings_by_severity['high']).toBe(0);
    expect(r.not_remeasured_by_severity['high']).toBe(1);
    expect(r.score_delta).toBe(5);
    expect(r.regressed).toBe(true);
  });

  it('dashboard since_previous: not re-measured, never resolved', () => {
    const { s, p } = npmFailedAfterOk();
    const snap = buildSnapshot(s.storage, p, NOW);
    expect(snap.deltas.since_previous).toMatchObject({ new_count: 1, resolved_count: 0, not_remeasured_count: 1 });
  });

  it('mirror: a baseline whose npm failed raises no alarm on the first npm-audit finding', async () => {
    const s = freshPlugin();
    const p = projectDir('runcmp-npm-mirror-');
    seedScan(s, {
      id: 'a', type: 'deps_audit', project: p,
      tools_run: [{ name: 'trivy', status: 'ok' }, { name: 'npm', status: 'failed', reason: 'failed to run' }],
      missing_tools: ['npm'],
    });
    const b = okResult<{ not_measured: string[]; warning: string }>(
      await tool('set_baseline').handler({ project_path: p, scan_type: 'deps_audit' }, s.plugin),
    );
    expect(b.not_measured).toEqual(['npm']);
    // The warning's promise — "not previously measured", never new — is what the readers below do.
    expect(b.warning).toMatch(/not previously measured/);
    seedScan(s, {
      id: 'b', type: 'deps_audit', project: p,
      tools_run: [{ name: 'trivy', status: 'ok' }, { name: 'npm', status: 'ok', reason: 'parsed into findings' }],
      findings: [{ fp: N, tool: 'npm-audit', subcategory: 'cve', severity: 'high' }],
    });

    const diff = okResult<DiffOut>(
      await tool('diff_scans').handler({ project_path: p, scan_type: 'deps_audit', from: 'baseline' }, s.plugin),
    );
    expect(diff.summary).toMatchObject({ new: 0, not_previously_measured: 1 });
    expect(diff.reference_not_measured).toEqual(['npm']);

    const alert = okResult<AlertOut>(
      await tool('regression_alert').handler({ project_path: p, scan_type: 'deps_audit', threshold: 0 }, s.plugin),
    );
    expect(alert.reference).toBe('baseline');
    expect(alert.score_delta).toBe(0);
    expect(alert.regressed).toBe(false);
    expect(alert.not_previously_measured_by_severity['high']).toBe(1);

    const snap = buildSnapshot(s.storage, p, NOW);
    expect(snap.deltas.since_baseline).toMatchObject({ new_count: 0, not_previously_measured_count: 1 });
  });
});

describe('a Trivy ecosystem gap (`trivy:<ecosystem>`) vetoes that ecosystem only', () => {
  // scan_deps / deps_audit write `trivy:dotnet` to missing_tools when Trivy
  // ran ok but produced no NuGet Result for a root .csproj/.sln — e.g. its
  // packages.lock.json was deleted. A NuGet CVE the older run found in that
  // lock file was then not looked for, so it is not resolved; an npm CVE
  // from package-lock.json WAS looked for, so its absence is a resolution.
  const NUGET = 'u'.repeat(64);
  const NPM = 'p'.repeat(64);
  const CONFIG = 'k'.repeat(64);

  function lockFileGone(type: 'deps' | 'deps_audit'): { s: Seeded; p: string } {
    const s = freshPlugin();
    const p = projectDir('runcmp-trivy-eco-');
    seedScan(s, {
      id: 'a', type, project: p,
      tools_run: [{ name: 'trivy', status: 'ok' }],
      findings: [
        { fp: NUGET, tool: 'trivy', subcategory: 'cve', file: 'src/Api/packages.lock.json', severity: 'high' },
        { fp: NPM, tool: 'trivy', subcategory: 'cve', file: 'package-lock.json', severity: 'high' },
      ],
    });
    seedScan(s, {
      id: 'b', type, project: p,
      tools_run: [{ name: 'trivy', status: 'ok', reason: 'no_supported_manifest' }],
      missing_tools: ['trivy:dotnet'],
    });
    return { s, p };
  }

  it.each(['deps', 'deps_audit'] as const)('%s: the NuGet CVE is not re-measured; the npm CVE is resolved', async (type) => {
    const { s, p } = lockFileGone(type);
    const r = okResult<DiffOut & { resolved_findings: Array<{ fingerprint: string }> }>(
      await tool('diff_scans').handler({ project_path: p, scan_type: type }, s.plugin),
    );
    expect(r.summary).toMatchObject({ resolved: 1, not_remeasured: 1 });
    expect(r.not_remeasured_findings.map((f) => f.fingerprint)).toEqual([NUGET]);
    expect(r.resolved_findings.map((f) => f.fingerprint)).toEqual([NPM]);
    expect(r.not_measured).toEqual(['trivy:dotnet']);
  });

  it("an audit whose security_scan_full sub-scan carries the gap: the IaC misconfiguration is not vetoed by it", async () => {
    // An audit is judged by its sub-scan's merged bookkeeping, where scan_deps'
    // `trivy:dotnet` sits beside scan_iac's `trivy-config`. Before the
    // ecosystem entries, `trivy:dotnet` fell back to the `trivy` entry's
    // not-ok keys — every Trivy key, misconfigurations included.
    const s = freshPlugin();
    const p = projectDir('runcmp-trivy-eco-audit-');
    const findings: SeedFinding[] = [
      { fp: NUGET, tool: 'trivy', subcategory: 'cve', file: 'packages.lock.json', severity: 'high' },
      { fp: CONFIG, tool: 'trivy', subcategory: 'misconfiguration', file: 'main.tf', severity: 'high' },
    ];
    seedScan(s, {
      id: 'full1', type: 'security_full', project: p,
      tools_run: [{ name: 'trivy', status: 'ok' }, { name: 'trivy-config', status: 'ok' }],
      findings,
    });
    seedScan(s, {
      id: 'audit1', type: 'audit', project: p,
      tools_run: [{ name: 'security_scan_full', status: 'ok' }],
      findings,
      meta: { sub_scan_ids: { security_scan_full: 'full1' } },
    });
    seedScan(s, {
      id: 'full2', type: 'security_full', project: p,
      tools_run: [{ name: 'trivy', status: 'ok', reason: 'no_supported_manifest' }, { name: 'trivy-config', status: 'ok' }],
      missing_tools: ['trivy:dotnet'],
    });
    seedScan(s, {
      id: 'audit2', type: 'audit', project: p,
      tools_run: [{ name: 'security_scan_full', status: 'ok' }],
      meta: { sub_scan_ids: { security_scan_full: 'full2' } },
    });
    const r = okResult<DiffOut & { resolved_findings: Array<{ fingerprint: string }> }>(
      await tool('diff_scans').handler({ from_scan_id: 'audit1', to_scan_id: 'audit2' }, s.plugin),
    );
    expect(r.not_remeasured_findings.map((f) => f.fingerprint)).toEqual([NUGET]);
    expect(r.resolved_findings.map((f) => f.fingerprint)).toEqual([CONFIG]);
    expect(r.not_measured).toEqual(['trivy:dotnet']);
  });

  it('control: without the gap, both CVEs are resolved', async () => {
    const s = freshPlugin();
    const p = projectDir('runcmp-trivy-eco-ctl-');
    seedScan(s, {
      id: 'a', type: 'deps', project: p,
      tools_run: [{ name: 'trivy', status: 'ok' }],
      findings: [
        { fp: NUGET, tool: 'trivy', subcategory: 'cve', file: 'packages.lock.json', severity: 'high' },
        { fp: NPM, tool: 'trivy', subcategory: 'cve', file: 'package-lock.json', severity: 'high' },
      ],
    });
    seedScan(s, { id: 'b', type: 'deps', project: p, tools_run: [{ name: 'trivy', status: 'ok' }] });
    const r = okResult<DiffOut>(await tool('diff_scans').handler({ project_path: p, scan_type: 'deps' }, s.plugin));
    expect(r.summary).toMatchObject({ resolved: 2, not_remeasured: 0 });
  });
});

describe('scan_dast: the engine is recorded as `guardian-dast`, its findings say `dast`', () => {
  function dast(second: ToolRun[], missing: string[] = []): { s: Seeded; p: string } {
    const s = freshPlugin();
    const p = projectDir('runcmp-dast-');
    seedScan(s, {
      id: 'a', type: 'dast', project: p,
      tools_run: [{ name: 'guardian-dast', status: 'ok' }, { name: 'nuclei', status: 'ok' }],
      findings: [{ fp: A, tool: 'dast', severity: 'high' }],
    });
    seedScan(s, { id: 'b', type: 'dast', project: p, tools_run: second, missing_tools: missing });
    return { s, p };
  }

  it('the engine failed, nuclei ran: the engine finding is not re-measured', async () => {
    const { s, p } = dast([{ name: 'guardian-dast', status: 'failed' }, { name: 'nuclei', status: 'ok' }]);
    const r = okResult<DiffOut>(await tool('diff_scans').handler({ project_path: p, scan_type: 'dast' }, s.plugin));
    expect(r.summary).toMatchObject({ resolved: 0, not_remeasured: 1 });
    expect(r.not_measured).toEqual(['guardian-dast']);
    const alert = okResult<AlertOut>(
      await tool('regression_alert').handler({ project_path: p, scan_type: 'dast', threshold: 0 }, s.plugin),
    );
    expect(alert.score_delta).toBe(0);
    expect(alert.resolved_findings_by_severity['high']).toBe(0);
    const snap = buildSnapshot(s.storage, p, NOW);
    expect(snap.deltas.since_previous).toMatchObject({ resolved_count: 0, not_remeasured_count: 1 });
  });

  it.each(['guardian-dast:unanswered', 'guardian-dast:wall-clock'])(
    'the engine ran but %s failed: a failed sub-pass vetoes "resolved"',
    async (subPass) => {
      const { s, p } = dast([
        { name: 'guardian-dast', status: 'ok' },
        { name: subPass, status: 'failed', reason: 'most probes reached no verdict' },
      ]);
      const r = okResult<DiffOut>(await tool('diff_scans').handler({ project_path: p, scan_type: 'dast' }, s.plugin));
      expect(r.summary).toMatchObject({ resolved: 0, not_remeasured: 1 });
      expect(r.not_measured).toEqual([subPass]);
      const alert = okResult<AlertOut>(
        await tool('regression_alert').handler({ project_path: p, scan_type: 'dast', threshold: 0 }, s.plugin),
      );
      expect(alert.score_delta).toBe(0);
    },
  );

  it('nuclei not requested this time: its earlier finding is not re-measured, and the note says why', async () => {
    const s = freshPlugin();
    const p = projectDir('runcmp-dast-nuclei-');
    seedScan(s, {
      id: 'a', type: 'dast', project: p,
      tools_run: [{ name: 'guardian-dast', status: 'ok' }, { name: 'nuclei', status: 'ok' }],
      findings: [{ fp: T, tool: 'nuclei', severity: 'high' }],
    });
    seedScan(s, { id: 'b', type: 'dast', project: p, tools_run: [{ name: 'guardian-dast', status: 'ok' }] });
    const r = okResult<DiffOut>(await tool('diff_scans').handler({ project_path: p, scan_type: 'dast' }, s.plugin));
    expect(r.summary).toMatchObject({ resolved: 0, not_remeasured: 1 });
    expect(r.note).toMatch(/nuclei/);
  });

  it('control: both runs measured everything, so a missing finding is resolved', async () => {
    const { s, p } = dast([{ name: 'guardian-dast', status: 'ok' }, { name: 'nuclei', status: 'ok' }]);
    const r = okResult<DiffOut>(await tool('diff_scans').handler({ project_path: p, scan_type: 'dast' }, s.plugin));
    expect(r.summary).toMatchObject({ resolved: 1, not_remeasured: 0 });
    expect(r.not_measured).toBeUndefined();
  });
});

describe('a finding tool no bookkeeping name is known to measure', () => {
  function unknownTool(second: ToolRun[]): { s: Seeded; p: string } {
    const s = freshPlugin();
    const p = projectDir('runcmp-unknown-');
    seedScan(s, {
      id: 'a', type: 'quality', project: p,
      tools_run: [{ name: 'eslint', status: 'ok' }],
      findings: [{ fp: A, tool: 'some-future-linter', severity: 'high', category: 'quality' }],
    });
    seedScan(s, { id: 'b', type: 'quality', project: p, tools_run: second });
    return { s, p };
  }

  it('is never counted as re-measured by a PARTIAL scan', async () => {
    const { s, p } = unknownTool([{ name: 'eslint', status: 'ok' }, { name: 'ruff', status: 'failed' }]);
    const r = okResult<DiffOut>(await tool('diff_scans').handler({ project_path: p, scan_type: 'quality' }, s.plugin));
    expect(r.summary).toMatchObject({ resolved: 0, not_remeasured: 1 });
  });

  it('is by a FULL one (it ran everything it tried)', async () => {
    const { s, p } = unknownTool([{ name: 'eslint', status: 'ok' }]);
    const r = okResult<DiffOut>(await tool('diff_scans').handler({ project_path: p, scan_type: 'quality' }, s.plugin));
    expect(r.summary).toMatchObject({ resolved: 1, not_remeasured: 0 });
  });
});

describe('a scanner recorded as several passes', () => {
  const G = 'g'.repeat(64);
  function secrets(second: ToolRun[]): { s: Seeded; p: string } {
    const s = freshPlugin();
    const p = projectDir('runcmp-gitleaks-');
    seedScan(s, {
      id: 'a', type: 'secrets', project: p,
      tools_run: [{ name: 'gitleaks', status: 'ok' }, { name: 'gitleaks-working-tree', status: 'ok' }],
      findings: [{ fp: G, tool: 'gitleaks', subcategory: 'secret', severity: 'high' }],
    });
    seedScan(s, { id: 'b', type: 'secrets', project: p, tools_run: second });
    return { s, p };
  }

  it("gitleaks' history pass failed, its working-tree pass ran: the secret is not re-measured", async () => {
    const { s, p } = secrets([
      { name: 'gitleaks', status: 'failed', reason: 'git: bad object' },
      { name: 'gitleaks-working-tree', status: 'ok' },
    ]);
    const r = okResult<DiffOut>(await tool('diff_scans').handler({ project_path: p, scan_type: 'secrets' }, s.plugin));
    expect(r.summary).toMatchObject({ resolved: 0, not_remeasured: 1 });
    expect(r.not_measured).toEqual(['gitleaks']);
  });

  it('a working-tree pass skipped for want of uncommitted files is no gap: the secret is resolved', async () => {
    const { s, p } = secrets([
      { name: 'gitleaks', status: 'ok' },
      { name: 'gitleaks-working-tree', status: 'skipped', reason: 'no uncommitted or untracked files' },
    ]);
    const r = okResult<DiffOut>(await tool('diff_scans').handler({ project_path: p, scan_type: 'secrets' }, s.plugin));
    expect(r.summary).toMatchObject({ resolved: 1, not_remeasured: 0 });
    expect(r.not_measured).toBeUndefined();
  });
});

describe('an audit_executive row is judged by its sub-scans, not by "the sub-tool answered"', () => {
  it("security_scan_full answered ok, but its Semgrep failed: the audit's SAST finding is not re-measured", async () => {
    const s = freshPlugin();
    const p = projectDir('runcmp-audit-');
    seedScan(s, {
      id: 'sast1', type: 'sast', project: p,
      tools_run: [{ name: 'semgrep', status: 'ok' }],
      findings: [{ fp: S, tool: 'semgrep', severity: 'high' }],
    });
    seedScan(s, {
      id: 'audit1', type: 'audit', project: p,
      tools_run: [{ name: 'security_scan_full', status: 'ok' }],
      findings: [{ fp: S, tool: 'semgrep', severity: 'high' }],
      meta: { sub_scan_ids: { security_scan_full: 'sast1' } },
    });
    seedScan(s, {
      id: 'sast2', type: 'sast', project: p,
      tools_run: [{ name: 'semgrep', status: 'failed', reason: 'exit 7' }, { name: 'bandit', status: 'ok' }],
    });
    seedScan(s, {
      id: 'audit2', type: 'audit', project: p,
      tools_run: [{ name: 'security_scan_full', status: 'ok' }],
      meta: { sub_scan_ids: { security_scan_full: 'sast2' } },
    });
    const r = okResult<DiffOut>(
      await tool('diff_scans').handler({ from_scan_id: 'audit1', to_scan_id: 'audit2' }, s.plugin),
    );
    expect(r.summary).toMatchObject({ resolved: 0, not_remeasured: 1 });
    expect(r.not_measured).toEqual(['semgrep']);
  });
});

/**
 * Task 15's scanners: scan_containers' `trivy image` now runs with
 * `--scanners vuln,secret,misconfig`, hadolint lints the Dockerfile, a
 * compose file is checked, and quality_check reads `.guardian/budgets.yml`.
 */
describe("Task 15's scanners in the comparison", () => {
  const M = 'm'.repeat(64);
  const H = 'h'.repeat(64);
  const C = 'c'.repeat(64);
  const B = 'b'.repeat(64);
  const misconfig: SeedFinding = { fp: M, tool: 'trivy', subcategory: 'dockerfile', severity: 'high' };

  function containers(first: ToolRun[], second: ToolRun[], findings: SeedFinding[] = [misconfig]): { s: Seeded; p: string } {
    const s = freshPlugin();
    const p = projectDir('runcmp-containers-');
    seedScan(s, { id: 'a', type: 'containers', project: p, tools_run: first, findings });
    seedScan(s, { id: 'b', type: 'containers', project: p, tools_run: second });
    return { s, p };
  }
  const diff = async (s: Seeded, p: string, scan_type: string): Promise<DiffOut> =>
    okResult<DiffOut>(await tool('diff_scans').handler({ project_path: p, scan_type }, s.plugin));

  it("an image's misconfiguration is resolved by the next image scan", async () => {
    const { s, p } = containers([{ name: 'trivy-image', status: 'ok' }], [{ name: 'trivy-image', status: 'ok' }]);
    expect((await diff(s, p, 'containers')).summary).toMatchObject({ resolved: 1, not_remeasured: 0 });
  });

  it("an image's misconfiguration is not resolved by a run that scanned only the Dockerfile", async () => {
    const { s, p } = containers(
      [{ name: 'trivy-dockerfile', status: 'ok' }, { name: 'trivy-image', status: 'ok' }],
      [{ name: 'trivy-dockerfile', status: 'ok' }],
    );
    const r = await diff(s, p, 'containers');
    expect(r.summary).toMatchObject({ resolved: 0, not_remeasured: 1 });
    expect(r.not_measured).toEqual(['trivy-image']);
    expect(r.note).toMatch(/trivy-image/);
  });

  it('a row with no bookkeeping at all still measured everything, the image pass included', async () => {
    const { s, p } = containers([{ name: 'trivy-image', status: 'ok' }], []);
    expect((await diff(s, p, 'containers')).summary).toMatchObject({ resolved: 1, not_remeasured: 0 });
  });

  it("control: a Dockerfile misconfiguration is resolved by the next Dockerfile scan, with or without an image", async () => {
    for (const second of [
      [{ name: 'trivy-dockerfile', status: 'ok' }],
      [{ name: 'trivy-dockerfile', status: 'ok' }, { name: 'trivy-image', status: 'ok' }],
    ] satisfies ToolRun[][]) {
      const { s, p } = containers([{ name: 'trivy-dockerfile', status: 'ok' }], second);
      expect((await diff(s, p, 'containers')).summary).toMatchObject({ resolved: 1, not_remeasured: 0 });
    }
  });

  /**
   * Task 24, item 4 — probes H1 and H1b (carried from Task 8's breaker). An
   * image's misconfiguration and a Dockerfile's share the key `trivy:config`,
   * and the finding does not say which pass produced it. `trivy-image`
   * measures that key, and `ownTarget` guarded only one direction: an
   * image-only run "re-measured" the Dockerfile misconfiguration it never
   * looked at and RESOLVED it, and regression_alert's new image CVE was
   * cancelled by that false resolution — score 0, regressed false (GC3).
   * A finding is re-measured only by a pass with the TARGET of a pass that
   * may have produced it: the image, or the project's files.
   */
  describe('H1 / H1b: an image pass and a Dockerfile pass never re-measure each other', () => {
    const I = 'i'.repeat(64);
    const D2 = 'e'.repeat(64);
    const dockerfileMisconfig: SeedFinding = {
      fp: M, tool: 'trivy', rule_id: 'DS-0002', subcategory: 'dockerfile', file: 'Dockerfile', severity: 'high',
    };
    const imageCve: SeedFinding = {
      fp: I, tool: 'trivy', rule_id: 'CVE-2099-0001', subcategory: 'cve', file: 'alpine:3.10 (alpine 3.10.9)', severity: 'high',
    };
    const imageMisconfig: SeedFinding = {
      fp: I, tool: 'trivy', rule_id: 'DS-0026', subcategory: 'dockerfile', file: 'app/Dockerfile', severity: 'high',
    };
    const newDockerfileMisconfig: SeedFinding = { ...dockerfileMisconfig, fp: D2, rule_id: 'DS-0001' };

    function pair(
      first: { runs: ToolRun[]; finding: SeedFinding },
      second: { runs: ToolRun[]; finding: SeedFinding },
    ): { s: Seeded; p: string } {
      const s = freshPlugin();
      const p = projectDir('runcmp-h1-');
      seedScan(s, { id: 'a', type: 'containers', project: p, tools_run: first.runs, findings: [first.finding] });
      seedScan(s, { id: 'b', type: 'containers', project: p, tools_run: second.runs, findings: [second.finding] });
      return { s, p };
    }
    const alert = async (s: Seeded, p: string): Promise<AlertOut> =>
      okResult<AlertOut>(await tool('regression_alert').handler({ project_path: p, threshold: 0 }, s.plugin));

    it("H1: an image-only run does not resolve the Dockerfile's misconfiguration, so the new image CVE regresses", async () => {
      const { s, p } = pair(
        { runs: [{ name: 'trivy-dockerfile', status: 'ok' }], finding: dockerfileMisconfig },
        { runs: [{ name: 'trivy-image', status: 'ok' }], finding: imageCve },
      );
      const d = await diff(s, p, 'containers');
      expect(d.summary).toMatchObject({ new: 1, resolved: 0, not_remeasured: 1 });
      expect(d.not_remeasured_findings.map((f) => f.fingerprint)).toEqual([M]);
      expect(d.not_measured).toEqual(['trivy-dockerfile']);

      const r = await alert(s, p);
      expect(r.resolved_findings_by_severity['high']).toBe(0);
      expect(r.not_remeasured_by_severity['high']).toBe(1);
      expect(r.score_delta).toBe(5);
      expect(r.regressed).toBe(true);
    });

    it("H1b: a Dockerfile-only run does not resolve the image's misconfiguration, so the new Dockerfile one regresses", async () => {
      const { s, p } = pair(
        { runs: [{ name: 'trivy-image', status: 'ok' }], finding: imageMisconfig },
        { runs: [{ name: 'trivy-dockerfile', status: 'ok' }], finding: newDockerfileMisconfig },
      );
      const d = await diff(s, p, 'containers');
      expect(d.summary).toMatchObject({ new: 1, resolved: 0, not_remeasured: 1 });
      expect(d.not_remeasured_findings.map((f) => f.fingerprint)).toEqual([I]);
      expect(d.not_measured).toEqual(['trivy-image']);

      const r = await alert(s, p);
      expect(r.resolved_findings_by_severity['high']).toBe(0);
      expect(r.score_delta).toBe(5);
      expect(r.regressed).toBe(true);
    });

    it('control: each pass still resolves its own findings — image by image, Dockerfile by Dockerfile', async () => {
      const image = pair(
        { runs: [{ name: 'trivy-image', status: 'ok' }], finding: imageCve },
        { runs: [{ name: 'trivy-image', status: 'ok' }], finding: { ...imageCve, fp: D2, rule_id: 'CVE-2099-0002' } },
      );
      expect((await diff(image.s, image.p, 'containers')).summary).toMatchObject({ new: 1, resolved: 1, not_remeasured: 0 });
      const dockerfile = pair(
        { runs: [{ name: 'trivy-dockerfile', status: 'ok' }], finding: dockerfileMisconfig },
        { runs: [{ name: 'trivy-dockerfile', status: 'ok' }, { name: 'trivy-image', status: 'ok' }], finding: imageCve },
      );
      expect((await diff(dockerfile.s, dockerfile.p, 'containers')).summary).toMatchObject({ new: 1, resolved: 1, not_remeasured: 0 });
    });
  });

  /**
   * Follow-up X5 — two images, one target. `trivy-image` was one target
   * whatever image it scanned, so scanning image B "re-measured" image A's
   * findings and resolved them. The run now records the image reference
   * (`ToolRun.target`), and a finding of an image pass is re-measured only
   * by a pass over the SAME image. A row written before the reference was
   * recorded (no `target`) keeps today's reading: any image pass.
   */
  describe('X5: an image pass re-measures only its own image', () => {
    const I = 'i'.repeat(64);
    const J = 'j'.repeat(64);
    const imageMisconfig: SeedFinding = {
      fp: I, tool: 'trivy', rule_id: 'DS-0026', subcategory: 'dockerfile', file: 'app/Dockerfile', severity: 'high',
    };
    const imageCve: SeedFinding = {
      fp: J, tool: 'trivy', rule_id: 'CVE-2099-0001', subcategory: 'cve', file: 'app:1 (alpine 3.10.9)', severity: 'high',
    };
    const image = (target: string | undefined): ToolRun =>
      target === undefined ? { name: 'trivy-image', status: 'ok' } : { name: 'trivy-image', status: 'ok', target };

    function pair(first: ToolRun[], second: ToolRun[], finding: SeedFinding): { s: Seeded; p: string } {
      const s = freshPlugin();
      const p = projectDir('runcmp-x5-');
      seedScan(s, { id: 'a', type: 'containers', project: p, tools_run: first, findings: [finding] });
      seedScan(s, { id: 'b', type: 'containers', project: p, tools_run: second });
      return { s, p };
    }

    it("scanning image B never resolves image A's misconfiguration, nor its CVE", async () => {
      for (const finding of [imageMisconfig, imageCve]) {
        const { s, p } = pair([image('registry/app:1')], [image('registry/other:2')], finding);
        const d = await diff(s, p, 'containers');
        expect(d.summary).toMatchObject({ resolved: 0, not_remeasured: 1 });
        expect(d.not_measured).toEqual(['trivy-image (registry/app:1)']);
        expect(d.note).toMatch(/registry\/app:1/);
      }
    });

    it('control: the same image scanned again resolves it', async () => {
      const { s, p } = pair([image('registry/app:1')], [image('registry/app:1')], imageMisconfig);
      expect((await diff(s, p, 'containers')).summary).toMatchObject({ resolved: 1, not_remeasured: 0 });
    });

    it("regression_alert: image B's scan does not cancel a real new high with image A's resolution", async () => {
      const s = freshPlugin();
      const p = projectDir('runcmp-x5-alert-');
      seedScan(s, { id: 'a', type: 'containers', project: p, tools_run: [image('registry/app:1')], findings: [imageMisconfig] });
      seedScan(s, {
        id: 'b', type: 'containers', project: p, tools_run: [image('registry/other:2')],
        findings: [{ ...imageCve, file: 'registry/other:2 (alpine 3.10.9)' }],
      });
      const r = okResult<AlertOut>(await tool('regression_alert').handler({ project_path: p, threshold: 0 }, s.plugin));
      expect(r.resolved_findings_by_severity['high']).toBe(0);
      expect(r.not_remeasured_by_severity['high']).toBe(1);
      expect(r.score_delta).toBe(5);
      expect(r.regressed).toBe(true);
    });

    it('a legacy row with no image reference, on either side, keeps reading any image pass as the same target', async () => {
      for (const [first, second] of [
        [image(undefined), image('registry/other:2')],
        [image('registry/app:1'), image(undefined)],
        [image(undefined), image(undefined)],
      ] satisfies [ToolRun, ToolRun][]) {
        const { s, p } = pair([first], [second], imageMisconfig);
        expect((await diff(s, p, 'containers')).summary).toMatchObject({ resolved: 1, not_remeasured: 0 });
      }
    });

    it('a Dockerfile pass still never re-measures an image, whatever image it names', async () => {
      const { s, p } = pair([image('registry/app:1')], [{ name: 'trivy-dockerfile', status: 'ok' }], imageMisconfig);
      const d = await diff(s, p, 'containers');
      expect(d.summary).toMatchObject({ resolved: 0, not_remeasured: 1 });
      expect(d.not_measured).toEqual(['trivy-image (registry/app:1)']);
    });
  });

  it("hadolint's finding: resolved when hadolint ran, whatever else failed; not re-measured when it failed", async () => {
    const lint = [{ fp: H, tool: 'hadolint', category: 'quality' as const, severity: 'medium' as const }];
    const first: ToolRun[] = [{ name: 'trivy-dockerfile', status: 'ok' }, { name: 'hadolint', status: 'ok' }];
    const ran = containers(
      first,
      [
        { name: 'trivy-dockerfile', status: 'ok' },
        { name: 'hadolint', status: 'ok' },
        { name: 'docker-compose', status: 'failed', reason: 'could not read the compose file' },
      ],
      lint,
    );
    expect((await diff(ran.s, ran.p, 'containers')).summary).toMatchObject({ resolved: 1, not_remeasured: 0 });
    const failed = containers(first, [{ name: 'trivy-dockerfile', status: 'ok' }, { name: 'hadolint', status: 'failed' }], lint);
    expect((await diff(failed.s, failed.p, 'containers')).summary).toMatchObject({ resolved: 0, not_remeasured: 1 });
  });

  it("a compose finding is resolved by a run that checked the compose file, whatever else failed", async () => {
    const { s, p } = containers(
      [{ name: 'trivy-dockerfile', status: 'ok' }, { name: 'docker-compose', status: 'ok' }],
      [{ name: 'trivy-dockerfile', status: 'failed' }, { name: 'docker-compose', status: 'ok' }],
      [{ fp: C, tool: 'docker-compose', severity: 'high' }],
    );
    expect((await diff(s, p, 'containers')).summary).toMatchObject({ resolved: 1, not_remeasured: 0 });
  });

  it('a quality budget finding: resolved when budgets and jscpd ran, not re-measured when jscpd failed', async () => {
    const budget = [{ fp: B, tool: 'budgets', rule_id: 'quality.duplication_pct', category: 'quality' as const, subcategory: 'budget', severity: 'medium' as const }];
    const quality = (second: ToolRun[]): { s: Seeded; p: string } => {
      const s = freshPlugin();
      const p = projectDir('runcmp-budgets-');
      seedScan(s, {
        id: 'a', type: 'quality', project: p, findings: budget,
        tools_run: [{ name: 'jscpd', status: 'ok' }, { name: 'eslint', status: 'ok' }, { name: 'budgets', status: 'ok' }],
      });
      seedScan(s, { id: 'b', type: 'quality', project: p, tools_run: second });
      return { s, p };
    };
    const fixed = quality([
      { name: 'jscpd', status: 'ok' },
      { name: 'eslint', status: 'failed', reason: 'exit 2' },
      { name: 'budgets', status: 'ok' },
    ]);
    expect((await diff(fixed.s, fixed.p, 'quality')).summary).toMatchObject({ resolved: 1, not_remeasured: 0 });
    const blind = quality([
      { name: 'jscpd', status: 'failed', reason: 'no readable report was written' },
      { name: 'eslint', status: 'ok' },
      { name: 'budgets', status: 'ok' },
    ]);
    expect((await diff(blind.s, blind.p, 'quality')).summary).toMatchObject({ resolved: 0, not_remeasured: 1 });
  });
});

/**
 * Fix round 5: the two sides are not symmetric. A newer scan that did not
 * run a scanner cannot resolve its findings (GC3), but a REFERENCE that did
 * not run one — it was not applicable then (no Python, no package.json, no
 * Dockerfile) or not requested (nuclei, security-code-scan's opt-in) — did
 * look at everything it had to; what that scanner finds now is new. Round 4
 * read both as "not measured", and regression_alert went silent on Bandit's
 * first high the day Python was added. Only a reference that NAMED the
 * scanner and failed it, or listed it missing, holds findings "not
 * previously measured".
 */
describe('a scanner the reference did not run at all: what it finds now is new', () => {
  interface Case {
    type: 'sast' | 'deps_audit' | 'dast' | 'containers';
    before: ToolRun[];
    after: ToolRun[];
    finding: SeedFinding;
    ran: string;
  }
  const X = 'x'.repeat(64);
  const cases: Record<string, Case> = {
    'Bandit, the day Python is added': {
      type: 'sast',
      before: [{ name: 'semgrep', status: 'ok' }],
      after: [{ name: 'semgrep', status: 'ok' }, { name: 'bandit', status: 'ok' }],
      finding: { fp: X, tool: 'bandit', severity: 'high' },
      ran: 'bandit',
    },
    'security-code-scan, once the project opts in': {
      type: 'sast',
      before: [{ name: 'semgrep', status: 'ok' }],
      after: [{ name: 'semgrep', status: 'ok' }, { name: 'security-code-scan', status: 'ok' }],
      finding: { fp: X, tool: 'security-code-scan', severity: 'high' },
      ran: 'security-code-scan',
    },
    'npm audit, the day a package.json appears': {
      type: 'deps_audit',
      before: [{ name: 'trivy', status: 'ok' }],
      after: [{ name: 'trivy', status: 'ok' }, { name: 'npm', status: 'ok' }],
      finding: { fp: X, tool: 'npm-audit', subcategory: 'cve', severity: 'high' },
      ran: 'npm-audit',
    },
    'nuclei, requested for the first time': {
      type: 'dast',
      before: [{ name: 'guardian-dast', status: 'ok' }],
      after: [{ name: 'guardian-dast', status: 'ok' }, { name: 'nuclei', status: 'ok' }],
      finding: { fp: X, tool: 'nuclei', severity: 'high' },
      ran: 'nuclei',
    },
    'Trivy, skipped for want of a Dockerfile, the day one is added': {
      type: 'containers',
      before: [
        { name: 'trivy', status: 'skipped', reason: 'no_dockerfile_or_image' },
        { name: 'docker-compose', status: 'ok' },
      ],
      after: [
        { name: 'trivy-dockerfile', status: 'ok' },
        { name: 'hadolint', status: 'ok' },
        { name: 'docker-compose', status: 'ok' },
      ],
      finding: { fp: X, tool: 'trivy', subcategory: 'dockerfile', severity: 'high' },
      ran: 'trivy',
    },
  };

  function seeded(c: Case): { s: Seeded; p: string } {
    const s = freshPlugin();
    const p = projectDir('runcmp-notrun-');
    seedScan(s, { id: 'a', type: c.type, project: p, tools_run: c.before });
    seedScan(s, { id: 'b', type: c.type, project: p, tools_run: c.after, findings: [c.finding] });
    return { s, p };
  }

  it.each(Object.entries(cases))(
    '%s: set_baseline flags nothing, diff_scans counts it new, regression_alert fires',
    async (_, c) => {
      const { s, p } = seeded(c);
      const b = okResult<Record<string, unknown>>(
        await tool('set_baseline').handler({ project_path: p, scan_id: 'a' }, s.plugin),
      );
      expect(b['not_measured']).toBeUndefined();
      expect(b['warning']).toBeUndefined();

      const diff = okResult<DiffOut>(
        await tool('diff_scans').handler({ project_path: p, scan_type: c.type, from: 'baseline' }, s.plugin),
      );
      expect(diff.summary).toMatchObject({ new: 1, not_previously_measured: 0 });
      expect(diff.reference_not_measured).toBeUndefined();
      expect(diff.note).toMatch(new RegExp(`did not run ${c.ran}`));
      expect(diff.note).not.toMatch(/once the scanner works/);

      const alert = okResult<AlertOut & { new_findings_by_severity: Record<string, number> }>(
        await tool('regression_alert').handler({ project_path: p, scan_type: c.type, threshold: 0 }, s.plugin),
      );
      expect(alert.reference).toBe('baseline');
      expect(alert.new_findings_by_severity['high']).toBe(1);
      expect(alert.score_delta).toBe(5);
      expect(alert.regressed).toBe(true);

      const snap = buildSnapshot(s.storage, p, NOW);
      expect(snap.deltas.since_baseline).toMatchObject({ new_count: 1 });
      expect(snap.deltas.since_baseline?.not_previously_measured_count).toBeUndefined();
    },
  );

  it('an orchestrated run: Bandit in the newer sast child, none in the baseline', async () => {
    const s = freshPlugin();
    const p = projectDir('runcmp-notrun-orch-');
    seedOrchestratedRun(s, 'run1', p, { sast: { runs: [{ name: 'semgrep', status: 'ok' }] } });
    s.storage.baselines.set({ scan_id: 'run1' });
    seedOrchestratedRun(s, 'run2', p, {
      sast: {
        runs: [{ name: 'semgrep', status: 'ok' }, { name: 'bandit', status: 'ok' }],
        findings: [{ fp: X, tool: 'bandit', identity: 'I-X', severity: 'high' }],
      },
    });
    const alert = okResult<AlertOut>(await tool('regression_alert').handler({ project_path: p, threshold: 0 }, s.plugin));
    expect(alert.reference).toBe('baseline');
    expect(alert.score_delta).toBe(5);
    expect(alert.regressed).toBe(true);
  });

  it('the newer side stays conservative: Python gone, Bandit not run — its finding is not re-measured, never resolved', async () => {
    const s = freshPlugin();
    const p = projectDir('runcmp-notrun-gone-');
    seedScan(s, {
      id: 'a', type: 'sast', project: p,
      tools_run: [{ name: 'semgrep', status: 'ok' }, { name: 'bandit', status: 'ok' }],
      findings: [{ fp: X, tool: 'bandit', severity: 'high' }],
    });
    seedScan(s, { id: 'b', type: 'sast', project: p, tools_run: [{ name: 'semgrep', status: 'ok' }] });
    const diff = okResult<DiffOut>(await tool('diff_scans').handler({ project_path: p, scan_type: 'sast' }, s.plugin));
    expect(diff.summary).toMatchObject({ resolved: 0, not_remeasured: 1 });
    expect(diff.not_measured).toEqual(['bandit']);
    expect(diff.note).toMatch(/did not run bandit/);
    expect(diff.note).not.toMatch(/once the scanner works/);
  });

  it('a scanner that failed in the newer scan is still worded as one to fix', async () => {
    const s = freshPlugin();
    const p = projectDir('runcmp-notrun-failed-');
    seedScan(s, {
      id: 'a', type: 'deps_audit', project: p,
      tools_run: [{ name: 'trivy', status: 'ok' }, { name: 'npm', status: 'ok' }],
      findings: [{ fp: N, tool: 'npm-audit', subcategory: 'cve', severity: 'high' }],
    });
    seedScan(s, {
      id: 'b', type: 'deps_audit', project: p,
      tools_run: [{ name: 'trivy', status: 'ok' }, { name: 'npm', status: 'failed', reason: 'no audit report' }],
      missing_tools: ['npm'],
    });
    const diff = okResult<DiffOut>(await tool('diff_scans').handler({ project_path: p, scan_type: 'deps_audit' }, s.plugin));
    expect(diff.note).toMatch(/did not measure npm/);
    expect(diff.note).toMatch(/once the scanner works/);
    expect(diff.note).not.toMatch(/did not run/);
  });

  describe('a reference that NAMED the scanner and did not run it ok still holds it "not previously measured"', () => {
    it('Bandit listed missing (not installed) in the baseline', async () => {
      const s = freshPlugin();
      const p = projectDir('runcmp-notrun-gap-');
      seedScan(s, {
        id: 'a', type: 'sast', project: p,
        tools_run: [{ name: 'semgrep', status: 'ok' }, { name: 'bandit', status: 'skipped', reason: 'not_installed' }],
        missing_tools: ['bandit'],
      });
      const b = okResult<{ not_measured: string[]; warning: string }>(
        await tool('set_baseline').handler({ project_path: p, scan_type: 'sast' }, s.plugin),
      );
      expect(b.not_measured).toEqual(['bandit']);
      seedScan(s, {
        id: 'b', type: 'sast', project: p,
        tools_run: [{ name: 'semgrep', status: 'ok' }, { name: 'bandit', status: 'ok' }],
        findings: [{ fp: X, tool: 'bandit', severity: 'high' }],
      });
      const diff = okResult<DiffOut>(
        await tool('diff_scans').handler({ project_path: p, scan_type: 'sast', from: 'baseline' }, s.plugin),
      );
      expect(diff.summary).toMatchObject({ new: 0, not_previously_measured: 1 });
      expect(diff.reference_not_measured).toEqual(['bandit']);
      const alert = okResult<AlertOut>(
        await tool('regression_alert').handler({ project_path: p, scan_type: 'sast', threshold: 0 }, s.plugin),
      );
      expect(alert.score_delta).toBe(0);
      expect(alert.regressed).toBe(false);
    });

    it('an audit whose security_scan_full sub-scan lost its scan_sast child (it threw)', async () => {
      const s = freshPlugin();
      const p = projectDir('runcmp-notrun-audit-');
      seedScan(s, {
        id: 'full1', type: 'security_full', project: p,
        tools_run: [
          { name: 'scan_sast', status: 'failed', reason: 'threw: boom' },
          { name: 'gitleaks', status: 'ok' },
          { name: 'trivy', status: 'ok' },
          { name: 'trivy-config', status: 'ok' },
        ],
      });
      seedScan(s, {
        id: 'audit1', type: 'audit', project: p,
        tools_run: [{ name: 'security_scan_full', status: 'ok' }],
        meta: { sub_scan_ids: { security_scan_full: 'full1' } },
      });
      seedScan(s, {
        id: 'full2', type: 'security_full', project: p,
        tools_run: [
          { name: 'semgrep', status: 'ok' },
          { name: 'gitleaks', status: 'ok' },
          { name: 'trivy', status: 'ok' },
          { name: 'trivy-config', status: 'ok' },
        ],
        findings: [{ fp: S, tool: 'semgrep', severity: 'high' }],
      });
      seedScan(s, {
        id: 'audit2', type: 'audit', project: p,
        tools_run: [{ name: 'security_scan_full', status: 'ok' }],
        findings: [{ fp: S, tool: 'semgrep', severity: 'high' }],
        meta: { sub_scan_ids: { security_scan_full: 'full2' } },
      });
      const diff = okResult<DiffOut>(
        await tool('diff_scans').handler({ from_scan_id: 'audit1', to_scan_id: 'audit2' }, s.plugin),
      );
      expect(diff.summary).toMatchObject({ new: 0, not_previously_measured: 1 });
      expect(diff.reference_not_measured).toEqual(['scan_sast']);
    });
  });
});

/**
 * Follow-up X1: a Semgrep run the shared judge found `partial` is `ok` AND
 * missing, the files named in `partially_parsed`. That shape reads as the
 * retry shape ("ran, with a narrower gap"), so without more it would have
 * MEASURED every Semgrep finding — including one inside the unparsed span of
 * a named file, which would then read resolved (or new). Before, the run was
 * `failed` and nothing of Semgrep's was measured. A finding in a file the run
 * only partly parsed is unmeasured; every other Semgrep finding is measured.
 */
describe('a Semgrep run that only partly parsed some files', () => {
  const partialRun = (...files: string[]): ToolRun => ({
    name: 'semgrep',
    status: 'ok',
    reason: 'partial',
    partially_parsed: files.map((file) => ({ file, type: 'PartialParsing', message: 'Syntax error' })),
  });

  function pair(findingFile: string, newer: ToolRun): { s: Seeded; p: string } {
    const s = freshPlugin();
    const p = projectDir('runcmp-partial-parse-');
    seedScan(s, { id: 'a', type: 'sast', project: p, findings: [{ fp: S, tool: 'semgrep', file: findingFile }] });
    seedScan(s, { id: 'b', type: 'sast', project: p, tools_run: [newer], missing_tools: ['semgrep'] });
    return { s, p };
  }
  const diff = async (s: Seeded, p: string): Promise<DiffOut> =>
    okResult<DiffOut>(await tool('diff_scans').handler({ project_path: p, scan_type: 'sast' }, s.plugin));

  it('does not resolve a finding in a file it only partly parsed, and names the file', async () => {
    const { s, p } = pair('wp/rest-controller.php', partialRun('wp/rest-controller.php'));
    const d = await diff(s, p);
    expect(d.summary).toMatchObject({ resolved: 0, not_remeasured: 1 });
    expect(d.not_measured).toEqual(['semgrep (partly parsed: wp/rest-controller.php)']);
  });

  it('control: resolves a finding in any other file — the rest of the run measured', async () => {
    const { s, p } = pair('src/app.js', partialRun('wp/rest-controller.php'));
    expect((await diff(s, p)).summary).toMatchObject({ resolved: 1, not_remeasured: 0 });
  });

  it('a reference that only partly parsed a file holds a finding there now "not previously measured", never new', async () => {
    const s = freshPlugin();
    const p = projectDir('runcmp-partial-parse-ref-');
    seedScan(s, { id: 'a', type: 'sast', project: p, tools_run: [partialRun('wp/rest-controller.php')], missing_tools: ['semgrep'] });
    seedScan(s, { id: 'b', type: 'sast', project: p, findings: [{ fp: D, tool: 'semgrep', file: 'wp/rest-controller.php' }] });
    const d = await diff(s, p);
    expect(d.summary).toMatchObject({ new: 0, not_previously_measured: 1 });
    expect(d.reference_not_measured).toEqual(['semgrep (partly parsed: wp/rest-controller.php)']);
  });
});
