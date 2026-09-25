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
import { freshPlugin, projectDir, seedOrchestratedRun, seedScan, type Seeded } from '../helpers/historySeed.js';

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
