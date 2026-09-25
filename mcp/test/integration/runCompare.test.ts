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
import { freshPlugin, projectDir, seedOrchestratedRun, type Seeded } from '../helpers/historySeed.js';

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
      not_remeasured_types: string[];
    }>(await tool('diff_scans').handler({ project_path: p }, s.plugin));
    expect([r.from_scan_id, r.to_scan_id]).toEqual(['run1', 'run2']);
    expect(r.summary).toEqual({ new: 1, resolved: 0, unchanged: 0, not_remeasured: 1 });
    expect(r.resolved_findings).toEqual([]);
    expect(r.not_remeasured_findings.map((f) => f.fingerprint)).toEqual([S]);
    expect(r.not_remeasured_types).toEqual(['sast']);
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
