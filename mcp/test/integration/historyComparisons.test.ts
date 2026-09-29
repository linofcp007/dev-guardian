/**
 * The comparison readers — `regression_alert`, `diff_scans`, `report_export`
 * and the dashboard's coverage — held to the rules every other history
 * reader follows.
 *
 *   - Suppressions. After `suppress_finding`, `regression_alert` still said
 *     `regressed: true, score_delta: 10` for the suppressed critical, and
 *     `diff_scans` listed it as new, while the dashboard and `risk_score`
 *     (which read the open set) said 0. Both now honour suppressions the way
 *     the open set does — per project, unexpired, by fingerprint or identity
 *     — and list suppressed findings apart, never as new or a regression.
 *   - One project. `diff_scans` and `report_export` took explicit scan ids of
 *     another project or scan type without checking, and `report_export`
 *     then wrote that scan into THIS project's `.guardian/reports`. Refused
 *     now, with the reason. A scan still running (its findings are inserted
 *     in chunks) is refused too.
 *   - Coverage. The dashboard read `partial` whenever any scan existed, even
 *     when every scan measured nothing, while `risk_score` said `none` for
 *     the same data.
 */

import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { buildSnapshot } from '../../src/dashboard/snapshot.js';
import { TOOLS } from '../../src/tools/index.js';
import { RESOURCES } from '../../src/resources/index.js';
import { cleanupTempDirs } from '../helpers/tempDir.js';
import { freshPlugin, projectDir, seedScan, type Seeded } from '../helpers/historySeed.js';
import { okResult } from '../helpers/toolResult.js';
import type { ToolResult } from '../../src/types.js';

afterAll(cleanupTempDirs);

beforeAll(async () => {
  await import('../../src/registerAll.js');
});

function tool(name: string) {
  const t = TOOLS.find((x) => x.name === name);
  if (!t) throw new Error(`tool ${name} not registered`);
  return t;
}

async function call(name: string, s: Seeded, input: Record<string, unknown>): Promise<ToolResult<Record<string, unknown>>> {
  return tool(name).handler(input, s.plugin);
}

function errorOf(r: ToolResult<Record<string, unknown>>): { code: string; message: string } {
  if (r.ok) throw new Error(`expected a refusal, got ${JSON.stringify(r).slice(0, 300)}`);
  return r.error;
}

/** A baseline with nothing, then a scan with one new critical: a regression of 10. */
function regressionOfOneCritical(): { s: Seeded; p: string } {
  const s = freshPlugin();
  const p = projectDir('cmp-');
  seedScan(s, { id: '00000000-0000-4000-8000-000000000001', type: 'sast', project: p, findings: [] });
  s.storage.baselines.set({ scan_id: '00000000-0000-4000-8000-000000000001', note: 'clean' });
  seedScan(s, {
    id: '00000000-0000-4000-8000-000000000002',
    type: 'sast',
    project: p,
    findings: [{ fp: 'fp-crit', severity: 'critical', identity: 'id-crit' }],
  });
  return { s, p };
}

describe('suppressions in regression_alert and diff_scans', () => {
  it('control: an unsuppressed new critical is a regression of 10', async () => {
    const { s, p } = regressionOfOneCritical();
    const r = okResult<{ regressed: boolean; score_delta: number }>(await call('regression_alert', s, { project_path: p }));
    expect(r.regressed).toBe(true);
    expect(r.score_delta).toBe(10);
  });

  it('regression_alert: a suppressed finding is listed apart and never counted as a regression', async () => {
    const { s, p } = regressionOfOneCritical();
    s.storage.suppressions.insert({ finding_fingerprint: 'fp-crit', finding_identity: 'id-crit', reason: 'accepted', project_path: p });

    const r = okResult<{
      regressed: boolean;
      score_delta: number;
      new_findings_by_severity: Record<string, number>;
      suppressed_by_severity: Record<string, number>;
    }>(await call('regression_alert', s, { project_path: p }));

    expect(r.regressed).toBe(false);
    expect(r.score_delta).toBe(0);
    expect(r.new_findings_by_severity['critical']).toBe(0);
    expect(r.suppressed_by_severity['critical']).toBe(1);
  });

  it('diff_scans: a suppressed finding is listed apart, never as new', async () => {
    const { s, p } = regressionOfOneCritical();
    s.storage.suppressions.insert({ finding_fingerprint: 'fp-crit', reason: 'accepted', project_path: p });

    const r = okResult<{
      summary: Record<string, number>;
      new_findings: Array<{ fingerprint: string }>;
      suppressed_findings: Array<{ fingerprint: string }>;
    }>(await call('diff_scans', s, { project_path: p, from: 'baseline' }));

    expect(r.summary['new']).toBe(0);
    expect(r.summary['suppressed']).toBe(1);
    expect(r.new_findings).toEqual([]);
    expect(r.suppressed_findings.map((f) => f.fingerprint)).toEqual(['fp-crit']);
  });

  it("another project's suppression, and an expired one, do not apply", async () => {
    const { s, p } = regressionOfOneCritical();
    const other = projectDir('cmp-other-');
    s.storage.suppressions.insert({ finding_fingerprint: 'fp-crit', reason: 'theirs', project_path: other });
    s.storage.suppressions.insert({
      finding_fingerprint: 'fp-crit',
      reason: 'lapsed',
      project_path: p,
      expires_at: '2020-01-01T00:00:00.000Z',
    });
    const r = okResult<{ regressed: boolean; score_delta: number }>(await call('regression_alert', s, { project_path: p }));
    expect(r.regressed).toBe(true);
    expect(r.score_delta).toBe(10);
  });
});

describe('explicit scan ids answer for one project and one scan type', () => {
  it("diff_scans refuses a to_scan_id of another project than project_path", async () => {
    const s = freshPlugin();
    const a = projectDir('cmp-a-');
    const b = projectDir('cmp-b-');
    const theirs = seedScan(s, { id: '00000000-0000-4000-8000-00000000000a', type: 'sast', project: b, findings: [] });
    seedScan(s, { id: '00000000-0000-4000-8000-00000000000b', type: 'sast', project: a, findings: [] });

    const err = errorOf(await call('diff_scans', s, { project_path: a, to_scan_id: theirs }));
    expect(err.message).toContain(b);
    expect(err.message).toContain(a);
  });

  it('diff_scans refuses a from_scan_id of another project than the to scan', async () => {
    const s = freshPlugin();
    const a = projectDir('cmp-a-');
    const b = projectDir('cmp-b-');
    const theirs = seedScan(s, { id: '00000000-0000-4000-8000-00000000000c', type: 'sast', project: b, findings: [] });
    const mine = seedScan(s, { id: '00000000-0000-4000-8000-00000000000d', type: 'sast', project: a, findings: [] });

    const err = errorOf(await call('diff_scans', s, { to_scan_id: mine, from_scan_id: theirs }));
    expect(err.message).toMatch(/another project/);
  });

  it('diff_scans refuses a from_scan_id of another scan type', async () => {
    const s = freshPlugin();
    const a = projectDir('cmp-a-');
    const deps = seedScan(s, {
      id: '00000000-0000-4000-8000-00000000000e',
      type: 'deps',
      project: a,
      tools_run: [{ name: 'trivy', status: 'ok' }],
      findings: [],
    });
    const sast = seedScan(s, { id: '00000000-0000-4000-8000-00000000000f', type: 'sast', project: a, findings: [] });

    const err = errorOf(await call('diff_scans', s, { project_path: a, to_scan_id: sast, from_scan_id: deps }));
    expect(err.message).toMatch(/'deps'/);
    expect(err.message).toMatch(/'sast'/);
  });

  it('diff_scans refuses a scan that is still running: its findings are not all in', async () => {
    const s = freshPlugin();
    const a = projectDir('cmp-a-');
    const done = seedScan(s, { id: '00000000-0000-4000-8000-000000000010', type: 'sast', project: a, findings: [] });
    s.storage.scans.insert({ scan_id: '00000000-0000-4000-8000-000000000011', scan_type: 'sast', project_path: a, tree_hash: 'h' });

    const err = errorOf(
      await call('diff_scans', s, { project_path: a, from_scan_id: done, to_scan_id: '00000000-0000-4000-8000-000000000011' }),
    );
    expect(err.message).toMatch(/still running/);
  });

  it("report_export refuses another project's scan, and writes nothing into this project's reports", async () => {
    const s = freshPlugin();
    const a = projectDir('cmp-a-');
    const b = projectDir('cmp-b-');
    const theirs = seedScan(s, {
      id: '00000000-0000-4000-8000-000000000012',
      type: 'sast',
      project: b,
      findings: [{ fp: 'fp-b', severity: 'high' }],
    });

    const r = await call('report_export', s, { project_path: a, scan_id: theirs, format: 'json' });
    const err = errorOf(r);
    expect(err.message).toContain(b);
    expect(existsSync(join(a, '.guardian', 'reports'))).toBe(false);
  });

  it('report_export refuses a scan that is still running', async () => {
    const s = freshPlugin();
    const a = projectDir('cmp-a-');
    s.storage.scans.insert({ scan_id: '00000000-0000-4000-8000-000000000013', scan_type: 'sast', project_path: a, tree_hash: 'h' });
    const err = errorOf(await call('report_export', s, { project_path: a, scan_id: '00000000-0000-4000-8000-000000000013' }));
    expect(err.message).toMatch(/still running/);
  });

  it("guardian://scans/{id} lists no findings for a scan still running, and says why", async () => {
    const s = freshPlugin();
    const a = projectDir('cmp-a-');
    const id = '00000000-0000-4000-8000-000000000014';
    s.storage.scans.insert({ scan_id: id, scan_type: 'sast', project_path: a, tree_hash: 'h' });
    s.storage.findings.bulkInsert([
      { scan_id: id, fingerprint: 'partial-1', tool: 'semgrep', severity: 'high', category: 'security', title: 't', fix_available: false, fix_applied: false },
    ]);
    const r = RESOURCES.find((x) => x.name === 'guardian-scans-by-id');
    if (!r) throw new Error('resource not registered');
    const json = (await r.handler(new URL(`guardian://scans/${id}`), { scan_id: id }, s.plugin)).json as {
      status: string;
      top_findings: unknown[];
      findings_count_by_severity: unknown;
      note?: string;
    };
    expect(json.status).toBe('running');
    expect(json.top_findings).toEqual([]);
    expect(json.findings_count_by_severity).toBeNull();
    expect(json.note).toMatch(/still running/);
  });
});

describe('how much suppressions take out is said, never silent', () => {
  // A trusted database is the user's own, so suppressions with no project
  // (matching every project) stay legitimate — but a mass suppression is how
  // findings disappear without a trace, so risk_score and health_status say
  // how many apply.
  it('risk_score counts the suppressed findings; health_status the active suppressions, by scope', async () => {
    const s = freshPlugin();
    const p = projectDir('cmp-suppressed-');
    seedScan(s, {
      id: '00000000-0000-4000-8000-000000000030',
      type: 'sast',
      project: p,
      findings: [
        { fp: 'fp-a', severity: 'critical' },
        { fp: 'fp-b', severity: 'high' },
        { fp: 'fp-c', severity: 'low' },
      ],
    });
    s.storage.suppressions.insert({ finding_fingerprint: 'fp-a', reason: 'mine', project_path: p });
    s.storage.suppressions.insert({ finding_fingerprint: 'fp-b', reason: 'no project: matches every project' });
    s.storage.suppressions.insert({ finding_fingerprint: 'fp-x', reason: 'another project', project_path: projectDir('cmp-other-') });

    const risk = okResult<{ suppressed_count: number; components: unknown }>(await call('risk_score', s, { project_path: p }));
    expect(risk.suppressed_count).toBe(2);
    const health = okResult<{ suppressions: Record<string, number> }>(await call('health_status', s, { project_path: p }));
    expect(health.suppressions).toEqual({ active: 2, this_project: 1, all_projects: 1 });
  });
});

describe('dashboard coverage, by the rule risk_score uses', () => {
  it('reads none when every scan measured nothing, as risk_score does', async () => {
    const s = freshPlugin();
    const p = projectDir('cmp-none-');
    seedScan(s, {
      id: '00000000-0000-4000-8000-000000000020',
      type: 'sast',
      project: p,
      tools_run: [{ name: 'semgrep', status: 'failed', reason: 'exit 7' }],
      missing_tools: ['semgrep'],
    });

    const risk = okResult<{ coverage: { level: string } }>(await call('risk_score', s, { project_path: p }));
    const snap = buildSnapshot(s.storage, p, Date.now());
    expect(risk.coverage.level).toBe('none');
    expect(snap.coverage.level).toBe('none');
  });
});
