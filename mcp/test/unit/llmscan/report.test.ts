/**
 * Coverage is computed in code, and `full` is earned: never while a task is
 * open, leased or undelivered, nor while an entry point is unvisited
 * (US-1.AC-8, SC-004). What is missing is named.
 *
 * T-08.
 */

import { describe, expect, it } from 'vitest';
import { computeReport } from '../../../src/llmscan/report.js';
import type { LlmScanPlan, LlmScanTask, ScanMode, TaskKind, VerifyVerdict } from '../../../src/llmscan/types.js';
import { mulberry32 } from '../../helpers/yamlFuzz.js';

type State = 'open' | 'leased' | 'valid' | 'invalid_submissions' | 'stale' | 'not_delivered';

function plan(id: string, modes: ScanMode[], setAside: string[]): LlmScanPlan {
  return {
    id,
    project_path: '/project',
    scan_id: `scan-${id}`,
    modes,
    prompt_version: 'v1',
    tree_hash: 'h',
    surface_snapshot_id: modes.includes('hunt') ? 1 : null,
    limits: { max_tasks: 200, max_estimated_tokens: 500_000, per_task_overhead: 60_000 },
    estimate: { tasks: 0, brief_tokens: 0, total_tokens: 0, assumptions: 'test' },
    confirmed: true,
    status: 'open',
    not_eligible: [],
    set_aside: setAside.map((entry_point) => ({ entry_point, reason: 'handler file not in the project' })),
    created_at: '2026-10-02T00:00:00.000Z',
    updated_at: '2026-10-02T00:00:00.000Z',
  };
}

const VERDICT: VerifyVerdict = {
  verdict: 'not_real',
  attacker_input: 'none',
  operation: 'src/a.ts:3',
  decisive_line: 'src/a.ts:3 — bound parameter',
  reasoning: 'Bound.',
};

function task(planId: string, n: number, kind: TaskKind, state: State, eps: string[]): LlmScanTask {
  const closed = state === 'valid' || state === 'invalid_submissions' || state === 'stale' || state === 'not_delivered';
  const delivered = state !== 'open' && state !== 'not_delivered';
  return {
    plan_id: planId,
    task_id: `t-${String(n).padStart(4, '0')}`,
    kind,
    target: kind === 'verify' ? { fingerprint: `fp-${n}`, files: ['src/a.ts'] } : { entry_points: eps, files: ['src/a.ts'] },
    status: closed ? 'closed' : state === 'leased' ? 'leased' : 'open',
    lease_token: state === 'leased' ? `lease-${n}` : null,
    lease_expires_at: state === 'leased' ? '2026-10-02T00:20:00.000Z' : null,
    attempts: state === 'invalid_submissions' ? 3 : 0,
    file_hashes: { 'src/a.ts': 'abc' },
    brief_chars: delivered ? 4000 : null,
    response_chars: closed && state !== 'not_delivered' ? 300 : null,
    independence: state === 'valid' || state === 'stale' ? 'subagent' : null,
    result:
      state === 'valid' || state === 'stale'
        ? kind === 'verify'
          ? VERDICT
          : { entry_points_reviewed: eps, findings: [] }
        : null,
    closed_reason: closed ? state : null,
    delivered_at: delivered ? '2026-10-02T00:00:01.000Z' : null,
    closed_at: closed ? '2026-10-02T00:00:02.000Z' : null,
  };
}

describe('T-08 coverage is full only with no open task and no unvisited entry point; what is missing is named (US-1.AC-8, SC-004)', () => {
  it('T-08 300 seeded plan states', () => {
    const rand = mulberry32(0x08_0008);
    const STATES: State[] = ['open', 'leased', 'valid', 'valid', 'valid', 'invalid_submissions', 'stale', 'not_delivered'];
    const pickState = (kind: TaskKind): State => {
      const s = STATES[Math.floor(rand() * STATES.length)] ?? 'valid';
      return s === 'stale' && kind !== 'verify' ? 'valid' : s;
    };
    let fullCases = 0;
    let partialCases = 0;

    for (let c = 0; c < 300; c += 1) {
      const id = `p${c}`;
      const modes: ScanMode[] = [['verify'], ['hunt'], ['verify', 'hunt']][Math.floor(rand() * 3)] as ScanMode[];
      const clean = rand() < 0.35;
      const hunting = modes.includes('hunt');
      let v = modes.includes('verify') ? Math.floor(rand() * 7) : 0;
      let h = hunting ? Math.floor(rand() * 5) : 0;
      if (clean && hunting && h === 0) h = 1;
      if (!hunting && v === 0) v = 1;
      const setAside = hunting && !clean ? Array.from({ length: Math.floor(rand() * 3) }, (_, i) => `GET /aside/${c}/${i}`) : [];

      const tasks: LlmScanTask[] = [];
      let n = 1;
      for (let i = 0; i < v; i += 1) tasks.push(task(id, n++, 'verify', clean ? 'valid' : pickState('verify'), []));
      for (let g = 0; g < h; g += 1) {
        const eps = Array.from({ length: 1 + Math.floor(rand() * 5) }, (_, k) => `GET /r/${c}/${g}/${k}`);
        tasks.push(task(id, n++, 'hunt', clean ? 'valid' : pickState('hunt'), eps));
      }
      if (hunting) tasks.push(task(id, n++, 'crosscut', clean ? 'valid' : pickState('crosscut'), []));

      const p = plan(id, modes, setAside);
      const report = computeReport(p, tasks);

      const notDone = tasks.filter((t) => t.status !== 'closed' || t.closed_reason === 'not_delivered');
      const huntEps = tasks.flatMap((t) => t.target.entry_points ?? []);
      const allEps = [...huntEps, ...setAside];
      const defect = notDone.length > 0 || setAside.length > 0 || (hunting && allEps.length === 0);
      const ambiguous = tasks.some((t) => t.closed_reason === 'invalid_submissions' || t.closed_reason === 'stale');
      const ctx = `case ${c}: ${JSON.stringify({ modes, states: tasks.map((t) => [t.task_id, t.kind, t.status, t.closed_reason]), setAside })}`;

      // Every entry point is accounted for exactly once.
      expect(report.entry_points.map((e) => e.entry_point).sort(), ctx).toEqual([...allEps].sort());
      for (const e of report.entry_points) {
        if (e.status === 'visited') {
          const by = tasks.find((t) => t.task_id === e.task_id);
          expect(by?.status, ctx).toBe('closed');
          expect(by?.target.entry_points ?? [], ctx).toContain(e.entry_point);
        }
        if (e.status === 'set_aside') expect((e.reason ?? '').trim(), ctx).not.toBe('');
      }
      expect(new Set(report.missing).size, ctx).toBe(report.missing.length);
      for (const m of report.missing) expect(tasks.map((t) => t.task_id), ctx).toContain(m);

      if (defect) {
        partialCases += 1;
        expect(report.coverage, ctx).not.toBe('full');
        for (const t of notDone) expect(report.missing, ctx).toContain(t.task_id);
        const unvisited = [...setAside, ...notDone.flatMap((t) => t.target.entry_points ?? [])];
        for (const ep of unvisited) expect(report.not_visited, ctx).toContain(ep);
      } else if (!ambiguous) {
        fullCases += 1;
        expect(report.coverage, ctx).toBe('full');
        expect(report.missing, ctx).toEqual([]);
        expect(report.not_visited, ctx).toEqual([]);
      }
    }
    // The generator exercised both sides.
    expect(fullCases).toBeGreaterThan(50);
    expect(partialCases).toBeGreaterThan(50);
  });

  it('T-08 the task counts partition the plan: closed with an answer, open, leased, never delivered', () => {
    const tasks = [
      task('p', 1, 'verify', 'valid', []),
      task('p', 2, 'verify', 'open', []),
      task('p', 3, 'verify', 'leased', []),
      task('p', 4, 'verify', 'not_delivered', []),
    ];
    const report = computeReport(plan('p', ['verify'], []), tasks);
    expect(report.tasks).toEqual({ planned: 4, closed: 1, open: 1, leased: 1, not_delivered: 1 });
    expect(report.coverage).toBe('partial');
    expect([...report.missing].sort()).toEqual(['t-0002', 't-0003', 't-0004']);
  });
});
