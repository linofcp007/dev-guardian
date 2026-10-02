/** Fix round 1 of task 2: max_tasks overflow is partial coverage, never full; the crosscut counts against the limit. */

import { resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { describe, expect, it } from 'vitest';
import { buildPlan, type PlanInput } from '../../../src/llmscan/plan.js';
import { computeReport } from '../../../src/llmscan/report.js';
import { LLM_SCAN_DEFAULTS, type LlmScanPlan, type LlmScanTask, type VerifyVerdict } from '../../../src/llmscan/types.js';
import { makeFinding } from '../../../src/runners/scannerParsers/index.js';

const ROOT = resolve(tmpdir(), 'llm-plan-limits-never-created');
const limits = (max_tasks: number): PlanInput['limits'] => ({
  max_tasks,
  max_estimated_tokens: LLM_SCAN_DEFAULTS.max_estimated_tokens,
  per_task_overhead: LLM_SCAN_DEFAULTS.per_task_overhead,
});
const finding = (i: number, file?: string): ReturnType<typeof makeFinding> =>
  makeFinding({
    tool: 'semgrep',
    rule_id: 'r',
    severity: 'high',
    category: 'security',
    title: `t${i}`,
    ...(file !== undefined ? { file_path: file, line_start: i + 1 } : {}),
  });

const VERDICT: VerifyVerdict = { verdict: 'not_real', attacker_input: 'none', operation: 'a.ts:1', decisive_line: 'a.ts:1 — x', reasoning: 'x' };

function run(input: PlanInput): { plan: LlmScanPlan; tasks: LlmScanTask[]; planned: ReturnType<typeof buildPlan> } {
  const planned = buildPlan(input);
  const plan: LlmScanPlan = {
    id: 'p',
    project_path: ROOT,
    scan_id: 's',
    modes: [...input.modes],
    prompt_version: 'v1',
    tree_hash: 'h',
    surface_snapshot_id: null,
    limits: input.limits,
    estimate: planned.estimate,
    confirmed: true,
    status: 'open',
    not_eligible: planned.not_eligible,
    set_aside: planned.set_aside,
    created_at: 'x',
    updated_at: 'x',
  };
  const tasks: LlmScanTask[] = planned.tasks.map((t) => ({
    plan_id: 'p',
    task_id: t.task_id,
    kind: t.kind,
    target: t.target,
    status: 'closed',
    lease_token: null,
    lease_expires_at: null,
    attempts: 0,
    file_hashes: {},
    brief_chars: 10,
    response_chars: 10,
    independence: 'subagent',
    result: t.kind === 'verify' ? VERDICT : { entry_points_reviewed: [], findings: [] },
    closed_reason: 'valid',
    delivered_at: 'x',
    closed_at: 'x',
  }));
  return { plan, tasks, planned };
}

const base = (over: Partial<PlanInput>): PlanInput => ({
  project_path: ROOT,
  modes: ['verify'],
  findings: [],
  surface: null,
  code_files: [],
  limits: limits(200),
  ...over,
});

describe('max_tasks overflow never reads as full coverage (US-4.AC-2)', () => {
  it('300 eligible findings, max_tasks 200, all 200 answered: partial, the 100 named', () => {
    const findings = Array.from({ length: 300 }, (_, i) => finding(i, 'src/a.ts'));
    const { plan, tasks } = run(base({ findings }));
    expect(tasks).toHaveLength(200);
    const report = computeReport(plan, tasks);
    expect(report.coverage).toBe('partial');
    expect(report.not_planned).toHaveLength(100);
    expect(report.notes.join('\n')).toContain(report.not_planned[0] ?? 'missing');
  });

  it('EC-1 reasons only, all tasks answered: still full', () => {
    const findings = [finding(1, 'src/a.ts'), finding(2)];
    const { plan, tasks, planned } = run(base({ findings }));
    expect(planned.not_eligible).toHaveLength(1);
    const report = computeReport(plan, tasks);
    expect(report.not_planned).toEqual([]);
    expect(report.coverage).toBe('full');
  });

  it('file-group overflow makes coverage partial too', () => {
    const code_files = Array.from({ length: 30 }, (_, i) => `src/m${i}.ts`);
    const { plan, tasks, planned } = run(base({ modes: ['hunt'], code_files, limits: limits(3) }));
    expect(planned.tasks).toHaveLength(3);
    expect(planned.set_aside.length).toBeGreaterThan(0);
    expect(computeReport(plan, tasks).coverage).toBe('partial');
  });
});

describe('the crosscut task counts against max_tasks', () => {
  it('max_tasks 0 plans nothing and says why', () => {
    const planned = buildPlan(base({ modes: ['hunt'], code_files: ['src/a.ts'], limits: limits(0) }));
    expect(planned.tasks).toEqual([]);
    expect(planned.nothing_to_plan ?? '').toContain('max_tasks');
  });

  it('max_tasks 1 with a hunt never plans more than the limit', () => {
    const planned = buildPlan(base({ modes: ['hunt'], code_files: ['src/a.ts', 'src/b.ts'], limits: limits(1) }));
    expect(planned.tasks.length).toBeLessThanOrEqual(1);
  });
});

describe('a verify task born of a hunt finding says so in the report', () => {
  it('demoted carries origin_task_id', () => {
    const { plan, tasks } = run(base({ findings: [finding(1, 'src/a.ts')] }));
    const t = tasks[0];
    if (t === undefined) throw new Error('no task');
    t.target = { ...t.target, origin_task_id: 't-0009' };
    const report = computeReport(plan, tasks);
    expect(report.demoted[0]?.origin_task_id).toBe('t-0009');
    expect(report.hunt_findings[0]?.sources).toEqual(['t-0009']);
  });
});
