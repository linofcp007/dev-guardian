/**
 * The planner is pure: findings, a surface snapshot and limits in, tasks out.
 *
 * T-17 (US-2.AC-1), T-18 (US-2.AC-2, EC-3).
 */

import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { describe, expect, it } from 'vitest';
import { MAX_ROUTES_PER_HUNT_TASK, buildPlan, entryPointId, type PlanInput, type PlanResult } from '../../../src/llmscan/plan.js';
import { computeReport } from '../../../src/llmscan/report.js';
import { LLM_SCAN_DEFAULTS, type LlmScanPlan, type LlmScanTask } from '../../../src/llmscan/types.js';
import { makeFinding } from '../../../src/runners/scannerParsers/index.js';
import type { AttackSurfaceSnapshot, RouteRecord } from '../../../src/types.js';

/** Never touched: the planner does no I/O. */
const ROOT = resolve(tmpdir(), 'llm-plan-root-never-created');

const LIMITS = {
  max_tasks: LLM_SCAN_DEFAULTS.max_tasks,
  max_estimated_tokens: LLM_SCAN_DEFAULTS.max_estimated_tokens,
  per_task_overhead: LLM_SCAN_DEFAULTS.per_task_overhead,
};

function route(method: RouteRecord['method'], path: string, rel: string, line: number): RouteRecord {
  return {
    method,
    provenance: 'code',
    path_raw: path,
    path_resolved: path,
    path_partial: false,
    file: join(ROOT, rel),
    line,
    framework: 'express',
    language: 'typescript',
    auth_hint: 'unknown',
    params: [],
    confidence: 'high',
  };
}

function snapshot(routes: RouteRecord[]): { id: number; snapshot: AttackSurfaceSnapshot } {
  return {
    id: 7,
    snapshot: {
      routes,
      env_vars: [],
      ports: [],
      webhooks: [],
      coverage: [],
      tools_run: [{ name: 'semgrep', status: 'ok' }],
      missing_tools: [],
      spec_files: [],
      spec_diff: null,
      imports: [],
    },
  };
}

function input(over: Partial<PlanInput>): PlanInput {
  return {
    project_path: ROOT,
    modes: ['hunt'],
    findings: [],
    surface: null,
    code_files: [],
    limits: LIMITS,
    ...over,
  };
}

const USERS = [
  route('GET', '/users', 'src/routes/users.ts', 6),
  route('GET', '/users/:id', 'src/routes/users.ts', 10),
  route('POST', '/users', 'src/routes/users.ts', 16),
  route('PUT', '/users/:id', 'src/routes/users.ts', 22),
  route('DELETE', '/users/:id', 'src/routes/users.ts', 27),
  route('GET', '/users/:id/export', 'src/routes/users.ts', 32),
  route('PATCH', '/users/:id/role', 'src/routes/users.ts', 40),
];
const FILES = [
  route('GET', '/files/:name', 'src/routes/files.ts', 9),
  route('POST', '/files/upload', 'src/routes/files.ts', 15),
  route('DELETE', '/files/:name', 'src/routes/files.ts', 21),
];
const ADMIN = [route('GET', '/admin/stats', 'src/routes/admin.ts', 7)];
const ALL = [...USERS, ...FILES, ...ADMIN];

const huntTasks = (p: PlanResult): PlanResult['tasks'] => p.tasks.filter((t) => t.kind === 'hunt');

describe('T-17 hunt plan: one task per group of at most 5 routes of one handler file, and one cross-cutting task (US-2.AC-1)', () => {
  it('T-17 groups routes by handler file, at most 5 per task, every route exactly once', () => {
    expect(MAX_ROUTES_PER_HUNT_TASK).toBe(5);
    const plan = buildPlan(input({ surface: snapshot(ALL) }));
    const fileOf = new Map(ALL.map((r) => [entryPointId(r, ROOT), r.file]));
    expect(fileOf.size).toBe(ALL.length); // ids are distinct

    const seen: string[] = [];
    for (const t of huntTasks(plan)) {
      const eps = t.target.entry_points ?? [];
      expect(eps.length, t.task_id).toBeGreaterThanOrEqual(1);
      expect(eps.length, t.task_id).toBeLessThanOrEqual(MAX_ROUTES_PER_HUNT_TASK);
      const files = new Set(eps.map((ep) => fileOf.get(ep)));
      expect(files.size, `${t.task_id} mixes handler files`).toBe(1);
      expect(files.has(undefined), `${t.task_id} names an entry point no route has`).toBe(false);
      seen.push(...eps);
    }
    expect(seen.sort()).toEqual([...fileOf.keys()].sort());
    // 7 + 3 + 1 routes: ceil(7/5) + 1 + 1.
    expect(huntTasks(plan)).toHaveLength(4);
  });

  it('T-17 adds exactly one cross-cutting task', () => {
    const plan = buildPlan(input({ surface: snapshot(ALL) }));
    expect(plan.tasks.filter((t) => t.kind === 'crosscut')).toHaveLength(1);
  });

  it('T-17 names files project-relative, POSIX, the handler file among them', () => {
    const plan = buildPlan(input({ surface: snapshot(ALL) }));
    const handlerOf = new Map(ALL.map((r) => [entryPointId(r, ROOT), r.file]));
    for (const t of huntTasks(plan)) {
      expect(t.target.files.length, t.task_id).toBeGreaterThan(0);
      for (const f of t.target.files) {
        expect(f, t.task_id).not.toMatch(/^([A-Za-z]:|\/|\\)/);
        expect(f, t.task_id).not.toContain('\\');
        expect(f.startsWith('..'), t.task_id).toBe(false);
      }
      const first = (t.target.entry_points ?? [])[0];
      const abs = first === undefined ? undefined : handlerOf.get(first);
      const rel = abs === undefined ? '' : abs.slice(ROOT.length + 1).replace(/\\/g, '/');
      expect(t.target.files, t.task_id).toContain(rel);
    }
  });

  it('T-17 gives tasks sequential, unique ids', () => {
    const plan = buildPlan(input({ surface: snapshot(ALL) }));
    const ids = plan.tasks.map((t) => t.task_id);
    expect(ids).toEqual(ids.map((_, i) => `t-${String(i + 1).padStart(4, '0')}`));
  });

  it('T-17 plans no verify task unless verify was asked for; both when both were', () => {
    const f = makeFinding({ tool: 'semgrep', rule_id: 'r', severity: 'high', category: 'security', title: 't', file_path: 'src/routes/users.ts', line_start: 12 });
    expect(buildPlan(input({ surface: snapshot(ALL), findings: [f] })).tasks.some((t) => t.kind === 'verify')).toBe(false);
    const both = buildPlan(input({ modes: ['verify', 'hunt'], surface: snapshot(ALL), findings: [f] }));
    expect(both.tasks.filter((t) => t.kind === 'verify').map((t) => t.target.fingerprint)).toEqual([f.fingerprint]);
    expect(huntTasks(both)).toHaveLength(4);
  });
});

describe('T-18 no entry points: tasks by groups of code files, said in the plan, never full coverage; nothing at all: nothing_to_plan (US-2.AC-2, EC-3)', () => {
  const CODE = Array.from({ length: 12 }, (_, i) => `src/lib/module${i}.ts`);

  it('T-18 with zero entry points, the hunt covers every code file exactly once, in file-group tasks', () => {
    const plan = buildPlan(input({ surface: snapshot([]), code_files: CODE }));
    expect(plan.nothing_to_plan).toBeNull();
    const groups = huntTasks(plan);
    expect(groups.length).toBeGreaterThan(0);
    const covered: string[] = [];
    for (const t of groups) {
      expect(t.target.entry_points ?? [], t.task_id).toEqual([]);
      expect(t.target.files.length, t.task_id).toBeGreaterThan(0);
      covered.push(...t.target.files);
    }
    expect(covered.sort()).toEqual([...CODE].sort());
  });

  it('T-18 the plan says that no entry point was found', () => {
    const plan = buildPlan(input({ surface: snapshot([]), code_files: CODE }));
    expect(plan.notes.some((n) => /entry.?points?/i.test(n)), JSON.stringify(plan.notes)).toBe(true);
  });

  it('T-18 a hunt with zero entry points never reports full coverage, even with every task closed', () => {
    const planned = buildPlan(input({ surface: snapshot([]), code_files: CODE }));
    const plan: LlmScanPlan = {
      id: 'plan-t18',
      project_path: ROOT,
      scan_id: 'scan-t18',
      modes: ['hunt'],
      prompt_version: 'v1',
      tree_hash: 'h',
      surface_snapshot_id: 7,
      limits: LIMITS,
      estimate: planned.estimate,
      confirmed: true,
      status: 'complete',
      not_eligible: [],
      set_aside: planned.set_aside,
      created_at: '2026-10-02T00:00:00.000Z',
      updated_at: '2026-10-02T00:00:00.000Z',
    };
    const tasks: LlmScanTask[] = planned.tasks.map((t) => ({
      plan_id: plan.id,
      task_id: t.task_id,
      kind: t.kind,
      target: t.target,
      status: 'closed',
      lease_token: null,
      lease_expires_at: null,
      attempts: 0,
      file_hashes: {},
      brief_chars: 1000,
      response_chars: 100,
      independence: 'subagent',
      result: { entry_points_reviewed: [], findings: [] },
      closed_reason: 'valid',
      delivered_at: '2026-10-02T00:00:01.000Z',
      closed_at: '2026-10-02T00:00:02.000Z',
    }));
    const report = computeReport(plan, tasks);
    expect(report.coverage).not.toBe('full');
    expect(report.notes.some((n) => /entry.?points?/i.test(n)), JSON.stringify(report.notes)).toBe(true);
  });

  it('T-18 EC-3: no entry points, no code files and no findings — an empty plan with the reason, never a clean one', () => {
    const plan = buildPlan(input({ modes: ['verify', 'hunt'], surface: snapshot([]), code_files: [], findings: [] }));
    expect(plan.tasks).toEqual([]);
    expect(typeof plan.nothing_to_plan).toBe('string');
    expect((plan.nothing_to_plan ?? '').trim()).not.toBe('');
  });
});
