/**
 * The LLM-scan tools' edges beyond the planned examples (task 5): the errors
 * the design's contract names, the preconditions the reviews of tasks 1–4
 * handed on (atomic hunt submission, explicit corrupt-plan error, typed
 * overflow, confirmation of an existing plan, stale at hand-out).
 */

import { appendFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { computeReport } from '../../src/llmscan/report.js';
import type { HuntResult, LlmScanPlan } from '../../src/llmscan/types.js';
import { cleanupTempDirs } from '../helpers/tempDir.js';
import { okResult } from '../helpers/toolResult.js';
import {
  PARAM_INSERT,
  callTool,
  emptyHunt,
  expectDomainError,
  harness,
  isTask,
  lease,
  leaseWhere,
  next,
  seedStandard,
  seedSurface,
  start,
  status,
  submit,
  submissionFixture,
  verdictAt,
  type SubmitOut,
} from '../helpers/llmScanHarness.js';

vi.setConfig({ testTimeout: 60_000 });
afterAll(cleanupTempDirs);
beforeAll(async () => {
  await import('../../src/registerAll.js');
});

describe('llm_scan_start errors', () => {
  it('needs_surface: a hunt with no attack surface snapshot', async () => {
    const h = harness();
    seedStandard(h);
    expectDomainError(await callTool(h, 'llm_scan_start', { project_path: h.project, modes: ['hunt'] }), 'needs_surface');
  });

  it('nothing_to_plan: no eligible finding, with the reason, and no plan is stored', async () => {
    const h = harness();
    const r = await callTool(h, 'llm_scan_start', { project_path: h.project, modes: ['verify'] });
    expectDomainError(r, 'nothing_to_plan');
    expect(h.repo.listPlans(h.project)).toEqual([]);
  });

  it('too_many_open_plans: the sixth plan is refused, naming the five active ones', async () => {
    const h = harness();
    seedStandard(h);
    const ids: string[] = [];
    for (let i = 0; i < 5; i += 1) ids.push((await start(h, { modes: ['verify'] })).plan_id);
    const r = await callTool(h, 'llm_scan_start', { project_path: h.project, modes: ['verify'] });
    expectDomainError(r, 'too_many_open_plans');
    for (const id of ids) expect(JSON.stringify(r)).toContain(id);
  });

  it('max_tasks below 1 is refused at the tool', async () => {
    const h = harness();
    seedStandard(h);
    expectDomainError(await callTool(h, 'llm_scan_start', { project_path: h.project, max_tasks: 0 }), 'invalid_input');
  });

  it('an unknown plan_id is not_found; an abandoned plan answers plan_abandoned on all three tools', async () => {
    const h = harness();
    seedStandard(h);
    expectDomainError(await callTool(h, 'llm_scan_start', { project_path: h.project, plan_id: 'nope' }), 'not_found');
    const out = await start(h, { modes: ['verify'] });
    const t = await lease(h, out.plan_id);
    expect(h.repo.updatePlan(out.plan_id, 'abandoned', new Date().toISOString())).toBe(true);
    expectDomainError(await callTool(h, 'llm_scan_start', { project_path: h.project, plan_id: out.plan_id }), 'plan_abandoned');
    expectDomainError(await callTool(h, 'llm_scan_task', { plan_id: out.plan_id }), 'plan_abandoned');
    expectDomainError(await submit(h, out.plan_id, t, verdictAt(PARAM_INSERT, 'real')), 'plan_abandoned');
  });

  it('a corrupt plan row is an explicit plan_corrupt, not "no such plan"', async () => {
    const h = harness();
    seedStandard(h);
    const out = await start(h, { modes: ['verify'] });
    h.db.prepare('UPDATE llm_scan_plans SET limits = ? WHERE id = ?').run('{not json', out.plan_id);
    expectDomainError(await callTool(h, 'llm_scan_task', { plan_id: out.plan_id }), 'plan_corrupt');
    expectDomainError(await callTool(h, 'llm_scan_start', { project_path: h.project, plan_id: out.plan_id }), 'plan_corrupt');
  });
});

describe('confirmation of an existing plan (US-4.AC-1)', () => {
  it('llm_scan_start { plan_id, confirm: true } confirms it, and the first task is then handed out', async () => {
    const h = harness();
    seedStandard(h);
    const over = await start(h, { modes: ['verify'], per_task_overhead: 300_000 });
    expect(over.needs_confirm).toBe(true);
    expectDomainError(await callTool(h, 'llm_scan_task', { plan_id: over.plan_id }), 'needs_confirm');
    const confirmed = okResult<{ needs_confirm: boolean }>(await callTool(h, 'llm_scan_start', { project_path: h.project, plan_id: over.plan_id, confirm: true }));
    expect(confirmed.needs_confirm).toBe(false);
    expect((await lease(h, over.plan_id)).kind).toBe('verify');
  });
});

describe('stale at hand-out (US-1.AC-9)', () => {
  it('a task whose file changed since planning is closed stale and never handed out', async () => {
    const h = harness();
    const s = seedStandard(h);
    const out = await start(h, { modes: ['verify'], fingerprints: [s.insert.fingerprint] });
    appendFileSync(join(h.project, PARAM_INSERT.file), '\n// edited after the plan was made\n');
    const r = await next(h, out.plan_id);
    expect(isTask(r)).toBe(false);
    const task = h.repo.listTasks(out.plan_id)[0];
    expect(task?.status).toBe('closed');
    expect(task?.closed_reason).toBe('stale');
    expect(task?.delivered_at).toBeNull();
    expect(h.storage.validations.listByProject(h.project).filter((v) => String(v.provider) === 'llm')).toEqual([]);
  });
});

describe('a hunt submission is atomic (US-2.AC-4)', () => {
  const huntValid = submissionFixture('hunt-valid.json') as HuntResult;

  it('when creating the verify tasks fails, the hunt task is not closed and no finding is stored without its task', async () => {
    const h = harness();
    await seedSurface(h);
    const out = await start(h, { modes: ['hunt'] });
    const t = await leaseWhere(h, out.plan_id, (x) => x.kind === 'hunt' && h.repo.getTask(out.plan_id, x.task_id)?.target.files.includes('src/routes/files.ts') === true);
    const payload = { ...emptyHunt(h, out.plan_id, t.task_id), findings: huntValid.findings };

    const spy = vi.spyOn(h.storage.llmScan, 'appendTasks').mockImplementation(() => {
      throw new Error('disk full');
    });
    try {
      expectDomainError(await submit(h, out.plan_id, t, payload), 'store_failed');
    } finally {
      spy.mockRestore();
    }
    expect(h.repo.getTask(out.plan_id, t.task_id)?.status).toBe('leased');
    expect(h.storage.findings.listByScan(out.scan_id).filter((f) => f.tool === 'llm-hunt')).toEqual([]);
    expect(h.repo.listTasks(out.plan_id).filter((x) => x.kind === 'verify')).toEqual([]);

    // Nothing was half-written: the same answer goes through, once.
    const again = okResult<SubmitOut & { verify_tasks_created: number }>(await submit(h, out.plan_id, t, payload));
    expect(again.accepted).toBe(true);
    expect(again.verify_tasks_created).toBe(2);
    expect(h.storage.findings.listByScan(out.scan_id).filter((f) => f.tool === 'llm-hunt')).toHaveLength(2);
  });

  it('the verify tasks of hunt findings are outside max_tasks', async () => {
    const h = harness();
    await seedSurface(h);
    // 4 hunt tasks + the cross-cutting one = 5; every one may be delivered, and then the findings' verify tasks too.
    const out = await start(h, { modes: ['hunt'], max_tasks: 5 });
    expect(out.tasks_total).toBe(5);
    const skipped: Awaited<ReturnType<typeof lease>>[] = [];
    const t = await leaseWhere(h, out.plan_id, (x) => x.kind === 'hunt' && h.repo.getTask(out.plan_id, x.task_id)?.target.files.includes('src/routes/files.ts') === true, skipped);
    expect(okResult<SubmitOut>(await submit(h, out.plan_id, t, { ...emptyHunt(h, out.plan_id, t.task_id), findings: huntValid.findings })).accepted).toBe(true);
    for (const x of skipped) okResult<SubmitOut>(await submit(h, out.plan_id, x, emptyHunt(h, out.plan_id, x.task_id)));
    for (let i = 0; i < 10; i += 1) {
      const x = await next(h, out.plan_id);
      if (!isTask(x)) break;
      if (x.kind === 'verify') {
        const row = h.storage.findings.listByScan(out.scan_id).find((f) => f.fingerprint === h.repo.getTask(out.plan_id, x.task_id)?.target.fingerprint);
        okResult<SubmitOut>(await submit(h, out.plan_id, x, verdictAt({ file: row?.file_path ?? '', line: row?.line_start ?? 0 }, 'real')));
      } else {
        okResult<SubmitOut>(await submit(h, out.plan_id, x, emptyHunt(h, out.plan_id, x.task_id)));
      }
    }
    expect((await status(h, out.plan_id)).report.hunt_findings.map((f) => f.status)).toEqual(['exploitable', 'exploitable']);
  });
});

describe('the report reads the typed overflow flag, with the prefix as fallback', () => {
  const plan = (not_eligible: LlmScanPlan['not_eligible']): LlmScanPlan => ({
    id: 'p',
    project_path: '/p',
    scan_id: 's',
    modes: ['verify'],
    prompt_version: 'v1',
    tree_hash: 'h',
    surface_snapshot_id: null,
    limits: { max_tasks: 1, max_estimated_tokens: 1, per_task_overhead: 0 },
    estimate: { tasks: 0, brief_tokens: 0, total_tokens: 0, assumptions: '' },
    confirmed: true,
    status: 'open',
    not_eligible,
    set_aside: [],
    created_at: '2026-10-02T00:00:00.000Z',
    updated_at: '2026-10-02T00:00:00.000Z',
  });

  it('overflow: true names a finding as not planned whatever its reason says', () => {
    const r = computeReport(plan([{ fingerprint: 'fp-1', reason: 'worded differently in a later release', overflow: true }]), []);
    expect(r.not_planned).toEqual(['fp-1']);
  });

  it('a finding with no file is not "not planned"', () => {
    expect(computeReport(plan([{ fingerprint: 'fp-2', reason: 'no file' }]), []).not_planned).toEqual([]);
  });
});
