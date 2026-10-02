/**
 * The LLM-assisted scan end to end through its three tools — `llm_scan_start`,
 * `llm_scan_task`, `llm_scan_submit` — on a copy of the fixture project, with
 * fixture verdicts and hunt results standing in for the host's model.
 *
 * T-01, T-04, T-05, T-09, T-19, T-20, T-22, T-26 – T-32.
 */

import { appendFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { openSetForProject } from '../../src/history/openSet.js';
import { entryPointId } from '../../src/llmscan/plan.js';
import type { HuntResult, VerifyVerdict } from '../../src/llmscan/types.js';
import { cleanupTempDirs } from '../helpers/tempDir.js';
import { okResult } from '../helpers/toolResult.js';
import {
  PARAM_INSERT,
  at,
  callTool,
  emptyHunt,
  expectDomainError,
  fakeSampling,
  fixtureRoutes,
  harness,
  isTask,
  lease,
  leaseWhere,
  locOfTask,
  next,
  reopen,
  responseTokens,
  samplingMeta,
  seedMany,
  seedStandard,
  seedSurface,
  start,
  status,
  submissionFixture,
  submit,
  verdictAt,
  type Harness,
  type Loc,
  type SamplingOut,
  type SubmitOut,
  type TaskOut,
} from '../helpers/llmScanHarness.js';

vi.setConfig({ testTimeout: 60_000 });
afterAll(cleanupTempDirs);
beforeAll(async () => {
  await import('../../src/registerAll.js');
});

const PER_TASK_OVERHEAD = 60_000;

/** Submits a valid verdict for `t`: `not_real` for the parameterised INSERT, `real` otherwise. */
async function answer(h: Harness, planId: string, t: TaskOut, locs: ReadonlyMap<string, Loc>): Promise<SubmitOut> {
  const loc = locOfTask(h, planId, t.task_id, locs);
  const verdict = loc === PARAM_INSERT ? 'not_real' : 'real';
  return okResult<SubmitOut>(await submit(h, planId, t, verdictAt(loc, verdict)));
}

describe('T-01 llm_scan_start plans one verify task per eligible finding, before handing any out (US-1.AC-1, EC-1)', () => {
  it('T-01 one task per finding with a file and a line; the CVE with no file is not_eligible, with the reason', async () => {
    const h = harness();
    const s = seedStandard(h);
    const out = await start(h, { modes: ['verify'] });
    expect(out.tasks_total).toBe(3);
    expect(out.by_kind.verify).toBe(3);
    expect(out.not_eligible.map((x) => x.fingerprint)).toEqual([s.cve.fingerprint]);
    expect(out.not_eligible[0]?.reason.trim()).not.toBe('');
    expect(out.prompt_version).toBe('v1');
    const tasks = h.repo.listTasks(out.plan_id);
    expect(tasks.map((t) => t.kind)).toEqual(['verify', 'verify', 'verify']);
    expect(tasks.map((t) => t.target.fingerprint).sort()).toEqual([s.sqli, s.insert, s.shell].map((f) => f.fingerprint).sort());
  });

  it('T-01 returns the token estimate — brief tokens plus the per-task overhead, with its assumptions — and hands nothing out yet', async () => {
    const h = harness();
    seedStandard(h);
    const out = await start(h, { modes: ['verify'] });
    expect(out.estimate.tasks).toBe(3);
    expect(out.estimate.brief_tokens).toBeGreaterThan(0);
    expect(out.estimate.total_tokens).toBe(out.estimate.brief_tokens + 3 * PER_TASK_OVERHEAD);
    expect(out.estimate.assumptions.trim()).not.toBe('');
    expect(out.needs_confirm).toBe(false);
    for (const t of h.repo.listTasks(out.plan_id)) {
      expect(t.status).toBe('open');
      expect(t.delivered_at).toBeNull();
      expect(t.brief_chars).toBeNull();
    }
    expect(h.repo.getPlan(out.plan_id)?.modes).toEqual(['verify']);
  });

  it('T-01 plans from a list of findings, or from one scan', async () => {
    const h = harness();
    const s = seedStandard(h);
    const one = await start(h, { modes: ['verify'], fingerprints: [s.sqli.fingerprint] });
    expect(one.tasks_total).toBe(1);
    const fromScan = await start(h, { modes: ['verify'], scan_id: s.sastScanId });
    expect(fromScan.tasks_total).toBe(3);
    expect(fromScan.not_eligible).toEqual([]);
  });
});

describe('T-04 an invalid verdict is refused with the reason; two more tries; then undetermined, invalid_submissions (US-1.AC-4)', () => {
  it('T-04 refused with the reason, the task stays with its holder, and a valid resubmission closes it', async () => {
    const h = harness();
    const s = seedStandard(h);
    const out = await start(h, { modes: ['verify'] });
    const t = await lease(h, out.plan_id);

    const bad = okResult<SubmitOut>(await submit(h, out.plan_id, t, submissionFixture('verify-bad-enum.json')));
    expect(bad.accepted).toBe(false);
    expect(bad.errors?.some((e) => e.path === 'verdict' && e.problem.trim() !== '')).toBe(true);
    expect(bad.attempts_left).toBe(2);
    const held = h.repo.getTask(out.plan_id, t.task_id);
    expect(held?.status).toBe('leased');
    expect(held?.attempts).toBe(1);

    const good = await answer(h, out.plan_id, t, s.locs);
    expect(good.accepted).toBe(true);
    expect(h.repo.getTask(out.plan_id, t.task_id)?.closed_reason).toBe('valid');
  });

  it('T-04 the third invalid submission closes the task as undetermined, invalid_submissions', async () => {
    const h = harness();
    seedStandard(h);
    const out = await start(h, { modes: ['verify'] });
    const t = await lease(h, out.plan_id);
    const left: Array<number | undefined> = [];
    for (const name of ['verify-bad-enum.json', 'verify-missing-field.json', 'verify-long-reasoning.json']) {
      const r = okResult<SubmitOut>(await submit(h, out.plan_id, t, submissionFixture(name)));
      expect(r.accepted).toBe(false);
      left.push(r.attempts_left);
    }
    expect(left).toEqual([2, 1, 0]);
    const closed = h.repo.getTask(out.plan_id, t.task_id);
    expect(closed?.status).toBe('closed');
    expect(closed?.closed_reason).toBe('invalid_submissions');
    expect((await status(h, out.plan_id)).report.counts.by_verdict.undetermined).toBe(1);
  });
});

describe('T-05 when every task closes, verdicts are stored (provider llm) and the counts and coverage computed in code (US-1.AC-5)', () => {
  it('T-05 three verdicts, three finding_validations rows; the report counts them; coverage full', async () => {
    const h = harness();
    const s = seedStandard(h);
    const out = await start(h, { modes: ['verify'] });
    for (let i = 0; i < 3; i += 1) expect((await answer(h, out.plan_id, await lease(h, out.plan_id), s.locs)).accepted).toBe(true);

    const rows = h.storage.validations
      .listByProject(h.project)
      .filter((v) => String(v.provider) === 'llm')
      .map((v) => [v.fingerprint, String(v.verdict)]);
    expect(rows.sort()).toEqual(
      [
        [s.sqli.fingerprint, 'exploitable'],
        [s.insert.fingerprint, 'not_exploitable'],
        [s.shell.fingerprint, 'exploitable'],
      ].sort(),
    );

    const end = await next(h, out.plan_id);
    expect(isTask(end)).toBe(false);
    if (isTask(end)) return;
    expect(end.report.coverage).toBe('full');
    expect(end.report.counts.by_verdict).toEqual({ exploitable: 2, not_exploitable: 1, undetermined: 0 });
    expect(end.report.tasks.planned).toBe(3);
    expect(end.report.tasks.closed).toBe(3);
    expect(end.report.missing).toEqual([]);
    expect(h.repo.getPlan(out.plan_id)?.status).toBe('complete');
  });
});

describe('T-09 a file changed between the plan and the verdict: stale, and no demotion (US-1.AC-9)', () => {
  it('T-09 the verdict closes the task as stale and demotes nothing', async () => {
    const h = harness();
    const s = seedStandard(h);
    const out = await start(h, { modes: ['verify'] });
    const t = await leaseWhere(h, out.plan_id, (x) => h.repo.getTask(out.plan_id, x.task_id)?.target.fingerprint === s.insert.fingerprint);
    appendFileSync(join(h.project, PARAM_INSERT.file), '\n// edited after the plan was made\n');

    const r = okResult<SubmitOut>(await submit(h, out.plan_id, t, verdictAt(PARAM_INSERT, 'not_real')));
    expect(r.accepted).toBe(true);
    expect(h.repo.getTask(out.plan_id, t.task_id)?.closed_reason).toBe('stale');
    expect((await status(h, out.plan_id)).report.demoted.map((d) => d.fingerprint)).not.toContain(s.insert.fingerprint);

    const triage = okResult<{ likely_false_positive: Array<{ fingerprint: string }>; keep: Array<{ fingerprint: string }> }>(
      await callTool(h, 'triage_findings', { project_path: h.project }),
    );
    expect(triage.likely_false_positive.map((b) => b.fingerprint)).not.toContain(s.insert.fingerprint);
    expect(triage.keep.map((b) => b.fingerprint)).toContain(s.insert.fingerprint);
  });
});

describe('T-19 hunt findings are validated one by one and stored as llm-hunt findings with a stable identity (US-2.AC-3, EC-4)', () => {
  const huntValid = submissionFixture('hunt-valid.json') as HuntResult;
  const badClass = (submissionFixture('hunt-bad-class.json') as HuntResult).findings[0];
  const noEvidence = (submissionFixture('hunt-no-evidence-ref.json') as HuntResult).findings[0];

  async function huntPlan(h: Harness): Promise<string> {
    await seedSurface(h);
    const out = await start(h, { modes: ['hunt'] });
    expect(out.by_kind.hunt).toBe(4); // users.ts: 6 routes = 2 tasks; files.ts; admin.ts
    expect(out.by_kind.crosscut).toBe(1);
    return out.plan_id;
  }

  const onFiles = (h: Harness, planId: string) => (t: TaskOut): boolean =>
    h.repo.getTask(planId, t.task_id)?.target.files.includes('src/routes/files.ts') === true && t.kind === 'hunt';

  it('T-19 the valid findings are stored as llm-hunt (class as the rule), the invalid ones named and dropped', async () => {
    const h = harness();
    const planId = await huntPlan(h);
    const scanId = h.repo.getPlan(planId)?.scan_id ?? '';
    const t = await leaseWhere(h, planId, onFiles(h, planId));
    const payload = { ...emptyHunt(h, planId, t.task_id), findings: [...huntValid.findings, badClass, noEvidence] };

    const r = okResult<SubmitOut>(await submit(h, planId, t, payload));
    expect(r.accepted).toBe(true);
    const rejectedPaths = (r.rejected ?? []).map((e) => e.path);
    expect(rejectedPaths.some((p) => p.startsWith('findings[2]'))).toBe(true);
    expect(rejectedPaths.some((p) => p.startsWith('findings[3]'))).toBe(true);

    const rows = h.storage.findings.listByScan(scanId).filter((f) => f.tool === 'llm-hunt');
    expect(rows.map((f) => [f.file_path, f.line_start, f.rule_id]).sort()).toEqual([
      ['src/routes/admin.ts', 7, 'broken-access-control'],
      ['src/routes/files.ts', 11, 'path-traversal'],
    ]);
    for (const f of rows) expect(typeof f.identity === 'string' && f.identity.length > 0, f.fingerprint).toBe(true);
  });

  it('T-19 EC-4: the same finding from two hunt tasks is one finding, with both tasks as its source', async () => {
    const h = harness();
    const planId = await huntPlan(h);
    const scanId = h.repo.getPlan(planId)?.scan_id ?? '';
    const t1 = await leaseWhere(h, planId, onFiles(h, planId));
    expect(okResult<SubmitOut>(await submit(h, planId, t1, { ...emptyHunt(h, planId, t1.task_id), findings: huntValid.findings })).accepted).toBe(true);
    const admin = huntValid.findings[1];
    if (admin === undefined) throw new Error('fixture');
    const t2 = await leaseWhere(h, planId, (t) => t.kind === 'crosscut');
    expect(okResult<SubmitOut>(await submit(h, planId, t2, { entry_points_reviewed: [], findings: [admin] })).accepted).toBe(true);

    const rows = h.storage.findings.listByScan(scanId).filter((f) => f.tool === 'llm-hunt');
    expect(rows).toHaveLength(2);
    const adminRow = rows.find((f) => f.file_path === 'src/routes/admin.ts');
    expect(adminRow).toBeDefined();
    const verifiers = h.repo.listTasks(planId).filter((t) => t.kind === 'verify' && t.target.fingerprint === adminRow?.fingerprint);
    expect(verifiers).toHaveLength(1);
    const account = (await status(h, planId)).report.hunt_findings.find((x) => x.fingerprint === adminRow?.fingerprint);
    expect([...(account?.sources ?? [])].sort()).toEqual([t1.task_id, t2.task_id].sort());
  });
});

describe('T-20 each stored hunt finding gets a verify task of its own and stays unverified until a verdict (US-2.AC-4)', () => {
  it('T-20 unverified hunt findings stay out of the open set; an independent real lets one in, a same_context one does not', async () => {
    const h = harness();
    await seedSurface(h);
    const out = await start(h, { modes: ['hunt'] });
    const skipped: TaskOut[] = [];
    const t = await leaseWhere(
      h,
      out.plan_id,
      (x) => x.kind === 'hunt' && h.repo.getTask(out.plan_id, x.task_id)?.target.files.includes('src/routes/files.ts') === true,
      skipped,
    );
    const huntValid = submissionFixture('hunt-valid.json') as HuntResult;
    expect(okResult<SubmitOut>(await submit(h, out.plan_id, t, { ...emptyHunt(h, out.plan_id, t.task_id), findings: huntValid.findings })).accepted).toBe(true);
    for (const x of skipped) okResult<SubmitOut>(await submit(h, out.plan_id, x, emptyHunt(h, out.plan_id, x.task_id)));

    const rows = h.storage.findings.listByScan(out.scan_id).filter((f) => f.tool === 'llm-hunt');
    expect(rows).toHaveLength(2);
    const verifiers = h.repo.listTasks(out.plan_id).filter((x) => x.kind === 'verify');
    expect(verifiers.map((x) => x.target.fingerprint).sort()).toEqual(rows.map((f) => f.fingerprint).sort());
    for (const v of verifiers) expect(v.target.origin_task_id).toBe(t.task_id);
    expect(openSetForProject(h.storage, h.project).findings.filter((f) => f.tool === 'llm-hunt')).toEqual([]);
    expect((await status(h, out.plan_id)).report.hunt_findings.map((x) => x.status)).toEqual(['unverified', 'unverified']);

    const traversal = rows.find((f) => f.file_path === 'src/routes/files.ts');
    const admin = rows.find((f) => f.file_path === 'src/routes/admin.ts');
    if (traversal === undefined || admin === undefined) throw new Error('rows');
    for (let i = 0; i < 50; i += 1) {
      const x = await next(h, out.plan_id);
      if (!isTask(x)) break;
      if (x.kind !== 'verify') {
        okResult<SubmitOut>(await submit(h, out.plan_id, x, emptyHunt(h, out.plan_id, x.task_id)));
        continue;
      }
      const fp = h.repo.getTask(out.plan_id, x.task_id)?.target.fingerprint;
      const row = fp === traversal.fingerprint ? traversal : admin;
      const loc: Loc = { file: row.file_path ?? '', line: row.line_start ?? 0 };
      // The admin finding is "confirmed" in the hunter's own context: shown, never counted.
      const independence = row === admin ? 'same_context' : 'subagent';
      expect(okResult<SubmitOut>(await submit(h, out.plan_id, x, verdictAt(loc, 'real'), independence)).accepted).toBe(true);
    }

    const open = openSetForProject(h.storage, h.project).findings.filter((f) => f.tool === 'llm-hunt');
    expect(open.map((f) => f.fingerprint)).toEqual([traversal.fingerprint]);
    const accounts = (await status(h, out.plan_id)).report.hunt_findings;
    expect(accounts.find((x) => x.fingerprint === traversal.fingerprint)).toMatchObject({ status: 'exploitable', independent: true });
    expect(accounts.find((x) => x.fingerprint === admin.fingerprint)).toMatchObject({ status: 'exploitable', independent: false });
  });
});

describe('T-22 every entry point is accounted for: visited, with its task, or listed as not visited (US-2.AC-6)', () => {
  it('T-22 one hunt task left open: its entry points are not visited and named; once it closes, all are visited and coverage is full', async () => {
    const h = harness();
    await seedSurface(h);
    const out = await start(h, { modes: ['hunt'] });
    const ids = fixtureRoutes(h.project).map((r) => entryPointId(r, h.project));

    const skipped: TaskOut[] = [];
    const left = await leaseWhere(h, out.plan_id, (t) => t.kind === 'hunt', skipped);
    const leftEps = h.repo.getTask(out.plan_id, left.task_id)?.target.entry_points ?? [];
    expect(leftEps.length).toBeGreaterThan(0);
    for (const t of skipped) okResult<SubmitOut>(await submit(h, out.plan_id, t, emptyHunt(h, out.plan_id, t.task_id)));
    // Every other task, handed out and answered — counted, so no call is made
    // while the one left behind is the only task not closed.
    const toHandOut = h.repo.listTasks(out.plan_id).filter((t) => t.status === 'open').length;
    for (let i = 0; i < toHandOut; i += 1) {
      const t = await lease(h, out.plan_id);
      okResult<SubmitOut>(await submit(h, out.plan_id, t, emptyHunt(h, out.plan_id, t.task_id)));
    }

    const mid = (await status(h, out.plan_id)).report;
    expect(mid.entry_points.map((e) => e.entry_point).sort()).toEqual([...ids].sort());
    for (const e of mid.entry_points) {
      if (leftEps.includes(e.entry_point)) {
        expect(e.status).toBe('not_visited');
      } else {
        expect(e.status).toBe('visited');
        const by = h.repo.getTask(out.plan_id, e.task_id ?? '');
        expect(by?.status).toBe('closed');
        expect(by?.target.entry_points ?? []).toContain(e.entry_point);
      }
    }
    expect([...mid.not_visited].sort()).toEqual([...leftEps].sort());
    expect(mid.coverage).toBe('partial');

    okResult<SubmitOut>(await submit(h, out.plan_id, left, emptyHunt(h, out.plan_id, left.task_id)));
    const end = (await status(h, out.plan_id)).report;
    expect(end.entry_points.every((e) => e.status === 'visited')).toBe(true);
    expect(end.not_visited).toEqual([]);
    expect(end.coverage).toBe('full');
  });
});

describe('T-26 a client with sampling: verify tasks run through it and are recorded as sampling (US-3.AC-2)', () => {
  it('T-26 execute: sampling runs every verify task through the client and records the sampling independence', async () => {
    const h = harness();
    const s = seedStandard(h);
    const out = await start(h, { modes: ['verify'] });
    const fake = fakeSampling(s.locs, (loc) => verdictAt(loc, loc === PARAM_INSERT ? 'not_real' : 'real'));

    const r = okResult<SamplingOut>(await callTool(h, 'llm_scan_task', { plan_id: out.plan_id, execute: 'sampling' }, samplingMeta(fake.fn)));
    expect(r.executed).toBe(3);
    expect(r.remaining).toBe(0);
    expect(fake.requests).toHaveLength(3);
    for (const loc of s.locs.values()) expect(fake.requests.some((q) => q.includes(at(loc)))).toBe(true);
    expect(r.report.counts.by_independence.sampling).toBe(3);
    for (const t of h.repo.listTasks(out.plan_id)) {
      expect(t.independence).toBe('sampling');
      expect(t.closed_reason).toBe('valid');
    }
  });

  it('T-26 a client without the capability: sampling_unavailable, and nothing is handed out', async () => {
    const h = harness();
    seedStandard(h);
    const out = await start(h, { modes: ['verify'] });
    expectDomainError(await callTool(h, 'llm_scan_task', { plan_id: out.plan_id, execute: 'sampling' }), 'sampling_unavailable');
    for (const t of h.repo.listTasks(out.plan_id)) expect(t.status).toBe('open');
  });
});

describe('T-27 every call answers within its budget and its size (US-3.AC-3, NFR-3)', () => {
  it('T-27 sampling starts no task once its time budget is spent, and returns the progress', async () => {
    const h = harness();
    const locs = seedMany(h, 8);
    const out = await start(h, { modes: ['verify'] });
    expect(out.tasks_total).toBe(8);
    // Each sampled task takes 20 s of (fake) time; a call may not run past 60 s.
    // The budget is the clock's — Date, performance, hrtime or a timer, all faked here.
    vi.useFakeTimers({
      shouldAdvanceTime: true,
      toFake: ['Date', 'performance', 'hrtime', 'setTimeout', 'clearTimeout', 'setInterval', 'clearInterval'],
    });
    try {
      const fake = fakeSampling(locs, (loc) => verdictAt(loc, 'real'), () => vi.advanceTimersByTime(20_000));
      let remaining = 8;
      let calls = 0;
      while (remaining > 0 && calls < 10) {
        const before = fake.requests.length;
        const r = okResult<SamplingOut>(await callTool(h, 'llm_scan_task', { plan_id: out.plan_id, execute: 'sampling' }, samplingMeta(fake.fn)));
        const ran = fake.requests.length - before;
        expect(r.executed).toBe(ran);
        expect(r.executed).toBeGreaterThanOrEqual(1);
        expect(r.executed * 20_000).toBeLessThanOrEqual(60_000);
        expect(r.remaining).toBe(remaining - r.executed);
        if (r.remaining > 0) expect(r.report.coverage).toBe('partial');
        remaining = r.remaining;
        calls += 1;
      }
      expect(remaining).toBe(0);
      expect(calls).toBeGreaterThan(1); // the budget really cut a call short
    } finally {
      vi.useRealTimers();
    }
  });

  it('T-27 no response exceeds 25 000 estimated tokens, even for a 200-task plan', async () => {
    const h = harness();
    const locs = seedMany(h, 200);
    const startRaw = await callTool(h, 'llm_scan_start', {
      project_path: h.project,
      modes: ['verify'],
      confirm: true,
      max_estimated_tokens: 50_000_000,
    });
    const out = okResult<{ plan_id: string; tasks_total: number }>(startRaw);
    expect(out.tasks_total).toBe(200);
    const sizes: Array<[string, number]> = [['llm_scan_start', responseTokens('llm_scan_start', startRaw)]];

    const taskRaw = await callTool(h, 'llm_scan_task', { plan_id: out.plan_id });
    sizes.push(['llm_scan_task', responseTokens('llm_scan_task', taskRaw)]);
    const t = okResult<TaskOut>(taskRaw);
    const badRaw = await submit(h, out.plan_id, t, { verdict: 'x'.repeat(5000), attacker_input: 7, operation: [], extra: 'y'.repeat(20_000) });
    sizes.push(['llm_scan_submit (refused)', responseTokens('llm_scan_submit', badRaw)]);
    const loc = locOfTask(h, out.plan_id, t.task_id, locs);
    const goodRaw = await submit(h, out.plan_id, t, verdictAt(loc, 'real'));
    sizes.push(['llm_scan_submit', responseTokens('llm_scan_submit', goodRaw)]);
    const statusRaw = await callTool(h, 'llm_scan_start', { project_path: h.project, plan_id: out.plan_id });
    sizes.push(['llm_scan_start (status)', responseTokens('llm_scan_start', statusRaw)]);

    for (const [name, tokens] of sizes) expect(tokens, name).toBeLessThanOrEqual(25_000);
  });
});

describe('T-28 an abandoned plan resumes from the database after a restart, and its partial report says what is missing (US-3.AC-4, NFR-2)', () => {
  it('T-28 reopened, the plan answers by plan_id, names the missing tasks, honours the old lease and finishes', async () => {
    const h = harness({ dbFile: true });
    const s = seedStandard(h);
    const out = await start(h, { modes: ['verify'] });
    const t1 = await lease(h, out.plan_id);
    expect((await answer(h, out.plan_id, t1, s.locs)).accepted).toBe(true);
    const t2 = await lease(h, out.plan_id);

    const h2 = reopen(h);
    const mid = (await status(h2, out.plan_id)).report;
    expect(mid.coverage).toBe('partial');
    const notClosed = h2.repo.listTasks(out.plan_id).filter((t) => t.task_id !== t1.task_id).map((t) => t.task_id);
    expect(notClosed).toHaveLength(2);
    expect([...mid.missing].sort()).toEqual([...notClosed].sort());

    expect((await answer(h2, out.plan_id, t2, s.locs)).accepted).toBe(true);
    const t3 = await lease(h2, out.plan_id);
    expect((await answer(h2, out.plan_id, t3, s.locs)).accepted).toBe(true);
    expect((await status(h2, out.plan_id)).report.coverage).toBe('full');
  });
});

describe('T-29 an estimate above the limit needs confirm: true before the first task (US-4.AC-1)', () => {
  it('T-29 over the limit: needs_confirm, and llm_scan_task refuses; confirmed, the first task is handed out', async () => {
    const h = harness();
    seedStandard(h);
    // 3 tasks x 300 000 > 500 000, the default limit.
    const over = await start(h, { modes: ['verify'], per_task_overhead: 300_000 });
    expect(over.estimate.total_tokens).toBeGreaterThan(500_000);
    expect(over.needs_confirm).toBe(true);
    expectDomainError(await callTool(h, 'llm_scan_task', { plan_id: over.plan_id }), 'needs_confirm');
    for (const t of h.repo.listTasks(over.plan_id)) expect(t.status).toBe('open');

    const confirmed = await start(h, { modes: ['verify'], per_task_overhead: 300_000, confirm: true });
    expect(confirmed.needs_confirm).toBe(false);
    expect((await lease(h, confirmed.plan_id)).kind).toBe('verify');
  });

  it('T-29 under the limit: no confirmation asked', async () => {
    const h = harness();
    seedStandard(h);
    const out = await start(h, { modes: ['verify'] });
    expect(out.needs_confirm).toBe(false);
    expect((await lease(h, out.plan_id)).kind).toBe('verify');
  });
});

describe('T-30 a limit reached stops delivery: limit_reached, coverage partial, the undelivered tasks named (US-4.AC-2)', () => {
  it('T-30 the task limit', async () => {
    const h = harness();
    const s = seedStandard(h);
    const out = await start(h, { modes: ['verify'], max_tasks: 2 });
    const a = await lease(h, out.plan_id);
    const b = await lease(h, out.plan_id);
    const stopped = await callTool(h, 'llm_scan_task', { plan_id: out.plan_id });
    expectDomainError(stopped, 'limit_reached');
    const undelivered = h.repo
      .listTasks(out.plan_id)
      .map((t) => t.task_id)
      .filter((id) => id !== a.task_id && id !== b.task_id);
    expect(undelivered.length).toBeGreaterThan(0);
    for (const id of undelivered) expect(JSON.stringify(stopped)).toContain(id);

    await answer(h, out.plan_id, a, s.locs);
    await answer(h, out.plan_id, b, s.locs);
    const report = (await status(h, out.plan_id)).report;
    expect(report.coverage).toBe('partial');
    for (const id of undelivered) expect(report.missing).toContain(id);
  });

  it('T-30 the estimated-token limit', async () => {
    const h = harness();
    seedStandard(h);
    // 3 x 60 000 > 130 000: confirmed, but delivery stops at the limit.
    const out = await start(h, { modes: ['verify'], max_estimated_tokens: 130_000, confirm: true });
    const delivered: string[] = [];
    let last = await callTool(h, 'llm_scan_task', { plan_id: out.plan_id });
    while (last.ok && delivered.length < 3) {
      delivered.push(okResult<TaskOut>(last).task_id);
      last = await callTool(h, 'llm_scan_task', { plan_id: out.plan_id });
    }
    expect(delivered.length).toBeGreaterThanOrEqual(1);
    expect(delivered.length).toBeLessThan(3);
    expectDomainError(last, 'limit_reached');
    const report = (await status(h, out.plan_id)).report;
    expect(report.coverage).toBe('partial');
    const undelivered = h.repo
      .listTasks(out.plan_id)
      .map((t) => t.task_id)
      .filter((id) => !delivered.includes(id));
    for (const id of undelivered) expect(report.missing).toContain(id);
  });
});

describe('T-31 brief and answer sizes are recorded per task; the report says only the host knows the real token use (US-4.AC-3)', () => {
  it('T-31 brief_chars is the brief handed out, response_chars the payload received', async () => {
    const h = harness();
    const s = seedStandard(h);
    const out = await start(h, { modes: ['verify'] });
    const t = await lease(h, out.plan_id);
    const payload: VerifyVerdict = verdictAt(locOfTask(h, out.plan_id, t.task_id, s.locs), 'real');
    expect(okResult<SubmitOut>(await submit(h, out.plan_id, t, payload)).accepted).toBe(true);

    const row = h.repo.getTask(out.plan_id, t.task_id);
    expect(row?.brief_chars).toBe(t.brief.length);
    expect(row?.response_chars).toBe(JSON.stringify(payload).length);

    const report = (await status(h, out.plan_id)).report;
    expect(report.sizes.brief_chars).toBeGreaterThanOrEqual(t.brief.length);
    expect(report.sizes.response_chars).toBeGreaterThanOrEqual(JSON.stringify(payload).length);
    expect(
      report.notes.some((n) => /(actual|real)[^.]{0,80}tokens?[^.]{0,120}host|host[^.]{0,120}(actual|real)[^.]{0,80}tokens?/i.test(n)),
      JSON.stringify(report.notes),
    ).toBe(true);
  });
});

describe('T-32 a closed task takes no second answer (EC-2); a wrong lease token is refused (US-1.AC-4)', () => {
  it('T-32 a second submission for a closed task: already_closed, the first verdict kept', async () => {
    const h = harness();
    const s = seedStandard(h);
    const out = await start(h, { modes: ['verify'] });
    const t = await lease(h, out.plan_id);
    const loc = locOfTask(h, out.plan_id, t.task_id, s.locs);
    expect(okResult<SubmitOut>(await submit(h, out.plan_id, t, verdictAt(loc, 'real'))).accepted).toBe(true);
    expectDomainError(await submit(h, out.plan_id, t, verdictAt(loc, 'not_real')), 'already_closed');
    const v = (h.repo.getTask(out.plan_id, t.task_id)?.result ?? null) as VerifyVerdict | null;
    expect(v?.verdict).toBe('real');
  });

  it('T-32 a wrong token, or another task\'s: bad_lease, and the holder can still answer', async () => {
    const h = harness();
    const s = seedStandard(h);
    const out = await start(h, { modes: ['verify'] });
    const a = await lease(h, out.plan_id);
    const b = await lease(h, out.plan_id);
    const loc = locOfTask(h, out.plan_id, a.task_id, s.locs);
    const forged = (submissionFixture('envelope-wrong-lease.json') as { lease_token: string }).lease_token;

    expectDomainError(await submit(h, out.plan_id, { task_id: a.task_id, lease_token: forged }, verdictAt(loc, 'real')), 'bad_lease');
    expectDomainError(await submit(h, out.plan_id, { task_id: a.task_id, lease_token: b.lease_token }, verdictAt(loc, 'real')), 'bad_lease');
    expect(h.repo.getTask(out.plan_id, a.task_id)?.status).toBe('leased');
    expect(okResult<SubmitOut>(await submit(h, out.plan_id, a, verdictAt(loc, 'real'))).accepted).toBe(true);
  });

  it('T-32 a task of another plan: bad_lease', async () => {
    const h = harness();
    seedStandard(h);
    const p1 = await start(h, { modes: ['verify'] });
    const p2 = await start(h, { modes: ['verify'] });
    const t = await lease(h, p1.plan_id);
    expectDomainError(await submit(h, p2.plan_id, t, verdictAt(PARAM_INSERT, 'real')), 'bad_lease');
  });
});
