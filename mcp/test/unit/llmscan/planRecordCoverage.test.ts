/**
 * llm-scan-plan-record-default-scan T-06: what a plan's scan record says it measured (rule 2).
 *
 * A hunt plan's record follows the valid answers of its hunt and cross-cutting tasks — a task closed as not
 * delivered, or after its invalid answers ran out, is not answered:
 *   - none answered, or no hunt task at all: `[{ llm-hunt, skipped, reason }]`, missing `['llm-hunt']` — none;
 *   - some: `[{ llm-hunt, ok }]`, missing `['llm-hunt:open-tasks']` — partial (the plan's own report says so too);
 *   - all, and no entry point set aside or left unvisited: `[{ llm-hunt, ok }]`, `[]` — full.
 * It is written at start, rewritten when a hunt answer is accepted and when an open plan is settled, and its
 * finish date never moves. A verify-only plan's record stays `tools_run: []`.
 *
 * The service functions (`llmscan/service.ts`) over the tests' harness: a copy of the fixture project, an
 * in-memory database, the attack surface seeded, every answer a fixture. No model.
 */

import { join } from 'node:path';
import { afterAll, describe, expect, it, vi } from 'vitest';
import { classifyDiff, compareScansFor } from '../../../src/history/runCompare.js';
import { leaseNext, MAX_INVALID_SUBMISSIONS, settlePlan, startPlan, submitAnswer, type Out } from '../../../src/llmscan/service.js';
import { LLM_SCAN_DEFAULTS, type HuntFinding, type HuntResult, type PlanLimits, type ScanMode, type TaskKind } from '../../../src/llmscan/types.js';
import { computeCoverage } from '../../../src/tools/scanCoverage.js';
import type { ScanCoverage, ScanRecord, ToolRun } from '../../../src/types.js';
import {
  PARAM_INSERT,
  SHELL,
  SQLI,
  emptyHunt,
  fixtureRoutes,
  harness,
  locOfTask,
  seedScan,
  seedSurface,
  submissionFixture,
  verdictAt,
  type Harness,
  type Loc,
} from '../../helpers/llmScanHarness.js';
import { cleanupTempDirs } from '../../helpers/tempDir.js';

vi.setConfig({ testTimeout: 60_000 });
afterAll(cleanupTempDirs);

const LIMITS: PlanLimits = {
  max_tasks: LLM_SCAN_DEFAULTS.max_tasks,
  max_estimated_tokens: LLM_SCAN_DEFAULTS.max_estimated_tokens,
  per_task_overhead: LLM_SCAN_DEFAULTS.per_task_overhead,
};

interface Bookkeeping {
  tools_run: ToolRun[];
  missing_tools: string[];
}

/** No hunt task answered: the hunt did not run. */
const NOT_HUNTED = { tools_run: [{ name: 'llm-hunt', status: 'skipped', reason: expect.any(String) }], missing_tools: ['llm-hunt'] };
/** Some answered: a pass of llm-hunt is still open (`base:suffix`, history/runNames.ts). */
const PARTLY_HUNTED = { tools_run: [{ name: 'llm-hunt', status: 'ok' }], missing_tools: ['llm-hunt:open-tasks'] };
/** Every hunt and cross-cutting task answered, every entry point visited. */
const HUNTED = { tools_run: [{ name: 'llm-hunt', status: 'ok' }], missing_tools: [] };

interface Plan {
  planId: string;
  scanId: string;
}

async function plan(h: Harness, modes: ScanMode[], opts: { limits?: Partial<PlanLimits>; confirm?: boolean } = {}): Promise<Plan> {
  const r = await startPlan(h.storage, { project: h.project, modes, limits: { ...LIMITS, ...opts.limits }, confirm: opts.confirm ?? false });
  if (!r.ok) throw new Error(`startPlan refused: ${r.error.code}: ${r.error.message}`);
  return { planId: String(r['plan_id']), scanId: String(r['scan_id']) };
}

function record(h: Harness, scanId: string): ScanRecord {
  const r = h.storage.scans.getById(scanId);
  if (r === null) throw new Error(`no scan ${scanId}`);
  return r;
}

function bookkeeping(h: Harness, scanId: string): Bookkeeping {
  const r = record(h, scanId);
  return { tools_run: r.tools_run, missing_tools: r.missing_tools };
}

function coverage(h: Harness, scanId: string): ScanCoverage {
  const r = record(h, scanId);
  return computeCoverage(r.tools_run, r.missing_tools);
}

/** The skipped llm-hunt run says why. */
const skipReason = (h: Harness, scanId: string): string => record(h, scanId).tools_run.find((t) => t.name === 'llm-hunt')?.reason ?? '';

interface Leased {
  task_id: string;
  kind: TaskKind;
  lease_token: string;
}

/** The next task, `done` at the plan's end, or the refusal's code (limit_reached). */
function leaseOne(h: Harness, planId: string): Leased | 'done' | { refused: string } {
  const r: Out = leaseNext(h.storage, planId);
  if (!r.ok) return { refused: r.error.code };
  if (r['done'] === true) return 'done';
  return { task_id: String(r['task_id']), kind: r['kind'] as TaskKind, lease_token: String(r['lease_token']) };
}

function leaseTask(h: Harness, planId: string): Leased {
  const t = leaseOne(h, planId);
  if (t === 'done' || 'refused' in t) throw new Error(`expected a task of plan ${planId}, got ${JSON.stringify(t)}`);
  return t;
}

function answer(h: Harness, planId: string, t: Leased, payload: unknown): Out {
  return submitAnswer(h.storage, { plan_id: planId, task_id: t.task_id, lease_token: t.lease_token, independence: 'subagent', payload });
}

/** A valid answer for `t`: no finding for a hunt or cross-cutting task, `real` for a verify task of `locs`. */
function answerValid(h: Harness, planId: string, t: Leased, locs: ReadonlyMap<string, Loc> = new Map()): void {
  const payload = t.kind === 'verify' ? verdictAt(locOfTask(h, planId, t.task_id, locs), 'real') : emptyHunt(h, planId, t.task_id);
  const r = answer(h, planId, t, payload);
  expect(r.ok && r['accepted'], JSON.stringify(r)).toBe(true);
}

/** Leases and validly answers tasks until the plan ends; the number answered. */
function answerToEnd(h: Harness, planId: string, locs?: ReadonlyMap<string, Loc>): number {
  for (let n = 0; n < 60; n += 1) {
    const t = leaseOne(h, planId);
    if (t === 'done') return n;
    if ('refused' in t) throw new Error(`plan ${planId}: ${t.refused}`);
    answerValid(h, planId, t, locs);
  }
  throw new Error(`plan ${planId} did not end within 60 tasks`);
}

/**
 * Leases and validly answers every hunt and cross-cutting task of plan `planId` — the first hunt task reports
 * `findings`, the others nothing — and leaves the verify tasks those findings get open.
 */
function answerHuntTasks(h: Harness, planId: string, findings: readonly HuntFinding[]): void {
  let reported = false;
  for (let n = 0; n < 60; n += 1) {
    const r: Out = leaseNext(h.storage, planId, { kinds: ['hunt', 'crosscut'] });
    if (!r.ok) throw new Error(`plan ${planId}: ${r.error.code}`);
    if (typeof r['task_id'] !== 'string') return;
    const t: Leased = { task_id: r['task_id'], kind: r['kind'] as TaskKind, lease_token: String(r['lease_token']) };
    const give = !reported && t.kind === 'hunt';
    if (give) reported = true;
    const done = answer(h, planId, t, { ...emptyHunt(h, planId, t.task_id), findings: give ? [...findings] : [] });
    expect(done.ok && done['accepted'], JSON.stringify(done)).toBe(true);
  }
  throw new Error(`plan ${planId}: its hunt tasks did not end within 60`);
}

/** Answers `real` every verify task of `p` that checks one of its own hunt findings. */
function confirmHuntFindings(h: Harness, p: Plan): void {
  for (let n = 0; n < 60; n += 1) {
    const t = leaseOne(h, p.planId);
    if (t === 'done') return;
    if ('refused' in t) throw new Error(`plan ${p.planId}: ${t.refused}`);
    const fp = h.repo.getTask(p.planId, t.task_id)?.target.fingerprint;
    const row = h.storage.findings.listByScan(p.scanId).find((f) => f.fingerprint === fp);
    if (row === undefined) throw new Error(`task ${t.task_id} checks no finding of plan ${p.planId}`);
    const r = answer(h, p.planId, t, verdictAt({ file: row.file_path ?? '', line: row.line_start ?? 0 }, 'real'));
    expect(r.ok && r['accepted'], JSON.stringify(r)).toBe(true);
  }
  throw new Error(`plan ${p.planId} did not end within 60 tasks`);
}

/** What a comparison of two plans' records calls resolved and not re-measured (`history/runCompare.ts`). */
function compared(h: Harness, fromScanId: string, toScanId: string): { resolved: number; not_remeasured: number } {
  const d = classifyDiff(
    compareScansFor(h.storage, record(h, fromScanId), record(h, toScanId)),
    h.storage.findings.listByScan(fromScanId),
    h.storage.findings.listByScan(toScanId),
  );
  return { resolved: d.resolved.length, not_remeasured: d.notRemeasured.length };
}

/** The fixture's three SAST findings; where each sits, by fingerprint. */
function seedSast(h: Harness): Map<string, Loc> {
  const locs = [SQLI, PARAM_INSERT, SHELL];
  const { findings } = seedScan(
    h.storage,
    h.db,
    h.project,
    'sast',
    locs.map((loc, i) => ({ tool: 'semgrep', rule_id: `fixture.rule-${String(i)}`, loc })),
  );
  return new Map(findings.map((f, i) => [f.fingerprint, locs[i] ?? SQLI]));
}

describe('llm-scan-plan-record-default-scan', () => {
  it('T-06 a verify-only plan still writes tools_run: []; a hunt plan\'s start writes llm-hunt skipped and missing (coverage none)', async () => {
    const h = harness();
    seedSast(h);
    const verify = await plan(h, ['verify']);
    expect(bookkeeping(h, verify.scanId), 'a verify-only plan').toEqual({ tools_run: [], missing_tools: [] });

    await seedSurface(h);
    const hunt = await plan(h, ['hunt']);
    expect(bookkeeping(h, hunt.scanId), 'a hunt plan, only started').toEqual(NOT_HUNTED);
    expect(skipReason(h, hunt.scanId)).toMatch(/\S/);
    expect(coverage(h, hunt.scanId)).toBe('none');
  });

  it('T-06 a hunt plan\'s record follows the valid answers of its hunt and cross-cutting tasks — none, some, all — and keeps its finish date', async () => {
    const h = harness();
    await seedSurface(h);
    const p = await plan(h, ['hunt']);
    const total = h.repo.listTasks(p.planId).length;
    expect(h.repo.listTasks(p.planId).every((t) => t.kind === 'hunt' || t.kind === 'crosscut')).toBe(true);
    const finished = record(h, p.scanId).finished_at;
    expect(bookkeeping(h, p.scanId), 'nothing answered').toEqual(NOT_HUNTED);

    for (let answered = 1; answered <= total; answered += 1) {
      answerValid(h, p.planId, leaseTask(h, p.planId));
      expect(bookkeeping(h, p.scanId), `${String(answered)} of ${String(total)} answered`).toEqual(answered < total ? PARTLY_HUNTED : HUNTED);
      expect(record(h, p.scanId).finished_at, 'the finish date').toBe(finished);
    }
    expect(coverage(h, p.scanId)).toBe('full');
  });

  it('T-06 a hunt task closed after its invalid answers ran out is not answered', async () => {
    const h = harness();
    await seedSurface(h);
    const p = await plan(h, ['hunt']);
    const spoilt = leaseTask(h, p.planId);
    for (let i = 0; i < MAX_INVALID_SUBMISSIONS; i += 1) {
      const r = answer(h, p.planId, spoilt, { entry_points_reviewed: [], findings: 'none' });
      expect(r.ok && r['accepted'], JSON.stringify(r)).toBe(false);
    }
    expect(h.repo.getTask(p.planId, spoilt.task_id)?.closed_reason).toBe('invalid_submissions');
    expect(bookkeeping(h, p.scanId), 'one task out of tries, none answered').toEqual(NOT_HUNTED);
    expect(answerToEnd(h, p.planId)).toBe(h.repo.listTasks(p.planId).length - 1);
    expect(bookkeeping(h, p.scanId), 'every other task answered').toEqual(PARTLY_HUNTED);
  });

  it('T-06 a hunt task closed as not delivered (the token limit) is not answered', async () => {
    // Stopped by the token limit after two tasks: the others closed as not delivered.
    const limited = harness();
    await seedSurface(limited);
    const lp = await plan(limited, ['hunt'], { limits: { per_task_overhead: 100_000, max_estimated_tokens: 250_000 }, confirm: true });
    let stopped = '';
    for (let n = 0; n < 60 && stopped === ''; n += 1) {
      const t = leaseOne(limited, lp.planId);
      if (t === 'done') break;
      if ('refused' in t) stopped = t.refused;
      else answerValid(limited, lp.planId, t);
    }
    expect(stopped).toBe('limit_reached');
    expect(limited.repo.listTasks(lp.planId).filter((t) => t.closed_reason === 'not_delivered').length).toBeGreaterThan(0);
    expect(bookkeeping(limited, lp.scanId), 'two answered, the rest not delivered').toEqual(PARTLY_HUNTED);

    // A limit nothing fits under: every task closed as not delivered, none answered.
    const blocked = harness();
    await seedSurface(blocked);
    const bp = await plan(blocked, ['hunt'], { limits: { max_estimated_tokens: 1 }, confirm: true });
    expect(leaseOne(blocked, bp.planId)).toEqual({ refused: 'limit_reached' });
    expect(blocked.repo.listTasks(bp.planId).every((t) => t.closed_reason === 'not_delivered')).toBe(true);
    expect(bookkeeping(blocked, bp.scanId), 'nothing delivered').toEqual(NOT_HUNTED);
  });

  it('T-06 a hunt plan with no hunt task — every entry point outside the project — records that the hunt did not run, with the reason', async () => {
    const h = harness();
    const locs = seedSast(h);
    const elsewhere = join(`${h.project}-elsewhere`, 'src', 'app.ts');
    await seedSurface(h, fixtureRoutes(h.project).map((r) => ({ ...r, file: elsewhere })));
    const p = await plan(h, ['hunt', 'verify']);
    expect(h.repo.listTasks(p.planId).map((t) => t.kind)).toEqual(['verify', 'verify', 'verify']);

    expect(bookkeeping(h, p.scanId), 'only started').toEqual(NOT_HUNTED);
    expect(answerToEnd(h, p.planId, locs)).toBe(3);
    expect(bookkeeping(h, p.scanId), 'every verify task answered').toEqual(NOT_HUNTED);
    expect(skipReason(h, p.scanId)).toMatch(/\S/);
  });

  it('T-06 a hunt plan that answered every task but set an entry point aside stays partial', async () => {
    const h = harness();
    const routes = fixtureRoutes(h.project);
    const first = routes[0];
    if (first === undefined) throw new Error('the fixture has routes');
    const outside = { ...first, path_raw: '/elsewhere', path_resolved: '/elsewhere', file: join(`${h.project}-elsewhere`, 'src', 'x.ts') };
    await seedSurface(h, [...routes, outside]);
    const p = await plan(h, ['hunt']);
    expect(h.repo.getPlan(p.planId)?.set_aside).toHaveLength(1);

    expect(answerToEnd(h, p.planId)).toBe(h.repo.listTasks(p.planId).length);
    expect(bookkeeping(h, p.scanId), 'every task answered, one entry point set aside').toEqual(PARTLY_HUNTED);
    expect(coverage(h, p.scanId)).toBe('partial');
  });

  it('T-06 settlePlan rewrites the record of an open plan whose old row says llm-hunt ok with hunt tasks unanswered', async () => {
    const h = harness();
    await seedSurface(h);
    const p = await plan(h, ['hunt']);
    answerValid(h, p.planId, leaseTask(h, p.planId));
    // The record as a build before this fix wrote it at start, and never changed.
    h.db.prepare('UPDATE scans SET tools_run = ?, missing_tools = ? WHERE id = ?').run(JSON.stringify([{ name: 'llm-hunt', status: 'ok' }]), '[]', p.scanId);
    const finished = record(h, p.scanId).finished_at;
    const open = h.repo.getPlan(p.planId);
    if (open === null) throw new Error(`no plan ${p.planId}`);
    expect(open.status).toBe('open');

    settlePlan(h.storage, open);
    expect(bookkeeping(h, p.scanId), 'after settlePlan, one of the hunt tasks answered').toEqual(PARTLY_HUNTED);
    expect(record(h, p.scanId).finished_at, 'the finish date').toBe(finished);
  });

  it('T-06 a hunt that answered every hunt and cross-cutting task while the checks of its own findings are open stays partial and resolves nothing; its checks answered, it is full', async () => {
    const h = harness();
    await seedSurface(h);
    const [earlierFinding, laterFinding] = (submissionFixture('hunt-valid.json') as HuntResult).findings;
    if (earlierFinding === undefined || laterFinding === undefined) throw new Error('the fixture has two hunt findings');

    // An earlier hunt, complete: it found one finding, and the check of it said real.
    const earlier = await plan(h, ['hunt']);
    answerHuntTasks(h, earlier.planId, [earlierFinding]);
    confirmHuntFindings(h, earlier);
    expect(bookkeeping(h, earlier.scanId), 'the earlier hunt, every task answered').toEqual(HUNTED);

    // A later hunt finds the other one instead: every hunt and cross-cutting task answered, its own check open.
    await seedSurface(h);
    const later = await plan(h, ['hunt']);
    answerHuntTasks(h, later.planId, [laterFinding]);
    expect(h.repo.listTasks(later.planId).filter((t) => t.status !== 'closed').map((t) => t.kind), 'what is still open').toEqual(['verify']);
    expect(bookkeeping(h, later.scanId), 'every hunt task answered, the check of its finding open').toEqual(PARTLY_HUNTED);
    expect(compared(h, earlier.scanId, later.scanId), 'the earlier hunt compared with it').toEqual({ resolved: 0, not_remeasured: 1 });

    // Its check answered: the plan's report is full, and so is the record — which now resolves what it did not find again.
    confirmHuntFindings(h, later);
    expect(bookkeeping(h, later.scanId), 'the check of its finding answered').toEqual(HUNTED);
    expect(compared(h, earlier.scanId, later.scanId), 'the earlier hunt compared with it, now').toEqual({ resolved: 1, not_remeasured: 0 });
  });
});
