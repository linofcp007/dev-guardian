import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import type { LlmScanPlan, LlmScanTask } from '../../../src/llmscan/types.js';
import { GuardianDatabase } from '../../../src/storage/db.js';
import { Storage } from '../../../src/storage/index.js';
import { PLAN_ABANDON_DAYS, PLAN_INACTIVE_DAYS, type TaskOutcome } from '../../../src/storage/llmScanRepo.js';
import { deletePrunableScans, listPrunableScans, pruneScans } from '../../../src/storage/maintenance.js';
import { runMigrations } from '../../../src/storage/migrations/runner.js';
import { makeTempDir } from '../../helpers/tempDir.js';

const T0 = '2026-10-02T00:00:00.000Z';
const DAY = 86_400_000;
const at = (ms: number): string => new Date(Date.parse(T0) + ms).toISOString();

function makeStorage(path = ':memory:'): Storage {
  const db = new GuardianDatabase(path);
  runMigrations(db);
  return new Storage(db);
}

/** Two servers on one database file, as two hosts share one project. */
function twoServers(): [Storage, Storage] {
  const file = join(makeTempDir('llm-scan-repo-'), 'guardian.db');
  return [makeStorage(file), makeStorage(file)];
}

function plan(over: Partial<LlmScanPlan> = {}): LlmScanPlan {
  return {
    id: 'p-1',
    project_path: '/proj',
    scan_id: 'scan-1',
    modes: ['verify', 'hunt'],
    prompt_version: 'v1',
    tree_hash: 'h',
    surface_snapshot_id: null,
    limits: { max_tasks: 200, max_estimated_tokens: 500_000, per_task_overhead: 60_000 },
    estimate: { tasks: 1, brief_tokens: 10, total_tokens: 60_010, assumptions: 'a' },
    confirmed: false,
    status: 'open',
    not_eligible: [{ fingerprint: 'f', reason: 'r' }],
    set_aside: [],
    created_at: T0,
    updated_at: T0,
    ...over,
  };
}

function task(over: Partial<LlmScanTask> = {}): LlmScanTask {
  return {
    plan_id: 'p-1',
    task_id: 't-0001',
    kind: 'verify',
    target: { fingerprint: 'f', files: ['a.ts'] },
    status: 'open',
    lease_token: null,
    lease_expires_at: null,
    attempts: 0,
    file_hashes: { 'a.ts': 'abc' },
    brief_chars: null,
    response_chars: null,
    independence: null,
    result: null,
    closed_reason: null,
    delivered_at: null,
    closed_at: null,
    ...over,
  };
}

const OUTCOME: TaskOutcome = {
  independence: 'subagent',
  result: { verdict: 'real', attacker_input: 'a:1', operation: 'a:2', decisive_line: 'a:2 — x', reasoning: 'r' },
  closed_reason: 'valid',
  response_chars: 120,
};

function seed(s: Storage, scanId: string, p: Partial<LlmScanPlan> = {}, tasks?: LlmScanTask[]): void {
  s.scans.insert({ scan_id: scanId, scan_type: 'llm_scan', project_path: '/proj', tree_hash: 'h' });
  s.scans.finalize({ scan_id: scanId, status: 'completed', tools_run: [{ name: 'llm-hunt', status: 'ok' }], missing_tools: [] });
  s.llmScan.insertPlan(plan({ scan_id: scanId, ...p }), tasks ?? [task({ plan_id: p.id ?? 'p-1' })]);
}

const activityOf = (s: Storage, id: string): string =>
  s.rawHandle().prepare<[string], { a: string }>('SELECT last_activity_at AS a FROM llm_scan_plans WHERE id = ?').get(id)?.a ?? '';

describe('LlmScanRepo — storage', () => {
  it('round-trips a plan and its tasks, structured fields intact', () => {
    const s = makeStorage();
    seed(s, 'scan-1');
    expect(s.llmScan.getPlan('p-1')).toEqual(plan());
    expect(s.llmScan.listTasks('p-1')).toEqual([task()]);
    expect(s.llmScan.getTask('p-1', 't-0001')).toEqual(task());
    expect(s.llmScan.getTask('p-1', 't-9999')).toBeNull();
    expect(s.llmScan.getPlan('nope')).toBeNull();
  });

  it("lists a project's plans newest first", () => {
    const s = makeStorage();
    seed(s, 'scan-1');
    seed(s, 'scan-2', { id: 'p-2', created_at: at(DAY) });
    expect(s.llmScan.listPlans('/proj').map((p) => p.id)).toEqual(['p-2', 'p-1']);
    expect(s.llmScan.listPlans('/other')).toEqual([]);
  });

  it('item 6: a task for a missing plan, and a plan for a missing scan, throw', () => {
    const s = makeStorage();
    expect(() => s.llmScan.insertPlan(plan({ scan_id: 'no-such-scan' }), [])).toThrow();
    expect(s.llmScan.getPlan('p-1')).toBeNull();
    seed(s, 'scan-1');
    expect(() => s.llmScan.insertPlan(plan({ id: 'p-2', scan_id: 'scan-1' }), [task({ plan_id: 'no-such-plan' })])).toThrow();
    // the transaction rolled the plan back with the bad task
    expect(s.llmScan.getPlan('p-2')).toBeNull();
  });

  it('item 3: a corrupt JSON column reads as absent: skipped from lists, null from a get', () => {
    const s = makeStorage();
    seed(s, 'scan-1');
    seed(s, 'scan-2', { id: 'p-2' }, [task({ plan_id: 'p-2' }), task({ plan_id: 'p-2', task_id: 't-0002' })]);
    const db = s.rawHandle();
    db.prepare(`UPDATE llm_scan_plans SET limits = '{not json' WHERE id = 'p-1'`).run();
    db.prepare(`UPDATE llm_scan_tasks SET target = 'oops' WHERE plan_id = 'p-2' AND task_id = 't-0002'`).run();
    expect(s.llmScan.getPlan('p-1')).toBeNull();
    expect(s.llmScan.listPlans('/proj').map((p) => p.id)).toEqual(['p-2']);
    expect(s.llmScan.getTask('p-2', 't-0002')).toBeNull();
    expect(s.llmScan.listTasks('p-2').map((t) => t.task_id)).toEqual(['t-0001']);
  });
});

describe('LlmScanRepo — atomic lease (D-2), two servers on one database file', () => {
  it('both claim the same open task: exactly one wins', () => {
    const [a, b] = twoServers();
    seed(a, 'scan-1');
    const wins = [
      a.llmScan.claimTask('p-1', 't-0001', 'tok-a', at(20 * 60_000), at(0)),
      b.llmScan.claimTask('p-1', 't-0001', 'tok-b', at(20 * 60_000), at(0)),
    ];
    expect(wins.filter(Boolean)).toHaveLength(1);
    const held = a.llmScan.getTask('p-1', 't-0001');
    expect(held?.status).toBe('leased');
    expect(held?.lease_token).toBe(wins[0] ? 'tok-a' : 'tok-b');
    expect(held?.delivered_at).toBe(at(0));
  });

  it('claimNextTask: two servers get two different tasks, a third finds none', () => {
    const [a, b] = twoServers();
    seed(a, 'scan-1', {}, [task(), task({ task_id: 't-0002' })]);
    const x = a.llmScan.claimNextTask('p-1', 'tok-a', at(60_000), at(0));
    const y = b.llmScan.claimNextTask('p-1', 'tok-b', at(60_000), at(0));
    expect([x?.task_id, y?.task_id]).toEqual(['t-0001', 't-0002']);
    expect(x?.lease_token).toBe('tok-a');
    expect(a.llmScan.claimNextTask('p-1', 'tok-c', at(60_000), at(1))).toBeNull();
  });

  it('an expired lease can be re-claimed; a live one cannot', () => {
    const [a, b] = twoServers();
    seed(a, 'scan-1');
    expect(a.llmScan.claimTask('p-1', 't-0001', 'tok-a', at(60_000), at(0))).toBe(true);
    expect(b.llmScan.claimTask('p-1', 't-0001', 'tok-b', at(120_000), at(30_000))).toBe(false);
    expect(b.llmScan.claimTask('p-1', 't-0001', 'tok-b', at(180_000), at(60_000))).toBe(true);
    expect(a.llmScan.getTask('p-1', 't-0001')?.lease_token).toBe('tok-b');
    // the first delivery time survives the re-claim
    expect(a.llmScan.getTask('p-1', 't-0001')?.delivered_at).toBe(at(0));
  });

  it('a late submit with the old token after a re-claim is refused, and the new holder can still close', () => {
    const [a, b] = twoServers();
    seed(a, 'scan-1');
    a.llmScan.claimTask('p-1', 't-0001', 'tok-a', at(60_000), at(0));
    b.llmScan.claimTask('p-1', 't-0001', 'tok-b', at(180_000), at(61_000));
    expect(a.llmScan.recordInvalidSubmission('p-1', 't-0001', 'tok-a')).toBeNull();
    expect(a.llmScan.closeTask('p-1', 't-0001', 'tok-a', OUTCOME, at(62_000))).toBe(false);
    expect(a.llmScan.getTask('p-1', 't-0001')).toMatchObject({ status: 'leased', attempts: 0, result: null });
    expect(b.llmScan.recordInvalidSubmission('p-1', 't-0001', 'tok-b')).toBe(1);
    expect(b.llmScan.closeTask('p-1', 't-0001', 'tok-b', OUTCOME, at(63_000))).toBe(true);
    expect(a.llmScan.getTask('p-1', 't-0001')).toMatchObject({
      status: 'closed',
      attempts: 1,
      closed_reason: 'valid',
      independence: 'subagent',
      response_chars: 120,
      closed_at: at(63_000),
      result: OUTCOME.result,
    });
  });

  it('a closed task cannot be re-claimed, closed again, counted against, or rewritten', () => {
    const [a, b] = twoServers();
    seed(a, 'scan-1');
    a.llmScan.claimTask('p-1', 't-0001', 'tok-a', at(60_000), at(0));
    expect(a.llmScan.closeTask('p-1', 't-0001', 'tok-a', OUTCOME, at(1_000))).toBe(true);
    const closed = a.llmScan.getTask('p-1', 't-0001');
    expect(b.llmScan.claimTask('p-1', 't-0001', 'tok-b', at(999_000), at(500_000))).toBe(false);
    expect(b.llmScan.claimNextTask('p-1', 'tok-b', at(999_000), at(500_000))).toBeNull();
    expect(b.llmScan.closeTask('p-1', 't-0001', 'tok-a', { ...OUTCOME, closed_reason: 'stale' }, at(2_000))).toBe(false);
    expect(b.llmScan.recordInvalidSubmission('p-1', 't-0001', 'tok-a')).toBeNull();
    expect(b.llmScan.getTask('p-1', 't-0001')).toEqual(closed);
  });
});

describe('LlmScanRepo — inactive plans (D-2), with an injected clock', () => {
  it('the constants are named: 7 days to leave the limit, 30 to be abandoned', () => {
    expect([PLAN_INACTIVE_DAYS, PLAN_ABANDON_DAYS]).toEqual([7, 30]);
  });

  it('activity starts at creation and is bumped by a claim and by an accepted close, not by an invalid one', () => {
    const s = makeStorage();
    seed(s, 'scan-1');
    expect(activityOf(s, 'p-1')).toBe(T0);
    s.llmScan.claimTask('p-1', 't-0001', 'tok', at(60_000), at(DAY));
    expect(activityOf(s, 'p-1')).toBe(at(DAY));
    s.llmScan.recordInvalidSubmission('p-1', 't-0001', 'tok');
    expect(activityOf(s, 'p-1')).toBe(at(DAY));
    s.llmScan.closeTask('p-1', 't-0001', 'tok', OUTCOME, at(2 * DAY));
    expect(activityOf(s, 'p-1')).toBe(at(2 * DAY));
    // a refused claim changes nothing
    s.llmScan.claimTask('p-1', 't-0001', 'tok2', at(60_000), at(3 * DAY));
    expect(activityOf(s, 'p-1')).toBe(at(2 * DAY));
  });

  it('countOpenPlans / listActivePlanIds count only open plans active in the last 7 days', () => {
    const s = makeStorage();
    seed(s, 'scan-1');
    seed(s, 'scan-2', { id: 'p-2', created_at: at(3 * DAY) });
    seed(s, 'scan-3', { id: 'p-3', created_at: at(3 * DAY), status: 'complete' });
    expect(s.llmScan.countOpenPlans('/proj', at(6 * DAY))).toBe(2);
    // p-1 is 8 days idle, p-2 five: only p-2 counts, and p-1 is still resumable by id
    expect(s.llmScan.listActivePlanIds('/proj', at(8 * DAY))).toEqual(['p-2']);
    expect(s.llmScan.countOpenPlans('/proj', at(8 * DAY))).toBe(1);
    expect(s.llmScan.getPlan('p-1')?.status).toBe('open');
    expect(s.llmScan.countOpenPlans('/other', at(6 * DAY))).toBe(0);
    // activity brings a plan back into the count
    s.llmScan.touchPlan('p-1', at(8 * DAY));
    expect(s.llmScan.countOpenPlans('/proj', at(8 * DAY))).toBe(2);
  });

  it('abandonStalePlans marks open plans idle more than 30 days, and only those', () => {
    const s = makeStorage();
    seed(s, 'scan-1');
    seed(s, 'scan-2', { id: 'p-2', created_at: at(20 * DAY) });
    seed(s, 'scan-3', { id: 'p-3', status: 'complete' });
    expect(s.llmScan.abandonStalePlans(at(30 * DAY))).toBe(0);
    expect(s.llmScan.abandonStalePlans(at(31 * DAY))).toBe(1);
    expect(['p-1', 'p-2', 'p-3'].map((id) => s.llmScan.getPlan(id)?.status)).toEqual(['abandoned', 'open', 'complete']);
    expect(s.llmScan.abandonStalePlans(at(31 * DAY))).toBe(0);
  });

  it('updatePlan only moves open -> complete | abandoned', () => {
    const s = makeStorage();
    seed(s, 'scan-1');
    expect(s.llmScan.updatePlan('p-1', 'complete', at(1))).toBe(true);
    expect(s.llmScan.updatePlan('p-1', 'abandoned', at(2))).toBe(false);
    expect(s.llmScan.getPlan('p-1')).toMatchObject({ status: 'complete', updated_at: at(1) });
    // a finished plan is not touched back into activity
    s.llmScan.touchPlan('p-1', at(DAY));
    expect(activityOf(s, 'p-1')).toBe(T0);
  });
});

describe('LlmScanRepo — retention', () => {
  function threeScans(): Storage {
    const s = makeStorage();
    seed(s, 'scan-open', { id: 'p-open' });
    seed(s, 'scan-done', { id: 'p-done', status: 'complete' });
    s.scans.insert({ scan_id: 'newest', scan_type: 'llm_scan', project_path: '/proj', tree_hash: 'h' });
    s.scans.finalize({ scan_id: 'newest', status: 'completed', tools_run: [{ name: 'llm-hunt', status: 'ok' }], missing_tools: [] });
    // Distinct start times: retention ranks by recency, so the two plans' scans are the old ones.
    const db = s.rawHandle();
    db.prepare('UPDATE scans SET started_at = ? WHERE id = ?').run('2026-01-01T00:00:00.000Z', 'scan-open');
    db.prepare('UPDATE scans SET started_at = ? WHERE id = ?').run('2026-01-02T00:00:00.000Z', 'scan-done');
    db.prepare('UPDATE scans SET started_at = ? WHERE id = ?').run('2026-01-03T00:00:00.000Z', 'newest');
    return s;
  }

  it('holds back the scan of an open plan and deletes a closed plan with its scan', () => {
    const s = threeScans();
    const db = s.rawHandle();
    expect(listPrunableScans(db, 1)).not.toContain('scan-open');
    expect(deletePrunableScans(db, ['scan-open', 'scan-done'], 1)).toBe(1);
    expect(s.llmScan.getPlan('p-open')).not.toBeNull();
    expect(s.llmScan.getPlan('p-done')).toBeNull();
    expect(s.llmScan.listTasks('p-done')).toEqual([]);
  });

  it('abandons a plan idle past 30 days first, so its scan is no longer protected and goes with its plan', () => {
    // seeded plans are dated 2026-10-02; the real clock (>= that date + 30 days is not guaranteed),
    // so age the plan in the table itself.
    const s = threeScans();
    const db = s.rawHandle();
    db.prepare(`UPDATE llm_scan_plans SET last_activity_at = '2026-01-01T00:00:00.000Z' WHERE id = 'p-open'`).run();
    expect(pruneScans(db, 1)).toMatchObject({ deleted: 2, complete: true });
    expect(s.llmScan.getPlan('p-open')).toBeNull();
    expect(s.llmScan.listTasks('p-open')).toEqual([]);
  });
});
