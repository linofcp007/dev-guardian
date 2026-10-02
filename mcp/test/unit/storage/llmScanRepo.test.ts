import { describe, expect, it } from 'vitest';
import type { LlmScanPlan, LlmScanTask } from '../../../src/llmscan/types.js';
import { GuardianDatabase } from '../../../src/storage/db.js';
import { Storage } from '../../../src/storage/index.js';
import { deletePrunableScans, listPrunableScans } from '../../../src/storage/maintenance.js';
import { runMigrations } from '../../../src/storage/migrations/runner.js';

function makeStorage(): Storage {
  const db = new GuardianDatabase(':memory:');
  runMigrations(db);
  return new Storage(db);
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
    created_at: '2026-10-02T00:00:00.000Z',
    updated_at: '2026-10-02T00:00:00.000Z',
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

function seed(s: Storage, scanId: string, p: Partial<LlmScanPlan> = {}): void {
  s.scans.insert({ scan_id: scanId, scan_type: 'llm_scan', project_path: '/proj', tree_hash: 'h' });
  s.scans.finalize({ scan_id: scanId, status: 'completed', tools_run: [{ name: 'llm-hunt', status: 'ok' }], missing_tools: [] });
  s.llmScan.insertPlan(plan({ scan_id: scanId, ...p }), [task({ plan_id: p.id ?? 'p-1' })]);
}

describe('LlmScanRepo', () => {
  it('round-trips a plan and its tasks, structured fields intact', () => {
    const s = makeStorage();
    seed(s, 'scan-1');
    expect(s.llmScan.getPlan('p-1')).toEqual(plan());
    expect(s.llmScan.listTasks('p-1')).toEqual([task()]);
    expect(s.llmScan.getTask('p-1', 't-0001')).toEqual(task());
    expect(s.llmScan.getTask('p-1', 't-9999')).toBeNull();
    expect(s.llmScan.getPlan('nope')).toBeNull();
  });

  it('persists a task update (lease, result, close) and counts open plans per project', () => {
    const s = makeStorage();
    seed(s, 'scan-1');
    const closed = task({
      status: 'closed',
      attempts: 1,
      result: { verdict: 'real', attacker_input: 'a:1', operation: 'a:2', decisive_line: 'a:2 — x', reasoning: 'r' },
      independence: 'subagent',
      closed_reason: 'valid',
    });
    s.llmScan.updateTask(closed);
    expect(s.llmScan.getTask('p-1', 't-0001')).toEqual(closed);
    expect(s.llmScan.countOpenPlans('/proj')).toBe(1);
    s.llmScan.updatePlan({ id: 'p-1', status: 'complete', confirmed: true, updated_at: 'x' });
    expect(s.llmScan.countOpenPlans('/proj')).toBe(0);
    expect(s.llmScan.getPlan('p-1')).toMatchObject({ status: 'complete', confirmed: true, updated_at: 'x' });
  });

  it('lists a project\'s plans newest first', () => {
    const s = makeStorage();
    seed(s, 'scan-1');
    seed(s, 'scan-2', { id: 'p-2', created_at: '2026-10-03T00:00:00.000Z' });
    expect(s.llmScan.listPlans('/proj').map((p) => p.id)).toEqual(['p-2', 'p-1']);
    expect(s.llmScan.listPlans('/other')).toEqual([]);
  });

  it('retention holds back the scan of an open plan and deletes a closed plan with its scan', () => {
    const s = makeStorage();
    const db = s.rawHandle();
    seed(s, 'scan-open', { id: 'p-open' });
    seed(s, 'scan-done', { id: 'p-done', status: 'complete' });
    s.scans.insert({ scan_id: 'newest', scan_type: 'llm_scan', project_path: '/proj', tree_hash: 'h' });
    s.scans.finalize({ scan_id: 'newest', status: 'completed', tools_run: [{ name: 'llm-hunt', status: 'ok' }], missing_tools: [] });
    // Distinct start times: retention ranks by recency, so the two plans' scans are the old ones.
    db.prepare('UPDATE scans SET started_at = ? WHERE id = ?').run('2026-01-01T00:00:00.000Z', 'scan-open');
    db.prepare('UPDATE scans SET started_at = ? WHERE id = ?').run('2026-01-02T00:00:00.000Z', 'scan-done');
    db.prepare('UPDATE scans SET started_at = ? WHERE id = ?').run('2026-01-03T00:00:00.000Z', 'newest');
    const listed = listPrunableScans(db, 1);
    expect(listed).not.toContain('scan-open');
    expect(deletePrunableScans(db, ['scan-open', 'scan-done'], 1)).toBe(1);
    expect(s.llmScan.getPlan('p-open')).not.toBeNull();
    expect(s.llmScan.getPlan('p-done')).toBeNull();
    expect(s.llmScan.listTasks('p-done')).toEqual([]);
  });
});
