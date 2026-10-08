/**
 * `execute: 'sampling'` past the paths T-26 and T-27 walk (task 7 review,
 * round 1):
 *
 *   - `payloadOf` takes ONE JSON object — a single code fence tolerated,
 *     prose, an array or trailing text refused as a host's submission is;
 *   - the budget counts from the tool's entry (`began`), and no request — nor
 *     a retry the slowest request would carry past the budget — starts after it;
 *   - a task cut short by the budget, the client failing or refusing, or the
 *     call being cancelled gives its lease back with no attempt spent, and
 *     the next call takes it up;
 *   - `executed` counts the tasks the call closed, so `remaining` falls by it.
 */

import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { payloadOf, runSampling } from '../../src/llmscan/sampling.js';
import type { SamplingFn } from '../../src/llmscan/types.js';
import { fakeSampling, harness, seedStandard, start, verdictAt, type Harness } from '../helpers/llmScanHarness.js';
import { cleanupTempDirs } from '../helpers/tempDir.js';

vi.setConfig({ testTimeout: 60_000 });
afterAll(cleanupTempDirs);
beforeAll(async () => {
  await import('../../src/registerAll.js');
});

interface Ran {
  ok: true;
  executed: number;
  remaining: number;
  stopped: string | null;
  failure?: string;
}

function ran(r: unknown): Ran {
  const out = r as Ran | { ok: false };
  if (out.ok !== true) throw new Error(`expected ok, got ${JSON.stringify(r)}`);
  return out;
}

async function verifyPlan(): Promise<{ h: Harness; planId: string; locs: ReturnType<typeof seedStandard>['locs'] }> {
  const h = harness();
  const s = seedStandard(h);
  const out = await start(h, { modes: ['verify'] });
  return { h, planId: out.plan_id, locs: s.locs };
}

/** A client that answers every request with `text`, after `onCall`. */
function answering(text: string, onCall: () => void = () => {}): { fn: SamplingFn; requests: number } {
  const state = { fn: null as unknown as SamplingFn, requests: 0 };
  state.fn = async () => {
    state.requests += 1;
    onCall();
    return { role: 'assistant', content: { type: 'text', text }, model: 'fake' };
  };
  return state;
}

/** A client that fails every request with `err`, after `onCall`. */
function failing(err: unknown, onCall: () => void = () => {}): { fn: SamplingFn; requests: number } {
  const state = { fn: null as unknown as SamplingFn, requests: 0 };
  state.fn = async () => {
    state.requests += 1;
    onCall();
    throw err;
  };
  return state;
}

const INVALID = JSON.stringify({ verdict: 'maybe' });

describe('payloadOf: one JSON object, nothing else', () => {
  it.each([
    ['{"a":1}', { a: 1 }],
    ['  {"a":1}\n', { a: 1 }],
    ['```json\n{"a":1}\n```', { a: 1 }],
    ['```\n{"a":1}\n```', { a: 1 }],
  ])('%j is the object', (text, value) => {
    expect(payloadOf(text)).toEqual(value);
  });

  it.each(['Here it is: {"a":1}', '{"a":1} and that is all', '[{"a":1}]', '{not json}', '', '```json\n{"a":1}\n```\n```json\n{"b":2}\n```'])(
    '%j stays text, for the validator to refuse',
    (text) => {
      expect(payloadOf(text)).toBe(text);
    },
  );
});

describe('the budget counts from the tool entry, and nothing starts after it', () => {
  it('a call whose budget planning already spent sends no request and leases nothing', async () => {
    const { h, planId, locs } = await verifyPlan();
    const fake = fakeSampling(locs, (loc) => verdictAt(loc, 'real'));
    const r = ran(await runSampling(h.storage, planId, fake.fn, { clock: () => 100_000, began: 0, budget_ms: 50_000 }));
    expect(fake.requests).toHaveLength(0);
    expect(r).toMatchObject({ executed: 0, remaining: 3, stopped: 'time_budget' });
    for (const t of h.repo.listTasks(planId)) expect(t.status).toBe('open');
  });

  it('a retry the budget cuts is not sent: the lease goes back, the invalid answer stays counted', async () => {
    const { h, planId } = await verifyPlan();
    let now = 0;
    const client = answering(INVALID, () => {
      now += 60_000;
    });
    const r = ran(await runSampling(h.storage, planId, client.fn, { clock: () => now, began: 0, budget_ms: 50_000 }));
    expect(client.requests).toBe(1);
    expect(r).toMatchObject({ executed: 0, remaining: 3, stopped: 'time_budget' });
    const tasks = h.repo.listTasks(planId);
    const tried = tasks.filter((t) => t.attempts > 0);
    expect(tried).toHaveLength(1);
    expect(tried[0]).toMatchObject({ status: 'open', attempts: 1, lease_token: null });
  });

  it('a retry the slowest request would carry past the budget is not started', async () => {
    const { h, planId } = await verifyPlan();
    let now = 0;
    const client = answering(INVALID, () => {
      now += 30_000;
    });
    const r = ran(await runSampling(h.storage, planId, client.fn, { clock: () => now, began: 0, budget_ms: 50_000 }));
    // 30 s spent; one more 30 s request would end at 60 s, past the 50 s budget.
    expect(client.requests).toBe(1);
    expect(r.stopped).toBe('time_budget');
    expect(h.repo.listTasks(planId).every((t) => t.status === 'open')).toBe(true);
  });
});

describe('a task the client or the host cuts short gives its lease back, no attempt spent', () => {
  it.each([
    ['client_error', new Error('the user declined the sampling request')],
    ['timeout', new DOMException('The operation timed out.', 'TimeoutError')],
  ])('a client that fails (%s): stopped, no attempt, the task open again — and the next call takes it up', async (failure, err) => {
    const { h, planId, locs } = await verifyPlan();
    const client = failing(err);
    const r = ran(await runSampling(h.storage, planId, client.fn));
    expect(client.requests).toBe(1);
    expect(r).toMatchObject({ executed: 0, remaining: 3, stopped: 'sampling_failed', failure });
    for (const t of h.repo.listTasks(planId)) expect(t).toMatchObject({ status: 'open', attempts: 0 });

    const fake = fakeSampling(locs, (loc) => verdictAt(loc, 'real'));
    const again = ran(await runSampling(h.storage, planId, fake.fn));
    expect(again).toMatchObject({ executed: 3, remaining: 0 });
  });

  it('a call the host cancelled before a request sends none', async () => {
    const { h, planId, locs } = await verifyPlan();
    const fake = fakeSampling(locs, (loc) => verdictAt(loc, 'real'));
    const ctl = new AbortController();
    ctl.abort();
    const r = ran(await runSampling(h.storage, planId, fake.fn, { signal: ctl.signal }));
    expect(fake.requests).toHaveLength(0);
    expect(r).toMatchObject({ executed: 0, remaining: 3, stopped: 'cancelled' });
  });

  it('a request the host cancels in flight is aborted, and its task is open again', async () => {
    const { h, planId } = await verifyPlan();
    const ctl = new AbortController();
    let sawAbort = false;
    const fn: SamplingFn = (_params, options) =>
      new Promise((_resolve, reject) => {
        options?.signal?.addEventListener('abort', () => {
          sawAbort = true;
          reject(new DOMException('aborted', 'AbortError'));
        });
        ctl.abort();
      });
    const r = ran(await runSampling(h.storage, planId, fn, { signal: ctl.signal }));
    expect(sawAbort).toBe(true);
    expect(r).toMatchObject({ executed: 0, stopped: 'sampling_failed', failure: 'cancelled' });
    for (const t of h.repo.listTasks(planId)) expect(t).toMatchObject({ status: 'open', attempts: 0 });
  });
});

describe('executed counts the tasks the call closed', () => {
  it('three invalid answers close the task (undetermined): one executed, remaining falls by one', async () => {
    const { h, planId } = await verifyPlan();
    let calls = 0;
    const client = answering(INVALID, () => {
      calls += 1;
    });
    const before = h.repo.listTasks(planId).filter((t) => t.status !== 'closed').length;
    // Only the first task: a budget that ends after its third request.
    let now = 0;
    const r = ran(
      await runSampling(h.storage, planId, client.fn, {
        clock: () => {
          now = calls >= 3 ? 1_000_000 : 0;
          return now;
        },
        began: 0,
        budget_ms: 50_000,
      }),
    );
    expect(client.requests).toBe(3);
    expect(r.executed).toBe(1);
    expect(r.remaining).toBe(before - r.executed);
  });
});
