/**
 * Running verify tasks through the client's MCP sampling (`execute:
 * 'sampling'`, US-3.AC-2). Each task is leased and answered through the SAME
 * `leaseNext` / `submitAnswer` a host uses, so every sampled answer meets the
 * same validators, attempt limit and guarded writes. The verdict is recorded
 * as independence `sampling`: a fresh model context the server did not run.
 *
 * One call stays under the hosts' common 60 s budget (US-3.AC-3), counted from
 * the tool's entry: no task is started unless the slowest one so far would
 * still end within the budget, and no request is sent once the budget is spent
 * — nor a retry the slowest request so far would carry past it. A task cut
 * short, by the budget, by the client failing or refusing, or by the host
 * cancelling the call, gives its lease back with no attempt spent: it is open
 * again for the next call, not held for 20 minutes under a token nobody has.
 * Attempts count invalid ANSWERS only. Hunts need tools, which sampling does
 * not give them, so they are never leased here and stay for the host.
 *
 * `executed` counts the tasks this call closed, so `remaining` falls by it.
 */

import type { Storage } from '../storage/index.js';
import { fail, leaseNext, loadPlan, MAX_INVALID_SUBMISSIONS, reportOf, settlePlan, submitAnswer, type Out } from './service.js';
import type { SamplingFn } from './types.js';

/** A call's time for sampling; the host's budget is commonly 60 s. */
export const SAMPLING_BUDGET_MS = 50_000;
/** A request may run this long past the budget; the host's 60 s still holds. */
const REQUEST_MARGIN_MS = 5_000;
const MAX_ANSWER_TOKENS = 2_000;
const SYSTEM_PROMPT = 'You verify one finding. Reply with ONLY the JSON object the brief asks for, no prose and no code fence.';

export interface SamplingOptions {
  /** Milliseconds, monotonic enough for a budget; injectable for tests. */
  clock?: () => number;
  budget_ms?: number;
  /** The instant (on `clock`) the tool call began: planning and rendering count against the budget. */
  began?: number;
  /** The tool call's own cancellation: it aborts the request in flight too. */
  signal?: AbortSignal;
}

/** Why a sampling request produced no answer — coarse on purpose: the client's message may hold its data. */
export type SamplingFailure = 'timeout' | 'cancelled' | 'client_error';

function failureOf(err: unknown, cancelled: boolean): SamplingFailure {
  if (cancelled) return 'cancelled';
  const name = err instanceof Error ? err.name : '';
  return name === 'TimeoutError' || name === 'AbortError' ? 'timeout' : 'client_error';
}

/**
 * The reply as ONE JSON object: whitespace and a single code fence around it
 * are tolerated, prose is not. Anything else is returned as the raw text, which
 * the validator refuses (the same strictness as a host's submission).
 */
export function payloadOf(text: string): unknown {
  const trimmed = text.trim();
  const fenced = /^```(?:json)?\s*\n([\s\S]*?)\n?```$/.exec(trimmed);
  const candidate = (fenced?.[1] ?? trimmed).trim();
  if (!candidate.startsWith('{') || !candidate.endsWith('}')) return text;
  try {
    return JSON.parse(candidate) as unknown;
  } catch {
    return text;
  }
}

export async function runSampling(storage: Storage, planId: string, sampling: SamplingFn, opts: SamplingOptions = {}): Promise<Out> {
  const clock = opts.clock ?? Date.now;
  const budget = opts.budget_ms ?? SAMPLING_BUDGET_MS;
  const began = opts.began ?? clock();
  const spent = (): number => clock() - began;
  const cancelled = (): boolean => opts.signal?.aborted === true;
  let slowestTask = 0;
  let slowestRequest = 0;
  let executed = 0;
  let stopped: string | null = null;
  let failure: SamplingFailure | null = null;

  while (stopped === null) {
    if (cancelled()) {
      stopped = 'cancelled';
      break;
    }
    if (spent() >= budget || (executed > 0 && spent() + slowestTask > budget)) {
      stopped = 'time_budget';
      break;
    }
    const leased = leaseNext(storage, planId, { kinds: ['verify'] });
    if (leased.ok !== true || typeof leased['task_id'] !== 'string') {
      if (executed === 0 && leased.ok !== true) return leased;
      stopped = leased.ok !== true ? leased.error.code : leased['done'] === true ? 'done' : 'nothing_to_sample';
      break;
    }
    const taskId = leased['task_id'];
    const token = String(leased['lease_token']);
    // A task cut short gives its lease back: open again for the next call, no attempt spent.
    const giveBack = (why: string): void => {
      storage.llmScan.releaseLease(planId, taskId, token);
      stopped = why;
    };
    const taskStarted = clock();
    let text = `${String(leased['brief'])}\n\nAnswer schema:\n${JSON.stringify(leased['response_schema'])}`;
    let closed = false;
    for (let attempt = 0; attempt < MAX_INVALID_SUBMISSIONS; attempt += 1) {
      // Before EVERY request: none starts after the budget, nor a retry the slowest request would carry past it.
      if (cancelled()) {
        giveBack('cancelled');
        break;
      }
      if (spent() >= budget || (attempt > 0 && spent() + slowestRequest > budget)) {
        giveBack('time_budget');
        break;
      }
      let payload: unknown;
      const requestStarted = clock();
      try {
        const timeout = AbortSignal.timeout(Math.max(1, budget + REQUEST_MARGIN_MS - spent()));
        const reply = await sampling(
          { messages: [{ role: 'user', content: { type: 'text', text } }], systemPrompt: SYSTEM_PROMPT, maxTokens: MAX_ANSWER_TOKENS },
          { signal: opts.signal === undefined ? timeout : AbortSignal.any([timeout, opts.signal]) },
        );
        payload = reply.content.type === 'text' ? payloadOf(reply.content.text) : null;
      } catch (err) {
        // No answer — refused, failed, timed out or cancelled: nothing for the validator to count, so no attempt.
        failure = failureOf(err, cancelled());
        giveBack('sampling_failed');
        break;
      } finally {
        slowestRequest = Math.max(slowestRequest, clock() - requestStarted);
      }
      const res = submitAnswer(storage, { plan_id: planId, task_id: taskId, lease_token: token, independence: 'sampling', payload });
      if (res.ok === true && res['accepted'] === false && res['closed'] === undefined) {
        // Validator errors only: never file content.
        text += `\n\nYour previous answer was refused: ${JSON.stringify(res['errors'])}. Answer again with only the corrected JSON.`;
        continue;
      }
      if (res.ok === true) closed = true; // accepted, or closed (stale, or out of tries)
      else giveBack(res.error.code); // store_failed and the like: the task is still ours
      break;
    }
    if (closed) executed += 1;
    slowestTask = Math.max(slowestTask, clock() - taskStarted);
  }

  const loaded = loadPlan(storage, planId);
  if (!loaded.ok) return loaded;
  const plan = settlePlan(storage, loaded.plan);
  const report = reportOf(storage, plan);
  const remaining = storage.llmScan.listTasks(plan.id).filter((t) => t.status !== 'closed').length;
  return { ok: true, executed, remaining, stopped, ...(failure !== null ? { failure } : {}), report };
}

export const samplingUnavailable = (): Out =>
  fail(
    'sampling_unavailable',
    'This client did not declare the MCP sampling capability; use execute: "host" (the default) and run the briefs in subagents.',
  );
