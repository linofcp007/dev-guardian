/**
 * Running verify tasks through the client's MCP sampling (`execute:
 * 'sampling'`, US-3.AC-2). Each task is leased and answered through the SAME
 * `leaseNext` / `submitAnswer` a host uses, so every sampled answer meets the
 * same validators, attempt limit and guarded writes. The verdict is recorded
 * as independence `sampling`: a fresh model context the server did not run.
 *
 * One call stays under the hosts' common 60 s budget (US-3.AC-3), counted from
 * the tool's entry: no task is started unless the slowest one so far would
 * still end within the budget, and no REQUEST is sent after the budget is
 * spent (a task cut short stays leased, with no attempt spent for a request
 * never sent). Hunts need tools, which sampling does not give them, so they
 * are never leased here and stay for the host.
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
  let slowest = 0;
  let executed = 0;
  let stopped: string | null = null;

  while (stopped === null) {
    if (spent() >= budget || (executed > 0 && spent() + slowest > budget)) {
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
    const taskStarted = clock();
    let sent = false;
    let text = `${String(leased['brief'])}\n\nAnswer schema:\n${JSON.stringify(leased['response_schema'])}`;
    let settled = false;
    for (let attempt = 0; attempt < MAX_INVALID_SUBMISSIONS && !settled; attempt += 1) {
      // Before EVERY request: none starts after the budget; the task stays leased, no attempt spent.
      if (spent() >= budget) {
        stopped = 'time_budget';
        break;
      }
      let payload: unknown;
      try {
        sent = true;
        const reply = await sampling(
          { messages: [{ role: 'user', content: { type: 'text', text } }], systemPrompt: SYSTEM_PROMPT, maxTokens: MAX_ANSWER_TOKENS },
          { signal: AbortSignal.timeout(Math.max(1, budget + REQUEST_MARGIN_MS - spent())) },
        );
        payload = reply.content.type === 'text' ? payloadOf(reply.content.text) : null;
      } catch {
        // The client refused, failed or timed out: spend an attempt so the lease does not hang for 20 minutes, and stop.
        submitAnswer(storage, { plan_id: planId, task_id: taskId, lease_token: token, independence: 'sampling', payload: null });
        stopped = 'sampling_failed';
        break;
      }
      const res = submitAnswer(storage, { plan_id: planId, task_id: taskId, lease_token: token, independence: 'sampling', payload });
      const refusedWithTriesLeft = res.ok === true && res['accepted'] === false && res['closed'] === undefined;
      if (refusedWithTriesLeft) {
        // Validator errors only: never file content.
        text += `\n\nYour previous answer was refused: ${JSON.stringify(res['errors'])}. Answer again with only the corrected JSON.`;
      } else {
        settled = true;
      }
    }
    if (sent) executed += 1;
    slowest = Math.max(slowest, clock() - taskStarted);
  }

  const loaded = loadPlan(storage, planId);
  if (!loaded.ok) return loaded;
  const plan = settlePlan(storage, loaded.plan);
  const report = reportOf(storage, plan);
  const remaining = storage.llmScan.listTasks(plan.id).filter((t) => t.status !== 'closed').length;
  return { ok: true, executed, remaining, stopped, report };
}

export const samplingUnavailable = (): Out =>
  fail(
    'sampling_unavailable',
    'This client did not declare the MCP sampling capability; use execute: "host" (the default) and run the briefs in subagents.',
  );
