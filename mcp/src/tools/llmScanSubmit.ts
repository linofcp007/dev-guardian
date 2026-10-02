/**
 * `llm_scan_submit` — the answer to a leased task. A verdict or a hunt result
 * is validated against the schema and the disk before anything is stored; an
 * invalid one is refused with the reason and the task stays open (two more
 * tries). Closing a hunt task stores its findings and creates their verify
 * tasks in the same transaction.
 */

import { z } from 'zod';
import type { PluginContext } from '../context.js';
import { fail, submitAnswer } from '../llmscan/service.js';
import { registerToolModule, type ToolModule } from './index.js';

const inputSchema = {
  plan_id: z.string().min(1).max(100).describe('The plan the task belongs to.'),
  task_id: z.string().min(1).max(40).describe('The task, as llm_scan_task returned it.'),
  lease_token: z.string().min(1).max(100).describe('The lease_token llm_scan_task returned with the task.'),
  independence: z
    .enum(['subagent', 'same_context'])
    .describe("'subagent': a fresh context ran the brief. 'same_context': you ran it yourself — shown, never used to demote or confirm."),
  payload: z.unknown().describe('The answer, matching the task response_schema. At most 64 KiB serialized.'),
};

const parser = z.object(inputSchema).strict();

const tool: ToolModule = {
  name: 'llm_scan_submit',
  title: 'Submit the answer to an LLM scan task',
  description:
    'Submit the JSON answer to a task leased with llm_scan_task: plan_id, task_id, lease_token, independence (subagent when a ' +
    'fresh context ran the brief, same_context when you did) and payload (at most 64 KiB, matching the task response_schema). ' +
    'Returns { accepted: true, progress } or { accepted: false, errors: [{path, problem}], attempts_left }: an invalid answer is ' +
    'refused with the reason and the task stays yours for two more tries, then it closes undetermined. Every file:line it cites ' +
    'is checked against the project on disk. A hunt result stores its valid findings (unverified until a verdict) and creates a ' +
    'verify task for each; rejected ones are named. Errors: already_closed (a task takes one answer), bad_lease (wrong plan, task ' +
    'or token), too_large, plan_abandoned. If the target file changed since planning, the verdict is recorded stale and demotes ' +
    'nothing. After submitting, call llm_scan_task for the next task.',
  inputSchema,
  handler: async (input, ctx) => handler(input, ctx),
};

registerToolModule(tool);

async function handler(input: Record<string, unknown>, ctx: PluginContext) {
  const parsed = parser.safeParse(input);
  if (!parsed.success) {
    return fail('invalid_input', `Invalid input: ${parsed.error.issues.map((i) => `${i.path.join('.') || '$'}: ${i.message}`).join('; ')}`);
  }
  const { plan_id, task_id, lease_token, independence, payload } = parsed.data;
  return submitAnswer(ctx.storage, { plan_id, task_id, lease_token, independence, payload });
}
