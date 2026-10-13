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
    .describe('subagent: a fresh context ran the brief; same_context: you did (never demotes or confirms).'),
  payload: z.unknown().describe('The answer, matching the task response_schema. At most 64 KiB serialized.'),
};

const parser = z.object(inputSchema).strict();

const tool: ToolModule = {
  name: 'llm_scan_submit',
  title: "Submit an LLM scan task's answer",
  description:
    'Submit the JSON answer to a leased task: plan_id, task_id, lease_token, independence and payload (at ' +
    'most 64 KiB, matching response_schema). An invalid answer is refused with the reasons; the task ' +
    'stays yours for two more tries. Every file:line it cites is checked on disk. Errors: already_closed, ' +
    'bad_lease, too_large, plan_abandoned. Then llm_scan_task for the next.',
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
