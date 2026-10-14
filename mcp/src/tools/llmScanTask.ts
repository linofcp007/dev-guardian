/**
 * `llm_scan_task` — the next task of a plan, leased to the caller for twenty
 * minutes: its brief, the schema its answer must follow, and the lease token
 * `llm_scan_submit` needs. `{ done: true, report }` when the plan is over.
 */

import { z } from 'zod';
import type { PluginContext } from '../context.js';
import { fail, leaseNext } from '../llmscan/service.js';
import { runSampling, samplingUnavailable } from '../llmscan/sampling.js';
import { defineTool, registerToolModule, type ToolCallMeta, type ToolInput } from './index.js';

const inputSchema = {
  plan_id: z.string().min(1).max(100).describe('The plan from llm_scan {step: "start"}.'),
  execute: z
    .enum(['host', 'sampling'])
    .optional()
    .describe("host (default): hand the task out. sampling: run it through the client's MCP sampling."),
};

const parser = z.object(inputSchema).strict();

const tool = defineTool({
  name: 'llm_scan_task',
  title: 'Lease the next LLM scan task',
  description:
    'Lease the next task of a plan: task_id, kind, lease_token, brief (give it to a fresh subagent, one ' +
    'per task) and response_schema; or {done: true, report}, or {waiting: true}. Then llm_scan {step: ' +
    '"submit"} the answer. needs_confirm: llm_scan {step: "start", plan_id, confirm: true} first; ' +
    'limit_reached: coverage is partial, the undelivered tasks named. A task whose file changed is closed stale.',
  inputSchema,
  // The brief is the bulk of the response and the model reads the text once.
  contentOnlyKeys: ['brief'],
  handler: async (input, ctx, meta) => handler(input, ctx, meta),
});

registerToolModule(tool);

async function handler(input: ToolInput<typeof inputSchema>, ctx: PluginContext, meta?: ToolCallMeta) {
  const began = Date.now(); // the sampling budget counts from the tool's entry
  // Parsed again: an in-process caller (a test) hands its input unparsed, and
  // the step's own refusal is invalid_input.
  const parsed = parser.safeParse(input);
  if (!parsed.success) {
    return fail('invalid_input', `Invalid input: ${parsed.error.issues.map((i) => `${i.path.join('.') || '$'}: ${i.message}`).join('; ')}`);
  }
  if (parsed.data.execute === 'sampling') {
    // `meta.sampling` exists only when the client declared the capability.
    if (meta?.sampling === undefined) return samplingUnavailable();
    return runSampling(ctx.storage, parsed.data.plan_id, meta.sampling, { began, ...(meta.signal !== undefined ? { signal: meta.signal } : {}) });
  }
  return leaseNext(ctx.storage, parsed.data.plan_id);
}
