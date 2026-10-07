/**
 * `llm_scan_task` — the next task of a plan, leased to the caller for twenty
 * minutes: its brief, the schema its answer must follow, and the lease token
 * `llm_scan_submit` needs. `{ done: true, report }` when the plan is over.
 */
import { z } from 'zod';
import { fail, leaseNext } from '../llmscan/service.js';
import { runSampling, samplingUnavailable } from '../llmscan/sampling.js';
import { registerToolModule } from './index.js';
const inputSchema = {
    plan_id: z.string().min(1).max(100).describe('The plan from llm_scan_start.'),
    execute: z
        .enum(['host', 'sampling'])
        .optional()
        .describe("'host' (default): hand the task out. 'sampling': run tasks through the client's MCP sampling, where it offers it."),
};
const parser = z.object(inputSchema).strict();
const tool = {
    name: 'llm_scan_task',
    title: 'Lease the next LLM scan task',
    description: 'Lease the next task of a plan made by llm_scan_start. Returns task_id, kind (verify, hunt, crosscut), lease_token, ' +
        'lease_expires_at, brief (self-contained: give it to a FRESH subagent/context, one per task) and response_schema (the ' +
        "JSON answer's schema), attempts_left; or { done: true, report } when every task is closed; or { waiting: true } when " +
        'the rest are leased to others. Then call llm_scan_submit with the answer. Errors: needs_confirm (the estimate is above ' +
        'the limit: llm_scan_start {plan_id, confirm: true}), limit_reached (max_tasks or max_estimated_tokens hit: the tasks ' +
        'not delivered are named and coverage is partial), plan_abandoned. A task whose file changed since planning is closed ' +
        "stale, not handed out. execute: 'sampling' runs tasks through the client's MCP sampling instead, where the client offers it.",
    inputSchema,
    // The brief is the bulk of the response and the model reads the text once.
    contentOnlyKeys: ['brief'],
    handler: async (input, ctx, meta) => handler(input, ctx, meta),
};
registerToolModule(tool);
async function handler(input, ctx, meta) {
    const began = Date.now(); // the sampling budget counts from the tool's entry
    const parsed = parser.safeParse(input);
    if (!parsed.success) {
        return fail('invalid_input', `Invalid input: ${parsed.error.issues.map((i) => `${i.path.join('.') || '$'}: ${i.message}`).join('; ')}`);
    }
    if (parsed.data.execute === 'sampling') {
        // `meta.sampling` exists only when the client declared the capability.
        if (meta?.sampling === undefined)
            return samplingUnavailable();
        return runSampling(ctx.storage, parsed.data.plan_id, meta.sampling, { began });
    }
    return leaseNext(ctx.storage, parsed.data.plan_id);
}
//# sourceMappingURL=llmScanTask.js.map