/**
 * `llm_scan_start` — plan an LLM-assisted scan (verify the scanners' findings,
 * hunt from the entry points), or, with `plan_id`, read a plan's status and
 * report. The planning, leasing and answers are `llmscan/service.ts`; the
 * model that does the reasoning is the host's, never this server's.
 */
import { z } from 'zod';
import { LLM_SCAN_DEFAULTS } from '../llmscan/types.js';
import { fail, planStatus, startPlan } from '../llmscan/service.js';
import { InvalidProjectPathError, projectPathErrorCode, resolveProjectPath } from '../platform/projectPath.js';
import { ProjectPath } from '../schemas.js';
import { registerToolModule } from './index.js';
const inputSchema = {
    project_path: ProjectPath,
    modes: z
        .array(z.enum(['verify', 'hunt']))
        .min(1)
        .max(2)
        .optional()
        .describe('verify checks scanner findings; hunt looks for what they miss. Default [verify].'),
    scan_id: z.string().uuid().optional().describe('Verify the findings of this scan. Default: the project open set.'),
    fingerprints: z.array(z.string().min(1).max(200)).min(1).max(1000).optional().describe('Verify only these findings.'),
    max_tasks: z.number().int().min(1).optional().describe(`Stop handing out tasks after this many. Default ${String(LLM_SCAN_DEFAULTS.max_tasks)}.`),
    max_estimated_tokens: z
        .number()
        .int()
        .min(1)
        .optional()
        .describe(`Above this estimate the plan needs confirm: true. Default ${String(LLM_SCAN_DEFAULTS.max_estimated_tokens)}.`),
    per_task_overhead: z.number().int().min(0).optional().describe(`Host tokens assumed per task. Default ${String(LLM_SCAN_DEFAULTS.per_task_overhead)}.`),
    confirm: z.boolean().optional().describe('Accept an estimate above the limit.'),
    plan_id: z.string().min(1).max(100).optional().describe("Return this plan's status and report instead of planning (with confirm: true, confirm it)."),
};
const parser = z.object(inputSchema).strict();
const tool = {
    name: 'llm_scan_start',
    title: 'Plan an LLM-assisted scan',
    description: "Plan a scan where your model verifies the scanners' findings and hunts what they miss; the server " +
        'calls no model. modes: verify (a task per finding with a file and line), hunt (needs ' +
        'map_attack_surface). Returns plan_id, the task count, what was left out and a token estimate; above ' +
        'max_estimated_tokens nothing is handed out until confirm: true, which the user must agree to. Then ' +
        'repeat llm_scan_task, the brief in a fresh subagent, llm_scan_submit. llm_scan_start {plan_id} ' +
        'returns the report.',
    inputSchema,
    handler: async (input, ctx) => handler(input, ctx),
};
registerToolModule(tool);
async function handler(input, ctx) {
    const parsed = parser.safeParse(input);
    if (!parsed.success) {
        return fail('invalid_input', `Invalid input: ${parsed.error.issues.map((i) => `${i.path.join('.') || '$'}: ${i.message}`).join('; ')}`);
    }
    const inp = parsed.data;
    let project;
    try {
        project = resolveProjectPath(inp.project_path).path;
    }
    catch (e) {
        if (e instanceof InvalidProjectPathError)
            return fail(projectPathErrorCode(e), e.message);
        throw e;
    }
    if (inp.plan_id !== undefined) {
        return planStatus(ctx.storage, inp.plan_id, inp.project_path === undefined ? null : project, inp.confirm === true);
    }
    return startPlan(ctx.storage, {
        project,
        modes: [...new Set(inp.modes ?? ['verify'])],
        ...(inp.scan_id !== undefined ? { scan_id: inp.scan_id } : {}),
        ...(inp.fingerprints !== undefined ? { fingerprints: inp.fingerprints } : {}),
        limits: {
            max_tasks: inp.max_tasks ?? LLM_SCAN_DEFAULTS.max_tasks,
            max_estimated_tokens: inp.max_estimated_tokens ?? LLM_SCAN_DEFAULTS.max_estimated_tokens,
            per_task_overhead: inp.per_task_overhead ?? LLM_SCAN_DEFAULTS.per_task_overhead,
        },
        confirm: inp.confirm === true,
    });
}
//# sourceMappingURL=llmScanStart.js.map