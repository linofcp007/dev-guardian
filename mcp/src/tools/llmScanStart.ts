/**
 * `llm_scan_start` — plan an LLM-assisted scan (verify the scanners' findings,
 * hunt from the entry points), or, with `plan_id`, read a plan's status and
 * report. The planning, leasing and answers are `llmscan/service.ts`; the
 * model that does the reasoning is the host's, never this server's.
 */

import { z } from 'zod';
import type { PluginContext } from '../context.js';
import { LLM_SCAN_DEFAULTS, type ScanMode } from '../llmscan/types.js';
import { fail, planStatus, startPlan } from '../llmscan/service.js';
import { InvalidProjectPathError, projectPathErrorCode, resolveProjectPath } from '../platform/projectPath.js';
import { ProjectPath } from '../schemas.js';
import { defineTool, registerToolModule, type ToolInput } from './index.js';

const inputSchema = {
  project_path: ProjectPath,
  modes: z
    .array(z.enum(['verify', 'hunt']))
    .min(1)
    .max(2)
    .optional()
    .describe('verify checks scanner findings; hunt looks for what they miss. Default [verify].'),
  scan_id: z.guid().optional().describe('Verify the findings of this scan. Default: the project open set.'),
  fingerprints: z.array(z.string().min(1).max(200)).min(1).max(1000).optional().describe('Verify only these findings.'),
  max_tasks: z.number().int().min(1).optional().describe(`Stop handing out tasks after this many. Default ${String(LLM_SCAN_DEFAULTS.max_tasks)}.`),
  max_estimated_tokens: z
    .number()
    .int()
    .min(1)
    .optional()
    .describe(
      `Above this estimate the plan needs confirm: true, which never raises it; a larger limit needs a new plan. Default ${String(LLM_SCAN_DEFAULTS.max_estimated_tokens)}.`,
    ),
  per_task_overhead: z.number().int().min(0).optional().describe(`Host tokens assumed per task. Default ${String(LLM_SCAN_DEFAULTS.per_task_overhead)}.`),
  confirm: z.boolean().optional().describe('Start a plan above max_estimated_tokens once the user agrees; delivery still stops at that limit.'),
  plan_id: z
    .string()
    .min(1)
    .max(100)
    .optional()
    .describe("Return this plan's status and report instead of planning; takes project_path and confirm only (confirm: true confirms it)."),
};

const parser = z.object(inputSchema).strict();

/** The keys `start` takes next to `plan_id`; the rule is this list, never the list of the refused. */
const PLAN_ID_KEYS: readonly string[] = ['plan_id', 'project_path', 'confirm'];

const tool = defineTool({
  name: 'llm_scan_start',
  title: 'Plan an LLM-assisted scan',
  description:
    "Plan a scan where your model verifies the scanners' findings and hunts what they miss; the server " +
    'calls no model. modes: verify (a task per finding with a file and line), hunt (needs ' +
    'map_attack_surface). Returns plan_id, the task count, what was left out and a token estimate; above ' +
    'max_estimated_tokens nothing is handed out until confirm: true, which the user must agree to. Then ' +
    'repeat llm_scan {step: "task"}, the brief in a fresh subagent, llm_scan {step: "submit"}. llm_scan ' +
    '{step: "start", plan_id} returns the report.',
  inputSchema,
  handler: async (input, ctx) => handler(input, ctx),
});

registerToolModule(tool);

async function handler(input: ToolInput<typeof inputSchema>, ctx: PluginContext) {
  // Parsed again: an in-process caller (a test) hands its input unparsed, and
  // the step's own refusal is invalid_input.
  const parsed = parser.safeParse(input);
  if (!parsed.success) {
    return fail('invalid_input', `Invalid input: ${parsed.error.issues.map((i) => `${i.path.join('.') || '$'}: ${i.message}`).join('; ')}`);
  }
  const inp = parsed.data;

  // With plan_id the step reads or confirms an existing plan and takes exactly plan_id, project_path and
  // confirm. A plan's limits, modes and findings are fixed when it is made, so any other parameter is
  // refused, never ignored, before the plan is read (named in the schema's order).
  if (inp.plan_id !== undefined) {
    const given = new Map(Object.entries(inp));
    const refused = Object.keys(inputSchema).filter((key) => !PLAN_ID_KEYS.includes(key) && given.get(key) !== undefined);
    if (refused.length > 0) {
      return fail(
        'invalid_input',
        `llm_scan {step: "start", plan_id} takes project_path and confirm only; it does not take ${refused.join(', ')}. ` +
          'To read or confirm this plan, call llm_scan { step: "start", plan_id } with only project_path; to confirm it, add confirm: true, ' +
          "which the user must agree to. A plan's limits, modes and findings are fixed when it is made: for others, " +
          'start a new plan with llm_scan { step: "start" } without plan_id.',
        { plan_id: inp.plan_id },
      );
    }
  }

  let project: string;
  try {
    project = resolveProjectPath(inp.project_path).path;
  } catch (e) {
    if (e instanceof InvalidProjectPathError) return fail(projectPathErrorCode(e), e.message);
    throw e;
  }
  if (inp.plan_id !== undefined) {
    return planStatus(ctx.storage, inp.plan_id, inp.project_path === undefined ? null : project, inp.confirm === true);
  }
  return startPlan(ctx.storage, {
    project,
    modes: [...new Set<ScanMode>(inp.modes ?? ['verify'])],
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
