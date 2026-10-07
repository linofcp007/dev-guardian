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
import { InvalidProjectPathError, resolveProjectPath } from '../platform/projectPath.js';
import { ProjectPath } from '../schemas.js';
import { registerToolModule, type ToolModule } from './index.js';

const inputSchema = {
  project_path: ProjectPath,
  modes: z
    .array(z.enum(['verify', 'hunt']))
    .min(1)
    .max(2)
    .optional()
    .describe("'verify' checks scanner findings, 'hunt' looks for what scanners miss from the entry points. Default ['verify']."),
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
  plan_id: z.string().min(1).max(100).optional().describe('Read this plan status and report instead of planning (with confirm: true, also confirm it).'),
};

const parser = z.object(inputSchema).strict();

const tool: ToolModule = {
  name: 'llm_scan_start',
  title: 'Plan an LLM-assisted scan',
  description:
    "Plan a scan in which YOUR model checks the scanners' findings and hunts what they miss; this server calls no model. " +
    'modes: verify (one task per finding with a file and line) and/or hunt (needs map_attack_surface first). Returns plan_id, ' +
    'the task count, what was left out and why (not_eligible, set_aside) and a token estimate; above max_estimated_tokens ' +
    '(default 500000) nothing is handed out until confirm: true. The loop: (1) llm_scan_task {plan_id} gives a task with a brief ' +
    'and a lease_token; (2) run that brief in a FRESH subagent/context, one per task (tasks may run in parallel); (3) ' +
    "llm_scan_submit {plan_id, task_id, lease_token, independence: 'subagent'|'same_context', payload} with its JSON answer; " +
    '(4) repeat until llm_scan_task says done. llm_scan_start {plan_id} returns the report at any time: counts, coverage ' +
    '(full only when every task closed and every entry point was visited), demoted findings, hunt findings. Only an independent ' +
    "verdict ('subagent', or 'sampling') demotes or confirms a finding. The real token use is known only to the host.",
  inputSchema,
  handler: async (input, ctx) => handler(input, ctx),
};

registerToolModule(tool);

async function handler(input: Record<string, unknown>, ctx: PluginContext) {
  const parsed = parser.safeParse(input);
  if (!parsed.success) {
    return fail('invalid_input', `Invalid input: ${parsed.error.issues.map((i) => `${i.path.join('.') || '$'}: ${i.message}`).join('; ')}`);
  }
  const inp = parsed.data;

  let project: string;
  try {
    project = resolveProjectPath(inp.project_path).path;
  } catch (e) {
    if (e instanceof InvalidProjectPathError) return fail('not_a_git_repo', e.message);
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
