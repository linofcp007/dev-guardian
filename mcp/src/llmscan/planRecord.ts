/**
 * What an `llm_scan` plan's scan record says the plan measured: its
 * `tools_run` and `missing_tools`, from which every history reader judges
 * the record's coverage (`tools/scanCoverage.ts#computeCoverage`) and what a
 * comparison may call resolved (`history/runCompare.ts`).
 *
 * The record is written completed when the plan starts, and the hunt's
 * findings are added as its answers are accepted. Its bookkeeping used to be
 * fixed at that start — `[llm-hunt ok]`, read "measured everything" — so a
 * hunt only started was a full, zero-finding scan: the open set's `llm_scan`
 * source, and the scan that resolved an earlier hunt's confirmed findings
 * (measured on 2026-11-20). It now follows the hunt and cross-cutting tasks
 * that have a VALID answer — a task closed as not delivered (a limit) or
 * after its invalid answers ran out does not count:
 *
 *   - none of them, or the plan has none: `llm-hunt` skipped with its reason,
 *     and missing — coverage `none`, a scan that did not run;
 *   - some of them: `llm-hunt` ok, with its pass `llm-hunt:open-tasks`
 *     missing — `partial`. A `base:suffix` name is a pass of its base
 *     (`history/runNames.ts`), so the hunt's findings read as not re-measured,
 *     never resolved. Never `llm-hunt` ok AND missing: that is the retry shape,
 *     which reads as measured;
 *   - all of them: `llm-hunt` ok, nothing missing — `full` — when no entry
 *     point of the plan's report is set aside or not visited; one that is
 *     keeps it `partial`.
 *
 * The record counts what was HUNTED (the owner's ruling of 2026-11-21): the
 * verify tasks — open, or closed stale, not delivered or after their invalid
 * answers — findings left out of a full plan, and a hunt by groups of files
 * in a project with no entry points do not hold it back, although the plan's
 * own report says `partial` for each of them.
 *
 * "Answered" and the entry points' accounts are both read off the plan's
 * report (`report.ts#computeReport`), never decided a second time here. A plan that
 * does not hunt writes no bookkeeping, and its record is never a state scan
 * (`history/scanRoles.ts#isVerifyOnlyPlanRecord`).
 */

import type { Bookkeeping } from '../history/runCompare.js';
import { LLM_HUNT_TOOL } from '../history/scanRoles.js';
import type { ToolRun } from '../types.js';
import { computeReport } from './report.js';
import type { LlmScanPlan, LlmScanTask } from './types.js';

/** The pass still open while the hunt is part done. */
const OPEN_TASKS = `${LLM_HUNT_TOOL}:open-tasks`;

/**
 * The hunt's entry in `tools_run`. Its name is written out rather than taken
 * from LLM_HUNT_TOOL: `test/unit/history/runNames.test.ts` reads every name a
 * scan writes to `tools_run` from the source, and cannot read one written
 * through a constant.
 */
function huntRun(run: Pick<ToolRun, 'status' | 'reason'>): ToolRun {
  return { name: 'llm-hunt', status: run.status, ...(run.reason !== undefined ? { reason: run.reason } : {}) };
}

/** What `plan`'s scan record says it measured, from its tasks as they stand. */
export function planRecordBookkeeping(plan: LlmScanPlan, tasks: readonly LlmScanTask[]): Bookkeeping {
  if (!plan.modes.includes('hunt')) return { tools_run: [], missing_tools: [] };
  const hunts = tasks.filter((t) => t.kind === 'hunt' || t.kind === 'crosscut');
  const report = computeReport(plan, tasks);
  const unanswered = new Set(report.missing);
  const answered = hunts.filter((t) => !unanswered.has(t.task_id)).length;
  if (answered === 0) {
    const reason =
      hunts.length === 0
        ? 'the plan has no hunt task: nothing in the project was eligible for one'
        : `none of the plan's ${String(hunts.length)} hunt task(s) has a valid answer`;
    return { tools_run: [huntRun({ status: 'skipped', reason })], missing_tools: [LLM_HUNT_TOOL] };
  }
  // What was hunted, not the whole plan: verify tasks and a hunt by groups of files (no entry points) do not count.
  const whole = answered === hunts.length && report.entry_points.every((e) => e.status === 'visited');
  return { tools_run: [huntRun({ status: 'ok' })], missing_tools: whole ? [] : [OPEN_TASKS] };
}
