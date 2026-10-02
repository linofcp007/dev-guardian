/**
 * The planner — pure: the open set's findings, the latest surface snapshot
 * and the limits in, the tasks out. No I/O, no clock, no storage; the tool
 * (`tools/llmScanStart.ts`) reads the inputs and persists the result.
 *
 *   - verify: one task per eligible finding — one with a file and a line;
 *     every other finding is `not_eligible`, with the reason (EC-1).
 *   - hunt: one task per group of at most {@link MAX_ROUTES_PER_HUNT_TASK}
 *     routes of the same handler file, plus one cross-cutting task
 *     (US-2.AC-1). With no entry points at all, tasks per group of code
 *     files, and the plan says so (US-2.AC-2).
 *   - nothing at all to plan: an empty plan with the reason (EC-3), never a
 *     clean one.
 *
 * Task ids are sequential (`t-0001`, …).
 */
/** US-2.AC-1 */
export const MAX_ROUTES_PER_HUNT_TASK = 5;
/**
 * The stable name of one entry point — what a hunt task's
 * `target.entry_points`, `set_aside` and the report's accounting all use.
 */
export function entryPointId(_route, _projectPath) {
    throw new Error('NotImplemented: entryPointId');
}
export function buildPlan(_input) {
    throw new Error('NotImplemented: buildPlan');
}
//# sourceMappingURL=plan.js.map