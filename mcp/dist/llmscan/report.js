/**
 * The plan's report — counts and coverage computed in code from the stored
 * plan and tasks, never taken from a model (US-1.AC-5).
 *
 * Coverage is `full` only when every planned task closed with a valid answer
 * and every entry point was visited (SC-004). An open or leased task, a task
 * never delivered (a limit was reached), an entry point set aside or not yet
 * visited, or a hunt with no entry points at all (US-2.AC-2) makes it
 * `partial`, and the report names what is missing.
 */
export function computeReport(_plan, _tasks) {
    throw new Error('NotImplemented: computeReport');
}
//# sourceMappingURL=report.js.map