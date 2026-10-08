/**
 * The LLM-assisted scan's data model — the design of record's "Modelos de
 * Dados", as TypeScript. Types and constants only: nothing here does I/O.
 *
 * The server plans, hands out, validates, counts and stores; the host's model
 * only reasons. Everything a model sends back (`VerifyVerdict`, `HuntResult`)
 * is untrusted input until `submission.ts` has validated it against the
 * schema and the disk.
 */
/** Defaults of the design's API contract (`llm_scan_start`) and its limits. */
export const LLM_SCAN_DEFAULTS = {
    max_tasks: 200,
    /** US-4.AC-1: above this estimate the plan needs `confirm: true`. */
    max_estimated_tokens: 500_000,
    /** The host's fixed cost per task, measured in the spike for a subagent. */
    per_task_overhead: 60_000,
    /** The same for a task run by MCP sampling (brief only, no agent context). */
    sampling_overhead: 1_000,
    /** A lease lasts this long; an expired lease returns the task to `open`. */
    lease_minutes: 20,
    /** No more than this many open plans per project. */
    max_open_plans: 5,
    /** `execute: 'sampling'` stops starting tasks once this much time has gone. */
    sampling_budget_ms: 50_000,
};
//# sourceMappingURL=types.js.map