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

import type { AttackSurfaceSnapshot, Finding, RouteRecord } from '../types.js';
import type { PlanEstimate, PlanLimits, ScanMode, TaskKind, TaskTarget } from './types.js';

/** US-2.AC-1 */
export const MAX_ROUTES_PER_HUNT_TASK = 5;

export interface PlanInput {
  /** Canonical project root; snapshot route files are absolute and relativized against it. */
  project_path: string;
  modes: readonly ScanMode[];
  /** The open set's findings (or the ones the caller named). */
  findings: readonly Finding[];
  /** The project's latest surface snapshot, or null when there is none. */
  surface: { id: number; snapshot: AttackSurfaceSnapshot } | null;
  /** Project-relative POSIX code files: the hunt's fallback when there are no entry points. */
  code_files: readonly string[];
  limits: PlanLimits;
  /** Estimated brief tokens of one planned task; a per-kind constant when omitted. */
  estimate_brief?: (task: PlannedTask) => number;
}

export interface PlannedTask {
  task_id: string;
  kind: TaskKind;
  target: TaskTarget;
}

export interface PlanResult {
  tasks: PlannedTask[];
  not_eligible: Array<{ fingerprint: string; reason: string }>;
  set_aside: Array<{ entry_point: string; reason: string }>;
  estimate: PlanEstimate;
  /** What a reader of the plan must be told about it — e.g. that no entry points were found (US-2.AC-2). */
  notes: string[];
  /** EC-3: why there is nothing to plan; null when there is something. */
  nothing_to_plan: string | null;
}

/**
 * The stable name of one entry point — what a hunt task's
 * `target.entry_points`, `set_aside` and the report's accounting all use.
 */
export function entryPointId(_route: RouteRecord, _projectPath: string): string {
  throw new Error('NotImplemented: entryPointId');
}

export function buildPlan(_input: PlanInput): PlanResult {
  throw new Error('NotImplemented: buildPlan');
}
