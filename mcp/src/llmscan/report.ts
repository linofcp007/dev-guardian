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

import type { ScanCoverage } from '../types.js';
import type { Independence, LlmScanPlan, LlmScanTask, LlmVerdict, TaskKind } from './types.js';

export interface EntryPointAccount {
  entry_point: string;
  status: 'visited' | 'set_aside' | 'not_visited';
  /** The closed task that visited it. */
  task_id?: string;
  /** Why it was set aside. */
  reason?: string;
}

export interface HuntFindingAccount {
  fingerprint: string;
  status: 'unverified' | LlmVerdict;
  /** Null while unverified. */
  independent: boolean | null;
  /** Every hunt task that reported it (EC-4). */
  sources: string[];
  verify_task_id: string | null;
}

export interface LlmScanReport {
  coverage: ScanCoverage;
  tasks: { planned: number; closed: number; open: number; leased: number; not_delivered: number };
  counts: {
    by_kind: Record<TaskKind, number>;
    by_verdict: Record<LlmVerdict, number>;
    by_independence: Record<Independence, number>;
  };
  /** Task ids not closed with an answer: open, leased, never delivered. */
  missing: string[];
  entry_points: EntryPointAccount[];
  /** Entry points not visited: set aside, or their task is not closed. */
  not_visited: string[];
  /** Findings an independent, non-stale `not_real` demotes. */
  demoted: Array<{ fingerprint: string; decisive_line: string; reasoning: string }>;
  hunt_findings: HuntFindingAccount[];
  /** US-4.AC-3: what was handed out and received, in characters. */
  sizes: { brief_chars: number; response_chars: number; estimated_brief_tokens: number };
  /** Statements a reader must see — among them, that only the host knows the real token use. */
  notes: string[];
}

export function computeReport(_plan: LlmScanPlan, _tasks: readonly LlmScanTask[]): LlmScanReport {
  throw new Error('NotImplemented: computeReport');
}
