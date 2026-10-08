/**
 * The LLM-assisted scan's data model — the design of record's "Modelos de
 * Dados", as TypeScript. Types and constants only: nothing here does I/O.
 *
 * The server plans, hands out, validates, counts and stores; the host's model
 * only reasons. Everything a model sends back (`VerifyVerdict`, `HuntResult`)
 * is untrusted input until `submission.ts` has validated it against the
 * schema and the disk.
 */

import type { CreateMessageRequest, CreateMessageResult } from '@modelcontextprotocol/sdk/types.js';
import type { LlmStoredVerdict } from '../validate/types.js';
import type { HuntClass } from './classes.js';

export type TaskKind = 'verify' | 'hunt' | 'crosscut';
export type Independence = 'subagent' | 'sampling' | 'same_context';
/** How a verdict is stored (`finding_validations`, provider `llm`). */
export type LlmVerdict = LlmStoredVerdict;
export type ScanMode = 'verify' | 'hunt';

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
} as const;

export interface PlanLimits {
  max_tasks: number;
  max_estimated_tokens: number;
  per_task_overhead: number;
}

export interface PlanEstimate {
  tasks: number;
  brief_tokens: number;
  total_tokens: number;
  /** What the estimate assumes (per-task overhead, chars per token), said in words. */
  assumptions: string;
}

export interface LlmScanPlan {
  id: string;
  project_path: string;
  /** The plan's `llm_scan` scan. */
  scan_id: string;
  modes: ScanMode[];
  prompt_version: string;
  tree_hash: string;
  surface_snapshot_id: number | null;
  limits: PlanLimits;
  estimate: PlanEstimate;
  /** US-4.AC-1 */
  confirmed: boolean;
  status: 'open' | 'complete' | 'abandoned';
  /** EC-1. `overflow`: left out only because the plan was full (it could have been verified). */
  not_eligible: Array<{ fingerprint: string; reason: string; overflow?: true }>;
  /** US-2.AC-6. `overflow`: as for `not_eligible`. */
  set_aside: Array<{ entry_point: string; reason: string; overflow?: true }>;
  created_at: string;
  updated_at: string;
}

export interface TaskTarget {
  fingerprint?: string;
  entry_points?: string[];
  /** Project-relative POSIX paths. */
  files: string[];
  /** For a verify task created from a hunt finding: the hunt task that found it. */
  origin_task_id?: string;
}

export interface LlmScanTask {
  plan_id: string;
  /** `t-0001`, … — sequential within a plan. */
  task_id: string;
  kind: TaskKind;
  target: TaskTarget;
  status: 'open' | 'leased' | 'closed';
  lease_token: string | null;
  lease_expires_at: string | null;
  /** Invalid submissions so far. */
  attempts: number;
  /** sha256 per file of the target, recorded when the plan was made (US-1.AC-9). */
  file_hashes: Record<string, string>;
  /** US-4.AC-3 */
  brief_chars: number | null;
  response_chars: number | null;
  independence: Independence | null;
  result: VerifyVerdict | HuntResult | null;
  closed_reason: 'valid' | 'invalid_submissions' | 'stale' | 'not_delivered' | null;
  delivered_at: string | null;
  closed_at: string | null;
}

/** A verify task's answer, as the model sends it (US-1.AC-3). */
export interface VerifyVerdict {
  /** Stored as exploitable / not_exploitable / undetermined. */
  verdict: 'real' | 'not_real' | 'undetermined';
  /** `file:line`, or `none`. */
  attacker_input: string;
  /** `file:line` */
  operation: string;
  /** `file:line — reason` */
  decisive_line: string;
  /** At most 120 words. */
  reasoning: string;
}

/** One hunt finding, as the model sends it (US-2.AC-3). */
export interface HuntFinding {
  file: string;
  line: number;
  class: HuntClass;
  /** At most 200 characters. */
  title: string;
  /** At most 200 characters. */
  attacker: string;
  /** At most 60 words, with at least one `file:line` reference. */
  evidence: string;
}

/** A hunt task's answer: at most 50 findings (US-2.AC-7). */
export interface HuntResult {
  entry_points_reviewed: string[];
  findings: HuntFinding[];
  /**
   * Set by the server when it stores the result, never sent by a model: the
   * fingerprints of the findings this task reported (EC-4 — the report names
   * every task that reported one).
   */
  fingerprints?: string[];
}

/**
 * What the open set attaches to a finding that has an `llm` validation
 * (`OpenFinding.llm`). Only an `independent` verdict demotes (`not_exploitable`)
 * or confirms (`exploitable`); a `same_context` one is shown and nothing more
 * (US-1.AC-7).
 */
export interface LlmMarker {
  verdict: LlmVerdict;
  independent: boolean;
  independence: Independence;
  decisive_line: string;
  reasoning: string;
  prompt_version: string;
}

/**
 * MCP sampling as a tool receives it (`ToolCallMeta.sampling`): one
 * `sampling/createMessage` round-trip to the client. Present only when the
 * client declared the `sampling` capability (US-3.AC-2).
 */
export type SamplingFn = (
  params: CreateMessageRequest['params'],
  options?: { signal?: AbortSignal },
) => Promise<CreateMessageResult>;
