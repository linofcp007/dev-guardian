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
import type { Independence, LlmScanPlan, LlmScanTask, LlmVerdict, TaskKind, VerifyVerdict } from './types.js';

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

const ESTIMATED_CHARS_PER_TOKEN = 4;

/** The stored verdict of a verify task's answer. */
const STORED: Record<VerifyVerdict['verdict'], LlmVerdict> = {
  real: 'exploitable',
  not_real: 'not_exploitable',
  undetermined: 'undetermined',
};

const isVerify = (r: LlmScanTask['result']): r is VerifyVerdict => r !== null && 'verdict' in r;

/** Closed with a valid answer — the only way a task counts toward coverage. */
const answered = (t: LlmScanTask): boolean => t.status === 'closed' && t.closed_reason === 'valid';
const neverDelivered = (t: LlmScanTask): boolean => t.status === 'closed' && t.closed_reason === 'not_delivered';

export function computeReport(plan: LlmScanPlan, tasks: readonly LlmScanTask[]): LlmScanReport {
  const counts = {
    by_kind: { verify: 0, hunt: 0, crosscut: 0 } as Record<TaskKind, number>,
    by_verdict: { exploitable: 0, not_exploitable: 0, undetermined: 0 } as Record<LlmVerdict, number>,
    by_independence: { subagent: 0, sampling: 0, same_context: 0 } as Record<Independence, number>,
  };
  const demoted: LlmScanReport['demoted'] = [];
  const huntFindings = new Map<string, HuntFindingAccount>();
  const visitedBy = new Map<string, string>();
  const entryOrder: string[] = [];
  const known = new Set<string>();
  const note = (ep: string): void => {
    if (!known.has(ep)) {
      known.add(ep);
      entryOrder.push(ep);
    }
  };

  for (const t of tasks) {
    counts.by_kind[t.kind] += 1;
    if (answered(t) && t.independence !== null) counts.by_independence[t.independence] += 1;
    if (t.kind === 'verify') {
      const verdict = answered(t) && isVerify(t.result) ? STORED[t.result.verdict] : null;
      if (verdict !== null && isVerify(t.result)) {
        counts.by_verdict[verdict] += 1;
        if (verdict === 'not_exploitable' && t.independence !== 'same_context' && t.target.fingerprint !== undefined) {
          demoted.push({ fingerprint: t.target.fingerprint, decisive_line: t.result.decisive_line, reasoning: t.result.reasoning });
        }
      }
      const fp = t.target.fingerprint;
      if (t.target.origin_task_id !== undefined && fp !== undefined) {
        const prior = huntFindings.get(fp);
        huntFindings.set(fp, {
          fingerprint: fp,
          status: verdict ?? prior?.status ?? 'unverified',
          independent: verdict === null ? (prior?.independent ?? null) : t.independence !== null && t.independence !== 'same_context',
          sources: [...new Set([...(prior?.sources ?? []), t.target.origin_task_id])],
          verify_task_id: t.task_id,
        });
      }
      continue;
    }
    for (const ep of t.target.entry_points ?? []) {
      note(ep);
      if (answered(t) && !visitedBy.has(ep)) visitedBy.set(ep, t.task_id);
    }
  }

  const asideReason = new Map(plan.set_aside.map((s) => [s.entry_point, s.reason]));
  for (const ep of asideReason.keys()) note(ep);
  const entry_points: EntryPointAccount[] = entryOrder.map((ep) => {
    const by = visitedBy.get(ep);
    if (by !== undefined) return { entry_point: ep, status: 'visited', task_id: by };
    const reason = asideReason.get(ep);
    if (reason !== undefined) return { entry_point: ep, status: 'set_aside', reason };
    return { entry_point: ep, status: 'not_visited' };
  });
  const not_visited = entry_points.filter((e) => e.status !== 'visited').map((e) => e.entry_point);

  const missing = tasks.filter((t) => !answered(t)).map((t) => t.task_id);
  const taskCounts = {
    planned: tasks.length,
    closed: tasks.filter((t) => t.status === 'closed' && !neverDelivered(t)).length,
    open: tasks.filter((t) => t.status === 'open').length,
    leased: tasks.filter((t) => t.status === 'leased').length,
    not_delivered: tasks.filter(neverDelivered).length,
  };

  const notes = ["The real token use is known only to the host; the sizes here are the server's estimate."];
  // US-2.AC-2: a hunt with no entry points is never full coverage.
  const noEntryPoints = plan.modes.includes('hunt') && entry_points.length === 0;
  if (noEntryPoints) notes.push('The hunt had no entry points (the attack surface found none), so coverage cannot be full.');
  if (missing.length > 0) notes.push(`${String(missing.length)} task(s) not closed with a valid answer: ${missing.join(', ')}.`);
  if (not_visited.length > 0) notes.push(`${String(not_visited.length)} entry point(s) not visited.`);
  const unverified = [...huntFindings.values()].filter((h) => h.status === 'unverified').length;
  if (unverified > 0) notes.push(`${String(unverified)} hunt finding(s) are unverified.`);

  const coverage: ScanCoverage =
    tasks.length === 0 ? 'none' : missing.length === 0 && not_visited.length === 0 && !noEntryPoints ? 'full' : 'partial';

  const briefChars = tasks.reduce((n, t) => n + (t.brief_chars ?? 0), 0);
  return {
    coverage,
    tasks: taskCounts,
    counts,
    missing,
    entry_points,
    not_visited,
    demoted,
    hunt_findings: [...huntFindings.values()],
    sizes: {
      brief_chars: briefChars,
      response_chars: tasks.reduce((n, t) => n + (t.response_chars ?? 0), 0),
      estimated_brief_tokens: Math.ceil(briefChars / ESTIMATED_CHARS_PER_TOKEN),
    },
    notes,
  };
}
