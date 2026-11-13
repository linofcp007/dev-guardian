/**
 * The verdict of one selftest control — a pure function of what was observed.
 *
 * Six verdicts, because each asks something different of the user:
 *
 *   - `detected` — the control ran to the end and reported its canary;
 *   - `silent` — it ran to the end, READ the canary, and reported nothing:
 *     a scan of that area with 0 findings proves nothing on this machine;
 *   - `missing` — the scanner is not installed;
 *   - `unverified` — the run cannot be taken to a verdict (it failed, timed
 *     out, was partial, never read the canary, had no vulnerability database,
 *     was not launched offline). Never `detected`, never `silent`;
 *   - `no_canary` — an installed scanner the selftest has no canary for. It is
 *     given to a scanner, never by {@link judgeControl};
 *   - `disabled_by_user` — a guard that answered more softly because the user
 *     switched it off: their decision, not a defect.
 *
 * The order of the rule matters and is the design's: a scanner that is not
 * there is `missing` whatever else was observed; a guard the user switched off
 * is `disabled_by_user` before anything is asked of its answer; and nothing
 * but a run that ended `ok` can say `detected` or `silent`.
 */

export const VERDICTS = ['detected', 'silent', 'missing', 'unverified', 'no_canary', 'disabled_by_user'] as const;
export type Verdict = (typeof VERDICTS)[number];

/** How a control's run ended. `partial`: the scanner says it did not cover everything it was given. */
export const RUN_ENDS = ['ok', 'partial', 'failed', 'timeout', 'not_run'] as const;
export type RunEnd = (typeof RUN_ENDS)[number];

export interface Observation {
  /** The scanner (or the hooks' dispatcher) is there to be run. */
  installed: boolean;
  ended: RunEnd;
  /** Whether the canary's file was read; `null` when that could not be learnt. */
  canaryRead: boolean | null;
  canaryReported: boolean;
  /** The user's own setting that makes the guard answer more softly, named. */
  softenedBy?: string;
  /** Why, for a verdict that is not `detected`. */
  reason?: string;
}

/** The one verdict an observation gets. */
export function judgeControl(o: Observation): Exclude<Verdict, 'no_canary'> {
  if (!o.installed) return 'missing';
  if (o.softenedBy !== undefined) return 'disabled_by_user';
  if (o.ended !== 'ok') return 'unverified';
  if (o.canaryReported) return 'detected';
  if (o.canaryRead === true) return 'silent';
  return 'unverified';
}

/**
 * The command's exit code from its controls' verdicts: 1 when one is
 * `silent`; 2 when none is and one is `unverified` or `missing`; 0 otherwise.
 * `no_canary` and `disabled_by_user` never change it.
 */
export function exitCodeFor(verdicts: readonly Verdict[]): 0 | 1 | 2 {
  if (verdicts.includes('silent')) return 1;
  if (verdicts.includes('unverified') || verdicts.includes('missing')) return 2;
  return 0;
}

/** How many controls got each verdict — every verdict present, at 0 when none did. */
export function countVerdicts(verdicts: readonly Verdict[]): Record<Verdict, number> {
  const counts = Object.fromEntries(VERDICTS.map((v) => [v, 0])) as Record<Verdict, number>;
  for (const v of verdicts) counts[v] += 1;
  return counts;
}

/** Worst first: what a scanner with several controls is summed up as. */
const SEVERITY: readonly Verdict[] = ['silent', 'unverified', 'missing', 'disabled_by_user', 'no_canary', 'detected'];

/** The worst of several verdicts (`silent` before `unverified` before `missing` …); `undefined` for none. */
export function worstVerdict(verdicts: readonly Verdict[]): Verdict | undefined {
  return SEVERITY.find((v) => verdicts.includes(v));
}
