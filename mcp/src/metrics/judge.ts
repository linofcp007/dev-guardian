/**
 * The judge of `metric-lines/1` — one rule for dev-guardian and
 * dev-spec-driven (the fixture's `judgeRule`, held case by case in
 * `test/unit/metrics/judge.test.ts`):
 *
 * - The terms (`better=`, `tolerance=`, the unit) are the REFERENCE's. The
 *   current line may only tighten: the smaller stated tolerance applies. A
 *   current line that adds a direction or a tolerance the reference lacks does
 *   not create one — the next reference carries it.
 * - A flipped or dropped `better=`, a raised or dropped tolerance or a changed
 *   unit is said once as `loosened`, and the value is judged by the
 *   reference's terms; a changed unit is not compared at all (no conversion).
 * - No defaults: a value is judged only when the reference states a direction
 *   AND a tolerance; otherwise it is `unjudged`, `why` naming the missing
 *   terms, shown with its delta.
 * - `n%` is n percent of |reference|; the boundary is inclusive and the
 *   verdict symmetric: `regressed` when worse by MORE than the tolerance,
 *   `improved` when better by more, `within` when |delta| is at most it.
 * - Values compare as exact decimals (`decimal.ts`).
 */

import {
  absolute,
  compare,
  type Decimal,
  decimalNumber,
  minimum,
  multiply,
  negate,
  parseDecimal,
  shift,
  subtract,
} from './decimal.js';
import type { MetricReading, MetricTolerance } from './metricLine.js';

export type MetricVerdict = 'new' | 'within' | 'improved' | 'regressed' | 'unjudged';
export type MetricTerm = 'better' | 'tolerance' | 'unit';

/** In the fixture's vocabulary order — `why` lists them in it. */
const TERM_ORDER: readonly MetricTerm[] = ['better', 'tolerance', 'unit'];

export interface MetricJudgment {
  readonly verdict: MetricVerdict;
  /** `unjudged` only: the terms that kept the value from a judgment. */
  readonly why: readonly MetricTerm[] | null;
  /** The term the current line loosened, said beside the verdict — one, even when it loosened several. */
  readonly loosened: MetricTerm | null;
  /** current − reference, exactly; null for `new` and across a unit change. */
  readonly delta: Decimal | null;
  /** The absolute tolerance the verdict used; null unless judged. */
  readonly applied: Decimal | null;
}

/** The exact value of a reading (its printed number), or of a tolerance. */
function exactOf(raw: string): Decimal {
  // Both come from the line's grammar, which only prints decimals parseDecimal reads.
  return parseDecimal(raw) ?? { coef: 0n, exp: 0 };
}

/** A tolerance as an absolute amount: `n%` of |reference|, or `n` itself. */
function amountOf(t: MetricTolerance, referenceAbs: Decimal): Decimal {
  const n = exactOf(t.raw);
  return t.percent ? shift(multiply(n, referenceAbs), -2) : n;
}

/**
 * Which term the current line loosened, if any: a changed unit first (the
 * value is then not compared at all), then a flipped or dropped direction,
 * then a raised or dropped tolerance.
 */
function loosenedTerm(reference: MetricReading, current: MetricReading, referenceAbs: Decimal): MetricTerm | null {
  if (reference.unit !== current.unit) return 'unit';
  if (reference.better !== null && current.better !== reference.better) return 'better';
  if (reference.tolerance !== null) {
    if (current.tolerance === null) return 'tolerance';
    if (compare(amountOf(current.tolerance, referenceAbs), amountOf(reference.tolerance, referenceAbs)) > 0) return 'tolerance';
  }
  return null;
}

/** `current` judged against `reference` (null: no earlier reading of the name — `new`). */
export function judgeMetric(reference: MetricReading | null, current: MetricReading): MetricJudgment {
  if (reference === null) return { verdict: 'new', why: null, loosened: null, delta: null, applied: null };
  const ref = exactOf(reference.raw);
  const refAbs = absolute(ref);
  const loosened = loosenedTerm(reference, current, refAbs);
  const missing = new Set<MetricTerm>();
  if (reference.better === null) missing.add('better');
  if (reference.tolerance === null) missing.add('tolerance');
  if (reference.unit !== current.unit) missing.add('unit');
  const delta = missing.has('unit') ? null : subtract(exactOf(current.raw), ref);
  const better = reference.better;
  const tolerance = reference.tolerance;
  if (delta === null || better === null || tolerance === null) {
    return { verdict: 'unjudged', why: TERM_ORDER.filter((t) => missing.has(t)), loosened, delta, applied: null };
  }
  // The reference's tolerance, or the current's when it is smaller: a line may tighten its judge, never loosen it.
  const stated = amountOf(tolerance, refAbs);
  const applied = current.tolerance === null ? stated : minimum(stated, amountOf(current.tolerance, refAbs));
  const worse = better === 'lower' ? delta : negate(delta);
  const verdict: MetricVerdict =
    compare(worse, applied) > 0 ? 'regressed' : compare(negate(worse), applied) > 0 ? 'improved' : 'within';
  return { verdict, why: null, loosened, delta, applied };
}

/** A judgment with its decimals as the numbers the fixture and the JSON output carry. */
export function judgmentNumbers(j: MetricJudgment): { delta: number | null; applied: number | null } {
  return {
    delta: j.delta === null ? null : decimalNumber(j.delta),
    applied: j.applied === null ? null : decimalNumber(j.applied),
  };
}
