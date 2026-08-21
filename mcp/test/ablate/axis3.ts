/**
 * Axis 3's unit of comparison, and the noise floor underneath it.
 *
 * ---- What axis 3 used to compare, and why it was noise -------------------
 *
 * The axis asks one question: *does this clause put findings into real code?*
 * It used to answer it by subtracting two WHOLE-CORPUS totals -- every rule in
 * the pack, every file in the corpus, before the ablation and after it. Two
 * things are wrong with that, and both were measured on `bugfix-cs.yml` over
 * `dotnet/runtime`:
 *
 *  1. **The attribution is structurally impossible.** A clause belongs to
 *     exactly one rule, and removing it cannot change what any OTHER rule
 *     matches. Yet all 14 findings the report attributed to clauses of
 *     `edge-case-modify-during-iteration` were `error-handling-empty-catch`
 *     findings, in `WMIGenerator.cs` and `XmlILOptimizerVisitor.cs`. They were
 *     not evidence about the clause at all; they were whatever else had moved
 *     between the two scans, landing on whichever clause happened to be under
 *     the knife.
 *
 *  2. **The totals jitter by more than the deltas.** Same pack, same corpus,
 *     two runs: 793 findings and 798. Axis 3 reports deltas of 2 and 3. A
 *     verdict of `+2` against a measurement error of +-5 is worse than no
 *     verdict, because it reads like a finding.
 *
 * So the comparison here is scoped twice over: to the ablated rule's OWN
 * findings, and to the files that every scan in the comparison finished. The
 * first is free -- it is just a filter -- and it removes the cross-rule
 * attribution outright. The second is what removes the jitter.
 *
 * ---- Why the exclusion is by FILE and not by (rule, file) ----------------
 *
 * Semgrep names the rule in a timeout: `Timeout when running <rule> on
 * <file>`. It is tempting to exclude only that pair. That is not enough.
 * `--timeout-threshold` (3 by default) drops the whole file for every rule
 * that has not run yet once three rules have timed out on it, and those rules
 * are never named anywhere in the output. In the measurement above, the five
 * findings that moved belonged to `empty-catch`, which appears in no timeout
 * message on either run: it was dropped WITH the file. Excluding the union of
 * timeout-affected FILES across the two runs took 793 vs 798 to 793 vs 793,
 * differing in nothing.
 *
 * The exclusion is a union across every scan in the comparison, not an
 * intersection, and it makes the verdict independent of WHICH side timed out:
 * whether the baseline or the ablated scan lost the file, the same findings
 * leave both sides, so the delta contributed is zero either way.
 *
 * What it costs: a clause whose only real-code effect is inside a file that
 * times out is invisible to axis 3. That is a blind spot with a name and a
 * printed size ({@link Axis3Scope.excludedFiles}), which is the difference
 * between a limitation and a defect.
 *
 * ---- The noise floor is measured, not assumed ----------------------------
 *
 * None of the above is worth anything if it is merely believed. The harness
 * scans the real corpus TWICE at baseline -- once with the pack as it sits on
 * disk, once with the byte-different but semantically identical round-trip of
 * it that every ablated variant is built from -- and runs
 * {@link noiseFloorByRule} over the pair. Two scans of the same rules over the
 * same code must agree exactly; whatever they disagree about is the floor, per
 * rule, and it is printed. A clause whose delta does not clear its rule's
 * floor is reported INCONCLUSIVE rather than as a finding.
 */

import { findingsMissingFrom } from './semgrep.js';
import type { Finding, ScanResult } from './semgrep.js';

/** What a single axis-3 comparison was allowed to look at. */
export interface Axis3Scope {
  /** Files dropped from both sides because some scan did not finish them. */
  readonly excluded: ReadonlySet<string>;
  /** Size of {@link excluded}, for the report. */
  readonly excludedFiles: number;
  /** Aborts that named no file, so nothing could be excluded for them. */
  readonly unscopedAborts: number;
}

/**
 * The files no scan in this comparison may be trusted on. Union, never
 * intersection: a file only one side lost is exactly the file that would
 * otherwise show up as a delta.
 */
export function scopeOf(scans: readonly ScanResult[]): Axis3Scope {
  const excluded = new Set<string>();
  let unscopedAborts = 0;
  for (const s of scans) {
    for (const f of s.abortedFiles) excluded.add(f);
    unscopedAborts += s.unscopedAborts;
  }
  return { excluded, excludedFiles: excluded.size, unscopedAborts };
}

/**
 * One rule's findings, on the files the comparison is allowed to look at.
 * Both filters matter and they are independent: the rule filter is what makes
 * the verdict an attribution rather than a coincidence, the file filter is
 * what makes it repeatable.
 */
export function comparable(
  findings: readonly Finding[],
  ruleId: string,
  scope: Axis3Scope,
): Finding[] {
  return findings.filter((f) => f.ruleId === ruleId && !scope.excluded.has(f.file));
}

/** Findings on the allowed files, all rules. Used for the corpus-wide counts. */
export function comparableAll(findings: readonly Finding[], scope: Axis3Scope): Finding[] {
  return findings.filter((f) => !scope.excluded.has(f.file));
}

/**
 * How far two scans of the SAME rules over the SAME code disagree, per rule,
 * once the scope is applied. Every entry should be 0. Any that is not is the
 * measurement error for that rule, and no axis-3 delta at or below it means
 * anything.
 *
 * Counted as the size of the symmetric difference rather than the difference
 * of the two counts, because a finding appearing in one scan and a different
 * one appearing in the other nets to zero and is still noise.
 */
export function noiseFloorByRule(
  a: readonly Finding[],
  b: readonly Finding[],
  ruleIds: readonly string[],
  scope: Axis3Scope,
): Map<string, number> {
  const floor = new Map<string, number>();
  for (const ruleId of ruleIds) {
    const ca = comparable(a, ruleId, scope);
    const cb = comparable(b, ruleId, scope);
    const drift = findingsMissingFrom(ca, cb).length + findingsMissingFrom(cb, ca).length;
    floor.set(ruleId, drift);
  }
  return floor;
}

/** The largest per-rule disagreement, i.e. the pack's noise floor. */
export function worstFloor(floor: ReadonlyMap<string, number>): number {
  let worst = 0;
  for (const n of floor.values()) if (n > worst) worst = n;
  return worst;
}

/** Rules whose two control scans disagreed, worst first, for the report. */
export function noisyRules(floor: ReadonlyMap<string, number>): { ruleId: string; drift: number }[] {
  return [...floor.entries()]
    .filter(([, drift]) => drift > 0)
    .map(([ruleId, drift]) => ({ ruleId, drift }))
    .sort((x, y) => y.drift - x.drift || x.ruleId.localeCompare(y.ruleId));
}

export type Axis3Verdict = 'PASS' | 'FAIL' | 'INCONCLUSIVE';

/**
 * `added` is what the clause put into real code: findings present with the
 * clause and gone without it, for the clause's own rule, on the allowed files.
 *
 * A delta that does not clear the rule's measured floor is INCONCLUSIVE, never
 * a pass and never a finding. `floor` is 0 in every measurement taken so far,
 * which makes this branch dead code on a healthy corpus -- and the only honest
 * answer on an unhealthy one.
 */
export function axis3Verdict(added: number, floor: number): Axis3Verdict {
  if (added === 0) return 'PASS';
  return added > floor ? 'FAIL' : 'INCONCLUSIVE';
}
