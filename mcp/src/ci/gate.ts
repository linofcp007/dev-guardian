/**
 * The gate: findings + baseline + threshold + coverage -> verdict and exit
 * code. Pure — every input arrives as an argument, so it can be tested from
 * fixtures with no filesystem or scanner involved.
 *
 * This module exists to enforce two rules:
 *
 *   1. Historical debt must not fail the build. A finding already present in
 *      the baseline never blocks, however severe — that is the whole point
 *      of a baseline: a repository adopting this tool with 200 existing
 *      findings must go green on day one.
 *   2. A missing scanner is not a green build. "Zero new findings" from a
 *      scan that did not run is not a pass; it is a scan that says nothing.
 *      `computeCoverage` (see `../tools/scanCoverage.ts`) is the single,
 *      shared definition of "did the scan actually run" — this module reuses
 *      it rather than re-deriving a second one that could disagree.
 *
 * `GATE_FAILED` outranks `INCOMPLETE_SCAN` when both apply: a real regression
 * is the actionable failure a pipeline must see, and the coverage gaps are
 * still reported alongside it, not swallowed by it.
 */

import { SEVERITY_ORDER, type Finding, type ScanCoverage, type Severity, type ToolRun } from '../types.js';
import { computeCoverage } from '../tools/scanCoverage.js';
import { newFindings } from './baseline.js';
import { CI_EXIT, type BaselineFile, type CiExitCode, type ScanStepResult } from './types.js';

export interface GateInput {
  findings: readonly Finding[];
  baseline: BaselineFile | null;
  failOn: Severity;
  steps: readonly ScanStepResult[];
  /**
   * Baseline entries `parseBaseline` could not validate — see
   * `BaselineParseResult['dropped']` in `./types.ts` (a future severity, a
   * corrupt line). Zero when the baseline is absent or parsed with nothing
   * dropped.
   *
   * Purely informational: folded into `coverageGaps` for visibility, never
   * into `coverage` or `exitCode`. A corrupt baseline LINE is not a scanner
   * that failed to run, so it does not get to invent a second, independent
   * reason to fail or flag the build — and it does not need to, because any
   * finding a dropped entry actually un-suppresses is still caught, on its
   * own severity merits, by the ordinary blocking-findings path below. What
   * this field adds is the other half of the story: naming WHY a fingerprint
   * that used to be known is not known any more, so a reader can tell "the
   * bug came back" apart from "the parser lost a line".
   */
  droppedBaselineEntries: number;
}

export interface GateVerdict {
  exitCode: CiExitCode;
  newFindings: Finding[];
  /** New findings at or above `failOn`. Subset of `newFindings`. */
  blocking: Finding[];
  coverage: ScanCoverage;
  /** One line per gap, naming the scanner and why. Empty only when none. */
  coverageGaps: string[];
  /**
   * True exactly when `GateInput.baseline` was `null` — no baseline file
   * could be read at all (absent, unparseable, or the wrong shape at the
   * document level; see `parseBaseline`'s module doc in `./baseline.ts`),
   * as distinct from a baseline that WAS read and simply lists nothing.
   * `newFindings` treats those two cases identically (nothing is known
   * either way, so everything is new) — which is exactly why this can't be
   * inferred from `newFindings`/`blocking`/`coverage` after the fact, and
   * has to be carried forward from `baseline` directly. Visibility only:
   * it must never feed `exitCode` or `coverage` — historical debt on a
   * repository's first scan is still historical debt once a baseline is
   * adopted, not a reason to fail or flag THIS build.
   */
  baselineAbsent: boolean;
}

/**
 * Coverage in, exit code out — the half of the gate's exit-code rule that
 * does not depend on findings at all. Exported so a caller that has no
 * `blocking` concept of its own (`dev-guardian baseline update`: it writes
 * the baseline unconditionally and has no pass/fail gate, but still has to
 * say whether the write it just made reflects every scanner running) can
 * reuse this exact mapping instead of re-encoding it as a second ternary
 * outside this module. `evaluateGate` below calls this too, so there is
 * only ever one definition of "what does an incomplete scan's coverage
 * value mean for an exit code", not two that could drift apart.
 */
export function exitCodeForCoverage(coverage: ScanCoverage): CiExitCode {
  return coverage === 'full' ? CI_EXIT.PASS : CI_EXIT.INCOMPLETE_SCAN;
}

export function evaluateGate(input: GateInput): GateVerdict {
  const { findings, baseline, failOn, steps, droppedBaselineEntries } = input;

  // Coverage comes from a single call to computeCoverage over the union of
  // every step's tool bookkeeping — never a second, hand-rolled notion of
  // "complete". A step that refused to run (`ran: false`) contributes its
  // own `tool` name into the "missing" side of that union: it is a gap in
  // exactly the sense computeCoverage already understands (something
  // expected did not happen), so `coverage` itself comes out 'partial' or
  // 'none' rather than leaving `coverage: 'full'` sitting next to an
  // INCOMPLETE_SCAN exit code.
  const allToolsRun: ToolRun[] = [];
  const allMissingTools: string[] = [];
  const coverageGaps: string[] = [];

  for (const step of steps) {
    allToolsRun.push(...step.tools_run);

    if (!step.ran) {
      allMissingTools.push(step.tool);
      coverageGaps.push(`${step.tool}: ${step.reason ?? 'did not run'}`);
      continue;
    }

    for (const missing of step.missing_tools) {
      allMissingTools.push(missing);
      coverageGaps.push(`${step.tool}: ${missing} not installed`);
    }

    for (const run of step.tools_run) {
      if (run.status === 'failed') {
        coverageGaps.push(`${step.tool}: ${run.name} failed${run.reason ? ` (${run.reason})` : ''}`);
      }
      // status 'skipped' (nothing to do, e.g. no Dockerfile) is deliberately
      // not a gap — computeCoverage's own contract, see scanCoverage.ts.
    }
  }

  if (droppedBaselineEntries > 0) {
    const noun = droppedBaselineEntries === 1 ? 'entry' : 'entries';
    const verb = droppedBaselineEntries === 1 ? 'is' : 'are';
    coverageGaps.push(
      `baseline: ${droppedBaselineEntries} ${noun} could not be read and ${verb} no longer suppressed`,
    );
  }

  const coverage = computeCoverage(allToolsRun, allMissingTools);

  // Historical debt must not fail the build: `newFindings` already excludes
  // anything the baseline recognises by fingerprint, however severe.
  const newlyFound = newFindings(findings, baseline);
  const blocking = newlyFound.filter(
    (finding) => SEVERITY_ORDER[finding.severity] >= SEVERITY_ORDER[failOn],
  );

  // GATE_FAILED outranks whatever exitCodeForCoverage would say on its own:
  // a real regression is the actionable failure a pipeline must see, ahead
  // of an incomplete-scan signal that is still reported (via coverageGaps)
  // but does not get to hide a blocking finding behind it.
  const exitCode: CiExitCode = blocking.length > 0 ? CI_EXIT.GATE_FAILED : exitCodeForCoverage(coverage);

  return {
    exitCode,
    newFindings: newlyFound,
    blocking,
    coverage,
    coverageGaps,
    baselineAbsent: baseline === null,
  };
}
