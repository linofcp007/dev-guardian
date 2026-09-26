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
 *
 * One gap can be ACCEPTED rather than failed on (`--accept-partial-parse`,
 * argv only): a Semgrep step that ran but could read some files only in part
 * (the shared judge's `partial` verdict), when the caller named every one of
 * those files. The gap is then printed as accepted and does not force exit 2
 * — but `coverage` is computed over every gap, accepted ones included, so it
 * stays `partial` in the verdict, the JSON and the SARIF. Nothing else is
 * acceptable: a skipped, failed or scanned-nothing scanner, or a file the
 * caller did not name, exits 2 as before.
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
  /**
   * `--accept-partial-parse <path>` (repeatable; argv only, never read from a
   * repository file): project-relative files the caller accepts as only
   * partly parsed. Matched exactly against each step's `partial_parses`
   * after {@link normalizeAcceptedPath} — no globs, no directories, no case
   * folding.
   */
  acceptedPartialParses?: readonly string[];
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
  /**
   * One line per gap accepted by `--accept-partial-parse`: every file its
   * scanner only partly parsed was named. Not in `coverageGaps` and not in
   * the exit code — but still in `coverage`, which stays `partial`.
   */
  acceptedGaps: string[];
  /** `--accept-partial-parse` paths no step reported as partly parsed (normalised). */
  unusedPartialParseAcceptances: string[];
}

/**
 * The one spelling `--accept-partial-parse` paths and the scanners' partial
 * files are compared in: `/`-separated, without a leading `./`. Nothing else
 * — "matched exactly" means a directory, a glob or another case is another
 * path.
 */
export function normalizeAcceptedPath(path: string): string {
  let out = path.replace(/\\/g, '/');
  while (out.startsWith('./')) out = out.slice(2);
  return out;
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

const withReason = (reason: string | undefined): string => (reason ? ` (${reason})` : '');

/**
 * The gap line for one `missing_tools` name, worded from what that step's
 * `tools_run` says about it — or null when the failed-run line below
 * already names it. "Not installed" is said only when nothing says
 * otherwise: a step lists a scanner missing for reasons other than absence,
 * and every one of them has sent a reader to reinstall a working scanner.
 *
 *   - an `ok` run of the same name ran, but did not cover everything (files
 *     it could not read, a pack that failed to load) — scanCoverage.ts's
 *     own convention;
 *   - a `failed` run of the same name is reported as failed, once;
 *   - a run `skipped` for a reason other than `not_installed` did not scan,
 *     and its reason says why (scan_deps: `trivy` recognised no manifest);
 *   - `<scanner>:<part>` with no run of its own is one part of a scanner
 *     that ran (scan_deps: `trivy:dotnet`, a manifest ecosystem Trivy
 *     produced nothing for) and is worded from that scanner's run.
 */
function describeMissing(name: string, toolsRun: readonly ToolRun[]): string | null {
  const own = toolsRun.filter((run) => run.name === name);
  const ok = own.find((run) => run.status === 'ok');
  if (ok !== undefined) return `${name} ran with reduced coverage${withReason(ok.reason)}`;
  if (own.some((run) => run.status === 'failed')) return null;
  const skipped = own.find((run) => run.status === 'skipped' && run.reason && run.reason !== 'not_installed');
  if (skipped !== undefined) return `${name} skipped${withReason(skipped.reason)}`;
  const colon = name.indexOf(':');
  if (own.length === 0 && colon > 0) {
    const scanner = name.slice(0, colon);
    const part = name.slice(colon + 1);
    const base = toolsRun.find((run) => run.name === scanner && run.status === 'ok');
    if (base !== undefined) return `${scanner} ran with reduced coverage — ${part} not covered${withReason(base.reason)}`;
  }
  return `${name} not installed`;
}

/**
 * Whether one `missing_tools` entry of a step is an accepted partial parse:
 * the step names the files that are its whole cause (`partial_parses`), the
 * caller accepted every one, and no run of that name in the step was skipped
 * or failed (that would be a gap of its own, whatever was accepted).
 */
function acceptance(
  name: string,
  files: readonly string[],
  toolsRun: readonly ToolRun[],
  accepted: ReadonlySet<string>,
): { accepted: true } | { accepted: false; note: string } {
  if (files.length === 0) return { accepted: false, note: '' };
  const unaccepted = files.filter((f) => !accepted.has(f));
  if (unaccepted.length > 0) {
    return {
      accepted: false,
      note: ` — not accepted: ${unaccepted.join(', ')} (--accept-partial-parse <path> accepts one file, matched exactly)`,
    };
  }
  const other = toolsRun.find((run) => run.name === name && run.status !== 'ok');
  if (other !== undefined) {
    return { accepted: false, note: ` — its partial parse is accepted, but ${name} also ${other.status} in this step` };
  }
  return { accepted: true };
}

export function evaluateGate(input: GateInput): GateVerdict {
  const { findings, baseline, failOn, steps, droppedBaselineEntries } = input;
  const accepted = new Set((input.acceptedPartialParses ?? []).map(normalizeAcceptedPath));
  const reported = new Set<string>();

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
  // The same, minus the accepted gaps: what the exit code is decided on.
  const gatingMissingTools: string[] = [];
  const coverageGaps: string[] = [];
  const acceptedGaps: string[] = [];

  for (const step of steps) {
    allToolsRun.push(...step.tools_run);

    if (!step.ran) {
      allMissingTools.push(step.tool);
      gatingMissingTools.push(step.tool);
      coverageGaps.push(`${step.tool}: ${step.reason ?? 'did not run'}`);
      continue;
    }

    for (const missing of step.missing_tools) {
      allMissingTools.push(missing);
      const files = (step.partial_parses?.[missing] ?? []).map(normalizeAcceptedPath);
      for (const file of files) reported.add(file);
      const verdict = acceptance(missing, files, step.tools_run, accepted);
      if (verdict.accepted) {
        acceptedGaps.push(`${step.tool}: ${missing} only partly parsed ${files.join(', ')} — accepted (--accept-partial-parse)`);
        continue;
      }
      gatingMissingTools.push(missing);
      const gap = describeMissing(missing, step.tools_run);
      if (gap !== null) coverageGaps.push(`${step.tool}: ${gap}${verdict.note}`);
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

  // Every gap, accepted ones included: an accepted partial parse is still
  // partial coverage, and says so in the JSON and the SARIF.
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
  //
  // The exit code reads coverage WITHOUT the accepted gaps — the one thing
  // `--accept-partial-parse` changes.
  const exitCode: CiExitCode =
    blocking.length > 0 ? CI_EXIT.GATE_FAILED : exitCodeForCoverage(computeCoverage(allToolsRun, gatingMissingTools));

  return {
    exitCode,
    newFindings: newlyFound,
    blocking,
    coverage,
    coverageGaps,
    baselineAbsent: baseline === null,
    acceptedGaps,
    unusedPartialParseAcceptances: [...accepted].filter((path) => !reported.has(path)),
  };
}
