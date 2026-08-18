/**
 * Scan coverage — turn per-scanner bookkeeping into a single trust signal.
 *
 * A scan's headline severity counts are only trustworthy when the scanners
 * that were *supposed* to run actually ran. A SAST scan reporting "0 critical"
 * because Semgrep was not installed is NOT a clean bill of health — it scanned
 * nothing. Every scan tool already records which scanners ran (`tools_run`)
 * and which were expected but absent (`missing_tools`); this module distils
 * that into a `coverage` value the factory and roll-ups can surface so a
 * silent "0 findings" never reads as "all clear".
 */

import type { ScanCoverage, ToolRun } from '../types.js';

export type { ScanCoverage };

/**
 * Derive coverage from the per-scanner outcomes.
 *
 *   - 'none'    — nothing ran successfully and something was expected but
 *                 missing or failed. A "0 findings" result here is meaningless.
 *   - 'partial' — at least one scanner ran ok, but some expected scanner was
 *                 missing or failed. Findings may be incomplete.
 *   - 'full'    — every scanner that was attempted ran ok and nothing expected
 *                 was missing. Counts can be trusted.
 *
 * A scan that legitimately had nothing to do (e.g. `scan_containers` with no
 * Dockerfile and no image) reports 'full': there were no gaps, just no work.
 * Such "nothing to scan" skips must NOT be added to `missing_tools` (they are
 * `skipped` with a not-applicable reason instead).
 */
export function computeCoverage(
  toolsRun: readonly ToolRun[],
  missingTools: readonly string[],
): ScanCoverage {
  const ranOk = toolsRun.some((t) => t.status === 'ok');
  const failed = toolsRun.some((t) => t.status === 'failed');
  const hasGaps = missingTools.length > 0 || failed;
  if (!hasGaps) return 'full';
  return ranOk ? 'partial' : 'none';
}

export interface CoverageAssessment {
  coverage: ScanCoverage;
  /** Loud, human-readable warning when coverage !== 'full', else null. */
  warning: string | null;
}

/**
 * Compute coverage and, when it is not 'full', a loud warning naming the
 * scanner(s) responsible for the gap. The warning for 'none' explicitly
 * states that a zero-findings result is not a clean result — this is the
 * anti-false-confidence line that downstream summaries and the model must
 * not paper over. The warning for 'partial' distinguishes a scanner that
 * genuinely did not run from one that ran (its own `tools_run` entry says
 * 'ok') but is still a named gap — the latter must not be worded as "did
 * not run", which would contradict its own status in the same response.
 */
export function assessCoverage(
  scanType: string,
  toolsRun: readonly ToolRun[],
  missingTools: readonly string[],
): CoverageAssessment {
  const coverage = computeCoverage(toolsRun, missingTools);
  if (coverage === 'full') return { coverage, warning: null };

  const failedTools = toolsRun.filter((t) => t.status === 'failed').map((t) => t.name);
  const gaps = [...new Set([...missingTools, ...failedTools])];
  const list = gaps.length > 0 ? gaps.join(', ') : 'one or more scanners';

  if (coverage === 'none') {
    return {
      coverage,
      warning:
        `⚠️ ${scanType}: NO scanner ran (unavailable/failed: ${list}). ` +
        `A "0 findings" result is NOT a clean bill of health — nothing was actually scanned. ` +
        `Install ${list} (or use the Docker fallback) and re-run before trusting this scan.`,
    };
  }

  // coverage === 'partial'. A name in `gaps` can mean two different things:
  // it genuinely never ran (skipped/failed — "did not run" is accurate), or
  // it DID run (its own `tools_run` entry says 'ok') but coverage is still
  // short — e.g. bug_hunt retrying with surviving Semgrep packs after one
  // local `--config` failed to load: semgrep's own tools_run entry is 'ok',
  // with the detail in its `reason`, yet `missing_tools` still (correctly)
  // carries 'semgrep' so this stays 'partial'. Saying "semgrep did not run"
  // in that case contradicts the structured tools_run entry sitting right
  // next to this warning in the same response — same family of bug as the
  // misleading "install semgrep" text fixed elsewhere (bugfix-rules-jsts).
  const ranOkNames = new Set(toolsRun.filter((t) => t.status === 'ok').map((t) => t.name));
  const notRun = gaps.filter((name) => !ranOkNames.has(name));
  const ranWithGaps = gaps.filter((name) => ranOkNames.has(name));
  const clauses: string[] = [];
  if (notRun.length > 0) clauses.push(`${notRun.join(', ')} did not run`);
  if (ranWithGaps.length > 0) {
    clauses.push(`${ranWithGaps.join(', ')} ran with reduced coverage (see its tools_run reason)`);
  }
  const clause = clauses.length > 0 ? clauses.join('; ') : `${list} did not run`;

  return {
    coverage,
    warning: `⚠️ ${scanType}: partial coverage — ${clause}; findings may be incomplete.`,
  };
}
