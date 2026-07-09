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
 * scanners that did not run. The warning for 'none' explicitly states that a
 * zero-findings result is not a clean result — this is the anti-false-confidence
 * line that downstream summaries and the model must not paper over.
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

  const warning =
    coverage === 'none'
      ? `⚠️ ${scanType}: NO scanner ran (unavailable/failed: ${list}). ` +
        `A "0 findings" result is NOT a clean bill of health — nothing was actually scanned. ` +
        `Install ${list} (or use the Docker fallback) and re-run before trusting this scan.`
      : `⚠️ ${scanType}: partial coverage — ${list} did not run; findings may be incomplete.`;

  return { coverage, warning };
}
