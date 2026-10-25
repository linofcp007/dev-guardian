/**
 * Risk scoring for a skill/agent audit.
 *
 * Aggregates every signal (pattern hit, signature match, taint flow, OSV
 * vuln) into a single 0–100 number plus an install recommendation, using the
 * field-standard weighting:
 *
 *   score = Σ severity_points × (executable ? 1.3 : 1), capped at 100
 *
 *   CRITICAL=50  HIGH=25  MEDIUM=10  LOW=5  INFO=0
 *
 * Bands: SAFE 0–20 · REVIEW 21–35 · CAUTION 36–50 · DO_NOT_INSTALL 51–100.
 *
 * "Executable" is a script file, a command a hook or an MCP server config
 * runs, and a command in an instruction file scored at its rule's own
 * severity — the model runs that as written (`analyze.ts`).
 *
 * One signal is enough for DO_NOT_INSTALL when it is critical, or
 * `decisive` — a download-and-execute, a credential sent out, a decoded
 * payload run, at its rule's own severity. Summed, one such signal read 25
 * to 50: a single `curl https://… | bash` in setup.sh was REVIEW, "Minor
 * signals found" (review of 3.6.0). What the rules lowered — a placeholder
 * for the target, a citation — is not decisive, and sums as before.
 *
 * Pure function. No I/O.
 */

import type { Severity } from '../types.js';
import {
  EXECUTABLE_MULTIPLIER,
  SEVERITY_POINTS,
  recommendationFor,
  type Recommendation,
} from './taxonomy.js';

export interface ScoreSignal {
  severity: Severity;
  isExecutable: boolean;
  /**
   * False: counted in `by_severity` and `total_findings`, but adds no points
   * — a repeat of a signal already scored (a rule's second citation in the
   * same skill, see `analyze.ts`). Default true.
   */
  scored?: boolean;
  /** Enough on its own for DO_NOT_INSTALL (see the module doc). A critical signal always is. */
  decisive?: boolean;
}

export interface ScoreResult {
  score: number;
  raw: number;
  recommendation: Recommendation;
  by_severity: Record<Severity, number>;
  executable_findings: number;
  total_findings: number;
}

/** The lowest DO_NOT_INSTALL score: where one decisive signal puts a skill. */
const DECISIVE_FLOOR = 51;

export function scoreFindings(signals: ScoreSignal[]): ScoreResult {
  const by_severity: Record<Severity, number> = {
    info: 0,
    low: 0,
    medium: 0,
    high: 0,
    critical: 0,
  };
  let raw = 0;
  let executableFindings = 0;
  let decisive = false;
  for (const s of signals) {
    by_severity[s.severity] += 1;
    const scored = s.scored !== false;
    const base = scored ? SEVERITY_POINTS[s.severity] : 0;
    raw += s.isExecutable ? base * EXECUTABLE_MULTIPLIER : base;
    if (s.isExecutable) executableFindings += 1;
    if (scored && (s.decisive === true || s.severity === 'critical')) decisive = true;
  }
  const score = Math.min(100, Math.max(Math.round(raw), decisive ? DECISIVE_FLOOR : 0));
  return {
    score,
    raw: Math.round(raw),
    recommendation: recommendationFor(score),
    by_severity,
    executable_findings: executableFindings,
    total_findings: signals.length,
  };
}
