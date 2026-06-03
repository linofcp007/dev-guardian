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
}

export interface ScoreResult {
  score: number;
  raw: number;
  recommendation: Recommendation;
  by_severity: Record<Severity, number>;
  executable_findings: number;
  total_findings: number;
}

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
  for (const s of signals) {
    by_severity[s.severity] += 1;
    const base = SEVERITY_POINTS[s.severity];
    raw += s.isExecutable ? base * EXECUTABLE_MULTIPLIER : base;
    if (s.isExecutable) executableFindings += 1;
  }
  const score = Math.min(100, Math.round(raw));
  return {
    score,
    raw: Math.round(raw),
    recommendation: recommendationFor(score),
    by_severity,
    executable_findings: executableFindings,
    total_findings: signals.length,
  };
}
