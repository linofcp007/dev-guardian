/**
 * `scoreRisk` — pure risk-scoring arithmetic, extracted from the `risk_score`
 * tool (`tools/riskScore.ts`) so the local dashboard can reuse it without
 * going through that tool's "any project" storage queries.
 *
 * Weights, caps, bands and recommendation strings are ported verbatim from
 * the tool this was extracted from — see
 * `docs/superpowers/specs/2026-08-15-local-dashboard-design.md` §3.1. This
 * module must not change what the numbers are, only where they are computed.
 *
 * Components (weighted sum, capped at 100):
 *   - 40 pts: severity-weighted finding count (critical=10, high=5, medium=2, low=1).
 *   - 30 pts: CVE count weighted by severity.
 *   - 15 pts: missing CI bots (renovate/dependabot) and policy docs.
 *   - 15 pts: stale baseline (more than 30 days old).
 *
 * Pure: every input arrives through `RiskInput`, including the clock. Never
 * call `Date.now()` in this file — that is what makes this function testable
 * without faking global time, and what lets `snapshot.ts` and `risk_score`
 * share one implementation while each supplies its own "now".
 */

import type { RiskAssessment, RiskInput } from './types.js';

export function scoreRisk(input: RiskInput): RiskAssessment {
  const findingsScore = clamp(
    input.findings.reduce((acc, f) => {
      switch (f.severity) {
        case 'critical': return acc + 10;
        case 'high':     return acc + 5;
        case 'medium':   return acc + 2;
        case 'low':      return acc + 1;
        default:         return acc;
      }
    }, 0),
    0,
    40,
  );

  const cveScore = clamp(
    input.cves.reduce((acc, c) => {
      switch (c.severity) {
        case 'critical': return acc + 8;
        case 'high':     return acc + 4;
        case 'medium':   return acc + 1.5;
        default:         return acc + 0.5;
      }
    }, 0),
    0,
    30,
  );

  // Compliance signals — penalise missing bots and policy docs.
  let complianceScore = input.policies_missing * 3; // up to 9
  if (!input.dependency_bot_configured) complianceScore += 6;
  complianceScore = clamp(complianceScore, 0, 15);

  // Baseline freshness.
  let baselineScore = 0;
  if (input.baseline_set_at === null) {
    baselineScore = 8; // never set a baseline → moderate penalty
  } else {
    const ageMs = input.now - new Date(input.baseline_set_at).getTime();
    const days = ageMs / (24 * 60 * 60 * 1000);
    if (days > 90) baselineScore = 15;
    else if (days > 30) baselineScore = 8;
  }

  const score = clamp(findingsScore + cveScore + complianceScore + baselineScore, 0, 100);
  const band = bandFor(score);
  const hasActiveBaseline = input.baseline_set_at !== null;

  return {
    score: Math.round(score),
    band,
    components: {
      findings: { score: Math.round(findingsScore), open_findings: input.findings.length },
      cves: { score: Math.round(cveScore), active_cves: input.cves.length },
      compliance: { score: Math.round(complianceScore), policies_missing: input.policies_missing },
      baseline: { score: Math.round(baselineScore), has_active_baseline: hasActiveBaseline },
    },
    next_action: recommendation(score, input.findings.length, input.cves.length, hasActiveBaseline),
    coverage_caveat: input.coverage_partial,
  };
}

function clamp(n: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, n));
}

function bandFor(score: number): 'low' | 'medium' | 'high' | 'critical' {
  if (score >= 70) return 'critical';
  if (score >= 40) return 'high';
  if (score >= 15) return 'medium';
  return 'low';
}

function recommendation(score: number, open: number, cves: number, hasBaseline: boolean): string {
  if (score >= 70) return 'Run audit_executive and triage critical findings before any new deploy.';
  if (cves > 0) return 'Address active CVEs via deps_update_plan with prefer=security.';
  if (!hasBaseline) return 'Set a baseline with set_baseline so diff_scans can track regressions.';
  if (open > 50) return 'Run triage_findings to identify likely false positives, then suppress.';
  return 'Posture is stable. Consider a periodic audit_executive to confirm.';
}
