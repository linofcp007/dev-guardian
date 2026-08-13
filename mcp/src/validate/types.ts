/**
 * The verdict envelope, shared by all three evidence providers.
 *
 * Defined once, now, so `runtime` and `dependency` slot in without changing
 * the persisted shape. If either later needs a change here, that is a finding
 * against the design, not against that provider.
 */

export const VERDICTS = ['unreachable', 'reachable', 'confirmed', 'unknown'] as const;
export type Verdict = (typeof VERDICTS)[number];

export const PROVIDERS = ['static', 'runtime', 'dependency'] as const;
export type Provider = (typeof PROVIDERS)[number];

export interface ValidationEvidence {
  /** One concrete, human-readable fact. Never a summary, never a score. */
  detail: string;
}

export interface FindingValidation {
  fingerprint: string;
  verdict: Verdict;
  confidence: 'high' | 'medium' | 'low';
  provider: Provider;
  evidence: ValidationEvidence[];
  /**
   * What this provider could NOT see. Empty only when nothing was missing —
   * a verdict count without these beside it is not an answer.
   */
  coverage_gaps: string[];
  /** The surface snapshot this was computed against. */
  snapshot_id: number;
  /** Tree hash at computation time. A verdict computed against tree N says
   *  nothing once the code moves; readers compare this to decide staleness. */
  tree_hash: string;
  computed_at: string;
}
