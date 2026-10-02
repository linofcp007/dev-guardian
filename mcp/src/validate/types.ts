/**
 * The verdict envelope, shared by all three evidence providers.
 *
 * Defined once, so `runtime` and `dependency` slot in without changing the
 * persisted shape. The one addition since: `dependency` needed a verdict the
 * other two never give — `imported`, "the project's code imports this
 * package, and no route was shown to reach the file that does". It is not
 * `reachable` (nothing connects it to a route) and it must not be
 * `unreachable` (the graph proves no absence of a path to a package), so it
 * is its own value — the only schema change, a new string in a TEXT column.
 */

export const VERDICTS = ['unreachable', 'reachable', 'imported', 'confirmed', 'unknown'] as const;
export type Verdict = (typeof VERDICTS)[number];

/**
 * What provider `llm` stores (llm-scan). Kept apart from {@link VERDICTS}:
 * those are the verdicts the evidence providers give, and `validate_finding`'s
 * summary counts exactly them.
 */
export const LLM_VERDICTS = ['exploitable', 'not_exploitable', 'undetermined'] as const;
export type LlmStoredVerdict = (typeof LLM_VERDICTS)[number];

export const PROVIDERS = ['static', 'runtime', 'dependency', 'llm'] as const;
export type Provider = (typeof PROVIDERS)[number];

/** The providers this version implements, in the order they run and report. */
export const IMPLEMENTED_PROVIDERS = ['static', 'dependency'] as const satisfies readonly Provider[];
export type ImplementedProvider = (typeof IMPLEMENTED_PROVIDERS)[number];

export interface ValidationEvidence {
  /** One concrete, human-readable fact. Never a summary, never a score. */
  detail: string;
}

export interface FindingValidation {
  fingerprint: string;
  verdict: Verdict | LlmStoredVerdict;
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
