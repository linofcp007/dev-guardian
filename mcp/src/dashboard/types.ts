/**
 * Shared types for the local dashboard (`dev-guardian status` /
 * `dev-guardian dashboard`) — see
 * `docs/superpowers/specs/2026-08-15-local-dashboard-design.md`.
 *
 * This file currently carries the risk-score slice (§3.1) and the
 * delta/hotspot slice (§7, §8 of the design). Later tasks extend it with
 * `DashboardSnapshot` and its other parts.
 */

import type { Cve, Finding } from '../types.js';

/**
 * Already-scoped inputs `scoreRisk` needs to compute a risk assessment.
 * Nothing here is queried by `risk.ts` itself — every field is resolved by
 * the caller (a tool handler today, `snapshot.ts` later), which is what
 * makes `risk.ts` a pure function over data rather than a database client.
 */
export interface RiskInput {
  /** Project-scoped, already suppression-filtered. */
  findings: readonly Finding[];
  /** Active CVEs for this project's latest deps-flavoured scan. */
  cves: readonly Cve[];
  /** 0–3: privacy_policy, terms_of_service, security_policy that are absent. */
  policies_missing: number;
  /** True when renovate OR dependabot is configured. */
  dependency_bot_configured: boolean;
  /** ISO timestamp of the active baseline, or null when none was ever set. */
  baseline_set_at: string | null;
  /** True when the scan behind these numbers did not run every intended tool. */
  coverage_partial: boolean;
  /** Injected clock. Never call Date.now() inside risk.ts. */
  now: number;
}

export interface RiskAssessment {
  score: number;
  band: 'low' | 'medium' | 'high' | 'critical';
  /** Shaped to match `risk_score`'s existing wire output exactly, so the tool
   *  can map this to its response without inventing or dropping a field. */
  components: {
    findings: { score: number; open_findings: number };
    cves: { score: number; active_cves: number };
    compliance: { score: number; policies_missing: number };
    baseline: { score: number; has_active_baseline: boolean };
  };
  /** → the tool's `recommended_next_action`. */
  next_action: string;
  /** True when computed over a partial scan. Both dashboard views must show
   *  this. Not part of `risk_score`'s output; the tool drops it. */
  coverage_caveat: boolean;
}

/** Tools whose absence removes a whole class of finding from the numbers.
 *  A tool absent from this table contributes its own name, never nothing. */
export const TOOL_CATEGORIES: Readonly<Record<string, string>> = {
  semgrep: 'static-analysis',
  gitleaks: 'secrets',
  trivy: 'container and dependency',
  nuclei: 'dynamic',
};

/**
 * The fingerprint delta between two scans — produced by
 * `delta.ts#compareFindings`. `new` = in `to` not `from`, `resolved` = in
 * `from` not `to`, `unchanged` = in both, computed over fingerprint sets
 * (design §7).
 */
export interface FindingDelta {
  from_scan_id: string;
  to_scan_id: string;
  /** The TRUE count of new findings. Never the length of `new_findings`
   *  below — that list may be capped; this number never is. See §2 and §8
   *  of the design: a capped list that also caps its own count is the exact
   *  lie this dashboard exists to refuse to tell. */
  new_count: number;
  resolved_count: number;
  unchanged_count: number;
  /** Possibly capped for display — see `TruncationNotice`. */
  new_findings: Finding[];
}

/**
 * One file's finding count — produced by `hotspots.ts#rankFiles`. A plain
 * count, not severity-weighted (design §12): a file with 11 low findings
 * outranks one with 2 criticals by design.
 */
export interface Hotspot {
  file_path: string;
  count: number;
}

/**
 * Discloses that a list shown to the user is shorter than its true total,
 * and why — design §8's rule that no cap is ever silent. Present only when
 * a cap actually cut something; both views render it when it is not null.
 */
export interface TruncationNotice {
  /** Which field was capped, e.g. 'new_findings'. */
  what: string;
  shown: number;
  total: number;
  reason: string;
}
