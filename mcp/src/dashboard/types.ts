/**
 * Shared types for the local dashboard (`dev-guardian status` /
 * `dev-guardian dashboard`) — see
 * `docs/superpowers/specs/2026-08-15-local-dashboard-design.md`.
 *
 * This file currently carries the risk-score slice (§3.1) and the
 * delta/hotspot slice (§7, §8 of the design). Later tasks extend it with
 * `DashboardSnapshot` and its other parts.
 */

import type { Cve, Finding, Severity } from '../types.js';

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

/**
 * `buildSnapshot`'s (`snapshot.ts`) return value — the one query pass both
 * dashboard views render, and the only place in this feature that touches
 * storage. See the design of record §5, and §5.1 for what every field holds
 * when `scan` is null (a project with no completed scan).
 */
export interface DashboardSnapshot {
  project_path: string;
  generated_at: string; // ISO
  scan: ScanSummary | null; // null ⇒ nothing scanned yet
  coverage: CoverageState;
  risk: RiskAssessment;
  findings: FindingsSummary;
  cves: CveSummary;
  deltas: { since_previous: FindingDelta | null; since_baseline: FindingDelta | null };
  baseline: BaselineState;
  suppressions: SuppressionState;
  truncation: TruncationNotice[]; // empty when nothing was capped
}

export interface CoverageState {
  level: 'full' | 'partial' | 'none';
  tools_run: string[];
  missing_tools: string[];
  /**
   * Subset of `missing_tools` whose scanner actually ran (its `tools_run`
   * entry has `status: 'ok'`) — a narrower gap than "this tool did not run
   * this scan". `bug_hunt` is the motivating case: when one Semgrep pack
   * failed to download but another still produced real findings, `semgrep`
   * lands in both `missing_tools` (the pack-level gap is real —
   * `coverage.level` must not read 'full') AND here (the tool itself ran
   * fine — findings from it ARE on screen). Both views render this with a
   * distinct, accurate sentence instead of "X did not run this scan",
   * which would be false for an 'ok' tool with `by_tool` findings already
   * showing. Optional so hand-built fixtures that predate this field
   * default to "nothing partial" (the old, fully-missing-only behaviour)
   * rather than crashing on a missing property.
   */
  partial_tools?: string[];
  /** Rendered verbatim by both views. Empty iff level === 'full'. */
  omitted_categories: string[]; // e.g. ['container and dependency', 'secrets']
}

export interface ScanSummary {
  scan_id: string;
  scan_type: string;
  status: string;
  started_at: string;
  finished_at: string | null;
  duration_seconds: number | null; // null while running or on a crash
  age_seconds: number;
}

export interface FindingsSummary {
  total: number;
  by_severity: Record<Severity, number>;
  by_category: Record<string, number>;
  by_tool: Record<string, number>;
  hotspots: Hotspot[]; // file + count, descending
  items: Finding[]; // possibly capped — see §8
}

export interface CveSummary {
  total: number;
  by_severity: Record<Severity, number>;
  items: Cve[]; // as cvesRepo already returns them
}

export interface BaselineState {
  /** null ⇒ no baseline has ever been set for this project. */
  active: { baseline_id: number; scan_id: string; set_at: string; note?: string } | null;
  age_days: number | null; // null iff active is null
}

export interface SuppressionState {
  active_count: number;
  /** Active suppressions expiring within 7 days, soonest first. */
  expiring_soon: { fingerprint: string; reason: string; expires_at: string }[];
}
