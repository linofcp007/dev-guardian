/**
 * Types for `create_fix_pr` — deciding which findings are fixable at all,
 * and how they group into one candidate pull request per ecosystem or
 * scanner (design doc `docs/superpowers/specs/2026-08-16-create-fix-pr-design.md`).
 *
 * `UpgradeStep` mirrors `depsUpdatePlan.ts`'s interface of the same name.
 * It is declared here, not imported, because that interface has no `export`
 * — this feature reads the shape off `deps_update_plan`'s JSON result, the
 * way `auditExecutive` already treats other sub-tools' results.
 */

import type { Severity } from '../types.js';

/** Mirrors depsUpdatePlan's un-exported UpgradeStep. Read from its JSON result. */
export interface UpgradeStep {
  package_name: string;
  installed_version: string;
  latest_version: string;
  classification: 'security' | 'patch' | 'minor' | 'major';
  ecosystem: 'npm' | 'pip' | 'composer' | 'cargo' | 'go' | 'rubygems' | 'dotnet' | 'unknown';
  reason?: string;
  upgrade_command: string;
}

export type FixSource = 'deps' | 'semgrep';

export interface FixCandidate {
  source: FixSource;
  /** Fingerprints this candidate is expected to resolve. */
  fingerprints: string[];
  /** Highest severity among those findings. */
  severity: Severity;
  /** For deps: the pinned upgrade command. For semgrep: null — the group runs one autofix pass. */
  command: string | null;
  /** Human label: "lodash 4.17.20 -> 4.17.21", or the rule id for semgrep. */
  label: string;
}

export interface FixGroup {
  source: FixSource;
  /** 'npm' | 'pip' | … for deps; 'semgrep' for semgrep. One PR per group. */
  key: string;
  candidates: FixCandidate[];
  /** Highest severity across the group — the ordering key. */
  severity: Severity;
  /** Deterministic: sha256 of the sorted fingerprints, first 12 hex chars. */
  hash: string;
}

export interface GroupSelection {
  selected: FixGroup[];
  /** Groups the cap excluded. NEVER silently dropped. */
  deferred: { key: string; source: FixSource; severity: Severity; finding_count: number }[];
  deferred_reason: string | null; // null iff deferred is empty
}
