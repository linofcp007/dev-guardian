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

/**
 * The scan differential's verdict (design doc §4.1) — produced by
 * `verify.ts#judgeScan`, consumed by `verify.ts#mayOpenPr` and, later, by
 * `pr.ts`'s report. Declared here rather than in `verify.ts` itself: design
 * doc §8's module table assigns `ScanVerdict`/`TestVerdict` to `types.ts`
 * alongside `FixCandidate`/`FixGroup`, matching how Task 1 already split
 * `candidates.ts`'s shapes out into this file rather than keeping them local.
 */
export interface ScanVerdict {
  passed: boolean;
  /** Target fingerprints confirmed gone from the after-scan. */
  resolved: string[];
  /** Target fingerprints that are still present in the after-scan. */
  still_present: string[];
  new_findings: { fingerprint: string; severity: string; title: string }[];
}

/** The test differential's outcome (design doc §4.2's three-verdict table,
 *  plus `not_run` for a project with no derivable test command). */
export type TestOutcome = 'passed' | 'broken_by_fix' | 'already_failing' | 'not_run';

/** The test differential's verdict — produced by `verify.ts#judgeTests`. */
export interface TestVerdict {
  outcome: TestOutcome;
  /** Null when outcome === 'not_run'. */
  command: string | null;
  origin: string | null;
  /** First lines of failure output, when there was a failure. */
  output_head: string | null;
}
