/**
 * Shapes shared by the CI entry point.
 *
 * `CiExitCode` is a union rather than bare numbers because the exit code IS
 * the contract with the pipeline: 2 in particular exists so that "a scanner
 * did not run" can never be mistaken for "nothing was found".
 */

import type { Severity, ToolRun } from '../types.js';

export const CI_EXIT = {
  PASS: 0,
  GATE_FAILED: 1,
  INCOMPLETE_SCAN: 2,
  USAGE_ERROR: 3,
} as const;
export type CiExitCode = (typeof CI_EXIT)[keyof typeof CI_EXIT];

export interface BaselineEntry {
  /**
   * The finding's line-independent identity (`fingerprint/findingIdentity.ts`)
   * — what an entry is matched on first. An additive field: absent from every
   * entry 2.0.x wrote (and from one 2.0.x rewrote, since it drops keys it does
   * not know), and from an entry whose finding came from a tool that computes
   * none; those match by `fingerprint`.
   */
  identity?: string;
  /**
   * The CI gate's tolerant key (`fingerprint/findingIdentity.ts#gateMatchKeys`):
   * a dependency finding without its installed version, a secret without the
   * commit that saw it, the path the file had when the entry was written.
   * Additive like `identity` — written since 3.3.0; every older reader
   * ignores it, and an entry without it matches by identity, as before.
   *
   * Never named with `key`, `token`, `secret` or the like: gitleaks'
   * `generic-api-key` rule reads `"<keyword>": "<64 hex>"` as a credential,
   * and the committed baseline would become a secret finding of its own
   * (measured, gitleaks 8.30.1, with this field first spelled `match_key`).
   */
  match_id?: string;
  fingerprint: string;
  severity: Severity;
  title: string;
  file_path?: string;
  /** ISO date this entry entered the baseline. Preserved across regenerations
   *  so a reviewer can see how long a suppression has been carried. */
  added: string;
}

/**
 * `buildBaseline` writes 1 — `identity` rides on version-1 entries as an
 * additive field, because 2.0.x rejects every other version (see
 * `baseline.ts`). 2 is read only because development builds of that change
 * briefly wrote it.
 */
export type BaselineVersion = 1 | 2;

export interface BaselineFile {
  version: BaselineVersion;
  generated_at: string;
  entries: BaselineEntry[];
}

/**
 * Result of `baseline.ts#parseBaseline` for a document that DID exist and had
 * the right top-level shape. `dropped` counts entries the parser could not
 * validate — most likely a `severity` newer than this build's `SEVERITIES` —
 * and therefore excluded from `file.entries` rather than failing the whole
 * document over one unrecognised token. A non-zero `dropped` must be
 * surfaced (the gate's coverage gaps, the report) rather than absorbed
 * silently: a finding that resurfaces because its entry was dropped is a
 * different fact from one that resurfaced because someone reintroduced the
 * underlying bug, and a reader must be able to tell them apart.
 */
export interface BaselineParseResult {
  file: BaselineFile;
  dropped: number;
}

export interface ScanStepResult {
  tool: string;
  ran: boolean;
  /** Present when `ran` is false: why the step did not produce results. */
  reason?: string;
  tools_run: ToolRun[];
  missing_tools: string[];
  /**
   * Per `missing_tools` name whose whole cause is files a scanner could read
   * only in part (project-relative, `/`-separated), each with Semgrep's error
   * type: Semgrep's `partial` verdict (`runners/semgrepReport.ts`), or
   * scan_dast's `guardian-dast:partial-surface` over a surface only partly
   * parsed. What the gate matches `--accept-partial-parse` against — and only
   * a parse type is acceptable there (`gate.ts`); built by `runScans.ts`.
   * Absent when there are none.
   */
  partial_parses?: Record<string, PartialParseRef[]>;
}

/** One file a step's scanner could read only in part, and Semgrep's error type for it. */
export interface PartialParseRef {
  file: string;
  type: string;
}

/**
 * What kind of gap a coverage gap is — part of the CI verdict's JSON
 * (`coverage_gap_details[].kind`), which dev-spec-driven's finish gate reads
 * to choose its own advice: only a `missing_tool` is "install something".
 */
export type GapKind =
  | 'missing_tool'
  | 'no_lockfile'
  | 'partial_parse'
  | 'file_timeout'
  | 'taint_timeout'
  | 'path_too_long'
  | 'scanner_failed'
  | 'skipped'
  | 'other';

export const GAP_KINDS: readonly GapKind[] = [
  'missing_tool',
  'no_lockfile',
  'partial_parse',
  'file_timeout',
  'taint_timeout',
  'path_too_long',
  'scanner_failed',
  'skipped',
  'other',
];

/** One gap as data (`gate.ts`, "Every gap, as data"). */
export interface CoverageGapDetail {
  /** The scanner (`semgrep`, `trivy:npm`), the step that did not run, or `baseline`. */
  tool: string;
  kind: GapKind;
  /** The gap's line, as `coverage_gaps` / `accepted_gaps` / `coverage_notes` print it. */
  detail: string;
  /** One short English sentence: what clears it — runnable where it names a command. */
  remedy: string;
  /** Whether it forces exit 2 (an accepted gap and a note do not). */
  gating: boolean;
}

/**
 * One accepted gap as data — one per `accepted_gaps` line, same order (3.4.1,
 * for dev-spec-driven, which counted them by parsing the English lines). An
 * accepted gap is one file: a step with several accepted files has a line,
 * and an entry, for each.
 */
export interface AcceptedGapDetail {
  /** The scanner whose gap it is (`semgrep`, `bandit`, `guardian-dast:partial-surface`). */
  tool: string;
  /** `file_timeout` (not analysed by the rules that timed out) or `partial_parse` (read only in part). */
  kind: Extract<GapKind, 'file_timeout' | 'partial_parse'>;
  /** The file, project-relative, `/`-separated. */
  file: string;
  /** What the scanner reported on it and what accepted it, in English: `Timeout — accepted by .guardian/scan.yml semgrep.accept_timeouts`. */
  reason: string;
}

/**
 * Under `--baseline-ref` / `--rules-ref`: the `semgrep.accept_timeouts` files
 * whose content is not what it was at that commit (`ci/changedSince.ts`). An
 * acceptance covers a file as it was reviewed, so a timeout on one of these
 * is not accepted (review 11, finding 1: a pull request appended a command
 * injection to an accepted file and passed). `error`: the comparison could
 * not be made, and no timeout is accepted.
 */
export interface TimeoutAcceptanceRef {
  /** The ref(s) compared with, as given (`BASE`, `origin/main`). */
  ref: string;
  changed: ReadonlySet<string>;
  error?: string;
}

/**
 * Where the gate's baseline came from (`--baseline-ref`, `ci/refConfig.ts`):
 * the scanned tree's own file — on a pull request, the pull request's — or
 * the commit a ref named.
 */
export type BaselineSource =
  | { from: 'tree'; path: string }
  | {
      from: 'ref';
      path: string;
      ref: string;
      commit: string;
      /** The ref has a baseline. False: no baseline — every finding is new. */
      present: boolean;
      /** The scanned tree's copy differs from the ref's (and was not read). */
      tree_differs: boolean;
    };

/**
 * Where the project's Semgrep rules and scanner configuration came from
 * (`--rules-ref`, `ci/refConfig.ts`), and every configuration file the tree
 * holds differently from the ref — `applied: 'tree'` ones the scan read
 * anyway (the gate cannot take them from a ref), for a reviewer to look at.
 */
export type RulesSource =
  | { from: 'tree' }
  | {
      from: 'ref';
      ref: string;
      commit: string;
      /** Read from the ref (project-relative). */
      copied: string[];
      /** Looked for at the ref and not there: read from nowhere. */
      absent: string[];
      tree_differences: ConfigDifference[];
    };

/**
 * What `--reset-exclusions-from` put back before the scan
 * (`ci/refConfig.ts#resetExclusionsFromRef`): project-relative paths.
 */
export interface ExclusionReset {
  ref: string;
  commit: string;
  /** Rewritten with the ref's bytes. */
  restored: string[];
  /** Deleted: the ref has none there. */
  removed: string[];
}

/** One configuration file the scanned tree holds differently from the `--rules-ref` ref. */
export interface ConfigDifference {
  /** Project-relative, `/`-separated. */
  path: string;
  change: 'added' | 'modified' | 'deleted';
  /**
   * The copy the scan read: `tree` — the pull request's own, so its change
   * WAS applied (a file the gate cannot take from a ref); `ref` — the ref's,
   * so it was not.
   */
  applied: 'tree' | 'ref';
  /** The scanners that read it. */
  read_by: string[];
}
