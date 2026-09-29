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
