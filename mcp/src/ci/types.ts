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
   * — what a version-2 file matches on first. Absent from every version-1
   * entry, and from a v2 entry whose finding came from a tool that computes
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
 * Version 1 (2.0.x) entries carry only a fingerprint, which changes when a
 * line is inserted above the finding. Version 2 adds `identity`. Both are
 * read; `buildBaseline` writes 2.
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
}
