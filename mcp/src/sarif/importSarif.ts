/**
 * SARIF 2.1.0 log → canonical findings and counts (feature `sarif-import`).
 *
 * PHASE 4 STUB — the types are the design's data model; `importSarif` throws
 * until it is implemented. The failing tests that pin its behaviour are
 * `test/unit/sarif/importSarif.test.ts` (and the integration/e2e files named
 * in the feature's test plan).
 *
 * Contract the tests hold it to:
 *   - pure: text in, result out — no file, URL or process is opened for
 *     anything the log names (US-1.AC-15); paths are resolved textually
 *     against `ctx.projectPath`;
 *   - a log that is not JSON, does not declare `version: "2.1.0"`, or has no
 *     `runs` array (an empty file included) is refused by THROWING an Error
 *     whose `code` is `'invalid_sarif'` and whose message names the field or
 *     index at fault — never content of the log (US-1.AC-10, US-1.AC-18);
 *   - one `SarifImportRun` per `runs[]` entry, in order.
 */

import type { Finding } from '../types.js';

/** What one run of an import counted (stored as the scan's `meta.counts`). */
export interface SarifImportCounts {
  /** Results read. */
  results: number;
  imported: number;
  /** US-1.AC-11: imported with no file and no line. */
  without_location: number;
  /** US-1.AC-12, EC-4: results that could not be imported, by index in the run, and why. */
  skipped: Array<{ index: number; reason: string }>;
  /** US-1.AC-8: results carrying an accepted suppression. */
  suppressed_at_source: number;
  /** US-1.AC-9: `kind` other than `fail`, or `level: none` with no `kind`. */
  not_findings: number;
  /** EC-6: the same result (same identity) repeated in the run. */
  duplicates: number;
  /** US-1.AC-5: findings whose identity was computed rather than derived from the log's fingerprints. */
  identity_computed: number;
  /** US-1.AC-17: results left out once the per-import limit was reached. */
  truncated: number;
}

/** The pure result of reading one `runs[]` entry. */
export interface SarifImportRun {
  /** `runs[].tool.driver.name`, trimmed, at most 100 characters. */
  source_tool: string;
  /** `runs[].tool.driver.version`, else `semanticVersion`. */
  source_version?: string;
  /** With `identity` set when the result carried fingerprints. */
  findings: Finding[];
  counts: SarifImportCounts;
}

export interface SarifImportResult {
  runs: SarifImportRun[];
}

/** `meta` of a `sarif_import` scan row. */
export interface SarifImportMeta {
  source_tool: string;
  source_version?: string;
  /** Relative to the project, or the basename when the log was outside it. */
  source_file: string;
  counts: SarifImportCounts;
}

export interface SarifImportContext {
  /** Canonical project root the log's locations are resolved against. */
  projectPath: string;
  /** Results read per import before stopping (default 50 000). */
  maxResults?: number;
}

export function importSarif(_text: string, _ctx: SarifImportContext): SarifImportResult {
  throw new Error('NotImplemented: importSarif');
}
