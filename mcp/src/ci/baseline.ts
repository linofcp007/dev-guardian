/**
 * Read, write, and diff `.guardian/baseline.json` against a finding set.
 *
 * Pure: every function takes its inputs as arguments — no filesystem access
 * and no `Date.now()`. A future `runScans.ts`/CLI task owns reading the file
 * and supplying `now`; this module only ever sees text and plain objects, so
 * it can be tested from fixtures with no I/O.
 *
 * The rule this module exists to enforce: an ABSENT baseline file is not an
 * EMPTY one. `parseBaseline(null)` returns `null`; a file that parses but
 * lists no entries returns `{ version: 1, generated_at, entries: [] }`.
 * Collapsing the two would fail the first build of every repository that
 * adopts this tool — with no file yet, every historical finding would read
 * as new, and the gate would block a pull request for debt the author did
 * not introduce.
 *
 * `null` is also what unparseable JSON and a document of the wrong shape
 * return: a corrupted or absent baseline is the CALLER's decision to make
 * (report it to the user, or proceed as though nothing is known yet) — this
 * module throwing instead would crash a CI run over a single bad commit to a
 * file humans hand-edit to suppress findings.
 */

import { SEVERITIES, type Finding, type Severity } from '../types.js';
import type { BaselineEntry, BaselineFile } from './types.js';

/** Where the committed baseline lives, relative to the project root. */
export const BASELINE_RELATIVE_PATH = '.guardian/baseline.json';

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isSeverity(value: unknown): value is Severity {
  return typeof value === 'string' && (SEVERITIES as readonly string[]).includes(value);
}

function isBaselineEntry(value: unknown): value is BaselineEntry {
  if (!isPlainObject(value)) return false;
  if (typeof value.fingerprint !== 'string') return false;
  if (!isSeverity(value.severity)) return false;
  if (typeof value.title !== 'string') return false;
  if (value.file_path !== undefined && typeof value.file_path !== 'string') return false;
  if (typeof value.added !== 'string') return false;
  return true;
}

/**
 * `null` means "no usable baseline": the file was absent (see module doc
 * above), `text` was not valid JSON, or it parsed to a document of the wrong
 * shape (wrong `version`, missing fields, an entry with the wrong types). All
 * three collapse to `null` rather than a thrown error, so a corrupted or
 * missing baseline never crashes a CI run — the caller decides what "no
 * usable baseline" means for it, which today means treating every finding as
 * new.
 */
export function parseBaseline(text: string | null): BaselineFile | null {
  if (text === null) return null;

  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return null;
  }
  if (!isPlainObject(parsed)) return null;

  const { version, generated_at, entries } = parsed;
  if (version !== 1) return null;
  if (typeof generated_at !== 'string') return null;
  if (!Array.isArray(entries)) return null;
  if (!entries.every(isBaselineEntry)) return null;

  return { version: 1, generated_at, entries };
}

/** Pretty-printed so the committed file is reviewable in a pull-request diff. */
export function serialiseBaseline(file: BaselineFile): string {
  return `${JSON.stringify(file, null, 2)}\n`;
}

/**
 * Regenerate the baseline from the current findings.
 *
 * A fingerprint already present in `previous` keeps its original `added`
 * date — a regeneration must not reset the clock on a suppression a reviewer
 * is already tracking the age of. Only a fingerprint with no prior entry is
 * stamped with `now`. A fingerprint that no longer appears in `findings` is
 * dropped: the loop below is driven by `findings`, so `previous` is consulted
 * only as a date lookup, never copied wholesale.
 *
 * Entries are accumulated in a `Map` keyed by fingerprint and only then
 * turned into an array, so two findings sharing a fingerprint can never
 * produce two entries — the second write simply replaces the first.
 *
 * The array is sorted by fingerprint before being returned so the file's
 * line order is a function of the findings alone, not of scan order. A file
 * whose order moved on every regeneration would produce a diff nobody could
 * review, which is the same as not reviewing it.
 */
export function buildBaseline(
  findings: readonly Finding[],
  previous: BaselineFile | null,
  now: string,
): BaselineFile {
  const previousByFingerprint = new Map<string, BaselineEntry>(
    (previous?.entries ?? []).map((entry) => [entry.fingerprint, entry]),
  );

  const byFingerprint = new Map<string, BaselineEntry>();
  for (const finding of findings) {
    const added = previousByFingerprint.get(finding.fingerprint)?.added ?? now;
    byFingerprint.set(finding.fingerprint, {
      fingerprint: finding.fingerprint,
      severity: finding.severity,
      title: finding.title,
      file_path: finding.file_path,
      added,
    });
  }

  const entries = [...byFingerprint.values()].sort((a, b) =>
    a.fingerprint.localeCompare(b.fingerprint),
  );

  return { version: 1, generated_at: now, entries };
}

/**
 * Findings whose fingerprint is not already recorded in the baseline.
 *
 * Matches on `fingerprint` alone — never severity, title, or any other
 * field — because a scanner re-wording a message or a rule pack changing a
 * severity must not resurface a finding someone already reviewed and
 * suppressed. A `null` baseline (file absent, see module doc) means nothing
 * is known yet, so everything is new.
 */
export function newFindings(
  findings: readonly Finding[],
  baseline: BaselineFile | null,
): Finding[] {
  if (baseline === null) return [...findings];
  const known = new Set(baseline.entries.map((entry) => entry.fingerprint));
  return findings.filter((finding) => !known.has(finding.fingerprint));
}
