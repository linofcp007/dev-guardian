/**
 * Read, write, and diff `.guardian/baseline.json` against a finding set.
 *
 * Pure: every function takes its inputs as arguments — no filesystem access
 * and no `Date.now()`. A future `runScans.ts`/CLI task owns reading the file
 * and supplying `now`; this module only ever sees text and plain objects, so
 * it can be tested from fixtures with no I/O.
 *
 * The rule this module exists to enforce: an ABSENT baseline file is not an
 * EMPTY one, and neither of those is the same failure as a well-shaped
 * DOCUMENT that contains one malformed ENTRY. `parseBaseline` therefore
 * returns one of three states, not two:
 *
 *   - `null` — no file, unparseable JSON, or a document whose top-level
 *     shape is wrong (bad `version`, missing `generated_at`, `entries` not
 *     an array). There is nothing here to salvage.
 *   - `{ file: { entries: [], ... }, dropped: 0 }` — a file that parses
 *     cleanly and genuinely lists nothing.
 *   - `{ file, dropped: N }` — a file that parsed, whose `entries` array
 *     contained N item(s) this build could not validate — typically a
 *     `severity` value newer than this build's `SEVERITIES` (see
 *     `isSeverity`). Those N are excluded from `file.entries`; every other
 *     entry survives.
 *
 * The third state exists because the naive fix for "one bad entry" —
 * rejecting the whole array, exactly like a wrong-shaped document — silently
 * reintroduces the very failure this module exists to prevent, through a
 * different door: a baseline written by a NEWER version of this tool and
 * read by an OLDER one would contain exactly one entry the older build
 * doesn't recognise, `parseBaseline` would return `null` for the entire
 * file, and `null` is indistinguishable from "no baseline exists" to every
 * caller — un-baselining a repository's whole suppression history over one
 * unrecognised token. Filtering keeps the blast radius to the one entry that
 * could not be read, and `dropped` makes that loss visible rather than
 * silent: a finding that resurfaces because its entry was dropped is a
 * different fact from one that resurfaced because someone reintroduced the
 * underlying bug, and a caller must be able to tell them apart (`gate.ts`
 * folding it into coverage gaps, the report naming it).
 *
 * An absent/unparseable/wrong-shaped-document baseline stays `null` rather
 * than thrown, and a corrupted-but-present one stays a present result rather
 * than `null`: either would crash a CI run, or misreport a corrupted commit
 * as if nothing had ever been baselined, over a file humans hand-edit to
 * suppress findings.
 *
 * ---- Versions ------------------------------------------------------------
 *
 * Version 1 (2.0.x) named each finding by `fingerprint` alone. The
 * fingerprint hashes the line range, so inserting one line above a baselined
 * finding made the gate report it as new (reproduced: `newFindings after
 * 1-line shift: 1`). Version 2 entries also carry the finding's
 * line-independent `identity` and are matched identity-first, fingerprint as
 * the fallback (`fingerprint/findingIdentity.ts#indexFindings`). Both
 * versions are read — a v1 file keeps gating exactly as it did, because the
 * fingerprint algorithm is frozen — and `buildBaseline` always writes 2,
 * carrying every entry's `added` date across, so the first `baseline
 * update` after upgrading converts the file without resetting any clock.
 */

import { indexFindings } from '../fingerprint/findingIdentity.js';
import { SEVERITIES, type Finding, type Severity } from '../types.js';
import type { BaselineEntry, BaselineFile, BaselineParseResult, BaselineVersion } from './types.js';

/** Where the committed baseline lives, relative to the project root. */
export const BASELINE_RELATIVE_PATH = '.guardian/baseline.json';

/** The version `buildBaseline` writes. */
export const BASELINE_VERSION: BaselineVersion = 2;

function isBaselineVersion(value: unknown): value is BaselineVersion {
  return value === 1 || value === 2;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isSeverity(value: unknown): value is Severity {
  return typeof value === 'string' && (SEVERITIES as readonly string[]).includes(value);
}

function isBaselineEntry(value: unknown): value is BaselineEntry {
  if (!isPlainObject(value)) return false;
  if (typeof value.fingerprint !== 'string') return false;
  if (value.identity !== undefined && typeof value.identity !== 'string') return false;
  if (!isSeverity(value.severity)) return false;
  if (typeof value.title !== 'string') return false;
  if (value.file_path !== undefined && typeof value.file_path !== 'string') return false;
  if (typeof value.added !== 'string') return false;
  return true;
}

/**
 * See the module doc for the three return states in full. In short: `null`
 * means there is no file to salvage (absent, unparseable, or the wrong shape
 * at the DOCUMENT level — a `version` other than 1 or 2, missing
 * `generated_at`, `entries` not an array). Otherwise every entry that fails
 * validation is dropped individually rather than failing the whole document,
 * and `dropped` reports how many were — a wrong-shaped ENTRY must never read
 * as either a wrong-shaped document or as "no baseline exists". The file's
 * own version is kept on the result.
 */
export function parseBaseline(text: string | null): BaselineParseResult | null {
  if (text === null) return null;

  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return null;
  }
  if (!isPlainObject(parsed)) return null;

  const { version, generated_at, entries } = parsed;
  if (!isBaselineVersion(version)) return null;
  if (typeof generated_at !== 'string') return null;
  if (!Array.isArray(entries)) return null;

  const validEntries = entries.filter(isBaselineEntry);
  const dropped = entries.length - validEntries.length;

  return { file: { version, generated_at, entries: validEntries }, dropped };
}

/** Pretty-printed so the committed file is reviewable in a pull-request diff. */
export function serialiseBaseline(file: BaselineFile): string {
  return `${JSON.stringify(file, null, 2)}\n`;
}

/**
 * Regenerate the baseline from the current findings, as a version-2 file.
 *
 * A finding already recorded in `previous` — matched the way the gate
 * matches (identity first, fingerprint as the fallback, so a v1 entry is
 * found by its fingerprint) — keeps its original `added` date: a regeneration
 * must not reset the clock on a suppression a reviewer is already tracking
 * the age of, and neither may converting a v1 file or a line shift that gave
 * the finding a new fingerprint. Only a finding with no prior entry is
 * stamped with `now`. A finding that no longer appears in `findings` is
 * dropped: the loop below is driven by `findings`, so `previous` is consulted
 * only as a date lookup, never copied wholesale.
 *
 * Entries are accumulated in a `Map` keyed by identity (fingerprint when
 * there is none) and only then turned into an array, so two findings that
 * are the same finding can never produce two entries — the later write
 * replaces the earlier. A fingerprint seen twice is likewise one entry.
 *
 * The array is sorted by that key before being returned so the file's line
 * order is a function of the findings alone, not of scan order — and, since
 * the identity survives a line shift, not of where in its file each finding
 * sits either. A file whose order moved on every regeneration would produce
 * a diff nobody could review, which is the same as not reviewing it.
 */
export function buildBaseline(
  findings: readonly Finding[],
  previous: BaselineFile | null,
  now: string,
): BaselineFile {
  const previousIndex = indexFindings(previous?.entries ?? []);

  const byKey = new Map<string, BaselineEntry>();
  const keyOfFingerprint = new Map<string, string>();
  for (const finding of findings) {
    const added = previousIndex.find(finding)?.added ?? now;
    const entry: BaselineEntry = {
      ...(finding.identity !== undefined ? { identity: finding.identity } : {}),
      fingerprint: finding.fingerprint,
      severity: finding.severity,
      title: finding.title,
      file_path: finding.file_path,
      added,
    };
    const key = keyOfFingerprint.get(finding.fingerprint) ?? entryKey(entry);
    keyOfFingerprint.set(finding.fingerprint, key);
    byKey.set(key, entry);
  }

  const entries = [...byKey.values()].sort(
    (a, b) => entryKey(a).localeCompare(entryKey(b)) || a.fingerprint.localeCompare(b.fingerprint),
  );

  return { version: BASELINE_VERSION, generated_at: now, entries };
}

function entryKey(entry: BaselineEntry): string {
  return entry.identity ?? entry.fingerprint;
}

/**
 * Findings not already recorded in the baseline.
 *
 * Matches on the finding's identity first and its fingerprint as the
 * fallback (see the module doc's "Versions") — never on severity, title, or
 * any other field — because a scanner re-wording a message or a rule pack
 * changing a severity must not resurface a finding someone already reviewed
 * and suppressed, and neither may a line inserted above it. A `null`
 * baseline (file absent, see module doc) means nothing is known yet, so
 * everything is new.
 */
export function newFindings(
  findings: readonly Finding[],
  baseline: BaselineFile | null,
): Finding[] {
  if (baseline === null) return [...findings];
  const known = indexFindings(baseline.entries);
  return findings.filter((finding) => !known.has(finding));
}
