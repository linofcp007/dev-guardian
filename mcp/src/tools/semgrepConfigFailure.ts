/**
 * Semgrep registry config-download failures.
 *
 * A `--config=p/xxx` shorthand resolves against Semgrep's public registry
 * (`https://semgrep.dev/c/p/xxx`) at scan time. Packs get retired from that
 * registry without warning — `p/bugs` started 404ing at some point after
 * `bug_hunt` was written, and every user of that tool got zero coverage
 * with no indication anything was wrong (see the bug_hunt fix report for
 * the full incident). Semgrep reports the failure as a structured entry in
 * the JSON output's `errors[]` array, not merely a non-zero exit code — and
 * (confirmed against 1.164.0) a SINGLE bad `--config=` aborts the entire
 * invocation: `results` and `paths.scanned` come back empty even for packs
 * that resolved fine. Confirmed too: when more than one `--config=` fails,
 * Semgrep emits one `errors[]` entry per failed pack (plus a trailing
 * summary entry with no attributable URL), so a caller running N packs can
 * discover every dead one from a single invocation rather than one at a
 * time.
 *
 * Exit code / outcome alone is not sufficient signal here: nothing
 * guarantees a future Semgrep release keeps exiting non-zero for this
 * condition, and an empty `results: []` from a clean-looking exit 0 would
 * silently read as "no bugs found" instead of "nothing was scanned".
 * Callers that run multiple `--config=` packs should read `errors[]`
 * explicitly (via `findConfigDownloadFailures`) rather than trusting
 * `outcome`/`exitCode`.
 */

import {
  asArray,
  getProp,
  getString,
  parseInputAsJson,
} from '../runners/scannerParsers/index.js';

export interface ConfigDownloadFailure {
  /**
   * The `--config=` value that failed to resolve, e.g. `p/r2c-bug-scan`,
   * recovered from the registry URL in Semgrep's error message. `null` when
   * the message didn't match the expected `.../c/<pack>` shape — still a
   * real failure, just not attributable to one specific pack.
   */
  pack: string | null;
  /** The full error message, kept for diagnostics (`tools_run[].reason`). */
  message: string;
}

const DOWNLOAD_FAILURE_RE = /Failed to download configuration from (\S+)/;
const REGISTRY_URL_PREFIX_RE = /^https?:\/\/semgrep\.dev\/c\//;

/**
 * Scan a Semgrep JSON report's `errors[]` for "could not download this
 * `--config=`" entries. Returns `[]` for null/unparsable input or JSON with
 * no matching errors — never throws, so callers can pass `readJsonSafe`'s
 * result straight through.
 */
export function findConfigDownloadFailures(raw: string | null): ConfigDownloadFailure[] {
  if (raw === null) return [];
  const root = parseInputAsJson(raw);
  const errors = asArray(getProp(root, 'errors'));
  const failures: ConfigDownloadFailure[] = [];
  for (const entry of errors) {
    const message = getString(entry, 'message');
    if (message === undefined) continue;
    const match = DOWNLOAD_FAILURE_RE.exec(message);
    if (!match) continue;
    const url = match[1];
    const pack = url !== undefined ? url.replace(REGISTRY_URL_PREFIX_RE, '') : null;
    failures.push({ pack, message });
  }
  return failures;
}

/** Which of `configured` were NOT named by any entry in `failures`. */
export function survivingPacks(
  configured: readonly string[],
  failures: readonly ConfigDownloadFailure[],
): string[] {
  const failedNames = new Set(
    failures.map((f) => f.pack).filter((p): p is string => p !== null),
  );
  return configured.filter((p) => !failedNames.has(p));
}

/** Render `pack (message)` for every failure, joined for a tools_run reason. */
export function describeConfigFailures(failures: readonly ConfigDownloadFailure[]): string {
  return failures.map((f) => `${f.pack ?? 'unknown config'} (${f.message})`).join('; ');
}
