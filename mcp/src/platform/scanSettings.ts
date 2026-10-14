/**
 * `.guardian/scan.yml` — the project's own settings for how its scans run,
 * committed and reviewed like code (review 8, finding 3).
 *
 *     semgrep:
 *       timeout: 30            # seconds per rule per file (Semgrep --timeout; 0: no limit)
 *       timeout_threshold: 0   # rules that may time out on a file before Semgrep drops
 *                              # the whole file (--timeout-threshold; 0: never drop it)
 *       accept_timeouts:       # files whose per-file Semgrep Timeout the CI gate accepts
 *         - src/generated/parser.js
 *
 * ---- Why these defaults ---------------------------------------------------
 *
 * Semgrep's own are `--timeout 5` and `--timeout-threshold 3`. At 5 s, a
 * medium-sized repository never passed the CI gate: dev-spec-driven's own
 * tree had about ten files time out (`cli/commands.js`, `engine/guards.js`),
 * every one a coverage gap with nothing a user could do. And after three
 * timeouts on one file, Semgrep drops the file for EVERY rule still to run,
 * naming none of them — so a timeout entry under-states what was lost
 * (CLAUDE.md, "the jitter is timeouts, and it is excluded by FILE"). With a
 * threshold of 0 only the rules that timed out miss the file, which is what
 * makes accepting a timeout honest.
 *
 * ---- Who may accept a timeout ---------------------------------------------
 *
 * `accept_timeouts` widens what the gate lets through, so it lives in a
 * committed file a reviewer sees, never in a flag a pipeline can grow
 * unnoticed — and the CI gate's `--rules-ref` reads this file from the ref,
 * like the project's Semgrep rules (`ci/refConfig.ts`), so a pull request
 * cannot accept the timeout its own change causes. Only a per-file `Timeout`
 * can be accepted there: a parse error is `--accept-partial-parse` (argv
 * only), and a scanner that did not run is never acceptable.
 *
 * A file that is missing is the defaults. One that is there but invalid is
 * never half-read: the defaults apply and the caller says why (the CLI exits
 * 3; a scan tool warns) — a typo must not read as a setting that silently
 * never applies.
 */

import { posix } from 'node:path';
import { describeReadRefusal, readProjectText } from './projectFs.js';
import { describeYamlRefusal, parseYamlBounded, YAML_CONFIG_LIMITS } from './boundedParse.js';

/** Where the settings live, relative to the project root. */
export const SCAN_SETTINGS_RELATIVE_PATH = '.guardian/scan.yml';

/** Semgrep's per-rule, per-file timeout dev-guardian passes, in seconds (Semgrep's own: 5). */
export const DEFAULT_SEMGREP_TIMEOUT_S = 30;
/** Semgrep's `--timeout-threshold` dev-guardian passes (Semgrep's own: 3). */
export const DEFAULT_SEMGREP_TIMEOUT_THRESHOLD = 0;

/** The largest settings file read. */
const MAX_BYTES = 256 * 1024;

export interface ScanSettings {
  semgrep: {
    /** `--timeout`, seconds; 0 is no limit. */
    timeout: number;
    /** `--timeout-threshold`; 0 is no limit. */
    timeoutThreshold: number;
    /** Project-relative, `/`-separated, without `./`: files whose per-file Timeout the gate accepts. */
    acceptTimeouts: string[];
  };
}

export type ScanSettingsLoad =
  | { kind: 'none'; settings: ScanSettings }
  | { kind: 'loaded'; path: string; settings: ScanSettings }
  /** Present but unusable: `settings` are the defaults, `error` says why. */
  | { kind: 'invalid'; path: string; error: string; settings: ScanSettings };

export function defaultScanSettings(): ScanSettings {
  return {
    semgrep: {
      timeout: DEFAULT_SEMGREP_TIMEOUT_S,
      timeoutThreshold: DEFAULT_SEMGREP_TIMEOUT_THRESHOLD,
      acceptTimeouts: [],
    },
  };
}

/**
 * `.guardian/scan.yml` under `root` — the project, or the CI gate's
 * `--rules-ref` copy of its configuration. Never throws.
 */
export function loadScanSettings(root: string): ScanSettingsLoad {
  const path = SCAN_SETTINGS_RELATIVE_PATH;
  const read = readProjectText(root, path, MAX_BYTES);
  if (read.status === 'absent') return { kind: 'none', settings: defaultScanSettings() };
  const invalid = (error: string): ScanSettingsLoad => ({ kind: 'invalid', path, error, settings: defaultScanSettings() });
  if (read.status === 'refused') return invalid(`the file was not read: ${describeReadRefusal(read.reason)}`);
  if (read.text.trim() === '') return { kind: 'loaded', path, settings: defaultScanSettings() };
  // A key written twice is refused, never "the last one wins": a reviewer
  // read `timeout: 30` and the scan applied the `timeout: 1` below it
  // (review 11, finding 15e).
  const parsed = parseYamlBounded(read.text, YAML_CONFIG_LIMITS, { uniqueKeys: true });
  if (!parsed.ok) {
    return invalid(parsed.reason === 'invalid' ? `invalid YAML: ${(parsed.detail ?? 'unparsable').split('\n')[0] ?? ''}` : describeYamlRefusal(parsed));
  }
  const settings = parseSettings(parsed.value);
  return typeof settings === 'string' ? invalid(settings) : { kind: 'loaded', path, settings };
}

/** The settings, or why they are not valid. */
export function parseSettings(doc: unknown): ScanSettings | string {
  const out = defaultScanSettings();
  if (doc === null || doc === undefined) return out;
  if (!isRecord(doc)) return 'the document must be a mapping with a semgrep: key';
  for (const key of Object.keys(doc)) {
    if (key !== 'semgrep') return `unrecognised top-level key "${key}" (only semgrep)`;
  }
  const semgrep = doc['semgrep'];
  if (semgrep === null || semgrep === undefined) return out;
  if (!isRecord(semgrep)) return '"semgrep:" must be a mapping';
  for (const [key, value] of Object.entries(semgrep)) {
    if (key === 'timeout') {
      // A whole number: Semgrep 1.176.1 refuses `--timeout 1.5` ("is not a
      // valid integer"), and every scan then failed on a setting nobody saw
      // named (review 10) — refused here, where the error names the file.
      if (typeof value !== 'number' || !Number.isInteger(value) || value < 0 || value > 3600) {
        return `semgrep.timeout must be a whole number of seconds from 0 to 3600, got ${JSON.stringify(value)}`;
      }
      out.semgrep.timeout = value;
    } else if (key === 'timeout_threshold') {
      if (typeof value !== 'number' || !Number.isInteger(value) || value < 0 || value > 10_000) {
        return `semgrep.timeout_threshold must be a whole number from 0 to 10000, got ${JSON.stringify(value)}`;
      }
      out.semgrep.timeoutThreshold = value;
    } else if (key === 'accept_timeouts') {
      if (value === null) continue;
      if (!Array.isArray(value)) return 'semgrep.accept_timeouts must be a list of project-relative file paths';
      for (const entry of value) {
        if (typeof entry !== 'string' || entry.trim() === '') {
          return `semgrep.accept_timeouts holds ${JSON.stringify(entry)}, which is not a file path`;
        }
        const problem = relativePathProblem(entry) ?? notOneFile(entry);
        if (problem !== null) return `semgrep.accept_timeouts: ${problem}`;
        const normal = normalizeRelative(entry);
        if (!out.semgrep.acceptTimeouts.includes(normal)) out.semgrep.acceptTimeouts.push(normal);
      }
    } else {
      return `unrecognised semgrep setting "${key}" (known: timeout, timeout_threshold, accept_timeouts)`;
    }
  }
  return out;
}

/** The arguments every Semgrep scan takes from the settings. */
export function semgrepTimeoutArgs(settings: ScanSettings): string[] {
  return ['--timeout', String(settings.semgrep.timeout), '--timeout-threshold', String(settings.semgrep.timeoutThreshold)];
}

/** `/`-separated, without a leading `./` — the spelling the gate compares files in. */
export function normalizeRelative(path: string): string {
  let out = path.trim().replace(/\\/g, '/');
  while (out.startsWith('./')) out = out.slice(2);
  return out;
}

/**
 * Why `path` is not ONE file, matched exactly — or null. An entry is compared
 * with the file a Timeout names, as is: `src/gen/*.js` or `src/gen/` matched
 * nothing, in silence (review 10). `*` and `?` are refused — no file name on
 * Windows holds them, and an exact match was never what they meant; `[` and
 * `{` are read as written, since `pages/[id].js` is a file.
 */
function notOneFile(path: string): string | null {
  if (/[*?]/.test(path)) return `'${path}' is a glob; name each file exactly (globs are not read)`;
  if (/[\\/]$/.test(path.trim())) return `'${path}' is a directory; name each file exactly`;
  return null;
}

/** Why `path` cannot name a file inside the project (absolute, or climbing out), or null. */
function relativePathProblem(path: string): string | null {
  const posixPath = path.replace(/\\/g, '/');
  if (posixPath.startsWith('/') || /^[A-Za-z]:/.test(path)) return `'${path}' is absolute; name the file relative to the project`;
  if (posix.normalize(posixPath).split('/').includes('..')) return `'${path}' leaves the project`;
  return null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
