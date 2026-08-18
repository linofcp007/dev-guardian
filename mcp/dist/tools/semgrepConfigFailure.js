/**
 * Semgrep config-load failures — registry packs AND local rule files.
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
 * A LOCAL `--config=` (`configs/semgrep/bugfix-js.yml`, wired in by
 * bugfix-rules-jsts Task 3) can't 404, but a hand-edited file can have
 * broken YAML — and empirically (live, 1.164.0, against a deliberately
 * corrupted copy with an unclosed `languages: [...]` bracket) that failure
 * mode is IDENTICAL to a registry 404 in every way that matters here: exit
 * 7, `results: []`, `paths.scanned: []`, one `errors[]` entry
 * (`type: 'SemgrepError'`, message starting `"Invalid YAML file <path>:"`)
 * plus the same trailing "N configs were invalid" summary line. So it needs
 * the SAME treatment — attributed to the failed `--config=` value and fed
 * through the same retry-survivor path — not a separate mechanism.
 *
 * That is a DIFFERENT failure from a single bad RULE inside an otherwise
 * loadable local file (e.g. a typo'd Semgrep `pattern:`). Also verified
 * live (1.164.0, three `--config=` values: the two base registry packs plus
 * a copy of bugfix-js.yml with exactly one rule's pattern broken): exit 2,
 * `type: 'Rule parse error'` (not `'SemgrepError'`), but — unlike the YAML
 * case — `paths.scanned` is NON-empty and `results` contains a REAL finding
 * from a different, still-valid rule in the SAME file. Semgrep drops only
 * the one broken rule and keeps running everything else, in that file and
 * in every sibling `--config`. Treating this the same as a whole-config
 * failure (dropping the pack, retrying without it) would be wrong twice
 * over: unnecessary, because nothing needs to be dropped for a scan that
 * already worked, and harmful, because a retry without the local file would
 * throw away the OTHER rules' already-obtained results. See
 * `wasAnythingScanned`/`describeRawErrors` below, and `bugHunt.ts`'s own use
 * of them, for how this case is told apart and reported instead.
 *
 * Exit code / outcome alone is not sufficient signal for either case:
 * nothing guarantees a future Semgrep release keeps exiting non-zero for
 * the download-failure condition, an empty `results: []` from a
 * clean-looking exit 0 would silently read as "no bugs found" instead of
 * "nothing was scanned", and exit code 2 alone cannot distinguish "nothing
 * was scanned" from "everything was scanned except one broken rule" (both
 * observed for that code — see the two paragraphs above). Callers should
 * read `errors[]` (and `paths.scanned`) explicitly rather than trusting
 * `outcome`/`exitCode` alone.
 */
import { asArray, getProp, getString, parseInputAsJson, } from '../runners/scannerParsers/index.js';
const DOWNLOAD_FAILURE_RE = /Failed to download configuration from (\S+)/;
const REGISTRY_URL_PREFIX_RE = /^https?:\/\/semgrep\.dev\/c\//;
/**
 * A local `--config=` file with broken YAML — verified live (1.164.0, see
 * this module's header comment) to produce `"Invalid YAML file <path>:"`
 * followed by parser detail on later lines. `.` does not match `\n` in JS
 * regex by default, so `(.+)` is already bounded to the first line; greedy
 * backtracking then finds the LAST `:` on that line (immediately before the
 * newline) rather than the first — which matters because a Windows
 * absolute path's own drive letter (`C:\...`) contains a colon that is NOT
 * the delimiter. Confirmed against the real captured message, not assumed.
 */
const LOCAL_YAML_FAILURE_RE = /^Invalid YAML file (.+):\r?\n/;
/**
 * Scan a Semgrep JSON report's `errors[]` for "this whole `--config=`
 * could not be loaded" entries — a registry download failure OR a local
 * file with invalid YAML (see this module's header comment for why both
 * belong in the same function: identical whole-invocation-aborts
 * behaviour, so the same retry-survivor treatment applies to both).
 * Returns `[]` for null/unparsable input or JSON with no matching errors —
 * never throws, so callers can pass `readJsonSafe`'s result straight
 * through. Deliberately does NOT match a `"Rule parse error"` (a single bad
 * rule inside an otherwise-loadable file) — see `wasAnythingScanned` /
 * `describeRawErrors` below for that case, which needs different handling,
 * not a bigger regex here.
 */
export function findConfigDownloadFailures(raw) {
    if (raw === null)
        return [];
    const root = parseInputAsJson(raw);
    const errors = asArray(getProp(root, 'errors'));
    const failures = [];
    for (const entry of errors) {
        const message = getString(entry, 'message');
        if (message === undefined)
            continue;
        const downloadMatch = DOWNLOAD_FAILURE_RE.exec(message);
        if (downloadMatch) {
            const url = downloadMatch[1];
            const pack = url !== undefined ? url.replace(REGISTRY_URL_PREFIX_RE, '') : null;
            failures.push({ pack, message });
            continue;
        }
        const localMatch = LOCAL_YAML_FAILURE_RE.exec(message);
        if (localMatch) {
            failures.push({ pack: localMatch[1] ?? null, message });
            continue;
        }
    }
    return failures;
}
/** Which of `configured` were NOT named by any entry in `failures`. */
export function survivingPacks(configured, failures) {
    const failedNames = new Set(failures.map((f) => f.pack).filter((p) => p !== null));
    return configured.filter((p) => !failedNames.has(p));
}
/** Render `pack (message)` for every failure, joined for a tools_run reason. */
export function describeConfigFailures(failures) {
    return failures.map((f) => `${f.pack ?? 'unknown config'} (${f.message})`).join('; ');
}
/**
 * Did Semgrep actually scan anything in this invocation? True whenever
 * `paths.scanned` is non-empty, regardless of exit code or `errors[]`.
 *
 * This is the signal that tells a `"Rule parse error"` (a single bad rule
 * in an otherwise-loadable local file — see this module's header comment)
 * apart from a genuine whole-invocation abort, WITHOUT hand-matching that
 * error type by name: live-verified (1.164.0) that exit code alone cannot
 * make this distinction — a whole-config YAML failure and a single broken
 * rule inside an otherwise-fine file can both leave Semgrep exiting
 * non-zero/non-one, but only one of them means nothing was scanned.
 * `paths.scanned` does not have that ambiguity.
 */
export function wasAnythingScanned(raw) {
    if (raw === null)
        return false;
    const root = parseInputAsJson(raw);
    const paths = getProp(root, 'paths');
    const scanned = asArray(getProp(paths, 'scanned'));
    return scanned.length > 0;
}
/**
 * Human-readable summary of whatever `errors[]` contains, for a
 * `tools_run[].reason` when `findConfigDownloadFailures` found neither
 * known whole-config-failure shape — e.g. a `"Rule parse error"`, whose
 * `rule_id` (when present) is prefixed onto its own message.
 *
 * Deliberately generic rather than one more hand-matched regex: the actual
 * gap this closes is "no reason given" for whatever Semgrep reports, not a
 * complete catalogue of every message shape it can produce. Returns `null`
 * for null/unparsable input or an empty `errors[]`, so a caller can use
 * that to mean "nothing to add" rather than pushing an empty reason.
 */
export function describeRawErrors(raw) {
    if (raw === null)
        return null;
    const root = parseInputAsJson(raw);
    const errors = asArray(getProp(root, 'errors'));
    const parts = [];
    for (const entry of errors) {
        const message = getString(entry, 'message');
        if (message === undefined)
            continue;
        const ruleId = getString(entry, 'rule_id');
        parts.push(ruleId !== undefined ? `${ruleId}: ${message}` : message);
    }
    return parts.length > 0 ? parts.join('; ') : null;
}
//# sourceMappingURL=semgrepConfigFailure.js.map