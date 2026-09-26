/**
 * Did one Semgrep run actually scan? — Global Constraint 3 for Semgrep.
 *
 * An exit code of 0 or 1 is necessary and never sufficient. Every one of these
 * has been observed to look like a clean run from the exit code alone:
 *
 *   - exit 7: a `--config` that could not be loaded (registry offline, pack
 *     retired, invalid YAML) aborts the WHOLE run with `paths.scanned: []`.
 *     `full-security-scan.sh` printed "Semgrep returned findings" for it.
 *   - exit 2: "Invalid scanning root" for a target that does not exist — one
 *     deleted file in a pull request made `review-scan.sh` scan nothing.
 *   - exit 0 with `paths.scanned: []`: a config with `rules: []`, or targets
 *     no rule applies to — measured on semgrep 1.176.1.
 *   - exit 0 with a non-empty `errors[]`: a target that failed to parse
 *     (`PartialParsing`) is only partly analysed.
 *
 * So a run counts as done (`ok`) only when the report exists, parses, scanned
 * at least one file when there were targets, and carries no errors. The
 * report's results are still worth reading when the check fails — they are
 * real findings — which is why this returns a verdict rather than throwing.
 *
 * ---- The verdict ------------------------------------------------------
 *
 * Every Semgrep call site used to read `ok` and nothing else, except
 * `map_attack_surface`, which had its own per-file classification. That
 * classification lives here now, so scan_sast, map_attack_surface and the
 * batched runs (`fileBatchScan.ts`) agree on the same four outcomes:
 *
 *   - `ok`: complete.
 *   - `partial`: a clean exit (0, or 1 for findings) that scanned files, where
 *     EVERY `errors[]` entry is a problem confined to one target file — a
 *     warn-level `PartialParsing` (PHP's legal `const NAMESPACE` on 1.176.1,
 *     measured), a syntax error in one file, a per-file timeout. Partial
 *     coverage, never `ok` and never `failed`: the caller records the scanner
 *     as run AND missing, with the files named (`partial`).
 *   - `scanned_nothing`: a clean exit, no error, nothing scanned although
 *     there were targets — a gap, `skipped`.
 *   - `failed`: everything fatal — an unclean exit, a run that did not
 *     finish, no or unparseable report, an error that is not tied to one
 *     target file (a rule or config error, an entry naming no file, one
 *     naming a YAML file, which cannot be told from the rule pack by name —
 *     a broken YAML target stays `failed`, the conservative reading), or
 *     per-file errors on a run that scanned nothing.
 *
 * `ok` stays true only for the first, so a caller that reads nothing else
 * (`fixpr/apply.ts`, `compliance_check`) keeps treating a partial run as
 * not done.
 */
import { asArray, getProp, getString, parseInputAsJson, toRelativeIfPossible } from './scannerParsers/index.js';
/** Longest error text carried into a reason. */
const MAX_ERROR_TEXT = 300;
/**
 * Error types that describe the rules or the configuration, never one target
 * file — fatal wherever they appear, even when the entry carries a path.
 * Measured on 1.176.1: `InvalidRuleSchemaError`, `Rule parse error` and
 * `SemgrepError` ("invalid configuration file found", "Invalid YAML file").
 */
const CONFIG_ERROR_TYPE = /rule|config|yaml|schema|plugin|SemgrepError|fatal/i;
export function checkSemgrepReport(args) {
    const { raw, exitCode, outcome, targets, projectPath } = args;
    if (outcome === 'cancelled' || outcome === 'timed_out' || outcome === 'output_too_large') {
        return { ok: false, verdict: 'failed', scanned: 0, errors: 0, reason: `semgrep did not finish (${outcome})` };
    }
    if (raw === null) {
        return { ok: false, verdict: 'failed', scanned: 0, errors: 0, reason: `semgrep wrote no JSON report (exit ${String(exitCode)})` };
    }
    const root = parseInputAsJson(raw);
    if (root === null || typeof root !== 'object' || Array.isArray(root)) {
        return { ok: false, verdict: 'failed', scanned: 0, errors: 0, reason: `semgrep report is not valid JSON (exit ${String(exitCode)})` };
    }
    const scanned = asArray(getProp(getProp(root, 'paths'), 'scanned')).length;
    const errorEntries = asArray(getProp(root, 'errors'));
    const errors = describeErrors(errorEntries);
    const exitClean = exitCode === 0 || exitCode === 1;
    const problems = [];
    if (!exitClean)
        problems.push(`exit ${String(exitCode)}`);
    if (targets > 0 && scanned === 0)
        problems.push(`scanned 0 of ${targets} target(s)`);
    if (errors.length > 0) {
        problems.push(`${errors.length} Semgrep error(s): ${clip(errors.join('; '))}`);
    }
    if (problems.length === 0)
        return { ok: true, verdict: 'ok', scanned, errors: 0 };
    const reason = problems.join('; ');
    if (exitClean && scanned === 0 && errors.length === 0) {
        return { ok: false, verdict: 'scanned_nothing', scanned, errors: 0, reason };
    }
    if (exitClean && scanned > 0 && errors.length > 0) {
        const partial = perFileErrors(errorEntries);
        if (partial !== null) {
            return {
                ok: false,
                verdict: 'partial',
                scanned,
                errors: errors.length,
                reason,
                partial: partial.map((p) => ({ ...p, file: toRelativeIfPossible(p.file, projectPath) })),
            };
        }
    }
    return { ok: false, verdict: 'failed', scanned, errors: errors.length, reason };
}
/**
 * The reason a `partial` run carries: `partial: N file(s) only partly parsed
 * — <what may be missing> (PartialParsing: a.php; Syntax error: b.js)`.
 */
export function describePartialParse(partial, consequence) {
    const listed = partial.map((p) => `${p.type}: ${p.file}`).join('; ');
    return `partial: ${partial.length} file(s) only partly parsed — ${consequence} (${listed})`;
}
/** `type: message` per `errors[]` entry (`type` may be a string or `[name, …]`). */
function describeErrors(errors) {
    return errors.map((entry) => {
        const rawType = getProp(entry, 'type');
        const type = typeof rawType === 'string' ? rawType : Array.isArray(rawType) ? String(rawType[0]) : 'error';
        const message = getString(entry, 'message') ?? '(no message)';
        return `${type}: ${message.split(/\r?\n/)[0] ?? message}`;
    });
}
/**
 * Every `errors[]` entry as a per-file problem, or null when any one of them
 * is not: a config/rule error type, no target file named, or the file named
 * is a YAML file (it cannot be told from a rule pack by its name). The file
 * comes from the entry's `path`, else its first span, else the location list
 * inside a `["PartialParsing", [...]]` type. The message is its first line.
 */
function perFileErrors(errors) {
    const out = [];
    for (const entry of errors) {
        const rawType = getProp(entry, 'type');
        const type = typeof rawType === 'string' ? rawType : Array.isArray(rawType) && typeof rawType[0] === 'string' ? rawType[0] : null;
        if (type === null || CONFIG_ERROR_TYPE.test(type))
            return null;
        const file = targetFileOf(entry, rawType);
        if (file === null || /\.ya?ml$/i.test(file))
            return null;
        const message = getString(entry, 'message') ?? type;
        out.push({ file, type, message: message.split(/\r?\n/)[0] ?? message });
    }
    return out.length > 0 ? out : null;
}
function targetFileOf(entry, rawType) {
    const path = getString(entry, 'path');
    if (path !== undefined && path.length > 0)
        return path;
    const span = asArray(getProp(entry, 'spans'))[0];
    const spanFile = span === undefined ? undefined : getString(span, 'file');
    if (spanFile !== undefined && spanFile.length > 0)
        return spanFile;
    if (Array.isArray(rawType)) {
        const location = asArray(rawType[1])[0];
        const locationPath = location === undefined ? undefined : getString(location, 'path');
        if (locationPath !== undefined && locationPath.length > 0)
            return locationPath;
    }
    return null;
}
function clip(text) {
    return text.length > MAX_ERROR_TEXT ? `${text.slice(0, MAX_ERROR_TEXT - 1)}…` : text;
}
/**
 * The environment every Semgrep (and Bandit) invocation gets: the caller's,
 * plus `PYTHONUTF8=1`. Semgrep's CLI is Python and writes `--output` in the
 * locale encoding otherwise — measured on Windows (cp1252), a target named
 * `日本.py` made semgrep 1.176.1 exit 2 without writing a report, and
 * `héllo.py` came back as `h�llo.py`. UTF-8 mode also reads rule files as
 * UTF-8, which is what they are.
 */
export function pythonUtf8Env(env) {
    return { ...(env ?? process.env), PYTHONUTF8: '1' };
}
//# sourceMappingURL=semgrepReport.js.map