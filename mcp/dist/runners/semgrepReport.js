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
 * So a run counts as done only when the report exists, parses, scanned at
 * least one file when there were targets, and carries no errors. The report's
 * results are still worth reading when the check fails — they are real
 * findings — which is why this returns a verdict rather than throwing.
 */
import { asArray, getProp, getString, parseInputAsJson } from './scannerParsers/index.js';
/** Longest error text carried into a reason. */
const MAX_ERROR_TEXT = 300;
export function checkSemgrepReport(args) {
    const { raw, exitCode, outcome, targets } = args;
    if (outcome === 'cancelled' || outcome === 'timed_out' || outcome === 'output_too_large') {
        return { ok: false, scanned: 0, reason: `semgrep did not finish (${outcome})` };
    }
    if (raw === null) {
        return { ok: false, scanned: 0, reason: `semgrep wrote no JSON report (exit ${String(exitCode)})` };
    }
    const root = parseInputAsJson(raw);
    if (root === null || typeof root !== 'object' || Array.isArray(root)) {
        return { ok: false, scanned: 0, reason: `semgrep report is not valid JSON (exit ${String(exitCode)})` };
    }
    const scanned = asArray(getProp(getProp(root, 'paths'), 'scanned')).length;
    const errors = describeErrors(asArray(getProp(root, 'errors')));
    const problems = [];
    if (exitCode !== 0 && exitCode !== 1)
        problems.push(`exit ${String(exitCode)}`);
    if (targets > 0 && scanned === 0)
        problems.push(`scanned 0 of ${targets} target(s)`);
    if (errors.length > 0) {
        problems.push(`${errors.length} Semgrep error(s): ${clip(errors.join('; '))}`);
    }
    if (problems.length > 0)
        return { ok: false, scanned, reason: problems.join('; ') };
    return { ok: true, scanned };
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