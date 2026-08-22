/**
 * `judgeScan` / `judgeTests` / `mayOpenPr` — the two differentials that
 * decide whether an applied fix gets a pull request (design doc
 * A fix is never applied-and-hoped; it is applied and then proved, twice,
 * and either proof failing means no pull request.
 *
 * **The scan differential (`judgeScan`).** Re-runs of the originating
 * scanner, before vs. after. Success requires BOTH that every target finding
 * is gone AND that no new finding appeared — the second half is not
 * decoration. A version bump that trades CVE-A for CVE-B is not a fix, and
 * reporting it as one is exactly the "something that did not happen
 * acquiring the appearance of having happened" this whole project exists to
 * eliminate (design §4.1).
 *
 * **The two halves compare by different keys, on purpose, per an amendment
 * to design §4.1 and §10 (2026-08-17, after task-7-review.md's I4).**
 * "Every target resolved" compares by fingerprint — plain set membership
 * against `targets`, since there we are asking about SPECIFIC findings we
 * set out to fix. "No new finding" compares by `(rule_id, file_path)`
 * instead. Fingerprints hash `line_start`/`line_end`/the snippet
 * (`../fingerprint/findingFingerprint.ts`), so ANY autofix pass that shifts a
 * line — or rewrites the matched line, changing the snippet — gives every
 * OTHER finding in that file a fresh fingerprint, measured at 4 of 4 on a
 * real repo. Comparing "no new finding" by fingerprint therefore means a
 * `semgrep --autofix` pass on a file with more than one finding
 * systematically fails its own differential and blames pre-existing,
 * untouched findings for it — the false accusation this amendment exists to
 * stop. Comparing by which `(rule_id, file_path)` pairs are newly present
 * survives that churn: a rule that already fired on a file, just at a
 * different line, is not new; a rule that never fired on that file before is.
 * The accepted cost: a genuine SECOND instance of the same rule newly
 * appearing in a file that already had one instance does not register as
 * new. That is a real weakening, and it is the right trade — the
 * alternative is a check that fires on every line shift a fix causes and
 * therefore tells us nothing. `compareFindings` (`../dashboard/delta.ts`) is
 * no longer used here: its diff is fingerprint-keyed end to end, which is
 * exactly the half of this differential fingerprints are wrong for.
 *
 * **The test differential (`judgeTests`) is lazy, and the laziness is a
 * correctness property, not an optimisation.** A project whose tests already
 * fail will fail after the fix too, and blaming the fix for that would be
 * the same dishonesty in another costume. So the derived command runs once,
 * in the worktree; only when THAT run fails does it run a second time, in
 * `projectPath` (the base commit), to find out who is actually responsible.
 * `outcome !== 'completed'` and `exitCode !== 0` are both checked, and
 * neither subsumes the other: a process can complete normally and still exit
 * non-zero (a real test failure), and a process can fail to complete at all
 * while somehow carrying no exit code worth trusting (a timeout). `!== 0`
 * throughout, never `??` or a truthy check — 0 is the PASSING exit code and
 * is exactly as falsy as any real failure code is truthy; this project has
 * hit that exact shape of bug five times before.
 */
import { runProcess } from '../runners/processRunner.js';
/** How many lines of a failing run's output ride along in the verdict —
 *  enough for a reader to recognise which tests broke, not the whole log. */
const OUTPUT_HEAD_LINES = 20;
export function judgeScan(targets, before, after) {
    // Set membership against `targets` — never "everything that disappeared",
    // which would answer "how many" over ALL of `before`, not "which of MY
    // targets". A fingerprint that disappeared but was never a target is
    // neither resolved nor still_present here; it is simply not this
    // differential's business.
    const afterFingerprints = new Set(after.findings.map((finding) => finding.fingerprint));
    const resolved = [];
    const still_present = [];
    for (const target of targets) {
        if (afterFingerprints.has(target))
            still_present.push(target);
        else
            resolved.push(target);
    }
    // (rule_id, file_path)-keyed, not fingerprint-keyed — see the module
    // comment for why. Never truncated: this differential's whole point is to
    // never understate what appeared.
    const newFindings = newByRuleAndFile(before.findings, after.findings);
    const new_findings = newFindings.map((finding) => ({
        fingerprint: finding.fingerprint,
        severity: finding.severity,
        title: finding.title,
    }));
    return {
        passed: still_present.length === 0 && newFindings.length === 0,
        resolved,
        still_present,
        new_findings,
    };
}
/**
 * Findings in `after` whose `(rule_id, file_path)` pair does not occur
 * anywhere in `before` — see the module comment for why this key, not the
 * fingerprint, answers "did something new appear". One representative
 * `Finding` per new key, in `after`'s own order, mirroring
 * `compareFindings`'s own de-duplication discipline (a repeated key within
 * `after` contributes exactly one row, the same as it contributes exactly
 * one member of the underlying key set).
 */
function newByRuleAndFile(before, after) {
    const beforeKeys = new Set(before.map(ruleFileKey));
    const seenNew = new Set();
    const result = [];
    for (const finding of after) {
        const key = ruleFileKey(finding);
        if (beforeKeys.has(key))
            continue;
        if (seenNew.has(key))
            continue;
        seenNew.add(key);
        result.push(finding);
    }
    return result;
}
/**
 * `JSON.stringify` of the pair, not a delimited string: `rule_id`/`file_path`
 * can themselves contain any character (a Windows path's `:`, for instance),
 * so a hand-picked delimiter risks two genuinely different pairs colliding
 * onto the same key. `?? null` normalises the optional fields so a missing
 * `rule_id` or `file_path` is a stable, distinct key of its own rather than
 * silently coinciding with a present-but-empty string.
 */
function ruleFileKey(finding) {
    return JSON.stringify([finding.rule_id ?? null, finding.file_path ?? null]);
}
export async function judgeTests(opts) {
    const { derived, worktreePath, projectPath, timeoutMs } = opts;
    // No command derived: state the absence, touch nothing. Never inferred
    // from silence downstream — design §4.2's last table row.
    if (derived === null) {
        return { outcome: 'not_run', command: null, origin: null, output_head: null };
    }
    const run = opts.run ?? runProcess;
    const command = [derived.command, ...derived.args].join(' ');
    const worktreeResult = await run({
        command: derived.command,
        args: derived.args,
        cwd: worktreePath,
        timeoutMs,
    });
    if (!hasFailed(worktreeResult)) {
        return { outcome: 'passed', command, origin: derived.origin, output_head: null };
    }
    // Lazy: this second run — the whole cost of the test differential — is
    // only ever paid once the worktree run has already produced a failure that
    // needs an owner. It runs in `projectPath`, the base commit, NEVER
    // `worktreePath` again — asking the same question of the tree that
    // existed before the fix.
    const baseResult = await run({
        command: derived.command,
        args: derived.args,
        cwd: projectPath,
        timeoutMs,
    });
    return {
        outcome: hasFailed(baseResult) ? 'already_failing' : 'broken_by_fix',
        command,
        origin: derived.origin,
        // The worktree run's output, not the base commit's — it is the failure
        // that needs explaining; the base run only exists to assign blame for it.
        output_head: headOf(worktreeResult.stdout, worktreeResult.stderr),
    };
}
/** A PR may be opened only when this is true. */
export function mayOpenPr(scan, tests) {
    return scan.passed && tests.outcome !== 'broken_by_fix';
}
// --------------------------------------------------------------- internal
/**
 * A run "failed" when the process did not complete normally (crashed, timed
 * out, was cancelled, or overflowed the output cap) OR when it completed but
 * exited non-zero — see the module comment for why both checks are needed
 * and neither is "more authoritative" than the other.
 */
function hasFailed(result) {
    return result.outcome !== 'completed' || result.exitCode !== 0;
}
/**
 * The first `OUTPUT_HEAD_LINES` lines of whichever stream actually carries
 * content — test runners overwhelmingly report failures on stdout (mocha,
 * jest, vitest, pytest, go test), so stdout is preferred; stderr is the
 * fallback for a runner that does not. `null`, not `''`, when neither stream
 * has anything — matching the field's own contract ("when there was a
 * failure"): a failing run with genuinely empty output should not read as
 * one that PRODUCED an empty-string report.
 */
function headOf(stdout, stderr) {
    const text = stdout.trim().length > 0 ? stdout : stderr;
    if (text.trim().length === 0)
        return null;
    return text.split(/\r?\n/).slice(0, OUTPUT_HEAD_LINES).join('\n');
}
//# sourceMappingURL=verify.js.map