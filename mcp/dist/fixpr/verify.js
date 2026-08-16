/**
 * `judgeScan` / `judgeTests` / `mayOpenPr` — the two differentials that
 * decide whether an applied fix gets a pull request (design doc
 * `docs/superpowers/specs/2026-08-16-create-fix-pr-design.md` §4.1, §4.2).
 * A fix is never applied-and-hoped; it is applied and then proved, twice,
 * and either proof failing means no pull request.
 *
 * **The scan differential (`judgeScan`).** Re-runs of the originating
 * scanner, before vs. after, compared by fingerprint. Success requires BOTH
 * that every target finding is gone AND that no new finding appeared — the
 * second half is not decoration. A version bump that trades CVE-A for CVE-B
 * is not a fix, and reporting it as one is exactly the "something that did
 * not happen acquiring the appearance of having happened" this whole project
 * exists to eliminate (design §4.1).
 *
 * The "no new finding" half is answered by `compareFindings`
 * (`../dashboard/delta.ts`), which already computes a correct, tested
 * fingerprint-set diff — including de-duplication and stable ordering. It is
 * called with an effectively uncapped `cap` (`Number.MAX_SAFE_INTEGER`)
 * because this differential's whole point is to never understate what
 * appeared; the dashboard's own display cap (500, for a UI) has no place
 * here. **No second comparator is written**: the "every target resolved"
 * half is a different question `compareFindings` was never built to
 * answer — it returns aggregate counts, not which specific fingerprints
 * resolved — so that half is plain set membership against `targets`, not a
 * reimplementation of the diff itself.
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
import { compareFindings } from '../dashboard/delta.js';
import { runProcess } from '../runners/processRunner.js';
/** Passed to `compareFindings` so the new-findings side of the differential
 *  is never truncated — see the module comment. */
const UNCAPPED = Number.MAX_SAFE_INTEGER;
/** How many lines of a failing run's output ride along in the verdict —
 *  enough for a reader to recognise which tests broke, not the whole log. */
const OUTPUT_HEAD_LINES = 20;
export function judgeScan(targets, before, after) {
    const { delta } = compareFindings(before, after, UNCAPPED);
    // Set membership against `targets` — not compareFindings's own
    // resolved_count/unchanged_count, which answer "how many" over ALL of
    // `before`, not "which of MY targets". A fingerprint that disappeared but
    // was never a target is neither resolved nor still_present here; it is
    // simply not this differential's business.
    const afterFingerprints = new Set(after.findings.map((finding) => finding.fingerprint));
    const resolved = [];
    const still_present = [];
    for (const target of targets) {
        if (afterFingerprints.has(target))
            still_present.push(target);
        else
            resolved.push(target);
    }
    const new_findings = delta.new_findings.map((finding) => ({
        fingerprint: finding.fingerprint,
        severity: finding.severity,
        title: finding.title,
    }));
    return {
        // delta.new_count, the TRUE count — never new_findings.length, which
        // would silently agree with a truncated list were one ever introduced
        // upstream. With UNCAPPED the two are always equal in practice; using
        // new_count anyway is the same discipline the dashboard itself follows.
        passed: still_present.length === 0 && delta.new_count === 0,
        resolved,
        still_present,
        new_findings,
    };
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