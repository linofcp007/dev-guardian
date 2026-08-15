/**
 * Render a `GateVerdict` for a CI consumer: human-readable text (the
 * default), JSON (for scripting), and SARIF (for GitHub/GitLab/Azure
 * code-scanning upload — the reason this task exists at all; see the design
 * doc §6).
 *
 * Pure: every renderer takes everything it needs as an argument — no
 * filesystem access, no clock, no environment lookups. `renderSarif` alone
 * also takes `projectPath`, because a SARIF `artifactLocation.uri` is
 * resolved by the *consumer* (GitHub, GitLab, ...) against the repository
 * checkout root: an absolute path — POSIX or a Windows drive letter —
 * matches nothing there, so the finding lands in the results list with no
 * line annotation on the diff, which is the entire point of shipping SARIF
 * (design doc §6, task resolution #2). See `toProjectRelativeUri`.
 *
 * SARIF generation is delegated to `../report/sarif.ts#toSarif`, the
 * project's existing SARIF producer (already used by the `report_export`
 * and `scan_skill` tools), rather than a second one. This module's own job
 * is limited to what CI specifically needs on top of that: relativised
 * URIs; `invocation.executionSuccessful` tied to `coverage`, so a consumer
 * reading only the SARIF upload can tell an incomplete scan from a clean one
 * without cross-referencing the exit code; and, for the one requirement
 * carried forward from Task 2 (see `renderSarif` below), a place for the
 * dropped-baseline-entries gap to surface via SARIF's own
 * `toolExecutionNotifications` mechanism. Design doc §9 originally read as
 * keeping ALL of `coverage` out of SARIF; it is being amended (see the task
 * report) to describe this — the coarse boolean signal in SARIF natively,
 * general coverage-gap prose (tool names, "not installed" reasons) still
 * out of it entirely.
 */
import { toSarif } from '../report/sarif.js';
import { CI_EXIT } from './types.js';
const EXIT_LABEL = {
    [CI_EXIT.PASS]: 'PASS',
    [CI_EXIT.GATE_FAILED]: 'GATE FAILED',
    [CI_EXIT.INCOMPLETE_SCAN]: 'INCOMPLETE SCAN',
    [CI_EXIT.USAGE_ERROR]: 'USAGE ERROR',
};
// ---------------------------------------------------------------------------
// Human
// ---------------------------------------------------------------------------
/**
 * The headline always names the exit-code state, not just a finding count.
 * `evaluateGate` exits INCOMPLETE_SCAN whenever coverage isn't 'full', even
 * with zero new findings (a missing scanner reporting nothing is not a clean
 * scan) — a reader must be able to tell that apart from a genuine, clean
 * PASS at a glance, not by cross-referencing the coverage line themselves.
 *
 * `coverageGaps` is printed in full whenever non-empty. That is also how the
 * dropped-baseline-entries line (carried forward from Task 2's review)
 * reaches human output: it is just another entry in `coverageGaps`, so it
 * needs no special case here — contrast `renderSarif`, which does need one,
 * because SARIF has no general-purpose home for free text.
 *
 * `baselineAbsent` (added on review of this task) gets its own line, printed
 * plainly rather than folded into `coverageGaps`: design doc §4 requires the
 * CLI to say so on a first run and to name `baseline update` as the fix, and
 * that is a one-time onboarding fact about the whole run, not a per-scanner
 * gap. It cannot be inferred from `newFindings`/`coverageGaps` — an absent
 * baseline and a present-but-empty one make every finding "new" identically
 * — which is exactly why `GateVerdict` carries it as its own field (see
 * `gate.ts`) rather than this function trying to derive it.
 */
export function renderHuman(v) {
    const lines = [
        `dev-guardian CI: ${EXIT_LABEL[v.exitCode]} (exit code ${v.exitCode})`,
        `coverage: ${v.coverage}`,
    ];
    if (v.baselineAbsent) {
        lines.push('no baseline found — run `dev-guardian baseline update` to adopt these findings as the baseline');
    }
    lines.push(`new findings: ${v.newFindings.length} (${v.blocking.length} at or above the fail-on threshold)`);
    if (v.coverageGaps.length > 0) {
        lines.push('coverage gaps:');
        for (const gap of v.coverageGaps)
            lines.push(`  - ${gap}`);
    }
    if (v.blocking.length > 0) {
        lines.push('blocking findings:');
        for (const f of v.blocking)
            lines.push(`  - ${describeFinding(f)}`);
    }
    return `${lines.join('\n')}\n`;
}
function describeFinding(f) {
    const location = f.file_path !== undefined
        ? ` (${f.file_path}${f.line_start !== undefined ? `:${f.line_start}` : ''})`
        : '';
    return `[${f.severity}] ${f.title}${location}`;
}
/**
 * snake_case keys, matching every other JSON-facing shape in `../types.ts`
 * (`Finding.file_path`, `ScanResult.findings_count_by_severity`, ...) so a
 * script consuming this alongside the rest of dev-guardian's JSON output
 * sees one convention, not two. Every field of `GateVerdict` is carried —
 * this is a full serialisation, not a summary.
 */
export function renderJson(v) {
    const payload = {
        exit_code: v.exitCode,
        coverage: v.coverage,
        coverage_gaps: v.coverageGaps,
        new_findings: v.newFindings,
        blocking_findings: v.blocking,
        baseline_absent: v.baselineAbsent,
    };
    return JSON.stringify(payload, null, 2);
}
// ---------------------------------------------------------------------------
// SARIF
// ---------------------------------------------------------------------------
/**
 * `gate.ts#evaluateGate` always builds the dropped-baseline-entries gap with
 * this exact prefix, and no other `coverageGaps` line starts with it — every
 * other line is `${step.tool}: ...`, and no scan step is named "baseline".
 * Matching the prefix (rather than owning a second copy of gate.ts's
 * wording) is what lets `renderSarif` single that one line out from the
 * general scanner-coverage gaps design doc §9 keeps out of SARIF entirely.
 */
const BASELINE_GAP_PREFIX = 'baseline: ';
/**
 * SARIF carries findings, plus two narrow, deliberate exceptions for facts
 * about the *run* that change how those findings should be read — not the
 * general coverage-gap prose (tool names, "semgrep not installed" reasons),
 * which has no home in a findings-shaped format and stays
 * exit-code-and-human/JSON-only.
 *
 * 1. `invocation.executionSuccessful` is set to `v.coverage === 'full'`.
 *    This is the SARIF-native way to say "this run was incomplete" — a
 *    consumer reading only the SARIF upload can now tell a clean scan from
 *    an incomplete one from this one boolean, without cross-referencing the
 *    exit code, closing the gap design doc §9 itself named as the reason
 *    exit code 2 has to exist as a separate channel. It is always present
 *    (every call attaches exactly one `invocations` entry), not only when
 *    there is a baseline gap to report alongside it — a fully clean run
 *    still gets an explicit `executionSuccessful: true`, so absence of
 *    `invocations` is never load-bearing for telling the two states apart.
 *
 * 2. A dropped baseline entry (carried forward from Task 2's review) is
 *    attached as a `toolExecutionNotifications` entry on that same
 *    invocation — SARIF's own mechanism for run-level messages that are not
 *    themselves findings. This one stays narrow (only the
 *    dropped-baseline-entries line, matched by prefix, never the general
 *    coverage gaps): it changes how a *result in this very document* should
 *    be read — a "new" finding that only resurfaced because its suppression
 *    entry could not be parsed, not because anyone reintroduced it — which
 *    is a fact about result trustworthiness, not scan completeness, so it
 *    does not piggyback on `executionSuccessful` (a dropped baseline entry
 *    alone must never flip that to `false` — `gate.ts` deliberately keeps
 *    `droppedBaselineEntries` out of `coverage` for the same reason; see the
 *    "surfaces a dropped-baseline-entries gap" test, which pins
 *    `executionSuccessful: true` in exactly this combination).
 *
 * (Design doc §9 originally read as excluding all of `coverage` from SARIF;
 * it is being amended to describe the above, so the doc and this code agree.)
 */
export function renderSarif(v, projectPath) {
    // A `file_path` that IS the project root relativises to `''`
    // (`toProjectRelativeUri`'s own "posixFile === posixRoot" branch). Passed
    // through, `toSarif`'s `if (f.file_path)` check (see `../report/sarif.ts`,
    // unmodified) treats that falsy `''` the same as an absent path and omits
    // `locations` entirely, rather than emitting an empty URI. That is the
    // right outcome, not a gap: a finding about the whole project has no
    // single line to annotate, so no location is more honest than one.
    const relocated = v.newFindings.map((f) => f.file_path === undefined ? f : { ...f, file_path: toProjectRelativeUri(f.file_path, projectPath) });
    const parsed = JSON.parse(toSarif(relocated));
    // Safe: this is JSON we just produced from `toSarif` on the line above,
    // not untrusted input — a full runtime re-validation of our own output
    // belongs in the schema-validation test, not here.
    const doc = parsed;
    const baselineGaps = v.coverageGaps.filter((gap) => gap.startsWith(BASELINE_GAP_PREFIX));
    const run = doc.runs[0];
    if (run !== undefined) {
        const invocation = { executionSuccessful: v.coverage === 'full' };
        if (baselineGaps.length > 0) {
            invocation.toolExecutionNotifications = baselineGaps.map((gap) => ({ message: { text: gap } }));
        }
        run.invocations = [invocation];
    }
    return JSON.stringify(doc, null, 2);
}
/**
 * Make `filePath` relative to `projectPath`, and — whatever relation the two
 * turn out to have — guarantee the result never starts with `/` or a drive
 * letter. GitHub (and every other SARIF consumer) resolves
 * `artifactLocation.uri` against the checkout root; an absolute path there
 * matches no file, so the finding renders in the results list with no line
 * annotation on the diff — silently, with nothing to say a path went wrong.
 *
 * This is deliberately a second line of defence, not the only one: most
 * scanner parsers already call `toRelativeIfPossible`
 * (`../runners/scannerParsers/index.ts`) before a `Finding` ever reaches
 * here. But that function's own fallback — reached when a path shares no
 * root with the project at all, e.g. a different Windows drive — returns
 * the path UNCHANGED, which can still be absolute; and a `Finding` can also
 * reach this module from anywhere else that builds one by hand. Rather than
 * trust every upstream caller to have relativised correctly, this function
 * makes "never absolute" hold unconditionally, for any input, including one
 * that is already relative (left untouched) or shares no root with
 * `projectPath` at all (stripped down to *something* non-absolute, on the
 * reasoning that an approximate relative path is still less wrong than an
 * absolute one GitHub will silently refuse to annotate).
 */
function toProjectRelativeUri(filePath, projectPath) {
    const posixFile = filePath.replace(/\\/g, '/');
    const posixRoot = projectPath.replace(/\\/g, '/').replace(/\/+$/, '');
    let rel = posixFile;
    if (posixRoot.length > 0) {
        if (posixFile === posixRoot) {
            rel = '';
        }
        else if (posixFile.startsWith(`${posixRoot}/`)) {
            rel = posixFile.slice(posixRoot.length + 1);
        }
    }
    // Whatever branch above ran, `rel` can still be absolute — e.g. a
    // `filePath` on a different Windows drive to `projectPath` shares no
    // prefix with it at all, so neither branch above touches it. Strip a
    // leading drive letter and a leading POSIX slash unconditionally so the
    // returned URI is never absolute, even in that case.
    return rel.replace(/^[A-Za-z]:\//, '').replace(/^\/+/, '');
}
//# sourceMappingURL=report.js.map