/**
 * The gate: findings + baseline + threshold + coverage -> verdict and exit
 * code. Pure — every input arrives as an argument, so it can be tested from
 * fixtures with no filesystem or scanner involved.
 *
 * This module exists to enforce two rules:
 *
 *   1. Historical debt must not fail the build. A finding already present in
 *      the baseline never blocks, however severe — that is the whole point
 *      of a baseline: a repository adopting this tool with 200 existing
 *      findings must go green on day one.
 *   2. A missing scanner is not a green build. "Zero new findings" from a
 *      scan that did not run is not a pass; it is a scan that says nothing.
 *      `computeCoverage` (see `../tools/scanCoverage.ts`) is the single,
 *      shared definition of "did the scan actually run" — this module reuses
 *      it rather than re-deriving a second one that could disagree.
 *
 * `GATE_FAILED` outranks `INCOMPLETE_SCAN` when both apply: a real regression
 * is the actionable failure a pipeline must see, and the coverage gaps are
 * still reported alongside it, not swallowed by it.
 *
 * ---- What does not force exit 2 ------------------------------------------
 *
 * A step that ran with a narrower gap — files a scanner read only in part
 * (the shared judge's `partial` verdict), named per file in
 * `partial_parses` — gates on those files, each by its type:
 *
 *   - a PARSE problem (`ACCEPTABLE_PARSE_TYPES`) is accepted when the caller
 *     named the file with `--accept-partial-parse` (argv only);
 *   - a per-file `Timeout` (Semgrep gave up on the file for one rule) is
 *     accepted when the project lists the file under
 *     `semgrep.accept_timeouts` in its committed `.guardian/scan.yml`
 *     (`acceptedTimeouts`; read from the `--rules-ref` ref when given, so a
 *     pull request cannot accept its own);
 *   - a taint `Fixpoint timeout` (the dataflow analysis of some functions
 *     gave up; Semgrep has no setting for it) never gates: it is a NOTE,
 *     reported, not a coverage gap (review 8, finding 3 — a medium-sized
 *     codebase never reached exit 0: dev-spec-driven's own tree had taint
 *     timeouts in 210 functions);
 *   - a file at a path too long for Windows (`Path too long`) was never
 *     opened, and nothing accepts it.
 *
 * A run whose gap is not only its files — rules that did not load, files
 * over the size limit, submodules, a stopped listing (`ToolRun.unscanned`),
 * or a skipped or failed run of the same scanner in the step — is never
 * cleared by naming files. Everything not cleared is a coverage gap and
 * exits 2.
 *
 * `coverage` is computed over every gap, accepted ones and notes included, so
 * it stays `partial` in the verdict, the JSON and the SARIF: accepting a gap
 * is not measuring it. The exit code reads only the gaps that gate
 * (`gatingCoverage`).
 *
 * ---- Every gap, as data -----------------------------------------------------
 *
 * `coverageGapDetails` describes each gap for a program reading the JSON
 * (dev-spec-driven's finish gate): one entry per `coverageGaps` line, same
 * order — its `kind` ({@link GapKind}), the line itself as `detail`, a
 * `remedy` (one English sentence, runnable where it names a command) and
 * `gating` — followed by one entry per accepted gap and per note, with
 * `gating: false` (those are not in `coverageGaps`).
 */
import { SEVERITY_ORDER } from '../types.js';
import { computeCoverage } from '../tools/scanCoverage.js';
import { FIXPOINT_TIMEOUT_TYPE } from '../runners/semgrepReport.js';
import { PATH_TOO_LONG_TYPE } from '../runners/semgrepCoverageGaps.js';
import { newFindings } from './baseline.js';
import { BASELINE_RELATIVE_PATH } from './baseline.js';
import { CI_EXIT, } from './types.js';
/**
 * The one spelling `--accept-partial-parse` paths and the scanners' partial
 * files are compared in: `/`-separated, without a leading `./`. Nothing else
 * — "matched exactly" means a directory, a glob or another case is another
 * path.
 */
export function normalizeAcceptedPath(path) {
    let out = path.replace(/\\/g, '/');
    while (out.startsWith('./'))
        out = out.slice(2);
    return out;
}
/**
 * Coverage in, exit code out — the half of the gate's exit-code rule that
 * does not depend on findings at all. Exported so a caller that has no
 * `blocking` concept of its own (`dev-guardian baseline update`: it writes
 * the baseline unconditionally and has no pass/fail gate, but still has to
 * say whether the write it just made reflects every scanner running) can
 * reuse this exact mapping instead of re-encoding it as a second ternary
 * outside this module. `evaluateGate` below calls this too, so there is
 * only ever one definition of "what does an incomplete scan's coverage
 * value mean for an exit code", not two that could drift apart. Pass it
 * `GateVerdict.gatingCoverage`: an accepted gap or a note is no reason for 2.
 */
export function exitCodeForCoverage(coverage) {
    return coverage === 'full' ? CI_EXIT.PASS : CI_EXIT.INCOMPLETE_SCAN;
}
const withReason = (reason) => (reason ? ` (${reason})` : '');
/**
 * The gap line for one `missing_tools` name, worded from what that step's
 * `tools_run` says about it — or null when the failed-run line below
 * already names it. "Not installed" is said only when nothing says
 * otherwise: a step lists a scanner missing for reasons other than absence,
 * and every one of them has sent a reader to reinstall a working scanner.
 *
 *   - an `ok` run of the same name ran, but did not cover everything (files
 *     it could not read, a pack that failed to load) — scanCoverage.ts's
 *     own convention;
 *   - a `failed` run of the same name is reported as failed, once;
 *   - a run `skipped` for a reason other than `not_installed` did not scan,
 *     and its reason says why (scan_deps: `trivy` recognised no manifest);
 *   - `<scanner>:<part>` with no run of its own is one part of a scanner
 *     that ran (scan_deps: `trivy:dotnet`, a manifest ecosystem Trivy
 *     produced nothing for) and is worded from that scanner's run.
 */
function describeMissing(name, toolsRun) {
    const own = toolsRun.filter((run) => run.name === name);
    const ok = own.find((run) => run.status === 'ok');
    if (ok !== undefined)
        return { line: `${name} ran with reduced coverage${withReason(ok.reason)}`, shape: 'reduced', ...reasonOf(ok) };
    if (own.some((run) => run.status === 'failed'))
        return { line: null, shape: 'failed' };
    const skipped = own.find((run) => run.status === 'skipped' && run.reason && run.reason !== 'not_installed');
    if (skipped !== undefined)
        return { line: `${name} skipped${withReason(skipped.reason)}`, shape: 'skipped', ...reasonOf(skipped) };
    const colon = name.indexOf(':');
    if (own.length === 0 && colon > 0) {
        const scanner = name.slice(0, colon);
        const part = name.slice(colon + 1);
        const base = toolsRun.find((run) => run.name === scanner && run.status === 'ok');
        if (base !== undefined) {
            return {
                line: `${scanner} ran with reduced coverage — ${part} not covered${withReason(base.reason)}`,
                shape: 'part',
                ...reasonOf(base),
            };
        }
    }
    return { line: `${name} not installed`, shape: 'not_installed' };
}
function reasonOf(run) {
    return run.reason !== undefined ? { reason: run.reason } : {};
}
/**
 * Semgrep error types `--accept-partial-parse` can accept: the file was
 * read, only part of it could be parsed. Every other per-file type the
 * shared judge calls partial (a `Timeout`, …) means the file was not
 * analysed, and stays a gap whatever is accepted there.
 */
export const ACCEPTABLE_PARSE_TYPES = ['PartialParsing', 'Syntax error', 'Lexical error'];
/** The per-file Semgrep type `semgrep.accept_timeouts` accepts. */
export const ACCEPTABLE_TIMEOUT_TYPE = 'Timeout';
/** What the project's own accept-list is called, in the lines that name it. */
const ACCEPT_TIMEOUTS_SOURCE = '.guardian/scan.yml semgrep.accept_timeouts';
function judgeMissing(step, name, refs, toolsRun, acceptParse, acceptTimeouts) {
    const out = { gating: true, note: '', accepted: [], notes: [] };
    if (refs.length === 0)
        return out;
    const taint = refs.filter((r) => r.type === FIXPOINT_TIMEOUT_TYPE);
    const files = refs.filter((r) => r.type !== FIXPOINT_TIMEOUT_TYPE);
    const parseOk = files.filter((r) => ACCEPTABLE_PARSE_TYPES.includes(r.type) && acceptParse.has(r.file));
    const timeoutOk = files.filter((r) => r.type === ACCEPTABLE_TIMEOUT_TYPE && acceptTimeouts.has(r.file));
    const gatingRefs = files.filter((r) => !parseOk.includes(r) && !timeoutOk.includes(r));
    if (taint.length > 0)
        out.notes.push(`${step}: ${name} ${describeTaint(taint)}`);
    if (parseOk.length > 0) {
        out.accepted.push({
            line: `${step}: ${name} only partly parsed ${uniqueFiles(parseOk).join(', ')} — accepted (--accept-partial-parse)`,
            kind: 'partial_parse',
        });
    }
    if (timeoutOk.length > 0) {
        out.accepted.push({
            line: `${step}: ${name} timed out on ${uniqueFiles(timeoutOk).join(', ')} — accepted (${ACCEPT_TIMEOUTS_SOURCE})`,
            kind: 'file_timeout',
        });
    }
    // A gap that is not only its files is never cleared by naming files.
    const sameName = toolsRun.filter((run) => run.name === name);
    const blocker = sameName.find((run) => run.status !== 'ok');
    const ok = sameName.find((run) => run.status === 'ok');
    const otherCause = ok !== undefined && ((ok.failed_rules?.length ?? 0) > 0 || ok.unscanned !== undefined);
    if (gatingRefs.length === 0 && blocker === undefined && !otherCause) {
        out.gating = false;
        return out;
    }
    // It gates after all: what it accepted is not accepted on its own.
    out.accepted = [];
    if (gatingRefs.length > 0) {
        out.kind = kindOfRefs(gatingRefs);
        out.note = notAcceptedNote(gatingRefs);
    }
    else if (blocker !== undefined) {
        out.note = ` — its partial parse is accepted, but ${name} also ${blocker.status} in this step`;
    }
    return out;
}
/** The files of `refs`, once each, in order. */
function uniqueFiles(refs) {
    return [...new Set(refs.map((r) => r.file))];
}
/** The kind a set of gating files makes a gap, by the most decisive type among them. */
function kindOfRefs(refs) {
    if (refs.some((r) => r.type === PATH_TOO_LONG_TYPE))
        return 'path_too_long';
    if (refs.some((r) => r.type === ACCEPTABLE_TIMEOUT_TYPE))
        return 'file_timeout';
    if (refs.some((r) => ACCEPTABLE_PARSE_TYPES.includes(r.type)))
        return 'partial_parse';
    return 'other';
}
/**
 * ` — not accepted: a.php, Timeout on b.js (…what accepts each…)`: a parse
 * gap by its file, any other by its type, and what would accept them.
 */
function notAcceptedNote(refs) {
    const parse = refs.filter((r) => ACCEPTABLE_PARSE_TYPES.includes(r.type));
    if (parse.length > 0) {
        return ` — not accepted: ${uniqueFiles(parse).join(', ')} (--accept-partial-parse <path> accepts one file, matched exactly)`;
    }
    const named = refs.map((r) => `${r.type} on ${r.file}`);
    const hints = [`--accept-partial-parse accepts parse errors only: ${ACCEPTABLE_PARSE_TYPES.join(', ')}`];
    if (refs.some((r) => r.type === ACCEPTABLE_TIMEOUT_TYPE))
        hints.push(`a reviewed per-file Timeout is accepted in ${ACCEPT_TIMEOUTS_SOURCE}`);
    if (refs.some((r) => r.type === PATH_TOO_LONG_TYPE))
        hints.push('a file at a path too long for Windows was never opened and is never accepted');
    return ` — not accepted: ${named.join(', ')} (${hints.join('; ')})`;
}
/** `taint analysis incomplete in N function(s) across M file(s): a, b, +K more — not gating`. */
function describeTaint(refs) {
    const files = uniqueFiles(refs);
    const shown = files.slice(0, 5);
    const more = files.length > shown.length ? `, +${files.length - shown.length} more` : '';
    return (`taint analysis incomplete (Semgrep fixpoint timeout) in ${files.length} file(s): ${shown.join(', ')}${more} — ` +
        'taint findings in those functions may be missing (not gating)');
}
/** The kind of a gap line `describeMissing` wrote. */
function kindOfMissing(shape, reason) {
    if (shape === 'not_installed')
        return 'missing_tool';
    if (shape === 'failed')
        return 'scanner_failed';
    if (reason !== undefined && /\bno_supported_manifest\b/.test(reason))
        return 'no_lockfile';
    if (shape === 'skipped')
        return /\bnot_installed\b|not installed/.test(reason ?? '') ? 'missing_tool' : 'skipped';
    return 'other';
}
/** The kind of a step that did not run, from its refusal (`<code>: <message>`, `runScans.ts`). */
function kindOfRefusal(reason) {
    if (reason === undefined)
        return 'other';
    if (/^missing_scanner\b/.test(reason))
        return 'missing_tool';
    if (/^scanner_failed\b/.test(reason))
        return 'scanner_failed';
    return 'other';
}
/** Install hints a missing-tool remedy can name. */
const INSTALL_HINT = {
    semgrep: 'pipx install semgrep',
    bandit: 'pipx install bandit',
    zizmor: 'pipx install zizmor',
};
/**
 * One short English sentence saying what clears a gap of `kind` — runnable
 * where it names a command. The `other` and `skipped` ones are chosen by what
 * the line says, since those kinds hold several causes.
 */
export function remedyFor(kind, tool, detail) {
    const scanner = tool.split(':')[0] ?? tool;
    switch (kind) {
        case 'missing_tool': {
            const hint = INSTALL_HINT[scanner];
            return hint !== undefined
                ? `Install ${scanner} (\`${hint}\`) and put it on PATH, then rerun the scan.`
                : `Install ${scanner} and put it on PATH (the install_toolchain MCP tool can), then rerun the scan.`;
        }
        case 'no_lockfile':
            return 'Commit the lockfile Trivy reads for that ecosystem (package-lock.json, yarn.lock, pnpm-lock.yaml, poetry.lock, packages.lock.json, …) and rerun.';
        case 'partial_parse':
            return 'Review the named file; if the gap is acceptable, pass `--accept-partial-parse <path>` on the scan command line (never from a repository file).';
        case 'file_timeout':
            return 'Raise semgrep.timeout in .guardian/scan.yml, or after review list the file under semgrep.accept_timeouts there and commit it.';
        case 'taint_timeout':
            return 'Nothing to do for the gate (not gating): taint findings in the named functions may be missing — splitting very large functions helps Semgrep.';
        case 'path_too_long':
            return 'Enable Windows long paths (LongPathsEnabled=1 under HKLM\\SYSTEM\\CurrentControlSet\\Control\\FileSystem, then restart) or move the project to a shorter path.';
        case 'scanner_failed':
            return /did not load|rule/i.test(detail)
                ? 'Fix or remove the rule the detail names, then rerun the scan.'
                : 'Fix the cause the detail names (the scanner, its configuration or its rules), then rerun the scan.';
        case 'skipped':
            return /local_only|--local-only/i.test(detail)
                ? 'Add rules of the project\'s own (a committed .semgrep.yml, or the init_project tool), or drop --local-only.'
                : 'Read why the scanner was skipped in the detail and give it something it can scan, or rerun where it can run.';
        default:
            if (/shallow|history truncated/i.test(detail))
                return 'Fetch the whole history (`git fetch --unshallow`, or fetch-depth: 0 in CI) and rerun.';
            if (/^baseline: /.test(detail))
                return 'Regenerate .guardian/baseline.json with a dev-guardian that reads its entries, or fix the entries by hand.';
            if (/target limit|size limit/i.test(detail))
                return "Split the files over Semgrep's 1 MB target limit, or list them in .guardianignore after review.";
            if (/submodule/i.test(detail))
                return 'Scan each submodule as a project of its own, or list it in .guardianignore after review.';
            if (/did not load/i.test(detail))
                return 'Fix or remove the rule the detail names, then rerun the scan.';
            return 'Read the detail; docs/ci.md says what each gap means and what clears it.';
    }
}
function detailOf(tool, kind, detail, gating) {
    return { tool, kind, detail, remedy: remedyFor(kind, tool, detail), gating };
}
export function evaluateGate(input) {
    const { findings, baseline, failOn, steps, droppedBaselineEntries } = input;
    const acceptParse = new Set((input.acceptedPartialParses ?? []).map(normalizeAcceptedPath));
    const acceptTimeouts = new Set((input.acceptedTimeouts ?? []).map(normalizeAcceptedPath));
    const reported = new Set();
    // Coverage comes from a single call to computeCoverage over the union of
    // every step's tool bookkeeping — never a second, hand-rolled notion of
    // "complete". A step that refused to run (`ran: false`) contributes its
    // own `tool` name into the "missing" side of that union: it is a gap in
    // exactly the sense computeCoverage already understands (something
    // expected did not happen), so `coverage` itself comes out 'partial' or
    // 'none' rather than leaving `coverage: 'full'` sitting next to an
    // INCOMPLETE_SCAN exit code.
    const allToolsRun = [];
    const allMissingTools = [];
    // The same, minus the accepted gaps and the notes: what the exit code is decided on.
    const gatingMissingTools = [];
    const coverageGaps = [];
    const gapDetails = [];
    const acceptedGaps = [];
    const acceptedDetails = [];
    const coverageNotes = [];
    const noteDetails = [];
    const pushGap = (line, tool, kind, gating) => {
        coverageGaps.push(line);
        gapDetails.push(detailOf(tool, kind, line, gating));
    };
    const suppressedByRepoConfig = [];
    for (const step of steps) {
        allToolsRun.push(...step.tools_run);
        for (const run of step.tools_run) {
            const s = run.suppressed_by_repo_config;
            if (s !== undefined)
                suppressedByRepoConfig.push({ step: step.tool, tool: run.name, ...s });
        }
        if (!step.ran) {
            allMissingTools.push(step.tool);
            gatingMissingTools.push(step.tool);
            pushGap(`${step.tool}: ${step.reason ?? 'did not run'}`, step.tool, kindOfRefusal(step.reason), true);
            continue;
        }
        for (const missing of step.missing_tools) {
            allMissingTools.push(missing);
            const refs = (step.partial_parses?.[missing] ?? []).map((r) => ({ ...r, file: normalizeAcceptedPath(r.file) }));
            for (const ref of refs)
                reported.add(ref.file);
            const judged = judgeMissing(step.tool, missing, refs, step.tools_run, acceptParse, acceptTimeouts);
            for (const note of judged.notes) {
                coverageNotes.push(note);
                noteDetails.push(detailOf(missing, 'taint_timeout', note, false));
            }
            if (!judged.gating) {
                for (const a of judged.accepted) {
                    acceptedGaps.push(a.line);
                    acceptedDetails.push(detailOf(missing, a.kind, a.line, false));
                }
                continue;
            }
            gatingMissingTools.push(missing);
            const described = describeMissing(missing, step.tools_run);
            if (described.line !== null) {
                pushGap(`${step.tool}: ${described.line}${judged.note}`, missing, judged.kind ?? kindOfMissing(described.shape, described.reason), true);
            }
        }
        for (const run of step.tools_run) {
            if (run.status === 'failed') {
                pushGap(`${step.tool}: ${run.name} failed${run.reason ? ` (${run.reason})` : ''}`, run.name, 'scanner_failed', true);
            }
            // status 'skipped' (nothing to do, e.g. no Dockerfile) is deliberately
            // not a gap — computeCoverage's own contract, see scanCoverage.ts.
        }
    }
    if (droppedBaselineEntries > 0) {
        const noun = droppedBaselineEntries === 1 ? 'entry' : 'entries';
        const verb = droppedBaselineEntries === 1 ? 'is' : 'are';
        // Visible, never gating (see `GateInput.droppedBaselineEntries`).
        pushGap(`baseline: ${droppedBaselineEntries} ${noun} could not be read and ${verb} no longer suppressed`, 'baseline', 'other', false);
    }
    // Every gap, accepted ones and notes included: an accepted partial parse is
    // still partial coverage, and says so in the JSON and the SARIF.
    const coverage = computeCoverage(allToolsRun, allMissingTools);
    const gatingCoverage = computeCoverage(allToolsRun, gatingMissingTools);
    // Historical debt must not fail the build: `newFindings` already excludes
    // anything the baseline recognises, however severe.
    const newlyFound = newFindings(findings, baseline, input.renamedFrom);
    const blocking = newlyFound.filter((finding) => SEVERITY_ORDER[finding.severity] >= SEVERITY_ORDER[failOn]);
    // GATE_FAILED outranks whatever exitCodeForCoverage would say on its own:
    // a real regression is the actionable failure a pipeline must see, ahead
    // of an incomplete-scan signal that is still reported (via coverageGaps)
    // but does not get to hide a blocking finding behind it.
    //
    // The exit code reads coverage WITHOUT the accepted gaps and the notes.
    const exitCode = blocking.length > 0 ? CI_EXIT.GATE_FAILED : exitCodeForCoverage(gatingCoverage);
    return {
        exitCode,
        newFindings: newlyFound,
        blocking,
        coverage,
        gatingCoverage,
        coverageGaps,
        coverageGapDetails: [...gapDetails, ...acceptedDetails, ...noteDetails],
        coverageNotes,
        baselineAbsent: baseline === null,
        acceptedGaps,
        unusedPartialParseAcceptances: [...acceptParse].filter((path) => !reported.has(path)),
        suppressedByRepoConfig,
        baselineSource: input.baselineSource ?? { from: 'tree', path: BASELINE_RELATIVE_PATH },
        rulesSource: input.rulesSource ?? { from: 'tree' },
        exclusionsReset: input.exclusionsReset ?? null,
    };
}
//# sourceMappingURL=gate.js.map