/**
 * What a Semgrep run cannot see and does not say — computed here, once, for
 * every caller that builds a result from a Semgrep run (review M1 / M2,
 * round 2: "one shared place, so a future caller can't miss them").
 *
 *   - **Files over Semgrep's size limit.** Semgrep ignores a target larger
 *     than `--max-target-bytes` (1 000 000 by default) in silence:
 *     `paths.skipped` names it only under `--verbose`. Measured on 1.176.1: a
 *     1.16 MB `big.py` beside a small file read coverage full; alone it read
 *     "nothing here is a language its rules cover". The files the scanners
 *     read, with a source language, are stat'ed here
 *     (`frameworks/projectLanguages.ts#oversizedSourceFilesAsync`).
 *   - **Git submodules.** Semgrep lists its targets with git, which holds an
 *     initialised submodule as one gitlink, so none of its files is scanned
 *     (measured: a `vendor/lib` with an `eval` read full). They are named,
 *     never scanned: a submodule is its own project. One the project's
 *     `.guardianignore` excludes is not named (round 4, item 6).
 *   - **A listing that stopped early** (the walk outside git reached its
 *     directory ceiling): files below it were not checked for their size, so
 *     the run cannot be called complete either.
 *
 * Every gap is named in the run's reason and makes the run partial (`ok`,
 * or `skipped`, AND listed missing).
 *
 * Not a gap, but named the same way on every run it shapes (round 5, item
 * 2; `runners/repoConfig.ts`): the project's `.semgrepignore` files — the
 * root one and any below it, each applying to its own subtree. Measured on
 * 1.176.1, Semgrep honours them for a DIRECTORY target, whatever the working
 * directory, and not for files named explicitly (a scope, a review's changed
 * files), so only a whole-project run names them. `test/unit/runners/semgrepCoverageGaps
 * .test.ts` fails when a file in `src/` spawns Semgrep for a result without
 * calling {@link applySemgrepCoverageGaps}.
 */
import { describeOversized, oversizedSourceFilesAsync } from '../frameworks/projectLanguages.js';
import { submodulesNotIgnored } from '../platform/guardianIgnore.js';
import { honouredFiles, withProjectConfig } from './repoConfig.js';
import { describeSubmodules, initialisedSubmodules } from './git.js';
export const NO_SEMGREP_GAPS = { oversized: [], submodules: [] };
/**
 * The gaps of a Semgrep run over `projectPath` — the whole project, or with
 * `files` exactly those files (a scope, a review's changed files). The
 * submodules named are the project's, or with `among` (default: `files`)
 * only those one of those paths reaches: a submodule a review's diff bumps,
 * never one it did not touch.
 */
export async function semgrepCoverageGaps(projectPath, opts = {}) {
    const from = opts.guardianIgnoreFrom;
    const sized = await oversizedSourceFilesAsync(projectPath, {
        ...(opts.files !== undefined ? { only: opts.files } : {}),
        ...(from !== undefined ? { guardianIgnoreFrom: from } : {}),
    });
    // A directory target reads them; explicit file targets do not.
    const honoured = opts.files === undefined ? await honouredFiles(projectPath, 'semgrep') : [];
    const withHonoured = (gaps) => honoured.length > 0 ? { ...gaps, honoured } : gaps;
    if (opts.submodules !== undefined) {
        const out = {
            oversized: sized.files,
            submodules: submodulesNotIgnored(projectPath, opts.submodules, from).sort(),
        };
        if (sized.incomplete !== undefined)
            out.incomplete = sized.incomplete;
        return withHonoured(out);
    }
    const all = submodulesNotIgnored(projectPath, await initialisedSubmodules(projectPath), from);
    const among = opts.among ?? opts.files;
    const submodules = among === undefined
        ? all
        : all.filter((sub) => among.some((p) => {
            const posix = p.split('\\').join('/');
            return posix === sub || posix.startsWith(`${sub}/`);
        }));
    const out = { oversized: sized.files, submodules };
    if (sized.incomplete !== undefined)
        out.incomplete = sized.incomplete;
    return withHonoured(out);
}
/** Each gap in words, in a fixed order. Empty: none. */
export function semgrepGapNotes(gaps) {
    const notes = [];
    if (gaps.oversized.length > 0)
        notes.push(describeOversized(gaps.oversized));
    if (gaps.submodules.length > 0)
        notes.push(describeSubmodules(gaps.submodules));
    if (gaps.incomplete !== undefined) {
        notes.push(`${gaps.incomplete} — files over Semgrep's size limit below it were not checked`);
    }
    return notes;
}
/**
 * Why a run that scanned no file scanned none, when the gaps say: every file
 * it would have read was over the size limit. Null otherwise — the caller's
 * own reason ("no file in a covered language") then stands.
 */
export function scannedNothingBecause(gaps) {
    return gaps.oversized.length > 0 ? `semgrep scanned 0 files — ${describeOversized(gaps.oversized)}` : null;
}
/**
 * `run` with the gaps applied: each note not already in its reason appended
 * to it, and `missing` true when a run that was not `failed` has any — the
 * caller lists the run's name in `missing_tools` (coverage partial). With
 * `scannedNothing`, the run scanned no file and its reason claims why; when
 * the files were only too large, that claim is replaced by
 * {@link scannedNothingBecause}.
 */
export function applySemgrepCoverageGaps(run, gaps, opts = {}) {
    const applied = applyGaps(run, gaps, opts);
    // What the run honoured is named whatever its gaps — on a run that scanned
    // nothing too: a .semgrepignore may be why. Not when Semgrep never ran.
    const ran = !(run.status === 'skipped' && run.reason === 'not_installed');
    const named = ran ? withProjectConfig(applied.toolRun, gaps.honoured ?? []) : applied.toolRun;
    return { toolRun: named, missing: applied.missing };
}
function applyGaps(run, gaps, opts) {
    const notes = semgrepGapNotes(gaps);
    if (notes.length === 0)
        return { toolRun: run, missing: false };
    const because = opts.scannedNothing === true ? scannedNothingBecause(gaps) : null;
    const base = because ?? run.reason;
    const added = notes.filter((n) => base === undefined || !base.includes(n));
    const reason = [base, ...added].filter((s) => s !== undefined && s.length > 0).join('; ');
    return { toolRun: { ...run, reason }, missing: run.status !== 'failed' };
}
/** Push `name` into `missing` once. */
export function markMissing(missing, name) {
    if (!missing.includes(name))
        missing.push(name);
}
//# sourceMappingURL=semgrepCoverageGaps.js.map