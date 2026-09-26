/**
 * What a comparison of two scans may call "resolved" — and "new".
 *
 * A finding of the older scan that the newer one does not report is resolved
 * only if the newer scan LOOKED — with the scanner that reports it. Counted
 * otherwise, the gap read as a fix: an orchestrated `security_scan_full`
 * run is compared as a whole (its parent row holds every child's findings
 * merged), and when a child measured nothing (Semgrep exit 7, Trivy not
 * installed) its type was absent from the parent and every earlier finding
 * of it read as resolved — in the dashboard's since_previous, `diff_scans`'s
 * default, `regression_alert` (where the false resolution cancelled a real
 * new high) and `set_baseline` (fix round 2). Nor is "the child ran" enough:
 * a Python project's sast child can be [semgrep failed, bandit ok] — coverage
 * partial, status completed — and every Semgrep finding still vanished (fix
 * round 3). So the question is asked per SCANNER:
 *
 *   - NOT RE-MEASURED: a finding of `from` whose scanner the newer scan did
 *     not measure (for the child that covers it) — it failed, was missing,
 *     or did not run at all. Never resolved, never unchanged.
 *   - NOT PREVIOUSLY MEASURED: a finding of `to` whose scanner the reference
 *     (a baseline, the previous run) NAMED and did not run ok — it failed, or
 *     was listed missing. Not "new": a partial baseline would otherwise raise
 *     a false regression alarm.
 *
 * The two are not mirrors (fix round 5). A reference that did not run a
 * scanner at all — not applicable then (no Python for Bandit, no
 * package.json for npm, no Dockerfile for Trivy's config pass) or not
 * requested (nuclei, security-code-scan's opt-in) — looked at everything it
 * had to, and what that scanner finds now is NEW: read as "not previously
 * measured", regression_alert stayed silent on Bandit's first high the day
 * Python was added. The newer side cannot make the same call — a scanner
 * that stopped running may simply be absent this time — so there a scanner
 * that did not run still leaves its findings not re-measured, never resolved.
 *
 * "Ran ok" is read from the scan's bookkeeping (`tools_run`, `missing_tools`)
 * through the explicit name table in `history/runNames.ts` — the names are
 * not the findings' tools (`npm` records npm-audit's findings,
 * `guardian-dast` the `dast` ones). For a finding's scanner:
 *
 *   - measured when some entry naming it ran ok, no entry naming it failed
 *     (a failed pass — `guardian-dast:unanswered`, `gitleaks-working-tree` —
 *     vetoes the whole scanner: its findings cannot be told apart by pass),
 *     and no `missing_tools` entry names it — unless that same name also ran
 *     ok, which is a run with a narrower gap inside it (bug_hunt's pack
 *     retry, gitleaks' size limits, a Semgrep partial parse) — and the
 *     finding is not in a file that run names as only partly parsed
 *     (`ToolRun.partially_parsed`: that file's findings are unmeasured);
 *   - UNMEASURED — a gap — when it is named, but a naming entry failed, or a
 *     `missing_tools` entry names it (outside the retry shape above), or no
 *     entry naming it ran ok;
 *   - NOT RUN when the bookkeeping never names a scanner the table knows —
 *     nuclei not requested, no image given: the scan did not look — or names
 *     it only in passes skipped with no gap recorded (`trivy` skipped for
 *     want of a Dockerfile: `computeCoverage`'s "nothing to scan"), and
 *     when one scan ran a pass that may have produced the finding and the
 *     other did not look at that pass's TARGET again: an image
 *     (`trivy-image`) and the project's files (`trivy-dockerfile`,
 *     `trivy-config`) are measured under the same key, but a Dockerfile
 *     pass never looked at the image, nor an image pass at the Dockerfile,
 *     nor a scan of image B at image A (`ToolRun.target`; see
 *     `targetNotRun`);
 *   - for a tool the table does not know at all, measured only by a scan
 *     with no gap anywhere (coverage `full`), never by a partial one;
 *   - a scan with no bookkeeping at all (the oldest rows) measured
 *     everything.
 *
 * An audit_executive row is judged by its sub-scans' own bookkeeping (its
 * own entries only say which sub-tool answered).
 */
import { indexFindings } from '../fingerprint/findingIdentity.js';
import { computeCoverage } from '../tools/scanCoverage.js';
import { KNOWN_FINDING_KEYS, findingKey, keysOfRun, runNameEntry } from './runNames.js';
import { isOrchestratedFullScan, isScriptEraFullScan, scriptEraSlotOfFinding } from './scanRoles.js';
/** A comparison with nothing unmeasured on either side (no reference scan row to read). */
export const COMPLETE_COMPARISON = {
    isNotRemeasured: () => false,
    isNotPreviouslyMeasured: () => false,
    notRunByTo: () => null,
    notRunByFrom: () => null,
    notMeasuredByTo: [],
    gapsByTo: [],
    notMeasuredByFrom: [],
};
/** An orchestrated run's children, as its parent row lists them. */
function childrenOf(storage, parent) {
    const listed = parent.meta?.['child_scans'];
    if (!Array.isArray(listed))
        return [];
    const out = [];
    for (const entry of listed) {
        if (entry === null || typeof entry !== 'object')
            continue;
        const e = entry;
        const row = typeof e.scan_id === 'string' ? storage.scans.getById(e.scan_id) : null;
        const type = row?.scan_type ?? (typeof e.tool === 'string' ? e.tool.replace(/^scan_/, '') : null);
        if (type !== null)
            out.push({ type, row });
    }
    return out;
}
/** A child that can speak for its type at all: present, completed. */
function usableChild(c) {
    return c.row !== null && c.row.status === 'completed';
}
/**
 * An audit_executive row's bookkeeping, as its sub-scans recorded it. The
 * row's own entries are one per sub-tool (`security_scan_full: ok`): that
 * the sub-tool answered, not that each of its scanners ran — a sub-scan
 * whose Semgrep failed still reports `ok`. Each ok entry is therefore
 * replaced by its sub-scan's own `tools_run` / `missing_tools`; an entry
 * without a readable sub-scan (a sub-tool that failed before it wrote one,
 * a pruned row) stays, and speaks through `runNames.ts`.
 */
function auditBookkeeping(storage, audit) {
    const ids = audit.meta?.['sub_scan_ids'];
    if (ids === null || typeof ids !== 'object' || Array.isArray(ids))
        return audit;
    const byTool = ids;
    const tools_run = [];
    const missing_tools = [...audit.missing_tools];
    for (const entry of audit.tools_run) {
        const id = Object.hasOwn(byTool, entry.name) ? byTool[entry.name] : undefined;
        const sub = entry.status === 'ok' && typeof id === 'string' ? storage.scans.getById(id) : null;
        if (sub === null || (sub.tools_run.length === 0 && sub.missing_tools.length === 0)) {
            tools_run.push(entry);
            continue;
        }
        tools_run.push(...sub.tools_run);
        missing_tools.push(...sub.missing_tools);
    }
    return { tools_run, missing_tools };
}
function bookkeepingOf(storage, scan) {
    return scan.scan_type === 'audit' ? auditBookkeeping(storage, scan) : scan;
}
// ---------------------------------------------------------------------------
// Per-scanner "did this bookkeeping measure this key?"
// ---------------------------------------------------------------------------
function keyVerdict(book, key) {
    let named = false;
    let anyOk = false;
    let anyFailed = false;
    const okNames = new Set();
    for (const run of book.tools_run) {
        const ok = run.status === 'ok';
        if (!(keysOfRun(run.name, ok)?.includes(key) ?? false))
            continue;
        named = true;
        if (ok) {
            anyOk = true;
            okNames.add(run.name);
        }
        else if (run.status === 'failed') {
            anyFailed = true;
        }
    }
    let missing = false;
    for (const name of book.missing_tools) {
        if (!(keysOfRun(name, false)?.includes(key) ?? false))
            continue;
        named = true;
        // Listed missing AND ok under the same name: the scanner ran, with a
        // narrower gap inside it (bug_hunt's pack retry, gitleaks' size limits).
        if (!okNames.has(name))
            missing = true;
    }
    if (named) {
        if (anyFailed || missing)
            return 'unmeasured';
        // Named only by passes skipped with no gap recorded — nothing for them to
        // scan (no Dockerfile, no uncommitted files) — is the same as not named.
        return anyOk ? 'measured' : 'not_run';
    }
    if (KNOWN_FINDING_KEYS.has(key))
        return 'not_run';
    // A tool no bookkeeping name is known to measure: only a scan with no gap
    // anywhere can speak for it — never a partial one.
    return computeCoverage(book.tools_run, book.missing_tools) === 'full' ? 'measured' : 'unmeasured';
}
function isEmptyBook(book) {
    return book.tools_run.length === 0 && book.missing_tools.length === 0;
}
function bookkeepingVerdict(book, f) {
    if (isEmptyBook(book))
        return 'measured';
    const verdict = keyVerdict(book, findingKey(f));
    return verdict === 'measured' && partlyParsedRunOf(book, f) !== null ? 'unmeasured' : verdict;
}
/**
 * The run measuring `f`'s key that could only partly parse `f`'s file
 * (`ToolRun.partially_parsed`: the shared Semgrep judge's `partial` verdict,
 * `ok` AND missing), or null. The rest of that run measured — the retry
 * shape above — but a finding inside the unparsed span of a named file was
 * not looked for: it is unmeasured, never resolved and never new. (Before
 * that verdict the whole run was `failed`, and none of its findings
 * measured.)
 */
function partlyParsedRunOf(book, f) {
    if (f.file_path === undefined)
        return null;
    const file = f.file_path.replace(/\\/g, '/');
    const key = findingKey(f);
    const run = book.tools_run.find((r) => r.status === 'ok' &&
        (r.partially_parsed ?? []).some((p) => p.file === file) &&
        (keysOfRun(r.name, true)?.includes(key) ?? false));
    return run === undefined ? null : { run, file };
}
/** The runs and missing names of `book` that record a gap in `key`: failed, or missing without an ok run. */
function gapNamesFor(book, key) {
    const okNames = new Set(book.tools_run.filter((r) => r.status === 'ok').map((r) => r.name));
    const names = [];
    const add = (name) => {
        if (!names.includes(name))
            names.push(name);
    };
    for (const run of book.tools_run) {
        if (run.status === 'failed' && (keysOfRun(run.name, false)?.includes(key) ?? false))
            add(run.name);
    }
    for (const name of book.missing_tools) {
        if (!okNames.has(name) && (keysOfRun(name, false)?.includes(key) ?? false))
            add(name);
    }
    return names;
}
/**
 * The open set's question (`openSet.ts`): does `asked`, a NEWER scan of the
 * same slot, leave `f` — a finding of the older scan `holder` describes —
 * still open, because it did not re-measure it for a reason it RECORDED?
 * Returns that gap's name, or null when `asked` re-measured `f` (and did not
 * find it: resolved) or did not run `f`'s scanner at all (no gap recorded —
 * not applicable, not requested: a Python-free project's Bandit).
 *
 * The same reading as {@link compareScansFor}'s "not re-measured", from the
 * same helpers — `keyVerdict`, `partlyParsedRunOf`, `targetNotRun` — minus
 * its did-not-run-at-all case:
 *
 *   - a gap in `f`'s key (`semgrep` failed, or listed missing) → those names;
 *   - `f`'s file only partly parsed → `semgrep (partly parsed: wp/a.php)`;
 *   - a pass over another target → `trivy-image (registry/app:1)`.
 */
export function openGapFor(holder, asked, f) {
    if (isEmptyBook(asked))
        return null;
    const key = findingKey(f);
    const verdict = keyVerdict(asked, key);
    if (verdict === 'not_run')
        return null;
    if (verdict === 'unmeasured') {
        const names = gapNamesFor(asked, key);
        return names.length > 0 ? names.join(', ') : key;
    }
    const partly = partlyParsedRunOf(asked, f);
    if (partly !== null)
        return `${partly.run.name} (partly parsed: ${partly.file})`;
    return targetNotRun(holder, asked, f);
}
/**
 * Whether ANY finding of the scan `holder` describes could be left open by
 * every scan of `chain` (newer ones) — {@link openGapFor} non-null against
 * each — judged per key from the bookkeeping alone, so the open set reads an
 * older scan's findings only when one of them could be carried. Necessary,
 * not sufficient: the per-finding test still decides (a partly parsed FILE,
 * for one). A key `holder` could have produced is one of a run that did not
 * skip (a skipped run produced nothing); a scan with no bookkeeping could
 * have produced anything, and a chain scan with none measured everything.
 */
export function mayCarryPast(holder, chain) {
    if (chain.length === 0 || chain.some(isEmptyBook))
        return false;
    const measuresKeyOk = (run, key) => run.status === 'ok' && (keysOfRun(run.name, true)?.includes(key) ?? false);
    const stillOpen = (asked, key) => {
        const verdict = keyVerdict(asked, key);
        if (verdict === 'unmeasured')
            return true;
        if (verdict === 'not_run')
            return false;
        if (asked.tools_run.some((r) => measuresKeyOk(r, key) && (r.partially_parsed ?? []).length > 0))
            return true;
        return holder.tools_run.some((h) => measuresKeyOk(h, key) &&
            !asked.tools_run.some((a) => measuresKeyOk(a, key) && sameTarget(targetOf(a), targetOf(h))));
    };
    const produced = new Set();
    let unknownProducer = isEmptyBook(holder);
    if (unknownProducer)
        for (const key of KNOWN_FINDING_KEYS)
            produced.add(key);
    for (const run of holder.tools_run) {
        if (run.status === 'skipped')
            continue;
        const keys = keysOfRun(run.name, run.status === 'ok');
        if (keys === null)
            unknownProducer = true;
        else
            for (const key of keys)
                produced.add(key);
    }
    // A finding tool no name is known to measure is open wherever coverage is not full (keyVerdict).
    if (unknownProducer && chain.every((a) => computeCoverage(a.tools_run, a.missing_tools) !== 'full'))
        return true;
    for (const key of produced) {
        if (chain.every((asked) => stillOpen(asked, key)))
            return true;
    }
    return false;
}
/** `semgrep (partly parsed: a.php, b.js)` for each run that only partly parsed some files. */
function partlyParsedNames(book) {
    return book.tools_run
        .filter((run) => run.status === 'ok' && (run.partially_parsed ?? []).length > 0)
        .map((run) => `${run.name} (partly parsed: ${(run.partially_parsed ?? []).map((p) => p.file).join(', ')})`);
}
// ---------------------------------------------------------------------------
// Scans
// ---------------------------------------------------------------------------
/**
 * The type of each finding of `scan`, in the terms of an orchestrated run's
 * children (sast / secrets / deps / iac), or null when it cannot be told.
 */
function typeResolver(storage, scan) {
    if (isOrchestratedFullScan(scan)) {
        const indexed = childrenOf(storage, scan)
            .filter((c) => c.row !== null)
            .map((c) => ({ type: c.type, index: indexFindings(storage.findings.listByScan(c.row.scan_id)) }));
        return (f) => indexed.find((c) => c.index.has(f))?.type ?? null;
    }
    if (isScriptEraFullScan(scan)) {
        return (f) => {
            const slot = scriptEraSlotOfFinding(f);
            // The script's Dockerfile pass is re-run today by scan_iac's
            // `trivy config` over the whole tree, the child an orchestrated run has.
            if (slot === 'containers')
                return 'iac';
            return slot === 'security_full' ? null : slot;
        };
    }
    return () => scan.scan_type;
}
function booksOf(storage, scan) {
    if (!isOrchestratedFullScan(scan)) {
        const book = bookkeepingOf(storage, scan);
        return () => book;
    }
    const children = childrenOf(storage, scan);
    return (fType) => {
        if (fType === null)
            return scan;
        const child = children.find((c) => c.type === fType);
        return child !== undefined && usableChild(child) ? child.row : null;
    };
}
/** Every pass without a target of its own looks at the project's files. */
const PROJECT_FILES = 'project files';
function targetOf(run) {
    if (runNameEntry(run.name)?.ownTarget !== true)
        return { pass: PROJECT_FILES };
    return run.target !== undefined && run.target !== '' ? { pass: run.name, ref: normalizeImageRef(run.target) } : { pass: run.name };
}
/**
 * One image reference in the one spelling Docker resolves it to, so that
 * `nginx`, `nginx:latest` and `docker.io/library/nginx:latest` are one
 * target (fix round 1): the registry defaults to `docker.io`
 * (`index.docker.io` is the same registry), an official image on it gets
 * `library/`, and a reference with neither tag nor digest gets `:latest`.
 * The first path component is a registry only when it looks like a host
 * (a `.` or a `:` in it, or `localhost`) — Docker's own rule. Nothing else
 * is changed: `nginx:1.25` and `nginx@sha256:…` stay distinct targets.
 */
export function normalizeImageRef(ref) {
    let name = ref.trim();
    let digest = '';
    const at = name.indexOf('@');
    if (at >= 0) {
        digest = name.slice(at);
        name = name.slice(0, at);
    }
    let tag = '';
    const colon = name.lastIndexOf(':');
    if (colon > name.lastIndexOf('/')) {
        tag = name.slice(colon);
        name = name.slice(0, colon);
    }
    const slash = name.indexOf('/');
    const first = slash >= 0 ? name.slice(0, slash) : '';
    const hasRegistry = slash >= 0 && (first.includes('.') || first.includes(':') || first === 'localhost');
    let registry = hasRegistry ? first : 'docker.io';
    let path = hasRegistry ? name.slice(slash + 1) : name;
    if (registry === 'index.docker.io' || registry === 'registry-1.docker.io')
        registry = 'docker.io';
    if (registry === 'docker.io' && !path.includes('/'))
        path = `library/${path}`;
    if (tag === '' && digest === '')
        tag = ':latest';
    return `${registry}/${path}${tag}${digest}`;
}
/**
 * The same target: the same pass, and — when BOTH runs recorded which image
 * — the same image. A legacy row that did not record it keeps the reading it
 * had before references were recorded (any run of the pass), so no stored
 * comparison changes; only two references that disagree tell images apart.
 */
function sameTarget(a, b) {
    if (a.pass !== b.pass)
        return false;
    return a.ref === undefined || b.ref === undefined || a.ref === b.ref;
}
/** The name a pass that did not run again is reported under: `trivy-image (registry/app:1)`, as the run recorded it. */
function passLabel(run, target) {
    return target.ref === undefined ? run.name : `${run.name} (${run.target ?? target.ref})`;
}
/**
 * A pass `holder` ran ok that may have produced `f` (it measures `f`'s key)
 * and whose TARGET `asked` did not look at — no pass of `asked` with that
 * target ran ok measuring the key — or null.
 *
 * `f` can share its key with passes that look elsewhere: an image's
 * misconfiguration and a Dockerfile's are both `trivy:config`, and the
 * finding does not say which pass produced it. So a finding is re-measured
 * only on every target that may have produced it, in BOTH directions: a
 * Dockerfile-only scan never looked at the image, and an image-only scan
 * never looked at the Dockerfile. The second direction was missing (Task
 * 24, probe H1): an image-only run resolved the Dockerfile's
 * misconfiguration, and in regression_alert that false resolution cancelled
 * a real new high. When the holder ran both passes the finding could be
 * either's, so only a scan that looked at both re-measures it. Two images
 * are two targets (follow-up X5): an image pass re-measures only the image
 * it scanned, so image B's scan never resolves image A's findings — reported
 * as `trivy-image (<image A>)`. A scan with no bookkeeping at all measured
 * everything, as everywhere else here.
 */
function targetNotRun(holder, asked, f) {
    if (holder === null || (asked.tools_run.length === 0 && asked.missing_tools.length === 0))
        return null;
    const key = findingKey(f);
    const measuresKeyOk = (run) => run.status === 'ok' && (keysOfRun(run.name, true)?.includes(key) ?? false);
    for (const run of holder.tools_run) {
        if (!measuresKeyOk(run))
            continue;
        const target = targetOf(run);
        if (!asked.tools_run.some((r) => measuresKeyOk(r) && sameTarget(targetOf(r), target)))
            return passLabel(run, target);
    }
    return null;
}
/**
 * How `asked` answers for `f`, a finding of `holder` — `to` for a finding
 * of `from`, and the other way round — both already narrowed to `f`'s child.
 */
function answerFor(holder, asked, f) {
    if (asked === null)
        return { verdict: 'unmeasured', notRun: null };
    const verdict = bookkeepingVerdict(asked, f);
    if (verdict !== 'measured')
        return { verdict, notRun: verdict === 'not_run' ? f.tool : null };
    const pass = targetNotRun(holder, asked, f);
    return pass === null ? { verdict, notRun: null } : { verdict: 'not_run', notRun: pass };
}
/**
 * What `scan` did not measure, for a caller to name — exactly the names
 * whose findings a comparison treats as unmeasured on the side `scope`
 * says, so a reader that promises "reported as not re-measured / not
 * previously measured" keeps the promise: the whole type of an orchestrated
 * run's missing, unfinished or blind child; the scan's own type when it
 * measured nothing at all; otherwise each bookkeeping name that failed or
 * is missing (`npm`, `guardian-dast:unanswered`, `pip-audit`), and — for
 * `any` — each one skipped with no gap recorded whose findings are then not
 * re-measured (`trivy` with no Dockerfile). A pass that was merely skipped
 * beside one that ran (no uncommitted files for gitleaks' working-tree pass)
 * is neither.
 */
export function notMeasured(storage, scan, scope = 'any') {
    const out = [];
    const add = (x) => {
        if (!out.includes(x))
            out.push(x);
    };
    const gapsOf = (book, wholeType) => {
        if (computeCoverage(book.tools_run, book.missing_tools) === 'none') {
            add(wholeType);
            return;
        }
        const names = [...book.tools_run.filter((t) => t.status !== 'ok').map((t) => t.name), ...book.missing_tools];
        for (const name of names) {
            if (scope === 'gaps') {
                if (isGap(book, name))
                    add(name);
                continue;
            }
            const keys = keysOfRun(name, false);
            if (keys === null || keys.length === 0 || keys.some((k) => keyVerdict(book, k) !== 'measured'))
                add(name);
        }
        // Files a run only partly parsed are a gap on both sides (partlyParsedRunOf).
        for (const name of partlyParsedNames(book))
            add(name);
    };
    if (!isOrchestratedFullScan(scan)) {
        gapsOf(bookkeepingOf(storage, scan), scan.scan_type);
        return out;
    }
    for (const child of childrenOf(storage, scan)) {
        if (!usableChild(child))
            add(child.type);
        else
            gapsOf(child.row, child.type);
    }
    return out;
}
/**
 * A name the bookkeeping records as a gap: it failed, or is listed missing
 * without also having run ok (the retry shape, `keyVerdict`). Whatever it
 * speaks for then reads `unmeasured`, never `not_run`.
 */
function isGap(book, name) {
    const as = (status) => book.tools_run.some((t) => t.name === name && t.status === status);
    return as('failed') || (book.missing_tools.includes(name) && !as('ok'));
}
export function compareScansFor(storage, from, to) {
    const typeOfFrom = typeResolver(storage, from);
    const typeOfTo = typeResolver(storage, to);
    const fromBooks = booksOf(storage, from);
    const toBooks = booksOf(storage, to);
    /** `to`'s answer for a finding of `from`. */
    const inTo = (f) => {
        const t = typeOfFrom(f);
        return answerFor(fromBooks(t), toBooks(t), f);
    };
    /** `from`'s answer for a finding of `to`. */
    const inFrom = (f) => {
        const t = typeOfTo(f);
        return answerFor(toBooks(t), fromBooks(t), f);
    };
    return {
        // Anything short of measured: the newer scan cannot resolve what it did
        // not look for, whether the scanner failed or did not run.
        isNotRemeasured: (f) => inTo(f).verdict !== 'measured',
        // Only a gap: a reference that did not run the scanner at all looked at
        // everything it had to, and the finding is new.
        isNotPreviouslyMeasured: (f) => inFrom(f).verdict === 'unmeasured',
        notRunByTo: (f) => inTo(f).notRun,
        notRunByFrom: (f) => inFrom(f).notRun,
        notMeasuredByTo: notMeasured(storage, to, 'any'),
        gapsByTo: notMeasured(storage, to, 'gaps'),
        notMeasuredByFrom: notMeasured(storage, from, 'gaps'),
    };
}
/**
 * Classifies two scans' findings. Matching is by identity with the
 * fingerprint as the fallback (`indexFindings`); a finding present on both
 * sides is unchanged whatever the bookkeeping says.
 */
export function classifyDiff(check, fromFindings, toFindings) {
    const fromIndex = indexFindings(fromFindings);
    const toIndex = indexFindings(toFindings);
    const out = {
        new: [],
        resolved: [],
        unchanged: [],
        notRemeasured: [],
        notPreviouslyMeasured: [],
        notRunByTo: [],
        notRunByFrom: [],
    };
    const note = (list, name) => {
        if (name !== null && !list.includes(name))
            list.push(name);
    };
    for (const f of toFindings) {
        if (fromIndex.has(f))
            out.unchanged.push(f);
        else if (check.isNotPreviouslyMeasured(f))
            out.notPreviouslyMeasured.push(f);
        else {
            out.new.push(f);
            note(out.notRunByFrom, check.notRunByFrom(f));
        }
    }
    for (const f of fromFindings) {
        if (toIndex.has(f))
            continue;
        if (check.isNotRemeasured(f)) {
            out.notRemeasured.push(f);
            note(out.notRunByTo, check.notRunByTo(f));
        }
        else
            out.resolved.push(f);
    }
    return out;
}
export function measurementGaps(check, d) {
    const byTo = [...check.notMeasuredByTo, ...d.notRunByTo.filter((x) => !check.notMeasuredByTo.includes(x))];
    return {
        byTo,
        notRunByTo: byTo.filter((x) => !check.gapsByTo.includes(x)),
        byFrom: check.notMeasuredByFrom,
        notRunByFrom: d.notRunByFrom.filter((x) => !check.notMeasuredByFrom.includes(x)),
    };
}
/**
 * A human line for a response, or null when both scans measured everything
 * they ran. A scanner that failed is one to fix; one that did not run is not
 * — it was not requested, or had nothing to scan — so the two are worded
 * apart, and neither tells the reader to wait for a scanner that works.
 */
export function describeMeasurementGaps(from, to, gaps) {
    const parts = [];
    const failedByTo = gaps.byTo.filter((x) => !gaps.notRunByTo.includes(x));
    if (failedByTo.length > 0) {
        parts.push(`Scan ${to.scan_id} did not measure ${failedByTo.join(', ')} (it failed, or is not installed): ` +
            'earlier findings from it are reported as not re-measured, never as resolved — re-run once the scanner works.');
    }
    if (gaps.notRunByTo.length > 0) {
        parts.push(`Scan ${to.scan_id} did not run ${gaps.notRunByTo.join(', ')} (not requested, or nothing for it to scan): ` +
            'earlier findings from it are reported as not re-measured, never as resolved — run it again to re-measure them.');
    }
    if (gaps.byFrom.length > 0) {
        parts.push(`The reference scan ${from.scan_id} did not measure ${gaps.byFrom.join(', ')} (it failed, or was not ` +
            'installed): findings from it are reported as not previously measured, never as new.');
    }
    if (gaps.notRunByFrom.length > 0) {
        parts.push(`The reference scan ${from.scan_id} did not run ${gaps.notRunByFrom.join(', ')} (not applicable, or not ` +
            'requested, then): findings from it are new.');
    }
    return parts.length > 0 ? parts.join(' ') : null;
}
//# sourceMappingURL=runCompare.js.map