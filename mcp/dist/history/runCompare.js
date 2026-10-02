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
import { join } from 'node:path';
import { indexFindings } from '../fingerprint/findingIdentity.js';
import { PLUGIN_PACK_FILES } from '../runners/semgrepConfigs.js';
import { FIXPOINT_TIMEOUT_PACK_TYPE } from '../runners/semgrepReport.js';
import { pluginPacksDir, ruleIdsInFile } from '../runners/semgrepRuleIds.js';
import { computeCoverage } from '../tools/scanCoverage.js';
import { KNOWN_FINDING_KEYS, findingKey, keysOfRun, runNameEntry } from './runNames.js';
import { isOrchestratedFullScan, isScriptEraFullScan, sameImportSlot, scriptEraSlotOfFinding } from './scanRoles.js';
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
/** A finding's file as the partial-parse lists name it: `/`-separated. */
function fileOf(f) {
    return f.file_path === undefined ? undefined : f.file_path.replace(/\\/g, '/');
}
/** Whether `run` ran ok and speaks for `key` — the one test every target and gap check below uses. */
function measuresKeyOk(run, key) {
    return run.status === 'ok' && (keysOfRun(run.name, true)?.includes(key) ?? false);
}
/**
 * Whether a partial-parse entry is the plugin's LLM pack's own taint timeout
 * (`runners/semgrepReport.ts#withPluginPackFixpoint`). It is the PACK's gap:
 * a finding in that file is left unmeasured only when it is one of the
 * pack's own rules ({@link isPluginPackRule}). Read as the run's gap, a
 * registry finding fixed in such a file stayed open as "not re-measured".
 */
function isPluginPackGap(pp) {
    return pp.type === FIXPOINT_TIMEOUT_PACK_TYPE;
}
let packRuleIds;
/**
 * The rule ids the plugin's packs declare (`configs/semgrep/llm.yml`, `web-js.yml`),
 * as its findings are stored — the pack rule's own id (`localRuleIds.ts`).
 * Read once. A project-root rule carrying the same id is stored the same
 * way and is read as the pack's: that can only keep one of its findings
 * open, never close one.
 */
function pluginPackRuleIds() {
    packRuleIds ??= new Set(PLUGIN_PACK_FILES.flatMap((file) => ruleIdsInFile(join(pluginPacksDir(), file))));
    return packRuleIds;
}
function isPluginPackRule(ruleId) {
    return ruleId !== undefined && pluginPackRuleIds().has(ruleId);
}
/**
 * The narrower gaps INSIDE an ok run that measures `key`: files it could
 * only partly parse (`ToolRun.partially_parsed`, the shared Semgrep judge's
 * `partial` verdict) and rules that did not load (`ToolRun.failed_rules`,
 * bug_hunt's broken-rule shape). The rest of that run measured — `ok` AND
 * missing, the retry shape `keyVerdict` reads as measured — but a finding in
 * one of those files, or of one of those rules, was not looked for. A file
 * of the plugin pack's own gap ({@link isPluginPackGap}) is a gap only for
 * the pack's rules: (file, pack rule) pairs.
 */
function narrowGapsOf(book, key) {
    const files = new Set();
    const rules = new Set();
    const pairs = new Map();
    for (const run of book.tools_run) {
        if (!measuresKeyOk(run, key))
            continue;
        for (const pp of run.partially_parsed ?? []) {
            if (isPluginPackGap(pp))
                pairs.set(pp.file, pluginPackRuleIds());
            else
                files.add(pp.file);
        }
        for (const fr of run.failed_rules ?? [])
            rules.add(fr.rule_id);
    }
    for (const f of files)
        pairs.delete(f);
    return { files, rules, pairs };
}
/**
 * The run measuring `f`'s key that left `f` out — its file only partly
 * parsed (by the pack, for a pack rule's finding), or its rule not loaded —
 * with the label a reader is given, or null.
 */
function narrowGapOf(book, f) {
    const key = findingKey(f);
    const file = fileOf(f);
    for (const run of book.tools_run) {
        if (!measuresKeyOk(run, key))
            continue;
        const entries = file === undefined ? [] : (run.partially_parsed ?? []).filter((pp) => pp.file === file);
        if (entries.some((pp) => !isPluginPackGap(pp))) {
            return { run, label: `${run.name} (partly parsed: ${file})` };
        }
        if (entries.length > 0 && isPluginPackRule(f.rule_id)) {
            return { run, label: `${run.name} (LLM pack partly measured: ${file})` };
        }
        if (f.rule_id !== undefined && (run.failed_rules ?? []).some((fr) => fr.rule_id === f.rule_id)) {
            return { run, label: `${run.name} (rule not loaded: ${f.rule_id})` };
        }
    }
    return null;
}
/**
 * How `book` answers for `f`, its scanner's verdict narrowed to the finding:
 * `unmeasured` also when the run that measured the key could only partly
 * parse `f`'s file, or did not load `f`'s rule.
 */
function bookkeepingVerdict(book, f) {
    if (isEmptyBook(book))
        return 'measured';
    const verdict = keyVerdict(book, findingKey(f));
    return verdict === 'measured' && narrowGapOf(book, f) !== null ? 'unmeasured' : verdict;
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
 * An ok pass of `holder` that runs only when it is asked for
 * (`runNames.ts` `onRequest`: `trivy-image` needs an image, nuclei must be
 * requested) and speaks for `key`, as its label — or null. A newer scan
 * that did not run such a pass at all did not look: the finding stays open.
 * A pass that runs whenever there is something for it (Bandit, when there
 * is Python) is not one: its absence says the target went away.
 */
function onRequestPassOf(holder, key) {
    const run = holder.tools_run.find((r) => measuresKeyOk(r, key) && runNameEntry(r.name)?.onRequest === true);
    return run === undefined ? null : passLabel(run, targetOf(run));
}
/**
 * The open set's question (`openSet.ts`): does `asked`, a NEWER scan of the
 * same slot, leave `f` — a finding of the older scan `holder` describes —
 * still open? Returns the name of the gap, or null when `asked` re-measured
 * `f` (and did not find it: resolved) or did not run `f`'s scanner at all
 * with no gap recorded (not applicable: a Python-free project's Bandit).
 *
 * It CALLS the verdict every comparison uses — {@link answerFor}, through
 * `bookkeepingVerdict` and `targetNotRun` — so the open set and
 * `compareScansFor`'s "not re-measured" cannot drift apart. The one reading
 * it adds: a `not_run` of a pass that runs only on request (an image, nuclei)
 * is still a gap — the newer scan did not ask, so it did not look.
 *
 *   - a gap in `f`'s key (`semgrep` failed, or listed missing) → those names;
 *   - `f`'s file only partly parsed → `semgrep (partly parsed: wp/a.php)`;
 *   - `f`'s rule not loaded → `semgrep (rule not loaded: <rule id>)`;
 *   - a pass over another target, or one not requested this time →
 *     `trivy-image (registry/app:1)`, `nuclei`.
 */
export function openGapFor(holder, asked, f) {
    const answer = answerFor(holder, asked, f);
    if (answer.verdict === 'measured')
        return null;
    if (answer.verdict === 'unmeasured') {
        const narrow = narrowGapOf(asked, f);
        if (narrow !== null)
            return narrow.label;
        const key = findingKey(f);
        const names = gapNamesFor(asked, key);
        return names.length > 0 ? names.join(', ') : key;
    }
    if (answer.byTarget)
        return answer.notRun;
    return onRequestPassOf(holder, findingKey(f));
}
const NO_PAIRS = new Map();
const ADMIT_ALL = { all: true };
const NEVER_SCOPE = { kind: 'never' };
/** The most (file, rule) pairs an {@link Admit} holds before it widens to the constraint itself (sound: a superset). */
export const MAX_ADMIT_PAIRS = 10_000;
function onlyConstraint(c) {
    const pairs = new Map();
    for (const [f, rs] of c.pairs ?? NO_PAIRS)
        if (!c.files.has(f))
            pairs.set(f, new Set(rs));
    return { all: false, files: new Set(c.files), rules: new Set(c.rules), pairs };
}
export function meetAdmit(s, c) {
    if (s.all)
        return onlyConstraint(c);
    const cPairs = c.pairs ?? NO_PAIRS;
    const files = new Set([...s.files].filter((f) => c.files.has(f)));
    const rules = new Set([...s.rules].filter((r) => c.rules.has(r)));
    // Before building any pair: how many could this meet make? Past the bound,
    // the constraint alone — a superset of the exact meet (see `Admit`).
    let bound = 0;
    for (const rs of s.pairs.values())
        bound += rs.size;
    let filesLeaving = 0;
    for (const f of s.files) {
        if (c.files.has(f))
            continue;
        filesLeaving += 1;
        bound += cPairs.get(f)?.size ?? 0;
    }
    let rulesLeaving = 0;
    for (const r of s.rules)
        if (!c.rules.has(r))
            rulesLeaving += 1;
    let cPairCount = 0;
    if (rulesLeaving > 0)
        for (const rs of cPairs.values())
            cPairCount += rs.size;
    bound += filesLeaving * c.rules.size + rulesLeaving * c.files.size + cPairCount;
    if (bound > MAX_ADMIT_PAIRS)
        return onlyConstraint(c);
    const pairs = new Map();
    const add = (f, r) => {
        if (files.has(f) || rules.has(r))
            return;
        let set = pairs.get(f);
        if (set === undefined) {
            set = new Set();
            pairs.set(f, set);
        }
        set.add(r);
    };
    const inCPairs = (f, r) => cPairs.get(f)?.has(r) ?? false;
    for (const [f, rs] of s.pairs)
        for (const r of rs)
            if (c.files.has(f) || c.rules.has(r) || inCPairs(f, r))
                add(f, r);
    for (const f of s.files) {
        if (c.files.has(f))
            continue;
        for (const r of c.rules)
            add(f, r);
        for (const r of cPairs.get(f) ?? [])
            add(f, r);
    }
    for (const r of s.rules) {
        if (c.rules.has(r))
            continue;
        for (const f of c.files)
            add(f, r);
        for (const [f, rs] of cPairs)
            if (rs.has(r))
                add(f, r);
    }
    return { all: false, files, rules, pairs };
}
function admitsNothing(s) {
    return !s.all && s.files.size === 0 && s.rules.size === 0 && s.pairs.size === 0;
}
/** Whether a finding in `file` of `rule` is inside `scope`. */
export function scopeAdmits(scope, file, rule) {
    if (scope.kind === 'never')
        return false;
    const a = scope.admit;
    if (a.all)
        return true;
    if (file !== undefined && a.files.has(file))
        return true;
    if (rule !== undefined && a.rules.has(rule))
        return true;
    return file !== undefined && rule !== undefined && (a.pairs.get(file)?.has(rule) ?? false);
}
/** The files and rules a finding admitted by `admit` can have — what the carry reads rows by. */
export function admitLookup(admit) {
    const files = new Set(admit.files);
    const rules = new Set(admit.rules);
    for (const [f, rs] of admit.pairs) {
        files.add(f);
        for (const r of rs)
            rules.add(r);
    }
    return { files: [...files], rules: [...rules] };
}
const NO_INDEXES = [];
function pushTo(map, key, i) {
    const list = map.get(key);
    if (list === undefined)
        map.set(key, [i]);
    else
        list.push(i);
}
function coversTarget(c, t) {
    if (t.pass === PROJECT_FILES)
        return c.project;
    if (t.ref === undefined)
        return c.any.has(t.pass);
    return c.legacy.has(t.pass) || c.images.has(`${t.pass}\0${t.ref}`);
}
/**
 * The chain of newer scans the open set's carry-forward walks back past,
 * indexed per key so that a holder's scope is read in time linear in the
 * scans that could change it — never by re-folding the whole chain per
 * holder, which was quadratic whenever holders differed (fix round 3, I-1:
 * 2000 image scans each over its own image, 21 s).
 *
 * For one key a holder is its {@link HolderClass}; two holders of one class
 * get one scope, folded once and carried on as the chain grows. A scope is
 * `never` once the chain holds a scan with no bookkeeping, a `not_run` (for
 * a holder without an on-request pass), or a `measured` scan that looked at
 * every one of the holder's targets and has no narrower gap; else it is the
 * {@link Admit} of the narrower gaps of the `measured` scans that did look
 * at them all. Those scans are found through the class's rarest target —
 * the scans that looked at its image, else its image pass, else the
 * project's files — so a holder whose image no newer scan looked at costs
 * nothing, however long the chain. The carry-predicate property test holds
 * {@link scopeAdmits} over this equal to {@link openGapFor} against every
 * scan of the chain, for one holder and for a growing chain shared by many.
 */
export class ChainIndex {
    chain = [];
    byKey = new Map();
    push(book) {
        this.chain.push(book);
    }
    get length() {
        return this.chain.length;
    }
    /** The chain's `i`-th scan, newest first. */
    bookAt(i) {
        return this.chain[i];
    }
    /** `holder` for one key, as {@link scopeOfClass} takes it. */
    classOf(holder, key) {
        const onRequest = onRequestPassOf(holder, key) !== null;
        const seen = new Map();
        for (const run of holder.tools_run) {
            if (!measuresKeyOk(run, key))
                continue;
            const t = targetOf(run);
            seen.set(`${t.pass}\0${t.ref ?? ''}\0${t.ref === undefined ? 'legacy' : 'ref'}`, t);
        }
        const targets = [...seen.values()];
        const signature = JSON.stringify([onRequest, [...seen.keys()].sort()]);
        return { signature, onRequest, targets };
    }
    /** {@link ChainScope} of `holder`'s findings under `key`, over the chain as it is now. */
    scope(holder, key) {
        return this.scopeOfClass(this.classOf(holder, key), key);
    }
    scopeOfClass(cls, key) {
        const idx = this.indexed(key);
        const L = this.chain.length;
        if (idx.firstEmpty < L || (!cls.onRequest && idx.firstNotRun < L))
            return NEVER_SCOPE;
        let state = idx.classes.get(cls.signature);
        if (state === undefined) {
            state = { admit: ADMIT_ALL, met: new Set(), closed: false, a: 0, b: 0, snapshot: null };
            idx.classes.set(cls.signature, state);
        }
        this.advance(idx, cls, state, L);
        if (state.closed)
            return NEVER_SCOPE;
        if (state.snapshot === null)
            state.snapshot = { kind: 'open', admit: state.admit };
        return state.snapshot;
    }
    /** The class's driver: one or two ascending lists that hold every scan able to look at all its targets. */
    driverOf(idx, cls) {
        const image = cls.targets.find((t) => t.pass !== PROJECT_FILES && t.ref !== undefined);
        if (image !== undefined) {
            return [idx.byImage.get(`${image.pass}\0${image.ref ?? ''}`) ?? NO_INDEXES, idx.legacy.get(image.pass) ?? NO_INDEXES];
        }
        const legacyImage = cls.targets.find((t) => t.pass !== PROJECT_FILES);
        if (legacyImage !== undefined)
            return [idx.anyOf.get(legacyImage.pass) ?? NO_INDEXES, NO_INDEXES];
        if (cls.targets.length > 0)
            return [idx.project, NO_INDEXES];
        return [idx.measured, NO_INDEXES];
    }
    advance(idx, cls, state, L) {
        while (!state.closed) {
            const [listA, listB] = this.driverOf(idx, cls);
            const ia = listA[state.a];
            const ib = listB[state.b];
            const na = ia !== undefined && ia < L ? ia : undefined;
            const nb = ib !== undefined && ib < L ? ib : undefined;
            if (na === undefined && nb === undefined)
                return;
            const i = na === undefined ? (nb ?? 0) : nb === undefined ? na : Math.min(na, nb);
            if (na === i)
                state.a += 1;
            if (nb === i)
                state.b += 1;
            const c = idx.at.get(i);
            if (c === undefined || !cls.targets.every((t) => coversTarget(c, t)))
                continue;
            state.snapshot = null;
            if (c.narrow === null) {
                state.closed = true;
                return;
            }
            // Met already: the set lies inside it, meeting it again changes nothing.
            if (state.met.has(c.narrowSig))
                continue;
            state.met.add(c.narrowSig);
            state.admit = meetAdmit(state.admit, c.narrow);
            if (admitsNothing(state.admit))
                state.closed = true;
        }
    }
    /** The key's index, caught up with the chain. */
    indexed(key) {
        let idx = this.byKey.get(key);
        if (idx === undefined) {
            idx = {
                len: 0,
                firstEmpty: Infinity,
                firstNotRun: Infinity,
                at: new Map(),
                measured: [],
                project: [],
                byImage: new Map(),
                legacy: new Map(),
                anyOf: new Map(),
                classes: new Map(),
            };
            this.byKey.set(key, idx);
        }
        for (; idx.len < this.chain.length; idx.len += 1) {
            const i = idx.len;
            const asked = this.chain[i];
            if (asked === undefined)
                break;
            if (isEmptyBook(asked)) {
                idx.firstEmpty = Math.min(idx.firstEmpty, i);
                continue;
            }
            const verdict = keyVerdict(asked, key);
            if (verdict === 'unmeasured')
                continue;
            if (verdict === 'not_run') {
                idx.firstNotRun = Math.min(idx.firstNotRun, i);
                continue;
            }
            const c = { project: false, images: new Set(), legacy: new Set(), any: new Set(), narrow: null, narrowSig: '' };
            for (const run of asked.tools_run) {
                if (!measuresKeyOk(run, key))
                    continue;
                const t = targetOf(run);
                if (t.pass === PROJECT_FILES) {
                    c.project = true;
                    continue;
                }
                c.any.add(t.pass);
                if (t.ref === undefined)
                    c.legacy.add(t.pass);
                else
                    c.images.add(`${t.pass}\0${t.ref}`);
            }
            const narrow = narrowGapsOf(asked, key);
            if (narrow.files.size > 0 || narrow.rules.size > 0 || narrow.pairs.size > 0) {
                c.narrow = narrow;
                // The pack's pairs are spelled by file: their rules are the pack's, always the same set.
                c.narrowSig = JSON.stringify([[...narrow.files].sort(), [...narrow.rules].sort(), [...narrow.pairs.keys()].sort()]);
            }
            idx.at.set(i, c);
            idx.measured.push(i);
            if (c.project)
                idx.project.push(i);
            for (const img of c.images)
                pushTo(idx.byImage, img, i);
            for (const pass of c.legacy)
                pushTo(idx.legacy, pass, i);
            for (const pass of c.any)
                pushTo(idx.anyOf, pass, i);
        }
        return idx;
    }
}
/** {@link ChainIndex} over a fixed chain, for one holder and key. */
export function chainScope(holder, chain, key) {
    const index = new ChainIndex();
    for (const book of chain)
        index.push(book);
    return index.scope(holder, key);
}
/** A key no bookkeeping name measures — a finding tool the table does not know. */
export const UNKNOWN_FINDING_KEY = '\0unknown';
/**
 * Every key a finding of the scan `holder` describes could have: one of a
 * run that did not skip (a skipped run produced nothing), and
 * {@link UNKNOWN_FINDING_KEY} when a run's name is not in the table. A scan
 * with no bookkeeping at all could have produced anything.
 */
export function producedKeys(holder) {
    const keys = new Set();
    if (isEmptyBook(holder)) {
        for (const key of KNOWN_FINDING_KEYS)
            keys.add(key);
        keys.add(UNKNOWN_FINDING_KEY);
    }
    for (const run of holder.tools_run) {
        if (run.status === 'skipped')
            continue;
        const k = keysOfRun(run.name, run.status === 'ok');
        if (k === null)
            keys.add(UNKNOWN_FINDING_KEY);
        else
            for (const key of k)
                keys.add(key);
    }
    return [...keys];
}
/**
 * Whether any scan OLDER than the chain could still have a finding every
 * scan of it leaves open, whatever that scan ran: {@link ChainIndex}'s
 * scope for the widest holder the slot's history allows — every pass name
 * the slot's scans ever recorded (`names`), each ok, each over a target no
 * scan recorded — over every key it could produce. When even that holder
 * has nothing left open the carry-forward walk stops. `anyEmpty`: some scan
 * of the slot has no bookkeeping, and could have produced anything.
 */
export class StillCarry {
    index;
    classes;
    /** How much of the chain `check` has looked at for an empty book. */
    seen = 0;
    sawEmpty = false;
    constructor(index, names, anyEmpty) {
        this.index = index;
        const widest = {
            tools_run: names.map((name) => ({ name, status: 'ok', target: '\0any image no scan recorded' })),
            missing_tools: [],
        };
        const keys = new Set(producedKeys(widest));
        if (anyEmpty) {
            for (const key of KNOWN_FINDING_KEYS)
                keys.add(key);
            keys.add(UNKNOWN_FINDING_KEY);
        }
        this.classes = [...keys].map((key) => ({ key, cls: index.classOf(widest, key) }));
    }
    check() {
        if (this.index.length === 0)
            return true;
        // A scan with no bookkeeping measured everything: nothing older is carried past it.
        for (; this.seen < this.index.length && !this.sawEmpty; this.seen += 1) {
            const book = this.index.bookAt(this.seen);
            if (book !== undefined && isEmptyBook(book))
                this.sawEmpty = true;
        }
        if (this.sawEmpty)
            return false;
        return this.classes.some(({ key, cls }) => this.index.scopeOfClass(cls, key).kind !== 'never');
    }
}
/** Whether a gap name is a narrower gap inside a run that measured ({@link narrowGapNames}). */
function isNarrowGapName(name) {
    return / \((partly parsed|rules not loaded|LLM pack partly measured): /.test(name);
}
/** How many files a run's narrower-gap name lists before "+N more" ({@link narrowGapNames}). */
const NARROW_GAP_FILES_NAMED = 5;
/**
 * `semgrep (partly parsed: a.php, b.js)` / `(rules not loaded: …)` for each
 * run with a narrower gap. The files are named once each and only the first
 * few, then counted (`+N more`): a loaded scan's taint fixpoint timeouts put
 * hundreds of files there (`runners/semgrepReport.ts`). Only a label — which
 * finding is not re-measured is decided from `partially_parsed` itself.
 */
function narrowGapNames(book) {
    const names = [];
    const named = (files) => {
        const more = files.length - NARROW_GAP_FILES_NAMED;
        return [...files.slice(0, NARROW_GAP_FILES_NAMED), ...(more > 0 ? [`+${more} more`] : [])].join(', ');
    };
    for (const run of book.tools_run) {
        if (run.status !== 'ok')
            continue;
        const entries = run.partially_parsed ?? [];
        const parsed = [...new Set(entries.filter((pp) => !isPluginPackGap(pp)).map((pp) => pp.file))];
        // The plugin pack's own gap, named as the pack's: only its rules' findings there were left unmeasured.
        const byPack = [...new Set(entries.filter(isPluginPackGap).map((pp) => pp.file))].filter((f) => !parsed.includes(f));
        const failed = run.failed_rules ?? [];
        if (parsed.length > 0)
            names.push(`${run.name} (partly parsed: ${named(parsed)})`);
        if (byPack.length > 0)
            names.push(`${run.name} (LLM pack partly measured: ${named(byPack)})`);
        if (failed.length > 0)
            names.push(`${run.name} (rules not loaded: ${failed.map((fr) => fr.rule_id).join(', ')})`);
    }
    return names;
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
    if (run.target === undefined || run.target === '')
        return { pass: run.name };
    // A verification's target is the image AND the signer it was verified
    // against (`ToolRun.signer`): a pass for another signer did not ask the
    // question the older verdict answered.
    const signer = run.signer !== undefined ? `\0signer\0${run.signer}` : '';
    return { pass: run.name, ref: `${normalizeImageRef(run.target)}${signer}` };
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
    if (target.ref === undefined)
        return run.name;
    const signer = run.signer !== undefined ? `, signer ${run.signer}` : '';
    return `${run.name} (${run.target ?? target.ref}${signer})`;
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
    return holder === null ? null : targetNotRunForKey(holder, asked, findingKey(f));
}
/** {@link targetNotRun} for every finding under `key` — it depends on nothing else. */
function targetNotRunForKey(holder, asked, key) {
    if (isEmptyBook(asked))
        return null;
    for (const run of holder.tools_run) {
        if (!measuresKeyOk(run, key))
            continue;
        const target = targetOf(run);
        if (!asked.tools_run.some((r) => measuresKeyOk(r, key) && sameTarget(targetOf(r), target)))
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
        return { verdict: 'unmeasured', notRun: null, byTarget: false };
    const verdict = bookkeepingVerdict(asked, f);
    if (verdict !== 'measured')
        return { verdict, notRun: verdict === 'not_run' ? f.tool : null, byTarget: false };
    const pass = targetNotRun(holder, asked, f);
    return pass === null ? { verdict, notRun: null, byTarget: false } : { verdict: 'not_run', notRun: pass, byTarget: true };
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
        // Files a run only partly parsed, rules it did not load: a gap on both sides (narrowGapOf).
        for (const name of narrowGapNames(book))
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
    // An import's findings are named by the tool that wrote the log, which no
    // bookkeeping name knows: "no gap anywhere" would let ANY full scan resolve
    // them. Only an import of the same source tool measures them (and an import
    // measures nothing a native scan found).
    const crossSlot = !sameImportSlot(from, to);
    const notLookedAt = (f) => ({ verdict: 'not_run', notRun: f.tool, byTarget: false });
    /** `to`'s answer for a finding of `from`. */
    const inTo = (f) => {
        if (crossSlot)
            return notLookedAt(f);
        const t = typeOfFrom(f);
        return answerFor(fromBooks(t), toBooks(t), f);
    };
    /** `from`'s answer for a finding of `to`. */
    const inFrom = (f) => {
        if (crossSlot)
            return notLookedAt(f);
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
    // A run that measured, with files it only partly parsed or rules that did
    // not load (`narrowGapNames`), neither failed nor is missing: said so.
    const narrowByTo = failedByTo.filter(isNarrowGapName);
    const brokenByTo = failedByTo.filter((x) => !isNarrowGapName(x));
    if (brokenByTo.length > 0) {
        parts.push(`Scan ${to.scan_id} did not measure ${brokenByTo.join(', ')} (it failed, or is not installed): ` +
            'earlier findings from it are reported as not re-measured, never as resolved — re-run once the scanner works.');
    }
    if (narrowByTo.length > 0) {
        parts.push(`Scan ${to.scan_id} only partly measured ${narrowByTo.join(', ')}: earlier findings in those files, or of those ` +
            'rules, are reported as not re-measured, never as resolved — they are measured again once a run reads the ' +
            "whole file (Semgrep's parser cannot always, even on valid code) and loads the rule.");
    }
    if (gaps.notRunByTo.length > 0) {
        parts.push(`Scan ${to.scan_id} did not run ${gaps.notRunByTo.join(', ')} (not requested, or nothing for it to scan): ` +
            'earlier findings from it are reported as not re-measured, never as resolved — run it again to re-measure them.');
    }
    const narrowByFrom = gaps.byFrom.filter(isNarrowGapName);
    const brokenByFrom = gaps.byFrom.filter((x) => !isNarrowGapName(x));
    if (brokenByFrom.length > 0) {
        parts.push(`The reference scan ${from.scan_id} did not measure ${brokenByFrom.join(', ')} (it failed, or was not ` +
            'installed): findings from it are reported as not previously measured, never as new.');
    }
    if (narrowByFrom.length > 0) {
        parts.push(`The reference scan ${from.scan_id} only partly measured ${narrowByFrom.join(', ')}: findings in those files, ` +
            'or of those rules, are reported as not previously measured, never as new.');
    }
    if (gaps.notRunByFrom.length > 0) {
        parts.push(`The reference scan ${from.scan_id} did not run ${gaps.notRunByFrom.join(', ')} (not applicable, or not ` +
            'requested, then): findings from it are new.');
    }
    return parts.length > 0 ? parts.join(' ') : null;
}
//# sourceMappingURL=runCompare.js.map