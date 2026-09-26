/**
 * The one place a raw secret value is read from disk — for
 * `scan_secrets verify_live`, and only there.
 *
 * Every other gitleaks run in this codebase uses `--redact`, and the parser
 * strips `Match`/`Secret` besides. Verification needs the value itself, so a
 * verifying run omits `--redact` — but ONLY into a report file inside a
 * private directory made for that one scan:
 *
 *   - `mkdtemp` under the OS temp directory; on POSIX the directory is 0700
 *     and each report file is created 0600 BEFORE gitleaks writes it (gitleaks
 *     truncates an existing file and keeps its mode). On Windows the
 *     per-user temp directory (`%LOCALAPPDATA%\Temp`) is the protection: its
 *     ACL admits only the user, SYSTEM and Administrators, and POSIX mode
 *     bits mean nothing there.
 *   - Each raw report is read once, by {@link sanitizeGitleaksReport}, and
 *     deleted straight after; the directory is removed when the scan's
 *     gitleaks passes are done (`runners/gitleaksScan.ts`, in `finally`).
 *     A directory a killed process left behind is swept by the next one
 *     ({@link sweepStaleReportDirs}).
 *   - What the rest of the scan sees — the parser input, the report kept
 *     under `.guardian/reports` — is the sanitized text: each value replaced
 *     by `REDACTED` in the fields that CARRY values, as `--redact` does, and
 *     every other field byte-identical. Only the values of rules
 *     `verify_live` can check survive, in memory, aligned with the report's
 *     items.
 *
 * ---- Which fields, and against which values ------------------------------
 *
 * gitleaks' own `Finding.Redact` rewrites `Line` (never serialized), `Match`
 * and `Secret`, each with that finding's OWN value. The locator fields —
 * `RuleID`, `Description`, `File`, `SymlinkFile`, `Commit`, `Fingerprint`,
 * the positions, `Author`/`Email`/`Date` — are never touched: they are what
 * the finding's path, fingerprint and identity are made of. The first
 * version scrubbed every string of every item against every value, which was
 * both quadratic (6000 items: 66 s, with the MCP server frozen) and wrong: a
 * custom rule reporting `Secret: "test"` turned `test/fixtures/fake.env` into
 * `REDACTED/fixtures/fake.env`, moving the finding and slipping it past
 * `.guardianignore`.
 *
 * So, per item:
 *
 *   - `Secret` → `REDACTED`.
 *   - `Match` → its own value, and the value of every finding whose span
 *     overlaps it, directly or through a chain of overlapping spans (same
 *     file and commit) → `REDACTED`. Another finding's value can only be
 *     inside a match that overlaps it. A sort + sweep merges the spans into
 *     runs that overlap, and each match is scrubbed of its run's values in
 *     ONE pass over it (`makeScrubber`): scrubbed value by value, 4000
 *     findings overlapping one region took 5.9 s — the count squared. A run
 *     of one value (most runs: a finding that overlaps nothing) is a native
 *     search; only several distinct values build a matcher, and each run's
 *     matches are scrubbed as it closes, so nothing per run outlives it.
 *     Overlapping occurrences — of two values, or of one value with itself —
 *     become one `REDACTED`, so no fragment survives. A match whose group
 *     has an item with no position cannot be placed and is withheld whole,
 *     as is the match of an item with no value.
 *   - `Message` (the commit message, which gitleaks does not redact) and
 *     `Tags` → the values found in that commit / that item → `REDACTED`.
 *   - `Line` and `Fragment`, should a gitleaks version serialize them (the
 *     whole source line / file) → withheld whole.
 */
import { chmodSync, closeSync, lstatSync, mkdtempSync, openSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
/** What gitleaks `--redact` writes in place of a value. */
export const REDACTED = 'REDACTED';
/** A `guardian-verify-*` directory untouched this long belongs to a scan that died. */
export const STALE_AFTER_MS = 6 * 60 * 60 * 1000;
const PREFIX = 'guardian-verify-';
const POSIX = process.platform !== 'win32';
/** See the module comment. Throws when no private directory can be made — the caller then does not capture. */
export function openPrivateReportDir() {
    sweepStaleReportDirs();
    const dir = mkdtempSync(join(tmpdir(), PREFIX));
    // mkdtemp already creates 0700 on POSIX; stated, not assumed.
    if (POSIX)
        chmodSync(dir, 0o700);
    return {
        dir,
        pathFor(name) {
            const path = join(dir, name);
            closeSync(openSync(path, 'w', 0o600));
            if (POSIX)
                chmodSync(path, 0o600);
            return path;
        },
        remove() {
            try {
                rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
                return null;
            }
            catch (e) {
                const code = typeof e === 'object' && e !== null ? e.code : undefined;
                return typeof code === 'string' ? code : 'unknown error';
            }
        },
    };
}
/**
 * Remove the `guardian-verify-*` directories a killed scan left in `root`: a
 * real directory (never a symlink or junction), owned by this user on POSIX,
 * untouched for {@link STALE_AFTER_MS}. Never throws; returns how many went.
 */
export function sweepStaleReportDirs(root = tmpdir(), now = Date.now()) {
    let names;
    try {
        names = readdirSync(root);
    }
    catch {
        return 0;
    }
    const uid = POSIX && typeof process.getuid === 'function' ? process.getuid() : null;
    let removed = 0;
    for (const name of names) {
        if (!name.startsWith(PREFIX))
            continue;
        try {
            const path = join(root, name);
            const st = lstatSync(path);
            if (st.isSymbolicLink() || !st.isDirectory())
                continue;
            if (uid !== null && st.uid !== uid)
                continue;
            if (now - st.mtimeMs < STALE_AFTER_MS)
                continue;
            rmSync(path, { recursive: true, force: true });
            removed += 1;
        }
        catch {
            // Someone else's, in use, or gone already: not this sweep's business.
        }
    }
    return removed;
}
/**
 * Split an unredacted gitleaks report into its sanitized text and the raw
 * values of the rules `keep` accepts — see the module comment for what is
 * redacted where. Null when the text is not a JSON array: it is then never
 * passed on or written anywhere, since it may hold raw values in a shape this
 * cannot clean.
 */
export function sanitizeGitleaksReport(text, keep) {
    let root;
    try {
        root = JSON.parse(text);
    }
    catch {
        return null;
    }
    if (!Array.isArray(root))
        return null;
    const items = root;
    const own = items.map((item) => {
        const s = stringField(item, 'Secret');
        return s !== null && s.length > 0 ? s : null;
    });
    const secrets = items.map((item, n) => {
        const rule = stringField(item, 'RuleID');
        return rule !== null && keep(rule) ? (own[n] ?? null) : null;
    });
    // Runs of overlapping matches, per file and commit. Each run's matches are
    // scrubbed as the run closes, so its matcher is garbage before the next run
    // is built: kept to the end, 10 000 findings with private-key values held
    // 1 GB, and 30 000 ended in a fatal heap OOM.
    const scrubbedMatch = items.map(() => null);
    const groups = new Map();
    const unplaceable = new Set();
    items.forEach((item, n) => {
        const key = `${stringField(item, 'File') ?? ''}\u0000${stringField(item, 'Commit') ?? ''}`;
        if (spanOf(item) === null) {
            unplaceable.add(key);
            return;
        }
        const list = groups.get(key);
        if (list === undefined)
            groups.set(key, [n]);
        else
            list.push(n);
    });
    for (const [key, members] of groups) {
        // A group with an item it cannot place has every match withheld whole.
        if (unplaceable.has(key))
            continue;
        const placed = members.flatMap((n) => {
            const span = spanOf(items[n]);
            return span === null ? [] : [{ n, span }];
        });
        placed.sort((a, b) => a.span.startLine - b.span.startLine || a.span.startCol - b.span.startCol);
        let run = [];
        let runEnd = null;
        const closeRun = () => {
            const scrub = makeScrubber(run.flatMap((n) => own[n] ?? []));
            for (const n of run) {
                const match = stringField(items[n], 'Match');
                if (match !== null && own[n] != null)
                    scrubbedMatch[n] = scrub(match);
            }
            run = [];
        };
        for (const current of placed) {
            if (runEnd !== null && endsBefore(runEnd, current.span))
                closeRun();
            if (run.length === 0 || runEnd === null || endsLater(current.span, runEnd))
                runEnd = current.span;
            run.push(current.n);
        }
        closeRun();
    }
    // The values of each commit, for its message.
    const byCommit = new Map();
    items.forEach((item, n) => {
        const value = own[n];
        if (value == null)
            return;
        const commit = stringField(item, 'Commit') ?? '';
        const set = byCommit.get(commit);
        if (set === undefined)
            byCommit.set(commit, new Set([value]));
        else
            set.add(value);
    });
    const messageCache = new Map();
    const cleanMessage = (commit, message) => {
        const cacheKey = `${commit}\u0000${message}`;
        const cached = messageCache.get(cacheKey);
        if (cached !== undefined)
            return cached;
        const found = [...(byCommit.get(commit) ?? [])].filter((v) => message.includes(v));
        const clean = replaceAll(message, found);
        messageCache.set(cacheKey, clean);
        return clean;
    };
    const clean = items.map((item, n) => {
        if (!isRecord(item))
            return item;
        const c = { ...item };
        const value = own[n] ?? null;
        const key = `${stringField(item, 'File') ?? ''}\u0000${stringField(item, 'Commit') ?? ''}`;
        if ('Secret' in c)
            c['Secret'] = REDACTED;
        if (typeof c['Match'] === 'string') {
            const scrubbed = scrubbedMatch[n] ?? null;
            c['Match'] =
                value === null || unplaceable.has(key) || spanOf(item) === null || scrubbed === null ? REDACTED : scrubbed;
        }
        if (typeof c['Message'] === 'string' && c['Message'].length > 0) {
            c['Message'] = cleanMessage(stringField(item, 'Commit') ?? '', c['Message']);
        }
        if (Array.isArray(c['Tags']) && value !== null) {
            c['Tags'] = c['Tags'].map((t) => (typeof t === 'string' ? replaceAll(t, [value]) : t));
        }
        if ('Line' in c)
            c['Line'] = REDACTED;
        if ('Fragment' in c)
            c['Fragment'] = REDACTED;
        return c;
    });
    return { text: JSON.stringify(clean), secrets };
}
/** Every occurrence of every needle → `REDACTED`, longest needle first. */
function replaceAll(text, needles) {
    const sorted = [...new Set(needles)].filter((n) => n.length > 0).sort((a, b) => b.length - a.length);
    let out = text;
    for (const n of sorted)
        if (out.includes(n))
            out = out.split(n).join(REDACTED);
    return out;
}
/**
 * Add an occurrence to `ranges` (kept in order of their ends): one that
 * OVERLAPS the ranges before it merges with them, so no fragment of any value
 * survives between two `REDACTED`s; one that merely touches stays apart, as a
 * value repeated back to back always did.
 */
function addRange(ranges, start, end) {
    let from = start;
    for (let last = ranges.at(-1); last !== undefined && last.end > from; last = ranges.at(-1)) {
        from = Math.min(from, last.start);
        ranges.pop();
    }
    ranges.push({ start: from, end });
}
/** `text` with each of `ranges` (disjoint, in order) replaced by `REDACTED`. */
function redactRanges(text, ranges) {
    if (ranges.length === 0)
        return text;
    let out = '';
    let pos = 0;
    for (const r of ranges) {
        out += text.slice(pos, r.start) + REDACTED;
        pos = r.end;
    }
    return out + text.slice(pos);
}
/**
 * A function that replaces every occurrence — overlapping ones included — of
 * any of `values` in a text by `REDACTED`. Most runs hold one finding, or
 * several findings of one value, and get the native search
 * ({@link makeValueScrubber}); only a run of several distinct values builds
 * the one-pass matcher ({@link makeTrieScrubber}), whose size is theirs.
 */
function makeScrubber(values) {
    const distinct = [...new Set(values)].filter((v) => v.length > 0);
    const [only] = distinct;
    if (only === undefined)
        return (text) => text;
    return distinct.length === 1 ? makeValueScrubber(only) : makeTrieScrubber(distinct);
}
/**
 * {@link makeScrubber} for one value. A text holding it at most once — every
 * match of a finding that overlaps no other — is one or two native
 * `indexOf`s. One holding it again goes through Knuth-Morris-Pratt from the
 * first occurrence, which finds every occurrence, overlapping ones included
 * (`abab` twice in `ababab`, which split/join cut in two), in one pass:
 * restarting `indexOf` after each occurrence costs the value's length per
 * occurrence, and a value of one repeated letter occurs at every position.
 */
function makeValueScrubber(value) {
    const m = value.length;
    /** KMP's prefix function of `value`, built the first time a text repeats it. */
    let border = null;
    return (text) => {
        const first = text.indexOf(value);
        if (first === -1)
            return text;
        if (text.indexOf(value, first + 1) === -1)
            return text.slice(0, first) + REDACTED + text.slice(first + m);
        border ??= prefixFunction(value);
        const ranges = [];
        let q = 0;
        for (let i = first; i < text.length; i++) {
            const c = text.charCodeAt(i);
            while (q > 0 && value.charCodeAt(q) !== c)
                q = border[q - 1] ?? 0;
            if (value.charCodeAt(q) === c)
                q += 1;
            if (q === m) {
                addRange(ranges, i + 1 - m, i + 1);
                q = border[m - 1] ?? 0;
            }
        }
        return redactRanges(text, ranges);
    };
}
/** For each prefix of `s`, the length of its longest proper prefix that is also its suffix. */
function prefixFunction(s) {
    const border = new Int32Array(s.length);
    let k = 0;
    for (let i = 1; i < s.length; i++) {
        const c = s.charCodeAt(i);
        while (k > 0 && s.charCodeAt(k) !== c)
            k = border[k - 1] ?? 0;
        if (s.charCodeAt(k) === c)
            k += 1;
        border[i] = k;
    }
    return border;
}
/** One UTF-16 code unit per trie edge: an edge's key is `node * EDGE + unit`. */
const EDGE = 0x10000;
/**
 * {@link makeScrubber} for several distinct values, in one pass over the
 * text however many there are (Aho-Corasick over UTF-16 code units — the
 * units `includes` compares). At each position the longest value ending
 * there marks its range ({@link addRange} merges the overlapping ones).
 * Building costs about the values' total length, in time and in memory — it
 * lives only while its run's matches are scrubbed.
 */
function makeTrieScrubber(values) {
    const at = (a, i) => a[i] ?? 0;
    const edges = new Map();
    const parent = [0];
    const unit = [0];
    const depth = [0];
    /** The length of the longest value that is a suffix of the node's string; 0 for none. */
    const longest = [0];
    for (const v of values) {
        let node = 0;
        for (let i = 0; i < v.length; i++) {
            const c = v.charCodeAt(i);
            let child = edges.get(node * EDGE + c);
            if (child === undefined) {
                child = parent.length;
                edges.set(node * EDGE + c, child);
                parent.push(node);
                unit.push(c);
                depth.push(i + 1);
                longest.push(0);
            }
            node = child;
        }
        if (node !== 0)
            longest[node] = v.length;
    }
    if (parent.length === 1)
        return (text) => text;
    // Failure links, shallowest node first: each one's parent and every
    // shorter suffix are settled before it.
    const fail = parent.map(() => 0);
    const order = parent.map((_, n) => n).sort((a, b) => at(depth, a) - at(depth, b));
    for (const v of order) {
        const p = at(parent, v);
        if (v === 0 || p === 0)
            continue;
        const c = at(unit, v);
        let f = at(fail, p);
        while (f !== 0 && !edges.has(f * EDGE + c))
            f = at(fail, f);
        const target = edges.get(f * EDGE + c) ?? 0;
        fail[v] = target;
        if (at(longest, v) === 0)
            longest[v] = at(longest, target);
    }
    return (text) => {
        const ranges = [];
        let node = 0;
        for (let i = 0; i < text.length; i++) {
            const c = text.charCodeAt(i);
            let next = edges.get(node * EDGE + c);
            while (next === undefined && node !== 0) {
                node = at(fail, node);
                next = edges.get(node * EDGE + c);
            }
            node = next ?? 0;
            const length = at(longest, node);
            if (length !== 0)
                addRange(ranges, i + 1 - length, i + 1);
        }
        return redactRanges(text, ranges);
    };
}
function spanOf(item) {
    const startLine = numberField(item, 'StartLine');
    const endLine = numberField(item, 'EndLine');
    const startCol = numberField(item, 'StartColumn');
    const endCol = numberField(item, 'EndColumn');
    if (startLine === null || endLine === null || startCol === null || endCol === null)
        return null;
    return { startLine, startCol: startCol - 1, endLine, endCol: endCol + 1 };
}
/** `a` ends strictly before `b` starts. */
function endsBefore(a, b) {
    return a.endLine < b.startLine || (a.endLine === b.startLine && a.endCol < b.startCol);
}
/** `a` ends strictly after `b` ends. */
function endsLater(a, b) {
    return a.endLine > b.endLine || (a.endLine === b.endLine && a.endCol > b.endCol);
}
function isRecord(v) {
    return typeof v === 'object' && v !== null && !Array.isArray(v);
}
function stringField(v, key) {
    if (!isRecord(v))
        return null;
    const x = v[key];
    return typeof x === 'string' ? x : null;
}
function numberField(v, key) {
    if (!isRecord(v))
        return null;
    const x = v[key];
    return typeof x === 'number' && Number.isFinite(x) ? x : null;
}
//# sourceMappingURL=rawReport.js.map