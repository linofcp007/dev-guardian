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
 *     OVERLAPS it (same file and commit; found with a sort + sweep, so the
 *     cost follows the overlaps, not the item count squared) → `REDACTED`.
 *     Another finding's value can only be inside a match that overlaps it.
 *     A match whose group has an item with no position cannot be placed and
 *     is withheld whole, as is the match of an item with no value.
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
    // Overlapping matches, per file and commit.
    const others = items.map(() => new Set());
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
    for (const members of groups.values()) {
        const placed = members.flatMap((n) => {
            const span = spanOf(items[n]);
            return span === null ? [] : [{ n, span }];
        });
        placed.sort((a, b) => a.span.startLine - b.span.startLine || a.span.startCol - b.span.startCol);
        let active = [];
        for (const current of placed) {
            active = active.filter((a) => !endsBefore(a.span, current.span));
            const mine = own[current.n];
            for (const a of active) {
                const theirs = own[a.n];
                if (theirs != null)
                    others[current.n]?.add(theirs);
                if (mine != null)
                    others[a.n]?.add(mine);
            }
            active.push(current);
        }
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
            c['Match'] =
                value === null || unplaceable.has(key) || spanOf(item) === null
                    ? REDACTED
                    : replaceAll(c['Match'], [value, ...(others[n] ?? [])]);
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