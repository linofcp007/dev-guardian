/**
 * Line-independent finding identity.
 *
 * `fingerprint` (`./findingFingerprint.ts`) hashes `line_start`/`line_end`
 * and the snippet, so inserting ONE line above a finding made it a different
 * finding to everything that compares findings across scans. Each of these
 * was reproduced: a suppression lapsed and the finding came back as open; the
 * CI gate reported it as new; `diff_scans` and `regression_alert` saw one new
 * plus one resolved; and `create_fix_pr` judged an UNFIXED target "resolved"
 * because the autofix above it had moved it down a line. Trivy's snippet also
 * carries the fixed version, so the advisory database learning about a fix
 * did the same to a dependency finding. `dast/analyze.ts` had already
 * documented and avoided this for its own findings.
 *
 * `identity` is what those comparisons key on now:
 *
 *     sha256(tool | rule_id | normalised relative path | contentKey | occurrence)
 *
 *   - **contentKey** is a hash of WHAT the finding flags, never of where:
 *       - a dependency finding: `package@installed_version` — never the fixed
 *         version (see {@link dependencyCoordinates});
 *       - a finding on source lines: those lines' text, whitespace-collapsed
 *         (so re-indenting or a CRLF checkout changes nothing), read from the
 *         file on disk;
 *       - otherwise the scanner's snippet, whitespace-collapsed — which is
 *         also what a finding with no file keys on, together with its target
 *         (`file_path` holds the image or lockfile Trivy names);
 *       - nothing at all when none of those exists.
 *   - **occurrence** tells apart findings that agree on everything else — the
 *     same rule on two identical lines of one file — by their order in the
 *     file. Moving both down keeps both identities.
 *
 * **Why the lines are read from disk even when there IS a snippet.** The
 * snippet is not reliably the source text of the lines. Semgrep ≥ ~1.120
 * without `semgrep login` reports the literal string "requires login"; Bandit's
 * `code` prefixes every line with its line number (so a one-line shift changes
 * it — the very bug); Trivy's misconfiguration snippet is the rule's
 * Resolution text; and every snippet is clamped to 1 KB, so a long match
 * hashed from the snippet on one machine and from the file on another would
 * disagree. The file is the one source that is the same for every scanner and
 * every machine, so it wins, and the snippet is the fallback for a file that
 * cannot be read (with Bandit's line numbers stripped from it, and never the
 * "requires login" placeholder). The one exception is a gitleaks finding that names a
 * commit: its lines live in history, not in the working tree (which may hold
 * anything at that line number today), and `rule=…;commit=…` is already a
 * stable, line-independent locator.
 *
 * **Secrets are never keyed on their line — not even hashed.** The identity
 * is committed to `.guardian/baseline.json`, and a fast unsalted hash of a
 * line such as `DB_PASSWORD=<value>` is an offline oracle: guess a
 * low-entropy value, hash, compare. So a credential finding
 * ({@link isCredentialFinding}: `subcategory: 'secret'`, or a rule/subcategory
 * that names a password, secret, credential or key) has its content keyed on
 * `secret` + its rule id, plus gitleaks' commit locator when it has one —
 * nothing derived from the value, so rotating the secret in place keeps the
 * identity, and the occurrence alone keeps two secrets of one rule in one
 * file apart. For every other finding, the text read from disk is hashed and
 * dropped: never written to the finding, the database or a response.
 *
 * `fingerprint` is untouched and stays each row's per-scan key. Everything
 * that matches across scans uses the identity first and falls back to the
 * fingerprint where either side predates it ({@link indexFindings}), which is
 * how a 2.0.x suppression or `baseline.json` keeps working.
 */
import { createHash } from 'node:crypto';
import { readFileSync, realpathSync, statSync } from 'node:fs';
import { isAbsolute, relative, resolve, sep } from 'node:path';
import { normalizePathPosix } from './findingFingerprint.js';
/** What modern Semgrep puts in `extra.lines` without `semgrep login`. */
export const REDACTED_SNIPPET = 'requires login';
/**
 * Part of every identity's hash. Changing the recipe changes every identity
 * ever stored, so it is versioned rather than silently different.
 */
const IDENTITY_VERSION = 1;
/** A file bigger than this is not read for its lines; the snippet stands in. */
const MAX_SOURCE_BYTES = 8 * 1024 * 1024;
/**
 * Every finding of ONE scan, with `identity` and `content_key` set. The
 * occurrence is counted within the batch, so the batch must be the whole scan
 * — the scan-tool factory calls this once, after every parser and the
 * cross-parser dedupe have run.
 *
 * A fingerprint that repeats in the batch is one finding (the database keeps
 * one row per fingerprint and scan): every copy gets the first copy's
 * identity and none of them advances the occurrence.
 *
 * Content is computed file by file (findings sorted by path), holding one
 * file's lines at a time: a scan with thousands of findings across thousands
 * of files reads each file once and never holds more than one in memory.
 */
export function assignIdentities(findings, opts = {}) {
    const located = findings.map((finding, index) => ({
        finding,
        index,
        location: locate(finding.file_path, opts.projectPath),
    }));
    const contentKeys = new Map();
    let currentPath = null;
    let currentLines = null;
    const linesOf = (readable) => {
        if (readable !== currentPath) {
            currentPath = readable;
            const text = opts.readSource === undefined ? null : opts.readSource(readable);
            currentLines = text === null ? null : text.split(/\r\n|\r|\n/);
        }
        return currentLines;
    };
    const byPath = [...located].sort((a, b) => compareStrings(a.location.readable ?? '', b.location.readable ?? ''));
    for (const { finding, index, location } of byPath) {
        contentKeys.set(index, sha256(contentSource(finding, location.readable, linesOf)));
    }
    const keyed = located.map(({ finding, index, location }) => ({
        finding,
        index,
        tool: finding.tool.toLowerCase(),
        rule: finding.rule_id ?? '',
        path: location.key,
        contentKey: contentKeys.get(index) ?? sha256('none'),
    }));
    const identities = identitiesOf(keyed);
    return keyed.map((k) => ({
        ...k.finding,
        identity: identities.get(k.index) ?? '',
        content_key: k.contentKey,
    }));
}
/**
 * The identity recipe for findings whose content key is already known —
 * {@link assignIdentities}' second half, shared with {@link rekeyStoredIdentities}
 * so a re-keyed stored row gets exactly the identity a fresh scan would.
 */
function identitiesOf(keyed) {
    const groups = new Map();
    for (const k of keyed) {
        const group = JSON.stringify([k.tool, k.rule, k.path, k.contentKey]);
        const members = groups.get(group);
        if (members === undefined)
            groups.set(group, [k]);
        else
            members.push(k);
    }
    // Order within a group: by position, then — for two findings on the same
    // line range — by their snippet, which moves with them. Not by fingerprint
    // first: it hashes the line number, so on a shift two such findings could
    // swap order and with it identities. The fingerprint only breaks ties
    // between findings whose snippet is equal too (then it rarely differs).
    const snippetOrder = (f) => sha256(f.snippet ?? '');
    const identities = new Map();
    for (const members of groups.values()) {
        members.sort((a, b) => (a.finding.line_start ?? 0) - (b.finding.line_start ?? 0) ||
            (a.finding.line_end ?? 0) - (b.finding.line_end ?? 0) ||
            compareStrings(snippetOrder(a.finding), snippetOrder(b.finding)) ||
            compareStrings(a.finding.fingerprint, b.finding.fingerprint) ||
            a.index - b.index);
        const byFingerprint = new Map();
        let occurrence = 0;
        for (const m of members) {
            let identity = byFingerprint.get(m.finding.fingerprint);
            if (identity === undefined) {
                identity = sha256(JSON.stringify([IDENTITY_VERSION, m.tool, m.rule, m.path, m.contentKey, occurrence]));
                occurrence += 1;
                byFingerprint.set(m.finding.fingerprint, identity);
            }
            identities.set(m.index, identity);
        }
    }
    return identities;
}
/**
 * Identities for the stored findings of ONE scan, after their `rule_id`
 * changed (`storage/localRuleIds.ts`: a local rule's path prefix removed):
 * the same recipe as {@link assignIdentities}, with each row's stored content
 * key — except a credential finding's, which IS its rule id
 * (`secret\n<rule id>`, see `contentSource`) and is recomputed. A row with
 * no content key (stored before identities existed) gets none. Returns the
 * new identity and content key per row, in input order.
 */
export function rekeyStoredIdentities(rows, projectPath) {
    const keyed = rows.flatMap((finding, index) => {
        if (finding.content_key === undefined)
            return [];
        const contentKey = isCredentialFinding(finding) && finding.tool.toLowerCase() !== 'gitleaks'
            ? sha256(`secret\n${finding.rule_id ?? ''}`)
            : finding.content_key;
        return [{
                finding,
                index,
                tool: finding.tool.toLowerCase(),
                rule: finding.rule_id ?? '',
                path: locate(finding.file_path, projectPath).key,
                contentKey,
            }];
    });
    const identities = identitiesOf(keyed);
    const contentKeys = new Map(keyed.map((k) => [k.index, k.contentKey]));
    return rows.map((_, index) => ({
        identity: identities.get(index) ?? null,
        content_key: contentKeys.get(index) ?? null,
    }));
}
/**
 * A reader confined to one project: a path that resolves outside it — `..`,
 * an absolute path elsewhere, a symlink pointing out — reads as null, as does
 * anything missing, unreadable, not a file or over {@link MAX_SOURCE_BYTES}.
 * No cache: {@link assignIdentities} asks for each file once.
 */
export function makeSourceReader(projectPath) {
    const root = realOrResolved(projectPath);
    return (filePath) => {
        const lexical = resolve(root, filePath);
        if (!isInside(root, lexical))
            return null;
        try {
            const real = realpathSync.native(lexical);
            const stat = statSync(real);
            if (!isInside(root, real) || !stat.isFile() || stat.size > MAX_SOURCE_BYTES)
                return null;
            return readFileSync(real, 'utf8');
        }
        catch {
            return null;
        }
    };
}
/**
 * `package` and installed version of a dependency finding, from the snippet
 * each dependency scanner writes: Trivy `pkg@installed->fixed` (a CVE),
 * npm audit `pkg@range`, WPScan `component:slug@version`. The name is
 * everything before the LAST `@` of the coordinate, which keeps scoped npm
 * names (`@babel/core`) whole. Trivy's `->fixed` is cut off here, and that is
 * the point: the fixed version is a property of the advisory database, not of
 * the project, and it used to change the finding's key when the database
 * learned of a fix. A finding with a line is source code, whatever its
 * snippet looks like.
 */
export function dependencyCoordinates(f) {
    if (f.line_start !== undefined || f.snippet === undefined)
        return null;
    if (f.tool.toLowerCase() === 'wpscan') {
        const prefix = 'component:';
        if (!f.snippet.startsWith(prefix))
            return null;
        return splitCoordinate(f.snippet.slice(prefix.length), true);
    }
    if (f.subcategory !== 'cve' && f.subcategory !== 'dependency')
        return null;
    const arrow = f.snippet.indexOf('->');
    return splitCoordinate(arrow >= 0 ? f.snippet.slice(0, arrow) : f.snippet, false);
}
/**
 * What `create_fix_pr`'s verification asks "is this target still there?" by:
 * a target is resolved only when NO finding of the re-scan has the same key.
 *
 *   - source finding: (tool, rule_id, path, content_key) — the identity minus
 *     its occurrence. With the occurrence, fixing the first of two identical
 *     lines would renumber the second into the first one's identity and call
 *     the fixed one present and the unfixed one gone;
 *   - dependency finding: (rule_id — the CVE or advisory —, package). The
 *     installed version is exactly what an upgrade changes, so an upgrade
 *     that is not enough must still read as present.
 *
 * Null for a source finding stored before identities existed: the caller
 * then falls back to the fingerprint.
 */
export function resolutionKey(f) {
    const dependency = dependencyCoordinates(f);
    if (dependency !== null) {
        return JSON.stringify(['dependency', f.rule_id ?? null, dependency.name.toLowerCase()]);
    }
    if (f.content_key === undefined)
        return null;
    return JSON.stringify([
        'content',
        f.tool.toLowerCase(),
        f.rule_id ?? null,
        locate(f.file_path, undefined).key,
        f.content_key,
    ]);
}
/**
 * Cross-scan matching: identity first, fingerprint as the fallback.
 *
 * `f` matches an item when their identities are equal, or — only when one of
 * the two has no identity (a row stored before schema 7, a v1 baseline entry,
 * a tool that computes none) — when their fingerprints are equal. Two
 * identities that differ are two findings even if the fingerprints agree:
 * that is the same rule on the same line whose code changed under a redacted
 * snippet, and calling it unchanged would hide the change.
 */
export function indexFindings(items) {
    const byIdentity = new Map();
    const byFingerprint = new Map();
    const add = (item) => {
        if (item.identity !== undefined && !byIdentity.has(item.identity)) {
            byIdentity.set(item.identity, item);
        }
        const same = byFingerprint.get(item.fingerprint);
        if (same === undefined)
            byFingerprint.set(item.fingerprint, [item]);
        else
            same.push(item);
    };
    for (const item of items)
        add(item);
    const find = (f) => {
        if (f.identity !== undefined) {
            const hit = byIdentity.get(f.identity);
            if (hit !== undefined)
                return hit;
        }
        for (const candidate of byFingerprint.get(f.fingerprint) ?? []) {
            if (candidate.identity === undefined || f.identity === undefined)
                return candidate;
        }
        return undefined;
    };
    return { find, has: (f) => find(f) !== undefined, add };
}
// ------------------------------------------------------------------ internal
/**
 * The path as it enters the identity (`key`: relative, POSIX, no `./`) and as
 * it is handed to the reader (`readable`: relative to the project, or null
 * when it is not a path inside it — an image name, an absolute path
 * elsewhere).
 */
function locate(filePath, projectPath) {
    let path = filePath ?? '';
    if (path === '')
        return { key: '', readable: null };
    let insideProject = !isAbsolute(path);
    if (projectPath !== undefined && isAbsolute(path)) {
        const rel = relative(projectPath, path);
        if (rel !== '' && !isAbsolute(rel) && rel !== '..' && !rel.startsWith(`..${sep}`)) {
            path = rel;
            insideProject = true;
        }
    }
    const key = normalizePathPosix(path).replace(/^(\.\/)+/, '');
    return { key, readable: insideProject ? path.replace(/\\/g, '/') : null };
}
function contentSource(f, readable, linesOf) {
    const dependency = dependencyCoordinates(f);
    if (dependency !== null)
        return `dep\n${dependency.name}@${dependency.version}`;
    // Never the line, never its hash — see "Secrets" in the module comment.
    // Checked before anything reads the file, so a credential line is not even
    // loaded for this finding.
    if (isCredentialFinding(f)) {
        const locator = isHistoryLocator(f) && f.snippet !== undefined ? `\n${collapse(f.snippet)}` : '';
        return `secret\n${f.rule_id ?? ''}${locator}`;
    }
    if (isHistoryLocator(f) && f.snippet !== undefined)
        return `text\n${collapse(f.snippet)}`;
    if (readable !== null && f.line_start !== undefined) {
        const fileLines = linesOf(readable);
        const lines = fileLines === null ? null : sourceLines(fileLines, f.line_start, f.line_end);
        if (lines !== null)
            return `text\n${collapse(lines)}`;
    }
    if (f.snippet !== undefined && usableSnippet(f.snippet)) {
        return `text\n${collapse(snippetText(f.tool, f.snippet))}`;
    }
    return 'none';
}
/**
 * The source text inside a snippet. Bandit prefixes each line of its `code`
 * with the line number (`"2 data = pickle.loads(x)"`); those numbers are
 * exactly what the identity must not depend on.
 */
function snippetText(tool, snippet) {
    if (tool.toLowerCase() !== 'bandit')
        return snippet;
    return snippet
        .split(/\r\n|\r|\n/)
        .map((line) => line.replace(/^\d+ /, ''))
        .join('\n');
}
/**
 * Rule ids and subcategories that name what they flag as a credential. Each
 * word must stand alone (bounded by a non-letter), so `jsonwebtoken` or a
 * CSRF-token rule does not match; a bare `token` is not in the list for that
 * reason. Matching too much costs only precision (the content then says less
 * than the line would); matching too little puts a hash of a secret into a
 * committed file, so this leans wide.
 */
const CREDENTIAL_RULE = /(^|[^a-z])(secrets?|passwords?|passwd|pwd|credentials?|api[-_]?keys?|private[-_]?keys?|access[-_]?keys?|aws[-_]?keys?|hardcoded[-_ ]?(passwords?|secrets?|credentials?|keys?|tokens?))([^a-z]|$)/i;
/**
 * A finding whose flagged line holds a credential: every `subcategory:
 * 'secret'` finding (gitleaks, Trivy secrets), and a finding whose rule id or
 * subcategory names one — Bandit's B105–B107 (`hardcoded_password_*`), the
 * shipped `hardcoded-aws-key` / `hardcoded-private-key` rules, the Semgrep
 * registry's `*.secrets.*` family.
 */
export function isCredentialFinding(f) {
    if ((f.subcategory ?? '').toLowerCase() === 'secret')
        return true;
    return CREDENTIAL_RULE.test(f.rule_id ?? '') || CREDENTIAL_RULE.test(f.subcategory ?? '');
}
/** A gitleaks finding whose snippet names the commit it was found in. */
function isHistoryLocator(f) {
    return (f.tool.toLowerCase() === 'gitleaks' &&
        /;commit=[0-9a-f]{7,64}$/i.test(f.snippet ?? ''));
}
function usableSnippet(snippet) {
    const text = collapse(snippet);
    return text !== '' && text.toLowerCase() !== REDACTED_SNIPPET;
}
/** Lines `start`..`end` (1-based, inclusive), or null when `start` is not in the file. */
function sourceLines(lines, start, end) {
    if (!Number.isInteger(start) || start < 1)
        return null;
    if (start > lines.length)
        return null;
    const requestedEnd = end !== undefined && Number.isInteger(end) ? end : start;
    const last = Math.min(Math.max(requestedEnd, start), lines.length);
    return lines.slice(start - 1, last).join('\n');
}
function collapse(text) {
    return text.replace(/\s+/g, ' ').trim();
}
function splitCoordinate(coordinate, allowBareName) {
    const at = coordinate.lastIndexOf('@');
    if (at > 0)
        return { name: coordinate.slice(0, at), version: coordinate.slice(at + 1) };
    if (allowBareName && coordinate !== '' && at < 0)
        return { name: coordinate, version: '' };
    return null;
}
function isInside(root, candidate) {
    const rel = relative(root, candidate);
    return rel !== '' && !isAbsolute(rel) && rel !== '..' && !rel.startsWith(`..${sep}`);
}
function realOrResolved(p) {
    try {
        return realpathSync.native(resolve(p));
    }
    catch {
        return resolve(p);
    }
}
function compareStrings(a, b) {
    return a < b ? -1 : a > b ? 1 : 0;
}
function sha256(text) {
    return createHash('sha256').update(text).digest('hex');
}
//# sourceMappingURL=findingIdentity.js.map