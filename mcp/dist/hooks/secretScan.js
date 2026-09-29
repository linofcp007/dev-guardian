/**
 * Fast, dependency-free secret detection for the guardian hooks.
 *
 * This is a deliberately small, *high-precision* pre-filter — not a
 * replacement for `scan_secrets` (gitleaks), which remains the authoritative
 * full-history scan. Its job is to catch an obvious credential the instant it
 * is written into a file or pasted into a command, with zero external
 * dependencies (no native modules, no gitleaks binary) so it runs everywhere
 * the plugin is installed, in milliseconds.
 *
 * Two confidence tiers:
 *   - 'high'   → provider-specific token shapes and private-key headers.
 *                Unambiguous; safe to *block* on (opt-in).
 *   - 'medium' → heuristic generic-assignment / JWT matches. Good for a
 *                non-blocking *warning*; never used for blocking.
 *
 * The raw secret bytes never leave this module: every hit is redacted to a
 * short masked preview before it is returned.
 *
 * Pure data + pure functions. No I/O.
 */
const CONFIDENCE_RANK = { medium: 0, high: 1 };
/**
 * High-precision, provider-specific credential shapes. Order matters only for
 * reporting; every rule is tried against every line.
 */
export const SECRET_RULES = [
    // ── Cloud / provider tokens (unambiguous shapes → 'high') ────────────────
    { id: 'aws-access-key-id', title: 'AWS access key ID', confidence: 'high', pattern: /\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA)[0-9A-Z]{16}\b/ },
    { id: 'aws-secret-access-key', title: 'AWS secret access key', confidence: 'high', pattern: /\baws_?secret_?access_?key\b["'\s:=]+["']?[A-Za-z0-9/+]{40}\b/i },
    { id: 'github-token', title: 'GitHub token', confidence: 'high', pattern: /\bgh[pousr]_[A-Za-z0-9]{36}\b/ },
    { id: 'github-fine-grained-pat', title: 'GitHub fine-grained PAT', confidence: 'high', pattern: /\bgithub_pat_[A-Za-z0-9_]{82}\b/ },
    { id: 'gitlab-pat', title: 'GitLab personal access token', confidence: 'high', pattern: /\bglpat-[A-Za-z0-9_-]{20}\b/ },
    { id: 'slack-token', title: 'Slack token', confidence: 'high', pattern: /\bxox[baprs]-[A-Za-z0-9-]{10,48}\b/ },
    { id: 'slack-webhook', title: 'Slack incoming webhook', confidence: 'high', pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9_/]{6,}/ },
    { id: 'stripe-live-key', title: 'Stripe live secret key', confidence: 'high', pattern: /\b[rs]k_live_[A-Za-z0-9]{20,}\b/ },
    { id: 'google-api-key', title: 'Google API key', confidence: 'high', pattern: /\bAIza[0-9A-Za-z_-]{35}\b/ },
    { id: 'google-oauth-token', title: 'Google OAuth access token', confidence: 'high', pattern: /\bya29\.[0-9A-Za-z_-]{20,}\b/ },
    { id: 'anthropic-api-key', title: 'Anthropic API key', confidence: 'high', pattern: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/ },
    // `(?!ant-)` — an Anthropic key (`sk-ant-…`) otherwise also satisfies this
    // shape (`sk-` + 32+ alnum/hyphen chars) and was reported twice, once under
    // each rule id.
    { id: 'openai-api-key', title: 'OpenAI API key', confidence: 'high', pattern: /\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{32,}\b/ },
    { id: 'sendgrid-key', title: 'SendGrid API key', confidence: 'high', pattern: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/ },
    { id: 'npm-token', title: 'npm access token', confidence: 'high', pattern: /\bnpm_[A-Za-z0-9]{36}\b/ },
    { id: 'pypi-token', title: 'PyPI upload token', confidence: 'high', pattern: /\bpypi-AgEIcHlwaS[A-Za-z0-9_-]{10,}/ },
    { id: 'twilio-account-sid', title: 'Twilio account SID', confidence: 'high', pattern: /\bAC[0-9a-fA-F]{32}\b/ },
    { id: 'private-key-block', title: 'Private key', confidence: 'high', pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----/ },
    // ── Heuristics (ambiguous → 'medium', warn only) ─────────────────────────
    //
    // Quantifiers bounded at 2000 (a real JWT segment is a few hundred base64
    // chars at most) rather than unbounded `{8,}`: unbounded, three greedy
    // classes each backed by a literal `.` that may not exist nearby turned
    // `'eyJ-'.repeat(50000)` (no dot anywhere in it) into ~27s of backtracking.
    // Bounding caps the work per candidate start at a constant instead of
    // letting it grow with input size — the other half of the fix is the 16KB
    // window below, which bounds input size itself. Even so, every `eyJ` of a
    // 16 KB run rescanned up to 2000 characters (~90 ms a window), so the
    // scanner uses `findJwt`, which reads each run once (review I3).
    {
        id: 'jwt',
        title: 'JSON Web Token (JWT)',
        confidence: 'medium',
        pattern: /\beyJ[A-Za-z0-9_-]{8,2000}\.eyJ[A-Za-z0-9_-]{8,2000}\.[A-Za-z0-9_-]{8,2000}\b/,
        find: (text, from) => findJwt(text, from),
    },
    {
        id: 'generic-assignment',
        title: 'Hard-coded credential',
        confidence: 'medium',
        // SCREAMING_SNAKE / kebab / bare key (DB_PASSWORD, api-key, password)
        // assigned a quoted value. The key must sit at a name boundary — start of
        // string or preceded by a non-alnum char — via the lookbehind, which is
        // also what lets `DB_PASSWORD` match at all: a plain `\b` sits between
        // two word characters at the `_` before PASSWORD ('_' and 'P' are both
        // \w), so no boundary exists there for `\b` to find.
        // An optional closing quote (`["'\`]?`) is allowed between the key and
        // the separator so JSON's `"password":` — the key's own closing `"`
        // sitting right before the colon — matches; that quote used to be
        // unaccounted for and silently broke every JSON-shaped hit.
        pattern: /(?<![A-Za-z0-9])(?:api[_-]?key|secret(?:[_-]?key)?|access[_-]?token|auth[_-]?token|client[_-]?secret|passwd|password|private[_-]?key|token)["'`]?\s*[:=]\s*["'`]([^"'`]{12,})["'`]/i,
    },
    {
        id: 'generic-assignment-camel',
        title: 'Hard-coded credential',
        confidence: 'medium',
        // camelCase key (stripeSecretKey, dbPassword, githubToken) assigned a
        // quoted value. Case-SENSITIVE and gated on a lowercase letter right
        // before the capitalised keyword (the camelCase boundary itself) —
        // deliberately not folded into the rule above via a case-insensitive
        // flag: that would also match the keyword in the MIDDLE of an ordinary
        // lowercase word ("monkey", "donkey" both contain "key") with nothing to
        // tell a real name boundary from a coincidence.
        pattern: /(?<=[a-z])(?:ApiKey|SecretKey|Secret|AccessToken|AuthToken|ClientSecret|Passwd|Password|PrivateKey|Token)["'`]?\s*[:=]\s*["'`]([^"'`]{12,})["'`]/,
    },
    {
        id: 'generic-assignment-env',
        title: 'Hard-coded credential',
        confidence: 'medium',
        // Same SCREAMING_SNAKE/bare key, unquoted `.env`-style assignment
        // (`DB_PASSWORD=hunter2hunter2`, `export ANTHROPIC_API_KEY=sk-ant-…`).
        // `=` only, never `:` — a bare `token: string` TypeScript annotation is
        // exactly this shape with `:`, and must stay silent. The value charset
        // excludes `$`, `{`, `}`, `<`, `>`, `(`, `)` and whitespace, which is what
        // keeps `${VAR}`, `<your-key>` and `password = getPassword()` unmatched
        // without needing a placeholder check to catch them.
        //
        // The value's run is rescanned from every key inside it when it does not
        // end at whitespace (`token=token=…"`: ~250 ms a window), so the scanner
        // uses `findEnvAssignment`, which reads each run once (review I3).
        pattern: /(?<![A-Za-z0-9])(?:api[_-]?key|secret(?:[_-]?key)?|access[_-]?token|auth[_-]?token|client[_-]?secret|passwd|password|private[_-]?key|token)\s*=\s*([^\s"'`${}<>()]{8,})(?=\s|$)/i,
        find: (text, from) => findEnvAssignment(text, from),
    },
    {
        id: 'uri-credentials',
        title: 'Credentials embedded in a URI',
        confidence: 'medium',
        // scheme://user:password@host — postgres://user:pass@host/db and the like.
        // The scheme is at most 32 characters (`mongodb+srv` is 11): unbounded,
        // every word start of a long `a-a-a-…` run rescanned the rest of it — up
        // to 0.5 s a window (review I3).
        pattern: /\b[a-z][a-z0-9+.-]{0,31}:\/\/[^\s/:@]+:([^\s/:@]{3,})@[^\s/'"]+/i,
    },
];
/** `[A-Za-z0-9_-]`: base64url, a JWT segment's alphabet. */
function isB64url(c) {
    return (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c === 95 || c === 45;
}
/** `\w` in a regular expression without the `u` flag. */
function isWordChar(c) {
    return (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c === 95;
}
/** Whether `\b` holds at `at`. */
function isBoundary(text, at) {
    const before = at > 0 && isWordChar(text.charCodeAt(at - 1));
    const after = at < text.length && isWordChar(text.charCodeAt(at));
    return before !== after;
}
/**
 * `runEnd(i)`: the first index at or after `i` whose character is not in the
 * class, from one right-to-left pass — so every start inside a run costs
 * nothing more.
 */
function runEnds(text, inClass) {
    const ends = new Int32Array(text.length + 1);
    ends[text.length] = text.length;
    for (let i = text.length - 1; i >= 0; i -= 1)
        ends[i] = inClass(text.charCodeAt(i)) ? (ends[i + 1] ?? i) : i;
    return (i) => (i >= text.length ? text.length : (ends[i] ?? i));
}
/**
 * The `jwt` pattern's first match at or after `from`, in linear time. A
 * segment's class has no `.`, so each segment ends where its run of
 * `[A-Za-z0-9_-]` ends: the first two must end at a `.` within 8-2000
 * characters, and the third takes the longest length of 8-2000 that ends at a
 * word boundary — the same answer the pattern's backtracking reaches.
 */
function findJwt(text, from) {
    if (!text.includes('.eyJ', from))
        return null;
    const end = runEnds(text, isB64url);
    let lastThird = -1;
    let lastThirdEnd = -1;
    for (let p = text.indexOf('eyJ', from); p >= 0; p = text.indexOf('eyJ', p + 1)) {
        if (p > 0 && isWordChar(text.charCodeAt(p - 1)))
            continue;
        const e1 = end(p + 3);
        const l1 = e1 - (p + 3);
        if (l1 < 8 || l1 > 2000 || !text.startsWith('.eyJ', e1))
            continue;
        const q = e1 + 4;
        const e2 = end(q);
        const l2 = e2 - q;
        if (l2 < 8 || l2 > 2000 || text.charCodeAt(e2) !== 46)
            continue;
        const r = e2 + 1;
        if (r !== lastThird) {
            lastThird = r;
            lastThirdEnd = -1;
            const longest = Math.min(end(r) - r, 2000);
            for (let x = r + longest; x >= r + 8; x -= 1) {
                if (isBoundary(text, x)) {
                    lastThirdEnd = x;
                    break;
                }
            }
        }
        if (lastThirdEnd >= 0)
            return { index: p, text: text.slice(p, lastThirdEnd) };
    }
    return null;
}
/** The keys of `generic-assignment-env`, then `\s*=\s*`. */
const ENV_KEY = /(?<![A-Za-z0-9])(?:api[_-]?key|secret(?:[_-]?key)?|access[_-]?token|auth[_-]?token|client[_-]?secret|passwd|password|private[_-]?key|token)\s*=\s*/gi;
/** Whether a character may be in an unquoted `.env` value: not whitespace, a quote, `$`, a brace, `<`, `>` or a parenthesis. */
function isEnvValueChar(c) {
    return !(c === 32 || (c >= 9 && c <= 13) || c === 0xa0 || c === 0x1680 || (c >= 0x2000 && c <= 0x200a) ||
        c === 0x2028 || c === 0x2029 || c === 0x202f || c === 0x205f || c === 0x3000 || c === 0xfeff ||
        c === 34 || c === 39 || c === 96 || c === 36 || c === 123 || c === 125 || c === 60 || c === 62 || c === 40 || c === 41);
}
/**
 * The `generic-assignment-env` pattern's first match at or after `from`, in
 * linear time: the value is the whole run after the `=` (its class has no
 * whitespace, so no shorter value can be followed by one), and it counts when
 * it is at least 8 characters and the run ends at whitespace or the end.
 */
function findEnvAssignment(text, from) {
    if (!text.includes('=', from))
        return null;
    const end = runEnds(text, isEnvValueChar);
    const key = new RegExp(ENV_KEY.source, ENV_KEY.flags);
    key.lastIndex = from;
    for (let m = key.exec(text); m !== null; m = key.exec(text)) {
        const v = m.index + m[0].length;
        const e = end(v);
        if (e - v >= 8 && (e === text.length || /\s/.test(text.charAt(e)))) {
            return { index: m.index, text: text.slice(m.index, e), value: text.slice(v, e) };
        }
        key.lastIndex = m.index + 1;
    }
    return null;
}
/** Rule ids whose match's capture group is the credential VALUE to vet
 *  (placeholder / entropy checks) rather than the whole match. */
const VALUE_CAPTURE_RULES = new Set([
    'generic-assignment',
    'generic-assignment-camel',
    'generic-assignment-env',
    'uri-credentials',
]);
/** Lowercased markers that mean "this is a placeholder, not a real secret". */
const PLACEHOLDER_MARKERS = [
    'example',
    'changeme',
    'change-me',
    'placeholder',
    'your-',
    'your_',
    'yourkey',
    'yourtoken',
    'redacted',
    'dummy',
    'sample',
    'xxxxx',
    'test-token',
    'fake',
    'notreal',
    '<your',
    '${',
    '{{',
    'env.',
    'process.env',
    'os.environ',
];
/** Shannon entropy in bits/char — used to reject low-entropy placeholders. */
export function shannonEntropy(s) {
    if (s.length === 0)
        return 0;
    const freq = new Map();
    for (const ch of s)
        freq.set(ch, (freq.get(ch) ?? 0) + 1);
    let h = 0;
    for (const count of freq.values()) {
        const p = count / s.length;
        h -= p * Math.log2(p);
    }
    return h;
}
function looksLikePlaceholder(value) {
    const lower = value.toLowerCase();
    if (PLACEHOLDER_MARKERS.some((m) => lower.includes(m)))
        return true;
    // All-same-char or trivially repetitive (e.g. "aaaaaaaaaaaa", "xxxxxxxx").
    if (/^(.)\1{6,}$/.test(value))
        return true;
    return false;
}
/**
 * Redact a secret to a short, safe preview that reveals only its shape.
 * Below 16 characters, only the 4-character head is shown (no tail) — a
 * secret that short is barely obscured by 6 of its ~12 characters, which is
 * what the old `length > 12` threshold revealed for anything 13-15 chars
 * long. 16+ still gets a head and a 2-character tail, unchanged.
 */
export function redact(secret) {
    const trimmed = secret.trim();
    const head = trimmed.slice(0, 4);
    const tail = trimmed.length >= 16 ? trimmed.slice(-2) : '';
    return `${head}…${tail} (${trimmed.length})`;
}
/**
 * A line is read in windows of this size — see the module doc's ReDoS note in
 * `bashGuard.ts`, which this mirrors: every pattern sees a bounded text,
 * however long the line. It used to be a cap: only the first 16 KB of a line
 * was read, and a token at column ~16.4K of a one-line JSON file or a minified
 * bundle passed the block, the warning and `check --file` (review I3).
 */
const WINDOW = 16 * 1024;
/**
 * Consecutive windows share this much, so any match up to this long lies
 * whole inside one of them: every provider token is under 256 characters, and
 * 2 KB also holds an ordinary JWT.
 */
const OVERLAP = 2 * 1024;
const STEP = WINDOW - OVERLAP;
function lineWindows(line) {
    if (line.length <= WINDOW)
        return [{ text: line, cutLeft: false, cutRight: false }];
    const out = [];
    for (let s = 0;; s += STEP) {
        const e = Math.min(line.length, s + WINDOW);
        const from = Math.max(0, s - 1);
        const to = Math.min(line.length, e + 1);
        out.push({ text: line.slice(from, to), cutLeft: from > 0, cutRight: to < line.length });
        if (e >= line.length)
            return out;
    }
}
/**
 * A rule's first match in a window that does not lean on the window's edge: a
 * match starting on the left context character belongs to the window before,
 * and one running up to the right edge may be the cut-off start of a longer
 * run — no `\b` really ends it there. That one is left to the next window,
 * which holds it whole when it is at most {@link OVERLAP} long; the search in
 * this window stops, so a window costs at most two searches per rule.
 */
function firstMatch(rule, re, w) {
    let from = 0;
    for (let tries = 0; tries < 2; tries += 1) {
        let m;
        if (rule.find !== undefined)
            m = rule.find(w.text, from);
        else {
            re.lastIndex = from;
            const r = re.exec(w.text);
            m = r === null ? null : { index: r.index, text: r[0], ...(r[1] !== undefined ? { value: r[1] } : {}) };
        }
        if (m === null)
            return null;
        if (w.cutRight && m.index + m.text.length >= w.text.length)
            return null;
        if (w.cutLeft && m.index === 0) {
            from = 1;
            continue;
        }
        return m;
    }
    return null;
}
/**
 * Scan free text for likely secrets. Returns redacted hits, de-duplicated by
 * (ruleId, line). The raw secret is never included in the output.
 */
export function scanForSecrets(text, options = {}) {
    if (!text)
        return [];
    const minRank = CONFIDENCE_RANK[options.minConfidence ?? 'medium'];
    const allow = (options.allowlist ?? []).map((a) => a.toLowerCase()).filter(Boolean);
    const rules = SECRET_RULES.filter((rule) => CONFIDENCE_RANK[rule.confidence] >= minRank).map((rule) => ({
        rule,
        re: new RegExp(rule.pattern.source, `${rule.pattern.flags.replace(/[gy]/g, '')}g`),
    }));
    const lines = text.split(/\r?\n/);
    const hits = [];
    for (let i = 0; i < lines.length; i++) {
        const rawLine = lines[i];
        if (rawLine === undefined || rawLine.length === 0)
            continue;
        const found = new Map();
        // Every pattern reads one bounded window at a time — the JWT rule's own
        // bounded quantifiers still rely on this: a 200KB single line of
        // `'eyJ-'.repeat(50000)` took ~27s before either fix.
        for (const w of lineWindows(rawLine)) {
            // The allowlist names text near the finding: per window, which for a
            // line of up to 16 KB is the whole line, as before.
            const lower = w.text.toLowerCase();
            if (allow.some((a) => lower.includes(a)))
                continue;
            for (const { rule, re } of rules) {
                if (found.has(rule))
                    continue;
                const hit = judge(rule, firstMatch(rule, re, w), i);
                if (hit !== null)
                    found.set(rule, hit);
            }
        }
        for (const { rule } of rules) {
            const hit = found.get(rule);
            if (hit !== undefined)
                hits.push(hit);
        }
    }
    return hits;
}
/** A match as a hit on line `i` (0-based), or `null` when its value is a placeholder or too plain. */
function judge(rule, m, i) {
    if (!m)
        return null;
    // For the value-capturing rules, the captured group is the credential
    // itself (not the whole match, which includes the key name / URI
    // prefix too); vet it before reporting.
    if (VALUE_CAPTURE_RULES.has(rule.id)) {
        const value = m.value ?? '';
        if (looksLikePlaceholder(value))
            return null;
        // The entropy floor is skipped for the unquoted `.env`-style rule
        // specifically: a human-chosen password (the brief's own example,
        // `DB_PASSWORD=hunter2hunter2`, is ~2.8 bits/char) is real and
        // common in a `.env` file, and routinely falls under 3.2 despite
        // being an actual credential. The other false-positive shapes an
        // entropy floor would catch here are already excluded structurally
        // — the value charset itself rules out `${VAR}`/`<your-key>`/a
        // function call, and `looksLikePlaceholder` still catches
        // `changeme`/repeated-char values — so this rule does not need it.
        if (rule.id !== 'generic-assignment-env' && shannonEntropy(value) < 3.2)
            return null;
    }
    const matched = VALUE_CAPTURE_RULES.has(rule.id) ? (m.value ?? m.text) : m.text;
    return {
        ruleId: rule.id,
        title: rule.title,
        confidence: rule.confidence,
        line: i + 1,
        preview: redact(matched),
    };
}
//# sourceMappingURL=secretScan.js.map