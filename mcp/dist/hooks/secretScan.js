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
    { id: 'openai-api-key', title: 'OpenAI API key', confidence: 'high', pattern: /\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b/ },
    { id: 'sendgrid-key', title: 'SendGrid API key', confidence: 'high', pattern: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/ },
    { id: 'npm-token', title: 'npm access token', confidence: 'high', pattern: /\bnpm_[A-Za-z0-9]{36}\b/ },
    { id: 'pypi-token', title: 'PyPI upload token', confidence: 'high', pattern: /\bpypi-AgEIcHlwaS[A-Za-z0-9_-]{10,}/ },
    { id: 'twilio-account-sid', title: 'Twilio account SID', confidence: 'high', pattern: /\bAC[0-9a-fA-F]{32}\b/ },
    { id: 'private-key-block', title: 'Private key', confidence: 'high', pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----/ },
    // ── Heuristics (ambiguous → 'medium', warn only) ─────────────────────────
    { id: 'jwt', title: 'JSON Web Token (JWT)', confidence: 'medium', pattern: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/ },
    {
        id: 'generic-assignment',
        title: 'Hard-coded credential',
        confidence: 'medium',
        // name like api_key/secret/token/password/passwd assigned a quoted value.
        pattern: /\b(?:api[_-]?key|secret(?:[_-]?key)?|access[_-]?token|auth[_-]?token|client[_-]?secret|passwd|password|private[_-]?key|token)\b\s*[:=]\s*["'`]([^"'`]{12,})["'`]/i,
    },
];
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
/** Redact a secret to a short, safe preview that reveals only its shape. */
export function redact(secret) {
    const trimmed = secret.trim();
    const head = trimmed.slice(0, 4);
    const tail = trimmed.length > 12 ? trimmed.slice(-2) : '';
    return `${head}…${tail} (${trimmed.length})`;
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
    const lines = text.split(/\r?\n/);
    const hits = [];
    const seen = new Set();
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (line === undefined || line.length === 0)
            continue;
        const lowerLine = line.toLowerCase();
        if (allow.some((a) => lowerLine.includes(a)))
            continue;
        for (const rule of SECRET_RULES) {
            if (CONFIDENCE_RANK[rule.confidence] < minRank)
                continue;
            const re = new RegExp(rule.pattern.source, rule.pattern.flags.replace('g', ''));
            const m = re.exec(line);
            if (!m)
                continue;
            // For the generic rule, the captured group is the value; vet it.
            if (rule.id === 'generic-assignment') {
                const value = m[1] ?? '';
                if (looksLikePlaceholder(value))
                    continue;
                if (shannonEntropy(value) < 3.2)
                    continue;
            }
            const dedupeKey = `${rule.id}:${i}`;
            if (seen.has(dedupeKey))
                continue;
            seen.add(dedupeKey);
            const matched = rule.id === 'generic-assignment' ? (m[1] ?? m[0]) : m[0];
            hits.push({
                ruleId: rule.id,
                title: rule.title,
                confidence: rule.confidence,
                line: i + 1,
                preview: redact(matched),
            });
        }
    }
    return hits;
}
//# sourceMappingURL=secretScan.js.map