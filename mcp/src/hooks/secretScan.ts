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

export type SecretConfidence = 'high' | 'medium';

export interface SecretRule {
  id: string;
  title: string;
  confidence: SecretConfidence;
  pattern: RegExp;
}

export interface SecretHit {
  ruleId: string;
  title: string;
  confidence: SecretConfidence;
  /** 1-based line within the scanned text. */
  line: number;
  /** Redacted preview — never the raw secret. e.g. "AKIA…IGb3 (20)". */
  preview: string;
}

export interface SecretScanOptions {
  /**
   * Case-insensitive substrings. A candidate line containing any of these is
   * skipped — the project's allowlist for known false positives / fixtures.
   */
  allowlist?: string[];
  /** Report hits at this confidence or above. Default 'medium'. */
  minConfidence?: SecretConfidence;
}

const CONFIDENCE_RANK: Record<SecretConfidence, number> = { medium: 0, high: 1 };

/**
 * High-precision, provider-specific credential shapes. Order matters only for
 * reporting; every rule is tried against every line.
 */
export const SECRET_RULES: SecretRule[] = [
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
  // per-line cap below, which bounds input size itself.
  { id: 'jwt', title: 'JSON Web Token (JWT)', confidence: 'medium', pattern: /\beyJ[A-Za-z0-9_-]{8,2000}\.eyJ[A-Za-z0-9_-]{8,2000}\.[A-Za-z0-9_-]{8,2000}\b/ },
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
    pattern:
      /(?<![A-Za-z0-9])(?:api[_-]?key|secret(?:[_-]?key)?|access[_-]?token|auth[_-]?token|client[_-]?secret|passwd|password|private[_-]?key|token)["'`]?\s*[:=]\s*["'`]([^"'`]{12,})["'`]/i,
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
    pattern:
      /(?<=[a-z])(?:ApiKey|SecretKey|Secret|AccessToken|AuthToken|ClientSecret|Passwd|Password|PrivateKey|Token)["'`]?\s*[:=]\s*["'`]([^"'`]{12,})["'`]/,
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
    pattern:
      /(?<![A-Za-z0-9])(?:api[_-]?key|secret(?:[_-]?key)?|access[_-]?token|auth[_-]?token|client[_-]?secret|passwd|password|private[_-]?key|token)\s*=\s*([^\s"'`${}<>()]{8,})(?=\s|$)/i,
  },
  {
    id: 'uri-credentials',
    title: 'Credentials embedded in a URI',
    confidence: 'medium',
    // scheme://user:password@host — postgres://user:pass@host/db and the like.
    pattern: /\b[a-z][a-z0-9+.-]*:\/\/[^\s/:@]+:([^\s/:@]{3,})@[^\s/'"]+/i,
  },
];

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
export function shannonEntropy(s: string): number {
  if (s.length === 0) return 0;
  const freq = new Map<string, number>();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let h = 0;
  for (const count of freq.values()) {
    const p = count / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

function looksLikePlaceholder(value: string): boolean {
  const lower = value.toLowerCase();
  if (PLACEHOLDER_MARKERS.some((m) => lower.includes(m))) return true;
  // All-same-char or trivially repetitive (e.g. "aaaaaaaaaaaa", "xxxxxxxx").
  if (/^(.)\1{6,}$/.test(value)) return true;
  return false;
}

/**
 * Redact a secret to a short, safe preview that reveals only its shape.
 * Below 16 characters, only the 4-character head is shown (no tail) — a
 * secret that short is barely obscured by 6 of its ~12 characters, which is
 * what the old `length > 12` threshold revealed for anything 13-15 chars
 * long. 16+ still gets a head and a 2-character tail, unchanged.
 */
export function redact(secret: string): string {
  const trimmed = secret.trim();
  const head = trimmed.slice(0, 4);
  const tail = trimmed.length >= 16 ? trimmed.slice(-2) : '';
  return `${head}…${tail} (${trimmed.length})`;
}

/** Each scanned line is capped here — see the module doc's ReDoS note in
 *  `bashGuard.ts`, which this mirrors. */
const MAX_LINE_LENGTH = 16 * 1024;

/**
 * Scan free text for likely secrets. Returns redacted hits, de-duplicated by
 * (ruleId, line). The raw secret is never included in the output.
 */
export function scanForSecrets(text: string, options: SecretScanOptions = {}): SecretHit[] {
  if (!text) return [];
  const minRank = CONFIDENCE_RANK[options.minConfidence ?? 'medium'];
  const allow = (options.allowlist ?? []).map((a) => a.toLowerCase()).filter(Boolean);
  const lines = text.split(/\r?\n/);
  const hits: SecretHit[] = [];
  const seen = new Set<string>();

  for (let i = 0; i < lines.length; i++) {
    const rawLine = lines[i];
    if (rawLine === undefined || rawLine.length === 0) continue;
    // Bounds every pattern below to a fixed-size worst case regardless of how
    // long the real line is — the JWT rule's own bounded quantifiers still
    // rely on this: a 200KB single line of `'eyJ-'.repeat(50000)` took ~27s
    // before either fix, and this alone caps the input the regex ever sees.
    const line = rawLine.length > MAX_LINE_LENGTH ? rawLine.slice(0, MAX_LINE_LENGTH) : rawLine;
    const lowerLine = line.toLowerCase();
    if (allow.some((a) => lowerLine.includes(a))) continue;

    for (const rule of SECRET_RULES) {
      if (CONFIDENCE_RANK[rule.confidence] < minRank) continue;
      const re = new RegExp(rule.pattern.source, rule.pattern.flags.replace('g', ''));
      const m = re.exec(line);
      if (!m) continue;

      // For the value-capturing rules, the captured group is the credential
      // itself (not the whole match, which includes the key name / URI
      // prefix too); vet it before reporting.
      if (VALUE_CAPTURE_RULES.has(rule.id)) {
        const value = m[1] ?? '';
        if (looksLikePlaceholder(value)) continue;
        // The entropy floor is skipped for the unquoted `.env`-style rule
        // specifically: a human-chosen password (the brief's own example,
        // `DB_PASSWORD=hunter2hunter2`, is ~2.8 bits/char) is real and
        // common in a `.env` file, and routinely falls under 3.2 despite
        // being an actual credential. The other false-positive shapes an
        // entropy floor would catch here are already excluded structurally
        // — the value charset itself rules out `${VAR}`/`<your-key>`/a
        // function call, and `looksLikePlaceholder` still catches
        // `changeme`/repeated-char values — so this rule does not need it.
        if (rule.id !== 'generic-assignment-env' && shannonEntropy(value) < 3.2) continue;
      }

      const dedupeKey = `${rule.id}:${i}`;
      if (seen.has(dedupeKey)) continue;
      seen.add(dedupeKey);

      const matched = VALUE_CAPTURE_RULES.has(rule.id) ? (m[1] ?? m[0]) : m[0];
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
