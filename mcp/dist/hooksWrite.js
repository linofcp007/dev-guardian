import { createRequire as __createRequire } from 'node:module'; const require = __createRequire(import.meta.url);
var __defProp = Object.defineProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};

// src/hooks/secretScan.ts
var secretScan_exports = {};
__export(secretScan_exports, {
  SECRET_RULES: () => SECRET_RULES,
  redact: () => redact,
  scanForSecrets: () => scanForSecrets,
  shannonEntropy: () => shannonEntropy
});
var CONFIDENCE_RANK = { medium: 0, high: 1 };
var SECRET_RULES = [
  // ── Cloud / provider tokens (unambiguous shapes → 'high') ────────────────
  { id: "aws-access-key-id", title: "AWS access key ID", confidence: "high", pattern: /\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA)[0-9A-Z]{16}\b/ },
  { id: "aws-secret-access-key", title: "AWS secret access key", confidence: "high", pattern: /\baws_?secret_?access_?key\b["'\s:=]+["']?[A-Za-z0-9/+]{40}\b/i },
  { id: "github-token", title: "GitHub token", confidence: "high", pattern: /\bgh[pousr]_[A-Za-z0-9]{36}\b/ },
  { id: "github-fine-grained-pat", title: "GitHub fine-grained PAT", confidence: "high", pattern: /\bgithub_pat_[A-Za-z0-9_]{82}\b/ },
  { id: "gitlab-pat", title: "GitLab personal access token", confidence: "high", pattern: /\bglpat-[A-Za-z0-9_-]{20}\b/ },
  { id: "slack-token", title: "Slack token", confidence: "high", pattern: /\bxox[baprs]-[A-Za-z0-9-]{10,48}\b/ },
  { id: "slack-webhook", title: "Slack incoming webhook", confidence: "high", pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9_/]{6,}/ },
  { id: "stripe-live-key", title: "Stripe live secret key", confidence: "high", pattern: /\b[rs]k_live_[A-Za-z0-9]{20,}\b/ },
  { id: "google-api-key", title: "Google API key", confidence: "high", pattern: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { id: "google-oauth-token", title: "Google OAuth access token", confidence: "high", pattern: /\bya29\.[0-9A-Za-z_-]{20,}\b/ },
  { id: "anthropic-api-key", title: "Anthropic API key", confidence: "high", pattern: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/ },
  // `(?!ant-)` — an Anthropic key (`sk-ant-…`) otherwise also satisfies this
  // shape (`sk-` + 32+ alnum/hyphen chars) and was reported twice, once under
  // each rule id.
  { id: "openai-api-key", title: "OpenAI API key", confidence: "high", pattern: /\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{32,}\b/ },
  { id: "sendgrid-key", title: "SendGrid API key", confidence: "high", pattern: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/ },
  { id: "npm-token", title: "npm access token", confidence: "high", pattern: /\bnpm_[A-Za-z0-9]{36}\b/ },
  { id: "pypi-token", title: "PyPI upload token", confidence: "high", pattern: /\bpypi-AgEIcHlwaS[A-Za-z0-9_-]{10,}/ },
  { id: "twilio-account-sid", title: "Twilio account SID", confidence: "high", pattern: /\bAC[0-9a-fA-F]{32}\b/ },
  // `PRIVATE KEY BLOCK`: a PGP key's own header — the `PGP ` alternative never
  // matched without it (review 8, item 12).
  { id: "private-key-block", title: "Private key", confidence: "high", pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/ },
  { id: "putty-private-key", title: "PuTTY private key", confidence: "high", pattern: /\bPuTTY-User-Key-File-\d+: / },
  { id: "huggingface-token", title: "Hugging Face token", confidence: "high", pattern: /\bhf_[A-Za-z]{34}\b/ },
  { id: "digitalocean-token", title: "DigitalOcean token", confidence: "high", pattern: /\bdo[opr]_v1_[a-f0-9]{64}\b/ },
  { id: "shopify-token", title: "Shopify access token", confidence: "high", pattern: /\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b/ },
  { id: "azure-storage-key", title: "Azure storage account key", confidence: "high", pattern: /\bAccountKey=[A-Za-z0-9+/]{86}==/ },
  { id: "telegram-bot-token", title: "Telegram bot token", confidence: "high", pattern: /\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b/ },
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
    id: "jwt",
    title: "JSON Web Token (JWT)",
    confidence: "medium",
    pattern: /\beyJ[A-Za-z0-9_-]{8,2000}\.eyJ[A-Za-z0-9_-]{8,2000}\.[A-Za-z0-9_-]{8,2000}\b/,
    find: (text, from) => findJwt(text, from),
    // At most 3 + 2000 + 4 + 2000 + 1 + 2000 characters: 8 KB holds any of
    // them, where the 2 KB every other rule shares did not (round 3, item 6).
    overlap: 8 * 1024
  },
  {
    id: "generic-assignment",
    title: "Hard-coded credential",
    confidence: "medium",
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
    pattern: /(?<![A-Za-z0-9])(?:api[_-]?key|secret(?:[_-]?key)?|access[_-]?token|auth[_-]?token|client[_-]?secret|passwd|password|private[_-]?key|token)["'`]?\s*[:=]\s*["'`]([^"'`]{12,})["'`]/i
  },
  {
    id: "generic-assignment-camel",
    title: "Hard-coded credential",
    confidence: "medium",
    // camelCase key (stripeSecretKey, dbPassword, githubToken) assigned a
    // quoted value. Case-SENSITIVE and gated on a lowercase letter right
    // before the capitalised keyword (the camelCase boundary itself) —
    // deliberately not folded into the rule above via a case-insensitive
    // flag: that would also match the keyword in the MIDDLE of an ordinary
    // lowercase word ("monkey", "donkey" both contain "key") with nothing to
    // tell a real name boundary from a coincidence.
    pattern: /(?<=[a-z])(?:ApiKey|SecretKey|Secret|AccessToken|AuthToken|ClientSecret|Passwd|Password|PrivateKey|Token)["'`]?\s*[:=]\s*["'`]([^"'`]{12,})["'`]/
  },
  {
    id: "generic-assignment-env",
    title: "Hard-coded credential",
    confidence: "medium",
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
    find: (text, from) => findEnvAssignment(text, from)
  },
  {
    id: "bearer-token",
    title: "Bearer token in an Authorization header",
    confidence: "medium",
    // `Authorization: Bearer <token>` written into a file — a curl line, a
    // .http request, a test fixture (review 8, item 12). The token is vetted
    // like the other captured values (placeholders, entropy).
    pattern: /\bAuthorization\s*:\s*Bearer\s+([A-Za-z0-9._~+/-]{20,}=*)/i
  },
  {
    id: "yaml-credential",
    title: "Hard-coded credential",
    confidence: "medium",
    // An unquoted YAML value (`password: Zx9…`) on a line of its own — the
    // quoted rules need quotes and the `.env` rule an `=` (review 8, item
    // 12). The value must hold a digit and a letter, so a type annotation
    // (`token: AccessToken`) or a reference (`password: ${DB_PASS}`) is not one.
    pattern: /^\s*(?:[\w-]*[_-])?(?:api[_-]?key|secret(?:[_-]?key)?|access[_-]?token|auth[_-]?token|client[_-]?secret|passwd|password|private[_-]?key|token)\s*:\s*([^\s'"`#{}[\]$<>(),;|&*!%@]{8,})\s*$/i
  },
  {
    id: "uri-credentials",
    title: "Credentials embedded in a URI",
    confidence: "medium",
    // scheme://user:password@host — postgres://user:pass@host/db and the like.
    // The scheme is at most 32 characters (`mongodb+srv` is 11): unbounded,
    // every word start of a long `a-a-a-…` run rescanned the rest of it — up
    // to 0.5 s a window (review I3).
    pattern: /\b[a-z][a-z0-9+.-]{0,31}:\/\/[^\s/:@]+:([^\s/:@]{3,})@[^\s/'"]+/i
  }
];
function isB64url(c) {
  return c >= 48 && c <= 57 || c >= 65 && c <= 90 || c >= 97 && c <= 122 || c === 95 || c === 45;
}
function isWordChar(c) {
  return c >= 48 && c <= 57 || c >= 65 && c <= 90 || c >= 97 && c <= 122 || c === 95;
}
function isBoundary(text, at) {
  const before = at > 0 && isWordChar(text.charCodeAt(at - 1));
  const after = at < text.length && isWordChar(text.charCodeAt(at));
  return before !== after;
}
function runEnds(text, inClass) {
  const cached = RUN_ENDS.get(inClass);
  if (cached !== void 0 && cached.text === text) return cached.end;
  const ends = new Int32Array(text.length + 1);
  ends[text.length] = text.length;
  for (let i = text.length - 1; i >= 0; i -= 1) ends[i] = inClass(text.charCodeAt(i)) ? ends[i + 1] ?? i : i;
  const end = (i) => i >= text.length ? text.length : ends[i] ?? i;
  RUN_ENDS.set(inClass, { text, end });
  return end;
}
var RUN_ENDS = /* @__PURE__ */ new Map();
function findJwt(text, from) {
  if (!text.includes(".eyJ", from)) return null;
  const end = runEnds(text, isB64url);
  let lastThird = -1;
  let lastThirdEnd = -1;
  for (let p = text.indexOf("eyJ", from); p >= 0; p = text.indexOf("eyJ", p + 1)) {
    if (p > 0 && isWordChar(text.charCodeAt(p - 1))) continue;
    const e1 = end(p + 3);
    const l1 = e1 - (p + 3);
    if (l1 < 8 || l1 > 2e3 || !text.startsWith(".eyJ", e1)) continue;
    const q = e1 + 4;
    const e2 = end(q);
    const l2 = e2 - q;
    if (l2 < 8 || l2 > 2e3 || text.charCodeAt(e2) !== 46) continue;
    const r = e2 + 1;
    if (r !== lastThird) {
      lastThird = r;
      lastThirdEnd = -1;
      const longest = Math.min(end(r) - r, 2e3);
      for (let x = r + longest; x >= r + 8; x -= 1) {
        if (isBoundary(text, x)) {
          lastThirdEnd = x;
          break;
        }
      }
    }
    if (lastThirdEnd >= 0) return { index: p, text: text.slice(p, lastThirdEnd) };
  }
  return null;
}
var ENV_KEY = /(?<![A-Za-z0-9])(?:api[_-]?key|secret(?:[_-]?key)?|access[_-]?token|auth[_-]?token|client[_-]?secret|passwd|password|private[_-]?key|token)\s*=\s*/gi;
function isEnvValueChar(c) {
  return !(c === 32 || c >= 9 && c <= 13 || c === 160 || c === 5760 || c >= 8192 && c <= 8202 || c === 8232 || c === 8233 || c === 8239 || c === 8287 || c === 12288 || c === 65279 || c === 34 || c === 39 || c === 96 || c === 36 || c === 123 || c === 125 || c === 60 || c === 62 || c === 40 || c === 41);
}
function findEnvAssignment(text, from) {
  if (!text.includes("=", from)) return null;
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
var VALUE_CAPTURE_RULES = /* @__PURE__ */ new Set([
  "generic-assignment",
  "generic-assignment-camel",
  "generic-assignment-env",
  "uri-credentials",
  "bearer-token",
  "yaml-credential"
]);
var QUOTED_VALUE_RULES = /* @__PURE__ */ new Set(["generic-assignment", "generic-assignment-camel"]);
var TOKEN_PLACEHOLDER_MARKERS = [
  "example",
  "xxxxx",
  "your-",
  "your_",
  "yourkey",
  "yourtoken",
  "placeholder",
  "changeme",
  "change-me",
  "redacted",
  "dummy",
  "sample",
  "fake",
  "notreal",
  "not-real",
  "replace",
  "insert",
  "<your"
];
var MIXED_TOKEN_RULES = /* @__PURE__ */ new Set(["openai-api-key", "anthropic-api-key", "huggingface-token"]);
function tokenIsPlaceholder(ruleId, token) {
  const lower = token.toLowerCase();
  if (TOKEN_PLACEHOLDER_MARKERS.some((m) => lower.includes(m))) return true;
  if (/(.)\1{7,}/.test(token)) return true;
  if (MIXED_TOKEN_RULES.has(ruleId)) {
    const body = token.replace(/^(?:sk-(?:ant-|proj-|svcacct-|admin-)?|hf_)/, "");
    if (ruleId === "huggingface-token") return !(/[a-z]/.test(body) && /[A-Z]/.test(body));
    return !(/[0-9]/.test(body) && /[A-Z]/.test(body) && /[a-z]/.test(body));
  }
  return false;
}
var PLACEHOLDER_MARKERS = [
  "example",
  "changeme",
  "change-me",
  "placeholder",
  "your-",
  "your_",
  "yourkey",
  "yourtoken",
  "redacted",
  "dummy",
  "sample",
  "xxxxx",
  "test-token",
  "fake",
  "notreal",
  "<your",
  "${",
  "{{",
  "env.",
  "process.env",
  "os.environ"
];
function shannonEntropy(s) {
  if (s.length === 0) return 0;
  const freq = /* @__PURE__ */ new Map();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let h = 0;
  for (const count of freq.values()) {
    const p = count / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}
function looksLikePlaceholder(value) {
  const lower = value.toLowerCase();
  if (PLACEHOLDER_MARKERS.some((m) => lower.includes(m))) return true;
  if (/^(.)\1{6,}$/.test(value)) return true;
  return false;
}
function redact(secret) {
  const trimmed = secret.trim();
  const head = trimmed.slice(0, 4);
  const tail = trimmed.length >= 16 ? trimmed.slice(-2) : "";
  return `${head}\u2026${tail} (${trimmed.length})`;
}
var WINDOW = 16 * 1024;
var OVERLAP = 2 * 1024;
function lineWindows(line, overlap = OVERLAP) {
  if (line.length <= WINDOW) return [{ text: line, cutLeft: false, cutRight: false }];
  const out = [];
  for (let s = 0; ; s += WINDOW - overlap) {
    const e = Math.min(line.length, s + WINDOW);
    const from = Math.max(0, s - 1);
    const to = Math.min(line.length, e + 1);
    out.push({ text: line.slice(from, to), cutLeft: from > 0, cutRight: to < line.length });
    if (e >= line.length) return out;
  }
}
function firstMatch(rule, re, w, start = 0) {
  let from = start;
  for (let tries = 0; tries < 2; tries += 1) {
    let m;
    if (rule.find !== void 0) m = rule.find(w.text, from);
    else {
      re.lastIndex = from;
      const r = re.exec(w.text);
      m = r === null ? null : { index: r.index, text: r[0], ...r[1] !== void 0 ? { value: r[1] } : {} };
    }
    if (m === null) return null;
    if (w.cutRight && m.index + m.text.length >= w.text.length) return null;
    if (w.cutLeft && m.index === 0) {
      from = 1;
      continue;
    }
    return m;
  }
  return null;
}
function firstHit(rule, re, w, line, skipPlaceholders) {
  let start = 0;
  while (start <= w.text.length) {
    const m = firstMatch(rule, re, w, start);
    if (m === null) return null;
    const hit = judge(rule, m, line, skipPlaceholders);
    if (hit !== null) return hit;
    start = Math.max(start + 1, m.index + Math.max(1, m.text.length));
  }
  return null;
}
function scanForSecrets(text, options = {}) {
  if (!text) return [];
  const minRank = CONFIDENCE_RANK[options.minConfidence ?? "medium"];
  const skipPlaceholders = options.skipPlaceholders !== false;
  const allow = (options.allowlist ?? []).map((a) => a.toLowerCase()).filter(Boolean);
  const rules = SECRET_RULES.filter((rule) => CONFIDENCE_RANK[rule.confidence] >= minRank).map((rule) => ({
    rule,
    re: new RegExp(rule.pattern.source, `${rule.pattern.flags.replace(/[gy]/g, "")}g`)
  }));
  const byOverlap = /* @__PURE__ */ new Map();
  for (const r of rules) {
    const overlap = r.rule.overlap ?? OVERLAP;
    byOverlap.set(overlap, [...byOverlap.get(overlap) ?? [], r]);
  }
  const lines = text.split(/\r?\n/);
  const hits = [];
  for (let i = 0; i < lines.length; i++) {
    const rawLine = lines[i];
    if (rawLine === void 0 || rawLine.length === 0) continue;
    const found = /* @__PURE__ */ new Map();
    for (const [overlap, group] of byOverlap) {
      for (const w of lineWindows(rawLine, overlap)) {
        const lower = w.text.toLowerCase();
        if (allow.some((a) => lower.includes(a))) continue;
        for (const { rule, re } of group) {
          if (found.has(rule)) continue;
          const hit = firstHit(rule, re, w, i, skipPlaceholders);
          if (hit !== null) found.set(rule, hit);
        }
      }
    }
    for (const { rule } of rules) {
      const hit = found.get(rule);
      if (hit !== void 0) hits.push(hit);
    }
  }
  return hits;
}
function judge(rule, m, i, skipPlaceholders = true) {
  if (!m) return null;
  if (skipPlaceholders && !VALUE_CAPTURE_RULES.has(rule.id) && rule.id !== "jwt" && rule.id !== "private-key-block" && rule.id !== "putty-private-key") {
    if (tokenIsPlaceholder(rule.id, m.text)) return null;
  }
  if (VALUE_CAPTURE_RULES.has(rule.id)) {
    const value = m.value ?? "";
    if (looksLikePlaceholder(value)) return null;
    if (skipPlaceholders && QUOTED_VALUE_RULES.has(rule.id) && /\s\S*\s/.test(value)) return null;
    if (rule.id === "yaml-credential" && !(/\d/.test(value) && /[A-Za-z]/.test(value))) return null;
    if (rule.id !== "generic-assignment-env" && shannonEntropy(value) < 3.2) return null;
  }
  const matched = VALUE_CAPTURE_RULES.has(rule.id) ? m.value ?? m.text : m.text;
  return {
    ruleId: rule.id,
    title: rule.title,
    confidence: rule.confidence,
    line: i + 1,
    preview: redact(matched)
  };
}

// src/hooks/settingsGuard.ts
var settingsGuard_exports = {};
__export(settingsGuard_exports, {
  applyEdit: () => applyEdit,
  hookLooseningSettings: () => hookLooseningSettings,
  isClaudeSettingsPath: () => isClaudeSettingsPath,
  newlyLoosened: () => newlyLoosened
});
function isClaudeSettingsPath(path, configDir) {
  if (/(?:^|[\\/])\.claude[\\/]settings(?:\.local)?\.json$/i.test(path)) return true;
  if (configDir === void 0 || configDir.trim() === "") return false;
  const fold = process.platform === "win32";
  const m = (fold ? /^(.*)[\\/](settings(?:\.local)?\.json)$/i : /^(.*)\/(settings(?:\.local)?\.json)$/).exec(path);
  if (m === null) return false;
  const norm = (p) => {
    const t = p.replace(/\\/g, "/").replace(/\/+$/, "");
    return fold ? t.toLowerCase() : t;
  };
  return norm(m[1] ?? "") === norm(configDir);
}
var ENV_SWITCHES = [
  { name: "GUARDIAN_HOOKS", off: ["off"] },
  { name: "GUARDIAN_HOOKS_BASH_BLOCK", off: ["0", "false"] },
  { name: "GUARDIAN_PKG_VET", off: ["0"] }
];
function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
var OUR_PLUGIN = /dev-guardian/i;
function fromObject(settings) {
  const found = [];
  if (settings["disableAllHooks"] === true) found.push("disableAllHooks: true");
  const env = settings["env"];
  if (isPlainObject(env)) {
    for (const [key, value] of Object.entries(env)) {
      const sw = ENV_SWITCHES.find((s) => s.name === key.toUpperCase());
      if (sw !== void 0 && sw.off.includes(String(value))) found.push(`env ${sw.name}=${String(value)}`);
    }
  }
  const plugins = settings["enabledPlugins"];
  if (isPlainObject(plugins)) {
    for (const [id, enabled] of Object.entries(plugins)) {
      if (enabled === false && OUR_PLUGIN.test(id)) found.push(`enabledPlugins ${id}=false`);
    }
  }
  return found;
}
var TEXT_PATTERNS = [
  { label: "disableAllHooks: true", re: /"disableAllHooks"\s*:\s*true\b/ },
  { label: "env GUARDIAN_HOOKS=off", re: /"GUARDIAN_HOOKS"\s*:\s*"off"/i },
  { label: "env GUARDIAN_HOOKS_BASH_BLOCK=0", re: /"GUARDIAN_HOOKS_BASH_BLOCK"\s*:\s*(?:"0"|0\b)/i },
  { label: "env GUARDIAN_HOOKS_BASH_BLOCK=false", re: /"GUARDIAN_HOOKS_BASH_BLOCK"\s*:\s*(?:"false"|false\b)/i },
  { label: "env GUARDIAN_PKG_VET=0", re: /"GUARDIAN_PKG_VET"\s*:\s*(?:"0"|0\b)/i }
];
var PLUGIN_OFF = /"([^"\n]*dev-guardian[^"\n]*)"\s*:\s*false\b/gi;
function fromText(text) {
  const found = TEXT_PATTERNS.filter((p) => p.re.test(text)).map((p) => p.label);
  for (const m of text.matchAll(PLUGIN_OFF)) found.push(`enabledPlugins ${m[1] ?? ""}=false`);
  return found;
}
function hookLooseningSettings(content) {
  const text = content.charCodeAt(0) === 65279 ? content.slice(1) : content;
  try {
    const parsed = JSON.parse(text);
    if (isPlainObject(parsed)) return fromObject(parsed);
  } catch {
  }
  return fromText(text);
}
function newlyLoosened(before, after) {
  const had = new Set(before === void 0 ? [] : hookLooseningSettings(before));
  return hookLooseningSettings(after).filter((label) => !had.has(label));
}
function applyEdit(content, oldString, newString, replaceAll = false) {
  if (oldString === "") return void 0;
  if (replaceAll) return content.includes(oldString) ? content.split(oldString).join(newString) : void 0;
  const at = content.indexOf(oldString);
  return at < 0 ? void 0 : content.slice(0, at) + newString + content.slice(at + oldString.length);
}

// src/hooks/dataRegistry.ts
var dataRegistry_exports = {};
__export(dataRegistry_exports, {
  registryDir: () => registryDir,
  userDataDir: () => userDataDir2,
  writesRegistry: () => writesRegistry
});
import { readdirSync } from "node:fs";
import { homedir as homedir2 } from "node:os";
import { isAbsolute as isAbsolute3, join as join4, parse as parse3, relative as relative2, resolve as resolve3 } from "node:path";

// src/hooks/configFile.ts
import { closeSync, constants, fstatSync, lstatSync, openSync, readlinkSync, readSync } from "node:fs";
import { isAbsolute, join, parse, relative, resolve } from "node:path";
var MAX_HOOK_CONFIG_BYTES = 64 * 1024;
var OPEN_FLAGS = constants.O_RDONLY | (constants.O_NONBLOCK ?? 0);
var MAX_LINK_HOPS = 32;
function isRemoteOrDeviceTarget(target) {
  return /^(?:[\\/]{2}|\\\?\?\\)/.test(target);
}
function isNetworkPath(path) {
  if (!/^(?:[\\/]{2}|\\\?\?\\)/.test(path)) return false;
  return !/^(?:[\\/]{2}[?.]|\\\?\?)[\\/][A-Za-z]:(?:[\\/]|$)/.test(path);
}
function localShareAsLocal(path, hostname2 = "") {
  const m = /^[\\/]{2}(?:\?[\\/]UNC[\\/])?([^\\/]+)[\\/]([A-Za-z])\$(?=[\\/]|$)(.*)$/i.exec(path);
  if (m === null) return void 0;
  const host = (m[1] ?? "").toLowerCase().replace(/^\[|\]$/g, "");
  const local = ["localhost", "127.0.0.1", "::1", "0:0:0:0:0:0:0:1"].includes(host) || hostname2 !== "" && host === hostname2.toLowerCase();
  if (!local) return void 0;
  const rest = m[3] ?? "";
  return `${(m[2] ?? "").toUpperCase()}:${rest === "" ? "\\" : rest}`;
}
function walkLinksUnder(under, path) {
  const rel = relative(resolve(under), resolve(path));
  if (rel === "" || rel.startsWith("..") || isAbsolute(rel)) return { ok: true };
  let current = resolve(under);
  const queue = rel.split(/[\\/]+/).filter((p) => p.length > 0);
  let hops = 0;
  for (let part = queue.shift(); part !== void 0; part = queue.shift()) {
    if (part === ".") continue;
    if (part === "..") {
      current = resolve(current, "..");
      continue;
    }
    const next = join(current, part);
    let isLink;
    try {
      isLink = lstatSync(next).isSymbolicLink();
    } catch {
      return { ok: true };
    }
    if (!isLink) {
      current = next;
      continue;
    }
    hops += 1;
    if (hops > MAX_LINK_HOPS) return { ok: false, reason: "unreadable", at: next };
    let target;
    try {
      target = readlinkSync(next);
    } catch {
      return { ok: false, reason: "unreadable", at: next };
    }
    if (isRemoteOrDeviceTarget(target)) return { ok: false, reason: "remote-link", at: next };
    const resolved = resolve(current, target);
    const root = parse(resolved).root;
    queue.unshift(...resolved.slice(root.length).split(/[\\/]+/).filter((p) => p.length > 0));
    current = root;
  }
  return { ok: true };
}

// src/hooks/guardedPath.ts
import { realpathSync, statSync } from "node:fs";
import { hostname } from "node:os";
import { basename, dirname, join as join2, parse as parse2 } from "node:path";
function safeHostname() {
  try {
    return hostname();
  } catch {
    return "";
  }
}
function windowsSegment(segment, trim) {
  if (segment === "" || segment === "." || segment === "..") return segment;
  const colon = segment.indexOf(":");
  let named = colon < 0 ? segment : segment.slice(0, colon);
  if (trim) {
    const trimmed = named.replace(/[. ]+$/, "");
    if (trimmed !== "") named = trimmed;
  }
  return named === "" ? segment : named;
}
function windowsName(path) {
  if (!/[:. ]/.test(path)) return path;
  const device = /^[\\/]{2}[?.][\\/]/.test(path);
  const prefix = /^(?:[\\/]{2}[?.][\\/])?(?:[A-Za-z]:)?/.exec(path)?.[0] ?? "";
  const parts = path.slice(prefix.length).split(/([\\/]+)/);
  return prefix + parts.map((part, i) => i % 2 === 1 ? part : windowsSegment(part, !device)).join("");
}
function resolveExisting(abs, realpath) {
  const root = parse2(abs).root;
  if (root === "" || !walkLinksUnder(root, abs).ok) return abs;
  const rest = [];
  let head = abs;
  for (let i = 0; i < 512; i += 1) {
    try {
      const real = realpath(head);
      return rest.length === 0 ? real : join2(real, ...rest.reverse());
    } catch {
      const parent = dirname(head);
      if (parent === head) return abs;
      rest.push(basename(head));
      head = parent;
    }
  }
  return abs;
}
function fileIdentity(abs) {
  if (isNetworkPath(abs)) return void 0;
  try {
    const root = parse2(abs).root;
    if (root === "" || !walkLinksUnder(root, abs).ok) return void 0;
    const s = statSync(abs, { bigint: true });
    return s.isFile() ? { dev: s.dev, ino: s.ino, nlink: s.nlink } : void 0;
  } catch {
    return void 0;
  }
}
function hardLinkedTo(abs, guarded) {
  const id = fileIdentity(abs);
  if (id === void 0 || id.nlink < 2n) return void 0;
  return guarded.find((g) => {
    const other = fileIdentity(g);
    return other !== void 0 && other.dev === id.dev && other.ino === id.ino;
  });
}
function guardedPath(abs, opts = {}) {
  const win = (opts.platform ?? process.platform) === "win32";
  let named = win ? windowsName(abs) : abs;
  if (win && isNetworkPath(named)) {
    const local = localShareAsLocal(named, opts.hostname ?? safeHostname());
    if (local === void 0) return named;
    named = windowsName(local);
  }
  try {
    return resolveExisting(named, opts.realpath ?? realpathSync.native);
  } catch {
    return named;
  }
}

// src/hooks/userDataDir.ts
import { homedir } from "node:os";
import { isAbsolute as isAbsolute2, join as join3, resolve as resolve2 } from "node:path";
function userDataDir(ctx = {}) {
  const env = ctx.env ?? process.env;
  const override = env["GUARDIAN_DATA_DIR"]?.trim();
  if (override !== void 0 && override !== "") return resolve2(override);
  const home = () => ctx.home ?? homedir();
  if ((ctx.platform ?? process.platform) === "win32") {
    const local = env["LOCALAPPDATA"]?.trim();
    return join3(local !== void 0 && isAbsolute2(local) ? local : join3(home(), "AppData", "Local"), "dev-guardian");
  }
  const xdg = env["XDG_DATA_HOME"]?.trim();
  return join3(xdg !== void 0 && isAbsolute2(xdg) ? xdg : join3(home(), ".local", "share"), "dev-guardian");
}

// src/hooks/dataRegistry.ts
function safeHome() {
  try {
    return homedir2();
  } catch {
    return "";
  }
}
function userDataDir2(ctx = {}) {
  return userDataDir({ ...ctx, home: ctx.home ?? safeHome() });
}
function registryDir(ctx = {}) {
  return join4(userDataDir2(ctx), "registry");
}
function atOrBelow(dir, path) {
  const rel = relative2(dir, path);
  return rel === "" || !rel.startsWith("..") && !isAbsolute3(rel);
}
var MAX_ENTRIES = 1024;
function filesIn(dir) {
  try {
    const root = parse3(dir).root;
    if (root === "" || !walkLinksUnder(root, dir).ok) return [];
    return readdirSync(dir).slice(0, MAX_ENTRIES).map((name) => join4(dir, name));
  } catch {
    return [];
  }
}
function writesRegistry(abs, ctx = {}) {
  const opts = ctx.platform === void 0 ? {} : { platform: ctx.platform };
  const registry = guardedPath(resolve3(registryDir(ctx)), opts);
  const target = guardedPath(resolve3(abs), opts);
  if (atOrBelow(registry, target)) return true;
  if (isNetworkPath(target)) return /(?:appdata[\\/]local|\.local[\\/]share)[\\/]dev-guardian[\\/]registry(?:[\\/]|$)/i.test(target);
  const id = fileIdentity(target);
  if (id === void 0 || id.nlink < 2n) return false;
  return hardLinkedTo(target, filesIn(registry)) !== void 0;
}
export {
  dataRegistry_exports as dataRegistry,
  secretScan_exports as secretScan,
  settingsGuard_exports as settingsGuard
};
