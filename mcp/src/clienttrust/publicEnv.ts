/**
 * Secrets behind a browser-exposed environment prefix, read in the project's
 * `.env*` files — the half of "trusting the client" a Semgrep rule cannot
 * see. `configs/semgrep/client-trust.yml` (`client-public-env-secret`) reads
 * the same names where code uses them (`process.env.X`, `import.meta.env.X`,
 * `$env/static/public`); this reads where they are SET, including the files
 * git ignores (`.env.local`, where they usually live), and judges the VALUE
 * too: a Stripe live key or a Supabase service-role JWT in
 * `NEXT_PUBLIC_SUPABASE_ANON_KEY` is caught by what it is, whatever its name.
 *
 * Every bundler named here writes a variable with its prefix into the
 * JavaScript the browser downloads (Next.js `NEXT_PUBLIC_`, Vite `VITE_`,
 * Expo `EXPO_PUBLIC_`, Create React App `REACT_APP_`, Nuxt `NUXT_PUBLIC_`,
 * Gatsby `GATSBY_`, Vue CLI `VUE_APP_`, SvelteKit and Astro `PUBLIC_`): its
 * value is public the moment the app is built with it.
 *
 * Public by design, never flagged: the Supabase anon / publishable key (an
 * `anon` JWT, `sb_publishable_…`), Stripe's `pk_…`, a Firebase web config
 * (`AIza…`, which Google's own rule calls an API key), a Twilio account SID.
 *
 * Privacy: a value is read in memory to be judged and never leaves this
 * module — a finding names the variable, the file, the line and the KIND of
 * secret ("a Stripe live secret key"), never the value or a preview of it.
 * The rule id names a secret, so the finding is a credential finding
 * (`fingerprint/findingIdentity.ts#isCredentialFinding`): its identity never
 * hashes the line, and no snippet is stored.
 *
 * Pure: text in, findings out. Finding the files is `clientTrustPass.ts`'s.
 */

import { scanForSecrets, shannonEntropy } from '../hooks/secretScan.js';
import { makeFinding } from '../runners/scannerParsers/index.js';
import type { Finding, Severity } from '../types.js';

/** The `tool` of every finding this module and `supabaseRls.ts` make, and their `tools_run` name. */
export const CLIENT_TRUST_TOOL = 'guardian-client-trust';

/** The rule id of a secret behind a browser prefix in an env file. */
export const ENV_PUBLIC_SECRET_RULE = 'client-env-public-secret';

/**
 * A browser-exposed variable whose NAME says secret — the same expression as
 * `client-public-env-secret`'s `metavariable-regex` in
 * `configs/semgrep/client-trust.yml` (a test holds the two equal). The name
 * must END in a group that says secret (`…_SECRET`, `…_SECRET_KEY`,
 * `…_SERVICE_ROLE_KEY`, `…_PRIVATE_KEY`, a paid provider's `…_API_KEY`,
 * `DATABASE_URL`…): `PASSWORD_MIN_LENGTH`, `PASSWORD_RESET_URL`,
 * `AUTH_TOKEN_KEY` and `SECRET_SANTA_MODE` only pass through one.
 */
export const PUBLIC_ENV_SECRET_NAME =
  /^(?:NEXT_PUBLIC|VITE|EXPO_PUBLIC|REACT_APP|NUXT_PUBLIC|GATSBY|VUE_APP|PUBLIC)_(?:\w+_)?(?:SECRET(?:_KEY|_TOKEN)?|SERVICE_ROLE(?:_KEY)?|SERVICE_KEY|PRIVATE_KEY|PASSWORD|PASSWD|DATABASE_URL|DB_URL|POSTGRES(?:QL)?_URL|MONGO(?:DB)?_UR[IL]|REDIS_URL|ADMIN_(?:API_)?KEY|MASTER_KEY|AUTH_TOKEN|(?:OPENAI|ANTHROPIC|CLAUDE|GROQ|MISTRAL|COHERE|REPLICATE|HUGGINGFACE|HF|TOGETHER|FIREWORKS|PERPLEXITY|DEEPSEEK|XAI|OPENROUTER|ELEVENLABS|DEEPGRAM|ASSEMBLYAI|GEMINI|PINECONE|RESEND|SENDGRID|MAILGUN|POSTMARK|TWILIO)(?:_API)?_(?:KEY|TOKEN))$/;

/** Each browser prefix and the framework that inlines it. */
const PUBLIC_PREFIXES: ReadonlyArray<readonly [string, string]> = [
  ['NEXT_PUBLIC_', 'Next.js'],
  ['VITE_', 'Vite'],
  ['EXPO_PUBLIC_', 'Expo'],
  ['REACT_APP_', 'Create React App'],
  ['NUXT_PUBLIC_', 'Nuxt'],
  ['GATSBY_', 'Gatsby'],
  ['VUE_APP_', 'Vue CLI'],
  ['PUBLIC_', 'SvelteKit and Astro'],
];

/** The longest variable name judged; a longer one is not an environment variable anyone writes. */
const MAX_NAME_LENGTH = 256;

/** The browser prefix of `name` and its framework, or null. */
function publicPrefixOf(name: string): { prefix: string; framework: string } | null {
  for (const [prefix, framework] of PUBLIC_PREFIXES) {
    if (name.startsWith(prefix) && name.length > prefix.length) return { prefix, framework };
  }
  return null;
}

/** Whether a browser-exposed variable's name says it holds a secret. */
export function publicNameSaysSecret(name: string): boolean {
  return name.length <= MAX_NAME_LENGTH && PUBLIC_ENV_SECRET_NAME.test(name);
}

/** `.env`, `.env.local`, `.env.production.local`, `.env.example` — never `.envrc` or `.environment`. */
export function isEnvFileName(name: string): boolean {
  return /^\.env(?:\.[\w.-]+)?$/.test(name);
}

/** A template others copy (`.env.example`, `.env.local.sample`, `.env.template`): its values are not the app's. */
export function isEnvTemplateName(name: string): boolean {
  return /\.(?:example|sample|template|tmpl|dist|defaults?|schema)(?:\.|$)/i.test(name.slice(4));
}

interface EnvAssignment {
  name: string;
  value: string;
  /** 1-based line of the assignment. */
  line: number;
}

/** The most lines a double-quoted value may span (a PEM key is ~30). */
const MAX_VALUE_LINES = 200;

/**
 * The assignments of a dotenv file: `KEY=value`, `export KEY=value`, spaces
 * around `=`, single, double or backtick quotes, a double-quoted value over
 * several lines, ` # comments` after an unquoted value. Anything else is
 * skipped, never guessed at.
 */
export function parseEnvFile(text: string): EnvAssignment[] {
  const lines = text.split(/\r?\n/);
  const out: EnvAssignment[] = [];
  for (let i = 0; i < lines.length; i += 1) {
    const raw = lines[i] ?? '';
    const m = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s?(.*)$/.exec(raw);
    if (m === null) continue;
    const name = m[1] ?? '';
    let rest = (m[2] ?? '').trim();
    const line = i + 1;
    const quote = rest.charAt(0);
    if (quote === '"' || quote === "'" || quote === '`') {
      const close = rest.indexOf(quote, 1);
      if (close > 0) {
        out.push({ name, value: rest.slice(1, close), line });
        continue;
      }
      // An open double quote runs on to the line that closes it.
      if (quote !== '"') {
        out.push({ name, value: rest.slice(1), line });
        continue;
      }
      const parts = [rest.slice(1)];
      let j = i + 1;
      for (; j < lines.length && j <= i + MAX_VALUE_LINES; j += 1) {
        const next = lines[j] ?? '';
        const end = next.indexOf('"');
        if (end >= 0) {
          parts.push(next.slice(0, end));
          break;
        }
        parts.push(next);
      }
      out.push({ name, value: parts.join('\n'), line });
      i = Math.min(j, lines.length - 1);
      continue;
    }
    const hash = rest.search(/\s#/);
    if (hash >= 0) rest = rest.slice(0, hash).trim();
    if (rest.startsWith('#')) rest = '';
    out.push({ name, value: rest, line });
  }
  return out;
}

/** An empty value, a `${VAR}` reference or a placeholder: nothing this file ships. */
function isPlaceholderValue(value: string): boolean {
  const v = value.trim();
  if (v.length === 0) return true;
  if (/^\$\{?[A-Za-z_]\w*\}?$/.test(v)) return true;
  if (/^<[^>]*>$/.test(v) || /^\[[^\]]*\]$/.test(v)) return true;
  const lower = v.toLowerCase();
  if (/^(?:x+|\*+|\.{3,}|changeme|change[-_]me|todo|tbd|none|null|undefined|secret|password)$/.test(lower)) return true;
  return /your[-_ ]|placeholder|replace[-_ ]?me|dummy|xxxx|insert[-_ ]|paste[-_ ]/.test(lower);
}

interface SecretValueKind {
  /** What the value is, as a finding says it ("a Stripe live secret key"). */
  label: string;
  /** A live credential (critical); false for a test-mode one (high). */
  live: boolean;
}

/** Provider rules of the hooks' scanner whose shapes are public by design in a browser variable. */
const PUBLIC_BY_DESIGN_RULES: ReadonlySet<string> = new Set(['google-api-key', 'twilio-account-sid']);

/** The role claim of a JWT's payload, or null when `value` is not a readable JWT. */
export function jwtRole(value: string): string | null {
  const m = /^eyJ[A-Za-z0-9_-]{2,4000}\.(eyJ[A-Za-z0-9_-]{2,8000})\.[A-Za-z0-9_-]{0,4000}$/.exec(value.trim());
  if (m === null) return null;
  try {
    const payload: unknown = JSON.parse(Buffer.from(m[1] ?? '', 'base64url').toString('utf8'));
    if (typeof payload !== 'object' || payload === null) return null;
    const role = (payload as { role?: unknown }).role;
    return typeof role === 'string' ? role : null;
  } catch {
    return null;
  }
}

/**
 * What a value IS when it is a secret by its own shape — whatever the name
 * of the variable holding it — or null: a Stripe secret, restricted or
 * webhook-signing key, a Supabase secret key or service-role JWT, a URL with
 * a password, a private key, or a provider token the hooks' scanner knows.
 */
export function classifySecretValue(value: string): SecretValueKind | null {
  const v = value.trim();
  if (v.length === 0 || v.length > 16 * 1024) return null;
  if (/^(?:sk|rk)_live_[0-9A-Za-z]{10,}$/.test(v)) return { label: 'a Stripe live secret key', live: true };
  if (/^(?:sk|rk)_test_[0-9A-Za-z]{10,}$/.test(v)) return { label: 'a Stripe test-mode secret key', live: false };
  if (/^whsec_[0-9A-Za-z+/=]{10,}$/.test(v)) return { label: 'a Stripe webhook signing secret', live: true };
  if (/^sb_secret_[0-9A-Za-z_-]{10,}$/.test(v)) return { label: 'a Supabase secret key', live: true };
  const role = jwtRole(v);
  if (role === 'service_role' || role === 'supabase_admin') return { label: 'a Supabase service-role key', live: true };
  if (role !== null) return null;
  const url = /^[a-z][a-z0-9+.-]{0,31}:\/\/[^\s/:@]+:([^\s/@]{3,})@/i.exec(v);
  if (url !== null && !isPlaceholderValue(url[1] ?? '')) return { label: 'a connection URL with a password', live: true };
  if (/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(v)) return { label: 'a private key', live: true };
  const hit = scanForSecrets(v, { minConfidence: 'high' }).find((h) => !PUBLIC_BY_DESIGN_RULES.has(h.ruleId));
  if (hit !== undefined) return { label: `${/^[aeiou]/i.test(hit.title) ? 'an' : 'a'} ${hit.title}`, live: true };
  return null;
}

/**
 * Whether a value LOOKS like a secret when no provider shape says what it is:
 * long enough, not words (`access_token`, `my-app`), not a bare number or a
 * URL without a password, and random enough (Shannon entropy ≥ 3 bits per
 * character). What lets a name-only match be critical.
 */
function looksSecret(value: string): boolean {
  const v = value.trim();
  if (v.length < 12) return false;
  if (/^[A-Za-z]+(?:[\s_.:/-]+[A-Za-z]+)*$/.test(v)) return false;
  if (/^\d+(?:\.\d+)?$/.test(v)) return false;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(v) && !/:\/\/[^\s/@]+:[^\s/@]+@/.test(v)) return false;
  return shannonEntropy(v) >= 3;
}

/**
 * The findings of one env file: every browser-exposed variable whose name
 * says secret, or whose value is one. `relPath` is project-relative. Critical
 * only when the VALUE is seen to be a secret; a name alone is a question.
 *
 *   - critical — a live secret by its shape (Stripe, Supabase, a provider
 *     token, a URL with a password), or a random-looking value of a variable
 *     whose name says secret: "rotate it now";
 *   - high — a test-mode secret (Stripe `sk_test_…`);
 *   - medium — the name says secret and the value does not look like one
 *     (`access_token`, `8`), or is empty or a placeholder (a template, or a
 *     file the deployment fills in): "check what it holds".
 */
export function checkEnvFile(relPath: string, text: string): Finding[] {
  const fileName = relPath.split('/').pop() ?? relPath;
  const template = isEnvTemplateName(fileName);
  const findings: Finding[] = [];
  for (const a of parseEnvFile(text)) {
    const exposed = publicPrefixOf(a.name);
    if (exposed === null) continue;
    const named = publicNameSaysSecret(a.name);
    const kind = classifySecretValue(a.value);
    if (kind === null && !named) continue;
    const empty = isPlaceholderValue(a.value);
    const seen = kind !== null || (!empty && looksSecret(a.value));
    let severity: Severity;
    if (kind !== null) severity = kind.live ? 'critical' : 'high';
    else severity = seen ? 'critical' : 'medium';
    const what = kind?.label ?? 'a secret';
    const how = `${exposed.framework} writes every ${exposed.prefix} variable into the JavaScript the browser downloads`;
    let message: string;
    if (!seen && empty) {
      message =
        `${fileName} declares ${a.name}, whose name says it is a secret, with no value here (${how}). ` +
        `${template ? 'Developers who copy this template' : 'A deployment that sets it'} would ship the secret to every ` +
        `visitor. Check what it is meant to hold: if a secret, drop the ${exposed.prefix} prefix and read it in server ` +
        'code only (an API route, a server action, an edge function), and rotate it at its provider if a build ' +
        'already had a value for it.';
    } else if (!seen) {
      message =
        `${fileName} sets ${a.name}, whose name says it is a secret, to a value that does not look like one (it is ` +
        `not shown here), and ${how}. Check what it holds: if it is a secret, every build that set it shipped it to ` +
        `browsers — rotate it at the provider, drop the ${exposed.prefix} prefix and read it in server code only; if ` +
        'it is not, rename the variable so its name stops saying secret.';
    } else {
      const aside = kind !== null && !named ? ' — whatever its name says' : '';
      message =
        `${fileName} sets ${a.name} to ${what}${aside}, and ${how}. If the app was built with it, the value has ` +
        `already reached the browsers of everyone who opened it: revoke and rotate it at the provider now — ` +
        `the value is not shown here. Then drop the ${exposed.prefix} prefix and use the secret in server code only.` +
        (kind?.label === 'a Supabase service-role key'
          ? ' The browser needs the anon (publishable) key, with row-level security deciding what it may read.'
          : '');
    }
    findings.push(
      makeFinding({
        tool: CLIENT_TRUST_TOOL,
        rule_id: ENV_PUBLIC_SECRET_RULE,
        severity,
        category: 'security',
        subcategory: 'client-trust',
        title: `${a.name}: ${kind !== null ? what : seen ? 'a secret' : 'a name that says secret'} behind the browser prefix ${exposed.prefix}`,
        message,
        file_path: relPath,
        line_start: a.line,
        line_end: a.line,
        taxonomy: { cwe: ['CWE-798'] },
      }),
    );
  }
  return findings;
}
