/**
 * A line of configuration — a command, a URL, a permission rule — with every
 * credential in it masked, for a finding that quotes the line.
 *
 * `redactCredentialSnippet` clears a credential finding's whole snippet; a
 * finding about something else (a plain-http server, an unpinned launcher, a
 * hook that reaches the network) quotes a line that may carry one beside what
 * it is about: `audit_agent_config` copied `http://10.0.0.5/mcp?api_key=…`,
 * `npx -y pkg --token ghp_…` and a hook's `curl -H "Authorization: Bearer …"`
 * into the message and the snippet, which the database, the reports and the
 * response all keep (review of 3.6.0). Here each one becomes the masked
 * preview `hooks/secretScan.ts#redact` gives (`ghp_…Q8 (40)`):
 *
 *   - every provider-shaped token and every captured value of the secret
 *     scanner's own rules (`SECRET_RULES`), placeholders included — a false
 *     positive costs a few characters, a miss a credential;
 *   - the value of a flag, a query parameter or an assignment whose name says
 *     credential (`--token X`, `?api_key=X`, `password=X`), unless it is a
 *     `${VAR}` / `$VAR` / `%VAR%` reference;
 *   - a URL's password, and an `Authorization` header's credential.
 *
 * Text past {@link MAX_MASKED_CHARS} is cut, not quoted: the scanner's
 * patterns are read on a bounded text, as the hooks read a line in windows.
 */

import { redact, SECRET_RULES } from '../hooks/secretScan.js';

/** How much of a line is quoted at all. */
const MAX_MASKED_CHARS = 2000;

const SECRET_NAME = String.raw`[\w.-]*(?:token|secret|passw(?:or)?d|pwd|api[_-]?key|access[_-]?key|private[_-]?key|auth|credential|signature)[\w.-]*`;

/** A reference to a value set elsewhere, which is no secret of its own. */
const REFERENCE = /^["']?(?:\$\{?[A-Za-z_]\w*\}?|%[A-Za-z_]\w*%|\$env:[A-Za-z_]\w*)["']?$/;

const NAMED_VALUE: readonly RegExp[] = [
  // `--token X`, `--api-key=X`, `-p X` is not one: the name must say credential.
  new RegExp(String.raw`(--?${SECRET_NAME}(?:=|\s+))("[^"]*"|'[^']*'|[^\s"'&]+)`, 'gi'),
  // `?api_key=X&…`, `password=X`, `"token": "X"`.
  new RegExp(String.raw`((?:^|[?&;,\s{"'])${SECRET_NAME}["']?\s*[:=]\s*)("[^"]*"|'[^']*'|[^\s"'&,;}]+)`, 'gi'),
  // `scheme://user:password@host`.
  /(\/\/[^\s/:@]+:)([^\s/@]+)(?=@)/g,
  // `Authorization: Bearer X`, `Authorization: Basic X`.
  /(authorization\s*[:=]\s*(?:bearer|basic|token)?\s*)("[^"]*"|'[^']*'|[^\s"',;]+)/gi,
];

const PROVIDER_PATTERNS: readonly RegExp[] = SECRET_RULES.map(
  (rule) => new RegExp(rule.pattern.source, `${rule.pattern.flags.replace(/[gy]/g, '')}g`),
);

function maskValue(value: string): string {
  if (REFERENCE.test(value) || value.includes('…')) return value;
  const quote = /^["']/.test(value) ? value.charAt(0) : '';
  const inner = quote === '' ? value : value.slice(1, -1);
  return inner === '' ? value : `${quote}${redact(inner)}${quote}`;
}

/** `text` with every credential in it masked — see the module doc. */
export function maskSecrets(text: string): string {
  let out = text.length > MAX_MASKED_CHARS ? `${text.slice(0, MAX_MASKED_CHARS)}…` : text;
  for (const re of PROVIDER_PATTERNS) {
    out = out.replace(re, (whole: string, value?: unknown) => {
      if (typeof value !== 'string' || value === '') return whole.includes('…') ? whole : redact(whole);
      return whole.replace(value, maskValue(value));
    });
  }
  for (const re of NAMED_VALUE) out = out.replace(re, (_whole: string, name: string, value: string) => `${name}${maskValue(value)}`);
  return out;
}
