/**
 * Credential redaction for `scan_dast`.
 *
 * The design's rule (§6) is absolute: credentials are never persisted — not
 * to SQLite, not to the evidence files — and never appear in anything the
 * tool hands back. This module is the single choke point that makes that true
 * by construction instead of by everyone remembering.
 *
 * Three decisions, each closing a hole that "we never put it there" leaves
 * open:
 *
 *   - **Redaction runs over the SERIALISED form of a whole object**
 *     (`redactObject`), not over a hand-picked list of fields. The credential
 *     is not something the orchestrator sprinkles into messages: `plan.ts`
 *     puts it verbatim into `ProbeRequest.headers.authorization`, every
 *     `ProbeResult` embeds its request, and every evidence record is built
 *     from one. A field-by-field redactor stays correct only until the next
 *     field is added upstream.
 *   - **A `<scheme> <token>` header contributes the bare token as a second
 *     secret.** Replacing only the full `Bearer abc` string would leave a
 *     standalone `abc` untouched. The extra entry costs nothing and errs
 *     toward redacting more.
 *   - **The JSON-escaped spelling of each secret is redacted too.** A
 *     credential containing `"` or `\` is written to disk in escaped form, so
 *     a plain substring replace over the serialised text would miss it.
 */

/** Replacement text. Fixed, so a redacted artifact is greppable. */
export const REDACTED = '«redacted»';

export type Redactor = (value: string) => string;

/**
 * Every string that must never survive to an output, derived from the
 * credential values the caller supplied. Blank and whitespace-only values
 * yield nothing: redacting the empty string would replace every character
 * boundary in every document.
 */
export function collectSecrets(...values: readonly (string | null | undefined)[]): string[] {
  const out = new Set<string>();
  for (const value of values) {
    if (value === null || value === undefined) continue;
    const trimmed = value.trim();
    if (trimmed === '') continue;
    out.add(trimmed);
    const schemeAndToken = /^\S+\s+(\S.*)$/.exec(trimmed);
    const token = schemeAndToken?.[1];
    if (token !== undefined) out.add(token);
  }
  return [...out];
}

export function makeRedactor(secrets: readonly string[]): Redactor {
  const variants = new Set<string>();
  for (const secret of secrets) {
    if (secret === '') continue;
    variants.add(secret);
    variants.add(JSON.stringify(secret).slice(1, -1));
  }
  // Longest first: when one secret contains another (a full header value and
  // its bare token), the containing one must be replaced whole, or the inner
  // match fragments it into a `Bearer «redacted»` shape instead of removing
  // the header value outright.
  const ordered = [...variants].sort((a, b) => b.length - a.length);
  if (ordered.length === 0) return (value) => value;
  return (value: string): string => {
    let out = value;
    // `split`/`join` rather than a RegExp: a credential is arbitrary text and
    // may contain regex metacharacters. There is nothing to escape this way.
    for (const secret of ordered) out = out.split(secret).join(REDACTED);
    return out;
  };
}

/**
 * Redact every string anywhere inside `value` by round-tripping it through
 * JSON. Non-serialisable input (`undefined`, a bare function) is returned
 * untouched rather than throwing — this runs on the way out of a tool, and a
 * redactor that can crash the response is worse than one that no-ops on a
 * shape that could not have carried a credential in the first place.
 */
export function redactObject<T>(value: T, redact: Redactor): T {
  const json = JSON.stringify(value);
  if (json === undefined) return value;
  return JSON.parse(redact(json)) as T;
}
