/**
 * Snippet redaction for findings that flag a credential.
 *
 * `isCredentialFinding` (`fingerprint/findingIdentity.ts`) already decides
 * WHICH findings flag a credential — gitleaks/Trivy `subcategory: 'secret'`,
 * Bandit's B105-B107, a rule/subcategory naming a password/secret/key — and
 * that classifier is reused here rather than duplicated, for the same reason
 * its own comment gives: matching too little puts a secret in a committed
 * file, matching too wide only costs precision.
 *
 * What that module does NOT do is touch `finding.snippet` itself: it only
 * decides what CONTENT KEYS on, so two rows can still carry the raw text a
 * scanner captured. This module is the one place that clears it, applied
 * once, before persistence, so a credential finding's `snippet` never
 * reaches the database, a tool response, a report, a GitHub issue or the
 * dashboard HTML — every one of those reads the SAME `Finding` objects this
 * runs over.
 *
 * **gitleaks is exempt.** Its own parser (`scannerParsers/gitleaks.ts`)
 * already guarantees `snippet` is a locator (`rule=<id>` or
 * `rule=<id>;commit=<sha>`), never the secret text, "even if gitleaks was
 * somehow run without `--redact`" — so redacting it again would destroy
 * useful, already-safe diagnostic information (which rule, which commit) for
 * no security benefit. Trivy's own secret parser never sets a `snippet` at
 * all, so it is already a no-op here without needing a matching exemption.
 *
 * **Semgrep's own "requires login" placeholder is exempt too** — it already
 * names the reason the content is missing (`findingIdentity.ts`'s
 * `REDACTED_SNIPPET`), which is a more useful signal than this module's
 * generic placeholder and was never the secret to begin with.
 */

import {
  isCredentialFinding,
  REDACTED_SNIPPET,
  type IdentitySubject,
} from '../fingerprint/findingIdentity.js';

/** Fixed replacement text — greppable, and never mistaken for real content. */
export const REDACTED_SECRET_SNIPPET = '[redacted — credential value omitted; see rule_id and file_path]';

/** The fields this module reads — a finding-shaped value, nothing scanner-specific. */
export type RedactableFinding = IdentitySubject;

/**
 * `f` with its `snippet` replaced by {@link REDACTED_SECRET_SNIPPET} when it
 * flags a credential, unchanged otherwise (including when it has no snippet
 * at all — there is nothing to redact, and inventing one would fabricate
 * context that never existed).
 *
 * Idempotent: running it again on an already-redacted finding is a no-op,
 * since the placeholder is itself not read back as the secret.
 */
export function redactCredentialSnippet<T extends RedactableFinding>(f: T): T {
  if (f.snippet === undefined) return f;
  if (f.tool.toLowerCase() === 'gitleaks') return f;
  if (f.snippet.toLowerCase() === REDACTED_SNIPPET) return f;
  if (!isCredentialFinding(f)) return f;
  return { ...f, snippet: REDACTED_SECRET_SNIPPET };
}

/**
 * Same, over a whole finding array — the shape every persistence call site
 * (the scan-tool factory, and every tool that inserts findings outside it)
 * holds its findings in just before `bulkInsert`.
 */
export function redactCredentialSnippets<T extends RedactableFinding>(findings: readonly T[]): T[] {
  return findings.map(redactCredentialSnippet);
}
