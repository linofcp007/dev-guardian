/**
 * What a verification does to a finding — and what it must not.
 *
 * `live` raises the finding to `critical` and says, in its `message`, which
 * provider accepted it and where to revoke it. `revoked` and `unknown` say so
 * too and never LOWER the severity: an unanswered check is not evidence the
 * secret is harmless, and a revoked one still sits in the code (and, for a
 * history finding, in every clone). `skipped` leaves the finding untouched.
 *
 * Nothing here touches what identifies a finding — `fingerprint` hashes the
 * tool, rule, path, lines and snippet, `identity` the tool, rule, path,
 * content key and occurrence (`fingerprint/findingIdentity.ts`) — so a
 * verified scan and an unverified one of the same tree report the same
 * findings, and every suppression, baseline and diff keeps matching.
 */

import { parseInputAsJson, type ParserOutput, type ScannerParser } from '../../runners/scannerParsers/index.js';
import type { Finding } from '../../types.js';
import type { SecretCheck } from './verify.js';

export function annotateFinding(f: Finding, check: SecretCheck): Finding {
  if (check.verdict === 'skipped') return f;
  const base = f.message !== undefined && f.message.length > 0 ? `${f.message}. ` : '';
  switch (check.verdict) {
    case 'live':
      return {
        ...f,
        severity: 'critical',
        message:
          `${base}verified: live — ${check.reason}. This credential works: rotate it now` +
          `${check.rotate !== null ? ` (${check.rotate})` : ''}, then replace it wherever it is used. ` +
          'Deleting it from the code does not disable it.',
      };
    case 'revoked':
      return {
        ...f,
        message: `${base}verified: revoked — ${check.reason}. Still remove it from the code (and the history).`,
      };
    case 'unknown':
      return { ...f, message: `${base}verified: unknown — ${check.reason}.` };
  }
}

/**
 * `inner` (gitleaks' parser, as `runners/gitleaksScan.ts` wraps it) with each
 * report item's verification applied to the finding it becomes. `checks` is
 * aligned with the report's items, so the items are parsed one at a time;
 * the findings, their order and their fingerprints are exactly `inner`'s.
 */
export function withSecretChecks(inner: ScannerParser, checks: ReadonlyArray<SecretCheck | null>): ScannerParser {
  return {
    name: inner.name,
    parse(input, ctx): ParserOutput {
      const root = parseInputAsJson(input);
      if (!Array.isArray(root)) return inner.parse(input, ctx);
      const out: ParserOutput = { findings: [], cves: [] };
      root.forEach((item: unknown, i) => {
        const parsed = inner.parse([item], ctx);
        const check = checks[i] ?? null;
        for (const f of parsed.findings) out.findings.push(check === null ? f : annotateFinding(f, check));
        out.cves.push(...parsed.cves);
      });
      return out;
    },
  };
}
