/**
 * What a verdict does to a finding: `live` raises it to critical with
 * provider-specific rotation guidance; `revoked` and `unknown` say so and
 * never lower it; none of them touches what identifies the finding.
 */

import { describe, expect, it } from 'vitest';

import { assignIdentities } from '../../../../src/fingerprint/findingIdentity.js';
import { gitleaksParser } from '../../../../src/runners/scannerParsers/gitleaks.js';
import { annotateFinding, withSecretChecks } from '../../../../src/secrets/verify/apply.js';
import type { SecretCheck } from '../../../../src/secrets/verify/verify.js';
import type { Finding } from '../../../../src/types.js';

function finding(): Finding {
  const out = gitleaksParser.parse([{ RuleID: 'github-pat', File: 'app.env', StartLine: 3, EndLine: 3, Secret: 'REDACTED' }]);
  const f = out.findings[0];
  if (f === undefined) throw new Error('parser produced nothing');
  return { ...f, message: 'location: working_tree — in an uncommitted or untracked file' };
}

const live: SecretCheck = {
  verdict: 'live',
  reason: 'api.github.com accepted it (HTTP 200)',
  provider: 'GitHub',
  host: 'api.github.com',
  sent: true,
  rotate: 'revoke it at https://github.com/settings/tokens',
};

describe('annotateFinding', () => {
  it('live: severity critical, the verdict and where to revoke in the message', () => {
    const f = finding();
    const a = annotateFinding(f, live);
    expect(a.severity).toBe('critical');
    expect(a.message).toMatch(/^location: working_tree/);
    expect(a.message).toMatch(/verified: live/);
    expect(a.message).toContain('https://github.com/settings/tokens');
  });

  it('revoked and unknown never lower the severity', () => {
    const f = { ...finding(), severity: 'critical' as const };
    for (const verdict of ['revoked', 'unknown'] as const) {
      const a = annotateFinding(f, { ...live, verdict, reason: 'r' });
      expect(a.severity).toBe('critical');
      expect(a.message).toMatch(new RegExp(`verified: ${verdict}`));
    }
    const high = finding();
    expect(annotateFinding(high, { ...live, verdict: 'unknown', reason: 'r' }).severity).toBe('high');
  });

  it('skipped leaves the finding as it was', () => {
    const f = finding();
    expect(annotateFinding(f, { ...live, verdict: 'skipped', reason: 'no verifier', sent: false })).toEqual(f);
  });

  it('never changes the fingerprint, snippet, rule, path or lines — so the identity is the same', () => {
    const f = finding();
    const a = annotateFinding(f, live);
    for (const key of ['fingerprint', 'snippet', 'rule_id', 'file_path', 'line_start', 'line_end', 'tool', 'subcategory'] as const) {
      expect(a[key]).toEqual(f[key]);
    }
    const ctx = { projectPath: '/nonexistent-project', readSource: () => null };
    expect(assignIdentities([a], ctx)[0]?.identity).toBe(assignIdentities([f], ctx)[0]?.identity);
  });
});

describe('withSecretChecks', () => {
  it('applies each item its own verdict, by position in the report', () => {
    const report = JSON.stringify([
      { RuleID: 'github-pat', File: 'a.env', StartLine: 1, Secret: 'REDACTED' },
      { RuleID: 'aws-access-token', File: 'b.env', StartLine: 1, Secret: 'REDACTED' },
      { RuleID: 'github-pat', File: 'c.env', StartLine: 1, Secret: 'REDACTED' },
    ]);
    const parser = withSecretChecks(gitleaksParser, [live, null, { ...live, verdict: 'revoked', reason: 'gone' }]);
    const out = parser.parse(report, {});
    expect(out.findings.map((f) => [f.file_path, f.severity])).toEqual([
      ['a.env', 'critical'],
      ['b.env', 'high'],
      ['c.env', 'high'],
    ]);
    expect(out.findings[2]?.message).toMatch(/verified: revoked/);
    // Same findings, same fingerprints, as the plain parser.
    expect(out.findings.map((f) => f.fingerprint)).toEqual(gitleaksParser.parse(report).findings.map((f) => f.fingerprint));
  });
});
