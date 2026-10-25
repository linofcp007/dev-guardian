import { describe, expect, it } from 'vitest';
import { computeFingerprint } from '../../../src/fingerprint/findingFingerprint.js';
import {
  credentialSafeFingerprint,
  REDACTED_SECRET_SNIPPET,
  redactCredentialSnippet,
  redactCredentialSnippets,
} from '../../../src/redaction/secretFindingRedaction.js';
import { makeFinding } from '../../../src/runners/scannerParsers/index.js';
import type { Finding } from '../../../src/types.js';

describe('redactCredentialSnippet', () => {
  it('redacts the snippet of a finding with subcategory secret', () => {
    const f = {
      tool: 'scan_dotnet_secrets',
      rule_id: 'dotnet-sql-server-conn',
      subcategory: 'secret',
      snippet: 'Server=db;Password=Sup3rS3cret!',
    };
    expect(redactCredentialSnippet(f).snippet).toBe(REDACTED_SECRET_SNIPPET);
  });

  it('redacts the snippet of a Bandit B105 hardcoded-password finding by subcategory', () => {
    const f = {
      tool: 'bandit',
      rule_id: 'B105',
      subcategory: 'hardcoded_password_string',
      snippet: '12 password = "hunter2"',
    };
    expect(redactCredentialSnippet(f).snippet).toBe(REDACTED_SECRET_SNIPPET);
  });

  it('redacts a rule/subcategory naming a credential-family word (aws key, jwt secret, etc.)', () => {
    const f = {
      tool: 'semgrep',
      rule_id: 'hardcoded-aws-key',
      snippet: 'const key = "AKIAABCDEFGHIJKLMNOP";',
    };
    expect(redactCredentialSnippet(f).snippet).toBe(REDACTED_SECRET_SNIPPET);
  });

  it('leaves a non-credential finding snippet untouched', () => {
    const f = {
      tool: 'semgrep',
      rule_id: 'sql-injection',
      subcategory: 'injection',
      snippet: 'db.query(`SELECT * FROM users WHERE id = ${id}`)',
    };
    expect(redactCredentialSnippet(f).snippet).toBe(f.snippet);
  });

  it('leaves a finding with no snippet at all untouched (nothing to redact)', () => {
    const f: { tool: string; rule_id: string; subcategory: string; snippet?: string } = {
      tool: 'bandit',
      rule_id: 'B105',
      subcategory: 'hardcoded_password_string',
    };
    const out = redactCredentialSnippet(f);
    expect(out.snippet).toBeUndefined();
    expect(out).not.toHaveProperty('snippet', REDACTED_SECRET_SNIPPET);
  });

  it('exempts Semgrep\'s own "requires login" placeholder — already safe, and a more useful signal', () => {
    const f = {
      tool: 'semgrep',
      rule_id: 'generic.secrets.security.detected-generic-secret',
      subcategory: 'secrets',
      snippet: 'requires login',
    };
    expect(redactCredentialSnippet(f).snippet).toBe('requires login');
  });

  it('exempts gitleaks: its snippet is always a safe rule/commit locator, never the secret', () => {
    const f = {
      tool: 'gitleaks',
      rule_id: 'aws-access-token',
      subcategory: 'secret',
      snippet: 'rule=aws-access-token;commit=abc1234',
    };
    expect(redactCredentialSnippet(f).snippet).toBe('rule=aws-access-token;commit=abc1234');
  });

  it('is idempotent: redacting twice yields the same placeholder', () => {
    const f = { tool: 'bandit', rule_id: 'B105', subcategory: 'hardcoded_password_string', snippet: 'x = "hunter2"' };
    const once = redactCredentialSnippet(f);
    const twice = redactCredentialSnippet(once);
    expect(twice.snippet).toBe(REDACTED_SECRET_SNIPPET);
  });

  it('does not mutate the input object', () => {
    const f = { tool: 'bandit', rule_id: 'B105', subcategory: 'hardcoded_password_string', snippet: 'x = "hunter2"' };
    redactCredentialSnippet(f);
    expect(f.snippet).toBe('x = "hunter2"');
  });

  // The fingerprint goes to `.guardian/baseline.json` and to SARIF's
  // partialFingerprints. Hashed over the raw snippet — Bandit's B105 `code`,
  // gosec's G101 line, a logged-in Semgrep secret's matched text — it was
  // the offline oracle the identity is built never to be: guess the value,
  // hash, compare.
  describe('a credential finding is fingerprinted over the redacted snippet', () => {
    const b105 = (code: string, line = 12): Finding =>
      makeFinding({
        tool: 'bandit', rule_id: 'B105', severity: 'low', category: 'security',
        subcategory: 'hardcoded_password_string', title: 'pw', file_path: 'app.py',
        line_start: line, line_end: line, snippet: code,
      });

    it('the plaintext changes nothing; the line still does', () => {
      const a = b105(`12 password = "${['hun', 'ter2'].join('')}"`);
      const b = b105(`12 password = "${['guess', '123'].join('')}"`);
      expect(a.snippet).toBe(REDACTED_SECRET_SNIPPET);
      expect(a.fingerprint).toBe(b.fingerprint);
      expect(a.fingerprint).toBe(
        computeFingerprint({ tool: 'bandit', rule_id: 'B105', file_path: 'app.py', line_start: 12, line_end: 12, snippet: REDACTED_SECRET_SNIPPET }),
      );
      expect(b105('13 password = "x"', 13).fingerprint).not.toBe(a.fingerprint);
    });

    it('leaves every other finding\'s fingerprint exactly as it was (the algorithm is frozen)', () => {
      const sqli = makeFinding({
        tool: 'semgrep', rule_id: 'sql-injection', severity: 'high', category: 'security', title: 'sqli',
        file_path: 'a.js', line_start: 3, line_end: 3, snippet: 'db.query(q + id)',
      });
      expect(sqli.fingerprint).toBe(
        computeFingerprint({ tool: 'semgrep', rule_id: 'sql-injection', file_path: 'a.js', line_start: 3, line_end: 3, snippet: 'db.query(q + id)' }),
      );
    });

    it('credentialSafeFingerprint gives a row stored before this the fingerprint a scan gives it now', () => {
      const fresh = b105('12 password = "x"');
      // As stored before: snippet redacted, fingerprint hashed over the plaintext.
      const stored: Finding = { ...fresh, fingerprint: computeFingerprint({ tool: 'bandit', rule_id: 'B105', file_path: 'app.py', line_start: 12, line_end: 12, snippet: '12 password = "x"' }) };
      expect(credentialSafeFingerprint(stored)).toBe(fresh.fingerprint);
      const plain = makeFinding({ tool: 'semgrep', rule_id: 'r', severity: 'low', category: 'security', title: 't', snippet: 'x' });
      expect(credentialSafeFingerprint(plain)).toBe(plain.fingerprint);
    });
  });

  describe('redactCredentialSnippets (array form)', () => {
    it('redacts only the credential findings in a mixed array', () => {
      const findings = [
        { tool: 'bandit', rule_id: 'B105', subcategory: 'hardcoded_password_string', snippet: 'pw = "x"' },
        { tool: 'semgrep', rule_id: 'sql-injection', snippet: 'SELECT * FROM t' },
      ];
      const out = redactCredentialSnippets(findings);
      expect(out[0]?.snippet).toBe(REDACTED_SECRET_SNIPPET);
      expect(out[1]?.snippet).toBe('SELECT * FROM t');
    });
  });
});
