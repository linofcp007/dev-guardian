import { describe, expect, it } from 'vitest';
import {
  REDACTED_SECRET_SNIPPET,
  redactCredentialSnippet,
  redactCredentialSnippets,
} from '../../../src/redaction/secretFindingRedaction.js';

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
