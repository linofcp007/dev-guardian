import { describe, expect, it } from 'vitest';
import {
  redact,
  scanForSecrets,
  shannonEntropy,
} from '../../../src/hooks/secretScan.js';

describe('scanForSecrets — high-confidence provider tokens', () => {
  it('detects an AWS access key id', () => {
    const hits = scanForSecrets('const k = "AKIAIOSFODNN7EXAMPLE";');
    expect(hits.map((h) => h.ruleId)).toContain('aws-access-key-id');
    expect(hits[0]?.confidence).toBe('high');
  });

  it('detects a classic GitHub token', () => {
    const token = 'ghp_' + 'a'.repeat(36);
    const hits = scanForSecrets(`GITHUB_TOKEN=${token}`);
    expect(hits.map((h) => h.ruleId)).toContain('github-token');
  });

  it('detects an Anthropic API key', () => {
    const hits = scanForSecrets('ANTHROPIC_API_KEY="sk-ant-api03-abcDEF1234567890abcDEF12"');
    expect(hits.map((h) => h.ruleId)).toContain('anthropic-api-key');
  });

  it('detects a private key header', () => {
    const hits = scanForSecrets('-----BEGIN OPENSSH PRIVATE KEY-----\nMIIE...');
    expect(hits.map((h) => h.ruleId)).toContain('private-key-block');
  });

  it('reports the 1-based line of the hit', () => {
    const text = ['line one', 'line two', 'AKIAIOSFODNN7EXAMPLE'].join('\n');
    const hits = scanForSecrets(text);
    expect(hits.find((h) => h.ruleId === 'aws-access-key-id')?.line).toBe(3);
  });
});

describe('scanForSecrets — redaction', () => {
  it('never returns the raw secret', () => {
    const secret = 'AKIAIOSFODNN7EXAMPLE';
    const hits = scanForSecrets(`key = "${secret}"`);
    for (const h of hits) {
      expect(h.preview).not.toContain(secret);
    }
  });

  it('redact() keeps only a short shape preview', () => {
    expect(redact('AKIAIOSFODNN7EXAMPLE')).toMatch(/^AKIA….* \(\d+\)$/);
  });
});

describe('scanForSecrets — generic heuristic + placeholders', () => {
  it('flags a high-entropy hard-coded password', () => {
    const hits = scanForSecrets('password = "Gx7$kPq2zVw9MtRb"');
    expect(hits.map((h) => h.ruleId)).toContain('generic-assignment');
    expect(hits.find((h) => h.ruleId === 'generic-assignment')?.confidence).toBe('medium');
  });

  it('ignores obvious placeholders', () => {
    expect(scanForSecrets('api_key = "your-api-key-here"')).toHaveLength(0);
    expect(scanForSecrets('password = "changeme123456"')).toHaveLength(0);
    expect(scanForSecrets('token = "${process.env.TOKEN}"')).toHaveLength(0);
  });

  it('ignores low-entropy repetitive values', () => {
    expect(scanForSecrets('secret = "aaaaaaaaaaaaaaaa"')).toHaveLength(0);
  });

  it('does not flag an env-var reference', () => {
    expect(scanForSecrets('const key = process.env.API_KEY')).toHaveLength(0);
  });
});

describe('scanForSecrets — options', () => {
  it('minConfidence=high suppresses heuristic medium hits', () => {
    const hits = scanForSecrets('password = "Gx7$kPq2zVw9MtRb"', { minConfidence: 'high' });
    expect(hits).toHaveLength(0);
  });

  it('still reports high hits when minConfidence=high', () => {
    const hits = scanForSecrets('AKIAIOSFODNN7EXAMPLE', { minConfidence: 'high' });
    expect(hits).toHaveLength(1);
  });

  it('allowlist substring skips a matching line', () => {
    const text = 'AKIAIOSFODNN7EXAMPLE # pragma: allowlist secret';
    expect(scanForSecrets(text, { allowlist: ['allowlist secret'] })).toHaveLength(0);
  });
});

describe('shannonEntropy', () => {
  it('is 0 for an empty string and low for repetition', () => {
    expect(shannonEntropy('')).toBe(0);
    expect(shannonEntropy('aaaaaaaa')).toBe(0);
  });

  it('is higher for mixed characters', () => {
    expect(shannonEntropy('Gx7$kPq2zVw9MtRb')).toBeGreaterThan(3.2);
  });
});

/**
 * task-1, finding 7: the generic rule's key-name matching missed
 * SCREAMING_SNAKE (`DB_PASSWORD`), JSON's quoted key immediately followed by
 * `:` (there is a closing `"` in between that the old pattern did not allow
 * for), camelCase (`stripeSecretKey`), and unquoted `.env`-style assignment.
 * Each row is a positive; the false-positive rows at the bottom must stay silent.
 */
describe('scanForSecrets — task-1: generic credential detection (finding 7)', () => {
  const positive: Array<{ name: string; line: string }> = [
    { name: 'SCREAMING_SNAKE with spaces', line: 'DB_PASSWORD = "Gx7$kPq2zVw9Mt"' },
    { name: 'SCREAMING_SNAKE with colon', line: 'JWT_SECRET: "Gx7$kPq2zVw9Mt"' },
    { name: 'SCREAMING_SNAKE no spaces', line: 'GITHUB_TOKEN = "Gx7$kPq2zVw9Mt"' },
    { name: 'SCREAMING_SNAKE tight equals', line: 'OPENAI_API_KEY="Gx7$kPq2zVw9Mt"' },
    { name: 'camelCase secret key', line: 'const stripeSecretKey = "Gx7$kPq2zVw9Mt";' },
    { name: 'camelCase password', line: 'const dbPassword = "Gx7$kPq2zVw9Mt";' },
    { name: 'camelCase token', line: 'const githubToken = "Gx7$kPq2zVw9Mt";' },
    { name: 'JSON quoted key', line: '"password": "Gx7$kPq2zVw9Mt"' },
    // The exact example from the task brief — a real, human-chosen `.env`
    // password (~2.8 bits/char) that must still be caught despite falling
    // under the entropy floor used for the quoted rules above.
    { name: 'unquoted .env line', line: 'DB_PASSWORD=hunter2hunter2' },
    { name: 'unquoted .env line with export', line: 'export ANTHROPIC_API_KEY=sk-ant-api03-abcDEF1234567890abcDEF12' },
  ];

  for (const { name, line } of positive) {
    it(`flags: ${name}`, () => {
      const hits = scanForSecrets(line);
      expect({ line, hits: hits.length }).toEqual({ line, hits: expect.any(Number) });
      expect(hits.length).toBeGreaterThan(0);
      for (const h of hits) expect(h.preview).not.toMatch(/Gx7\$kPq2zVw9Mt|hunter2hunter2|sk-ant-/);
    });
  }

  const negative: Array<{ name: string; line: string }> = [
    { name: 'assigned from a function call', line: 'const password = getPassword();' },
    { name: 'TypeScript type annotation', line: 'function f(token: string) {}' },
    { name: 'interpolated env var reference', line: 'const token = `${process.env.TOKEN}`;' },
    { name: 'bare ${VAR} unquoted', line: 'PASSWORD=${OTHER_VAR}' },
    { name: 'angle-bracket placeholder', line: 'api_key = "<your-key>"' },
    { name: 'changeme placeholder', line: 'password = "changeme"' },
    { name: 'xxxx placeholder', line: 'token = "xxxx"' },
    { name: 'empty string', line: 'password = ""' },
    { name: 'empty unquoted', line: 'DB_PASSWORD=' },
    { name: 'an ordinary word containing "key" is not a credential name', line: 'const monkeyName = "harambe the gorilla";' },
  ];

  for (const { name, line } of negative) {
    it(`does not flag: ${name}`, () => {
      expect(scanForSecrets(line)).toHaveLength(0);
    });
  }

  it('URI credentials are detected', () => {
    const hits = scanForSecrets('DATABASE_URL = "postgres://svc_user:S0meLongPassw0rd@db.internal/app"');
    expect(hits.length).toBeGreaterThan(0);
    for (const h of hits) expect(h.preview).not.toContain('S0meLongPassw0rd');
  });
});

/** task-1, finding 8: an Anthropic key must not ALSO read as an OpenAI key. */
describe('scanForSecrets — task-1: no double-report of an Anthropic key (finding 8)', () => {
  it('reports sk-ant-… once, as anthropic-api-key only', () => {
    const hits = scanForSecrets('ANTHROPIC_API_KEY="sk-ant-api03-abcDEF1234567890abcDEF12"');
    const ids = hits.map((h) => h.ruleId);
    expect(ids).toContain('anthropic-api-key');
    expect(ids).not.toContain('openai-api-key');
  });

  it('a real OpenAI key is still detected', () => {
    const hits = scanForSecrets(`OPENAI_API_KEY="sk-${'a'.repeat(40)}"`);
    expect(hits.map((h) => h.ruleId)).toContain('openai-api-key');
  });

  it('an sk-proj-… key is still detected as OpenAI', () => {
    const hits = scanForSecrets(`OPENAI_API_KEY="sk-proj-${'a'.repeat(40)}"`);
    expect(hits.map((h) => h.ruleId)).toContain('openai-api-key');
  });
});

/** task-1, finding 9: ReDoS caps — both inputs must resolve in well under 500ms. */
describe('scanForSecrets — task-1: ReDoS caps (finding 9)', () => {
  it('a pathological JWT-shaped repeat resolves in well under 500ms', () => {
    const text = 'eyJ-'.repeat(50_000);
    const start = performance.now();
    scanForSecrets(text);
    expect(performance.now() - start).toBeLessThan(500);
  });

  it('a real JWT is still detected after the pattern was bounded', () => {
    const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({ sub: '1234567890', name: 'Test' })).toString('base64url');
    const jwt = `${header}.${payload}.abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG`;
    const hits = scanForSecrets(`Authorization: Bearer ${jwt}`);
    expect(hits.map((h) => h.ruleId)).toContain('jwt');
  });

  it('a single 100 KB unquoted line resolves in well under 500ms', () => {
    const text = `password = "${'a'.repeat(100_000)}"`;
    const start = performance.now();
    scanForSecrets(text);
    expect(performance.now() - start).toBeLessThan(500);
  });
});

/**
 * task-1, finding 11: redact() must show at most 4 characters total for any
 * secret shorter than 16 characters — today's `length > 12` threshold still
 * reveals 6 of a 13-15 char secret.
 */
describe('redact — task-1: short secrets reveal at most 4 characters (finding 11)', () => {
  it('a 13-character secret reveals only the 4-character head', () => {
    const secret = 'abcdefghijklm'; // 13 chars
    expect(redact(secret)).toBe(`abcd… (${secret.length})`);
  });

  it('a 15-character secret reveals only the 4-character head', () => {
    const secret = 'abcdefghijklmno'; // 15 chars
    expect(redact(secret)).toBe(`abcd… (${secret.length})`);
  });

  it('a 16-character-or-longer secret still reveals a head and tail', () => {
    const secret = 'abcdefghijklmnop'; // 16 chars
    expect(redact(secret)).toBe(`abcd…op (${secret.length})`);
  });
});
