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
