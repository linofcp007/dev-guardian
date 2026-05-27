import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { gitleaksParser } from '../../../../src/runners/scannerParsers/gitleaks.js';

const here = dirname(fileURLToPath(import.meta.url));
const FIXTURE = resolve(here, '../../../fixtures/scanners/gitleaks.json');

describe('gitleaksParser', () => {
  it('maps every entry to a security/secret finding at severity=high', () => {
    const { findings, cves } = gitleaksParser.parse(readFileSync(FIXTURE, 'utf8'));
    expect(findings).toHaveLength(2);
    expect(cves).toEqual([]);
    for (const f of findings) {
      expect(f.category).toBe('security');
      expect(f.subcategory).toBe('secret');
      expect(f.severity).toBe('high');
    }
  });

  it('never copies Match or Secret bytes into the snippet', () => {
    const { findings } = gitleaksParser.parse(readFileSync(FIXTURE, 'utf8'));
    for (const f of findings) {
      expect(f.snippet ?? '').not.toMatch(/REDACTED/);
      expect(f.snippet ?? '').toMatch(/^rule=/);
    }
  });

  it('produces stable fingerprints across re-parses', () => {
    const a = gitleaksParser.parse(readFileSync(FIXTURE, 'utf8')).findings;
    const b = gitleaksParser.parse(readFileSync(FIXTURE, 'utf8')).findings;
    expect(a.map((f) => f.fingerprint)).toEqual(b.map((f) => f.fingerprint));
  });

  it('handles an empty array gracefully', () => {
    expect(gitleaksParser.parse('[]').findings).toEqual([]);
  });
});
