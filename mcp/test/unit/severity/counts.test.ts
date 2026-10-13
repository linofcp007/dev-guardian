import { describe, expect, it } from 'vitest';
import { countBySeverity, topFindings } from '../../../src/severity/counts.js';
import type { Finding, Severity } from '../../../src/types.js';

/** Only the fields the two summaries read. */
const f = (severity: Severity, fingerprint: string): Finding => ({ severity, fingerprint }) as unknown as Finding;

describe('countBySeverity / topFindings — one copy for every scan result (review 8, finding 14)', () => {
  it('every tier is present, zeroes included', () => {
    expect(countBySeverity([])).toEqual({ info: 0, low: 0, medium: 0, high: 0, critical: 0 });
    expect(countBySeverity([f('high', 'a'), f('high', 'b'), f('info', 'c')])).toEqual({ info: 1, low: 0, medium: 0, high: 2, critical: 0 });
  });

  it('worst first, by fingerprint within a tier, cut at the limit — and the input is left alone', () => {
    const input = [f('low', 'z'), f('critical', 'b'), f('high', 'b'), f('critical', 'a'), f('medium', 'm')];
    expect(topFindings(input, 3).map((x) => `${x.severity}:${x.fingerprint}`)).toEqual(['critical:a', 'critical:b', 'high:b']);
    expect(input[0]?.fingerprint).toBe('z');
  });
});
