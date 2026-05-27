import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { jscpdParser } from '../../../../src/runners/scannerParsers/jscpd.js';

const here = dirname(fileURLToPath(import.meta.url));
const FIXTURE = resolve(here, '../../../fixtures/scanners/jscpd.json');

describe('jscpdParser', () => {
  it('produces one Finding per duplicate pair', () => {
    const { findings } = jscpdParser.parse(readFileSync(FIXTURE, 'utf8'));
    expect(findings).toHaveLength(2);
  });

  it('anchors findings at firstFile and references secondFile in the message', () => {
    const { findings } = jscpdParser.parse(readFileSync(FIXTURE, 'utf8'));
    const [first] = findings;
    expect(first?.file_path).toBe('src/billing.js');
    expect(first?.message).toContain('src/invoice.js');
  });

  it('uses severity=low and category=quality for all duplicates', () => {
    const { findings } = jscpdParser.parse(readFileSync(FIXTURE, 'utf8'));
    expect(findings.every((f) => f.severity === 'low')).toBe(true);
    expect(findings.every((f) => f.category === 'quality')).toBe(true);
    expect(findings.every((f) => f.subcategory === 'duplicate')).toBe(true);
  });

  it('returns no findings on empty input', () => {
    expect(jscpdParser.parse('{}').findings).toEqual([]);
  });
});
