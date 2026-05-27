import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { ruffParser } from '../../../../src/runners/scannerParsers/ruff.js';

const here = dirname(fileURLToPath(import.meta.url));
const FIXTURE = resolve(here, '../../../fixtures/scanners/ruff.json');

describe('ruffParser', () => {
  it('produces one Finding per ruff entry', () => {
    const { findings } = ruffParser.parse(readFileSync(FIXTURE, 'utf8'));
    expect(findings).toHaveLength(3);
  });

  it('classifies S* codes as security/high', () => {
    const { findings } = ruffParser.parse(readFileSync(FIXTURE, 'utf8'));
    const s = findings.find((f) => f.rule_id === 'S301');
    expect(s?.severity).toBe('high');
    expect(s?.category).toBe('security');
  });

  it('classifies F* codes as quality/medium', () => {
    const { findings } = ruffParser.parse(readFileSync(FIXTURE, 'utf8'));
    const f = findings.find((f) => f.rule_id === 'F401');
    expect(f?.severity).toBe('medium');
    expect(f?.category).toBe('quality');
  });

  it('classifies W* codes as quality/low', () => {
    const { findings } = ruffParser.parse(readFileSync(FIXTURE, 'utf8'));
    const w = findings.find((f) => f.rule_id === 'W291');
    expect(w?.severity).toBe('low');
  });

  it('sets fix_available based on the presence of a fix payload', () => {
    const { findings } = ruffParser.parse(readFileSync(FIXTURE, 'utf8'));
    expect(findings.find((f) => f.rule_id === 'F401')?.fix_available).toBe(true);
    expect(findings.find((f) => f.rule_id === 'S301')?.fix_available).toBe(false);
  });
});
