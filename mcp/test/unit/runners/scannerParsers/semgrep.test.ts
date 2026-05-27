import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { semgrepParser } from '../../../../src/runners/scannerParsers/semgrep.js';

const here = dirname(fileURLToPath(import.meta.url));
const FIXTURE = resolve(here, '../../../fixtures/scanners/semgrep.json');

function readFixture(): string {
  return readFileSync(FIXTURE, 'utf8');
}

describe('semgrepParser', () => {
  it('returns one Finding per result entry', () => {
    const { findings, cves } = semgrepParser.parse(readFixture());
    expect(findings).toHaveLength(3);
    expect(cves).toEqual([]);
  });

  it('upgrades security ERROR findings to critical', () => {
    const { findings } = semgrepParser.parse(readFixture());
    const xss = findings.find((f) => f.rule_id?.includes('express-xss'));
    expect(xss?.severity).toBe('critical');
    expect(xss?.category).toBe('security');
  });

  it('maps performance WARNING to medium and category=performance', () => {
    const { findings } = semgrepParser.parse(readFixture());
    const perf = findings.find((f) => f.rule_id?.endsWith('list-comprehension'));
    expect(perf?.severity).toBe('medium');
    expect(perf?.category).toBe('performance');
  });

  it('marks fix_available=true when extra.fix is present', () => {
    const { findings } = semgrepParser.parse(readFixture());
    const perf = findings.find((f) => f.rule_id?.endsWith('list-comprehension'));
    expect(perf?.fix_available).toBe(true);
  });

  it('produces stable fingerprints across re-parses', () => {
    const a = semgrepParser.parse(readFixture()).findings.map((f) => f.fingerprint);
    const b = semgrepParser.parse(readFixture()).findings.map((f) => f.fingerprint);
    expect(a).toEqual(b);
  });

  it('accepts already-parsed JSON in addition to raw strings', () => {
    const obj = JSON.parse(readFixture()) as unknown;
    const a = semgrepParser.parse(readFixture()).findings.length;
    const b = semgrepParser.parse(obj).findings.length;
    expect(a).toBe(b);
  });

  it('returns empty arrays on garbage input', () => {
    expect(semgrepParser.parse('not json').findings).toEqual([]);
    expect(semgrepParser.parse(null).findings).toEqual([]);
    expect(semgrepParser.parse({}).findings).toEqual([]);
  });
});
