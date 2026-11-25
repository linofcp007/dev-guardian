/**
 * The METRIC judge (`src/metrics/judge.ts`) against every judge case of the
 * shared contract, `test/fixtures/metrics/metric-lines.v1.json`, and the two
 * rules both readers add to it: the verdict is symmetric (a
 * small improvement inside the tolerance is `within`), and a current line that
 * adds a term the reference lacks does not create a judgment.
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { decimalString, parseDecimal } from '../../../src/metrics/decimal.js';
import { judgeMetric, judgmentNumbers } from '../../../src/metrics/judge.js';
import { readMetricLine, type MetricReading } from '../../../src/metrics/metricLine.js';

const FIXTURE = fileURLToPath(new URL('../../fixtures/metrics/metric-lines.v1.json', import.meta.url));

interface JudgeCase {
  id: string;
  reference: string | null;
  current: string;
  expect: { verdict: string; why: string[] | null; loosened: string | null; delta: number | null; applied: number | null };
}
const fx = JSON.parse(readFileSync(FIXTURE, 'utf8')) as { judge: JudgeCase[] };

function reading(text: string): MetricReading {
  const r = readMetricLine(text);
  if (r.kind !== 'metric') throw new Error(`not a metric line: ${text}`);
  return r.reading;
}

function judged(reference: string | null, current: string) {
  const j = judgeMetric(reference === null ? null : reading(reference), reading(current));
  return { verdict: j.verdict, why: j.why === null ? null : [...j.why], loosened: j.loosened, ...judgmentNumbers(j) };
}

describe('metric-lines/1 — the fixture, judge case by judge case', () => {
  it.each(fx.judge.map((c) => [c.id, c] as const))('%s', (_id, c) => {
    expect(judged(c.reference, c.current)).toEqual(c.expect);
  });

  it('the decimals are exact: 122.4 - 120 is 2.4, never 2.4000000000000057', () => {
    const j = judgeMetric(reading('METRIC b=120 kB better=lower tolerance=2%'), reading('METRIC b=122.4 kB'));
    expect(j.delta === null ? null : decimalString(j.delta)).toBe('2.4');
    expect(j.applied === null ? null : decimalString(j.applied)).toBe('2.4');
  });
});

describe('the judge — the two rules both readers add', () => {
  it('(1) symmetric: worse or better by MORE than the tolerance; a small improvement inside it is within', () => {
    const ref = 'METRIC b=120 kB better=lower tolerance=2%';
    expect(judged(ref, 'METRIC b=118 kB').verdict).toBe('within');
    expect(judged(ref, 'METRIC b=117.6 kB').verdict).toBe('within');
    expect(judged(ref, 'METRIC b=117.59 kB').verdict).toBe('improved');
    const up = 'METRIC ops=100 better=higher tolerance=5';
    expect(judged(up, 'METRIC ops=104').verdict).toBe('within');
    expect(judged(up, 'METRIC ops=106').verdict).toBe('improved');
    expect(judged(up, 'METRIC ops=95').verdict).toBe('within');
    expect(judged(up, 'METRIC ops=94.9').verdict).toBe('regressed');
  });

  it("(2) the terms are the reference's: a current line adding a direction or a tolerance creates no judgment", () => {
    expect(judged('METRIC t=30 s', 'METRIC t=99 s better=lower tolerance=1%')).toEqual({
      verdict: 'unjudged',
      why: ['better', 'tolerance'],
      loosened: null,
      delta: 69,
      applied: null,
    });
    expect(judged('METRIC t=30 s better=lower', 'METRIC t=99 s better=lower tolerance=1%')).toMatchObject({
      verdict: 'unjudged',
      why: ['tolerance'],
      loosened: null,
    });
    expect(judged('METRIC t=30 s tolerance=1', 'METRIC t=99 s better=lower tolerance=1')).toMatchObject({
      verdict: 'unjudged',
      why: ['better'],
      loosened: null,
    });
  });

  it('a unit added or dropped is a changed unit: not compared, said once', () => {
    expect(judged('METRIC n=5 better=lower tolerance=0', 'METRIC n=9 ms better=lower tolerance=0')).toEqual({
      verdict: 'unjudged',
      why: ['unit'],
      loosened: 'unit',
      delta: null,
      applied: null,
    });
  });

  it('one loosened term is said: a changed unit first, then the direction, then the tolerance', () => {
    expect(judged('METRIC s=120 kB better=lower tolerance=2%', 'METRIC s=0.1 MB better=higher tolerance=9%').loosened).toBe('unit');
    expect(judged('METRIC s=120 kB better=lower tolerance=2%', 'METRIC s=121 kB better=higher tolerance=9%').loosened).toBe('better');
    expect(judged('METRIC s=120 kB better=lower tolerance=2%', 'METRIC s=121 kB better=lower tolerance=9%').loosened).toBe('tolerance');
    expect(judged('METRIC s=120 kB better=lower tolerance=2%', 'METRIC s=121 kB better=lower tolerance=2.4').loosened).toBeNull();
  });

  it('a loosened direction is said even when no tolerance lets the value be judged', () => {
    expect(judged('METRIC t=30 s better=lower', 'METRIC t=31 s better=higher')).toMatchObject({
      verdict: 'unjudged',
      why: ['tolerance'],
      loosened: 'better',
    });
  });

  it('exact decimals hold at the grammar\'s extremes', () => {
    expect(decimalString(parseDecimal('1.5e3') ?? { coef: 0n, exp: 0 })).toBe('1500');
    expect(decimalString(parseDecimal('-0.000000001e-5') ?? { coef: 0n, exp: 0 })).toBe('-0.00000000000001');
    const tiny = judged('METRIC x=1e-300 better=lower tolerance=0', 'METRIC x=2e-300 better=lower tolerance=0');
    expect(tiny.verdict).toBe('regressed');
  });
});

describe('the judge — parity with dev-spec 1.41 metric.js where the fixture is silent', () => {
  it('parity with dev-spec 1.41 metric.js: a changed unit and a flipped better= say loosened unit, and why lists the missing terms, then unit', () => {
    expect(judged('METRIC s=120 kB better=lower tolerance=2%', 'METRIC s=0.1 MB better=higher tolerance=2%')).toEqual({
      verdict: 'unjudged', why: ['unit'], loosened: 'unit', delta: null, applied: null,
    });
    expect(judged('METRIC s=120 kB better=lower', 'METRIC s=0.1 MB better=higher')).toEqual({
      verdict: 'unjudged', why: ['tolerance', 'unit'], loosened: 'unit', delta: null, applied: null,
    });
    expect(judged('METRIC s=120 kB', 'METRIC s=0.1 MB better=higher tolerance=1')).toEqual({
      verdict: 'unjudged', why: ['better', 'tolerance', 'unit'], loosened: 'unit', delta: null, applied: null,
    });
  });
});
