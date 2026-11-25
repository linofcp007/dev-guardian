/**
 * The METRIC line reader (`src/metrics/metricLine.ts`) against the shared
 * contract, `test/fixtures/metrics/metric-lines.v1.json` (its bytes are pinned
 * by metricLinesFixture.test.ts), case by case — and the points the fixture
 * leaves to each reader's own suite: tokens split on runs
 * of blanks, the known keys in any order, `__proto__` an ordinary name, a
 * candidate over 512 bytes a drop, a malformed repeat never replacing a
 * reading, CSI sequences removed, and each bound's drop said.
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  METRIC_BOUNDS,
  readMetricLine,
  readMetricOutput,
  type LineRead,
  type MetricOutput,
  type MetricReading,
} from '../../../src/metrics/metricLine.js';
import { expectNearReference } from '../../helpers/timing.js';

const FIXTURE = fileURLToPath(new URL('../../fixtures/metrics/metric-lines.v1.json', import.meta.url));

interface Tol {
  amount: number;
  percent: boolean;
}
interface Reading {
  value: number;
  unit: string | null;
  better: string | null;
  tolerance: Tol | null;
}
interface LineCase {
  id: string;
  text: string;
  expect: { kind: string } & Partial<Reading> & { name?: string };
}
interface OutputCase {
  id: string;
  text: string;
  expect: { metrics: Record<string, Reading>; repeats: number; malformed: number; dropped: string[] };
}
const fx = JSON.parse(readFileSync(FIXTURE, 'utf8')) as {
  bounds: Record<string, number>;
  grammar: { unitMaxChars: number; name: string; number: string };
  lines: LineCase[];
  outputs: OutputCase[];
};

function asFixture(r: MetricReading): Reading {
  return {
    value: r.value,
    unit: r.unit,
    better: r.better,
    tolerance: r.tolerance === null ? null : { amount: Number(r.tolerance.raw), percent: r.tolerance.percent },
  };
}

function lineAsFixture(read: LineRead): LineCase['expect'] {
  if (read.kind !== 'metric') return { kind: read.kind };
  return { kind: 'metric', name: read.reading.name, ...asFixture(read.reading) };
}

function outputAsFixture(o: MetricOutput): OutputCase['expect'] {
  return {
    metrics: Object.fromEntries([...o.metrics].map(([name, r]) => [name, asFixture(r)])),
    repeats: o.repeats,
    malformed: o.malformed,
    dropped: [...o.dropped],
  };
}

describe('metric-lines/1 — the fixture, line by line', () => {
  it('the reader uses the fixture bounds', () => {
    expect({ ...METRIC_BOUNDS }).toEqual(fx.bounds);
  });

  it.each(fx.lines.map((c) => [c.id, c] as const))('%s', (_id, c) => {
    expect(lineAsFixture(readMetricLine(c.text))).toEqual(c.expect);
  });
});

describe('metric-lines/1 — the fixture, whole outputs', () => {
  it.each(fx.outputs.map((c) => [c.id, c] as const))('%s', (_id, c) => {
    const got = outputAsFixture(readMetricOutput(c.text));
    expect(got).toEqual(c.expect);
    // Key order too: a reading's names in the order their winning lines were printed.
    expect(Object.keys(got.metrics)).toEqual(Object.keys(c.expect.metrics));
  });
});

const metric = (text: string): MetricReading => {
  const r = readMetricLine(text);
  if (r.kind !== 'metric') throw new Error(`not a metric: ${text} (${r.kind})`);
  return r.reading;
};

describe("metric-lines/1 — what the fixture leaves to each reader's suite", () => {
  it('(3) tokens split on runs of blanks, tabs included, and a trailing blank is ignored', () => {
    expect(asFixture(metric('METRIC x=1\t\tms   better=lower \ttolerance=2%  \t'))).toEqual({
      value: 1,
      unit: 'ms',
      better: 'lower',
      tolerance: { amount: 2, percent: true },
    });
    expect(metric('METRIC\tx=1').name).toBe('x');
  });

  it('(4) the known keys are read in any order, and each at most once', () => {
    expect(asFixture(metric('METRIC x=1 kB tolerance=2% better=lower'))).toEqual({
      value: 1,
      unit: 'kB',
      better: 'lower',
      tolerance: { amount: 2, percent: true },
    });
    expect(asFixture(metric('METRIC x=1 runs=5 better=higher'))).toMatchObject({ better: 'higher' });
    expect(readMetricLine('METRIC x=1 better=lower better=higher')).toEqual({ kind: 'malformed', part: 'better' });
    expect(readMetricLine('METRIC x=1 tolerance=1 tolerance=2')).toEqual({ kind: 'malformed', part: 'tolerance' });
    expect(readMetricLine('METRIC x=1 tolerance=-1')).toEqual({ kind: 'malformed', part: 'tolerance' });
    expect(readMetricLine('METRIC x=1 tolerance=1e400%')).toEqual({ kind: 'malformed', part: 'tolerance' });
    expect(readMetricLine('METRIC x=1 kB higher')).toEqual({ kind: 'malformed', part: 'token' });
  });

  it('(5) __proto__, constructor and prototype are ordinary names', () => {
    const o = readMetricOutput('METRIC __proto__=1\nMETRIC constructor=2 ms\nMETRIC prototype=3\nMETRIC toString=4\n');
    expect([...o.metrics.keys()]).toEqual(['__proto__', 'constructor', 'prototype', 'toString']);
    expect(o.metrics.get('__proto__')?.value).toBe(1);
    expect(o.metrics.get('constructor')?.unit).toBe('ms');
    expect(o.repeats).toBe(0);
  });

  it('(6) a candidate over 512 bytes is a drop (candidateBytes), never malformed; one of 512 is read', () => {
    const at = (bytes: number): string => {
      const head = 'METRIC x=1 ms runs=';
      return head + 'a'.repeat(bytes - head.length);
    };
    expect(Buffer.byteLength(at(512))).toBe(512);
    const read = readMetricOutput(`${at(512)}\n`);
    expect(read.metrics.get('x')?.value).toBe(1);
    expect(read.dropped).toEqual([]);
    const over = readMetricOutput(`METRIC y=2\n${at(513)}\n`);
    expect([...over.metrics.keys()]).toEqual(['y']);
    expect(over.malformed).toBe(0);
    expect(over.dropped).toEqual(['candidateBytes']);
    // Bytes, not characters: 300 two-byte characters are 600 bytes.
    const wide = readMetricOutput(`METRIC z=1 ${'é'.repeat(300)}=1\n`);
    expect(wide.dropped).toEqual(['candidateBytes']);
  });

  it('(7) a later malformed line of a name already read is counted, and the last VALID value stands', () => {
    const o = readMetricOutput('METRIC p95=12 ms better=lower\nMETRIC p95=oops ms\n');
    expect(o.metrics.get('p95')?.value).toBe(12);
    expect(o.malformed).toBe(1);
    expect(o.repeats).toBe(0);
    expect(o.malformedLines).toEqual([{ text: 'METRIC p95=oops ms', part: 'value' }]);
  });

  it('(8) repeats are the sum over names of (occurrences - 1)', () => {
    const o = readMetricOutput('METRIC a=1\nMETRIC b=1\nMETRIC a=2\nMETRIC a=3\nMETRIC b=2\n');
    expect(o.repeats).toBe(3);
    expect(o.metrics.get('a')?.value).toBe(3);
    expect(o.metrics.get('b')?.value).toBe(2);
    expect([...o.metrics.keys()]).toEqual(['a', 'b']);
  });

  it('(9) ANSI CSI sequences are removed before the line is read', () => {
    const o = readMetricOutput('\u001b[32mMETRIC heap_mb=48 MB better=lower tolerance=5%\u001b[0m\n  \u001b[2K# METRIC t=3 s\n');
    expect(asFixture(o.metrics.get('heap_mb') ?? metric('METRIC none=0'))).toEqual({
      value: 48,
      unit: 'MB',
      better: 'lower',
      tolerance: { amount: 5, percent: true },
    });
    expect(o.metrics.get('t')?.unit).toBe('s');
    // Only CSI: another escape stays, and the line is no candidate.
    expect(readMetricLine('\u001b]0;title\u0007METRIC x=1').kind).toBe('ignored');
  });

  it('(10) a unit is one token of at most 16 characters, any but a blank or =', () => {
    expect(metric('METRIC x=1 abcdefghijklmnop').unit).toBe('abcdefghijklmnop');
    expect(metric('METRIC x=1 µs/req').unit).toBe('µs/req');
    expect(metric('METRIC x=1 <b>').unit).toBe('<b>');
    expect(readMetricLine(`METRIC x=1 ${'é'.repeat(17)}`)).toEqual({ kind: 'malformed', part: 'unit' });
    // Characters, not UTF-16 units: 9 emoji are 18 units and 9 characters.
    const emoji = String.fromCodePoint(0x1f680).repeat(9);
    expect(metric(`METRIC x=1 ${emoji}`).unit).toBe(emoji);
  });

  it('the number is the grammar, not what Number() accepts', () => {
    for (const v of ['.5', '5.', '+5', '0x10', '007', '1_000', '1234567890123456', '1.0123456789', '1e1000', '1e+', ' 1']) {
      expect(readMetricLine(`METRIC x=${v}`), v).toEqual({ kind: 'malformed', part: 'value' });
    }
    expect(metric('METRIC x=123456789012345.123456789e-999').value).toBe(0);
  });

  it('the keyword is a word of its own: METRICx=1 is no attempt', () => {
    for (const t of ['METRICx=1', 'METRIC_x=1', 'METRIC-x=1']) expect(readMetricLine(t), t).toEqual({ kind: 'ignored' });
  });
});

describe('metric-lines/1 — the bounds, each said when it drops input', () => {
  const many = (n: number, line: (i: number) => string): string => Array.from({ length: n }, (_, i) => `${line(i)}\n`).join('');

  it('at most 1,000 candidates are walked from the END: the 1,001st from the end is dropped, and said', () => {
    const exact = readMetricOutput(`METRIC first=1\n${many(999, (i) => `METRIC m=${i}`)}`);
    expect(exact.metrics.get('first')?.value).toBe(1);
    expect(exact.dropped).toEqual([]);
    const past = readMetricOutput(`METRIC first=1\n${many(1000, (i) => `METRIC m=${i}`)}`);
    expect(past.metrics.has('first')).toBe(false);
    expect(past.metrics.get('m')?.value).toBe(999);
    expect(past.repeats).toBe(999);
    expect(past.dropped).toEqual(['candidates']);
  });

  it('a candidate is a line the keyword starts: ignored candidates count, lines that only mention METRIC do not', () => {
    const ignored = readMetricOutput(`METRIC first=1\n${many(1000, () => 'METRIC | BEFORE | AFTER')}`);
    expect(ignored.dropped).toEqual(['candidates']);
    const traces = readMetricOutput(`METRIC first=1\n${many(5000, (i) => `+ echo 'METRIC m=${i}'`)}`);
    expect(traces.metrics.get('first')?.value).toBe(1);
    expect(traces.dropped).toEqual([]);
  });

  it('the bounds are injectable, and the names kept are the ones printed last', () => {
    const o = readMetricOutput('METRIC a=1\nMETRIC b=2\nMETRIC c=3\nMETRIC a=4\n', { bounds: { names: 2 } });
    expect([...o.metrics.keys()]).toEqual(['c', 'a']);
    expect(o.dropped).toEqual(['names']);
  });

  it('a truncated output says readBytes, and its cut first line is never read', () => {
    const o = readMetricOutput("METRIC x=1'\nMETRIC y=2\n", { truncated: true });
    expect([...o.metrics.keys()]).toEqual(['y']);
    expect(o.dropped).toEqual(['readBytes']);
    expect(readMetricOutput('METRIC x=1', { truncated: true }).metrics.size).toBe(0);
  });

  it('every dropped bound is listed once, in the fixture order', () => {
    const big = `METRIC w=1 ${'a'.repeat(600)}=1\n`;
    const o = readMetricOutput(`cut line\n${big}METRIC a=1\nMETRIC b=1\n`, { truncated: true, bounds: { names: 1 } });
    expect(o.dropped).toEqual(['readBytes', 'candidateBytes', 'names']);
  });

  it('keeps at most 5 malformed lines to show, the last ones printed, while counting all', () => {
    const o = readMetricOutput(many(8, (i) => `METRIC m${i}=x${i}`));
    expect(o.malformed).toBe(8);
    expect(o.malformedLines.map((l) => l.text)).toEqual(['METRIC m3=x3', 'METRIC m4=x4', 'METRIC m5=x5', 'METRIC m6=x6', 'METRIC m7=x7']);
  });
});

describe('metric-lines/1 — the walk is linear (cost guard)', () => {
  it('a line holding the keyword twice is read once', () => {
    const o = readMetricOutput('first\nMETRIC a=1 METRIC\nlast\n');
    expect(o.metrics.get('a')?.unit).toBe('METRIC');
    expect(o.repeats).toBe(0);
  });

  // The same bytes and the same hits two ways (each after a first line: the walk
  // stops at the output's first line, whatever it does before): one line holding the keyword
  // 80,000 times, and 80,000 short lines holding it once. The walk passes a
  // line once whatever it holds; taking each hit's line again would make the
  // first side quadratic (one line of ~1 MiB walked 80,000 times).
  it('one long line of keyword hits costs what the same bytes as short lines cost', () => {
    const unit = 'x METRIC y ';
    const n = 80_000;
    const oneLine = `start\n${unit.repeat(n).slice(0, -1)}\n`;
    const shortLines = `start\n${`${unit.slice(0, -1)}\n`.repeat(n)}`;
    expect(oneLine.length).toBe(shortLines.length);
    expectNearReference(
      'readMetricOutput, one line of 80,000 keyword hits',
      () => void readMetricOutput(oneLine),
      () => void readMetricOutput(shortLines),
      { maxRatio: 8 },
    );
  });
});

// Where the fixture is silent, dev-spec-driven 1.41's reader (mcp/lib/engine/metric.js) chose these, and both
// readers must agree: one test per point.
describe('metric-lines/1 — parity with dev-spec 1.41 metric.js where the fixture is silent', () => {
  it('parity with dev-spec 1.41 metric.js: a known key given twice on one line is malformed', () => {
    expect(readMetricLine('METRIC x=1 better=lower better=lower')).toEqual({ kind: 'malformed', part: 'better' });
    expect(readMetricLine('METRIC x=1 tolerance=2% tolerance=2%')).toEqual({ kind: 'malformed', part: 'tolerance' });
  });

  it('parity with dev-spec 1.41 metric.js: a unit only right after the number, never after a key=value', () => {
    expect(metric('METRIC x=12 ms better=lower').unit).toBe('ms');
    expect(readMetricLine('METRIC x=12 better=lower ms')).toEqual({ kind: 'malformed', part: 'token' });
    expect(readMetricLine('METRIC x=12 runs=5 ms')).toEqual({ kind: 'malformed', part: 'token' });
  });

  it('parity with dev-spec 1.41 metric.js: a negative tolerance is malformed', () => {
    for (const t of ['-1', '-2%', '-0']) expect(readMetricLine(`METRIC x=1 tolerance=${t}`), t).toEqual({ kind: 'malformed', part: 'tolerance' });
  });

  it('parity with dev-spec 1.41 metric.js: a lone CR is no line start; only a CR before the LF is stripped', () => {
    const o = readMetricOutput('progress 50%\rMETRIC a=1\nMETRIC b=2\r\n');
    expect([...o.metrics.keys()]).toEqual(['b']);
    expect(o.malformed).toBe(0);
    expect(readMetricLine('METRIC c=3\r')).toMatchObject({ kind: 'metric' });
  });
});
