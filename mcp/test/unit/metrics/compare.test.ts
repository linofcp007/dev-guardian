/**
 * Two outputs compared (`src/metrics/compare.ts`): the exit code the
 * `metrics` command takes from it, and its three renderings. The command
 * itself, run as a process, is test/e2e/metricsCli.test.ts.
 */

import { describe, expect, it } from 'vitest';
import {
  compareMetricOutputs,
  metricsExitCode,
  metricsHuman,
  metricsJson,
  metricsMarkdown,
  type MetricsReportContext,
} from '../../../src/metrics/compare.js';
import { readMetricOutput } from '../../../src/metrics/metricLine.js';

const ctx = (over: Partial<MetricsReportContext> = {}): MetricsReportContext => ({
  toolVersion: '0.0.0-test',
  headFile: 'head.txt',
  baseFile: 'base.txt',
  strict: false,
  exitCode: 0,
  ...over,
});

const BASE = [
  'METRIC bundle-size=120 kB better=lower tolerance=2%',
  'METRIC tests.count=812 better=higher tolerance=0',
  'METRIC build_s=31.4 s better=lower',
  'METRIC gone=1',
].join('\n');

describe('compareMetricOutputs and the exit code', () => {
  it('judges each head metric against the base, lists what the head lacks, and exits 0 without --strict', () => {
    const head = readMetricOutput('METRIC bundle-size=125 kB better=lower tolerance=2%\nMETRIC tests.count=815 better=higher tolerance=0\nMETRIC build_s=33 s better=lower\nMETRIC fresh=3\n');
    const c = compareMetricOutputs(head, readMetricOutput(BASE));
    expect(c.comparisons.map((m) => [m.name, m.judgment.verdict])).toEqual([
      ['bundle-size', 'regressed'],
      ['tests.count', 'improved'],
      ['build_s', 'unjudged'],
      ['fresh', 'new'],
    ]);
    expect(c.missing).toEqual(['gone']);
    expect(metricsExitCode(c, false)).toBe(0);
    expect(metricsExitCode(c, true)).toBe(1);
  });

  it('--strict exits 1 for a regression, a loosened term, a missing metric or a malformed head line — and 0 when there is none', () => {
    const base = readMetricOutput('METRIC a=10 better=lower tolerance=1\n');
    const strict = (head: string): number => metricsExitCode(compareMetricOutputs(readMetricOutput(head), base), true);
    expect(strict('METRIC a=10.5 better=lower tolerance=1\n')).toBe(0);
    expect(strict('METRIC a=12 better=lower tolerance=1\n')).toBe(1);
    expect(strict('METRIC a=10 better=higher tolerance=1\n')).toBe(1);
    expect(strict('METRIC b=1\n')).toBe(1);
    expect(strict('METRIC a=10 better=lower tolerance=1\nMETRIC c=oops\n')).toBe(1);
    // Repeats are the format's own rule (the last line wins), not a failure.
    expect(strict('METRIC a=11 better=lower tolerance=1\nMETRIC a=10 better=lower tolerance=1\n')).toBe(0);
  });

  it('exits 2 when the head holds no METRIC line it could read, whatever --strict says', () => {
    for (const head of ['', 'nothing here\n', 'METRIC x=oops\n']) {
      const c = compareMetricOutputs(readMetricOutput(head), readMetricOutput(BASE));
      expect(metricsExitCode(c, false), JSON.stringify(head)).toBe(2);
      expect(metricsExitCode(c, true), JSON.stringify(head)).toBe(2);
    }
  });

  it('a base with no METRIC line is no reference: every head metric is new', () => {
    const c = compareMetricOutputs(readMetricOutput('METRIC a=1\nMETRIC b=2\n'), readMetricOutput('no metrics\n'));
    expect(c.comparisons.map((m) => m.judgment.verdict)).toEqual(['new', 'new']);
    expect(c.missing).toEqual([]);
    expect(metricsExitCode(c, true)).toBe(0);
  });
});

describe('the renderings', () => {
  const head = readMetricOutput('METRIC bundle-size=122.4 kB better=lower tolerance=2%\nMETRIC odd=1 a|b\nMETRIC esc=2 \u0007x\n');
  const base = readMetricOutput('METRIC bundle-size=120 kB better=lower tolerance=2%\nMETRIC odd=1 a|b\nMETRIC esc=2 \u0007x\n');
  const c = compareMetricOutputs(head, base);

  it('JSON: the stable keys, the reference terms, exact numbers', () => {
    const j = metricsJson(c, ctx());
    expect(Object.keys(j)).toEqual([
      'format', 'tool_version', 'exit_code', 'strict', 'head', 'base', 'comparisons',
      'regressed', 'improved', 'within', 'new', 'unjudged', 'loosened', 'missing',
    ]);
    expect(j['format']).toBe('metric-lines/1');
    const first = (j['comparisons'] as Array<Record<string, unknown>>)[0];
    expect(first).toEqual({
      name: 'bundle-size', unit: 'kB', base: 120, head: 122.4, delta: 2.4, applied: 2.4,
      better: 'lower', tolerance: { amount: 2, percent: true }, verdict: 'within', why: null, loosened: null,
    });
    expect(j['within']).toEqual(['bundle-size']);
  });

  it('markdown: a unit holding | stays in its cell, and names and units are code spans', () => {
    const md = metricsMarkdown(c, ctx());
    const row = md.split('\n').find((l) => l.startsWith('| `odd`'));
    expect(row).toBeDefined();
    // 6 columns: 7 unescaped pipes.
    expect((row ?? '').replace(/\\\|/g, '').split('|').length - 1).toBe(7);
    expect(row).toContain('`a\\|b`');
  });

  it('human and markdown: a control character read from a file is shown escaped, never raw', () => {
    for (const out of [metricsHuman(c, ctx()), metricsMarkdown(c, ctx())]) {
      expect(out).not.toContain('\u0007');
      expect(out).toContain('\\u{0007}');
    }
  });

  it('human: a head with nothing to read says so', () => {
    const empty = compareMetricOutputs(readMetricOutput('METRIC x=oops\n'), null);
    const text = metricsHuman(empty, ctx({ baseFile: null, exitCode: 2 }));
    expect(text).toMatch(/holds no METRIC line that could be read/);
    expect(text).toMatch(/1 malformed METRIC line/);
  });
});
