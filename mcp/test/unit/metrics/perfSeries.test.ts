/**
 * perf_check's series rules (`src/metrics/perfSeries.ts`): the reference is
 * the median of the last 3–5 earlier runs that have the metric, a regressed
 * run never enters a later reference, `confirmed` is the newest earlier run's
 * verdict, and the series key is a property of the run. The tool's own reads
 * and writes are test/integration/perfHistory.test.ts.
 *
 * The Lighthouse numbers are those of 7 real Lighthouse 13.5.0 runs of one
 * static page (LCP 1624.6–1630.3 ms, TTFB 0–4 ms, CLS 0.148, 40,269 bytes).
 */

import { describe, expect, it } from 'vitest';
import {
  judgeSeries,
  k6Samples,
  k6Series,
  lighthouseSamples,
  lighthouseSeries,
  PERF_RULES,
  type PerfMetricHistory,
  type SeriesRun,
  seriesHint,
  seriesRunOf,
} from '../../../src/metrics/perfSeries.js';

let clock = Date.parse('2026-11-01T00:00:00.000Z');
/** Earlier runs, given OLDEST first (the order they ran); returned newest first, as the tool reads them. */
function runs(...rs: Array<Record<string, number | [number, string]>>): SeriesRun[] {
  return rs
    .map((r) => {
      clock += 60_000;
      const metrics = new Map<string, { value: number; unit: string | null }>();
      const verdicts = new Map<string, string>();
      for (const [name, v] of Object.entries(r)) {
        const [value, verdict] = Array.isArray(v) ? v : [v, 'within'];
        metrics.set(name, { value, unit: name.endsWith('_ms') ? 'ms' : null });
        verdicts.set(name, verdict);
      }
      return { startedAt: new Date(clock).toISOString(), metrics, verdicts };
    })
    .reverse();
}

const lcp = (value: number) => ({ name: 'perf.lcp_ms', value, unit: 'ms' });
const one = (earlier: SeriesRun[], value: number): PerfMetricHistory => {
  const [m] = judgeSeries(earlier, [lcp(value)]);
  if (m === undefined) throw new Error('no verdict');
  return m;
};

describe('judgeSeries — the window', () => {
  it('H1: the first run is new, the 2nd and 3rd unjudged (too few runs, with their delta), the 4th judged', () => {
    expect(one([], 2000)).toMatchObject({ verdict: 'new', previous: null, reference: null, runs: 0 });
    expect(one(runs({ 'perf.lcp_ms': 2000 }), 2600)).toMatchObject({
      verdict: 'unjudged', why: ['too_few_runs'], previous: 2000, reference: 2000, runs: 1, delta: 600,
    });
    expect(one(runs({ 'perf.lcp_ms': 2000 }, { 'perf.lcp_ms': 2000 }), 2600)).toMatchObject({ verdict: 'unjudged', runs: 2 });
    expect(one(runs({ 'perf.lcp_ms': 2000 }, { 'perf.lcp_ms': 2000 }, { 'perf.lcp_ms': 2000 }), 2600)).toMatchObject({
      verdict: 'regressed', runs: 3, reference: 2000, delta: 600, applied: 200,
    });
  });

  it('H2: the median, not the mean — [2000 x4, 6000] then 2500 regresses', () => {
    const earlier = runs(...[2000, 2000, 2000, 2000, 6000].map((v) => ({ 'perf.lcp_ms': v })));
    expect(one(earlier, 2500)).toMatchObject({ verdict: 'regressed', reference: 2000 });
  });

  it('H3: at most the last 5 runs — [2000 x4, 2600 x3] (oldest first) then 2700 is within', () => {
    const earlier = runs(...[2000, 2000, 2000, 2000, 2600, 2600, 2600].map((v) => ({ 'perf.lcp_ms': v })));
    expect(one(earlier, 2700)).toMatchObject({ verdict: 'within', reference: 2600, runs: 5 });
  });

  it('an even window takes the middle two, exactly', () => {
    const earlier = runs(...[1000, 1001, 1002, 1003].map((v) => ({ 'perf.lcp_ms': v })));
    expect(one(earlier, 1001.5)).toMatchObject({ reference: 1001.5, delta: 0, runs: 4 });
  });

  it('H7: every timing has a floor — the measured TTFB 0 -> 4 ms is within', () => {
    const earlier = runs({ 'perf.ttfb_ms': 4 }, { 'perf.ttfb_ms': 0 }, { 'perf.ttfb_ms': 1 }, { 'perf.ttfb_ms': 0 }, { 'perf.ttfb_ms': 2 });
    const [m] = judgeSeries(earlier, [{ name: 'perf.ttfb_ms', value: 4, unit: 'ms' }]);
    expect(m).toMatchObject({ verdict: 'within', reference: 1, applied: 50 });
  });

  it('H13: each metric over the runs that HAVE it — 3 runs with LCP, then 3 without, is judged with 3', () => {
    const earlier = runs({ 'perf.lcp_ms': 2000 }, { 'perf.lcp_ms': 2000 }, { 'perf.lcp_ms': 2000 }, { 'perf.cls': 0.1 }, { 'perf.cls': 0.1 }, { 'perf.cls': 0.1 });
    expect(one(earlier, 2000)).toMatchObject({ verdict: 'within', runs: 3 });
  });
});

describe('judgeSeries — a regression is never washed out', () => {
  it('H12: 2000 x5 then 2500 x4 — every 2500 regressed, from the 2nd on confirmed', () => {
    let earlier = runs(...[2000, 2000, 2000, 2000, 2000].map((v) => ({ 'perf.lcp_ms': v })));
    const verdicts: string[] = [];
    for (let i = 0; i < 4; i += 1) {
      const m = one(earlier, 2500);
      verdicts.push(`${m.verdict}${m.confirmed === true ? '!' : ''}`);
      // The run is kept with its verdict, newest first.
      clock += 60_000;
      earlier = [
        { startedAt: new Date(clock).toISOString(), metrics: new Map([['perf.lcp_ms', { value: 2500, unit: 'ms' }]]), verdicts: new Map([['perf.lcp_ms', m.verdict]]) },
        ...earlier,
      ];
    }
    expect(verdicts).toEqual(['regressed', 'regressed!', 'regressed!', 'regressed!']);
  });

  it('H8: confirmed is the NEWEST earlier run with the metric — an older regression confirms nothing', () => {
    const base = [2000, 2000, 2000, 2000].map((v) => ({ 'perf.lcp_ms': v }));
    const olderRegressed = runs(...base, { 'perf.lcp_ms': [2600, 'regressed'] }, { 'perf.lcp_ms': 2000 });
    expect(one(olderRegressed, 2600)).toMatchObject({ verdict: 'regressed', confirmed: false });
    const newestRegressed = runs(...base, { 'perf.lcp_ms': [2600, 'regressed'] });
    expect(one(newestRegressed, 2600)).toMatchObject({ verdict: 'regressed', confirmed: true, previous: 2600 });
    // A run with no LCP in between does not hide the regression before it.
    const gap = runs(...base, { 'perf.lcp_ms': [2600, 'regressed'] }, { 'perf.cls': 0.1 });
    expect(one(gap, 2600)).toMatchObject({ confirmed: true });
  });

  it('H14: since is the median of the oldest 3 usable runs, dated by the oldest — report-only', () => {
    const earlier = runs(
      { 'perf.lcp_ms': [9000, 'regressed'] },
      { 'perf.lcp_ms': 2000 },
      { 'perf.lcp_ms': 2100 },
      { 'perf.lcp_ms': 2050 },
      ...[2900, 2950, 3000, 3050, 3100].map((v) => ({ 'perf.lcp_ms': v })),
    );
    const oldestUsable = earlier[earlier.length - 2]?.startedAt;
    const m = one(earlier, 3120);
    expect(m.since).toEqual({ value: 2050, at: oldestUsable });
    expect(m).toMatchObject({ verdict: 'within', reference: 3000 });
  });

  it('improved is said beyond the tolerance, and an unknown metric is recorded unjudged', () => {
    const earlier = runs(...[2000, 2000, 2000].map((v) => ({ 'perf.lcp_ms': v, 'k6.requests': 100 })));
    expect(one(earlier, 1700)).toMatchObject({ verdict: 'improved' });
    const [req] = judgeSeries(earlier, [{ name: 'k6.requests', value: 5000, unit: null }]);
    expect(req).toMatchObject({ verdict: 'unjudged', why: ['better', 'tolerance'], delta: 4900, better: null, tolerance: null });
  });
});

describe('the rules', () => {
  const ref = (name: string, unit: string | null, values: number[], value: number) => {
    const earlier = values.map((v) => ({ startedAt: '2026-11-01T00:00:00.000Z', metrics: new Map([[name, { value: v, unit }]]), verdicts: new Map<string, string>() }));
    return judgeSeries(earlier, [{ name, value, unit }])[0];
  };

  it('perf timings: 10%, at least 50 ms; CLS 0.01; page weight 1%; scores 2 points; k6 10%, at least 5 ms; errors 0.5 points', () => {
    expect(ref('perf.lcp_ms', 'ms', [3000, 3000, 3000], 3300)).toMatchObject({ verdict: 'within', applied: 300 });
    expect(ref('perf.lcp_ms', 'ms', [3000, 3000, 3000], 3300.01)).toMatchObject({ verdict: 'regressed' });
    expect(ref('perf.cls', null, [0.148, 0.148, 0.148], 0.158)).toMatchObject({ verdict: 'within', applied: 0.01 });
    expect(ref('perf.cls', null, [0.148, 0.148, 0.148], 0.1581)).toMatchObject({ verdict: 'regressed' });
    expect(ref('perf.bundle_size_kb', 'KB', [100, 100, 100], 101)).toMatchObject({ verdict: 'within', applied: 1 });
    expect(ref('lighthouse.performance', null, [93, 93, 93], 91)).toMatchObject({ verdict: 'within', better: 'higher' });
    expect(ref('lighthouse.performance', null, [93, 93, 93], 90)).toMatchObject({ verdict: 'regressed' });
    expect(ref('k6.latency_p95_ms', 'ms', [20, 20, 20], 25)).toMatchObject({ verdict: 'within', applied: 5 });
    expect(ref('k6.latency_p95_ms', 'ms', [20, 20, 20], 25.1)).toMatchObject({ verdict: 'regressed' });
    expect(ref('k6.error_rate_pct', '%', [1, 1, 1], 1.5)).toMatchObject({ verdict: 'within', applied: 0.5 });
    expect(PERF_RULES.length).toBe(6);
  });

  it('each tolerance at its edge — the floors, the page weight and the error rate', () => {
    expect(ref('perf.tbt_ms', 'ms', [100, 100, 100], 150)).toMatchObject({ verdict: 'within', applied: 50 });
    expect(ref('perf.tbt_ms', 'ms', [100, 100, 100], 150.01)).toMatchObject({ verdict: 'regressed' });
    expect(ref('perf.bundle_size_kb', 'KB', [100, 100, 100], 101.01)).toMatchObject({ verdict: 'regressed' });
    expect(ref('k6.error_rate_pct', '%', [1, 1, 1], 1.51)).toMatchObject({ verdict: 'regressed' });
    expect(ref('k6.latency_avg_ms', 'ms', [100, 100, 100], 110.01)).toMatchObject({ verdict: 'regressed', applied: 10 });
  });
});

describe('samples', () => {
  it('H15: Lighthouse — what it measured, an audit with no value is no sample; page weight in KB', () => {
    const samples = lighthouseSamples({
      scores: { performance: 93, accessibility: null },
      core_web_vitals: {
        'largest-contentful-paint': 1629.7,
        'cumulative-layout-shift': 0.15,
        'interaction-to-next-paint': null,
        'total-blocking-time': 0,
        'first-contentful-paint': 1629.7,
        'speed-index': 1629.7,
        'server-response-time': 4,
        'total-byte-weight': 40269,
      },
    });
    expect(samples.map((s) => s.name)).toEqual([
      'perf.lcp_ms', 'perf.fcp_ms', 'perf.speed_index_ms', 'perf.tbt_ms', 'perf.ttfb_ms', 'perf.cls',
      'perf.bundle_size_kb', 'lighthouse.performance',
    ]);
    expect(samples.find((s) => s.name === 'perf.bundle_size_kb')).toEqual({ name: 'perf.bundle_size_kb', value: 40269 / 1024, unit: 'KB' });
  });

  it('k6 — the latencies, the error rate as a percentage (exactly), the request count', () => {
    expect(k6Samples({ latency_avg_ms: 5, latency_p95_ms: 9, latency_p99_ms: null, error_rate: 0.07, requests_total: 10 })).toEqual([
      { name: 'k6.latency_avg_ms', value: 5, unit: 'ms' },
      { name: 'k6.latency_p95_ms', value: 9, unit: 'ms' },
      { name: 'k6.error_rate_pct', value: 7, unit: '%' },
      { name: 'k6.requests', value: 10, unit: null },
    ]);
  });
});

describe('the series key — a property of the run', () => {
  const lh = (url: string, version: string, cats: string[]) => lighthouseSeries(url, version, cats).key;

  it('H4: the page, without its fragment', () => {
    expect(lh('http://localhost:3000/', '13.5.0', ['performance'])).not.toBe(lh('http://localhost:3000/a', '13.5.0', ['performance']));
    expect(lh('http://localhost:3000/#top', '13.5.0', ['performance'])).toBe(lh('http://localhost:3000/', '13.5.0', ['performance']));
  });

  it("H5: Lighthouse's major version", () => {
    expect(lh('http://h/', '12.8.2', ['performance'])).not.toBe(lh('http://h/', '13.5.0', ['performance']));
    expect(lh('http://h/', '13.4.0', ['performance'])).toBe(lh('http://h/', '13.5.0', ['performance']));
  });

  it('H6b: the categories the report scored, in any order', () => {
    expect(lh('http://h/', '13.5.0', ['accessibility'])).not.toBe(lh('http://h/', '13.5.0', ['performance']));
    expect(lh('http://h/', '13.5.0', ['seo', 'performance'])).toBe(lh('http://h/', '13.5.0', ['performance', 'seo']));
  });

  it("the label never carries a URL's credentials", () => {
    const s = lighthouseSeries('https://user:secret@h.example/app#x', '13.5.0', ['performance']);
    expect(s.label).toBe('Lighthouse 13 · https://h.example/app · performance');
    expect(s.key).toMatch(/^[0-9a-f]{64}$/);
  });

  it('H6 and H6c: k6 — the script, its content, and the load k6 measured', () => {
    const a = k6Series('load/smoke.js', 'a'.repeat(64), 10).key;
    expect(k6Series('load/smoke.js', 'b'.repeat(64), 10).key).not.toBe(a);
    expect(k6Series('load/other.js', 'a'.repeat(64), 10).key).not.toBe(a);
    expect(k6Series('load/smoke.js', 'a'.repeat(64), 100).key).not.toBe(a);
    expect(k6Series('load/smoke.js', 'a'.repeat(64), 10).key).toBe(a);
  });
});

describe('stored rows and the hint', () => {
  it('reads a stored row defensively: a metric that is not a finite number is left out', () => {
    const r = seriesRunOf({
      started_at: 't',
      meta: { metrics: { 'perf.lcp_ms': { value: 1, unit: 'ms' }, bad: { value: 'x' }, worse: null, cls: { value: 0.1 } }, verdicts: { 'perf.lcp_ms': 'within', bad: 7 } },
    });
    expect(r === null ? null : [...r.metrics]).toEqual([['perf.lcp_ms', { value: 1, unit: 'ms' }], ['cls', { value: 0.1, unit: null }]]);
    expect(r === null ? null : [...r.verdicts]).toEqual([['perf.lcp_ms', 'within']]);
    expect(seriesRunOf({ started_at: 't', meta: { other: 1 } })).toBeNull();
    expect(seriesRunOf({ started_at: 't' })).toBeNull();
  });

  it('says a confirmed regression, a fresh one, a first run, too few runs, and nothing regressed', () => {
    const m = (over: Partial<PerfMetricHistory>): PerfMetricHistory => ({
      name: 'perf.lcp_ms', value: 1, unit: 'ms', previous: 1, reference: 1, runs: 5, delta: 0, better: 'lower',
      tolerance: '10%, at least 50 ms', applied: 50, verdict: 'within', ...over,
    });
    expect(seriesHint([m({ verdict: 'regressed', confirmed: true })])).toMatch(/two runs in a row/);
    expect(seriesHint([m({ verdict: 'regressed', confirmed: false })])).toMatch(/not yet confirmed: run perf_check again/);
    expect(seriesHint([m({ verdict: 'new' })])).toMatch(/^The first run of this target/);
    expect(seriesHint([m({ verdict: 'unjudged', why: ['too_few_runs'] })])).toMatch(/^Too few earlier runs/);
    expect(seriesHint([m({ verdict: 'improved' })])).toMatch(/perf\.lcp_ms improved/);
    expect(seriesHint([m({})])).toMatch(/^Nothing regressed: every judged metric/);
  });
});
