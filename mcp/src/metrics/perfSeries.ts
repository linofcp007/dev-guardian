/**
 * `perf_check`'s history: every measured run is a `perf` scan row whose
 * `meta` holds its numbers, and the run is judged against the earlier runs of
 * the same SERIES — the same target measured the same way. Pure: the tool
 * reads the rows and writes the new one (`tools/perfCheck.ts`).
 *
 * - The series key is a property of the run, never a list of names: for
 *   Lighthouse the page (its href without the fragment), Lighthouse's major
 *   version and the categories the report scored; for k6 the script's
 *   project-relative path and content (sha256) and the `vus_max` k6 measured —
 *   10 VUs against 100 is another load, not a regression.
 * - Each metric is judged over the earlier runs that HAVE it: the reference is
 *   the median of the last 3–5 of them, and fewer than 3 is `unjudged`
 *   (`too_few_runs`), shown with its delta. A run whose verdict for the metric
 *   was `regressed` never enters a later reference, so a regression that is
 *   never fixed stays `regressed` — re-running it does not wash it out — and
 *   `confirmed` says the newest earlier run with the metric regressed too.
 * - `since` (report-only, no verdict): the median of the oldest 3 such runs
 *   the series still keeps, and when the oldest was taken — what a slow creep
 *   under the tolerance is read against.
 *
 * The rules ({@link PERF_RULES}) judge only these series and reach no gate;
 * the METRIC lines of `metric-lines/1` state their own terms (`judge.ts`).
 */

import { createHash } from 'node:crypto';
import {
  absolute,
  add,
  compare,
  type Decimal,
  decimalNumber,
  decimalOfNumber,
  half,
  maximum,
  multiply,
  negate,
  parseDecimal,
  shift,
  subtract,
} from './decimal.js';
import type { MetricVerdict } from './judge.js';
import type { Better } from './metricLine.js';

interface PerfSample {
  readonly name: string;
  readonly value: number;
  readonly unit: string | null;
}

interface PerfRule {
  readonly better: Better;
  /** A share of |reference|, in percent. */
  readonly percent?: string;
  /** With `percent`: the tolerance is never below this amount. */
  readonly floor?: string;
  /** An absolute amount. */
  readonly amount?: string;
  readonly text: string;
}

/**
 * The built-in rules, first match wins. Lighthouse's timings move by a few
 * milliseconds near zero (TTFB 0–4 ms across 7 runs of one static page), so
 * every timing has a floor. `k6.requests` has none: it is recorded, not judged.
 */
export const PERF_RULES: ReadonlyArray<{ readonly match: RegExp; readonly rule: PerfRule }> = [
  { match: /^perf\.[a-z_]+_ms$/, rule: { better: 'lower', percent: '10', floor: '50', text: '10%, at least 50 ms' } },
  { match: /^perf\.cls$/, rule: { better: 'lower', amount: '0.01', text: '0.01' } },
  { match: /^perf\.bundle_size_kb$/, rule: { better: 'lower', percent: '1', text: '1%' } },
  { match: /^lighthouse\./, rule: { better: 'higher', amount: '2', text: '2 points' } },
  { match: /^k6\.latency_[a-z0-9]+_ms$/, rule: { better: 'lower', percent: '10', floor: '5', text: '10%, at least 5 ms' } },
  { match: /^k6\.error_rate_pct$/, rule: { better: 'lower', amount: '0.5', text: '0.5 points' } },
];

function ruleFor(name: string): PerfRule | null {
  return PERF_RULES.find((r) => r.match.test(name))?.rule ?? null;
}

/** Lighthouse's audits as samples: [audit id, sample name, unit]. */
const LIGHTHOUSE_AUDITS: ReadonlyArray<readonly [string, string, string | null]> = [
  ['largest-contentful-paint', 'perf.lcp_ms', 'ms'],
  ['first-contentful-paint', 'perf.fcp_ms', 'ms'],
  ['speed-index', 'perf.speed_index_ms', 'ms'],
  ['total-blocking-time', 'perf.tbt_ms', 'ms'],
  ['interaction-to-next-paint', 'perf.inp_ms', 'ms'],
  ['server-response-time', 'perf.ttfb_ms', 'ms'],
  ['cumulative-layout-shift', 'perf.cls', null],
];

const finite = (v: unknown): v is number => typeof v === 'number' && Number.isFinite(v);

/** A Lighthouse run's samples: what it measured — an audit with no value (INP in a navigation run) is no sample. */
export function lighthouseSamples(summary: {
  scores: Record<string, number | null>;
  core_web_vitals: Record<string, number | null>;
}): PerfSample[] {
  const out: PerfSample[] = [];
  for (const [audit, name, unit] of LIGHTHOUSE_AUDITS) {
    const v = summary.core_web_vitals[audit];
    if (finite(v)) out.push({ name, value: v, unit });
  }
  // Lighthouse's total-byte-weight: every byte the page loaded — what budgets.yml's bundle_size_kb is read against.
  const bytes = summary.core_web_vitals['total-byte-weight'];
  if (finite(bytes)) out.push({ name: 'perf.bundle_size_kb', value: bytes / 1024, unit: 'KB' });
  for (const [category, score] of Object.entries(summary.scores)) {
    if (finite(score)) out.push({ name: `lighthouse.${category}`, value: score, unit: null });
  }
  return out;
}

/** A k6 run's samples, from `perf_check`'s k6 summary. */
export function k6Samples(summary: Record<string, unknown>): PerfSample[] {
  const out: PerfSample[] = [];
  for (const key of ['latency_avg_ms', 'latency_p95_ms', 'latency_p99_ms']) {
    const v = summary[key];
    if (finite(v)) out.push({ name: `k6.${key}`, value: v, unit: 'ms' });
  }
  const rate = summary['error_rate'];
  const exact = finite(rate) ? decimalOfNumber(rate) : null;
  if (exact !== null) out.push({ name: 'k6.error_rate_pct', value: decimalNumber(shift(exact, 2)), unit: '%' });
  const requests = summary['requests_total'];
  if (finite(requests)) out.push({ name: 'k6.requests', value: requests, unit: null });
  return out;
}

interface PerfSeries {
  /** Stored as `meta.series`: a digest, so a URL's credentials never reach the column. */
  readonly key: string;
  readonly label: string;
}

function digest(parts: readonly unknown[]): string {
  return createHash('sha256').update(JSON.stringify(parts)).digest('hex');
}

export function lighthouseSeries(url: string, lighthouseVersion: string | undefined, categories: readonly string[]): PerfSeries {
  const page = new URL(url);
  page.hash = '';
  const major = /^([0-9]+)\./.exec(lighthouseVersion ?? '')?.[1] ?? null;
  const scored = [...new Set(categories)].sort();
  const shown = new URL(page.href);
  shown.username = '';
  shown.password = '';
  return {
    key: digest(['lighthouse', major, page.href, scored]),
    label: `Lighthouse ${major ?? '?'} · ${shown.href} · ${scored.length > 0 ? scored.join(', ') : 'no category'}`,
  };
}

export function k6Series(script: string, contentSha256: string, vusMax: number | null): PerfSeries {
  return {
    key: digest(['k6', script, contentSha256, vusMax]),
    label: `k6 · ${script} (${contentSha256.slice(0, 12)}) · ${vusMax === null ? '? VUs' : `${vusMax} VUs`}`,
  };
}

/** One earlier run of the series, as its row's `meta` and start date hold it. */
export interface SeriesRun {
  readonly startedAt: string;
  readonly metrics: ReadonlyMap<string, { value: number; unit: string | null }>;
  readonly verdicts: ReadonlyMap<string, string>;
}

const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);

/** A stored row read back; null when its meta is not a perf run's. */
export function seriesRunOf(row: { started_at: string; meta?: Record<string, unknown> | undefined }): SeriesRun | null {
  const metrics = row.meta?.['metrics'];
  if (!isRecord(metrics)) return null;
  const out = new Map<string, { value: number; unit: string | null }>();
  for (const [name, m] of Object.entries(metrics)) {
    if (!isRecord(m) || !finite(m['value'])) continue;
    const unit = m['unit'];
    out.set(name, { value: m['value'], unit: typeof unit === 'string' ? unit : null });
  }
  const verdicts = new Map<string, string>();
  const stored = row.meta?.['verdicts'];
  if (isRecord(stored)) for (const [name, v] of Object.entries(stored)) if (typeof v === 'string') verdicts.set(name, v);
  return { startedAt: row.started_at, metrics: out, verdicts };
}

export interface PerfMetricHistory {
  readonly name: string;
  readonly value: number;
  readonly unit: string | null;
  /** The newest earlier run's value of this metric. */
  readonly previous: number | null;
  /** The median of the window, null when it is empty. */
  readonly reference: number | null;
  /** How many runs the reference is the median of. */
  readonly runs: number;
  /** value − reference. */
  readonly delta: number | null;
  readonly better: Better | null;
  readonly tolerance: string | null;
  /** The absolute tolerance a judged verdict used. */
  readonly applied: number | null;
  readonly verdict: MetricVerdict;
  readonly why?: readonly string[];
  readonly confirmed?: boolean;
  readonly since?: { readonly value: number; readonly at: string };
}

const WINDOW_MAX = 5;
const WINDOW_MIN = 3;
const SINCE_RUNS = 3;

function exactOf(n: number): Decimal {
  return decimalOfNumber(n) ?? { coef: 0n, exp: 0 };
}

function median(values: readonly number[]): Decimal {
  const sorted = values.map(exactOf).sort(compare);
  const mid = Math.floor(sorted.length / 2);
  const hi = sorted[mid] ?? { coef: 0n, exp: 0 };
  const lo = sorted[mid - 1];
  return sorted.length % 2 === 1 || lo === undefined ? hi : half(add(lo, hi));
}

function appliedOf(rule: PerfRule, reference: Decimal): Decimal {
  if (rule.amount !== undefined) return parseDecimal(rule.amount) ?? { coef: 0n, exp: 0 };
  const share = shift(multiply(parseDecimal(rule.percent ?? '0') ?? { coef: 0n, exp: 0 }, absolute(reference)), -2);
  return rule.floor === undefined ? share : maximum(share, parseDecimal(rule.floor) ?? { coef: 0n, exp: 0 });
}

/** Each sample judged against the earlier runs of its series, newest first. */
export function judgeSeries(earlier: readonly SeriesRun[], samples: readonly PerfSample[]): PerfMetricHistory[] {
  return samples.map((s) => {
    const having = earlier.filter((r) => r.metrics.get(s.name)?.unit === s.unit);
    const valueIn = (r: SeriesRun): number => r.metrics.get(s.name)?.value ?? 0;
    const newest = having[0];
    const rule = ruleFor(s.name);
    const base = {
      name: s.name,
      value: s.value,
      unit: s.unit,
      previous: newest === undefined ? null : valueIn(newest),
      better: rule?.better ?? null,
      tolerance: rule?.text ?? null,
    };
    if (newest === undefined) {
      return { ...base, reference: null, runs: 0, delta: null, applied: null, verdict: 'new' as const };
    }
    // A run that regressed on this metric never becomes part of a later reference.
    const usable = having.filter((r) => r.verdicts.get(s.name) !== 'regressed');
    const window = usable.slice(0, WINDOW_MAX);
    const oldestRun = usable[usable.length - 1];
    const since =
      oldestRun === undefined
        ? {}
        : { since: { value: decimalNumber(median(usable.slice(-SINCE_RUNS).map(valueIn))), at: oldestRun.startedAt } };
    const reference = window.length > 0 ? median(window.map(valueIn)) : null;
    const delta = reference === null ? null : subtract(exactOf(s.value), reference);
    const shown = {
      ...base,
      reference: reference === null ? null : decimalNumber(reference),
      runs: window.length,
      delta: delta === null ? null : decimalNumber(delta),
      ...since,
    };
    if (rule === null) return { ...shown, applied: null, verdict: 'unjudged' as const, why: ['better', 'tolerance'] };
    if (reference === null || delta === null || window.length < WINDOW_MIN) {
      return { ...shown, applied: null, verdict: 'unjudged' as const, why: ['too_few_runs'] };
    }
    const applied = appliedOf(rule, reference);
    const worse = rule.better === 'lower' ? delta : negate(delta);
    const verdict: MetricVerdict =
      compare(worse, applied) > 0 ? 'regressed' : compare(negate(worse), applied) > 0 ? 'improved' : 'within';
    const judged = { ...shown, applied: decimalNumber(applied), verdict };
    return verdict === 'regressed' ? { ...judged, confirmed: newest.verdicts.get(s.name) === 'regressed' } : judged;
  });
}

/** What the run's history says, in one sentence. */
export function seriesHint(metrics: readonly PerfMetricHistory[]): string {
  const regressed = metrics.filter((m) => m.verdict === 'regressed');
  const confirmed = regressed.filter((m) => m.confirmed === true).map((m) => m.name);
  const fresh = regressed.filter((m) => m.confirmed !== true).map((m) => m.name);
  if (confirmed.length > 0) {
    return (
      `${confirmed.join(', ')} regressed in two runs in a row: a real regression. A regressed run never becomes part ` +
      "of a later reference, so it stays flagged until the metric is back within its tolerance of this target's median."
    );
  }
  if (fresh.length > 0) {
    return (
      `${fresh.join(', ')} regressed against the median of this target's last runs, not yet confirmed: run ` +
      'perf_check again — a regression the next run repeats is real.'
    );
  }
  if (metrics.every((m) => m.verdict === 'new')) {
    return "The first run of this target: each run is kept, and judged from the 4th on against the median of this target's last 3-5.";
  }
  if (metrics.some((m) => m.why?.includes('too_few_runs') === true)) {
    return "Too few earlier runs of this target to judge: from the 4th run on, each is judged against the median of the last 3-5.";
  }
  const improved = metrics.filter((m) => m.verdict === 'improved').map((m) => m.name);
  return improved.length > 0
    ? `Nothing regressed; ${improved.join(', ')} improved beyond its tolerance.`
    : "Nothing regressed: every judged metric is within its tolerance of this target's median.";
}
