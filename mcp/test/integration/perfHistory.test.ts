/**
 * perf_check's history (3.17.0): every measured run is a `perf` row, judged
 * against the earlier runs of its series (`src/metrics/perfSeries.ts`, unit-
 * tested in test/unit/metrics/perfSeries.test.ts). Here: the tool's own reads
 * and writes, on a real database, with Lighthouse and k6 scripted
 * (runProcess + scannerAvailable mocked, as in opsTools.test.ts).
 *
 * The Lighthouse reports carry the numbers of 7 real Lighthouse 13.5.0 runs of
 * one static page (LCP 1624.6–1630.3 ms, TTFB 0–4 ms, score 93).
 *
 * Still passes: opsTools.test.ts's perf_check tests (the measurement, the
 * budgets, the exit codes) — the response only gains `history`.
 */

import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../src/runners/processRunner.js', () => ({ runProcess: vi.fn() }));
vi.mock('../../src/tools/scanHelpers.js', async () => {
  const actual = await vi.importActual<typeof import('../../src/tools/scanHelpers.js')>('../../src/tools/scanHelpers.js');
  return { ...actual, scannerAvailable: vi.fn() };
});

import { runProcess } from '../../src/runners/processRunner.js';
import { scannerAvailable } from '../../src/tools/scanHelpers.js';
import { latestStateScan } from '../../src/history/openSet.js';
import { TOOLS } from '../../src/tools/index.js';
import { cleanupTempDirs } from '../helpers/tempDir.js';
import { freshPlugin, projectDir, seedScan, type Seeded } from '../helpers/historySeed.js';

afterAll(cleanupTempDirs);

beforeAll(async () => {
  await import('../../src/tools/perfCheck.js');
  await import('../../src/tools/setBaseline.js');
});

beforeEach(() => {
  vi.mocked(runProcess).mockReset();
  vi.mocked(scannerAvailable).mockReset();
});

function tool(name: string) {
  const t = TOOLS.find((x) => x.name === name);
  if (!t) throw new Error(`Tool '${name}' not registered`);
  return t;
}

interface LhRun {
  lcp: number;
  ttfb?: number;
  score?: number;
  version?: string;
  categories?: string[];
  runtimeError?: boolean;
  /** Lighthouse's numericValue, unrounded (default: a real run's 0.1480355010107018). */
  cls?: number;
}

/** Lighthouse, scripted: writes a report of the real run's shape. */
function scriptLighthouse(run: LhRun): void {
  vi.mocked(scannerAvailable).mockImplementation(async (name) => (name === 'lighthouse' ? '/fake/bin/lighthouse' : null));
  vi.mocked(runProcess).mockImplementationOnce(async (opts) => {
    const out = opts.args?.find((a) => a.startsWith('--output-path='))?.replace('--output-path=', '');
    const cats = run.categories ?? ['performance'];
    if (out !== undefined) {
      writeFileSync(
        out,
        JSON.stringify({
          lighthouseVersion: run.version ?? '13.5.0',
          configSettings: { onlyCategories: cats, formFactor: 'mobile' },
          categories: Object.fromEntries(cats.map((c) => [c, { score: (run.score ?? 93) / 100 }])),
          audits: {
            'largest-contentful-paint': { numericValue: run.lcp },
            'first-contentful-paint': { numericValue: run.lcp },
            'speed-index': { numericValue: run.lcp },
            'total-blocking-time': { numericValue: 0 },
            'cumulative-layout-shift': { numericValue: run.cls ?? 0.1480355010107018 },
            'server-response-time': { numericValue: run.ttfb ?? 0 },
            'total-byte-weight': { numericValue: 40269 },
          },
          ...(run.runtimeError === true ? { runtimeError: { code: 'NO_FCP', message: 'The page did not paint any content.' } } : {}),
        }),
        'utf8',
      );
    }
    return { outcome: 'completed' as const, exitCode: run.runtimeError === true ? 1 : 0, stdout: '', stderr: '', truncated: false };
  });
}

type History = {
  series: string;
  recorded: boolean;
  scan_id?: string;
  reason?: string;
  metrics?: Array<{ name: string; verdict: string; confirmed?: boolean; why?: string[]; runs: number; reference: number | null }>;
  regressed?: string[];
  hint?: string;
};

type LhResult = { ok: boolean; history?: History; summary?: { core_web_vitals: Record<string, number | null> } };

async function lighthouse(s: Seeded, project: string, run: LhRun, url = 'http://127.0.0.1:64288/'): Promise<LhResult> {
  scriptLighthouse(run);
  return (await tool('perf_check').handler({ project_path: project, target_url: url }, s.plugin)) as LhResult;
}

const verdictOf = (h: History | undefined, name: string): string | undefined => h?.metrics?.find((m) => m.name === name)?.verdict;
const perfRows = (s: Seeded, project: string) => s.storage.scans.listCompletedOfTypes(project, ['perf'], { limit: 100 });

describe('perf_check history: Lighthouse', () => {
  it('keeps each measured run as a perf row, and judges the 4th against the median of the earlier ones', async () => {
    const s = freshPlugin();
    const project = projectDir('perf-hist-');
    const lcps = [1629.6964, 1627.4114, 1625.68];
    const first = await lighthouse(s, project, { lcp: lcps[0] ?? 0, ttfb: 4 });
    expect(first.ok).toBe(true);
    expect(first.history).toMatchObject({ recorded: true, series: 'Lighthouse 13 · http://127.0.0.1:64288/ · performance' });
    expect(verdictOf(first.history, 'perf.lcp_ms')).toBe('new');
    for (const lcp of lcps.slice(1)) await lighthouse(s, project, { lcp, ttfb: 1 });
    const fourth = await lighthouse(s, project, { lcp: 1624.6433, ttfb: 0 });
    expect(fourth.history?.metrics?.find((m) => m.name === 'perf.lcp_ms')).toMatchObject({ verdict: 'within', runs: 3, reference: 1627.41 });
    expect(verdictOf(fourth.history, 'perf.ttfb_ms')).toBe('within');
    expect(verdictOf(fourth.history, 'lighthouse.performance')).toBe('within');

    const rows = perfRows(s, project);
    expect(rows).toHaveLength(4);
    const newest = rows[0];
    expect(newest?.scan_id).toBe(fourth.history?.scan_id);
    expect(newest?.tools_run).toEqual([{ name: 'lighthouse', status: 'ok', version: '13.5.0' }]);
    expect(newest?.meta).toMatchObject({
      tool: 'lighthouse',
      tool_version: '13.5.0',
      series_label: 'Lighthouse 13 · http://127.0.0.1:64288/ · performance',
      metrics: { 'perf.lcp_ms': { value: 1624.64, unit: 'ms' } },
      verdicts: { 'perf.lcp_ms': 'within' },
    });
    expect(String(newest?.meta?.['series'])).toMatch(/^[0-9a-f]{64}$/);
    // No finding: the budget findings stay in the response, as before.
    expect(s.storage.findings.listByScan(String(newest?.scan_id))).toEqual([]);
  });

  it('a regression is flagged, confirmed by the next run, and never becomes part of a later reference', async () => {
    const s = freshPlugin();
    const project = projectDir('perf-hist-');
    for (let i = 0; i < 5; i += 1) await lighthouse(s, project, { lcp: 2000 });
    const verdicts: string[] = [];
    for (let i = 0; i < 4; i += 1) {
      const r = await lighthouse(s, project, { lcp: 2500 });
      const m = r.history?.metrics?.find((x) => x.name === 'perf.lcp_ms');
      verdicts.push(`${m?.verdict ?? '?'}${m?.confirmed === true ? '!' : ''}`);
      if (i === 0) expect(r.history?.hint).toMatch(/not yet confirmed/);
      if (i === 3) expect(r.history?.hint).toMatch(/two runs in a row/);
    }
    expect(verdicts).toEqual(['regressed', 'regressed!', 'regressed!', 'regressed!']);
  });

  it('H4, H5, H6b: another page, another Lighthouse major or other categories is another series', async () => {
    const s = freshPlugin();
    const project = projectDir('perf-hist-');
    for (let i = 0; i < 3; i += 1) await lighthouse(s, project, { lcp: 2000 });
    expect(verdictOf((await lighthouse(s, project, { lcp: 9000 }, 'http://127.0.0.1:64288/other')).history, 'perf.lcp_ms')).toBe('new');
    expect(verdictOf((await lighthouse(s, project, { lcp: 9000, version: '12.8.2' })).history, 'perf.lcp_ms')).toBe('new');
    const a11y = await lighthouse(s, project, { lcp: 9000, categories: ['accessibility'] });
    expect(verdictOf(a11y.history, 'lighthouse.accessibility')).toBe('new');
    expect(verdictOf(a11y.history, 'perf.lcp_ms')).toBe('new');
    // The first series is untouched by them.
    expect(verdictOf((await lighthouse(s, project, { lcp: 9000 })).history, 'perf.lcp_ms')).toBe('regressed');
  });

  it('H-5: CLS is sampled unrounded — 0.1351 x3 then 0.1549 (+0.0198) regresses, then 0.1449 (+0.0098) is within', async () => {
    const s = freshPlugin();
    const project = projectDir('perf-hist-');
    for (let i = 0; i < 3; i += 1) await lighthouse(s, project, { lcp: 2000, cls: 0.1351 });
    const worse = await lighthouse(s, project, { lcp: 2000, cls: 0.1549 });
    expect(worse.history?.metrics?.find((m) => m.name === 'perf.cls')).toMatchObject({ verdict: 'regressed', reference: 0.1351 });
    expect(verdictOf((await lighthouse(s, project, { lcp: 2000, cls: 0.1449 })).history, 'perf.cls')).toBe('within');
    // The response's summary is unchanged: rounded to 0.01, as before.
    expect(worse.summary?.core_web_vitals['cumulative-layout-shift']).toBe(0.15);
  });

  it('H-8: the stored series label keeps no query string and no fragment; the query still keys the series', async () => {
    const s = freshPlugin();
    const project = projectDir('perf-hist-');
    const first = await lighthouse(s, project, { lcp: 2000 }, 'http://127.0.0.1:64288/app?access_token=tok3n#top');
    // R2-DG-HZ-4: the query shows as a short digest of it, so another query shows another label.
    expect(first.history?.series).toMatch(/^Lighthouse 13 · http:\/\/127\.0\.0\.1:64288\/app\?…#[0-9a-f]{6} · performance$/);
    expect(JSON.stringify(perfRows(s, project)[0]?.meta)).not.toMatch(/tok3n|access_token|#top/);
    for (let i = 0; i < 2; i += 1) await lighthouse(s, project, { lcp: 2000 }, 'http://127.0.0.1:64288/app?access_token=tok3n');
    const same = await lighthouse(s, project, { lcp: 9000 }, 'http://127.0.0.1:64288/app?access_token=tok3n');
    expect(verdictOf(same.history, 'perf.lcp_ms')).toBe('regressed');
    expect(same.history?.series).toBe(first.history?.series);
    const other = await lighthouse(s, project, { lcp: 9000 }, 'http://127.0.0.1:64288/app?other=1');
    expect(verdictOf(other.history, 'perf.lcp_ms')).toBe('new');
    expect(other.history?.series).not.toBe(first.history?.series);
  });

  it('H17: another project\'s runs of the same page are never read', async () => {
    const s = freshPlugin();
    const a = projectDir('perf-hist-a-');
    const b = projectDir('perf-hist-b-');
    for (let i = 0; i < 4; i += 1) await lighthouse(s, a, { lcp: 2000 });
    expect(verdictOf((await lighthouse(s, b, { lcp: 9000 })).history, 'perf.lcp_ms')).toBe('new');
  });

  it('H9: a run that measured nothing (runtimeError) writes no row', async () => {
    const s = freshPlugin();
    const project = projectDir('perf-hist-');
    const r = await lighthouse(s, project, { lcp: 2000, runtimeError: true });
    expect(r.ok).toBe(false);
    expect(perfRows(s, project)).toEqual([]);
  });

  it('H10: a history that cannot be written or read never fails the measurement — recorded: false says why', async () => {
    const s = freshPlugin();
    const project = projectDir('perf-hist-');
    const insert = vi.spyOn(s.storage.scans, 'insert').mockImplementation(() => {
      throw new Error('attempt to write a readonly database');
    });
    const written = await lighthouse(s, project, { lcp: 2000 });
    insert.mockRestore();
    expect(written.ok).toBe(true);
    expect(written.history).toMatchObject({ recorded: false });
    expect(written.history?.reason).toMatch(/judged but could not be kept in the history: attempt to write a readonly database/);
    expect(verdictOf(written.history, 'perf.lcp_ms')).toBe('new');

    const read = vi.spyOn(s.storage.scans, 'listCompletedPerfSeries').mockImplementation(() => {
      throw new Error('database is locked');
    });
    const unread = await lighthouse(s, project, { lcp: 2000 });
    read.mockRestore();
    expect(unread.ok).toBe(true);
    expect(unread.history).toEqual({
      series: 'Lighthouse 13 · http://127.0.0.1:64288/ · performance',
      recorded: false,
      reason: 'the history could not be read, so the run was neither judged nor kept: database is locked',
    });
    expect(perfRows(s, project)).toEqual([]);
  });

  it('H11: perf rows are never "the latest scan" — latestStateScan and set_baseline still take the SAST scan', async () => {
    const s = freshPlugin();
    const project = projectDir('perf-hist-');
    seedScan(s, { id: 'sast-1', type: 'sast', project, tools_run: [{ name: 'semgrep', status: 'ok' }], findings: [{ rule_id: 'r1' }] });
    for (let i = 0; i < 3; i += 1) await lighthouse(s, project, { lcp: 2000 });
    expect(latestStateScan(s.storage, project).scan?.scan_id).toBe('sast-1');
    const baseline = (await tool('set_baseline').handler({ project_path: project }, s.plugin)) as { ok: boolean; scan_id?: string };
    expect(baseline).toMatchObject({ ok: true, scan_id: 'sast-1' });
    const perfId = perfRows(s, project)[0]?.scan_id ?? '';
    const named = (await tool('set_baseline').handler({ project_path: project, scan_id: perfId }, s.plugin)) as {
      ok: boolean;
      error?: { code: string };
    };
    expect(named).toMatchObject({ ok: false, error: { code: 'unsupported_target' } });
  });

  // R2-DG-HZ-6: the refusal said "records no findings" of review_pr, audit and the audits, which do record
  // findings, and its article read "A init" / "A audit".
  it("H-6: set_baseline refuses a type that is never a project's baseline, by scan_type and by scan_id, and says so", async () => {
    const s = freshPlugin();
    const project = projectDir('perf-hist-');
    const ran = [{ name: 'semgrep', status: 'ok' as const }];
    seedScan(s, { id: 'sast-1', type: 'sast', project, tools_run: ran, findings: [{ rule_id: 'r1' }] });
    seedScan(s, { id: 'sbom-1', type: 'sbom', project, tools_run: [{ name: 'syft', status: 'ok' }] });
    seedScan(s, { id: 'audit-1', type: 'audit', project, tools_run: ran, findings: [{ rule_id: 'r1' }] });
    seedScan(s, { id: 'review-1', type: 'review_pr', project, tools_run: ran, findings: [{ rule_id: 'r1' }] });
    seedScan(s, { id: 'init-1', type: 'init', project, tools_run: ran });
    seedScan(s, { id: 'obs-1', type: 'observability', project, tools_run: ran });
    await lighthouse(s, project, { lcp: 2000 });
    type Result = { ok: boolean; scan_id?: string; error?: { code: string; message: string } };
    const set = async (scanType: string) =>
      (await tool('set_baseline').handler({ project_path: project, scan_type: scanType }, s.plugin)) as Result;
    const named = async (scanId: string) => (await tool('set_baseline').handler({ project_path: project, scan_id: scanId }, s.plugin)) as Result;
    const refused = (message: string) => ({ ok: false, error: { code: 'unsupported_target', message: `${message} Baseline a scan of a finding-producing type.` } });
    for (const [type, article] of [['perf', 'A'], ['sbom', 'A'], ['review_pr', 'A'], ['audit', 'An'], ['init', 'An'], ['observability', 'An']] as const) {
      expect(await set(type), type).toEqual(refused(`${article} \`${type}\` scan is never a project's baseline.`));
    }
    for (const [id, type, article] of [['audit-1', 'audit', 'an'], ['review-1', 'review_pr', 'a'], ['init-1', 'init', 'an'], ['sbom-1', 'sbom', 'a']] as const) {
      expect(await named(id), id).toEqual(refused(`Scan '${id}' is ${article} \`${type}\` scan, which is never a project's baseline.`));
    }
    expect(s.storage.baselines.getActiveForProject(project)).toBeNull();
    // Still-pass: a finding-producing type is baselined as before.
    expect(await set('sast')).toMatchObject({ ok: true, scan_id: 'sast-1' });
  });
});

describe('perf_check history: k6', () => {
  // Hermetic: the K6_* settings perf_check hands k6 are part of the key (R2-DG-HZ-1), so the shell's own never
  // reach these runs — only what a test sets.
  beforeEach(() => {
    for (const name of Object.keys(process.env)) if (name.toUpperCase().startsWith('K6_')) vi.stubEnv(name, undefined);
  });
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  /** The stored series keys, newest first. */
  const seriesKeys = (s: Seeded, project: string): string[] => perfRows(s, project).map((r) => String(r.meta?.['series']));

  function scriptK6(exitCode: number, vusMax: number, p95: number): void {
    vi.mocked(scannerAvailable).mockImplementation(async (name) => (name === 'k6' ? '/fake/bin/k6' : null));
    vi.mocked(runProcess).mockImplementationOnce(async (opts) => {
      const file = opts.args?.find((a) => a.startsWith('--summary-export='))?.replace('--summary-export=', '');
      if (file !== undefined) {
        writeFileSync(
          file,
          JSON.stringify({
            metrics: {
              http_reqs: { count: 1000, rate: 99.8 },
              http_req_duration: { avg: p95 / 2, 'p(95)': p95, 'p(99)': p95 * 1.2 },
              vus_max: { value: vusMax, min: vusMax, max: vusMax },
            },
          }),
          'utf8',
        );
      }
      return { outcome: 'completed' as const, exitCode, stdout: '', stderr: '', truncated: false };
    });
  }
  async function k6(s: Seeded, project: string, script: string, exitCode = 0, vusMax = 10, p95 = 20): Promise<{ ok: boolean; passed?: boolean; history?: History }> {
    scriptK6(exitCode, vusMax, p95);
    return (await tool('perf_check').handler({ project_path: project, k6_script_path: script }, s.plugin)) as { ok: boolean; passed?: boolean; history?: History };
  }

  it('H16: a completed run whose threshold failed (exit 99) is kept; the key is the script, its content and the K6_* settings', async () => {
    const s = freshPlugin();
    const project = projectDir('perf-k6-');
    writeFileSync(join(project, 'smoke.js'), 'export default function () {}\n', 'utf8');
    const failedThreshold = await k6(s, project, 'smoke.js', 99);
    expect(failedThreshold).toMatchObject({ ok: true, passed: false, history: { recorded: true } });
    expect(failedThreshold.history?.series).toMatch(/^k6 · smoke\.js \([0-9a-f]{12}\)$/);
    for (let i = 0; i < 2; i += 1) await k6(s, project, 'smoke.js');
    const judged = await k6(s, project, 'smoke.js', 0, 10, 40);
    expect(verdictOf(judged.history, 'k6.latency_p95_ms')).toBe('regressed');
    expect(judged.history?.metrics?.find((m) => m.name === 'k6.requests')).toMatchObject({ verdict: 'unjudged', why: ['better', 'tolerance'] });
    // R2-DG-HZ-1: a VU count k6 measured is no part of the key — the same inputs are the same load.
    expect(verdictOf((await k6(s, project, 'smoke.js', 0, 100, 400)).history, 'k6.latency_p95_ms')).toBe('regressed');
    // Another K6_VUS is another load: a new series, unjudged until it has 3 runs.
    vi.stubEnv('K6_VUS', '100');
    const more = await k6(s, project, 'smoke.js', 0, 100, 400);
    expect(verdictOf(more.history, 'k6.latency_p95_ms')).toBe('new');
    expect(more.history?.series).toMatch(/^k6 · smoke\.js \([0-9a-f]{12}\) · K6_\* #[0-9a-f]{6}$/);
    vi.stubEnv('K6_VUS', undefined);
    // An edited script starts a new series.
    writeFileSync(join(project, 'smoke.js'), 'export default function () { /* edited */ }\n', 'utf8');
    expect(verdictOf((await k6(s, project, 'smoke.js', 0, 10, 400)).history, 'k6.latency_p95_ms')).toBe('new');
  });

  /**
   * The file `k6 run --summary-export` writes (the legacy summary, k6 0.3x to 1.x): a Rate metric is
   * `{ passes, fails, value }` — its rate is `value` — and a gauge `{ value, min, max }`.
   */
  function scriptK6Summary(summary: Record<string, unknown>): void {
    vi.mocked(scannerAvailable).mockImplementation(async (name) => (name === 'k6' ? '/fake/bin/k6' : null));
    vi.mocked(runProcess).mockImplementationOnce(async (opts) => {
      const file = opts.args?.find((a) => a.startsWith('--summary-export='))?.replace('--summary-export=', '');
      if (file !== undefined) writeFileSync(file, JSON.stringify(summary), 'utf8');
      return { outcome: 'completed' as const, exitCode: 0, stdout: '', stderr: '', truncated: false };
    });
  }
  const legacy = (p95: number, failRate: number, vusMax: Record<string, number>) => ({
    root_group: { name: '', path: '', id: 'd41d8cd98f00b204e9800998ecf8427e', groups: {}, checks: {} },
    metrics: {
      http_reqs: { count: 1000, rate: 99.8 },
      http_req_duration: { avg: p95 / 2, min: 1, med: p95 / 2, max: p95 * 2, 'p(90)': p95 * 0.9, 'p(95)': p95 },
      http_req_failed: { passes: Math.round(failRate * 1000), fails: 1000 - Math.round(failRate * 1000), value: failRate },
      vus_max: vusMax,
      vus: { value: 0, min: 0, max: vusMax['max'] ?? 0 },
    },
  });
  type K6Result = { ok: boolean; summary?: Record<string, unknown>; history?: History };
  async function k6Summary(s: Seeded, project: string, summary: Record<string, unknown>): Promise<K6Result> {
    scriptK6Summary(summary);
    return (await tool('perf_check').handler({ project_path: project, k6_script_path: 'load.js' }, s.plugin)) as K6Result;
  }
  const vus = (min: number, max: number) => ({ value: max, min, max });

  it("H-1: the error rate of k6's --summary-export (http_req_failed.value) is read and judged", async () => {
    const s = freshPlugin();
    const project = projectDir('perf-k6-');
    writeFileSync(join(project, 'load.js'), 'export default function () {}\n', 'utf8');
    for (let i = 0; i < 3; i += 1) await k6Summary(s, project, legacy(20, 0, vus(10, 10)));
    const failing = await k6Summary(s, project, legacy(20, 0.3, vus(10, 10)));
    expect(failing.summary?.['error_rate']).toBe(0.3);
    expect(failing.history?.metrics?.find((m) => m.name === 'k6.error_rate_pct')).toMatchObject({ verdict: 'regressed', reference: 0 });
    expect(perfRows(s, project)[0]?.meta?.['metrics']).toMatchObject({ 'k6.error_rate_pct': { value: 30, unit: '%' } });
  });

  it('H-1 still-pass: a summary whose http_req_failed holds `rate` is still read', async () => {
    const s = freshPlugin();
    const project = projectDir('perf-k6-');
    writeFileSync(join(project, 'load.js'), 'export default function () {}\n', 'utf8');
    const summary = legacy(20, 0, vus(10, 10));
    const r = await k6Summary(s, project, { ...summary, metrics: { ...summary.metrics, http_req_failed: { rate: 0.07 } } });
    expect(r.summary?.['error_rate']).toBe(0.07);
    expect(verdictOf(r.history, 'k6.error_rate_pct')).toBe('new');
  });

  it('H-2: an arrival-rate run that allocated more VUs (vus_max min 10, max 23) stays in its series and reads regressed', async () => {
    const s = freshPlugin();
    const project = projectDir('perf-k6-');
    writeFileSync(
      join(project, 'load.js'),
      'export const options = { scenarios: { s: { executor: "constant-arrival-rate", rate: 100, preAllocatedVUs: 10, maxVUs: 100 } } };\n',
      'utf8',
    );
    for (let i = 0; i < 3; i += 1) await k6Summary(s, project, legacy(20, 0, vus(10, 10)));
    const slow = await k6Summary(s, project, legacy(45, 0, vus(10, 23)));
    expect(verdictOf(slow.history, 'k6.latency_p95_ms')).toBe('regressed');
    // Jitter in what k6 added (11 vs 23) is no new load either.
    const next = await k6Summary(s, project, legacy(20, 0, vus(10, 11)));
    expect(next.history?.series).toBe(slow.history?.series);
    expect(new Set(seriesKeys(s, project)).size).toBe(1);
  });

  // Review 2 (R2-DG-HZ-1, the user's ruling "only inputs"): k6 samples `vus_max` from the start of the VUs'
  // init, so a constant-vus run whose init outlasts the first 1 s sample has a min that jitters — keyed by
  // it, every run was `new` and none was ever judged; a heavy init read "0 VUs".
  it("R2-DG-HZ-1: constant-vus 500 whose VU init outlasts k6's first sample (vus_max min 187, 203, 176, 198) is one series, and the slow run reads regressed", async () => {
    const s = freshPlugin();
    const project = projectDir('perf-k6-');
    writeFileSync(join(project, 'load.js'), 'export const options = { vus: 500, duration: "30s" };\nexport default function () {}\n', 'utf8');
    const labels: Array<string | undefined> = [];
    for (const min of [187, 203, 176]) labels.push((await k6Summary(s, project, legacy(20, 0, vus(min, 500)))).history?.series);
    const slow = await k6Summary(s, project, legacy(45, 0, vus(198, 500)));
    expect(verdictOf(slow.history, 'k6.latency_p95_ms')).toBe('regressed');
    labels.push(slow.history?.series);
    // A heavy init's min 0, and a summary with no vus_max at all: the same series still.
    labels.push((await k6Summary(s, project, legacy(20, 0, vus(0, 500)))).history?.series);
    const summary = legacy(20, 0, vus(0, 0));
    const metrics: Record<string, unknown> = { ...summary.metrics };
    delete metrics['vus_max'];
    labels.push((await k6Summary(s, project, { ...summary, metrics })).history?.series);
    expect(seriesKeys(s, project)).toHaveLength(6);
    expect(new Set(seriesKeys(s, project)).size).toBe(1);
    expect([...new Set(labels)]).toEqual([expect.stringMatching(/^k6 · load\.js \([0-9a-f]{12}\)$/)]);
  });

  it("R2-DG-HZ-1 still-pass: another load is another series when an input sets it — the script's options or a K6_* setting", async () => {
    const s = freshPlugin();
    const project = projectDir('perf-k6-');
    const script = (pre: number): string =>
      `export const options = { scenarios: { s: { executor: "constant-arrival-rate", rate: 100, preAllocatedVUs: ${pre}, maxVUs: 200 } } };\n`;
    const p95 = async (summary: Record<string, unknown>) => verdictOf((await k6Summary(s, project, summary)).history, 'k6.latency_p95_ms');
    writeFileSync(join(project, 'load.js'), script(10), 'utf8');
    for (let i = 0; i < 3; i += 1) await k6Summary(s, project, legacy(20, 0, vus(10, 23)));
    writeFileSync(join(project, 'load.js'), script(100), 'utf8');
    expect(await p95(legacy(45, 0, vus(100, 100)))).toBe('new');
    // The first script again: its series, judged.
    writeFileSync(join(project, 'load.js'), script(10), 'utf8');
    expect(await p95(legacy(45, 0, vus(10, 23)))).toBe('regressed');
    vi.stubEnv('K6_VUS', '50');
    expect(await p95(legacy(45, 0, vus(10, 23)))).toBe('new');
    vi.stubEnv('K6_VUS', undefined);
    expect(await p95(legacy(45, 0, vus(10, 23)))).toBe('regressed');
  });

  it('R2-DG-HZ-1: a K6_* value reaches the key as a digest only, never the stored meta or the label; what k6 is not handed keys nothing', async () => {
    const s = freshPlugin();
    const project = projectDir('perf-k6-');
    writeFileSync(join(project, 'load.js'), 'export default function () {}\n', 'utf8');
    vi.stubEnv('K6_OUT', 'influxdb=http://k6:pa55word9@db.internal:8086/k6');
    // A credential-shaped name is never handed to k6 (allowlistedEnv), so it is no part of the key.
    vi.stubEnv('K6_CLOUD_TOKEN', 'cloudvalue1');
    // Handed (the proxy), but no K6_* setting.
    vi.stubEnv('HTTPS_PROXY', 'http://proxy.internal:3128');
    const first = await k6Summary(s, project, legacy(20, 0, vus(10, 10)));
    const handed = vi.mocked(runProcess).mock.calls.at(-1)?.[0].env ?? {};
    expect(handed['K6_OUT']).toContain('pa55word9');
    expect(handed).not.toHaveProperty('K6_CLOUD_TOKEN');
    expect(first.history?.series).toMatch(/^k6 · load\.js \([0-9a-f]{12}\) · K6_\* #[0-9a-f]{6}$/);
    expect(JSON.stringify(perfRows(s, project)[0]?.meta)).not.toMatch(/pa55word9|influxdb|cloudvalue1|K6_OUT|K6_CLOUD/);
    vi.stubEnv('K6_CLOUD_TOKEN', 'cloudvalue2');
    vi.stubEnv('HTTPS_PROXY', 'http://proxy2.internal:3128');
    const second = await k6Summary(s, project, legacy(20, 0, vus(10, 10)));
    expect(second.history?.series).toBe(first.history?.series);
    expect(new Set(seriesKeys(s, project)).size).toBe(1);
    // The handed value does key it.
    vi.stubEnv('K6_OUT', 'influxdb=http://db.internal:8086/k6');
    const third = await k6Summary(s, project, legacy(20, 0, vus(10, 10)));
    expect(third.history?.series).not.toBe(first.history?.series);
    expect(new Set(seriesKeys(s, project)).size).toBe(2);
  });

  it('a run whose summary holds no metric is not kept, and says so', async () => {
    const s = freshPlugin();
    const project = projectDir('perf-k6-');
    writeFileSync(join(project, 'smoke.js'), 'export default function () {}\n', 'utf8');
    vi.mocked(scannerAvailable).mockImplementation(async (name) => (name === 'k6' ? '/fake/bin/k6' : null));
    vi.mocked(runProcess).mockImplementationOnce(async (opts) => {
      const file = opts.args?.find((a) => a.startsWith('--summary-export='))?.replace('--summary-export=', '');
      if (file !== undefined) writeFileSync(file, '{}', 'utf8');
      return { outcome: 'completed' as const, exitCode: 0, stdout: '', stderr: '', truncated: false };
    });
    const r = (await tool('perf_check').handler({ project_path: project, k6_script_path: 'smoke.js' }, s.plugin)) as { ok: boolean; history?: History };
    expect(r.ok).toBe(true);
    expect(r.history).toMatchObject({ recorded: false, reason: 'the run measured no metric, so it is not kept' });
    expect(perfRows(s, project)).toEqual([]);
  });
});
