/**
 * llm-scan-plan-record-default-scan: the scan record an `llm_scan` plan writes says what the plan measured.
 *
 * Every `start` writes a completed `llm_scan` record: `tools_run: []` for a verify-only plan, `[llm-hunt ok]`
 * for a hunt — both read "measured everything". That record then answered for "the latest scan" (report_export,
 * set_baseline, diff_scans), counted as full coverage, and — started after a complete hunt — took that hunt's
 * confirmed findings out of the open set and gave them as resolved. Measured on 2026-11-20
 * (`.specs/llm-scan-plan-record-default-scan/measurement-hunt-verify-2026-11-20.md`).
 *
 * The real handlers over an in-memory database and a copy of the fixture project (`llmScanHarness.ts`), as the
 * measurement ran them: the SAST scan and the attack surface are seeded, the hunt results and the verdicts are
 * fixtures submitted as `subagent`. "The base" is a SAST scan with 3 findings and a hunt that answered every task
 * with 2 findings confirmed (5 open), on a surface where no entry point is set aside or left unvisited.
 *
 * T-01, T-02, T-03, T-05, T-07 (T-04 is in `test/unit/history/sarifSlot.test.ts`, T-06 in
 * `test/unit/llmscan/planRecordCoverage.test.ts`).
 */

import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { buildSnapshot } from '../../src/dashboard/snapshot.js';
import { latestStateScan, openSetForProject, type OpenSet, type SkippedSummary } from '../../src/history/openSet.js';
import { HUNT_CLASSES } from '../../src/llmscan/classes.js';
import { toFindingValidation } from '../../src/llmscan/submission.js';
import type { HuntResult, Independence, LlmVerdict, ScanMode, VerifyVerdict } from '../../src/llmscan/types.js';
import { computeCoverage } from '../../src/tools/scanCoverage.js';
import type { Finding, ScanCoverage } from '../../src/types.js';
import { seedScan as seedHistoryScan } from '../helpers/historySeed.js';
import {
  PARAM_INSERT,
  SHELL,
  SOURCE_LINES,
  SQLI,
  callTool,
  emptyHunt,
  expectDomainError,
  harness,
  isTask,
  lease,
  leaseWhere,
  llmOf,
  locOfTask,
  next,
  seedScan,
  seedSurface,
  start,
  status,
  submissionFixture,
  submit,
  verdictAt,
  type Harness,
  type Loc,
  type Raw,
  type SeedSpec,
  type StartOut,
  type SubmitOut,
} from '../helpers/llmScanHarness.js';
import { cleanupTempDirs } from '../helpers/tempDir.js';
import { okResult } from '../helpers/toolResult.js';
import { mulberry32 } from '../helpers/yamlFuzz.js';

vi.setConfig({ testTimeout: 120_000 });
afterAll(cleanupTempDirs);
beforeAll(async () => {
  await import('../../src/registerAll.js');
});

// ---- the project ---------------------------------------------------------

const SQL_RULE = 'javascript.express.security.injection.tainted-sql-string';
const EXEC_RULE = 'javascript.lang.security.detect-child-process';
/** The three SAST findings the fixture project holds (the measurement's, and `seedStandard`'s without its CVE). */
const SAST_FINDINGS: ReadonlyArray<{ rule_id: string; loc: Loc; message: string }> = [
  { rule_id: SQL_RULE, loc: SQLI, message: 'User input flows into a SQL string.' },
  { rule_id: SQL_RULE, loc: PARAM_INSERT, message: 'User input flows into a SQL string.' },
  { rule_id: EXEC_RULE, loc: SHELL, message: 'A child process is started with input.' },
];
const SAST_SPECS: SeedSpec[] = SAST_FINDINGS.map((f) => ({ tool: 'semgrep', ...f }));

interface Sast {
  scanId: string;
  /** Where each finding sits, by fingerprint. */
  locs: Map<string, Loc>;
}

/** One completed, whole-project SAST scan holding the three findings. */
function seedSast(h: Harness): Sast {
  const { scanId, findings } = seedScan(h.storage, h.db, h.project, 'sast', SAST_SPECS);
  return { scanId, locs: new Map(findings.map((f, i) => [f.fingerprint, SAST_FINDINGS[i]?.loc ?? SQLI])) };
}

/** The same three findings in a SCOPED SAST scan: its row carries `meta.scope`, as `scan_sast { scope }` writes it. */
function seedScopedSast(h: Harness): string {
  return seedHistoryScan(h, {
    id: randomUUID(),
    type: 'sast',
    project: h.project,
    meta: { scope: { kind: 'paths', paths: ['src'], files: 7 } },
    findings: SAST_FINDINGS.map((f) => ({ tool: 'semgrep', rule_id: f.rule_id, file: f.loc.file, line: f.loc.line, message: f.message })),
  });
}

/** An `llm` verdict row, written the way the feature writes it. */
function writeVerdict(h: Harness, fingerprint: string, verdict: LlmVerdict, independence: Independence): void {
  h.storage.validations.upsert(h.project, [
    toFindingValidation({
      fingerprint,
      verdict,
      independence,
      decisive_line: 'src/routes/files.ts:11 — the fixture verdict',
      reasoning: 'Followed the value.',
      prompt_version: 'v1',
      tree_hash: 'tree-under-test',
      computed_at: '2026-10-02T12:00:00.000Z',
    }),
  ]);
}

// ---- the plans -----------------------------------------------------------

/** A hunt plan on the tree as it is now: the surface is seeded just before, as map_attack_surface leaves it. */
async function startHunt(h: Harness, input: Record<string, unknown> = {}): Promise<StartOut> {
  await seedSurface(h);
  return start(h, { modes: ['hunt'], ...input });
}

const HUNT_VALID = submissionFixture('hunt-valid.json') as HuntResult;

/** The verdict a verify task gives a scanner finding: `not_real` for the parameterised INSERT, `real` otherwise. */
const scannerVerdict = (loc: Loc): VerifyVerdict['verdict'] => (loc === PARAM_INSERT ? 'not_real' : 'real');
const STORED: Record<VerifyVerdict['verdict'], LlmVerdict> = { real: 'exploitable', not_real: 'not_exploitable', undetermined: 'undetermined' };

/**
 * Answers every task of `plan` to its end, as a subagent: with `find`, the hunt task over src/routes/files.ts
 * reports the two findings of hunt-valid.json, and every other hunt or cross-cutting task none; a verify task
 * of a hunt finding is answered `real`, one of a scanner finding (`locs`) with {@link scannerVerdict}, recorded
 * in `judged`.
 */
async function answerAll(
  h: Harness,
  plan: StartOut,
  opts: { find: boolean; locs?: ReadonlyMap<string, Loc>; judged?: Map<string, LlmVerdict> },
): Promise<void> {
  let reported = false;
  for (let i = 0; i < 60; i += 1) {
    const t = await next(h, plan.plan_id);
    if (!isTask(t)) return;
    if (t.kind === 'verify') {
      const fp = h.repo.getTask(plan.plan_id, t.task_id)?.target.fingerprint;
      const row = h.storage.findings.listByScan(plan.scan_id).find((f) => f.fingerprint === fp);
      if (row !== undefined) {
        const loc: Loc = { file: row.file_path ?? '', line: row.line_start ?? 0 };
        expect(okResult<SubmitOut>(await submit(h, plan.plan_id, t, verdictAt(loc, 'real'))).accepted).toBe(true);
        continue;
      }
      const loc = locOfTask(h, plan.plan_id, t.task_id, opts.locs ?? new Map<string, Loc>());
      expect(okResult<SubmitOut>(await submit(h, plan.plan_id, t, verdictAt(loc, scannerVerdict(loc)))).accepted).toBe(true);
      if (fp !== undefined) opts.judged?.set(fp, STORED[scannerVerdict(loc)]);
      continue;
    }
    const give = opts.find && !reported && t.kind === 'hunt' && h.repo.getTask(plan.plan_id, t.task_id)?.target.files.includes('src/routes/files.ts') === true;
    if (give) reported = true;
    const payload = { ...emptyHunt(h, plan.plan_id, t.task_id), findings: give ? HUNT_VALID.findings : [] };
    expect(okResult<SubmitOut>(await submit(h, plan.plan_id, t, payload)).accepted).toBe(true);
  }
  throw new Error(`plan ${plan.plan_id} did not end within 60 tasks`);
}

/**
 * Leases and answers (no finding) the tasks of a hunt plan until delivery stops; true when it stopped with
 * limit_reached, false when the plan ended.
 */
async function answerUntilLimit(h: Harness, plan: StartOut): Promise<boolean> {
  for (let i = 0; i < 60; i += 1) {
    const r = await callTool(h, 'llm_scan_task', { plan_id: plan.plan_id });
    if (!r.ok) {
      expect(r.error.code, r.error.message).toBe('limit_reached');
      return true;
    }
    if (r['done'] === true) return false;
    const taskId = String(r['task_id']);
    const lease_token = String(r['lease_token']);
    expect(okResult<SubmitOut>(await submit(h, plan.plan_id, { task_id: taskId, lease_token }, emptyHunt(h, plan.plan_id, taskId))).accepted).toBe(true);
  }
  throw new Error(`plan ${plan.plan_id} neither ended nor stopped within 60 tasks`);
}

interface Base {
  sast: Sast;
  hunt: StartOut;
}

/** The base: a SAST scan with 3 findings, then a hunt that answered every task, 2 findings confirmed — 5 open. */
async function base(h: Harness): Promise<Base> {
  const sast = seedSast(h);
  const hunt = await startHunt(h);
  await answerAll(h, hunt, { find: true });
  expect((await status(h, hunt.plan_id)).report.coverage, "the base hunt's own report").toBe('full');
  expect(byTool(openSetForProject(h.storage, h.project)), 'the base: 3 SAST findings, 2 confirmed hunt findings').toEqual({ 'llm-hunt': 2, semgrep: 3 });
  return { sast, hunt };
}

// ---- the readers ---------------------------------------------------------

function byTool(set: OpenSet): Record<string, number> {
  const out: Record<string, number> = {};
  for (const f of set.findings) out[f.tool] = (out[f.tool] ?? 0) + 1;
  return out;
}

const slotSourceIds = (set: OpenSet, slot: string): string[] => set.sources.filter((s) => s.slot === slot).map((s) => s.scan_id);

/** The coverage the readers judge a stored record by. */
function recordCoverage(h: Harness, scanId: string): ScanCoverage {
  const r = h.storage.scans.getById(scanId);
  if (r === null) throw new Error(`no scan ${scanId}`);
  return computeCoverage(r.tools_run, r.missing_tools);
}

interface Risk {
  score: number;
  components: { findings: { open_findings: number } };
  coverage: { level: string };
}

async function risk(h: Harness): Promise<{ score: number; open_findings: number; level: string }> {
  const r = okResult<Risk>(await callTool(h, 'risk_score', { project_path: h.project }));
  return { score: r.score, open_findings: r.components.findings.open_findings, level: r.coverage.level };
}

async function ranked(h: Harness): Promise<{ total_open: number; fingerprints: string[] }> {
  const r = okResult<{ summary: { total_open: number }; ranked: Array<{ finding: Finding }> }>(
    await callTool(h, 'prioritize_findings', { project_path: h.project }),
  );
  return { total_open: r.summary.total_open, fingerprints: r.ranked.map((x) => x.finding.fingerprint).sort() };
}

const diff = (h: Harness, input: Record<string, unknown>): Promise<Raw> => callTool(h, 'diff_scans', { project_path: h.project, ...input });

interface Compared {
  scan_type: unknown;
  from: unknown;
  to: unknown;
  summary: unknown;
  /** The tools of the findings it gives as not re-measured. */
  not_remeasured: string[];
}

/** diff_scans (mode diff) as one value an assertion can show whole: what it compared and counted, or its error code. */
async function compared(h: Harness, input: Record<string, unknown>): Promise<Compared | { error: string }> {
  const r = await diff(h, input);
  if (!r.ok) return { error: r.error.code };
  const notRemeasured = Array.isArray(r['not_remeasured_findings']) ? (r['not_remeasured_findings'] as Finding[]) : [];
  return { scan_type: r['scan_type'], from: r['from_scan_id'], to: r['to_scan_id'], summary: r['summary'], not_remeasured: notRemeasured.map((f) => f.tool) };
}

interface Exported {
  scan_id: string;
  file_path: string;
  findings_count: number;
  skipped_scans?: SkippedSummary;
}

const exportDefault = (h: Harness, format: 'markdown' | 'json'): Promise<Raw> => callTool(h, 'report_export', { project_path: h.project, format });

/** report_export {}, set_baseline {} and diff_scans { mode: "regression" }, each answering for the SAST scan. */
async function expectDefaultReadersOnSast(h: Harness, sastId: string, judged: number): Promise<void> {
  const md = okResult<Exported>(await exportDefault(h, 'markdown'));
  expect(md.scan_id, 'report_export { format: "markdown" }').toBe(sastId);
  const text = readFileSync(md.file_path, 'utf8');
  expect(text).toContain('- **Type:** sast');
  expect(text).toContain('## Findings (3)');
  expect(text.split('\n').find((l) => l.startsWith('## LLM verification'))).toBe(judged === 0 ? undefined : `## LLM verification (${String(judged)})`);
  const json = okResult<Exported>(await exportDefault(h, 'json'));
  expect(json.scan_id, 'report_export { format: "json" }').toBe(sastId);
  expect((JSON.parse(readFileSync(json.file_path, 'utf8')) as { scan: { scan_id: string } }).scan.scan_id).toBe(sastId);
  const baseline = okResult<{ scan_id: string; scan_type: string }>(await callTool(h, 'set_baseline', { project_path: h.project }));
  expect(baseline.scan_id, 'set_baseline {}').toBe(sastId);
  const regression = await diff(h, { mode: 'regression' });
  expect(regression.ok ? regression['scan_type'] : regression.error, 'diff_scans { mode: "regression" }').toBe('sast');
}

describe('llm-scan-plan-record-default-scan', () => {
  it('T-01 a verify-only plan started after a complete hunt leaves the open set, risk_score, prioritize_findings, the dashboard and diff_scans as they were', async () => {
    const h = harness();
    const { hunt } = await base(h);
    const riskBefore = await risk(h);
    const rankedBefore = await ranked(h);

    // The default mode, verify only; no task of it is answered.
    const verify = await start(h, {});

    const set = openSetForProject(h.storage, h.project);
    expect(byTool(set), 'the open set').toEqual({ 'llm-hunt': 2, semgrep: 3 });
    expect(slotSourceIds(set, 'llm_scan'), "the llm_scan slot's source").toEqual([hunt.scan_id]);
    expect(await risk(h), 'risk_score').toEqual(riskBefore);
    expect(await ranked(h), 'prioritize_findings').toEqual(rankedBefore);
    expect(buildSnapshot(h.storage, h.project, Date.now()).deltas.since_previous?.resolved_count ?? 0, 'the dashboard').toBe(0);

    // One usable hunt: nothing to compare it with, by default or by type.
    expect(await compared(h, {}), 'diff_scans {}').toEqual({ error: 'unknown_scan_id' });
    expect(await compared(h, { scan_type: 'llm_scan' }), 'diff_scans { scan_type: "llm_scan" }').toEqual({ error: 'unknown_scan_id' });

    // By ids: the verify-only record, as the newer side, measured nothing.
    expect(await compared(h, { from_scan_id: hunt.scan_id, to_scan_id: verify.scan_id }), 'diff_scans { from: hunt, to: verify-only }').toMatchObject({
      summary: { resolved: 0, not_remeasured: 2 },
      not_remeasured: ['llm-hunt', 'llm-hunt'],
    });
    // As the reference it answers as it does today: the hunt's two findings are new.
    expect(await compared(h, { from_scan_id: verify.scan_id, to_scan_id: hunt.scan_id }), 'diff_scans { from: verify-only, to: hunt }').toMatchObject({
      summary: { new: 2, resolved: 0 },
    });
  });

  it('T-01 with a verify-only plan between two complete hunts, diff_scans { scan_type: "llm_scan" } compares the two hunts', async () => {
    const h = harness();
    const { hunt } = await base(h);
    await start(h, {});
    const second = await startHunt(h);
    await answerAll(h, second, { find: true });

    expect(await compared(h, { scan_type: 'llm_scan' }), 'diff_scans { scan_type: "llm_scan" }').toMatchObject({ from: hunt.scan_id, to: second.scan_id });
    expect(byTool(openSetForProject(h.storage, h.project)), 'the open set').toEqual({ 'llm-hunt': 2, semgrep: 3 });
  });

  it('T-02 a second hunt plan measures what its answered hunt tasks measured: none at start, partial with one answered, full with all — and only then resolves what the first hunt found', async () => {
    const h = harness();
    const { hunt } = await base(h);
    const second = await startHunt(h);

    expect(recordCoverage(h, second.scan_id), "the second hunt's record, only started").toBe('none');
    expect(byTool(openSetForProject(h.storage, h.project)), 'the open set, the second hunt only started').toEqual({ 'llm-hunt': 2, semgrep: 3 });
    expect(await compared(h, { scan_type: 'llm_scan' }), 'the hunts compared, the second only started').toEqual({ error: 'unknown_scan_id' });

    const one = await leaseWhere(h, second.plan_id, (t) => t.kind === 'hunt');
    expect(okResult<SubmitOut>(await submit(h, second.plan_id, one, emptyHunt(h, second.plan_id, one.task_id))).accepted).toBe(true);
    expect(recordCoverage(h, second.scan_id), "the second hunt's record, one hunt task answered").toBe('partial');
    expect(byTool(openSetForProject(h.storage, h.project)), 'the open set, one hunt task answered').toEqual({ 'llm-hunt': 2, semgrep: 3 });
    expect(await compared(h, { scan_type: 'llm_scan' }), 'the hunts compared, one task of the second answered').toMatchObject({
      from: hunt.scan_id,
      to: second.scan_id,
      summary: { resolved: 0, not_remeasured: 2 },
    });

    // Every task answered, with no finding: the second hunt resolves what it did not find again, as today.
    await answerAll(h, second, { find: false });
    expect(recordCoverage(h, second.scan_id), "the second hunt's record, every task answered").toBe('full');
    expect(await compared(h, { scan_type: 'llm_scan' }), 'the hunts compared, every task of the second answered').toMatchObject({
      from: hunt.scan_id,
      to: second.scan_id,
      summary: { resolved: 2, not_remeasured: 0 },
    });
    expect(byTool(openSetForProject(h.storage, h.project)), 'the open set, every task of the second hunt answered').toEqual({ semgrep: 3 });
  });

  it('T-02 a second hunt plan stopped by the token limit, its other tasks closed as not delivered, stays partial and resolves nothing', async () => {
    const h = harness();
    const { hunt } = await base(h);
    // About two tasks fit: 100 000 tokens of host cost each against 250 000.
    const second = await startHunt(h, { per_task_overhead: 100_000, max_estimated_tokens: 250_000, confirm: true });

    const one = await lease(h, second.plan_id);
    expect(okResult<SubmitOut>(await submit(h, second.plan_id, one, emptyHunt(h, second.plan_id, one.task_id))).accepted).toBe(true);
    expect(recordCoverage(h, second.scan_id), "the second hunt's record, one hunt task answered").toBe('partial');

    expect(await answerUntilLimit(h, second), 'delivery stopped at the token limit').toBe(true);
    expect(h.repo.listTasks(second.plan_id).some((t) => t.closed_reason === 'not_delivered')).toBe(true);
    expect(recordCoverage(h, second.scan_id), "the second hunt's record, stopped by the limit").toBe('partial');
    expect(byTool(openSetForProject(h.storage, h.project)), 'the open set').toEqual({ 'llm-hunt': 2, semgrep: 3 });
    expect(await compared(h, { scan_type: 'llm_scan' }), 'the two hunts compared').toMatchObject({
      from: hunt.scan_id,
      to: second.scan_id,
      summary: { resolved: 0, not_remeasured: 2 },
    });
  });

  it('T-03 with a verify-only plan, before and after its 3 verdicts, report_export {} (Markdown and JSON), set_baseline {} and diff_scans { mode: "regression" } answer for the SAST scan', async () => {
    const h = harness();
    const sast = seedSast(h);
    const plan = await start(h, {});
    await expectDefaultReadersOnSast(h, sast.scanId, 0);

    for (let i = 0; i < 3; i += 1) {
      const t = await lease(h, plan.plan_id);
      const loc = locOfTask(h, plan.plan_id, t.task_id, sast.locs);
      expect(okResult<SubmitOut>(await submit(h, plan.plan_id, t, verdictAt(loc, scannerVerdict(loc)))).accepted).toBe(true);
    }
    await expectDefaultReadersOnSast(h, sast.scanId, 3);
  });

  it('T-03 with two SAST scans and a verify-only plan, diff_scans {} compares the two SAST scans', async () => {
    const h = harness();
    const older = seedSast(h);
    const newer = seedSast(h);
    await start(h, {});
    expect(await compared(h, {}), 'diff_scans {}').toMatchObject({ scan_type: 'sast', from: older.scanId, to: newer.scanId });
  });

  it('T-03 in a project whose only candidates for "the latest scan" are verify-only plans\' records, report_export {} and set_baseline {} answer unknown_scan_id', async () => {
    const h = harness();
    // A scoped scan is never a state scan: the plans' records are all there is.
    const scoped = seedScopedSast(h);
    await start(h, { scan_id: scoped });
    await start(h, { scan_id: scoped });
    expectDomainError(await exportDefault(h, 'markdown'), 'unknown_scan_id');
    expectDomainError(await callTool(h, 'set_baseline', { project_path: h.project }), 'unknown_scan_id');
  });

  it('T-03 in a project whose only scan is a scoped scan_sast, a verify-only plan leaves the open set at coverage none with the same sources, and risk_score does not say full', async () => {
    const h = harness();
    const scoped = seedScopedSast(h);
    const before = openSetForProject(h.storage, h.project);
    expect(before.coverage, 'the open set before the plan').toBe('none');

    await start(h, { scan_id: scoped });
    const after = openSetForProject(h.storage, h.project);
    expect(after.coverage, 'the open set after the plan').toBe('none');
    expect(after.sources.map((s) => s.scan_id), 'its sources').toEqual(before.sources.map((s) => s.scan_id));
    expect((await risk(h)).level, 'risk_score coverage.level').not.toBe('full');
  });

  it('T-07 with a SAST scan and a hunt plan only started, report_export {} exports the SAST scan and names the skipped hunt (coverage_none)', async () => {
    const h = harness();
    const sast = seedSast(h);
    const hunt = await startHunt(h);
    const r = okResult<Exported>(await exportDefault(h, 'markdown'));
    expect(r.scan_id, 'report_export {}').toBe(sast.scanId);
    expect(r.skipped_scans?.newest ?? [], 'the skipped scans it names').toEqual(
      expect.arrayContaining([expect.objectContaining({ scan_id: hunt.scan_id, reason: 'coverage_none' })]),
    );
  });

  it('T-07 in a project with no scan, a hunt plan only started is no scan: report_export {} and set_baseline {} answer unknown_scan_id, the open set stays at coverage none, risk_score does not say full, and set_baseline refuses it by id', async () => {
    const h = harness();
    expect(openSetForProject(h.storage, h.project).coverage, 'the open set before the plan').toBe('none');
    const hunt = await startHunt(h);

    expectDomainError(await exportDefault(h, 'markdown'), 'unknown_scan_id');
    expectDomainError(await callTool(h, 'set_baseline', { project_path: h.project }), 'unknown_scan_id');
    expect(openSetForProject(h.storage, h.project).coverage, 'the open set after the plan').toBe('none');
    expect((await risk(h)).level, 'risk_score coverage.level').not.toBe('full');
    expectDomainError(await callTool(h, 'set_baseline', { project_path: h.project, scan_id: hunt.scan_id }), 'unsupported_target');
  });

  it('T-05 projects whose last plan is a hunt that answered every task (after 0 to 2 verify-only plans) read as today: its findings open, records by id, verdicts on the verified findings, imports out of the search, a verify record as a baseline, an old llm-hunt row', async () => {
    const rand = mulberry32(0x05_0005);
    // What the generator really offered, over every case.
    const offered = { verdictsOfVerifyOnlyPlans: 0, baselines: 0, oldConfirmed: 0 };
    for (let c = 0; c < 12; c += 1) {
      const h = harness();
      const sast = seedSast(h);
      const judged = new Map<string, LlmVerdict>();

      // 0, 1 or 2 verify-only plans, each with 0 to 3 of its tasks answered.
      const verifies: StartOut[] = [];
      for (let v = 0; v < c % 3; v += 1) {
        const plan = await start(h, {});
        verifies.push(plan);
        const answered = Math.floor(rand() * 4);
        for (let a = 0; a < answered; a += 1) {
          const t = await lease(h, plan.plan_id);
          const loc = locOfTask(h, plan.plan_id, t.task_id, sast.locs);
          expect(okResult<SubmitOut>(await submit(h, plan.plan_id, t, verdictAt(loc, scannerVerdict(loc)))).accepted).toBe(true);
          const fp = h.repo.getTask(plan.plan_id, t.task_id)?.target.fingerprint;
          if (fp !== undefined) judged.set(fp, STORED[scannerVerdict(loc)]);
          offered.verdictsOfVerifyOnlyPlans += 1;
        }
      }
      // The last plan: a hunt, or a hunt and a verification at once (EC-2), answered to its end.
      const modes: ScanMode[] = c % 2 === 0 ? ['hunt'] : ['hunt', 'verify'];
      // Both modes plan 8 tasks, and the 2 verify tasks of the hunt's findings follow: room for all of them.
      const hunt = await startHunt(h, { modes, max_estimated_tokens: 2_000_000 });
      await answerAll(h, hunt, { find: true, locs: sast.locs, judged });
      // A SARIF import made after every plan.
      const imported = randomUUID();
      h.storage.scans.insert({ scan_id: imported, scan_type: 'sarif_import', project_path: h.project, tree_hash: `h-${imported}`, meta: { source_tool: 'CodeQL' } });
      h.storage.scans.finalize({ scan_id: imported, status: 'completed', tools_run: [{ name: 'sarif', status: 'ok' }], missing_tools: [] });
      const ctx = `case ${String(c)}: ${String(verifies.length)} verify-only plan(s), last plan ${modes.join('+')}, ${String(judged.size)} scanner finding(s) judged`;

      // The hunt's confirmed findings are open.
      const set = openSetForProject(h.storage, h.project);
      const huntRows = h.storage.findings.listByScan(hunt.scan_id);
      expect(huntRows, ctx).toHaveLength(2);
      for (const row of huntRows) expect(set.findings.find((f) => f.fingerprint === row.fingerprint)?.scan_id, ctx).toBe(hunt.scan_id);

      // A plan's record by its scan_id, as today.
      const byId = okResult<Exported>(await callTool(h, 'report_export', { project_path: h.project, scan_id: hunt.scan_id, format: 'markdown' }));
      expect(byId.scan_id, ctx).toBe(hunt.scan_id);
      expect(byId.findings_count, ctx).toBe(2);
      expect(readFileSync(byId.file_path, 'utf8'), ctx).toContain('- **Type:** llm_scan');
      for (const v of verifies) {
        const r = okResult<Exported>(await callTool(h, 'report_export', { project_path: h.project, scan_id: v.scan_id, format: 'markdown' }));
        expect([r.scan_id, r.findings_count], ctx).toEqual([v.scan_id, 0]);
      }

      // Each verdict sits on the finding of the scan it verified.
      for (const [fp, verdict] of judged) {
        const f = set.findings.find((x) => x.fingerprint === fp);
        expect(f?.scan_id, `${ctx} — ${fp}`).toBe(sast.scanId);
        expect(f === undefined ? undefined : llmOf(f)?.verdict, `${ctx} — ${fp}`).toBe(verdict);
      }
      const sastReport = okResult<Exported>(await callTool(h, 'report_export', { project_path: h.project, scan_id: sast.scanId, format: 'markdown' }));
      const heading = readFileSync(sastReport.file_path, 'utf8').split('\n').find((l) => l.startsWith('## LLM verification'));
      expect(heading, ctx).toBe(judged.size === 0 ? undefined : `## LLM verification (${String(judged.size)})`);

      // The newer import is never "the latest scan": the any-type search answers with the hunt's record.
      const latest = latestStateScan(h.storage, h.project);
      expect(latest.scan?.scan_id, ctx).toBe(hunt.scan_id);

      // A verify-only plan's record is still accepted as a baseline, by id.
      const chosen = verifies[Math.floor(rand() * verifies.length)];
      if (chosen !== undefined) {
        const accepted = okResult<{ scan_id: string; scan_type: string }>(await callTool(h, 'set_baseline', { project_path: h.project, scan_id: chosen.scan_id }));
        expect([accepted.scan_id, accepted.scan_type], ctx).toEqual([chosen.scan_id, 'llm_scan']);
        expect(h.storage.baselines.getActiveForProject(h.project, 'llm_scan')?.scan_id, ctx).toBe(chosen.scan_id);
        offered.baselines += 1;
      }

      // An old llm_scan row with llm-hunt ok and findings, no plan behind it: read as today.
      const old = harness();
      const specs: SeedSpec[] = Array.from({ length: 1 + Math.floor(rand() * 3) }, (_, i) => ({
        tool: 'llm-hunt',
        rule_id: HUNT_CLASSES[Math.floor(rand() * HUNT_CLASSES.length)] ?? 'business-logic',
        loc: SOURCE_LINES[7 * i + 3] ?? SQLI,
      }));
      const row = seedScan(old.storage, old.db, old.project, 'llm_scan', specs, [{ name: 'llm-hunt', status: 'ok' }]);
      const confirmed: string[] = [];
      for (const f of row.findings) {
        const pick = rand();
        if (pick < 0.5) {
          writeVerdict(old, f.fingerprint, 'exploitable', 'subagent');
          confirmed.push(f.fingerprint);
          offered.oldConfirmed += 1;
        } else if (pick < 0.75) {
          writeVerdict(old, f.fingerprint, 'exploitable', 'same_context');
        }
      }
      const oldSet = openSetForProject(old.storage, old.project);
      expect(oldSet.findings.filter((f) => f.tool === 'llm-hunt').map((f) => f.fingerprint).sort(), `${ctx} — the old row`).toEqual([...confirmed].sort());
      expect(latestStateScan(old.storage, old.project, 'llm_scan'), `${ctx} — the old row`).toMatchObject({ scan: { scan_id: row.scanId }, coverage: 'full' });
    }
    expect(offered.verdictsOfVerifyOnlyPlans, 'verdicts given by verify-only plans').toBeGreaterThan(0);
    expect(offered.baselines, 'verify-only records set as a baseline').toBeGreaterThan(0);
    expect(offered.oldConfirmed, 'confirmed findings of old llm-hunt rows').toBeGreaterThan(0);
  });
});
