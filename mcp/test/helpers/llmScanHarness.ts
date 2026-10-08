/**
 * Shared set-up for the LLM-assisted scan's integration tests
 * (`test/integration/llmScan*.test.ts`): a copy of the fixture project, a
 * migrated database, the scanner findings the fixture is known to hold, its
 * routes as a surface snapshot, and thin wrappers over the three tools.
 *
 * No model anywhere: verdicts and hunt results are fixtures, and MCP sampling
 * is a fake function handed to the tool through its call metadata.
 */

import { randomUUID } from 'node:crypto';
import { cpSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect } from 'vitest';
import type { PluginContext } from '../../src/context.js';
import type { LlmScanReport } from '../../src/llmscan/report.js';
import type { SubmissionError } from '../../src/llmscan/submission.js';
import type {
  HuntResult,
  Independence,
  LlmMarker,
  PlanEstimate,
  SamplingFn,
  TaskKind,
  VerifyVerdict,
} from '../../src/llmscan/types.js';
import type { OpenFinding } from '../../src/history/openSet.js';
import { resolveProjectPath } from '../../src/platform/projectPath.js';
import { makeFinding } from '../../src/runners/scannerParsers/index.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { Storage } from '../../src/storage/index.js';
import { LlmScanRepo } from '../../src/storage/llmScanRepo.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { TOOLS, toCallToolResult, type ToolCallMeta } from '../../src/tools/index.js';
import { computeTreeHash } from '../../src/treeHash/computeTreeHash.js';
import type { AttackSurfaceSnapshot, Category, Finding, RouteRecord, ScanType, ToolResult, ToolRun } from '../../src/types.js';
import { makeTempDir } from './tempDir.js';
import { okResult } from './toolResult.js';

export const LLM_FIXTURES = fileURLToPath(new URL('../fixtures/llm-scan/', import.meta.url));

export interface Harness {
  project: string;
  dbPath: string;
  db: Database;
  storage: Storage;
  plugin: PluginContext;
  repo: LlmScanRepo;
}

function open(project: string, dbPath: string): Harness {
  const db = new Database(dbPath);
  runMigrations(db);
  const storage = new Storage(db);
  const plugin: PluginContext = { storage, shell: null, scriptsDir: '', progressNotifier: { send: () => {} } };
  return { project, dbPath, db, storage, plugin, repo: new LlmScanRepo(db) };
}

/** A fresh copy of the fixture project and a fresh database (in memory, or a file to reopen). */
export function harness(opts: { dbFile?: boolean } = {}): Harness {
  const project = resolveProjectPath(makeTempDir('llm-scan-project-')).path;
  cpSync(join(LLM_FIXTURES, 'project'), project, { recursive: true });
  const dbPath = opts.dbFile === true ? join(makeTempDir('llm-scan-db-'), 'guardian.db') : ':memory:';
  return open(project, dbPath);
}

/** The server restarting: the database closed and opened again from its file. */
export function reopen(h: Harness): Harness {
  if (h.dbPath === ':memory:') throw new Error('reopen needs harness({ dbFile: true })');
  h.storage.close();
  return open(h.project, h.dbPath);
}

export function submissionFixture(name: string): unknown {
  return JSON.parse(readFileSync(join(LLM_FIXTURES, 'submissions', name), 'utf8')) as unknown;
}

// ---- What the fixture project holds ------------------------------------

export interface Loc {
  file: string;
  line: number;
}
export const at = (l: Loc): string => `${l.file}:${l.line}`;

/** `req.params.id` concatenated into SQL: a true positive. */
export const SQLI: Loc = { file: 'src/routes/users.ts', line: 12 };
/** A parameterised INSERT a SQL rule also flags: a false positive. */
export const PARAM_INSERT: Loc = { file: 'src/routes/users.ts', line: 18 };
/** A report name reaching `exec` unquoted: a true positive. */
export const SHELL: Loc = { file: 'src/util/shell.ts', line: 8 };
/** AWS's documentation example key. */
export const AWS_KEY_LINE: Loc = { file: 'src/config.ts', line: 6 };

/** Every line of every source file, for seeding many findings at real locations. */
export const SOURCE_LINES: Loc[] = (
  [
    ['src/routes/users.ts', 35],
    ['src/routes/files.ts', 18],
    ['src/routes/admin.ts', 10],
    ['src/util/shell.ts', 10],
    ['src/db.ts', 13],
    ['src/app.ts', 14],
    ['src/middleware/auth.ts', 11],
  ] as const
).flatMap(([file, n]) => Array.from({ length: n }, (_, i) => ({ file, line: i + 1 })));

export interface SeedSpec {
  tool: string;
  rule_id: string;
  loc?: Loc;
  title?: string;
  message?: string;
  subcategory?: string;
  category?: Category;
  snippet?: string;
  severity?: Finding['severity'];
}

let clock = Date.parse('2026-09-01T00:00:00.000Z');

/**
 * One completed scan of `type` for `project`, holding `specs`. `type` is a
 * string so a scan type this build does not know yet (`llm_scan`) can be
 * seeded the way the feature will write it.
 */
export function seedScan(
  storage: Storage,
  db: Database,
  project: string,
  type: string,
  specs: SeedSpec[],
  toolsRun: ToolRun[] = [{ name: specs[0]?.tool ?? 'semgrep', status: 'ok' }],
): { scanId: string; findings: Finding[] } {
  const scanId = randomUUID();
  storage.scans.insert({ scan_id: scanId, scan_type: type as ScanType, project_path: project, tree_hash: `h-${scanId}` });
  const findings = specs.map((s) =>
    makeFinding({
      tool: s.tool,
      rule_id: s.rule_id,
      severity: s.severity ?? 'high',
      category: s.category ?? 'security',
      title: s.title ?? `${s.rule_id} finding`,
      ...(s.message !== undefined ? { message: s.message } : {}),
      ...(s.subcategory !== undefined ? { subcategory: s.subcategory } : {}),
      ...(s.snippet !== undefined ? { snippet: s.snippet } : {}),
      ...(s.loc !== undefined ? { file_path: s.loc.file, line_start: s.loc.line } : {}),
    }),
  );
  if (findings.length > 0) storage.findings.bulkInsert(findings.map((f) => ({ ...f, scan_id: scanId })));
  storage.scans.finalize({ scan_id: scanId, status: 'completed', tools_run: toolsRun, missing_tools: [] });
  clock += 1000;
  db.prepare('UPDATE scans SET started_at = ?, finished_at = ? WHERE id = ?').run(
    new Date(clock).toISOString(),
    new Date(clock + 500).toISOString(),
    scanId,
  );
  return { scanId, findings };
}

export interface Seeded {
  sastScanId: string;
  sqli: Finding;
  insert: Finding;
  shell: Finding;
  /** A dependency CVE: no file, so not eligible for verification (EC-1). */
  cve: Finding;
  /** Where each eligible finding sits, by fingerprint. */
  locs: Map<string, Loc>;
}

const SQL_RULE = 'javascript.express.security.injection.tainted-sql-string';
const EXEC_RULE = 'javascript.lang.security.detect-child-process';

/** The three SAST findings the fixture holds, and one CVE with no file. */
export function seedStandard(h: Harness): Seeded {
  const sast = seedScan(h.storage, h.db, h.project, 'sast', [
    { tool: 'semgrep', rule_id: SQL_RULE, loc: SQLI, message: 'User input flows into a SQL string.' },
    { tool: 'semgrep', rule_id: SQL_RULE, loc: PARAM_INSERT, message: 'User input flows into a SQL string.' },
    { tool: 'semgrep', rule_id: EXEC_RULE, loc: SHELL, message: 'A child process is started with input.' },
  ]);
  const deps = seedScan(
    h.storage,
    h.db,
    h.project,
    'deps',
    [{ tool: 'trivy', rule_id: 'CVE-2024-29041', title: 'express: open redirect in malformed URLs', severity: 'medium' }],
    [{ name: 'trivy', status: 'ok' }],
  );
  const [sqli, insert, shell] = sast.findings;
  const [cve] = deps.findings;
  if (sqli === undefined || insert === undefined || shell === undefined || cve === undefined) throw new Error('seeding failed');
  return {
    sastScanId: sast.scanId,
    sqli,
    insert,
    shell,
    cve,
    locs: new Map([
      [sqli.fingerprint, SQLI],
      [insert.fingerprint, PARAM_INSERT],
      [shell.fingerprint, SHELL],
    ]),
  };
}

/** `n` SAST findings at real lines of the fixture, each its own rule. */
export function seedMany(h: Harness, n: number): Map<string, Loc> {
  const specs: SeedSpec[] = Array.from({ length: n }, (_, i) => {
    const loc = SOURCE_LINES[i % SOURCE_LINES.length] ?? SQLI;
    return { tool: 'semgrep', rule_id: `fixture.rule-${i}`, loc, message: `Fixture finding ${i}.` };
  });
  const { findings } = seedScan(h.storage, h.db, h.project, 'sast', specs);
  return new Map(findings.map((f, i) => [f.fingerprint, specs[i]?.loc ?? SQLI]));
}

// ---- The fixture's routes, as map_attack_surface would store them ------

export const FIXTURE_ROUTES: Array<{ method: RouteRecord['method']; path: string; loc: Loc }> = [
  { method: 'GET', path: '/users', loc: { file: 'src/routes/users.ts', line: 6 } },
  { method: 'GET', path: '/users/:id', loc: { file: 'src/routes/users.ts', line: 10 } },
  { method: 'POST', path: '/users', loc: { file: 'src/routes/users.ts', line: 16 } },
  { method: 'PUT', path: '/users/:id', loc: { file: 'src/routes/users.ts', line: 22 } },
  { method: 'DELETE', path: '/users/:id', loc: { file: 'src/routes/users.ts', line: 27 } },
  { method: 'GET', path: '/users/:id/export', loc: { file: 'src/routes/users.ts', line: 32 } },
  { method: 'GET', path: '/files/:name', loc: { file: 'src/routes/files.ts', line: 9 } },
  { method: 'POST', path: '/files/upload', loc: { file: 'src/routes/files.ts', line: 15 } },
  { method: 'GET', path: '/admin/stats', loc: { file: 'src/routes/admin.ts', line: 7 } },
];

export function fixtureRoutes(project: string): RouteRecord[] {
  return FIXTURE_ROUTES.map((r) => ({
    method: r.method,
    provenance: 'code',
    path_raw: r.path,
    path_resolved: r.path,
    path_partial: false,
    // Stored absolute, as map_attack_surface stores it.
    file: join(project, r.loc.file),
    line: r.loc.line,
    framework: 'express',
    language: 'typescript',
    auth_hint: 'unknown',
    params: [],
    confidence: 'high',
  }));
}

/** A current surface snapshot of the project (its tree hash is the tree's own). */
export async function seedSurface(h: Harness, routes: RouteRecord[] = fixtureRoutes(h.project)): Promise<number> {
  const snapshot: AttackSurfaceSnapshot = {
    routes,
    env_vars: [],
    ports: [],
    webhooks: [],
    coverage: [],
    tools_run: [{ name: 'semgrep', status: 'ok' }],
    missing_tools: [],
    spec_files: [],
    spec_diff: null,
    imports: [],
  };
  const tree_hash = await computeTreeHash(h.project);
  return h.storage.surface.insert({ project_path: h.project, tree_hash, snapshot }).id;
}

// ---- The tools ----------------------------------------------------------

export type Raw = ToolResult<Record<string, unknown>>;

export async function callTool(h: Harness, name: string, input: Record<string, unknown>, meta?: ToolCallMeta): Promise<Raw> {
  const tool = TOOLS.find((t) => t.name === name);
  expect(tool, `${name} is registered`).toBeDefined();
  if (tool === undefined) throw new Error(`${name} is not registered`);
  return tool.handler(input, h.plugin, meta);
}

/** What the model reads of a response: its text content, in estimated tokens (chars / 4). */
export function responseTokens(name: string, r: Raw): number {
  const tool = TOOLS.find((t) => t.name === name);
  const call = toCallToolResult(r, tool?.contentOnlyKeys ?? []);
  return Math.ceil(call.content.map((c) => c.text).join('').length / 4);
}

export interface StartOut {
  plan_id: string;
  scan_id: string;
  tasks_total: number;
  by_kind: Partial<Record<TaskKind, number>>;
  not_eligible: Array<{ fingerprint: string; reason: string }>;
  set_aside: Array<{ entry_point: string; reason: string }>;
  estimate: PlanEstimate;
  needs_confirm: boolean;
  recipe: unknown;
  prompt_version: string;
}

export interface TaskOut {
  task_id: string;
  kind: TaskKind;
  lease_token: string;
  lease_expires_at: string;
  brief: string;
  response_schema: unknown;
  attempts_left: number;
}

export interface DoneOut {
  done: true;
  report: LlmScanReport;
}

export interface SubmitOut {
  accepted: boolean;
  progress?: unknown;
  errors?: SubmissionError[];
  rejected?: SubmissionError[];
  attempts_left?: number;
}

export interface StatusOut {
  plan_id: string;
  report: LlmScanReport;
}

export interface SamplingOut {
  executed: number;
  remaining: number;
  report: LlmScanReport;
}

export async function start(h: Harness, input: Record<string, unknown>): Promise<StartOut> {
  return okResult<StartOut>(await callTool(h, 'llm_scan_start', { project_path: h.project, ...input }));
}

export async function status(h: Harness, planId: string): Promise<StatusOut> {
  return okResult<StatusOut>(await callTool(h, 'llm_scan_start', { project_path: h.project, plan_id: planId }));
}

/** The next task, or the plan's end. */
export async function next(h: Harness, planId: string): Promise<TaskOut | DoneOut> {
  const r = okResult<Partial<TaskOut> & { done?: boolean; report?: LlmScanReport }>(
    await callTool(h, 'llm_scan_task', { plan_id: planId }),
  );
  if (r.done === true) {
    expect(r.report, 'a finished plan comes with its report').toBeDefined();
    return r as DoneOut;
  }
  expect(typeof r.task_id, JSON.stringify(r)).toBe('string');
  expect(typeof r.lease_token).toBe('string');
  expect(typeof r.brief).toBe('string');
  return r as TaskOut;
}

export const isTask = (x: TaskOut | DoneOut): x is TaskOut => !('done' in x);

/** The next task — the plan must not be over. */
export async function lease(h: Harness, planId: string): Promise<TaskOut> {
  const t = await next(h, planId);
  if (!isTask(t)) throw new Error('expected a task, the plan is done');
  return t;
}

/**
 * Leases tasks until one matches. The others stay leased; pass `skipped` to
 * get them back, so a test that later runs the plan to its end can answer
 * them (a leased task is not handed out again while its lease lasts).
 */
export async function leaseWhere(
  h: Harness,
  planId: string,
  match: (t: TaskOut) => boolean,
  skipped: TaskOut[] = [],
  max = 20,
): Promise<TaskOut> {
  for (let i = 0; i < max; i += 1) {
    const t = await lease(h, planId);
    if (match(t)) return t;
    skipped.push(t);
  }
  throw new Error('no matching task was handed out');
}

export async function submit(
  h: Harness,
  planId: string,
  t: { task_id: string; lease_token: string },
  payload: unknown,
  independence: Exclude<Independence, 'sampling'> = 'subagent',
): Promise<Raw> {
  return callTool(h, 'llm_scan_submit', {
    plan_id: planId,
    task_id: t.task_id,
    lease_token: t.lease_token,
    independence,
    payload,
  });
}

export function expectDomainError(r: Raw, code: string): void {
  expect(r.ok, JSON.stringify(r)).toBe(false);
  if (r.ok) return;
  expect(r.error.code).toBe(code);
}

/** A schema-valid verdict about the finding at `loc`. */
export function verdictAt(loc: Loc, verdict: VerifyVerdict['verdict']): VerifyVerdict {
  const where = at(loc);
  return {
    verdict,
    attacker_input: 'none',
    operation: where,
    decisive_line:
      verdict === 'not_real'
        ? `${where} — the value is bound as a parameter, never part of the statement`
        : `${where} — request input reaches the operation unchanged`,
    reasoning: `Followed the value into the operation at ${where}.`,
  };
}

/** Where the finding a verify task checks sits. */
export function locOfTask(h: Harness, planId: string, taskId: string, locs: ReadonlyMap<string, Loc>): Loc {
  const t = h.repo.getTask(planId, taskId);
  const fp = t?.target.fingerprint;
  const loc = fp === undefined ? undefined : locs.get(fp);
  if (loc === undefined) throw new Error(`task ${taskId} checks no seeded finding`);
  return loc;
}

/** An empty hunt answer for a hunt or cross-cutting task: the entry points it covered, nothing found. */
export function emptyHunt(h: Harness, planId: string, taskId: string): HuntResult {
  return { entry_points_reviewed: h.repo.getTask(planId, taskId)?.target.entry_points ?? [], findings: [] };
}

/** The LLM marker the open set attaches (`OpenFinding.llm`). */
export function llmOf(f: OpenFinding): LlmMarker | undefined {
  return (f as OpenFinding & { llm?: LlmMarker }).llm;
}

/** Call metadata carrying MCP sampling, as the server passes it when the client declares the capability. */
export function samplingMeta(fn: SamplingFn): ToolCallMeta {
  const meta: ToolCallMeta & { sampling: SamplingFn } = { sampling: fn };
  return meta;
}

/**
 * A client's sampling, faked: answers each request with the verdict `answer`
 * gives for the location it finds in the request, and records the request.
 */
export function fakeSampling(
  locs: ReadonlyMap<string, Loc>,
  answer: (loc: Loc) => VerifyVerdict,
  onCall?: () => void,
): { fn: SamplingFn; requests: string[] } {
  const requests: string[] = [];
  const fn: SamplingFn = async (params) => {
    const text = JSON.stringify(params);
    requests.push(text);
    onCall?.();
    // `file:12` must not be read as `file:1`.
    const cites = (l: Loc): boolean => new RegExp(`${at(l).replace(/[.*+?^${}()|[\]\\/]/g, '\\$&')}(?!\\d)`).test(text);
    const loc = [...locs.values()].find(cites);
    const verdict = loc === undefined ? { verdict: 'undetermined', reasoning: 'no location' } : answer(loc);
    return { role: 'assistant', content: { type: 'text', text: JSON.stringify(verdict) }, model: 'fake-sampling-model' };
  };
  return { fn, requests };
}
