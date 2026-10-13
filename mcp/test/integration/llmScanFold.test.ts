/**
 * The LLM scan as ONE listed tool, `llm_scan { step }` (src/tools/folds.ts),
 * called through a real MCP client — as a host calls it:
 *
 *   - the whole loop runs through it: start, task, submit, the report; the
 *     brief of a new plan (prompts v6) names the fold, never the alias;
 *   - `llm_scan_start`, `llm_scan_task` and `llm_scan_submit` stay callable
 *     as hidden aliases, with the same answers;
 *   - each step takes its member's parameters only, and keeps its member's
 *     required ones (invalid_input, naming them);
 *   - a submit without a `payload` is refused before the task is touched,
 *     through the fold and the alias alike: no try is spent on a call that
 *     carries no answer;
 *   - a plan made with v5 still renders v5 briefs, which name
 *     `llm_scan_submit`, and the alias takes their answer;
 *   - every hint a response gives names the fold, never a hidden alias (a
 *     model in Claude Code can call listed names only).
 */

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { attachAllTools } from '../../src/tools/index.js';
import { cleanupTempDirs } from '../helpers/tempDir.js';
import {
  PARAM_INSERT,
  harness,
  locOfTask,
  seedStandard,
  verdictAt,
  type Harness,
  type Loc,
} from '../helpers/llmScanHarness.js';

vi.setConfig({ testTimeout: 60_000 });
afterAll(cleanupTempDirs);
beforeAll(async () => {
  await import('../../src/registerAll.js');
});

interface CallResult {
  isError?: boolean;
  content: Array<{ type: string; text?: string }>;
  structuredContent?: Record<string, unknown>;
}

interface Session {
  h: Harness;
  locs: ReadonlyMap<string, Loc>;
  call: (name: string, args: Record<string, unknown>) => Promise<CallResult>;
}

async function session(): Promise<Session> {
  const h = harness();
  const { locs } = seedStandard(h);
  const server = new McpServer({ name: 'llm-scan-fold', version: '0.0.0' });
  attachAllTools(server, h.plugin);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const client = new Client({ name: 'llm-scan-fold-client', version: '0.0.0' });
  await client.connect(clientTransport);
  const call = async (name: string, args: Record<string, unknown>): Promise<CallResult> =>
    (await client.callTool({ name, arguments: args })) as unknown as CallResult;
  return { h, locs, call };
}

const text = (r: CallResult): string => r.content.map((c) => c.text ?? '').join('\n');
/** The result as the model reads it: the JSON of the text block. */
const body = (r: CallResult): Record<string, unknown> => JSON.parse(text(r)) as Record<string, unknown>;
const ALIAS = /llm_scan_(?:start|task|submit)/;

interface Leased {
  task_id: string;
  lease_token: string;
  brief: string;
}

async function startPlan(s: Session, extra: Record<string, unknown> = {}): Promise<string> {
  const r = await s.call('llm_scan', { step: 'start', project_path: s.h.project, modes: ['verify'], ...extra });
  expect(r.isError, text(r)).toBeFalsy();
  return String(body(r)['plan_id']);
}

async function leaseVia(s: Session, name: 'llm_scan' | 'llm_scan_task', planId: string): Promise<Leased> {
  const r = await s.call(name, name === 'llm_scan' ? { step: 'task', plan_id: planId } : { plan_id: planId });
  expect(r.isError, text(r)).toBeFalsy();
  // The brief is the step's content-only key: one representation, the text block.
  expect(r.structuredContent).toBeUndefined();
  return body(r) as unknown as Leased;
}

function answerFor(s: Session, planId: string, t: Leased): Record<string, unknown> {
  const loc = locOfTask(s.h, planId, t.task_id, s.locs);
  return { ...verdictAt(loc, loc === PARAM_INSERT ? 'not_real' : 'real') };
}

function submitArgs(planId: string, t: Leased, payload: unknown): Record<string, unknown> {
  return { plan_id: planId, task_id: t.task_id, lease_token: t.lease_token, independence: 'subagent', payload };
}

describe('llm_scan runs the whole loop', () => {
  it('start, task, submit until done, then the report — and the briefs name the fold', async () => {
    const s = await session();
    const started = await s.call('llm_scan', { step: 'start', project_path: s.h.project, modes: ['verify'] });
    const plan = body(started);
    expect(plan).toMatchObject({ ok: true, tasks_total: 3, prompt_version: 'v6' });
    const planId = String(plan['plan_id']);

    for (let i = 0; i < 3; i += 1) {
      const t = await leaseVia(s, 'llm_scan', planId);
      expect(t.brief).toContain('prompt v6');
      expect(t.brief).toContain('the `llm_scan` tool and `step: "submit"`');
      expect(t.brief).not.toMatch(ALIAS);
      const r = await s.call('llm_scan', { step: 'submit', ...submitArgs(planId, t, answerFor(s, planId, t)) });
      expect(body(r), text(r)).toMatchObject({ ok: true, accepted: true });
    }
    expect(body(await s.call('llm_scan', { step: 'task', plan_id: planId }))).toMatchObject({ ok: true, done: true });
    const report = body(await s.call('llm_scan', { step: 'start', project_path: s.h.project, plan_id: planId }));
    expect(report).toMatchObject({ ok: true, status: 'complete' });
    expect(JSON.stringify(report['report'])).toContain('"coverage":"full"');
  });

  it('the hidden aliases answer as the fold does, on the same plan', async () => {
    const s = await session();
    const planId = await startPlan(s);
    const viaAlias = await leaseVia(s, 'llm_scan_task', planId);
    const viaFold = await leaseVia(s, 'llm_scan', planId);
    expect(Object.keys(viaAlias).sort()).toEqual(Object.keys(viaFold).sort());

    const a = await s.call('llm_scan_submit', submitArgs(planId, viaAlias, answerFor(s, planId, viaAlias)));
    const b = await s.call('llm_scan', { step: 'submit', ...submitArgs(planId, viaFold, answerFor(s, planId, viaFold)) });
    expect(body(a)).toMatchObject({ ok: true, accepted: true });
    expect(body(b)).toMatchObject({ ok: true, accepted: true });

    const statusAlias = await s.call('llm_scan_start', { project_path: s.h.project, plan_id: planId });
    const statusFold = await s.call('llm_scan', { step: 'start', project_path: s.h.project, plan_id: planId });
    expect(statusFold.structuredContent).toEqual(statusAlias.structuredContent);
  });
});

describe('each step takes its own parameters, and requires what its member requires', () => {
  it.each([
    [{ step: 'task', plan_id: 'p', confirm: true }, /llm_scan \{step: "task"\} does not take confirm; it takes plan_id, execute/],
    [{ step: 'start', task_id: 't-0001' }, /llm_scan \{step: "start"\} does not take task_id/],
    [
      { step: 'submit', plan_id: 'p', task_id: 't', lease_token: 'l', independence: 'subagent', payload: {}, modes: ['verify'] },
      /llm_scan \{step: "submit"\} does not take modes; it takes plan_id, task_id, lease_token, independence, payload/,
    ],
  ])('%j is refused, naming what the step takes', async (args, why) => {
    const s = await session();
    const r = await s.call('llm_scan', args);
    expect(r.isError).toBe(true);
    expect(text(r)).toMatch(/invalid_input/);
    expect(text(r)).toMatch(why);
  });

  it.each([
    [{ step: 'task' }, /plan_id: Required/],
    [{ step: 'submit', plan_id: 'p', task_id: 't', lease_token: 'l', payload: {} }, /independence: Required/],
    [{ step: 'submit', plan_id: 'p', independence: 'subagent', payload: {} }, /task_id: Required; lease_token: Required/],
  ])('%j is refused, naming the missing argument', async (args, why) => {
    const s = await session();
    const r = await s.call('llm_scan', args);
    expect(r.isError).toBe(true);
    expect(text(r)).toMatch(/invalid_input/);
    expect(text(r)).toMatch(why);
  });

  it('no step is refused by the schema, before any member runs', async () => {
    const s = await session();
    const r = await s.call('llm_scan', { plan_id: 'p' });
    expect(r.isError).toBe(true);
    expect(text(r)).toMatch(/step/);
    expect(s.h.repo.listPlans(s.h.project)).toEqual([]);
  });
});

describe('a submit without a payload spends no try', () => {
  it.each(['llm_scan', 'llm_scan_submit'])('through %s: refused as invalid_input, the task still leased and untried', async (name) => {
    const s = await session();
    const planId = await startPlan(s);
    const t = await leaseVia(s, 'llm_scan', planId);
    const { payload: _none, ...noPayload } = submitArgs(planId, t, undefined);
    const r = await s.call(name, name === 'llm_scan' ? { step: 'submit', ...noPayload } : noPayload);
    expect(r.isError).toBe(true);
    expect(text(r)).toMatch(/payload/);
    expect(s.h.repo.getTask(planId, t.task_id)).toMatchObject({ status: 'leased', attempts: 0 });

    const answered = await s.call(name, name === 'llm_scan' ? { step: 'submit', ...submitArgs(planId, t, answerFor(s, planId, t)) } : submitArgs(planId, t, answerFor(s, planId, t)));
    expect(body(answered)).toMatchObject({ ok: true, accepted: true });
  });
});

describe('a plan made with an older prompt version', () => {
  it('renders its own version, which names llm_scan_submit, and the alias takes the answer', async () => {
    const s = await session();
    const planId = await startPlan(s);
    s.h.db.prepare('UPDATE llm_scan_plans SET prompt_version = ? WHERE id = ?').run('v5', planId);
    const t = await leaseVia(s, 'llm_scan', planId);
    expect(t.brief).toContain('prompt v5');
    expect(t.brief).toContain('`llm_scan_submit`');
    const r = await s.call('llm_scan_submit', submitArgs(planId, t, answerFor(s, planId, t)));
    expect(body(r)).toMatchObject({ ok: true, accepted: true });
    const row = s.h.storage.validations.listByProvider(s.h.project, 'llm')[0];
    expect(row?.evidence.map((e) => e.detail)).toContain('prompt_version: v5');
  });
});

describe('the hints a response gives name the fold, never a hidden alias', () => {
  it('start over the token limit: confirm_with and the recipe; task before the confirmation: the needs_confirm message', async () => {
    const s = await session();
    const over = body(await s.call('llm_scan', { step: 'start', project_path: s.h.project, modes: ['verify'], per_task_overhead: 300_000 }));
    expect(over['needs_confirm']).toBe(true);
    expect(over['confirm_with']).toBe('llm_scan { step: "start", plan_id, confirm: true }');
    expect(JSON.stringify(over['recipe'])).toContain('llm_scan { step: \\"task\\", plan_id }');
    expect(JSON.stringify(over)).not.toMatch(ALIAS);

    const refused = await s.call('llm_scan', { step: 'task', plan_id: String(over['plan_id']) });
    expect(refused.isError).toBe(true);
    expect(text(refused)).toMatch(/needs_confirm/);
    expect(text(refused)).toMatch(/Confirm with llm_scan \{ step: "start", plan_id: /);
    expect(text(refused)).not.toMatch(ALIAS);
  });

  it('too_many_open_plans and plan_abandoned', async () => {
    const s = await session();
    const ids: string[] = [];
    for (let i = 0; i < 5; i += 1) ids.push(await startPlan(s));
    const sixth = await s.call('llm_scan', { step: 'start', project_path: s.h.project, modes: ['verify'] });
    expect(text(sixth)).toMatch(/too_many_open_plans/);
    expect(text(sixth)).toMatch(/read its report with llm_scan \{ step: "start", plan_id \}/);
    expect(text(sixth)).not.toMatch(ALIAS);

    const first = ids[0] ?? '';
    expect(s.h.repo.updatePlan(first, 'abandoned', new Date().toISOString())).toBe(true);
    const gone = await s.call('llm_scan', { step: 'task', plan_id: first });
    expect(text(gone)).toMatch(/plan_abandoned/);
    expect(text(gone)).toMatch(/Start a new plan with llm_scan \{ step: "start" \}/);
    expect(text(gone)).not.toMatch(ALIAS);
  });
});
