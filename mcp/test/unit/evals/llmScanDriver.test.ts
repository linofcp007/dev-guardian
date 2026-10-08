/**
 * The eval driver's pure half (`test/evals/llmScan/driver.ts`): the CLI
 * arguments that isolate a run, the child's environment, reading the CLI's
 * `stream-json` output, pulling the JSON answer out of the final message,
 * and telling the tool calls that left the brief. No model is run.
 */

import { join, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  HARNESS_NOTE,
  MODE_TOOLS,
  addUsage,
  childEnv,
  claudeArgs,
  driveTask,
  extractAnswer,
  extractAnswerDetailed,
  insideRoot,
  isolationProblem,
  jsonProblem,
  outOfBriefCalls,
  parseClaudeOutput,
  pool,
  usageOf,
  type AnswerCheck,
  type ClaudeRun,
  type DriverOptions,
} from '../../evals/llmScan/driver.js';

const valueAfter = (args: readonly string[], flag: string): string | undefined => {
  const i = args.indexOf(flag);
  return i === -1 ? undefined : args[i + 1];
};

describe('the CLI invocation', () => {
  it('subagent mode: Read, Grep and Glob only, pre-approved; isolated from MCP, settings, plugins and saved sessions', () => {
    const a = claudeArgs({ mode: 'subagent', model: 'sonnet' });
    expect(a[0]).toBe('-p');
    expect(valueAfter(a, '--output-format')).toBe('stream-json');
    expect(a).toContain('--verbose');
    expect(valueAfter(a, '--model')).toBe('sonnet');
    expect(valueAfter(a, '--tools')).toBe('Read,Grep,Glob');
    expect(valueAfter(a, '--allowedTools')).toBe('Read,Grep,Glob');
    for (const f of ['--restricted', '--safe-mode', '--strict-mcp-config', '--no-session-persistence']) expect(a).toContain(f);
    expect(valueAfter(a, '--permission-prompts')).toBe('none');
    expect(valueAfter(a, '--append-system-prompt')).toBe(HARNESS_NOTE);
    expect(a.join(' ')).not.toMatch(/Bash|WebFetch|dangerously/);
  });

  it('brief-only mode: no tool at all — an empty --tools, nothing pre-approved', () => {
    const a = claudeArgs({ mode: 'brief-only', model: 'haiku' });
    expect(valueAfter(a, '--tools')).toBe('');
    expect(a).not.toContain('--allowedTools');
    expect(MODE_TOOLS['brief-only']).toEqual([]);
  });

  it('the child never sees the corpora variables (they name the keys) nor the parent session\'s markers', () => {
    const env = childEnv({ PATH: '/bin', GUARDIAN_VAMPI_SRC: '/c/VAmPI', GUARDIAN_LLMSCAN_SPIKE: '/keys', CLAUDECODE: '1', HOME: '/h' });
    expect(env).toEqual({ PATH: '/bin', HOME: '/h' });
  });
});

const ev = (o: unknown): string => JSON.stringify(o);

describe('reading stream-json', () => {
  const stream = [
    ev({ type: 'system', subtype: 'init', tools: ['Glob', 'Grep', 'Read'], session_id: 's' }),
    ev({ type: 'assistant', message: { id: 'm1', content: [{ type: 'text', text: 'Looking.' }] } }),
    ev({ type: 'assistant', message: { id: 'm1', content: [{ type: 'tool_use', id: 't1', name: 'Read', input: { file_path: 'src/a.ts' } }] } }),
    ev({ type: 'user', message: { content: [{ type: 'tool_result', tool_use_id: 't1', content: '...' }] } }),
    ev({ type: 'assistant', message: { id: 'm1', content: [{ type: 'tool_use', id: 't1', name: 'Read', input: { file_path: 'src/a.ts' } }] } }),
    ev({ type: 'assistant', message: { id: 'm2', content: [{ type: 'tool_use', id: 't2', name: 'Bash', input: { command: 'ls' } }] } }),
    'not json at all',
    ev({
      type: 'result',
      subtype: 'success',
      is_error: false,
      num_turns: 3,
      total_cost_usd: 0.12,
      result: '{"verdict":"real"}',
      usage: { input_tokens: 10, output_tokens: 20, cache_creation_input_tokens: 300, cache_read_input_tokens: 4000 },
    }),
  ].join('\n');

  it('reads the tools offered, every tool call once, the final text, usage, turns and cost', () => {
    const p = parseClaudeOutput(stream);
    expect(p.available_tools).toEqual(['Glob', 'Grep', 'Read']);
    expect(p.tool_calls.map((c) => [c.id, c.name])).toEqual([
      ['t1', 'Read'],
      ['t2', 'Bash'],
    ]);
    expect(p.final_text).toBe('{"verdict":"real"}');
    expect(p.usage).toEqual({ input: 10, output: 20, cache_creation: 300, cache_read: 4000, total: 4330 });
    expect(p.num_turns).toBe(3);
    expect(p.cost_usd).toBe(0.12);
    expect(p.is_error).toBe(false);
    expect(p.subtype).toBe('success');
  });

  it('also reads the single object --output-format json prints', () => {
    const p = parseClaudeOutput(ev({ type: 'result', subtype: 'success', is_error: false, result: 'ok', usage: { input_tokens: 1, output_tokens: 2 } }));
    expect(p.final_text).toBe('ok');
    expect(p.usage.total).toBe(3);
    expect(p.tool_calls).toEqual([]);
    expect(p.available_tools).toBeNull();
  });

  it('no result event, or one that says so, is an error', () => {
    expect(parseClaudeOutput(stream.split('\n').slice(0, 3).join('\n')).is_error).toBe(true);
    expect(parseClaudeOutput(ev({ type: 'result', subtype: 'error_max_turns', is_error: true })).is_error).toBe(true);
    expect(parseClaudeOutput('').final_text).toBe('');
  });

  it('usage arithmetic', () => {
    expect(usageOf(undefined).total).toBe(0);
    expect(addUsage(usageOf({ input_tokens: 1 }), usageOf({ output_tokens: 2, cache_read_input_tokens: 3 }))).toEqual({ input: 1, output: 2, cache_creation: 0, cache_read: 3, total: 6 });
  });
});

describe('the JSON answer in the final message', () => {
  it('bare, fenced, or wrapped in prose', () => {
    expect(extractAnswer('{"verdict":"real"}')).toEqual({ verdict: 'real' });
    expect(extractAnswer('```json\n{"verdict":"not_real"}\n```')).toEqual({ verdict: 'not_real' });
    expect(extractAnswer('Here it is:\n{"verdict":"undetermined","reasoning":"x"}\nDone.')).toEqual({ verdict: 'undetermined', reasoning: 'x' });
  });

  it('unwraps the submit envelope, but not a payload that merely has a payload key', () => {
    expect(extractAnswer('{"plan_id":"p","task_id":"t-0001","payload":{"verdict":"real"}}')).toEqual({ verdict: 'real' });
    expect(extractAnswer('{"verdict":"real","payload":{"x":1}}')).toEqual({ verdict: 'real', payload: { x: 1 } });
  });

  it('nothing JSON: undefined (the validator then refuses it)', () => {
    expect(extractAnswer('I think it is real.')).toBeUndefined();
    expect(extractAnswer('[1, 2]')).toBeUndefined();
    expect(extractAnswer('{ broken')).toBeUndefined();
  });

  it('review round 1: says when the answer needed leniency the product\'s submit does not have', () => {
    expect(extractAnswerDetailed('{"verdict":"real"}').lenient).toBe(false);
    expect(extractAnswerDetailed('  {"verdict":"real"}\n').lenient).toBe(false);
    expect(extractAnswerDetailed('```json\n{"verdict":"real"}\n```').lenient).toBe(true);
    expect(extractAnswerDetailed('Verdict:\n{"verdict":"real"}').lenient).toBe(true);
    expect(extractAnswerDetailed('{"plan_id":"p","payload":{"verdict":"real"}}')).toEqual({ value: { verdict: 'real' }, lenient: true });
    expect(extractAnswerDetailed('no json')).toEqual({ value: undefined, lenient: false });
  });

  it('says why an object-shaped message is not JSON, with the text where the parser stopped', () => {
    const quote = jsonProblem('{"verdict":"real","reasoning":"possible = "ABC" so guess is B"}');
    expect(quote).toMatch(/^JSON\.parse: /);
    expect(quote).toContain('near ');
    expect(quote).toContain('possible = ');
    expect(jsonProblem('{"reasoning":"line one\nline two"}')).toMatch(/^JSON\.parse: .*near /);
    expect(jsonProblem('{"verdict":"real"}')).toBeNull();
    expect(jsonProblem('no object here')).toBeNull();
  });
});

describe('review round 1: isolation is verified on every session', () => {
  it('the init event must offer exactly the mode\'s tools, and must be there', () => {
    expect(isolationProblem(['Glob', 'Grep', 'Read'], 'subagent')).toBeNull();
    expect(isolationProblem([], 'brief-only')).toBeNull();
    expect(isolationProblem(['Glob', 'Grep', 'Read', 'Bash'], 'subagent')).toMatch(/Bash/);
    expect(isolationProblem(['Read', 'mcp__dev-guardian__suppress_finding'], 'subagent')).toMatch(/mcp__dev-guardian__suppress_finding/);
    expect(isolationProblem(['Read'], 'brief-only')).toMatch(/brief-only mode: Read/);
    expect(isolationProblem(null, 'subagent')).toMatch(/init event was not seen/);
  });

  const opts: DriverOptions & { retries: number } = { mode: 'subagent', model: 'sonnet', bin: 'claude', timeoutMs: 1000, retries: 2 };
  const run = (tools: string[] | null, finalText: string): ClaudeRun => ({
    final_text: finalText,
    tool_calls: [],
    available_tools: tools,
    usage: usageOf({ input_tokens: 1 }),
    num_turns: 1,
    cost_usd: 0,
    is_error: false,
    subtype: 'success',
    ok: true,
    error: null,
    exit_code: 0,
    duration_ms: 1,
    stderr_tail: '',
  });
  const accept = (seen: unknown[]) => (a: unknown): AnswerCheck<unknown> => {
    seen.push(a);
    return { ok: true, value: a };
  };

  it('a session offered Bash or an MCP tool makes the task invalid at once: the answer is not read, nothing is retried', async () => {
    for (const tools of [['Glob', 'Grep', 'Read', 'Bash'], ['Read', 'mcp__srv__x'], null]) {
      const seen: unknown[] = [];
      let calls = 0;
      const d = await driveTask('brief', '/tmp/x', opts, accept(seen), async () => {
        calls += 1;
        return run(tools, '{"verdict":"real"}');
      });
      expect(d.failure).toBe('invalid');
      expect(d.value).toBeNull();
      expect(d.isolation).not.toBeNull();
      expect(seen).toEqual([]);
      expect(calls).toBe(1);
    }
  });

  it('an isolated session is read as before, and a lenient answer is counted', async () => {
    const seen: unknown[] = [];
    const d = await driveTask('brief', '/tmp/x', opts, accept(seen), async () => run(['Glob', 'Grep', 'Read'], '```json\n{"verdict":"real"}\n```'));
    expect(d.failure).toBeNull();
    expect(d.isolation).toBeNull();
    expect(d.value).toEqual({ verdict: 'real' });
    expect(d.lenient_extractions).toBe(1);
  });
});

describe('tool calls outside the brief', () => {
  const root = resolve('/tmp/ws-x/app-v');

  it('any tool the mode does not allow, and any allowed file tool pointed outside the copy', () => {
    const calls = [
      { id: '1', name: 'Read', input: { file_path: 'models/user_model.py' } },
      { id: '2', name: 'Read', input: { file_path: join(root, 'config.py') } },
      { id: '3', name: 'Read', input: { file_path: resolve('/tmp/ws-x/answer-keys/key.tsv') } },
      { id: '4', name: 'Grep', input: { pattern: 'SECRET', path: '..' } },
      { id: '5', name: 'Glob', input: { pattern: '../**/*.tsv' } },
      { id: '6', name: 'Glob', input: { pattern: '**/*.py' } },
      { id: '7', name: 'mcp__dev-guardian__suppress_finding', input: {} },
      { id: '8', name: 'Bash', input: { command: 'cat ../key.tsv' } },
    ];
    const out = outOfBriefCalls(calls, MODE_TOOLS.subagent, root);
    expect(out.map((o) => o.name)).toEqual(['Read', 'Grep', 'Glob', 'mcp__dev-guardian__suppress_finding', 'Bash']);
    expect(outOfBriefCalls(calls.slice(0, 2), MODE_TOOLS['brief-only'], root)).toHaveLength(2);
  });

  it('review round 1: Grep\'s glob filter is inspected too', () => {
    const calls = [
      { id: '1', name: 'Grep', input: { pattern: 'x', glob: '*.py' } },
      { id: '2', name: 'Grep', input: { pattern: 'x', glob: '../**/*.tsv' } },
      { id: '3', name: 'Grep', input: { pattern: 'x', glob: resolve('/tmp/ws-x/answer-keys/*.tsv') } },
      { id: '4', name: 'Grep', input: { pattern: 'x', glob: join(root, 'models', '*.py') } },
    ];
    const out = outOfBriefCalls(calls, MODE_TOOLS.subagent, root);
    expect(out).toHaveLength(2);
    expect(out.every((o) => o.name === 'Grep' && o.why.startsWith('glob outside the project'))).toBe(true);
  });

  it('insideRoot', () => {
    expect(insideRoot(root, '.')).toBe(true);
    expect(insideRoot(root, 'a/../b')).toBe(true);
    expect(insideRoot(root, '../app-vx/a')).toBe(false);
    expect(insideRoot(root, `${root}x/a`)).toBe(false);
  });
});

describe('pool', () => {
  it('keeps input order and never runs more than the limit at once', async () => {
    let running = 0;
    let peak = 0;
    const out = await pool([5, 1, 4, 2, 3], 2, async (n) => {
      running += 1;
      peak = Math.max(peak, running);
      await new Promise((r) => setTimeout(r, n * 3));
      running -= 1;
      return n * 10;
    });
    expect(out).toEqual([50, 10, 40, 20, 30]);
    expect(peak).toBe(2);
    expect(await pool([], 4, async () => 1)).toEqual([]);
  });
});
