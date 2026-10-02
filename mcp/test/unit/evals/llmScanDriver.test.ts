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
  extractAnswer,
  insideRoot,
  outOfBriefCalls,
  parseClaudeOutput,
  pool,
  usageOf,
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
