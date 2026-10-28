/**
 * `runners/semgrepValidate.ts`: a refusal is Semgrep's verdict in its output,
 * never the exit code alone. The outputs are Semgrep 1.182.0's own (measured
 * 2026-10-27); the last two are what a run that broke prints. A valid house
 * rule read as refused, once, under the full suite's load
 * (createFixPrLocalRules), which is what the two broken runs stand for.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { ProcessRunResult } from '../../../src/runners/processRunner.js';

const answers = vi.hoisted(() => ({ queue: [] as Array<Pick<ProcessRunResult, 'exitCode' | 'stdout' | 'stderr'>> }));
vi.mock('../../../src/runners/semgrepRun.js', () => ({
  runSemgrep: async (): Promise<ProcessRunResult> => {
    const next = answers.queue.shift();
    if (next === undefined) throw new Error('an unexpected semgrep --validate run');
    return { outcome: next.exitCode === 0 ? 'completed' : 'failed', truncated: false, ...next };
  },
}));

import { validateRuleFiles } from '../../../src/runners/semgrepValidate.js';

const VALID = 'Configuration is valid - found 0 configuration error(s), and 1 rule(s).\n';
const BROKEN_PATTERN =
  'Configuration is invalid - found 1 configuration error(s), and 1 rule(s).\n' +
  '[ERROR] Pattern parse error in rule bad:\n Invalid pattern for Python:\n';
const UNKNOWN_LANGUAGE =
  'semgrep error: invalid language: nolang\nunsupported language: nolang. supported languages are: apex, bash, …\n';
const ENGINE_KILLED =
  'semgrep-core exited with -9!\n' +
  'Configuration is invalid - found 1 configuration error(s), and 1 rule(s).\n' +
  '[ERROR] Error while running rules: \n You are seeing this because the engine was killed.\n';
const CRASH =
  'Traceback (most recent call last):\n  File "semgrep\\main.py", line 21, in main\n' +
  'OSError: [WinError 1455] The paging file is too small for this operation to complete\n';

afterEach(() => {
  answers.queue = [];
});

describe('semgrep --validate: what counts as a refusal', () => {
  it('exit 0 validates', async () => {
    answers.queue.push({ exitCode: 0, stdout: VALID, stderr: '' });
    expect(await validateRuleFiles(['a.yml'], '.')).toEqual({ validated: true, invalid: new Map() });
  });

  it.each([
    ['a broken pattern (exit 2)', 2, BROKEN_PATTERN, /Pattern parse error in rule bad/],
    ['an unknown language (exit 8, no verdict line)', 8, UNKNOWN_LANGUAGE, /invalid language: nolang/],
  ])('%s is a refusal, in Semgrep\'s words', async (_name, exitCode, stderr, said) => {
    answers.queue.push({ exitCode, stdout: '', stderr });
    const v = await validateRuleFiles(['a.yml'], '.');
    expect(v.validated).toBe(true);
    if (v.validated) expect(v.invalid.get('a.yml')).toMatch(said);
  });

  it.each([
    ['the engine killed under the run, beside the verdict', 2, ENGINE_KILLED, /exit 2/],
    ['a crash with no verdict at all', 1, CRASH, /exit 1\): Traceback.*WinError 1455/],
  ])('%s refused nothing: not validated, named', async (_name, exitCode, stderr, said) => {
    answers.queue.push({ exitCode, stdout: '', stderr });
    const v = await validateRuleFiles(['a.yml'], '.');
    expect(v.validated).toBe(false);
    if (!v.validated) expect(v.reason).toMatch(said);
  });

  it('two files, refused together, then one of the single runs breaks: nothing is validated', async () => {
    answers.queue.push(
      { exitCode: 2, stdout: '', stderr: BROKEN_PATTERN },
      { exitCode: 2, stdout: '', stderr: BROKEN_PATTERN },
      { exitCode: 1, stdout: '', stderr: CRASH },
    );
    const v = await validateRuleFiles(['bad.yml', 'good.yml'], '.');
    expect(v.validated).toBe(false);
    expect(answers.queue).toEqual([]);
  });
});
