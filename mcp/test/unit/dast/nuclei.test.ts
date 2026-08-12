import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../src/runners/processRunner.js', () => ({ runProcess: vi.fn() }));

import { runProcess, type ProcessRunResult } from '../../../src/runners/processRunner.js';
import { buildNucleiArgs, interpretRun, invokeNuclei } from '../../../src/dast/nuclei.js';

const BASE = {
  binaryPath: '/usr/bin/nuclei', targetUrl: 'http://localhost:3000',
  outputPath: '/tmp/out.jsonl', allowIntrusive: false, timeoutMs: 120000,
};

describe('buildNucleiArgs', () => {
  it('always disables interactsh', () => {
    // Out-of-band probes make the TARGET call a third-party server. That is an
    // exfiltration channel out of a scanner pointed at an internal network,
    // and it must not depend on any other flag.
    expect(buildNucleiArgs(BASE)).toContain('-no-interactsh');
    expect(buildNucleiArgs({ ...BASE, allowIntrusive: true })).toContain('-no-interactsh');
  });

  it('excludes destructive tag families under the default envelope', () => {
    const args = buildNucleiArgs(BASE);
    const i = args.indexOf('-exclude-tags');
    expect(i).toBeGreaterThan(-1);
    const value = args[i + 1] ?? '';
    for (const tag of ['dos', 'fuzz', 'intrusive']) {
      expect(value.split(','), tag).toContain(tag);
    }
  });

  it('writes jsonl to the given output path and targets the given url', () => {
    const args = buildNucleiArgs(BASE);
    expect(args).toContain('-jsonl');
    expect(args[args.indexOf('-output') + 1]).toBe('/tmp/out.jsonl');
    expect(args[args.indexOf('-target') + 1]).toBe('http://localhost:3000');
  });

  it('sets a rate limit', () => {
    expect(buildNucleiArgs(BASE)).toContain('-rate-limit');
  });

  // Addition beyond the brief's given tests: `allowIntrusive` must narrow the
  // exclude list by exactly the `intrusive` tag. A wrong implementation that
  // also drops 'dos' or 'fuzz' once intrusive templates are allowed would
  // reopen the fuzzing/DoS-shaped templates the design doc's non-goals
  // permanently rule out of this tool (real fuzzing stays behind nuclei's own
  // `-dast` mode, which this integration never enables).
  it('keeps dos and fuzz excluded even when intrusive templates are allowed', () => {
    const args = buildNucleiArgs({ ...BASE, allowIntrusive: true });
    const i = args.indexOf('-exclude-tags');
    const value = (args[i + 1] ?? '').split(',');
    expect(value).toContain('dos');
    expect(value).toContain('fuzz');
    expect(value).not.toContain('intrusive');
  });
});

// Addition beyond the brief's given tests, mirroring `scanSemgrep.test.ts`'s
// `buildToolRun` block: exit-code interpretation is pure, so it is tested
// directly against fabricated `ProcessRunResult` values — no real process,
// no binary required.
describe('interpretRun', () => {
  function run(outcome: ProcessRunResult['outcome'], stderr = ''): ProcessRunResult {
    return { outcome, exitCode: outcome === 'completed' ? 0 : 1, stdout: '', stderr, truncated: false };
  }

  it('treats a completed run (exit 0) as ok, whether or not templates matched', () => {
    // nuclei carries none of Semgrep's "non-zero exit means it found
    // something" behaviour: a maintainer-confirmed reproduction
    // (projectdiscovery/nuclei#5086) shows exit 0 with zero results too. A
    // wrong implementation ports Semgrep's `exitCode === 1` special case over
    // unchanged and would misreport a genuine execution failure that happens
    // to share that exit code as success.
    expect(interpretRun(run('completed'))).toEqual({ ok: true });
  });

  it('treats a non-zero exit as a real failure and carries the first stderr line', () => {
    const result = interpretRun(run('failed', '\nFATAL: could not load templates\nmore'));
    expect(result.ok).toBe(false);
    expect(result.reason).toBe('FATAL: could not load templates');
  });

  it('names the outcome when stderr is empty, rather than an undefined reason', () => {
    const result = interpretRun(run('timed_out'));
    expect(result.ok).toBe(false);
    expect(result.reason).toBe('nuclei timed_out');
  });
});

// Addition beyond the brief's given tests, mirroring `scanSemgrep.test.ts`'s
// `invokeSemgrep` block: `runProcess` is mocked so this exercises the real
// wiring (command, argv, timeout) without spawning anything.
describe('invokeNuclei', () => {
  beforeEach(() => {
    vi.mocked(runProcess).mockReset();
  });

  it('spawns the resolved binary with the built argv and the given timeout', async () => {
    vi.mocked(runProcess).mockResolvedValue({
      outcome: 'completed', exitCode: 0, stdout: '', stderr: '', truncated: false,
    });

    await invokeNuclei(BASE);

    const call = vi.mocked(runProcess).mock.calls[0]?.[0];
    expect(call?.command).toBe('/usr/bin/nuclei');
    expect(call?.args).toEqual(buildNucleiArgs(BASE));
    expect(call?.timeoutMs).toBe(120000);
  });

  it('surfaces a failed run as ok: false with a reason', async () => {
    vi.mocked(runProcess).mockResolvedValue({
      outcome: 'failed', exitCode: 2, stdout: '', stderr: 'bad flag', truncated: false,
    });

    const result = await invokeNuclei(BASE);
    expect(result).toEqual({ ok: false, reason: 'bad flag' });
  });
});
