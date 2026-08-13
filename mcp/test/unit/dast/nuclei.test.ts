import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../src/runners/processRunner.js', () => ({ runProcess: vi.fn() }));

import { runProcess, type ProcessRunResult } from '../../../src/runners/processRunner.js';
import { buildNucleiArgs, interpretRun, invokeNuclei, nucleiEnv } from '../../../src/dast/nuclei.js';

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

/**
 * nuclei is handed a target URL and nothing else — never the caller's
 * Authorization header. But a child process inherits the parent's whole
 * environment by default, and `scan_dast`'s recommended credential path is
 * `auth_header_env`, which names a variable holding exactly that header
 * value. So the secret the tool takes care never to put on nuclei's command
 * line was being handed to it anyway, one level down.
 */
describe('the nuclei child environment', () => {
  const SECRET_VAR = 'GUARDIAN_DAST_TEST_AUTH';
  const SECRET = 'Bearer nuclei-must-never-see-this';

  /**
   * What the child ACTUALLY receives, modelling execa's own contract:
   * `env` is MERGED over `process.env` unless `extendEnv: false`. Asserting
   * on `options.env` alone is the trap here — it passes vacuously today,
   * when `env` is undefined and the child inherits everything.
   */
  function childEnv(options: Parameters<typeof runProcess>[0]): NodeJS.ProcessEnv {
    return options.extendEnv === false
      ? (options.env ?? {})
      : { ...process.env, ...(options.env ?? {}) };
  }

  beforeEach(() => {
    vi.mocked(runProcess).mockReset();
    vi.mocked(runProcess).mockResolvedValue({
      outcome: 'completed', exitCode: 0, stdout: '', stderr: '', truncated: false,
    });
    process.env[SECRET_VAR] = SECRET;
  });

  afterEach(() => {
    delete process.env[SECRET_VAR];
  });

  it('does not reach the child, even though execa merges with process.env by default', async () => {
    await invokeNuclei(BASE);
    const call = vi.mocked(runProcess).mock.calls[0]?.[0];
    expect(call).toBeDefined();
    if (call === undefined) return;
    expect(Object.values(childEnv(call)).join('\n')).not.toContain(SECRET);
    expect(Object.keys(childEnv(call))).not.toContain(SECRET_VAR);
  });

  it('passes extendEnv: false, without which the allowlist is a no-op', async () => {
    // Stated as its own assertion because it is the entire mechanism: an
    // allowlisted `env` with `extendEnv` left at its default is merged ON TOP
    // of the full parent environment and scrubs nothing.
    await invokeNuclei(BASE);
    expect(vi.mocked(runProcess).mock.calls[0]?.[0].extendEnv).toBe(false);
  });

  it('still carries what the binary needs to run', async () => {
    // The other half of the envelope: an over-tight allowlist turns a working
    // scan into a mysteriously failing one. PATH must survive.
    await invokeNuclei(BASE);
    const env = childEnv(vi.mocked(runProcess).mock.calls[0]?.[0] ?? { command: '', cwd: '' });
    const names = Object.keys(env).map((k) => k.toLowerCase());
    expect(names).toContain('path');
  });
});

describe('nucleiEnv', () => {
  it('copies allowlisted names and drops everything else', () => {
    const out = nucleiEnv({
      PATH: '/usr/bin',
      HOME: '/home/dev',
      API_TOKEN: 'sk-live-secret',
      GUARDIAN_DAST_AUTH: 'Bearer secret',
    });
    expect(out['PATH']).toBe('/usr/bin');
    expect(out['HOME']).toBe('/home/dev');
    expect(out['API_TOKEN']).toBeUndefined();
    expect(out['GUARDIAN_DAST_AUTH']).toBeUndefined();
  });

  it('matches names case-insensitively, so Windows PATH survives', () => {
    // Windows spells it `Path`. A case-sensitive allowlist drops it there and
    // nowhere else — a failure that reproduces on one platform only.
    expect(nucleiEnv({ Path: 'C:\\Windows', SystemRoot: 'C:\\Windows' })).toEqual({
      Path: 'C:\\Windows',
      SystemRoot: 'C:\\Windows',
    });
  });

  it('drops a variable whose name merely contains an allowlisted one', () => {
    // Guards a substring/prefix match: `PATH_TO_VAULT_TOKEN` is not `PATH`.
    expect(nucleiEnv({ PATH_TO_VAULT_TOKEN: 'shhh', MY_HOME: 'x' })).toEqual({});
  });

  it('omits an allowlisted name that is unset rather than defining it as undefined', () => {
    // `{ PATH: undefined }` is not the same as `{}` once execa spreads it.
    expect(Object.keys(nucleiEnv({ HOME: '/home/dev' }))).toEqual(['HOME']);
  });
});
