import { chmodSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { execPath } from 'node:process';
import { fileURLToPath } from 'node:url';
import { execa } from 'execa';
import { afterAll, afterEach, beforeEach, describe, expect, it } from 'vitest';
import { runProcess } from '../../../src/runners/processRunner.js';
import { makeTempDir, cleanupTempDirs } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

const MCP_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');

/**
 * `extendEnv` is the half of the environment-scrubbing contract that is easy
 * to get wrong invisibly: execa MERGES `env` over `process.env` by default, so
 * a caller that passes a carefully allowlisted `env` and forgets
 * `extendEnv: false` hands the child every parent variable anyway. Nothing
 * about that failure is observable from the option object — only from what the
 * child actually receives.
 *
 * So these spawn a real Node child (the same portable-shell trick
 * `shellRunner.test.ts` uses — no bash required) and read the environment back
 * out of its stdout. A mock of `runProcess` could not prove this: the whole
 * question is what execa does with the options, not what it is handed.
 */
function writeEnvPrinter(): { path: string; dir: string } {
  const dir = makeTempDir('processrunner-');
  const path = join(dir, 'printenv.js');
  // JSON of the child's own environment, so the test reads exactly what the
  // child sees rather than a shell's rendering of it.
  writeFileSync(path, 'process.stdout.write(JSON.stringify(process.env));');
  return { path, dir };
}

const PARENT_ONLY = 'GUARDIAN_PROCESSRUNNER_PARENT_SECRET';

async function childEnv(options: {
  env?: NodeJS.ProcessEnv;
  extendEnv?: boolean;
}): Promise<Record<string, string>> {
  const { path, dir } = writeEnvPrinter();
  const result = await runProcess({
    command: execPath,
    args: [path],
    cwd: dir,
    ...options,
  });
  expect(result.outcome).toBe('completed');
  return JSON.parse(result.stdout) as Record<string, string>;
}

/**
 * The exit-code contract every scanner wrapper — and every test that mocks
 * `runProcess` — has to match: ANY non-zero exit is `outcome: 'failed'`, with
 * the code alongside. A scanner that exits 1 for "findings" (actionlint,
 * hadolint, bandit) therefore reports `failed` + 1, never `completed` + 1. A
 * mock returning `completed` + 1 describes a runner that does not exist; it
 * hid scan_iac discarding every actionlint finding (Task 24 fix round 1, M7).
 */
describe('runProcess exit-code contract', () => {
  it.each([
    [0, 'completed'],
    [1, 'failed'],
    [2, 'failed'],
  ] as const)('exit %i is outcome %s, with the exit code reported', async (code, outcome) => {
    const dir = makeTempDir('processrunner-exit-');
    const result = await runProcess({ command: execPath, args: ['-e', `process.exit(${code})`], cwd: dir });
    expect(result.outcome).toBe(outcome);
    expect(result.exitCode).toBe(code);
  });
});

describe('runProcess environment handling', () => {
  beforeEach(() => {
    process.env[PARENT_ONLY] = 'inherited-value';
  });

  afterEach(() => {
    delete process.env[PARENT_ONLY];
  });

  it('inherits the parent environment by default', async () => {
    // The baseline the scrub has to overcome, and the behaviour every other
    // caller in this repo (semgrep, trivy, gitleaks, git) still relies on.
    const env = await childEnv({});
    expect(env[PARENT_ONLY]).toBe('inherited-value');
  });

  it('still inherits when env is passed WITHOUT extendEnv: false', async () => {
    // The trap, pinned: an allowlist alone scrubs nothing. If this ever starts
    // returning undefined, execa's default changed and `extendEnv: false` at
    // the call sites is no longer what is doing the work.
    const env = await childEnv({ env: { GUARDIAN_EXPLICIT: 'yes' } });
    expect(env['GUARDIAN_EXPLICIT']).toBe('yes');
    expect(env[PARENT_ONLY]).toBe('inherited-value');
  });

  it('replaces the environment when extendEnv is false', async () => {
    // THE assertion: the parent-only variable must be gone from the child.
    const env = await childEnv({ env: { GUARDIAN_EXPLICIT: 'yes' }, extendEnv: false });
    expect(env['GUARDIAN_EXPLICIT']).toBe('yes');
    expect(env[PARENT_ONLY]).toBeUndefined();
  });
});

/**
 * The process-TREE half of the runner's contract.
 *
 * execa's own `timeout` signals only the direct child. A scanner that forks
 * (bash → semgrep → semgrep-core) leaves a grandchild holding the stdout pipe,
 * and `await child` waits for that pipe to close — reproduced before the fix:
 * `timeoutMs: 2000` returned after 25 151 ms, the full lifetime of the
 * grandchild. So these assert two things: the call returns promptly, AND the
 * grandchild is actually gone afterwards (returning promptly alone could be
 * achieved by abandoning the pipe and orphaning the process).
 */
function findBash(): string | null {
  if (process.platform === 'win32') {
    const gitBash = 'C:\\Program Files\\Git\\bin\\bash.exe';
    return existsSync(gitBash) ? gitBash : null;
  }
  return existsSync('/bin/bash') ? '/bin/bash' : 'bash';
}

const BASH = findBash();

/**
 * A parent that spawns a grandchild sharing its stdout (so the grandchild
 * holds the runner's pipe open), records the grandchild's pid, then idles.
 * The grandchild exits on its own after 20 s, so a regression costs a slow
 * test rather than a process leaked for ever.
 */
function writeForkingParent(): { parent: string; pidFile: string; dir: string } {
  const dir = makeTempDir('processrunner-tree-');
  const parent = join(dir, 'parent.cjs');
  const pidFile = join(dir, 'grandchild.pid');
  writeFileSync(
    parent,
    [
      "const { spawn } = require('node:child_process');",
      "const { writeFileSync } = require('node:fs');",
      "const gc = spawn(process.execPath, ['-e', 'setTimeout(() => process.exit(0), 20000)'], { stdio: 'inherit' });",
      'writeFileSync(process.argv[2], String(gc.pid));',
      'setTimeout(() => process.exit(0), 20000);',
    ].join('\n'),
  );
  return { parent, pidFile, dir };
}

function isAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === 'EPERM';
  }
}

async function waitFor(predicate: () => boolean, ms: number): Promise<boolean> {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    if (predicate()) return true;
    await new Promise((r) => setTimeout(r, 50));
  }
  return predicate();
}

/**
 * Budget for a NATIVE tree kill. On Windows that is one `taskkill /T`, and
 * every Windows process enumeration (taskkill, tasklist, wmic alike) was
 * measured at ~2.5 s on a loaded machine and up to ~5 s with several suites
 * running at once. The grandchild lives 20 s, so anything well under that
 * still proves it was killed rather than waited for; the separate
 * `isAlive` check proves it is gone.
 */
const NATIVE_KILL_BUDGET_MS = 10_000;

function readPid(pidFile: string): number {
  const pid = Number(readFileSync(pidFile, 'utf8').trim());
  expect(Number.isInteger(pid) && pid > 0).toBe(true);
  return pid;
}

describe('runProcess kills the whole process tree', () => {
  it.skipIf(BASH === null)(
    "times out `bash -c 'sleep 25 & wait'` in under 5 s",
    async () => {
      const started = Date.now();
      const result = await runProcess({
        command: BASH ?? 'bash',
        args: ['-c', 'sleep 25 & wait'],
        cwd: MCP_ROOT,
        timeoutMs: 2_000,
      });
      const elapsed = Date.now() - started;
      expect(result.outcome).toBe('timed_out');
      expect(elapsed).toBeLessThan(5_000);
    },
    30_000,
  );

  it('on timeout, kills a grandchild that holds stdout and returns promptly', async () => {
    const { parent, pidFile, dir } = writeForkingParent();
    const started = Date.now();
    const result = await runProcess({
      command: execPath,
      args: [parent, pidFile],
      cwd: dir,
      timeoutMs: 1_500,
    });
    const elapsed = Date.now() - started;
    expect(result.outcome).toBe('timed_out');
    expect(elapsed).toBeLessThan(NATIVE_KILL_BUDGET_MS);
    const pid = readPid(pidFile);
    expect(await waitFor(() => !isAlive(pid), 3_000)).toBe(true);
  }, 30_000);

  it('on abort, kills the grandchild too', async () => {
    const { parent, pidFile, dir } = writeForkingParent();
    const controller = new AbortController();
    const running = runProcess({
      command: execPath,
      args: [parent, pidFile],
      cwd: dir,
      timeoutMs: 60_000,
      signal: controller.signal,
    });
    expect(await waitFor(() => existsSync(pidFile), 10_000)).toBe(true);
    const started = Date.now();
    controller.abort();
    const result = await running;
    expect(result.outcome).toBe('cancelled');
    expect(Date.now() - started).toBeLessThan(NATIVE_KILL_BUDGET_MS);
    const pid = readPid(pidFile);
    expect(await waitFor(() => !isAlive(pid), 3_000)).toBe(true);
  }, 30_000);

  /**
   * The one thing a group kill cannot reach: a grandchild in its OWN session
   * (`setsid`, here via `detached`) that still holds the runner's stdout. The
   * runner cannot kill it, but it must not wait on it for ever either: after
   * the SIGKILL grace it stops reading the pipes and returns. 1.5 s timeout +
   * 5 s grace + 1 s abandon ≈ 7.5 s, against the grandchild's 20 s life.
   */
  it('returns even when a grandchild outside the tree keeps the pipe open', async () => {
    const dir = makeTempDir('processrunner-setsid-');
    const parent = join(dir, 'parent.cjs');
    writeFileSync(
      parent,
      [
        "const { spawn } = require('node:child_process');",
        "spawn(process.execPath, ['-e', 'setTimeout(() => process.exit(0), 20000)'], { stdio: 'inherit', detached: true });",
        'setTimeout(() => process.exit(0), 20000);',
      ].join('\n'),
    );
    const started = Date.now();
    const result = await runProcess({ command: execPath, args: [parent], cwd: dir, timeoutMs: 1_500 });
    expect(result.outcome).toBe('timed_out');
    expect(Date.now() - started).toBeLessThan(12_000);
  }, 30_000);

  /**
   * POSIX puts the child in its own process group (`detached`) so a timeout
   * can signal the whole group. That opts it out of execa's own
   * kill-the-child-when-the-parent-exits cleanup, so the runner has to supply
   * it: when the MCP server or the CLI exits — `process.exit()` or an
   * unhandled SIGTERM — the scanner's whole group must go with it. Windows has
   * no process groups and keeps execa's cleanup unchanged (direct child only),
   * so this is POSIX-only by construction.
   */
  it.skipIf(process.platform === 'win32').each(['exit', 'SIGTERM'])(
    'kills the grandchild when the parent process ends via %s',
    async (mode) => {
      const { parent, pidFile } = writeForkingParent();
      const harness = join(MCP_ROOT, 'test', 'helpers', 'processRunnerExitHarness.ts');
      const r = await execa(execPath, ['--import', 'tsx', harness, parent, pidFile, mode], {
        cwd: MCP_ROOT,
        reject: false,
        timeout: 20_000,
      });
      expect(r.timedOut).toBe(false);
      const pid = readPid(pidFile);
      expect(await waitFor(() => !isAlive(pid), 3_000)).toBe(true);
    },
    30_000,
  );
});

/**
 * Git Bash's MSYS layer rewrites POSIX-looking arguments when an MSYS process
 * launches a native one: `-w /src` reaches docker as
 * `-w C:/Program Files/Git/src`. A Node parent does not do that itself
 * (measured: execa → native exe keeps `/src`), but a Docker invocation must
 * not depend on which parent happens to be in the chain, so every `docker`
 * command the runner launches carries the two variables that switch the
 * rewrite off, whatever the caller passed in `env`.
 */
describe('runProcess disables MSYS path conversion for docker', () => {
  function writeFakeDocker(): string {
    const dir = makeTempDir('processrunner-docker-');
    const printer = join(dir, 'printenv.cjs');
    writeFileSync(printer, 'process.stdout.write(JSON.stringify(process.env));');
    if (process.platform === 'win32') {
      const shim = join(dir, 'docker.cmd');
      writeFileSync(shim, `@"${execPath}" "${printer}" %*\r\n`);
      return shim;
    }
    const shim = join(dir, 'docker');
    writeFileSync(shim, `#!/bin/sh\nexec "${execPath}" "${printer}" "$@"\n`);
    chmodSync(shim, 0o755);
    return shim;
  }

  beforeEach(() => {
    delete process.env['MSYS_NO_PATHCONV'];
    delete process.env['MSYS2_ARG_CONV_EXCL'];
  });

  it('sets MSYS_NO_PATHCONV and MSYS2_ARG_CONV_EXCL for a docker command', async () => {
    const docker = writeFakeDocker();
    const result = await runProcess({
      command: docker,
      args: ['run', '-w', '/src'],
      cwd: dirname(docker),
      env: { GUARDIAN_EXPLICIT: 'yes' },
    });
    expect(result.outcome).toBe('completed');
    const env = JSON.parse(result.stdout) as Record<string, string>;
    expect(env['MSYS_NO_PATHCONV']).toBe('1');
    expect(env['MSYS2_ARG_CONV_EXCL']).toBe('*');
    expect(env['GUARDIAN_EXPLICIT']).toBe('yes');
  });

  it('leaves every other command alone', async () => {
    const env = await childEnv({});
    expect(env['MSYS_NO_PATHCONV']).toBeUndefined();
    expect(env['MSYS2_ARG_CONV_EXCL']).toBeUndefined();
  });
});
