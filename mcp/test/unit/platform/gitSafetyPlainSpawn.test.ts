/**
 * The async git of the hook bundle stops git's whole tree too (3.4.0, after
 * review 10 finding 12 met the per-event hook parts).
 *
 * The engine runs async git on the shared tree kill (`runners/gitExec.ts`,
 * installed into `gitSafety.ts` by `useGitSpawner`). The hook bundle cannot
 * hold it — it brings `cross-spawn` and `signal-exit`, and a hook part may
 * hold no npm package — so SessionStart's `git status` and the configuration
 * probe ran on the plain spawner, which killed git alone and then waited for
 * the pipes: a helper git had started, holding them, held the answer — and
 * the SessionStart briefing — for as long as the helper lived. The plain
 * spawner now stops the tree with what Node and the OS have (a process group
 * on POSIX, `taskkill /T` on Windows), and answers at most a few seconds after
 * a stop whatever still holds the pipes.
 *
 * A Node script stands in for git (`spawnGitPlain` takes the command as given),
 * as in `test/unit/runners/gitExec.test.ts`.
 */

import { execFileSync, spawnSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { join } from 'node:path';
import { execPath } from 'node:process';
import { afterAll, describe, expect, it } from 'vitest';
import { execGitSync, spawnGitPlain } from '../../../src/platform/gitSafety.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';
import { hangBound } from '../../helpers/timing.js';

afterAll(cleanupTempDirs);

function alive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

async function until(check: () => boolean, ms: number): Promise<boolean> {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (check()) return true;
    await new Promise((r) => setTimeout(r, 100));
  }
  return check();
}

const HAS_GIT = spawnSync('git', ['--version'], { windowsHide: true }).status === 0;

/**
 * The pids of the processes whose command line holds `text` (not this one).
 * On Linux from `/proc` — a slim container has no `ps` (procps), and the
 * Docker run failed on `spawnSync ps ENOENT`; a zombie's command line is
 * empty there, so a stopped process that nobody reaped does not count.
 */
function processesNaming(text: string): number[] {
  const out =
    process.platform === 'win32'
      ? execFileSync(
          'powershell',
          [
            '-NoProfile',
            '-NonInteractive',
            '-Command',
            `Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like '*${text}*' -and $_.Name -notlike 'powershell*' } | ForEach-Object { $_.ProcessId }`,
          ],
          { windowsHide: true, encoding: 'utf8' },
        )
      : existsSync('/proc/self/cmdline')
        ? readdirSync('/proc')
            .filter((entry) => /^\d+$/.test(entry))
            .filter((pid) => {
              try {
                return readFileSync(`/proc/${pid}/cmdline`, 'utf8').split('\0').join(' ').includes(text);
              } catch {
                return false; // gone since the listing
              }
            })
            .join('\n')
        : execFileSync('ps', ['-eo', 'pid=,args='], { encoding: 'utf8' })
            .split('\n')
            .filter((line) => line.includes(text) && !line.includes('ps -eo'))
            .map((line) => line.trim().split(/\s+/)[0] ?? '')
            .join('\n');
  return out
    .split(/\r?\n/)
    .map((s) => Number(s.trim()))
    .filter((pid) => Number.isInteger(pid) && pid > 0 && pid !== process.pid);
}

/**
 * A "git" that starts a helper holding its stdout for 60 s, writes the helper's
 * pid, and hangs. On Windows the helper is started `detached`, out of the job
 * object Node puts its children in — which kills them with their parent, as
 * no real git's helper is: without it, killing the stand-in alone would
 * already stop the helper, and the test would prove nothing there.
 */
function stallingGit(dir: string): { script: string; pidFile: string } {
  const pidFile = join(dir, 'helper.pid');
  const script = join(dir, 'git.cjs');
  writeFileSync(
    script,
    [
      "const { spawn } = require('node:child_process');",
      "const { writeFileSync } = require('node:fs');",
      "const helper = spawn(process.execPath, ['-e', 'setTimeout(() => {}, 60000)'], { stdio: 'inherit', detached: process.platform === 'win32' });",
      `writeFileSync(${JSON.stringify(pidFile)}, String(helper.pid));`,
      'setTimeout(() => {}, 60000);',
    ].join('\n'),
  );
  return { script, pidFile };
}

describe("the hook bundle's async git (no npm package) stops git's tree", () => {
  it('at the timeout, git AND the helper it started are stopped, and the caller hears back', async () => {
    const dir = makeTempDir('git-plain-');
    const { script, pidFile } = stallingGit(dir);
    const started = Date.now();
    const r = await spawnGitPlain(execPath, [script], { env: process.env, timeoutMs: 2_000, maxBuffer: 1024 * 1024 });
    expect(r.error?.code).toBe('ETIMEDOUT');
    expect(r.status).toBeNull();
    // The helper lives 60 s: an answer well before that did not wait for it.
    expect(Date.now() - started).toBeLessThan(hangBound(10_000));
    expect(existsSync(pidFile)).toBe(true);
    const helper = Number(readFileSync(pidFile, 'utf8'));
    expect(await until(() => !alive(helper), hangBound(5_000)), `helper ${helper} still running`).toBe(true);
  }, 60_000);

  it('a normal run: status, stdout and stderr as git wrote them', async () => {
    const r = await spawnGitPlain(execPath, ['-e', "process.stdout.write('out'); process.stderr.write('err'); process.exit(3)"], {
      env: process.env,
      timeoutMs: 30_000,
      maxBuffer: 1024,
    });
    expect(r.error).toBeUndefined();
    expect(r.status).toBe(3);
    expect(r.stdout.toString()).toBe('out');
    expect(r.stderr.toString()).toBe('err');
  });

  // Review 11, finding 15d: Node refuses to start a `.cmd` without a shell
  // (EINVAL, thrown synchronously) — the promise rejected, against the
  // contract the hook's callers rely on.
  it.runIf(process.platform === 'win32')('a git that is a .cmd resolves to a failure, never a rejection', async () => {
    const dir = makeTempDir('git-plain-cmd-');
    const cmd = join(dir, 'git.cmd');
    writeFileSync(cmd, '@echo off\r\ngit %*\r\n');
    const r = await spawnGitPlain(cmd, ['status'], { env: process.env, timeoutMs: 10_000, maxBuffer: 1024 });
    expect(r.status).toBeNull();
    expect(r.error?.code).toBe('EINVAL');
  });

  it('more stdout than the cap stops it, as too large; a missing git is ENOENT', async () => {
    const big = await spawnGitPlain(execPath, ['-e', "process.stdout.write('x'.repeat(4096)); setTimeout(() => {}, 30000)"], {
      env: process.env,
      timeoutMs: 30_000,
      maxBuffer: 1024,
    });
    expect(big.error?.code).toBe('ENOBUFS');
    const missing = await spawnGitPlain(join(makeTempDir('git-plain-none-'), 'no-git-here.exe'), [], {
      env: process.env,
      timeoutMs: 10_000,
      maxBuffer: 1024,
    });
    expect(missing.error?.code).toBe('ENOENT');
  }, 60_000);
});

// Review 11, finding 15c: `spawnSync` killed git alone at its timeout, and an
// `ls-remote` or a clone over HTTPS left `git-remote-http` running.
describe.runIf(HAS_GIT)('the synchronous git stops what git started too', () => {
  it("at the timeout, git's remote helper is stopped with it (a server that never answers)", async () => {
    // The kernel completes the connection from the listen backlog while
    // `spawnSync` holds this thread: git sends its request and waits.
    const server = createServer(() => {});
    await new Promise<void>((done) => server.listen(0, '127.0.0.1', done));
    const address = server.address();
    const port = typeof address === 'object' && address !== null ? address.port : 0;
    try {
      const r = execGitSync(makeTempDir('git-sync-'), ['ls-remote', `http://127.0.0.1:${port}/x.git`], { timeoutMs: 3_000 });
      expect(r.failure?.code).toBe('timeout');
      expect(await until(() => processesNaming(`127.0.0.1:${port}`).length === 0, hangBound(5_000))).toBe(true);
    } finally {
      for (const pid of processesNaming(`127.0.0.1:${port}`)) {
        try {
          process.kill(pid, 'SIGKILL');
        } catch {
          /* gone */
        }
      }
      server.close();
    }
  }, 90_000);

  it.runIf(process.platform === 'win32')('a .cmd git is a failure, never a throw', () => {
    const dir = makeTempDir('git-sync-cmd-');
    const cmd = join(dir, 'git.cmd');
    writeFileSync(cmd, '@echo off\r\ngit %*\r\n');
    const r = execGitSync(dir, ['status'], { git: cmd, timeoutMs: 10_000 });
    expect(r.status).toBeNull();
    expect(r.failure).not.toBeNull();
  });
});
