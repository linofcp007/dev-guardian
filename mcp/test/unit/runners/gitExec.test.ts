/**
 * Review 10, finding 12: an async git stopped at its timeout took only git
 * with it — `git remote-https` survived, held the pipes, and `scan_skill` on a
 * URL that stalled answered after more than 330 s against its 120 s timeout.
 * Async git now runs on the shared tree kill (`runners/gitExec.ts`), installed
 * into `platform/gitSafety.ts` by `runners/git.ts`.
 *
 * A Node script stands in for git (`spawnGitTree` takes the command as given):
 * it starts a grandchild — the remote helper — that holds stdout, and never
 * finishes.
 */
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { execPath } from 'node:process';
import { afterAll, describe, expect, it } from 'vitest';
import { useGitSpawner } from '../../../src/platform/gitSafety.js';
import '../../../src/runners/git.js';
import { spawnGitTree } from '../../../src/runners/gitExec.js';
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

/** A "git" that starts a helper holding its stdout for 60 s, writes the helper's pid, and hangs. */
function stallingGit(dir: string): { script: string; pidFile: string } {
  const pidFile = join(dir, 'helper.pid');
  const script = join(dir, 'git.cjs');
  writeFileSync(
    script,
    [
      "const { spawn } = require('node:child_process');",
      "const { writeFileSync } = require('node:fs');",
      "const helper = spawn(process.execPath, ['-e', 'setTimeout(() => {}, 60000)'], { stdio: 'inherit' });",
      `writeFileSync(${JSON.stringify(pidFile)}, String(helper.pid));`,
      'setTimeout(() => {}, 60000);',
    ].join('\n'),
  );
  return { script, pidFile };
}

describe('async git runs on the shared tree kill (review 10, finding 12)', () => {
  it('runners/git.ts installs it into gitSafety', () => {
    const previous = useGitSpawner(spawnGitTree);
    expect(previous).toBe(spawnGitTree);
  });

  it('at the timeout, git AND the helper it started are stopped, and the caller hears back', async () => {
    const dir = makeTempDir('git-tree-');
    const { script, pidFile } = stallingGit(dir);
    const started = Date.now();
    const r = await spawnGitTree(execPath, [script], { env: process.env, timeoutMs: 2_000, maxBuffer: 1024 * 1024 });
    expect(r.error?.code).toBe('ETIMEDOUT');
    expect(r.status).toBeNull();
    // The helper lives 60 s: an answer well before that did not wait for it.
    expect(Date.now() - started).toBeLessThan(hangBound(10_000));
    expect(existsSync(pidFile)).toBe(true);
    const helper = Number(readFileSync(pidFile, 'utf8'));
    expect(await until(() => !alive(helper), hangBound(5_000)), `helper ${helper} still running`).toBe(true);
  }, 60_000);

  it('a normal run: status, stdout and stderr as git wrote them', async () => {
    const r = await spawnGitTree(execPath, ['-e', "process.stdout.write('out'); process.stderr.write('err'); process.exit(3)"], {
      env: process.env,
      timeoutMs: 30_000,
      maxBuffer: 1024,
    });
    expect(r.error).toBeUndefined();
    expect(r.status).toBe(3);
    expect(r.stdout.toString()).toBe('out');
    expect(r.stderr.toString()).toBe('err');
  });

  it('more stdout than the cap stops the tree, as too large; a missing git is ENOENT', async () => {
    const big = await spawnGitTree(execPath, ['-e', "process.stdout.write('x'.repeat(4096)); setTimeout(() => {}, 30000)"], {
      env: process.env,
      timeoutMs: 30_000,
      maxBuffer: 1024,
    });
    expect(big.error?.code).toBe('ENOBUFS');
    const missing = await spawnGitTree(join(makeTempDir('git-none-'), 'no-git-here.exe'), [], {
      env: process.env,
      timeoutMs: 10_000,
      maxBuffer: 1024,
    });
    expect(missing.error?.code).toBe('ENOENT');
  }, 60_000);
});
