/**
 * The shared spawn and tree kill (review 8, finding 4): `runners/spawn.ts`
 * (cross-spawn without a shell, `captureOutput`) and `runners/childProcess.ts`
 * (`startChild`, `stopTree`). `runProcess`, the DAST app runner and the MCP
 * audit transport were three copies of this; their own tests hold each
 * caller's contract (`processRunner.test.ts`, `ci/appRunner.test.ts`,
 * `integration/auditMcpTools*.test.ts`). Held here: what the primitives
 * promise every caller — real processes, no mocks.
 */
import { existsSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { execPath } from 'node:process';
import { afterAll, describe, expect, it } from 'vitest';
import { startChild, stopTree } from '../../../src/runners/childProcess.js';
import { runProcess } from '../../../src/runners/processRunner.js';
import { captureOutput, readText } from '../../../src/runners/spawn.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

/** A Node script that keeps a grandchild holding its stdout for 20 s, and exits itself after 20 s. */
function forkingParent(dir: string): string {
  const parent = join(dir, 'parent.cjs');
  writeFileSync(
    parent,
    [
      "const { spawn } = require('node:child_process');",
      "spawn(process.execPath, ['-e', 'setTimeout(() => {}, 20000)'], { stdio: 'inherit' });",
      "process.stdout.write('started\\n');",
      'setTimeout(() => process.exit(0), 20000);',
    ].join('\n'),
  );
  return parent;
}

describe('captureOutput — a one-process command, answered by its deadline', () => {
  it('collects stdout, stderr and the exit code', async () => {
    const r = await captureOutput(execPath, ['-e', "process.stdout.write('out'); process.stderr.write('err'); process.exit(3)"], {
      timeoutMs: 30_000,
    });
    expect(r).toMatchObject({ exitCode: 3, stdout: 'out', stderr: 'err', timedOut: false });
  });

  it('at the timeout, answers even while a grandchild still holds the pipes (execa waited for it)', async () => {
    const dir = makeTempDir('capture-tree-');
    const started = Date.now();
    const r = await captureOutput(execPath, [forkingParent(dir)], { timeoutMs: 1_500 });
    expect(r.timedOut).toBe(true);
    expect(r.exitCode).toBeNull();
    // The grandchild lives 20 s: an answer well before that was not a wait for it.
    expect(Date.now() - started).toBeLessThan(15_000);
  }, 30_000);

  it('a command on no PATH entry is an answer, not a throw — and never one found in the working directory', async () => {
    const dir = makeTempDir('capture-cwd-');
    const planted = process.platform === 'win32' ? 'zz-planted-tool.cmd' : 'zz-planted-tool';
    writeFileSync(join(dir, planted), process.platform === 'win32' ? '@echo planted\r\n' : '#!/bin/sh\necho planted\n', { mode: 0o755 });
    const r = await captureOutput('zz-planted-tool', [], { cwd: dir, env: { ...process.env, PATH: join(dir, 'nowhere') }, timeoutMs: 10_000 });
    expect(r.spawnError).toMatch(/not found on PATH/);
    expect(r.stdout).toBe('');
  });
});

describe('startChild / stopTree', () => {
  it('stopTree stops the tree and resolves; a second call is the same stop', async () => {
    const dir = makeTempDir('child-stop-');
    const child = startChild(execPath, [forkingParent(dir)], { cwd: dir, env: { ...process.env } });
    let out = '';
    readText(child.process.stdout, (t) => (out += t));
    while (!out.includes('started')) await new Promise((r) => setTimeout(r, 25));
    const first = stopTree(child, { graceMs: 2_000, abandonMs: 1_000 });
    const second = stopTree(child, { graceMs: 2_000, abandonMs: 1_000 });
    expect(second).toBe(first);
    await first;
    expect(child.settled()).toBe(true);
    const exit = await child.done;
    expect(exit.exitCode === 0).toBe(false);
  }, 30_000);

  it('a command that cannot start settles done with its spawn error, never a throw', async () => {
    const dir = makeTempDir('child-enoent-');
    const child = startChild(join(dir, 'no-such-program.exe'), [], { cwd: dir, env: { ...process.env } });
    const exit = await child.done;
    expect(exit.exitCode).toBeNull();
    expect(exit.spawnError?.code).toBe('ENOENT');
  });

  // cross-spawn runs a `.cmd` through cmd.exe with every argument escaped: a
  // metacharacter in an argument is data, never a second command.
  it.skipIf(process.platform !== 'win32')('a .cmd shim gets its arguments literally — & | ^ " are data', async () => {
    const dir = makeTempDir('child-cmd-');
    const shim = join(dir, 'echo-args.cmd');
    writeFileSync(shim, `@"${execPath}" -e "console.log(JSON.stringify(process.argv.slice(1)))" %*\r\n`);
    const marker = join(dir, 'injected.txt');
    const args = ['a & echo injected > "' + marker + '"', 'b | more', 'c ^ d', 'e "quoted"', '%PATH%'];
    const r = await runProcess({ command: shim, args, cwd: dir, gitHardening: false, timeoutMs: 30_000 });
    expect(r.outcome, r.stderr).toBe('completed');
    expect(JSON.parse(r.stdout.trim())).toEqual(args);
    expect(existsSync(marker)).toBe(false);
  });
});

describe('readText — UTF-8 across chunk boundaries', () => {
  it('a character split between two writes is read whole (runProcess decoded each chunk alone)', async () => {
    const dir = makeTempDir('child-utf8-');
    const script = join(dir, 'split.cjs');
    // '€' is E2 82 AC: one byte, a pause, the other two.
    writeFileSync(
      script,
      'process.stdout.write(Buffer.from([0xe2]), () => setTimeout(() => process.stdout.write(Buffer.from([0x82, 0xac, 0x0a])), 200));',
    );
    const r = await runProcess({ command: execPath, args: [script], cwd: dir, gitHardening: false, timeoutMs: 30_000 });
    expect(r.outcome).toBe('completed');
    expect(r.stdout).toBe('€\n');
  });
});
