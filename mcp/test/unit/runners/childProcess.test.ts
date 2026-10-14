/**
 * The shared spawn and tree kill (review 8, finding 4): `runners/spawn.ts`
 * (cross-spawn without a shell, `captureOutput`) and `runners/childProcess.ts`
 * (`startChild`, `stopTree`). `runProcess`, the DAST app runner and the MCP
 * audit transport were three copies of this; their own tests hold each
 * caller's contract (`processRunner.test.ts`, `ci/appRunner.test.ts`,
 * `integration/auditMcpTools*.test.ts`). Held here: what the primitives
 * promise every caller — real processes, no mocks.
 */
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { execPath } from 'node:process';
import crossSpawn from 'cross-spawn';
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
    readText(child.process?.stdout, (t) => (out += t));
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

});

/**
 * A `.cmd` / `.bat` runs through cmd.exe, which parses its line twice — the
 * second time when the batch file expands `%*` — and cross-spawn escapes for
 * the first parse only (review 10, finding 3, "BatBadBut"). The old test here
 * put every `"` AFTER the `&`, so the quotes it opened were still open; a `"`
 * BEFORE an `&` closes them, and the rest ran as a command. Such an argument
 * is now refused, nothing started (`runners/spawn.ts`).
 */
describe.runIf(process.platform === 'win32')('a batch file is handed only what cmd.exe cannot misread', () => {
  /** A batch file that records that it ran, then prints its arguments as Node received them. */
  function echoShim(dir: string, name: string): { shim: string; ran: string } {
    const shim = join(dir, name);
    const ran = join(dir, `${name}.ran`);
    writeFileSync(shim, `@echo ran>"${ran}"\r\n@"${execPath}" -e "console.log(JSON.stringify(process.argv.slice(1)))" %*\r\n`);
    return { shim, ran };
  }
  /** The payload: a `"` that closes the quotes, then a second command writing `pwned.txt` in the child's cwd. */
  const PAYLOAD = 'x"&echo PWNED>pwned.txt&"';

  it('the control: cross-spawn alone runs the payload as a second command', async () => {
    const dir = makeTempDir('child-bat-control-');
    const { shim } = echoShim(dir, 'tool.bat');
    const proc = crossSpawn(shim, [PAYLOAD], { cwd: dir, stdio: 'ignore', windowsHide: true });
    await new Promise((resolve) => proc.once('close', resolve));
    expect(existsSync(join(dir, 'pwned.txt')), 'the payload must be a real injection for the tests below to mean anything').toBe(true);
  });

  for (const name of ['tool.bat', 'tool.cmd', join('node_modules', '.bin', 'tool.cmd')]) {
    it(`${name}: a " before an & is refused — nothing runs, the refusal is the spawn failure`, async () => {
      const dir = makeTempDir('child-bat-');
      mkdirSync(join(dir, 'node_modules', '.bin'), { recursive: true });
      const { shim, ran } = echoShim(dir, name);
      const r = await runProcess({ command: shim, args: ['--path=ok', PAYLOAD], cwd: dir, gitHardening: false, timeoutMs: 30_000 });
      expect(r.outcome).toBe('failed');
      expect(r.notRun?.code).toBe('batch_argument_refused');
      expect(r.notRun?.message).toMatch(/cmd\.exe.*double quote/);
      expect(existsSync(join(dir, 'pwned.txt'))).toBe(false);
      expect(existsSync(ran), 'the batch file never started').toBe(false);
    });
  }

  it('a percent sign, a carriage return and a line feed are refused too: % expands before quoting is read, a line break ends the command', async () => {
    const dir = makeTempDir('child-bat-pct-');
    const { shim, ran } = echoShim(dir, 'tool.cmd');
    for (const [arg, what] of [
      ['%CMDCMDLINE:~-1%&echo PWNED>pwned.txt', /percent sign/],
      ['a%PATH%b', /percent sign/],
      ['a\r\necho PWNED>pwned.txt', /carriage return/],
      ['a\necho PWNED>pwned.txt', /line feed/],
    ] as const) {
      const r = await runProcess({ command: shim, args: [arg], cwd: dir, gitHardening: false, timeoutMs: 30_000 });
      expect(r.notRun?.code, JSON.stringify(arg)).toBe('batch_argument_refused');
      expect(r.notRun?.message).toMatch(what);
    }
    expect(existsSync(join(dir, 'pwned.txt'))).toBe(false);
    expect(existsSync(ran)).toBe(false);
  });

  it('every other metacharacter stays data: & | ^ < > ( ) ! , ; = and spaces arrive literally', async () => {
    const dir = makeTempDir('child-bat-meta-');
    const args = ['a & echo PWNED>pwned.txt', 'b | more', 'c ^ d', '<e>', '(f)', 'g!PATH!h', 'i,j;k=l', 'https://x.example/?a=1&b=2'];
    for (const name of ['tool.cmd', join('node_modules', '.bin', 'tool.cmd')]) {
      mkdirSync(join(dir, 'node_modules', '.bin'), { recursive: true });
      const { shim } = echoShim(dir, name);
      const r = await runProcess({ command: shim, args, cwd: dir, gitHardening: false, timeoutMs: 30_000 });
      expect(r.outcome, r.stderr).toBe('completed');
      expect(JSON.parse(r.stdout.trim())).toEqual(args);
    }
    expect(existsSync(join(dir, 'pwned.txt'))).toBe(false);
  });

  it('an .exe is never judged: " and % reach it through CreateProcess, literally', async () => {
    const dir = makeTempDir('child-exe-');
    const args = [PAYLOAD, '%PATH%', 'a"b'];
    const r = await runProcess({
      command: execPath,
      args: ['-e', 'console.log(JSON.stringify(process.argv.slice(1)))', ...args],
      cwd: dir,
      gitHardening: false,
      timeoutMs: 30_000,
    });
    expect(r.outcome, r.stderr).toBe('completed');
    expect(JSON.parse(r.stdout.trim())).toEqual(args);
  });

  it('startChild and captureOutput report the refusal as a spawn failure, never a throw', async () => {
    const dir = makeTempDir('child-bat-start-');
    const { shim, ran } = echoShim(dir, 'tool.bat');
    const child = startChild(shim, [PAYLOAD], { cwd: dir, env: { ...process.env } });
    expect(child.process).toBeNull();
    expect(child.settled()).toBe(true);
    const exit = await child.done;
    expect(exit.spawnError?.code).toBe('batch_argument_refused');
    await stopTree(child, { graceMs: 1_000, abandonMs: 1_000 });
    const captured = await captureOutput(shim, [PAYLOAD], { cwd: dir, timeoutMs: 10_000 });
    expect(captured.exitCode).toBeNull();
    expect(captured.spawnError).toMatch(/cmd\.exe/);
    expect(existsSync(ran)).toBe(false);
    expect(existsSync(join(dir, 'pwned.txt'))).toBe(false);
  });

  // Review 11, finding 15a: cross-spawn doubles only the LAST trailing
  // backslash, so `C:\site\\` left its closing quote escaped and swallowed the
  // next argument.
  it('an argument ending in two or more backslashes is refused (cross-spawn alone splits the next one into it)', async () => {
    const dir = makeTempDir('child-bat-bs-');
    const { shim } = echoShim(dir, 'tool.cmd');
    const args = ['C:\\site\\\\', 'p --injected=1'];
    const control = crossSpawn(shim, args, { cwd: dir, windowsHide: true });
    let out = '';
    control.stdout?.on('data', (c: Buffer) => (out += c.toString()));
    await new Promise((resolve) => control.once('close', resolve));
    expect(JSON.parse(out.trim()), 'the control must show the split for the refusal to mean anything').not.toEqual(args);

    const r = await runProcess({ command: shim, args, cwd: dir, gitHardening: false, timeoutMs: 30_000 });
    expect(r.notRun?.code).toBe('batch_argument_refused');
    expect(r.notRun?.message).toMatch(/two or more backslashes/);
    // One trailing backslash is doubled right, and passes.
    const one = await runProcess({ command: shim, args: ['C:\\site\\', 'next'], cwd: dir, gitHardening: false, timeoutMs: 30_000 });
    expect(one.outcome, one.stderr).toBe('completed');
    expect(JSON.parse(one.stdout.trim())).toEqual(['C:\\site\\', 'next']);
  });
});

/**
 * Review 11, finding 15b: the refusal above broke legitimate runs through an
 * npm cmd-shim — `perf_check` on any percent-escaped URL through
 * `lighthouse.cmd`. Such a shim only starts Node on one script, so it is run
 * as that (`runners/npmCmdShim.ts`): no cmd.exe, every argument literal.
 */
describe.runIf(process.platform === 'win32')('an npm cmd-shim runs as node <script>, never through cmd.exe', () => {
  const CURRENT = (script: string): string =>
    [
      '@ECHO off',
      'GOTO start',
      ':find_dp0',
      'SET dp0=%~dp0',
      'EXIT /b',
      ':start',
      'SETLOCAL',
      'CALL :find_dp0',
      '',
      'IF EXIST "%dp0%\\node.exe" (',
      '  SET "_prog=%dp0%\\node.exe"',
      ') ELSE (',
      '  SET "_prog=node"',
      '  SET PATHEXT=%PATHEXT:;.JS;=;%',
      ')',
      '',
      `endLocal & goto #_undefined_# 2>NUL || title %COMSPEC% & "%_prog%"  "%dp0%\\${script}" %*`,
      '',
    ].join('\r\n');
  const OLDER = (script: string): string =>
    [
      '@IF EXIST "%~dp0\\node.exe" (',
      `  "%~dp0\\node.exe"  "%~dp0\\${script}" %*`,
      ') ELSE (',
      '  @SETLOCAL',
      '  @SET PATHEXT=%PATHEXT:;.JS;=;%',
      `  node  "%~dp0\\${script}" %*`,
      ')',
      '',
    ].join('\r\n');
  const ARGS = ['https://site.example/?q=a%20b&r="x"', '%PATH%', 'x"&echo PWNED>pwned.txt&"', 'C:\\site\\\\', 'next'];

  for (const [name, template] of [
    ['the current template', CURRENT],
    ['the older template', OLDER],
  ] as const) {
    it(`${name}: a percent-escaped URL, a quote and trailing backslashes reach the script literally`, async () => {
      const dir = makeTempDir('child-shim-');
      mkdirSync(join(dir, 'node_modules', 'lh', 'cli'), { recursive: true });
      writeFileSync(join(dir, 'node_modules', 'lh', 'cli', 'index.js'), 'console.log(JSON.stringify(process.argv.slice(2)));\n');
      const shim = join(dir, 'lighthouse.cmd');
      writeFileSync(shim, template('node_modules\\lh\\cli\\index.js'));
      const r = await runProcess({ command: shim, args: ARGS, cwd: dir, gitHardening: false, timeoutMs: 30_000 });
      expect(r.outcome, r.notRun?.message ?? r.stderr).toBe('completed');
      expect(JSON.parse(r.stdout.trim())).toEqual(ARGS);
      expect(existsSync(join(dir, 'pwned.txt'))).toBe(false);
    });
  }

  it('a shim of something else, or one whose script is missing, is still a batch file — judged as one', async () => {
    const dir = makeTempDir('child-shim-other-');
    writeFileSync(join(dir, 'sh-tool.cmd'), CURRENT('bin\\tool.sh').replace(/node\.exe/g, 'sh.exe').replace('"_prog=node"', '"_prog=sh"'));
    writeFileSync(join(dir, 'gone.cmd'), CURRENT('node_modules\\gone\\index.js'));
    for (const name of ['sh-tool.cmd', 'gone.cmd']) {
      const r = await runProcess({ command: join(dir, name), args: ['a%20b'], cwd: dir, gitHardening: false, timeoutMs: 30_000 });
      expect(r.notRun?.code, name).toBe('batch_argument_refused');
    }
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
