import { mkdtempSync, writeFileSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { execPath } from 'node:process';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { runShellScript } from '../../../src/runners/shellRunner.js';
import type { ShellChoice } from '../../../src/platform/shellProbe.js';

/**
 * These tests use Node itself (process.execPath) as the "shell". The
 * ShellRunner spawns `node script.js`, which gives us a portable way to
 * verify outcomes, stdout/stderr capture, timeouts, abort, and oversize
 * handling without relying on bash being installed.
 */
function fakeNodeShell(): ShellChoice {
  return {
    command: execPath,
    args_prefix: [],
    needs_wsl_path_translate: false,
    label: 'node-as-shell',
  };
}

function writeScript(body: string): { path: string; dir: string } {
  const dir = mkdtempSync(join(tmpdir(), 'shellrunner-'));
  const path = join(dir, 'script.js');
  writeFileSync(path, body);
  try {
    chmodSync(path, 0o755);
  } catch {
    // Windows ignores chmod; Node executes regardless.
  }
  return { path, dir };
}

describe('runShellScript', () => {
  it('captures stdout and reports outcome=completed for exit 0', async () => {
    const { path, dir } = writeScript(`process.stdout.write('hello'); process.exit(0);`);
    const result = await runShellScript({
      shell: fakeNodeShell(),
      scriptPath: path,
      cwd: dir,
    });
    expect(result.outcome).toBe('completed');
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toBe('hello');
    expect(result.truncated).toBe(false);
  });

  it('reports outcome=failed for non-zero exit and captures stderr', async () => {
    const { path, dir } = writeScript(
      `process.stderr.write('boom\\n'); process.exit(2);`,
    );
    const result = await runShellScript({
      shell: fakeNodeShell(),
      scriptPath: path,
      cwd: dir,
    });
    expect(result.outcome).toBe('failed');
    expect(result.exitCode).toBe(2);
    expect(result.stderr).toContain('boom');
  });

  it('truncates and reports outcome=output_too_large when stdout exceeds 5 MB', async () => {
    // 6 MB of stdout, written in one go.
    const { path, dir } = writeScript(
      `const chunk = 'a'.repeat(1024 * 1024);
       for (let i = 0; i < 6; i++) process.stdout.write(chunk);`,
    );
    const result = await runShellScript({
      shell: fakeNodeShell(),
      scriptPath: path,
      cwd: dir,
    });
    expect(result.outcome).toBe('output_too_large');
    expect(result.truncated).toBe(true);
  });

  it('honours an aborted signal by killing the child', async () => {
    const { path, dir } = writeScript(`setTimeout(() => process.exit(0), 30000);`);
    const controller = new AbortController();
    const promise = runShellScript({
      shell: fakeNodeShell(),
      scriptPath: path,
      cwd: dir,
      signal: controller.signal,
      timeoutMs: 60_000,
    });
    setTimeout(() => controller.abort(), 100);
    const result = await promise;
    expect(result.outcome).toBe('cancelled');
  });

  it('returns outcome=timed_out when the timeout fires', async () => {
    const { path, dir } = writeScript(`setTimeout(() => process.exit(0), 30000);`);
    const result = await runShellScript({
      shell: fakeNodeShell(),
      scriptPath: path,
      cwd: dir,
      timeoutMs: 250,
    });
    expect(result.outcome).toBe('timed_out');
  });

  it('forwards stderr lines through onLog', async () => {
    const { path, dir } = writeScript(
      `console.error('one'); console.error('two'); process.exit(0);`,
    );
    const lines: string[] = [];
    await runShellScript({
      shell: fakeNodeShell(),
      scriptPath: path,
      cwd: dir,
      onLog: (l) => lines.push(l),
    });
    expect(lines).toContain('one');
    expect(lines).toContain('two');
  });
});
