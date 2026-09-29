/**
 * Every Semgrep spawn goes through `runners/semgrepRun.ts`, which runs it in
 * Python's UTF-8 mode (review M3): bug_hunt and scan_wordpress spawned
 * Semgrep without it, so with PYTHONUTF8 unset a file named `日本.py` made
 * Semgrep 1.176.1 exit 2 without a report on Windows (cp1252) — "report is
 * not valid JSON (exit 2)", and "Install semgrep". The last test fails when
 * any file in `src/` names Semgrep as a command outside the helper.
 */

import { readdirSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../src/runners/processRunner.js', () => ({ runProcess: vi.fn() }));

import { runProcess } from '../../../src/runners/processRunner.js';
import { buildSemgrepDockerArgs, DEFAULT_SEMGREP_IMAGE } from '../../../src/runners/dockerScanner.js';
import { TOOL_CATALOG } from '../../../src/runners/installCatalog.js';
import { runSemgrep, SEMGREP_COMMAND, SEMGREP_NO_VERSION_CHECK_ENV, semgrepSpawn } from '../../../src/runners/semgrepRun.js';
import { runVersionProbe } from '../../../src/runners/toolProbe.js';

beforeEach(() => {
  vi.mocked(runProcess).mockReset();
  vi.mocked(runProcess).mockResolvedValue({ outcome: 'completed', exitCode: 0, stdout: '', stderr: '', truncated: false });
});

describe('semgrepSpawn / runSemgrep', () => {
  it('sets PYTHONUTF8=1 and SEMGREP_ENABLE_VERSION_CHECK=0 over the caller’s environment, whatever it held', async () => {
    await runSemgrep({
      args: ['--version'],
      cwd: '/p',
      env: { PATH: '/bin', PYTHONUTF8: '0', SEMGREP_ENABLE_VERSION_CHECK: '1' },
    });
    const call = vi.mocked(runProcess).mock.calls[0]?.[0];
    expect(call?.command).toBe('semgrep');
    expect(call?.env).toEqual({ PATH: '/bin', PYTHONUTF8: '1', SEMGREP_ENABLE_VERSION_CHECK: '0' });
    expect(call?.args).toEqual(['--version']);
  });

  it('with no environment given, the server’s own plus PYTHONUTF8 and no version check', () => {
    vi.stubEnv('SEMGREP_ENABLE_VERSION_CHECK', '1');
    try {
      const spawn = semgrepSpawn(undefined);
      expect(spawn.command).toBe(SEMGREP_COMMAND);
      expect(spawn.env['PYTHONUTF8']).toBe('1');
      expect(spawn.env['SEMGREP_ENABLE_VERSION_CHECK']).toBe('0');
      expect(spawn.env['PATH'] ?? spawn.env['Path']).toBe(process.env['PATH'] ?? process.env['Path']);
    } finally {
      vi.unstubAllEnvs();
    }
  });

  it('an injected runner gets the same options (create_fix_pr’s worktree runner)', async () => {
    const run = vi.fn().mockResolvedValue({ outcome: 'completed', exitCode: 0, stdout: '', stderr: '', truncated: false });
    await runSemgrep({ args: ['--json'], cwd: '/w' }, run);
    expect(run.mock.calls[0]?.[0]).toMatchObject({
      command: 'semgrep',
      cwd: '/w',
      env: { PYTHONUTF8: '1', SEMGREP_ENABLE_VERSION_CHECK: '0' },
    });
    expect(runProcess).not.toHaveBeenCalled();
  });
});

/**
 * Review 3.0, wave 2 (d): Semgrep's own version check contacts Semgrep's
 * servers on every run, `--metrics=off` and `local_only` included. It is off
 * for every Semgrep dev-guardian starts: the helper's environment, the
 * Docker fallback's container (`-e`), and check_toolchain's
 * `semgrep --version` probe.
 */
describe('Semgrep never checks for a newer version', () => {
  it('the Docker fallback passes it into the container, before the image', () => {
    const args = buildSemgrepDockerArgs({ projectPath: '/p', outFileHost: '/p/out.json' });
    const e = args.indexOf('SEMGREP_ENABLE_VERSION_CHECK=0');
    expect(e).toBeGreaterThan(0);
    expect(args[e - 1]).toBe('-e');
    expect(e).toBeLessThan(args.indexOf(DEFAULT_SEMGREP_IMAGE));
  });

  it("check_toolchain's `semgrep --version` probe runs with it off", async () => {
    const probe = TOOL_CATALOG['semgrep']?.probe;
    expect(probe?.env).toEqual(SEMGREP_NO_VERSION_CHECK_ENV);
    await runVersionProbe({ command: 'semgrep', args: ['--version'], env: SEMGREP_NO_VERSION_CHECK_ENV }, '/p');
    const call = vi.mocked(runProcess).mock.calls[0]?.[0];
    expect(call?.env?.['SEMGREP_ENABLE_VERSION_CHECK']).toBe('0');
  });

  it('is the one value every place uses', () => {
    expect(SEMGREP_NO_VERSION_CHECK_ENV).toEqual({ SEMGREP_ENABLE_VERSION_CHECK: '0' });
  });
});

const SRC = fileURLToPath(new URL('../../../src/', import.meta.url));

function tsFiles(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const abs = join(dir, e.name);
    if (e.isDirectory()) return tsFiles(abs);
    return e.name.endsWith('.ts') ? [abs] : [];
  });
}

/** A spawn that names Semgrep: `command: 'semgrep'`, or `execa('semgrep'` / `spawn('semgrep'` and kin. */
const SEMGREP_SPAWN =
  /command:\s*['"`]semgrep['"`]|\b(?:execa|execaSync|spawn|spawnSync|execFile|execFileSync)\(\s*['"`]semgrep['"`]/;
/** The toolchain catalogue's `semgrep --version` probe: runs in the plugin's own directory, reads no project. */
const PROBE_LINE = /probe:\s*\{\s*command:\s*'semgrep',\s*args:\s*\['--version'\],\s*env:\s*SEMGREP_NO_VERSION_CHECK_ENV\s*\}/;

describe('every Semgrep spawn in src/ goes through runners/semgrepRun.ts', () => {
  it('no file but the helper names Semgrep as a command', () => {
    const offenders: string[] = [];
    for (const path of tsFiles(SRC)) {
      const rel = relative(SRC, path).split('\\').join('/');
      if (rel === 'runners/semgrepRun.ts') continue;
      readFileSync(path, 'utf8')
        .split(/\r?\n/)
        .forEach((line, i) => {
          if (SEMGREP_SPAWN.test(line) && !PROBE_LINE.test(line)) offenders.push(`${rel}:${i + 1}: ${line.trim()}`);
        });
    }
    expect(offenders).toEqual([]);
  });

  it('the pattern catches what it is for (positive control)', () => {
    expect(SEMGREP_SPAWN.test("      command: 'semgrep',")).toBe(true);
    expect(SEMGREP_SPAWN.test("execa('semgrep', ['--version'])")).toBe(true);
    expect(SEMGREP_SPAWN.test("tools_run.push({ name: 'semgrep', status: 'ok' })")).toBe(false);
  });
});
