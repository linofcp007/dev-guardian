/**
 * `runners/trivyRun.ts` — every Trivy spawn runs in a directory this scan
 * created, with `--config` pointing at an empty file, so the scanned
 * repository's own `trivy.yaml` is never read; its `.trivyignore` is passed
 * explicitly, and named. See the module comment for the reproduction.
 *
 * The last test holds the rule for the whole tree: a Trivy spawn anywhere in
 * `src/` outside the helper fails it.
 */

import { existsSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../src/runners/processRunner.js', () => ({ runProcess: vi.fn() }));
vi.mock('execa', () => ({ execa: vi.fn() }));

import { execa } from 'execa';
import { runProcess } from '../../../src/runners/processRunner.js';
import {
  honouredNote,
  NEUTRAL_TRIVY_CONFIG,
  resetTrivyVersionCache,
  runTrivy,
  trivyArgv,
  withHonoured,
} from '../../../src/runners/trivyRun.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

const mockedRun = vi.mocked(runProcess);

beforeEach(() => {
  mockedRun.mockReset();
  mockedRun.mockResolvedValue({ outcome: 'completed', exitCode: 0, stdout: '', stderr: '', truncated: false });
  // No version known unless a test says so: the flags are then withheld.
  vi.mocked(execa).mockReset();
  vi.mocked(execa).mockRejectedValue(new Error('no trivy here'));
  resetTrivyVersionCache();
});

describe('trivyArgv', () => {
  it('puts --config before the target, and the target last', () => {
    expect(trivyArgv({ args: ['fs', '--scanners', 'vuln', '--quiet'], target: '/p' }, '/r/cfg.yaml', null)).toEqual([
      'fs',
      '--scanners',
      'vuln',
      '--quiet',
      '--config',
      '/r/cfg.yaml',
      '/p',
    ]);
  });

  it('adds --ignorefile when the project has a .trivyignore', () => {
    expect(trivyArgv({ args: ['config'], target: '/p' }, '/r/cfg.yaml', '/p/.trivyignore')).toEqual([
      'config',
      '--config',
      '/r/cfg.yaml',
      '--ignorefile',
      '/p/.trivyignore',
      '/p',
    ]);
  });
});

describe('runTrivy', () => {
  it('runs in the work directory, never the project, with an empty config it wrote there', async () => {
    const project = makeTempDir('trivy-run-project-');
    const work = makeTempDir('trivy-run-work-');
    writeFileSync(join(project, 'trivy.yaml'), 'severity:\n  - UNKNOWN\n');
    const r = await runTrivy({ args: ['fs', '--format', 'json'], target: project, workDir: work, ignoreFrom: project });

    expect(mockedRun).toHaveBeenCalledTimes(1);
    const call = mockedRun.mock.calls[0]?.[0];
    expect(call?.command).toBe('trivy');
    expect(call?.cwd).toBe(work);
    const config = join(work, NEUTRAL_TRIVY_CONFIG);
    expect(call?.args).toEqual(['fs', '--format', 'json', '--config', config, project]);
    // Comments only: YAML with no key, which Trivy reads as no configuration.
    const text = readFileSync(config, 'utf8');
    expect(text.split('\n').every((l) => l === '' || l.startsWith('#'))).toBe(true);
    expect(r.honoured).toEqual([]);
  });

  it("passes the project's .trivyignore explicitly and names it", async () => {
    const project = makeTempDir('trivy-run-project-');
    const work = makeTempDir('trivy-run-work-');
    writeFileSync(join(project, '.trivyignore'), 'CVE-2020-8203\n');
    const r = await runTrivy({ args: ['fs'], target: project, workDir: work, ignoreFrom: project });
    expect(mockedRun.mock.calls[0]?.[0].args).toEqual(
      expect.arrayContaining(['--ignorefile', join(project, '.trivyignore')]),
    );
    expect(r.honoured).toEqual(['.trivyignore']);
    expect(honouredNote(r.honoured)).toMatch(/\.trivyignore/);
    const named = withHonoured({ name: 'trivy-image', status: 'ok', reason: 'image x' }, r.honoured);
    expect(named.reason).toMatch(/^image x; honoured the project's \.trivyignore/);
    expect(named.honoured_config).toEqual(['.trivyignore']);
    const plain = { name: 'trivy', status: 'ok' } as const;
    expect(withHonoured(plain, [])).toBe(plain);
  });

  it('a .trivyignore that is not a regular file is not passed', async () => {
    const project = makeTempDir('trivy-run-project-');
    const work = makeTempDir('trivy-run-work-');
    // A directory by that name.
    const { mkdirSync } = await import('node:fs');
    mkdirSync(join(project, '.trivyignore'));
    const r = await runTrivy({ args: ['fs'], target: project, workDir: work, ignoreFrom: project });
    expect(mockedRun.mock.calls[0]?.[0].args).not.toContain('--ignorefile');
    expect(r.honoured).toEqual([]);
  });

  it('without ignoreFrom (an image), no project file is read', async () => {
    const work = makeTempDir('trivy-run-work-');
    const r = await runTrivy({ args: ['image'], target: 'alpine:3.19', workDir: work });
    expect(mockedRun.mock.calls[0]?.[0].args).toEqual(['image', '--config', join(work, NEUTRAL_TRIVY_CONFIG), 'alpine:3.19']);
    expect(r.honoured).toEqual([]);
  });

  it('a config that cannot be written is a failed run, and Trivy is never started without it', async () => {
    const project = makeTempDir('trivy-run-project-');
    // A FILE where the work directory should be: mkdir fails.
    const blocker = join(project, 'not-a-dir');
    writeFileSync(blocker, 'x');
    const r = await runTrivy({ args: ['fs'], target: project, workDir: join(blocker, 'sub') });
    expect(r.outcome).toBe('failed');
    expect(r.stderr).toMatch(/neutral Trivy configuration/);
    expect(mockedRun).not.toHaveBeenCalled();
    expect(existsSync(join(blocker, 'sub'))).toBe(false);
  });
});

// ---------------------------------------------------------------- no phoning home

/**
 * Every Trivy run contacted check.trivy.dev — its version check, which also
 * carries anonymous usage data — `fs --scanners license` included (measured
 * by the plugin-surface review with a logging proxy). Only BOTH
 * TRIVY_SKIP_VERSION_CHECK=true and TRIVY_DISABLE_TELEMETRY=true stopped it.
 * The flags came with the check itself, in Trivy 0.63.0 (`pkg/flag/
 * scan_flags.go`: absent at v0.62.1, present at v0.63.0); an older Trivy
 * refuses an unknown flag, so they are passed only to a Trivy known to be
 * 0.63.0 or newer, and the environment variables always.
 */
describe('Trivy never phones home', () => {
  it('passes --skip-version-check --disable-telemetry to a Trivy 0.63.0 or newer, before --config', () => {
    expect(trivyArgv({ args: ['fs', '--quiet'], target: '/p' }, '/r/c.yaml', null, '0.69.3')).toEqual([
      'fs',
      '--quiet',
      '--skip-version-check',
      '--disable-telemetry',
      '--config',
      '/r/c.yaml',
      '/p',
    ]);
    expect(trivyArgv({ args: ['fs'], target: '/p' }, '/r/c.yaml', null, '0.63.0')).toContain('--disable-telemetry');
  });

  it.each([['0.62.1'], ['0.40.0'], [null]])('does not pass the flags to Trivy %s (an unknown flag is fatal there)', (version) => {
    const argv = trivyArgv({ args: ['fs'], target: '/p' }, '/r/c.yaml', null, version);
    expect(argv).not.toContain('--skip-version-check');
    expect(argv).not.toContain('--disable-telemetry');
  });

  it('always sets both environment variables, over whatever the caller passed', async () => {
    const work = makeTempDir('trivy-run-work-');
    await runTrivy({
      args: ['fs'],
      target: '/p',
      workDir: work,
      env: { PATH: '/bin', TRIVY_DISABLE_TELEMETRY: 'false' },
    });
    const env = mockedRun.mock.calls[0]?.[0].env ?? {};
    expect(env['TRIVY_SKIP_VERSION_CHECK']).toBe('true');
    expect(env['TRIVY_DISABLE_TELEMETRY']).toBe('true');
    expect(env['PATH']).toBe('/bin');
  });

  it('asks the installed Trivy its version once, and passes the flags when it is new enough', async () => {
    vi.mocked(execa).mockResolvedValue({ exitCode: 0, stdout: 'Version: 0.69.3\nVulnerability DB:\n' } as never);
    const work = makeTempDir('trivy-run-work-');
    await runTrivy({ args: ['fs'], target: '/p', workDir: work });
    await runTrivy({ args: ['config'], target: '/p', workDir: work });
    expect(vi.mocked(execa)).toHaveBeenCalledTimes(1);
    const probe = vi.mocked(execa).mock.calls[0];
    expect(probe?.[0]).toBe('trivy');
    expect(probe?.[1]).toEqual(['--version']);
    for (const c of mockedRun.mock.calls) expect(c[0].args).toEqual(expect.arrayContaining(['--skip-version-check', '--disable-telemetry']));
  });
});

// ---------------------------------------------------------------- the whole tree

const SRC = fileURLToPath(new URL('../../../src/', import.meta.url));

function tsFiles(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const abs = join(dir, e.name);
    if (e.isDirectory()) return tsFiles(abs);
    return e.name.endsWith('.ts') ? [abs] : [];
  });
}

/** A process spawn that names Trivy: `command: 'trivy'`, or `execa('trivy'` / `spawn('trivy'` and kin. */
const TRIVY_SPAWN = /command:\s*['"`]trivy['"`]|\b(?:execa|execaSync|spawn|spawnSync|execFile|execFileSync)\(\s*['"`]trivy['"`]/;

/**
 * The one exemption: the toolchain catalogue's `trivy --version` probe
 * (runners/installCatalog.ts), which reads no project — it runs in the
 * server's own directory, never a scanned one.
 */
const PROBE_LINE = /probe:\s*\{\s*command:\s*'trivy',\s*args:\s*\['--version'\][^}]*\}/;

describe('every Trivy spawn in src/ goes through runners/trivyRun.ts', () => {
  it('no file but the helper spawns Trivy', () => {
    const offenders: string[] = [];
    for (const path of tsFiles(SRC)) {
      const rel = relative(SRC, path).split('\\').join('/');
      if (rel === 'runners/trivyRun.ts') continue;
      readFileSync(path, 'utf8')
        .split(/\r?\n/)
        .forEach((line, i) => {
          if (TRIVY_SPAWN.test(line) && !PROBE_LINE.test(line)) offenders.push(`${rel}:${i + 1}: ${line.trim()}`);
        });
    }
    expect(offenders).toEqual([]);
  });

  it('the pattern catches what it is for (positive control)', () => {
    expect(TRIVY_SPAWN.test("        command: 'trivy',")).toBe(true);
    expect(TRIVY_SPAWN.test("await execa('trivy', ['fs'])")).toBe(true);
    expect(TRIVY_SPAWN.test("tools_run.push({ name: 'trivy', status: 'ok' })")).toBe(false);
  });
});
