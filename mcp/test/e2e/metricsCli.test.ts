/**
 * `cli/dev-guardian.mjs metrics` as a real subprocess: the METRIC lines of a
 * head output judged against a base's (`src/metrics/`, unit-tested in
 * test/unit/metrics/). Advisory: exit 0 whatever it finds; 2 only when the head
 * holds no METRIC line it could read (or cannot be read); `--strict` makes a
 * regressed or loosened metric, a missing one or a malformed head line exit 1;
 * 3 for a usage error, an unreadable `--base` included. No database is opened
 * and nothing is written.
 */

import { readdirSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';
import { spawnSyncCapped } from '../helpers/spawnCap.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

afterAll(cleanupTempDirs);

const REPO_ROOT = resolve(fileURLToPath(new URL('../../..', import.meta.url)));
const CLI = resolve(REPO_ROOT, 'cli', 'dev-guardian.mjs');

function run(args: string[], cwd?: string) {
  const r = spawnSyncCapped(process.execPath, [CLI, 'metrics', ...args], {
    encoding: 'utf8',
    cwd: cwd ?? makeTempDir('metrics-cwd-'),
    env: { ...process.env, NO_COLOR: '1' },
    timeout: 15_000,
  });
  return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

function files(head: string, base?: string): { dir: string; head: string; base: string } {
  const dir = makeTempDir('metrics-cli-');
  writeFileSync(join(dir, 'head.txt'), head);
  if (base !== undefined) writeFileSync(join(dir, 'base.txt'), base);
  return { dir, head: join(dir, 'head.txt'), base: join(dir, 'base.txt') };
}

const BASE = 'METRIC bundle-size=120 kB better=lower tolerance=2%\nMETRIC tests.count=812 better=higher tolerance=0\n';

function json(r: { stdout: string }): Record<string, unknown> {
  return JSON.parse(r.stdout) as Record<string, unknown>;
}

describe('metrics: the verdicts and the exit code', () => {
  it('C2: a regression is reported, exit 0 without --strict', () => {
    const f = files('METRIC bundle-size=125 kB better=lower tolerance=2%\nMETRIC tests.count=812 better=higher tolerance=0\n', BASE);
    const r = run(['--head', f.head, '--base', f.base, '--format', 'json']);
    expect(r.status, r.stderr).toBe(0);
    const j = json(r);
    expect(j).toMatchObject({ format: 'metric-lines/1', exit_code: 0, strict: false, regressed: ['bundle-size'], within: ['tests.count'] });
    expect(typeof j['tool_version']).toBe('string');
  });

  it('C3, C4, C5: --strict exits 1 for a regression, a loosened term or a missing metric', () => {
    const cases = [
      'METRIC bundle-size=125 kB better=lower tolerance=2%\nMETRIC tests.count=812 better=higher tolerance=0\n',
      'METRIC bundle-size=120 kB better=lower tolerance=9%\nMETRIC tests.count=812 better=higher tolerance=0\n',
      'METRIC bundle-size=120 kB better=lower tolerance=2%\n',
    ];
    for (const head of cases) {
      const f = files(head, BASE);
      const r = run(['--head', f.head, '--base', f.base, '--strict', '--format', 'json']);
      expect(r.status, head).toBe(1);
      expect(json(r)['exit_code']).toBe(1);
    }
    const clean = files('METRIC bundle-size=121 kB better=lower tolerance=2%\nMETRIC tests.count=813 better=higher tolerance=0\n', BASE);
    expect(run(['--head', clean.head, '--base', clean.base, '--strict']).status).toBe(0);
  });

  it('C1, C6: a malformed head line beside valid ones, and a metric the head lacks, are reported with exit 0', () => {
    const f = files('METRIC bundle-size=121 kB better=lower tolerance=2%\nMETRIC broken=1,5\n', BASE);
    const r = run(['--head', f.head, '--base', f.base, '--format', 'json']);
    expect(r.status).toBe(0);
    expect(json(r)).toMatchObject({ missing: ['tests.count'], head: { malformed: 1, malformed_lines: [{ text: 'METRIC broken=1,5', part: 'value' }] } });
  });

  it('C7: a base with no METRIC line is no reference — every head metric is new, exit 0', () => {
    const f = files(BASE, 'the build failed before printing anything\n');
    const r = run(['--head', f.head, '--base', f.base, '--format', 'json']);
    expect(r.status).toBe(0);
    expect(json(r)).toMatchObject({ new: ['bundle-size', 'tests.count'], missing: [] });
  });

  it('C8, C9: exit 2 when the head holds no METRIC line it could read, or cannot be read', () => {
    for (const head of ['', 'no metric here\n', 'METRIC x=oops\n']) {
      const f = files(head, BASE);
      const r = run(['--head', f.head, '--base', f.base]);
      expect(r.status, JSON.stringify(head)).toBe(2);
      expect(r.stdout).toMatch(/holds no METRIC line that could be read/);
    }
    const dir = makeTempDir('metrics-cli-');
    const missing = run(['--head', join(dir, 'missing.txt'), '--format', 'json']);
    expect(missing.status).toBe(2);
    expect(json(missing)).toMatchObject({ format: 'metric-lines/1', exit_code: 2 });
    expect(String(json(missing)['error'])).toMatch(/no such file/);
    const human = run(['--head', join(dir, 'missing.txt')]);
    expect(human.status).toBe(2);
    expect(human.stderr).toMatch(/--head .*missing\.txt: no such file — nothing was measured/);
  });

  it('C10, C11: usage errors are exit 3 — an unreadable --base, no --head, an unknown flag, a bad --format', () => {
    const f = files(BASE);
    expect(run(['--head', f.head, '--base', join(f.dir, 'nope.txt')]).status).toBe(3);
    expect(run(['--base', f.head]).status).toBe(3);
    expect(run(['--head', f.head, '--wat']).status).toBe(3);
    expect(run(['--head', f.head, '--format', 'sarif']).status).toBe(3);
    expect(run(['--head']).status).toBe(3);
    expect(run(['--head', '']).status).toBe(3);
  });

  it('markdown and human render the same comparison; --head=<file> works; nothing is written', () => {
    const f = files('METRIC bundle-size=125 kB better=lower tolerance=2%\nMETRIC tests.count=812 better=higher tolerance=0\n', BASE);
    const before = readdirSync(f.dir).sort();
    const md = run([`--head=${f.head}`, `--base=${f.base}`, '--format=markdown'], f.dir);
    expect(md.status).toBe(0);
    expect(md.stdout).toMatch(/^### dev-guardian metrics\n\n\| metric \| base \| head \| change \|/);
    expect(md.stdout).toMatch(/\| `bundle-size` \| 120 `kB` \| 125 `kB` \| \+5 \(\+4\.2%\) \| lower, 2% \| regressed \(tolerance 2\.4\) \|/);
    const human = run(['--head', f.head, '--base', f.base], f.dir);
    expect(human.stdout).toMatch(/bundle-size\s+120 kB\s+125 kB\s+\+5 \(\+4\.2%\)\s+lower, 2%\s+regressed/);
    expect(human.stdout).toMatch(/1 regressed, 1 within/);
    expect(readdirSync(f.dir).sort()).toEqual(before);
  });

  it('--help names the command', () => {
    const r = spawnSyncCapped(process.execPath, [CLI, '--help'], { encoding: 'utf8', timeout: 15_000 });
    expect(r.stdout).toMatch(/node cli\/dev-guardian\.mjs metrics --head <file> \[--base <file>\]/);
    expect(r.stdout).toMatch(/^metrics — /m);
  });
});
