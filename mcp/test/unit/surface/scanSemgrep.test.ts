import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../src/tools/scanHelpers.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/tools/scanHelpers.js')>();
  return { ...actual, scannerAvailable: vi.fn() };
});
vi.mock('../../../src/runners/processRunner.js', () => ({ runProcess: vi.fn() }));
// The docker-fallback branch stages the rule pack with a real `copyFileSync`
// before it ever calls (mocked) `runProcess`. OPTS below uses paths chosen
// only for assertions, not files that exist on disk, so the real copy would
// throw ENOENT and the docker branch would return early — never reaching
// `runProcess` — unless this is neutralised the same way the two deps above
// are.
vi.mock('node:fs', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs')>();
  return { ...actual, copyFileSync: vi.fn() };
});

import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { runProcess, type ProcessRunResult } from '../../../src/runners/processRunner.js';
import { scannerAvailable } from '../../../src/tools/scanHelpers.js';
import {
  buildToolRun,
  countRouteTargets,
  invokeSemgrep,
  judgeSurfaceReport,
} from '../../../src/surface/scanSemgrep.js';

function run(outcome: ProcessRunResult['outcome'], exitCode: number, stderr = ''): ProcessRunResult {
  return { outcome, exitCode, stdout: '', stderr, truncated: false };
}

const OPTS = {
  projectPath: '/p',
  rulesPath: '/rules/routes.yml',
  outFile: '/p/.guardian/out.json',
  reportDir: '/p/.guardian',
};

describe('buildToolRun', () => {
  it('treats exit 1 as success — semgrep exits 1 when it FINDS matches', () => {
    expect(buildToolRun(run('failed', 1))).toEqual({ name: 'semgrep', status: 'ok' });
  });

  it('treats a genuine failure as failed and carries the first stderr line', () => {
    const t = buildToolRun(run('failed', 2, '\nfatal: broken rule\nmore'));
    expect(t.status).toBe('failed');
    expect(t.reason).toBe('fatal: broken rule');
  });

  it('records the docker route in the reason when one was used', () => {
    expect(buildToolRun(run('completed', 0), 'docker (img)')).toEqual({
      name: 'semgrep',
      status: 'ok',
      reason: 'ran via docker (img)',
    });
  });
});

describe('judgeSurfaceReport (Global Constraint 3, and the I3 ruling)', () => {
  const report = (o: Record<string, unknown>): string => JSON.stringify({ results: [], errors: [], ...o });
  const SCANNED = { paths: { scanned: ['/p/app.ts', '/p/wp.php'] } };
  const judge = (r: ProcessRunResult, raw: string, via: string | null = null, targets = 2) =>
    judgeSurfaceReport({ run: r, raw, via, targets });

  it('ok: a clean exit that scanned files and reported no error', () => {
    expect(judge(run('completed', 0), report(SCANNED))).toEqual({
      verdict: 'ok',
      toolRun: { name: 'semgrep', status: 'ok' },
    });
    expect(judge(run('failed', 1), report(SCANNED)).verdict).toBe('ok');
  });

  it('scanned_nothing: route-language targets exist, exit 0, no error, nothing scanned — skipped, never ok', () => {
    for (const raw of [report({ paths: { scanned: [] } }), JSON.stringify({ results: [] })]) {
      const j = judge(run('completed', 0), raw);
      expect(j.verdict).toBe('scanned_nothing');
      expect(j.toolRun.status).toBe('skipped');
      expect(j.toolRun.reason).toMatch(/scanned 0 of 2 file/);
    }
  });

  it('partial: every error is a per-file problem (warn PartialParsing; a syntax error in one file) — ok, files named', () => {
    const raw = report({
      ...SCANNED,
      errors: [
        {
          level: 'warn',
          type: ['PartialParsing', [{ path: '/p/wp.php' }]],
          message: 'Syntax error at line /p/wp.php:20:\n `const NAMESPACE` was unexpected',
          path: '/p/wp.php',
        },
        { level: 'error', type: 'Syntax error', message: 'bad', spans: [{ file: '/p/app.ts' }] },
      ],
    });
    const j = judge(run('completed', 0), raw);
    expect(j.verdict).toBe('partial');
    expect(j.toolRun.status).toBe('ok');
    expect(j.toolRun.reason).toMatch(/^partial: 2 file\(s\) only partly parsed/);
    expect(j.partial).toEqual([
      { file: '/p/wp.php', type: 'PartialParsing', message: 'Syntax error at line /p/wp.php:20:' },
      { file: '/p/app.ts', type: 'Syntax error', message: 'bad' },
    ]);
  });

  it.each([
    ['an error tied to no target file', { level: 'warn', type: 'Timeout', message: 'rule timed out' }],
    ['a rule error', { level: 'error', type: 'Rule parse error', message: 'bad pattern', path: '/p/app.ts' }],
    ['an error naming the rule file', { level: 'warn', type: 'Syntax error', message: 'x', path: '/r/routes.yml' }],
  ])('failed: %s is fatal, even beside per-file ones', (_label, fatal) => {
    const raw = report({ ...SCANNED, errors: [{ level: 'warn', type: 'PartialParsing', message: 'x', path: '/p/wp.php' }, fatal] });
    expect(judge(run('completed', 0), raw).verdict).toBe('failed');
  });

  it('failed: per-file errors on a run that scanned nothing, or exited unclean', () => {
    const perFile = [{ level: 'warn', type: 'PartialParsing', message: 'x', path: '/p/wp.php' }];
    expect(judge(run('completed', 0), report({ paths: { scanned: [] }, errors: perFile })).verdict).toBe('failed');
    expect(judge(run('failed', 2), report({ ...SCANNED, errors: perFile })).verdict).toBe('failed');
  });

  it('failed: an unclean exit, even with a report that scanned nothing (exit 7: a config that did not load)', () => {
    const j = judge(run('failed', 7, 'invalid config\n'), report({ paths: { scanned: [] } }), 'docker (img)', 1);
    expect(j.verdict).toBe('failed');
    expect(j.toolRun.reason).toBe('docker (img): exit 7; scanned 0 of 1 target(s); invalid config');
  });
});

describe('countRouteTargets — the files Semgrep would scan, per its default ignore', () => {
  // Measured on Semgrep 1.176.1 with the routes pack over exactly this tree:
  // WITHOUT a .semgrepignore it scanned src/ok.go, testdata/t.go, lib/app.js,
  // spec/s.rb and __tests__/t.js — and none of test/, tests/, deep/test/,
  // deep/tests/, foo_test.go, build/, dist/, vendor/, lib/app.min.js.
  const TREE = [
    'main.tf', 'test/x_test.go', 'test/helper.go', 'tests/app.py', 'deep/test/y.go', 'deep/tests/z.go',
    'foo_test.go', 'src/ok.go', 'build/b.go', 'dist/d.go', 'vendor/v.go', 'lib/app.min.js', 'lib/app.js',
    'spec/s.rb', '__tests__/t.js', 'testdata/t.go',
  ];

  function tree(withIgnore: boolean): string {
    const root = mkdtempSync(join(tmpdir(), 'route-targets-'));
    for (const file of TREE) {
      mkdirSync(dirname(join(root, file)), { recursive: true });
      writeFileSync(join(root, file), 'x\n');
    }
    if (withIgnore) writeFileSync(join(root, '.semgrepignore'), '# own\n');
    return root;
  }

  it('with no .semgrepignore: exactly the five files Semgrep scanned', () => {
    const root = tree(false);
    try {
      expect(countRouteTargets(root)).toBe(5);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it('with a .semgrepignore of its own: test/, tests/ and *_test.go count again (the build-output walk excludes stay)', () => {
    const root = tree(true);
    try {
      // 15 route-language files, minus build/, dist/, vendor/ (always excluded from the walk).
      expect(countRouteTargets(root)).toBe(12);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});

describe('invokeSemgrep', () => {
  beforeEach(() => {
    vi.mocked(scannerAvailable).mockReset();
    vi.mocked(runProcess).mockReset();
  });

  it('runs semgrep natively when it is on PATH, passing the rules path', async () => {
    vi.mocked(scannerAvailable).mockResolvedValue('/bin/semgrep');
    vi.mocked(runProcess).mockResolvedValue(run('completed', 0));

    const result = await invokeSemgrep(OPTS);

    expect(result?.toolRun.status).toBe('ok');
    const args = vi.mocked(runProcess).mock.calls[0]?.[0].args ?? [];
    expect(args).toContain('--config');
    expect(args).toContain('/rules/routes.yml');
  });

  it('runs native semgrep in UTF-8 mode, like every other Semgrep call site', async () => {
    vi.mocked(scannerAvailable).mockResolvedValue('/bin/semgrep');
    vi.mocked(runProcess).mockResolvedValue(run('completed', 0));

    await invokeSemgrep(OPTS);

    expect(vi.mocked(runProcess).mock.calls[0]?.[0].env?.['PYTHONUTF8']).toBe('1');
  });

  it('returns the process and the Docker route with the verdict', async () => {
    vi.mocked(scannerAvailable).mockImplementation(async (n: string) => (n === 'docker' ? '/bin/docker' : null));
    const proc = run('completed', 0);
    vi.mocked(runProcess).mockResolvedValue(proc);

    const result = await invokeSemgrep(OPTS);

    expect(result?.run).toBe(proc);
    expect(result?.via).toMatch(/^docker \(/);
  });

  it('returns null when neither semgrep nor docker is available', async () => {
    vi.mocked(scannerAvailable).mockResolvedValue(null);
    expect(await invokeSemgrep(OPTS)).toBeNull();
    expect(vi.mocked(runProcess)).not.toHaveBeenCalled();
  });

  it('falls back to docker when semgrep is absent', async () => {
    vi.mocked(scannerAvailable).mockImplementation(async (n: string) =>
      n === 'docker' ? '/bin/docker' : null,
    );
    vi.mocked(runProcess).mockResolvedValue(run('completed', 0));

    const result = await invokeSemgrep(OPTS);

    expect(vi.mocked(runProcess).mock.calls[0]?.[0].command).toBe('docker');
    expect(result?.toolRun.reason).toMatch(/^ran via docker/);
  });
});
