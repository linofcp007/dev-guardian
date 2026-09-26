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

import { runProcess, type ProcessRunResult } from '../../../src/runners/processRunner.js';
import { scannerAvailable } from '../../../src/tools/scanHelpers.js';
import { buildToolRun, invokeSemgrep, judgeSurfaceReport } from '../../../src/surface/scanSemgrep.js';

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

describe('judgeSurfaceReport (Global Constraint 3)', () => {
  const report = (o: Record<string, unknown>): string => JSON.stringify({ results: [], errors: [], ...o });
  const SCANNED = { paths: { scanned: ['/p/app.ts'] } };

  it('ok: a clean exit that scanned files and reported no error', () => {
    expect(judgeSurfaceReport({ run: run('completed', 0), raw: report(SCANNED), via: null })).toEqual({
      verdict: 'ok',
      toolRun: { name: 'semgrep', status: 'ok' },
    });
    expect(judgeSurfaceReport({ run: run('failed', 1), raw: report(SCANNED), via: null }).verdict).toBe('ok');
  });

  it('scanned_nothing: exit 0, no error, paths.scanned empty or absent — skipped, never ok', () => {
    for (const raw of [report({ paths: { scanned: [] } }), JSON.stringify({ results: [] })]) {
      const j = judgeSurfaceReport({ run: run('completed', 0), raw, via: null });
      expect(j.verdict).toBe('scanned_nothing');
      expect(j.toolRun.status).toBe('skipped');
      expect(j.toolRun.reason).toMatch(/scanned 0 files/);
    }
  });

  it('failed: errors[] on a clean exit, naming the error', () => {
    const raw = report({ ...SCANNED, errors: [{ type: 'PartialParsing', message: 'Syntax error\nat line 3' }] });
    const j = judgeSurfaceReport({ run: run('completed', 0), raw, via: null });
    expect(j.verdict).toBe('failed');
    expect(j.toolRun.reason).toBe('1 Semgrep error(s): PartialParsing: Syntax error');
  });

  it('failed: an unclean exit, even with a report that scanned nothing (exit 7: a config that did not load)', () => {
    const j = judgeSurfaceReport({
      run: run('failed', 7, 'invalid config\n'),
      raw: report({ paths: { scanned: [] } }),
      via: 'docker (img)',
    });
    expect(j.verdict).toBe('failed');
    expect(j.toolRun.reason).toBe('docker (img): exit 7; scanned 0 of 1 target(s); invalid config');
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
