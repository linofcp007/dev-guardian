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
import { buildToolRun, invokeSemgrep } from '../../../src/surface/scanSemgrep.js';

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
