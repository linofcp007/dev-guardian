/**
 * `create_github_issues` against a fake `gh` that behaves like the real one
 * where it matters:
 *
 *   - `gh issue list` without `--state all` returns OPEN issues only, so a
 *     finding whose issue was closed got filed again on every run;
 *   - `gh issue create --label x` fails outright when label `x` does not
 *     exist in the repository — the default labels (`dev-guardian`,
 *     `security`) exist in almost no repository, so the default call failed
 *     every plan;
 *   - and when every plan failed, the tool still answered `ok: true`.
 */

import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../src/tools/scanHelpers.js', async () => {
  const actual =
    await vi.importActual<typeof import('../../src/tools/scanHelpers.js')>(
      '../../src/tools/scanHelpers.js',
    );
  return { ...actual, scannerAvailable: vi.fn() };
});
vi.mock('../../src/runners/processRunner.js', () => ({ runProcess: vi.fn() }));

import { runProcess, type ProcessRunOptions, type ProcessRunResult } from '../../src/runners/processRunner.js';
import { scannerAvailable } from '../../src/tools/scanHelpers.js';
import { TOOLS } from '../../src/tools/index.js';
import { okResult } from '../helpers/toolResult.js';
import { cleanupTempDirs } from '../helpers/tempDir.js';
import { freshPlugin, projectDir, seedScan } from '../helpers/historySeed.js';

afterAll(cleanupTempDirs);

beforeAll(async () => {
  await import('../../src/tools/createGithubIssues.js');
});

function tool() {
  const t = TOOLS.find((x) => x.name === 'create_github_issues');
  if (!t) throw new Error('create_github_issues not registered');
  return t;
}

interface FakeRepo {
  issues: Array<{ number: number; title: string; state: 'OPEN' | 'CLOSED' }>;
  labels: string[];
  /** Labels `gh label create` refuses (permissions, say). */
  uncreatable?: string[];
  /** When true, `gh issue create` always fails. */
  createFails?: boolean;
  calls: string[][];
}

function ok(stdout: string): ProcessRunResult {
  return { outcome: 'completed', exitCode: 0, stdout, stderr: '', truncated: false };
}
function fail(stderr: string): ProcessRunResult {
  return { outcome: 'failed', exitCode: 1, stdout: '', stderr, truncated: false };
}

function fakeGh(repo: FakeRepo): void {
  vi.mocked(scannerAvailable).mockResolvedValue('gh');
  vi.mocked(runProcess).mockImplementation(async (opts: ProcessRunOptions) => {
    const args = opts.args ?? [];
    repo.calls.push(args);
    const [noun, verb] = args;
    if (noun === 'issue' && verb === 'list') {
      const stateIdx = args.indexOf('--state');
      const state = stateIdx >= 0 ? args[stateIdx + 1] : 'open';
      const visible = repo.issues.filter((i) => state === 'all' || i.state === 'OPEN');
      return ok(JSON.stringify(visible));
    }
    if (noun === 'label' && verb === 'list') {
      return ok(JSON.stringify(repo.labels.map((name) => ({ name }))));
    }
    if (noun === 'label' && verb === 'create') {
      const name = args[2] ?? '';
      if (repo.uncreatable?.includes(name)) return fail(`HTTP 403: cannot create label ${name}`);
      repo.labels.push(name);
      return ok('');
    }
    if (noun === 'issue' && verb === 'create') {
      if (repo.createFails === true) return fail('HTTP 401: Bad credentials');
      for (let i = 0; i < args.length; i++) {
        if (args[i] === '--label' && !repo.labels.includes(args[i + 1] ?? '')) {
          return fail(`could not add label: '${args[i + 1] ?? ''}' not found`);
        }
      }
      const titleIdx = args.indexOf('--title');
      const number = repo.issues.length + 1;
      repo.issues.push({ number, title: args[titleIdx + 1] ?? '', state: 'OPEN' });
      return ok(`https://github.com/o/r/issues/${number}\n`);
    }
    return fail(`unexpected gh ${args.join(' ')}`);
  });
}

beforeEach(() => {
  vi.mocked(runProcess).mockReset();
  vi.mocked(scannerAvailable).mockReset();
});

function seedOne(fp: string) {
  const s = freshPlugin();
  const p = projectDir('gh-');
  seedScan(s, { id: 's1', type: 'sast', project: p, findings: [{ fp, severity: 'high' }] });
  return { s, p };
}

describe('create_github_issues', () => {
  it('does not refile a finding whose issue was closed', async () => {
    const fp = 'd'.repeat(64);
    const { s, p } = seedOne(fp);
    const repo: FakeRepo = {
      issues: [{ number: 7, title: `[HIGH] old [guardian:${fp.slice(0, 12)}]`, state: 'CLOSED' }],
      labels: ['dev-guardian', 'security'],
      calls: [],
    };
    fakeGh(repo);

    const r = okResult<{ plans: Array<{ status: string }> }>(await tool().handler({ project_path: p }, s.plugin));
    expect(r.plans.map((x) => x.status)).toEqual(['skipped_existing']);
    expect(repo.calls.some((c) => c[0] === 'issue' && c[1] === 'create')).toBe(false);
  });

  it('creates a missing label, and omits one it cannot create instead of failing the issue', async () => {
    const fp = 'e'.repeat(64);
    const { s, p } = seedOne(fp);
    const repo: FakeRepo = { issues: [], labels: [], uncreatable: ['security'], calls: [] };
    fakeGh(repo);

    const r = okResult<{ plans: Array<{ status: string }>; labels_applied: string[]; labels_omitted: string[] }>(
      await tool().handler({ project_path: p }, s.plugin),
    );
    expect(r.plans.map((x) => x.status)).toEqual(['created']);
    expect(r.labels_applied).toEqual(['dev-guardian']);
    expect(r.labels_omitted).toEqual(['security']);
    const create = repo.calls.find((c) => c[0] === 'issue' && c[1] === 'create') ?? [];
    expect(create).toContain('dev-guardian');
    expect(create).not.toContain('security');
  });

  it("narrows the dedupe listing to dev-guardian's own issues, by title", async () => {
    const fp = '9'.repeat(64);
    const { s, p } = seedOne(fp);
    const repo: FakeRepo = { issues: [], labels: ['dev-guardian', 'security'], calls: [] };
    fakeGh(repo);

    await tool().handler({ project_path: p }, s.plugin);
    const list = repo.calls.find((c) => c[0] === 'issue' && c[1] === 'list') ?? [];
    expect(list).toContain('--state');
    expect(list[list.indexOf('--state') + 1]).toBe('all');
    expect(list).toContain('--search');
    expect(list[list.indexOf('--search') + 1]).toBe('"[guardian:" in:title');
  });

  it('files nothing when the listing may have been cut at its limit — it could hide an existing issue', async () => {
    // 1000 dev-guardian issues already exist; the one for this finding may
    // be the 1001st. Filing anyway is a duplicate public issue.
    const fp = '8'.repeat(64);
    const { s, p } = seedOne(fp);
    const issues = Array.from({ length: 1000 }, (_, i) => ({
      number: i + 1,
      title: `[HIGH] old ${i} [guardian:${i.toString(16).padStart(12, '0')}]`,
      state: 'CLOSED' as const,
    }));
    const repo: FakeRepo = { issues, labels: ['dev-guardian', 'security'], calls: [] };
    fakeGh(repo);

    const r = await tool().handler({ project_path: p }, s.plugin);
    expect(r.ok).toBe(false);
    if (r.ok) throw new Error('expected failure');
    expect(r.error.message).toMatch(/1000/);
    expect(repo.calls.some((c) => c[0] === 'issue' && c[1] === 'create')).toBe(false);
  });

  it('answers ok:false when every plan failed', async () => {
    const fp = 'f'.repeat(64);
    const { s, p } = seedOne(fp);
    fakeGh({ issues: [], labels: ['dev-guardian', 'security'], createFails: true, calls: [] });

    const r = await tool().handler({ project_path: p }, s.plugin);
    expect(r.ok).toBe(false);
    if (r.ok) throw new Error('expected failure');
    expect(r.error.message).toContain('Bad credentials');
  });
});
