/**
 * `security_scan_full` as an orchestration of the TypeScript scan tools.
 *
 * It used to run `scripts/scan/full-security-scan.sh` and call a scanner `ok`
 * whenever its report file existed. Reproduced against that script:
 *
 *   - Semgrep exit 7 (registry offline) → "Semgrep returned findings", `ok`;
 *   - `find … | head -1` under `pipefail` → SIGPIPE on a large tree, Bandit
 *     silently skipped (3 000 `.py` files);
 *   - `auto_fix` accepted and ignored; only `--config=auto`, never the
 *     project's `.semgrep.yml`, registered rules or `local_only`.
 *
 * Scanners are mocked at `runProcess`; everything above them is real. The
 * `runShellScript` mock replays what the script wrote, so the same tests read
 * the old behaviour honestly.
 */

import { execa } from 'execa';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

/**
 * Real git and real files, several thousand of them in two tests: under a
 * loaded full-suite run the 10 s default was measured too short. A file-level
 * ceiling, not a global one — see vitest.config.ts.
 */
vi.setConfig({ testTimeout: 180_000 });

const { treeHashCalls } = vi.hoisted(() => ({ treeHashCalls: { n: 0 } }));
vi.mock('../../src/treeHash/computeTreeHash.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/treeHash/computeTreeHash.js')>();
  return {
    ...actual,
    computeTreeHash: vi.fn(async (...args: Parameters<typeof actual.computeTreeHash>) => {
      treeHashCalls.n += 1;
      return actual.computeTreeHash(...args);
    }),
  };
});
vi.mock('../../src/runners/processRunner.js', () => ({ runProcess: vi.fn() }));
vi.mock('../../src/runners/shellRunner.js', () => ({ runShellScript: vi.fn() }));
vi.mock('../../src/tools/scanHelpers.js', async () => {
  const actual = await vi.importActual<typeof import('../../src/tools/scanHelpers.js')>(
    '../../src/tools/scanHelpers.js',
  );
  return { ...actual, scannerAvailable: vi.fn() };
});

import { runProcess, type ProcessRunOptions, type ProcessRunResult } from '../../src/runners/processRunner.js';
import { runShellScript } from '../../src/runners/shellRunner.js';
import { scannerAvailable } from '../../src/tools/scanHelpers.js';
import type { PluginContext } from '../../src/context.js';
import { resetLimiter } from '../../src/runners/concurrencyLimiter.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';
import type { ToolRun } from '../../src/types.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

afterAll(cleanupTempDirs);
beforeAll(async () => {
  await import('../../src/tools/securityScanFull.js');
});

const here = dirname(fileURLToPath(import.meta.url));
const FIX = resolve(here, '..', 'fixtures', 'scanners');
const fixture = (name: string): string => readFileSync(join(FIX, name), 'utf8');

/** The Semgrep fixture, with the `paths.scanned` a real run carries. */
const semgrepReport = (): string =>
  JSON.stringify({ ...JSON.parse(fixture('semgrep.json')), paths: { scanned: ['src/app.js'] } });
const SEMGREP_EXIT_7 = JSON.stringify({
  results: [],
  errors: [{ type: 'SemgrepError', level: 'error', message: 'Failed to download configuration from https://semgrep.dev/c/auto' }],
  paths: { scanned: [] },
});

type Call = ProcessRunOptions & { args: string[] };
let calls: Call[] = [];
let semgrep: { report: string; exitCode: number } = { report: '', exitCode: 1 };

function result(exitCode: number, stderr = ''): ProcessRunResult {
  return { outcome: exitCode === 0 ? 'completed' : 'failed', exitCode, stdout: '', stderr, truncated: false };
}

function after(args: readonly string[], flag: string): string {
  return args[args.indexOf(flag) + 1] ?? '';
}

/** Each scanner writes its fixture where the tool asked it to. */
async function fakeScanner(opts: ProcessRunOptions): Promise<ProcessRunResult> {
  const call: Call = { ...opts, args: opts.args ?? [] };
  calls.push(call);
  const a = call.args;
  switch (opts.command) {
    case 'semgrep':
      writeFileSync(after(a, '--output'), semgrep.report);
      return result(semgrep.exitCode);
    case 'gitleaks': {
      const report = a.find((x) => x.startsWith('--report-path='))?.slice('--report-path='.length) ?? '';
      writeFileSync(report, fixture('gitleaks.json'));
      return result(1, 'INF 1 commits scanned.');
    }
    case 'trivy':
      writeFileSync(after(a, '--output'), a[0] === 'fs' ? fixture('trivy-fs.json') : fixture('trivy-dockerfile.json'));
      return result(0);
    case 'bandit':
      writeFileSync(after(a, '-o'), fixture('bandit.json'));
      return result(1);
    default:
      return result(0);
  }
}

beforeEach(() => {
  calls = [];
  semgrep = { report: semgrepReport(), exitCode: 1 };
  vi.mocked(scannerAvailable).mockReset();
  vi.mocked(scannerAvailable).mockImplementation(async (name: string) =>
    name === 'docker' || name === 'dotnet' ? null : `/fake/bin/${name}`,
  );
  vi.mocked(runProcess).mockReset();
  vi.mocked(runProcess).mockImplementation(fakeScanner);
  // What full-security-scan.sh left behind: a report per scanner that ran.
  vi.mocked(runShellScript).mockReset();
  vi.mocked(runShellScript).mockImplementation(async (opts) => {
    const dir = join(opts.cwd, '.guardian', 'reports', `security-${Date.now()}`);
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'sast.json'), semgrep.report);
    writeFileSync(join(dir, 'secrets.json'), fixture('gitleaks.json'));
    writeFileSync(join(dir, 'deps.json'), fixture('trivy-fs.json'));
    return { outcome: 'completed', exitCode: 0, stdout: '', stderr: '', truncated: false };
  });
});

function plugin(project: string): PluginContext {
  const db = new Database(':memory:');
  runMigrations(db);
  return {
    storage: new Storage(db),
    shell: { command: 'bash', args_prefix: [], needs_wsl_path_translate: false, label: 'fake' },
    scriptsDir: project,
    progressNotifier: { send: () => {} },
  };
}

interface FullResult {
  ok: true;
  scan_id: string;
  coverage: string;
  tools_run: ToolRun[];
  missing_tools: string[];
  findings_count_by_severity: Record<string, number>;
  child_scans?: Array<{ tool: string; scan_id: string | null }>;
}

async function full(project: string, input: Record<string, unknown> = {}, p = plugin(project)) {
  const tool = TOOLS.find((t) => t.name === 'security_scan_full');
  if (!tool) throw new Error('security_scan_full not registered');
  const r = await tool.handler({ project_path: project, force: true, ...input }, p);
  return { r, p };
}

function project(): string {
  const dir = makeTempDir('sec-full-');
  writeFileSync(join(dir, 'app.js'), 'res.send(req.query.q);\n');
  return dir;
}

const total = (counts: Record<string, number>): number => Object.values(counts).reduce((a, b) => a + b, 0);

describe('security_scan_full orchestrates the scan tools', () => {
  it('runs scan_sast, scan_secrets, scan_deps and scan_iac as child scans that point at the parent', async () => {
    const dir = project();
    const { r, p } = await full(dir);
    expect(r.ok).toBe(true);
    const res = r as unknown as FullResult;

    const children = p.storage.scans
      .listHistory(50)
      .filter((s) => s.meta?.['parent_scan_id'] === res.scan_id);
    expect(children.map((s) => s.scan_type).sort()).toEqual(['deps', 'iac', 'sast', 'secrets']);
    expect(children.every((s) => s.status === 'completed')).toBe(true);

    // The parent row keeps the merged findings: 3 semgrep + 2 gitleaks + 3 trivy fs + 1 trivy config.
    expect(total(res.findings_count_by_severity)).toBe(9);
    expect(p.storage.findings.listByScan(res.scan_id)).toHaveLength(9);
    // And the CVEs, so a reader of the latest security_full scan still finds them.
    expect(p.storage.cves.listActive(res.scan_id)).toHaveLength(2);
    expect(res.child_scans?.map((c) => c.tool).sort()).toEqual(['scan_deps', 'scan_iac', 'scan_sast', 'scan_secrets']);
    expect(res.coverage).toBe('full');
  });

  it('hashes the tree once for the whole run, not once per child', async () => {
    const dir = project();
    treeHashCalls.n = 0;
    await full(dir);
    expect(treeHashCalls.n).toBe(1);
  });

  it('reports Semgrep exit 7 as a failed scanner, never as findings, and coverage is not full', async () => {
    semgrep = { report: SEMGREP_EXIT_7, exitCode: 7 };
    const { r } = await full(project());
    const res = r as unknown as FullResult;
    const run = res.tools_run.find((t) => t.name === 'semgrep');
    expect(run?.status).toBe('failed');
    expect(res.coverage).not.toBe('full');
  });

  it('runs Bandit on a project with 3 000 .py files and no Python manifest', async () => {
    const dir = project();
    for (let i = 0; i < 3000; i++) writeFileSync(join(dir, `m${i}.py`), 'x = 1\n');
    const { r } = await full(dir);
    const res = r as unknown as FullResult;
    expect(calls.some((c) => c.command === 'bandit')).toBe(true);
    expect(res.tools_run.find((t) => t.name === 'bandit')?.status).toBe('ok');
  });

  it("loads the project's own .semgrep.yml, and local_only drops the registry and turns metrics off", async () => {
    const dir = project();
    writeFileSync(
      join(dir, '.semgrep.yml'),
      'rules:\n  - id: r\n    languages: [javascript]\n    severity: ERROR\n    message: m\n    pattern: eval(...)\n',
    );
    await full(dir);
    const first = calls.find((c) => c.command === 'semgrep')?.args ?? [];
    expect(first).toContain('--config=auto');
    expect(first.some((a) => a.startsWith('--config=') && a.endsWith('.semgrep.yml'))).toBe(true);

    calls = [];
    await full(dir, { local_only: true });
    const local = calls.find((c) => c.command === 'semgrep')?.args ?? [];
    expect(local).not.toContain('--config=auto');
    expect(local).toContain('--metrics=off');
    expect(local.some((a) => a.endsWith('.semgrep.yml'))).toBe(true);
  });

  it('passes auto_fix to Semgrep once the working tree is known clean, and refuses a dirty one', async () => {
    const dir = project();
    await execa('git', ['init', '-q'], { cwd: dir });
    writeFileSync(join(dir, '.gitignore'), '.guardian/\n');
    await execa('git', ['add', '-A'], { cwd: dir });
    await execa(
      'git',
      ['-c', 'user.email=t@example.com', '-c', 'user.name=t', '-c', 'commit.gpgsign=false', 'commit', '-q', '-m', 'x'],
      { cwd: dir },
    );
    const { r } = await full(dir, { auto_fix: true });
    expect(r.ok).toBe(true);
    expect(calls.find((c) => c.command === 'semgrep')?.args).toContain('--autofix');

    writeFileSync(join(dir, 'app.js'), 'changed\n');
    calls = [];
    const dirty = await full(dir, { auto_fix: true });
    expect(dirty.r.ok).toBe(false);
    if (!dirty.r.ok) expect(dirty.r.error.code).toBe('working_tree_dirty');
    expect(calls).toHaveLength(0);
  });

  it('a child that cannot run leaves coverage partial, named, never full', async () => {
    vi.mocked(scannerAvailable).mockImplementation(async (name: string) =>
      name === 'trivy' || name === 'docker' || name === 'dotnet' ? null : `/fake/bin/${name}`,
    );
    const { r } = await full(project());
    const res = r as unknown as FullResult;
    expect(res.missing_tools).toContain('trivy');
    expect(res.coverage).toBe('partial');
  });

  it('cancelling the call stops the children and records the parent as cancelled', async () => {
    const controller = new AbortController();
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      if (opts.command === 'semgrep') {
        controller.abort();
        return { outcome: 'cancelled', exitCode: null, stdout: '', stderr: '', truncated: false };
      }
      return fakeScanner(opts);
    });
    const dir = project();
    const p = plugin(dir);
    const tool = TOOLS.find((t) => t.name === 'security_scan_full');
    if (!tool) throw new Error('not registered');
    const r = await tool.handler({ project_path: dir, force: true }, p, { signal: controller.signal });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe('cancelled');
    // No child after the cancelled one started a scanner.
    expect(calls.filter((c) => c.command !== 'semgrep')).toHaveLength(0);
    const parent = p.storage.scans.listHistory(50).find((s) => s.scan_type === 'security_full');
    expect(parent?.status).toBe('cancelled');
  });

  it('two concurrent full scans both finish — the parent never holds a scanner slot its children need', async () => {
    resetLimiter();
    const a = project();
    const b = project();
    const [ra, rb] = await Promise.all([full(a), full(b)]);
    expect(ra.r.ok).toBe(true);
    expect(rb.r.ok).toBe(true);
  }, 90_000);

  it('serves a repeat call from the cache, with the child scans it ran', async () => {
    const dir = project();
    const p = plugin(dir);
    const tool = TOOLS.find((t) => t.name === 'security_scan_full');
    if (!tool) throw new Error('not registered');
    const first = (await tool.handler({ project_path: dir }, p)) as unknown as FullResult;
    const scannerCalls = calls.length;
    const second = (await tool.handler({ project_path: dir }, p)) as unknown as FullResult & { cached?: boolean };
    expect(second.cached).toBe(true);
    expect(second.scan_id).toBe(first.scan_id);
    expect(calls.length).toBe(scannerCalls);
    expect(second.child_scans?.length).toBe(4);
  });
});
