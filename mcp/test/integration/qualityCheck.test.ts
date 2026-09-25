/**
 * `quality_check` without `scripts/scan/quality-scan.sh`.
 *
 * Reproduced against the script: `find … | head -1` under `pipefail` lost
 * ruff (and radon) on a large Python tree; eslint, radon and staticcheck
 * output was captured and thrown away ("recognised but not parsed");
 * `categories` was never read; and `npx eslint` would download ESLint from
 * the network into a project that had none.
 *
 * Scanners are mocked at `runProcess`; the `runShellScript` mock is the
 * script, reporting nothing, so these tests also read the old tool honestly.
 */

import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

/**
 * One test writes 3 000 files: a file-level ceiling for a loaded full-suite
 * run, not a global one — see vitest.config.ts.
 */
vi.setConfig({ testTimeout: 180_000 });

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
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';
import type { ToolRun } from '../../src/types.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

afterAll(cleanupTempDirs);
beforeAll(async () => {
  await import('../../src/tools/qualityCheck.js');
});

const here = dirname(fileURLToPath(import.meta.url));
const FIX = resolve(here, '..', 'fixtures', 'scanners');
const fixture = (name: string): string => readFileSync(join(FIX, name), 'utf8');

type Call = ProcessRunOptions & { args: string[] };
let calls: Call[] = [];
let ruffExit = 0;

function result(exitCode: number, stdout = ''): ProcessRunResult {
  return { outcome: exitCode === 0 ? 'completed' : 'failed', exitCode, stdout, stderr: '', truncated: false };
}

function after(args: readonly string[], flag: string): string {
  return args[args.indexOf(flag) + 1] ?? '';
}

async function fakeScanner(opts: ProcessRunOptions): Promise<ProcessRunResult> {
  const call: Call = { ...opts, args: opts.args ?? [] };
  calls.push(call);
  const a = call.args;
  if (opts.command === 'jscpd') {
    const dir = after(a, '--output');
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'jscpd-report.json'), fixture('jscpd.json'));
    return result(0);
  }
  if (opts.command === 'ruff') {
    if (ruffExit === 0) writeFileSync(after(a, '--output-file'), fixture('ruff.json'));
    return result(ruffExit);
  }
  if (opts.command === 'radon') {
    writeFileSync(after(a, '-O'), fixture('radon-cc.json'));
    return result(0);
  }
  if (opts.command === 'staticcheck') return result(1, fixture('staticcheck.jsonl'));
  if (a[0]?.endsWith('eslint.js')) {
    writeFileSync(after(a, '--output-file'), fixture('eslint.json'));
    return result(1);
  }
  return result(0);
}

beforeEach(() => {
  calls = [];
  ruffExit = 0;
  vi.mocked(scannerAvailable).mockReset();
  vi.mocked(scannerAvailable).mockImplementation(async (name: string) => `/fake/bin/${name}`);
  vi.mocked(runProcess).mockReset();
  vi.mocked(runProcess).mockImplementation(fakeScanner);
  vi.mocked(runShellScript).mockReset();
  vi.mocked(runShellScript).mockResolvedValue({ outcome: 'completed', exitCode: 0, stdout: '', stderr: '', truncated: false });
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

interface QualityResult {
  ok: true;
  scan_id: string;
  coverage: string;
  tools_run: ToolRun[];
  missing_tools: string[];
  findings_count_by_severity: Record<string, number>;
  category_filter?: { categories: string[]; withheld: number };
}

async function quality(project: string, input: Record<string, unknown> = {}) {
  const tool = TOOLS.find((t) => t.name === 'quality_check');
  if (!tool) throw new Error('quality_check not registered');
  const p = plugin(project);
  const r = await tool.handler({ project_path: project, force: true, ...input }, p);
  return { r: r as unknown as QualityResult, p };
}

const total = (c: Record<string, number>): number => Object.values(c).reduce((a, b) => a + b, 0);

/** A project with Python, JS (ESLint configured and installed locally) and Go. */
function polyglot(): string {
  const dir = makeTempDir('quality-');
  writeFileSync(join(dir, 'app.py'), 'x = 1\n');
  writeFileSync(join(dir, 'package.json'), '{"name":"x"}\n');
  writeFileSync(join(dir, 'eslint.config.js'), 'export default [];\n');
  mkdirSync(join(dir, 'node_modules', 'eslint', 'bin'), { recursive: true });
  writeFileSync(join(dir, 'node_modules', 'eslint', 'bin', 'eslint.js'), '// fake\n');
  writeFileSync(join(dir, 'go.mod'), 'module x\n');
  return dir;
}

describe('quality_check', () => {
  it('parses eslint, radon and staticcheck into findings alongside jscpd and ruff', async () => {
    const { r, p } = await quality(polyglot());
    expect(r.ok).toBe(true);
    const byTool = new Map<string, number>();
    for (const f of p.storage.findings.listByScan(r.scan_id)) byTool.set(f.tool, (byTool.get(f.tool) ?? 0) + 1);
    expect(Object.fromEntries(byTool)).toEqual({ jscpd: 2, ruff: 3, radon: 3, eslint: 3, staticcheck: 3 });
    expect(total(r.findings_count_by_severity)).toBe(14);
    for (const name of ['jscpd', 'ruff', 'radon', 'eslint', 'staticcheck']) {
      expect(r.tools_run.find((t) => t.name === name)?.status, name).toBe('ok');
    }
    // What the analysers could not read is said, not dropped.
    expect(r.tools_run.find((t) => t.name === 'eslint')?.reason).toMatch(/broken\.js/);
    expect(r.tools_run.find((t) => t.name === 'radon')?.reason).toMatch(/broken\.py/);
    expect(r.tools_run.find((t) => t.name === 'staticcheck')?.reason).toMatch(/bad\.go/);
    expect(r.coverage).toBe('full');
  });

  it('runs ruff and radon on a project with 3 000 .py files and no Python manifest', async () => {
    const dir = makeTempDir('quality-py-');
    mkdirSync(join(dir, 'pkg'));
    for (let i = 0; i < 3000; i++) writeFileSync(join(dir, 'pkg', `m${i}.py`), 'x = 1\n');
    const { r } = await quality(dir);
    expect(calls.some((c) => c.command === 'ruff')).toBe(true);
    expect(calls.some((c) => c.command === 'radon')).toBe(true);
    expect(r.tools_run.find((t) => t.name === 'ruff')?.status).toBe('ok');
  });

  it('never runs npx, and says so when ESLint is configured but not installed locally', async () => {
    const dir = makeTempDir('quality-js-');
    writeFileSync(join(dir, 'package.json'), '{"name":"x"}\n');
    writeFileSync(join(dir, '.eslintrc.json'), '{}\n');
    const { r } = await quality(dir);
    expect(calls.some((c) => c.command === 'npx' || c.args.includes('eslint'))).toBe(false);
    const eslint = r.tools_run.find((t) => t.name === 'eslint');
    expect(eslint?.status).toBe('skipped');
    expect(eslint?.reason).toMatch(/node_modules/);
    expect(r.missing_tools).toContain('eslint');
    expect(r.coverage).toBe('partial');
  });

  it('runs a locally installed ESLint with node, never through npx', async () => {
    await quality(polyglot());
    const eslint = calls.find((c) => c.args[0]?.endsWith('eslint.js'));
    expect(eslint?.command).toBe(process.execPath);
    expect(calls.some((c) => c.command === 'npx')).toBe(false);
  });

  it('honours categories in the response, and still records every finding', async () => {
    const { r, p } = await quality(polyglot(), { categories: ['duplicate'] });
    expect(total(r.findings_count_by_severity)).toBe(2);
    expect(r.category_filter?.categories).toEqual(['duplicate']);
    expect(r.category_filter?.withheld).toBe(12);
    expect(p.storage.findings.listByScan(r.scan_id)).toHaveLength(14);

    const naming = await quality(polyglot(), { categories: ['naming'] });
    // eslint camelcase + staticcheck ST1003.
    expect(total(naming.r.findings_count_by_severity)).toBe(2);
    const complexity = await quality(polyglot(), { categories: ['complexity'] });
    // radon x3 + eslint complexity.
    expect(total(complexity.r.findings_count_by_severity)).toBe(4);
  });

  it('a scanner that errors is failed and coverage is partial, not "0 findings"', async () => {
    ruffExit = 2;
    const dir = makeTempDir('quality-fail-');
    writeFileSync(join(dir, 'a.py'), 'x = 1\n');
    const { r } = await quality(dir);
    expect(r.tools_run.find((t) => t.name === 'ruff')?.status).toBe('failed');
    expect(r.coverage).toBe('partial');
  });
});
