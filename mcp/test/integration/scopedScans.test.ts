/**
 * Scoped scans and `.guardianignore`, tool by tool, with every scanner mocked
 * at `runProcess` so the arguments each one would receive can be inspected.
 *
 * What these reproduce: the seven scoped commands (`guardian-diff`, `-file`,
 * `-branch`, `-since`, `-prepush`, `-incoming`, `-postinstall`) had no way to
 * ask a scan tool for less than a whole directory — a file path was
 * `not_a_directory` — so they ran whole-project scans; and a self-scan of
 * dev-guardian reported its own deliberately vulnerable fixtures.
 */

import { execa } from 'execa';
import { mkdirSync, readdirSync, writeFileSync } from 'node:fs';
import { join, sep } from 'node:path';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

/** Real git repositories under a loaded suite: a file-level ceiling (see vitest.config.ts). */
vi.setConfig({ testTimeout: 120_000 });

vi.mock('../../src/runners/processRunner.js', () => ({ runProcess: vi.fn() }));
vi.mock('../../src/runners/shellRunner.js', () => ({ runShellScript: vi.fn() }));
vi.mock('../../src/tools/scanHelpers.js', async () => {
  const actual = await vi.importActual<typeof import('../../src/tools/scanHelpers.js')>(
    '../../src/tools/scanHelpers.js',
  );
  return { ...actual, scannerAvailable: vi.fn() };
});

import { runProcess, type ProcessRunOptions, type ProcessRunResult } from '../../src/runners/processRunner.js';
import { scannerAvailable } from '../../src/tools/scanHelpers.js';
import type { PluginContext } from '../../src/context.js';
import { resolveProjectPath } from '../../src/platform/projectPath.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';
import type { Finding, ToolRun } from '../../src/types.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

afterAll(cleanupTempDirs);
beforeAll(async () => {
  await import('../../src/tools/scanSast.js');
  await import('../../src/tools/scanSecrets.js');
  await import('../../src/tools/bugHunt.js');
  await import('../../src/tools/qualityCheck.js');
  await import('../../src/tools/scanDeps.js');
});

type Call = ProcessRunOptions & { args: string[] };
let calls: Call[] = [];
/** What the fake gitleaks saw in its `-s .` directory, per call. */
let gitleaksSaw: string[][] = [];
let available: Set<string>;

function done(exitCode = 0, stderr = ''): ProcessRunResult {
  return { outcome: exitCode === 0 ? 'completed' : 'failed', exitCode, stdout: '', stderr, truncated: false };
}

function after(args: readonly string[], flag: string): string {
  return args[args.indexOf(flag) + 1] ?? '';
}

/** The explicit targets after `--`. */
function targets(args: readonly string[]): string[] {
  const i = args.indexOf('--');
  return i >= 0 ? args.slice(i + 1) : [];
}

function listRel(root: string, rel = ''): string[] {
  const out: string[] = [];
  for (const e of readdirSync(join(root, rel), { withFileTypes: true })) {
    const r = rel === '' ? e.name : `${rel}/${e.name}`;
    if (e.isDirectory()) out.push(...listRel(root, r));
    else out.push(r);
  }
  return out.sort();
}

/** One ERROR result per target, so every scanned file produces a finding. */
function semgrepReport(files: readonly string[]): string {
  return JSON.stringify({
    results: files.map((f) => ({
      check_id: 'test.rule',
      path: f,
      start: { line: 1, col: 1 },
      end: { line: 1, col: 2 },
      extra: { severity: 'ERROR', message: 'bad', lines: 'eval(x)' },
    })),
    errors: [],
    paths: { scanned: files },
  });
}

async function fake(opts: ProcessRunOptions): Promise<ProcessRunResult> {
  const call: Call = { ...opts, args: opts.args ?? [] };
  calls.push(call);
  const a = call.args;
  if (opts.command === 'semgrep') {
    const t = targets(a);
    writeFileSync(after(a, '--output'), semgrepReport(t.length > 0 ? t : ['whole.py']));
    return done(1);
  }
  if (opts.command === 'bandit') {
    writeFileSync(after(a, '-o'), JSON.stringify({ results: [], errors: [], metrics: {} }));
    return done(0);
  }
  if (opts.command === 'gitleaks') {
    const report = a.find((x) => x.startsWith('--report-path='));
    if (report) writeFileSync(report.slice('--report-path='.length), '[]');
    if (a.includes('--no-git') && opts.cwd !== undefined) gitleaksSaw.push(listRel(opts.cwd));
    return done(0, 'INF 1 commits scanned.');
  }
  if (opts.command === 'trivy') {
    writeFileSync(after(a, '--output'), JSON.stringify({ Results: [] }));
    return done(0);
  }
  if (opts.command === 'jscpd') {
    const dir = after(a, '--output');
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'jscpd-report.json'), JSON.stringify({ statistics: { total: { lines: 10, duplicatedLines: 0 } }, duplicates: [] }));
    return done(0);
  }
  if (opts.command === 'ruff') {
    writeFileSync(after(a, '--output-file'), '[]');
    return done(0);
  }
  if (opts.command === 'radon') {
    writeFileSync(after(a, '-O'), '{}');
    return done(0);
  }
  return done(0);
}

beforeEach(() => {
  calls = [];
  gitleaksSaw = [];
  available = new Set(['semgrep', 'bandit', 'gitleaks', 'trivy', 'jscpd', 'ruff', 'radon', 'dotnet', 'docker']);
  vi.mocked(scannerAvailable).mockReset();
  vi.mocked(scannerAvailable).mockImplementation(async (name: string) => (available.has(name) ? `/fake/bin/${name}` : null));
  vi.mocked(runProcess).mockReset();
  vi.mocked(runProcess).mockImplementation(fake);
});

function plugin(project: string): PluginContext {
  const db = new Database(':memory:');
  runMigrations(db);
  return { storage: new Storage(db), shell: null, scriptsDir: project, progressNotifier: { send: () => {} } };
}

interface ScanPayload {
  scan_id: string;
  coverage: string;
  tools_run: ToolRun[];
  missing_tools: string[];
  warnings: string[];
  top_findings: Finding[];
  findings_count_by_severity: Record<string, number>;
  scope?: Record<string, unknown>;
  exclusions?: Record<string, unknown>;
  package_filter?: Record<string, unknown>;
}

async function run(name: string, project: string, input: Record<string, unknown> = {}) {
  const tool = TOOLS.find((t) => t.name === name);
  if (!tool) throw new Error(`${name} not registered`);
  const p = plugin(project);
  const r = await tool.handler({ project_path: project, force: true, ...input }, p);
  return { r, p };
}

async function ok(name: string, project: string, input: Record<string, unknown> = {}): Promise<ScanPayload> {
  const { r } = await run(name, project, input);
  if (!r.ok) throw new Error(`${name} failed: ${JSON.stringify(r.error)}`);
  return r as unknown as ScanPayload;
}

function write(dir: string, rel: string, content = 'eval(x)\n'): void {
  const abs = join(dir, rel);
  mkdirSync(join(abs, '..'), { recursive: true });
  writeFileSync(abs, content);
}

function project(prefix = 'scoped-'): string {
  return resolveProjectPath(makeTempDir(prefix)).path;
}

async function git(cwd: string, ...args: string[]): Promise<string> {
  return (await execa('git', args, { cwd })).stdout;
}

async function repo(files: Record<string, string>): Promise<string> {
  const dir = project('scoped-git-');
  await git(dir, 'init', '-q');
  await git(dir, 'symbolic-ref', 'HEAD', 'refs/heads/main');
  await git(dir, 'config', 'user.email', 'guardian-test@example.com');
  await git(dir, 'config', 'user.name', 'Guardian Test');
  await git(dir, 'config', 'commit.gpgsign', 'false');
  for (const [p, c] of Object.entries(files)) write(dir, p, c);
  await git(dir, 'add', '-A');
  await git(dir, 'commit', '-q', '-m', 'base');
  return dir;
}

async function commitAll(dir: string): Promise<void> {
  await git(dir, 'add', '-A');
  await git(dir, 'commit', '-q', '-m', 'change');
}

const byCommand = (command: string): Call[] => calls.filter((c) => c.command === command);

// ---------------------------------------------------------------------------

describe('scan_sast — scope', () => {
  it('hands Semgrep and Bandit exactly the scoped files, as explicit targets after `--`', async () => {
    const dir = project();
    for (const f of ['src/a.py', 'src/sub dir/héllo.py', 'src/-dash.py', 'src/app.js', 'other/b.py']) write(dir, f);
    const r = await ok('scan_sast', dir, { scope: { paths: ['src'] } });

    const semgrep = byCommand('semgrep');
    expect(semgrep).toHaveLength(1);
    expect([...targets(semgrep[0]?.args ?? [])].sort()).toEqual(['src/-dash.py', 'src/a.py', 'src/app.js', 'src/sub dir/héllo.py']);
    expect(semgrep[0]?.args).not.toContain(dir);
    const bandit = byCommand('bandit');
    expect(bandit).toHaveLength(1);
    expect([...targets(bandit[0]?.args ?? [])].sort()).toEqual(['src/-dash.py', 'src/a.py', 'src/sub dir/héllo.py']);
    expect(bandit[0]?.args).not.toContain('-r');

    expect(r.coverage).toBe('full');
    expect(r.scope).toMatchObject({ kind: 'paths', files: 4 });
    expect(r.findings_count_by_severity.high).toBe(4);
  });

  it('a file as project_path is refused with the scoped call to make', async () => {
    const dir = project();
    write(dir, 'app.py');
    const { r } = await run('scan_sast', join(dir, 'app.py'));
    expect(r.ok).toBe(false);
    if (r.ok) throw new Error('expected failure');
    expect(r.error.code).toBe('unsupported_target');
    expect(r.error.retry_with).toEqual({ project_path: dir, scope: { paths: ['app.py'] } });
    expect(calls).toHaveLength(0);
  });

  it('reports .NET build analysis as not applicable to a scope — never runs dotnet, never pretends', async () => {
    const dir = project();
    write(dir, 'App.csproj', '<Project Sdk="Microsoft.NET.Sdk"></Project>\n');
    write(dir, 'Program.cs', 'class P {}\n');
    const r = await ok('scan_sast', dir, { scope: { paths: ['Program.cs'] } });
    expect(byCommand('dotnet')).toHaveLength(0);
    const entry = r.tools_run.find((t) => t.name === 'dotnet-analyzers');
    expect(entry?.status).toBe('skipped');
    expect(entry?.reason).toMatch(/project-level/);
    // A C# file in scope that the analyzers did not see is a gap.
    expect(r.missing_tools).toContain('dotnet-analyzers');
    expect(r.coverage).toBe('partial');
  });

  it('without Semgrep on PATH, a scoped scan is a named gap — the Docker fallback takes no file list', async () => {
    available.delete('semgrep');
    const dir = project();
    write(dir, 'a.py');
    const r = await ok('scan_sast', dir, { scope: { paths: ['a.py'] } });
    expect(byCommand('docker')).toHaveLength(0);
    const entry = r.tools_run.find((t) => t.name === 'semgrep');
    expect(entry?.status).toBe('skipped');
    expect(r.missing_tools).toContain('semgrep');
  });

  it('an empty change set runs nothing, and says so', async () => {
    const dir = await repo({ 'a.py': 'x = 1\n' });
    const r = await ok('scan_sast', dir, { scope: { diff: {} } });
    expect(byCommand('semgrep')).toHaveLength(0);
    expect(r.tools_run.find((t) => t.name === 'semgrep')?.reason).toMatch(/no file/);
    expect(r.warnings.some((w) => w.includes('nothing was scanned'))).toBe(true);
  });

  it('scope.diff scans the uncommitted files only', async () => {
    const dir = await repo({ 'a.py': 'x = 1\n', 'b.py': 'y = 1\n' });
    write(dir, 'b.py', 'eval(y)\n');
    write(dir, 'new.py');
    await ok('scan_sast', dir, { scope: { diff: {} } });
    expect(targets(byCommand('semgrep')[0]?.args ?? [])).toEqual(['b.py', 'new.py']);
  });
});

describe('scan_sast — .guardianignore', () => {
  it('passes the excluded paths to Semgrep (--exclude) and Bandit (-x), and drops what they would still report', async () => {
    const dir = project();
    write(dir, '.guardianignore', 'mcp/test/fixtures/\n');
    write(dir, 'mcp/test/fixtures/vuln.py');
    write(dir, 'app.py');
    const r = await ok('scan_sast', dir);
    const semgrep = byCommand('semgrep')[0]?.args ?? [];
    expect(semgrep).toContain('--exclude=/mcp/test/fixtures');
    const bandit = byCommand('bandit')[0]?.args ?? [];
    expect(after(bandit, '-x').split(',')).toContain(`${join(dir, 'mcp', 'test', 'fixtures')}${sep}`);
    expect(r.exclusions).toEqual({ file: '.guardianignore', patterns: 1, excluded_files: 1, findings_excluded: 0 });
  });
});

describe('scan_secrets — scope', () => {
  it('scope.paths: gitleaks reads a copy holding exactly those files, and no history', async () => {
    const dir = await repo({ 'a.env': 'k=1\n', 'src/b.env': 'k=2\n', 'other/c.env': 'k=3\n' });
    const r = await ok('scan_secrets', dir, { scope: { paths: ['src', 'a.env'] } });
    const leaks = byCommand('gitleaks');
    expect(leaks).toHaveLength(1);
    expect(leaks[0]?.args).toContain('--no-git');
    expect(gitleaksSaw[0]).toEqual(['a.env', 'src/b.env']);
    expect(leaks.some((c) => c.args.some((x) => x.startsWith('--log-opts')))).toBe(false);
    expect(r.scope).toMatchObject({ kind: 'paths', files: 2 });
  });

  it('scope.diff.base: exactly the range for history, no working-tree pass', async () => {
    const dir = await repo({ 'a.env': 'k=1\n' });
    const base = (await git(dir, 'rev-parse', 'HEAD')).trim();
    await git(dir, 'checkout', '-q', '-b', 'feature');
    write(dir, 'b.env', 'k=2\n');
    await commitAll(dir);
    const head = (await git(dir, 'rev-parse', 'HEAD')).trim();
    write(dir, 'untracked.env', 'k=3\n');
    await ok('scan_secrets', dir, { scope: { diff: { base: 'main' } } });
    const leaks = byCommand('gitleaks');
    expect(leaks).toHaveLength(1);
    expect(leaks[0]?.args).toContain(`--log-opts=${base}..${head}`);
    expect(leaks[0]?.args).not.toContain('--no-git');
  });

  it('scope.since as a date narrows history with --since', async () => {
    const dir = await repo({ 'a.env': 'k=1\n' });
    await ok('scan_secrets', dir, { scope: { since: '2000-01-01' } });
    const leaks = byCommand('gitleaks');
    expect(leaks.map((c) => c.args.find((x) => x.startsWith('--log-opts=')))).toEqual(['--log-opts=--since=2000-01-01']);
  });

  it('scope.diff {} is the working-tree pass over the uncommitted files', async () => {
    const dir = await repo({ 'a.env': 'k=1\n', 'b.env': 'k=2\n' });
    write(dir, 'b.env', 'k=22\n');
    write(dir, 'new.env', 'k=3\n');
    await ok('scan_secrets', dir, { scope: { diff: {} } });
    expect(byCommand('gitleaks')).toHaveLength(1);
    expect(gitleaksSaw[0]).toEqual(['b.env', 'new.env']);
  });

  it('scope and log_opts together are refused', async () => {
    const dir = await repo({ 'a.env': 'k=1\n' });
    const { r } = await run('scan_secrets', dir, { scope: { paths: ['a.env'] }, log_opts: '--all' });
    expect(r.ok).toBe(false);
    if (r.ok) throw new Error('expected failure');
    expect(r.error.code).toBe('unsupported_target');
    expect(calls).toHaveLength(0);
  });
});

describe('bug_hunt — scope', () => {
  it('runs its packs over exactly the scoped files', async () => {
    const dir = project();
    write(dir, 'src/a.py');
    write(dir, 'lib/b.py');
    const r = await ok('bug_hunt', dir, { scope: { paths: ['src/a.py'] } });
    const semgrep = byCommand('semgrep');
    expect(semgrep).toHaveLength(1);
    expect(targets(semgrep[0]?.args ?? [])).toEqual(['src/a.py']);
    expect(semgrep[0]?.args.some((x) => x.startsWith('--config='))).toBe(true);
    expect(r.scope).toMatchObject({ files: 1 });
    expect(r.top_findings.every((f) => f.category === 'bug')).toBe(true);
  });

  it('re-runs the surviving packs over the scoped files when a registry pack is gone, and names the gap', async () => {
    const dir = project();
    write(dir, 'a.py');
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      const call: Call = { ...opts, args: opts.args ?? [] };
      calls.push(call);
      if (opts.command !== 'semgrep') return done(0);
      const out = after(call.args, '--output');
      if (call.args.includes('--config=p/r2c-bug-scan')) {
        writeFileSync(
          out,
          JSON.stringify({
            results: [],
            errors: [{ type: 'SemgrepError', message: 'Failed to download configuration from https://semgrep.dev/c/p/r2c-bug-scan HTTP 404.' }],
            paths: { scanned: [] },
          }),
        );
        return done(7);
      }
      writeFileSync(out, semgrepReport(targets(call.args)));
      return done(1);
    });
    const r = await ok('bug_hunt', dir, { scope: { paths: ['a.py'] } });
    const semgrep = byCommand('semgrep');
    expect(semgrep).toHaveLength(2);
    expect(semgrep[1]?.args).not.toContain('--config=p/r2c-bug-scan');
    expect(targets(semgrep[1]?.args ?? [])).toEqual(['a.py']);
    const entry = r.tools_run.find((t) => t.name === 'semgrep');
    expect(entry?.status).toBe('ok');
    expect(entry?.reason).toMatch(/p\/r2c-bug-scan/);
    expect(r.missing_tools).toContain('semgrep');
    expect(r.findings_count_by_severity.high).toBe(1);
  });

  it('passes .guardianignore to Semgrep on a whole-project run', async () => {
    const dir = project();
    write(dir, '.guardianignore', 'fixtures/\n');
    write(dir, 'fixtures/x.py');
    write(dir, 'a.py');
    await ok('bug_hunt', dir);
    expect(byCommand('semgrep')[0]?.args).toContain('--exclude=/fixtures');
  });
});

describe('quality_check — scope', () => {
  it('hands jscpd the scoped files and ruff/radon the scoped Python files; budgets are project-level', async () => {
    const dir = project();
    write(dir, 'src/a.py', 'x = 1\n');
    write(dir, 'src/b.ts', 'let x = 1\n');
    write(dir, 'other/c.py', 'y = 1\n');
    write(dir, '.guardian/budgets.yml', 'quality:\n  duplication_pct: 5\n');
    const r = await ok('quality_check', dir, { scope: { paths: ['src'] } });
    expect(targets(byCommand('jscpd')[0]?.args ?? []).sort()).toEqual(['src/a.py', 'src/b.ts']);
    expect(targets(byCommand('ruff')[0]?.args ?? [])).toEqual(['src/a.py']);
    expect(targets(byCommand('radon')[0]?.args ?? [])).toEqual(['src/a.py']);
    const budgets = r.tools_run.find((t) => t.name === 'budgets');
    expect(budgets?.status).toBe('skipped');
    expect(budgets?.reason).toMatch(/project-level/);
    expect(r.scope).toMatchObject({ files: 2 });
  });
});

describe('scan_deps — packages and .guardianignore', () => {
  function trivyWith(vulns: Array<{ id: string; pkg: string; target: string }>): void {
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      const call: Call = { ...opts, args: opts.args ?? [] };
      calls.push(call);
      if (opts.command !== 'trivy') return done(0);
      const byTarget = new Map<string, Array<Record<string, string>>>();
      for (const v of vulns) {
        const list = byTarget.get(v.target) ?? [];
        list.push({ VulnerabilityID: v.id, PkgName: v.pkg, InstalledVersion: '1.0.0', FixedVersion: '1.0.1', Severity: 'HIGH' });
        byTarget.set(v.target, list);
      }
      writeFileSync(
        after(call.args, '--output'),
        JSON.stringify({ Results: [...byTarget].map(([Target, Vulnerabilities]) => ({ Target, Type: 'npm', Vulnerabilities })) }),
      );
      return done(0);
    });
  }

  it('`packages` narrows the response, never the stored scan, and names requested packages it did not find', async () => {
    const dir = project();
    write(dir, 'package-lock.json', '{}\n');
    trivyWith([
      { id: 'CVE-1', pkg: 'lodash', target: 'package-lock.json' },
      { id: 'CVE-2', pkg: 'minimist', target: 'package-lock.json' },
    ]);
    const { r, p } = await run('scan_deps', dir, { packages: ['lodash', 'left-pad'] });
    if (!r.ok) throw new Error(JSON.stringify(r.error));
    const res = r as unknown as ScanPayload;
    expect(res.top_findings.map((f) => f.rule_id)).toEqual(['CVE-1']);
    expect(res.package_filter).toMatchObject({ packages: ['lodash', 'left-pad'], withheld: 1, not_found: ['left-pad'] });
    expect(p.storage.findings.listByScan(res.scan_id)).toHaveLength(2);
  });

  it('skips excluded manifests natively and keeps their CVEs out of the stored scan', async () => {
    const dir = project();
    write(dir, '.guardianignore', 'mcp/test/fixtures/\n');
    write(dir, 'package-lock.json', '{}\n');
    write(dir, 'mcp/test/fixtures/deps/package-lock.json', '{}\n');
    trivyWith([
      { id: 'CVE-1', pkg: 'lodash', target: 'package-lock.json' },
      { id: 'CVE-9', pkg: 'evil', target: 'mcp/test/fixtures/deps/package-lock.json' },
    ]);
    const { r, p } = await run('scan_deps', dir);
    if (!r.ok) throw new Error(JSON.stringify(r.error));
    const res = r as unknown as ScanPayload;
    const trivy = byCommand('trivy')[0]?.args ?? [];
    expect(after(trivy, '--skip-dirs')).toBe('mcp/test/fixtures');
    expect(p.storage.findings.listByScan(res.scan_id).map((f) => f.rule_id)).toEqual(['CVE-1']);
    expect(p.storage.cves.listActive(res.scan_id).map((c) => c.cve_id)).toEqual(['CVE-1']);
    expect(res.exclusions).toMatchObject({ findings_excluded: 1 });
  });
});

describe('tool descriptions', () => {
  // Claude Code truncates at 2048; this repo keeps a 1500 margin (Global Constraint 11).
  it.each(['scan_sast', 'scan_secrets', 'quality_check', 'scan_deps'])('%s stays within 1500 characters', (name) => {
    const tool = TOOLS.find((t) => t.name === name);
    expect(tool?.description.length).toBeLessThanOrEqual(1500);
  });
});
