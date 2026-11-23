/**
 * deps-tools-host-other-texts, task 2, T-09 (red until the fix): the whole answer of the real handlers, in JSON, holds
 * no made-up part of a credential written in a URL of a project file, a `.mcp.json`, the repository's git
 * configuration, or an error line of a program. Every case is a form the measurement of 2026-11-20 found said whole
 * (`.specs/_findings-2026-11-20/measurements/tool-texts/`).
 *
 * `runProcess` and `scannerAvailable` are mocked, as in that harness: no package manager, no `dotnet`, no scanner and no
 * `git push` runs; the throwaway repositories use `git` itself. The heartbeat case uses fake timers: a progress message
 * carries the last stderr line of the program that runs, so a URL in it is said as everything else.
 *
 * Every credential-looking value is MADE UP and built from parts.
 */

import { execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../src/runners/processRunner.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/runners/processRunner.js')>();
  return { ...actual, runProcess: vi.fn() };
});
vi.mock('../../src/tools/scanHelpers.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/tools/scanHelpers.js')>();
  return { ...actual, scannerAvailable: vi.fn() };
});

import type { PluginContext } from '../../src/context.js';
import type { ProgressPayload } from '../../src/progress/progressEmitter.js';
import { runProcess, type ProcessRunOptions, type ProcessRunResult } from '../../src/runners/processRunner.js';
import { GuardianDatabase } from '../../src/storage/db.js';
import { Storage } from '../../src/storage/index.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { scannerAvailable } from '../../src/tools/scanHelpers.js';
import { TOOLS } from '../../src/tools/index.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

// The review_pr row checks a head out of a real throwaway repository: 12 s on Windows, over the 10 s default. A file-level
// ceiling, as reviewPr.test.ts has, not a global one.
vi.setConfig({ testTimeout: 60_000 });

afterAll(cleanupTempDirs);
beforeAll(async () => {
  await import('../../src/registerAll.js');
});

const FEATURE = 'deps-tools-host-other-texts';
const WIN = process.platform === 'win32';
const T = ['tok', 'ZzQ', '7731'].join('');
const K = ['ken', 'Qq', '88'].join('');
const U = ['dg', 'user', 'zq'].join('');
const H = 'host.example';
const BS = String.fromCharCode(92);
const partsIn = (text: string): string[] => [T, K, U].filter((p) => text.toLowerCase().includes(p.toLowerCase()));
/** The whole answer, in JSON, holds no part. */
const expectNoPart = (whole: unknown): void => {
  const text = JSON.stringify(whole);
  expect(partsIn(text), text.slice(0, 600)).toEqual([]);
};

const OK: ProcessRunResult = { outcome: 'completed', exitCode: 0, stdout: '', stderr: '', truncated: false };
const bare = (cmd: string): string => (cmd.split(/[\\/]/).pop() ?? '').replace(/\.(exe|cmd|bat)$/i, '').toLowerCase();
type Answer = (name: string, opts: ProcessRunOptions) => ProcessRunResult | undefined | Promise<ProcessRunResult | undefined>;

/** `installed` are on PATH for the tools, nothing else is; no process is started at all. */
function mocked(installed: readonly string[], answer?: Answer): void {
  vi.mocked(scannerAvailable).mockImplementation(async (name: string) => (installed.includes(name) ? `/fake/bin/${name}` : null));
  vi.mocked(runProcess).mockImplementation(async (opts: ProcessRunOptions) => (await answer?.(bare(opts.command), opts)) ?? OK);
}
beforeEach(() => {
  vi.mocked(scannerAvailable).mockReset();
  vi.mocked(runProcess).mockReset();
});
afterEach(() => {
  vi.unstubAllEnvs();
  vi.useRealTimers();
});

const J = (o: unknown): string => `${JSON.stringify(o, null, 2)}\n`;
function project(files: Record<string, string>): string {
  const dir = makeTempDir('dg-tooltexts-');
  for (const [name, text] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, name)), { recursive: true });
    writeFileSync(join(dir, name), text);
  }
  return dir;
}
function plugin(dir: string, sent: ProgressPayload[] = []): PluginContext {
  const db = new GuardianDatabase(':memory:');
  runMigrations(db);
  return { storage: new Storage(db), shell: null, scriptsDir: dir, progressNotifier: { send: (p) => sent.push(p) } };
}
async function call(name: string, input: Record<string, unknown>, p: PluginContext, meta?: { progressToken: string }): Promise<unknown> {
  const t = TOOLS.find((x) => x.name === name);
  if (t === undefined) throw new Error(`${name} is not registered`);
  return t.handler(input, p, meta);
}

/** The user's NuGet configuration, in a temporary home: nothing of this machine's is read. */
function nugetHome(): void {
  const home = makeTempDir('dg-home-');
  vi.stubEnv('APPDATA', join(home, 'Roaming'));
  vi.stubEnv('LOCALAPPDATA', join(home, 'Local'));
  vi.stubEnv('USERPROFILE', home);
  vi.stubEnv('HOME', home);
  vi.stubEnv('DOTNET_CLI_HOME', home);
  vi.stubEnv('ProgramFiles(x86)', join(home, 'pf86'));
  vi.stubEnv('ProgramFiles', join(home, 'pf'));
}

const ROOT = { name: 'dgproj', version: '1.0.0' };
const MANIFEST = J({ ...ROOT, dependencies: { dgdep: '^1.0.0' } });
const CSPROJ = (items = ''): string =>
  `<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net10.0</TargetFramework></PropertyGroup><ItemGroup><PackageReference Include="Dg.Fake" Version="1.0.0" />${items}</ItemGroup></Project>\n`;

async function audit(files: Record<string, string>, installed: readonly string[], answer?: Answer): Promise<unknown> {
  const dir = project(files);
  mocked(installed, answer);
  return call('deps_audit', { project_path: dir, force: true }, plugin(dir));
}

describe(`${FEATURE} T-09 deps_audit`, () => {
  it('T-09 a yarn.lock with resolved "//T/a,K@H/x.tgz"', async () => {
    const lock = `# yarn lockfile v1\n\n\ndgdep@^1.0.0:\n  version "1.0.0"\n  resolved "//${T}/a,${K}@${H}/x.tgz"\n`;
    const whole = await audit({ 'package.json': MANIFEST, 'yarn.lock': lock }, ['npm']);
    expect(JSON.stringify(whole)).toContain('network path');
    expectNoPart(whole);
  });

  it('T-09 a .npmrc with registry=https://T/K@H/', async () => {
    const whole = await audit({ 'package.json': MANIFEST, '.npmrc': `registry=https://${T}/${K}@${H}/\n` }, ['npm']);
    expect(JSON.stringify(whole)).toContain('as its registry');
    expectNoPart(whole);
  });

  it('T-09 a requirements.txt with dgpkg @ https://T;K@H/x.tar.gz', async () => {
    const whole = await audit({ 'requirements.txt': `dgpkg-probe==1.0.0\ndgpkg @ https://${T};${K}@${H}/x.tar.gz\n` }, ['pip-audit']);
    expect(JSON.stringify(whole)).toContain('direct reference');
    expectNoPart(whole);
  });

  it.each([
    // Windows only: on POSIX `//x` is a local path (`platform/projectPath.ts`), as the 3.16.0 release run on Linux showed.
    { id: '//T/K@H/share/Lib.csproj', path: `//${T}/${K}@${H}/share/Lib.csproj`, windowsOnly: true },
    { id: 'UNC T/K@H/share/Lib.csproj', path: `${BS}${BS}${T}${BS}${K}@${H}${BS}share${BS}Lib.csproj`, windowsOnly: true },
  ].filter((c) => WIN || !c.windowsOnly))('T-09 a ProjectReference on a network path, $id', async ({ path }) => {
    nugetHome();
    const whole = await audit({ 'App.csproj': CSPROJ(`<ProjectReference Include="${path}" />`) }, ['dotnet']);
    expect(JSON.stringify(whole)).toContain('network path');
    expectNoPart(whole);
  });

  it('T-09 a simulated dotnet restore with NU1301 … https://U:T@H/v3/index.json.', async () => {
    nugetHome();
    const answer: Answer = (name, opts) =>
      name === 'dotnet' && (opts.args ?? [])[0] === 'restore'
        ? { outcome: 'failed', exitCode: 1, stdout: '', stderr: `App.csproj : error NU1301: Unable to load the service index for source https://${U}:${T}@${H}/v3/index.json. [App.csproj]\n`, truncated: false }
        : undefined;
    const whole = await audit({ 'App.csproj': CSPROJ() }, ['dotnet'], answer);
    expect(JSON.stringify(whole)).toContain('/v3/index.json');
    expectNoPart(whole);
  });
});

describe(`${FEATURE} T-09 deps_update_plan`, () => {
  it('T-09 a lock version https://U:T@H/dgdep-1.0.0.tgz', async () => {
    const version = `https://${U}:${T}@${H}/dgdep-1.0.0.tgz`;
    const lock = J({ ...ROOT, lockfileVersion: 1, requires: true, dependencies: { dgdep: { version, integrity: 'sha512-AAAA' } } });
    const dir = project({ 'package.json': MANIFEST, 'package-lock.json': lock });
    mocked(['npm']);
    const p = plugin(dir);
    p.storage.scans.insert({ scan_id: '00000000-0000-4000-8000-000000000001', scan_type: 'deps', project_path: dir, tree_hash: 'deadbeef' });
    p.storage.findings.bulkInsert([
      { fingerprint: 'fp-dgdep', tool: 'trivy', rule_id: 'CVE-2099-100001', severity: 'high', category: 'security', subcategory: 'cve', title: 'dgdep: a vulnerability', file_path: 'package-lock.json', snippet: 'dgdep@1.0.0->1.0.1', fix_available: true, scan_id: '00000000-0000-4000-8000-000000000001' },
    ]);
    p.storage.cves.upsert({ cve_id: 'CVE-2099-100001', package_name: 'dgdep', installed_version: '1.0.0', fixed_version: '1.0.1', severity: 'high', scan_id: '00000000-0000-4000-8000-000000000001' });
    p.storage.scans.finalize({ scan_id: '00000000-0000-4000-8000-000000000001', status: 'completed', tools_run: [{ name: 'trivy', status: 'ok' }], missing_tools: [] });
    const whole = await call('deps_update_plan', { project_path: dir, force: true }, p);
    expect(JSON.stringify(whole)).toContain('dgdep');
    expectNoPart(whole);
  });
});

describe(`${FEATURE} T-09 the .mcp.json tools`, () => {
  it('T-09 audit_mcp_tools with url: https://T/K@H/mcp', async () => {
    const dir = project({ '.mcp.json': J({ mcpServers: { dgsrv: { type: 'http', url: `https://${T}/${K}@${H}/mcp` } } }) });
    mocked([]);
    const whole = await call('audit_mcp_tools', { project_path: dir, servers: ['dgsrv'], allow_remote: false, include_user_config: false }, plugin(dir));
    expect(JSON.stringify(whole)).toContain('dgsrv');
    expectNoPart(whole);
  });

  it('T-09 audit_agent_config with http://T@H/mcp', async () => {
    const dir = project({ '.mcp.json': J({ mcpServers: { dgsrv: { type: 'http', url: `http://${T}@${H}/mcp` } } }) });
    mocked([]);
    const whole = await call('audit_agent_config', { project_path: dir, include_user_config: false }, plugin(dir));
    expect(JSON.stringify(whole)).toContain('agent-audit-http-remote');
    expectNoPart(whole);
  });
});

// ── git configuration keys dev-guardian did not apply ────────────────────────────────────────────────────────────
const KEY = `http.https://${U}:${T}@${H}/.extraheader`;
function git(cwd: string, ...args: string[]): void {
  execFileSync('git', ['-C', cwd, ...args], { stdio: 'ignore' });
}
function repo(): string {
  const dir = makeTempDir('dg-gitkeys-');
  execFileSync('git', ['init', '-q', '-b', 'main', dir], { stdio: 'ignore' });
  git(dir, 'config', 'user.email', 't@example.com');
  git(dir, 'config', 'user.name', 'T');
  git(dir, 'config', 'commit.gpgsign', 'false');
  git(dir, 'config', 'core.autocrlf', 'false');
  writeFileSync(join(dir, 'a.txt'), 'one\n');
  git(dir, 'add', '-A');
  git(dir, 'commit', '-q', '-m', 'base');
  return dir;
}

describe(`${FEATURE} T-09 a git configuration key with a URL as its subsection`, () => {
  it('T-09 scan_secrets: a runProcess that reports http.https://U:T@H/.extraheader as not applied', async () => {
    const dir = repo();
    mocked(['gitleaks'], (name, opts) => {
      if (name !== 'gitleaks') return undefined;
      const report = (opts.args ?? []).find((a) => a.startsWith('--report-path='));
      if (report !== undefined) writeFileSync(report.slice('--report-path='.length), '[]');
      return { outcome: 'completed', exitCode: 0, stdout: '', stderr: 'INF 1 commits scanned.\n', truncated: false, gitNotApplied: [KEY] };
    });
    const whole = await call('scan_secrets', { project_path: dir, force: true }, plugin(dir));
    expect(JSON.stringify(whole)).toContain('was not applied for');
    expectNoPart(whole);
  });

  it('T-09 review_pr: the head checkout of a repository whose own configuration has that key', async () => {
    const dir = repo();
    git(dir, 'checkout', '-q', '-b', 'feature');
    writeFileSync(join(dir, 'a.txt'), 'two\n');
    git(dir, 'commit', '-q', '-am', 'change');
    git(dir, 'checkout', '-q', 'main');
    git(dir, 'config', KEY, 'X-Probe: 1');
    mocked(['semgrep', 'gitleaks'], (name, opts) => {
      const args = opts.args ?? [];
      if (name === 'semgrep') {
        const out = args[args.indexOf('--output') + 1];
        if (out !== undefined) writeFileSync(out, JSON.stringify({ results: [], errors: [], paths: { scanned: ['a.txt'] } }));
      }
      if (name === 'gitleaks') {
        const report = args.find((a) => a.startsWith('--report-path='));
        if (report !== undefined) writeFileSync(report.slice('--report-path='.length), '[]');
        return { outcome: 'completed', exitCode: 0, stdout: '', stderr: 'INF 1 commits scanned.\n', truncated: false };
      }
      return undefined;
    });
    const whole = await call('review_pr', { project_path: dir, base_ref: 'main', head_ref: 'feature', local_only: true, force: true }, plugin(dir));
    expect(JSON.stringify(whole)).toContain('was not applied for');
    expectNoPart(whole);
  });
});

// ── the heartbeat (criterion 10) ─────────────────────────────────────────────────────────────────────────────────
describe(`${FEATURE} T-09 the progress heartbeat says the last stderr line of a running program`, () => {
  it('T-09 deps_audit: a progress message carries /v3/index.json and no part of the credentials', async () => {
    nugetHome();
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'setInterval', 'clearInterval'] });
    const line = `error NU1301: Unable to load the service index for source https://${U}:${T}@${H}/v3/index.json.`;
    let reached = false;
    const dir = project({ 'App.csproj': CSPROJ() });
    mocked(['dotnet'], async (name, opts) => {
      if (name !== 'dotnet' || (opts.args ?? [])[0] !== 'restore') return undefined;
      reached = true;
      opts.onLog?.(line);
      await new Promise<void>((resolve) => setTimeout(resolve, 25_000));
      return { outcome: 'failed', exitCode: 1, stdout: '', stderr: `${line}\n`, truncated: false };
    });
    const sent: ProgressPayload[] = [];
    const running = call('deps_audit', { project_path: dir, force: true }, plugin(dir, sent), { progressToken: 'dg-token' });
    // The handler's own file reading takes real turns of the event loop (setImmediate is not faked): wait for them.
    const started = Date.now();
    while (!reached && Date.now() - started < 20_000) await new Promise<void>((resolve) => setImmediate(resolve));
    expect(reached, 'the simulated dotnet restore started').toBe(true);
    await vi.advanceTimersByTimeAsync(10_000);
    const messages = sent.map((p) => p.message ?? '');
    await vi.advanceTimersByTimeAsync(30_000);
    await running;
    // A message that carries the line: without one this row would be green for the wrong reason.
    expect(messages.some((m) => m.includes('/v3/index.json')), JSON.stringify(messages)).toBe(true);
    expect(partsIn(messages.join(' | ')), messages.join(' | ')).toEqual([]);
  }, 60_000);
});
