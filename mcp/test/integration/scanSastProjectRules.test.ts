/**
 * What `scan_sast` actually asks Semgrep to run.
 *
 * ---- The defect these tests exist for --------------------------------
 *
 * `init_project` writes 13 security rules into a project as `.semgrep.yml`,
 * and `scan_sast` ran `--config=auto` — which does not load it. Measured
 * against semgrep 1.164.0 on a project containing `<?php echo $_GET['name'];`
 * and a copy of `configs/semgrep/base.yml`:
 *
 *   --config=<that file>  → 1 finding (wp-unescaped-output), scanned 2
 *   --config=auto         → 0 findings,                      scanned 2
 *
 * So the rule pack this plugin ships had no consumer at all. The
 * `wp-unescaped-output` rule fixed in b51a2dc was dead twice over, for
 * independent reasons, and the second reason only surfaced because someone
 * went looking for who read the file.
 *
 * These are argv-level tests against a mocked runner; the end-to-end proof
 * with the real binary is `test/e2e/projectRulesFixture.test.ts`.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';
import { okResult } from '../helpers/toolResult.js';

vi.mock('../../src/runners/processRunner.js', () => ({ runProcess: vi.fn() }));
vi.mock('../../src/runners/shellRunner.js', () => ({ runShellScript: vi.fn() }));
vi.mock('../../src/tools/scanHelpers.js', async () => {
  const actual =
    await vi.importActual<typeof import('../../src/tools/scanHelpers.js')>(
      '../../src/tools/scanHelpers.js',
    );
  return { ...actual, scannerAvailable: vi.fn() };
});

import type { PluginContext } from '../../src/context.js';
import { customRulesMetaKey } from '../../src/platform/customRules.js';
import { planSemgrepConfigs } from '../../src/runners/semgrepConfigs.js';
import { runProcess } from '../../src/runners/processRunner.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';
import { scannerAvailable } from '../../src/tools/scanHelpers.js';

afterAll(cleanupTempDirs);

beforeAll(async () => {
  await import('../../src/tools/scanSast.js');
});

const RULES =
  'rules:\n  - id: x\n    pattern: foo(...)\n    message: m\n    languages: [python]\n    severity: WARNING\n';

function getTool(name: string) {
  const t = TOOLS.find((x) => x.name === name);
  if (!t) throw new Error(`Tool '${name}' not registered`);
  return t;
}

function makePlugin(projectPath: string): PluginContext {
  const db = new Database(':memory:');
  runMigrations(db);
  return {
    storage: new Storage(db),
    shell: { command: 'bash', args_prefix: [], needs_wsl_path_translate: false, label: 'fake' },
    scriptsDir: projectPath,
    progressNotifier: { send: () => {} },
  };
}

/** Captured argv of the last `runProcess` call, per command. */
const captured: Array<{ command: string; args: string[] }> = [];

/** What the mocked Semgrep writes as its report — a real run always has `paths`. */
const CLEAN_REPORT = { results: [], errors: [], paths: { scanned: ['a.py'] } };

function mockSemgrepOnPath(exitCode = 0, report: unknown = CLEAN_REPORT): void {
  vi.mocked(scannerAvailable).mockImplementation(async (name: string) =>
    name === 'semgrep' ? '/fake/bin/semgrep' : null,
  );
  vi.mocked(runProcess).mockImplementation(async (opts) => {
    captured.push({ command: opts.command, args: [...(opts.args ?? [])] });
    const out = opts.args?.find((_a, i) => opts.args?.[i - 1] === '--output');
    if (out) {
      writeFileSync(
        out,
        JSON.stringify(report),
        'utf8',
      );
    }
    return { outcome: 'completed' as const, exitCode, stdout: '', stderr: '', truncated: false };
  });
}

function semgrepArgs(): string[] {
  const call = captured.find((c) => c.command === 'semgrep');
  if (call === undefined) throw new Error('semgrep was never invoked');
  return call.args;
}

interface SastPayload {
  tools_run: Array<{ name: string; status: string; reason?: string }>;
  missing_tools: string[];
  status: string;
}

async function runSast(
  project: string,
  plugin: PluginContext,
  extra: Record<string, unknown> = {},
): Promise<{ ok: true } & SastPayload> {
  return okResult<SastPayload>(
    await getTool('scan_sast').handler({ project_path: project, force: true, ...extra }, plugin),
  );
}

beforeEach(() => {
  captured.length = 0;
  vi.mocked(runProcess).mockReset();
  vi.mocked(scannerAvailable).mockReset();
});
afterEach(() => {
  vi.mocked(runProcess).mockReset();
  vi.mocked(scannerAvailable).mockReset();
});

describe('scan_sast loads the project’s own Semgrep rules', () => {
  it('passes .semgrep.yml to Semgrep alongside --config=auto', async () => {
    const project = makeTempDir('sast-rules-');
    writeFileSync(join(project, '.semgrep.yml'), RULES, 'utf8');
    mockSemgrepOnPath();

    await runSast(project, makePlugin(project));

    const args = semgrepArgs();
    expect(args).toContain('--config=auto');
    expect(args).toContain(`--config=${join(project, '.semgrep.yml')}`);
  });

  it('follows the manifest to a config that is not called .semgrep.yml', async () => {
    const project = makeTempDir('sast-rules-');
    mkdirSync(join(project, 'ci'), { recursive: true });
    writeFileSync(join(project, 'ci', 'rules.yml'), RULES, 'utf8');
    mkdirSync(join(project, '.dev-guardian'), { recursive: true });
    writeFileSync(
      join(project, '.dev-guardian', 'configs.json'),
      JSON.stringify({
        schema_version: 1,
        entries: [
          {
            target: 'ci/rules.yml',
            source: 'semgrep/base.yml',
            plugin_version: '1.8.0',
            source_sha256: 'a'.repeat(64),
            target_sha256: 'a'.repeat(64),
            recorded_at: '2026-01-01T00:00:00.000Z',
            provenance: 'copied',
          },
        ],
      }),
      'utf8',
    );
    mockSemgrepOnPath();

    await runSast(project, makePlugin(project));
    expect(semgrepArgs()).toContain(`--config=${join(project, 'ci', 'rules.yml')}`);
  });

  it('refuses to pass a config that would abort the whole scan', async () => {
    // Measured: a malformed --config gives `paths.scanned: []` and exit 7, so
    // one stray character in a file the user owns would turn every SAST scan
    // into a silent "0 findings".
    const project = makeTempDir('sast-rules-');
    writeFileSync(join(project, '.semgrep.yml'), 'rules: [ broken', 'utf8');
    mockSemgrepOnPath();

    await runSast(project, makePlugin(project));
    const args = semgrepArgs();
    expect(args).toContain('--config=auto');
    expect(args.some((a) => a.includes('.semgrep.yml'))).toBe(false);
  });

  it('says so, rather than silently dropping it', async () => {
    const project = makeTempDir('sast-rules-');
    writeFileSync(join(project, '.semgrep.yml'), 'rules: [ broken', 'utf8');
    mockSemgrepOnPath();

    const r = await runSast(project, makePlugin(project));
    const run = r.tools_run.find((t) => t.name === 'semgrep');
    expect(run?.reason ?? '').toContain('.semgrep.yml');
  });

  it('reaches the Docker fallback too, expressed inside the mount', async () => {
    const project = makeTempDir('sast-rules-');
    writeFileSync(join(project, '.semgrep.yml'), RULES, 'utf8');
    vi.mocked(scannerAvailable).mockImplementation(async (name: string) =>
      name === 'docker' ? '/usr/bin/docker' : null,
    );
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      captured.push({ command: opts.command, args: [...(opts.args ?? [])] });
      const i = opts.args?.findIndex((a) => a === '--output') ?? -1;
      const containerOut = i >= 0 ? opts.args?.[i + 1] : undefined;
      if (containerOut !== undefined) {
        // Container path back to a host path, without assuming a separator.
        const host = join(project, ...containerOut.replace('/src/', '').split('/'));
        writeFileSync(host, JSON.stringify({ results: [], errors: [] }), 'utf8');
      }
      return { outcome: 'completed' as const, exitCode: 0, stdout: '', stderr: '', truncated: false };
    });

    await runSast(project, makePlugin(project));
    const call = captured.find((c) => c.command === 'docker');
    if (call === undefined) throw new Error('docker was never invoked');
    // The container cannot see host paths — it must be the /src form.
    expect(call.args).toContain('--config=/src/.semgrep.yml');
    expect(call.args.some((a) => a.startsWith(`--config=${project}`))).toBe(false);
  });
});

describe('scan_sast cache key covers the rules it loads', () => {
  it('re-scans when a registered custom rule file OUTSIDE the project changes', async () => {
    // The file is outside the project, so the tree hash cannot see it: only
    // the rule-pack part of the cache key can.
    const project = makeTempDir('sast-cache-');
    const rulesDir = makeTempDir('sast-cache-rules-');
    const rules = join(rulesDir, 'team.yml');
    writeFileSync(rules, RULES, 'utf8');
    const plugin = makePlugin(project);
    plugin.storage.runtimeMeta.setJson(customRulesMetaKey(project), [rules]);
    mockSemgrepOnPath();
    const tool = getTool('scan_sast');

    await tool.handler({ project_path: project }, plugin);
    const hit = okResult<{ cached?: boolean }>(await tool.handler({ project_path: project }, plugin));
    expect(hit.cached).toBe(true);

    writeFileSync(rules, RULES.replace('foo(...)', 'bar(...)'), 'utf8');
    const miss = okResult<{ cached?: boolean }>(await tool.handler({ project_path: project }, plugin));
    expect(miss.cached).toBeUndefined();
    expect(captured.filter((c) => c.command === 'semgrep')).toHaveLength(2);
  });

  it('never answers local_only from a registry-backed scan, or the reverse', async () => {
    const project = makeTempDir('sast-cache-');
    writeFileSync(join(project, '.semgrep.yml'), RULES, 'utf8');
    const plugin = makePlugin(project);
    mockSemgrepOnPath();
    const tool = getTool('scan_sast');

    await tool.handler({ project_path: project }, plugin);
    const local = okResult<{ cached?: boolean }>(
      await tool.handler({ project_path: project, local_only: true }, plugin),
    );
    expect(local.cached).toBeUndefined();
    expect(captured.filter((c) => c.command === 'semgrep')).toHaveLength(2);
  });
});

describe('scan_sast applies Global Constraint 3 to every Semgrep run', () => {
  // Exit 0/1 is necessary and never sufficient: the report decides.
  const FINDING = {
    check_id: 'x',
    path: 'a.py',
    start: { line: 1 },
    end: { line: 1 },
    extra: { severity: 'WARNING', message: 'm', lines: 'foo()' },
  };

  it('a rule that did not compile (exit 2, errors[]) is a failed run — its findings are still recorded', async () => {
    // This used to be `ok` ("one bad rule costs that rule"). A non-empty
    // `errors[]` means the run did not cover what it was given.
    const project = makeTempDir('sast-rules-');
    writeFileSync(join(project, '.semgrep.yml'), RULES, 'utf8');
    mockSemgrepOnPath(2, {
      results: [FINDING],
      errors: [{ type: 'Rule parse error', message: 'Invalid pattern in rule x' }],
      paths: { scanned: ['a.py'] },
    });

    const r = await runSast(project, makePlugin(project));
    const run = r.tools_run.find((t) => t.name === 'semgrep');
    expect(run?.status).toBe('failed');
    expect(run?.reason).toContain('Invalid pattern in rule x');
    expect((r as unknown as { coverage: string }).coverage).not.toBe('full');
    expect((r as unknown as { findings_count_by_severity: Record<string, number> }).findings_count_by_severity['medium']).toBe(1);
  });

  it('exit 0 with a non-empty errors[] (a file that did not parse) is not ok', async () => {
    const project = makeTempDir('sast-rules-');
    mockSemgrepOnPath(0, {
      results: [],
      errors: [{ type: ['PartialParsing', []], message: 'Syntax error at line a.py:3' }],
      paths: { scanned: ['a.py'] },
    });
    const r = await runSast(project, makePlugin(project));
    expect(r.tools_run.find((t) => t.name === 'semgrep')?.status).toBe('failed');
  });

  it('exit 0 that scanned nothing is never a clean result — skipped, listed missing, coverage not full', async () => {
    // Measured shapes: `rules: []`, or a tree no loaded rule applies to.
    const project = makeTempDir('sast-rules-');
    mockSemgrepOnPath(0, { results: [], errors: [], paths: { scanned: [] } });
    const r = await runSast(project, makePlugin(project));
    const run = r.tools_run.find((t) => t.name === 'semgrep');
    expect(run?.status).toBe('skipped');
    expect(run?.reason).toMatch(/scanned 0 files/);
    expect(r.missing_tools).toContain('semgrep');
    expect((r as unknown as { coverage: string }).coverage).not.toBe('full');
  });

  it('a report with no `paths` at all (not a real Semgrep report) is not ok either', async () => {
    const project = makeTempDir('sast-rules-');
    mockSemgrepOnPath(0, { results: [], errors: [] });
    const r = await runSast(project, makePlugin(project));
    expect(r.tools_run.find((t) => t.name === 'semgrep')?.status).not.toBe('ok');
  });

  it('the Docker fallback is judged the same way', async () => {
    const project = makeTempDir('sast-rules-docker-');
    vi.mocked(scannerAvailable).mockImplementation(async (name: string) => (name === 'docker' ? '/usr/bin/docker' : null));
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      const i = opts.args?.findIndex((a) => a === '--output') ?? -1;
      const containerOut = i >= 0 ? opts.args?.[i + 1] : undefined;
      if (containerOut !== undefined) {
        const host = join(project, ...containerOut.replace('/src/', '').split('/'));
        writeFileSync(host, JSON.stringify({ results: [], errors: [], paths: { scanned: [] } }), 'utf8');
      }
      return { outcome: 'completed' as const, exitCode: 0, stdout: '', stderr: '', truncated: false };
    });
    const r = await runSast(project, makePlugin(project));
    expect(r.tools_run.find((t) => t.name === 'semgrep')?.status).toBe('skipped');
    expect(r.missing_tools).toContain('semgrep');
  });
});

describe('scan_sast argv and cache key come from one plan', () => {
  it('passes exactly the rule packs its cache key covers — registry, project config, and this project\'s registered rules', async () => {
    const project = makeTempDir('sast-plan-');
    writeFileSync(join(project, '.semgrep.yml'), RULES, 'utf8');
    const rulesDir = makeTempDir('sast-plan-rules-');
    const team = join(rulesDir, 'team.yml');
    writeFileSync(team, RULES, 'utf8');
    const plugin = makePlugin(project);
    plugin.storage.runtimeMeta.setJson(customRulesMetaKey(project), [team]);
    mockSemgrepOnPath();

    await runSast(project, plugin);
    const configs = semgrepArgs().filter((a) => a.startsWith('--config=')).map((a) => a.slice('--config='.length));
    expect(configs).toEqual(planSemgrepConfigs(project, plugin, false).rulePacks);
    expect(configs).toEqual(['auto', join(project, '.semgrep.yml'), team]);
  });

  it("never runs another project's registered rules", async () => {
    const project = makeTempDir('sast-plan-');
    const other = makeTempDir('sast-plan-other-');
    const otherRules = join(other, 'r.yml');
    writeFileSync(otherRules, RULES, 'utf8');
    const plugin = makePlugin(project);
    plugin.storage.runtimeMeta.setJson(customRulesMetaKey(other), [otherRules]);
    mockSemgrepOnPath();

    await runSast(project, plugin);
    expect(semgrepArgs()).not.toContain(`--config=${otherRules}`);
  });
});

describe('scan_sast local_only mode', () => {
  it('drops --config=auto and turns Semgrep telemetry off', async () => {
    // `--config=auto` REFUSES to run with metrics off ("Cannot create auto
    // config when metrics are off"), which is why every scan today sends
    // telemetry. With the project's own rules actually loaded there is finally
    // a coherent local-only alternative.
    const project = makeTempDir('sast-rules-');
    writeFileSync(join(project, '.semgrep.yml'), RULES, 'utf8');
    mockSemgrepOnPath();

    await runSast(project, makePlugin(project), { local_only: true });
    const args = semgrepArgs();
    expect(args).toContain('--metrics=off');
    expect(args).not.toContain('--config=auto');
    expect(args).toContain(`--config=${join(project, '.semgrep.yml')}`);
  });

  it('never pairs --metrics=off with --config=auto, in either mode', async () => {
    // Semgrep refuses the combination outright, so this is not style — getting
    // it wrong makes the scan exit 7 and report nothing.
    const project = makeTempDir('sast-rules-');
    writeFileSync(join(project, '.semgrep.yml'), RULES, 'utf8');
    for (const local_only of [false, true]) {
      captured.length = 0;
      mockSemgrepOnPath();
      await runSast(project, makePlugin(project), { local_only });
      const args = semgrepArgs();
      expect(args.includes('--metrics=off')).toBe(!args.includes('--config=auto'));
    }
  });

  it('still scans a project that has no rules of its own', async () => {
    // The mirror image of the change: making the project's config load must
    // not make its absence fatal. Asserted here rather than in the e2e file
    // because it needs no real binary — and a second registry-backed pass in
    // the e2e was measured breaking createFixPr.test.ts under suite load.
    const project = makeTempDir('sast-rules-bare-');
    mockSemgrepOnPath();

    const r = await runSast(project, makePlugin(project));
    const args = semgrepArgs();
    expect(args).toContain('--config=auto');
    expect(args.some((a) => a.startsWith('--config=') && a.includes('semgrep.y'))).toBe(false);
    expect(r.tools_run.find((t) => t.name === 'semgrep')?.status).toBe('ok');
    expect(r.status).toBe('completed');
  });

  it('refuses to pretend it scanned when there are no local rules at all', async () => {
    const project = makeTempDir('sast-rules-');
    mockSemgrepOnPath();

    const r = await runSast(project, makePlugin(project), { local_only: true });
    expect(captured.some((c) => c.command === 'semgrep')).toBe(false);
    const run = r.tools_run.find((t) => t.name === 'semgrep');
    expect(run?.status).toBe('skipped');
    expect(run?.reason ?? '').toContain('local_only');
    expect(r.missing_tools).toContain('semgrep');
  });
});

describe('scan_sast .NET: the SDK security analyzers, read from SARIF (Task 11 item 8)', () => {
  const SARIF = readFileSync(
    join(dirname(fileURLToPath(import.meta.url)), '../fixtures/scanners/dotnet-build.sarif.json'),
    'utf8',
  );
  const CSPROJ = '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>';

  /** semgrep + dotnet on PATH; `dotnet build` writes the fixture SARIF where
   *  its relative `-p:ErrorLog=obj/<name>` points, beside the project. */
  function mockDotnet(opts: { exitCode?: number; stdout?: string; writeSarif?: boolean } = {}): void {
    vi.mocked(scannerAvailable).mockImplementation(async (name: string) =>
      name === 'semgrep' || name === 'dotnet' ? `/fake/bin/${name}` : null,
    );
    vi.mocked(runProcess).mockImplementation(async (o) => {
      captured.push({ command: o.command, args: [...(o.args ?? [])] });
      if (o.command === 'semgrep') {
        const out = o.args?.find((_a, i) => o.args?.[i - 1] === '--output');
        if (out) writeFileSync(out, JSON.stringify(CLEAN_REPORT), 'utf8');
      }
      if (o.command === 'dotnet' && opts.writeSarif !== false) {
        const target = o.args?.[1] ?? '';
        const errorLog = o.args?.find((a) => a.startsWith('-p:ErrorLog='))?.slice('-p:ErrorLog='.length) ?? '';
        const rel = errorLog.split('%2C')[0] ?? '';
        const sarif = join(dirname(target), ...rel.split('/'));
        mkdirSync(dirname(sarif), { recursive: true });
        writeFileSync(sarif, SARIF, 'utf8');
      }
      return { outcome: 'completed' as const, exitCode: opts.exitCode ?? 0, stdout: opts.stdout ?? '', stderr: '', truncated: false };
    });
  }

  function dotnetCall(): string[] {
    const call = captured.find((c) => c.command === 'dotnet');
    if (call === undefined) throw new Error('dotnet was never invoked');
    return call.args;
  }

  it('builds with AnalysisModeSecurity=All and a per-project SARIF ErrorLog — never --verbosity:diag — even without Security Code Scan', async () => {
    const project = makeTempDir('sast-dotnet-');
    writeFileSync(join(project, 'App.csproj'), CSPROJ, 'utf8');
    mockDotnet();
    const plugin = makePlugin(project);

    const r = await runSast(project, plugin);
    const args = dotnetCall();
    expect(args[0]).toBe('build');
    expect(args).toContain('-p:AnalysisModeSecurity=All');
    expect(args.some((a) => /^-p:ErrorLog=obj\/.+\.sarif%2Cversion=2\.1$/.test(a))).toBe(true);
    expect(args.some((a) => /diag/.test(a))).toBe(false);

    const run = r.tools_run.find((t) => t.name === 'dotnet-analyzers');
    expect(run?.status).toBe('ok');
    expect(r.tools_run.some((t) => t.name === 'security-code-scan')).toBe(false);
    const rows = plugin.storage.findings.listByScan((r as unknown as { scan_id: string }).scan_id);
    expect(rows.map((f) => f.rule_id).sort()).toEqual(['CA5351', 'SCS0005']);
    // The SARIF is read and removed — nothing of ours is left in obj/.
    const errorLog = args.find((a) => a.startsWith('-p:ErrorLog=')) ?? '';
    const rel = (errorLog.slice('-p:ErrorLog='.length).split('%2C')[0] ?? '').split('/');
    expect(existsSync(join(project, ...rel))).toBe(false);
  });

  it('reports Security Code Scan too when the project references it', async () => {
    const project = makeTempDir('sast-dotnet-');
    writeFileSync(
      join(project, 'App.csproj'),
      CSPROJ.replace('</Project>', '<ItemGroup><PackageReference Include="SecurityCodeScan.VS2019" Version="5.6.7" /></ItemGroup></Project>'),
      'utf8',
    );
    mockDotnet();
    const r = await runSast(project, makePlugin(project));
    expect(r.tools_run.find((t) => t.name === 'security-code-scan')?.status).toBe('ok');
  });

  it('a build that fails is a failed run with the error line — never ok', async () => {
    const project = makeTempDir('sast-dotnet-');
    writeFileSync(join(project, 'App.csproj'), CSPROJ, 'utf8');
    mockDotnet({ exitCode: 1, stdout: 'Program.cs(3,1): error CS1002: ; expected [App.csproj]', writeSarif: false });
    const r = await runSast(project, makePlugin(project));
    const run = r.tools_run.find((t) => t.name === 'dotnet-analyzers');
    expect(run?.status).toBe('failed');
    expect(run?.reason).toContain('CS1002');
    expect((r as unknown as { coverage: string }).coverage).not.toBe('full');
  });

  it('a build that wrote no SARIF at all is not a clean result', async () => {
    const project = makeTempDir('sast-dotnet-');
    writeFileSync(join(project, 'App.csproj'), CSPROJ, 'utf8');
    mockDotnet({ writeSarif: false });
    const r = await runSast(project, makePlugin(project));
    expect(r.tools_run.find((t) => t.name === 'dotnet-analyzers')?.status).toBe('failed');
  });

  it('names the missing SDK when dotnet is absent', async () => {
    const project = makeTempDir('sast-dotnet-');
    writeFileSync(join(project, 'App.csproj'), CSPROJ, 'utf8');
    mockSemgrepOnPath();
    const r = await runSast(project, makePlugin(project));
    expect(r.tools_run.find((t) => t.name === 'dotnet-analyzers')?.status).toBe('skipped');
    expect(r.missing_tools).toContain('dotnet-sdk');
  });
});
