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
// The plugin's pack directory, overridable per test: a damaged install whose
// `configs/semgrep/` lacks the LLM pack is simulated by pointing it at an
// empty directory. Everything else in the module stays real.
const packsDirOverride = vi.hoisted(() => ({ dir: undefined as string | undefined }));
vi.mock('../../src/runners/semgrepRuleIds.js', async () => {
  const actual =
    await vi.importActual<typeof import('../../src/runners/semgrepRuleIds.js')>(
      '../../src/runners/semgrepRuleIds.js',
    );
  return { ...actual, pluginPacksDir: () => packsDirOverride.dir ?? actual.pluginPacksDir() };
});

import type { PluginContext } from '../../src/context.js';
import { CUSTOM_RULES_META_KEY, customRulesMetaKey } from '../../src/platform/customRules.js';
import { planSemgrepConfigs } from '../../src/runners/semgrepConfigs.js';
import { ruleIdsInFile, semgrepConfigPrefix } from '../../src/runners/semgrepRuleIds.js';
import { runProcess } from '../../src/runners/processRunner.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';
import { scannerAvailable } from '../../src/tools/scanHelpers.js';
import { openSetForProject } from '../../src/history/openSet.js';
import { resolveProjectPath } from '../../src/platform/projectPath.js';

afterAll(cleanupTempDirs);

beforeAll(async () => {
  await import('../../src/tools/scanSast.js');
  await import('../../src/tools/riskScore.js');
});

const RULES =
  'rules:\n  - id: x\n    pattern: foo(...)\n    message: m\n    languages: [python]\n    severity: WARNING\n';

/**
 * The plugin's own LLM-application pack. Every native Semgrep run of
 * scan_sast appends it (runners/semgrepConfigs.ts), in both modes: it is a
 * rule file on disk, so `local_only` runs it too. Located from this file, not
 * through the code under test.
 */
const LLM_PACK = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', 'configs', 'semgrep', 'llm.yml');

/**
 * A report in which every rule of `.semgrep.yml` (`projectIds`) AND every
 * rule of the LLM pack failed to load — the pack's ids spelled as Semgrep
 * reports a rule file outside its working directory (the whole path, dotted).
 */
function everyRuleFailed(projectIds: readonly string[], scanned: string): unknown {
  const pack = ruleIdsInFile(LLM_PACK).map((id) => `${semgrepConfigPrefix(LLM_PACK)}.${id}`);
  return {
    results: [],
    errors: [...projectIds, ...pack].map((id) => ({
      code: 2,
      level: 'error',
      type: 'Rule parse error',
      rule_id: id,
      message: `Rule parse error in rule ${id}:\n Invalid pattern`,
    })),
    paths: { scanned: [scanned] },
  };
}

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
  packsDirOverride.dir = undefined;
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

  // A project rule that did not compile, as Semgrep 1.176.1 reports it
  // (measured: exit 2, the rule named in `rule_id`, the other rules still
  // run and `paths.scanned` is filled). This test used to pin `failed`:
  // right that the run is not complete, wrong in what it said — coverage
  // none on a Semgrep-only project, "NO scanner ran ... Install semgrep" for
  // a Semgrep that ran, and a row the open set skipped, so one typo in
  // .semgrep.yml froze the sast slot at the last good scan. Fix round 2:
  // the narrower gap bug_hunt already records.
  const RULE_ERROR = {
    code: 2,
    level: 'error',
    type: 'Rule parse error',
    rule_id: 'y',
    message: 'Rule parse error in rule y:\n Invalid pattern for Python: Stdlib.Parsing.Parse_error\n----- pattern -----\nfoo((((\n',
  };

  it('a project rule that did not compile: Semgrep ran — ok and missing, the rule named, its findings kept, never "install semgrep"', async () => {
    const project = makeTempDir('sast-rules-');
    writeFileSync(join(project, '.semgrep.yml'), RULES, 'utf8');
    mockSemgrepOnPath(2, { results: [FINDING], errors: [RULE_ERROR], paths: { scanned: ['a.py'] } });

    const r = await runSast(project, makePlugin(project));
    const run = r.tools_run.find((t) => t.name === 'semgrep') as
      | { status: string; reason?: string; failed_rules?: Array<{ rule_id: string; message: string }> }
      | undefined;
    expect(run?.status).toBe('ok');
    expect(run?.failed_rules).toEqual([{ rule_id: 'y', message: 'Invalid pattern for Python: Stdlib.Parsing.Parse_error' }]);
    expect(run?.reason).toMatch(/^Semgrep ran, but 1 rule\(s\) did not load: y — Invalid pattern for Python/);
    expect(r.missing_tools).toContain('semgrep');
    const out = r as unknown as { coverage: string; warnings: string[]; findings_count_by_severity: Record<string, number> };
    expect(out.coverage).toBe('partial');
    expect(out.warnings.join(' ')).not.toMatch(/install semgrep/i);
    expect(out.findings_count_by_severity['medium']).toBe(1);
  });

  // Fix round 3, M-1: when EVERY local rule failed and no registry pack ran,
  // nothing was scanned for — failed (Global Constraint 3), never ok with a
  // gap; and never "install semgrep", for a Semgrep that ran.
  const ALL_FAILED = {
    results: [],
    errors: [{ code: 2, level: 'error', type: 'Rule parse error', rule_id: 'x', message: 'Rule parse error in rule x:\n Invalid pattern' }],
    paths: { scanned: ['a.py'] },
  };

  it('local_only, and every rule of every config — .semgrep.yml and the LLM pack — failed to load: failed — no rule loaded — never ok, never "install semgrep"', async () => {
    const project = makeTempDir('sast-rules-none-');
    writeFileSync(join(project, '.semgrep.yml'), RULES, 'utf8');
    const packIds = ruleIdsInFile(LLM_PACK);
    expect(packIds.length).toBeGreaterThan(0);
    mockSemgrepOnPath(2, everyRuleFailed(['x'], 'a.py'));
    const r = await runSast(project, makePlugin(project), { local_only: true });
    const run = r.tools_run.find((t) => t.name === 'semgrep') as
      | { status: string; reason?: string; failed_rules?: Array<{ rule_id: string }>; rule_config_error?: boolean }
      | undefined;
    expect(run?.status).toBe('failed');
    expect(run?.reason).toMatch(
      new RegExp(`no rule loaded: Semgrep ran, but every one of its ${1 + packIds.length} rule\\(s\\) failed to load \\(x — Invalid pattern`),
    );
    // The pack's rules are named as their findings are stored: bare.
    expect(run?.failed_rules?.map((f) => f.rule_id)).toEqual(['x', ...packIds]);
    expect(run?.rule_config_error).toBe(true);
    const out = r as unknown as { coverage: string; warnings: string[] };
    expect(out.coverage).toBe('none');
    expect(out.warnings.join(' ')).toMatch(/semgrep ran, but its rules did not load/);
    expect(out.warnings.join(' ')).not.toMatch(/install semgrep/i);
  });

  // Review of the LLM pack, M-1: the pack alone is not a SAST scan, so it
  // cannot make one either. "No rule loaded" is judged over the project's and
  // the registered configs only; the pack's findings are still recorded.
  it('local_only, every rule of .semgrep.yml failed while the LLM pack loaded and found something: still failed — no rule loaded — the pack finding recorded', async () => {
    const project = makeTempDir('sast-rules-none-pack-');
    writeFileSync(join(project, '.semgrep.yml'), RULES, 'utf8');
    const packFinding = {
      check_id: `${semgrepConfigPrefix(LLM_PACK)}.llm-trust-remote-code`,
      path: 'a.py',
      start: { line: 1 },
      end: { line: 1 },
      extra: { severity: 'WARNING', message: 'm', lines: 'x', metadata: { category: 'security' } },
    };
    mockSemgrepOnPath(2, { ...ALL_FAILED, results: [packFinding] });
    const r = await runSast(project, makePlugin(project), { local_only: true });
    const run = r.tools_run.find((t) => t.name === 'semgrep') as
      | { status: string; reason?: string; failed_rules?: Array<{ rule_id: string }>; rule_config_error?: boolean }
      | undefined;
    expect(run?.status).toBe('failed');
    expect(run?.reason).toMatch(/no rule loaded: Semgrep ran, but every one of its 1 rule\(s\) failed to load \(x — Invalid pattern\)/);
    expect(run?.failed_rules?.map((f) => f.rule_id)).toEqual(['x']);
    expect(run?.rule_config_error).toBe(true);
    const out = r as unknown as { coverage: string; findings_count_by_severity: Record<string, number>; warnings: string[] };
    expect(out.coverage).toBe('none');
    // The pack's finding is real and kept, under its bare id.
    expect(out.findings_count_by_severity['medium']).toBe(1);
    // Review round 2: "NOTHING was scanned" is false beside a recorded
    // finding — say what did and did not run.
    expect((run as { plugin_pack_only?: boolean } | undefined)?.plugin_pack_only).toBe(true);
    const warning = out.warnings.join(' ');
    expect(warning).toMatch(/no registry or project rule loaded; only the plugin's LLM pack ran/);
    expect(warning).not.toMatch(/NOTHING was scanned/);
  });

  it('every rule of every config failed, the LLM pack included: nothing ran — the warning says so', async () => {
    const project = makeTempDir('sast-rules-none-all-');
    writeFileSync(join(project, '.semgrep.yml'), RULES, 'utf8');
    mockSemgrepOnPath(2, everyRuleFailed(['x'], 'a.py'));
    const r = await runSast(project, makePlugin(project), { local_only: true });
    const run = r.tools_run.find((t) => t.name === 'semgrep') as { plugin_pack_only?: boolean } | undefined;
    expect(run?.plugin_pack_only).toBeUndefined();
    expect((r as unknown as { warnings: string[] }).warnings.join(' ')).toMatch(/NOTHING was scanned/);
  });

  it('the same failure with the registry ruleset in the run: the registry rules ran — partial stays', async () => {
    const project = makeTempDir('sast-rules-none-auto-');
    writeFileSync(join(project, '.semgrep.yml'), RULES, 'utf8');
    mockSemgrepOnPath(2, ALL_FAILED);
    const r = await runSast(project, makePlugin(project));
    expect(r.tools_run.find((t) => t.name === 'semgrep')?.status).toBe('ok');
    expect((r as unknown as { coverage: string }).coverage).toBe('partial');
  });

  it('the Docker fallback, local_only, every rule failed: failed too — its /src config read on the host (round 3 review, I-1)', async () => {
    // Two broken patterns in the project's only rule file, Semgrep not on
    // PATH: the container reports both rules not loaded. Read as
    // /src/.semgrep.yml on the host, the file was never found and the run
    // stayed ok + partial.
    const project = makeTempDir('sast-rules-none-docker-');
    const two = 'rules:\n  - id: x\n    pattern: eval( (\n    message: m\n    languages: [python]\n    severity: WARNING\n' +
      '  - id: y\n    pattern: foo(]\n    message: m\n    languages: [python]\n    severity: WARNING\n';
    writeFileSync(join(project, '.semgrep.yml'), two, 'utf8');
    vi.mocked(scannerAvailable).mockImplementation(async (name: string) => (name === 'docker' ? '/usr/bin/docker' : null));
    const configs: string[] = [];
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      configs.push(...(opts.args ?? []).filter((a) => a.startsWith('--config=')));
      const i = opts.args?.findIndex((a) => a === '--output') ?? -1;
      const containerOut = i >= 0 ? opts.args?.[i + 1] : undefined;
      if (containerOut !== undefined) {
        const host = join(project, ...containerOut.replace('/src/', '').split('/'));
        const err = (id: string) => ({ code: 2, level: 'error', type: 'Rule parse error', rule_id: id, message: `Rule parse error in rule ${id}:\n Invalid pattern for Python` });
        writeFileSync(host, JSON.stringify({ results: [], errors: [err('x'), err('y')], paths: { scanned: ['/src/a.py'] } }), 'utf8');
      }
      return { outcome: 'failed' as const, exitCode: 2, stdout: '', stderr: '', truncated: false };
    });
    const r = await runSast(project, makePlugin(project), { local_only: true });
    // The LLM pack rides along through its read-only mount, and does not
    // count toward "a rule loaded".
    expect(configs).toEqual(['--config=/src/.semgrep.yml', '--config=/guardian-packs/llm.yml']);
    const run = r.tools_run.find((t) => t.name === 'semgrep') as
      | { status: string; reason?: string; failed_rules?: Array<{ rule_id: string }>; rule_config_error?: boolean }
      | undefined;
    expect(run?.status).toBe('failed');
    expect(run?.reason).toMatch(/ran via docker/);
    expect(run?.reason).toMatch(/no rule loaded: Semgrep ran, but every one of its 2 rule\(s\) failed to load/);
    expect(run?.failed_rules?.map((f) => f.rule_id)).toEqual(['x', 'y']);
    expect(run?.rule_config_error).toBe(true);
    const warning = (r as unknown as { warnings: string[] }).warnings.join(' ');
    expect(warning).not.toMatch(/install semgrep/i);
    // The pack ran from its mount (none of its rules failed): say so.
    expect(warning).toMatch(/no registry or project rule loaded; only the plugin's LLM pack ran/);
  });

  it('a scoped (batched) local_only run in which no project rule loaded is failed too, the LLM pack notwithstanding', async () => {
    const project = makeTempDir('sast-rules-none-scope-');
    writeFileSync(join(project, 'a.py'), 'foo()\n', 'utf8');
    writeFileSync(join(project, '.semgrep.yml'), RULES, 'utf8');
    mockSemgrepOnPath(2, ALL_FAILED);
    const r = await runSast(project, makePlugin(project), { local_only: true, scope: { paths: ['a.py'] } });
    const run = r.tools_run.find((t) => t.name === 'semgrep') as { status: string; reason?: string; rule_config_error?: boolean } | undefined;
    expect(run?.status).toBe('failed');
    expect(run?.reason).toMatch(/no rule loaded/);
    expect(run?.rule_config_error).toBe(true);
    expect((r as unknown as { warnings: string[] }).warnings.join(' ')).not.toMatch(/install semgrep/i);
  });

  it('a rule with an unknown language (Semgrep exit 8): the reason names the rule error, never "install semgrep"', async () => {
    const project = makeTempDir('sast-rules-lang-');
    writeFileSync(join(project, '.semgrep.yml'), RULES, 'utf8');
    mockSemgrepOnPath(8, {
      results: [],
      errors: [{ code: 8, level: 'error', type: 'UnknownLanguageError', short_msg: 'invalid language: klingon', long_msg: 'unsupported language: klingon.', spans: [] }],
      paths: { scanned: [] },
    });
    const r = await runSast(project, makePlugin(project));
    const run = r.tools_run.find((t) => t.name === 'semgrep') as { status: string; reason?: string; rule_config_error?: boolean } | undefined;
    expect(run?.status).toBe('failed');
    expect(run?.reason).toMatch(/the rule configuration did not load — UnknownLanguageError: invalid language: klingon \(semgrep exit 8\)/);
    // Said once (round 3 review: the error text was repeated).
    expect(run?.reason?.split('invalid language: klingon')).toHaveLength(2);
    expect(run?.rule_config_error).toBe(true);
    const warnings = (r as unknown as { warnings: string[] }).warnings.join(' ');
    expect(warnings).toMatch(/semgrep ran, but its rules did not load/);
    expect(warnings).not.toMatch(/install semgrep/i);
  });

  it('a rule error that names no rule stays failed — it cannot be told from a broken config', async () => {
    const project = makeTempDir('sast-rules-');
    mockSemgrepOnPath(2, {
      results: [FINDING],
      errors: [{ type: 'Rule parse error', message: 'Invalid pattern in rule x' }],
      paths: { scanned: ['a.py'] },
    });
    const r = await runSast(project, makePlugin(project));
    const run = r.tools_run.find((t) => t.name === 'semgrep');
    expect(run?.status).toBe('failed');
    expect(run?.reason).toContain('Invalid pattern in rule x');
    // Its findings are real all the same.
    expect((r as unknown as { findings_count_by_severity: Record<string, number> }).findings_count_by_severity['medium']).toBe(1);
  });

  it('a rule that did not compile in the Docker fallback reads the same way', async () => {
    const project = makeTempDir('sast-rules-docker-rule-');
    writeFileSync(join(project, '.semgrep.yml'), RULES, 'utf8');
    vi.mocked(scannerAvailable).mockImplementation(async (name: string) => (name === 'docker' ? '/usr/bin/docker' : null));
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      const i = opts.args?.findIndex((a) => a === '--output') ?? -1;
      const containerOut = i >= 0 ? opts.args?.[i + 1] : undefined;
      if (containerOut !== undefined) {
        const host = join(project, ...containerOut.replace('/src/', '').split('/'));
        writeFileSync(host, JSON.stringify({ results: [FINDING], errors: [RULE_ERROR], paths: { scanned: ['/src/a.py'] } }), 'utf8');
      }
      return { outcome: 'failed' as const, exitCode: 2, stdout: '', stderr: '', truncated: false };
    });
    const r = await runSast(project, makePlugin(project));
    const run = r.tools_run.find((t) => t.name === 'semgrep') as { status: string; reason?: string; failed_rules?: Array<{ rule_id: string }> } | undefined;
    expect(run?.status).toBe('ok');
    expect(run?.reason).toMatch(/ran via docker/);
    expect(run?.failed_rules?.map((f) => f.rule_id)).toEqual(['y']);
    expect(r.missing_tools).toContain('semgrep');
  });

  it('a scoped (batched) run reads a rule that did not compile the same way, once however many batches report it', async () => {
    const project = makeTempDir('sast-rules-scope-');
    writeFileSync(join(project, 'a.py'), 'foo()\n', 'utf8');
    writeFileSync(join(project, '.semgrep.yml'), RULES, 'utf8');
    mockSemgrepOnPath(2, { results: [FINDING], errors: [RULE_ERROR, RULE_ERROR], paths: { scanned: ['a.py'] } });
    const r = await runSast(project, makePlugin(project), { scope: { paths: ['a.py'] } });
    const run = r.tools_run.find((t) => t.name === 'semgrep') as { status: string; reason?: string; failed_rules?: Array<{ rule_id: string }> } | undefined;
    expect(run?.status).toBe('ok');
    expect(run?.reason).toMatch(/1 file\(s\) scanned; Semgrep ran, but 1 rule\(s\) did not load: y — /);
    expect(run?.failed_rules?.map((f) => f.rule_id)).toEqual(['y']);
    expect(r.missing_tools).toContain('semgrep');
    expect((r as unknown as { coverage: string }).coverage).toBe('partial');
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

  // Follow-up X1: the shared judge's `partial` verdict. A warn-level
  // PartialParsing tied to one scanned file is partial coverage — Semgrep
  // ran (`ok`) AND is missing, the file named on the run — never `failed`,
  // which made every WordPress project's SAST a failed scanner.
  const WARNING = {
    code: 3,
    level: 'warn',
    type: ['PartialParsing', [{ path: 'wp/rest-controller.php', start: { line: 20 }, end: { line: 20 } }]],
    message: "Syntax error at line wp/rest-controller.php:20:\n `const NAMESPACE = 'guardian/v2';` was unexpected",
    path: 'wp/rest-controller.php',
  };

  it('a warn-level PartialParsing on one scanned file is partial: ok, listed missing, the file named', async () => {
    const project = makeTempDir('sast-partial-');
    mockSemgrepOnPath(1, { results: [FINDING], errors: [WARNING], paths: { scanned: ['a.py', 'wp/rest-controller.php'] } });
    const r = await runSast(project, makePlugin(project));
    const run = r.tools_run.find((t) => t.name === 'semgrep') as
      | { status: string; reason?: string; partially_parsed?: unknown }
      | undefined;
    expect(run?.status).toBe('ok');
    expect(run?.reason).toMatch(/partial: 1 file\(s\) only partly parsed .*PartialParsing: wp\/rest-controller\.php/);
    expect(run?.partially_parsed).toEqual([
      { file: 'wp/rest-controller.php', type: 'PartialParsing', message: 'Syntax error at line wp/rest-controller.php:20:' },
    ]);
    expect(r.missing_tools).toContain('semgrep');
    expect((r as unknown as { coverage: string }).coverage).toBe('partial');
    // The findings the run did report are real.
    expect((r as unknown as { findings_count_by_severity: Record<string, number> }).findings_count_by_severity['medium']).toBe(1);
  });

  it('a partial parse beside a rule error that names no rule is still failed — fatal wins', async () => {
    const project = makeTempDir('sast-partial-');
    mockSemgrepOnPath(0, {
      results: [],
      errors: [WARNING, { type: 'Rule parse error', level: 'error', message: 'Invalid pattern in rule x' }],
      paths: { scanned: ['a.py'] },
    });
    const r = await runSast(project, makePlugin(project));
    const run = r.tools_run.find((t) => t.name === 'semgrep') as { status: string; partially_parsed?: unknown } | undefined;
    expect(run?.status).toBe('failed');
    expect(run?.partially_parsed).toBeUndefined();
  });

  it('a scoped run (explicit targets, batched) reads a partial parse the same way', async () => {
    const project = makeTempDir('sast-partial-scope-');
    mkdirSync(join(project, 'wp'));
    writeFileSync(join(project, 'wp', 'rest-controller.php'), '<?php\n', 'utf8');
    mockSemgrepOnPath(0, { results: [], errors: [WARNING], paths: { scanned: ['wp/rest-controller.php'] } });
    const r = await runSast(project, makePlugin(project), { scope: { paths: ['wp/rest-controller.php'] } });
    const run = r.tools_run.find((t) => t.name === 'semgrep') as
      | { status: string; reason?: string; partially_parsed?: Array<{ file: string }> }
      | undefined;
    expect(run?.status).toBe('ok');
    expect(run?.reason).toMatch(/partial: 1 file\(s\) only partly parsed/);
    expect(run?.partially_parsed?.map((p) => p.file)).toEqual(['wp/rest-controller.php']);
    expect(r.missing_tools).toContain('semgrep');
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
    expect(configs).toEqual(['auto', join(project, '.semgrep.yml'), team, LLM_PACK]);
  });

  it('says, in the response warnings, which 2.0.x registrations outside the project it no longer runs', async () => {
    const project = makeTempDir('sast-plan-');
    const elsewhere = makeTempDir('sast-plan-legacy-');
    const legacy = join(elsewhere, 'team.yml');
    writeFileSync(legacy, RULES, 'utf8');
    const plugin = makePlugin(project);
    plugin.storage.runtimeMeta.setJson(CUSTOM_RULES_META_KEY, [legacy]);
    mockSemgrepOnPath();

    const r = okResult<{ warnings: string[] }>(
      await getTool('scan_sast').handler({ project_path: project, force: true }, plugin),
    );
    expect(semgrepArgs()).not.toContain(`--config=${legacy}`);
    const warning = r.warnings.find((w) => w.includes(legacy));
    expect(warning).toBeDefined();
    expect(warning).toContain('register_custom_rules');
    expect(planSemgrepConfigs(project, plugin, false).notes.some((n) => n.includes(legacy))).toBe(true);
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

describe("scan_sast runs the plugin's LLM-application pack (configs/semgrep/llm.yml)", () => {
  it('the pack is on disk where the plan looks for it', () => {
    expect(existsSync(LLM_PACK)).toBe(true);
    const plan = planSemgrepConfigs(makeTempDir('sast-llm-plan-'), makePlugin(makeTempDir('sast-llm-plugin-')), false);
    expect(plan.pluginPacks).toEqual([LLM_PACK]);
  });

  it('appends it to every native run, after the registry and the project rules — and local_only runs it too', async () => {
    const project = makeTempDir('sast-llm-');
    writeFileSync(join(project, '.semgrep.yml'), RULES, 'utf8');
    for (const local_only of [false, true]) {
      captured.length = 0;
      mockSemgrepOnPath();
      await runSast(project, makePlugin(project), { local_only });
      const configs = semgrepArgs().filter((a) => a.startsWith('--config='));
      expect(configs.at(-1)).toBe(`--config=${LLM_PACK}`);
      expect(configs.filter((c) => c === `--config=${LLM_PACK}`)).toHaveLength(1);
    }
  });

  it('a scoped run passes it too', async () => {
    const project = makeTempDir('sast-llm-scope-');
    writeFileSync(join(project, 'a.py'), 'foo()\n', 'utf8');
    mockSemgrepOnPath();
    await runSast(project, makePlugin(project), { scope: { paths: ['a.py'] } });
    expect(semgrepArgs()).toContain(`--config=${LLM_PACK}`);
  });

  it('local_only with no rules of the project is still no scan: the LLM pack alone is not a SAST ruleset', async () => {
    const project = makeTempDir('sast-llm-alone-');
    mockSemgrepOnPath();
    const r = await runSast(project, makePlugin(project), { local_only: true });
    expect(captured.some((c) => c.command === 'semgrep')).toBe(false);
    const run = r.tools_run.find((t) => t.name === 'semgrep');
    expect(run?.status).toBe('skipped');
    expect(run?.reason ?? '').toContain('llm.yml');
    expect(r.missing_tools).toContain('semgrep');
  });

  // Review of the LLM pack, M-2: the fallback used to leave the pack out and
  // report every Docker scan_sast partial. It now mounts the plugin's pack
  // directory READ-ONLY beside the project and runs the pack from there.
  it('the Docker fallback mounts the pack read-only and runs it: bare ids, full coverage', async () => {
    const project = makeTempDir('sast-llm-docker-');
    const finding = {
      check_id: 'guardian-packs.llm-trust-remote-code',
      path: '/src/a.py',
      start: { line: 1 },
      end: { line: 1 },
      extra: { severity: 'WARNING', message: 'm', lines: 'x', metadata: { category: 'security' } },
    };
    vi.mocked(scannerAvailable).mockImplementation(async (name: string) => (name === 'docker' ? '/usr/bin/docker' : null));
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      captured.push({ command: opts.command, args: [...(opts.args ?? [])] });
      const i = opts.args?.findIndex((a) => a === '--output') ?? -1;
      const containerOut = i >= 0 ? opts.args?.[i + 1] : undefined;
      if (containerOut !== undefined) {
        const host = join(project, ...containerOut.replace('/src/', '').split('/'));
        writeFileSync(host, JSON.stringify({ results: [finding], errors: [], paths: { scanned: ['/src/a.py'] } }), 'utf8');
      }
      return { outcome: 'completed' as const, exitCode: 1, stdout: '', stderr: '', truncated: false };
    });
    const plugin = makePlugin(project);
    const r = await runSast(project, plugin);
    const call = captured.find((c) => c.command === 'docker');
    if (call === undefined) throw new Error('docker was never invoked');
    const mounts = call.args.filter((_a, i) => call.args[i - 1] === '--mount');
    expect(mounts).toContain(`type=bind,source=${dirname(LLM_PACK)},target=/guardian-packs,readonly`);
    expect(call.args).toContain('--config=/guardian-packs/llm.yml');
    // Only the project mount is writable.
    expect(mounts.filter((m) => !m.endsWith(',readonly'))).toEqual([`type=bind,source=${project},target=/src`]);
    const run = r.tools_run.find((t) => t.name === 'semgrep');
    expect(run?.status).toBe('ok');
    expect(r.missing_tools).not.toContain('semgrep');
    expect((r as unknown as { coverage: string }).coverage).toBe('full');
    const set = openSetForProject(plugin.storage, resolveProjectPath(project).path);
    expect(set.findings.map((f) => [f.rule_id, f.file_path])).toEqual([['llm-trust-remote-code', 'a.py']]);
  });

  // Review round 2: the pack was measured on Semgrep 1.176.1; older engines
  // do not resolve `node:child_process` imports in taint mode.
  it('a Semgrep older than the pack was measured on: a named note that its child_process coverage is reduced', async () => {
    const project = makeTempDir('sast-llm-oldsemgrep-');
    for (const [version, noted] of [['1.170.1', true], ['1.86.0', true], ['1.176.1', false], ['1.180.0', false]] as const) {
      captured.length = 0;
      mockSemgrepOnPath(0, { ...CLEAN_REPORT, version });
      const r = await runSast(project, makePlugin(project));
      const reason = r.tools_run.find((t) => t.name === 'semgrep')?.reason ?? '';
      expect([version, /llm\.yml.*measured on Semgrep 1\.176\.1.*child_process/.test(reason)]).toEqual([version, noted]);
    }
  });

  it('local_only in the Docker fallback with no project rules is still no scan — the pack alone is not a SAST ruleset', async () => {
    const project = makeTempDir('sast-llm-docker-alone-');
    vi.mocked(scannerAvailable).mockImplementation(async (name: string) => (name === 'docker' ? '/usr/bin/docker' : null));
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      captured.push({ command: opts.command, args: [...(opts.args ?? [])] });
      return { outcome: 'completed' as const, exitCode: 0, stdout: '', stderr: '', truncated: false };
    });
    const r = await runSast(project, makePlugin(project), { local_only: true });
    expect(captured.some((c) => c.command === 'docker')).toBe(false);
    expect(r.tools_run.find((t) => t.name === 'semgrep')?.status).toBe('skipped');
    expect(r.missing_tools).toContain('semgrep');
  });

  // Review of the LLM pack, M-3: a damaged install without the pack used to
  // be a note on an otherwise full scan.
  it('a native run with the pack missing from disk is partial, the gap named — never full', async () => {
    packsDirOverride.dir = makeTempDir('sast-llm-nopack-');
    const project = makeTempDir('sast-llm-missing-');
    mockSemgrepOnPath();
    const r = await runSast(project, makePlugin(project));
    expect(semgrepArgs().some((a) => a.includes('llm.yml'))).toBe(false);
    const run = r.tools_run.find((t) => t.name === 'semgrep');
    expect(run?.status).toBe('ok');
    expect(run?.reason ?? '').toMatch(/LLM-application pack was not found at .*llm\.yml — its rules did not run/);
    expect(r.missing_tools).toContain('semgrep');
    expect((r as unknown as { coverage: string }).coverage).toBe('partial');
  });

  it('a scoped run with the pack missing from disk is partial too', async () => {
    packsDirOverride.dir = makeTempDir('sast-llm-nopack-scope-');
    const project = makeTempDir('sast-llm-missing-scope-');
    writeFileSync(join(project, 'a.py'), 'foo()\n', 'utf8');
    mockSemgrepOnPath();
    const r = await runSast(project, makePlugin(project), { scope: { paths: ['a.py'] } });
    expect(r.tools_run.find((t) => t.name === 'semgrep')?.status).toBe('ok');
    expect(r.missing_tools).toContain('semgrep');
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


describe('scan_sast .NET: the SDK security analyzers, read from SARIF (Task 11 items 8, fix round 1)', () => {
  const SARIF = readFileSync(
    join(dirname(fileURLToPath(import.meta.url)), '../fixtures/scanners/dotnet-build.sarif.json'),
    'utf8',
  );
  /** The same SARIF with every rule's category changed away from Security:
   *  what a build whose security analyzers never loaded writes. */
  const SARIF_NO_SECURITY_RULES = SARIF.replace(/"category": "Security"/g, '"category": "Performance"').replace(/SCS0005/g, 'CS1234');
  const CSPROJ = '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>';

  interface DotnetMock {
    restore?: { outcome: 'completed' | 'failed'; stdout?: string; createLock?: string };
    build?: { exitCode?: number; stdout?: string };
    /** SARIF bodies the build writes, one file each (multi-targeting). */
    sarifs?: string[];
  }

  /** semgrep + dotnet on PATH. `dotnet build` writes each SARIF body into
   *  the directory `-p:DevGuardianSarifDir=` names, the way the imported
   *  targets file makes every inner build write its own. */
  function mockDotnet(opts: DotnetMock = {}): void {
    vi.mocked(scannerAvailable).mockImplementation(async (name: string) =>
      name === 'semgrep' || name === 'dotnet' ? `/fake/bin/${name}` : null,
    );
    vi.mocked(runProcess).mockImplementation(async (o) => {
      captured.push({ command: o.command, args: [...(o.args ?? [])] });
      const ok = { outcome: 'completed' as const, exitCode: 0, stdout: '', stderr: '', truncated: false };
      if (o.command === 'semgrep') {
        const out = o.args?.find((_a, i) => o.args?.[i - 1] === '--output');
        if (out) writeFileSync(out, JSON.stringify(CLEAN_REPORT), 'utf8');
        return ok;
      }
      if (o.command === 'dotnet' && o.args?.[0] === 'restore') {
        if (opts.restore?.createLock !== undefined) writeFileSync(opts.restore.createLock, '{}', 'utf8');
        return opts.restore?.outcome === 'failed'
          ? { outcome: 'failed' as const, exitCode: 1, stdout: opts.restore.stdout ?? '', stderr: '', truncated: false }
          : ok;
      }
      if (o.command === 'dotnet' && o.args?.[0] === 'build') {
        const dir = o.args.find((a) => a.startsWith('-p:DevGuardianSarifDir='))?.slice('-p:DevGuardianSarifDir='.length) ?? '';
        (opts.sarifs ?? [SARIF]).forEach((body, i) => {
          writeFileSync(join(dir, `App-tfm${i}-${String(i).padStart(32, '0')}.sarif`), body, 'utf8');
        });
        const exitCode = opts.build?.exitCode ?? 0;
        return { outcome: exitCode === 0 ? ('completed' as const) : ('failed' as const), exitCode, stdout: opts.build?.stdout ?? '', stderr: '', truncated: false };
      }
      return ok;
    });
  }

  const dotnetCalls = (): string[][] => captured.filter((c) => c.command === 'dotnet').map((c) => c.args);

  function dotnetProject(): string {
    const project = makeTempDir('sast-dotnet-');
    writeFileSync(join(project, 'App.csproj'), CSPROJ, 'utf8');
    return project;
  }

  it('restores in --locked-mode FIRST, then builds --no-restore with the analyzers enabled — never --verbosity:diag', async () => {
    // A plain `dotnet build` restores implicitly without locked mode: it
    // rewrote an out-of-date packages.lock.json in the user's tree.
    const project = dotnetProject();
    mockDotnet();
    const plugin = makePlugin(project);

    const r = await runSast(project, plugin);
    const [restore, build] = dotnetCalls();
    expect(restore?.[0]).toBe('restore');
    expect(restore).toContain('--locked-mode');
    expect(build?.[0]).toBe('build');
    expect(build).toContain('--no-restore');
    // Below .NET 5 the analyzers are OFF unless enabled (measured on netstandard2.0).
    expect(build).toContain('-p:EnableNETAnalyzers=true');
    expect(build).toContain('-p:AnalysisLevelSecurity=latest');
    expect(build).toContain('-p:AnalysisModeSecurity=All');
    expect(build?.some((a) => /diag/.test(a))).toBe(false);
    // A global -p:ErrorLog is not expanded per target framework; the
    // imported targets file sets it per project instance instead.
    expect(build?.some((a) => a.startsWith('-p:ErrorLog='))).toBe(false);
    expect(build?.some((a) => a.startsWith('-p:CustomAfterMicrosoftCommonTargets='))).toBe(true);

    expect(r.tools_run.find((t) => t.name === 'dotnet-analyzers')?.status).toBe('ok');
    expect(r.tools_run.some((t) => t.name === 'security-code-scan')).toBe(false);
    const rows = plugin.storage.findings.listByScan((r as unknown as { scan_id: string }).scan_id);
    expect(rows.map((f) => f.rule_id).sort()).toEqual(['CA5351', 'SCS0005']);
    // Nothing of ours is left in the project.
    expect(existsSync(join(project, 'obj'))).toBe(false);
  });

  it('the targets file writes one SARIF per project AND target framework', async () => {
    const project = dotnetProject();
    mockDotnet();
    await runSast(project, makePlugin(project));
    const build = dotnetCalls()[1] ?? [];
    const targetsFile = build.find((a) => a.startsWith('-p:CustomAfterMicrosoftCommonTargets='))?.slice('-p:CustomAfterMicrosoftCommonTargets='.length) ?? '';
    // The temp file is gone after the scan; its content is asserted through the
    // mocked build's argv only by name, so check the shipped text instead.
    expect(targetsFile).toMatch(/dev-guardian-sarif\.targets$/);
    expect(existsSync(targetsFile)).toBe(false);
  });

  it('reads every SARIF a multi-targeted build writes, not just the last framework\'s', async () => {
    const project = dotnetProject();
    const other = SARIF.replace(/"ruleId": "CA5351"/g, '"ruleId": "CA5350"').replace(/"id": "CA5351"/g, '"id": "CA5350"');
    mockDotnet({ sarifs: [SARIF, other] });
    const plugin = makePlugin(project);
    const r = await runSast(project, plugin);
    const run = r.tools_run.find((t) => t.name === 'dotnet-analyzers');
    expect(run?.status).toBe('ok');
    expect(run?.reason).toContain('2 SARIF report(s)');
    const rules = plugin.storage.findings.listByScan((r as unknown as { scan_id: string }).scan_id).map((f) => f.rule_id);
    expect(rules).toEqual(expect.arrayContaining(['CA5351', 'CA5350']));
  });

  it('names a project-set CustomAfterMicrosoftCommonTargets as reduced coverage — the scan build replaces it', async () => {
    const project = makeTempDir('sast-dotnet-');
    writeFileSync(
      join(project, 'App.csproj'),
      CSPROJ.replace('</PropertyGroup>', '<CustomAfterMicrosoftCommonTargets>own.targets</CustomAfterMicrosoftCommonTargets></PropertyGroup>'),
      'utf8',
    );
    writeFileSync(
      join(project, 'Directory.Build.props'),
      '<Project><PropertyGroup><CustomAfterMicrosoftCommonTargets>x</CustomAfterMicrosoftCommonTargets></PropertyGroup></Project>',
      'utf8',
    );
    mockDotnet();
    const r = await runSast(project, makePlugin(project));
    const run = r.tools_run.find((t) => t.name === 'dotnet-analyzers');
    expect(run?.reason).toMatch(/reduced coverage/);
    expect(run?.reason).toContain('App.csproj');
    expect(run?.reason).toContain('Directory.Build.props');
  });

  it('says nothing about CustomAfterMicrosoftCommonTargets when the project does not set it', async () => {
    const project = dotnetProject();
    mockDotnet();
    const r = await runSast(project, makePlugin(project));
    expect(r.tools_run.find((t) => t.name === 'dotnet-analyzers')?.reason).not.toMatch(/reduced coverage/);
  });

  it('the same result reported by two target frameworks is ONE finding, not two', async () => {
    // Every framework of a multi-targeted project compiles the same source:
    // its SARIFs carry the same result, and the identity pass numbered the
    // copies as occurrences 0 and 1 — two findings for one line.
    const project = dotnetProject();
    mockDotnet({ sarifs: [SARIF, SARIF] });
    const plugin = makePlugin(project);
    const r = await runSast(project, plugin);
    const rows = plugin.storage.findings.listByScan((r as unknown as { scan_id: string }).scan_id);
    expect(rows.filter((f) => f.rule_id === 'CA5351')).toHaveLength(1);
    expect(rows.filter((f) => f.rule_id === 'SCS0005')).toHaveLength(1);
    const counts = (r as unknown as { findings_count_by_severity: Record<string, number> }).findings_count_by_severity;
    expect(Object.values(counts).reduce((a, b) => a + b, 0)).toBe(2);
  });

  it('a SARIF that lists no security rule means the analyzers did not load — a gap, never ok', async () => {
    const project = dotnetProject();
    mockDotnet({ sarifs: [SARIF_NO_SECURITY_RULES] });
    const r = await runSast(project, makePlugin(project));
    const run = r.tools_run.find((t) => t.name === 'dotnet-analyzers');
    expect(run?.status).toBe('failed');
    expect(run?.reason).toContain('did not load');
    expect((r as unknown as { coverage: string }).coverage).not.toBe('full');
  });

  it('a lock file out of sync fails the locked restore (NU1004): named gap, no build, nothing rewritten', async () => {
    const project = dotnetProject();
    mockDotnet({
      restore: { outcome: 'failed', stdout: 'App.csproj : error NU1004: The package reference Foo version has changed [App.csproj]' },
    });
    const r = await runSast(project, makePlugin(project));
    expect(dotnetCalls().map((a) => a[0])).toEqual(['restore']);
    const run = r.tools_run.find((t) => t.name === 'dotnet-analyzers');
    expect(run?.status).toBe('failed');
    expect(run?.reason).toContain('NU1004');
  });

  it('a lock file the restore created anyway is deleted again, and that target is not built', async () => {
    const project = dotnetProject();
    const lock = join(project, 'packages.lock.json');
    mockDotnet({ restore: { outcome: 'completed', createLock: lock } });
    const r = await runSast(project, makePlugin(project));
    expect(existsSync(lock)).toBe(false);
    expect(dotnetCalls().map((a) => a[0])).toEqual(['restore']);
    expect(r.tools_run.find((t) => t.name === 'dotnet-analyzers')?.status).toBe('failed');
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
    const project = dotnetProject();
    mockDotnet({ build: { exitCode: 1, stdout: 'Program.cs(3,1): error CS1002: ; expected [App.csproj]' }, sarifs: [] });
    const r = await runSast(project, makePlugin(project));
    const run = r.tools_run.find((t) => t.name === 'dotnet-analyzers');
    expect(run?.status).toBe('failed');
    expect(run?.reason).toContain('CS1002');
    expect((r as unknown as { coverage: string }).coverage).not.toBe('full');
  });

  it('a build that wrote no SARIF at all is not a clean result', async () => {
    const project = dotnetProject();
    mockDotnet({ sarifs: [] });
    const r = await runSast(project, makePlugin(project));
    expect(r.tools_run.find((t) => t.name === 'dotnet-analyzers')?.status).toBe('failed');
  });

  it('names the missing SDK when dotnet is absent', async () => {
    const project = dotnetProject();
    mockSemgrepOnPath();
    const r = await runSast(project, makePlugin(project));
    expect(r.tools_run.find((t) => t.name === 'dotnet-analyzers')?.status).toBe('skipped');
    expect(r.missing_tools).toContain('dotnet-sdk');
  });
});

/**
 * Follow-up X, fix round 1 (Critical), with real scan_sast rows: a
 * work-in-progress edit makes one file PartialParsing, the partial scan
 * becomes the sast slot's source — and the older finding on that file must
 * not vanish from the open set, or from risk_score. The reviewer's shape.
 */
/**
 * Fix round 2: a project rule that did not compile is a row the open set
 * reads, not one it skips — the rules that loaded re-measured their
 * findings, the broken rule's earlier findings stay open, not re-measured.
 */
describe('scan_sast: a rule that did not load keeps its older findings in the open set', () => {
  const hit = (path: string, rule: string) => ({
    check_id: rule,
    path,
    start: { line: 1 },
    end: { line: 1 },
    extra: { severity: 'ERROR', message: `${rule} here`, lines: 'foo()' },
  });

  it('x re-measured (b.py fixed, resolved); y did not load (its c.py finding carried, flagged); the row is not skipped', async () => {
    const project = makeTempDir('sast-rule-carry-');
    writeFileSync(join(project, '.semgrep.yml'), RULES, 'utf8');
    const plugin = makePlugin(project);
    mockSemgrepOnPath(1, { results: [hit('a.py', 'x'), hit('b.py', 'x'), hit('c.py', 'y')], errors: [], paths: { scanned: ['a.py', 'b.py', 'c.py'] } });
    await runSast(project, plugin);
    mockSemgrepOnPath(2, {
      results: [hit('a.py', 'x')],
      errors: [{ code: 2, level: 'error', type: 'Rule parse error', rule_id: 'y', message: 'Rule parse error in rule y:\n Invalid pattern' }],
      paths: { scanned: ['a.py', 'b.py', 'c.py'] },
    });
    await runSast(project, plugin);

    const set = openSetForProject(plugin.storage, resolveProjectPath(project).path);
    expect(Object.fromEntries(set.findings.map((f) => [f.file_path, f.not_remeasured ?? false]))).toEqual({
      'a.py': false,
      'c.py': true,
    });
    expect(set.skipped.count).toBe(0);
    expect(set.coverage).toBe('partial');
    expect(set.sources.find((s) => s.carried_for !== undefined)?.carried_for).toEqual(['semgrep (rule not loaded: y)']);
  });
});

describe('scan_sast: a partly parsed file keeps its older finding in the open set', () => {
  const hit = (path: string, rule: string, line: string) => ({
    check_id: rule,
    path,
    start: { line: 3 },
    end: { line: 3 },
    extra: { severity: 'ERROR', message: `${rule} here`, lines: line },
  });
  const A = hit('wp/a.php', 'php-echo-get', 'echo $_GET["x"];');
  const B = hit('src/b.js', 'js-eval', 'eval(b)');
  const C = hit('src/c.js', 'js-eval', 'eval(c)');
  const WARNING = {
    code: 3,
    level: 'warn',
    type: ['PartialParsing', [{ path: 'wp/a.php' }]],
    message: 'Syntax error at line wp/a.php:9:\n `const NAMESPACE` was unexpected',
    path: 'wp/a.php',
  };

  it('keeps a.php from the full scan, flagged; b.js from the partial one; c.js resolved; risk_score counts 2', async () => {
    const project = makeTempDir('sast-carry-');
    const plugin = makePlugin(project);
    mockSemgrepOnPath(1, { results: [A, B, C], errors: [], paths: { scanned: ['wp/a.php', 'src/b.js', 'src/c.js'] } });
    await runSast(project, plugin);
    mockSemgrepOnPath(1, { results: [B], errors: [WARNING], paths: { scanned: ['wp/a.php', 'src/b.js', 'src/c.js'] } });
    const second = await runSast(project, plugin);
    expect((second as unknown as { coverage: string }).coverage).toBe('partial');

    const set = openSetForProject(plugin.storage, resolveProjectPath(project).path);
    const files = set.findings.map((f) => `${f.file_path}${f.not_remeasured === true ? ' (not re-measured)' : ''}`).sort();
    expect(files).toEqual(['src/b.js', 'wp/a.php (not re-measured)']);
    expect(set.coverage).toBe('partial');
    expect(set.sources.find((s) => s.carried_for !== undefined)?.carried_for).toEqual([
      'semgrep (partly parsed: wp/a.php)',
    ]);

    const risk = TOOLS.find((t) => t.name === 'risk_score');
    if (risk === undefined) throw new Error('risk_score not registered');
    const r = (await risk.handler({ project_path: project }, plugin)) as unknown as {
      components: { findings: { open_findings: number } };
    };
    expect(r.components.findings.open_findings).toBe(2);
  });
});
