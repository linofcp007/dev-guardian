/**
 * `runSelftest` end to end, with every process it starts replaced
 * (`src/selftest/run.ts`): the runners are fakes that answer as a scanner
 * would, the canaries are a directory built here in the shape the plugin
 * ships, and the hook checks go through the real launcher into a fake
 * dispatcher that records what it was handed.
 *
 * What only this file can show is the orchestration: which verdict each
 * observation becomes once the probe run, the per-pack runs and the user's
 * own settings meet; that the temporary directory is gone whatever happens;
 * and that nothing the user owns is touched and nothing private is kept.
 * The real scanners are `test/e2e/selftestCli.test.ts`'s.
 */

import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { basename, dirname, isAbsolute, join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { semgrepSpawn } from '../../src/runners/semgrepRun.js';
import { CANARY_MARKER, CANARY_SUFFIX, PROBE_RULE_FILE, PROBE_RULE_SOURCE, TOKEN_PLACEHOLDER, WORKSPACE_PREFIX, canaryToken } from '../../src/selftest/canaries.js';
import { CORE_CONTROLS, PROBE_RULE_ID, type Control } from '../../src/selftest/controls.js';
import { defaultRunners } from '../../src/selftest/defaultRunners.js';
import { SECRET_CANARY } from '../../src/selftest/hookChecks.js';
import { renderJson, renderTable } from '../../src/selftest/report.js';
import { runSelftest, type HookRunArgs, type ScanArgs, type ScanOutcome, type SelftestOptions, type SelftestResult, type SelftestRunners } from '../../src/selftest/run.js';
import { HISTORY_FILE, LAST_FILE, readHistory, selftestDir, type SelftestRun } from '../../src/selftest/store.js';
import type { Verdict } from '../../src/selftest/verdict.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

vi.setConfig({ testTimeout: 60_000 });
afterAll(cleanupTempDirs);

const REPO_ROOT = fileURLToPath(new URL('../../..', import.meta.url));
const PACKS_DIR = join(REPO_ROOT, 'configs', 'semgrep');
const NOW = Date.parse('2026-11-13T12:00:00.000Z');

let CANARIES = '';
let DISPATCHER = '';
let EMPTY_HOME = '';

/** The environment a run is given: this process's, without what the suite or the machine set for the hooks and the network. */
function cleanEnv(extra: Record<string, string> = {}): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env };
  for (const key of ['GUARDIAN_OFFLINE', 'GUARDIAN_HOOKS', 'GUARDIAN_HOOKS_BASH_BLOCK', 'FAKE_MUTE', 'FAKE_RECORD']) delete env[key];
  return { ...env, ...extra };
}

beforeAll(() => {
  // The canaries, in the shape the plugin ships them: every seeded file under its name plus the suffix.
  CANARIES = makeTempDir('selftest-canaries-');
  for (const c of CORE_CONTROLS) {
    if (c.canary === null) continue;
    const file = join(CANARIES, 'project', ...`${c.canary}${CANARY_SUFFIX}`.split('/'));
    mkdirSync(dirname(file), { recursive: true });
    writeFileSync(file, c.canary === SECRET_CANARY ? `aws.accessKeyId=${TOKEN_PLACEHOLDER}\n` : `# ${CANARY_MARKER}\nthe canary of ${c.id}\n`);
  }
  writeFileSync(join(CANARIES, PROBE_RULE_SOURCE), 'rules: []\n');

  // A dispatcher that answers as a working guard does, records what it was handed, and stays mute on request.
  const dir = makeTempDir('selftest-dispatcher-');
  DISPATCHER = join(dir, 'fake-dispatcher.mjs');
  writeFileSync(
    DISPATCHER,
    [
      "import { appendFileSync, readFileSync } from 'node:fs';",
      "const input = readFileSync(0, 'utf8');",
      'const payload = JSON.parse(input);',
      "const kind = payload.hook_event_name === 'PostToolUse' ? 'secret' : payload.tool_name === 'Bash' ? 'bash' : payload.tool_name === 'PowerShell' ? 'powershell' : 'settings';",
      'if (process.env.FAKE_RECORD) {',
      '  appendFileSync(process.env.FAKE_RECORD, JSON.stringify({ argv: process.argv.slice(1), stdin: input, home: process.env.HOME ?? null,',
      '    userprofile: process.env.USERPROFILE ?? null, project: process.env.CLAUDE_PROJECT_DIR ?? null, cwd: process.cwd(), kind }) + "\\n");',
      '}',
      "const mute = (process.env.FAKE_MUTE ?? '').split(',');",
      "if (mute.includes('all') || mute.includes(kind)) process.exit(0);",
      "const out = kind === 'secret'",
      "  ? { hookEventName: 'PostToolUse', additionalContext: 'possible secret(s) just written' }",
      "  : { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: 'blocked' };",
      'process.stdout.write(JSON.stringify({ hookSpecificOutput: out }));',
      '',
    ].join('\n'),
  );
  EMPTY_HOME = makeTempDir('selftest-home-');
});

const ok = (findings: ScanOutcome['findings'], read: ScanOutcome['read'] = null): ScanOutcome => ({ ended: 'ok', findings, read });

/** The files of the seeded project that carry the marker — what the probe rule reports. */
function markedFiles(project: string, dir = project): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === '.guardian') continue;
    const path = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...markedFiles(project, path));
    else if (entry.isFile() && readFileSync(path, 'utf8').includes(CANARY_MARKER)) out.push(relative(project, path).split(sep).join('/'));
  }
  return out;
}

const control = (id: string): Control => {
  const c = CORE_CONTROLS.find((x) => x.id === id);
  if (c === undefined) throw new Error(`no control ${id}`);
  return c;
};

interface Calls {
  semgrep: Array<ScanArgs & { rulesPath: string; canaryThere: boolean }>;
  gitleaks: ScanArgs[];
  trivy: Array<ScanArgs & { mode: 'deps' | 'iac'; offline: boolean }>;
  hook: HookRunArgs[];
  probe: string[];
  /** The seeded project of each run, as the runners saw it. */
  projects: Set<string>;
}

/** Runners that answer as scanners that all detect, and say what they were called with. */
function fakes(over: Partial<SelftestRunners> = {}): { runners: SelftestRunners; calls: Calls } {
  const calls: Calls = { semgrep: [], gitleaks: [], trivy: [], hook: [], probe: [], projects: new Set() };
  const runners: SelftestRunners = {
    probe: async (scanner) => {
      calls.probe.push(scanner);
      return { installed: true, version: '9.9.9' };
    },
    semgrep: async (args) => {
      calls.projects.add(args.project);
      const pack = CORE_CONTROLS.find((c) => c.pack === basename(args.rulesPath));
      calls.semgrep.push({ ...args, canaryThere: pack?.canary != null && existsSync(join(args.project, ...pack.canary.split('/'))) });
      if (basename(args.rulesPath) === PROBE_RULE_FILE) return ok(markedFiles(args.project).map((file) => ({ rule: PROBE_RULE_ID, file })));
      return ok(pack?.canary != null ? [{ rule: pack.expect, file: pack.canary }] : []);
    },
    gitleaks: async (args) => {
      calls.projects.add(args.project);
      calls.gitleaks.push(args);
      return ok([{ rule: 'aws-access-token', file: SECRET_CANARY }]);
    },
    trivy: async (args) => {
      calls.projects.add(args.project);
      calls.trivy.push(args);
      const c = control(args.mode === 'deps' ? 'trivy:deps' : 'trivy:iac');
      const canary = c.canary ?? '';
      return ok([{ rule: args.mode === 'deps' ? c.expect : 'DS002', file: canary }], [canary]);
    },
    hook: async (args) => {
      calls.hook.push(args);
      const post = args.event === 'PostToolUse';
      const out = post ? { hookEventName: 'PostToolUse', additionalContext: 'possible secret(s) just written' } : { hookEventName: 'PreToolUse', permissionDecision: 'deny' };
      return { exitCode: 0, stdout: JSON.stringify({ hookSpecificOutput: out }), timedOut: false };
    },
    installedTools: async () => ['gitleaks', 'semgrep', 'trivy'],
    ...over,
  };
  return { runners, calls };
}

interface Ran {
  result: SelftestResult;
  tmpRoot: string;
  dataDir: string;
  run: SelftestRun;
  verdict: (id: string) => Verdict | undefined;
  reason: (id: string) => string;
}

async function selftest(runners: SelftestRunners, opts: Partial<SelftestOptions> = {}): Promise<Ran> {
  const tmpRoot = opts.tmpRoot ?? makeTempDir('selftest-tmp-');
  const dataDir = opts.dataDir ?? makeTempDir('selftest-data-');
  const result = await runSelftest({
    runners,
    packsDir: PACKS_DIR,
    canariesDir: CANARIES,
    dispatcherPath: DISPATCHER,
    dataDir,
    pluginVersion: '3.9.0',
    tmpRoot,
    env: cleanEnv(),
    homeDir: EMPTY_HOME,
    now: () => new Date(NOW),
    ...opts,
  });
  const by = new Map(result.report.run.controls.map((c) => [c.id, c]));
  return {
    result,
    tmpRoot,
    dataDir,
    run: result.report.run,
    verdict: (id) => by.get(id)?.verdict,
    reason: (id) => by.get(id)?.reason ?? '',
  };
}

/** The hook checks through the real launcher, into the fake dispatcher. */
const realHook: SelftestRunners['hook'] = (args) => defaultRunners().hook(args);
const HOOK_IDS = ['hooks:bash-block', 'hooks:powershell-block', 'hooks:settings-guard', 'hooks:secret-warning'];
const packIds = (): string[] => CORE_CONTROLS.filter((c) => c.kind === 'semgrep-pack').map((c) => c.id);

describe('a selftest run', () => {
  it('T-01 makes a new directory under the temporary root, seeds the canaries without their suffix, runs every control and gives each a verdict', async () => {
    const { runners, calls } = fakes();
    const { result, run, tmpRoot } = await selftest(runners);
    expect(CORE_CONTROLS.length).toBeGreaterThanOrEqual(22);
    expect(run.controls.map((c) => c.id).sort()).toEqual(CORE_CONTROLS.map((c) => c.id).sort());
    for (const c of run.controls) expect(c.verdict, c.id).toBe('detected');
    expect(run.summary.detected).toBe(CORE_CONTROLS.length);
    expect(result.exitCode).toBe(0);
    expect(run.exit_code).toBe(0);
    expect(run).toMatchObject({ schema: 1, plugin_version: '3.9.0', ran_at: new Date(NOW).toISOString() });

    // One directory, under the root it was given, by the name a leftover is recognised by.
    expect(calls.projects.size).toBe(1);
    const project = [...calls.projects][0] ?? '';
    expect(basename(project)).toBe('project');
    expect(basename(dirname(project)).startsWith(WORKSPACE_PREFIX)).toBe(true);
    expect(realpathSync.native(dirname(dirname(project)))).toBe(realpathSync.native(tmpRoot));
    // The probe ran once, before the packs, with the probe rule beside the project — outside the scanned tree.
    const probeRuns = calls.semgrep.filter((c) => basename(c.rulesPath) === PROBE_RULE_FILE);
    expect(probeRuns).toHaveLength(1);
    expect(calls.semgrep[0]?.rulesPath).toBe(probeRuns[0]?.rulesPath);
    expect(relative(project, probeRuns[0]?.rulesPath ?? '').startsWith('..')).toBe(true);
    // Each pack ran alone, with its own file, on a project where its canary was there under its real name.
    const packRuns = calls.semgrep.filter((c) => basename(c.rulesPath) !== PROBE_RULE_FILE);
    expect(packRuns.map((c) => c.rulesPath).sort()).toEqual(
      CORE_CONTROLS.filter((c) => c.kind === 'semgrep-pack').map((c) => join(PACKS_DIR, c.pack ?? '')).sort(),
    );
    for (const c of packRuns) expect(c.canaryThere, c.rulesPath).toBe(true);
    expect(calls.gitleaks).toHaveLength(1);
    expect(calls.trivy.map((c) => c.mode)).toEqual(['deps', 'iac']);
    expect(calls.hook).toHaveLength(4);
  });

  it('T-03 by default the runners are the scan tools own, and the dispatcher is started where the install has it, with the user home untouched', async () => {
    // The real runners are built on the functions the scan tools call — not on a second way of running a scanner.
    const source = readFileSync(join(REPO_ROOT, 'mcp', 'src', 'selftest', 'defaultRunners.ts'), 'utf8');
    for (const name of ['invokeSemgrep', 'checkSemgrepReport', 'runGitleaksScan', 'runTrivy', 'judgeTrivyFs', 'judgeTrivyConfig', 'scannerAvailable']) {
      expect(source, name).toMatch(new RegExp(`\\b${name}\\(`));
    }
    const record = join(makeTempDir('selftest-record-'), 'calls.jsonl');
    const { runners } = fakes({ hook: realHook });
    const { run } = await selftest(runners, { env: cleanEnv({ FAKE_RECORD: record }) });
    for (const id of HOOK_IDS) expect(run.controls.find((c) => c.id === id)?.verdict, id).toBe('detected');
    const seen = readFileSync(record, 'utf8').trim().split('\n').map((l) => JSON.parse(l) as { argv: string[]; home: string | null; userprofile: string | null; project: string; cwd: string });
    expect(seen).toHaveLength(4);
    for (const s of seen) {
      expect(realpathSync.native(s.argv[0] ?? '')).toBe(realpathSync.native(DISPATCHER));
      // The user's own configuration is what is tested: their home is the one the dispatcher sees.
      expect(s.home).toBe(process.env['HOME'] ?? null);
      expect(s.userprofile).toBe(process.env['USERPROFILE'] ?? null);
      // The project is the temporary one — never the directory the command was run from.
      expect(basename(s.project)).toBe('project');
      expect(realpathSync.native(s.cwd)).not.toBe(realpathSync.native(process.cwd()));
    }
  });

  it('T-05 a scanner that is not installed is missing, with how to install it; one that is there and cannot say its version is unverified', async () => {
    const { runners, calls } = fakes({
      probe: async (scanner) => {
        if (scanner === 'semgrep') return { installed: false, version: null, installCommand: 'pipx install semgrep' };
        if (scanner === 'gitleaks') return { installed: true, version: null, problem: 'gitleaks version exited 3' };
        return { installed: true, version: '0.74.0' };
      },
    });
    const { result, run, verdict, reason } = await selftest(runners);
    for (const id of packIds()) {
      expect(verdict(id), id).toBe('missing');
      expect(run.controls.find((c) => c.id === id)?.next, id).toContain('pipx install semgrep');
      expect(run.controls.find((c) => c.id === id)?.scanner_version, id).toBeNull();
    }
    expect(verdict('gitleaks')).toBe('unverified');
    expect(reason('gitleaks')).toContain('gitleaks version exited 3');
    expect(verdict('trivy:deps')).toBe('detected');
    expect(run.controls.find((c) => c.id === 'trivy:deps')?.scanner_version).toBe('0.74.0');
    // Nothing of a scanner that is not there, or cannot be asked, was started.
    expect(calls.semgrep).toHaveLength(0);
    expect(calls.gitleaks).toHaveLength(0);
    expect(result.exitCode).toBe(2);
  });

  it('T-06 each way a control cannot be taken to a verdict is unverified with its reason — never detected, never silent', async () => {
    const [failing, slow, partial] = CORE_CONTROLS.filter((c) => c.kind === 'semgrep-pack');
    expect(partial).toBeDefined();
    const base = fakes();
    const { runners } = fakes({
      semgrep: async (args) => {
        const name = basename(args.rulesPath);
        if (name === failing?.pack) return { ended: 'failed', reason: 'semgrep exited 2: invalid configuration', findings: [], read: null };
        if (name === slow?.pack) return { ended: 'timeout', reason: 'did not finish in 180 s', findings: [], read: null };
        // A partial run that still reported the canary: not a detection.
        if (name === partial?.pack) return { ended: 'partial', reason: '1 file could not be parsed', findings: [{ rule: partial.expect, file: partial.canary ?? '' }], read: null };
        return base.runners.semgrep(args);
      },
      trivy: async (args) =>
        args.mode === 'deps'
          ? { ended: 'failed', reason: 'the vulnerability database is not available (no local copy, and it could not be downloaded)', findings: [], read: null }
          : base.runners.trivy(args),
    });
    const a = await selftest(runners);
    expect(a.verdict(failing?.id ?? '')).toBe('unverified');
    expect(a.reason(failing?.id ?? '')).toContain('semgrep exited 2');
    expect(a.verdict(slow?.id ?? '')).toBe('unverified');
    expect(a.reason(slow?.id ?? '')).toContain('did not finish');
    expect(a.verdict(partial?.id ?? '')).toBe('unverified');
    expect(a.reason(partial?.id ?? '')).toContain('could not be parsed');
    // EC-2: no vulnerability database.
    expect(a.verdict('trivy:deps')).toBe('unverified');
    expect(a.reason('trivy:deps')).toContain('vulnerability database is not available');
    expect(a.verdict('trivy:iac')).toBe('detected');
    expect(a.result.exitCode).toBe(2);

    // A runner that never answers does not hold the run: its control is given up as timed out.
    const hung = fakes({ gitleaks: () => new Promise<ScanOutcome>(() => undefined) });
    const quick: Control[] = CORE_CONTROLS.map((c) => (c.id === 'gitleaks' ? { ...c, timeoutMs: 30 } : c));
    const b = await selftest(hung.runners, { controls: quick, timeoutGraceMs: 30 });
    expect(b.verdict('gitleaks')).toBe('unverified');
    expect(b.reason('gitleaks')).toMatch(/did not finish/);
    expect(b.verdict('trivy:deps')).toBe('detected');

    // EC-3: a temporary directory Semgrep does not scan (below a `test/` it ignores). Neither the probe
    // rule nor any pack reads a canary: that is not a blind pack, and no control is called silent.
    const ignoring = fakes({ semgrep: async () => ok([], []) });
    const below = join(makeTempDir('selftest-ec3-'), 'test');
    mkdirSync(below);
    const c = await selftest(ignoring.runners, { tmpRoot: below });
    for (const id of packIds()) {
      expect(c.verdict(id), id).toBe('unverified');
      expect(c.reason(id), id).toMatch(/does not scan this temporary directory/);
    }
    expect(c.run.summary.silent).toBe(0);

    // The probe run itself failed: a pack that reports nothing cannot be called silent either.
    const noProbe = fakes({
      semgrep: async (args) => (basename(args.rulesPath) === PROBE_RULE_FILE ? { ended: 'failed', reason: 'semgrep exited 2', findings: [], read: null } : ok([])),
    });
    const d = await selftest(noProbe.runners);
    for (const id of packIds()) expect(d.verdict(id), id).toBe('unverified');

    // EC-4: a canary that is gone when its scan begins (quarantined by something else).
    const victim = control('trivy:deps');
    const quarantine = fakes();
    const e = await selftest({
      ...quarantine.runners,
      gitleaks: async (args) => {
        rmSync(join(args.project, ...(victim.canary ?? '').split('/')));
        return quarantine.runners.gitleaks(args);
      },
    });
    expect(e.verdict('trivy:deps')).toBe('unverified');
    expect(e.reason('trivy:deps')).toMatch(/was not in the temporary project/);
    expect(quarantine.calls.trivy.map((t) => t.mode)).toEqual(['iac']);
  });

  it('T-06 a control that read its canary and did not report it is silent — the one verdict the others must never be mistaken for', async () => {
    const [blind] = CORE_CONTROLS.filter((c) => c.kind === 'semgrep-pack');
    const base = fakes();
    const { runners } = fakes({
      // The pack ran to the end and reported nothing; the probe rule read the canary.
      semgrep: async (args) => (basename(args.rulesPath) === blind?.pack ? ok([]) : base.runners.semgrep(args)),
      // An empty report with exit 0.
      gitleaks: async () => ok([]),
      // Trivy read the lockfile and found nothing in it.
      trivy: async (args) => (args.mode === 'deps' ? ok([], [control('trivy:deps').canary ?? '']) : ok([], [])),
    });
    const r = await selftest(runners);
    expect(r.verdict(blind?.id ?? '')).toBe('silent');
    expect(r.verdict('gitleaks')).toBe('silent');
    expect(r.verdict('trivy:deps')).toBe('silent');
    // Trivy says what it read, and the Dockerfile is not in it: not read is not silent.
    expect(r.verdict('trivy:iac')).toBe('unverified');
    expect(r.reason('trivy:iac')).toMatch(/did not read/);
    expect(r.result.exitCode).toBe(1);
    expect(r.run.summary.silent).toBe(3);
    // A finding of another rule on the canary, or of the right rule on another file, is not the canary reported.
    const wrong = fakes({
      semgrep: async (args) => {
        if (basename(args.rulesPath) !== blind?.pack) return base.runners.semgrep(args);
        return ok([
          { rule: 'some-other-rule', file: blind.canary ?? '' },
          { rule: blind.expect, file: 'elsewhere/file.py' },
        ]);
      },
    });
    expect((await selftest(wrong.runners)).verdict(blind?.id ?? '')).toBe('silent');
  });

  it('T-07 an installed scanner with no canary is listed as no_canary and is in no count of verified controls', async () => {
    const { runners } = fakes({ installedTools: async () => ['trivy', 'phpcs', 'semgrep', 'bandit', 'gitleaks'] });
    const { result, run } = await selftest(runners);
    expect(run.no_canary).toEqual(['bandit', 'phpcs']);
    expect(run.summary.no_canary).toBe(2);
    expect(run.summary.detected).toBe(CORE_CONTROLS.length);
    expect(run.controls.some((c) => c.id === 'bandit' || c.scanner === 'bandit')).toBe(false);
    expect(result.exitCode).toBe(0);
    expect(renderTable(result.report)).toMatch(/no canary.*bandit, phpcs/);
  });

  it('T-08 a guard that answers more softly is disabled_by_user only when a setting of the user explains it; otherwise silent; no dispatcher is missing', async () => {
    const hooks = async (env: Record<string, string>, home?: Record<string, unknown>) => {
      const homeDir = makeTempDir('selftest-home-');
      if (home !== undefined) {
        mkdirSync(join(homeDir, '.config', 'dev-guardian'), { recursive: true });
        writeFileSync(join(homeDir, '.config', 'dev-guardian', 'hooks.json'), JSON.stringify(home));
      }
      const r = await selftest(fakes({ hook: realHook }).runners, { env: cleanEnv(env), homeDir });
      return { ...r, verdicts: HOOK_IDS.map((id) => r.verdict(id)) };
    };
    const SHELL = ['hooks:bash-block', 'hooks:powershell-block'];

    const off = await hooks({ GUARDIAN_HOOKS: 'off', FAKE_MUTE: 'all' });
    expect(off.verdicts).toEqual(['disabled_by_user', 'disabled_by_user', 'disabled_by_user', 'disabled_by_user']);
    for (const id of HOOK_IDS) expect(off.reason(id), id).toContain('GUARDIAN_HOOKS=off');
    // The user's decision is not a defect: it does not change the exit code.
    expect(off.result.exitCode).toBe(0);

    const noBlock = await hooks({ GUARDIAN_HOOKS_BASH_BLOCK: '0', FAKE_MUTE: 'bash,powershell' });
    expect(noBlock.verdicts).toEqual(['disabled_by_user', 'disabled_by_user', 'detected', 'detected']);
    for (const id of SHELL) expect(noBlock.reason(id), id).toContain('GUARDIAN_HOOKS_BASH_BLOCK=0');

    const disabled = await hooks({ FAKE_MUTE: 'all' }, { enabled: false });
    expect(disabled.verdicts).toEqual(['disabled_by_user', 'disabled_by_user', 'disabled_by_user', 'disabled_by_user']);
    for (const id of HOOK_IDS) expect(disabled.reason(id), id).toContain('"enabled": false');

    const userNoBlock = await hooks({ FAKE_MUTE: 'bash,powershell' }, { bash: { block: false } });
    expect(userNoBlock.verdicts).toEqual(['disabled_by_user', 'disabled_by_user', 'detected', 'detected']);
    for (const id of SHELL) expect(userNoBlock.reason(id), id).toContain('"bash": {"block": false}');

    const noWarn = await hooks({ FAKE_MUTE: 'secret' }, { secrets: { warn: false } });
    expect(noWarn.verdicts).toEqual(['detected', 'detected', 'detected', 'disabled_by_user']);
    expect(noWarn.reason('hooks:secret-warning')).toContain('"secrets": {"warn": false}');

    // The setting is there and the guard answered as a working one: detected, not "disabled".
    const stillWorks = await hooks({ GUARDIAN_HOOKS_BASH_BLOCK: '0' });
    expect(stillWorks.verdicts).toEqual(['detected', 'detected', 'detected', 'detected']);
    // A setting for ANOTHER guard does not excuse this one.
    const other = await hooks({ FAKE_MUTE: 'settings,secret' }, { bash: { block: false } });
    expect(other.verdicts).toEqual(['detected', 'detected', 'silent', 'silent']);
    // The environment says block, the user file says not: the environment wins, as in the dispatcher.
    const envWins = await hooks({ GUARDIAN_HOOKS_BASH_BLOCK: '1', FAKE_MUTE: 'bash' }, { bash: { block: false } });
    expect(envWins.verdicts[0]).toBe('silent');

    // Softer with nothing of the user's to explain it: silent, and the command says so by its exit code.
    const oneMute = await hooks({ FAKE_MUTE: 'bash' });
    expect(oneMute.verdicts).toEqual(['silent', 'detected', 'detected', 'detected']);
    expect(oneMute.result.exitCode).toBe(1);
    // EC-5: a dispatcher that answers nothing at all (a damaged bundle fails open) — silent, every guard.
    const mute = await hooks({ FAKE_MUTE: 'all' });
    expect(mute.verdicts).toEqual(['silent', 'silent', 'silent', 'silent']);
    // EC-5: no dispatcher in the install — missing.
    const none = await selftest(fakes({ hook: realHook }).runners, { dispatcherPath: join(makeTempDir('selftest-nodisp-'), 'guardian-hook.mjs') });
    expect(HOOK_IDS.map((id) => none.verdict(id))).toEqual(['missing', 'missing', 'missing', 'missing']);
    expect(none.result.exitCode).toBe(2);
  });

  it('T-10 the temporary directory is gone after a full run, a control that throws, a run that cannot begin and an interrupted one; kept only on request', async () => {
    const empty = (root: string): string[] => readdirSync(root);

    const full = await selftest(fakes().runners);
    expect(empty(full.tmpRoot)).toEqual([]);
    expect(full.result.report.workspace).toBeUndefined();

    // A control that throws is that control's problem: unverified, and the others still ran.
    const thrower = await selftest(
      fakes({
        gitleaks: async () => {
          throw new Error('spawn EPERM');
        },
      }).runners,
    );
    expect(thrower.verdict('gitleaks')).toBe('unverified');
    expect(thrower.reason('gitleaks')).toContain('spawn EPERM');
    expect(thrower.verdict('trivy:iac')).toBe('detected');
    expect(empty(thrower.tmpRoot)).toEqual([]);

    // The run cannot even begin (no canaries in the install): it rejects, and leaves nothing behind.
    const tmpRoot = makeTempDir('selftest-tmp-');
    const dataDir = makeTempDir('selftest-data-');
    await expect(selftest(fakes().runners, { tmpRoot, dataDir, canariesDir: join(tmpRoot, 'no-such-canaries') })).rejects.toThrow(/canaries/);
    expect(empty(tmpRoot)).toEqual([]);
    expect(existsSync(selftestDir(dataDir))).toBe(false);

    // Interrupted in the middle (EC-7): what was not reached is unverified, nothing is saved, the directory is gone.
    const stop = new AbortController();
    const base = fakes();
    const interrupted = await selftest(
      {
        ...base.runners,
        gitleaks: async (args) => {
          stop.abort();
          return base.runners.gitleaks(args);
        },
      },
      { signal: stop.signal },
    );
    expect(interrupted.result.report.interrupted).toBe(true);
    expect(interrupted.verdict('trivy:deps')).toBe('unverified');
    expect(interrupted.reason('trivy:deps')).toMatch(/interrupted/);
    for (const id of HOOK_IDS) expect(interrupted.verdict(id), id).toBe('unverified');
    expect(interrupted.run.controls).toHaveLength(CORE_CONTROLS.length);
    expect(base.calls.trivy).toHaveLength(0);
    expect(base.calls.hook).toHaveLength(0);
    expect(interrupted.result.report.saved).toMatchObject({ saved: false, skipped: 'interrupted' });
    expect(existsSync(join(selftestDir(interrupted.dataDir), LAST_FILE))).toBe(false);
    expect(existsSync(join(selftestDir(interrupted.dataDir), HISTORY_FILE))).toBe(false);
    expect(empty(interrupted.tmpRoot)).toEqual([]);

    // --keep: it stays, and the report says where.
    const kept = await selftest(fakes().runners, { keep: true });
    const left = empty(kept.tmpRoot);
    expect(left).toHaveLength(1);
    expect(kept.result.report.workspace).toMatchObject({ kept: true });
    expect(realpathSync.native(kept.result.report.workspace?.path ?? '')).toBe(realpathSync.native(join(kept.tmpRoot, left[0] ?? '')));
    expect(existsSync(join(kept.tmpRoot, left[0] ?? '', 'project', ...SECRET_CANARY.split('/')))).toBe(true);
    expect(renderTable(kept.result.report)).toContain(kept.result.report.workspace?.path ?? 'no path');
    expect(kept.result.exitCode).toBe(0);
  });

  it('T-11 a directory that cannot be removed is named, and the command does not exit 0', async () => {
    const r = await selftest(fakes().runners, {
      remove: () => {
        throw new Error('EBUSY: resource busy or locked');
      },
    });
    for (const c of r.run.controls) expect(c.verdict, c.id).toBe('detected');
    const left = readdirSync(r.tmpRoot);
    expect(left).toHaveLength(1);
    expect(r.result.report.workspace).toMatchObject({ kept: false, note: expect.stringContaining('EBUSY') });
    expect(realpathSync.native(r.result.report.workspace?.path ?? '')).toBe(realpathSync.native(join(r.tmpRoot, left[0] ?? '')));
    expect(r.result.exitCode).toBe(2);
    expect(r.run.exit_code).toBe(2);
    const table = renderTable(r.result.report);
    expect(table).toMatch(/NOT REMOVED/);
    expect(table).toContain(r.result.report.workspace?.path ?? 'no path');
    // With a silent control the exit code stays 1: the leftover never hides a blind control.
    const both = await selftest(fakes({ gitleaks: async () => ok([]) }).runners, {
      remove: () => {
        throw new Error('EBUSY');
      },
    });
    expect(both.result.exitCode).toBe(1);
  });

  it('T-16 abuse case: run from inside a project with a database, a baseline and suppressions — nothing of it is touched, and no database is opened', async () => {
    const project = makeTempDir('selftest-userproject-');
    mkdirSync(join(project, '.guardian'));
    const owned: Record<string, string> = {
      '.guardian/guardian.db': 'SQLite format 3\u0000 — not a real database, and it must not be opened to find out',
      '.guardian/baseline.json': '{"version":1,"findings":[]}',
      '.guardian/suppressions.json': '[]',
      '.guardianignore': 'vendor/\n',
      'app.js': 'console.log(1);\n',
    };
    for (const [rel, text] of Object.entries(owned)) writeFileSync(join(project, ...rel.split('/')), text);
    const before = Object.fromEntries(Object.keys(owned).map((rel) => [rel, statSync(join(project, ...rel.split('/'))).mtimeMs]));
    const listing = (): string[] => readdirSync(project, { recursive: true }).map(String).sort();
    const filesBefore = listing();

    const dataDir = makeTempDir('selftest-data-');
    const cwd = process.cwd();
    process.chdir(project);
    let ran: Ran;
    try {
      ran = await selftest(fakes().runners, { dataDir, env: cleanEnv({ CLAUDE_PROJECT_DIR: project }) });
    } finally {
      process.chdir(cwd);
    }
    expect(ran.result.exitCode).toBe(0);
    expect(listing()).toEqual(filesBefore);
    for (const [rel, text] of Object.entries(owned)) {
      const file = join(project, ...rel.split('/'));
      expect(readFileSync(file, 'utf8'), rel).toBe(text);
      expect(statSync(file).mtimeMs, rel).toBe(before[rel]);
    }
    // The data directory holds the selftest's own two files and nothing else: no registry of trusted
    // databases, no fallback database — which is what opening one leaves behind.
    expect(readdirSync(dataDir)).toEqual(['selftest']);
    expect(readdirSync(selftestDir(dataDir)).sort()).toEqual([HISTORY_FILE, LAST_FILE].sort());
    // And no module of the selftest reaches the storage layer at all.
    const dir = join(REPO_ROOT, 'mcp', 'src', 'selftest');
    for (const name of readdirSync(dir)) {
      expect(readFileSync(join(dir, name), 'utf8'), name).not.toMatch(/from '\.\.\/storage\/(db|index|dbRegistry)\.js'|openDatabase|node:sqlite/);
    }
  });

  it('T-18 whatever the verdicts, the secret canary is in nothing that is printed or saved', async () => {
    const token = canaryToken();
    const leaky = (text: string): ScanOutcome => ({ ended: 'failed', reason: `${text} ${token} in stderr`, findings: [{ rule: token, file: SECRET_CANARY }], read: null });
    const mixes: Array<Partial<SelftestRunners>> = [
      {},
      { gitleaks: async () => ok([]) },
      { gitleaks: async () => leaky('gitleaks printed') },
      { trivy: async () => leaky('trivy printed'), semgrep: async () => leaky('semgrep printed') },
      {
        gitleaks: async () => {
          throw new Error(`could not read aws.accessKeyId=${token}`);
        },
        probe: async () => ({ installed: true, version: null, problem: `version said ${token}` }),
      },
      { hook: async () => ({ exitCode: 0, stdout: `{"note":"${token}"}`, timedOut: false }) },
    ];
    for (const [i, over] of mixes.entries()) {
      const r = await selftest(fakes(over).runners);
      const outputs: Record<string, string> = {
        table: renderTable(r.result.report),
        json: renderJson(r.result.report),
        'last.json': readFileSync(join(selftestDir(r.dataDir), LAST_FILE), 'utf8'),
        'history.json': readFileSync(join(selftestDir(r.dataDir), HISTORY_FILE), 'utf8'),
      };
      for (const [where, text] of Object.entries(outputs)) {
        expect(text.includes(token), `mix ${i}: ${where}`).toBe(false);
        expect(text.length, `mix ${i}: ${where}`).toBeGreaterThan(50);
      }
    }
  });

  it('T-19 abuse case: a hook check reaches the dispatcher only as text on its standard input — never in an argument, never through a shell', async () => {
    const record = join(makeTempDir('selftest-record-'), 'calls.jsonl');
    const { runners } = fakes({ hook: realHook });
    await selftest(runners, { env: cleanEnv({ FAKE_RECORD: record }) });
    const seen = readFileSync(record, 'utf8').trim().split('\n').map((l) => JSON.parse(l) as { argv: string[]; stdin: string; kind: string });
    expect(seen.map((s) => s.kind).sort()).toEqual(['bash', 'powershell', 'secret', 'settings']);
    for (const s of seen) {
      // The dispatcher and the event's name: nothing else was ever on a command line.
      expect(s.argv).toHaveLength(2);
      expect(s.argv[1]).toMatch(/^(PreToolUse|PostToolUse)$/);
      const payload = JSON.parse(s.stdin) as { tool_name: string; tool_input: Record<string, string> };
      if (s.kind === 'bash' || s.kind === 'powershell') {
        const command = payload.tool_input['command'] ?? '';
        expect(command.length, s.kind).toBeGreaterThan(5);
        expect(s.argv.join(' ').includes(command), s.kind).toBe(false);
      }
      if (s.kind === 'settings') expect(payload.tool_input['content']).toContain('disableAllHooks');
    }
    // Nothing in the selftest starts a shell: every process goes through the no-shell spawn or a scan tool's runner.
    const dir = join(REPO_ROOT, 'mcp', 'src', 'selftest');
    for (const name of readdirSync(dir)) {
      const text = readFileSync(join(dir, name), 'utf8');
      expect(text, name).not.toMatch(/shell:\s*true|\bexecSync\(|\bexec\(|child_process/);
    }
    // The dispatcher's launcher is the repository's no-shell spawn, and the real runners use it.
    expect(readFileSync(join(dir, 'hookRunner.ts'), 'utf8')).toMatch(/spawnNoShell\(/);
    expect(readFileSync(join(dir, 'defaultRunners.ts'), 'utf8')).toMatch(/hook: runDispatcher/);
  });

  it('T-20 abuse case: two runs at once get two directories, private to the user; a link inside one is removed as a link', async () => {
    const tmpRoot = makeTempDir('selftest-tmp-');
    const outside = makeTempDir('selftest-outside-');
    writeFileSync(join(outside, 'precious.txt'), 'not the selftest\'s to remove\n');
    const modes: number[] = [];
    const planting = (): SelftestRunners => {
      const f = fakes();
      return {
        ...f.runners,
        gitleaks: async (args) => {
          modes.push(statSync(dirname(args.project)).mode & 0o777);
          // Something a scanner, or anything else, left in the temporary project: a link that leads out of it.
          symlinkSync(outside, join(args.project, 'link-out'), 'junction');
          return f.runners.gitleaks(args);
        },
      };
    };
    const seenA = fakes();
    const [a, b] = await Promise.all([
      selftest({ ...planting(), semgrep: seenA.runners.semgrep }, { tmpRoot }),
      selftest(planting(), { tmpRoot, keep: true }),
    ]);
    const dirA = dirname([...seenA.calls.projects][0] ?? '');
    const dirB = b.result.report.workspace?.path ?? '';
    expect(dirA).not.toBe('');
    expect(dirB).not.toBe('');
    expect(realpathSync.native(dirname(dirB))).toBe(realpathSync.native(tmpRoot));
    expect(basename(dirA)).not.toBe(basename(dirB));
    expect(a.result.exitCode).toBe(0);
    if (process.platform !== 'win32') for (const mode of modes) expect(mode.toString(8)).toBe('700');
    expect(modes).toHaveLength(2);
    // The first is gone, the link with it — and what the link pointed at is not.
    expect(existsSync(dirA)).toBe(false);
    expect(readFileSync(join(outside, 'precious.txt'), 'utf8')).toContain('not the selftest');
    expect(readdirSync(tmpRoot)).toEqual([basename(dirB)]);
  });

  it('T-21 with GUARDIAN_OFFLINE=1 the dependency audit is not started and is unverified; Semgrep is only ever given local files', async () => {
    const { runners, calls } = fakes();
    const r = await selftest(runners, { env: cleanEnv({ GUARDIAN_OFFLINE: '1' }) });
    expect(calls.trivy.map((c) => c.mode)).toEqual(['iac']);
    expect(calls.trivy[0]?.offline).toBe(true);
    expect(r.verdict('trivy:deps')).toBe('unverified');
    expect(r.reason('trivy:deps')).toContain('GUARDIAN_OFFLINE=1');
    expect(r.result.exitCode).toBe(2);
    // Online, it is started, and told so.
    const online = fakes();
    await selftest(online.runners);
    expect(online.calls.trivy.map((c) => [c.mode, c.offline])).toEqual([['deps', false], ['iac', false]]);
    // Every configuration Semgrep is given is a file on this machine: no registry pack, no URL.
    expect(calls.semgrep.length).toBe(packIds().length + 1);
    for (const c of calls.semgrep) {
      expect(isAbsolute(c.rulesPath), c.rulesPath).toBe(true);
      expect(c.rulesPath, c.rulesPath).not.toMatch(/^(p|r)\/|^https?:|^auto$/);
      expect(basename(c.rulesPath) === PROBE_RULE_FILE || existsSync(c.rulesPath), c.rulesPath).toBe(true);
      // What Semgrep is started with from this environment has its version check — a request of its own — off.
      expect(semgrepSpawn(c.env).env['SEMGREP_ENABLE_VERSION_CHECK']).toBe('0');
      expect(c.env['GUARDIAN_OFFLINE']).toBe('1');
    }
  });

  it('T-24 a run is saved per install: the UTC date, the plugin version, the platform and, per control, its id, verdict, scanner version and reason', async () => {
    const r = await selftest(fakes({ gitleaks: async () => ok([]) }).runners, { platform: 'linux-x64' });
    expect(r.result.report.saved).toMatchObject({ saved: true });
    const last = JSON.parse(readFileSync(join(selftestDir(r.dataDir), LAST_FILE), 'utf8')) as SelftestRun;
    expect(last).toMatchObject({ schema: 1, ran_at: '2026-11-13T12:00:00.000Z', plugin_version: '3.9.0', platform: 'linux-x64', exit_code: 1 });
    expect(last.controls.map((c) => c.id).sort()).toEqual(CORE_CONTROLS.map((c) => c.id).sort());
    for (const c of last.controls) {
      expect(c.verdict, c.id).toBe(c.id === 'gitleaks' ? 'silent' : 'detected');
      expect(c.scanner_version, c.id).toBe(c.scanner === 'hooks' ? '3.9.0' : '9.9.9');
    }
    expect(last.controls.find((c) => c.id === 'gitleaks')?.reason).toEqual(expect.any(String));
    expect(last).toEqual(r.run);
    expect(readHistory(r.dataDir).runs).toEqual([r.run]);
  });

  it('T-30 with save off nothing is written in the data directory', async () => {
    const r = await selftest(fakes().runners, { save: false });
    expect(r.result.report.saved).toMatchObject({ saved: false, skipped: 'no-save' });
    expect(readdirSync(r.dataDir)).toEqual([]);
    expect(renderTable(r.result.report)).toMatch(/Not saved \(--no-save\)/);
    expect(r.result.exitCode).toBe(0);
  });

  it('T-31 a data directory that cannot be written: the report is whole, says it was not saved, and the exit code is the verdicts own', async () => {
    // A file where the data directory should be: nothing can be created below it.
    const blocked = join(makeTempDir('selftest-data-'), 'not-a-directory');
    writeFileSync(blocked, 'x');
    const detected = await selftest(fakes().runners, { dataDir: blocked });
    expect(detected.run.controls).toHaveLength(CORE_CONTROLS.length);
    expect(detected.result.report.saved?.saved).toBe(false);
    expect(detected.result.report.saved?.note).toEqual(expect.any(String));
    expect(detected.result.exitCode).toBe(0);
    expect(renderTable(detected.result.report)).toMatch(/Not saved: /);
    expect(readFileSync(blocked, 'utf8')).toBe('x');
    const silent = await selftest(fakes({ gitleaks: async () => ok([]) }).runners, { dataDir: blocked });
    expect(silent.result.exitCode).toBe(1);
  });

  it('T-33 what is saved holds no path of the user, of the temporary directory or of where the command ran, and no environment value', async () => {
    const mark = 'zz-marked-environment-value-7731';
    let workspace = '';
    const base = fakes();
    const { runners } = fakes({
      gitleaks: async (args) => {
        workspace = dirname(args.project);
        // What a real scanner's error looks like: paths, and whatever the environment held.
        return {
          ended: 'failed',
          reason: `could not open ${join(args.project, 'secrets', 'app.properties')} (cwd ${process.cwd()}, report ${args.reportDir.split(sep).join('/')}, home ${EMPTY_HOME}, token ${mark})`,
          findings: [],
          read: null,
        };
      },
      semgrep: base.runners.semgrep,
    });
    const r = await selftest(runners, { env: cleanEnv({ SELFTEST_MARK: mark }) });
    expect(workspace).not.toBe('');
    expect(r.verdict('gitleaks')).toBe('unverified');
    const saved = readFileSync(join(selftestDir(r.dataDir), LAST_FILE), 'utf8') + readFileSync(join(selftestDir(r.dataDir), HISTORY_FILE), 'utf8');
    const lower = saved.toLowerCase().replace(/\\\\/g, '/').replace(/\\/g, '/');
    const absent = (path: string): boolean => !lower.includes(path.toLowerCase().replace(/\\/g, '/'));
    expect(absent(workspace), 'the temporary directory').toBe(true);
    expect(absent(basename(workspace)), 'the temporary directory by its name').toBe(true);
    expect(absent(r.tmpRoot), 'the temporary root').toBe(true);
    expect(absent(process.cwd()), 'where the command ran').toBe(true);
    expect(absent(EMPTY_HOME), 'the home directory').toBe(true);
    expect(absent(r.dataDir), 'the data directory').toBe(true);
    // The reason is still there to be read — with the paths taken out, not thrown away whole.
    expect(r.reason('gitleaks')).toMatch(/could not open/);
    // Nor a value of the environment: a scanner's error may quote one, and it is named instead ($SELFTEST_MARK).
    expect(saved.includes(mark), 'a value of the environment').toBe(false);
    expect(r.reason('gitleaks')).toContain('$SELFTEST_MARK');
    expect(r.reason('gitleaks').length).toBeLessThanOrEqual(600);
    expect(saved.includes(JSON.stringify(process.env['PATH'] ?? 'no PATH').slice(1, -1))).toBe(false);
  });

  it('T-38 a history that cannot be read: the selftest still runs, says so, puts the old file aside and begins a new history', async () => {
    const dataDir = makeTempDir('selftest-data-');
    mkdirSync(selftestDir(dataDir), { recursive: true });
    writeFileSync(join(selftestDir(dataDir), HISTORY_FILE), '{"schema":1,"runs":[{"not":"a run"');
    const r = await selftest(fakes().runners, { dataDir });
    expect(r.result.exitCode).toBe(0);
    expect(r.result.report.saved).toMatchObject({ saved: true });
    expect(r.result.report.saved?.history_note).toMatch(/history/);
    expect(renderTable(r.result.report)).toMatch(/History: /);
    const files = readdirSync(selftestDir(dataDir)).sort();
    const aside = files.filter((f) => f !== HISTORY_FILE && f !== LAST_FILE);
    expect(aside).toHaveLength(1);
    expect(aside[0]).toMatch(/^history\.unreadable-.*\.json$/);
    expect(readFileSync(join(selftestDir(dataDir), aside[0] ?? ''), 'utf8')).toBe('{"schema":1,"runs":[{"not":"a run"');
    expect(readHistory(dataDir).runs).toEqual([r.run]);
    // No run in an unreadable history: nothing can have regressed from it.
    expect(r.run.controls.some((c) => c.regressed === true)).toBe(false);
  });
});
