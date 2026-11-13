/**
 * `dev-guardian selftest`, as a user runs it: the real CLI on the real
 * bundle, the real dispatcher, and — where they are installed — the real
 * scanners over the canaries the plugin ships.
 *
 * Three kinds of run:
 *
 *   - with NO scanner in reach (a bare PATH, an empty home): the command's
 *     shape — one JSON document, the exit codes, the history — on any
 *     machine, in seconds;
 *   - with Semgrep, gitleaks and Trivy (skipped, visibly, without them;
 *     `GUARDIAN_REQUIRE_SEMGREP=1` with `GUARDIAN_REQUIRE_GITLEAKS=1` makes
 *     their absence a failure): every core control detects (SC-001);
 *   - seeded faults (SC-002): a pack that no longer matches its canary, a
 *     pack that loads no rule, a damaged hooks bundle, a scanner that
 *     reports nothing — each is `silent`, and none is ever `detected`.
 */

import { cpSync, mkdirSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { CORE_CONTROLS } from '../../src/selftest/controls.js';
import { defaultRunners } from '../../src/selftest/defaultRunners.js';
import { installPaths } from '../../src/selftest/paths.js';
import { HOOKS_NOTE } from '../../src/selftest/report.js';
import { runSelftest, type ScanOutcome } from '../../src/selftest/run.js';
import { saveRun, type SelftestRun } from '../../src/selftest/store.js';
import { countVerdicts } from '../../src/selftest/verdict.js';
import { spawnSyncCapped, timeoutAbove } from '../helpers/spawnCap.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';
import { isInstalled } from '../helpers/toolchain.js';

const FAST_MS = 90_000;
/** A whole selftest with the real scanners: sixteen Semgrep runs, gitleaks, two Trivy scans. */
const FULL_MS = 900_000;
vi.setConfig({ testTimeout: timeoutAbove(FAST_MS) });
afterAll(cleanupTempDirs);

const REPO_ROOT = fileURLToPath(new URL('../../..', import.meta.url));
const CLI = join(REPO_ROOT, 'cli', 'dev-guardian.mjs');
const REQUIRED = process.env['GUARDIAN_REQUIRE_SEMGREP'] === '1' && process.env['GUARDIAN_REQUIRE_GITLEAKS'] === '1';

interface Run {
  status: number | null;
  stdout: string;
  stderr: string;
}

function cli(args: string[], env: NodeJS.ProcessEnv, timeout = FAST_MS): Run {
  const r = spawnSyncCapped(process.execPath, [CLI, 'selftest', ...args], { cwd: makeTempDir('selftest-cwd-'), encoding: 'utf8', timeout, env });
  return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

/**
 * An environment in which no scanner can be found: a PATH that is one empty
 * directory, and a home that has no `~/.local/bin`. Not Node's own directory —
 * on Linux that is `/usr/local/bin`, where the scanners are installed too
 * (measured in the toolchain container: gitleaks was found there). The CLI and
 * the hooks' dispatcher are started by Node's absolute path and need neither.
 */
function noScanners(dataDir: string): NodeJS.ProcessEnv {
  const home = makeTempDir('selftest-nohome-');
  const env: NodeJS.ProcessEnv = { ...process.env, NO_COLOR: '1', GUARDIAN_DATA_DIR: dataDir, HOME: home, USERPROFILE: home, PATH: makeTempDir('selftest-nopath-') };
  for (const key of ['Path', 'GUARDIAN_OFFLINE', 'GUARDIAN_HOOKS', 'GUARDIAN_HOOKS_BASH_BLOCK', 'LOCALAPPDATA', 'APPDATA', 'XDG_DATA_HOME']) delete env[key];
  return env;
}

/** This machine's environment, with the network the scanners use on a normal scan allowed. */
function realEnv(dataDir: string): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env, NO_COLOR: '1', GUARDIAN_DATA_DIR: dataDir };
  for (const key of ['GUARDIAN_OFFLINE', 'GUARDIAN_HOOKS', 'GUARDIAN_HOOKS_BASH_BLOCK']) delete env[key];
  return env;
}

interface Doc extends SelftestRun {
  saved?: { saved: boolean };
}

let scannersHere = false;
let semgrepHere = false;

beforeAll(async () => {
  const [semgrep, gitleaks, trivy] = await Promise.all([isInstalled('semgrep'), isInstalled('gitleaks'), isInstalled('trivy')]);
  semgrepHere = semgrep;
  scannersHere = semgrep && gitleaks && trivy;
});

describe('dev-guardian selftest — the command', () => {
  it('T-13 --json writes one JSON document with the same controls and verdicts as the table; an unknown option exits 3 with the usage', () => {
    const dataDir = makeTempDir('selftest-cli-data-');
    const env = noScanners(dataDir);
    const json = cli(['--json', '--no-save'], env);
    // No scanner in reach: every scanner control is missing, which is exit 2 — and still a whole report.
    expect(json.status, json.stderr).toBe(2);
    const doc = JSON.parse(json.stdout) as Doc;
    expect(json.stdout.trim().startsWith('{') && json.stdout.trim().endsWith('}')).toBe(true);
    expect(doc.schema).toBe(1);
    expect(doc.exit_code).toBe(2);
    expect(doc.hooks_note).toBe(HOOKS_NOTE);
    expect(doc.controls.map((c) => c.id).sort()).toEqual(CORE_CONTROLS.map((c) => c.id).sort());
    for (const c of doc.controls) {
      // The dispatcher is this checkout's, and it answers: the four hook checks detect with no scanner at all.
      expect(c.verdict, c.id).toBe(c.scanner === 'hooks' ? 'detected' : 'missing');
      if (c.verdict === 'missing') expect(c.next, c.id).toEqual(expect.any(String));
    }
    expect(doc.saved).toMatchObject({ saved: false });
    expect(readdirSync(dataDir)).toEqual([]);
    // Progress goes to stderr, never into the document.
    expect(json.stderr).toMatch(/hooks:bash-block/);

    const table = cli(['--no-save'], env);
    expect(table.status, table.stderr).toBe(2);
    const lines = table.stdout.split('\n');
    for (const c of doc.controls) {
      const line = lines.find((l) => l.trimStart().startsWith(`${c.id} `));
      expect(line, c.id).toBeDefined();
      expect(line, c.id).toContain(c.verdict);
    }
    expect(table.stdout).toContain(HOOKS_NOTE);

    for (const bad of [['--frobnicate'], ['--json', 'extra'], ['--history', '--keep']]) {
      const r = cli(bad, env);
      expect(r.status, bad.join(' ')).toBe(3);
      expect(r.stdout, bad.join(' ')).toBe('');
      expect(r.stderr, bad.join(' ')).toMatch(/selftest/);
      expect(r.stderr, bad.join(' ')).toMatch(/--json/);
    }
    // And the command is in the CLI's own help.
    const help = spawnSyncCapped(process.execPath, [CLI, '--help'], { encoding: 'utf8', timeout: FAST_MS, env });
    expect(`${help.stdout}${help.stderr}`).toMatch(/selftest \[--json\] \[--keep\] \[--no-save\] \[--history\]/);
  });

  it('T-37 --history prints the saved runs newest first and starts no scanner; with --json, the same as JSON', () => {
    const dataDir = makeTempDir('selftest-cli-history-');
    const at = (day: number): SelftestRun => {
      const controls = CORE_CONTROLS.map((c) => ({
        id: c.id,
        scanner: c.scanner,
        scanner_version: '9.9.9',
        verdict: day === 12 && c.id === 'gitleaks' ? ('silent' as const) : ('detected' as const),
      }));
      const verdicts = controls.map((c) => c.verdict);
      return {
        schema: 1,
        ran_at: `2026-11-${String(day).padStart(2, '0')}T08:00:00.000Z`,
        plugin_version: '3.9.0',
        platform: 'linux-x64',
        controls,
        no_canary: [],
        summary: countVerdicts(verdicts),
        exit_code: day === 12 ? 1 : 0,
        hooks_note: HOOKS_NOTE,
      };
    };
    for (const day of [10, 11, 12]) expect(saveRun(dataDir, at(day)).saved).toBe(true);
    const env = noScanners(dataDir);

    const text = cli(['--history'], env);
    expect(text.status, text.stderr).toBe(0);
    const order = ['2026-11-12T08:00:00.000Z', '2026-11-11T08:00:00.000Z', '2026-11-10T08:00:00.000Z'].map((d) => text.stdout.indexOf(d));
    expect(order.every((i) => i >= 0)).toBe(true);
    expect(order).toEqual([...order].sort((a, b) => a - b));
    expect(text.stdout).toMatch(/gitleaks\s+silent/);
    // It ran nothing: no progress line of a control, and the three runs are still the three runs.
    expect(text.stderr).not.toMatch(/hooks:bash-block|semgrep:/);

    const json = cli(['--history', '--json'], env);
    expect(json.status, json.stderr).toBe(0);
    const doc = JSON.parse(json.stdout) as { schema: number; runs: SelftestRun[] };
    expect(doc.schema).toBe(1);
    expect(doc.runs.map((r) => r.ran_at)).toEqual(['2026-11-12T08:00:00.000Z', '2026-11-11T08:00:00.000Z', '2026-11-10T08:00:00.000Z']);
    expect(doc.runs[0]?.controls.find((c) => c.id === 'gitleaks')?.verdict).toBe('silent');

    // Nothing saved yet: said, exit 0.
    const none = cli(['--history'], noScanners(makeTempDir('selftest-cli-empty-')));
    expect(none.status, none.stderr).toBe(0);
    expect(none.stdout).toMatch(/No selftest has been saved/);
  });
});

describe('dev-guardian selftest — the real scanners', () => {
  it.runIf(REQUIRED)('GUARDIAN_REQUIRE_SEMGREP=1 and GUARDIAN_REQUIRE_GITLEAKS=1 — Semgrep, gitleaks and Trivy must be on PATH', () => {
    expect(scannersHere, 'semgrep, gitleaks and trivy on PATH').toBe(true);
  });

  it(
    'T-22 with Semgrep, gitleaks and Trivy installed, every core control detects its canary and the command exits 0 (SC-001)',
    (ctx) => {
      if (!scannersHere) return ctx.skip();
      const dataDir = makeTempDir('selftest-cli-real-');
      const r = cli(['--json'], realEnv(dataDir), FULL_MS);
      const doc = JSON.parse(r.stdout) as Doc;
      const notDetected = doc.controls.filter((c) => c.verdict !== 'detected').map((c) => `${c.id}: ${c.verdict} — ${c.reason ?? ''}`);
      expect(notDetected).toEqual([]);
      expect(doc.controls).toHaveLength(CORE_CONTROLS.length);
      expect(doc.controls.length).toBeGreaterThanOrEqual(22);
      // A version, or — for a Semgrep that only exists as its Docker image — the image's name.
      for (const c of doc.controls) expect(c.scanner_version, c.id).toEqual(expect.stringMatching(/\d+\.\d+|^docker \(/));
      expect(r.status, r.stderr).toBe(0);
      expect(doc.saved).toMatchObject({ saved: true });
      expect(readdirSync(join(dataDir, 'selftest')).sort()).toEqual(['history.json', 'last.json']);
    },
    timeoutAbove(FULL_MS),
  );

  it(
    'T-22 the real gitleaks and Trivy runners, in this process: each reports its canary, with the version that ran',
    async (ctx) => {
      if (!scannersHere) return ctx.skip();
      const paths = installPaths();
      const r = await runSelftest({
        ...paths,
        runners: defaultRunners(),
        dataDir: makeTempDir('selftest-real-data-'),
        // A copy of the environment, as any caller may hand one: the scanners must still be found.
        env: realEnv(''),
        controls: CORE_CONTROLS.filter((c) => c.scanner === 'gitleaks' || c.scanner === 'trivy'),
        save: false,
      });
      const controls = r.report.run.controls;
      expect(controls.map((c) => c.id).sort()).toEqual(['gitleaks', 'trivy:deps', 'trivy:iac']);
      for (const c of controls) {
        expect(`${c.id}: ${c.verdict} ${c.reason ?? ''}`.trim(), c.id).toBe(`${c.id}: detected`);
        expect(c.scanner_version, c.id).toEqual(expect.stringMatching(/\d+\.\d+/));
      }
      expect(r.exitCode).toBe(0);
    },
    timeoutAbove(FULL_MS),
  );

  it(
    'T-23 seeded faults with the real Semgrep: a pack that no longer matches its canary and a pack that loads no rule are silent (SC-002)',
    async (ctx) => {
      if (!semgrepHere) return ctx.skip();
      const paths = installPaths();
      const [stale, empty, intact] = CORE_CONTROLS.filter((c) => c.kind === 'semgrep-pack');
      expect(intact).toBeDefined();
      const packs = makeTempDir('selftest-faulty-packs-');
      cpSync(paths.packsDir, packs, { recursive: true });
      // The pack is valid, loads, runs — and its one rule matches nothing the canary holds.
      writeFileSync(
        join(packs, stale?.pack ?? ''),
        'rules:\n  - id: a-rule-that-matches-nothing\n    languages: [generic]\n    severity: WARNING\n    message: nothing\n    pattern: zz_no_such_text_anywhere_zz\n',
      );
      writeFileSync(join(packs, empty?.pack ?? ''), 'rules: []\n');
      const r = await runSelftest({
        ...paths,
        packsDir: packs,
        runners: defaultRunners(),
        dataDir: makeTempDir('selftest-faulty-data-'),
        env: realEnv(''),
        controls: [stale, empty, intact].filter((c) => c !== undefined),
        save: false,
      });
      const verdict = (id: string | undefined): string | undefined => r.report.run.controls.find((c) => c.id === id)?.verdict;
      expect(verdict(intact?.id), 'the untouched pack still detects: the faults are what is measured').toBe('detected');
      expect(verdict(stale?.id)).toBe('silent');
      expect(verdict(empty?.id)).toBe('silent');
      expect(r.exitCode).toBe(1);
    },
    timeoutAbove(FULL_MS),
  );

  it('T-23 seeded faults that need no scanner: a damaged hooks bundle and a scanner that reports nothing are silent, never detected (SC-002)', async () => {
    const paths = installPaths();
    // A copy of the hooks and of their bundle, with the shell guard's part cut off: the dispatcher fails open.
    const copy = makeTempDir('selftest-faulty-hooks-');
    cpSync(join(REPO_ROOT, 'hooks'), join(copy, 'hooks'), { recursive: true });
    mkdirSync(join(copy, 'mcp', 'dist'), { recursive: true });
    for (const name of readdirSync(join(REPO_ROOT, 'mcp', 'dist'))) {
      if (/^hooks.*\.js$/.test(name)) cpSync(join(REPO_ROOT, 'mcp', 'dist', name), join(copy, 'mcp', 'dist', name));
    }
    cpSync(join(REPO_ROOT, '.claude-plugin'), join(copy, '.claude-plugin'), { recursive: true });
    writeFileSync(join(copy, 'mcp', 'dist', 'hooksBash.js'), 'export const broken = ;\n');
    const nothing = async (): Promise<ScanOutcome> => ({ ended: 'ok', findings: [], read: null });
    const real = defaultRunners();
    const env = realEnv('');
    const home = makeTempDir('selftest-faulty-home-');
    const r = await runSelftest({
      ...paths,
      dispatcherPath: join(copy, 'hooks', 'guardian-hook.mjs'),
      dataDir: makeTempDir('selftest-faulty-data-'),
      env: { ...env, HOME: home, USERPROFILE: home },
      homeDir: home,
      save: false,
      controls: CORE_CONTROLS.filter((c) => c.kind !== 'semgrep-pack'),
      runners: {
        ...real,
        probe: async () => ({ installed: true, version: '0.0.0' }),
        // An empty report with exit 0 — from a scanner that has stopped seeing.
        gitleaks: nothing,
        // Trivy read the file and found nothing in it.
        trivy: async (args) => ({
          ended: 'ok',
          findings: [],
          read: [CORE_CONTROLS.find((c) => c.id === (args.mode === 'deps' ? 'trivy:deps' : 'trivy:iac'))?.canary ?? ''],
        }),
        installedTools: async () => [],
      },
    });
    const verdict = (id: string): string | undefined => r.report.run.controls.find((c) => c.id === id)?.verdict;
    for (const id of ['gitleaks', 'trivy:deps', 'trivy:iac', 'hooks:bash-block', 'hooks:powershell-block']) expect(verdict(id), id).toBe('silent');
    // The parts of the bundle that were not touched still answer.
    expect(verdict('hooks:settings-guard')).toBe('detected');
    expect(verdict('hooks:secret-warning')).toBe('detected');
    expect(r.exitCode).toBe(1);
  });
});
