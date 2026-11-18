/**
 * What a selftest prints (`src/selftest/report.ts`): a line a person can act
 * on for every control that did not detect, and the sentence that keeps the
 * hook checks honest — they prove the detectors answer, not that the host
 * runs them.
 */

import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';
import { CORE_CONTROLS } from '../../../src/selftest/controls.js';
import { SECRET_CANARY } from '../../../src/selftest/hookChecks.js';
import { HOOKS_NOTE, nextStepFor, renderHistory, renderHistoryJson, renderJson, renderTable, type SelftestReport } from '../../../src/selftest/report.js';
import { runSelftest, type HookRunArgs, type ScanOutcome, type SelftestRunners } from '../../../src/selftest/run.js';
import { readLast, scannerSelftest, SELFTEST_SCANNERS, selftestStatus, type ControlResult, type SelftestRun } from '../../../src/selftest/store.js';
import { countVerdicts } from '../../../src/selftest/verdict.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

const CONTROLS: ControlResult[] = [
  { id: 'gitleaks', scanner: 'gitleaks', scanner_version: '8.30.1', verdict: 'detected' },
  { id: 'hooks:bash-block', scanner: 'hooks', scanner_version: '3.9.0', verdict: 'disabled_by_user', reason: 'switched off by the user: GUARDIAN_HOOKS=off' },
  { id: 'hooks:settings-guard', scanner: 'hooks', scanner_version: '3.9.0', verdict: 'silent', reason: 'the dispatcher ran and did not deny it' },
  { id: 'semgrep:bugfix-py', scanner: 'semgrep', scanner_version: '1.182.0', verdict: 'silent', reason: 'ran to the end, read the canary and did not report it' },
  { id: 'semgrep:base', scanner: 'semgrep', scanner_version: '1.182.0', verdict: 'unverified', reason: 'did not finish in 180 s' },
  { id: 'trivy:deps', scanner: 'trivy', scanner_version: null, verdict: 'missing', reason: 'trivy is not installed' },
];

function report(controls: ControlResult[] = CONTROLS): SelftestReport {
  const withNext = controls.map((c) => {
    const next = nextStepFor(c, { installCommand: 'scoop install trivy', ...(c.id === 'semgrep:bugfix-py' ? { pack: 'bugfix-py.yml' } : {}) });
    return next !== undefined ? { ...c, next } : c;
  });
  const run: SelftestRun = {
    schema: 1,
    ran_at: '2026-11-13T10:00:00.000Z',
    plugin_version: '3.9.0',
    platform: 'win32-x64',
    controls: withNext,
    no_canary: ['bandit', 'phpcs'],
    summary: { ...countVerdicts(withNext.map((c) => c.verdict)), no_canary: 2 },
    exit_code: 1,
    hooks_note: HOOKS_NOTE,
  };
  return { run, saved: { saved: true, dir: 'the data directory' } };
}

describe('the selftest report', () => {
  it('T-09 gives every control its scanner version, and every silent, unverified and missing control what to check next', () => {
    for (const c of CONTROLS) {
      const next = nextStepFor(c, { installCommand: 'scoop install trivy' });
      if (c.verdict === 'silent' || c.verdict === 'unverified' || c.verdict === 'missing') {
        expect(next, c.id).toEqual(expect.any(String));
        expect((next ?? '').length, c.id).toBeGreaterThan(20);
      } else {
        expect(next, c.id).toBeUndefined();
      }
    }
    // A missing scanner is told how it is installed; a silent pack is named.
    expect(nextStepFor(CONTROLS[5] as ControlResult, { installCommand: 'scoop install trivy' })).toContain('scoop install trivy');
    expect(nextStepFor(CONTROLS[3] as ControlResult, { pack: 'bugfix-py.yml' })).toContain('bugfix-py.yml');

    const table = renderTable(report());
    const lines = table.split('\n');
    for (const c of report().run.controls) {
      const line = lines.find((l) => l.trimStart().startsWith(`${c.id} `));
      expect(line, c.id).toBeDefined();
      expect(line, c.id).toContain(c.verdict);
      expect(line, c.id).toContain(c.scanner_version ?? '-');
      if (c.next !== undefined) expect(table, c.id).toContain(`next: ${c.next}`);
    }
    // Installed scanners with no canary are listed apart, never as a verified control.
    expect(table).toMatch(/no canary.*bandit, phpcs/);
    expect(lines.some((l) => l.trimStart().startsWith('bandit '))).toBe(false);
  });

  it('T-14 the table and the JSON both say that the hook checks do not prove the host runs the hooks', () => {
    expect(HOOKS_NOTE).toMatch(/do not prove that the host\s+runs it/);
    expect(renderTable(report())).toContain(HOOKS_NOTE);
    const json = JSON.parse(renderJson(report())) as { schema: number; hooks_note: string; controls: unknown[] };
    expect(json.schema).toBe(1);
    expect(json.hooks_note).toBe(HOOKS_NOTE);
    expect(json.controls).toHaveLength(CONTROLS.length);
    // One document: nothing before or after it.
    expect(renderJson(report()).trim().startsWith('{')).toBe(true);
    expect(renderJson(report()).trim().endsWith('}')).toBe(true);
  });

  it('T-09 says what happened around the run: interrupted, kept, not removed, left behind, not saved', () => {
    const base = report();
    const interrupted = renderTable({ ...base, interrupted: true, saved: { saved: false, skipped: 'interrupted' } });
    expect(interrupted).toMatch(/Interrupted: the controls not reached are unverified, and nothing was saved/);
    expect(interrupted).not.toMatch(/Not saved:/);
    expect(renderTable({ ...base, workspace: { path: '/tmp/dev-guardian-selftest-abc', kept: true } })).toContain('Kept, as asked: /tmp/dev-guardian-selftest-abc');
    const left = renderTable({ ...base, workspace: { path: '/tmp/dev-guardian-selftest-abc', kept: false, note: 'EBUSY' } });
    expect(left).toMatch(/NOT REMOVED — the temporary directory is still there: \/tmp\/dev-guardian-selftest-abc \(EBUSY\)/);
    expect(renderTable({ ...base, leftovers: ['/tmp/dev-guardian-selftest-old'] })).toMatch(/An earlier selftest left its temporary directory behind.*dev-guardian-selftest-old/);
    expect(renderTable({ ...base, saved: { saved: false, note: 'the result was not saved in X: EACCES' } })).toContain('Not saved: the result was not saved in X: EACCES.');
    expect(renderTable({ ...base, saved: { saved: true, dir: 'D', history_note: 'the selftest history is not JSON' } })).toContain('History: the selftest history is not JSON.');
    // A regressed control says so, with what changed — or that nothing recorded did.
    const regressed = report([
      { id: 'gitleaks', scanner: 'gitleaks', scanner_version: '8.31.0', verdict: 'silent', regressed: true, changed: ['gitleaks 8.30.1 → 8.31.0'] },
      { id: 'trivy:deps', scanner: 'trivy', scanner_version: '0.74.0', verdict: 'unverified', regressed: true, changed: [], reason: 'offline' },
    ]);
    const table = renderTable(regressed);
    expect(table).toMatch(/gitleaks +silent +8\.31\.0 +REGRESSED — detected in the run before this one; changed: gitleaks 8\.30\.1 → 8\.31\.0/);
    expect(table).toMatch(/trivy:deps +unverified +0\.74\.0 +REGRESSED — detected in the run before this one; nothing recorded changed — offline/);
    // What to check next, for the hooks too.
    expect(nextStepFor({ id: 'hooks:bash-block', scanner: 'hooks', verdict: 'missing' })).toMatch(/dispatcher.*reinstall the plugin/);
    expect(nextStepFor({ id: 'hooks:bash-block', scanner: 'hooks', verdict: 'silent' })).toMatch(/GUARDIAN_HOOKS_DEBUG=1/);
    expect(nextStepFor({ id: 'hooks:bash-block', scanner: 'hooks', verdict: 'unverified' })).toMatch(/run the selftest again/);
    expect(nextStepFor({ id: 'gitleaks', scanner: 'gitleaks', verdict: 'missing' })).toMatch(/install gitleaks.*check_toolchain/);
    expect(nextStepFor({ id: 'gitleaks', scanner: 'gitleaks', verdict: 'silent' })).toMatch(/gitleaks read the canary and reported nothing/);
  });

  it('T-37 the saved runs are printed newest first as they are given, a line per control, and as one JSON document', () => {
    const newer = report().run;
    const older: SelftestRun = { ...newer, ran_at: '2026-11-12T10:00:00.000Z', exit_code: 0, controls: newer.controls.map((c) => ({ ...c, verdict: 'detected' as const })) };
    const marked: SelftestRun = { ...newer, controls: newer.controls.map((c) => (c.id === 'gitleaks' ? { ...c, verdict: 'silent' as const, regressed: true as const } : c)) };
    const text = renderHistory([marked, older]);
    expect(text.indexOf(newer.ran_at)).toBeGreaterThanOrEqual(0);
    expect(text.indexOf(newer.ran_at)).toBeLessThan(text.indexOf(older.ran_at));
    expect(text).toMatch(/gitleaks +silent +8\.30\.1 +REGRESSED/);
    expect(text).toMatch(/\(exit 1\)/);
    expect(text).toMatch(/\(exit 0\)/);
    for (const c of newer.controls) expect(text, c.id).toContain(c.id);
    expect(renderHistory([])).toMatch(/No selftest has been saved on this machine/);
    expect(renderHistory([], 'the selftest history is not JSON')).toMatch(/^the selftest history is not JSON\.\n\nNo selftest has been saved/);
    const json = JSON.parse(renderHistoryJson([marked, older], 'a problem')) as { schema: number; problem?: string; runs: SelftestRun[] };
    expect(json).toMatchObject({ schema: 1, problem: 'a problem' });
    expect(json.runs.map((r) => r.ran_at)).toEqual([newer.ran_at, older.ran_at]);
    expect(JSON.parse(renderHistoryJson([]))).toEqual({ schema: 1, runs: [] });
  });
});

// ───────────────── selftest-install-vet-canary — the fifth hook check, shown where the other four are

describe('selftest-install-vet-canary', () => {
  const VET = 'hooks:install-vet';
  const SHELL = 'hooks:bash-block';
  const REPO_ROOT = fileURLToPath(new URL('../../../..', import.meta.url));
  const NOW = Date.parse('2026-11-13T12:00:00.000Z');
  const COMMAND = 'node "/plugin/cli/dev-guardian.mjs" selftest';

  /** What a working guard prints: a deny before a tool runs, the secret warning after a write. */
  const working = (args: HookRunArgs): string =>
    JSON.stringify({
      hookSpecificOutput:
        args.event === 'PostToolUse'
          ? { hookEventName: 'PostToolUse', additionalContext: 'possible secret(s) just written' }
          : { hookEventName: 'PreToolUse', permissionDecision: 'deny' },
    });
  /** The two checks whose payload is a Bash command: the shell guard's and the install's. */
  const isBash = (args: HookRunArgs): boolean => args.payload['tool_name'] === 'Bash';

  /**
   * A selftest of the secret scan and the hook checks, every process
   * replaced: gitleaks reports its canary, and the dispatcher's answer to
   * each payload is `answer`'s. Saved in a data directory of its own.
   */
  async function ran(answer: (args: HookRunArgs) => string, env: Record<string, string> = {}): Promise<{ report: SelftestReport; exitCode: number; dataDir: string }> {
    const noScanner = async (): Promise<ScanOutcome> => {
      throw new Error('this scanner is not run by this test');
    };
    const runners: SelftestRunners = {
      probe: async () => ({ installed: true, version: '9.9.9' }),
      semgrep: noScanner,
      gitleaks: async () => ({ ended: 'ok', findings: [{ rule: 'aws-access-token', file: SECRET_CANARY }], read: null }),
      trivy: noScanner,
      hook: async (args) => ({ exitCode: 0, stdout: answer(args), timedOut: false }),
      installedTools: async () => [],
    };
    const dataDir = makeTempDir('selftest-report-data-');
    const result = await runSelftest({
      runners,
      packsDir: join(REPO_ROOT, 'configs', 'semgrep'),
      canariesDir: join(REPO_ROOT, 'configs', 'selftest'),
      // Only looked at, to see that an install has one: the launcher above starts nothing.
      dispatcherPath: join(REPO_ROOT, 'hooks', 'guardian-hook.mjs'),
      dataDir,
      pluginVersion: '3.9.0',
      tmpRoot: makeTempDir('selftest-report-tmp-'),
      env,
      homeDir: makeTempDir('selftest-report-home-'),
      now: () => new Date(NOW),
      controls: CORE_CONTROLS.filter((c) => c.kind === 'hook' || c.kind === 'gitleaks'),
    });
    return { report: result.report, exitCode: result.exitCode, dataDir };
  }

  const controlOf = (shown: SelftestReport, id: string): ControlResult | undefined => shown.run.controls.find((c) => c.id === id);
  const rowOf = (shown: SelftestReport, id: string): string => renderTable(shown).split('\n').find((l) => l.trimStart().startsWith(`${id} `)) ?? '';
  const health = (dataDir: string): ReturnType<typeof selftestStatus> => selftestStatus({ dataDir, pluginVersion: '3.9.0', command: COMMAND, now: NOW });

  it('T-06 the install check is in the table, in the JSON and in what is saved; health_status and check_toolchain tell its silent as they tell the other hook checks', async () => {
    // Every guard answers as a working one.
    const all = await ran(working);
    const detected = { id: VET, scanner: 'hooks', scanner_version: '3.9.0', verdict: 'detected' };
    expect(controlOf(all.report, VET), `the run has the control ${VET}`).toEqual(detected);
    expect(rowOf(all.report, VET)).toMatch(/^\s+hooks:install-vet +detected +3\.9\.0$/);
    const json = JSON.parse(renderJson(all.report)) as SelftestRun;
    expect(json.controls.find((c) => c.id === VET)).toEqual(detected);
    expect(json.summary.detected).toBe(json.controls.length);
    const saved = readLast(all.dataDir, NOW);
    expect(saved.state === 'ok' ? saved.run.controls.find((c) => c.id === VET) : saved).toEqual(detected);
    expect(health(all.dataDir).warning).toBeNull();
    expect(all.exitCode).toBe(0);

    // The dispatcher lets both Bash payloads through: the shell guard and the install check are silent, and told alike.
    const mute = await ran((args) => (isBash(args) ? '' : working(args)));
    const vet = controlOf(mute.report, VET);
    const shell = controlOf(mute.report, SHELL);
    expect([shell?.verdict, vet?.verdict]).toEqual(['silent', 'silent']);
    expect(vet?.next).toEqual(expect.any(String));
    expect(vet?.next).toBe(shell?.next);
    expect(rowOf(mute.report, VET)).toMatch(/^\s+hooks:install-vet +silent +3\.9\.0 +\S/);
    expect(mute.exitCode).toBe(1);
    // health_status: both are named in the one warning that says 0 findings prove nothing here.
    const blind = health(mute.dataDir);
    expect(blind.selftest.silent).toEqual([SHELL, VET]);
    for (const id of [SHELL, VET]) expect(blind.warning, id).toContain(id);
    expect(blind.warning).toMatch(/0 findings proves nothing on this machine/);
    // check_toolchain shows scanners, and the hooks are none: a silent hook check is no scanner's verdict.
    expect(SELFTEST_SCANNERS as readonly string[]).not.toContain('hooks');
    const gitleaks = scannerSelftest(readLast(mute.dataDir, NOW), 'gitleaks', '9.9.9');
    expect(gitleaks).toMatchObject({ verdict: 'detected', stale: false });
    expect(gitleaks).not.toHaveProperty('silent');

    // Unverified is said in the table with its reason and counted — and, as for any control, is not that warning.
    const offline = await ran(working, { GUARDIAN_OFFLINE: '1' });
    const unverified = controlOf(offline.report, VET);
    expect(unverified?.verdict).toBe('unverified');
    expect(unverified?.next).toEqual(expect.any(String));
    expect(rowOf(offline.report, VET)).toContain(unverified?.reason ?? 'no reason');
    expect(JSON.parse(renderJson(offline.report))).toMatchObject({ summary: { unverified: 1, silent: 0 }, exit_code: 2 });
    const open = health(offline.dataDir);
    expect(open.warning).toBeNull();
    expect(open.selftest.counts).toMatchObject({ unverified: 1, silent: 0 });
  });
});
