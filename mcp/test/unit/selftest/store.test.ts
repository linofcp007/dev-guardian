/**
 * The saved selftest result (`src/selftest/store.ts`): what is read back is
 * put in front of a model as "this install was verified", so a file that is
 * not a result — unreadable, the wrong shape, from the future, too large — is
 * NO result, and a result of another version or another month is `stale`.
 */

import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';
import { decideInstallCommand } from '../../../src/pkgvet/hookDecision.js';
import { CORE_CONTROLS } from '../../../src/selftest/controls.js';
import { HOOKS_NOTE } from '../../../src/selftest/report.js';
import { runSelftest, type HookRunArgs, type ScanOutcome, type SelftestRunners } from '../../../src/selftest/run.js';
import {
  HISTORY_FILE,
  HISTORY_MAX,
  LAST_FILE,
  LAST_MAX_BYTES,
  markRegressions,
  readHistory,
  readLast,
  saveRun,
  scannerSelftest,
  selftestDir,
  selftestStatus,
  type ControlResult,
  type SelftestRun,
} from '../../../src/selftest/store.js';
import { countVerdicts, type Verdict } from '../../../src/selftest/verdict.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

const NOW = Date.parse('2026-11-13T12:00:00.000Z');
const DAY = 24 * 60 * 60 * 1000;
const COMMAND = 'node "/plugin/cli/dev-guardian.mjs" selftest';

function control(id: string, verdict: Verdict, version: string | null = '1.182.0'): ControlResult {
  return { id, scanner: id.split(':')[0] === 'hooks' ? 'hooks' : (id.split(':')[0] ?? id), scanner_version: version, verdict };
}

function aRun(over: Partial<SelftestRun> = {}): SelftestRun {
  const controls = over.controls ?? [control('semgrep:base', 'detected'), control('gitleaks', 'detected', '8.30.1')];
  return {
    schema: 1,
    ran_at: new Date(NOW - DAY).toISOString(),
    plugin_version: '3.9.0',
    platform: 'win32-x64',
    controls,
    no_canary: [],
    summary: countVerdicts(controls.map((c) => c.verdict)),
    exit_code: 0,
    hooks_note: HOOKS_NOTE,
    ...over,
  };
}

/** A data directory whose `selftest/last.json` holds `content`. */
function dataDirWithLast(content: string | Buffer): string {
  const dir = makeTempDir('selftest-store-');
  mkdirSync(selftestDir(dir), { recursive: true });
  writeFileSync(join(selftestDir(dir), LAST_FILE), content);
  return dir;
}

const status = (dataDir: string, pluginVersion = '3.9.0') => selftestStatus({ dataDir, pluginVersion, command: COMMAND, now: NOW });

describe('the saved result, read back', () => {
  it('T-28 a result of another plugin version, or older than 30 days, is stale and says why', () => {
    const fresh = status(dataDirWithLast(JSON.stringify(aRun())));
    expect(fresh.selftest).toMatchObject({ state: 'ok', age_days: 1, plugin_version: '3.9.0', command: COMMAND });
    expect(fresh.selftest.stale_because).toBeUndefined();

    const otherVersion = status(dataDirWithLast(JSON.stringify(aRun())), '3.10.0');
    expect(otherVersion.selftest.state).toBe('stale');
    expect(otherVersion.selftest.stale_because).toHaveLength(1);
    expect(otherVersion.selftest.stale_because?.[0]).toMatch(/3\.9\.0.*3\.10\.0/);

    const at = (days: number) => status(dataDirWithLast(JSON.stringify(aRun({ ran_at: new Date(NOW - days * DAY).toISOString() }))));
    expect(at(30).selftest.state).toBe('ok');
    expect(at(31).selftest.state).toBe('stale');
    expect(at(31).selftest.stale_because?.[0]).toMatch(/31 days/);
    expect(at(31).selftest.age_days).toBe(31);

    // Both at once: both reasons.
    const both = selftestStatus({
      dataDir: dataDirWithLast(JSON.stringify(aRun({ ran_at: new Date(NOW - 40 * DAY).toISOString() }))),
      pluginVersion: '4.0.0',
      command: COMMAND,
      now: NOW,
    });
    expect(both.selftest.stale_because).toHaveLength(2);
  });

  it('T-32 a last.json that is not a result — unreadable, not JSON, another shape, from the future, too large — is never_run with a note, never ok', () => {
    const none = status(makeTempDir('selftest-none-'));
    expect(none.selftest).toEqual({ state: 'never_run', command: COMMAND });
    expect(none.warning).toBeNull();

    const asDirectory = makeTempDir('selftest-store-');
    mkdirSync(join(selftestDir(asDirectory), LAST_FILE), { recursive: true });
    const valid = aRun();
    const cases: Array<[string, string]> = [
      ['a directory in its place', asDirectory],
      ['not JSON', dataDirWithLast('{ "schema": 1, ')],
      ['a JSON array', dataDirWithLast('[]')],
      ['another schema version', dataDirWithLast(JSON.stringify({ ...valid, schema: 2 }))],
      ['a key this code does not write', dataDirWithLast(JSON.stringify({ ...valid, verified: true }))],
      ['a verdict that does not exist', dataDirWithLast(JSON.stringify({ ...valid, controls: [{ ...valid.controls[0], verdict: 'passed' }] }))],
      ['no controls key', dataDirWithLast(JSON.stringify({ ...valid, controls: undefined }))],
      ['a date that is not one', dataDirWithLast(JSON.stringify({ ...valid, ran_at: 'yesterday' }))],
      ['dated in the future', dataDirWithLast(JSON.stringify(aRun({ ran_at: new Date(NOW + DAY).toISOString() })))],
      ['larger than the cap', dataDirWithLast(JSON.stringify({ ...valid, hooks_note: 'x'.repeat(LAST_MAX_BYTES) }))],
    ];
    for (const [what, dataDir] of cases) {
      const read = readLast(dataDir, NOW);
      expect(read.state, what).toBe('invalid');
      const s = status(dataDir);
      expect(s.selftest.state, what).toBe('never_run');
      expect(s.selftest.note, what).toEqual(expect.any(String));
      expect(s.selftest.ran_at, what).toBeUndefined();
      expect(s.selftest.counts, what).toBeUndefined();
      expect(s.warning, what).toBeNull();
      // And no scanner is said to have been verified by it.
      expect(scannerSelftest(read, 'semgrep', '1.182.0'), what).toBe('never_verified');
    }
    // The valid one, for contrast: the same reader does say ok.
    expect(readLast(dataDirWithLast(JSON.stringify(valid)), NOW).state).toBe('ok');
  });

  it('T-34 after N saves the history holds the newest min(N, 50) runs, newest first', () => {
    const dataDir = makeTempDir('selftest-history-');
    for (let n = 1; n <= 120; n += 1) {
      const ranAt = new Date(NOW + n * 60_000).toISOString();
      const saved = saveRun(dataDir, aRun({ ran_at: ranAt }), NOW + n * 60_000);
      expect(saved.saved, `save ${n}: ${saved.note ?? ''}`).toBe(true);
      if (n === 1 || n === 49 || n === 50 || n === 51 || n === 120) {
        const history = readHistory(dataDir);
        expect(history.problem, `after ${n}`).toBeUndefined();
        expect(history.runs, `after ${n}`).toHaveLength(Math.min(n, HISTORY_MAX));
        expect(history.runs[0]?.ran_at, `after ${n}`).toBe(ranAt);
        const times = history.runs.map((r) => Date.parse(r.ran_at));
        expect(times, `after ${n}`).toEqual([...times].sort((a, b) => b - a));
        // The oldest kept is the (N - 49)th saved, never an earlier one.
        expect(times[times.length - 1], `after ${n}`).toBe(NOW + Math.max(1, n - HISTORY_MAX + 1) * 60_000);
        // last.json is the newest run alone.
        const last = JSON.parse(readFileSync(join(selftestDir(dataDir), LAST_FILE), 'utf8')) as SelftestRun;
        expect(last.ran_at, `after ${n}`).toBe(ranAt);
      }
    }
    expect(JSON.parse(readFileSync(join(selftestDir(dataDir), HISTORY_FILE), 'utf8'))).toMatchObject({ schema: 1 });
  });

  it('T-35 a control that detected in the run before and is silent, unverified or missing now is regressed, with what changed', () => {
    const before = aRun({
      plugin_version: '3.8.1',
      platform: 'win32-x64',
      controls: [
        control('semgrep:base', 'detected', '1.182.0'),
        control('semgrep:bugfix-py', 'detected', '1.182.0'),
        control('gitleaks', 'detected', '8.30.1'),
        control('trivy:deps', 'unverified', '0.74.0'),
        control('trivy:iac', 'detected', '0.74.0'),
        control('hooks:bash-block', 'detected', '3.8.1'),
      ],
    });
    const after = aRun({
      plugin_version: '3.9.0',
      platform: 'linux-x64',
      controls: [
        control('semgrep:base', 'silent', '1.190.0'),
        control('semgrep:bugfix-py', 'detected', '1.190.0'),
        control('gitleaks', 'unverified', '8.30.1'),
        control('trivy:deps', 'silent', '0.74.0'),
        control('trivy:iac', 'missing', null),
        control('hooks:bash-block', 'disabled_by_user', '3.9.0'),
        control('semgrep:new-pack', 'silent', '1.190.0'),
      ],
    });
    const marked = markRegressions(after, before);
    const by = new Map(marked.controls.map((c) => [c.id, c]));
    expect(by.get('semgrep:base')).toMatchObject({ regressed: true });
    expect(by.get('semgrep:base')?.changed).toEqual(['plugin 3.8.1 → 3.9.0', 'semgrep 1.182.0 → 1.190.0', 'platform win32-x64 → linux-x64']);
    // The scanner did not change for gitleaks: only what did is named.
    expect(by.get('gitleaks')).toMatchObject({ regressed: true, changed: ['plugin 3.8.1 → 3.9.0', 'platform win32-x64 → linux-x64'] });
    expect(by.get('trivy:iac')).toMatchObject({ regressed: true });
    expect(by.get('trivy:iac')?.changed).toContain('trivy 0.74.0 → unknown');
    // Still detecting; not detected before either; switched off by the user; not in the run before (EC-8).
    for (const id of ['semgrep:bugfix-py', 'trivy:deps', 'hooks:bash-block', 'semgrep:new-pack']) {
      expect(by.get(id)?.regressed, id).toBeUndefined();
      expect(by.get(id)?.changed, id).toBeUndefined();
    }
    // A first run has nothing to regress from.
    expect(markRegressions(after, undefined)).toEqual(after);
    // What health_status reads back names them.
    const dataDir = makeTempDir('selftest-regressed-');
    expect(saveRun(dataDir, marked, NOW).saved).toBe(true);
    const s = selftestStatus({ dataDir, pluginVersion: '3.9.0', command: COMMAND, now: NOW + DAY });
    expect(s.selftest.regressed).toEqual(['semgrep:base', 'gitleaks', 'trivy:iac']);
    expect(s.selftest.silent).toEqual(['semgrep:base', 'trivy:deps', 'semgrep:new-pack']);
    expect(s.warning).toEqual(expect.any(String));
  });
});

// ───────────────── selftest-install-vet-canary — what is saved of the one hook check that hears from the network

describe('selftest-install-vet-canary', () => {
  const VET = 'hooks:install-vet';
  const REPO_ROOT = fileURLToPath(new URL('../../../..', import.meta.url));
  /** In everything the dispatcher answers the install check here, around what the selftest may keep: it must be in nothing saved. */
  const MARK = 'zz-raw-answer-7731';
  /** The keys of a saved control: the answer has no field of its own. */
  const KEPT = ['id', 'next', 'reason', 'scanner', 'scanner_version', 'verdict'];
  /** The canary's install, as the selftest hands it to the hook: text, put together from pieces. */
  const CANARY_INSTALL = ['npm', 'install', 'crossenv'].join(' ');

  const answer = (output: Record<string, unknown>): string => JSON.stringify({ hookSpecificOutput: { hookEventName: 'PreToolUse', ...output } });
  const isVet = (args: HookRunArgs): boolean => args.payload['tool_name'] === 'Bash' && JSON.stringify(args.payload['tool_input']).includes('crossenv');

  /**
   * What a selftest of the hook checks saves when the dispatcher prints
   * `vetAnswer` for the install check (and answers the other four as a
   * working guard does): the control as it is read back, and the text of the
   * two files. Every process is replaced.
   */
  async function savedAfter(vetAnswer: string): Promise<{ control: ControlResult | undefined; files: string; readsBack: string }> {
    const noScanner = async (): Promise<ScanOutcome> => {
      throw new Error('no scanner is run by this test');
    };
    const runners: SelftestRunners = {
      probe: async () => ({ installed: true, version: '9.9.9' }),
      semgrep: noScanner,
      gitleaks: noScanner,
      trivy: noScanner,
      hook: async (args) => {
        if (isVet(args)) return { exitCode: 0, stdout: vetAnswer, timedOut: false };
        const working = args.event === 'PostToolUse' ? { hookEventName: 'PostToolUse', additionalContext: 'possible secret(s) just written' } : { permissionDecision: 'deny' };
        return { exitCode: 0, stdout: answer(working), timedOut: false };
      },
      installedTools: async () => [],
    };
    const dataDir = makeTempDir('selftest-store-vet-');
    const { report } = await runSelftest({
      runners,
      packsDir: join(REPO_ROOT, 'configs', 'semgrep'),
      canariesDir: join(REPO_ROOT, 'configs', 'selftest'),
      // Only looked at, to see that an install has one: the launcher above starts nothing.
      dispatcherPath: join(REPO_ROOT, 'hooks', 'guardian-hook.mjs'),
      dataDir,
      pluginVersion: '3.9.0',
      tmpRoot: makeTempDir('selftest-store-tmp-'),
      env: {},
      homeDir: makeTempDir('selftest-store-home-'),
      now: () => new Date(NOW),
      controls: CORE_CONTROLS.filter((c) => c.kind === 'hook'),
    });
    expect(report.saved, report.saved?.note).toMatchObject({ saved: true });
    const last = readLast(dataDir, NOW);
    return {
      control: last.state === 'ok' ? last.run.controls.find((c) => c.id === VET) : undefined,
      files: readFileSync(join(selftestDir(dataDir), LAST_FILE), 'utf8') + readFileSync(join(selftestDir(dataDir), HISTORY_FILE), 'utf8'),
      readsBack: last.state,
    };
  }

  it('T-08 what is saved of the install check is its verdict and its reason — nothing of what the dispatcher answered around them', async () => {
    const RAW = [MARK, 'hookSpecificOutput', 'permissionDecision', 'additionalContext'];
    const holdsNothingRaw = (saved: { control: ControlResult | undefined; files: string; readsBack: string }, what: string): void => {
      expect(saved.readsBack, `${what}: what was saved reads back as a result`).toBe('ok');
      for (const raw of RAW) expect({ what, raw, saved: saved.files.includes(raw) }).toEqual({ what, raw, saved: false });
      for (const key of Object.keys(saved.control ?? {})) expect(KEPT, `${what}: ${key}`).toContain(key);
    };

    // Detected: the verdict alone — the deny's own sentence is the hook's, and is not kept.
    const denied = await savedAfter(answer({ permissionDecision: 'deny', permissionDecisionReason: `dev-guardian blocked this install: 'crossenv@0.0.1-security' ${MARK}` }));
    expect(denied.control, `the saved run has the control ${VET}`).toEqual({ id: VET, scanner: 'hooks', scanner_version: '3.9.0', verdict: 'detected' });
    holdsNothingRaw(denied, 'detected');

    // Silent: a reason this code wrote, and nothing of the context the hook gave instead of a deny.
    const letThrough = await savedAfter(answer({ additionalContext: `⚠️ dev-guardian package vetting — review before relying on these:\n  • crossenv: ${MARK}` }));
    expect(letThrough.control?.verdict).toBe('silent');
    expect(letThrough.control?.reason).toEqual(expect.any(String));
    holdsNothingRaw(letThrough, 'silent');

    // Unverified: the hook's reason is kept — one bounded line — and not the answer it came in. The hook's line is
    // taken from the hook itself, for a registry that cannot be reached (nothing leaves this process; the popular
    // list is emptied so that the name is not first a typosquat suspect).
    const said = await decideInstallCommand(CANARY_INSTALL, {
      cwd: makeTempDir('selftest-store-cwd-'),
      homeDir: makeTempDir('selftest-store-home-'),
      env: {},
      fetchImpl: async () => {
        throw new Error('getaddrinfo ENOTFOUND registry.npmjs.org');
      },
      popular: { npm: [] },
    });
    const line = said?.context ?? '';
    const why = /\((.+)\)/.exec(line)?.[1] ?? '';
    expect(why, `the hook's line says why, in parentheses: "${line}"`).toMatch(/ENOTFOUND/);
    const notVetted = await savedAfter(answer({ additionalContext: [`a line before it ${MARK}`, line, `${'x'.repeat(4000)} ${MARK}`].join('\n') }));
    expect(notVetted.control?.verdict).toBe('unverified');
    expect(notVetted.control?.reason).toContain(why);
    expect((notVetted.control?.reason ?? '').length).toBeLessThanOrEqual(600);
    holdsNothingRaw(notVetted, 'unverified');
  });
});
