/**
 * The table of hook checks (`src/selftest/hookChecks.ts`): which of the
 * user's own settings explains a guard that answers more softly.
 *
 * `softenedBy` is read as the dispatcher reads its switches — the environment
 * and the user-level file, never more: a setting it does not honour would
 * excuse a guard that is in fact broken.
 */

import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';
import { CORE_CONTROLS } from '../../../src/selftest/controls.js';
import { HOOK_CHECKS, softenedBy } from '../../../src/selftest/hookChecks.js';
import { runSelftest, type HookRunArgs, type ScanOutcome, type SelftestResult, type SelftestRunners } from '../../../src/selftest/run.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

const REPO_ROOT = fileURLToPath(new URL('../../../..', import.meta.url));

/** A home directory whose user-level hooks file holds `settings`; an empty one without. */
function homeWith(settings?: Record<string, unknown>): string {
  const home = makeTempDir('selftest-hookchecks-home-');
  if (settings !== undefined) {
    mkdirSync(join(home, '.config', 'dev-guardian'), { recursive: true });
    writeFileSync(join(home, '.config', 'dev-guardian', 'hooks.json'), JSON.stringify(settings));
  }
  return home;
}

// ───────────────── selftest-install-vet-canary — the user's own switch of package vetting

describe('selftest-install-vet-canary', () => {
  /** A `string`, not the literal: it is compared with ids whose type does not hold it before the check exists. */
  const VET: string = 'hooks:install-vet';
  const FILE = '~/.config/dev-guardian/hooks.json';

  /** The install check's entry in the table. */
  function vetCheck(): (typeof HOOK_CHECKS)[number] {
    const check = HOOK_CHECKS.find((h) => (h.id as string) === VET);
    if (check === undefined) throw new Error(`HOOK_CHECKS (selftest/hookChecks.ts) has no entry ${VET}`);
    return check;
  }

  /** What a working guard prints: a deny before a tool runs, the secret warning after a write. */
  const working = (args: HookRunArgs): string =>
    JSON.stringify({
      hookSpecificOutput:
        args.event === 'PostToolUse'
          ? { hookEventName: 'PostToolUse', additionalContext: 'possible secret(s) just written' }
          : { hookEventName: 'PreToolUse', permissionDecision: 'deny' },
    });
  /** The launch of the install check: the Bash payload that names the canary package. */
  const isVet = (args: HookRunArgs): boolean => args.payload['tool_name'] === 'Bash' && JSON.stringify(args.payload['tool_input']).includes('crossenv');

  /**
   * A selftest of the hook checks alone, every process replaced: no scanner
   * is run, and the dispatcher's answer to each payload is `answer`'s.
   */
  async function hooksOnly(
    env: Record<string, string>,
    home: string = homeWith(),
    answer: (args: HookRunArgs) => string = working,
  ): Promise<{ result: SelftestResult; launched: HookRunArgs[]; verdict: string | undefined; reason: string }> {
    const launched: HookRunArgs[] = [];
    const noScanner = async (): Promise<ScanOutcome> => {
      throw new Error('no scanner is run by this test');
    };
    const runners: SelftestRunners = {
      probe: async () => ({ installed: true, version: '9.9.9' }),
      semgrep: noScanner,
      gitleaks: noScanner,
      trivy: noScanner,
      hook: async (args) => {
        launched.push(args);
        return { exitCode: 0, stdout: answer(args), timedOut: false };
      },
      installedTools: async () => [],
    };
    const result = await runSelftest({
      runners,
      packsDir: join(REPO_ROOT, 'configs', 'semgrep'),
      canariesDir: join(REPO_ROOT, 'configs', 'selftest'),
      // Only looked at, to see that an install has one: the launcher above starts nothing.
      dispatcherPath: join(REPO_ROOT, 'hooks', 'guardian-hook.mjs'),
      dataDir: makeTempDir('selftest-hookchecks-data-'),
      pluginVersion: '3.9.0',
      tmpRoot: makeTempDir('selftest-hookchecks-tmp-'),
      env,
      homeDir: home,
      save: false,
      controls: CORE_CONTROLS.filter((c) => c.kind === 'hook'),
    });
    const control = result.report.run.controls.find((c) => c.id === VET);
    return { result, launched, verdict: control?.verdict, reason: control?.reason ?? '' };
  }

  it(`T-05 GUARDIAN_PKG_VET=0, GUARDIAN_HOOKS=off and "enabled": false in the user's file switch the install check off — disabled_by_user, the setting named, the dispatcher never launched for it; GUARDIAN_HOOKS_BASH_BLOCK=0 does not`, async () => {
    const check = vetCheck();
    const none = homeWith();
    expect(softenedBy(check, {}, none)).toBeUndefined();
    // Each named as the user wrote it.
    expect(softenedBy(check, { GUARDIAN_PKG_VET: '0' }, none)).toBe('GUARDIAN_PKG_VET=0');
    expect(softenedBy(check, { GUARDIAN_HOOKS: 'off' }, none)).toBe('GUARDIAN_HOOKS=off');
    expect(softenedBy(check, {}, homeWith({ enabled: false }))).toBe(`"enabled": false in ${FILE}`);
    // The shell guard's switch, and the secret warning's, are not package vetting's.
    for (const value of ['0', 'false']) expect(softenedBy(check, { GUARDIAN_HOOKS_BASH_BLOCK: value }, none), value).toBeUndefined();
    expect(softenedBy(check, {}, homeWith({ bash: { block: false }, secrets: { warn: false } }))).toBeUndefined();
    // Read as the dispatcher reads it (`GUARDIAN_PKG_VET === '0'`): no other value switches the vetting off.
    for (const value of ['1', 'false']) expect(softenedBy(check, { GUARDIAN_PKG_VET: value }, none), value).toBeUndefined();
    // And package vetting's switch excuses no other guard.
    for (const other of HOOK_CHECKS.filter((h) => h !== check)) expect(softenedBy(other, { GUARDIAN_PKG_VET: '0' }, none), other.id).toBeUndefined();

    // Switched off by the user: said, and the dispatcher is not launched for it — so nothing is asked of a registry.
    // (The launcher of this test would deny it: a control that was launched all the same would read `detected`.)
    const cases: Array<[named: string, env: Record<string, string>, home: string]> = [
      ['GUARDIAN_PKG_VET=0', { GUARDIAN_PKG_VET: '0' }, homeWith()],
      ['GUARDIAN_HOOKS=off', { GUARDIAN_HOOKS: 'off' }, homeWith()],
      [`"enabled": false in ${FILE}`, {}, homeWith({ enabled: false })],
    ];
    for (const [named, env, home] of cases) {
      const off = await hooksOnly(env, home);
      expect(off.verdict, named).toBe('disabled_by_user');
      expect(off.reason, named).toContain(named);
      expect(off.launched.filter(isVet), named).toEqual([]);
      expect(off.launched, `${named}: the other four are still handed to the dispatcher`).toHaveLength(4);
      // The user's decision is not a defect.
      expect(off.result.exitCode, named).toBe(0);
    }

    // A switch of another guard: the install check is launched, and judged by its answer.
    const shellOff = await hooksOnly({ GUARDIAN_HOOKS_BASH_BLOCK: '0' });
    expect(shellOff.launched.filter(isVet)).toHaveLength(1);
    expect(shellOff.verdict).toBe('detected');
    const letThrough = await hooksOnly({ GUARDIAN_HOOKS_BASH_BLOCK: '0' }, homeWith({ bash: { block: false } }), (args) => (isVet(args) ? '' : working(args)));
    expect(letThrough.verdict, 'nothing of the user explains an install check that lets the canary through').toBe('silent');
    expect(letThrough.result.exitCode).toBe(1);
  });
});
