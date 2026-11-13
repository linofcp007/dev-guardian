/**
 * The server shows the last selftest, and never more than it was: the real
 * `health_status` and `check_toolchain` handlers reading what a selftest
 * saved in the data directory they share (`src/selftest/store.ts`).
 *
 * The reading itself — stale, invalid, the cap — is `test/unit/selftest/store.test.ts`'s.
 * What only this file can show is the two tools carrying it: the fields are
 * there in every state, and the warning says the one thing a model must not
 * get wrong — that 0 findings from a silent control prove nothing here.
 */

import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import type { PluginContext } from '../../src/context.js';
import { resolveVersion } from '../../src/platform/version.js';
import { HOOKS_NOTE } from '../../src/selftest/report.js';
import { saveRun, type ControlResult, type ScannerSelftest, type SelftestRun, type SelftestStatus } from '../../src/selftest/store.js';
import { countVerdicts, exitCodeFor, type Verdict } from '../../src/selftest/verdict.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { Storage } from '../../src/storage/index.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { TOOLS } from '../../src/tools/index.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

vi.setConfig({ testTimeout: 120_000 });
afterAll(cleanupTempDirs);

const REPO_ROOT = fileURLToPath(new URL('../../..', import.meta.url));
const VERSION = resolveVersion();
const DAY = 24 * 60 * 60 * 1000;

let savedDataDir: string | undefined;

beforeAll(async () => {
  await import('../../src/tools/healthStatus.js');
  await import('../../src/tools/checkToolchain.js');
});

beforeEach(() => {
  savedDataDir = process.env['GUARDIAN_DATA_DIR'];
});

afterEach(() => {
  if (savedDataDir === undefined) delete process.env['GUARDIAN_DATA_DIR'];
  else process.env['GUARDIAN_DATA_DIR'] = savedDataDir;
});

function plugin(): PluginContext {
  const db = new Database(':memory:');
  runMigrations(db);
  return { storage: new Storage(db), shell: null, scriptsDir: join(REPO_ROOT, 'scripts'), progressNotifier: { send: () => {} } };
}

interface Health {
  ok: true;
  selftest: SelftestStatus;
  selftest_warning: string | null;
}

async function health(): Promise<Health> {
  const tool = TOOLS.find((t) => t.name === 'health_status');
  if (tool === undefined) throw new Error('health_status is not registered');
  const result = (await tool.handler({}, plugin())) as unknown as Health;
  // Both fields are there in every state, never only when there is something to say.
  expect(result, 'health_status returns selftest').toHaveProperty('selftest');
  expect(result, 'health_status returns selftest_warning').toHaveProperty('selftest_warning');
  return result;
}

interface ToolRow {
  name: string;
  installed: boolean;
  version: string;
  selftest?: ScannerSelftest;
}

async function toolchain(): Promise<Map<string, ToolRow>> {
  const tool = TOOLS.find((t) => t.name === 'check_toolchain');
  if (tool === undefined) throw new Error('check_toolchain is not registered');
  const result = (await tool.handler({}, plugin())) as unknown as { ok: true; tools: ToolRow[] };
  return new Map(result.tools.map((t) => [t.name, t]));
}

const control = (id: string, verdict: Verdict, version: string | null, extra: Partial<ControlResult> = {}): ControlResult => ({
  id,
  scanner: id.startsWith('hooks:') ? 'hooks' : (id.split(':')[0] ?? id),
  scanner_version: version,
  verdict,
  ...extra,
});

/** A data directory holding one saved run of `controls`, made `ageDays` ago. */
function dataDirWith(controls: ControlResult[], ageDays = 3, pluginVersion = VERSION): string {
  const dataDir = makeTempDir('selftest-server-');
  const verdicts = controls.map((c) => c.verdict);
  const run: SelftestRun = {
    schema: 1,
    ran_at: new Date(Date.now() - ageDays * DAY - 60_000).toISOString(),
    plugin_version: pluginVersion,
    platform: `${process.platform}-${process.arch}`,
    controls,
    no_canary: [],
    summary: countVerdicts(verdicts),
    exit_code: exitCodeFor(verdicts),
    hooks_note: HOOKS_NOTE,
  };
  const saved = saveRun(dataDir, run);
  expect(saved.saved, saved.note).toBe(true);
  process.env['GUARDIAN_DATA_DIR'] = dataDir;
  return dataDir;
}

const ALL_DETECTED: ControlResult[] = [
  control('semgrep:base', 'detected', '1.182.0'),
  control('semgrep:bugfix-py', 'detected', '1.182.0'),
  control('gitleaks', 'detected', '8.30.1'),
  control('trivy:deps', 'detected', '0.74.0'),
  control('trivy:iac', 'detected', '0.74.0'),
  control('hooks:bash-block', 'detected', VERSION),
];

describe('health_status shows the last selftest', () => {
  it('T-25 with a saved result: its date, its age, the count per verdict and the silent controls', async () => {
    dataDirWith([
      control('semgrep:base', 'detected', '1.182.0'),
      control('semgrep:bugfix-py', 'silent', '1.182.0', { reason: 'ran to the end, read the canary and did not report it' }),
      control('gitleaks', 'detected', '8.30.1'),
      control('trivy:deps', 'unverified', '0.74.0', { reason: 'the vulnerability database is not available' }),
      control('trivy:iac', 'missing', null),
      control('hooks:bash-block', 'disabled_by_user', VERSION),
    ]);
    const { selftest } = await health();
    expect(selftest.state).toBe('ok');
    expect(selftest.age_days).toBe(3);
    expect(Date.parse(selftest.ran_at ?? '')).toBeLessThan(Date.now() - 3 * DAY);
    expect(selftest.plugin_version).toBe(VERSION);
    expect(selftest.counts).toEqual({ detected: 2, silent: 1, missing: 1, unverified: 1, no_canary: 0, disabled_by_user: 1 });
    expect(selftest.silent).toEqual(['semgrep:bugfix-py']);
    expect(selftest.regressed).toEqual([]);
    expect(selftest.command).toMatch(/selftest$/);
  });

  it('T-26 a silent control in the last result is a warning that names it and says 0 findings prove nothing here; without one, null', async () => {
    dataDirWith([...ALL_DETECTED.slice(0, 1), control('semgrep:bugfix-py', 'silent', '1.182.0'), control('gitleaks', 'silent', '8.30.1')]);
    const blind = await health();
    expect(blind.selftest_warning).toEqual(expect.any(String));
    expect(blind.selftest_warning).toContain('semgrep:bugfix-py');
    expect(blind.selftest_warning).toContain('gitleaks');
    expect(blind.selftest_warning).toMatch(/0 findings proves? nothing on this machine/);
    expect(blind.selftest_warning).toMatch(/tell the user/i);
    // It is for the user to act on: the command is in it.
    expect(blind.selftest_warning).toContain(blind.selftest.command);

    dataDirWith(ALL_DETECTED);
    expect((await health()).selftest_warning).toBeNull();
    // Unverified, missing and switched off by the user are said in `selftest`, and are not this warning.
    dataDirWith([control('trivy:deps', 'unverified', '0.74.0'), control('trivy:iac', 'missing', null), control('hooks:bash-block', 'disabled_by_user', VERSION)]);
    const open = await health();
    expect(open.selftest_warning).toBeNull();
    expect(open.selftest.counts).toMatchObject({ unverified: 1, missing: 1, disabled_by_user: 1 });
  });

  it('T-27 with no saved result: never_run, and a command line whose CLI is really there', async () => {
    process.env['GUARDIAN_DATA_DIR'] = makeTempDir('selftest-server-empty-');
    const { selftest, selftest_warning: warning } = await health();
    expect(selftest.state).toBe('never_run');
    expect(warning).toBeNull();
    expect(selftest.ran_at).toBeUndefined();
    expect(selftest.counts).toBeUndefined();
    const line = /^node "([^"]+)" selftest$/.exec(selftest.command);
    expect(line, selftest.command).not.toBeNull();
    expect(existsSync(line?.[1] ?? ''), selftest.command).toBe(true);
    expect(line?.[1]).toMatch(/cli\/dev-guardian\.mjs$/);
    // A result of another plugin version is shown as stale, never as this install's verification.
    dataDirWith(ALL_DETECTED, 3, '0.0.1');
    const stale = await health();
    expect(stale.selftest.state).toBe('stale');
    expect(stale.selftest.stale_because?.[0]).toContain('0.0.1');
  });

  it('T-36 the controls that regressed in the last run are listed, and the warning names them', async () => {
    dataDirWith([
      control('semgrep:base', 'detected', '1.190.0'),
      control('gitleaks', 'unverified', '8.30.1', { regressed: true, changed: ['plugin 3.8.1 → 3.9.0'], reason: 'the run failed' }),
      control('trivy:iac', 'missing', null, { regressed: true, changed: ['trivy 0.74.0 → unknown'] }),
      control('semgrep:bugfix-py', 'silent', '1.190.0', { regressed: true, changed: ['semgrep 1.182.0 → 1.190.0'] }),
    ]);
    const { selftest, selftest_warning: warning } = await health();
    expect(selftest.regressed).toEqual(['gitleaks', 'trivy:iac', 'semgrep:bugfix-py']);
    expect(selftest.silent).toEqual(['semgrep:bugfix-py']);
    for (const id of ['gitleaks', 'trivy:iac', 'semgrep:bugfix-py']) expect(warning, id).toContain(id);
    expect(warning).toMatch(/detected before/);
    // A regression with no silent control is still a warning: it used to see, and now it is not known to.
    dataDirWith([control('gitleaks', 'unverified', '8.30.1', { regressed: true, changed: [] })]);
    const only = await health();
    expect(only.selftest.silent).toEqual([]);
    expect(only.selftest_warning).toContain('gitleaks');
  });
});

describe('check_toolchain shows what the last selftest said of each scanner', () => {
  it('T-29 semgrep, gitleaks and trivy carry the verdict and the date; stale when another version is installed; never_verified with no result', async () => {
    process.env['GUARDIAN_DATA_DIR'] = makeTempDir('selftest-server-empty-');
    const before = await toolchain();
    for (const name of ['semgrep', 'gitleaks', 'trivy']) expect(before.get(name)?.selftest, name).toBe('never_verified');
    // A scanner the selftest has no control for carries no such field at all.
    expect(before.get('bandit')).toBeDefined();
    expect(before.get('bandit')).not.toHaveProperty('selftest');
    expect(before.get('node')).not.toHaveProperty('selftest');

    // What is installed here decides what "another version" is: verified as installed for gitleaks, as something else for trivy.
    const installed = (name: string): string => before.get(name)?.version ?? '';
    const dataDir = dataDirWith([
      control('semgrep:base', 'detected', installed('semgrep') || '1.182.0'),
      control('semgrep:bugfix-py', 'silent', installed('semgrep') || '1.182.0'),
      control('semgrep:web-js', 'unverified', installed('semgrep') || '1.182.0'),
      control('gitleaks', 'detected', installed('gitleaks') || '8.30.1'),
      control('trivy:deps', 'detected', '0.0.1'),
      control('trivy:iac', 'detected', '0.0.1'),
      control('hooks:bash-block', 'detected', VERSION),
    ]);
    expect(existsSync(dataDir)).toBe(true);
    const after = await toolchain();
    const of = (name: string): Exclude<ScannerSelftest, 'never_verified'> => {
      const s = after.get(name)?.selftest;
      if (s === undefined || s === 'never_verified') throw new Error(`${name}: ${String(s)}`);
      return s;
    };
    // Semgrep's is the worst of its packs, the silent ones named.
    expect(of('semgrep').verdict).toBe('silent');
    expect(of('semgrep').silent).toEqual(['semgrep:bugfix-py']);
    expect(of('semgrep').stale).toBe(false);
    expect(of('gitleaks')).toMatchObject({ verdict: 'detected', stale: false });
    expect(of('gitleaks').silent).toBeUndefined();
    expect(of('trivy').verdict).toBe('detected');
    // Verified as 0.0.1: stale exactly when a Trivy is installed here, which is then another version.
    expect(of('trivy').stale).toBe(after.get('trivy')?.installed === true);
    for (const name of ['semgrep', 'gitleaks', 'trivy']) {
      expect(Date.parse(of(name).ran_at), name).toBeLessThan(Date.now());
      expect(Date.parse(of(name).ran_at), name).toBeGreaterThan(Date.now() - 4 * DAY);
    }
    expect(after.get('bandit')).not.toHaveProperty('selftest');
  });
});
