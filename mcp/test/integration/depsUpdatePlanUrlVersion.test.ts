/**
 * deps-tools-host-other-texts, task 2, T-06 (red until the fix): `deps_update_plan`, by the real handler, over a lock
 * whose `version` for `dgdep` is a URL (npm writes one for a URL or git dependency). The URL reaches three places:
 * the `unplanned` reason (depsUpdatePlan.ts:1040), a step of the `plan` as its `installed_version` (the variant of the
 * M-3 where `npm outdated` lists `dgdep` with no `current`) and the reason of `:962` (the variant where `dgdep` is
 * transitive and its CVE row records the lock's version). Credentials of such a URL must not be said; a well-formed
 * one is said as the parser writes it without them.
 *
 * `runProcess` and `scannerAvailable` are mocked, as in the harness of 2026-11-20: no package manager runs, nothing is
 * installed, nothing is fetched. Every credential-looking value is MADE UP and built from parts.
 */

import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../src/runners/processRunner.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/runners/processRunner.js')>();
  return { ...actual, runProcess: vi.fn() };
});
vi.mock('../../src/tools/scanHelpers.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/tools/scanHelpers.js')>();
  return { ...actual, scannerAvailable: vi.fn() };
});

import type { PluginContext } from '../../src/context.js';
import { runProcess, type ProcessRunOptions, type ProcessRunResult } from '../../src/runners/processRunner.js';
import { GuardianDatabase } from '../../src/storage/db.js';
import { Storage } from '../../src/storage/index.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { scannerAvailable } from '../../src/tools/scanHelpers.js';
import { TOOLS } from '../../src/tools/index.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

afterAll(cleanupTempDirs);
beforeAll(async () => {
  await import('../../src/registerAll.js');
});

const FEATURE = 'deps-tools-host-other-texts';
const T = ['tok', 'ZzQ', '7731'].join('');
const K = ['ken', 'Qq', '88'].join('');
const U = ['dg', 'user', 'zq'].join('');
const H = 'host.example';
const PARTS = [T, K, U];
const partsIn = (text: string): string[] => PARTS.filter((p) => text.toLowerCase().includes(p.toLowerCase()));

const OK: ProcessRunResult = { outcome: 'completed', exitCode: 0, stdout: '', stderr: '', truncated: false };
const bare = (cmd: string): string => (cmd.split(/[\\/]/).pop() ?? '').replace(/\.(exe|cmd|bat)$/i, '').toLowerCase();

function mocked(answer?: (name: string, opts: ProcessRunOptions) => ProcessRunResult | undefined): void {
  vi.mocked(scannerAvailable).mockImplementation(async (name: string) => (name === 'npm' ? '/fake/bin/npm' : null));
  vi.mocked(runProcess).mockImplementation(async (opts: ProcessRunOptions) => answer?.(bare(opts.command), opts) ?? OK);
}
beforeEach(() => {
  vi.mocked(scannerAvailable).mockReset();
  vi.mocked(runProcess).mockReset();
});

const J = (o: unknown): string => `${JSON.stringify(o, null, 2)}\n`;
const ROOT = { name: 'dgproj', version: '1.0.0' };
const MANIFEST = J({ ...ROOT, dependencies: { dgdep: '^1.0.0' } });
const lockV3 = (version: string): string =>
  J({ ...ROOT, lockfileVersion: 3, requires: true, packages: { '': { ...ROOT, dependencies: { dgdep: '^1.0.0' } }, 'node_modules/dgdep': { version, resolved: 'https://registry.npmjs.org/dgdep/-/dgdep-1.0.0.tgz', integrity: 'sha512-AAAA' } } });
const lockV1 = (version: string): string => J({ ...ROOT, lockfileVersion: 1, requires: true, dependencies: { dgdep: { version, integrity: 'sha512-AAAA' } } });
const LOCKS: Array<{ id: string; lock: (v: string) => string }> = [
  { id: 'lock v1', lock: lockV1 },
  { id: 'lock v3', lock: lockV3 },
];

/** The versions: the four forms of the plan, and the two controls the plan keeps as they are. */
const VERSIONS: Array<{ id: string; value: string; said?: string }> = [
  { id: 'https://T/K@H/dgdep-1.0.0.tgz', value: `https://${T}/${K}@${H}/dgdep-1.0.0.tgz` },
  { id: 'git+https://T/K@H/dgrepo.git#0123abc', value: `git+https://${T}/${K}@${H}/dgrepo.git#0123abc` },
  { id: 'https://U:T@H/dgdep-1.0.0.tgz', value: `https://${U}:${T}@${H}/dgdep-1.0.0.tgz`, said: `https://${H}/dgdep-1.0.0.tgz` },
  { id: 'git+https://T@H/dgrepo.git#0123abc', value: `git+https://${T}@${H}/dgrepo.git#0123abc` },
];

interface PlanReply {
  ok: boolean;
  plan?: Array<{ package_name: string; installed_version: string; latest_version: string; classification: string; upgrade_command: string }>;
  unplanned?: Array<{ package_name: string; reason: string }>;
}

function plugin(dir: string): PluginContext {
  const db = new GuardianDatabase(':memory:');
  runMigrations(db);
  return { storage: new Storage(db), shell: null, scriptsDir: dir, progressNotifier: { send: () => {} } };
}
let seeded = 0;
/** One open dependency finding with its CVE row, as test/integration/createFixPrInstallSources.test.ts seeds one. */
function seed(p: PluginContext, dir: string, installed: string): void {
  seeded += 1;
  const scanId = `00000000-0000-4000-8000-${String(seeded).padStart(12, '0')}`;
  const cve = `CVE-2099-${String(100000 + seeded)}`;
  p.storage.scans.insert({ scan_id: scanId, scan_type: 'deps', project_path: dir, tree_hash: 'deadbeef' });
  p.storage.findings.bulkInsert([
    { fingerprint: `fp-dgdep-${seeded}`, tool: 'trivy', rule_id: cve, severity: 'high', category: 'security', subcategory: 'cve', title: 'dgdep: a vulnerability', file_path: 'package-lock.json', snippet: 'dgdep@1.0.0->1.0.1', fix_available: true, scan_id: scanId },
  ]);
  p.storage.cves.upsert({ cve_id: cve, package_name: 'dgdep', installed_version: installed, fixed_version: '1.0.1', severity: 'high', scan_id: scanId });
  p.storage.scans.finalize({ scan_id: scanId, status: 'completed', tools_run: [{ name: 'trivy', status: 'ok' }], missing_tools: [] });
}

async function plan(files: Record<string, string>, seedInstalled: string, answer?: Parameters<typeof mocked>[0]): Promise<PlanReply> {
  const dir = makeTempDir('dg-planurl-');
  for (const [name, text] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, name)), { recursive: true });
    writeFileSync(join(dir, name), text);
  }
  mocked(answer);
  const p = plugin(dir);
  seed(p, dir, seedInstalled);
  const t = TOOLS.find((x) => x.name === 'deps_update_plan');
  if (t === undefined) throw new Error('deps_update_plan is not registered');
  return (await t.handler({ project_path: dir, force: true }, p)) as unknown as PlanReply;
}

/** `npm outdated` lists `dgdep` with no `current` (the M-3, variant b). */
const OUTDATED = (name: string, opts: ProcessRunOptions): ProcessRunResult | undefined =>
  name === 'npm' && (opts.args ?? [])[0] === 'outdated'
    ? { ...OK, exitCode: 1, outcome: 'failed', stdout: JSON.stringify({ dgdep: { wanted: '1.0.1', latest: '1.0.1', location: 'node_modules/dgdep' } }) }
    : undefined;

describe(`${FEATURE} T-06 deps_update_plan says a version that is a URL without its credentials`, () => {
  describe.each(LOCKS)('$id', ({ lock }) => {
    it.each(VERSIONS)('T-06 (a) unplanned reason, $id: no part of the credentials, and the entry stays unplanned', async ({ value, said }) => {
      const r = await plan({ 'package.json': MANIFEST, 'package-lock.json': lock(value) }, '1.0.0');
      expect(r.ok).toBe(true);
      const entry = (r.unplanned ?? []).find((u) => u.package_name === 'dgdep');
      expect(entry, JSON.stringify(r.unplanned)).toBeDefined();
      expect(partsIn(JSON.stringify(entry))).toEqual([]);
      if (said !== undefined) expect(entry?.reason).toContain(said);
    });

    it.each(VERSIONS)('T-06 (b) plan step, $id: installed_version without any part, the same classification and command', async ({ value, said }) => {
      const control = await plan({ 'package.json': MANIFEST, 'package-lock.json': lock(`https://${H}/dgdep-1.0.0.tgz`) }, '1.0.0', OUTDATED);
      const controlStep = (control.plan ?? []).find((s) => s.package_name === 'dgdep');
      const r = await plan({ 'package.json': MANIFEST, 'package-lock.json': lock(value) }, '1.0.0', OUTDATED);
      const step = (r.plan ?? []).find((s) => s.package_name === 'dgdep');
      expect(step, JSON.stringify(r)).toBeDefined();
      expect(partsIn(JSON.stringify(step))).toEqual([]);
      if (said !== undefined) expect(step?.installed_version).toBe(said);
      expect(step?.upgrade_command).toBe('npm install dgdep@1.0.1 --ignore-scripts');
      expect(step?.classification).toBe(controlStep?.classification);
    });

    it.each(VERSIONS)('T-06 (c) transitive reason, $id: no part of the credentials', async ({ value, said }) => {
      const files = { 'package.json': J({ ...ROOT, dependencies: { other: '^1.0.0' } }), 'package-lock.json': lock(value) };
      const r = await plan(files, value);
      const entry = (r.unplanned ?? []).find((u) => u.package_name === 'dgdep');
      expect(entry, JSON.stringify(r)).toBeDefined();
      expect(partsIn(JSON.stringify(entry))).toEqual([]);
      if (said !== undefined) expect(entry?.reason).toContain(said);
    });

    it.each([`https://${H}/dgdep-1.0.0.tgz`, '1.0.0'])('T-06 (b) (guard) %s is said as today: the step names it as it is', async (value) => {
      const r = await plan({ 'package.json': MANIFEST, 'package-lock.json': lock(value) }, '1.0.0', OUTDATED);
      const step = (r.plan ?? []).find((s) => s.package_name === 'dgdep');
      expect(step?.installed_version).toBe(value);
      expect(step?.upgrade_command).toBe('npm install dgdep@1.0.1 --ignore-scripts');
    });

    it.each([`https://${H}/dgdep-1.0.0.tgz`, '1.0.0'])('T-06 (c) (guard) %s is said as today: the reason holds it as it is', async (value) => {
      const files = { 'package.json': J({ ...ROOT, dependencies: { other: '^1.0.0' } }), 'package-lock.json': lock(value) };
      const r = await plan(files, value);
      // A loose version is planned (pinned by an override); a URL is not: either way the version is said as it is.
      const said = [...(r.plan ?? []).map((s) => s.installed_version), ...(r.unplanned ?? []).map((u) => u.reason)].join(' | ');
      expect(said).toContain(value);
    });
  });
});
