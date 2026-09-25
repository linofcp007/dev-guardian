/**
 * Real, unmocked `deps_update_plan` against a real pnpm install — fix round
 * 4, item D. `mkdirp@0.5.1` pulls in `minimist@0.0.8` transitively; with a
 * CVE recorded on minimist, round 3 emitted `npm pkg set
 * overrides[minimist]=1.2.6` + `npm install --ignore-scripts`, labelled
 * security. pnpm ignores npm's top-level `overrides` (measured on 10.33.2:
 * the lock kept minimist@0.0.8), and the npm install would write a
 * package-lock.json next to pnpm-lock.yaml. This proves the replacement end
 * to end: no npm command, the manual fix it names really works, and after
 * applying it the same CVE reads `already_fixed`.
 *
 * Gated on pnpm being on PATH (a skip reports as a skip); needs registry
 * access, like the .NET e2e next to it.
 */

import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { execa } from 'execa';
import { afterAll, describe, expect, it } from 'vitest';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import type { PluginContext } from '../../src/context.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';
import { isInstalled } from '../helpers/toolchain.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

await import('../../src/tools/depsUpdatePlan.js');

afterAll(cleanupTempDirs);

const PNPM_INSTALLED = await isInstalled('pnpm');

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

async function plan(project: string) {
  const plugin = makePlugin(project);
  plugin.storage.scans.insert({ scan_id: 's1', scan_type: 'deps', project_path: project, tree_hash: 'h' });
  plugin.storage.scans.finalize({ scan_id: 's1', status: 'completed', tools_run: [], missing_tools: [] });
  plugin.storage.cves.upsert({
    severity: 'high',
    scan_id: 's1',
    cve_id: 'CVE-2021-44906',
    package_name: 'minimist',
    installed_version: '0.0.8',
    fixed_version: '1.2.6',
  });
  const tool = TOOLS.find((t) => t.name === 'deps_update_plan');
  if (!tool) throw new Error('deps_update_plan not registered');
  return (await tool.handler({ project_path: project }, plugin)) as {
    ok: true;
    plan: Array<{ upgrade_command: string }>;
    unplanned: Array<{ package_name: string; ecosystem: string; reason: string }>;
    unsupported_ecosystems_present: string[];
  };
}

describe('deps_update_plan — pnpm project (real pnpm, gated)', () => {
  it.skipIf(!PNPM_INSTALLED)(
    'emits no npm command, names the pnpm.overrides fix — and that fix, applied, turns the CVE into already_fixed',
    async () => {
      const project = makeTempDir('pnpm-plan-e2e-');
      writeFileSync(join(project, 'package.json'), JSON.stringify({ name: 'x', version: '1.0.0', dependencies: { mkdirp: '0.5.1' } }), 'utf8');
      await execa('pnpm', ['install', '--ignore-scripts'], { cwd: project });
      expect(readFileSync(join(project, 'pnpm-lock.yaml'), 'utf8')).toContain('minimist@0.0.8');

      const before = await plan(project);
      expect(before.plan.filter((s) => s.upgrade_command.startsWith('npm'))).toEqual([]);
      expect(before.plan).toEqual([]);
      expect(before.unsupported_ecosystems_present).toContain('pnpm');
      const minimist = before.unplanned.find((u) => u.package_name === 'minimist');
      expect(minimist?.ecosystem).toBe('npm');
      expect(minimist?.reason).toContain('"pnpm": { "overrides": { "minimist": "1.2.6" } }');
      expect(minimist?.reason).toContain('pnpm install --ignore-scripts');
      expect(existsSync(join(project, 'package-lock.json'))).toBe(false);

      // Apply exactly the fix the reason names.
      const pkg = JSON.parse(readFileSync(join(project, 'package.json'), 'utf8')) as Record<string, unknown>;
      pkg['pnpm'] = { overrides: { minimist: '1.2.6' } };
      writeFileSync(join(project, 'package.json'), JSON.stringify(pkg), 'utf8');
      await execa('pnpm', ['install', '--ignore-scripts'], { cwd: project });
      const lock = readFileSync(join(project, 'pnpm-lock.yaml'), 'utf8');
      expect(lock).toContain('minimist@1.2.6');
      expect(lock).not.toContain('minimist@0.0.8');

      const after = await plan(project);
      expect(after.unplanned.find((u) => u.package_name === 'minimist')?.reason).toMatch(/^already_fixed: installed version 1\.2\.6/);
      expect(existsSync(join(project, 'package-lock.json'))).toBe(false);
    },
    240_000,
  );

  it.skipIf(PNPM_INSTALLED)('skip notice: pnpm is not on PATH — this e2e did not run', () => {
    expect(PNPM_INSTALLED).toBe(false);
  });
});
