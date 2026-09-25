/**
 * `deps_update_plan` on a FRESH CHECKOUT — a lock file and no installed
 * dependencies — which is exactly where create_fix_pr plans since Task 11
 * (a detached worktree of HEAD). Each ecosystem's "outdated" command must
 * either plan from the lock file or report a runner failure; an empty plan
 * that reads as "nothing to upgrade" is the defect (Composer's plain
 * `outdated` printed `[]`, exit 0).
 *
 * Real tools, each gated on its binary (`it.skipIf`, so a skip reports as a
 * skip), and each needs its registry: Composer (Packagist), Bundler
 * (rubygems.org), Go (proxy.golang.org). npm and .NET are covered by
 * createFixPr.test.ts and dotnetScaFixture.test.ts; cargo-outdated was not
 * available to measure.
 */

import { execFileSync } from 'node:child_process';
import { existsSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
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

const COMPOSER = await isInstalled('composer');
const BUNDLE = await isInstalled('bundle');
const GO = await isInstalled('go');
const TIMEOUT_MS = 240_000;
const SHELL = process.platform === 'win32';

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

interface Plan {
  ok: true;
  plan: Array<{ package_name: string; ecosystem: string; installed_version: string; upgrade_command: string }>;
  runner_failures: Array<{ ecosystem: string; code: string; reason: string }>;
}

async function plan(project: string): Promise<Plan> {
  const tool = TOOLS.find((t) => t.name === 'deps_update_plan');
  if (tool === undefined) throw new Error('deps_update_plan not registered');
  return (await tool.handler({ project_path: project }, makePlugin(project))) as unknown as Plan;
}

describe('deps_update_plan on a fresh checkout — lock file, nothing installed (real tools, gated)', () => {
  it.skipIf(!COMPOSER)(
    'composer: plans from composer.lock with no vendor/',
    async () => {
      const project = makeTempDir('fresh-composer-');
      writeFileSync(join(project, 'composer.json'), JSON.stringify({ require: { 'psr/log': '1.0.0' } }));
      execFileSync('composer', ['update', '--no-install', '--no-interaction', '--no-plugins', '--no-scripts', '--quiet'], {
        cwd: project,
        shell: SHELL,
      });
      expect(existsSync(join(project, 'composer.lock'))).toBe(true);
      expect(existsSync(join(project, 'vendor'))).toBe(false);

      const r = await plan(project);
      expect(r.runner_failures.filter((f) => f.ecosystem === 'composer')).toEqual([]);
      expect(r.plan).toEqual(
        expect.arrayContaining([expect.objectContaining({ package_name: 'psr/log', ecosystem: 'composer', installed_version: '1.0.0' })]),
      );
    },
    TIMEOUT_MS,
  );

  it.skipIf(!BUNDLE)(
    'bundler: plans from Gemfile.lock with no gems installed, and only re-locks',
    async () => {
      const project = makeTempDir('fresh-bundler-');
      writeFileSync(join(project, 'Gemfile'), "source 'https://rubygems.org'\ngem 'rack', '2.2.3'\n");
      execFileSync('bundle', ['lock'], { cwd: project, shell: SHELL, stdio: 'ignore' });
      expect(existsSync(join(project, 'Gemfile.lock'))).toBe(true);

      const r = await plan(project);
      expect(r.runner_failures.filter((f) => f.ecosystem === 'rubygems')).toEqual([]);
      expect(r.plan).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ package_name: 'rack', installed_version: '2.2.3', upgrade_command: 'bundle lock --update rack' }),
        ]),
      );
    },
    TIMEOUT_MS,
  );

  it.skipIf(!GO)(
    'go: plans from go.mod/go.sum with nothing vendored',
    async () => {
      const project = makeTempDir('fresh-go-');
      writeFileSync(join(project, 'go.mod'), 'module example.com/x\n\ngo 1.21\n\nrequire golang.org/x/text v0.3.0\n');
      writeFileSync(join(project, 'main.go'), 'package main\n\nimport _ "golang.org/x/text/language"\n\nfunc main() {}\n');
      execFileSync('go', ['mod', 'download'], { cwd: project, stdio: 'ignore' });

      const r = await plan(project);
      expect(r.runner_failures.filter((f) => f.ecosystem === 'go')).toEqual([]);
      expect(r.plan).toEqual(
        expect.arrayContaining([expect.objectContaining({ package_name: 'golang.org/x/text', installed_version: 'v0.3.0' })]),
      );
    },
    TIMEOUT_MS,
  );
});
