/**
 * Real, unmocked `deps_update_plan` against real pnpm installs — fix round
 * 4, item D, and review R7-I5. `mkdirp@0.5.1` pulls in `minimist@0.0.8`
 * transitively; with a CVE recorded on minimist the plan emits no npm
 * command (pnpm ignores npm's top-level `overrides`, and an npm install would
 * write a package-lock.json beside pnpm-lock.yaml) and names the override to
 * add — in the place THIS project's pnpm reads it:
 *
 *   - pnpm before 10.5: `"pnpm": { "overrides" }` in package.json (a
 *     pnpm-workspace.yaml without `packages` fails there);
 *   - pnpm 10.5 and later: `overrides:` in pnpm-workspace.yaml — pnpm 11 and
 *     later no longer read package.json's "pnpm" field at all (measured with
 *     12.8.1: a WARN, and the lock kept minimist@0.0.8).
 *
 * Each case pins its pnpm with `packageManager` and runs THAT pnpm through
 * corepack, in a private COREPACK_HOME (nothing lands in the user's corepack
 * cache), applies exactly the fix the plan names, reinstalls, and checks the
 * CVE reads `already_fixed`. The version each case ran against is printed.
 * This file used to pass here only because a cached pnpm 10.33.2 answered
 * `pnpm`: a fresh corepack resolves pnpm 12, where the old advice does
 * nothing.
 *
 * Gated on corepack being on PATH and able to fetch the pinned pnpm (a skip
 * reports as a skip); needs registry access.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
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

const COREPACK_INSTALLED = await isInstalled('corepack');
const OLD_PNPM = '10.4.1';
const NEW_PNPM = '12.8.1';

const corepackHome = COREPACK_INSTALLED ? makeTempDir('pnpm-plan-corepack-') : '';

function corepackEnv(): NodeJS.ProcessEnv {
  return {
    ...process.env,
    COREPACK_HOME: corepackHome,
    COREPACK_ENABLE_DOWNLOAD_PROMPT: '0',
    COREPACK_ENABLE_STRICT: '0',
  };
}

async function pnpm(version: string, cwd: string, ...args: string[]): Promise<string> {
  const r = await execa('corepack', [`pnpm@${version}`, ...args], { cwd, env: corepackEnv(), reject: false });
  if (r.exitCode !== 0) throw new Error(`pnpm@${version} ${args.join(' ')} exited ${String(r.exitCode)}: ${r.stderr}`);
  return `${r.stdout}\n${r.stderr}`;
}

/** Whether corepack can run this pnpm here (fetched into the private cache), printed either way. */
async function pnpmAvailable(v: string): Promise<boolean> {
  if (!COREPACK_INSTALLED) return false;
  try {
    const out = (await pnpm(v, corepackHome, '--version')).trim();
    // The version each case runs against, in the output.
    console.info(`[depsUpdatePlanPnpm] corepack pnpm@${v} --version -> ${out}`);
    return out.startsWith(v);
  } catch (e) {
    console.info(`[depsUpdatePlanPnpm] pnpm@${v} unavailable: ${e instanceof Error ? e.message.split('\n')[0] : String(e)}`);
    return false;
  }
}
const OLD_OK = await pnpmAvailable(OLD_PNPM);
const NEW_OK = await pnpmAvailable(NEW_PNPM);

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

const JSON_FIX = 'add "pnpm": { "overrides": { "minimist": "1.2.6" } } to package.json';
const YAML_FIX = 'add `overrides: { "minimist": "1.2.6" }` to pnpm-workspace.yaml';

describe('deps_update_plan — pnpm project (real pnpm through corepack, gated)', () => {
  async function namedFixWorks(version: string, fix: string): Promise<void> {
    const project = makeTempDir(`pnpm-plan-e2e-${version}-`);
    const manifest: Record<string, unknown> = {
      name: 'x',
      version: '1.0.0',
      packageManager: `pnpm@${version}`,
      dependencies: { mkdirp: '0.5.1' },
    };
    writeFileSync(join(project, 'package.json'), JSON.stringify(manifest), 'utf8');
    await pnpm(version, project, 'install', '--ignore-scripts');
    expect(readFileSync(join(project, 'pnpm-lock.yaml'), 'utf8')).toContain('minimist@0.0.8');

    const before = await plan(project);
    expect(before.plan).toEqual([]);
    expect(before.unsupported_ecosystems_present).toContain('pnpm');
    const minimist = before.unplanned.find((u) => u.package_name === 'minimist');
    expect(minimist?.ecosystem).toBe('npm');
    expect(minimist?.reason).toContain(`pnpm ${version} (package.json "packageManager")`);
    expect(minimist?.reason).toContain(fix);
    expect(minimist?.reason).toContain('pnpm install --ignore-scripts');
    expect(existsSync(join(project, 'package-lock.json'))).toBe(false);

    // Apply exactly the fix the reason names.
    if (fix === JSON_FIX) {
      manifest['pnpm'] = { overrides: { minimist: '1.2.6' } };
      writeFileSync(join(project, 'package.json'), JSON.stringify(manifest), 'utf8');
    } else {
      writeFileSync(join(project, 'pnpm-workspace.yaml'), 'overrides: { "minimist": "1.2.6" }\n', 'utf8');
    }
    await pnpm(version, project, 'install', '--ignore-scripts');
    const lock = readFileSync(join(project, 'pnpm-lock.yaml'), 'utf8');
    expect(lock).toContain('minimist@1.2.6');
    expect(lock).not.toContain('minimist@0.0.8');

    const after = await plan(project);
    expect(after.unplanned.find((u) => u.package_name === 'minimist')?.reason).toMatch(/^already_fixed: installed version 1\.2\.6/);
    expect(existsSync(join(project, 'package-lock.json'))).toBe(false);
  }

  it.skipIf(!OLD_OK)(
    `pnpm ${OLD_PNPM}: no npm command, the fix named is package.json "pnpm.overrides" — and applied, it turns the CVE into already_fixed`,
    () => namedFixWorks(OLD_PNPM, JSON_FIX),
    300_000,
  );

  it.skipIf(!NEW_OK)(
    `pnpm ${NEW_PNPM}: no npm command, the fix named is pnpm-workspace.yaml "overrides" — and applied, it turns the CVE into already_fixed`,
    () => namedFixWorks(NEW_PNPM, YAML_FIX),
    300_000,
  );

  it.skipIf(!NEW_OK)(`pnpm ${NEW_PNPM}: the old advice does nothing there (the reason this changed)`, async () => {
    const project = makeTempDir('pnpm-plan-e2e-old-advice-');
    writeFileSync(
      join(project, 'package.json'),
      JSON.stringify({
        name: 'x',
        version: '1.0.0',
        packageManager: `pnpm@${NEW_PNPM}`,
        dependencies: { mkdirp: '0.5.1' },
        pnpm: { overrides: { minimist: '1.2.6' } },
      }),
      'utf8',
    );
    const out = await pnpm(NEW_PNPM, project, 'install', '--ignore-scripts');
    expect(out).toMatch(/"pnpm" field in package\.json is no longer read/);
    expect(readFileSync(join(project, 'pnpm-lock.yaml'), 'utf8')).toContain('minimist@0.0.8');
  }, 300_000);

  it.skipIf(!NEW_OK)(`pnpm ${NEW_PNPM} WORKSPACE MEMBER: the fix names the root pnpm-workspace.yaml, and it works`, async () => {
    // The member has package.json + node_modules but no lock of its own —
    // the one pnpm-lock.yaml is at the root.
    const root = makeTempDir('pnpm-ws-e2e-');
    mkdirSync(join(root, '.git'));
    writeFileSync(join(root, 'package.json'), JSON.stringify({ name: 'root', private: true, packageManager: `pnpm@${NEW_PNPM}` }), 'utf8');
    writeFileSync(join(root, 'pnpm-workspace.yaml'), "packages:\n  - 'packages/*'\n", 'utf8');
    const member = join(root, 'packages', 'web');
    mkdirSync(member, { recursive: true });
    writeFileSync(join(member, 'package.json'), JSON.stringify({ name: 'web', version: '1.0.0', dependencies: { mkdirp: '0.5.1' } }), 'utf8');
    await pnpm(NEW_PNPM, root, 'install', '--ignore-scripts');
    expect(existsSync(join(member, 'pnpm-lock.yaml'))).toBe(false);

    const before = await plan(member);
    expect(before.plan).toEqual([]);
    const minimist = before.unplanned.find((u) => u.package_name === 'minimist');
    expect(minimist?.reason).toContain(
      'add `overrides: { "minimist": "1.2.6" }` to the workspace root pnpm-workspace.yaml (../../pnpm-workspace.yaml)',
    );

    // Apply the fix where the reason says: the ROOT pnpm-workspace.yaml.
    writeFileSync(join(root, 'pnpm-workspace.yaml'), "packages:\n  - 'packages/*'\noverrides: { \"minimist\": \"1.2.6\" }\n", 'utf8');
    await pnpm(NEW_PNPM, root, 'install', '--ignore-scripts');
    expect(readFileSync(join(root, 'pnpm-lock.yaml'), 'utf8')).not.toContain('minimist@0.0.8');

    const after = await plan(member);
    expect(after.unplanned.find((u) => u.package_name === 'minimist')?.reason).toMatch(/^already_fixed: installed version 1\.2\.6/);
    expect(existsSync(join(member, 'package-lock.json'))).toBe(false);
  }, 300_000);

  it.skipIf(COREPACK_INSTALLED)('skip notice: corepack is not on PATH — this e2e did not run', () => {
    expect(COREPACK_INSTALLED).toBe(false);
  });
});
