/**
 * End-to-end test against the eval-vuln fixture (test/e2e/eval-vuln-fixture/):
 *   - app.js with `eval(req.query.expr)`  → the bundled Semgrep rule
 *     `js-eval-of-user-input` (configs/semgrep/base.yml) must flag it,
 *   - package.json with `lodash@4.17.20`.
 *
 * Skipped when Semgrep is not installed, so a bare runner stays green; CI
 * installs Semgrep and runs it. We scan with the **bundled local ruleset**
 * (offline, no registry/token) so the result is deterministic across machines.
 */

import Database from 'better-sqlite3';
import { execa } from 'execa';
import { existsSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { beforeAll, describe, expect, it } from 'vitest';

import type { PluginContext } from '../../src/context.js';
import { detectOs } from '../../src/platform/osDetect.js';
import { probeShell } from '../../src/platform/shellProbe.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(here, '..', '..', '..');
const FIXTURE = resolve(here, 'eval-vuln-fixture');
const SCRIPTS_DIR = resolve(ROOT, 'scripts');
const BASE_RULES = resolve(ROOT, 'configs', 'semgrep', 'base.yml');

beforeAll(async () => {
  await import('../../src/tools/securityScanFull.js');
  await import('../../src/tools/scanSast.js');
  await import('../../src/tools/scanDeps.js');
});

async function isInstalled(bin: string): Promise<boolean> {
  try {
    const r = await execa(detectOs() === 'win32' ? 'where' : 'which', [bin], {
      reject: false,
      timeout: 2_000,
    });
    return r.exitCode === 0;
  } catch {
    return false;
  }
}

describe('E2E — eval-vuln fixture', () => {
  it.skipIf(true)('placeholder so the suite always has at least one test in this file', () => {});

  it('the bundled Semgrep rule flags eval() in the fixture (real scanner, offline)', async () => {
    if (!existsSync(FIXTURE)) {
      console.warn('[e2e] fixture missing, skipping');
      return;
    }
    if (!(await isInstalled('semgrep'))) {
      console.warn('[e2e] semgrep not installed, skipping');
      return;
    }

    const r = await execa(
      'semgrep',
      ['--config', BASE_RULES, '--json', '--quiet', '--no-git-ignore', FIXTURE],
      { reject: false, timeout: 5 * 60_000 },
    );
    const out = JSON.parse(r.stdout || '{"results":[]}') as {
      results?: Array<{ check_id?: string }>;
    };
    const ruleIds = (out.results ?? []).map((x) => String(x.check_id ?? ''));

    expect(ruleIds.length).toBeGreaterThan(0);
    expect(ruleIds.some((id) => /eval/i.test(id))).toBe(true);
  }, 6 * 60_000);

  it('security_scan_full runs end-to-end without crashing (orchestration smoke)', async () => {
    if (!existsSync(FIXTURE) || !(await isInstalled('semgrep'))) {
      console.warn('[e2e] semgrep/fixture absent, skipping orchestration smoke');
      return;
    }

    const db = new Database(':memory:');
    runMigrations(db);
    const storage = new Storage(db);
    const shell = await probeShell(storage.runtimeMeta);
    if (!shell) {
      console.warn('[e2e] no usable shell, skipping');
      return;
    }
    const plugin: PluginContext = {
      storage,
      shell,
      scriptsDir: SCRIPTS_DIR,
      progressNotifier: { send: () => {} },
    };

    const tool = TOOLS.find((t) => t.name === 'security_scan_full');
    expect(tool).toBeDefined();
    const result = (await tool!.handler({ project_path: FIXTURE, force: true }, plugin)) as {
      ok: boolean;
    };
    expect(result.ok).toBe(true);
  }, 6 * 60_000);
});
