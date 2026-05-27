/**
 * End-to-end test against the eval-vuln fixture.
 *
 * Boots the security_scan_full tool in-process against
 * test/e2e/eval-vuln-fixture/, which intentionally contains:
 *   - app.js with `eval(req.query.expr)` (Semgrep should flag),
 *   - package.json with `lodash@4.17.20` (Trivy should flag a CVE).
 *
 * The test is `skip`'d when Semgrep / Trivy are not installed locally —
 * we don't want CI on a bare runner to red-flag a green PR. CI jobs that
 * pre-install scanners will run it.
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
const FIXTURE = resolve(here, 'eval-vuln-fixture');
const SCRIPTS_DIR = resolve(here, '..', '..', '..', 'scripts');

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

  // Real test gates on scanner availability + bash availability. Vitest's
  // `it.skipIf(condition)` evaluates the condition at collection time, so
  // we route through a runtime guard inside the test body instead.
  it('security_scan_full finds the eval rule and a lodash CVE (when scanners are installed)', async () => {
    if (!existsSync(FIXTURE)) {
      console.warn('[e2e] fixture missing, skipping');
      return;
    }
    const haveSemgrep = await isInstalled('semgrep');
    const haveTrivy = await isInstalled('trivy');
    if (!haveSemgrep || !haveTrivy) {
      console.warn('[e2e] semgrep + trivy required, skipping');
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
    const result = (await tool!.handler(
      { project_path: FIXTURE, force: true },
      plugin,
    )) as {
      ok: true;
      scan_id: string;
      findings_count_by_severity: Record<string, number>;
      top_findings: Array<{ rule_id?: string; category: string; severity: string }>;
    };

    expect(result.ok).toBe(true);
    const total = Object.values(result.findings_count_by_severity).reduce((a, b) => a + b, 0);
    expect(total).toBeGreaterThan(0);

    // At least one Semgrep eval / dangerous-code rule fired.
    const evalLike = result.top_findings.find(
      (f) => /eval|dangerous|inject/i.test(f.rule_id ?? ''),
    );
    expect(evalLike).toBeDefined();

    // At least one Trivy CVE on lodash exists.
    const cves = plugin.storage.cves.listActive(result.scan_id);
    const lodashCves = cves.filter((c) => c.package_name === 'lodash');
    expect(lodashCves.length).toBeGreaterThan(0);
  }, 5 * 60_000); // up to 5 min — scanners can be slow on first run
});
