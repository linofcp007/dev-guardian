/**
 * Bandit's `.bandit` files — against the REAL Bandit on PATH (round 4,
 * item 3).
 *
 * `bandit -r <project>` walks the WHOLE tree for a file named `.bandit` and
 * applies it to every file it scans. Measured on Bandit 1.9.4, a project
 * whose `a.py` has an `assert` and a `subprocess.call(…, shell=True)`
 * (B101, B404, B602):
 *   - a `.bandit` with `skips: B101,B602,B404` at the root → 0 results;
 *   - the same file in `sub/` — or in a dependency's directory
 *     (`node_modules/pkg/.bandit`), which the scan itself excludes — → 0
 *     results for the root's `a.py` too, logged only as "Found project level
 *     .bandit file";
 *   - two of them → exit 2, "Multiple .bandit files found".
 * `--ini <file>` replaces the search: the project's own root `.bandit` is
 * passed that way and named, and without one an empty `[bandit]` file is.
 *
 * Gated on Bandit being on PATH.
 */

import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import type { PluginContext } from '../../src/context.js';
import { resolveProjectPath } from '../../src/platform/projectPath.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';
import { resetScannerCache } from '../../src/tools/scanHelpers.js';
import type { ToolRun } from '../../src/types.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';
import { isInstalled } from '../helpers/toolchain.js';

vi.setConfig({ testTimeout: 300_000 });

afterAll(cleanupTempDirs);
beforeAll(async () => {
  await import('../../src/tools/scanSast.js');
  resetScannerCache();
});

const BANDIT_INSTALLED = await isInstalled('bandit');

const CODE = 'import subprocess\n\n\ndef f(x):\n    assert x\n    subprocess.call(x, shell=True)\n';
const SKIP_ALL = '[bandit]\nskips: B101,B602,B404\n';

function project(files: Record<string, string>): string {
  const dir = resolveProjectPath(makeTempDir('bandit-repo-config-')).path;
  for (const [rel, body] of Object.entries({ 'a.py': CODE, ...files })) {
    mkdirSync(dirname(join(dir, rel)), { recursive: true });
    writeFileSync(join(dir, rel), body);
  }
  return dir;
}

async function sast(dir: string): Promise<{ bandit: ToolRun | undefined; ids: string[] }> {
  const tool = TOOLS.find((t) => t.name === 'scan_sast');
  if (!tool) throw new Error('scan_sast not registered');
  const db = new Database(':memory:');
  runMigrations(db);
  const p: PluginContext = { storage: new Storage(db), shell: null, scriptsDir: dir, progressNotifier: { send: () => {} } };
  const r = await tool.handler({ project_path: dir, force: true, local_only: true }, p);
  if (!r.ok) throw new Error(JSON.stringify(r.error));
  const out = r as unknown as { scan_id: string; tools_run: ToolRun[] };
  const ids = p.storage.findings
    .listByScan(out.scan_id)
    .filter((f) => f.tool === 'bandit')
    .map((f) => f.rule_id ?? '')
    .sort();
  return { bandit: out.tools_run.find((t) => t.name === 'bandit'), ids };
}

describe(".bandit files never steer the scan in silence (real Bandit)", () => {
  it.skipIf(!BANDIT_INSTALLED)("a .bandit below the root — a dependency's — no longer silences the project", async () => {
    const clean = await sast(project({}));
    expect(clean.ids).toEqual(['B101', 'B404', 'B602']);
    const nested = await sast(project({ 'node_modules/pkg/.bandit': SKIP_ALL, 'sub/.bandit': SKIP_ALL }));
    expect(nested.bandit?.status).toBe('ok');
    expect(nested.ids).toEqual(clean.ids);
    expect(nested.bandit?.honoured_config).toBeUndefined();
  });

  it.skipIf(!BANDIT_INSTALLED)("the project's own root .bandit is honoured, and named", async () => {
    const own = await sast(project({ '.bandit': '[bandit]\nskips: B101\n', 'sub/.bandit': SKIP_ALL }));
    expect(own.bandit?.status).toBe('ok');
    expect(own.ids).toEqual(['B404', 'B602']);
    expect(own.bandit?.honoured_config).toEqual(['.bandit']);
    expect(own.bandit?.reason).toMatch(/honoured the project's \.bandit/);
  });
});
