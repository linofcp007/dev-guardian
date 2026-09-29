/**
 * Review M3, against the REAL Semgrep on PATH: bug_hunt and scan_wordpress
 * spawned Semgrep without Python's UTF-8 mode. With PYTHONUTF8 unset, a
 * file named `日本.py` (bug_hunt's local bugfix-py pack reads it) made
 * Semgrep 1.176.1 exit 2 without writing its report on Windows (cp1252):
 * "report is not valid JSON (exit 2)", and a coverage warning saying to
 * install Semgrep. This machine sets PYTHONUTF8=1 globally, which masks it,
 * so the test unsets it.
 *
 * On POSIX with a UTF-8 locale the defect does not reproduce (the test then
 * passes either way); the unit test in `test/unit/runners/semgrepRun.test.ts`
 * holds every spawn to the helper on every platform.
 */

import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
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

vi.setConfig({ testTimeout: 400_000 });

afterAll(cleanupTempDirs);
beforeAll(async () => {
  await import('../../src/tools/bugHunt.js');
  resetScannerCache();
});
afterEach(() => {
  vi.unstubAllEnvs();
});

const SEMGREP_INSTALLED = await isInstalled('semgrep');
const REQUIRE_SEMGREP = process.env['GUARDIAN_REQUIRE_SEMGREP'] === '1';

describe('Semgrep spawns run in UTF-8 mode (real Semgrep)', () => {
  it.runIf(REQUIRE_SEMGREP)('GUARDIAN_REQUIRE_SEMGREP=1 — semgrep must be on PATH', () => {
    expect(SEMGREP_INSTALLED).toBe(true);
  });

  it.skipIf(!SEMGREP_INSTALLED)('bug_hunt reads a file named 日本.py with PYTHONUTF8 unset', async () => {
    vi.stubEnv('PYTHONUTF8', undefined);
    const dir = resolveProjectPath(makeTempDir('semgrep-utf8-')).path;
    writeFileSync(join(dir, '日本.py'), 'def f(xs):\n    for i in range(len(xs) + 1):\n        print(xs[i])\n');
    const db = new Database(':memory:');
    runMigrations(db);
    const p: PluginContext = { storage: new Storage(db), shell: null, scriptsDir: dir, progressNotifier: { send: () => {} } };
    const tool = TOOLS.find((t) => t.name === 'bug_hunt');
    if (!tool) throw new Error('bug_hunt not registered');
    const r = await tool.handler({ project_path: dir, force: true }, p);
    if (!r.ok) throw new Error(JSON.stringify(r.error));
    const out = r as unknown as { tools_run: ToolRun[]; coverage: string };
    const semgrep = out.tools_run.find((t) => t.name === 'semgrep');
    expect(semgrep?.reason ?? '').not.toMatch(/not valid JSON/);
    expect(semgrep?.status).toBe('ok');
  });
});
