/**
 * Round 5, item 2, against the REAL scanners on PATH: the repository
 * configuration a scanner honours is named on its run.
 *
 *   - Semgrep honours every `.semgrepignore` of the project — the root one
 *     and one below it, each for its own subtree — for a directory target,
 *     and none for files named explicitly (measured on 1.176.1). A
 *     whole-project scan names them all; a scoped scan, none.
 *   - `.guardianignore` shapes every run of a scan: named on each.
 *   - ruff and jscpd read `ruff.toml` and `.jscpd.json`: named on theirs.
 *
 * Each gated on its scanner being on PATH.
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
  await import('../../src/tools/qualityCheck.js');
  resetScannerCache();
});

const SEMGREP = await isInstalled('semgrep');
const RUFF = await isInstalled('ruff');
const JSCPD = await isInstalled('jscpd');

const RULES = 'rules:\n  - id: no-eval\n    languages: [python]\n    severity: ERROR\n    message: eval\n    pattern: eval(...)\n';

function project(files: Record<string, string>): string {
  const dir = resolveProjectPath(makeTempDir('repo-config-e2e-')).path;
  for (const [rel, body] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, rel)), { recursive: true });
    writeFileSync(join(dir, rel), body);
  }
  return dir;
}

async function run(name: string, dir: string, input: Record<string, unknown> = {}): Promise<{ tools_run: ToolRun[] }> {
  const tool = TOOLS.find((t) => t.name === name);
  if (!tool) throw new Error(`${name} not registered`);
  const db = new Database(':memory:');
  runMigrations(db);
  const p: PluginContext = { storage: new Storage(db), shell: null, scriptsDir: dir, progressNotifier: { send: () => {} } };
  const r = await tool.handler({ project_path: dir, force: true, ...input }, p);
  if (!r.ok) throw new Error(JSON.stringify(r.error));
  return r as unknown as { tools_run: ToolRun[] };
}

describe('the repository configuration a scanner honours is named on its run (real scanners)', () => {
  it.skipIf(!SEMGREP)('scan_sast: every .semgrepignore, and .guardianignore; a scoped scan names no .semgrepignore', async () => {
    const dir = project({
      '.semgrep.yml': RULES,
      'a.py': 'eval(x)\n',
      'ignored/b.py': 'eval(y)\n',
      'sub/c.py': 'eval(z)\n',
      'sub/deep/d.py': 'eval(w)\n',
      '.semgrepignore': 'ignored/\n',
      'sub/.semgrepignore': 'deep/\n',
      '.guardianignore': 'docs/\n',
    });
    const whole = await run('scan_sast', dir, { local_only: true });
    const semgrep = whole.tools_run.find((t) => t.name === 'semgrep');
    expect(semgrep?.honoured_config).toEqual(['.semgrepignore', 'sub/.semgrepignore', '.guardianignore']);
    expect(semgrep?.reason).toMatch(
      /honoured the project's \.semgrepignore, sub\/\.semgrepignore \(its patterns decide which files are scanned\)/,
    );
    expect(semgrep?.reason).toMatch(/honoured the project's \.guardianignore \(its entries are not scanned or reported\)/);

    const scoped = await run('scan_sast', dir, { local_only: true, scope: { paths: ['a.py', 'sub/deep/d.py'] } });
    const scopedRun = scoped.tools_run.find((t) => t.name === 'semgrep');
    expect(scopedRun?.honoured_config).toEqual(['.guardianignore']);
  });

  it.skipIf(!RUFF || !JSCPD)("quality_check: ruff's ruff.toml and jscpd's .jscpd.json", async () => {
    const dir = project({
      'app.py': 'import os\n\n\ndef f(x):\n    return x\n',
      'ruff.toml': 'line-length = 100\n',
      '.jscpd.json': '{"threshold": 50}\n',
    });
    const r = await run('quality_check', dir);
    expect(r.tools_run.find((t) => t.name === 'ruff')?.honoured_config).toEqual(['ruff.toml']);
    expect(r.tools_run.find((t) => t.name === 'jscpd')?.honoured_config).toEqual(['.jscpd.json']);
  });
});
