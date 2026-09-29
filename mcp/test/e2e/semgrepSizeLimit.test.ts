/**
 * Review M1, against the REAL Semgrep on PATH: Semgrep ignores a target
 * larger than `--max-target-bytes` (default 1 000 000) in silence —
 * `paths.skipped` lists it only with `--verbose`. Measured on 1.176.1: a
 * 1.16 MB `big.py` holding `eval(x)` beside a small one gave one finding
 * (the small file's), `paths.scanned` without big.py, `errors: []` — coverage
 * full; alone, it gave `paths.scanned: []`, which scan_sast read as "nothing
 * here is a language its rules cover".
 *
 * The files over the limit are computed by dev-guardian (the files the
 * scanners read, with a source language, stat'ed), so a scan names them as
 * a gap: `ok`, `semgrep` missing, coverage partial.
 */

import { execa } from 'execa';
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

const SEMGREP_INSTALLED = await isInstalled('semgrep');
const REQUIRE_SEMGREP = process.env['GUARDIAN_REQUIRE_SEMGREP'] === '1';

const RULES = `rules:
  - id: no-eval
    languages: [python]
    severity: ERROR
    message: eval on dynamic input
    pattern: eval(...)
`;
/** 1.16 MB of Python with an eval() on its first line. */
const BIG = `eval(x)\n${'# padding padding padding padding padding padding padding\n'.repeat(20_000)}`;

async function project(files: Record<string, string>): Promise<string> {
  const dir = resolveProjectPath(makeTempDir('semgrep-size-')).path;
  await execa('git', ['init', '-q'], { cwd: dir });
  for (const [rel, body] of Object.entries({ '.semgrep.yml': RULES, ...files })) {
    mkdirSync(dirname(join(dir, rel)), { recursive: true });
    writeFileSync(join(dir, rel), body);
  }
  return dir;
}

async function sast(dir: string, input: Record<string, unknown> = {}): Promise<{ tools_run: ToolRun[]; missing_tools: string[]; coverage: string }> {
  const db = new Database(':memory:');
  runMigrations(db);
  const p: PluginContext = { storage: new Storage(db), shell: null, scriptsDir: dir, progressNotifier: { send: () => {} } };
  const tool = TOOLS.find((t) => t.name === 'scan_sast');
  if (!tool) throw new Error('scan_sast not registered');
  const r = await tool.handler({ project_path: dir, local_only: true, force: true, ...input }, p);
  if (!r.ok) throw new Error(JSON.stringify(r.error));
  return r as unknown as { tools_run: ToolRun[]; missing_tools: string[]; coverage: string };
}

describe("files over Semgrep's size limit are a named gap (real Semgrep)", () => {
  it.runIf(REQUIRE_SEMGREP)('GUARDIAN_REQUIRE_SEMGREP=1 — semgrep must be on PATH', () => {
    expect(SEMGREP_INSTALLED).toBe(true);
  });

  it.skipIf(!SEMGREP_INSTALLED)('beside a scanned file: ok, semgrep missing, the file named with its size', async () => {
    const dir = await project({ 'src/big.py': BIG, 'src/small.py': 'eval(y)\n' });
    const r = await sast(dir);
    const semgrep = r.tools_run.find((t) => t.name === 'semgrep');
    expect(semgrep?.status).toBe('ok');
    expect(semgrep?.reason).toMatch(/1 file over Semgrep's 1 MB target limit was not scanned: src\/big\.py \(1\.2 MB\)/);
    expect(r.missing_tools).toContain('semgrep');
    expect(r.coverage).toBe('partial');
  });

  it.skipIf(!SEMGREP_INSTALLED)('alone: the reason is the size limit, never "no covered language"', async () => {
    const dir = await project({ 'big.py': BIG });
    const r = await sast(dir);
    const semgrep = r.tools_run.find((t) => t.name === 'semgrep');
    expect(semgrep?.reason ?? '').not.toMatch(/nothing here is a language its rules cover/);
    expect(semgrep?.reason).toMatch(/over Semgrep's 1 MB target limit.*big\.py/);
    expect(r.missing_tools).toContain('semgrep');
  });

  it.skipIf(!SEMGREP_INSTALLED)('a scoped scan names the scoped file over the limit too', async () => {
    const dir = await project({ 'big.py': BIG, 'small.py': 'eval(y)\n' });
    const r = await sast(dir, { scope: { paths: ['big.py', 'small.py'] } });
    expect(r.tools_run.find((t) => t.name === 'semgrep')?.reason).toMatch(/target limit.*big\.py/);
    expect(r.coverage).toBe('partial');
  });

  it.skipIf(!SEMGREP_INSTALLED)('a file over the limit that .guardianignore excludes is no gap', async () => {
    const dir = await project({ 'vendored/big.py': BIG, 'small.py': 'eval(y)\n', '.guardianignore': 'vendored/\n' });
    const r = await sast(dir);
    expect(r.tools_run.find((t) => t.name === 'semgrep')?.reason ?? '').not.toMatch(/target limit/);
    expect(r.coverage).toBe('full');
  });
});
