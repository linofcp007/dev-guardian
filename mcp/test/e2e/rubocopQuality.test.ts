/**
 * quality_check against the REAL RuboCop, over `fixtures/rubocop/project`
 * (`runners/rubocopRun.ts`):
 *
 *   - the project's `.rubocop.yml` — whose `require:` and `plugins:` would run
 *     `evil.rb`, which writes a marker — is never read, and neither is its
 *     `.rubocop` (RuboCop's arguments file, `--require ./evil.rb`): no marker;
 *   - `lib/app.rb`'s eval, Marshal.load and useless assignment are reported;
 *   - `lib/broken.rb` does not parse: named `Syntax error`, partial;
 *   - `lib/modern.rb` (an endless method, `it`) is valid Ruby 3.4 — parsed as
 *     the `.ruby-version` says, never a syntax error;
 *   - the RSpec `describe` block of 32 lines is no BlockLength offense;
 *   - POSIX: a file with a `*` in its name is never handed over (RuboCop
 *     would read it as a pattern) and is named `Not read`.
 *
 * Gated on Ruby and RuboCop's script on PATH; `GUARDIAN_REQUIRE_RUBOCOP=1`
 * turns the skip into a failure.
 */

import { cpSync, existsSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import type { PluginContext } from '../../src/context.js';
import { resolveProjectPath } from '../../src/platform/projectPath.js';
import { ensureUserBinOnPath } from '../../src/platform/userBin.js';
import { findRubocop } from '../../src/runners/rubocopRun.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';
import { resetScannerCache } from '../../src/tools/scanHelpers.js';
import type { Finding, ToolRun } from '../../src/types.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';
import { isInstalled } from '../helpers/toolchain.js';

vi.setConfig({ testTimeout: 300_000 });

const FIXTURE = resolve(dirname(fileURLToPath(import.meta.url)), '../fixtures/rubocop/project');
ensureUserBinOnPath();
const READY = findRubocop() !== null && (await isInstalled('ruby'));
if (!READY && process.env['GUARDIAN_REQUIRE_RUBOCOP'] === '1') {
  throw new Error('GUARDIAN_REQUIRE_RUBOCOP=1 but ruby or RuboCop (its rubocop script on PATH) is not there');
}

afterAll(cleanupTempDirs);
beforeAll(async () => {
  await import('../../src/tools/qualityCheck.js');
  resetScannerCache();
});

describe.skipIf(!READY)('quality_check: RuboCop over Ruby', () => {
  it("never the project's .rubocop.yml; offenses, the broken file named, modern syntax parsed for the declared Ruby", async () => {
    const dir = resolveProjectPath(makeTempDir('rubocop-e2e-')).path;
    cpSync(FIXTURE, dir, { recursive: true });
    const db = new Database(':memory:');
    runMigrations(db);
    const storage = new Storage(db);
    const p: PluginContext = { storage, shell: null, scriptsDir: dir, progressNotifier: { send: () => {} } };
    const tool = TOOLS.find((t) => t.name === 'quality_check');
    if (!tool) throw new Error('quality_check not registered');
    const r = await tool.handler({ project_path: dir, force: true }, p);
    if (!r.ok) throw new Error(JSON.stringify(r.error));
    const out = r as unknown as { scan_id: string; tools_run: ToolRun[]; missing_tools: string[] };

    expect(existsSync(join(dir, 'RUBOCOP-CONFIG-RAN'))).toBe(false);
    const rubocop = out.tools_run.find((t) => t.name === 'rubocop');
    expect(rubocop?.status).toBe('ok');
    expect(rubocop?.reason).toContain('parsed as Ruby 3.4, as .ruby-version says');
    expect(rubocop?.partially_parsed?.map((pp) => [pp.file, pp.type])).toEqual([['lib/broken.rb', 'Syntax error']]);
    expect(out.missing_tools).toContain('rubocop');

    const findings: Finding[] = storage.findings.listByScan(out.scan_id).filter((f) => f.tool === 'rubocop');
    const got = findings.map((f) => `${f.rule_id}@${(f.file_path ?? '').split('\\').join('/')}:${f.line_start ?? ''}`);
    expect(got).toEqual(
      expect.arrayContaining(['Security/Eval@lib/app.rb:3', 'Security/MarshalLoad@lib/app.rb:7', 'Lint/UselessAssignment@lib/app.rb:2']),
    );
    expect(got.filter((g) => g.includes('modern.rb') && g.startsWith('Lint/Syntax'))).toEqual([]);
    expect(got.filter((g) => g.startsWith('Metrics/BlockLength'))).toEqual([]);
  });

  it.skipIf(process.platform === 'win32')('a `*` in a file name: never handed over, named Not read', async () => {
    const dir = resolveProjectPath(makeTempDir('rubocop-glob-')).path;
    cpSync(FIXTURE, dir, { recursive: true });
    writeFileSync(join(dir, 'lib', 'odd*name.rb'), 'eval(ARGV[0])\n');
    const db = new Database(':memory:');
    runMigrations(db);
    const storage = new Storage(db);
    const p: PluginContext = { storage, shell: null, scriptsDir: dir, progressNotifier: { send: () => {} } };
    const tool = TOOLS.find((t) => t.name === 'quality_check');
    if (!tool) throw new Error('quality_check not registered');
    const r = await tool.handler({ project_path: dir, force: true }, p);
    if (!r.ok) throw new Error(JSON.stringify(r.error));
    const out = r as unknown as { tools_run: ToolRun[] };
    const rubocop = out.tools_run.find((t) => t.name === 'rubocop');
    expect(rubocop?.partially_parsed).toContainEqual({ file: 'lib/odd*name.rb', type: 'Not read', message: expect.stringContaining('pattern') });
  });
});
