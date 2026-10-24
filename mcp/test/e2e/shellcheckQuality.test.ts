/**
 * quality_check against the REAL shellcheck, over `fixtures/shellcheck/project`
 * (`runners/shellcheckRun.ts`):
 *
 *   - the `.sh` scripts and the extensionless `bin/release` (bash shebang) are
 *     checked; the zsh script and the Python helper are never handed over;
 *   - `scripts/broken.sh` does not parse: shellcheck is `ok` with the file
 *     named (`partially_parsed`) and listed missing;
 *   - the root `.shellcheckrc` (disable=SC2035) is honoured and named, the
 *     nested `scripts/.shellcheckrc` (disable=SC2164) is not read;
 *   - a scope hands it the scope's scripts only.
 *
 * Gated on shellcheck being on PATH; `GUARDIAN_REQUIRE_LINTERS=1` turns the
 * skip into a failure.
 */

import { cpSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import type { PluginContext } from '../../src/context.js';
import { resolveProjectPath } from '../../src/platform/projectPath.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';
import { resetScannerCache } from '../../src/tools/scanHelpers.js';
import type { Finding, ToolRun } from '../../src/types.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';
import { isInstalled } from '../helpers/toolchain.js';

vi.setConfig({ testTimeout: 180_000 });

const FIXTURE = resolve(dirname(fileURLToPath(import.meta.url)), '../fixtures/shellcheck/project');
const INSTALLED = await isInstalled('shellcheck');
if (!INSTALLED && process.env['GUARDIAN_REQUIRE_LINTERS'] === '1') {
  throw new Error('GUARDIAN_REQUIRE_LINTERS=1 but shellcheck is not on PATH');
}

afterAll(cleanupTempDirs);
beforeAll(async () => {
  await import('../../src/tools/qualityCheck.js');
  resetScannerCache();
});

interface Out {
  scan_id: string;
  tools_run: ToolRun[];
  missing_tools: string[];
}

async function qualityCheck(input: Record<string, unknown>): Promise<{ out: Out; findings: Finding[] }> {
  const dir = resolveProjectPath(makeTempDir('shellcheck-e2e-')).path;
  cpSync(FIXTURE, dir, { recursive: true });
  const db = new Database(':memory:');
  runMigrations(db);
  const p: PluginContext = { storage: new Storage(db), shell: null, scriptsDir: dir, progressNotifier: { send: () => {} } };
  const tool = TOOLS.find((t) => t.name === 'quality_check');
  if (!tool) throw new Error('quality_check not registered');
  const r = await tool.handler({ project_path: dir, force: true, ...input }, p);
  if (!r.ok) throw new Error(JSON.stringify(r.error));
  const out = r as unknown as Out;
  return { out, findings: p.storage.findings.listByScan(out.scan_id).filter((f) => f.tool === 'shellcheck') };
}

describe('quality_check: shellcheck over the shell scripts (real shellcheck, gated)', () => {
  it.skipIf(!INSTALLED)('the scripts, the root .shellcheckrc only, the unparsable script named', async () => {
    const { out, findings } = await qualityCheck({});
    const run = out.tools_run.find((t) => t.name === 'shellcheck');
    expect(run?.status).toBe('ok');
    expect(run?.reason).toMatch(/^4 script\(s\) checked/);
    expect(run?.partially_parsed?.map((p) => [p.file, p.type])).toEqual([['scripts/broken.sh', 'Syntax error']]);
    expect(run?.honoured_config).toEqual(['.shellcheckrc']);
    expect(out.missing_tools).toContain('shellcheck');

    const at = new Set(findings.map((f) => `${f.rule_id ?? ''} ${f.file_path ?? ''}`));
    expect([...at]).toEqual(
      expect.arrayContaining(['SC2086 scripts/deploy.sh', 'SC2086 bin/release', 'SC2164 scripts/deploy.sh', 'SC1073 scripts/broken.sh']),
    );
    // Disabled by the root rc; the nested rc's SC2164 above was not.
    expect(findings.some((f) => f.rule_id === 'SC2035')).toBe(false);
    expect(findings.filter((f) => /^tools\//.test(f.file_path ?? '') || f.file_path === 'scripts/clean.sh')).toEqual([]);
  });

  it.skipIf(!INSTALLED)('a scope hands it the scope’s scripts only', async () => {
    const { out, findings } = await qualityCheck({ scope: { paths: ['bin/release', 'README.md'] } });
    const run = out.tools_run.find((t) => t.name === 'shellcheck');
    expect(run?.status).toBe('ok');
    expect(run?.reason).toMatch(/^1 script\(s\) checked/);
    expect(new Set(findings.map((f) => f.file_path))).toEqual(new Set(['bin/release']));
  });
});
