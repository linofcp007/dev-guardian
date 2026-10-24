/**
 * deps_audit against the REAL govulncheck and Go toolchain, over
 * `fixtures/govulncheck/project` (`runners/govulncheckRun.ts`):
 *
 *   - the root module calls `language.ParseAcceptLanguage` of x/text v0.3.7
 *     (GO-2022-1059): one finding, at web/langs.go:7;
 *   - `tools/` is a nested module with nothing vulnerable, analysed on its own;
 *   - `broken/` is a nested module that does not type-check: govulncheck is
 *     `ok` with `broken/go.mod` named (`partially_parsed`) and listed missing.
 *
 * It downloads x/text v0.3.7 (the module proxy) and reads the Go vulnerability
 * database (vuln.go.dev). Gated on govulncheck and go being on PATH;
 * `GUARDIAN_REQUIRE_GOSEC=1` turns the skip into a failure.
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
import type { ToolRun } from '../../src/types.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';
import { isInstalled } from '../helpers/toolchain.js';

vi.setConfig({ testTimeout: 300_000 });

const FIXTURE = resolve(dirname(fileURLToPath(import.meta.url)), '../fixtures/govulncheck/project');
const TOOLCHAIN = (await isInstalled('govulncheck')) && (await isInstalled('go'));
if (!TOOLCHAIN && process.env['GUARDIAN_REQUIRE_GOSEC'] === '1') {
  throw new Error('GUARDIAN_REQUIRE_GOSEC=1 but govulncheck or go is not on PATH');
}

afterAll(cleanupTempDirs);
beforeAll(async () => {
  await import('../../src/tools/depsAudit.js');
  resetScannerCache();
});

describe('deps_audit: govulncheck per Go module (real govulncheck, gated)', () => {
  it.skipIf(!TOOLCHAIN)('the called vulnerability at its call site; the nested modules each analysed or named', async () => {
    const dir = resolveProjectPath(makeTempDir('govulncheck-e2e-')).path;
    cpSync(FIXTURE, dir, { recursive: true });
    const db = new Database(':memory:');
    runMigrations(db);
    const p: PluginContext = { storage: new Storage(db), shell: null, scriptsDir: dir, progressNotifier: { send: () => {} } };
    const tool = TOOLS.find((t) => t.name === 'deps_audit');
    if (!tool) throw new Error('deps_audit not registered');
    const r = await tool.handler({ project_path: dir, force: true }, p);
    if (!r.ok) throw new Error(JSON.stringify(r.error));
    const out = r as unknown as { scan_id: string; tools_run: ToolRun[]; missing_tools: string[] };

    const run = out.tools_run.find((t) => t.name === 'govulncheck');
    expect(run?.status).toBe('ok');
    expect(run?.reason).toMatch(/^2 of 3 module\(s\) analysed: 1 vulnerability\(ies\) the code calls/);
    expect(run?.partially_parsed?.map((x) => [x.file, x.type])).toEqual([['broken/go.mod', 'Module not analysed']]);
    expect(run?.partially_parsed?.[0]?.message).toMatch(/undefined: undefinedThing/);
    expect(out.missing_tools).toContain('govulncheck');

    const findings = p.storage.findings.listByScan(out.scan_id).filter((f) => f.tool === 'govulncheck');
    expect(findings.map((f) => `${f.rule_id ?? ''} ${f.file_path ?? ''}:${String(f.line_start)}`)).toEqual(['GO-2022-1059 web/langs.go:7']);
    expect(findings[0]?.vuln_aliases).toContain('CVE-2022-32149');
  });
});
