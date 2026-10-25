/**
 * quality_check against the REAL detekt, over `fixtures/detekt/project`
 * (`runners/detektRun.ts`):
 *
 *   - `Demo.kt`'s empty function, generic and swallowed exception are
 *     reported, and its magic numbers too: the project's
 *     `config/detekt/detekt.yml` turns MagicNumber back on over
 *     dev-guardian's own configuration, and is named;
 *   - `Broken.kt` does not parse — detekt says nothing of it, and reports
 *     what it can read;
 *   - no file name reaches detekt's command line, so `a,b.kt`, a path with a
 *     space and `日本.kt` (both written here) are read like any other;
 *   - a directory `.guardianignore` leaves out is walked by detekt, and its
 *     findings are left out, counted;
 *   - a scope keeps the scope's Kotlin only.
 *
 * Gated on detekt (`detekt-cli.jar` on PATH) and Java; `GUARDIAN_REQUIRE_DETEKT=1`
 * turns the skip into a failure.
 */

import { cpSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import type { PluginContext } from '../../src/context.js';
import { resolveProjectPath } from '../../src/platform/projectPath.js';
import { ensureUserBinOnPath } from '../../src/platform/userBin.js';
import { findDetekt } from '../../src/runners/detektRun.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';
import { resetScannerCache } from '../../src/tools/scanHelpers.js';
import type { Finding, ToolRun } from '../../src/types.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';
import { isInstalled } from '../helpers/toolchain.js';

vi.setConfig({ testTimeout: 300_000 });

const FIXTURE = resolve(dirname(fileURLToPath(import.meta.url)), '../fixtures/detekt/project');
ensureUserBinOnPath();
const READY = findDetekt() !== null && (await isInstalled('java'));
if (!READY && process.env['GUARDIAN_REQUIRE_DETEKT'] === '1') {
  throw new Error('GUARDIAN_REQUIRE_DETEKT=1 but detekt (detekt-cli.jar on PATH) or java is not there');
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

const EMPTY = 'package demo\n\nfun empty() {\n}\n';

async function qualityCheck(input: Record<string, unknown>): Promise<{ out: Out; findings: Finding[] }> {
  // A space in the project's own path too.
  const dir = join(resolveProjectPath(makeTempDir('detekt-e2e-')).path, 'my project');
  cpSync(FIXTURE, dir, { recursive: true });
  mkdirSync(join(dir, 'src', 'main', 'kotlin', 'demo', 'tela inicial'), { recursive: true });
  writeFileSync(join(dir, 'src', 'main', 'kotlin', 'demo', 'tela inicial', 'Tela.kt'), EMPTY);
  writeFileSync(join(dir, 'src', 'main', 'kotlin', 'demo', '日本.kt'), EMPTY);
  mkdirSync(join(dir, 'gen'), { recursive: true });
  writeFileSync(join(dir, 'gen', 'Generated.kt'), EMPTY);
  writeFileSync(join(dir, '.guardianignore'), 'gen/\n');
  const db = new Database(':memory:');
  runMigrations(db);
  const storage = new Storage(db);
  const p: PluginContext = { storage, shell: null, scriptsDir: dir, progressNotifier: { send: () => {} } };
  const tool = TOOLS.find((t) => t.name === 'quality_check');
  if (!tool) throw new Error('quality_check not registered');
  const r = await tool.handler({ project_path: dir, force: true, ...input }, p);
  if (!r.ok) throw new Error(JSON.stringify(r.error));
  const out = r as unknown as Out;
  return { out, findings: storage.findings.listByScan(out.scan_id) };
}

const located = (f: Finding): string => `${f.rule_id}@${(f.file_path ?? '').split('\\').join('/')}:${f.line_start ?? ''}`;

describe.skipIf(!READY)('quality_check: detekt over Kotlin', () => {
  it("the project's detekt.yml over dev-guardian's, named; every file read, whatever its name; the ignored left out", async () => {
    const { out, findings } = await qualityCheck({});
    const detekt = out.tools_run.find((t) => t.name === 'detekt');
    expect(detekt?.status).toBe('ok');
    // The detekt.yml handed over, and the .guardianignore the factory applied to its findings.
    expect(detekt?.honoured_config?.map((c) => c.split(' ')[0])).toEqual(['config/detekt/detekt.yml', '.guardianignore']);
    expect(detekt?.partially_parsed ?? []).toEqual([]);
    // gen/Generated.kt's empty function and its package, which does not match its directory.
    expect(detekt?.reason).toMatch(/^5 Kotlin file\(s\) analysed.*; 2 finding\(s\) in Kotlin the scan does not read \(generated, ignored\) left out/);
    expect(out.missing_tools).not.toContain('detekt');
    const got = findings.filter((f) => f.tool === 'detekt').map(located);
    expect(got).toEqual(
      expect.arrayContaining([
        'EmptyFunctionBlock@src/main/kotlin/demo/Demo.kt:4',
        'TooGenericExceptionCaught@src/main/kotlin/demo/Demo.kt:10',
        'SwallowedException@src/main/kotlin/demo/Demo.kt:10',
        'MagicNumber@src/main/kotlin/demo/Demo.kt:9',
        'EmptyFunctionBlock@src/main/kotlin/demo/a,b.kt:3',
        'EmptyFunctionBlock@src/main/kotlin/demo/tela inicial/Tela.kt:3',
        'EmptyFunctionBlock@src/main/kotlin/demo/日本.kt:3',
      ]),
    );
    // Broken.kt: analysed in part, never named a parse error by detekt itself.
    expect(got.some((g) => g.includes('Broken.kt'))).toBe(true);
    expect(got.some((g) => g.includes('gen/'))).toBe(false);
  });

  it("a scope: the project walked, the scope's Kotlin only kept", async () => {
    const { out, findings } = await qualityCheck({ scope: { paths: ['src/main/kotlin/demo/Demo.kt'] } });
    const detekt = out.tools_run.find((t) => t.name === 'detekt');
    expect(detekt?.status).toBe('ok');
    expect(detekt?.reason).toContain('the project walked for a scope of 1 file(s)');
    const files = new Set(findings.filter((f) => f.tool === 'detekt').map((f) => (f.file_path ?? '').split('\\').join('/')));
    expect([...files]).toEqual(['src/main/kotlin/demo/Demo.kt']);
  });
});
