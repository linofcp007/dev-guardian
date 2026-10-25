/**
 * scan_sast against the REAL SpotBugs with FindSecBugs, over
 * `fixtures/spotbugs/project` compiled here with `javac` into the Maven
 * layout's `target/classes` (`runners/spotbugsRun.ts`):
 *
 *   - its command injection, SQL injection and MD5 are reported under the
 *     source's project path, with their CWEs — and never `==` on strings, a
 *     correctness pattern a security scan leaves out;
 *   - the same sources never built: `skipped`, said why, and no gap.
 *
 * Gated on SpotBugs (install_toolchain's directory or SPOTBUGS_HOME), Java,
 * javac and Semgrep; `GUARDIAN_REQUIRE_SPOTBUGS=1` turns the skip into a
 * failure.
 */

import { cpSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execa } from 'execa';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import type { PluginContext } from '../../src/context.js';
import { resolveProjectPath } from '../../src/platform/projectPath.js';
import { spotbugsJar } from '../../src/platform/userBin.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';
import { resetScannerCache } from '../../src/tools/scanHelpers.js';
import type { Finding, ToolRun } from '../../src/types.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';
import { isInstalled } from '../helpers/toolchain.js';

vi.setConfig({ testTimeout: 300_000 });

const FIXTURE = resolve(dirname(fileURLToPath(import.meta.url)), '../fixtures/spotbugs/project');
const READY = spotbugsJar() !== null && (await isInstalled('java')) && (await isInstalled('javac')) && (await isInstalled('semgrep'));
if (!READY && process.env['GUARDIAN_REQUIRE_SPOTBUGS'] === '1') {
  throw new Error('GUARDIAN_REQUIRE_SPOTBUGS=1 but SpotBugs, java, javac or semgrep is not there');
}

afterAll(cleanupTempDirs);
beforeAll(async () => {
  await import('../../src/tools/scanSast.js');
  resetScannerCache();
});

const RULES = 'rules:\n  - id: java-exec\n    languages: [java]\n    severity: ERROR\n    message: exec\n    pattern: Runtime.getRuntime().exec($X)\n';

async function scanSast(
  build: boolean,
  resourcesOnly = false,
): Promise<{ out: { scan_id: string; tools_run: ToolRun[]; missing_tools: string[] }; findings: Finding[] }> {
  const dir = resolveProjectPath(makeTempDir('spotbugs-e2e-')).path;
  cpSync(FIXTURE, dir, { recursive: true });
  writeFileSync(join(dir, '.semgrep.yml'), RULES);
  if (resourcesOnly) {
    mkdirSync(join(dir, 'target', 'classes'), { recursive: true });
    writeFileSync(join(dir, 'target', 'classes', 'application.properties'), 'x=1\n');
  }
  if (build) {
    mkdirSync(join(dir, 'target', 'classes'), { recursive: true });
    await execa('javac', ['-d', join(dir, 'target', 'classes'), join(dir, 'src', 'main', 'java', 'com', 'example', 'App.java')]);
  }
  const db = new Database(':memory:');
  runMigrations(db);
  const storage = new Storage(db);
  const p: PluginContext = { storage, shell: null, scriptsDir: dir, progressNotifier: { send: () => {} } };
  const tool = TOOLS.find((t) => t.name === 'scan_sast');
  if (!tool) throw new Error('scan_sast not registered');
  const r = await tool.handler({ project_path: dir, force: true, local_only: true }, p);
  if (!r.ok) throw new Error(JSON.stringify(r.error));
  const out = r as unknown as { scan_id: string; tools_run: ToolRun[]; missing_tools: string[] };
  return { out, findings: storage.findings.listByScan(out.scan_id) };
}

describe.skipIf(!READY)('scan_sast: SpotBugs with FindSecBugs over compiled Java', () => {
  it('its security findings, under the source path, with their CWEs; never a correctness pattern', async () => {
    const { out, findings } = await scanSast(true);
    const spotbugs = out.tools_run.find((t) => t.name === 'spotbugs');
    expect(spotbugs?.status).toBe('ok');
    expect(out.missing_tools).not.toContain('spotbugs');
    const ours = findings.filter((f) => f.tool === 'spotbugs');
    const got = ours.map((f) => `${f.rule_id}@${(f.file_path ?? '').split('\\').join('/')}:${f.line_start ?? ''}`);
    expect(got).toEqual(
      expect.arrayContaining([
        'COMMAND_INJECTION@src/main/java/com/example/App.java:14',
        'SQL_INJECTION_JDBC@src/main/java/com/example/App.java:10',
        'WEAK_MESSAGE_DIGEST_MD5@src/main/java/com/example/App.java:18',
      ]),
    );
    expect(got.some((g) => g.startsWith('ES_COMPARING'))).toBe(false);
    expect(ours.find((f) => f.rule_id === 'COMMAND_INJECTION')?.cwe).toContain('CWE-78');
  });

  it('never built — or a class directory with resources only, which SpotBugs refuses — skipped, said why, and no gap', async () => {
    const { out } = await scanSast(false, true);
    const spotbugs = out.tools_run.find((t) => t.name === 'spotbugs');
    expect(spotbugs?.status).toBe('skipped');
    expect(spotbugs?.reason).toContain('no compiled classes');
    expect(out.missing_tools).not.toContain('spotbugs');
  });
});
