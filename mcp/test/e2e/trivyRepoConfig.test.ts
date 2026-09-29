/**
 * A repository's own `trivy.yaml` must not decide what its scan reports
 * (`runners/trivyRun.ts`) — against the REAL Trivy on PATH.
 *
 * The reproduction, measured on Trivy 0.69.3 before the fix: a project
 * pinning lodash 4.17.15 gave 7 findings; the same project with a committed
 * `trivy.yaml` of `severity: [UNKNOWN]` gave 0, coverage full, no gap — from
 * scan_deps, and from the CI gate (`cli/dev-guardian.mjs scan`), which exited
 * 0 instead of 1.
 *
 * Also here: the project's `.trivyignore` is still honoured, and the result
 * names it.
 *
 * Gated on Trivy being on PATH (`it.skipIf`); `GUARDIAN_REQUIRE_SEMGREP=1`
 * turns a missing Trivy into a failure, as elsewhere. The CLI test runs the
 * committed `mcp/dist`, so it is GREEN only after `npm run build`.
 */

import { spawnSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
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

/** Trivy may refresh its DB on a first run. */
vi.setConfig({ testTimeout: 300_000 });

afterAll(cleanupTempDirs);
beforeAll(async () => {
  await import('../../src/tools/scanDeps.js');
  await import('../../src/tools/scanIac.js');
  resetScannerCache();
});

const TRIVY_INSTALLED = await isInstalled('trivy');
const REQUIRE_TOOLCHAIN = process.env['GUARDIAN_REQUIRE_SEMGREP'] === '1';

const here = dirname(fileURLToPath(import.meta.url));
const CLI = resolve(here, '..', '..', '..', 'cli', 'dev-guardian.mjs');

const PKG = { name: 'x', version: '1.0.0', dependencies: { lodash: '4.17.15' } };
const LOCK = {
  name: 'x',
  version: '1.0.0',
  lockfileVersion: 3,
  requires: true,
  packages: {
    '': { name: 'x', version: '1.0.0', dependencies: { lodash: '4.17.15' } },
    'node_modules/lodash': { version: '4.17.15', resolved: 'https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz' },
  },
};
/** Everything below UNKNOWN is dropped: every real finding. */
const HOSTILE_TRIVY_YAML = 'severity:\n  - UNKNOWN\n';

const OPEN_SG_TF = `resource "aws_security_group" "open" {
  name = "open"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
`;

function npmProject(extra: Record<string, string> = {}): string {
  const dir = resolveProjectPath(makeTempDir('trivy-repo-config-')).path;
  writeFileSync(join(dir, 'package.json'), JSON.stringify(PKG, null, 2));
  writeFileSync(join(dir, 'package-lock.json'), JSON.stringify(LOCK, null, 2));
  for (const [rel, body] of Object.entries(extra)) {
    mkdirSync(dirname(join(dir, rel)), { recursive: true });
    writeFileSync(join(dir, rel), body);
  }
  return dir;
}

function plugin(dir: string): PluginContext {
  const db = new Database(':memory:');
  runMigrations(db);
  return { storage: new Storage(db), shell: null, scriptsDir: dir, progressNotifier: { send: () => {} } };
}

interface ScanOut {
  scan_id: string;
  coverage: string;
  tools_run: ToolRun[];
  missing_tools: string[];
}

async function runTool(name: string, dir: string): Promise<{ out: ScanOut; ruleIds: string[] }> {
  const tool = TOOLS.find((t) => t.name === name);
  if (!tool) throw new Error(`${name} not registered`);
  const p = plugin(dir);
  const r = await tool.handler({ project_path: dir, force: true }, p);
  if (!r.ok) throw new Error(JSON.stringify(r.error));
  const out = r as unknown as ScanOut;
  const ruleIds = p.storage.findings
    .listByScan(out.scan_id)
    .map((f) => f.rule_id ?? '')
    .sort();
  return { out, ruleIds };
}

describe("a repository's trivy.yaml never reaches Trivy (real Trivy)", () => {
  it.runIf(REQUIRE_TOOLCHAIN)('GUARDIAN_REQUIRE_SEMGREP=1 — Trivy must be on PATH', () => {
    expect(TRIVY_INSTALLED).toBe(true);
  });

  it.skipIf(!TRIVY_INSTALLED)('scan_deps: the same findings with and without a hostile trivy.yaml', async () => {
    const clean = await runTool('scan_deps', npmProject());
    const hostile = await runTool('scan_deps', npmProject({ 'trivy.yaml': HOSTILE_TRIVY_YAML }));
    expect(clean.ruleIds.length).toBeGreaterThan(0);
    expect(hostile.ruleIds).toEqual(clean.ruleIds);
    expect(hostile.out.coverage).toBe('full');
  });

  it.skipIf(!TRIVY_INSTALLED)('scan_iac: the open security group is still reported beside a hostile trivy.yaml', async () => {
    const dir = resolveProjectPath(makeTempDir('trivy-repo-config-iac-')).path;
    writeFileSync(join(dir, 'main.tf'), OPEN_SG_TF);
    const clean = await runTool('scan_iac', dir);
    writeFileSync(join(dir, 'trivy.yaml'), HOSTILE_TRIVY_YAML);
    const hostile = await runTool('scan_iac', dir);
    expect(clean.ruleIds.length).toBeGreaterThan(0);
    expect(hostile.ruleIds).toEqual(clean.ruleIds);
  });

  it.skipIf(!TRIVY_INSTALLED)("the project's .trivyignore is honoured, and named in the result", async () => {
    const clean = await runTool('scan_deps', npmProject());
    const ignored = clean.ruleIds[0] ?? '';
    expect(ignored).toMatch(/^(CVE|GHSA)-/);
    const withIgnore = await runTool('scan_deps', npmProject({ '.trivyignore': `${ignored}\n` }));
    expect(withIgnore.ruleIds).not.toContain(ignored);
    expect(withIgnore.ruleIds.length).toBe(clean.ruleIds.filter((id) => id !== ignored).length);
    const trivy = withIgnore.out.tools_run.find((t) => t.name === 'trivy');
    expect(trivy?.reason ?? '').toMatch(/\.trivyignore/);
    // Without one, nothing is claimed.
    expect(clean.out.tools_run.find((t) => t.name === 'trivy')?.reason ?? '').not.toMatch(/trivyignore/);
  });

  it.skipIf(!TRIVY_INSTALLED)('the CI gate (cli scan --local-only) still fails on the findings beside a hostile trivy.yaml', () => {
    const run = (dir: string): { status: number | null; stdout: string } => {
      const r = spawnSync(process.execPath, [CLI, 'scan', '--project', dir, '--local-only', '--format', 'json', '--fail-on', 'low'], {
        encoding: 'utf8',
        timeout: 280_000,
        env: { ...process.env, GUARDIAN_OFFLINE: '1' },
      });
      return { status: r.status, stdout: r.stdout };
    };
    const clean = run(npmProject());
    const hostile = run(npmProject({ 'trivy.yaml': HOSTILE_TRIVY_YAML }));
    expect(clean.status).toBe(1);
    expect(hostile.status).toBe(clean.status);
  });
});
