/**
 * Review I1 / I2, against the REAL Trivy on PATH: a manifest Trivy did not
 * read is a named gap wherever it sits in the tree, and in every tool that
 * runs Trivy's dependency pass.
 *
 * Reproduced on Trivy 0.69.3 before the fix:
 *   - scan_deps on web/package.json (lodash 4.17.4, minimist 0.0.8, no lock),
 *     api/pyproject.toml (django==2.2.0) and api/requirements-dev.txt: trivy
 *     ok, coverage FULL, 0 findings, no Results key — the same package.json
 *     at the root read coverage none;
 *   - a go.mod that does not parse: Trivy logs `num=0`, exits 0 — full;
 *   - scan_wordpress on a plugin with composer.json (guzzle 6.3.0, twig
 *     1.20.0) and no composer.lock: trivy ok, full — scan_deps on the same
 *     tree said none.
 *
 * Gated on Trivy being on PATH; `GUARDIAN_REQUIRE_SEMGREP=1` turns a missing
 * Trivy into a failure, as elsewhere.
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
  await import('../../src/tools/scanDeps.js');
  await import('../../src/tools/scanWordpress.js');
  resetScannerCache();
});

const TRIVY_INSTALLED = await isInstalled('trivy');
const REQUIRE_TOOLCHAIN = process.env['GUARDIAN_REQUIRE_SEMGREP'] === '1';

function project(files: Record<string, string>): string {
  const dir = resolveProjectPath(makeTempDir('trivy-nested-e2e-')).path;
  for (const [rel, body] of Object.entries(files)) {
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
  coverage: string;
  tools_run: ToolRun[];
  missing_tools: string[];
  manifest_coverage_gaps?: Array<{ ecosystem: string; files: string[] }>;
  coverage_warning?: string;
}

async function run(name: string, dir: string): Promise<ScanOut> {
  const tool = TOOLS.find((t) => t.name === name);
  if (!tool) throw new Error(`${name} not registered`);
  const r = await tool.handler({ project_path: dir, force: true }, plugin(dir));
  if (!r.ok) throw new Error(JSON.stringify(r.error));
  return r as unknown as ScanOut;
}

const WEB_PKG = JSON.stringify({ name: 'web', version: '1.0.0', dependencies: { lodash: '4.17.4', minimist: '0.0.8' } });
const API_PEP621 = '[project]\nname = "api"\nversion = "0.1.0"\ndependencies = ["django==2.2.0"]\n';

describe('Trivy manifest coverage over the whole tree (real Trivy)', () => {
  it.runIf(REQUIRE_TOOLCHAIN)('GUARDIAN_REQUIRE_SEMGREP=1 — Trivy must be on PATH', () => {
    expect(TRIVY_INSTALLED).toBe(true);
  });

  it.skipIf(!TRIVY_INSTALLED)('scan_deps names buried manifests Trivy did not read: never full', async () => {
    const dir = project({
      'web/package.json': WEB_PKG,
      'api/pyproject.toml': API_PEP621,
      'api/requirements-dev.txt': 'pytest==7.0.0\n',
    });
    const r = await run('scan_deps', dir);
    expect(r.coverage).toBe('none');
    expect(r.manifest_coverage_gaps).toEqual([
      { ecosystem: 'npm', files: ['web/package.json'] },
      { ecosystem: 'python', files: ['api/pyproject.toml', 'api/requirements-dev.txt'] },
    ]);
    expect(r.tools_run.find((t) => t.name === 'trivy')?.status).toBe('skipped');
  });

  it.skipIf(!TRIVY_INSTALLED)('scan_deps: a nested manifest beside a covered root lock is partial, named', async () => {
    const dir = project({
      'package.json': JSON.stringify({ name: 'x', version: '1.0.0', dependencies: { lodash: '4.17.15' } }),
      'package-lock.json': JSON.stringify({
        name: 'x',
        version: '1.0.0',
        lockfileVersion: 3,
        requires: true,
        packages: {
          '': { name: 'x', version: '1.0.0', dependencies: { lodash: '4.17.15' } },
          'node_modules/lodash': { version: '4.17.15', resolved: 'https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz' },
        },
      }),
      'web/package.json': WEB_PKG,
    });
    const r = await run('scan_deps', dir);
    expect(r.coverage).toBe('partial');
    expect(r.missing_tools).toContain('trivy:npm');
    expect(r.manifest_coverage_gaps).toEqual([{ ecosystem: 'npm', files: ['web/package.json'] }]);
  });

  it.skipIf(!TRIVY_INSTALLED)('a go.mod Trivy could not parse is a go gap; one it read is covered', async () => {
    const broken = await run('scan_deps', project({ 'go.mod': 'module example.com/x\n\ngo 1.21\n\nrequire golang.org/x/text v0.3.0 (\n' }));
    expect(broken.coverage).not.toBe('full');
    expect(broken.manifest_coverage_gaps).toEqual([{ ecosystem: 'go', files: ['go.mod'] }]);

    const fine = await run('scan_deps', project({ 'svc/go.mod': 'module example.com/x\n\ngo 1.21\n\nrequire golang.org/x/text v0.3.0\n' }));
    expect(fine.coverage).toBe('full');
    expect(fine.manifest_coverage_gaps).toBeUndefined();
  });

  it.skipIf(!TRIVY_INSTALLED)('scan_wordpress runs the same check: a composer.json with no lock is never full', async () => {
    const dir = project({
      'composer.json': JSON.stringify({ name: 'acme/plugin', require: { 'guzzlehttp/guzzle': '6.3.0', 'twig/twig': '1.20.0' } }),
      'readme.txt': '=== Acme ===\n',
      'acme.php': '<?php\n/* Plugin Name: Acme */\n',
    });
    const r = await run('scan_wordpress', dir);
    const trivy = r.tools_run.find((t) => t.name === 'trivy');
    expect(trivy?.status).toBe('skipped');
    expect(trivy?.reason).toMatch(/^no_supported_manifest/);
    expect(r.missing_tools).toContain('trivy');
    expect(r.manifest_coverage_gaps).toEqual([{ ecosystem: 'composer', files: ['composer.json'] }]);
    expect(r.coverage).not.toBe('full');
  });
});
