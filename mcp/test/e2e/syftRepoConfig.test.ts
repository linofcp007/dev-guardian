/**
 * A repository's own `.syft.yaml` must not decide what its SBOM lists
 * (`runners/syftRun.ts`) — against the REAL Syft on PATH.
 *
 * The reproduction, measured on Syft 1.51.1 before the fix: `generate_sbom`
 * ran `syft <project>` with the project as its working directory and no
 * `-c`, so Syft read the project's `.syft.yaml` (its debug log: `config:
 * .syft.yaml`). A committed `select-catalogers: ['-javascript']` took a
 * project pinning lodash 4.17.15 from 2 library components to 0 — an SBOM
 * that omits the dependency every later VEX and licence check reads.
 *
 * Gated on Syft being on PATH.
 */

import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import type { PluginContext } from '../../src/context.js';
import { resolveProjectPath } from '../../src/platform/projectPath.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';
import { resetScannerCache } from '../../src/tools/scanHelpers.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';
import { isInstalled } from '../helpers/toolchain.js';

vi.setConfig({ testTimeout: 300_000 });

afterAll(cleanupTempDirs);
beforeAll(async () => {
  await import('../../src/tools/generateSbom.js');
  resetScannerCache();
});

const SYFT_INSTALLED = await isInstalled('syft');

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

function project(extra: Record<string, string> = {}): string {
  const dir = resolveProjectPath(makeTempDir('syft-repo-config-')).path;
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'x', version: '1.0.0', dependencies: { lodash: '4.17.15' } }));
  writeFileSync(join(dir, 'package-lock.json'), JSON.stringify(LOCK));
  for (const [rel, body] of Object.entries(extra)) writeFileSync(join(dir, rel), body);
  return dir;
}

async function sbom(dir: string): Promise<{ produced_by: string; components_count: number }> {
  const tool = TOOLS.find((t) => t.name === 'generate_sbom');
  if (!tool) throw new Error('generate_sbom not registered');
  const db = new Database(':memory:');
  runMigrations(db);
  const plugin: PluginContext = { storage: new Storage(db), shell: null, scriptsDir: dir, progressNotifier: { send: () => {} } };
  const r = await tool.handler({ project_path: dir, inline_max_kb: 0 }, plugin);
  if (!r.ok) throw new Error(JSON.stringify(r.error));
  return r as unknown as { produced_by: string; components_count: number };
}

describe("a repository's .syft.yaml never reaches Syft (real Syft)", () => {
  it.skipIf(!SYFT_INSTALLED)('the same components with and without a hostile .syft.yaml', async () => {
    const clean = await sbom(project());
    expect(clean.produced_by).toBe('syft');
    expect(clean.components_count).toBeGreaterThan(0);
    const hostile = await sbom(project({ '.syft.yaml': "select-catalogers:\n  - '-javascript'\n" }));
    expect(hostile.produced_by).toBe('syft');
    expect(hostile.components_count).toBe(clean.components_count);
  });
});
