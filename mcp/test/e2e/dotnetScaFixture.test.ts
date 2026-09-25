/**
 * Real, unmocked `deps_audit` run against a `.csproj` referencing a known-
 * vulnerable NuGet package (Newtonsoft.Json 12.0.1, GHSA-5crp-9r3c-p9vr) —
 * item 2 of Task 10's brief: ".NET SCA... e2e gated on the SDK."
 *
 * Gated on the .NET SDK being on PATH (`isInstalled('dotnet')`), the same
 * `it.skipIf` discipline `rulePackFixture.test.ts` documents for Semgrep: a
 * skip must report as a skip, never a silent pass. This restores from
 * nuget.org, so it also needs network access — same trust boundary
 * `deps_update_plan`'s own dotnet branch already crosses, and the reason
 * this lives in `test/e2e/` rather than `test/integration/` (which mocks
 * `runProcess`/`scannerAvailable` for every OTHER deps_audit scenario).
 */

import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import type { PluginContext } from '../../src/context.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';
import { isInstalled } from '../helpers/toolchain.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

await import('../../src/tools/depsAudit.js');

afterAll(cleanupTempDirs);

const DOTNET_INSTALLED = await isInstalled('dotnet');

function getTool(name: string) {
  const t = TOOLS.find((x) => x.name === name);
  if (!t) throw new Error(`Tool '${name}' not registered`);
  return t;
}

function makePlugin(projectPath: string): PluginContext {
  const db = new Database(':memory:');
  runMigrations(db);
  const storage = new Storage(db);
  return {
    storage,
    shell: { command: 'bash', args_prefix: [], needs_wsl_path_translate: false, label: 'fake' },
    scriptsDir: projectPath,
    progressNotifier: { send: () => {} },
  };
}

describe('deps_audit — .NET SCA (real dotnet, gated)', () => {
  it.skipIf(!DOTNET_INSTALLED)(
    'reports a Finding for Newtonsoft.Json 12.0.1 (GHSA-5crp-9r3c-p9vr)',
    async () => {
      const project = makeTempDir('dotnet-sca-e2e-');
      writeFileSync(
        join(project, 'Vuln.csproj'),
        [
          '<Project Sdk="Microsoft.NET.Sdk">',
          '  <PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup>',
          '  <ItemGroup><PackageReference Include="Newtonsoft.Json" Version="12.0.1" /></ItemGroup>',
          '</Project>',
        ].join('\n'),
        'utf8',
      );
      const plugin = makePlugin(project);

      const r = (await getTool('deps_audit').handler({ project_path: project }, plugin)) as {
        ok: true;
        tools_run: Array<{ name: string; status: string; reason?: string }>;
        findings_count_by_severity: Record<string, number>;
      };

      expect(r.ok).toBe(true);
      const dotnet = r.tools_run.find((t) => t.name === 'dotnet');
      expect(dotnet?.status).toBe('ok');
      const total = Object.values(r.findings_count_by_severity).reduce((a, b) => a + b, 0);
      expect(total).toBeGreaterThan(0);

      const scanId = (r as unknown as { scan_id: string }).scan_id;
      const findings = plugin.storage.findings.listByScan(scanId);
      const dotnetFinding = findings.find((f) => f.tool === 'dotnet-list-package');
      expect(dotnetFinding).toBeDefined();
      expect(dotnetFinding?.snippet).toContain('Newtonsoft.Json');
    },
    120_000,
  );

  it.skipIf(DOTNET_INSTALLED)('skip notice: .NET SDK is not on PATH — this e2e did not run', () => {
    expect(DOTNET_INSTALLED).toBe(false);
  });
});
