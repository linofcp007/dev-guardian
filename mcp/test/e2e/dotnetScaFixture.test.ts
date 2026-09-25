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

import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
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

  it.skipIf(!DOTNET_INSTALLED)(
    'item 8 (fix round 1): a scan never modifies a tracked packages.lock.json',
    async () => {
      const project = makeTempDir('dotnet-sca-lockfile-e2e-');
      writeFileSync(
        join(project, 'Locked.csproj'),
        [
          '<Project Sdk="Microsoft.NET.Sdk">',
          '  <PropertyGroup>',
          '    <TargetFramework>net8.0</TargetFramework>',
          '    <RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>',
          '  </PropertyGroup>',
          '  <ItemGroup><PackageReference Include="Newtonsoft.Json" Version="12.0.1" /></ItemGroup>',
          '</Project>',
        ].join('\n'),
        'utf8',
      );
      // Generate the REAL lock file once, the way a developer committing it
      // would — this is setup, not the thing under test.
      execFileSync('dotnet', ['restore', '--nologo', '--verbosity', 'quiet'], { cwd: project });
      const lockPath = join(project, 'packages.lock.json');
      expect(existsSync(lockPath)).toBe(true);
      const before = createHash('sha256').update(readFileSync(lockPath)).digest('hex');

      const plugin = makePlugin(project);
      const r = await getTool('deps_audit').handler({ project_path: project }, plugin);
      expect(r.ok).toBe(true);

      const after = createHash('sha256').update(readFileSync(lockPath)).digest('hex');
      expect(after).toBe(before);
    },
    120_000,
  );

  it.skipIf(!DOTNET_INSTALLED)(
    'item 8 (fix round 2): an OUT-OF-SYNC tracked packages.lock.json is never rewritten either — restore fails closed and the gap is reported, not a silent ok',
    async () => {
      const project = makeTempDir('dotnet-sca-outofsync-lockfile-e2e-');
      writeFileSync(
        join(project, 'OutOfSync.csproj'),
        [
          '<Project Sdk="Microsoft.NET.Sdk">',
          '  <PropertyGroup>',
          '    <TargetFramework>net8.0</TargetFramework>',
          '    <RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>',
          '  </PropertyGroup>',
          '  <ItemGroup><PackageReference Include="Newtonsoft.Json" Version="12.0.1" /></ItemGroup>',
          '</Project>',
        ].join('\n'),
        'utf8',
      );
      // Generate the real, IN-SYNC lock file first — this is setup.
      execFileSync('dotnet', ['restore', '--nologo', '--verbosity', 'quiet'], { cwd: project });
      const lockPath = join(project, 'packages.lock.json');
      expect(existsSync(lockPath)).toBe(true);

      // Now drift the csproj away from what the committed lock describes —
      // a routine real-world sequence: a PR bumps a PackageReference
      // version and the author forgets to regenerate the lock file.
      const csprojPath = join(project, 'OutOfSync.csproj');
      const original = readFileSync(csprojPath, 'utf8');
      writeFileSync(csprojPath, original.replace('12.0.1', '12.0.3'), 'utf8');

      // Delete the restore-cache `obj/` the setup restore left behind — a
      // real checkout of this repo would never have it (gitignored, never
      // committed alongside `packages.lock.json`). Leaving it in place
      // would let `dotnet list --no-restore` silently serve the STALE
      // (pre-drift, still-12.0.1) cached assets instead of ever reaching
      // this function's own explicit, `--locked-mode` restore attempt —
      // succeeding, quietly, on data that no longer matches the csproj.
      rmSync(join(project, 'obj'), { recursive: true, force: true });

      const before = createHash('sha256').update(readFileSync(lockPath)).digest('hex');

      const plugin = makePlugin(project);
      const r = (await getTool('deps_audit').handler({ project_path: project }, plugin)) as {
        ok: true;
        tools_run: Array<{ name: string; status: string; reason?: string }>;
        missing_tools: string[];
      };
      expect(r.ok).toBe(true);

      const after = createHash('sha256').update(readFileSync(lockPath)).digest('hex');
      // The lock file must be byte-identical either way — this is the part
      // that ALSO passed on the fix round 1 code, because `dotnet list`
      // itself restores implicitly (no `--locked-mode` equivalent) and
      // simply rewrote the lock to match the drifted csproj, silently.
      expect(after).toBe(before);

      // What fix round 1 got WRONG: with the lock silently rewritten, the
      // implicit restore "succeeded" and the scan read as a clean `ok`.
      // `--no-restore` on `dotnet list` closes that gap — the restore this
      // function runs explicitly is the ONLY one that can happen, it runs
      // with `--locked-mode` (the lock file exists), and an out-of-sync
      // lock makes THAT fail closed instead.
      const dotnet = r.tools_run.find((t) => t.name === 'dotnet');
      expect(dotnet?.status).not.toBe('ok');
      expect(r.missing_tools).toContain('dotnet');
    },
    120_000,
  );

  it.skipIf(DOTNET_INSTALLED)('skip notice: .NET SDK is not on PATH — this e2e did not run', () => {
    expect(DOTNET_INSTALLED).toBe(false);
  });
});
