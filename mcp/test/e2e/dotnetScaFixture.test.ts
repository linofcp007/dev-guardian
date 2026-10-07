/**
 * Real, unmocked `deps_audit` run against a `.csproj` referencing a known-
 * vulnerable NuGet package (Newtonsoft.Json 12.0.1, GHSA-5crp-9r3c-p9vr) —
 * item 2 of Task 10's brief: ".NET SCA... e2e gated on the SDK." The fix
 * round 4 cases also drive `deps_update_plan`'s dotnet branch, which shares
 * the restore plan (`src/deps/dotnetRestore.ts`).
 *
 * Gated on a .NET SDK being installed (`isDotnetSdkInstalled()`), the same
 * `it.skipIf` discipline `rulePackFixture.test.ts` documents for Semgrep: a
 * skip must report as a skip, never a silent pass. This restores from
 * nuget.org, so it also needs network access — same trust boundary
 * `deps_update_plan`'s own dotnet branch already crosses, and the reason
 * this lives in `test/e2e/` rather than `test/integration/` (which mocks
 * `runProcess`/`scannerAvailable` for every OTHER deps_audit scenario).
 */

import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import type { PluginContext } from '../../src/context.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';
import { isDotnetSdkInstalled } from '../helpers/toolchain.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

await import('../../src/tools/depsAudit.js');
await import('../../src/tools/depsUpdatePlan.js');

afterAll(cleanupTempDirs);

const DOTNET_INSTALLED = await isDotnetSdkInstalled();

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

  it.skipIf(!DOTNET_INSTALLED)(
    'item 8 (fix round 3): a STALE obj/ (the routine case — restored once, csproj edited since, obj/ NOT deleted) must still be caught, not read as a clean ok',
    async () => {
      // This is the exact case fix round 2 missed: `dotnet list --no-restore`
      // on a stale (but present) `obj/` exits 0 with valid-looking JSON built
      // from the OLD resolution — no restore failure, no empty output,
      // nothing the fix round 2 "try list first" shape could ever catch. Fix
      // round 3 restores explicitly FIRST, every time, so this now reaches
      // the same `--locked-mode` failure the out-of-sync-lock test above
      // does. Deliberately does NOT delete `obj/` — that is the whole point
      // of this test, and why it exists separately from the one above.
      const project = makeTempDir('dotnet-sca-staleobj-lockfile-e2e-');
      writeFileSync(
        join(project, 'StaleObj.csproj'),
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
      execFileSync('dotnet', ['restore', '--nologo', '--verbosity', 'quiet'], { cwd: project });
      const lockPath = join(project, 'packages.lock.json');
      expect(existsSync(lockPath)).toBe(true);
      expect(existsSync(join(project, 'obj'))).toBe(true); // the stale cache this test is about

      const csprojPath = join(project, 'StaleObj.csproj');
      const original = readFileSync(csprojPath, 'utf8');
      writeFileSync(csprojPath, original.replace('12.0.1', '12.0.3'), 'utf8');
      // obj/ is intentionally left in place, still describing 12.0.1.

      const before = createHash('sha256').update(readFileSync(lockPath)).digest('hex');

      const plugin = makePlugin(project);
      const r = (await getTool('deps_audit').handler({ project_path: project }, plugin)) as {
        ok: true;
        tools_run: Array<{ name: string; status: string; reason?: string }>;
        missing_tools: string[];
      };
      expect(r.ok).toBe(true);

      const after = createHash('sha256').update(readFileSync(lockPath)).digest('hex');
      expect(after).toBe(before);

      const dotnet = r.tools_run.find((t) => t.name === 'dotnet');
      expect(dotnet?.status).not.toBe('ok');
      expect(dotnet?.reason).toMatch(/NU1004/);
      expect(r.missing_tools).toContain('dotnet');
    },
    120_000,
  );

  // -------------------------------------------------------------- fix round 4

  const csproj = (refs: Array<[string, string]>, extraProps = ''): string =>
    [
      '<Project Sdk="Microsoft.NET.Sdk">',
      `  <PropertyGroup><TargetFramework>net8.0</TargetFramework>${extraProps}</PropertyGroup>`,
      '  <ItemGroup>',
      ...refs.map(([name, version]) => `    <PackageReference Include="${name}" Version="${version}" />`),
      '  </ItemGroup>',
      '</Project>',
    ].join('\n');
  const LOCK_OPT_IN = '<RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>';
  const sha = (p: string): string => createHash('sha256').update(readFileSync(p)).digest('hex');

  it.skipIf(!DOTNET_INSTALLED)(
    'E (fix round 4): a lock FIVE directories below the .sln (out of sync, stale obj/) is found from the solution list and never rewritten',
    async () => {
      // Reviewer's deep.mjs: the round 3 depth-4 walk never saw this lock, so
      // the restore ran without --locked-mode and REWROTE it, reading `ok`.
      const project = makeTempDir('dotnet-sca-deep-e2e-');
      const rel = join('src', 'a', 'b', 'c', 'App');
      mkdirSync(join(project, rel), { recursive: true });
      const csprojPath = join(project, rel, 'App.csproj');
      writeFileSync(csprojPath, csproj([['Newtonsoft.Json', '12.0.1']], LOCK_OPT_IN), 'utf8');
      execFileSync('dotnet', ['new', 'sln', '-n', 'Root', '--format', 'sln'], { cwd: project });
      execFileSync('dotnet', ['sln', 'Root.sln', 'add', join(rel, 'App.csproj')], { cwd: project });
      execFileSync('dotnet', ['restore', 'Root.sln', '--nologo', '--verbosity', 'quiet'], { cwd: project });
      writeFileSync(csprojPath, csproj([['Newtonsoft.Json', '12.0.3']], LOCK_OPT_IN), 'utf8'); // obj/ left stale
      const lockPath = join(project, rel, 'packages.lock.json');
      const before = sha(lockPath);

      const r = (await getTool('deps_audit').handler({ project_path: project }, makePlugin(project))) as {
        ok: true;
        tools_run: Array<{ name: string; status: string; reason?: string }>;
      };
      expect(sha(lockPath)).toBe(before);
      const dotnet = r.tools_run.find((t) => t.name === 'dotnet');
      expect(dotnet?.status).toBe('failed');
      expect(dotnet?.reason).toMatch(/NU1004/);
    },
    180_000,
  );

  it.skipIf(!DOTNET_INSTALLED)(
    'E (fix round 4): RestorePackagesWithLockFile=true with NO committed lock — the scan never creates packages.lock.json',
    async () => {
      // Measured: a plain restore AND `--locked-mode` alone both create it.
      const project = makeTempDir('dotnet-sca-nolock-e2e-');
      writeFileSync(join(project, 'App.csproj'), csproj([['Newtonsoft.Json', '12.0.1']], LOCK_OPT_IN), 'utf8');
      const r = (await getTool('deps_audit').handler({ project_path: project }, makePlugin(project))) as {
        ok: true;
        tools_run: Array<{ name: string; status: string }>;
        findings_count_by_severity: Record<string, number>;
      };
      expect(existsSync(join(project, 'packages.lock.json'))).toBe(false);
      expect(r.tools_run.find((t) => t.name === 'dotnet')?.status).toBe('ok');
      expect(Object.values(r.findings_count_by_severity).reduce((a, b) => a + b, 0)).toBeGreaterThan(0);
    },
    120_000,
  );

  it.skipIf(!DOTNET_INSTALLED)(
    'C (fix round 4): a floating version (12.*) is scanned — its finding is kept, not discarded as "stale"',
    async () => {
      const project = makeTempDir('dotnet-sca-floating-e2e-');
      writeFileSync(join(project, 'App.csproj'), csproj([['Newtonsoft.Json', '12.*']]), 'utf8');
      const plugin = makePlugin(project);
      const r = (await getTool('deps_audit').handler({ project_path: project }, plugin)) as {
        ok: true;
        scan_id: string;
        tools_run: Array<{ name: string; status: string }>;
      };
      expect(r.tools_run.find((t) => t.name === 'dotnet')?.status).toBe('ok');
      const finding = plugin.storage.findings.listByScan(r.scan_id).find((f) => f.tool === 'dotnet-list-package');
      expect(finding?.snippet).toContain('Newtonsoft.Json');
    },
    120_000,
  );

  function seedNewtonsoftCve(plugin: PluginContext, project: string): void {
    plugin.storage.scans.insert({ scan_id: 's1', scan_type: 'deps', project_path: project, tree_hash: 'h' });
    plugin.storage.scans.finalize({ scan_id: 's1', status: 'completed', tools_run: [], missing_tools: [] });
    plugin.storage.cves.upsert({
      severity: 'high',
      scan_id: 's1',
      cve_id: 'GHSA-5crp-9r3c-p9vr',
      package_name: 'Newtonsoft.Json',
      installed_version: '12.0.1',
      fixed_version: '13.0.1',
    });
  }

  it.skipIf(!DOTNET_INSTALLED)(
    'C (fix round 4): deps_update_plan keeps the Newtonsoft.Json security step next to a floating Serilog 2.*',
    async () => {
      // Reviewer's floatplan.mjs P2: round 3 returned an EMPTY .NET plan here.
      const project = makeTempDir('dotnet-plan-floating-e2e-');
      writeFileSync(join(project, 'App.csproj'), csproj([['Newtonsoft.Json', '12.0.1'], ['Serilog', '2.*']]), 'utf8');
      const plugin = makePlugin(project);
      seedNewtonsoftCve(plugin, project);
      const r = (await getTool('deps_update_plan').handler({ project_path: project }, plugin)) as {
        ok: true;
        plan: Array<{ package_name: string; classification: string }>;
        runner_failures: unknown[];
      };
      expect(r.runner_failures).toEqual([]);
      expect(r.plan.find((s) => s.package_name === 'Newtonsoft.Json')?.classification).toBe('security');
      expect(r.plan.some((s) => s.package_name === 'Serilog')).toBe(true);
    },
    180_000,
  );

  it.skipIf(!DOTNET_INSTALLED)(
    'A (fix round 4): deps_update_plan reports a package the feed does not have as NU1101 in runner_failures, and attributes the CVE to dotnet',
    async () => {
      // Reviewer's feed.mjs shape, on the plan side: round 3 returned [] and
      // the catch-all claimed no runner had found evidence for a package the
      // .csproj declares.
      const project = makeTempDir('dotnet-plan-feed-e2e-');
      writeFileSync(
        join(project, 'App.csproj'),
        csproj([['Newtonsoft.Json', '12.0.1'], ['Zz.Does.Not.Exist.Guardian', '1.0.0']]),
        'utf8',
      );
      const plugin = makePlugin(project);
      seedNewtonsoftCve(plugin, project);
      const r = (await getTool('deps_update_plan').handler({ project_path: project }, plugin)) as {
        ok: true;
        runner_failures: Array<{ ecosystem: string; code: string }>;
        unplanned: Array<{ package_name: string; ecosystem: string; reason: string }>;
      };
      expect(r.runner_failures).toEqual([expect.objectContaining({ ecosystem: 'dotnet', code: 'NU1101' })]);
      const newtonsoft = r.unplanned.find((u) => u.package_name === 'Newtonsoft.Json');
      expect(newtonsoft?.ecosystem).toBe('dotnet');
      expect(newtonsoft?.reason).toMatch(/dotnet runner failed/);
      expect(newtonsoft?.reason).toMatch(/NU1101/);
    },
    180_000,
  );

  it.skipIf(DOTNET_INSTALLED)('skip notice: .NET SDK is not on PATH — this e2e did not run', () => {
    expect(DOTNET_INSTALLED).toBe(false);
  });
});
