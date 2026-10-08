/**
 * Real, unmocked `scan_sast` .NET pass (Task 11 item 8 and its fix round):
 * locked restore, then `dotnet build --no-restore` with the SDK's security
 * analyzers enabled and one SARIF per project and target framework.
 *
 * Each case pins a measured failure of the first version:
 *   - netstandard2.0: the analyzers are OFF by default below .NET 5 — the
 *     shipped args built clean with an EMPTY SARIF and reported ok;
 *   - multi-targeting: every inner build wrote the same ErrorLog, so only the
 *     last framework's results survived;
 *   - lock files: the build's implicit, unlocked restore rewrote an
 *     out-of-sync packages.lock.json and created one for an opted-in project.
 *
 * Gated on the .NET SDK being on PATH (`it.skipIf`, so a skip reports as a
 * skip). `local_only: true` with no local Semgrep rules keeps Semgrep and the
 * registry out of it. netstandard2.0 restores NETStandard.Library from the
 * NuGet cache or nuget.org — same trust boundary as dotnetScaFixture.
 */

import { execFileSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import type { PluginContext } from '../../src/context.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';
import { isDotnetSdkInstalled } from '../helpers/toolchain.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

await import('../../src/tools/scanSast.js');

afterAll(cleanupTempDirs);

const DOTNET_INSTALLED = await isDotnetSdkInstalled();
const TIMEOUT_MS = 300_000;

const MD5_CS =
  'namespace Weak { public class C { public byte[] H(byte[] d) { using (var m = System.Security.Cryptography.MD5.Create()) { return m.ComputeHash(d); } } } }\n';

function makePlugin(projectPath: string): PluginContext {
  const db = new Database(':memory:');
  runMigrations(db);
  return {
    storage: new Storage(db),
    shell: { command: 'bash', args_prefix: [], needs_wsl_path_translate: false, label: 'fake' },
    scriptsDir: projectPath,
    progressNotifier: { send: () => {} },
  };
}

interface SastResult {
  ok: true;
  scan_id: string;
  tools_run: Array<{ name: string; status: string; reason?: string }>;
}

async function scan(project: string, plugin: PluginContext): Promise<SastResult> {
  const tool = TOOLS.find((t) => t.name === 'scan_sast');
  if (tool === undefined) throw new Error('scan_sast not registered');
  return (await tool.handler({ project_path: project, local_only: true, force: true }, plugin)) as unknown as SastResult;
}

function library(frameworks: string, extraProperties = ''): string {
  const project = makeTempDir('dotnet-sast-e2e-');
  const tfm = frameworks.includes(';') ? `<TargetFrameworks>${frameworks}</TargetFrameworks>` : `<TargetFramework>${frameworks}</TargetFramework>`;
  writeFileSync(
    join(project, 'Weak.csproj'),
    `<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup>${tfm}<LangVersion>latest</LangVersion>${extraProperties}</PropertyGroup></Project>\n`,
    'utf8',
  );
  writeFileSync(join(project, 'Class1.cs'), MD5_CS, 'utf8');
  return project;
}

function sarifLeftIn(project: string): boolean {
  const walk = (dir: string): boolean =>
    readdirSync(dir, { withFileTypes: true }).some((e) =>
      e.isDirectory() ? walk(join(dir, e.name)) : e.name.endsWith('.sarif'),
    );
  return walk(project);
}

describe('scan_sast — .NET SDK security analyzers (real dotnet, gated)', () => {
  it.skipIf(!DOTNET_INSTALLED)(
    'reports CA5351 for MD5 on the SDK\'s default framework, with no Security Code Scan, and leaves no SARIF behind',
    async () => {
      const project = makeTempDir('dotnet-sast-e2e-');
      execFileSync('dotnet', ['new', 'classlib', '-n', 'Weak', '-o', project, '--force'], { stdio: 'ignore' });
      writeFileSync(join(project, 'Class1.cs'), MD5_CS, 'utf8');
      const plugin = makePlugin(project);

      const r = await scan(project, plugin);
      const run = r.tools_run.find((t) => t.name === 'dotnet-analyzers');
      expect(run?.status, JSON.stringify(run)).toBe('ok');
      const md5 = plugin.storage.findings.listByScan(r.scan_id).find((f) => f.rule_id === 'CA5351');
      expect(md5).toMatchObject({ tool: 'dotnet-analyzers', category: 'security' });
      expect(md5?.file_path?.replace(/\\/g, '/')).toBe('Class1.cs');
      expect(sarifLeftIn(project)).toBe(false);
    },
    TIMEOUT_MS,
  );

  it.skipIf(!DOTNET_INSTALLED)(
    'netstandard2.0: enables the analyzers (off by default below .NET 5) and finds CA5351 instead of an empty ok',
    async () => {
      const project = library('netstandard2.0');
      const plugin = makePlugin(project);
      const r = await scan(project, plugin);
      const run = r.tools_run.find((t) => t.name === 'dotnet-analyzers');
      expect(run?.status, JSON.stringify(run)).toBe('ok');
      expect(plugin.storage.findings.listByScan(r.scan_id).map((f) => f.rule_id)).toContain('CA5351');
    },
    TIMEOUT_MS,
  );

  it.skipIf(!DOTNET_INSTALLED)(
    'multi-targeting: one SARIF per target framework, every one read',
    async () => {
      const project = library('net10.0;netstandard2.0');
      const plugin = makePlugin(project);
      const r = await scan(project, plugin);
      const run = r.tools_run.find((t) => t.name === 'dotnet-analyzers');
      expect(run?.status, JSON.stringify(run)).toBe('ok');
      expect(run?.reason).toContain('2 SARIF report(s)');
      expect(plugin.storage.findings.listByScan(r.scan_id).map((f) => f.rule_id)).toContain('CA5351');
    },
    TIMEOUT_MS,
  );

  it.skipIf(!DOTNET_INSTALLED)(
    'an out-of-sync packages.lock.json is never rewritten: the locked restore fails (NU1004) and says so',
    async () => {
      const project = library('net10.0', '<RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>');
      // A lock naming a package the project does not reference: out of sync.
      const lock = join(project, 'packages.lock.json');
      const stale =
        '{\n  "version": 1,\n  "dependencies": {\n    "net10.0": {\n      "Newtonsoft.Json": {\n        "type": "Direct",\n' +
        '        "requested": "[13.0.3, )",\n        "resolved": "13.0.3",\n        "contentHash": "HrC5BXdl00IP9zeV+0Z848QWPAoCr9P3bDEZguI+gkLcBKAOxix/tLEAAHC+UvDNPv4a2d18lOReHMOagPa+zQ=="\n      }\n    }\n  }\n}';
      writeFileSync(lock, stale, 'utf8');
      const before = readFileSync(lock);

      const r = await scan(project, makePlugin(project));
      expect(readFileSync(lock).equals(before)).toBe(true);
      const run = r.tools_run.find((t) => t.name === 'dotnet-analyzers');
      expect(run?.status).toBe('failed');
      expect(run?.reason).toMatch(/NU1004|out of sync/);
    },
    TIMEOUT_MS,
  );

  it.skipIf(!DOTNET_INSTALLED)(
    'a project that opts into lock files but has none: scanned, and no packages.lock.json is created',
    async () => {
      const project = library('net10.0', '<RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>');
      const r = await scan(project, makePlugin(project));
      expect(existsSync(join(project, 'packages.lock.json'))).toBe(false);
      expect(r.tools_run.find((t) => t.name === 'dotnet-analyzers')?.status).toBe('ok');
    },
    TIMEOUT_MS,
  );
});
