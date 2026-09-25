/**
 * Real, unmocked `scan_sast` .NET pass (Task 11 item 8): `dotnet build` with
 * the SDK's own security analyzers (`-p:AnalysisModeSecurity=All`) and a
 * per-project SARIF ErrorLog, on a class library that uses MD5 — CA5351, no
 * Security Code Scan anywhere. The project is created with `dotnet new
 * classlib`, so it targets whatever framework the installed SDK defaults to
 * and builds offline.
 *
 * Gated on the .NET SDK being on PATH, with `it.skipIf` so a skip reports as
 * a skip. `local_only: true` with no local Semgrep rules keeps Semgrep (and
 * the registry) out of it — the .NET pass is what is under test.
 */

import { execFileSync } from 'node:child_process';
import { readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import type { PluginContext } from '../../src/context.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';
import { isInstalled } from '../helpers/toolchain.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

await import('../../src/tools/scanSast.js');

afterAll(cleanupTempDirs);

const DOTNET_INSTALLED = await isInstalled('dotnet');

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

describe('scan_sast — .NET SDK security analyzers (real dotnet, gated)', () => {
  it.skipIf(!DOTNET_INSTALLED)(
    'reports CA5351 for MD5 from the SARIF, with no Security Code Scan reference, and leaves no SARIF behind',
    async () => {
      const project = makeTempDir('dotnet-sast-e2e-');
      execFileSync('dotnet', ['new', 'classlib', '-n', 'Weak', '-o', project, '--force'], { stdio: 'ignore' });
      writeFileSync(
        join(project, 'Class1.cs'),
        'namespace Weak; public class C { public byte[] H(byte[] d) { using var m = System.Security.Cryptography.MD5.Create(); return m.ComputeHash(d); } }\n',
        'utf8',
      );
      const plugin = makePlugin(project);
      const tool = TOOLS.find((t) => t.name === 'scan_sast');
      if (tool === undefined) throw new Error('scan_sast not registered');

      const r = (await tool.handler({ project_path: project, local_only: true, force: true }, plugin)) as {
        ok: true;
        scan_id: string;
        tools_run: Array<{ name: string; status: string; reason?: string }>;
      };

      expect(r.ok).toBe(true);
      const run = r.tools_run.find((t) => t.name === 'dotnet-analyzers');
      expect(run?.status, JSON.stringify(run)).toBe('ok');
      const rows = plugin.storage.findings.listByScan(r.scan_id);
      const md5 = rows.find((f) => f.rule_id === 'CA5351');
      expect(md5).toMatchObject({ tool: 'dotnet-analyzers', category: 'security' });
      expect(md5?.file_path?.replace(/\\/g, '/')).toBe('Class1.cs');
      expect(readdirSync(join(project, 'obj')).some((n) => n.endsWith('.sarif'))).toBe(false);
    },
    300_000,
  );
});
