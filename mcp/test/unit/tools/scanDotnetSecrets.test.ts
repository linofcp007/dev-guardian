/**
 * `scan_dotnet_secrets` — the whole matched line (password and all) used to
 * be stored verbatim as the finding's snippet (Task 12, brief item 1:
 * `scanDotnetSecrets.ts:183`). These tests pin that it is redacted before
 * persistence and before the tool's own response.
 */
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { beforeAll, afterAll, describe, expect, it } from 'vitest';
import { GuardianDatabase as Database } from '../../../src/storage/db.js';
import type { PluginContext } from '../../../src/context.js';
import { runMigrations } from '../../../src/storage/migrations/runner.js';
import { Storage } from '../../../src/storage/index.js';
import { TOOLS } from '../../../src/tools/index.js';
import { makeTempDir, cleanupTempDirs } from '../../helpers/tempDir.js';

beforeAll(async () => {
  await import('../../../src/tools/scanDotnetSecrets.js');
});

afterAll(cleanupTempDirs);

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

describe('scan_dotnet_secrets', () => {
  it('redacts the connection-string snippet in both the response and the stored finding', async () => {
    const project = makeTempDir('dotnet-secrets-');
    writeFileSync(
      join(project, 'appsettings.json'),
      JSON.stringify({
        ConnectionStrings: {
          Default: 'Server=db.internal;Database=app;Password=Sup3rS3cret!',
        },
      }),
      'utf8',
    );

    const plugin = makePlugin(project);
    const tool = getTool('scan_dotnet_secrets');
    const r = (await tool.handler({ project_path: project }, plugin)) as {
      ok: true;
      scan_id: string;
      findings: Array<{ snippet?: string }>;
    };
    expect(r.ok).toBe(true);
    expect(r.findings.length).toBeGreaterThan(0);
    for (const f of r.findings) {
      expect(f.snippet).toBeDefined();
      expect(f.snippet).not.toContain('Sup3rS3cret!');
    }

    const stored = plugin.storage.findings.listByScan(r.scan_id);
    expect(stored.length).toBeGreaterThan(0);
    for (const f of stored) {
      expect(f.snippet).toBeDefined();
      expect(f.snippet).not.toContain('Sup3rS3cret!');
    }
  });
});
