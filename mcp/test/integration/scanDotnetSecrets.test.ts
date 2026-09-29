/**
 * `scan_dotnet_secrets` (review M4): the `dotnet-jwt-secret` pattern could not
 * match JSON — `"JwtSecret": "…"` has a quote between the key and the colon —
 * so an appsettings.json signing key was never reported; and a file over
 * 2 MB, or one that could not be read, was skipped but still counted in
 * `files_scanned`. Skipped files are now named, not counted, and make the
 * scan partial.
 */

import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';

// One file in these projects cannot be read: `Locked.config` (EACCES).
vi.mock('node:fs', async () => {
  const actual = await vi.importActual<typeof import('node:fs')>('node:fs');
  const readFileSync = ((path: unknown, ...rest: unknown[]) => {
    if (typeof path === 'string' && path.endsWith('Locked.config')) {
      throw Object.assign(new Error(`EACCES: permission denied, open '${path}'`), { code: 'EACCES' });
    }
    return (actual.readFileSync as (...a: unknown[]) => unknown)(path, ...rest);
  }) as typeof actual.readFileSync;
  return { ...actual, default: { ...actual, readFileSync }, readFileSync };
});

import type { PluginContext } from '../../src/context.js';
import { resolveProjectPath } from '../../src/platform/projectPath.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';
import type { ToolRun } from '../../src/types.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

afterAll(cleanupTempDirs);
beforeAll(async () => {
  await import('../../src/tools/scanDotnetSecrets.js');
});

function project(files: Record<string, string>): string {
  const dir = resolveProjectPath(makeTempDir('dotnet-secrets-')).path;
  for (const [rel, body] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, rel)), { recursive: true });
    writeFileSync(join(dir, rel), body);
  }
  return dir;
}

interface Out {
  ok: true;
  files_scanned: number;
  files_not_scanned: Array<{ file: string; reason: string }>;
  coverage: string;
  tools_run: ToolRun[];
  missing_tools: string[];
  findings: Array<{ rule_id: string; file_path: string }>;
}

async function scan(dir: string): Promise<Out> {
  const db = new Database(':memory:');
  runMigrations(db);
  const p: PluginContext = { storage: new Storage(db), shell: null, scriptsDir: dir, progressNotifier: { send: () => {} } };
  const tool = TOOLS.find((t) => t.name === 'scan_dotnet_secrets');
  if (!tool) throw new Error('scan_dotnet_secrets not registered');
  const r = await tool.handler({ project_path: dir }, p);
  if (!r.ok) throw new Error(JSON.stringify(r.error));
  return r as unknown as Out;
}

const KEY = 'a-very-long-signing-key-0123456789';

describe('scan_dotnet_secrets (review M4)', () => {
  it.each([
    ['JSON, flat', `{\n  "JwtSecret": "${KEY}"\n}\n`],
    ['JSON, a nested SigningKey', `{\n  "Jwt": {\n    "SigningKey": "${KEY}"\n  }\n}\n`],
    ['JSON, JWT_SECRET', `{ "JWT_SECRET": '${KEY}' }\n`],
  ])('reports a JWT signing key in appsettings.json (%s)', async (_label, body) => {
    const out = await scan(project({ 'appsettings.json': body }));
    expect(out.findings.map((f) => f.rule_id)).toContain('dotnet-jwt-secret');
  });

  it('still reports the key=value form, and not a short value', async () => {
    const out = await scan(project({ 'App.config': `<add key="JwtSecret" value="x"/>\nJwtSecret = "${KEY}"\n` }));
    expect(out.findings.filter((f) => f.rule_id === 'dotnet-jwt-secret')).toHaveLength(1);
  });

  it('a file over 2 MB and one that cannot be read are named, not counted, and the scan is partial', async () => {
    const dir = project({
      'appsettings.json': '{}\n',
      'appsettings.Huge.json': `{ "x": "${'y'.repeat(2_100_000)}" }\n`,
      'Locked.config': '<configuration/>\n',
    });
    const out = await scan(dir);
    expect(out.files_scanned).toBe(1);
    expect(out.files_not_scanned).toEqual([
      { file: 'Locked.config', reason: expect.stringMatching(/EACCES/) },
      { file: 'appsettings.Huge.json', reason: expect.stringMatching(/over 2 MB/) },
    ]);
    expect(out.tools_run).toEqual([
      { name: 'scan_dotnet_secrets', status: 'ok', reason: expect.stringMatching(/2 file\(s\) not scanned/) },
    ]);
    expect(out.missing_tools).toEqual(['scan_dotnet_secrets']);
    expect(out.coverage).toBe('partial');
  });

  it('every file read: full, nothing named', async () => {
    const out = await scan(project({ 'appsettings.json': '{}\n' }));
    expect(out.files_scanned).toBe(1);
    expect(out.files_not_scanned).toEqual([]);
    expect(out.coverage).toBe('full');
  });
});
