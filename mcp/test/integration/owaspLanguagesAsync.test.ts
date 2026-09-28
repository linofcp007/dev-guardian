/**
 * The MCP readers of OWASP coverage (report_export, compliance_evidence)
 * never list the project's files with a SYNCHRONOUS child process: on a
 * large tree `git ls-files --others` takes seconds, and a spawnSync there
 * blocks the server's event loop for every other request (measured on a
 * 47 000-file tree, review round 3). Their fallback to today's tree — a scan
 * that predates recorded languages — goes through the async listing.
 */

import { execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';

const syncCalls: string[][] = [];
vi.mock('node:child_process', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:child_process')>();
  return {
    ...actual,
    spawnSync: ((command: string, args?: readonly string[], options?: object) => {
      syncCalls.push([command, ...(args ?? [])]);
      return actual.spawnSync(command, args ?? [], options ?? {});
    }) as typeof actual.spawnSync,
  };
});

import type { PluginContext } from '../../src/context.js';
import { resolveProjectPath } from '../../src/platform/projectPath.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { Storage } from '../../src/storage/index.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { TOOLS } from '../../src/tools/index.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

beforeAll(async () => {
  await import('../../src/tools/reportExport.js');
  await import('../../src/tools/complianceEvidence.js');
});
afterAll(cleanupTempDirs);

function plugin(): PluginContext {
  const db = new Database(':memory:');
  runMigrations(db);
  return {
    storage: new Storage(db),
    shell: { command: 'bash', args_prefix: [], needs_wsl_path_translate: false, label: 'fake' },
    scriptsDir: '',
    progressNotifier: { send: () => {} },
  };
}

function gitProject(): string {
  const dir = resolveProjectPath(makeTempDir('owasp-async-')).path;
  mkdirSync(join(dir, 'src'), { recursive: true });
  writeFileSync(join(dir, 'src', 'app.js'), 'x\n');
  execFileSync('git', ['init', '-q'], { cwd: dir });
  return dir;
}

function seed(p: PluginContext, project: string): string {
  // A row written before scans recorded their languages: the readers fall
  // back to listing today's tree.
  p.storage.scans.insert({ scan_id: 'S1', scan_type: 'sast', project_path: project, tree_hash: 'h', meta: { local_only: false } });
  p.storage.scans.finalize({ scan_id: 'S1', status: 'completed', tools_run: [{ name: 'semgrep', status: 'ok' }], missing_tools: [] });
  return 'S1';
}

const listed = (): string[][] => syncCalls.filter((c) => c.includes('ls-files'));

describe('OWASP coverage readers list files without blocking', () => {
  it('report_export', async () => {
    const p = plugin();
    const project = gitProject();
    const scanId = seed(p, project);
    syncCalls.length = 0;
    const tool = TOOLS.find((t) => t.name === 'report_export');
    const r = (await tool?.handler({ project_path: project, scan_id: scanId, format: 'json' }, p)) as { ok: boolean };
    expect(r.ok).toBe(true);
    expect(listed()).toEqual([]);
  });

  it('compliance_evidence', async () => {
    const p = plugin();
    const project = gitProject();
    seed(p, project);
    syncCalls.length = 0;
    const tool = TOOLS.find((t) => t.name === 'compliance_evidence');
    const r = (await tool?.handler({ project_path: project, framework: 'owasp-top10-2025' }, p)) as { ok: boolean; markdown: string };
    expect(r.ok).toBe(true);
    expect(r.markdown).toMatch(/Project languages: javascript \(/);
    expect(listed()).toEqual([]);
  });
});
