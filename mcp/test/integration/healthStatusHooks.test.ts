/**
 * `health_status` and the session mark, end to end: the real tool handler
 * reading what the real dispatcher wrote.
 *
 * The decision itself is `hooksStatus`'s, held by
 * `test/unit/hooks/heartbeat.test.ts`. What only this file can show is the two
 * halves meeting: the hook and the server deriving the same host process and
 * the same project key from what Claude Code gives each of them, in a data
 * directory they share.
 */

import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import type { PluginContext } from '../../src/context.js';
import type { HooksStatus } from '../../src/hooks/heartbeat.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';
import { HOOK_TIMEOUT_MS, runHook } from '../helpers/runHook.js';
import { timeoutAbove } from '../helpers/spawnCap.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

vi.setConfig({ testTimeout: timeoutAbove(HOOK_TIMEOUT_MS) });

afterAll(cleanupTempDirs);

const REPO_ROOT = fileURLToPath(new URL('../../..', import.meta.url));

/** The environment this file changes, restored after each test. */
const TOUCHED = ['GUARDIAN_DATA_DIR', 'CLAUDE_PLUGIN_ROOT', 'CLAUDE_PROJECT_DIR', 'CLAUDE_PID'] as const;
let saved: Record<string, string | undefined>;

beforeAll(async () => {
  await import('../../src/tools/healthStatus.js');
});

beforeEach(() => {
  saved = Object.fromEntries(TOUCHED.map((k) => [k, process.env[k]]));
});

afterEach(() => {
  for (const k of TOUCHED) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k];
  }
});

function plugin(client?: { name: string; version: string }): PluginContext {
  const db = new Database(':memory:');
  runMigrations(db);
  return {
    storage: new Storage(db),
    shell: null,
    scriptsDir: join(REPO_ROOT, 'scripts'),
    progressNotifier: { send: () => {} },
    ...(client !== undefined ? { clientInfo: () => client } : {}),
  };
}

interface Health {
  ok: true;
  hooks: HooksStatus;
  hooks_warning: string | null;
}

async function health(ctx: PluginContext): Promise<Health> {
  const tool = TOOLS.find((t) => t.name === 'health_status');
  if (tool === undefined) throw new Error('health_status is not registered');
  const result = (await tool.handler({}, ctx)) as unknown as Health;
  // Both fields are there in every state, never only when there is something to say.
  expect(result, 'health_status returns hooks').toHaveProperty('hooks');
  expect(result, 'health_status returns hooks_warning').toHaveProperty('hooks_warning');
  return result;
}

/** This server as Claude Code starts the plugin's: its root, the session's project, the host process. */
function asPluginServer(project: string, dataDir: string, hostPid: number): void {
  process.env['CLAUDE_PLUGIN_ROOT'] = REPO_ROOT;
  process.env['CLAUDE_PROJECT_DIR'] = project;
  process.env['GUARDIAN_DATA_DIR'] = dataDir;
  process.env['CLAUDE_PID'] = String(hostPid);
}

/** The hook as the same Claude Code starts it. */
function sessionStart(project: string, dataDir: string, hostPid: number): void {
  const r = runHook(
    { hook_event_name: 'SessionStart', source: 'startup', cwd: project },
    { cwd: project, homeDir: makeTempDir('guardian-hs-home-'), env: { GUARDIAN_DATA_DIR: dataDir, CLAUDE_PID: String(hostPid) } },
  );
  expect(r.status, r.stderr).toBe(0);
}

describe('health_status says whether the hooks started in this session', () => {
  it('T-20 hooks and hooks_warning are always there; after the dispatcher\'s SessionStart, in the same host process, the state is running', async () => {
    const project = makeTempDir('guardian-hs-project-');
    const dataDir = join(makeTempDir('guardian-hs-data-'), 'dev-guardian');

    // Not the plugin's server: no hooks are expected, and the fields are still there.
    delete process.env['CLAUDE_PLUGIN_ROOT'];
    process.env['GUARDIAN_DATA_DIR'] = dataDir;
    const elsewhere = await health(plugin({ name: 'cursor-vscode', version: '1.9.0' }));
    expect(elsewhere.hooks.state).toBe('not_applicable');
    expect(elsewhere.hooks.host).toBe('cursor-vscode 1.9.0');
    expect(elsewhere.hooks_warning).toBeNull();

    // The plugin's server, moments after it started and before any hook: pending, no warning yet.
    asPluginServer(project, dataDir, 880_001);
    const early = await health(plugin({ name: 'claude-code', version: '2.1.322' }));
    expect(early.hooks.state).toBe('pending');
    expect(early.hooks_warning).toBeNull();

    // The real dispatcher, started by the same host process.
    sessionStart(project, dataDir, 880_001);
    const after = await health(plugin({ name: 'claude-code', version: '2.1.322' }));
    expect(after.hooks).toMatchObject({ state: 'running', matched_by: 'host_process', host: 'claude-code 2.1.322' });
    expect(after.hooks.age_seconds).toBeGreaterThanOrEqual(0);
    expect(after.hooks_warning).toBeNull();

    // EC-1: a second session of the same project, in another host process — each server finds its own mark.
    sessionStart(project, dataDir, 880_002);
    expect((await health(plugin())).hooks).toMatchObject({ state: 'running', matched_by: 'host_process' });
    asPluginServer(project, dataDir, 880_002);
    expect((await health(plugin())).hooks).toMatchObject({ state: 'running', matched_by: 'host_process' });

    // EC-6: the server looking in another data directory finds no mark there. Inside the grace period that
    // reads `pending`; `hooksStatus` past it is the unit file's T-05.
    asPluginServer(project, join(makeTempDir('guardian-hs-data-'), 'dev-guardian'), 880_001);
    const other = await health(plugin());
    expect(['pending', 'not_observed']).toContain(other.hooks.state);
    expect(other.hooks.matched_by).toBeUndefined();
  });
});
