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
import { spawn, type ChildProcess } from 'node:child_process';
import { symlinkSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join, resolve } from 'node:path';
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

/**
 * Two host processes that really exist: this one, and a child that only waits.
 * A made-up id would not do — SessionStart removes the mark of a host process
 * that is gone, so the next session's start would take the first one's away.
 */
const HOST_A = process.pid;
let second: ChildProcess;
let HOST_B = 0;

afterAll(() => {
  second?.kill();
  cleanupTempDirs();
});

const REPO_ROOT = fileURLToPath(new URL('../../..', import.meta.url));

/** The environment this file changes, restored after each test. */
const TOUCHED = ['GUARDIAN_DATA_DIR', 'CLAUDE_PLUGIN_ROOT', 'CLAUDE_PROJECT_DIR', 'CLAUDE_PID'] as const;
let saved: Record<string, string | undefined>;

beforeAll(async () => {
  await import('../../src/tools/healthStatus.js');
  second = spawn(process.execPath, ['-e', 'setTimeout(() => {}, 120000)'], { stdio: 'ignore' });
  HOST_B = second.pid ?? 0;
  expect(HOST_B).toBeGreaterThan(0);
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
    asPluginServer(project, dataDir, HOST_A);
    const early = await health(plugin({ name: 'claude-code', version: '2.1.322' }));
    expect(early.hooks.state).toBe('pending');
    expect(early.hooks_warning).toBeNull();

    // The real dispatcher, started by the same host process.
    sessionStart(project, dataDir, HOST_A);
    const after = await health(plugin({ name: 'claude-code', version: '2.1.322' }));
    expect(after.hooks).toMatchObject({ state: 'running', matched_by: 'host_process', host: 'claude-code 2.1.322' });
    expect(after.hooks.age_seconds).toBeGreaterThanOrEqual(0);
    expect(after.hooks_warning).toBeNull();

    // EC-1: a second session of the same project, in another host process — each server finds its own mark.
    sessionStart(project, dataDir, HOST_B);
    expect((await health(plugin())).hooks).toMatchObject({ state: 'running', matched_by: 'host_process' });
    asPluginServer(project, dataDir, HOST_B);
    expect((await health(plugin())).hooks).toMatchObject({ state: 'running', matched_by: 'host_process' });

    // EC-6: the server looking in another data directory finds no mark there. Inside the grace period that
    // reads `pending`; `hooksStatus` past it is the unit file's T-05.
    asPluginServer(project, join(makeTempDir('guardian-hs-data-'), 'dev-guardian'), HOST_A);
    const other = await health(plugin());
    expect(['pending', 'not_observed']).toContain(other.hooks.state);
    expect(other.hooks.matched_by).toBeUndefined();
  });
});

/**
 * hooks-state-linked-plugin-root. Claude Code names the plugin's root as it
 * reaches it (`<its config directory>/plugins/cache/…`); Node names the
 * server's own file with every link resolved. With several accounts sharing
 * one `plugins` directory through a junction, the server took itself for
 * another server and answered `not_applicable` in a session whose hooks had
 * started — and would have, the same, in one where they had not.
 */
describe("the plugin's root reached through a link", () => {
  it("T-01 a server whose root Claude Code names through a link is still the plugin's: pending, then running once the hook has started", async () => {
    const project = makeTempDir('guardian-hs-project-');
    const dataDir = join(makeTempDir('guardian-hs-data-'), 'dev-guardian');
    // As an account's config directory reaches a shared install: a link to the root this server runs from.
    const linked = join(makeTempDir('guardian-hs-account-'), 'dev-guardian');
    symlinkSync(resolve(REPO_ROOT), linked, process.platform === 'win32' ? 'junction' : 'dir');

    asPluginServer(project, dataDir, HOST_A);
    process.env['CLAUDE_PLUGIN_ROOT'] = linked;
    const early = await health(plugin({ name: 'claude-code', version: '2.1.323' }));
    expect(early.hooks.reason, 'the server took itself for another one').toBeUndefined();
    expect(early.hooks.state).toBe('pending');
    expect(early.hooks_warning).toBeNull();

    // The real dispatcher, started by the same host process.
    sessionStart(project, dataDir, HOST_A);
    const after = await health(plugin({ name: 'claude-code', version: '2.1.323' }));
    expect(after.hooks).toMatchObject({ state: 'running', matched_by: 'host_process', host: 'claude-code 2.1.323' });
    expect(after.hooks_warning).toBeNull();
  });
});
