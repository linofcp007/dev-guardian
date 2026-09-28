/**
 * `audit_mcp_tools` stays within its bounds whatever the server does — fix
 * round 3 of Part A.
 *
 *   - C1: a server flooding stdout starved the event loop on Windows (no
 *     timer fired; timeout_ms 8000 still running after 5 min), and a command
 *     on a UNC path blocked it synchronously from the first second (and
 *     contacted SMB without allow_remote). Both are run in a CHILD process
 *     with a kill timer and an event-loop heartbeat: in-process they would
 *     freeze the test worker instead of failing a test.
 *   - I2: the common remote shapes behind a stdio command (`mcp-remote
 *     https://…`, a UNC command or argument) are remote: skipped without
 *     allow_remote, never started.
 *   - I3: a listing past its item, page or byte budget is a named partial.
 *   - I8: cancelling stops launching.
 *   - M1: every failure says what really happened.
 *   - M9: an overall budget for the whole audit.
 */

import { spawn } from 'node:child_process';
import { existsSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';

import type { PluginContext } from '../../src/context.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';
import { MCP_ROOT, TSX_NODE_ARGS } from '../helpers/tsxNode.js';

vi.setConfig({ testTimeout: 180_000 });

afterAll(cleanupTempDirs);
afterEach(() => {
  vi.unstubAllEnvs();
});

beforeAll(async () => {
  await import('../../src/tools/auditMcpTools.js');
});

const FIXTURE = fileURLToPath(new URL('../fixtures/mcpaudit/server.mjs', import.meta.url));
const UNC_COMMAND = '\\\\192.0.2.1\\share\\evil.exe';

interface ServerReport {
  name: string;
  status: 'ok' | 'partial' | 'failed' | 'skipped';
  reason?: string;
  tools_count: number;
}

interface AuditResult {
  ok: true;
  coverage: string;
  servers: ServerReport[];
  tools_run: Array<{ name: string; status: string; reason?: string }>;
  missing_tools: string[];
}

function makePlugin(): PluginContext {
  const db = new Database(':memory:');
  runMigrations(db);
  return {
    storage: new Storage(db),
    shell: { command: 'bash', args_prefix: [], needs_wsl_path_translate: false, label: 'fake' },
    scriptsDir: '',
    progressNotifier: { send: () => {} },
  };
}

function stdio(mode: string, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return { command: process.execPath, args: [FIXTURE, mode], ...extra };
}

function project(servers: Record<string, unknown>): string {
  const dir = makeTempDir('mcp-bounds-');
  writeFileSync(join(dir, '.mcp.json'), JSON.stringify({ mcpServers: servers }), 'utf8');
  return dir;
}

async function audit(
  input: Record<string, unknown>,
  meta?: { signal: AbortSignal },
): Promise<AuditResult> {
  const tool = TOOLS.find((t) => t.name === 'audit_mcp_tools');
  if (tool === undefined) throw new Error('audit_mcp_tools not registered');
  const r = (await tool.handler(input, makePlugin(), meta)) as unknown as AuditResult | { ok: false; error: unknown };
  if (!r.ok) throw new Error(`audit failed: ${JSON.stringify(r.error)}`);
  return r;
}

interface ChildAudit {
  killed: boolean;
  elapsed: number;
  /** Longest gap between two ticks of a 50 ms interval during the audit. */
  maxGap: number;
  result?: AuditResult;
}

/** Runs the tool in a child process, killed after `killAfterMs`. */
function auditInChild(input: Record<string, unknown>, killAfterMs: number): Promise<ChildAudit> {
  const dir = makeTempDir('mcp-bounds-child-');
  const url = (rel: string): string => JSON.stringify(pathToFileURL(resolve(MCP_ROOT, 'src', rel)).href);
  const script = join(dir, 'audit.mjs');
  writeFileSync(
    script,
    [
      `import { GuardianDatabase } from ${url('storage/db.ts')};`,
      `import { runMigrations } from ${url('storage/migrations/runner.ts')};`,
      `import { Storage } from ${url('storage/index.ts')};`,
      `import ${url('tools/auditMcpTools.ts')};`,
      `import { TOOLS } from ${url('tools/index.ts')};`,
      'const input = JSON.parse(process.argv[2]);',
      "const db = new GuardianDatabase(':memory:');",
      'runMigrations(db);',
      "const ctx = { storage: new Storage(db), shell: { command: 'bash', args_prefix: [], needs_wsl_path_translate: false, label: 'fake' }, scriptsDir: '', progressNotifier: { send() {} } };",
      'let last = Date.now(); let maxGap = 0;',
      'const hb = setInterval(() => { const now = Date.now(); maxGap = Math.max(maxGap, now - last); last = now; }, 50);',
      'const t0 = Date.now();',
      "const result = await TOOLS.find((t) => t.name === 'audit_mcp_tools').handler(input, ctx);",
      'clearInterval(hb);',
      'process.stdout.write(JSON.stringify({ elapsed: Date.now() - t0, maxGap, result }));',
      'process.exit(0);',
    ].join('\n'),
  );
  return new Promise((done) => {
    const started = Date.now();
    const child = spawn(process.execPath, [...TSX_NODE_ARGS, script, JSON.stringify(input)], {
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let out = '';
    child.stdout.on('data', (d: Buffer) => {
      out += d.toString('utf8');
    });
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      done({ killed: true, elapsed: Date.now() - started, maxGap: Number.NaN });
    }, killAfterMs);
    child.on('exit', () => {
      clearTimeout(timer);
      try {
        const parsed = JSON.parse(out) as { elapsed: number; maxGap: number; result: AuditResult };
        done({ killed: false, ...parsed });
      } catch {
        done({ killed: false, elapsed: Date.now() - started, maxGap: Number.NaN });
      }
    });
  });
}

describe('C1: the audit keeps its own time', () => {
  it('fails a server that floods stdout, on time, without starving the event loop', async () => {
    const dir = project({ flood: stdio('flood') });
    const r = await auditInChild({ project_path: dir, servers: ['flood'], timeout_ms: 5000 }, 120_000);
    expect(r.killed, 'the audit never returned and was killed').toBe(false);
    expect(r.elapsed).toBeLessThan(30_000);
    expect(r.maxGap).toBeLessThan(3000);
    const server = r.result?.servers[0];
    expect(server?.status).toBe('failed');
    expect(server?.reason).toMatch(/budget|more than|did not answer/i);
  });

  it('skips a command on a UNC path without allow_remote, at once and without starting it', async () => {
    const dir = project({ unc: { command: UNC_COMMAND, args: [] } });
    const r = await auditInChild({ project_path: dir, servers: ['unc'], timeout_ms: 2000 }, 120_000);
    expect(r.killed, 'the audit never returned and was killed').toBe(false);
    expect(r.elapsed).toBeLessThan(10_000);
    expect(r.result?.servers[0]?.status).toBe('skipped');
    expect(r.result?.servers[0]?.reason).toContain('allow_remote');
  });

  it('with allow_remote, fails an unreachable UNC command within its budget and never blocks the event loop', async () => {
    const dir = project({ unc: { command: UNC_COMMAND, args: [] } });
    const r = await auditInChild({ project_path: dir, servers: ['unc'], timeout_ms: 2000, allow_remote: true }, 120_000);
    expect(r.killed, 'the audit never returned and was killed').toBe(false);
    expect(r.elapsed).toBeLessThan(20_000);
    expect(r.maxGap).toBeLessThan(3000);
    expect(r.result?.servers[0]?.status).toBe('failed');
  });
});

describe('I2: remote shapes behind a stdio command', () => {
  it.each([
    ['an https URL argument (mcp-remote)', 'https://192.0.2.1/mcp'],
    ['a wss URL argument', 'wss://192.0.2.1/socket'],
    ['a UNC path argument', '\\\\192.0.2.1\\share\\server.js'],
    ['a UNC path in a --flag=value argument', '--config=\\\\192.0.2.1\\share\\c.json'],
  ])('skips a command line with %s without allow_remote, and never starts it', async (_what, arg) => {
    const dir = project({ proxy: stdio('poisoned', { args: [FIXTURE, 'poisoned', arg], env: { MARK: 'proxy' } }) });
    const r = await audit({ project_path: dir, servers: ['proxy'] });
    expect(r.servers[0]?.status).toBe('skipped');
    expect(r.servers[0]?.reason).toContain('allow_remote');
    expect(existsSync(join(dir, 'probe-poisoned-proxy.json'))).toBe(false);
    expect(r.coverage).toBe('none');
  });

  it('starts that same command line when allow_remote is given', async () => {
    const dir = project({
      proxy: stdio('poisoned', { args: [FIXTURE, 'poisoned', 'https://192.0.2.1/mcp'], env: { MARK: 'proxy' } }),
    });
    const r = await audit({ project_path: dir, servers: ['proxy'], allow_remote: true, timeout_ms: 60_000 });
    expect(r.servers[0]?.status).toBe('ok');
    expect(existsSync(join(dir, 'probe-poisoned-proxy.json'))).toBe(true);
  });
});

describe('I3 and M1: budgets, and saying which one stopped the listing', () => {
  it('lists at most 1000 tools and calls the result partial, not a pass', async () => {
    const dir = project({ many: stdio('many') });
    const r = await audit({ project_path: dir, servers: ['many'], timeout_ms: 60_000 });
    expect(r.servers[0]?.status).toBe('partial');
    expect(r.servers[0]?.tools_count).toBe(1000);
    expect(r.servers[0]?.reason).toContain('1000');
    expect(r.missing_tools).toContain('mcp-tool-audit:.mcp.json::many');
    expect(r.coverage).toBe('partial');
  });

  it('stops at a repeated cursor and says so', async () => {
    const dir = project({ loop: stdio('cursorloop') });
    const r = await audit({ project_path: dir, servers: ['loop'], timeout_ms: 60_000 });
    expect(r.servers[0]?.status).toBe('partial');
    expect(r.servers[0]?.reason).toMatch(/repeated cursor/i);
  });

  it('fails a server whose single message exceeds the per-message cap, and names the cap', async () => {
    const dir = project({ big: stdio('bigline') });
    const r = await audit({ project_path: dir, servers: ['big'], timeout_ms: 60_000 });
    expect(r.servers[0]?.status).toBe('failed');
    expect(r.servers[0]?.reason).toMatch(/8 MiB/);
    expect(r.servers[0]?.reason).not.toMatch(/exited with code/);
  });
});

describe('I8: cancelling stops launching', () => {
  it('starts nothing when the call is already cancelled', async () => {
    const dir = project({ a: stdio('poisoned', { env: { MARK: 'a' } }), b: stdio('poisoned', { env: { MARK: 'b' } }) });
    const controller = new AbortController();
    controller.abort();
    const r = await audit({ project_path: dir, servers: ['a', 'b'] }, { signal: controller.signal });
    expect(r.servers.map((s) => s.status)).toEqual(['skipped', 'skipped']);
    expect(r.servers.every((s) => (s.reason ?? '').includes('cancelled'))).toBe(true);
    expect(existsSync(join(dir, 'probe-poisoned-a.json'))).toBe(false);
    expect(existsSync(join(dir, 'probe-poisoned-b.json'))).toBe(false);
  });

  it('does not start the next server after a cancel in the middle of the audit', async () => {
    const dir = project({ slow: stdio('hang'), next: stdio('poisoned', { env: { MARK: 'next' } }) });
    const controller = new AbortController();
    setTimeout(() => controller.abort(), 1500);
    const t0 = Date.now();
    const r = await audit({ project_path: dir, servers: ['slow', 'next'], timeout_ms: 60_000 }, { signal: controller.signal });
    expect(Date.now() - t0).toBeLessThan(30_000);
    expect(r.servers.find((s) => s.name === 'next')?.status).toBe('skipped');
    expect(existsSync(join(dir, 'probe-poisoned-next.json'))).toBe(false);
  });
});

describe('M9: an overall budget for the whole audit', () => {
  it('skips the servers left once GUARDIAN_MCP_AUDIT_BUDGET_MS is used up, with the reason', async () => {
    vi.stubEnv('GUARDIAN_MCP_AUDIT_BUDGET_MS', '3000');
    const dir = project({ slow: stdio('hang'), next: stdio('poisoned', { env: { MARK: 'next' } }) });
    const t0 = Date.now();
    const r = await audit({ project_path: dir, servers: ['slow', 'next'], timeout_ms: 60_000 });
    expect(Date.now() - t0).toBeLessThan(30_000);
    expect(r.servers.find((s) => s.name === 'slow')?.status).toBe('failed');
    const next = r.servers.find((s) => s.name === 'next');
    expect(next?.status).toBe('skipped');
    expect(next?.reason).toMatch(/budget/i);
    expect(existsSync(join(dir, 'probe-poisoned-next.json'))).toBe(false);
  });
});
