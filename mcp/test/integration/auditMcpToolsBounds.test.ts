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
  pins?: { first_audit: boolean; changed: string[]; added: string[]; removed: string[] };
}

interface AuditResult {
  ok: true;
  scan_id: string;
  coverage: string;
  findings: Array<{ rule_id?: string; severity: string; title: string; message?: string; snippet?: string }>;
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
  plugin: PluginContext = makePlugin(),
): Promise<AuditResult> {
  const tool = TOOLS.find((t) => t.name === 'audit_mcp_tools');
  if (tool === undefined) throw new Error('audit_mcp_tools not registered');
  const r = (await tool.handler(input, plugin, meta)) as unknown as AuditResult | { ok: false; error: unknown };
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
function auditInChild(input: Record<string, unknown>, killAfterMs: number, nodeFlags: string[] = []): Promise<ChildAudit> {
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
      // The gap still open when the handler returns counts too: fix round 4
      // found a 19 s analysis stall this test missed by clearing first.
      'maxGap = Math.max(maxGap, Date.now() - last);',
      'clearInterval(hb);',
      'process.stdout.write(JSON.stringify({ elapsed: Date.now() - t0, maxGap, result }));',
      'process.exit(0);',
    ].join('\n'),
  );
  return new Promise((done) => {
    const started = Date.now();
    const child = spawn(process.execPath, [...nodeFlags, ...TSX_NODE_ARGS, script, JSON.stringify(input)], {
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

/**
 * Fix round 4, C1 residual: the ANALYSIS ran synchronously over every
 * listing, unbounded, with all of them held to the end. Measured by the
 * review: one server of 4 pages x a 7 MiB "send data " description stalled
 * the event loop 19 s (and reported ok, coverage full); 4 x 250 tools x
 * 4000 enum strings, 27 s; three such servers, 44 s at 1.7 GB RSS, and a
 * heap abort under --max-old-space-size=600.
 */
/**
 * Fix round 5, I-1 (reproduced): one tool holding 6000 nested arrays
 * (~12 KB) threw `RangeError: Maximum call stack size exceeded` in the pin
 * hash, outside any per-server guard — another server's findings and pins
 * were lost and the whole scan failed.
 */
describe('I-1: one server cannot cost another its results', () => {
  it('audits a server with a value 6000 arrays deep beside a poisoned one: both reported, the deep one partial', async () => {
    const plugin = makePlugin();
    const dir = project({ deep: stdio('deep'), bad: stdio('poisoned', { env: { MARK: 'bad' } }) });
    const r = await audit({ project_path: dir, servers: ['deep', 'bad'], timeout_ms: 60_000 }, undefined, plugin);
    const deep = r.servers.find((s) => s.name === 'deep');
    expect(deep?.status).toBe('partial');
    expect(r.findings.some((f) => f.rule_id === 'mcp-tool-schema-too-deep')).toBe(true);
    expect(r.servers.find((s) => s.name === 'bad')?.status).toBe('ok');
    expect(r.findings.some((f) => f.rule_id === 'mcp-tool-poisoning' && f.title.includes("'bad'"))).toBe(true);
    expect(plugin.storage.scans.getById(r.scan_id)?.status).toBe('completed');
  });

  it("keeps the other servers' results when processing one server throws", async () => {
    const plugin = makePlugin();
    const original = plugin.storage.mcpToolPins.getServerPins.bind(plugin.storage.mcpToolPins);
    vi.spyOn(plugin.storage.mcpToolPins, 'getServerPins').mockImplementation((projectPath, serverKey) => {
      if (serverKey.includes('"first"')) throw new Error('storage exploded');
      return original(projectPath, serverKey);
    });
    const dir = project({ first: stdio('poisoned', { env: { MARK: 'first' } }), second: stdio('poisoned', { env: { MARK: 'second' } }) });
    const r = await audit({ project_path: dir, servers: ['first', 'second'], timeout_ms: 60_000 }, undefined, plugin);
    const first = r.servers.find((s) => s.name === 'first');
    expect(first?.status).toBe('partial');
    expect(first?.reason).toContain('storage exploded');
    expect(r.servers.find((s) => s.name === 'second')?.status).toBe('ok');
    expect(r.findings.some((f) => f.title.includes("'second'"))).toBe(true);
    expect(r.coverage).toBe('partial');
  });
});

describe('C1 residual: the analysis is bounded, yields, and is never a clean pass when cut', () => {
  const quick = (r: ChildAudit): void => {
    expect(r.killed, 'the audit never returned and was killed').toBe(false);
    expect(r.elapsed).toBeLessThan(60_000);
    expect(r.maxGap).toBeLessThan(1500);
  };

  it.each([
    ['4 pages x a 7 MiB description', 'huge'],
    ['4 pages x 250 tools x 4000 enum strings', 'enum'],
  ])('the review shape (%s) returns promptly, and not as a clean pass', async (_what, mode) => {
    const dir = project({ s: stdio(mode) });
    const r = await auditInChild({ project_path: dir, servers: ['s'], timeout_ms: 60_000 }, 150_000);
    quick(r);
    expect(r.result?.servers[0]?.status).not.toBe('ok');
    expect(r.result?.coverage).not.toBe('full');
  });

  it('text past the analysed-text bound makes the server partial, with the reason', async () => {
    const dir = project({ s: stdio('bulky') });
    const r = await auditInChild({ project_path: dir, servers: ['s'], timeout_ms: 60_000 }, 150_000);
    quick(r);
    expect(r.result?.servers[0]?.status).toBe('partial');
    expect(r.result?.servers[0]?.reason).toMatch(/2 MiB of text/);
  });

  it('strings past the analysed-string count make the server partial, with the reason', async () => {
    const dir = project({ s: stdio('manyenum') });
    const r = await auditInChild({ project_path: dir, servers: ['s'], timeout_ms: 60_000 }, 150_000);
    quick(r);
    expect(r.result?.servers[0]?.status).toBe('partial');
    expect(r.result?.servers[0]?.reason).toMatch(/strings/);
  });

  it('a string over the per-string bound is a finding, and the server partial', async () => {
    const dir = project({ s: stdio('longstring') });
    const r = await audit({ project_path: dir, servers: ['s'], timeout_ms: 60_000 });
    expect(r.servers[0]?.status).toBe('partial');
    const findings = (r as AuditResult & { findings: Array<{ rule_id?: string }> }).findings;
    expect(findings.some((f) => f.rule_id === 'mcp-tool-string-over-bound')).toBe(true);
  });

  it('three heavy servers in one audit stay within a 400 MB heap', async () => {
    const dir = project({ a: stdio('bulky', { env: { MARK: 'a' } }), b: stdio('bulky', { env: { MARK: 'b' } }), c: stdio('huge') });
    const r = await auditInChild(
      { project_path: dir, servers: ['a', 'b', 'c'], timeout_ms: 60_000 },
      300_000,
      ['--max-old-space-size=400'],
    );
    quick(r);
    expect(r.result?.servers.map((s) => s.status)).toHaveLength(3);
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

  // Fix round 4, I2 residual (reproduced): this started, wrote the marker and
  // tried SMB, and came back failed rather than skipped.
  it('never starts a shell whose command string reaches a network path', async () => {
    const shell =
      process.platform === 'win32'
        ? { command: 'cmd', args: ['/c', 'echo started> marker.txt & type \\\\192.0.2.1\\share\\x.txt'] }
        : { command: 'sh', args: ['-c', 'echo started > marker.txt; cat //192.0.2.1/share/x.txt'] };
    const dir = project({ sh: shell });
    const r = await audit({ project_path: dir, servers: ['sh'] });
    expect(r.servers[0]?.status).toBe('skipped');
    expect(r.servers[0]?.reason).toContain('allow_remote');
    expect(existsSync(join(dir, 'marker.txt'))).toBe(false);
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

  // Fix round 4 (reproduced): -32603 on resources/templates/list read ok,
  // coverage full, missing_tools empty. Only MethodNotFound is silent.
  it.each(['tools/list', 'prompts/list', 'resources/list', 'resources/templates/list'])(
    'makes the server partial when %s answers an error other than MethodNotFound',
    async (method) => {
      const dir = project({ e: stdio('listerror', { env: { LIST_ERRORS: JSON.stringify({ [method]: -32603 }) } }) });
      const r = await audit({ project_path: dir, servers: ['e'], timeout_ms: 60_000 });
      expect(r.servers[0]?.status).toBe('partial');
      expect(r.servers[0]?.reason).toContain(method);
      expect(r.coverage).toBe('partial');
      expect(r.missing_tools).toContain('mcp-tool-audit:.mcp.json::e');
    },
  );

  // Fix round 5, I-2 (reproduced): page 1 with a nextCursor, then -32601 on
  // page 2, read ok — clean, pins replaced as complete, unseen tools
  // tombstoned. MethodNotFound is silent only on a list's FIRST page.
  it('makes the server partial when a later page answers MethodNotFound, and tombstones nothing', async () => {
    const plugin = makePlugin();
    const flag = join(makeTempDir('mcp-bounds-flag-'), 'missing');
    const dir = project({ p: stdio('poisoned', { env: { PAGE2_MISSING_FILE: flag } }) });
    const first = await audit({ project_path: dir, servers: ['p'], timeout_ms: 60_000 }, undefined, plugin);
    expect(first.servers[0]?.status).toBe('ok');
    writeFileSync(flag, '', 'utf8');
    const second = await audit({ project_path: dir, servers: ['p'], timeout_ms: 60_000 }, undefined, plugin);
    expect(second.servers[0]?.status).toBe('partial');
    expect(second.servers[0]?.reason).toMatch(/tools\/list.*page 2/);
    expect(second.servers[0]?.pins?.removed ?? []).toEqual([]);
    expect(second.coverage).toBe('partial');
  });

  it('stays silent when a list method is MethodNotFound (-32601)', async () => {
    const errors = { 'prompts/list': -32601, 'resources/templates/list': -32601 };
    const dir = project({ e: stdio('listerror', { env: { LIST_ERRORS: JSON.stringify(errors) } }) });
    const r = await audit({ project_path: dir, servers: ['e'], timeout_ms: 60_000 });
    expect(r.servers[0]?.status).toBe('ok');
    expect(r.coverage).toBe('full');
  });

  it('fails a server whose single message exceeds the per-message cap, and names the cap', async () => {
    const dir = project({ big: stdio('bigline') });
    const r = await audit({ project_path: dir, servers: ['big'], timeout_ms: 60_000 });
    expect(r.servers[0]?.status).toBe('failed');
    expect(r.servers[0]?.reason).toMatch(/2 MiB/);
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
