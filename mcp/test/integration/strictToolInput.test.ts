/**
 * An argument a tool does not take is an error — read the way a host calls
 * the tool, through a real MCP client over an in-memory transport.
 *
 * Review 3.0 I1. The registry handed the SDK a raw zod shape, which the SDK
 * wraps in a stripping `z.object`: an unknown key was removed without a word,
 * while `tools/list` advertised `additionalProperties: false`. So a misnamed
 * parameter did not fail — it silently became the default, and the default is
 * often the most expensive or most wrong answer:
 *
 *   - `scan_skill { project_path: "<evil-skill>" }` (it takes `target`)
 *     audited the server's working directory and answered SAFE;
 *   - `validate_finding { finding_fingerprint }` (it took `fingerprint`)
 *     validated every open finding instead of the one named.
 *
 * Every tool's schema is now registered strict, so the SDK answers -32602
 * naming the key, and the handler never runs.
 */

import { afterAll, afterEach, describe, expect, it, vi } from 'vitest';

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { TOOLS, attachAllTools, type ToolModule } from '../../src/tools/index.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';
import { freshPlugin } from '../helpers/historySeed.js';
// Static, not in a beforeAll: `it.each(TOOLS…)` below is expanded when the
// file is collected, and an empty registry would generate no tests at all.
import '../../src/registerAll.js';

afterAll(cleanupTempDirs);
afterEach(() => {
  vi.restoreAllMocks();
});

async function connect(): Promise<Client> {
  const server = new McpServer({ name: 'test', version: '0.0.0' });
  attachAllTools(server, freshPlugin().plugin);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const client = new Client({ name: 'test-client', version: '0.0.0' });
  await client.connect(clientTransport);
  return client;
}

function getTool(name: string): ToolModule {
  const t = TOOLS.find((x) => x.name === name);
  if (!t) throw new Error(`Tool '${name}' not registered`);
  return t;
}

/** A handler that must not run: it answers ok, so a stripped key reads as success. */
function neverRuns(tool: ToolModule) {
  return vi.spyOn(tool, 'handler').mockResolvedValue({ ok: true });
}

function textOf(res: Awaited<ReturnType<Client['callTool']>>): string {
  const content = res.content as Array<{ type: string; text?: string }>;
  return content.map((c) => c.text ?? '').join('\n');
}

const FP = 'a'.repeat(64);

describe('an argument a tool does not take is an error', () => {
  it('scan_skill { project_path } — it takes `target` — is -32602 naming the key, and nothing is audited', async () => {
    const client = await connect();
    const spy = neverRuns(getTool('scan_skill'));
    const res = await client.callTool({ name: 'scan_skill', arguments: { project_path: makeTempDir('evil-skill-') } });
    expect(res.isError).toBe(true);
    expect(textOf(res)).toContain('-32602');
    expect(textOf(res)).toContain('project_path');
    expect(spy).not.toHaveBeenCalled();
  });

  it('suppress_finding { fingerprint } — it takes `finding_fingerprint` — names the key', async () => {
    const client = await connect();
    const spy = neverRuns(getTool('suppress_finding'));
    const res = await client.callTool({
      name: 'suppress_finding',
      arguments: { fingerprint: FP, finding_fingerprint: FP, reason: 'r' },
    });
    expect(res.isError).toBe(true);
    expect(textOf(res)).toMatch(/Unrecognized key.*'fingerprint'/);
    expect(spy).not.toHaveBeenCalled();
  });

  it('validate_finding { finding_fingerprint } is accepted: the alias reaches the handler', async () => {
    const client = await connect();
    const spy = neverRuns(getTool('validate_finding'));
    const res = await client.callTool({ name: 'validate_finding', arguments: { finding_fingerprint: 'abc' } });
    expect(res.isError).toBeFalsy();
    expect(spy).toHaveBeenCalledTimes(1);
    expect(spy.mock.calls[0]?.[0]).toMatchObject({ finding_fingerprint: 'abc' });
  });

  it('a call with only known keys still reaches the handler', async () => {
    const client = await connect();
    const spy = neverRuns(getTool('scan_skill'));
    const res = await client.callTool({ name: 'scan_skill', arguments: { target: 'x', check_deps: false } });
    expect(res.isError).toBeFalsy();
    expect(spy).toHaveBeenCalledTimes(1);
  });
});

describe('every registered tool rejects an unknown key', () => {
  it('covers the registry', () => {
    expect(TOOLS.length).toBeGreaterThanOrEqual(59);
  });

  it.each(TOOLS.map((t) => [t.name] as const))('%s', async (name) => {
    const client = await connect();
    const spy = neverRuns(getTool(name));
    const res = await client.callTool({ name, arguments: { not_a_parameter: 1 } });
    expect(res.isError).toBe(true);
    expect(textOf(res)).toContain('-32602');
    expect(textOf(res)).toContain('not_a_parameter');
    expect(spy).not.toHaveBeenCalled();
  });

  it('tools/list advertises exactly that: additionalProperties false on every input schema', async () => {
    const client = await connect();
    const { tools } = await client.listTools();
    expect(tools).toHaveLength(TOOLS.length);
    const open = tools
      .filter((t) => (t.inputSchema as { additionalProperties?: unknown }).additionalProperties !== false)
      .map((t) => t.name);
    expect(open).toEqual([]);
  });
});
