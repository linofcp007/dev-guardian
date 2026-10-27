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
import { z } from 'zod';
import {
  MAX_INPUT_ARRAY,
  TOOLS,
  attachAllTools,
  listedTools,
  strictInputSchema,
  type ToolModule,
} from '../../src/tools/index.js';
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
    expect(textOf(res)).toMatch(/Unrecognized key.*"fingerprint"/);
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

// Review 3.0 round 3 (N7): the MCP spec makes `arguments` optional, but a
// tools/call without it got -32602 "Required" from every tool — measured on
// 430c797 too, before the schemas were strict — including check_toolchain,
// which takes no parameters at all. A missing `arguments` is now `{}`.
describe('a tools/call with no arguments', () => {
  const allOptional = (t: ToolModule): boolean => Object.values(t.inputSchema).every((s) => s.isOptional());

  it('check_toolchain, which takes no parameters, runs', async () => {
    const client = await connect();
    const spy = neverRuns(getTool('check_toolchain'));
    const res = await client.callTool({ name: 'check_toolchain' });
    expect(res.isError).toBeFalsy();
    expect(spy).toHaveBeenCalledTimes(1);
    expect(spy.mock.calls[0]?.[0]).toEqual({});
  });

  it.each(TOOLS.filter(allOptional).map((t) => [t.name] as const))('%s (every parameter optional) runs', async (name) => {
    const client = await connect();
    const spy = neverRuns(getTool(name));
    const res = await client.callTool({ name });
    expect(res.isError, textOf(res)).toBeFalsy();
    expect(spy).toHaveBeenCalledTimes(1);
  });

  it.each(TOOLS.filter((t) => !allOptional(t)).map((t) => [t.name] as const))(
    '%s (a required parameter) is -32602 naming that parameter, not the whole object',
    async (name) => {
      const client = await connect();
      const spy = neverRuns(getTool(name));
      const res = await client.callTool({ name });
      expect(res.isError).toBe(true);
      const required = Object.entries(getTool(name).inputSchema)
        .filter(([, s]) => !s.isOptional())
        .map(([k]) => k);
      expect(textOf(res)).toContain('-32602');
      expect(required.some((k) => textOf(res).includes(k))).toBe(true);
      expect(spy).not.toHaveBeenCalled();
    },
  );
});

// zod 3 parsed every element of an array even past its `.max()`, keeping one
// issue per failing element (GHSA-mrhx-c7xc-m3w5); zod 4.6.6 answers a `.max()`
// first. A list longer than any schema accepts is still refused before zod
// walks it: a list with no `.max()` is walked whole.
describe('a list past MAX_INPUT_ARRAY', () => {
  const wrong = Array.from({ length: 200_000 }, () => 7);

  it('zod answers 200 000 wrong items past a .max(1000) with one issue; with no .max(), one per item', () => {
    const capped = z.array(z.string()).max(1000).safeParse(wrong);
    expect(capped.success).toBe(false);
    expect(capped.error?.issues.map((i) => i.code)).toEqual(['too_big']);
    expect(z.array(z.string()).safeParse(wrong).error?.issues).toHaveLength(wrong.length);
  });

  it('is refused by the preprocess step alone: one issue, the object never parsed', async () => {
    const parsed = await strictInputSchema(getTool('llm_scan_start')).safeParseAsync({ fingerprints: wrong, not_a_parameter: 1 });
    expect(parsed.error?.issues).toEqual([
      expect.objectContaining({ code: 'custom', path: ['fingerprints'], message: `at most ${MAX_INPUT_ARRAY} items per list (200000 given)` }),
    ]);
    const none = await strictInputSchema(getTool('check_toolchain')).safeParseAsync(undefined);
    expect(none).toMatchObject({ success: true, data: {} });
  });

  it('is -32602 naming its path, and the handler never runs; a list at the limit reaches zod', async () => {
    const client = await connect();
    const spy = neverRuns(getTool('llm_scan_start'));
    const huge = Array.from({ length: MAX_INPUT_ARRAY + 1 }, () => 7);
    const res = await client.callTool({ name: 'llm_scan_start', arguments: { fingerprints: huge } });
    expect(res.isError).toBe(true);
    expect(textOf(res)).toContain('-32602');
    expect(textOf(res)).toContain(`at most ${MAX_INPUT_ARRAY} items per list (${MAX_INPUT_ARRAY + 1} given)`);
    expect(textOf(res)).toContain('fingerprints');
    const atLimit = await client.callTool({ name: 'llm_scan_start', arguments: { fingerprints: huge.slice(1) } });
    expect(atLimit.isError).toBe(true);
    expect(textOf(atLimit)).not.toContain('items per list');
    expect(spy).not.toHaveBeenCalled();
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
    // The listed tools; a hidden alias is strict too, and is called by name in the tests above.
    expect(tools).toHaveLength(listedTools().length);
    const open = tools
      .filter((t) => (t.inputSchema as { additionalProperties?: unknown }).additionalProperties !== false)
      .map((t) => t.name);
    expect(open).toEqual([]);
  });
});
