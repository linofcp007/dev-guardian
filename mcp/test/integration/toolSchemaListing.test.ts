/**
 * The input schemas a host is shown, read the way a host reads them: through
 * `tools/list` on a real MCP client.
 *
 *   - Every parameter says what it is for. Review 3.0 M1 found a dozen with
 *     no description at all — `init_project.profile`, `diff_scans`'s four ids,
 *     `create_github_issues.dry_run` (whose default FILES REAL ISSUES),
 *     `wp_audit`'s toggles, `wp_rest_audit.timeout_ms` — so the model had the
 *     name and the type, and guessed the rest.
 *   - No schema uses `$ref`. Review 3.0 M2: `scan_containers` reused one zod
 *     instance for three parameters, and the converter emitted
 *     `{"$ref":"#/properties/signer_identity","description":…}` for the other
 *     two. Under draft-07 a keyword beside `$ref` is ignored, so their own
 *     descriptions were invisible, and a host that does not resolve `$ref`
 *     sees no type at all.
 */

import { describe, expect, it } from 'vitest';

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { TOOL_ANNOTATIONS } from '../../src/tools/annotations.js';
import { attachAllTools, listedTools, TOOLS } from '../../src/tools/index.js';
import { freshPlugin } from '../helpers/historySeed.js';
import '../../src/registerAll.js';

interface JsonSchema {
  type?: unknown;
  description?: unknown;
  properties?: Record<string, JsonSchema>;
  items?: JsonSchema | JsonSchema[];
  anyOf?: JsonSchema[];
}

interface Annotations {
  readOnlyHint?: unknown;
  destructiveHint?: unknown;
  idempotentHint?: unknown;
  openWorldHint?: unknown;
}

async function listTools(): Promise<Array<{ name: string; inputSchema: JsonSchema; annotations?: Annotations }>> {
  const server = new McpServer({ name: 'test', version: '0.0.0' });
  attachAllTools(server, freshPlugin().plugin);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const client = new Client({ name: 'test-client', version: '0.0.0' });
  await client.connect(clientTransport);
  const { tools } = await client.listTools();
  return tools.map((t) => ({
    name: t.name,
    inputSchema: t.inputSchema as JsonSchema,
    ...(t.annotations !== undefined ? { annotations: t.annotations as Annotations } : {}),
  }));
}

describe('the tool schemas a host is shown', () => {
  it('every parameter of every tool has a non-empty description', async () => {
    const missing: string[] = [];
    for (const t of await listTools()) {
      for (const [param, schema] of Object.entries(t.inputSchema.properties ?? {})) {
        if (typeof schema.description !== 'string' || schema.description.trim() === '') {
          missing.push(`${t.name}.${param}`);
        }
      }
    }
    expect(missing).toEqual([]);
  });

  it('no schema contains a $ref', async () => {
    const withRef = (await listTools())
      .filter((t) => JSON.stringify(t.inputSchema).includes('"$ref"'))
      .map((t) => t.name);
    expect(withRef).toEqual([]);
  });
});

// Review 8, finding 7: no tool declared annotations, so a host could not tell
// install_toolchain (installs by default) or create_fix_pr (pushes to GitHub)
// from health_status. Read the way a host reads them: through tools/list.
describe('the behaviour hints a host is shown (tools/list annotations)', () => {
  const HINTS = ['readOnlyHint', 'destructiveHint', 'idempotentHint', 'openWorldHint'] as const;

  it('every tool declares all four hints, as booleans', async () => {
    const tools = await listTools();
    expect(tools.length).toBe(listedTools().length);
    const incomplete = tools
      .filter((t) => HINTS.some((h) => typeof t.annotations?.[h] !== 'boolean'))
      .map((t) => t.name);
    expect(incomplete).toEqual([]);
  });

  it('the table names exactly the registered tools — no stale entry, none missing', () => {
    expect(Object.keys(TOOL_ANNOTATIONS).sort()).toEqual(TOOLS.map((t) => t.name).sort());
  });

  it('a read-only tool is never destructive', () => {
    const wrong = Object.entries(TOOL_ANNOTATIONS)
      .filter(([, a]) => a.readOnlyHint && a.destructiveHint)
      .map(([name]) => name);
    expect(wrong).toEqual([]);
  });

  it('says what the review asked of the tools that act on the world', async () => {
    const byName = new Map((await listTools()).map((t) => [t.name, t.annotations ?? {}]));
    expect(byName.get('health_status')).toMatchObject({ readOnlyHint: true, openWorldHint: false });
    expect(byName.get('check_toolchain')).toMatchObject({ readOnlyHint: true });
    expect(byName.get('install_toolchain')).toMatchObject({ readOnlyHint: false, destructiveHint: true, openWorldHint: true });
    expect(byName.get('create_fix_pr')).toMatchObject({ readOnlyHint: false, idempotentHint: false, openWorldHint: true });
    expect(byName.get('create_github_issues')).toMatchObject({ readOnlyHint: false, idempotentHint: false, openWorldHint: true });
    expect(byName.get('scan_dast')).toMatchObject({ readOnlyHint: false, destructiveHint: true, openWorldHint: true });
    for (const name of ['suppress_finding', 'set_baseline', 'init_project']) {
      expect(byName.get(name), name).toMatchObject({ readOnlyHint: false });
    }
    for (const name of ['scan_sast', 'bug_hunt', 'security_scan_full']) {
      expect(byName.get(name), `${name}: auto_fix rewrites source`).toMatchObject({ destructiveHint: true });
    }
  });
});
