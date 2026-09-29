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
import { attachAllTools } from '../../src/tools/index.js';
import { freshPlugin } from '../helpers/historySeed.js';
import '../../src/registerAll.js';

interface JsonSchema {
  type?: unknown;
  description?: unknown;
  properties?: Record<string, JsonSchema>;
  items?: JsonSchema | JsonSchema[];
  anyOf?: JsonSchema[];
}

async function listTools(): Promise<Array<{ name: string; inputSchema: JsonSchema }>> {
  const server = new McpServer({ name: 'test', version: '0.0.0' });
  attachAllTools(server, freshPlugin().plugin);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const client = new Client({ name: 'test-client', version: '0.0.0' });
  await client.connect(clientTransport);
  const { tools } = await client.listTools();
  return tools.map((t) => ({ name: t.name, inputSchema: t.inputSchema as JsonSchema }));
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
