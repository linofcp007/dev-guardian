/**
 * Resources and response sizes, read the way a host reads them — through a
 * real MCP client over an in-memory transport, not by calling handlers.
 *
 * That is the only way to see the first defect here: the findings resources
 * documented `?page=` / `?page_size=`, the handlers even implemented them,
 * and yet `guardian://findings/open?page=2` answered "Resource not found",
 * because the SDK matches a read against static URIs exactly and no
 * template covered the query string.
 */

import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { writeFileSync } from 'node:fs';

vi.mock('../../src/tools/scanHelpers.js', async () => {
  const actual =
    await vi.importActual<typeof import('../../src/tools/scanHelpers.js')>(
      '../../src/tools/scanHelpers.js',
    );
  return { ...actual, scannerAvailable: vi.fn() };
});
vi.mock('../../src/runners/processRunner.js', () => ({ runProcess: vi.fn() }));

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { PluginContext } from '../../src/context.js';
import { attachAllResources } from '../../src/resources/index.js';
import { runProcess } from '../../src/runners/processRunner.js';
import { scannerAvailable } from '../../src/tools/scanHelpers.js';
import { attachAllTools } from '../../src/tools/index.js';
import type { RouteRecord } from '../../src/types.js';
import { cleanupTempDirs } from '../helpers/tempDir.js';
import { freshPlugin, projectDir, seedScan } from '../helpers/historySeed.js';

afterAll(cleanupTempDirs);
afterEach(() => {
  vi.restoreAllMocks();
  vi.mocked(scannerAvailable).mockReset();
  vi.mocked(runProcess).mockReset();
});

beforeAll(async () => {
  await import('../../src/registerAll.js');
});

async function connect(plugin: PluginContext): Promise<Client> {
  const server = new McpServer({ name: 'test', version: '0.0.0' });
  attachAllTools(server, plugin);
  attachAllResources(server, plugin);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const client = new Client({ name: 'test-client', version: '0.0.0' });
  await client.connect(clientTransport);
  return client;
}

async function readJson(client: Client, uri: string): Promise<{ text: string; json: Record<string, unknown> }> {
  const res = await client.readResource({ uri });
  const first = res.contents[0];
  if (first === undefined || !('text' in first) || typeof first.text !== 'string') {
    throw new Error(`no text content for ${uri}`);
  }
  return { text: first.text, json: JSON.parse(first.text) as Record<string, unknown> };
}

function threeFindings(): { plugin: PluginContext; project: string } {
  const s = freshPlugin();
  const project = projectDir('paging-');
  seedScan(s, {
    id: 'p1', type: 'sast', project,
    findings: [
      { severity: 'critical' },
      { severity: 'high' },
      { severity: 'high', message: 'm'.repeat(2000) },
    ],
  });
  vi.spyOn(process, 'cwd').mockReturnValue(project);
  return { plugin: s.plugin, project };
}

describe('findings resources are pageable through the protocol', () => {
  it('serves guardian://findings/open?page=2 instead of "Resource not found"', async () => {
    const { plugin } = threeFindings();
    const client = await connect(plugin);
    const { json } = await readJson(client, 'guardian://findings/open?page=2');
    expect(json['page']).toBe(2);
    expect(json['total']).toBe(3);
    expect(json['findings']).toEqual([]);
  });

  it('honours page and page_size together, in either order', async () => {
    const { plugin } = threeFindings();
    const client = await connect(plugin);
    for (const uri of [
      'guardian://findings/open?page=2&page_size=2',
      'guardian://findings/open?page_size=2&page=2',
    ]) {
      const { json } = await readJson(client, uri);
      expect(json['total']).toBe(3);
      expect(json['page_size']).toBe(2);
      expect(json['findings']).toHaveLength(1);
    }
  });

  it('pages critical and by-severity too', async () => {
    const { plugin } = threeFindings();
    const client = await connect(plugin);
    const critical = await readJson(client, 'guardian://findings/critical?page=1');
    expect(critical.json['total']).toBe(1);
    const high = await readJson(client, 'guardian://findings/by-severity/high?page=2&page_size=1');
    expect(high.json['total']).toBe(2);
    expect(high.json['findings']).toHaveLength(1);
    expect(high.json['level']).toBe('high');
  });

  it('caps page_size at 100', async () => {
    const { plugin } = threeFindings();
    const client = await connect(plugin);
    const { json } = await readJson(client, 'guardian://findings/open?page_size=500');
    expect(json['page_size']).toBe(100);
  });

  it('serves compact JSON with messages truncated to 500 characters', async () => {
    const { plugin } = threeFindings();
    const client = await connect(plugin);
    const { text, json } = await readJson(client, 'guardian://findings/open');
    expect(text).not.toContain('\n');
    const messages = (json['findings'] as Array<{ message?: string }>).map((f) => f.message ?? '');
    expect(Math.max(...messages.map((m) => m.length))).toBeLessThanOrEqual(500);
  });

  it('advertises the paged templates and still lists the plain URIs', async () => {
    const { plugin } = threeFindings();
    const client = await connect(plugin);
    const templates = (await client.listResourceTemplates()).resourceTemplates.map((t) => t.uriTemplate);
    expect(templates).toEqual(
      expect.arrayContaining([
        'guardian://findings/open{?page,page_size}',
        'guardian://findings/critical{?page,page_size}',
        'guardian://findings/by-severity/{level}{?page,page_size}',
      ]),
    );
    const listed = (await client.listResources()).resources.map((r) => r.uri);
    expect(listed).toEqual(expect.arrayContaining(['guardian://findings/open', 'guardian://findings/critical']));
  });
});

describe('guardian://surface/latest is bounded and says what it left out', () => {
  function route(i: number): RouteRecord {
    return {
      method: 'GET', provenance: 'code', path_raw: `/r${i}`, path_resolved: `/r${i}`,
      path_partial: false, file: `src/r${i}.ts`, line: 1, framework: 'express',
      language: 'typescript', auth_hint: 'unknown', params: [], confidence: 'high',
    };
  }

  it('returns at most 200 routes with the true totals', async () => {
    const s = freshPlugin();
    const project = projectDir('surface-');
    const routes = Array.from({ length: 450 }, (_, i) => route(i));
    s.storage.surface.insert({
      project_path: project,
      tree_hash: 'h',
      snapshot: {
        routes, env_vars: [], ports: [], webhooks: [], coverage: [], tools_run: [],
        missing_tools: [], spec_files: [], spec_diff: null,
        imports: Array.from({ length: 5000 }, (_, i) => ({ file: `a${i}.ts`, module_file: `b${i}.ts` })),
      },
    });
    vi.spyOn(process, 'cwd').mockReturnValue(project);
    const client = await connect(s.plugin);
    const { json, text } = await readJson(client, 'guardian://surface/latest');
    const snapshot = json['snapshot'] as { routes: unknown[]; imports?: unknown[] };
    expect(snapshot.routes).toHaveLength(200);
    expect(snapshot.imports).toBeUndefined();
    expect(json['totals']).toEqual(expect.objectContaining({ routes: 450, imports: 5000 }));
    expect(json['truncated']).toEqual(expect.arrayContaining(['routes']));
    expect(text.length).toBeLessThan(100_000);
  });

  it('counts the third-party imports rather than inlining them, like the import edges', async () => {
    const s = freshPlugin();
    const project = projectDir('surface-ext-');
    s.storage.surface.insert({
      project_path: project,
      tree_hash: 'h',
      snapshot: {
        routes: [route(1)], env_vars: [], ports: [], webhooks: [], coverage: [], tools_run: [],
        missing_tools: [], spec_files: [], spec_diff: null, imports: [],
        external_imports: Array.from({ length: 5000 }, (_, i) => ({
          file: `src/f${i}.ts`, specifier: `pkg-${i}`, language: 'typescript',
        })),
      },
    });
    vi.spyOn(process, 'cwd').mockReturnValue(project);
    const client = await connect(s.plugin);
    const { json, text } = await readJson(client, 'guardian://surface/latest');
    const snapshot = json['snapshot'] as { external_imports?: unknown[] };
    expect(snapshot.external_imports).toBeUndefined();
    expect(json['totals']).toEqual(expect.objectContaining({ external_imports: 5000 }));
    expect(text.length).toBeLessThan(100_000);
  });

  it("does not answer with another project's snapshot", async () => {
    const s = freshPlugin();
    const mine = projectDir('surface-a-');
    const theirs = projectDir('surface-b-');
    s.storage.surface.insert({
      project_path: theirs, tree_hash: 'h',
      snapshot: {
        routes: [route(1)], env_vars: [], ports: [], webhooks: [], coverage: [], tools_run: [],
        missing_tools: [], spec_files: [], spec_diff: null, imports: [],
      },
    });
    vi.spyOn(process, 'cwd').mockReturnValue(mine);
    const client = await connect(s.plugin);
    const { json } = await readJson(client, 'guardian://surface/latest');
    expect(json['snapshot']).toBeNull();
  });
});

describe('generate_sbom response size', () => {
  function fakeSyft(bytes: number): void {
    vi.mocked(scannerAvailable).mockImplementation(async (name: string) => (name === 'syft' ? 'syft' : null));
    vi.mocked(runProcess).mockImplementation(async (opts) => {
      const out = (opts.args ?? []).find((a) => a.startsWith('cyclonedx-json='));
      if (out !== undefined) {
        const components = [];
        let size = 0;
        for (let i = 0; size < bytes; i++) {
          const c = { name: `pkg-${i}`, version: '1.0.0', purl: `pkg:npm/pkg-${i}@1.0.0` };
          components.push(c);
          size += JSON.stringify(c).length + 1;
        }
        writeFileSync(out.slice('cyclonedx-json='.length), JSON.stringify({ bomFormat: 'CycloneDX', components }));
      }
      return { outcome: 'completed', exitCode: 0, stdout: '', stderr: '', truncated: false };
    });
  }

  it('does not inline a 100 KB SBOM by default (64 KB)', async () => {
    fakeSyft(100 * 1024);
    const s = freshPlugin();
    const project = projectDir('sbom-');
    const client = await connect(s.plugin);
    const res = await client.callTool({ name: 'generate_sbom', arguments: { project_path: project } });
    const structured = res.structuredContent as Record<string, unknown>;
    expect(structured['ok']).toBe(true);
    expect(structured['inline']).toBeUndefined();
    expect(structured['inlined']).toBe(false);
  });

  it('never sends the inlined document twice', async () => {
    fakeSyft(20 * 1024);
    const s = freshPlugin();
    const project = projectDir('sbom-');
    const client = await connect(s.plugin);
    const res = await client.callTool({ name: 'generate_sbom', arguments: { project_path: project } });
    const structured = res.structuredContent as Record<string, unknown>;
    expect(structured['inlined']).toBe(true);
    expect(structured['inline']).toBeUndefined();
    const text = (res.content as Array<{ type: string; text?: string }>)
      .map((c) => c.text ?? '')
      .join('');
    // Once — in the text the model reads — and nowhere else.
    expect(text.split('"bomFormat"').length - 1).toBe(1);
  });

  it('refuses inline_max_kb above 1 MB, and accepts exactly 1 MB', async () => {
    fakeSyft(1024);
    const s = freshPlugin();
    const project = projectDir('sbom-');
    const client = await connect(s.plugin);
    const over = await client.callTool({
      name: 'generate_sbom',
      arguments: { project_path: project, inline_max_kb: 2048 },
    });
    expect(over.isError).toBe(true);
    const max = await client.callTool({
      name: 'generate_sbom',
      arguments: { project_path: project, inline_max_kb: 1024 },
    });
    expect(max.isError).not.toBe(true);
  });
});
