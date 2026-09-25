import { describe, expect, it } from 'vitest';
import { extractMcpServers } from '../../../src/agentaudit/mcpServers.js';
import type { ConfigSource } from '../../../src/agentaudit/configSources.js';

function source(overrides: Partial<ConfigSource>): ConfigSource {
  return {
    label: '.mcp.json',
    kind: 'project',
    absolutePath: '/proj/.mcp.json',
    mcpServersField: 'mcpServers',
    exists: true,
    ...overrides,
  };
}

describe('extractMcpServers', () => {
  it('extracts entries under `mcpServers`', () => {
    const src = source({
      json: {
        mcpServers: {
          'dev-guardian': { command: 'node', args: ['mcp/dist/server.js'], env: {} },
        },
      },
    });
    const entries = extractMcpServers(src);
    expect(entries).toHaveLength(1);
    expect(entries[0]).toMatchObject({
      sourceLabel: '.mcp.json',
      name: 'dev-guardian',
      command: 'node',
      args: ['mcp/dist/server.js'],
    });
  });

  it('extracts entries under `servers` (VS Code shape)', () => {
    const src = source({
      label: '.vscode/mcp.json',
      mcpServersField: 'servers',
      json: { servers: { foo: { type: 'stdio', command: 'node', args: ['x.js'] } } },
    });
    const entries = extractMcpServers(src);
    expect(entries).toHaveLength(1);
    expect(entries[0]?.name).toBe('foo');
    expect(entries[0]?.type).toBe('stdio');
  });

  it('extracts a remote http/sse server entry (url, no command)', () => {
    const src = source({
      json: { mcpServers: { remote: { type: 'http', url: 'http://example.com/mcp' } } },
    });
    const entries = extractMcpServers(src);
    expect(entries[0]).toMatchObject({ name: 'remote', type: 'http', url: 'http://example.com/mcp' });
    expect(entries[0]?.command).toBeUndefined();
  });

  it('returns [] when mcpServersField is null', () => {
    const src = source({ mcpServersField: null, json: { mcpServers: { x: { command: 'node' } } } });
    expect(extractMcpServers(src)).toEqual([]);
  });

  it('returns [] when the file does not exist', () => {
    const src = source({ exists: false, json: undefined });
    expect(extractMcpServers(src)).toEqual([]);
  });

  it('returns [] when json has no mcpServers object', () => {
    expect(extractMcpServers(source({ json: {} }))).toEqual([]);
    expect(extractMcpServers(source({ json: { mcpServers: 'not-an-object' } }))).toEqual([]);
  });

  it('skips a non-object entry rather than throwing', () => {
    const src = source({ json: { mcpServers: { good: { command: 'node' }, bad: 'nope' } } });
    const entries = extractMcpServers(src);
    expect(entries.map((e) => e.name)).toEqual(['good']);
  });

  it('preserves the raw entry object for hashing', () => {
    const raw = { command: 'node', args: ['x.js'], env: { A: '1' } };
    const src = source({ json: { mcpServers: { srv: raw } } });
    const entries = extractMcpServers(src);
    expect(entries[0]?.raw).toEqual(raw);
  });
});
