import { describe, expect, it } from 'vitest';
import { GuardianDatabase } from '../../../src/storage/db.js';
import { Storage } from '../../../src/storage/index.js';
import { runMigrations } from '../../../src/storage/migrations/runner.js';

function fresh(): Storage {
  const db = new GuardianDatabase(':memory:');
  runMigrations(db);
  return new Storage(db);
}

describe('McpToolPinsRepo', () => {
  it('returns an empty map for a server with no pins', () => {
    const storage = fresh();
    expect(storage.mcpToolPins.getServerPins('/proj', '.mcp.json::srv')).toEqual(new Map());
    expect(storage.mcpToolPins.hasServer('/proj', '.mcp.json::srv')).toBe(false);
  });

  it('round-trips the pins of one server', () => {
    const storage = fresh();
    storage.mcpToolPins.replaceServerPins('/proj', '.mcp.json::srv', [
      { tool_name: 'read', hash: 'a' },
      { tool_name: 'write', hash: 'b' },
    ]);
    const pins = storage.mcpToolPins.getServerPins('/proj', '.mcp.json::srv');
    expect(pins).toEqual(
      new Map([
        ['read', 'a'],
        ['write', 'b'],
      ]),
    );
    expect(storage.mcpToolPins.hasServer('/proj', '.mcp.json::srv')).toBe(true);
  });

  it('replaces the set: a changed hash is updated and a tool no longer listed is dropped', () => {
    const storage = fresh();
    storage.mcpToolPins.replaceServerPins('/proj', 's', [
      { tool_name: 'read', hash: 'a' },
      { tool_name: 'gone', hash: 'g' },
    ]);
    storage.mcpToolPins.replaceServerPins('/proj', 's', [
      { tool_name: 'read', hash: 'a2' },
      { tool_name: 'new', hash: 'n' },
    ]);
    expect(storage.mcpToolPins.getServerPins('/proj', 's')).toEqual(
      new Map([
        ['new', 'n'],
        ['read', 'a2'],
      ]),
    );
  });

  // A server that answered with no tools at all was still audited: the
  // next audit must compare against "nothing", not treat itself as the first.
  it('remembers a server that was audited with zero tools', () => {
    const storage = fresh();
    storage.mcpToolPins.replaceServerPins('/proj', 's', []);
    expect(storage.mcpToolPins.hasServer('/proj', 's')).toBe(true);
    expect(storage.mcpToolPins.getServerPins('/proj', 's')).toEqual(new Map());
  });

  it('keeps servers and projects apart', () => {
    const storage = fresh();
    storage.mcpToolPins.replaceServerPins('/a', 's1', [{ tool_name: 't', hash: '1' }]);
    storage.mcpToolPins.replaceServerPins('/a', 's2', [{ tool_name: 't', hash: '2' }]);
    storage.mcpToolPins.replaceServerPins('/b', 's1', [{ tool_name: 't', hash: '3' }]);
    storage.mcpToolPins.replaceServerPins('/a', 's1', []);
    expect(storage.mcpToolPins.getServerPins('/a', 's2').get('t')).toBe('2');
    expect(storage.mcpToolPins.getServerPins('/b', 's1').get('t')).toBe('3');
    expect(storage.mcpToolPins.getServerPins('/a', 's1').size).toBe(0);
  });

  it('lists every pinned tool name of a project with its server', () => {
    const storage = fresh();
    storage.mcpToolPins.replaceServerPins('/a', 's1', [{ tool_name: 'send_email', hash: '1' }]);
    storage.mcpToolPins.replaceServerPins('/a', 's2', [{ tool_name: 'read_file', hash: '2' }]);
    storage.mcpToolPins.replaceServerPins('/b', 's3', [{ tool_name: 'other', hash: '3' }]);
    expect(storage.mcpToolPins.listToolNames('/a')).toEqual([
      { server_key: 's1', tool_name: 'send_email' },
      { server_key: 's2', tool_name: 'read_file' },
    ]);
  });
});
