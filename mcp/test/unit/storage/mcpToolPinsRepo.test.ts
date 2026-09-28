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
      { key: 'read', hash: 'a' },
      { key: 'write', hash: 'b' },
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
      { key: 'read', hash: 'a' },
      { key: 'gone', hash: 'g' },
    ]);
    storage.mcpToolPins.replaceServerPins('/proj', 's', [
      { key: 'read', hash: 'a2' },
      { key: 'new', hash: 'n' },
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
    storage.mcpToolPins.replaceServerPins('/a', 's1', [{ key: 't', hash: '1' }]);
    storage.mcpToolPins.replaceServerPins('/a', 's2', [{ key: 't', hash: '2' }]);
    storage.mcpToolPins.replaceServerPins('/b', 's1', [{ key: 't', hash: '3' }]);
    storage.mcpToolPins.replaceServerPins('/a', 's1', []);
    expect(storage.mcpToolPins.getServerPins('/a', 's2').get('t')).toBe('2');
    expect(storage.mcpToolPins.getServerPins('/b', 's1').get('t')).toBe('3');
    expect(storage.mcpToolPins.getServerPins('/a', 's1').size).toBe(0);
  });

  // A tombstone (`-` + hash) is a tool no longer served: kept for the next
  // comparison, but not a name another server's description can shadow.
  it('keeps tombstones as pins but leaves them out of the listed keys', () => {
    const storage = fresh();
    storage.mcpToolPins.replaceServerPins('/a', 's1', [
      { key: 'live_tool', hash: 'v3:1' },
      { key: 'gone_tool', hash: '-v3:2' },
    ]);
    expect(storage.mcpToolPins.getServerPins('/a', 's1').get('gone_tool')).toBe('-v3:2');
    expect(storage.mcpToolPins.listPinKeys('/a')).toEqual([{ server_key: 's1', key: 'live_tool' }]);
  });

  it('lists every pinned key of a project with its server', () => {
    const storage = fresh();
    storage.mcpToolPins.replaceServerPins('/a', 's1', [{ key: 'send_email', hash: '1' }]);
    storage.mcpToolPins.replaceServerPins('/a', 's2', [{ key: 'read_file', hash: '2' }]);
    storage.mcpToolPins.replaceServerPins('/b', 's3', [{ key: 'other', hash: '3' }]);
    expect(storage.mcpToolPins.listPinKeys('/a')).toEqual([
      { server_key: 's1', key: 'send_email' },
      { server_key: 's2', key: 'read_file' },
    ]);
  });
});
