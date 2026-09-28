import { describe, expect, it } from 'vitest';
import { GuardianDatabase } from '../../../src/storage/db.js';
import { Storage } from '../../../src/storage/index.js';
import { runMigrations } from '../../../src/storage/migrations/runner.js';

function fresh(): Storage {
  const db = new GuardianDatabase(':memory:');
  runMigrations(db);
  return new Storage(db);
}

describe('AgentAuditRepo', () => {
  it('returns an empty map for a project with no recorded hashes', () => {
    const storage = fresh();
    expect(storage.agentAudit.getHashes('/proj')).toEqual(new Map());
  });

  it('round-trips hashes written by upsertHashes', () => {
    const storage = fresh();
    storage.agentAudit.upsertHashes('/proj', [
      { entry_key: '.mcp.json::dev-guardian', hash: 'aaa' },
      { entry_key: '.cursor/mcp.json::dev-guardian', hash: 'bbb' },
    ]);
    const hashes = storage.agentAudit.getHashes('/proj');
    expect(hashes.get('.mcp.json::dev-guardian')).toBe('aaa');
    expect(hashes.get('.cursor/mcp.json::dev-guardian')).toBe('bbb');
    expect(hashes.size).toBe(2);
  });

  it('overwrites the hash on a second upsert for the same entry_key', () => {
    const storage = fresh();
    storage.agentAudit.upsertHashes('/proj', [{ entry_key: '.mcp.json::x', hash: 'old' }]);
    storage.agentAudit.upsertHashes('/proj', [{ entry_key: '.mcp.json::x', hash: 'new' }]);
    const hashes = storage.agentAudit.getHashes('/proj');
    expect(hashes.get('.mcp.json::x')).toBe('new');
    expect(hashes.size).toBe(1);
  });

  it('keeps hashes for different projects apart', () => {
    const storage = fresh();
    storage.agentAudit.upsertHashes('/proj-a', [{ entry_key: 'k', hash: 'a' }]);
    storage.agentAudit.upsertHashes('/proj-b', [{ entry_key: 'k', hash: 'b' }]);
    expect(storage.agentAudit.getHashes('/proj-a').get('k')).toBe('a');
    expect(storage.agentAudit.getHashes('/proj-b').get('k')).toBe('b');
  });

  it('upsertHashes([]) is a no-op', () => {
    const storage = fresh();
    expect(() => storage.agentAudit.upsertHashes('/proj', [])).not.toThrow();
    expect(storage.agentAudit.getHashes('/proj').size).toBe(0);
  });
});
