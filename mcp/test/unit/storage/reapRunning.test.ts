import { GuardianDatabase as Database } from '../../../src/storage/db.js';
import { describe, expect, it } from 'vitest';
import { runMigrations } from '../../../src/storage/migrations/runner.js';
import { ScansRepo } from '../../../src/storage/scansRepo.js';

describe('reapRunning (simulated server restart)', () => {
  it('flips orphaned running scans to failed across a connection cycle', () => {
    const path = ':memory:';
    const db1 = new Database(path);
    runMigrations(db1);

    const repo1 = new ScansRepo(db1);
    repo1.insert({
      scan_id: 'will-orphan',
      scan_type: 'sast',
      project_path: '/p',
      tree_hash: 'h',
    });
    expect(repo1.getById('will-orphan')?.status).toBe('running');

    // Simulate a new server boot reusing the same connection (in-memory
    // databases vanish when the connection closes, so we keep db1 alive but
    // construct a new repo to mimic a fresh process discovering old state).
    const repo2 = new ScansRepo(db1);
    const reaped = repo2.reapRunning();
    expect(reaped).toBe(1);
    expect(repo2.getById('will-orphan')?.status).toBe('failed');
  });
});
