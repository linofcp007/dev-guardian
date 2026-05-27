import Database from 'better-sqlite3';
import { describe, expect, it } from 'vitest';
import { BaselinesRepo } from '../../../src/storage/baselinesRepo.js';
import { runMigrations } from '../../../src/storage/migrations/runner.js';
import { ScansRepo } from '../../../src/storage/scansRepo.js';

function setup() {
  const db = new Database(':memory:');
  runMigrations(db);
  const scans = new ScansRepo(db);
  const baselines = new BaselinesRepo(db);
  // Seed two scans so foreign keys are happy.
  scans.insert({ scan_id: 's1', scan_type: 'audit', project_path: '/p', tree_hash: 'h' });
  scans.insert({ scan_id: 's2', scan_type: 'audit', project_path: '/p', tree_hash: 'h' });
  return { baselines };
}

describe('BaselinesRepo', () => {
  it('returns null when no baseline is set yet', () => {
    const { baselines } = setup();
    expect(baselines.getActive()).toBeNull();
  });

  it('treats the latest insert as the active baseline (history is kept)', () => {
    const { baselines } = setup();
    baselines.set({ scan_id: 's1', note: 'first' });
    baselines.set({ scan_id: 's2', note: 'second' });

    expect(baselines.getActive()?.scan_id).toBe('s2');
    expect(baselines.listAll().map((b) => b.scan_id)).toEqual(['s2', 's1']);
  });
});
