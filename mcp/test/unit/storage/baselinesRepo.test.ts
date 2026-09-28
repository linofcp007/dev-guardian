import { GuardianDatabase as Database } from '../../../src/storage/db.js';
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

describe('BaselinesRepo — per project, per scan type', () => {
  function twoProjects() {
    const db = new Database(':memory:');
    runMigrations(db);
    const scans = new ScansRepo(db);
    const baselines = new BaselinesRepo(db);
    scans.insert({ scan_id: 'a-sast', scan_type: 'sast', project_path: '/a', tree_hash: 'h' });
    scans.insert({ scan_id: 'a-secrets', scan_type: 'secrets', project_path: '/a', tree_hash: 'h' });
    scans.insert({ scan_id: 'b-sast', scan_type: 'sast', project_path: '/b', tree_hash: 'h' });
    return { baselines };
  }

  it("records the scan's project and type", () => {
    const { baselines } = twoProjects();
    const b = baselines.set({ scan_id: 'a-sast', note: 'n' });
    expect(b).toEqual(expect.objectContaining({ scan_id: 'a-sast', project_path: '/a', scan_type: 'sast', note: 'n' }));
  });

  it('answers for one project only, however recently another set one', () => {
    const { baselines } = twoProjects();
    baselines.set({ scan_id: 'a-sast' });
    baselines.set({ scan_id: 'b-sast' });
    expect(baselines.getActiveForProject('/a')?.scan_id).toBe('a-sast');
    expect(baselines.getActiveForProject('/b')?.scan_id).toBe('b-sast');
    expect(baselines.getActiveForProject('/c')).toBeNull();
  });

  it('narrows to one scan type when asked', () => {
    const { baselines } = twoProjects();
    baselines.set({ scan_id: 'a-sast' });
    baselines.set({ scan_id: 'a-secrets' });
    expect(baselines.getActiveForProject('/a')?.scan_id).toBe('a-secrets');
    expect(baselines.getActiveForProject('/a', 'sast')?.scan_id).toBe('a-sast');
    expect(baselines.getActiveForProject('/a', 'deps')).toBeNull();
  });
});
