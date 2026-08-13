import { describe, expect, it } from 'vitest';
import { GuardianDatabase as Database } from '../../../src/storage/db.js';
import { runMigrations } from '../../../src/storage/migrations/runner.js';
import { Storage } from '../../../src/storage/index.js';
import type { FindingValidation } from '../../../src/validate/types.js';

function makeStorage(): Storage {
  const db = new Database(':memory:');
  runMigrations(db);
  return new Storage(db);
}

function row(over: Partial<FindingValidation> = {}): FindingValidation {
  return {
    fingerprint: 'fp1',
    verdict: 'unknown',
    confidence: 'low',
    provider: 'static',
    evidence: [{ detail: 'nothing to say' }],
    coverage_gaps: [],
    snapshot_id: 1,
    tree_hash: 'tree-a',
    computed_at: '2026-08-13T00:00:00.000Z',
    ...over,
  };
}

describe('ValidationsRepo', () => {
  it('round-trips a validation, preserving evidence and gaps as structured data', () => {
    const s = makeStorage();
    s.validations.upsert('/proj', [
      row({ evidence: [{ detail: 'a' }, { detail: 'b' }], coverage_gaps: ['go: no_rules'] }),
    ]);
    const got = s.validations.getByFingerprint('/proj', 'fp1');
    expect(got?.evidence).toEqual([{ detail: 'a' }, { detail: 'b' }]);
    expect(got?.coverage_gaps).toEqual(['go: no_rules']);
    expect(got?.verdict).toBe('unknown');
  });

  it('replaces a verdict for the same (project, fingerprint, provider)', () => {
    // Guards the wrong implementation that INSERTs and leaves both rows: a
    // stale verdict surviving beside a fresh one is worse than no verdict.
    const s = makeStorage();
    s.validations.upsert('/proj', [row({ verdict: 'unknown', tree_hash: 'tree-a' })]);
    s.validations.upsert('/proj', [row({ verdict: 'unreachable', tree_hash: 'tree-b' })]);
    expect(s.validations.listByProject('/proj')).toHaveLength(1);
    const got = s.validations.getByFingerprint('/proj', 'fp1');
    expect(got?.verdict).toBe('unreachable');
    expect(got?.tree_hash).toBe('tree-b');
  });

  it('keeps verdicts from different providers side by side', () => {
    const s = makeStorage();
    s.validations.upsert('/proj', [row({ provider: 'static', verdict: 'reachable' })]);
    s.validations.upsert('/proj', [row({ provider: 'runtime', verdict: 'confirmed' })]);
    expect(s.validations.listByProject('/proj')).toHaveLength(2);
  });

  it('scopes rows by project_path', () => {
    const s = makeStorage();
    s.validations.upsert('/a', [row()]);
    expect(s.validations.listByProject('/b')).toEqual([]);
    expect(s.validations.getByFingerprint('/b', 'fp1')).toBeNull();
  });

  it('returns null for an unknown fingerprint rather than throwing', () => {
    expect(makeStorage().validations.getByFingerprint('/proj', 'nope')).toBeNull();
  });
});
