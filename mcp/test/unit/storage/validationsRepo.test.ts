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

  it('downgrades to unknown/low, naming the column, when evidence is not valid JSON', () => {
    // coverage_gaps: [] means "nothing was missing" (see FindingValidation's
    // doc comment) — so a wrong implementation that falls back to [] here
    // would report a damaged row as the most reassuring possible answer.
    // Guards against reading back the STORED verdict/confidence too: a
    // damaged row's own claims about itself are exactly what can't be
    // trusted.
    const s = makeStorage();
    s.rawHandle()
      .prepare(
        `INSERT INTO finding_validations
         (project_path, fingerprint, provider, verdict, confidence, evidence, coverage_gaps, snapshot_id, tree_hash, computed_at)
         VALUES ('/proj', 'fp1', 'static', 'unreachable', 'high', 'not valid json', '[]', 1, 'tree-a', '2026-08-13T00:00:00.000Z')`,
      )
      .run();

    const got = s.validations.getByFingerprint('/proj', 'fp1');
    expect(got?.verdict).toBe('unknown');
    expect(got?.confidence).toBe('low');
    expect(got?.coverage_gaps).toEqual(['stored verdict could not be read: evidence was not valid JSON']);
  });

  it('downgrades to unknown/low, naming the column, when coverage_gaps is not valid JSON', () => {
    // Sibling of the evidence test above — a fix that only checks `evidence`
    // would pass that test while this column still fails open.
    const s = makeStorage();
    s.rawHandle()
      .prepare(
        `INSERT INTO finding_validations
         (project_path, fingerprint, provider, verdict, confidence, evidence, coverage_gaps, snapshot_id, tree_hash, computed_at)
         VALUES ('/proj', 'fp1', 'static', 'unreachable', 'high', '[]', 'not valid json', 1, 'tree-a', '2026-08-13T00:00:00.000Z')`,
      )
      .run();

    const got = s.validations.getByFingerprint('/proj', 'fp1');
    expect(got?.verdict).toBe('unknown');
    expect(got?.confidence).toBe('low');
    expect(got?.coverage_gaps).toEqual([
      'stored verdict could not be read: coverage_gaps was not valid JSON',
    ]);
  });
});
