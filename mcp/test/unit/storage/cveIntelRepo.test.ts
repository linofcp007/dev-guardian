import { describe, expect, it } from 'vitest';
import { CveIntelRepo, type UpsertCveIntelInput } from '../../../src/storage/cveIntelRepo.js';
import { GuardianDatabase } from '../../../src/storage/db.js';
import { runMigrations } from '../../../src/storage/migrations/runner.js';

function fresh(): CveIntelRepo {
  const db = new GuardianDatabase(':memory:');
  runMigrations(db);
  return new CveIntelRepo(db);
}

function row(cveId: string, extra: Partial<UpsertCveIntelInput> = {}): UpsertCveIntelInput {
  return { cve_id: cveId, kev: false, fetched_at: '2026-09-25T00:00:00.000Z', ...extra };
}

describe('CveIntelRepo', () => {
  it('returns nothing for a CVE that was never cached', () => {
    const repo = fresh();
    expect(repo.getMany(['CVE-NEVER'])).toEqual(new Map());
  });

  it('round-trips a KEV-listed CVE with an EPSS score', () => {
    const repo = fresh();
    repo.upsertMany([
      row('CVE-KEV-1', { kev: true, kev_date_added: '2026-01-01', epss_score: 0.97, epss_percentile: 0.99 }),
    ]);
    const got = repo.getMany(['CVE-KEV-1']);
    expect(got.get('CVE-KEV-1')).toEqual({
      cve_id: 'CVE-KEV-1',
      kev: true,
      kev_date_added: '2026-01-01',
      epss_score: 0.97,
      epss_percentile: 0.99,
      fetched_at: '2026-09-25T00:00:00.000Z',
    });
  });

  it('round-trips a non-KEV CVE with no EPSS score as null, not a missing row', () => {
    const repo = fresh();
    repo.upsertMany([row('CVE-UNSCORED')]);
    const got = repo.getMany(['CVE-UNSCORED']);
    expect(got.get('CVE-UNSCORED')).toEqual({
      cve_id: 'CVE-UNSCORED',
      kev: false,
      kev_date_added: null,
      epss_score: null,
      epss_percentile: null,
      fetched_at: '2026-09-25T00:00:00.000Z',
    });
  });

  it('upsert replaces the same cve_id in place rather than accumulating rows', () => {
    const repo = fresh();
    repo.upsertMany([row('CVE-X', { epss_score: 0.1, fetched_at: '2026-09-01T00:00:00.000Z' })]);
    repo.upsertMany([row('CVE-X', { kev: true, epss_score: 0.9, fetched_at: '2026-09-25T00:00:00.000Z' })]);
    const got = repo.getMany(['CVE-X']);
    expect(got.size).toBe(1);
    expect(got.get('CVE-X')).toMatchObject({ kev: true, epss_score: 0.9, fetched_at: '2026-09-25T00:00:00.000Z' });
  });

  it('getMany returns only the requested, cached CVEs — a mixed hit/miss batch', () => {
    const repo = fresh();
    repo.upsertMany([row('CVE-A'), row('CVE-B', { kev: true })]);
    const got = repo.getMany(['CVE-A', 'CVE-MISSING', 'CVE-B']);
    expect([...got.keys()].sort()).toEqual(['CVE-A', 'CVE-B']);
  });

  it('getMany([]) returns an empty map without querying', () => {
    const repo = fresh();
    expect(repo.getMany([])).toEqual(new Map());
  });

  it('upsertMany([]) is a no-op', () => {
    const repo = fresh();
    expect(() => repo.upsertMany([])).not.toThrow();
  });
});
