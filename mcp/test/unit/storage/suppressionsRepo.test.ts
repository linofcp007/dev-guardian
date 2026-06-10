import { GuardianDatabase as Database } from '../../../src/storage/db.js';
import { describe, expect, it } from 'vitest';
import { runMigrations } from '../../../src/storage/migrations/runner.js';
import { SuppressionsRepo } from '../../../src/storage/suppressionsRepo.js';

function freshRepo() {
  const db = new Database(':memory:');
  runMigrations(db);
  return new SuppressionsRepo(db);
}

describe('SuppressionsRepo', () => {
  it('scopes a suppression to a single fingerprint', () => {
    const repo = freshRepo();
    repo.insert({ finding_fingerprint: 'abc', reason: 'fp' });
    expect(repo.isSuppressed('abc')).toBe(true);
    expect(repo.isSuppressed('def')).toBe(false);
  });

  it('treats expired suppressions as inactive', () => {
    const repo = freshRepo();
    repo.insert({
      finding_fingerprint: 'abc',
      reason: 'temp',
      expires_at: '2000-01-01T00:00:00.000Z',
    });
    expect(repo.isSuppressed('abc')).toBe(false);
  });

  it('keeps future-expiring suppressions active', () => {
    const repo = freshRepo();
    repo.insert({
      finding_fingerprint: 'abc',
      reason: 'snoozed',
      expires_at: '2999-01-01T00:00:00.000Z',
    });
    expect(repo.isSuppressed('abc')).toBe(true);
  });

  it('listActive omits expired rows', () => {
    const repo = freshRepo();
    repo.insert({ finding_fingerprint: 'forever', reason: 'fp' });
    repo.insert({
      finding_fingerprint: 'gone',
      reason: 'old',
      expires_at: '2000-01-01T00:00:00.000Z',
    });
    const active = repo.listActive().map((s) => s.finding_fingerprint);
    expect(active).toContain('forever');
    expect(active).not.toContain('gone');
  });
});
