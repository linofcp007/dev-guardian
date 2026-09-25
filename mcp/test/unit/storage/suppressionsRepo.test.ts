import { GuardianDatabase as Database } from '../../../src/storage/db.js';
import { describe, expect, it } from 'vitest';
import { FindingsRepo } from '../../../src/storage/findingsRepo.js';
import { runMigrations } from '../../../src/storage/migrations/runner.js';
import { ScansRepo } from '../../../src/storage/scansRepo.js';
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

  it('matches a finding by identity too, so a line shift (new fingerprint) does not lapse it', () => {
    const repo = freshRepo();
    repo.insert({ finding_fingerprint: 'at-line-10', finding_identity: 'id-1', reason: 'fp' });
    expect(repo.isSuppressed('at-line-11', 'id-1')).toBe(true);
    expect(repo.isSuppressed('at-line-11', 'id-2')).toBe(false);
    expect(repo.isSuppressed('at-line-10')).toBe(true);
    expect(repo.listActive()[0]?.finding_identity).toBe('id-1');
  });

  it('never matches two missing identities to each other', () => {
    const repo = freshRepo();
    repo.insert({ finding_fingerprint: 'abc', reason: 'fp' }); // a 2.0.x suppression
    expect(repo.isSuppressed('other')).toBe(false);
    expect(repo.listActive()[0]?.finding_identity).toBeUndefined();
  });

  it('round-trips project_path (migration 011); omitted stays undefined, not the literal string "null"', () => {
    const repo = freshRepo();
    repo.insert({ finding_fingerprint: 'scoped', reason: 'fp', project_path: '/my-project' });
    repo.insert({ finding_fingerprint: 'legacy', reason: 'no project given' });

    const byFp = new Map(repo.listAll().map((s) => [s.finding_fingerprint, s]));
    expect(byFp.get('scoped')?.project_path).toBe('/my-project');
    expect(byFp.get('legacy')?.project_path).toBeUndefined();
  });

  it('listAll returns every row regardless of expiry, unlike listActive', () => {
    const repo = freshRepo();
    repo.insert({ finding_fingerprint: 'forever', reason: 'fp' });
    repo.insert({
      finding_fingerprint: 'gone',
      reason: 'old',
      expires_at: '2000-01-01T00:00:00.000Z',
    });
    const all = repo.listAll().map((s) => s.finding_fingerprint);
    expect(all).toContain('forever');
    expect(all).toContain('gone'); // the whole point: listActive() would drop this
    expect(repo.listActive().map((s) => s.finding_fingerprint)).not.toContain('gone');
  });
});

describe('SuppressionsRepo.adoptIdentities', () => {
  function withScan() {
    const db = new Database(':memory:');
    runMigrations(db);
    const scans = new ScansRepo(db);
    const findings = new FindingsRepo(db);
    const suppressions = new SuppressionsRepo(db);
    scans.insert({ scan_id: 's1', scan_type: 'sast', project_path: '/p', tree_hash: 'h' });
    const base = { tool: 't', severity: 'high' as const, category: 'security' as const, title: 't', fix_available: false };
    findings.bulkInsert([
      { ...base, fingerprint: 'fp-a', identity: 'id-a', content_key: 'c', scan_id: 's1' },
      { ...base, fingerprint: 'fp-legacy', scan_id: 's1' },
    ]);
    return { suppressions };
  }

  it('gives a fingerprint-only suppression the identity the scan reported for that fingerprint, once', () => {
    const { suppressions } = withScan();
    suppressions.insert({ finding_fingerprint: 'fp-a', reason: 'from 2.0.x' });
    suppressions.insert({ finding_fingerprint: 'fp-legacy', reason: 'no identity to adopt' });
    suppressions.insert({ finding_fingerprint: 'fp-a', finding_identity: 'id-kept', reason: 'already has one' });

    expect(suppressions.adoptIdentities('s1')).toBe(1);
    const byReason = new Map(suppressions.listAll().map((s) => [s.reason, s.finding_identity]));
    expect(byReason.get('from 2.0.x')).toBe('id-a');
    expect(byReason.get('no identity to adopt')).toBeUndefined();
    expect(byReason.get('already has one')).toBe('id-kept');

    // From now on it follows the finding across a line shift.
    expect(suppressions.isSuppressed('fp-a-shifted', 'id-a')).toBe(true);
    expect(suppressions.adoptIdentities('s1')).toBe(0);
  });

  // Coordinator fix round 2: adoptIdentities had no project predicate at
  // all, so a suppression scoped to a DIFFERENT project than the scan doing
  // the adopting could pick up that scan's identity for its own fingerprint
  // — attributing an identity computed in one project to a suppression that
  // belongs to another.
  it('does not adopt an identity onto a suppression scoped to a different project', () => {
    const { suppressions } = withScan();
    suppressions.insert({
      finding_fingerprint: 'fp-a',
      reason: 'belongs to a different project',
      project_path: '/other',
    });

    expect(suppressions.adoptIdentities('s1')).toBe(0);
    expect(suppressions.listAll()[0]?.finding_identity).toBeUndefined();
  });

  it('still adopts across a NULL (legacy/unscoped) suppression, and onto one scoped to the scan\'s own project', () => {
    const { suppressions } = withScan();
    suppressions.insert({ finding_fingerprint: 'fp-a', reason: 'legacy, no project' });
    suppressions.insert({ finding_fingerprint: 'fp-a', reason: 'scoped to the scan\'s own project', project_path: '/p' });

    expect(suppressions.adoptIdentities('s1')).toBe(2);
    const byReason = new Map(suppressions.listAll().map((s) => [s.reason, s.finding_identity]));
    expect(byReason.get('legacy, no project')).toBe('id-a');
    expect(byReason.get("scoped to the scan's own project")).toBe('id-a');
  });
});

describe('SuppressionsRepo.listActiveForRule', () => {
  function withFindingsInTwoProjects() {
    const db = new Database(':memory:');
    runMigrations(db);
    const scans = new ScansRepo(db);
    const findings = new FindingsRepo(db);
    const suppressions = new SuppressionsRepo(db);
    scans.insert({ scan_id: 'p1', scan_type: 'sast', project_path: '/p', tree_hash: 'h' });
    scans.insert({ scan_id: 'o1', scan_type: 'sast', project_path: '/other', tree_hash: 'h' });
    const base = {
      tool: 'semgrep',
      rule_id: 'r1',
      severity: 'high' as const,
      category: 'security' as const,
      title: 't',
      fix_available: false,
    };
    findings.bulkInsert([
      { ...base, fingerprint: 'fp-p', scan_id: 'p1' },
      { ...base, fingerprint: 'fp-o', scan_id: 'o1' },
    ]);
    return { suppressions };
  }

  // Coordinator fix round 2: this fed suggest_fix's "similar findings were
  // suppressed before" hint with every project's history, not just this
  // project's own.
  it("lists a suppression scoped to the given project, or scoped to none, but not another project's", () => {
    const { suppressions } = withFindingsInTwoProjects();
    suppressions.insert({ finding_fingerprint: 'fp-p', reason: 'mine', project_path: '/p' });
    suppressions.insert({ finding_fingerprint: 'fp-o', reason: 'theirs', project_path: '/other' });
    suppressions.insert({ finding_fingerprint: 'fp-p', reason: 'legacy, no project' });

    const reasons = suppressions
      .listActiveForRule('semgrep', 'r1', 20, '/p')
      .map((s) => s.reason)
      .sort();
    expect(reasons).toEqual(['legacy, no project', 'mine']);
  });
});
