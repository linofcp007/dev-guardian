import { GuardianDatabase as Database } from '../../../src/storage/db.js';
import { describe, expect, it } from 'vitest';
import { FindingsRepo } from '../../../src/storage/findingsRepo.js';
import { runMigrations } from '../../../src/storage/migrations/runner.js';
import { ScansRepo } from '../../../src/storage/scansRepo.js';
import { SuppressionsRepo } from '../../../src/storage/suppressionsRepo.js';
import type { Finding } from '../../../src/types.js';

function makeFinding(overrides: Partial<Finding> & { fingerprint: string }): Finding {
  return {
    tool: 'semgrep',
    severity: 'medium',
    category: 'security',
    title: 'Some rule',
    fix_available: false,
    ...overrides,
  };
}

function setup() {
  const db = new Database(':memory:');
  runMigrations(db);
  const scans = new ScansRepo(db);
  const findings = new FindingsRepo(db);
  const suppressions = new SuppressionsRepo(db);
  return { db, scans, findings, suppressions };
}

describe('FindingsRepo', () => {
  it('bulk inserts findings and returns the count', () => {
    const { scans, findings } = setup();
    scans.insert({
      scan_id: 's1',
      scan_type: 'sast',
      project_path: '/p',
      tree_hash: 'h',
    });
    const inserted = findings.bulkInsert([
      { ...makeFinding({ fingerprint: 'a' }), scan_id: 's1' },
      { ...makeFinding({ fingerprint: 'b', severity: 'critical' }), scan_id: 's1' },
    ]);
    expect(inserted).toBe(2);
    expect(findings.listByScan('s1')).toHaveLength(2);
  });

  it('counts by severity returns a record with every severity slot', () => {
    const { scans, findings } = setup();
    scans.insert({ scan_id: 's1', scan_type: 'sast', project_path: '/p', tree_hash: 'h' });
    findings.bulkInsert([
      { ...makeFinding({ fingerprint: 'a', severity: 'critical' }), scan_id: 's1' },
      { ...makeFinding({ fingerprint: 'b', severity: 'critical' }), scan_id: 's1' },
      { ...makeFinding({ fingerprint: 'c', severity: 'low' }), scan_id: 's1' },
    ]);
    const counts = findings.countBySeverity('s1');
    expect(counts).toEqual({ info: 0, low: 1, medium: 0, high: 0, critical: 2 });
  });

  it('topFindings sorts by severity descending then by fingerprint', () => {
    const { scans, findings } = setup();
    scans.insert({ scan_id: 's1', scan_type: 'sast', project_path: '/p', tree_hash: 'h' });
    findings.bulkInsert([
      { ...makeFinding({ fingerprint: 'aa', severity: 'low' }), scan_id: 's1' },
      { ...makeFinding({ fingerprint: 'bb', severity: 'critical' }), scan_id: 's1' },
      { ...makeFinding({ fingerprint: 'cc', severity: 'high' }), scan_id: 's1' },
      { ...makeFinding({ fingerprint: 'ab', severity: 'critical' }), scan_id: 's1' },
    ]);
    const top = findings.topFindings('s1', 10);
    expect(top.map((f) => f.fingerprint)).toEqual(['ab', 'bb', 'cc', 'aa']);
  });

  it('listOpen excludes active suppressions but keeps expired ones', () => {
    const { scans, findings, suppressions } = setup();
    scans.insert({ scan_id: 's1', scan_type: 'sast', project_path: '/p', tree_hash: 'h' });
    findings.bulkInsert([
      { ...makeFinding({ fingerprint: 'shown' }), scan_id: 's1' },
      { ...makeFinding({ fingerprint: 'hidden' }), scan_id: 's1' },
      { ...makeFinding({ fingerprint: 'expired' }), scan_id: 's1' },
    ]);
    scans.finalize({ scan_id: 's1', status: 'completed', tools_run: [], missing_tools: [] });

    suppressions.insert({ finding_fingerprint: 'hidden', reason: 'fp' });
    suppressions.insert({
      finding_fingerprint: 'expired',
      reason: 'fp',
      expires_at: '2000-01-01T00:00:00.000Z',
    });

    const open = findings.listOpen().map((f) => f.fingerprint);
    expect(open).toContain('shown');
    expect(open).toContain('expired');
    expect(open).not.toContain('hidden');
  });

  it('listOpenForProject ignores a newer completed scan belonging to another project', () => {
    // listOpen() selects the latest completed scan across the WHOLE
    // database, no project filter — correct for a caller with no project in
    // scope, wrong for one that resolved a specific projectPath and must not
    // read another project's findings just because that project's scan
    // happened to complete more recently.
    const { scans, findings } = setup();
    scans.insert({ scan_id: 'a1', scan_type: 'sast', project_path: '/project-a', tree_hash: 'ha' });
    findings.bulkInsert([{ ...makeFinding({ fingerprint: 'a-finding' }), scan_id: 'a1' }]);
    scans.finalize({ scan_id: 'a1', status: 'completed', tools_run: [], missing_tools: [] });

    // Inserted second, so it wins listOpen()'s unscoped `started_at DESC,
    // rowid DESC` ordering — the "newer, belongs to project B" case.
    scans.insert({ scan_id: 'b1', scan_type: 'sast', project_path: '/project-b', tree_hash: 'hb' });
    findings.bulkInsert([{ ...makeFinding({ fingerprint: 'b-finding' }), scan_id: 'b1' }]);
    scans.finalize({ scan_id: 'b1', status: 'completed', tools_run: [], missing_tools: [] });

    // listOpen() must NOT move for the callers that keep it: still answers
    // with project B's finding, the newer scan, from ANY project.
    expect(findings.listOpen().map((f) => f.fingerprint)).toEqual(['b-finding']);

    expect(findings.listOpenForProject('/project-a').map((f) => f.fingerprint)).toEqual([
      'a-finding',
    ]);
    expect(findings.listOpenForProject('/project-b').map((f) => f.fingerprint)).toEqual([
      'b-finding',
    ]);
  });

  it('listOpenForProject returns nothing for a project whose only scan belongs to someone else', () => {
    const { scans, findings } = setup();
    scans.insert({ scan_id: 's1', scan_type: 'sast', project_path: '/theirs', tree_hash: 'h' });
    findings.bulkInsert([{ ...makeFinding({ fingerprint: 'theirs' }), scan_id: 's1' }]);
    scans.finalize({ scan_id: 's1', status: 'completed', tools_run: [], missing_tools: [] });

    expect(findings.listOpenForProject('/mine')).toEqual([]);
  });

  it('listBySeverity uses the latest completed scan only', () => {
    const { scans, findings } = setup();
    scans.insert({ scan_id: 'older', scan_type: 'sast', project_path: '/p', tree_hash: 'h1' });
    findings.bulkInsert([
      { ...makeFinding({ fingerprint: 'old-crit', severity: 'critical' }), scan_id: 'older' },
    ]);
    scans.finalize({ scan_id: 'older', status: 'completed', tools_run: [], missing_tools: [] });

    scans.insert({ scan_id: 'newer', scan_type: 'sast', project_path: '/p', tree_hash: 'h2' });
    findings.bulkInsert([
      { ...makeFinding({ fingerprint: 'new-crit', severity: 'critical' }), scan_id: 'newer' },
      { ...makeFinding({ fingerprint: 'new-low', severity: 'low' }), scan_id: 'newer' },
    ]);
    scans.finalize({ scan_id: 'newer', status: 'completed', tools_run: [], missing_tools: [] });

    const crits = findings.listBySeverity('critical').map((f) => f.fingerprint);
    expect(crits).toEqual(['new-crit']);
    expect(crits).not.toContain('old-crit');
  });

  // --- task-7-review.md I3 ---------------------------------------------
  //
  // create_fix_pr re-runs a scanner inside a disposable worktree
  // (project_path starting with 'guardian-fixpr-wt-') to verify a fix. That
  // scan is real and completed, so without this exclusion it would win
  // listOpen()/listBySeverity()'s unscoped "latest" ordering the moment it
  // finishes — reporting a false all-clear for a directory that no longer
  // exists, while the real project's findings sit untouched and unreported.

  it('listOpen ignores a create_fix_pr worktree re-scan, even though it completed more recently', () => {
    const { scans, findings } = setup();
    scans.insert({ scan_id: 'real', scan_type: 'sast', project_path: '/real-project', tree_hash: 'h1' });
    findings.bulkInsert([
      { ...makeFinding({ fingerprint: 'real-finding' }), scan_id: 'real' },
    ]);
    scans.finalize({ scan_id: 'real', status: 'completed', tools_run: [], missing_tools: [] });

    // Inserted (and completed) SECOND, so it would win the unscoped
    // `started_at DESC, rowid DESC` ordering if not excluded by name.
    scans.insert({
      scan_id: 'verify',
      scan_type: 'sast',
      project_path: '/tmp/guardian-fixpr-wt-AbC123',
      tree_hash: 'h2',
    });
    findings.bulkInsert([
      { ...makeFinding({ fingerprint: 'worktree-finding' }), scan_id: 'verify' },
    ]);
    scans.finalize({ scan_id: 'verify', status: 'completed', tools_run: [], missing_tools: [] });

    const open = findings.listOpen().map((f) => f.fingerprint);
    expect(open).toEqual(['real-finding']);
    expect(open).not.toContain('worktree-finding');
  });

  it('listBySeverity ignores a create_fix_pr worktree re-scan the same way', () => {
    const { scans, findings } = setup();
    scans.insert({ scan_id: 'real', scan_type: 'sast', project_path: '/real-project', tree_hash: 'h1' });
    findings.bulkInsert([
      { ...makeFinding({ fingerprint: 'real-crit', severity: 'critical' }), scan_id: 'real' },
    ]);
    scans.finalize({ scan_id: 'real', status: 'completed', tools_run: [], missing_tools: [] });

    scans.insert({
      scan_id: 'verify',
      scan_type: 'deps',
      project_path: '/tmp/guardian-fixpr-wt-XyZ789',
      tree_hash: 'h2',
    });
    findings.bulkInsert([
      { ...makeFinding({ fingerprint: 'worktree-crit', severity: 'critical' }), scan_id: 'verify' },
    ]);
    scans.finalize({ scan_id: 'verify', status: 'completed', tools_run: [], missing_tools: [] });

    const crits = findings.listBySeverity('critical').map((f) => f.fingerprint);
    expect(crits).toEqual(['real-crit']);
    expect(crits).not.toContain('worktree-crit');
  });
});
