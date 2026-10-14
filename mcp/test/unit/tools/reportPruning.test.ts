/**
 * `.guardian/reports/` keeps the newest report directories of each kind
 * (review 8, finding 14 and C5): nothing pruned them — a toy project held 29
 * after about 8 scans, a mid-size one 4.3 MB after 3 CI runs, all untracked.
 */
import { existsSync, mkdirSync, readdirSync, symlinkSync, utimesSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, afterEach, describe, expect, it, vi } from 'vitest';
import { DEFAULT_KEPT_REPORTS, ensureReportDir } from '../../../src/tools/scanHelpers.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

// Review 11: when `.guardian/reports` is a link or not a directory, a scan's
// reports go to a fresh `guardian-reports-<kind>-…` in the temp directory —
// and nothing ever removed those (a review run left 15).
describe('the temp directory fallback is pruned like the project folder', () => {
  it(`keeps the ${DEFAULT_KEPT_REPORTS} newest of its kind, and no other kind`, () => {
    const temp = makeTempDir('reports-fallback-tmp-');
    for (const name of ['TMPDIR', 'TMP', 'TEMP']) vi.stubEnv(name, temp);
    vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    try {
      const project = makeTempDir('reports-fallback-');
      mkdirSync(join(project, '.guardian'));
      writeFileSync(join(project, '.guardian', 'reports'), 'not a directory');
      const old = (name: string, ageS: number): void => {
        mkdirSync(join(temp, name));
        const at = new Date(Date.now() - ageS * 1000);
        utimesSync(join(temp, name), at, at);
      };
      for (let i = 1; i <= 4; i++) {
        old(`guardian-reports-deps-old00${i}`, 100 * i);
        old(`guardian-reports-depsaudit-old00${i}`, 100 * i);
        old(`guardian-reports-dast-old00${i}`, 100 * i);
      }
      const made = ensureReportDir(project, 'abcdef0123456789', 'deps');
      expect(made.startsWith(join(temp, 'guardian-reports-deps-'))).toBe(true);
      const left = readdirSync(temp).sort();
      expect(left.filter((n) => n.startsWith('guardian-reports-deps-'))).toEqual(
        ['guardian-reports-deps-old001', 'guardian-reports-deps-old002', made.slice(temp.length + 1)].sort(),
      );
      // Another kind (`depsaudit-` is not `deps-`), and a kind never pruned (DAST evidence), untouched.
      expect(left.filter((n) => n.startsWith('guardian-reports-depsaudit-'))).toHaveLength(4);
      expect(left.filter((n) => n.startsWith('guardian-reports-dast-'))).toHaveLength(4);
    } finally {
      vi.unstubAllEnvs();
      vi.restoreAllMocks();
    }
  });
});
afterEach(() => {
  delete process.env['GUARDIAN_KEEP_REPORTS'];
});

/** A report directory `<prefix>-<id>` with a file, dated `ageS` seconds ago. */
function seed(project: string, name: string, ageS: number): string {
  const dir = join(project, '.guardian', 'reports', name);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'report.json'), '{}');
  const at = new Date(Date.now() - ageS * 1000);
  utimesSync(dir, at, at);
  return dir;
}

const reports = (project: string): string[] => readdirSync(join(project, '.guardian', 'reports')).sort();

describe('ensureReportDir prunes older report directories of its kind', () => {
  it(`keeps the ${DEFAULT_KEPT_REPORTS} newest, the new one among them`, () => {
    const project = makeTempDir('reports-prune-');
    for (let i = 1; i <= 5; i++) seed(project, `sast-0000000${i}`, 100 * i);
    const made = ensureReportDir(project, 'abcdef0123456789', 'sast');
    expect(made.endsWith('sast-abcdef01')).toBe(true);
    // The new one, plus the two newest of the old.
    expect(reports(project)).toEqual(['sast-00000001', 'sast-00000002', 'sast-abcdef01']);
  });

  it('touches no other kind: deps- never takes depsaudit-, nor secrets- init-secrets-', () => {
    const project = makeTempDir('reports-prune-kinds-');
    for (let i = 1; i <= 4; i++) {
      seed(project, `depsaudit-0000000${i}`, 100 * i);
      seed(project, `init-secrets-0000000${i}`, 100 * i);
      seed(project, `vex-0000000${i}`, 100 * i);
      seed(project, `dast-0000000${i}`, 100 * i);
    }
    ensureReportDir(project, '11111111aaaa', 'deps');
    ensureReportDir(project, '22222222bbbb', 'secrets');
    const left = reports(project);
    for (let i = 1; i <= 4; i++) {
      expect(left).toContain(`depsaudit-0000000${i}`);
      expect(left).toContain(`init-secrets-0000000${i}`);
      // Documents a user asked for, and DAST evidence a finding points at: never pruned.
      expect(left).toContain(`vex-0000000${i}`);
      expect(left).toContain(`dast-0000000${i}`);
    }
  });

  it('GUARDIAN_KEEP_REPORTS=1 keeps only the new one', () => {
    process.env['GUARDIAN_KEEP_REPORTS'] = '1';
    const project = makeTempDir('reports-prune-one-');
    seed(project, 'iac-00000001', 50);
    ensureReportDir(project, 'feedfacecafe', 'iac');
    expect(reports(project)).toEqual(['iac-feedface']);
  });

  it('never deletes through a link: a link entry is not a report directory', () => {
    const project = makeTempDir('reports-prune-link-');
    const outside = makeTempDir('reports-prune-outside-');
    writeFileSync(join(outside, 'precious.txt'), 'keep me');
    for (let i = 1; i <= 4; i++) seed(project, `sast-0000000${i}`, 100 * i);
    symlinkSync(outside, join(project, '.guardian', 'reports', 'sast-0000000a'), 'junction');
    ensureReportDir(project, 'abcdef0123456789', 'sast');
    expect(existsSync(join(outside, 'precious.txt'))).toBe(true);
  });
});
