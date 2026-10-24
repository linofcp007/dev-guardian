/**
 * `runners/semgrepCoverageGaps.ts` — the size-limit and submodule gaps of a
 * Semgrep run, in one place (review M1 / M2, round 2). The last describe
 * holds the rule for the whole tree: a file that spawns Semgrep for a result
 * and never applies the gaps fails it.
 */

import { readdirSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { longPathsOf } from '../../../src/frameworks/projectLanguages.js';
import {
  applySemgrepCoverageGaps,
  markMissing,
  NO_SEMGREP_GAPS,
  PATH_TOO_LONG_TYPE,
  scannedNothingBecause,
  semgrepGapNotes,
  type SemgrepCoverageGaps,
} from '../../../src/runners/semgrepCoverageGaps.js';

const BIG: SemgrepCoverageGaps = { oversized: [{ path: 'src/big.py', bytes: 1_160_008 }], submodules: [] };
const SUB: SemgrepCoverageGaps = { oversized: [], submodules: ['vendor/lib'] };
const BOTH: SemgrepCoverageGaps = { ...BIG, submodules: ['vendor/lib'], incomplete: 'the file walk stopped after 20000 directories' };

describe('semgrepGapNotes', () => {
  it('names each gap, in order', () => {
    expect(semgrepGapNotes(NO_SEMGREP_GAPS)).toEqual([]);
    expect(semgrepGapNotes(BOTH)).toEqual([
      "1 file over Semgrep's 1 MB target limit was not scanned: src/big.py (1.2 MB)",
      'submodule contents not scanned: vendor/lib',
      "the file walk stopped after 20000 directories — files over Semgrep's size limit below it were not checked",
    ]);
  });
});

describe('applySemgrepCoverageGaps', () => {
  it('no gap: the run unchanged, nothing missing', () => {
    const run = { name: 'semgrep', status: 'ok' } as const;
    expect(applySemgrepCoverageGaps(run, NO_SEMGREP_GAPS)).toEqual({ toolRun: run, missing: false });
  });

  it('an ok run keeps its reason, gains the notes, and is a gap', () => {
    const r = applySemgrepCoverageGaps({ name: 'semgrep', status: 'ok', reason: 'ran via docker' }, SUB);
    expect(r.toolRun.reason).toBe('ran via docker; submodule contents not scanned: vendor/lib');
    expect(r.missing).toBe(true);
  });

  it('a failed run is named, but already not full: not listed twice', () => {
    const r = applySemgrepCoverageGaps({ name: 'semgrep', status: 'failed', reason: 'boom' }, SUB);
    expect(r.toolRun.reason).toMatch(/^boom; submodule/);
    expect(r.missing).toBe(false);
  });

  it('scanned nothing because every file was too large: that is the reason, not "no covered language"', () => {
    const run = { name: 'semgrep', status: 'skipped', reason: 'semgrep scanned 0 files — nothing here is a language its rules cover' } as const;
    const r = applySemgrepCoverageGaps(run, BIG, { scannedNothing: true });
    expect(r.toolRun.reason).toBe(
      "semgrep scanned 0 files — 1 file over Semgrep's 1 MB target limit was not scanned: src/big.py (1.2 MB)",
    );
    expect(r.missing).toBe(true);
    // Scanned nothing for another reason: the caller's claim stands.
    expect(applySemgrepCoverageGaps(run, SUB, { scannedNothing: true }).toolRun.reason).toMatch(/nothing here is a language.*; submodule/);
  });

  it('a note the caller already put in its reason is not repeated', () => {
    const because = scannedNothingBecause(BIG) ?? '';
    const r = applySemgrepCoverageGaps({ name: 'semgrep', status: 'skipped', reason: because }, BIG);
    expect(r.toolRun.reason).toBe(because);
  });

  // Review 8, finding 2: on Windows a file at a path of 260 characters or more
  // was missing from Semgrep's paths.scanned with no error, and the gate read
  // coverage full. A long path the report does not list is a named gap, per
  // file, under its own type; one it lists (long paths enabled) is none.
  describe('paths too long for Windows', () => {
    const LONG = 'deep/nested/app.js';
    const GAPS: SemgrepCoverageGaps = { oversized: [], submodules: [], longPaths: [LONG] };
    const report = (scanned: string[]): string => JSON.stringify({ results: [], errors: [], paths: { scanned } });

    it('a long path the report does not list is a gap: named, partial, typed Path too long', () => {
      const r = applySemgrepCoverageGaps({ name: 'semgrep', status: 'ok' }, GAPS, { reports: [report(['short.js'])] });
      expect(r.missing).toBe(true);
      expect(r.toolRun.reason).toMatch(
        /1 file\(s\) at a path of 260 characters or more, or in a directory of 248 or more, were not scanned \(Windows MAX_PATH\): deep\/nested\/app\.js/,
      );
      expect(r.toolRun.partially_parsed).toEqual([expect.objectContaining({ file: LONG, type: PATH_TOO_LONG_TYPE })]);
      expect(r.toolRun.unscanned).toBeUndefined();
    });

    it('one the report lists as scanned — relative, absolute or in another case — is no gap', () => {
      const bs = String.fromCharCode(92);
      for (const listed of [LONG, `C:${bs}proj${bs}deep${bs}nested${bs}app.js`, 'DEEP/Nested/App.js', `./${LONG}`]) {
        const r = applySemgrepCoverageGaps({ name: 'semgrep', status: 'ok' }, GAPS, { reports: [report(['short.js', listed])] });
        expect(r.missing, listed).toBe(false);
      }
    });

    it('with no readable report, every long path is a gap — never a silent pass', () => {
      expect(applySemgrepCoverageGaps({ name: 'semgrep', status: 'ok' }, GAPS).missing).toBe(true);
      expect(applySemgrepCoverageGaps({ name: 'semgrep', status: 'ok' }, GAPS, { reports: ['not json'] }).missing).toBe(true);
    });

    it('a batched run: scanned by any of its reports is scanned', () => {
      const r = applySemgrepCoverageGaps({ name: 'semgrep', status: 'ok' }, GAPS, { reports: [report(['a.js']), report([LONG])] });
      expect(r.missing).toBe(false);
    });

    it('a Semgrep that never ran adds no long-path gap', () => {
      const r = applySemgrepCoverageGaps({ name: 'semgrep', status: 'skipped', reason: 'not_installed' }, GAPS);
      expect(r.toolRun.partially_parsed).toBeUndefined();
    });

    it('the other gaps are recorded as data on the run (unscanned), for the CI gate', () => {
      expect(applySemgrepCoverageGaps({ name: 'semgrep', status: 'ok' }, BOTH).toolRun.unscanned).toEqual({
        oversized: 1,
        submodules: 1,
        listing_incomplete: true,
      });
    });

    it('longPathsOf: Windows only, at 260 characters and over', () => {
      const root = `C:${String.fromCharCode(92)}p`;
      const at = (n: number): string => 'a'.repeat(n - root.length - 1);
      expect(longPathsOf(root, [at(259), at(260), at(300)], 'win32')).toEqual([at(260), at(300)].sort());
      expect(longPathsOf(root, [at(300)], 'linux')).toEqual([]);
    });
  });

  it('markMissing lists a name once', () => {
    const missing = ['semgrep'];
    markMissing(missing, 'semgrep');
    markMissing(missing, 'semgrep-wp');
    expect(missing).toEqual(['semgrep', 'semgrep-wp']);
  });
});

// ---------------------------------------------------------------- the whole tree

const SRC = fileURLToPath(new URL('../../../src/', import.meta.url));

function tsFiles(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const abs = join(dir, e.name);
    if (e.isDirectory()) return tsFiles(abs);
    return e.name.endsWith('.ts') ? [abs] : [];
  });
}

/** A Semgrep run a result is built from: the spawn helpers, the batch runner, the Docker argv, the surface's runner. */
const SEMGREP_RUN =
  /\b(?:runSemgrep|spawnSemgrep|semgrepSpawn|semgrepOnFiles|buildSemgrepDockerArgs|invokeSemgrep)\(/;

/**
 * Files that run Semgrep and build no scan result from it, each with why.
 * A new one fails the test below until it applies the gaps or is listed
 * here.
 */
const EXEMPT: Readonly<Record<string, string>> = {
  'runners/semgrepRun.ts': 'the spawn helper itself',
  'runners/semgrepCoverageGaps.ts': 'this module',
  'runners/fileBatchScan.ts': 'defines semgrepOnFiles; each caller applies the gaps to its result',
  'runners/dockerScanner.ts': 'defines buildSemgrepDockerArgs',
  'runners/semgrepValidate.ts': '`semgrep --validate` of rule files: it scans no target',
  'fixpr/apply.ts': "create_fix_pr's autofix of named files; the fix is verified by re-running a scan tool",
  'surface/scanSemgrep.ts': "defines invokeSemgrep; tools/mapAttackSurface.ts builds the surface's result",
};

describe('every Semgrep result applies the shared coverage gaps', () => {
  it('no file runs Semgrep for a result without applySemgrepCoverageGaps', () => {
    const offenders: string[] = [];
    for (const path of tsFiles(SRC)) {
      const rel = relative(SRC, path).split('\\').join('/');
      if (Object.hasOwn(EXEMPT, rel)) continue;
      const text = readFileSync(path, 'utf8');
      if (SEMGREP_RUN.test(text) && !text.includes('applySemgrepCoverageGaps(')) offenders.push(rel);
    }
    expect(offenders).toEqual([]);
  });

  it('every exemption still names a file that runs Semgrep (no stale entries)', () => {
    const stale = Object.keys(EXEMPT).filter((rel) => {
      try {
        return !SEMGREP_RUN.test(readFileSync(join(SRC, rel), 'utf8')) && rel !== 'runners/semgrepCoverageGaps.ts';
      } catch {
        return true;
      }
    });
    expect(stale).toEqual([]);
  });

  it('the pattern catches what it is for (positive control)', () => {
    expect(SEMGREP_RUN.test('const r = await runSemgrep({ args })')).toBe(true);
    expect(SEMGREP_RUN.test('await semgrepOnFiles({ files })')).toBe(true);
    expect(SEMGREP_RUN.test("tools_run.push({ name: 'semgrep', status: 'ok' })")).toBe(false);
  });
});
