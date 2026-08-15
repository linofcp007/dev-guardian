import { describe, expect, it } from 'vitest';
import { rankFiles } from '../../../src/dashboard/hotspots.js';
import type { Finding } from '../../../src/types.js';

function f(file_path: string): Finding {
  return {
    fingerprint: `${file_path}-${Math.random()}`, tool: 'semgrep', rule_id: 'r',
    severity: 'low', category: 'security', subcategory: null, title: 't',
    message: 'm', file_path, line_start: 1, line_end: 1, snippet: null,
    fix_available: false, fix_applied: false, raw: {},
  } as unknown as Finding;
}

describe('rankFiles', () => {
  it('ranks files by finding count, descending', () => {
    const r = rankFiles([f('a.ts'), f('b.ts'), f('a.ts'), f('a.ts'), f('b.ts')], 10);
    expect(r.hotspots).toEqual([
      { file_path: 'a.ts', count: 3 },
      { file_path: 'b.ts', count: 2 },
    ]);
    expect(r.remaining_files).toBe(0);
  });

  it('reports how many files it did NOT show', () => {
    // Otherwise "3 hottest files" reads as "3 files have findings".
    const rows = ['a', 'b', 'c', 'd', 'e'].flatMap((n) => [f(`${n}.ts`)]);
    const r = rankFiles(rows, 3);
    expect(r.hotspots).toHaveLength(3);
    expect(r.remaining_files).toBe(2);
  });

  it('breaks ties by path so the output is stable across runs', () => {
    // An unstable sort makes the terminal screen change between two runs over
    // identical data, which reads as "something moved" when nothing did.
    const r = rankFiles([f('b.ts'), f('a.ts')], 10);
    expect(r.hotspots.map((h) => h.file_path)).toEqual(['a.ts', 'b.ts']);
  });

  it('groups findings with no file path under a single explicit bucket', () => {
    const orphan = { ...f('x'), file_path: null } as unknown as Finding;
    const r = rankFiles([orphan, orphan], 10);
    expect(r.hotspots).toEqual([{ file_path: '(no file)', count: 2 }]);
  });

  it('folds an empty-string file path into the same (no file) bucket', () => {
    // Not hypothetical: toRelativeIfPossible (runners/scannerParsers/index.ts)
    // returns '' for a finding whose file_path IS the project root, and it
    // feeds semgrep, trivy, gitleaks and every other path-normalising
    // parser. report/sarif.ts already treats this exact case as known and
    // real. `??` would miss it — only `||` falls through on ''.
    const wholeProject = { ...f('x'), file_path: '' } as unknown as Finding;
    const r = rankFiles([wholeProject, wholeProject], 10);
    expect(r.hotspots).toEqual([{ file_path: '(no file)', count: 2 }]);
  });

  it('collapses null, undefined and empty-string file paths into ONE bucket together', () => {
    // Guards against a fix that handles '' correctly in isolation but
    // routes it to a different sentinel than null/undefined — three
    // "no file" findings must count as 3 in one row, not spread across
    // look-alike buckets.
    const nullPath = { ...f('x'), file_path: null } as unknown as Finding;
    const undefinedPath = { ...f('x'), file_path: undefined } as unknown as Finding;
    const emptyPath = { ...f('x'), file_path: '' } as unknown as Finding;
    const r = rankFiles([nullPath, undefinedPath, emptyPath], 10);
    expect(r.hotspots).toEqual([{ file_path: '(no file)', count: 3 }]);
  });

  it('does NOT fold a whitespace-only file path into (no file)', () => {
    // Decision, not an oversight: unlike '', nothing in this codebase
    // produces a whitespace-only file_path today, so there is no evidence
    // it means "absent". Folding it in on spec would also hide a genuine
    // anomaly (e.g. a future parser bug) behind the same label as the
    // well-understood "whole project" case above, instead of surfacing it.
    const whitespace = { ...f('x'), file_path: '   ' } as unknown as Finding;
    const r = rankFiles([whitespace], 10);
    expect(r.hotspots).toEqual([{ file_path: '   ', count: 1 }]);
  });

  it('is empty-safe', () => {
    expect(rankFiles([], 5)).toEqual({ hotspots: [], remaining_files: 0 });
  });
});
