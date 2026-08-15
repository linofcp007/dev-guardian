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

  it('is empty-safe', () => {
    expect(rankFiles([], 5)).toEqual({ hotspots: [], remaining_files: 0 });
  });
});
