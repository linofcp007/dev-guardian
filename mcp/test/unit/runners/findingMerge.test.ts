import { describe, expect, it } from 'vitest';
import { dedupeFindings, findingMergeKey } from '../../../src/runners/findingMerge.js';
import { makeFinding } from '../../../src/runners/scannerParsers/index.js';

const f = (file: string, line: number) =>
  makeFinding({ tool: 't', rule_id: 'r', severity: 'high', category: 'security', title: 'x', file_path: file, line_start: line });

describe('dedupeFindings', () => {
  it('keeps the first of each finding and the order of the rest', () => {
    const a = f('a.ts', 1);
    const b = f('b.ts', 2);
    expect(dedupeFindings([a, b, { ...a }, b]).map(findingMergeKey)).toEqual([
      findingMergeKey(a),
      findingMergeKey(b),
    ]);
  });
});
