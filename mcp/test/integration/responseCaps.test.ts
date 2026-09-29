/**
 * Response caps for the history readers that list findings: counts are
 * always the true totals; each bucket carries at most 50 items and says when
 * it was cut. A project with a few thousand findings otherwise answered
 * `diff_scans` with all of them — three times over (new, resolved,
 * unchanged).
 */

import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { TOOLS } from '../../src/tools/index.js';
import { okResult } from '../helpers/toolResult.js';
import { cleanupTempDirs } from '../helpers/tempDir.js';
import { freshPlugin, projectDir, seedScan, type SeedFinding } from '../helpers/historySeed.js';

afterAll(cleanupTempDirs);

beforeAll(async () => {
  await import('../../src/tools/diffScans.js');
  await import('../../src/tools/triageFindings.js');
});

function tool(name: string) {
  const t = TOOLS.find((x) => x.name === name);
  if (!t) throw new Error(`tool ${name} not registered`);
  return t;
}

function many(n: number, prefix: string, file: (i: number) => string): SeedFinding[] {
  return Array.from({ length: n }, (_, i) => ({ fp: `${prefix}${String(i).padStart(63, '0')}`.slice(0, 64), file: file(i) }));
}

describe('diff_scans', () => {
  it('returns true counts and at most 50 items per bucket, flagged when cut', async () => {
    const s = freshPlugin();
    const p = projectDir('caps-');
    const kept = many(70, 'a', (i) => `src/k${i}.ts`);
    const from = seedScan(s, { id: 'from', type: 'sast', project: p, findings: [...kept, ...many(60, 'b', (i) => `src/r${i}.ts`)] });
    const to = seedScan(s, { id: 'to', type: 'sast', project: p, findings: [...kept, ...many(3, 'c', (i) => `src/n${i}.ts`)] });

    const r = okResult<{
      summary: { new: number; resolved: number; unchanged: number; not_remeasured: number; not_previously_measured: number };
      new_findings: unknown[];
      resolved_findings: unknown[];
      unchanged_findings: unknown[];
      truncated: { new: boolean; resolved: boolean; unchanged: boolean; not_remeasured: boolean; not_previously_measured: boolean };
    }>(await tool('diff_scans').handler({ from_scan_id: from, to_scan_id: to, project_path: p }, s.plugin));

    expect(r.summary).toEqual({ new: 3, resolved: 60, unchanged: 70, not_remeasured: 0, not_previously_measured: 0, suppressed: 0 });
    expect(r.new_findings).toHaveLength(3);
    expect(r.resolved_findings).toHaveLength(50);
    expect(r.unchanged_findings).toHaveLength(50);
    expect(r.truncated).toEqual({ new: false, resolved: true, unchanged: true, not_remeasured: false, not_previously_measured: false, suppressed: false });
  });
});

describe('triage_findings', () => {
  it('returns true counts and at most 50 items per bucket, flagged when cut', async () => {
    const s = freshPlugin();
    const p = projectDir('caps-');
    seedScan(s, {
      id: 's1', type: 'sast', project: p,
      findings: [
        ...many(55, 'a', (i) => `test/t${i}.ts`),     // likely_false_positive
        ...many(4, 'b', (i) => `vendor/v${i}.js`),    // probably_safe
        ...many(80, 'c', (i) => `src/s${i}.ts`),      // keep
      ],
    });

    const r = okResult<{
      summary: { total: number; likely_false_positive: number; probably_safe: number; keep: number };
      likely_false_positive: unknown[];
      probably_safe: unknown[];
      keep: unknown[];
      truncated: { likely_false_positive: boolean; probably_safe: boolean; keep: boolean };
    }>(await tool('triage_findings').handler({ project_path: p }, s.plugin));

    expect(r.summary).toEqual({ total: 139, likely_false_positive: 55, probably_safe: 4, keep: 80 });
    expect(r.likely_false_positive).toHaveLength(50);
    expect(r.probably_safe).toHaveLength(4);
    expect(r.keep).toHaveLength(50);
    expect(r.truncated).toEqual({ likely_false_positive: true, probably_safe: false, keep: true });
  });
});
