/**
 * T-07 (slot): the readers of an imported log's slot — previous scan,
 * baselines, the slot list — each stay inside one source tool.
 */
import { afterAll, describe, expect, it } from 'vitest';
import { latestStateScan, openSetForProject } from '../../../src/history/openSet.js';
import { freshPlugin, seedScan, type Seeded } from '../../helpers/historySeed.js';
import { cleanupTempDirs } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

const P = '/p';
const imp = (s: Seeded, id: string, tool: string | null): void => {
  seedScan(s, {
    id,
    type: 'sarif_import',
    project: P,
    tools_run: [{ name: 'sarif', status: 'ok' }],
    ...(tool === null ? {} : { meta: { source_tool: tool } }),
    findings: [{ tool: tool ?? 'x', fp: `fp-${id}` }],
  });
};

describe('T-07 (slot) latestStateScan of sarif_import', () => {
  it('"previous" of an import is the previous import of the SAME tool', () => {
    const s = freshPlugin();
    imp(s, 'snyk-1', 'Snyk');
    imp(s, 'codeql-1', 'CodeQL');
    imp(s, 'snyk-2', 'Snyk');
    imp(s, 'codeql-2', 'CodeQL');
    expect(latestStateScan(s.storage, P, 'sarif_import', { beforeScanId: 'codeql-2' }).scan?.scan_id).toBe('codeql-1');
    expect(latestStateScan(s.storage, P, 'sarif_import', { beforeScanId: 'snyk-2' }).scan?.scan_id).toBe('snyk-1');
    expect(latestStateScan(s.storage, P, 'sarif_import', { beforeScanId: 'snyk-1' }).scan).toBeNull();
  });

  it('an explicit sourceTool picks that tool newest; the any-type search ignores imports', () => {
    const s = freshPlugin();
    seedScan(s, { id: 'n1', type: 'sast', project: P });
    imp(s, 'snyk-1', 'Snyk');
    imp(s, 'codeql-1', 'CodeQL');
    expect(latestStateScan(s.storage, P, 'sarif_import', { sourceTool: 'Snyk' }).scan?.scan_id).toBe('snyk-1');
    expect(latestStateScan(s.storage, P).scan?.scan_id).toBe('n1');
  });
});

describe('T-07 (slot) open-set slots', () => {
  it('one slot per source tool, the empty bucket for a scan without a tool', () => {
    const s = freshPlugin();
    imp(s, 'a1', 'A');
    imp(s, 'a2', 'A');
    imp(s, 'b1', 'B');
    imp(s, 'u1', null);
    expect(s.storage.scans.sarifSourceTools(P).sort()).toEqual(['', 'A', 'B']);
    const slots = openSetForProject(s.storage, P).sources.map((x) => x.slot).sort();
    expect(slots).toEqual(['sarif_import:', 'sarif_import:A', 'sarif_import:B']);
  });
});

describe('an imported log never shadows a native finding of the same identity', () => {
  // A SARIF log comes from wherever the caller found it — the repository
  // under scan, say — and `devGuardianIdentity` is any 64-hex string it
  // chooses. Matched newest first across slots, a log carrying a Semgrep
  // critical's identity at severity info hid the critical until the next
  // native scan.
  const identity = 'c'.repeat(64);
  const seed = (s: Seeded): void => {
    seedScan(s, { id: 'native', type: 'sast', project: P, findings: [{ identity, severity: 'critical', fp: 'fp-native' }] });
    seedScan(s, {
      id: 'imported',
      type: 'sarif_import',
      project: P,
      tools_run: [{ name: 'sarif', status: 'ok' }],
      meta: { source_tool: 'Forged' },
      findings: [{ tool: 'Forged', identity, severity: 'info', fp: 'fp-imported' }],
    });
  };

  it('keeps the native copy, newer import or not', () => {
    const s = freshPlugin();
    seed(s);
    const set = openSetForProject(s.storage, P);
    expect(set.findings.map((f) => [f.scan_id, f.severity])).toEqual([['native', 'critical']]);
  });

  it('keeps the native copy a newer native scan carried forward, too', () => {
    const s = freshPlugin();
    seed(s);
    // A newer Semgrep that failed beside an ok Bandit: the critical is carried, not re-measured.
    seedScan(s, {
      id: 'blind', type: 'sast', project: P,
      tools_run: [{ name: 'semgrep', status: 'failed', reason: 'exit 7' }, { name: 'bandit', status: 'ok' }],
      missing_tools: ['semgrep'],
    });
    const set = openSetForProject(s.storage, P);
    expect(set.findings.map((f) => [f.scan_id, f.severity])).toEqual([['native', 'critical']]);
  });
});

describe('T-07 (slot) baselines', () => {
  it('a baseline of an import never answers a read that names no type', () => {
    const s = freshPlugin();
    seedScan(s, { id: 'n1', type: 'sast', project: P });
    imp(s, 'snyk-1', 'Snyk');
    s.storage.baselines.set({ scan_id: 'n1' });
    const set = s.storage.baselines.set({ scan_id: 'snyk-1' });
    expect(set.slot).toBe('sarif_import:Snyk');
    expect(s.storage.baselines.getActiveForProject(P)?.scan_id).toBe('n1');
    expect(s.storage.baselines.getActive()?.scan_id).toBe('n1');
    expect(s.storage.baselines.getActiveForProject(P, 'sarif_import')?.scan_id).toBe('snyk-1');
    expect(s.storage.baselines.getActiveForProject(P, 'sarif_import', 'sarif_import:Snyk')?.scan_id).toBe('snyk-1');
    expect(s.storage.baselines.getActiveForProject(P, 'sarif_import', 'sarif_import:CodeQL')).toBeNull();
  });
});
