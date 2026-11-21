/**
 * T-07 (slot): the readers of an imported log's slot — previous scan,
 * baselines, the slot list — each stay inside one source tool.
 *
 * llm-scan-plan-record-default-scan T-04: the same search, and the
 * carry-forward walk, pass over a verify-only plan's `llm_scan` record.
 */
import { afterAll, describe, expect, it } from 'vitest';
import { latestStateScan, openSetForProject } from '../../../src/history/openSet.js';
import { toFindingValidation } from '../../../src/llmscan/submission.js';
import type { ToolRun } from '../../../src/types.js';
import { freshPlugin, seedOrchestratedRun, seedScan, type Seeded } from '../../helpers/historySeed.js';
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

describe('llm-scan-plan-record-default-scan', () => {
  // A verify-only plan's record, seeded with its bookkeeping written out: the
  // helper's default is `[semgrep ok]`, and `start` writes it empty.
  const verifyRecord = (s: Seeded, id: string): void => {
    seedScan(s, { id, type: 'llm_scan', project: P, tools_run: [], missing_tools: [], meta: { plan_id: `plan-${id}`, modes: ['verify'] } });
  };
  const HUNT_OK: ToolRun[] = [{ name: 'llm-hunt', status: 'ok' }];
  // Semgrep, gitleaks and Trivy absent, no IaC: the iac child skipped everything with nothing to scan
  // (coverage full), its parent measured nothing (none) — the search passes over it and searches again below.
  const BLIND_RUN = {
    sast: { blind: true },
    secrets: { blind: true },
    deps: { blind: true },
    iac: { runs: [{ name: 'trivy-config', status: 'skipped', reason: 'nothing to scan' }] satisfies ToolRun[], missing: [] },
  };

  it('T-04 latestStateScan, without a type and with scan_type llm_scan, never answers with a verify-only plan\'s record (tools_run: []) in either of its searches; a hunt\'s record is answered', () => {
    // SAST < verify-only record < an orchestrated run judged none: the record is reached by the second search.
    const s = freshPlugin();
    seedScan(s, { id: 'sast', type: 'sast', project: P });
    verifyRecord(s, 'verify');
    seedOrchestratedRun(s, 'blind-run', P, BLIND_RUN);
    expect(latestStateScan(s.storage, P).scan?.scan_id, 'any type').toBe('sast');
    expect(latestStateScan(s.storage, P, 'llm_scan').scan, 'scan_type llm_scan').toBeNull();

    // Only verify-only records: no scan at all.
    const only = freshPlugin();
    verifyRecord(only, 'verify-1');
    verifyRecord(only, 'verify-2');
    expect(latestStateScan(only.storage, P).scan, 'any type, verify-only records only').toBeNull();
    expect(latestStateScan(only.storage, P, 'llm_scan').scan, 'scan_type llm_scan, verify-only records only').toBeNull();

    // A hunt's record (llm-hunt ok) is a scan of the project, also under a newer verify-only record.
    const hunted = freshPlugin();
    seedScan(hunted, { id: 'sast', type: 'sast', project: P });
    seedScan(hunted, { id: 'hunt', type: 'llm_scan', project: P, tools_run: HUNT_OK });
    verifyRecord(hunted, 'verify');
    expect(latestStateScan(hunted.storage, P).scan?.scan_id, 'any type, a hunt under a verify-only record').toBe('hunt');
    expect(latestStateScan(hunted.storage, P, 'llm_scan').scan?.scan_id, 'scan_type llm_scan, a hunt under a verify-only record').toBe('hunt');
    seedScan(hunted, { id: 'hunt-2', type: 'llm_scan', project: P, tools_run: HUNT_OK });
    expect(latestStateScan(hunted.storage, P, 'llm_scan').scan?.scan_id, 'the newest hunt').toBe('hunt-2');
    expect(latestStateScan(hunted.storage, P, 'llm_scan', { beforeScanId: 'hunt-2' }).scan?.scan_id, 'the hunt before it').toBe('hunt');
  });

  it('T-04 the carry-forward walk passes over an older verify-only plan\'s record and carries a complete hunt\'s confirmed findings past a partial hunt', () => {
    const s = freshPlugin();
    const confirmedFps = ['a'.repeat(64), 'b'.repeat(64)];
    // A complete hunt: two findings confirmed by an independent `exploitable`, one left unconfirmed (never shown).
    seedScan(s, {
      id: 'hunt-1',
      type: 'llm_scan',
      project: P,
      tools_run: HUNT_OK,
      findings: [
        { fp: 'a'.repeat(64), tool: 'llm-hunt', rule_id: 'path-traversal', file: 'src/routes/files.ts', line: 11 },
        { fp: 'b'.repeat(64), tool: 'llm-hunt', rule_id: 'broken-access-control', file: 'src/routes/admin.ts', line: 7 },
        { fp: 'c'.repeat(64), tool: 'llm-hunt', rule_id: 'ssrf', file: 'src/routes/users.ts', line: 3 },
      ],
    });
    for (const fingerprint of confirmedFps) {
      s.storage.validations.upsert(P, [
        toFindingValidation({
          fingerprint,
          verdict: 'exploitable',
          independence: 'subagent',
          decisive_line: 'src/routes/files.ts:11 — the fixture verdict',
          reasoning: 'Followed the value.',
          prompt_version: 'v1',
          tree_hash: 'tree-under-test',
          computed_at: '2026-10-02T12:00:00.000Z',
        }),
      ]);
    }
    verifyRecord(s, 'verify');
    // A partial hunt, as rule 2 records one with some hunt tasks still unanswered.
    seedScan(s, { id: 'hunt-2', type: 'llm_scan', project: P, tools_run: HUNT_OK, missing_tools: ['llm-hunt:open-tasks'] });

    const set = openSetForProject(s.storage, P);
    expect(set.sources.find((x) => x.slot === 'llm_scan' && x.carried_for === undefined)?.scan_id, "the llm_scan slot's source").toBe('hunt-2');
    const hunted = set.findings.filter((f) => f.tool === 'llm-hunt');
    expect(hunted.map((f) => f.fingerprint).sort(), 'the confirmed findings, carried past the partial hunt').toEqual(confirmedFps);
    expect(hunted.map((f) => f.scan_id)).toEqual(['hunt-1', 'hunt-1']);
  });
});
