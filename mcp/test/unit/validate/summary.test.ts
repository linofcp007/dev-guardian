/**
 * Unit tests for the batch summary.
 *
 * The integration suite covers the ordinary paths end to end. These cover the
 * ones it cannot reach cheaply or at all: the 20 000-edge cap (which would
 * need a 20 001-edge fixture through the tool), an unparseable scan timestamp
 * (which no repo will write), and the exact arithmetic behind `age_hours`,
 * where "which timestamp did you read" is invisible to a `typeof` assertion.
 */

import { describe, expect, it } from 'vitest';
import { buildSummary, type DastCrossReference, type SummaryInput } from '../../../src/validate/summary.js';
import { buildImportGraph, type ImportGraph } from '../../../src/validate/importGraph.js';
import type { PersistedSurfaceSnapshot } from '../../../src/storage/surfaceRepo.js';
import type { AttackSurfaceSnapshot, RouteRecord, ScanRecord } from '../../../src/types.js';
import type { FindingValidation } from '../../../src/validate/types.js';

const FINISHED_AT = '2026-08-13T00:00:00.000Z';
const HOUR_MS = 3_600_000;

function snapshot(over: Partial<AttackSurfaceSnapshot> = {}): AttackSurfaceSnapshot {
  return {
    routes: [],
    env_vars: [],
    ports: [],
    webhooks: [],
    coverage: [],
    tools_run: [],
    missing_tools: [],
    spec_files: [],
    spec_diff: null,
    imports: [{ file: 'src/a.ts', module_file: 'src/b.ts' }],
    ...over,
  };
}

function persisted(over: Partial<AttackSurfaceSnapshot> = {}): PersistedSurfaceSnapshot {
  return {
    id: 7,
    project_path: '/p',
    captured_at: FINISHED_AT,
    tree_hash: 'tree-a',
    snapshot: snapshot(over),
  };
}

function scan(over: Partial<ScanRecord> = {}): ScanRecord {
  return {
    scan_id: 'dast-1',
    scan_type: 'dast',
    project_path: '/p',
    tree_hash: 'tree-a',
    // Deliberately four hours BEFORE `finished_at`: an implementation that
    // reads the wrong timestamp reports 6 hours where the correct one
    // reports 2, and both are plausible numbers.
    started_at: '2026-08-12T20:00:00.000Z',
    finished_at: FINISHED_AT,
    status: 'completed',
    tools_run: [],
    missing_tools: [],
    report_paths: [],
    ...over,
  };
}

function validation(over: Partial<FindingValidation> = {}): FindingValidation {
  return {
    fingerprint: 'fp1',
    verdict: 'unknown',
    confidence: 'low',
    provider: 'static',
    evidence: [],
    coverage_gaps: [],
    snapshot_id: 7,
    tree_hash: 'tree-a',
    computed_at: FINISHED_AT,
    ...over,
  };
}

function dast(over: Partial<DastCrossReference> = {}): DastCrossReference {
  return { scan: scan(), files: new Set(), scansSearched: 3, ...over };
}

function input(over: Partial<SummaryInput> = {}): SummaryInput {
  return {
    persisted: persisted(),
    graph: buildImportGraph([{ file: 'src/a.ts', module_file: 'src/b.ts' }]),
    validations: [validation()],
    dast: dast(),
    sourceScan: scan({ scan_id: 'sast-1', scan_type: 'sast' }),
    workingTreeHash: 'tree-a',
    now: Date.parse(FINISHED_AT) + 2 * HOUR_MS,
    ...over,
  };
}

function gaps(summary: Record<string, unknown>): string[] {
  return summary['coverage_gaps'] as string[];
}

function dastBlock(summary: Record<string, unknown>): Record<string, unknown> {
  return summary['dast'] as Record<string, unknown>;
}

describe('buildSummary — caps and gaps', () => {
  it('names the edge cap in coverage_gaps when the graph was truncated', () => {
    const truncated: ImportGraph = {
      edges: new Map([['src/a.ts', new Set(['src/b.ts'])]]),
      files: new Set(['src/a.ts', 'src/b.ts']),
      truncated: true,
    };

    const summary = buildSummary(input({ graph: truncated }));

    // `graph.truncated: true` alone is the plausible-wrong implementation:
    // the flag is technically present, but a reader looking at
    // coverage_gaps — the field the design says the counts are meaningless
    // without — never learns the graph was cut.
    expect(summary['graph']).toEqual({ files: 2, edges: 1, truncated: true });
    expect(gaps(summary).join(' | ')).toMatch(/20000-edge cap/);
  });

  it('deduplicates a gap two findings reported identically', () => {
    const shared = "3 import(s) for 'typescript' could not be resolved";
    const summary = buildSummary(
      input({
        validations: [
          validation({ fingerprint: 'fp1', coverage_gaps: [shared] }),
          validation({ fingerprint: 'fp2', coverage_gaps: [shared] }),
        ],
      }),
    );

    expect(gaps(summary).filter((g) => g === shared)).toHaveLength(1);
  });

  it('reports every verdict at zero for an empty batch, rather than an empty object', () => {
    const summary = buildSummary(input({ validations: [] }));

    expect(summary['counts_by_verdict']).toEqual({
      unreachable: 0,
      reachable: 0,
      confirmed: 0,
      unknown: 0,
    });
    expect(summary['findings_selected']).toBe(0);
  });
});

describe('buildSummary — routes_total counts the roots that were actually used', () => {
  function route(over: Partial<RouteRecord> = {}): RouteRecord {
    return {
      method: 'GET', provenance: 'code', path_raw: '/users', path_resolved: '/users',
      path_partial: false, file: 'src/routes.ts', line: 1, framework: 'express',
      language: 'typescript', auth_hint: 'unknown', params: [], confidence: 'high',
      ...over,
    };
  }

  it('excludes spec-provenance routes, which are never reachability roots', () => {
    // `groupRoutesByRelFile` (staticProvider.ts) skips spec routes: a spec
    // route's `file` is the OpenAPI document, which no code import graph ever
    // contains. Counting them here produced the worst possible pairing — a
    // project whose routes came only from an imported spec read
    // `routes_total: 3` beside a batch of `unreachable` verdicts computed
    // from ZERO roots. It also disagreed with map_attack_surface's own
    // `routes_total`, which is code-only by explicit decision.
    const summary = buildSummary(
      input({
        persisted: persisted({
          routes: [
            route(),
            route({ provenance: 'spec', file: 'openapi.yaml', path_resolved: '/documented' }),
            route({ provenance: 'spec', file: 'openapi.yaml', path_resolved: '/also-documented' }),
          ],
        }),
      }),
    );

    const snapshotBlock = summary['snapshot'] as Record<string, unknown>;
    expect(snapshotBlock['routes_total']).toBe(1);
    // The count the evidence sentences quote ("reached by X of Y known
    // route(s)") is this same code-route count, so the two must agree.
    expect(snapshotBlock['spec_routes_excluded']).toBe(2);
  });

  it('reports zero roots for a spec-only project rather than a number nothing was computed from', () => {
    const summary = buildSummary(
      input({
        persisted: persisted({
          routes: [route({ provenance: 'spec', file: 'openapi.yaml' })],
        }),
      }),
    );

    const snapshotBlock = summary['snapshot'] as Record<string, unknown>;
    expect(snapshotBlock['routes_total']).toBe(0);
    expect(snapshotBlock['root_files']).toBe(0);
  });

  it('deduplicates roots by file: three routes in one file are one root', () => {
    // `root_files` is the number `reachFrom` actually traverses from, which
    // is the deduplicated FILE count, not the route count.
    const summary = buildSummary(
      input({
        persisted: persisted({
          routes: [
            route(),
            route({ method: 'POST' }),
            route({ file: 'src/admin.ts', path_resolved: '/admin' }),
          ],
        }),
      }),
    );

    const snapshotBlock = summary['snapshot'] as Record<string, unknown>;
    expect(snapshotBlock['routes_total']).toBe(3);
    expect(snapshotBlock['root_files']).toBe(2);
  });
});

describe('buildSummary — the scan the validated findings came from', () => {
  it('names the scan id, its type and its tree hash', () => {
    // The documented hazard: `validate_finding` validates whatever the latest
    // completed scan left open, so running it right after `scan_dast`
    // validates the DAST findings, not the SAST ones the caller had in mind.
    // Naming the scan turns that from something a reader must remember into
    // something they can see.
    const summary = buildSummary(
      input({ sourceScan: scan({ scan_id: 'sast-9', scan_type: 'sast', tree_hash: 'tree-b' }) }),
    );

    expect(summary['findings_from_scan']).toEqual({
      scan_id: 'sast-9',
      scan_type: 'sast',
      tree_hash: 'tree-b',
      finished_at: FINISHED_AT,
      matches_snapshot_tree: false,
    });
  });

  it('reports matches_snapshot_tree when the scan and the snapshot describe the same tree', () => {
    // Not decoration: findings from a different tree than the snapshot's are
    // being placed on a map of a different codebase.
    const summary = buildSummary(input({ sourceScan: scan({ scan_type: 'sast', tree_hash: 'tree-a' }) }));
    const block = summary['findings_from_scan'] as Record<string, unknown>;
    expect(block['matches_snapshot_tree']).toBe(true);
  });

  it('is null, not absent, when no scan could be identified', () => {
    // An absent key reads as "not measured"; null says the lookup ran and
    // found nothing — the same distinction `counts_by_verdict` seeds itself
    // with zeros for.
    const summary = buildSummary(input({ sourceScan: null }));
    expect(summary).toHaveProperty('findings_from_scan');
    expect(summary['findings_from_scan']).toBeNull();
  });
});

describe('buildSummary — the DAST age', () => {
  it('measures the age from when the scan finished, not when it started', () => {
    // 2, not 6. `started_at` is four hours earlier by construction above.
    expect(dastBlock(buildSummary(input()))['age_hours']).toBe(2);
  });

  it('falls back to started_at when the scan never recorded a finish', () => {
    const summary = buildSummary(input({ dast: dast({ scan: scan({ finished_at: null }) }) }));
    expect(dastBlock(summary)['age_hours']).toBe(6);
  });

  it('reports a null age for an unparseable timestamp rather than an age of zero', () => {
    // The wrong implementation returns NaN, which serialises to `null` in
    // JSON anyway — but arrives as NaN to any in-process consumer, and
    // `NaN < 24` is false, so an "is this fresh enough" check silently reads
    // it as stale. More importantly, an age of 0 would read as "just ran".
    const summary = buildSummary(
      input({ dast: dast({ scan: scan({ finished_at: 'not-a-date', started_at: 'nope' }) }) }),
    );
    expect(dastBlock(summary)['age_hours']).toBeNull();
  });
});
