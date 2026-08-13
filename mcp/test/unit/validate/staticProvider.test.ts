import { describe, expect, it } from 'vitest';
import { validateStatically, type StaticProviderInput } from '../../../src/validate/staticProvider.js';
import { buildImportGraph } from '../../../src/validate/importGraph.js';
import type { ImportRecord } from '../../../src/surface/resolvers/node.js';
import type { AttackSurfaceSnapshot, CoverageEntry, Finding, RouteRecord } from '../../../src/types.js';

function imp(file: string, module_file: string): ImportRecord {
  return { symbol: 'x', file, module_file };
}

function route(over: Partial<RouteRecord> = {}): RouteRecord {
  return {
    method: 'GET', provenance: 'code', path_raw: '/users', path_resolved: '/users',
    path_partial: false, file: 'src/routes.ts', line: 1, framework: 'express',
    language: 'typescript', auth_hint: 'unknown', params: [], confidence: 'high',
    ...over,
  };
}

function coverage(over: Partial<CoverageEntry> = {}): CoverageEntry {
  return {
    language: 'typescript', detected: true, routes_found: 1, unreadable_matches: 0,
    unresolved_imports: 0, status: 'ok', ...over,
  };
}

function finding(over: Partial<Finding> = {}): Finding {
  return {
    fingerprint: 'fp1', tool: 'semgrep', severity: 'high', category: 'security',
    title: 'SQL injection', file_path: 'src/db.ts', line_start: 88, fix_available: false,
    ...over,
  };
}

// Deliberately NOT a prefix of any relative-looking test path ('src/...') below,
// so every given test's paths pass through `toRelativeIfPossible` unchanged —
// this default exists only so `projectPath` is never accidentally `undefined`
// in a test that does not care about it. Tests that DO care (the path-
// convention describe block) override it explicitly.
const DEFAULT_PROJECT_PATH = 'C:\\project';

function input(over: Partial<StaticProviderInput> = {}): StaticProviderInput {
  const snapshot = {
    routes: [route()], env_vars: [], ports: [], webhooks: [],
    coverage: [coverage()], tools_run: [], missing_tools: [],
    spec_files: [], spec_diff: null,
  } as unknown as AttackSurfaceSnapshot;
  return {
    snapshot,
    snapshotId: 1,
    treeHash: 'tree-a',
    graph: buildImportGraph([imp('src/routes.ts', 'src/db.ts')]),
    findings: [finding()],
    anonymouslyExposedRouteFiles: new Set<string>(),
    computedAt: '2026-08-13T00:00:00.000Z',
    languageOf: () => 'typescript',
    projectPath: DEFAULT_PROJECT_PATH,
    ...over,
  };
}

describe('validateStatically — the positive direction', () => {
  it('reports reachable with the hop count and the nearest route', () => {
    const v = validateStatically(input())[0];
    expect(v?.verdict).toBe('reachable');
    expect(v?.evidence.some((e) => e.detail.includes('GET /users'))).toBe(true);
    expect(v?.evidence.some((e) => e.detail.includes('1 hop'))).toBe(true);
  });

  it('reports 0 hops and high confidence when the finding IS in a route file', () => {
    const v = validateStatically(input({ findings: [finding({ file_path: 'src/routes.ts' })] }))[0];
    expect(v?.verdict).toBe('reachable');
    expect(v?.confidence).toBe('high');
    expect(v?.evidence.some((e) => e.detail.includes('0 hops'))).toBe(true);
  });

  it('names an anonymously exposed reaching route when one is known', () => {
    // Realistic data, not a convenience shortcut: dast/analyze.ts sets a
    // route-derived finding's file_path to `route.file` verbatim (no
    // relativization anywhere in that path), so a real
    // anonymouslyExposedRouteFiles set is absolute, native-separator — the
    // SAME string route.file would be, not pre-relativized POSIX. A wrong
    // implementation that compares this set against relativized
    // reachingRoots without relativizing the set itself never matches.
    const projectPath = 'C:\\Users\\dev\\app';
    const v = validateStatically(input({
      projectPath,
      snapshot: {
        ...input().snapshot,
        routes: [route({ file: 'C:\\Users\\dev\\app\\src\\routes.ts' })],
      },
      graph: buildImportGraph([imp('src/routes.ts', 'src/db.ts')]),
      anonymouslyExposedRouteFiles: new Set(['C:\\Users\\dev\\app\\src\\routes.ts']),
    }))[0];
    expect(v?.evidence.some((e) => /anonymous/i.test(e.detail))).toBe(true);
  });

  it('says nothing about anonymous exposure when no DAST scan supplied one', () => {
    // Guards the wrong implementation that reports "not anonymously exposed"
    // when it simply does not know — the inverse of the truth.
    const v = validateStatically(input())[0];
    expect(v?.evidence.some((e) => /anonymous/i.test(e.detail))).toBe(false);
  });

  it('reports how many routes reach the file out of how many known routes', () => {
    // Two routes: one at the reaching file, one elsewhere that reaches
    // nothing — a wrong implementation that counts ALL known routes as
    // "reaching" (instead of only those at a file reachFrom actually found)
    // would report "2 of 2", not "1 of 2".
    const v = validateStatically(input({
      snapshot: {
        ...input().snapshot,
        routes: [route(), route({ file: 'src/unrelated.ts', path_resolved: '/orders' })],
      },
    }))[0];
    expect(v?.evidence.some((e) => e.detail.includes('1 of 2'))).toBe(true);
  });

  it('groups multiple routes registered in the same file under one root, and counts both', () => {
    // Two routes at the SAME file: the nearest-route pick must be
    // deterministic (first in input order, not whichever the grouping
    // happens to visit last), and the total must count both, not collapse
    // them to one because they share a root.
    const v = validateStatically(input({
      snapshot: {
        ...input().snapshot,
        routes: [route(), route({ method: 'POST', path_resolved: '/users' })],
      },
    }))[0];
    expect(v?.verdict).toBe('reachable');
    expect(v?.evidence.some((e) => e.detail.includes('GET /users'))).toBe(true);
    expect(v?.evidence.some((e) => e.detail.includes('2 of 2'))).toBe(true);
  });

  it('does not use a spec-provenance route as a reachability root', () => {
    // A spec route's `file` is the spec document, not a code file — it must
    // never act as a graph root. A wrong implementation that roots on every
    // route regardless of provenance would see this spec route's `file`
    // equal the finding's `file_path` and report 0-hop `reachable`.
    const v = validateStatically(input({
      snapshot: {
        ...input().snapshot,
        routes: [route(), route({ provenance: 'spec', file: 'src/other-target.ts' })],
      },
      graph: buildImportGraph([imp('src/routes.ts', 'src/nowhere.ts')]),
      findings: [finding({ file_path: 'src/other-target.ts' })],
    }))[0];
    expect(v?.verdict).toBe('unreachable');
  });
});

describe('validateStatically — unknown, never unreachable', () => {
  const orphanGraph = buildImportGraph([imp('src/routes.ts', 'src/other.ts')]);
  const orphan = { graph: orphanGraph, findings: [finding({ file_path: 'src/db.ts' })] };

  it('reports unreachable when all four gates pass', () => {
    const v = validateStatically(input(orphan))[0];
    expect(v?.verdict).toBe('unreachable');
  });

  it('is unknown when the language has no import rules (coverage no_rules)', () => {
    const v = validateStatically(input({
      ...orphan,
      snapshot: { ...input().snapshot, coverage: [coverage({ status: 'no_rules' })] },
    }))[0];
    expect(v?.verdict).toBe('unknown');
    expect(v?.coverage_gaps.some((g) => g.includes('no_rules'))).toBe(true);
  });

  it('is unknown when routes were matched but unreadable', () => {
    const v = validateStatically(input({
      ...orphan,
      snapshot: { ...input().snapshot, coverage: [coverage({ status: 'unreadable' })] },
    }))[0];
    expect(v?.verdict).toBe('unknown');
  });

  it('is unknown when no coverage entry exists at all for the language', () => {
    // Distinct from 'no_rules': here the language is not even MENTIONED in
    // coverage, e.g. a stale/missing stack-detection run. A wrong
    // implementation that treats "no entry found" as passing gate 2 (by
    // defaulting to some permissive status) would report unreachable.
    const v = validateStatically(input({
      ...orphan,
      snapshot: { ...input().snapshot, coverage: [] },
    }))[0];
    expect(v?.verdict).toBe('unknown');
  });

  it('STILL reports unreachable when the language legitimately declares no routes', () => {
    // no_matches means the rules ran and found nothing, so no route in this
    // language can reach anything. The strict reading ("only ok") would answer
    // unknown for every file in every language with no HTTP surface.
    const v = validateStatically(input({
      ...orphan,
      snapshot: { ...input().snapshot, coverage: [coverage({ status: 'no_matches', routes_found: 0 })] },
    }))[0];
    expect(v?.verdict).toBe('unreachable');
  });

  it('is unknown in a runtime-resolution stack, even with a clean graph', () => {
    for (const language of ['ruby', 'java', 'csharp', 'php']) {
      const v = validateStatically(input({
        ...orphan,
        languageOf: () => language,
        snapshot: { ...input().snapshot, coverage: [coverage({ language, status: 'ok' })] },
      }))[0];
      expect(v?.verdict, language).toBe('unknown');
      expect(v?.coverage_gaps.some((g) => /runtime|inject|autoload|container/i.test(g)), language).toBe(true);
    }
  });

  it('is unknown when the graph was truncated', () => {
    const truncated = { ...orphanGraph, truncated: true };
    const v = validateStatically(input({ ...orphan, graph: truncated }))[0];
    expect(v?.verdict).toBe('unknown');
  });

  it('is unknown when the finding has no file_path at all', () => {
    const v = validateStatically(input({ findings: [finding({ file_path: undefined })] }))[0];
    expect(v?.verdict).toBe('unknown');
  });

  it('is unknown when the file language cannot be determined', () => {
    const v = validateStatically(input({ ...orphan, languageOf: () => null }))[0];
    expect(v?.verdict).toBe('unknown');
  });

  it('carries the snapshot id and tree hash onto every verdict', () => {
    // Not decoration: these two are what lets a reader tell a current verdict
    // from one computed before the code moved.
    const v = validateStatically(input({ snapshotId: 42, treeHash: 'tree-z' }))[0];
    expect(v?.snapshot_id).toBe(42);
    expect(v?.tree_hash).toBe('tree-z');
  });

  it('returns one verdict per finding, in input order', () => {
    const out = validateStatically(input({
      findings: [finding({ fingerprint: 'a' }), finding({ fingerprint: 'b' })],
    }));
    expect(out.map((v) => v.fingerprint)).toEqual(['a', 'b']);
  });
});

describe('validateStatically — unresolved imports are reported, never gating', () => {
  const orphanGraph = buildImportGraph([imp('src/routes.ts', 'src/other.ts')]);
  const orphan = { graph: orphanGraph, findings: [finding({ file_path: 'src/db.ts' })] };

  it('does not block the negative verdict on unresolved imports alone, but still reports them', () => {
    const v = validateStatically(input({
      ...orphan,
      snapshot: { ...input().snapshot, coverage: [coverage({ status: 'ok', unresolved_imports: 3 })] },
    }))[0];
    expect(v?.verdict).toBe('unreachable');
    expect(v?.coverage_gaps.some((g) => g.includes('3'))).toBe(true);
  });

  it('reports unresolved imports as a coverage gap even on a reachable verdict', () => {
    const v = validateStatically(input({
      snapshot: { ...input().snapshot, coverage: [coverage({ unresolved_imports: 4 })] },
    }))[0];
    expect(v?.verdict).toBe('reachable');
    expect(v?.coverage_gaps.some((g) => g.includes('4'))).toBe(true);
  });

  it('reports nothing when there are zero unresolved imports', () => {
    const v = validateStatically(input(orphan))[0];
    expect(v?.coverage_gaps).toEqual([]);
  });
});

describe('validateStatically — path conventions', () => {
  // Task 3b's review: snapshot.imports (and therefore every ImportGraph key)
  // is project-relative POSIX, but snapshot.routes[].file is absolute with
  // native separators — toRoute() assigns it verbatim from Semgrep's
  // results[].path and nothing relativizes it upstream. Rooting reachFrom at
  // route.file as-is means `root === target` never holds and `edges.get(root)`
  // never resolves, so every verdict comes back the negative — universally,
  // silently. This is the load-bearing test for that failure mode.
  it('relativizes an absolute, native-separator route file before rooting the graph', () => {
    const projectPath = 'C:\\Users\\dev\\app';
    const v = validateStatically(input({
      projectPath,
      snapshot: {
        ...input().snapshot,
        routes: [route({ file: 'C:\\Users\\dev\\app\\src\\routes.ts' })],
      },
      graph: buildImportGraph([imp('src/routes.ts', 'src/db.ts')]),
      findings: [finding({ file_path: 'src/db.ts' })],
    }))[0];
    expect(v?.verdict).toBe('reachable');
    expect(v?.evidence.some((e) => e.detail.includes('1 hop'))).toBe(true);
  });

  it('relativizes an absolute, native-separator finding file_path too', () => {
    const projectPath = 'C:\\Users\\dev\\app';
    const v = validateStatically(input({
      projectPath,
      graph: buildImportGraph([imp('src/routes.ts', 'src/db.ts')]),
      findings: [finding({ file_path: 'C:\\Users\\dev\\app\\src\\db.ts' })],
    }))[0];
    expect(v?.verdict).toBe('reachable');
  });
});
