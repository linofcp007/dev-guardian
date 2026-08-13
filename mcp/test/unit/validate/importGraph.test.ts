import { describe, expect, it } from 'vitest';
import { buildImportGraph, reachFrom, MAX_GRAPH_EDGES } from '../../../src/validate/importGraph.js';
import type { ImportRecord } from '../../../src/surface/resolvers/node.js';

function imp(file: string, module_file: string): ImportRecord {
  return { symbol: 'x', file, module_file };
}

describe('buildImportGraph', () => {
  it('builds directed edges from importer to imported', () => {
    const g = buildImportGraph([imp('a.ts', 'b.ts'), imp('a.ts', 'c.ts')]);
    expect([...(g.edges.get('a.ts') ?? [])].sort()).toEqual(['b.ts', 'c.ts']);
    // Direction matters: a wrong implementation that reverses the edge would
    // also produce "some" adjacency, and every reachability answer would be
    // backwards.
    expect(g.edges.get('b.ts')).toBeUndefined();
  });

  it('records every file on either end, so an import target with no imports of its own is known', () => {
    const g = buildImportGraph([imp('a.ts', 'b.ts')]);
    expect([...g.files].sort()).toEqual(['a.ts', 'b.ts']);
  });

  it('collapses duplicate edges', () => {
    const g = buildImportGraph([imp('a.ts', 'b.ts'), imp('a.ts', 'b.ts')]);
    expect([...(g.edges.get('a.ts') ?? [])]).toEqual(['b.ts']);
  });

  it('reports truncation when the edge cap cuts the graph, and does not report it otherwise', () => {
    const many = Array.from({ length: MAX_GRAPH_EDGES + 1 }, (_, i) => imp('a.ts', `m${i}.ts`));
    expect(buildImportGraph(many).truncated).toBe(true);
    expect(buildImportGraph([imp('a.ts', 'b.ts')]).truncated).toBe(false);
  });

  it('counts distinct edges, not records, so duplicates cannot exhaust the cap', () => {
    // The same edge repeated past the cap. An implementation that charges the
    // cap per record scanned rather than per distinct edge accepted reports
    // truncated: true here.
    const same = Array.from({ length: MAX_GRAPH_EDGES + 1 }, () => imp('a.ts', 'b.ts'));
    const g = buildImportGraph(same);
    expect(g.truncated).toBe(false);
    expect([...(g.edges.get('a.ts') ?? [])]).toEqual(['b.ts']);
  });
});

describe('reachFrom', () => {
  const chain = buildImportGraph([
    imp('routes.ts', 'service.ts'),
    imp('service.ts', 'db.ts'),
    imp('db.ts', 'util.ts'),
  ]);

  it('returns 0 hops when the target IS a root', () => {
    expect(reachFrom(chain, ['routes.ts'], 'routes.ts')).toEqual({
      hops: 0,
      reachingRoots: ['routes.ts'],
    });
  });

  it('counts hops transitively', () => {
    expect(reachFrom(chain, ['routes.ts'], 'util.ts').hops).toBe(3);
  });

  it('returns null hops and no roots for an unreached file', () => {
    const g = buildImportGraph([imp('routes.ts', 'service.ts'), imp('orphan.ts', 'lonely.ts')]);
    expect(reachFrom(g, ['routes.ts'], 'lonely.ts')).toEqual({ hops: null, reachingRoots: [] });
  });

  it('returns null for a file absent from the graph entirely', () => {
    expect(reachFrom(chain, ['routes.ts'], 'never-seen.ts').hops).toBeNull();
  });

  it('reports the MINIMUM hop count across several roots, and lists them nearest first', () => {
    // Exact values, not "contains": a wrong implementation that returns the
    // first root found rather than the nearest would still list both.
    const g = buildImportGraph([
      imp('far.ts', 'mid.ts'),
      imp('mid.ts', 'target.ts'),
      imp('near.ts', 'target.ts'),
    ]);
    const r = reachFrom(g, ['far.ts', 'near.ts'], 'target.ts');
    expect(r.hops).toBe(1);
    expect(r.reachingRoots).toEqual(['near.ts', 'far.ts']);
  });

  it('breaks an equal-hop tie by name, so the order is stable across runs', () => {
    // Both roots are 1 hop away, so the primary sort cannot decide this —
    // only the tie-break can. Insertion order is deliberately the reverse of
    // alphabetical, so an implementation that drops the tie-break returns
    // ['zebra.ts', 'apple.ts'] and fails here.
    const g = buildImportGraph([imp('zebra.ts', 'target.ts'), imp('apple.ts', 'target.ts')]);
    const r = reachFrom(g, ['zebra.ts', 'apple.ts'], 'target.ts');
    expect(r.hops).toBe(1);
    expect(r.reachingRoots).toEqual(['apple.ts', 'zebra.ts']);
  });

  it('terminates on a cycle instead of looping forever', () => {
    const g = buildImportGraph([imp('a.ts', 'b.ts'), imp('b.ts', 'a.ts'), imp('b.ts', 'c.ts')]);
    expect(reachFrom(g, ['a.ts'], 'c.ts').hops).toBe(2);
  });
});
