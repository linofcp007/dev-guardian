# `validate_finding` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `validate_finding` MCP tool that answers, per finding, whether
anything outside the process can reach the file it lives in — reporting the
verdict and its evidence without suppressing anything or touching severity.

**Architecture:** One tool, three evidence providers sharing one verdict
envelope; this plan delivers the envelope, its table, the tool, and the `static`
provider. `static` builds a file-level import graph from the Semgrep rule pack,
roots it at the route-declaring files in the latest surface snapshot, and gates
the negative verdict on four independent conditions. Pure modules hold every
rule; the orchestrator is glue.

**Tech Stack:** TypeScript (ESM, `"module": "NodeNext"` — `.js` import
specifiers), `node:sqlite` via the existing `Storage`, Semgrep for the import
rules, zod for the input schema, vitest.

**Design of record:** [`docs/superpowers/specs/2026-08-13-validate-finding-design.md`](../specs/2026-08-13-validate-finding-design.md).
Read it before starting. Where this plan and the spec disagree, **the spec
wins** — report the discrepancy rather than silently picking one. That has
happened six times across the previous two features and reporting it was correct
every time.

## Global Constraints

- **Build and test from `mcp/`.** `npm run build`, `npm test`, `npm run test:coverage`.
- **Commit `mcp/dist/`.** The repo *is* the distribution — Claude Code runs
  `mcp/dist/server.js` with no install-time build. Run `npm run build` and stage
  `mcp/dist/` in the **same commit** as any `src/` change.
- TypeScript: `noUncheckedIndexedAccess: true`, `noUnusedLocals`,
  `noUnusedParameters`. **No `!` non-null assertions. No `any`.**
- **ESM import specifiers end in `.js`** even for `.ts` sources.
- **No new runtime dependencies.**
- **`unknown` is the default verdict and every path must earn its way out.**
  Absence of evidence is never `unreachable`. This is the single rule the whole
  feature exists to enforce.
- **No suppression, no severity mutation, anywhere in the diff.** If a diff
  touches `Finding.severity` or writes to `suppressions`, that is a defect.
- **Every cap, truncation and uncovered language is reported**, never silently
  applied.
- **Tests must distinguish the correct implementation from the plausible-wrong
  one.** Seven of ten tasks in the previous feature shipped an assertion that
  passed for both — the most common defect in this codebase. Before writing an
  assertion, name the wrong implementation you are guarding against and confirm
  your assertion fails against it. Prefer exact expected values over predicates.
- **A skipped test must read as a skip** — `it.skipIf`, never `console.warn` +
  bare `return`. `GUARDIAN_REQUIRE_SEMGREP=1` turns absence into a hard failure.
- Markdownlint stays clean for `skills/`, `commands/`, `README.md`.

---

## File Structure

| File | Kind | Responsibility |
| --- | --- | --- |
| `mcp/src/validate/types.ts` | types | The verdict envelope, shared by all three providers. |
| `mcp/src/validate/importGraph.ts` | **pure** | `ImportRecord[]` → adjacency + transitive closure from a root set. |
| `mcp/src/validate/staticProvider.ts` | **pure** | Snapshot + graph + finding → verdict. All four gates. |
| `mcp/src/storage/migrations/003_finding_validations.sql` | schema | |
| `mcp/src/storage/validationsRepo.ts` | I/O | Persist and read verdicts. |
| `mcp/src/storage/index.ts` | modify | Expose the repo on `Storage`. |
| `mcp/src/tools/validateFinding.ts` | orchestrator | Wiring, refusals, result shape. No verdict logic. |
| `mcp/src/registerAll.ts` | modify | Side-effect import (`import './tools/mapAttackSurface.js';` sits at line 69 — add the sibling line). |
| `configs/semgrep/routes.yml` | modify | Import rules for eight stacks; close the named-import gap. |
| `mcp/test/fixtures/...` | test asset | Multi-language fixture with an orphan and a 3-hop file. |

---

## Task 1: The verdict envelope, its table, and the repository

**Files:**

- Create: `mcp/src/validate/types.ts`
- Create: `mcp/src/storage/migrations/003_finding_validations.sql`
- Create: `mcp/src/storage/validationsRepo.ts`
- Modify: `mcp/src/storage/index.ts`
- Test: `mcp/test/unit/storage/validationsRepo.test.ts`

**Interfaces:**

- Consumes: `GuardianDatabase` from `../storage/db.js`; the migration runner
  discovers `NNN_name.sql` files beside itself automatically — no registration.
- Produces: everything in `validate/types.ts`, and
  `ValidationsRepo` with `upsert(rows)`, `listByProject(projectPath)`,
  `getByFingerprint(projectPath, fingerprint)`.

- [ ] **Step 1: Write `mcp/src/validate/types.ts`**

Types-only file; no test. It exists so Tasks 2–6 agree on names.

```ts
/**
 * The verdict envelope, shared by all three evidence providers.
 *
 * Defined once, now, so `runtime` and `dependency` slot in without changing
 * the persisted shape. If either later needs a change here, that is a finding
 * against the design, not against that provider.
 */

export const VERDICTS = ['unreachable', 'reachable', 'confirmed', 'unknown'] as const;
export type Verdict = (typeof VERDICTS)[number];

export const PROVIDERS = ['static', 'runtime', 'dependency'] as const;
export type Provider = (typeof PROVIDERS)[number];

export interface ValidationEvidence {
  /** One concrete, human-readable fact. Never a summary, never a score. */
  detail: string;
}

export interface FindingValidation {
  fingerprint: string;
  verdict: Verdict;
  confidence: 'high' | 'medium' | 'low';
  provider: Provider;
  evidence: ValidationEvidence[];
  /**
   * What this provider could NOT see. Empty only when nothing was missing —
   * a verdict count without these beside it is not an answer.
   */
  coverage_gaps: string[];
  /** The surface snapshot this was computed against. */
  snapshot_id: number;
  /** Tree hash at computation time. A verdict computed against tree N says
   *  nothing once the code moves; readers compare this to decide staleness. */
  tree_hash: string;
  computed_at: string;
}
```

- [ ] **Step 2: Write the migration**

`mcp/src/storage/migrations/003_finding_validations.sql`. The runner picks up
`NNN_name.sql` beside itself — no code change registers it.

```sql
-- 003_finding_validations.sql
-- Verdicts produced by `validate_finding`.
--
-- Its own table, mirroring 002's reasoning: a verdict is a judgment ABOUT a
-- finding, not a finding. Putting it on `findings` would also mean a re-scan
-- that rewrites a findings row silently discards the judgment attached to it.
--
-- (project_path, fingerprint, provider) is the key: one verdict per provider
-- per finding, replaced when recomputed. tree_hash rides along so a reader can
-- tell a current verdict from one computed before the code moved.

CREATE TABLE IF NOT EXISTS finding_validations (
  project_path  TEXT NOT NULL,
  fingerprint   TEXT NOT NULL,
  provider      TEXT NOT NULL,
  verdict       TEXT NOT NULL,
  confidence    TEXT NOT NULL,
  evidence      TEXT NOT NULL,
  coverage_gaps TEXT NOT NULL,
  snapshot_id   INTEGER NOT NULL,
  tree_hash     TEXT NOT NULL,
  computed_at   TEXT NOT NULL,
  PRIMARY KEY (project_path, fingerprint, provider)
);

CREATE INDEX IF NOT EXISTS idx_validations_fingerprint
  ON finding_validations(fingerprint);
```

- [ ] **Step 3: Write the failing test**

Create `mcp/test/unit/storage/validationsRepo.test.ts`. Follow the shape of
`mcp/test/unit/storage/surfaceRepo.test.ts` — read it first for how a repo test
builds an in-memory database and runs migrations.

```ts
import { describe, expect, it } from 'vitest';
import { GuardianDatabase as Database } from '../../../src/storage/db.js';
import { runMigrations } from '../../../src/storage/migrations/runner.js';
import { Storage } from '../../../src/storage/index.js';
import type { FindingValidation } from '../../../src/validate/types.js';

function makeStorage(): Storage {
  const db = new Database(':memory:');
  runMigrations(db);
  return new Storage(db);
}

function row(over: Partial<FindingValidation> = {}): FindingValidation {
  return {
    fingerprint: 'fp1',
    verdict: 'unknown',
    confidence: 'low',
    provider: 'static',
    evidence: [{ detail: 'nothing to say' }],
    coverage_gaps: [],
    snapshot_id: 1,
    tree_hash: 'tree-a',
    computed_at: '2026-08-13T00:00:00.000Z',
    ...over,
  };
}

describe('ValidationsRepo', () => {
  it('round-trips a validation, preserving evidence and gaps as structured data', () => {
    const s = makeStorage();
    s.validations.upsert('/proj', [
      row({ evidence: [{ detail: 'a' }, { detail: 'b' }], coverage_gaps: ['go: no_rules'] }),
    ]);
    const got = s.validations.getByFingerprint('/proj', 'fp1');
    expect(got?.evidence).toEqual([{ detail: 'a' }, { detail: 'b' }]);
    expect(got?.coverage_gaps).toEqual(['go: no_rules']);
    expect(got?.verdict).toBe('unknown');
  });

  it('replaces a verdict for the same (project, fingerprint, provider)', () => {
    // Guards the wrong implementation that INSERTs and leaves both rows: a
    // stale verdict surviving beside a fresh one is worse than no verdict.
    const s = makeStorage();
    s.validations.upsert('/proj', [row({ verdict: 'unknown', tree_hash: 'tree-a' })]);
    s.validations.upsert('/proj', [row({ verdict: 'unreachable', tree_hash: 'tree-b' })]);
    expect(s.validations.listByProject('/proj')).toHaveLength(1);
    const got = s.validations.getByFingerprint('/proj', 'fp1');
    expect(got?.verdict).toBe('unreachable');
    expect(got?.tree_hash).toBe('tree-b');
  });

  it('keeps verdicts from different providers side by side', () => {
    const s = makeStorage();
    s.validations.upsert('/proj', [row({ provider: 'static', verdict: 'reachable' })]);
    s.validations.upsert('/proj', [row({ provider: 'runtime', verdict: 'confirmed' })]);
    expect(s.validations.listByProject('/proj')).toHaveLength(2);
  });

  it('scopes rows by project_path', () => {
    const s = makeStorage();
    s.validations.upsert('/a', [row()]);
    expect(s.validations.listByProject('/b')).toEqual([]);
    expect(s.validations.getByFingerprint('/b', 'fp1')).toBeNull();
  });

  it('returns null for an unknown fingerprint rather than throwing', () => {
    expect(makeStorage().validations.getByFingerprint('/proj', 'nope')).toBeNull();
  });
});
```

- [ ] **Step 4: Run the test to verify it fails**

Run: `cd mcp && npx vitest run test/unit/storage/validationsRepo.test.ts`
Expected: FAIL — `s.validations` is undefined / module not found.

- [ ] **Step 5: Implement the repo and wire it into `Storage`**

Write `mcp/src/storage/validationsRepo.ts` following the prepared-statement
style of `surfaceRepo.ts` (read it first). `evidence` and `coverage_gaps` are
stored as JSON text and parsed on read. Use `INSERT ... ON CONFLICT ... DO
UPDATE` so a recomputation replaces rather than accumulates.

In `mcp/src/storage/index.ts`, add `readonly validations: ValidationsRepo;` and
construct it beside the existing repos.

- [ ] **Step 6: Run the test, then the suite and build**

```bash
cd mcp && npx vitest run test/unit/storage/validationsRepo.test.ts && npm test && npm run build
```

- [ ] **Step 7: Commit**

```bash
git add mcp/src/validate mcp/src/storage mcp/test/unit/storage/validationsRepo.test.ts mcp/dist
git commit -m "feat(validate): verdict envelope, finding_validations table and repo"
```

---

## Task 2: The import graph

**Files:**

- Create: `mcp/src/validate/importGraph.ts`
- Test: `mcp/test/unit/validate/importGraph.test.ts`

**Interfaces:**

- Consumes: `ImportRecord` from `../surface/resolvers/node.js` —
  `{ symbol: string; module_file: string; file: string }`, where `file` contains
  the import statement and `module_file` is what it resolves to.
- Produces:

```ts
export const MAX_GRAPH_EDGES = 20000;
export interface ImportGraph {
  /** importer file → files it imports. Both project-relative, POSIX. */
  edges: ReadonlyMap<string, ReadonlySet<string>>;
  /** Every file that appears as an importer or an import target. */
  files: ReadonlySet<string>;
  /** True when the edge cap cut the graph. Always reported, never silent. */
  truncated: boolean;
}
export function buildImportGraph(records: readonly ImportRecord[]): ImportGraph;
export interface ReachResult {
  /** Minimum hops from any root; 0 means the file IS a root. null = unreached. */
  hops: number | null;
  /** Roots that reach the file, nearest first. Empty when unreached. */
  reachingRoots: string[];
}
export function reachFrom(graph: ImportGraph, roots: readonly string[], target: string): ReachResult;
```

- [ ] **Step 1: Write the failing test**

```ts
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

  it('terminates on a cycle instead of looping forever', () => {
    const g = buildImportGraph([imp('a.ts', 'b.ts'), imp('b.ts', 'a.ts'), imp('b.ts', 'c.ts')]);
    expect(reachFrom(g, ['a.ts'], 'c.ts').hops).toBe(2);
  });
});
```

- [ ] **Step 2: Run to verify it fails.** Expected: module not found.

- [ ] **Step 3: Implement `importGraph.ts`**

Breadth-first from the root set so the first time a file is seen is its minimum
hop count. Keep a `visited` set — the cycle test exists because a naive
depth-first walk hangs. Sort `reachingRoots` by hop count ascending, then by
name for a stable tie-break.

Doc comment must explain *why* the graph is file-level and what it cannot say
(an import is not a call), in the house style of `surface/specDiff.ts`.

- [ ] **Step 4: Run to verify it passes.** Expected: PASS, 11 tests.

- [ ] **Step 5: Suite, build, commit**

```bash
cd mcp && npm test && npm run build
git add mcp/src/validate/importGraph.ts mcp/test/unit/validate mcp/dist
git commit -m "feat(validate): file-level import graph with hop counts"
```

---

## Task 3: Import rules for eight stacks

**Files:**

- Modify: `configs/semgrep/routes.yml`
- Test: `mcp/test/e2e/rulePackFixture.test.ts` (extend), plus fixture files under
  the existing multi-language fixture directory

**Interfaces:**

- Produces: Semgrep matches carrying `metadata.guardian_kind: import` with
  metavariables the extractor already reads for `guardian-import-esm`
  (`$SYMBOL`, `$MODULE`). **Do not invent a new metadata contract** — check how
  `mcp/src/surface/extract.ts` reads import matches and produce the same shape.

- [ ] **Step 1: Read the existing contract before writing any rule**

Read `configs/semgrep/routes.yml`'s `guardian-import-esm` (around line 183) and
the code that consumes it in `mcp/src/surface/extract.ts`. Confirm which
metavariables are read and whether `module_file` resolution expects a relative
specifier. Write down what you found — the next steps depend on it.

- [ ] **Step 2: Close the named-import gap in JS/TS**

`guardian-import-esm` matches only `import $SYMBOL from "$MODULE"` and
`const $SYMBOL = require("$MODULE")`. It misses `import { foo } from "./bar"` and
`import * as ns from "./bar"` — the dominant forms in modern TypeScript. Add
them. This also silently weakened item 1's mount resolution, so it is a
correction as much as an addition; say so in the rule's comment.

- [ ] **Step 3: Add import rules for the other seven stacks**

One rule family per language, `guardian_kind: import`:

- **Python** — `import $M`, `from $M import $S`, including relative `from .x import y`
- **Go** — single and grouped `import` blocks
- **Rust** — `use` including grouped braces
- **PHP** — `use $NS\$C;`
- **Java** — `import $P;` including `static` and wildcard
- **C#** — `using $NS;` including aliased `using $A = $NS;`
- **Ruby** — `require`, `require_relative`, `load`

For each, prefer `focus-metavariable` over post-hoc anchoring where a capture is
needed. **A rule that binds no metavariable, or that Semgrep degrades into
matching every node in the file, is worse than no rule** — item 1's Rust route
rules fabricated four routes for every real one exactly that way.

- [ ] **Step 4: Validate every new rule against a real Semgrep run**

Semgrep is installed but **not on PATH** — it lives under
`%APPDATA%\Roaming\Python\Python314\Scripts`. Add it to PATH for the run.

```bash
semgrep --config configs/semgrep/routes.yml --json <fixture-dir> | \
  node -e "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{const j=JSON.parse(s);console.log('errors:',JSON.stringify(j.errors));const k={};for(const r of j.results){const m=r.extra.metadata.guardian_kind;k[m]=(k[m]||0)+1}console.log(k)})"
```

**`errors` must be empty.** Five NestJS rules once shipped with a parse error
that made them match nothing on every run, and the suite was green. Report the
per-`guardian_kind` counts you measured.

- [ ] **Step 5: Extend the fixture and the e2e assertion**

Add small files to the multi-language fixture so each new language has at least
one import to match. Extend `rulePackFixture.test.ts` with an assertion on the
**exact set** of languages that produced an import match — not a count, which
passes when one rule breaks and another over-matches.

- [ ] **Step 6: Full suite with Semgrep required, then commit**

```bash
cd mcp && GUARDIAN_REQUIRE_SEMGREP=1 npm test && npm run build
git add configs/semgrep/routes.yml mcp/test mcp/dist
git commit -m "feat(surface): import rules for all eight stacks, and named imports in JS/TS"
```

---

## Task 4: The static provider and its four gates

**Files:**

- Create: `mcp/src/validate/staticProvider.ts`
- Test: `mcp/test/unit/validate/staticProvider.test.ts`

**Interfaces:**

- Consumes: `ImportGraph`, `reachFrom` (Task 2); `FindingValidation`,
  `ValidationEvidence` (Task 1); `AttackSurfaceSnapshot`, `CoverageEntry`,
  `Finding` from `../types.js`.
- Produces:

```ts
export const RUNTIME_RESOLUTION_LANGUAGES: ReadonlySet<string>;  // ruby, java, csharp, php
export interface StaticProviderInput {
  snapshot: AttackSurfaceSnapshot;
  snapshotId: number;
  treeHash: string;
  graph: ImportGraph;
  findings: readonly Finding[];
  /** file_path of every persisted scan_dast anonymous_exposure finding. */
  anonymouslyExposedRouteFiles: ReadonlySet<string>;
  computedAt: string;              // injected, never Date.now() — keeps this pure
  /** Files whose language could not be determined. */
  languageOf: (filePath: string) => string | null;
}
export function validateStatically(input: StaticProviderInput): FindingValidation[];
```

- [ ] **Step 1: Write the failing test**

The load-bearing set is one named test per path that yields `unknown` instead of
`unreachable`. Each is an opportunity to deprioritise something exploitable.

```ts
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
  return { language: 'typescript', detected: true, routes_found: 1, unreadable_matches: 0, status: 'ok', ...over };
}

function finding(over: Partial<Finding> = {}): Finding {
  return {
    fingerprint: 'fp1', tool: 'semgrep', severity: 'high', category: 'security',
    title: 'SQL injection', file_path: 'src/db.ts', line_start: 88, fix_available: false,
    ...over,
  };
}

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
    const v = validateStatically(input({
      anonymouslyExposedRouteFiles: new Set(['src/routes.ts']),
    }))[0];
    expect(v?.evidence.some((e) => /anonymous/i.test(e.detail))).toBe(true);
  });

  it('says nothing about anonymous exposure when no DAST scan supplied one', () => {
    // Guards the wrong implementation that reports "not anonymously exposed"
    // when it simply does not know — the inverse of the truth.
    const v = validateStatically(input())[0];
    expect(v?.evidence.some((e) => /anonymous/i.test(e.detail))).toBe(false);
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
```

- [ ] **Step 2: Run to verify it fails.** Expected: module not found.

- [ ] **Step 3: Implement `staticProvider.ts`**

Gate order for the negative verdict — **all four must hold**, and the first that
fails decides the `unknown` and names itself in `coverage_gaps`:

1. The finding has a `file_path` and its language is determinable.
2. The snapshot's `CoverageEntry` for that language has status `ok` or
   `no_matches` (see the table in design §5.2 — `no_matches` permitting the
   negative is the non-obvious half).
3. The language is not in `RUNTIME_RESOLUTION_LANGUAGES` (`ruby`, `java`,
   `csharp`, `php`).
4. The graph was not truncated.

Confidence: `high` for 0 hops; `medium` for a reached file; `medium` for
`unreachable` (it is a claim about an over-approximating graph); `low` for
`unknown`.

Every function under ~30 lines. The doc comment must state the asymmetry — this
module is far better at disproving reachability than proving it — and why each
gate exists, in the house style.

- [ ] **Step 4: Run to verify it passes**, then suite, build, commit

```bash
cd mcp && npx vitest run test/unit/validate/staticProvider.test.ts && npm test && npm run build
git add mcp/src/validate/staticProvider.ts mcp/test/unit/validate mcp/dist
git commit -m "feat(validate): the static provider and the four gates on the negative verdict"
```

---

## Task 5: The orchestrator and the tool contract

**Files:**

- Create: `mcp/src/tools/validateFinding.ts`
- Modify: `mcp/src/registerAll.ts` (side-effect import beside line 69's
  `import './tools/mapAttackSurface.js';`)
- Test: `mcp/test/integration/validateFinding.test.ts`

**Interfaces:**

- Consumes: everything from Tasks 1–4; `resolveProjectPath`
  (`../platform/projectPath.js`), `computeTreeHash` (`../treeHash/computeTreeHash.js`),
  `ctx.storage.surface.getLatest()`, `ctx.storage.findings.listOpen()`.
- Produces: the registered `validate_finding` tool.

Read `mcp/src/tools/mapAttackSurface.ts` for the house shape of a tool module:
zod `inputSchema` (a raw shape, not a `ZodObject`), `handler`,
`registerToolModule(tool)`, `ToolResult<T>` returns.

- [ ] **Step 1: Write the failing integration test**

The refusal paths are the highest-value tests here — each must be a *distinct*
result, never an empty batch.

```ts
describe('validate_finding', () => {
  it('refuses with no_surface_snapshot, naming map_attack_surface', async () => {
    const r = await tool().handler({ project_path: p }, ctx) as { ok: false; error: { code: string; message: string } };
    expect(r.ok).toBe(false);
    expect(r.error.code).toBe('no_surface_snapshot');
    expect(r.error.message).toMatch(/map_attack_surface/);
  });

  it('errors on an unknown fingerprint rather than returning an empty batch', async () => {
    seedSnapshot(ctx); seedFinding(ctx, 'fp1');
    const r = await tool().handler({ project_path: p, fingerprint: 'nope' }, ctx) as { ok: false; error: { code: string } };
    expect(r.ok).toBe(false);
  });

  it('validates every open finding when no fingerprint is given', async () => { /* exact count */ });

  it('persists each verdict and returns it with the summary', async () => { /* asserts db rows === result length */ });

  it('reports provider-level coverage gaps in the summary, not only per finding', async () => { /* ... */ });

  it('flags a stored verdict as stale when the tree hash has moved', async () => {
    // The load-bearing one: a verdict computed against tree N says nothing
    // after the code moves, and serving it as current is the failure class
    // this project exists to prevent.
  });

  it('never writes to suppressions and never changes a finding severity', async () => {
    // Read the finding rows before and after; assert severity is byte-identical
    // and the suppressions table is untouched.
  });
});
```

- [ ] **Step 2: Run to verify it fails.** Expected: `validate_finding` not registered.

- [ ] **Step 3: Implement `validateFinding.ts`**

Order of operations, each stop a *distinct* outcome:

1. `resolveProjectPath` → `not_a_git_repo`.
2. `ctx.storage.surface.getLatest()` → `no_surface_snapshot`, message naming
   `map_attack_surface`.
3. Select findings: `fingerprint` given → that one, error if absent; else every
   open finding.
4. Build the graph from the snapshot's import records; derive roots from
   `snapshot.routes.map(r => r.file)` (deduped).
5. Collect `anonymouslyExposedRouteFiles` from persisted `scan_dast` findings
   whose `subcategory` is `anonymous_exposure` — absent a DAST scan, an empty
   set, and the summary says a DAST scan was unavailable.
6. `validateStatically(...)` with `computedAt` from the orchestrator (the
   provider stays pure).
7. Persist via `ctx.storage.validations.upsert`.
8. Return validations + a summary: counts by verdict, provider-level
   `coverage_gaps`, whether a DAST scan was available and its age.

**No verdict logic in this file.** If a status-code, language or hop decision
appears here, it belongs in `staticProvider.ts`.

The tool `description` is an agent's only discovery surface — for
`map_attack_surface` that turned out to be literally true and had to be
rewritten late. State: what it answers, that it requires a prior
`map_attack_surface` run, that it suppresses nothing and changes no severity,
and that `unreachable` is unavailable in runtime-resolution stacks.

- [ ] **Step 4: Run to verify it passes**, then suite, build, commit

```bash
cd mcp && npm test && npm run build
git add mcp/src/tools/validateFinding.ts mcp/src/registerAll.ts mcp/test/integration/validateFinding.test.ts mcp/dist
git commit -m "feat(validate): validate_finding orchestrator, persistence and refusals"
```

---

## Task 6: End-to-end, and the discovery surface

**Files:**

- Test: `mcp/test/e2e/validateFindingFixture.test.ts`
- Fixture: extend the existing multi-language fixture with a genuinely orphaned
  file and one reachable at three hops
- Modify: `host-rules/AGENTS.md` and its paired host-context files,
  `CHANGELOG.md`, `README.md`

- [ ] **Step 1: Build the fixture and the e2e**

Run the real chain: `map_attack_surface` → `validate_finding` over seeded
findings, one in the orphan and one in the 3-hop file. Assert the **exact
verdict per finding**, and that the orphan's is `unreachable` while the 3-hop
file's is `reachable` with `hops === 3`. Both directions measured, not reasoned
about. `it.skipIf` with `GUARDIAN_REQUIRE_SEMGREP=1`.

- [ ] **Step 2: Measure the tool count and update every place it appears**

```bash
cd mcp && node -e "import('./dist/registerAll.js').then(()=>import('./dist/tools/index.js')).then(m=>console.log(m.TOOLS.length))"
grep -rn "5[0-9] tools\|5[0-9] MCP" --include=*.md --include=*.json .. | grep -v node_modules
```

The previous feature found **ten** files carrying a stale count. Update each to
the measured number; do not assume.

- [ ] **Step 3: Document the flow and the honest limits**

`host-rules/AGENTS.md` (and every paired host file — this repo keeps them in
sync) gains `map_attack_surface` → `validate_finding` as an intent mapping.

The CHANGELOG entry states the limits in the same breath as the feature, from
design §11: file granularity (a finding in an uncalled helper reads
`reachable`); `unreachable` unavailable in Ruby/Java/C#/PHP and wherever a
dynamic import cannot be resolved; reachability is computed from route entry
points only, so a file reached solely by a CLI or a cron job reads as
unreachable-by-route, **which is not a claim that the code never runs**.

- [ ] **Step 4: Full verification gate**

```bash
cd mcp && npm run build && GUARDIAN_REQUIRE_SEMGREP=1 npm test && npm run test:coverage
npx markdownlint-cli2 "skills/**/*.md" "commands/**/*.md" "README.md"
```

Report the exact skip count — target **zero** — and all four coverage numbers
against thresholds 70/62/72/70.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "docs(validate): document validate_finding and its honest limits"
```

---

## Self-Review Notes

Checked against the spec:

- §3 architecture / new files → Tasks 1, 2, 4, 5 create all of them.
- §4 envelope → Task 1, including `confirmed` present-but-unused so the
  persisted shape does not change when `runtime` lands.
- §5.1–5.4 the four gates → Task 4, one named test each, plus the `no_matches`
  case that permits the negative.
- §6 rule pack → Task 3, with the real-Semgrep validation step and the empty
  `errors` requirement.
- §7 evidence → Task 4's positive-direction tests, including the "says nothing
  when it does not know" guard on anonymous exposure.
- §8 persistence → Tasks 1 and 5, with the staleness test in Task 5.
- §9 tool contract → Task 5; batch default and unknown-fingerprint-is-an-error
  both pinned.
- §10 testing → the test files named in each task, plus Task 6's e2e.
- §11 limitations → Task 6's CHANGELOG entry carries them verbatim.
- §12 definition of done → Task 6 Step 4 is the gate.

Type consistency: `FindingValidation` is defined once in Task 1 and consumed by
Tasks 4 and 5. `ImportGraph`/`reachFrom` are defined in Task 2 and consumed by
Task 4. `StaticProviderInput.computedAt` is injected by Task 5 so Task 4 stays
pure — no `Date.now()` anywhere in `validate/`.
