# OpenAPI Spec Import Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Import OpenAPI 3.x and Swagger 2.0 documents found in the repository, and report the difference between what the specs declare and what the code registers — shadow endpoints and dead documentation.

> **Checkbox audit — 2026-08-22.** These boxes were ticked retrospectively, by
> reconciling every step against the shipped code, its tests and `git log`. They
> were **not** ticked during execution, so they are an audit of the result, not a
> live record of the run. Steps whose only product is an observation ("run the
> test, expected: FAIL", "RED first", "commit with this subject") cannot be
> verified after the fact; each was ticked on the artefact it was meant to leave
> behind — the named test file, or the named commit in `git log` — never on
> evidence that anyone watched it go red.
> Nothing in this plan was left unticked.

**Architecture:** `map_attack_surface` stays the only entry point. Inside, the Semgrep invocation moves out to its own I/O module, and three new modules are added: spec discovery (I/O), spec import (pure) and spec diffing (pure). Every module that makes a decision is pure and testable with no scanner, no disk and no network — the split that held up across the whole `map_attack_surface` build, while every defect came from a layer that read files and decided at once.

**Tech Stack:** TypeScript (ESM, NodeNext), `yaml` (promoted to a runtime dependency), Node's `node:sqlite`, vitest, Semgrep.

**Spec:** [`docs/superpowers/specs/2026-08-12-openapi-spec-import-design.md`](../specs/2026-08-12-openapi-spec-import-design.md)

## Global Constraints

Every task's requirements implicitly include this section.

- **Working directory is `mcp/`** for all npm commands.
- **ESM `"module": "NodeNext"`** — every relative import specifier ends in `.js`, even when importing a `.ts` file.
- **`noUncheckedIndexedAccess: true`** — every array index and `Record` lookup yields `T | undefined`. Guard before use; never use `!`.
- **`noUnusedLocals` / `noUnusedParameters` are on** — prefix intentionally-unused parameters with `_`.
- **`npm test` is `vitest run` and does NOT check coverage.** `npm run test:coverage` is the only run that enforces the thresholds (statements 70, branches 62, functions 72, lines 70).
- **Semgrep-dependent e2e tests skip visibly** via `it.skipIf` and hard-fail under `GUARDIAN_REQUIRE_SEMGREP=1`. Semgrep on this machine is at `C:\Users\Administrator\AppData\Roaming\Python\Python314\Scripts` and is **not** on the system PATH — export it, or you are testing nothing.
- **Baseline at branch point: 578 passed / 0 skipped** with the gate on. Do not regress it.
- **Commit `mcp/dist/` in the same commit as any TypeScript change.** The repo IS the distribution; Claude Code runs `mcp/dist/server.js` with no install-time build.
- **`npm run build` is `tsc` + `copy-assets.mjs` + `bundle.mjs`.** All three must succeed.
- **Do not bump versions.** `.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json` and `mcp/package.json` stay at 1.2.1; `CHANGELOG.md` keeps its `Unreleased` heading.

---

## File Structure

| Path | Responsibility | Purity |
| --- | --- | --- |
| `mcp/src/surface/scanSemgrep.ts` (create) | Probe for Semgrep, run it natively or via Docker, return the tool-run record | I/O |
| `mcp/src/surface/specDiscover.ts` (create) | Find candidate spec files, read them, enforce caps | I/O |
| `mcp/src/surface/specImport.ts` (create) | One document's text → routes + report | **pure** |
| `mcp/src/surface/specDiff.ts` (create) | Code routes × spec routes → `SpecDiff` | **pure** |
| `mcp/src/types.ts` (modify) | `RouteProvenance`, `SpecFileReport`, `SpecDiffEntry`, `SpecDiff`; `RouteRecord.provenance`; snapshot fields | — |
| `mcp/src/surface/extract.ts` (modify) | Set `provenance: 'code'` on extracted routes | pure |
| `mcp/src/storage/surfaceRepo.ts` (modify) | Backfill `provenance` on read for pre-existing snapshots | — |
| `mcp/src/tools/mapAttackSurface.ts` (modify) | Coordination only; gains the spec stages, loses the Semgrep invocation | I/O |

Tests mirror the source tree under `mcp/test/unit/surface/`.

---

### Task 1: Extract the Semgrep invocation

A behaviour-preserving move. It must land first, because every later task adds to a file that is already doing too much.

**Files:**

- Create: `mcp/src/surface/scanSemgrep.ts`
- Modify: `mcp/src/tools/mapAttackSurface.ts` (remove `invokeSemgrep`, `buildToolRun`, and the now-unused `copyFileSync` / `dockerScanner` / `processRunner` imports; import from the new module)
- Test: `mcp/test/unit/surface/scanSemgrep.test.ts`

**Interfaces:**

- Consumes: `runProcess` + `ProcessRunResult` from `runners/processRunner.js`; `buildSemgrepDockerArgs`, `toContainerPath`, `DEFAULT_SEMGREP_IMAGE` from `runners/dockerScanner.js`; `scannerAvailable` from `tools/scanHelpers.js`; `ToolRun` from `types.js`.
- Produces:

```ts
export interface SemgrepRunOptions {
  projectPath: string;
  rulesPath: string;
  outFile: string;
  reportDir: string;
}

/** `null` means neither Semgrep nor Docker is available. */
export async function invokeSemgrep(
  options: SemgrepRunOptions,
): Promise<{ toolRun: ToolRun } | null>;

export function buildToolRun(run: ProcessRunResult, via?: string): ToolRun;
```

The current implementation takes four positional strings. Moving to an options object is part of the move: four adjacent `string` parameters is a call site waiting to be transposed silently.

- [x] **Step 1: Write the failing test**

Create `mcp/test/unit/surface/scanSemgrep.test.ts`:

```ts
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../src/tools/scanHelpers.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/tools/scanHelpers.js')>();
  return { ...actual, scannerAvailable: vi.fn() };
});
vi.mock('../../../src/runners/processRunner.js', () => ({ runProcess: vi.fn() }));

import { runProcess, type ProcessRunResult } from '../../../src/runners/processRunner.js';
import { scannerAvailable } from '../../../src/tools/scanHelpers.js';
import { buildToolRun, invokeSemgrep } from '../../../src/surface/scanSemgrep.js';

function run(outcome: ProcessRunResult['outcome'], exitCode: number, stderr = ''): ProcessRunResult {
  return { outcome, exitCode, stdout: '', stderr, truncated: false };
}

const OPTS = {
  projectPath: '/p',
  rulesPath: '/rules/routes.yml',
  outFile: '/p/.guardian/out.json',
  reportDir: '/p/.guardian',
};

describe('buildToolRun', () => {
  it('treats exit 1 as success — semgrep exits 1 when it FINDS matches', () => {
    expect(buildToolRun(run('failed', 1))).toEqual({ name: 'semgrep', status: 'ok' });
  });

  it('treats a genuine failure as failed and carries the first stderr line', () => {
    const t = buildToolRun(run('failed', 2, '\nfatal: broken rule\nmore'));
    expect(t.status).toBe('failed');
    expect(t.reason).toBe('fatal: broken rule');
  });

  it('records the docker route in the reason when one was used', () => {
    expect(buildToolRun(run('completed', 0), 'docker (img)')).toEqual({
      name: 'semgrep',
      status: 'ok',
      reason: 'ran via docker (img)',
    });
  });
});

describe('invokeSemgrep', () => {
  beforeEach(() => {
    vi.mocked(scannerAvailable).mockReset();
    vi.mocked(runProcess).mockReset();
  });

  it('runs semgrep natively when it is on PATH, passing the rules path', async () => {
    vi.mocked(scannerAvailable).mockResolvedValue('/bin/semgrep');
    vi.mocked(runProcess).mockResolvedValue(run('completed', 0));

    const result = await invokeSemgrep(OPTS);

    expect(result?.toolRun.status).toBe('ok');
    const args = vi.mocked(runProcess).mock.calls[0]?.[0].args ?? [];
    expect(args).toContain('--config');
    expect(args).toContain('/rules/routes.yml');
  });

  it('returns null when neither semgrep nor docker is available', async () => {
    vi.mocked(scannerAvailable).mockResolvedValue(null);
    expect(await invokeSemgrep(OPTS)).toBeNull();
    expect(vi.mocked(runProcess)).not.toHaveBeenCalled();
  });

  it('falls back to docker when semgrep is absent', async () => {
    vi.mocked(scannerAvailable).mockImplementation(async (n: string) =>
      n === 'docker' ? '/bin/docker' : null,
    );
    vi.mocked(runProcess).mockResolvedValue(run('completed', 0));

    const result = await invokeSemgrep(OPTS);

    expect(vi.mocked(runProcess).mock.calls[0]?.[0].command).toBe('docker');
    expect(result?.toolRun.reason).toMatch(/^ran via docker/);
  });
});
```

- [x] **Step 2: Run the test to verify it fails**

Run: `npm test -- test/unit/surface/scanSemgrep.test.ts`
Expected: FAIL — `Cannot find module '../../../src/surface/scanSemgrep.js'`.

- [x] **Step 3: Move the code**

Create `mcp/src/surface/scanSemgrep.ts` containing `invokeSemgrep` and `buildToolRun` **exactly as they are today** in `mapAttackSurface.ts:361-425`, with two changes only: the four positional parameters become the `SemgrepRunOptions` object, and both functions are exported. Keep the explanatory comment above `buildToolRun` verbatim — it records why exit 1 is success and cites the three sibling tools that agree.

- [x] **Step 4: Update the call site**

In `mapAttackSurface.ts`, delete both functions and import from `../surface/scanSemgrep.js`. Pass the options object. Remove imports that are now unused — `copyFileSync`, `buildSemgrepDockerArgs`, `toContainerPath`, `DEFAULT_SEMGREP_IMAGE`, `runProcess`, `ProcessRunResult` — `noUnusedLocals` will name any you miss.

- [x] **Step 5: Run the full suite — this is the real test of the move**

Run: `export PATH="$PATH:/c/Users/Administrator/AppData/Roaming/Python/Python314/Scripts" && GUARDIAN_REQUIRE_SEMGREP=1 npm test`
Expected: PASS, 578 + 6 new = 584. **No existing test may change.** If one does, the move was not behaviour-preserving.

- [x] **Step 6: Build and commit**

```bash
npm run build
git add src/surface/scanSemgrep.ts src/tools/mapAttackSurface.ts test/unit/surface/scanSemgrep.test.ts dist/
git commit -m "refactor(surface): extract the semgrep invocation from the orchestrator"
```

---

### Task 2: Route provenance

**Files:**

- Modify: `mcp/src/types.ts`, `mcp/src/surface/extract.ts`, `mcp/src/storage/surfaceRepo.ts`, `mcp/src/tools/mapAttackSurface.ts` (`buildCoverage` only)
- Test: `mcp/test/unit/storage/surfaceRepo.test.ts` (extend), `mcp/test/unit/surface/extract.test.ts` (extend)

**Interfaces:**

- Produces: `export type RouteProvenance = 'code' | 'spec';` and a required `provenance: RouteProvenance` on `RouteRecord`.

- [x] **Step 1: Write the failing tests**

Append to `mcp/test/unit/surface/extract.test.ts`:

```ts
describe('provenance', () => {
  it('marks every extracted route as coming from code', () => {
    const { routes } = extractSurface(fixture('express.json'));
    expect(routes.every((r) => r.provenance === 'code')).toBe(true);
  });
});
```

Append to `mcp/test/unit/storage/surfaceRepo.test.ts`:

```ts
it('backfills provenance as code for snapshots written before the field existed', () => {
  const db = new Database(':memory:');
  runMigrations(db);
  const legacyRoute = { ...makeRoute() } as Record<string, unknown>;
  delete legacyRoute['provenance'];
  db.prepare(
    `INSERT INTO surface_snapshots (project_path, captured_at, tree_hash, json)
     VALUES ('/p', '2026-01-01T00:00:00.000Z', 'h', ?)`,
  ).run(JSON.stringify({ routes: [legacyRoute] }));

  const repo = new SurfaceRepo(db);
  expect(repo.getLatest()?.snapshot.routes[0]?.provenance).toBe('code');
});
```

- [x] **Step 2: Run the tests to verify they fail**

Run: `npm test -- test/unit/surface/extract.test.ts test/unit/storage/surfaceRepo.test.ts`
Expected: FAIL — `provenance` is not a property of `RouteRecord`, and `undefined` is not `'code'`.

- [x] **Step 3: Add the type**

In `mcp/src/types.ts`, before `RouteRecord`:

```ts
/**
 * Where a route came from. `'code'` means Semgrep matched a route registration
 * in source; `'spec'` means an OpenAPI or Swagger document declared it. The two
 * live in the same `routes[]` array so a consumer sees one inventory, but the
 * difference between them is the whole point of the spec diff — a route that is
 * only `'code'` is undocumented, and one that is only `'spec'` may not exist.
 */
export type RouteProvenance = 'code' | 'spec';
```

Add to `RouteRecord`: `provenance: RouteProvenance;`

- [x] **Step 4: Set it at the two construction sites**

In `mcp/src/surface/extract.ts`, `toRoute` adds `provenance: 'code'` to the record it builds.

In `mcp/src/storage/surfaceRepo.ts`, `rowToSnapshot` maps routes through a backfill:

```ts
// Snapshots written before provenance existed carry routes without it. A
// snapshot is a point-in-time artifact and stale ones are history, so this
// backfills on read rather than migrating: every pre-existing route came from
// source extraction, because spec import did not exist yet.
routes: (parsed.routes ?? []).map((r) => ({ provenance: 'code' as const, ...r })),
```

Spread order matters: `provenance` first so a record that *does* carry one keeps it.

- [x] **Step 5: Keep spec routes out of the language coverage**

In `mapAttackSurface.ts`, `buildCoverage` derives its language set from `routes.map(r => r.language)`. Spec routes carry `language: 'spec'`, which would create a phantom entry reading `status: 'no_rules'` — true and meaningless. Filter at the top of the function:

```ts
const codeRoutes = routes.filter((r) => r.provenance === 'code');
```

and use `codeRoutes` everywhere `routes` is used inside it. `coverage[]` is a per-language report about code; a spec is not a language.

- [x] **Step 6: Run the suite**

Run: `export PATH="$PATH:/c/Users/Administrator/AppData/Roaming/Python/Python314/Scripts" && GUARDIAN_REQUIRE_SEMGREP=1 npm test`
Expected: PASS. Test helpers that build a `RouteRecord` literal will fail to typecheck until they add `provenance` — fix each, do not loosen the type.

- [x] **Step 7: Build and commit**

```bash
npm run build
git add src/types.ts src/surface/extract.ts src/storage/surfaceRepo.ts src/tools/mapAttackSurface.ts test/ dist/
git commit -m "feat(surface): tag routes with their provenance, code or spec"
```

---

### Task 3: Spec import

**Files:**

- Create: `mcp/src/surface/specImport.ts`
- Modify: `mcp/src/types.ts` (add `SpecFileReport`), `mcp/package.json` (move `yaml` to dependencies)
- Test: `mcp/test/unit/surface/specImport.test.ts`

**Interfaces:**

- Consumes: `RouteRecord`, `HttpMethod` from `types.js`; `parseDocument` from `yaml`.
- Produces:

```ts
export interface SpecImportResult {
  routes: RouteRecord[];
  report: SpecFileReport;
}

/** Pure: `text` is the document, `file` is only used to label the output. */
export function importSpec(file: string, text: string): SpecImportResult;
```

And in `types.ts`:

```ts
export interface SpecFileReport {
  file: string;
  format: 'openapi-3' | 'swagger-2' | 'unknown';
  status: 'ok' | 'parse_error' | 'unsupported_version' | 'no_paths';
  routes_found: number;
  /** Present for every status except 'ok'. One line, names the cause. */
  reason?: string;
  /**
   * Path items that were an unresolved external `$ref`. Counted, never ignored:
   * a path item that vanished silently would resurface as false dead
   * documentation in the diff.
   */
  unresolved_refs: number;
}
```

- [x] **Step 1: Promote `yaml` to a runtime dependency**

```bash
npm uninstall --save-dev yaml && npm install --save yaml
```

Verify `yaml` is under `dependencies` in `mcp/package.json` and no longer under `devDependencies`.

- [x] **Step 2: Write the failing test**

Create `mcp/test/unit/surface/specImport.test.ts`:

```ts
import { describe, expect, it } from 'vitest';
import { importSpec } from '../../../src/surface/specImport.js';

const OPENAPI = `
openapi: "3.0.3"
servers:
  - url: https://api.example.com/v1
security:
  - bearer: []
paths:
  /users:
    get:
      summary: list
    post:
      security: []
  /users/{id}:
    get:
      parameters:
        - name: id
          in: path
          required: true
`;

describe('importSpec — OpenAPI 3', () => {
  it('imports one route per operation, with the server base path applied', () => {
    const { routes, report } = importSpec('openapi.yaml', OPENAPI);
    expect(report.format).toBe('openapi-3');
    expect(report.status).toBe('ok');
    expect(report.routes_found).toBe(3);
    expect(routes.map((r) => `${r.method} ${r.path_resolved}`).sort()).toEqual([
      'GET /v1/users',
      'GET /v1/users/{id}',
      'POST /v1/users',
    ]);
  });

  it('marks every route as coming from a spec, at high confidence', () => {
    const { routes } = importSpec('openapi.yaml', OPENAPI);
    expect(routes.every((r) => r.provenance === 'spec')).toBe(true);
    expect(routes.every((r) => r.confidence === 'high')).toBe(true);
    expect(routes.every((r) => r.language === 'spec')).toBe(true);
    expect(routes.every((r) => r.framework === 'openapi-3')).toBe(true);
  });

  it('reads security: [] as an affirmative declaration that the route is public', () => {
    const { routes } = importSpec('openapi.yaml', OPENAPI);
    const post = routes.find((r) => r.method === 'POST');
    expect(post?.auth_hint).toBe('none');
  });

  it('inherits document-level security as required', () => {
    const { routes } = importSpec('openapi.yaml', OPENAPI);
    expect(routes.find((r) => r.path_raw === '/users' && r.method === 'GET')?.auth_hint)
      .toBe('required');
  });

  it('leaves auth unknown when neither the operation nor the document declares any', () => {
    const { routes } = importSpec('o.yaml', 'openapi: "3.0.0"\npaths:\n  /x:\n    get: {}\n');
    expect(routes[0]?.auth_hint).toBe('unknown');
  });

  it('extracts path parameters from the template', () => {
    const { routes } = importSpec('openapi.yaml', OPENAPI);
    expect(routes.find((r) => r.path_raw === '/users/{id}')?.params).toEqual(['id']);
  });

  it('reports a YAML line for each route', () => {
    const { routes } = importSpec('openapi.yaml', OPENAPI);
    expect(routes.every((r) => r.line > 0)).toBe(true);
  });

  it('is not partial when the document declares no servers — the default base is /', () => {
    const { routes } = importSpec('o.yaml', 'openapi: "3.0.0"\npaths:\n  /x:\n    get: {}\n');
    expect(routes[0]?.path_partial).toBe(false);
    expect(routes[0]?.path_resolved).toBe('/x');
  });

  it('is partial when the server url is templated', () => {
    const text = 'openapi: "3.0.0"\nservers:\n  - url: https://{env}.example.com/v2\npaths:\n  /x:\n    get: {}\n';
    expect(importSpec('o.yaml', text).routes[0]?.path_partial).toBe(true);
  });

  it('uses the first server when several are declared', () => {
    const text =
      'openapi: "3.0.0"\nservers:\n  - url: https://a.example.com/one\n  - url: https://b.example.com/two\npaths:\n  /x:\n    get: {}\n';
    expect(importSpec('o.yaml', text).routes[0]?.path_resolved).toBe('/one/x');
  });
});

describe('importSpec — Swagger 2', () => {
  it('applies basePath and reports the swagger-2 format', () => {
    const text = 'swagger: "2.0"\nbasePath: /api\npaths:\n  /pets:\n    get: {}\n';
    const { routes, report } = importSpec('swagger.yaml', text);
    expect(report.format).toBe('swagger-2');
    expect(routes[0]?.path_resolved).toBe('/api/pets');
    expect(routes[0]?.framework).toBe('swagger-2');
  });
});

describe('importSpec — JSON documents', () => {
  it('parses JSON and reports line 0, because JSON.parse gives no positions', () => {
    const text = JSON.stringify({ openapi: '3.0.0', paths: { '/x': { get: {} } } });
    const { routes, report } = importSpec('openapi.json', text);
    expect(report.status).toBe('ok');
    expect(routes[0]?.line).toBe(0);
  });
});

describe('importSpec — degradation', () => {
  it('reports a parse error rather than throwing', () => {
    const { routes, report } = importSpec('bad.yaml', 'paths:\n  - [unclosed\n');
    expect(report.status).toBe('parse_error');
    expect(report.reason).toBeTruthy();
    expect(routes).toEqual([]);
  });

  it('reports an unsupported version when neither openapi nor swagger is present', () => {
    const { report } = importSpec('x.yaml', 'foo: bar\n');
    expect(report.status).toBe('unsupported_version');
    expect(report.format).toBe('unknown');
  });

  it('reports no_paths for a valid document that declares nothing', () => {
    const { report } = importSpec('o.yaml', 'openapi: "3.0.0"\npaths: {}\n');
    expect(report.status).toBe('no_paths');
    expect(report.routes_found).toBe(0);
  });

  it('counts an external $ref path item instead of dropping it', () => {
    const text = 'openapi: "3.0.0"\npaths:\n  /x:\n    $ref: "./paths/x.yaml"\n';
    const { routes, report } = importSpec('o.yaml', text);
    expect(report.unresolved_refs).toBe(1);
    expect(routes).toEqual([]);
  });

  it('ignores non-operation keys under a path item', () => {
    const text =
      'openapi: "3.0.0"\npaths:\n  /x:\n    summary: not an operation\n    parameters: []\n    get: {}\n';
    expect(importSpec('o.yaml', text).routes).toHaveLength(1);
  });
});
```

- [x] **Step 3: Run the test to verify it fails**

Run: `npm test -- test/unit/surface/specImport.test.ts`
Expected: FAIL — module not found.

- [x] **Step 4: Write the implementation**

Create `mcp/src/surface/specImport.ts`. The shape:

```ts
/**
 * Parse one OpenAPI 3.x or Swagger 2.0 document into RouteRecords.
 *
 * Pure: the caller supplies the text. Never throws — a malformed document is a
 * report with `status: 'parse_error'`, because one bad spec in a repository
 * must not cost the diff of the good ones.
 */

import { parseDocument } from 'yaml';
import type { HttpMethod, RouteRecord, SpecFileReport } from '../types.js';

const OPERATION_KEYS: readonly string[] = [
  'get', 'put', 'post', 'delete', 'options', 'head', 'patch', 'trace',
];
```

Implementation notes the engineer needs:

- **Parse once, both formats.** Try `JSON.parse` first; on failure use `parseDocument` from `yaml`. Keep the `yaml` `Document` when you used it — it is what gives line numbers. Track which path you took so `line` is `0` for JSON.
- **`parseDocument` does NOT throw on malformed YAML.** It returns a Document with a populated `doc.errors` array — verified: `paths:\n  - [unclosed\n` yields `errors.length === 1` with the message *"Flow sequence in block collection must be sufficiently indented…"*. A `try/catch` around it catches nothing. Check `doc.errors.length > 0` and use `doc.errors[0]?.message` as the report's `reason`.
- **Line numbers — read the KEY node, not the value.** `doc.getIn(['paths', p], true)` returns the path item's *value* (a `YAMLMap`), whose range starts at the first operation. Verified: for a `/users/{id}` key on line 7, that route computes to line 8. Iterate the map's items instead:

```ts
const pathsNode = doc.get('paths', true);
// YAMLMap items each carry `key` and `value` nodes with their own ranges.
for (const item of pathsNode.items) {
  const offset = item.key.range[0];
  const line = text.slice(0, offset).split('\n').length;   // 1-based
}
```

Verified against a two-path document: keys on source lines 5 and 7 compute to 5 and 7.

Remaining behaviours:

- **Version detection** reads the top-level `openapi` (starts with `3.`) or `swagger` (equals `2.0`) key. Neither → `unsupported_version`, and return before touching `paths`.
- **Base path.** OpenAPI 3: `new URL(servers[0].url).pathname`, but the url may be templated or relative — if it contains `{`, set `path_partial: true` on every route and use an empty base. If `servers` is absent, base is `''` and **not** partial. Swagger 2: `basePath ?? ''`, same partial rule for a `{` in it. Strip a trailing `/` from the base.
- **`trace` is in `OPERATION_KEYS`** but is not in `HttpMethod`; map it to `'ANY'` rather than dropping the route.
- **`auth_hint`**, in this order: operation has `security` and it is an empty array → `'none'`; operation has non-empty `security` → `'required'`; no operation `security` and document `security` is non-empty → `'required'`; otherwise `'unknown'`.
- **`params`** come from `{...}` segments in the path template, plus entries of the operation's and path item's `parameters` whose `in` is `path`. Resolve internal `$ref`s (`#/components/parameters/X` or `#/parameters/X`) by walking the document; do not follow anything that does not start with `#`.
- **An external `$ref` as the path item value** increments `unresolved_refs` and contributes no route.
- Every returned route: `provenance: 'spec'`, `language: 'spec'`, `confidence: 'high'`, `framework` is the detected format, `file` is the `file` argument, `path_raw` is the template as written, `namespace` unset.

- [x] **Step 5: Run the test to verify it passes**

Run: `npm test -- test/unit/surface/specImport.test.ts`
Expected: PASS, 17 tests.

- [x] **Step 6: Build and commit**

```bash
npm run build
git add src/surface/specImport.ts src/types.ts package.json package-lock.json test/unit/surface/specImport.test.ts dist/
git commit -m "feat(surface): import OpenAPI 3 and Swagger 2 documents as routes"
```

---

### Task 4: The spec↔code diff

The task that produces the finding. Pure, and the place where the honesty rules live.

**Files:**

- Create: `mcp/src/surface/specDiff.ts`
- Modify: `mcp/src/types.ts` (add `SpecDiffEntry`, `SpecDiff`)
- Test: `mcp/test/unit/surface/specDiff.test.ts`

**Interfaces:**

- Consumes: `RouteRecord`, `HttpMethod` from `types.js`.
- Produces:

```ts
/** `null` when no spec parsed — never a diff in which everything is undocumented. */
export function diffSpecRoutes(
  codeRoutes: readonly RouteRecord[],
  specRoutes: readonly RouteRecord[],
  specsParsed: number,
): SpecDiff | null;

export function normalisePath(path: string): string;
```

And in `types.ts`:

```ts
export interface SpecDiffEntry {
  method: HttpMethod;
  /** The normalised comparison key, human-readable: `/users/{}`. */
  path: string;
  code_route?: RouteRecord;
  spec_route?: RouteRecord;
  /** Present on `unmatchable` entries: one line saying why. */
  reason?: string;
}

export interface SpecDiff {
  matched: SpecDiffEntry[];
  /** In the code, absent from every spec — shadow endpoints. */
  code_only: SpecDiffEntry[];
  /** In a spec, absent from the code — dead documentation. */
  spec_only: SpecDiffEntry[];
  /** Could not be classified either way. Never reported as a finding. */
  unmatchable: SpecDiffEntry[];
}
```

- [x] **Step 1: Write the failing test**

Create `mcp/test/unit/surface/specDiff.test.ts`:

```ts
import { describe, expect, it } from 'vitest';
import { diffSpecRoutes, normalisePath } from '../../../src/surface/specDiff.js';
import type { RouteRecord } from '../../../src/types.js';

function route(over: Partial<RouteRecord> & { path_resolved: string }): RouteRecord {
  return {
    method: 'GET',
    path_raw: over.path_resolved,
    path_partial: false,
    file: 'f',
    line: 1,
    framework: 'express',
    language: 'typescript',
    auth_hint: 'unknown',
    params: [],
    confidence: 'high',
    provenance: 'code',
    ...over,
  };
}

const spec = (over: Partial<RouteRecord> & { path_resolved: string }): RouteRecord =>
  route({ ...over, provenance: 'spec', framework: 'openapi-3', language: 'spec' });

describe('normalisePath', () => {
  it('collapses every parameter syntax to one placeholder', () => {
    expect(normalisePath('/users/{id}')).toBe('/users/{}');
    expect(normalisePath('/users/:id')).toBe('/users/{}');
    expect(normalisePath('/users/:id?')).toBe('/users/{}');
    expect(normalisePath('/users/<int:id>')).toBe('/users/{}');
    expect(normalisePath('/users/(?P<id>\\d+)')).toBe('/users/{}');
  });

  it('strips a trailing slash and guarantees a leading one', () => {
    expect(normalisePath('/users/')).toBe('/users');
    expect(normalisePath('users')).toBe('/users');
  });
});

describe('diffSpecRoutes', () => {
  it('returns null when no spec parsed — absence of a spec is not a finding', () => {
    expect(diffSpecRoutes([route({ path_resolved: '/a' })], [], 0)).toBeNull();
  });

  it('matches the same endpoint written in two syntaxes', () => {
    const d = diffSpecRoutes(
      [route({ path_resolved: '/users/:id' })],
      [spec({ path_resolved: '/users/{id}' })],
      1,
    );
    expect(d?.matched).toHaveLength(1);
    expect(d?.code_only).toEqual([]);
    expect(d?.spec_only).toEqual([]);
  });

  it('reports a code route no spec documents as a shadow endpoint', () => {
    const d = diffSpecRoutes([route({ path_resolved: '/secret' })], [spec({ path_resolved: '/known' })], 1);
    expect(d?.code_only.map((e) => e.path)).toEqual(['/secret']);
  });

  it('reports a spec route no code implements as dead documentation', () => {
    const d = diffSpecRoutes([route({ path_resolved: '/known' })], [spec({ path_resolved: '/gone' })], 1);
    expect(d?.spec_only.map((e) => e.path)).toEqual(['/gone']);
  });

  it('treats an ANY code route as matching any documented method', () => {
    const d = diffSpecRoutes(
      [route({ path_resolved: '/x', method: 'ANY' })],
      [spec({ path_resolved: '/x', method: 'POST' })],
      1,
    );
    expect(d?.matched).toHaveLength(1);
  });

  it('sends a partial code route to unmatchable, never to shadow', () => {
    const d = diffSpecRoutes(
      [route({ path_resolved: '/list', path_partial: true })],
      [spec({ path_resolved: '/other' })],
      1,
    );
    expect(d?.code_only).toEqual([]);
    expect(d?.unmatchable.some((e) => e.code_route?.path_resolved === '/list')).toBe(true);
  });

  it('sends a spec route with a templated server to unmatchable', () => {
    const d = diffSpecRoutes([], [spec({ path_resolved: '/x', path_partial: true })], 1);
    expect(d?.spec_only).toEqual([]);
    expect(d?.unmatchable).toHaveLength(1);
  });

  it('does not call a spec route dead when a partial code route could be it', () => {
    // The code registers /list behind an unresolved mount; the spec says
    // /api/list. That is the same route, not dead documentation.
    const d = diffSpecRoutes(
      [route({ path_resolved: '/list', path_partial: true })],
      [spec({ path_resolved: '/api/list' })],
      1,
    );
    expect(d?.spec_only).toEqual([]);
    expect(d?.unmatchable.some((e) => e.spec_route?.path_resolved === '/api/list')).toBe(true);
  });

  it('still calls a spec route dead when no partial route shares its suffix', () => {
    const d = diffSpecRoutes(
      [route({ path_resolved: '/list', path_partial: true })],
      [spec({ path_resolved: '/api/orders' })],
      1,
    );
    expect(d?.spec_only.map((e) => e.path)).toEqual(['/api/orders']);
  });

  it('ignores provenance mislabelling by filtering its own inputs', () => {
    // Defensive: the caller splits by provenance, but a spec route arriving in
    // the code list must not be diffed against itself.
    const d = diffSpecRoutes(
      [spec({ path_resolved: '/x' })],
      [spec({ path_resolved: '/x' })],
      1,
    );
    expect(d?.code_only).toEqual([]);
  });
});
```

- [x] **Step 2: Run the test to verify it fails**

Run: `npm test -- test/unit/surface/specDiff.test.ts`
Expected: FAIL — module not found.

- [x] **Step 3: Write the implementation**

Create `mcp/src/surface/specDiff.ts`.

```ts
/**
 * Compare routes extracted from source against routes declared in a spec.
 *
 * Pure. The two rules that matter are both about refusing to guess:
 *
 *   1. With no spec parsed there is no diff. `null`, not a diff in which every
 *      code route is undocumented.
 *   2. A route whose full path is unknown goes to `unmatchable`, and so does
 *      any spec route it might have been. See `spec_only` below.
 */

const PARAM_SYNTAX: readonly RegExp[] = [
  // WordPress first: `(?P<id>\d+)` contains `<id>`, which the Flask rule would
  // otherwise eat and leave `(?P{}\d+)` behind.
  /\(\?P<[^>]+>[^)]*\)/g,
  /\{[^}]*\}/g,        // OpenAPI, Spring: {id}
  /<[^>]*>/g,          // Flask: <int:id>
  /:[A-Za-z_]\w*\??/g, // Express, Rails: :id and :id?
];

export function normalisePath(path: string): string {
  let out = path;
  for (const re of PARAM_SYNTAX) out = out.replace(re, '{}');
  out = out.replace(/\/+$/, '');
  if (!out.startsWith('/')) out = `/${out}`;
  return out;
}
```

The algorithm:

1. Filter inputs by provenance — `codeRoutes` to `'code'`, `specRoutes` to `'spec'` — so a mislabelled caller cannot diff a set against itself.
2. If `specsParsed === 0`, return `null`.
3. Split each side into resolvable (`!path_partial`) and partial.
4. Key every resolvable route as `` `${method} ${normalisePath(path_resolved)}` ``. Build a map for each side, and a second map keyed on path alone for the `ANY` case.
5. `matched`: keys present on both sides, plus any pair where one side's method is `ANY` and the paths agree.
6. `code_only`: resolvable code keys with no spec counterpart.
7. Every partial route on either side → `unmatchable`, with `reason` naming which (`'code route has an unresolved prefix'` / `'spec server url is templated'`).
8. `spec_only` is the last bucket and the guarded one: a resolvable spec route with no code counterpart is `spec_only` **only if** no partial code route's normalised `path_raw` is a suffix of the spec's normalised path. If one is, the spec route joins `unmatchable` with a reason naming the partial route. Suffix is the right test because a partial route is missing exactly a prefix.

- [x] **Step 4: Run the test to verify it passes**

Run: `npm test -- test/unit/surface/specDiff.test.ts`
Expected: PASS, 12 tests.

- [x] **Step 5: Build and commit**

```bash
npm run build
git add src/surface/specDiff.ts src/types.ts test/unit/surface/specDiff.test.ts dist/
git commit -m "feat(surface): diff spec-declared routes against code-extracted ones"
```

---

### Task 5: Spec discovery

**Files:**

- Create: `mcp/src/surface/specDiscover.ts`
- Test: `mcp/test/unit/surface/specDiscover.test.ts`

**Interfaces:**

- Produces:

```ts
export interface DiscoveredSpec { file: string; text: string }

export interface DiscoveryOutcome {
  specs: DiscoveredSpec[];
  /** Files skipped for exceeding the size cap, with their paths. */
  oversized: string[];
  /** True when the file cap truncated the candidate set. */
  truncated: boolean;
}

export function discoverSpecs(projectPath: string, explicit?: readonly string[]): DiscoveryOutcome;

export const MAX_SPEC_FILES = 20;
export const MAX_SPEC_BYTES = 5 * 1024 * 1024;
```

- [x] **Step 1: Write the failing test**

Create `mcp/test/unit/surface/specDiscover.test.ts`:

```ts
import { describe, expect, it } from 'vitest';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { discoverSpecs, MAX_SPEC_FILES } from '../../../src/surface/specDiscover.js';

function project(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), 'guardian-spec-'));
  for (const [rel, content] of Object.entries(files)) {
    const abs = join(dir, rel);
    mkdirSync(join(abs, '..'), { recursive: true });
    writeFileSync(abs, content);
  }
  return dir;
}

describe('discoverSpecs', () => {
  it('finds the conventional names at the project root', () => {
    const dir = project({
      'openapi.yaml': 'a', 'swagger.json': 'b', 'api-docs.json': 'c', 'README.md': 'd',
    });
    expect(discoverSpecs(dir).specs.map((s) => s.file.split(/[\\/]/).pop()).sort())
      .toEqual(['api-docs.json', 'openapi.yaml', 'swagger.json']);
  });

  it('finds documents inside an openapi/ directory', () => {
    const dir = project({ 'docs/openapi/v1.yml': 'a' });
    expect(discoverSpecs(dir).specs).toHaveLength(1);
  });

  it('skips node_modules and the other excluded directories', () => {
    const dir = project({ 'node_modules/pkg/openapi.yaml': 'a', 'dist/openapi.yaml': 'b' });
    expect(discoverSpecs(dir).specs).toEqual([]);
  });

  it('reads the file contents', () => {
    const dir = project({ 'openapi.yaml': 'openapi: "3.0.0"' });
    expect(discoverSpecs(dir).specs[0]?.text).toBe('openapi: "3.0.0"');
  });

  it('uses the explicit list instead of discovery when given one', () => {
    const dir = project({ 'openapi.yaml': 'discovered', 'custom/thing.yaml': 'explicit' });
    const out = discoverSpecs(dir, [join(dir, 'custom', 'thing.yaml')]);
    expect(out.specs).toHaveLength(1);
    expect(out.specs[0]?.text).toBe('explicit');
  });

  it('reports an explicit path that does not exist rather than throwing', () => {
    const dir = project({});
    expect(discoverSpecs(dir, [join(dir, 'missing.yaml')]).specs).toEqual([]);
  });

  it('reports the file cap instead of silently returning the first N', () => {
    const files: Record<string, string> = {};
    for (let i = 0; i < MAX_SPEC_FILES + 3; i += 1) files[`openapi/s${i}.yaml`] = 'x';
    const out = discoverSpecs(project(files));
    expect(out.specs).toHaveLength(MAX_SPEC_FILES);
    expect(out.truncated).toBe(true);
  });

  it('reports an oversized file instead of reading it', () => {
    const dir = project({ 'openapi.yaml': 'x'.repeat(6 * 1024 * 1024) });
    const out = discoverSpecs(dir);
    expect(out.specs).toEqual([]);
    expect(out.oversized).toHaveLength(1);
  });
});
```

- [x] **Step 2: Run the test to verify it fails**

Run: `npm test -- test/unit/surface/specDiscover.test.ts`
Expected: FAIL — module not found.

- [x] **Step 3: Write the implementation**

Create `mcp/src/surface/specDiscover.ts`. Walk the project tree with the same exclusion set `computeTreeHash` uses (`mcp/src/treeHash/computeTreeHash.ts:27-45` — import it if it is exported, otherwise copy it and note in a comment that the two must stay aligned). Match a file when its basename is one of `openapi`, `swagger`, `api-docs` with a `.json`, `.yaml` or `.yml` extension, **or** when any parent directory is named `openapi` and the extension matches. Sort results for determinism. Enforce both caps, recording rather than hiding them. `statSync` before `readFileSync` so an oversized file is never read into memory. Never throw: an unreadable file is simply absent.

- [x] **Step 4: Run the test to verify it passes**

Run: `npm test -- test/unit/surface/specDiscover.test.ts`
Expected: PASS, 8 tests.

- [x] **Step 5: Build and commit**

```bash
npm run build
git add src/surface/specDiscover.ts test/unit/surface/specDiscover.test.ts dist/
git commit -m "feat(surface): discover OpenAPI and Swagger documents in the project"
```

---

### Task 6: Wire it into the tool

**Files:**

- Modify: `mcp/src/tools/mapAttackSurface.ts`, `mcp/src/types.ts` (`AttackSurfaceSnapshot`)
- Test: `mcp/test/integration/surfaceTools.test.ts` (extend)

**Interfaces:**

- Consumes: `discoverSpecs` (Task 5), `importSpec` (Task 3), `diffSpecRoutes` (Task 4).
- Produces: `AttackSurfaceSnapshot` gains `spec_files: SpecFileReport[]` and `spec_diff: SpecDiff | null`; the tool input gains `spec_paths`; the result gains `spec_routes_total`, `spec_files`, `spec_diff_summary` and `shadow_sample`.

- [x] **Step 1: Write the failing integration tests**

Append to `mcp/test/integration/surfaceTools.test.ts` — reuse the file's existing mocking of `scannerAvailable`, `runProcess` and `readJsonSafe`, and write real spec files into the temp project directory:

```ts
describe('map_attack_surface — spec import and diff', () => {
  const SPEC = [
    'openapi: "3.0.0"',
    'paths:',
    '  /users:',
    '    get: {}',
    '  /documented-but-gone:',
    '    get: {}',
  ].join('\n');

  it('imports spec routes, keeps routes_total counting code only, and finds both findings', async () => {
    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/semgrep');
    vi.mocked(runProcess).mockResolvedValue(okRun());
    vi.mocked(readJsonSafe).mockReturnValue(SEMGREP_OUTPUT); // one route: GET /users

    const ctx = makeCtx();
    const projectPath = mkdtempSync(join(tmpdir(), 'guardian-surface-'));
    writeFileSync(join(projectPath, 'openapi.yaml'), SPEC);
    // A second code route the spec does not document.
    // SEMGREP_OUTPUT_WITH_SHADOW adds GET /internal/metrics.
    vi.mocked(readJsonSafe).mockReturnValue(SEMGREP_OUTPUT_WITH_SHADOW);

    const r = (await tool().handler({ project_path: projectPath }, ctx)) as {
      routes_total: number;
      spec_routes_total: number;
      spec_diff_summary: { matched: number; code_only: number; spec_only: number } | null;
      shadow_sample: { path: string }[];
    };

    expect(r.routes_total).toBe(2);        // code routes only
    expect(r.spec_routes_total).toBe(2);
    expect(r.spec_diff_summary?.matched).toBe(1);
    expect(r.spec_diff_summary?.code_only).toBe(1);
    expect(r.spec_diff_summary?.spec_only).toBe(1);
    expect(r.shadow_sample[0]?.path).toBe('/internal/metrics');
  });

  it('produces no diff at all when the project has no spec', async () => {
    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/semgrep');
    vi.mocked(runProcess).mockResolvedValue(okRun());
    vi.mocked(readJsonSafe).mockReturnValue(SEMGREP_OUTPUT);

    const ctx = makeCtx();
    const projectPath = mkdtempSync(join(tmpdir(), 'guardian-surface-'));
    const r = (await tool().handler({ project_path: projectPath }, ctx)) as {
      spec_diff_summary: unknown;
      routes_total: number;
    };

    // The trap this guards: with no spec, every code route would otherwise
    // look undocumented.
    expect(r.spec_diff_summary).toBeNull();
    expect(r.routes_total).toBeGreaterThan(0);
  });

  it('keeps spec routes out of the per-language coverage report', async () => {
    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/semgrep');
    vi.mocked(runProcess).mockResolvedValue(okRun());
    vi.mocked(readJsonSafe).mockReturnValue(SEMGREP_OUTPUT);

    const ctx = makeCtx();
    const projectPath = mkdtempSync(join(tmpdir(), 'guardian-surface-'));
    writeFileSync(join(projectPath, 'openapi.yaml'), SPEC);

    const r = (await tool().handler({ project_path: projectPath }, ctx)) as {
      coverage: { language: string }[];
    };
    expect(r.coverage.some((c) => c.language === 'spec')).toBe(false);
  });

  it('reports a malformed spec without losing the diff of the good one', async () => {
    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/semgrep');
    vi.mocked(runProcess).mockResolvedValue(okRun());
    vi.mocked(readJsonSafe).mockReturnValue(SEMGREP_OUTPUT);

    const ctx = makeCtx();
    const projectPath = mkdtempSync(join(tmpdir(), 'guardian-surface-'));
    writeFileSync(join(projectPath, 'openapi.yaml'), SPEC);
    writeFileSync(join(projectPath, 'swagger.yaml'), 'paths:\n  - [unclosed\n');

    const r = (await tool().handler({ project_path: projectPath }, ctx)) as {
      spec_files: { status: string }[];
      spec_diff_summary: unknown;
    };
    expect(r.spec_files.some((f) => f.status === 'parse_error')).toBe(true);
    expect(r.spec_diff_summary).not.toBeNull();
  });
});
```

Add `SEMGREP_OUTPUT_WITH_SHADOW` beside the existing `SEMGREP_OUTPUT` constant: the same JSON with a second `guardian-route-express` result for `GET /internal/metrics`.

- [x] **Step 2: Run the tests to verify they fail**

Run: `npm test -- test/integration/surfaceTools.test.ts`
Expected: FAIL — `spec_diff_summary` is undefined.

- [x] **Step 3: Add the snapshot fields**

In `mcp/src/types.ts`, `AttackSurfaceSnapshot` gains:

```ts
  spec_files: SpecFileReport[];
  /**
   * `null` when no spec parsed. Deliberately not an empty diff: "no spec was
   * found" and "the spec documents nothing" must stay distinguishable, or a
   * project without a spec reads as one where every endpoint is undocumented.
   */
  spec_diff: SpecDiff | null;
```

- [x] **Step 4: Add the input and the pipeline stages**

Add to the tool's `inputSchema`:

```ts
const SpecPaths = z
  .array(z.string().min(1))
  .optional()
  .describe(
    'Explicit OpenAPI/Swagger document paths. Replaces automatic discovery entirely when supplied.',
  );
```

In `buildSnapshot`, after the code routes are resolved: discover, import each document, concatenate the spec routes into `routes`, and diff. `specsParsed` is the count of reports whose status is `ok` or `no_paths` — a valid document declaring nothing is a successfully parsed spec.

Record discovery caps as a `SpecFileReport` with `status: 'parse_error'` and a reason naming the cap, so a truncated set is visible in the same place a reader is already looking.

- [x] **Step 5: Extend `summarize`**

Add `spec_routes_total`, `spec_files`, `spec_diff_summary` (counts only, `null` when the diff is null) and `shadow_sample` (first 20 of `code_only`). **`routes_total` keeps counting `provenance === 'code'` only** — a consumer reading it today gets the same number tomorrow.

Full diff lists stay out of the tool result and are served by the existing resources, for the same reason the full route list already is.

- [x] **Step 6: Run the suite**

Run: `export PATH="$PATH:/c/Users/Administrator/AppData/Roaming/Python/Python314/Scripts" && GUARDIAN_REQUIRE_SEMGREP=1 npm test`
Expected: PASS. `toolSurface.test.ts` should be unaffected — no tool or resource was added.

- [x] **Step 7: Build and commit**

```bash
npm run build
git add src/tools/mapAttackSurface.ts src/types.ts test/integration/surfaceTools.test.ts dist/
git commit -m "feat(surface): wire spec import and the spec-vs-code diff into map_attack_surface"
```

---

### Task 7: End-to-end fixture and documentation

**Files:**

- Create: `mcp/test/fixtures/surface/apps/openapi.yaml`
- Modify: `mcp/test/e2e/rulePackFixture.test.ts`, `README.md`, `CHANGELOG.md`
- Test: the e2e itself

**Interfaces:** none new.

- [x] **Step 1: Write the fixture spec**

First read `EXPECTED_ROUTES` in `mcp/test/e2e/rulePackFixture.test.ts` — it is the exact set of 64 routes the fixture app tree produces, and every path you document must be copied from it or deliberately absent from it.

Create `mcp/test/fixtures/surface/apps/openapi.yaml` with a deliberate mixture:

- **two or three paths copied verbatim from `EXPECTED_ROUTES`**, so `matched` is non-empty. Prefer routes that are not `[partial]` in that list — a partial route lands in `unmatchable`, which is correct but tests a different thing.
- **at least one real route from `EXPECTED_ROUTES` deliberately omitted**, which must surface as a shadow endpoint.
- **one path that appears nowhere in `EXPECTED_ROUTES`**, e.g. `/deprecated/v0/orders`, which must surface as dead documentation.

Comment each of the three intentions inline, naming which assertion depends on which entry. The fixture is the artifact that makes future rule and diff changes verifiable, and an uncommented fixture is one somebody edits without knowing what they broke.

Note the `servers` block: with none, the base is `/` and the documented paths must match the fixture routes exactly as written.

- [x] **Step 2: Write the failing e2e assertions**

In `mcp/test/e2e/rulePackFixture.test.ts`, add a test asserting the diff as an **exact set**, in the same style as the existing `EXPECTED_ROUTES`:

```ts
/** Same shape as the file's existing `describeRoute`, for diff entries. */
function describeDiffEntry(e: SpecDiffEntry): string {
  return `${e.method} ${e.path}`;
}

const EXPECTED_SHADOW = [/* `${method} ${path}` for every real route the spec omits */];
const EXPECTED_DEAD = [/* the paths declared but not implemented */];

it.skipIf(!SEMGREP_AVAILABLE)('reports shadow endpoints and dead documentation', async () => {
  const snapshot = await runTool();
  const diff = snapshot.spec_diff;
  expect(diff).not.toBeNull();
  expect(diff?.code_only.map(describeDiffEntry).sort()).toEqual(EXPECTED_SHADOW);
  expect(diff?.spec_only.map(describeDiffEntry).sort()).toEqual(EXPECTED_DEAD);
});
```

A count assertion is not enough: it passes when one rule breaks and another over-matches.

- [x] **Step 3: Run the e2e**

Run: `export PATH="$PATH:/c/Users/Administrator/AppData/Roaming/Python/Python314/Scripts" && GUARDIAN_REQUIRE_SEMGREP=1 npm test -- test/e2e/rulePackFixture.test.ts`
Expected: FAIL first with the real numbers, then PASS once `EXPECTED_SHADOW` and `EXPECTED_DEAD` are filled from what the tool actually produces — **after** checking each entry is genuinely what the fixture intends. Do not paste the output in without reading it; that is how a wrong expectation becomes a regression test.

- [x] **Step 4: Update the docs**

`README.md`, all three language sections: `map_attack_surface`'s description gains spec import and the diff. Note that `yaml` is now a runtime dependency if the README lists dependencies.

`CHANGELOG.md`, under the existing `## [Unreleased]`: what was added, and the two honesty rules — no spec means no diff, and an unresolvable route is never reported as a shadow endpoint. State which formats are supported and that Postman is not.

Markdownlint must stay clean: `npx markdownlint-cli2 README.md CHANGELOG.md`.

- [x] **Step 5: Full verification**

```bash
export PATH="$PATH:/c/Users/Administrator/AppData/Roaming/Python/Python314/Scripts"
GUARDIAN_REQUIRE_SEMGREP=1 npm test
npm run test:coverage
npm run build
```

Expected: suite green with zero skipped; coverage above 70/62/72/70; build clean.

- [x] **Step 6: Commit**

```bash
git add test/fixtures/surface/apps/openapi.yaml test/e2e/rulePackFixture.test.ts dist/ ../README.md ../CHANGELOG.md
git commit -m "test(surface): end-to-end shadow-endpoint and dead-documentation fixture"
```

---

## Definition of Done

- [x] OpenAPI 3.x and Swagger 2.0 documents, JSON and YAML, are discovered, parsed and imported.
- [x] Spec routes carry `provenance: 'spec'`; code routes `'code'`; pre-existing snapshots read back as `'code'`.
- [x] `auth_hint: 'none'` is emitted for `security: []` and never inferred from absence.
- [x] All four diff buckets are produced; `unmatchable` is never reported as a finding.
- [x] A spec route whose suffix matches a partial code route is not called dead documentation.
- [x] No spec, or every spec failing, yields `spec_diff: null` with a reason.
- [x] `routes_total` still counts code routes only; `coverage[]` carries no `spec` language.
- [x] Discovery caps and unresolved external `$ref`s are reported, never silent.
- [x] `scanSemgrep.ts` extracted with every pre-existing test passing unchanged.
- [x] Suite green with `GUARDIAN_REQUIRE_SEMGREP=1`; coverage above thresholds.
- [x] `mcp/dist/` rebuilt and staged in every commit that touched TypeScript.
