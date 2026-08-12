# Design — OpenAPI spec import and spec↔code diff

**Date:** 2026-08-12
**Status:** approved, ready for implementation planning
**Scope:** three new pure modules, one new I/O module, one orchestrator split, one
runtime dependency, no new MCP tool.

---

## 1. Context

`map_attack_surface` extracts an application's HTTP routes from source. This adds a
second source — OpenAPI 3.x and Swagger 2.0 documents found in the repository — and,
more importantly, the comparison between the two.

The comparison is the deliverable. Two findings fall out of it:

- **Shadow endpoints** — routes the code registers that no spec documents. A real
  security finding: an endpoint nobody wrote down is an endpoint nobody reviews.
- **Dead documentation** — paths a spec declares that no code implements.

Feeding `scan_dast` a target list comes free, because spec routes land in the same
inventory as extracted ones.

This is the second of seven gaps identified against
[usestrix/strix](https://github.com/usestrix/strix). Remaining after this:
`scan_dast` → `validate_finding` → headless CLI scan → local dashboard →
`create_fix_pr`.

### Non-goals

- **Fetching specs over HTTP.** Everything is read from files in the repository,
  consistent with §1 of the `map_attack_surface` design: no network, no live
  enumeration.
- **Postman collections.** A different tree shape — nested items, `{{variable}}`
  URLs, no formal path templating — and a second parser rather than a variation on
  the first. Deferred, and declared as unsupported rather than silently skipped.
- Request/response body schemas, examples, and external `$ref` resolution.

---

## 2. Decisions taken during design

| Decision | Choice | Rationale |
| --- | --- | --- |
| Primary purpose | The spec↔code diff, not the import | Shadow endpoints and dead documentation are actionable; a merged inventory alone is not. DAST targeting comes free either way. |
| Formats | OpenAPI 3.x + Swagger 2.0 | Together they cover the overwhelming majority of documented APIs and share one `paths → method → operation` tree; 2.0 normalises into 3.x cheaply. Postman would be a second parser. |
| Architecture | One tool, pure modules, orchestrator split | Everything pure in the existing feature survived; every defect came from a layer that read files and decided at the same time. Also splits a 679-line file already doing too much. |
| YAML | Promote `yaml` from dev to runtime dependency | Most real OpenAPI documents are YAML. Runtime deps go 3 → 4 and the committed bundle grows ~100–150 KB on 1.4 MB. Hand-rolling a YAML parser after what the recovery heuristics cost would be learning nothing. |
| `routes_total` | Keeps counting code routes only | Silently changing what an existing field means is how consumers break. Spec routes are counted in `spec_routes_total`. |
| No spec found | `spec_diff: null` | See §5. This is the correctness decision of the whole design. |

---

## 3. Architecture

```text
map_attack_surface(project_path, force?, include_env_vars?, spec_paths?)
  │
  ├─ 1. StackRepo.getLatest()
  │
  ├─ 2. surface/scanSemgrep.ts      [I/O]   extracted from mapAttackSurface.ts
  │                                          scannerAvailable + runProcess +
  │                                          Docker fallback + readJsonSafe
  │
  ├─ 3. recoverMetavars → extract → resolvers → collectors   [PURE, unchanged]
  │        → RouteRecord[] with provenance 'code'
  │
  ├─ 4. surface/specDiscover.ts     [I/O]   candidate spec files → { file, text }[]
  │
  ├─ 5. surface/specImport.ts       [PURE]  text → RouteRecord[] provenance 'spec'
  │                                          + SpecFileReport
  │
  ├─ 6. surface/specDiff.ts         [PURE]  code routes × spec routes → SpecDiff
  │
  └─ 7. SurfaceRepo.insert(snapshot)
```

Only steps 2 and 4 touch the filesystem. Every module that makes a decision is pure
and unit-testable with no scanner, no disk and no network.

### The orchestrator split

`mcp/src/tools/mapAttackSurface.ts` is 679 lines and currently owns stack lookup,
scanner availability, native invocation, Docker fallback, output reading, metavar
recovery wiring, coverage building and result summarising. This design adds spec
discovery, import and diffing on top.

Extract the Semgrep invocation — availability probe, native run, Docker fallback,
output read — into `mcp/src/surface/scanSemgrep.ts`, leaving `mapAttackSurface.ts`
as coordination. The move is behaviour-preserving; the 578 existing tests are the
net.

### New files

| Path | Responsibility |
| --- | --- |
| `mcp/src/surface/scanSemgrep.ts` | Run Semgrep (native or Docker), return raw output. I/O. |
| `mcp/src/surface/specDiscover.ts` | Find candidate spec files, read them, enforce caps. I/O. |
| `mcp/src/surface/specImport.ts` | Parse one document → routes + report. Pure. |
| `mcp/src/surface/specDiff.ts` | Compare code and spec routes → `SpecDiff`. Pure. |

---

## 4. Data model

### Provenance

```ts
export type RouteProvenance = 'code' | 'spec';
```

`RouteRecord` gains a required `provenance` field. Snapshots written before this
change have routes without it; `rowToSnapshot` in `storage/surfaceRepo.ts` backfills
`'code'` on read. No migration — a snapshot is a point-in-time artifact, and stale
ones are history.

### Spec-derived routes

| Field | Value |
| --- | --- |
| `method` | the operation key (`get`, `post`, …), uppercased |
| `path_raw` | the path template as written, e.g. `/users/{id}` |
| `path_resolved` | server base path + `path_raw` (see below) |
| `path_partial` | true **only** when the server URL is templated |
| `file` | the spec file path |
| `line` | YAML: the path item's line, from the parser's position info. JSON: 0 — `JSON.parse` reports no positions. |
| `framework` | `openapi-3` or `swagger-2` |
| `language` | `spec` |
| `auth_hint` | see below |
| `params` | path-template parameters, plus `parameters` entries with `in: path` |
| `confidence` | `high` |
| `provenance` | `spec` |

**Resolving the base path.** OpenAPI 3: the path component of `servers[0].url`.
Swagger 2: `basePath`. A document with **no** `servers` / `basePath` is not partial —
both specifications define the default as `/`, so the path template *is* the full
path. Only a server URL containing a `{variable}` makes the base genuinely unknown.
Getting this backwards would send every spec without an explicit `servers` block to
`unmatchable` and gut the feature.

When `servers` has more than one entry, the first is used and the others ignored.
Multiple servers usually means the same API at several hosts, not several base
paths; if that assumption is ever wrong for a real document it will show up as
`spec_only` entries, not as false shadow endpoints.

**`auth_hint` from a spec is the one place authentication is declared
affirmatively.** The rule established in the `map_attack_surface` design is that
`'none'` is never inferred from the absence of an auth decorator. OpenAPI's
`security: []` on an operation is not an absence — it is an explicit statement that
the operation is unauthenticated, and it is the second legitimate source of `'none'`
after WordPress's `permission_callback: '__return_true'`.

- operation `security: []` → `'none'`
- operation `security: [...]` non-empty → `'required'`
- no operation `security`, document-level `security` non-empty → `'required'`
- no operation `security`, no document-level `security` → `'unknown'`

### Reports and diff

```ts
export interface SpecFileReport {
  file: string;
  format: 'openapi-3' | 'swagger-2' | 'unknown';
  status: 'ok' | 'parse_error' | 'unsupported_version' | 'no_paths';
  routes_found: number;
  /** Present for every status except 'ok'. Names the cause in one line. */
  reason?: string;
  /** Path items that were an unresolved external $ref. Counted, never ignored. */
  unresolved_refs: number;
}

export interface SpecDiffEntry {
  method: HttpMethod;
  /** The normalised comparison key, human-readable: `/users/{}`. */
  path: string;
  code_route?: RouteRecord;
  spec_route?: RouteRecord;
  /** Present on `unmatchable` entries: why it could not be classified. */
  reason?: string;
}

export interface SpecDiff {
  matched: SpecDiffEntry[];
  /** In code, absent from every spec — shadow endpoints. */
  code_only: SpecDiffEntry[];
  /** In a spec, absent from the code — dead documentation. */
  spec_only: SpecDiffEntry[];
  /** Could not be classified either way. Never counted as a finding. */
  unmatchable: SpecDiffEntry[];
}
```

`AttackSurfaceSnapshot` gains `spec_files: SpecFileReport[]` and
`spec_diff: SpecDiff | null`. `routes[]` holds both provenances.

**`buildCoverage` must filter to `provenance === 'code'`.** It currently derives its
language set from `routes.map(r => r.language)`, so spec routes carrying
`language: 'spec'` would create a phantom coverage entry reading
`status: 'no_rules'` — the rule pack covers no framework for the language "spec",
which is true and meaningless. `coverage[]` is a per-language report about code, and
a spec is not a language.

---

## 5. Matching, and the rule that governs it

Both sides normalise to a comparison key of `(method, normalised path)`. Every
parameter syntax collapses to a single placeholder, so the same endpoint written
four ways compares equal:

| Source | Written | Normalised |
| --- | --- | --- |
| OpenAPI | `/users/{id}` | `/users/{}` |
| Express | `/users/:id` | `/users/{}` |
| Flask | `/users/<int:id>` | `/users/{}` |
| WordPress | `/users/(?P<id>\d+)` | `/users/{}` |

Trailing slashes are stripped. A code route whose method is `ANY` matches a spec
operation of any method — the code genuinely accepts all of them.

### `unmatchable` is not a rounding error

A code route with `path_partial: true` has an unresolved prefix. Its full path is
unknown, so it cannot be shown absent from a spec — only unclassified. The same
holds for a spec route whose server URL is templated. Both go to `unmatchable` with
a reason, and **neither is ever reported as a shadow endpoint or as dead
documentation**.

**The unmatchable route also protects its counterpart.** This is the part that is
easy to get wrong. Suppose the code registers `/list` behind an unresolved router
mount, and the spec declares `/api/list`. The code route goes to `unmatchable`
correctly — but the spec route, having matched nothing, would then fall into
`spec_only` and be reported as dead documentation. It is not dead; it is the very
route we could not resolve.

So: an unmatched spec route is classified `spec_only` **only if no `path_partial`
code route's normalised `path_raw` is a suffix of it**. If one is, both go to
`unmatchable` with the reason naming the other. Suffix is the right test because
what a partial route is missing is precisely a prefix.

This costs some true dead-documentation findings when a project has partial routes.
That is the correct direction: a missed finding is a gap, a false "this endpoint no
longer exists" is a lie that gets documentation deleted.

### Without a spec there is no diff

If no candidate file was found, or every candidate failed to parse, `spec_diff` is
`null` with a reason. It is never a diff in which every code route is `code_only`.

This is the correctness decision of the design, and it is written down because the
`map_attack_surface` implementation produced five separate defects of exactly this
class — a value that is not known acquiring the appearance of being known, twice
emitted as a resolved URL. "No spec was found" and "the spec documents nothing"
must remain distinguishable, and the only safe way is to refuse to produce a diff.

---

## 6. Discovery and error handling

Candidate files, searched with the exclusion set `computeTreeHash` already uses:

- `openapi.{json,yaml,yml}`, `swagger.{json,yaml,yml}`, `api-docs.json`
- anything under an `openapi/` directory with those extensions

`spec_paths` on the tool input replaces discovery entirely when supplied.

**Caps:** at most 20 files, at most 5 MB each. When a cap truncates the set, the
result says so — a silent cap reads as "there were only 20".

**Version detection:** `openapi: "3.x"` → `openapi-3`; `swagger: "2.0"` →
`swagger-2`; neither key → `unknown` with status `unsupported_version`.

| Condition | Behaviour |
| --- | --- |
| No candidate files | `spec_files: []`, `spec_diff: null`, reason `no_specs` |
| YAML/JSON parse error | `parse_error` + reason; contributes no routes; other specs still count |
| Valid document, zero paths | `no_paths`; contributes no routes; counts as a successful parse — a spec declaring nothing is information |
| File exceeds the size cap | `parse_error`, reason names the cap |
| Every candidate failed | `spec_diff: null`, reason names it |
| Path item is an external `$ref` | counted in `unresolved_refs`, contributes no route |

Internal `$ref`s (`#/components/parameters/...`) are resolved within the document.
External file references are not followed in v1, and are counted rather than
skipped — an unresolved path item that vanished silently would resurface as false
dead documentation.

---

## 7. Tool contract

```text
map_attack_surface(
  project_path?, force?, include_env_vars?,
  spec_paths?: string[]        // overrides discovery
)
→ {
    routes_total,              // code routes only — meaning unchanged
    spec_routes_total,
    by_language[], coverage[],
    spec_files: SpecFileReport[],
    spec_diff_summary: {
      matched: number, code_only: number,
      spec_only: number, unmatchable: number
    } | null,
    shadow_sample: SpecDiffEntry[],   // first 20 of code_only
    snapshot_id, sample, env_vars_total, ports,
    tools_run[], missing_tools[]
  }
```

Full diff lists are served by the existing resources, not the tool result — same
reason the full route list already is: a large project would exhaust the agent's
context window on every call.

---

## 8. Testing

| Layer | Target | Cases |
| --- | --- | --- |
| unit | `specImport` | OpenAPI 3 with `servers`; Swagger 2 with `host` + `basePath`; `security: []` → `'none'`; document-level security; operation override; version detection; internal `$ref` parameters; external `$ref` path item; malformed YAML; malformed JSON; zero-paths document |
| unit | `specDiff` | all four buckets; `ANY` method; the four parameter syntaxes; trailing slash; `path_partial` code route → `unmatchable`; templated server → `unmatchable`; **a spec route whose suffix matches a partial code route → both `unmatchable`, neither `spec_only`**; a spec route sharing no suffix with any partial route → still `spec_only`; empty spec set → `null`; every-spec-failed → `null` |
| unit | `specDiscover` | name patterns; exclusion set; file cap; size cap; `spec_paths` override |
| unit | `scanSemgrep` | behaviour preserved after extraction — the existing integration tests cover this and must pass unchanged |
| integration | `surfaceTools` | a project with code and a spec: shadow detected, dead documentation detected, `path_partial` route not reported as shadow |
| e2e | `rulePackFixture` | the fixture app tree gains an `openapi.yaml` documenting some real routes, omitting one (shadow) and declaring one that does not exist (dead); asserted as an exact set, gated by `GUARDIAN_REQUIRE_SEMGREP` as the existing e2e is |

---

## 9. Repo conventions

- Build and test from `mcp/`. `npm test` is `vitest run`; `npm run test:coverage`
  enforces 70/62/72/70.
- Semgrep-dependent tests skip visibly via `it.skipIf` and hard-fail under
  `GUARDIAN_REQUIRE_SEMGREP=1`. Semgrep on this machine lives at
  `%APPDATA%\Roaming\Python\Python314\Scripts` and is not on the system PATH.
- **Commit `mcp/dist/` in the same commit as any TypeScript change.** The repo is
  the distribution.
- ESM `NodeNext`: relative import specifiers end in `.js`.
  `noUncheckedIndexedAccess` is on; no `!` assertions.
- Versions in `.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json` and
  `mcp/package.json` move in lock-step at release time; this work keeps them at
  1.2.1 with a `CHANGELOG.md` `Unreleased` entry.

---

## 10. Definition of done

- [ ] OpenAPI 3.x and Swagger 2.0 documents are discovered, parsed and imported.
- [ ] Spec routes carry `provenance: 'spec'`; code routes `provenance: 'code'`;
      old snapshots read back as `'code'`.
- [ ] `auth_hint: 'none'` is emitted for `security: []` and never inferred.
- [ ] The four diff buckets are produced, with `unmatchable` never reported as a
      finding.
- [ ] No spec, or every spec failing, yields `spec_diff: null` with a reason — never
      a diff declaring every route undocumented.
- [ ] `routes_total` still counts code routes only.
- [ ] Caps and unresolved external `$ref`s are reported, never silent.
- [ ] `scanSemgrep.ts` extracted with the existing tests passing unchanged.
- [ ] Suite green with `GUARDIAN_REQUIRE_SEMGREP=1`; coverage above thresholds.
- [ ] `mcp/dist/` rebuilt and staged in the same commit.
