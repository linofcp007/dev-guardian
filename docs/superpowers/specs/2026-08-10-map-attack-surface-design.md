# Design — `map_attack_surface`

**Date:** 2026-08-10
**Status:** approved, ready for implementation planning
**Scope:** one MCP tool, one migration, one repository, one resource module (two URIs),
one Semgrep rule pack.

---

## 1. Context

dev-guardian is entirely static today. It never executes the target application and
never enumerates what that application exposes. Three consequences:

- `scan_dast` (planned next) would have no target list — a blind crawl.
- `risk_score` weights findings by severity alone. It cannot tell a handler on a public
  route from a one-off build script.
- Nothing answers the plain question "what does this app expose?".

`map_attack_surface` is the first of three tools in the *Attack surface + DAST*
sub-project. It produces a structured, persisted inventory of the application's
externally reachable surface, extracted **statically from source**.

This is the first of seven planned gaps identified against
[usestrix/strix](https://github.com/usestrix/strix). The agreed order is:
`map_attack_surface` → OpenAPI import → `scan_dast` → `validate_finding` →
headless CLI scan → local dashboard → `create_fix_pr`. Each gets its own
spec → plan → implementation cycle.

### Non-goals

Deliberately excluded, and excluded permanently rather than deferred:

- **Live infrastructure enumeration** — open ports on a host, cloud buckets, subdomain
  discovery. That is reconnaissance: it requires network access to systems the user may
  not own, and it changes dev-guardian's risk profile from "defensive, runs locally" to
  "offensive tooling". Everything in this design is derived from files in the repository.

Deferred to later specs (not this one):

- OpenAPI / Swagger / Postman import — the next spec in the sub-project.
- GraphQL schema and gRPC service extraction.
- Authentication-flow simulation.
- Prefix resolution for languages other than JavaScript/TypeScript and PHP/WordPress.

---

## 2. Decisions taken during design

| Decision | Choice | Rationale |
| --- | --- | --- |
| Primary consumer | Single schema serving DAST **and** `risk_score` **and** human inventory, with DAST driving priority | The expensive work is parsing routes. Once the parse is running, `handler_file:line` (for `risk_score`) and referenced env vars (for inventory) are byproducts of the same pass, not extra work. |
| Language coverage | All 8 stacks `detect_stack` knows: JS/TS, Python, PHP, Go, Rust, Ruby, Java, C#/.NET | User requirement. Drives the engine choice below. |
| Extraction engine | **Hybrid**: a Semgrep rule pack as the universal extractor, plus a pure-TypeScript resolver pass for route-prefix resolution | Semgrep already parses all 8 languages and is already a hard dependency. Rules are data, so a new framework is a YAML entry rather than a new parser. Hand-written extractors for 8 languages would turn the project into a parser-maintenance effort. |
| Resolver scope | JS/TS router mounting and WordPress `register_rest_route` namespaces only | These two cover the stacks with the largest user base and the worst raw-path accuracy. Each resolver gates on the route's own language/framework — see §5, which records why a rule-metadata flag was rejected. |
| Persistence | New `surface_snapshots` table, not the `findings` table | A route is not a finding: no severity, no fingerprint, no meaningful suppression. Same reasoning that gave `detect_stack` its own `stack_snapshots` table. |
| Tool return shape | Summary + `snapshot_id` + 20-route sample; full list via MCP resource | A 400-route project would exhaust the agent's context window on every call. Downstream tools read the snapshot from SQLite rather than receiving routes as arguments. |
| Failed scan | Persist **nothing** | See §6. This is a correctness decision, not cosmetics. |

---

## 3. Architecture

```text
map_attack_surface(project_path, force?, include_env_vars?)
  │
  ├─ 1. StackRepo.getLatest()          → which languages are present
  │
  ├─ 2. Semgrep pass                   ← the ONLY step with external I/O
  │       semgrep --config <plugin>/configs/semgrep/routes.yml --json
  │       reuses scannerAvailable() + runProcess() + the Docker fallback
  │       already implemented in scanSast.ts
  │
  ├─ 3. src/surface/extract.ts         PURE   semgrep JSON → RouteRecord[]
  │
  ├─ 4. src/surface/resolvers/         PURE
  │        node.ts        app.use('/api', router) → resolved prefix
  │        wordpress.ts   register_rest_route(ns, r) → /wp-json/<ns><r>
  │
  ├─ 5. src/surface/collectors/        PURE   env vars, ports, webhooks
  │
  └─ 6. SurfaceRepo.insert(snapshot)   → surface_snapshots
```

Only step 2 touches the outside world. Steps 3–5 are pure functions over data and are
unit-testable with no scanner installed — the same split already used by
`mcp/src/hooks/{secretScan,bashGuard}.ts`, where pure detectors are shared between the
hook dispatcher and the CLI.

That split is also what makes the hybrid cheap: the resolver is a transformation over an
array, not a second scanner.

### New files

| Path | Purpose |
| --- | --- |
| `configs/semgrep/routes.yml` | The rule pack. Resolved via `resolveConfigsDir(ctx.scriptsDir)`, the same way `initProject` resolves `semgrep/base.yml`. |
| `mcp/src/surface/extract.ts` | Semgrep JSON → `RouteRecord[]` |
| `mcp/src/surface/resolvers/node.ts` | JS/TS router-mount prefix resolution |
| `mcp/src/surface/resolvers/wordpress.ts` | WP REST namespace resolution |
| `mcp/src/surface/collectors/envVars.ts` | Referenced environment variables |
| `mcp/src/surface/collectors/ports.ts` | `EXPOSE` directives, compose `ports:` |
| `mcp/src/storage/surfaceRepo.ts` | Mirrors `stackRepo.ts` |
| `mcp/src/storage/migrations/002_attack_surface.sql` | `surface_snapshots` table |
| `mcp/src/tools/mapAttackSurface.ts` | The tool module |
| `mcp/src/resources/surface.ts` | `guardian://surface/latest`, `guardian://surface/{id}` |

`mcp/src/registerAll.ts` gains one tool import and one resource import.

---

## 4. Data model

```ts
type HttpMethod =
  | 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'
  | 'OPTIONS' | 'HEAD' | 'ANY';

interface RouteRecord {
  method: HttpMethod;
  path_raw: string;          // exactly as written at the match site
  path_resolved: string;     // after prefix resolution; equals path_raw when no resolver applies
  /**
   * True when `path_resolved` is NOT a usable URL path. Two causes:
   *   1. a prefix may be missing and we know it (unresolved router mount,
   *      missing WordPress namespace);
   *   2. the captured value is a code expression rather than a literal —
   *      `self::NAMESPACE`, `$this->namespace`, `Paths.ORDERS`, `routeVar`.
   *
   * Case 2 matters more than it looks: `register_rest_route(self::NAMESPACE, …)`
   * is the dominant idiom in real WordPress plugins, and emitting the variable
   * name as a resolved path would hand a DAST tool a fabricated URL to attack.
   * The route is still reported — surface we cannot name is still surface — but
   * never as though we knew where it lives.
   */
  path_partial: boolean;
  file: string;
  line: number;
  framework: string;         // 'express' | 'fastapi' | 'aspnet-minimal' | 'gin' | ...
  language: string;
  auth_hint: 'none' | 'required' | 'unknown';
  params: string[];          // path parameters, normalised: ':id' and '{id}' both → 'id'
  confidence: 'high' | 'medium' | 'low';
  /**
   * Framework-level route namespace, when the framework has one. Currently
   * only WordPress: `register_rest_route('myplugin/v1', '/items')` yields
   * namespace 'myplugin/v1'. The WP resolver combines it with path_raw to
   * produce the served /wp-json path.
   */
  namespace?: string;
}
```

### How `auth_hint` is derived

`auth_hint` comes **only** from rule metadata, never from inference:

- `'required'` — the rule matched an explicit authenticated-route idiom
  (`@login_required`, `[Authorize]`, a `permission_callback` that is not `__return_true`).
- `'none'` — the rule matched an explicit *public* declaration. In practice v1 emits this
  only for WordPress `permission_callback: '__return_true'`, which is an affirmative
  statement that the route is open.
- `'unknown'` — everything else, which will be the majority.

Absence of an auth decorator must never produce `'none'`. Auth is frequently applied by
middleware, a route group, or a framework-wide default that a pattern matcher cannot see;
reporting "no auth" from silence would hand `scan_dast` and `risk_score` a confident
falsehood. `'unknown'` is the honest answer and downstream tools must treat it as such.

### Snapshot types

```ts
interface CoverageEntry {
  language: string;
  detected: boolean;         // the stack snapshot reported this language
  routes_found: number;
  status: 'ok' | 'no_matches' | 'no_rules';
}

interface AttackSurfaceSnapshot {
  routes: RouteRecord[];
  env_vars: { name: string; file: string; line: number }[];
  ports: { port: number; source: string }[];
  webhooks: RouteRecord[];   // convenience view: routes whose path matches /webhook|callback|hook/i
  coverage: CoverageEntry[];
  tools_run: ToolRun[];
  missing_tools: string[];
}
```

`ToolRun` is the existing type from `mcp/src/types.ts`. `webhooks` duplicates entries that
are already in `routes` — it is a precomputed view, kept because every consumer would
otherwise re-derive it with the same regex.

### Table

```sql
-- 002_attack_surface.sql
CREATE TABLE IF NOT EXISTS surface_snapshots (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  project_path TEXT NOT NULL,
  captured_at  TEXT NOT NULL,
  tree_hash    TEXT NOT NULL,
  json         TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_surface_captured_at
  ON surface_snapshots(captured_at DESC);
CREATE INDEX IF NOT EXISTS idx_surface_tree_hash
  ON surface_snapshots(tree_hash);
```

Forward-only, matching the existing runner. `SurfaceRepo` mirrors `StackRepo`:
`insert()`, `getLatest()`, `listRecent(limit)`, `getById(id)`.

`getById` is the one addition over `StackRepo` — the resource needs it to serve
`guardian://surface/{id}`.

### Caching and the `force` flag

`tree_hash` is a column here rather than a row in the existing `tree_cache` table, because
`tree_cache` declares `FOREIGN KEY (scan_id) REFERENCES scans(id)`. `map_attack_surface`
produces a snapshot, not a scan, so reusing that table would mean fabricating a `scans`
row purely to satisfy the constraint.

The tool computes the tree hash with the existing `computeTreeHash()`
(`mcp/src/treeHash/computeTreeHash.ts`). When `force` is `false` and the latest snapshot
for this project carries the same hash, the tool returns that snapshot without invoking
Semgrep, and reports `tools_run: [{ name: 'semgrep', status: 'skipped', reason: 'cached' }]`.
`force: true` always re-runs.

---

## 5. Rule pack and the metadata contract

The rules themselves are data and will grow over time. The part that is **design** is the
metadata contract between the YAML and `extract.ts`:

```yaml
rules:
  - id: guardian-route-express
    languages: [javascript, typescript]
    severity: INFO
    message: express route
    metadata:
      guardian_kind: route      # extract.ts ignores any match without this
      framework: express
      confidence: high          # flows to RouteRecord.confidence — a trust signal, so
                                # rate it honestly rather than optimistically
    patterns:
      - pattern: $APP.$METHOD($PATH, ...)
      - metavariable-regex:
          metavariable: $METHOD
          regex: ^(get|post|put|patch|delete|options|head|all)$
```

- The HTTP method comes from the `$METHOD` metavariable, the path from `$PATH`
  (`extra.metavars.$PATH.abstract_content` in Semgrep's JSON).
- One rule per framework family rather than one per method. This keeps the pack at
  roughly 15–20 rules across 8 languages instead of 100+.
- Decorator- and attribute-based frameworks (`@app.get`, `@GetMapping`, `[HttpGet]`,
  `Route::get`) use the same shape with the pattern written against the decorator.
- **Namespaced frameworks capture two metavariables.** WordPress's
  `register_rest_route($NS, $ROUTE, ...)` yields `$NS` and `$ROUTE` rather than `$PATH`.
  Semgrep cannot concatenate metavariables into a third, so the extractor reads both and
  fills `RouteRecord.namespace` alongside `path_raw`. Any future namespaced framework
  follows the same shape — the composition lives in `extract.ts`, where it is testable,
  never in a magic separator inside a path string.

Two properties this contract guarantees:

1. **This Semgrep run produces no findings.** It is a separate `--config` invocation whose
   output is consumed by the surface extractor and never reaches `findingsRepo`.
   `severity: INFO` exists only because Semgrep requires the field.
2. **The resolvers gate on the route's language and framework, not on a rule-pack flag.**
   `resolveNodeMounts` runs only for `javascript` / `typescript` routes;
   `resolveWordpressRoutes` only for `framework: wp-rest`. Everything else passes through
   with `path_resolved === path_raw` and `path_partial: false`.

   An earlier draft of this design put a `mountable: true` flag in the rule metadata and
   claimed the boundary lived in the data. That was rejected during implementation: a flag
   only works if every future rule author remembers to set it, and a forgotten flag fails
   silently — the route simply never gets its prefix. Deriving the gate from the language
   the route was extracted from cannot be forgotten. The rule pack carries no such flag.

`extract.ts` must tolerate rules whose metadata is incomplete: a match missing
`guardian_kind: route` is skipped; a match missing `confidence` defaults to `'low'`.
The rule pack is user-extensible, so malformed third-party rules must not crash the tool.

### Literal guards belong in the extractor, not in the rules

A metavariable can bind a code expression rather than a string — `self::NAMESPACE`,
`$this->namespace`, `Paths.ORDERS`. Those must be reported as routes with
`path_partial: true`, never as resolved paths.

The guard lives in `extract.ts`, not in the YAML, and the reason is mechanical:
Semgrep's `metavariable-regex` is a **conjunct**. A rule carrying one does not
report a non-matching capture as a weaker match — it discards the match entirely.
So a literal guard in the pack deletes exactly the routes this design wants
flagged, and `coverage` then reports `no_matches` for the language: the
"this application exposes nothing" falsehood §6 exists to prevent.

Two rules keep a YAML guard because there the capture genuinely disambiguates
*whether a match is a route at all* rather than whether its path is literal:
`guardian-route-rails` (its `$METHOD $PATH` pattern matches any one-argument Ruby
call) and `guardian-route-express`. Everywhere else, a match already means "this
is a route registration", and the only open question is whether we can name it.

Putting the guard in the extractor also covers rules users add through
`register_custom_rules`, which the pack cannot.

---

## 6. Error handling and honest coverage

### A failed scan persists nothing

If Semgrep is unavailable (not installed and no Docker fallback), or the Semgrep process
fails, the tool returns a degraded result — `missing_tools: ['semgrep']`, a `tools_run`
entry with `status: 'skipped'`, and the install hint — and **writes no snapshot**.

The reason is downstream correctness. A zero-route snapshot written by a failed run would
later be read by `scan_dast` and `risk_score` as *"this application exposes nothing"* —
the exact inverse of the truth. "Zero routes because the scan failed" and "zero routes
because there are none" must stay distinguishable, and the only safe way to do that is to
write nothing on failure.

### Coverage is reported per language

| `status` | Meaning |
| --- | --- |
| `ok` | Rules existed for this language and matched. |
| `no_matches` | Rules existed and found nothing — most likely there are no routes. |
| `no_rules` | The language was detected but no rule covers its framework. |

`no_rules` is the case most tools hide. If a project uses Hapi or Actix and the pack has no
rule for it, the output says so rather than reporting zero and implying safety. This
follows the honest-coverage posture established in release 1.1.4.

### Other failure modes

| Condition | Behaviour |
| --- | --- |
| Not a git repository | `DomainError` `not_a_git_repo`, consistent with `detect_stack`. |
| No stack snapshot exists yet | Run anyway with all rules enabled; `coverage[].detected` is `false` for every language, and the result advises running `detect_stack` first. |
| Semgrep exits non-zero but emits partial JSON | Parse what is there, mark the `tools_run` entry `failed`, persist the snapshot, and set the affected languages to `no_matches`. Partial data is still useful; the `tools_run` status carries the warning. |
| Malformed rule metadata | Skip that match, continue. Never throw. |

---

## 7. Tool contract

```text
map_attack_surface(
  project_path?: string,      // ProjectPath, from schemas.ts
  force?: boolean,            // Force, from schemas.ts — bypass the tree-hash cache
  include_env_vars?: boolean  // default true
)
→ {
    routes_total: number,
    by_language: { language: string, routes: number }[],
    coverage: CoverageEntry[],
    snapshot_id: number,
    sample: RouteRecord[],    // first 20, ordered by language then path
    env_vars_total: number,
    ports: { port: number, source: string }[],
    tools_run: ToolRun[],
    missing_tools: string[]
  }
```

Input primitives come from `mcp/src/schemas.ts` rather than inline literals, per the
convention documented in that file.

### Resources

- `guardian://surface/latest` — the most recent full `AttackSurfaceSnapshot`.
- `guardian://surface/{id}` — a specific snapshot by id.

---

## 8. Testing

All tests run without Semgrep installed. Integration tests mock `scannerAvailable` and
`runProcess` and feed recorded scanner output, following the pattern established in
`mcp/test/integration/securityTools.test.ts`.

| Layer | Target | Cases |
| --- | --- | --- |
| unit | `surface/extract.ts` | One recorded Semgrep JSON fixture per language in `test/fixtures/surface/`; malformed metadata; missing `guardian_kind`; missing `confidence` |
| unit | `surface/resolvers/node.ts` | Nested `app.use()` chains; a router never mounted; the same router mounted twice; mount with a variable prefix (→ `path_partial: true`) |
| unit | `surface/resolvers/wordpress.ts` | Namespace plus route; leading/trailing slash variants |
| unit | `surface/collectors/envVars.ts` | `process.env.X`, `os.environ[...]`, `getenv()`, `Environment.GetEnvironmentVariable` |
| unit | `surface/collectors/ports.ts` | Dockerfile `EXPOSE`; compose `ports:` in both short and long form |
| unit | `storage/surfaceRepo.ts` | insert / getLatest / getById / listRecent |
| unit | migrations | `002` applies cleanly on top of a database already at `001` |
| integration | `test/integration/surfaceTools.test.ts` | Happy path; **Semgrep missing ⇒ nothing persisted**; Semgrep partial failure ⇒ snapshot persisted with `failed` tool run; `no_rules` coverage reporting |
| integration | `toolSurface.test.ts` | Snapshot updated: +1 tool, +2 resources — a deliberate, reviewed change |

---

## 9. Repo conventions this must respect

From `CLAUDE.md`:

- Build from `mcp/`: `npm run build`, then `npm test`.
- **Commit `mcp/dist/` in the same commit as the TypeScript change.** The repo is the
  distribution; a stale `dist/` desyncs silently.
- `copy-assets.mjs` mirrors `src/storage/migrations/*.sql` into `dist/`. The new migration
  is covered by the existing rule and needs no change to that script. `configs/semgrep/`
  sits at the plugin root and is read from there at runtime, so it is not affected either.
- Markdownlint stays clean for `skills/`, `commands/` and `README.md`.
- A release bumps the version in `.claude-plugin/plugin.json`,
  `.claude-plugin/marketplace.json` and `mcp/package.json` together, adds a `CHANGELOG.md`
  entry, and tags `vX.Y.Z`.

---

## 10. Definition of done

- [ ] `map_attack_surface` registered and visible in the MCP tool surface.
- [ ] `configs/semgrep/routes.yml` covers all 8 stacks, with `no_rules` honestly reported
      for framework families the pack does not cover.
- [ ] Prefix resolution works for JS/TS router mounting and WP REST namespaces.
- [ ] `surface_snapshots` persists across runs; both resources serve.
- [ ] A failed or scanner-less run persists nothing and says why.
- [ ] Full test matrix in §8 passes with `npm test`, with Semgrep absent from the machine.
- [ ] `mcp/dist/` rebuilt and staged in the same commit.
