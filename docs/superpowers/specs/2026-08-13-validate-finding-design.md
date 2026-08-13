# Design — `validate_finding`, reachability qualification for findings

Item 4 of 7 in the strix-gap project. `triage_findings` classifies by file
path; `prioritize_findings` orders by severity and age. Neither knows whether
the vulnerable code can be reached at all. This tool answers that, using what
items 1–3 built: a route inventory carrying `file` and `line`, and live
confirmation of which routes actually answer.

## 1. Context

A static finding at `src/db/users.ts:88` is worth a different amount depending
on an answer no scanner in this server currently produces: **can anything
outside the process reach that line?** A SQL injection in a helper no route
imports is a latent defect; the same injection one hop from an anonymously
reachable `GET /admin/export` is an incident waiting to happen.

The tool is asymmetric by nature and the design leans into it: it is far better
at **disproving** reachability than proving it. "No externally reachable route
imports this file, directly or transitively" is a strong claim. "It is imported,
therefore the vulnerability is reachable" is weak — importing is not calling.
Every rule below follows from that asymmetry.

### Non-goals (v1)

- **No call graph.** Granularity is the file. An import graph cannot say whether
  the vulnerable function is invoked; claiming otherwise would fabricate the
  one thing the data does not contain.
- **No automatic suppression, and no severity mutation.** The verdict is
  reported and persisted; closing a finding stays a human decision. An import
  graph with a hole would otherwise silently deprioritise an exploitable finding
  — and severity is a field `set_baseline` and `diff_scans` compare across runs.
- **No LLM calls.** Consistent with `triage_findings` and `prioritize_findings`:
  boring, inspectable rules only.

## 2. Decisions taken during design

Locked with the user, in order:

1. **Three evidence providers under one tool** — `static` (this cycle),
   `runtime`, `dependency`. One shared verdict envelope, defined once now.
2. **Import rules for all eight stacks**, accepting that four of them can never
   yield the negative verdict (§5). The positive direction and the hop evidence
   justify them on their own.
3. **Report only.** No auto-suppression, no severity adjustment, no flag to
   enable either.
4. Granularity is the **file**; the tool accepts a single `fingerprint` **or**
   validates every open finding, batch by default (controller decisions, stated
   here so they are not re-litigated).

## 3. Architecture

```text
validate_finding(project_path, fingerprint?, providers?)
        │
        ├── static      ← import graph + surface snapshot      (this cycle)
        ├── runtime     ← the scan_dast probe engine           (next cycle)
        └── dependency  ← advisories + package manifests       (last cycle)
                │
                v
        one verdict per finding, persisted
```

Each provider is its own spec → plan → implementation cycle. **This cycle
delivers the envelope, the table, the tool, and the `static` provider.** The
other two must slot in without changing the contract; if either turns out to
need a contract change, that is a finding against this design, not against them.

### New files

| Module | Kind | Responsibility |
| --- | --- | --- |
| `mcp/src/validate/types.ts` | types | The verdict envelope, shared by all three providers. |
| `mcp/src/validate/importGraph.ts` | **pure** | `ImportRecord[]` → adjacency, transitive closure from a root set. No I/O. |
| `mcp/src/validate/staticProvider.ts` | **pure** | Snapshot + graph + finding → verdict. All the honesty rules live here. |
| `mcp/src/storage/validationsRepo.ts` | I/O | `finding_validations` table. |
| `mcp/src/storage/migrations/003_finding_validations.sql` | schema | |
| `mcp/src/tools/validateFinding.ts` | orchestrator | Wiring. No verdict logic. |
| `configs/semgrep/routes.yml` | modify | Import rules for all eight stacks (§6). |

The pure/I-O split is the boundary that survived items 1–3: every fabrication
defect in this project was born in a layer that read input and decided at the
same time.

## 4. The verdict envelope

```ts
export type Verdict = 'unreachable' | 'reachable' | 'confirmed' | 'unknown';

export interface ValidationEvidence {
  /** One concrete, human-readable fact. Never a summary or a score. */
  detail: string;
}

export interface FindingValidation {
  fingerprint: string;
  verdict: Verdict;
  confidence: 'high' | 'medium' | 'low';
  provider: 'static' | 'runtime' | 'dependency';
  evidence: ValidationEvidence[];
  /** What this provider could NOT see. Empty only when nothing was missing. */
  coverage_gaps: string[];
  /** The surface snapshot this was computed against. */
  snapshot_id: number;
  tree_hash: string;
  computed_at: string;
}
```

**`unknown` is the default and every provider must earn its way out of it.**
Absence of evidence is `unknown`, never `unreachable`. A provider that cannot
answer says so; it does not fall back to the reassuring value.

`confirmed` exists for the `runtime` provider and is not producible by `static`.
It is in the union now so the persisted shape does not change when that provider
lands.

## 5. When the negative verdict is available — and when it is not

`unreachable` is the tool's strongest output and its most dangerous. Emitting it
wrongly deprioritises an exploitable finding, and nobody looks again. It is
therefore gated on **three** conditions, all of which must hold:

### 5.1 The graph must cover the file's language

No import rule for a language means no edges for its files. A Go file in a
project whose Go rules did not run is `unknown` — not `unreachable`.

### 5.2 The route set must be complete

`unreachable` means "no route reaches this". That is a claim about the *whole*
route list, so it is unsound when the list is partial.

The surface snapshot's `coverage` is **per language**, not a single value, and
the gate is per language too — deliberately tighter than a global check. A
route written in Go cannot import a TypeScript file: reachability does not cross
language boundaries inside one process. So the negative verdict for a file in
language L requires the snapshot's coverage entry **for L** to be `ok`; a
missing Python rule pack does not block an `unreachable` verdict about a Go
file, and must not, or the tool would answer `unknown` to almost everything in
any polyglot repository.

`CoverageEntry.status` has four values and they split two-and-two:

| status | `unreachable` permitted? | Why |
| --- | --- | --- |
| `ok` | **yes** | rules ran, routes found and readable |
| `no_matches` | **yes** | rules ran and this language genuinely declares no routes — so no route in it can reach anything |
| `no_rules` | **no** | the language is present and the pack covers no framework for it; routes may exist unseen |
| `unreadable` | **no** | Semgrep matched routes here and the captures could not be read — routes exist and are missing from the inventory |

`no_matches` permitting the negative is the non-obvious half, and it matters: the
strict reading ("only `ok`") would answer `unknown` for every file in any
language that legitimately has no HTTP surface, which is most of them in most
repositories. When the entry is `no_rules` or `unreadable`, the negative verdict
is unavailable for that file and the reason is named in `coverage_gaps`.

This is the first time in this project that `coverage` carries weight rather
than decorating a result. It becomes a **precondition of a verdict**.

### 5.3 The stack must resolve code by import

An import graph describes reachability only where importing is how code reaches
code. In four of the eight stacks it is not:

| Stack | `unreachable` available? | Why |
| --- | --- | --- |
| JS / TS | **yes** | explicit imports |
| Go | **yes** | explicit imports |
| Rust | **yes** | explicit `use` |
| Python | **yes** | explicit imports |
| Ruby / Rails | **no** | autoload by convention — most files are imported by nothing |
| Java / Spring | **no** | annotation-driven injection |
| C# / ASP.NET | **no** | DI container |
| PHP / Laravel | **no** | service container |

In a Rails project "nothing imports this file" is true of nearly every file and
means nothing. **In a runtime-resolution stack the `static` provider returns
only `reachable` or `unknown`, never `unreachable`**, and says which of the two
reasons applies.

This is not a defect to fix later. It is what an import graph can honestly
assert, and the rules still earn their place in those stacks through the
positive direction and the hop evidence.

### 5.4 Reflection and dynamic imports, everywhere

`import(expr)`, `require(variable)`, reflection, and plugin registries are
invisible to any import graph. They under-approximate reachability in *every*
stack, including the four above. Where the extractor can see that a file
contains a dynamic import it cannot resolve, that file's dependents are
`unknown` rather than `unreachable`, and the unresolved import is named in
`coverage_gaps`.

## 6. Import rules — the rule pack extension

`configs/semgrep/routes.yml` gains import rules for all eight stacks, following
the metadata contract already established there (`guardian_kind: import`).

The existing `guardian-import-esm` matches only `import X from "…"` and
`const X = require("…")` — **it misses `import { foo } from "./bar"`, the
dominant form in modern TypeScript**. That gap is closed as part of this work;
it also silently weakened item 1's mount resolution, so fixing it is a
correction, not only an addition.

Per-stack forms to cover, at minimum: default, named and namespace imports plus
`require` (JS/TS); `import`/`from … import` including aliased and relative
(Python); grouped and single `import` blocks (Go); `use` including grouped
(Rust); `use` statements (PHP); `import` including static and wildcard (Java);
`using` including aliased (C#); `require`/`require_relative`/`load` (Ruby).

Two constraints carried from the item-1 rule-pack work, both learned the hard
way:

- **Every new rule must be validated against the multi-language fixture with a
  real Semgrep run.** Five NestJS rules once shipped with a parse error that
  made them match nothing on every run, and the suite was green.
- **A rule that binds no metavariable, or that Semgrep degrades to matching
  every node in the file, is worse than no rule** — item 1's Rust rules
  fabricated four routes for every real one that way. Where a capture is needed,
  `focus-metavariable` is preferred over post-hoc anchoring.

## 7. What the evidence says

For a `reachable` verdict the evidence is concrete, never a score:

- the **nearest** reaching route, its method and resolved path, and the hop
  count;
- how many routes reach the file in total (a file reached by 200 of 210 routes
  is shared infrastructure — the tool reports that and lets the reader judge,
  rather than inventing a "too shared to matter" heuristic);
- whether any reaching route is **confirmed live and anonymously reachable**.
  The concrete signal is a persisted `scan_dast` finding whose `subcategory` is
  `anonymous_exposure` and whose `file_path` matches the reaching route's file —
  that check fires only on a route the spec declared auth-required and the live
  server served anonymously, so it is evidence, not inference. Absent a DAST
  scan for this project, the clause is simply absent; it is never assumed in
  either direction.

A finding whose own file declares a route is `reachable` at **0 hops**, the
highest-confidence positive this provider can produce.

## 8. Persistence

A new table, `finding_validations`. This mirrors item 1's ruling — *"a route is
not a finding"* justified its own table — for the same reason: **a verdict is a
judgment *about* a finding, not a finding.**

Each row carries `snapshot_id` and `tree_hash`. **A verdict ages**: computed
against tree N, it says nothing once the code moves. Readers get the stored
verdict together with a staleness flag derived by comparing the stored
`tree_hash` against the working tree's current hash. Serving a stale verdict as
current would be the same failure class this project spent three features
removing.

Findings are keyed by fingerprint, which is stable across runs by construction,
so a validation survives re-scans of unchanged code.

## 9. Tool contract

```text
validate_finding(
  project_path: string,
  fingerprint?: string,          // one finding; omitted = every open finding
  providers?: ('static')[],      // v1 accepts only 'static'; the union grows.
                                 // Omitted = every provider available in this
                                 // version, so a caller written today keeps
                                 // working when `runtime` lands.
)
```

Batch is the default and the point: validating findings one at a time saves
nobody any triage effort. An unknown `fingerprint` is an error, not an empty
batch.

Result: per-finding validations, plus a summary carrying the counts by verdict
and the **provider-level coverage gaps** — the languages with no rules, whether
the surface snapshot was `full`, whether a DAST scan was available for the
liveness cross-reference.

Refusals are distinct outcomes, never an empty result: no surface snapshot
(`no_surface_snapshot`, naming `map_attack_surface`), no open findings, and an
unknown fingerprint each read differently.

**A verdict count without its `coverage_gaps` beside it is not an answer** —
the same consumer contract items 1 and 3 carry.

## 10. Testing

- **Pure modules** (`importGraph`, `staticProvider`) get exhaustive unit tests.
  The load-bearing set is **one named test per path that yields `unknown`
  instead of `unreachable`**: uncovered language, snapshot `coverage` not
  `full`, runtime-resolution stack, file absent from the graph, unresolvable
  dynamic import, graph truncated by a cap. Each is an opportunity to
  deprioritise something exploitable, so each gets an assertion that fails if
  the guard is removed.
- **Assertions must distinguish the correct implementation from the
  plausible-wrong one.** Seven of ten tasks in the previous feature shipped an
  assertion that passed for both; this is a standing review criterion, not
  advice.
- **e2e against a multi-language fixture** containing a genuinely orphaned file
  and one reachable at three hops, so both directions are measured rather than
  reasoned about. Semgrep-dependent tests use `it.skipIf` with
  `GUARDIAN_REQUIRE_SEMGREP=1` turning absence into a hard failure — a skipped
  test must read as a skip.

## 11. Known limitations at first release

- File granularity: a finding inside an uncalled helper in an imported file
  reads `reachable`. Correct for what an import graph knows; an over-report in
  the safe direction.
- `unreachable` unavailable in four stacks (§5.3) and wherever an unresolvable
  dynamic import appears (§5.4).
- Reachability is computed from route entry points only. A file reached solely
  by a CLI entry point, a cron job, or a queue consumer reads as unreachable-by-
  route — which is what it is, and what the evidence says. It is not a claim
  that the code never runs.
- The liveness cross-reference is only as fresh as the last `scan_dast` run for
  the project, and its age is reported alongside it.

## 12. Definition of done

- Envelope, table, migration, tool and the `static` provider implemented, with
  the pure/I-O split held.
- Import rules for eight stacks, each validated against the fixture under a real
  Semgrep run; the named-import gap in `guardian-import-esm` closed.
- Every `unknown`-instead-of-`unreachable` path has a named test.
- `unreachable` provably unreachable (in the code sense) when any of §5.1–5.4
  fails.
- Verdicts persisted with `snapshot_id` + `tree_hash`, staleness reported.
- No suppression and no severity mutation anywhere in the diff.
- `npm run build` clean; `npm test` green with **zero skips** under
  `GUARDIAN_REQUIRE_SEMGREP=1`; coverage thresholds held.
- `validate_finding` documented in `host-rules/AGENTS.md` and its paired host
  files, with the two-step relationship to `map_attack_surface` stated.
