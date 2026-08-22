# CLAUDE.md — working in the dev-guardian repo

Guidance for AI assistants (and humans) **contributing to dev-guardian itself**.
For *using* the tools in another project, see [`host-rules/AGENTS.md`](host-rules/AGENTS.md).

## What this repo is

An all-in-one, 100% open-source Claude Code / Cowork plugin for security, bugfix,
quality, deps, observability, performance and compliance. Two halves:

- **Plugin front-end** — `skills/` (13 skills) + `commands/` (slash commands),
  declared in [`.claude-plugin/plugin.json`](.claude-plugin/plugin.json).
- **MCP server** — `mcp/` (TypeScript + SQLite), the real engine: 54 tools,
  18 resources. Built to `mcp/dist/`.
- **Guardrail hooks** — `hooks/hooks.json` (auto-discovered at the plugin root)
  with the `hooks/guardian-hook.mjs` dispatcher. Dependency-free and fail-open: SessionStart
  posture briefing, PostToolUse secret warning, PreToolUse catastrophic-Bash
  block. Detection lives in `mcp/src/hooks/{secretScan,bashGuard}.ts` (pure,
  unit-tested) and is shared with the `dev-guardian check` CLI subcommand.

## Build & test (always from `mcp/`)

```bash
cd mcp
npm install          # first time only — no native modules, storage is node:sqlite
npm run build        # tsc -> mcp/dist + copy-assets + esbuild bundle
npm test             # vitest run (full suite)
npm run test:coverage # the only run that enforces the coverage thresholds
```

Semgrep-dependent e2e tests skip when Semgrep is absent. A skip is visible as a
skip, and `GUARDIAN_REQUIRE_SEMGREP=1` turns absence into a hard failure — set it
when you need to know the rule pack was actually exercised.

## Ablating a Semgrep rule pack (`npm run ablate`)

```bash
cd mcp
npm run ablate -- all                          # every registered pack
npm run ablate -- bugfix-js                    # one pack
npm run ablate -- bugfix-java --filter=optional-get # one rule, while iterating
npm run ablate -- bugfix-js --list             # enumerate clauses, no scanning
npm run ablate -- routes                       # the 64-rule route pack, ~80 min
```

Semgrep is found via `--semgrep=<path>`, then `GUARDIAN_SEMGREP`, then `PATH`.
Code lives in [`mcp/test/ablate/`](mcp/test/ablate/) — under `test/` because
it is developer tooling that must never reach `dist/`, and because
`tsconfig.test.json` already type-checks that tree at full strictness. It is
**not** a vitest test (`vitest.config.ts` only collects `*.test.ts`): a full
run is tens of minutes, and the report is the product. Its pure half — clause
enumeration and removal, the report's coverage arithmetic, and axis 3's
comparison and noise floor — *is* unit-tested, in
[`mcp/test/ablate/clauses.test.ts`](mcp/test/ablate/clauses.test.ts),
[`mcp/test/ablate/report.test.ts`](mcp/test/ablate/report.test.ts) and
[`mcp/test/ablate/axis3.test.ts`](mcp/test/ablate/axis3.test.ts).

**What it is for.** Six exclusion clauses that did nothing at all have shipped
across the rule-pack series. Every one was written by someone sure it was
needed, and found only when somebody deleted it and watched nothing change.
The harness deletes one clause at a time, re-runs the pack, and reports three
verdicts — all three, because each axis was added after a defect escaped the
previous ones. A fourth, **axis 0**, is a property of the *rule* rather than of
a clause, and is the only one that reaches a rule with no clauses at all:

0. **fires on `hits/`** — the rule produces at least one baseline finding in
   the fixture directory built to hold the bugs it is for. A rule that matches
   nothing is the sixth silent-failure mode: in C#, `foreach ($T $X in $C)`
   found **0 of 5** real bugs where `foreach (var $X in $C)` found all five,
   with `paths.scanned` healthy, zero errors and every gate green. A rule
   ported by textual analogy finds nothing and nothing complains. It costs no
   extra scan — the baseline fixture scan is already there — and it applies to
   every rule in the pack, not only the clauseless ones.
1. **live** — removing the clause changes the result somewhere.
2. **keeps true positives** — removing it must not *reveal* findings in
   `hits/`. `pattern-not-inside` excludes the whole node it matched, so a
   guard written for an `if` also swallowed the `else` arm, where the bug was.
3. **no rise in the real-code count** — scan a corpus nobody wrote as a
   fixture (`mcp/src`, for the JS/TS pack) and compare **the ablated rule's
   own findings, on the files every scan finished**. If removing the clause
   *lowers* that count, the clause was adding those findings. This is the axis
   that caught `unchecked-match` going 0 → 13 false positives on our own
   TypeScript; axes 1 and 2 both passed, because "live" and "keeps true
   positives" are both true of a clause that only *adds* false positives.
   Both scopings in that first sentence were bought with a defect — see
   "Axis 3 compares one rule" below, and do not widen them back.

**Read the coverage line, not the axis fractions.** Axes 1–3 are properties of
a **clause**, so a rule with no ablatable clause has no verdict on any of them.
Two shapes have none: a bare `pattern:` (or `pattern-regex:`) with no
`patterns:` group and no `pattern-either:`, and a `patterns:` group holding
nothing but positive terms. **29 of the 134 rules** across the nine packs are
one of those — 23 bare and 6 positive-only — and they used to appear
**nowhere** in the report: not in the clause list, not under `skipped`. So
`44/44 live, 0 DEAD` read as "the pack was checked" when it covered 10 rules of
11. The capability was never missing — there is genuinely nothing to ablate.
The *reporting* was dishonest, in exactly the way axis 3 refuses to be when it
prints `N/A`.

| pack | rules | with ablatable clauses | with none |
| --- | --- | --- | --- |
| `bugfix-js` | 13 | 12 | 1 |
| `bugfix-py` | 10 | 10 | 0 |
| `bugfix-go` | 9 | 8 | 1 |
| `bugfix-java` | 7 | 7 | 0 |
| `bugfix-cs` | 11 | 10 | 1 |
| `bugfix-php` | 6 | 6 | 0 |
| `bugfix-rs` | 1 | 1 | 0 |
| `base` | 13 | 7 | 6 |
| `routes` | 64 | 44 | 20 |

The report therefore leads with a coverage line naming both halves —
`44 clause(s) across 10 of 11 rules; 1 rule(s) have no ablatable clauses (axis
0 only)` — lists **every** rule under `RULE COVERAGE` with its clause count and
its `hits/` count, and names each clauseless rule with the reason it has none.
`npm run ablate -- <pack> --list` does the same without scanning.

**`DEAD` never means "safe to delete" on its own.** Three different situations
produce it, and they have different fixes:

- the clause really is inert — six of those have shipped here;
- the clause works, but the **fixture that would prove it** does not exist. All
  four `bugfix-js` DEAD verdicts from the first run were this: probed by hand,
  each one did exactly its job on a shape no fixture carried. The fix is a
  fixture, not a deletion, and the same call was made for nine Java clauses;
- the clause is **mutually redundant with a sibling** in the same rule. Each
  half alone reads DEAD; removing both is a regression. `type-assert-no-ok`
  and `err-discarded` have both shipped that pair. The harness re-ablates
  same-rule DEAD clauses **in pairs** and reports `MOVES` when it finds one,
  but it only pairs clauses that were already DEAD, so a redundant pair whose
  halves are individually live is still invisible.

Probe the shape by hand before deleting anything.

Axes 2 and 3 are attributions, not proofs, and both flag more than the defect
they were built for. Axis 2 fires whenever a `hits/` fixture deliberately
carries the excluded near-miss beside the bug — the `real_bugs` files do, and
annotate it. Axis 3 fires for any clause whose removal makes its own rule match
less, which includes a *working* positive branch. Read the lines it prints —
they now all carry the ablated rule's id, so a line that names another rule is
a harness bug rather than a finding.

Axis 3 needs a real-code corpus in a language the pack matches, so it is a
property of the invocation — registered per pack in
[`mcp/test/ablate/packs.ts`](mcp/test/ablate/packs.ts), overridable with
`--real-code=<dir>` / `--no-real-code`, and reported as `N/A` (never silently
skipped) where none exists. **Every pack has one now**, and all but the JS/TS
one read a path from an environment variable, because the corpus cannot live in
this tree — `GUARDIAN_RUST_SRC`, `GUARDIAN_CS_SRC`, `GUARDIAN_JAVA_SRC`,
`GUARDIAN_PY_SRC`, `GUARDIAN_GO_SRC`, `GUARDIAN_PHP_SRC`; unset means `N/A`,
set-but-missing **throws**. Measured with the corpora below:

| pack | corpus | files | baseline findings | axis-3 flags |
| --- | --- | ---: | ---: | ---: |
| `bugfix-js` | this repo's `mcp/src` | 190 | 45 | 3 |
| `bugfix-py` | CPython `Lib/` | 5803 | 1078 | several, all positive branches |
| `bugfix-go` | Go stdlib `src/` | 6515 | 3101 | **1** |
| `bugfix-php` | WordPress core | 1512 | 40 | 8 |
| `bugfix-cs` | `dotnet/runtime` | 11800 | ~790 | 10 |
| `bugfix-java` | OpenJDK + Spring | 17347 | — | 5 |
| `bugfix-rs` | Rust stdlib | 1201 | 0 | 0 |

The PHP number is a cross-check worth keeping: **40** is exactly the
10 + 26 + 2 + 2 the PHP probe measured by hand, rule by rule, weeks earlier and
by a different method. The C# one was added after the fact and immediately deleted a rule:
`as-cast-deref` fired 6490 times on `dotnet/runtime` with no true positives,
having passed axes 0, 1 and 2 on its author's own fixtures throughout. The Java
one was added after nine fix waves of fixture-reading and changed four rules of
eight in its first round, in both directions: two narrowed (eight of
`stream-not-closed`'s twelve OpenJDK findings were two-resource
try-with-resources headers, and fifteen of `optional-get`'s twenty-six were two
guard shapes nobody had enumerated) and two widened (`static-dateformat` was
blind to the one genuine race either corpus held, and `off-by-one` to `++i`,
`i += 1` and `for (var i = 0;`).

**A pack can have a corpus that reaches almost none of it, and that reads as a
pass.** Axis 3 compares the ablated rule's *own* findings, so a rule the corpus
never triggers passes by comparing an empty set against an empty set.
`routes.yml` makes this the common case rather than the exception: `mcp/src` is
TypeScript, and of the pack's 64 rules exactly **two** ever fire on it —
`guardian-import-esm` (824 findings) and `guardian-env-node` (6). The corpus is
registered anyway, because 824 findings on 190 files of our own code is the
most sensitive real-code baseline in the repo and the alternative was `N/A` for
the whole pack. What keeps that honest is the coverage line: every rule carries
its real-code baseline, and a rule with none prints
`real 0 -- axis 3 vacuous here` instead of the same `+0, floor 0` a genuinely
measured rule gets.

Axis 0 needs a `hits/` corpus on the same terms and reports `N/A` for the whole
pack where the fixture root has no `hits/` subdirectory. Two knobs exist for a
corpus whose directories predate that convention, and both are `routes.yml`'s:
`hitsSubdir: '.'` makes the fixture **root** the hits corpus, and
`decoySubdirs` names trees inside it that are near-misses rather than true
positives, subtracting them. Their baseline finding count is **printed and
pinned, never gated at zero** — see the routes section below.

**Axis 3 compares one rule, on the files every scan finished, against a
measured floor.** All three halves of that sentence are repairs, and the
report prints all three. Axis 3 used to subtract **whole-corpus totals across
two separate scans**, which is invalid twice over — measured on `bugfix-cs.yml`
over `dotnet/runtime`:

- **A clause of rule A cannot move rule B's count.** All **14 findings** once
  attributed to clauses of `modify-during-iteration` were `empty-catch`
  findings. They were not evidence about the clause; they were whatever else
  had drifted between the two scans, landing on whichever clause was under the
  knife. So the comparison is now filtered to `f.ruleId === clause.ruleId`,
  for **axis 1's real-code half as well as axis 3's** — an unscoped axis 1
  turns drift anywhere in the pack into "this clause is live", which is how two
  runs of the same pack came to disagree on **6 of 12** clause verdicts.
- **The totals jitter by more than the deltas.** 793 findings on one run and
  798 on the next, same pack, same corpus. Axis 3 reports deltas of 2 and 3.
  `+2` against a measurement error of ±5 is worse than no verdict.
- **The jitter is timeouts, and it is excluded by FILE, not by (rule, file).**
  Semgrep names the rule in `Timeout when running <rule> on <file>`, but
  `--timeout-threshold` (3 by default) then drops the **whole file for every
  rule still to run**, and names none of them. All five findings that moved
  above belonged to `empty-catch`, which appears in no timeout message on
  either run: it went down *with* `WMIGenerator.cs` and `XmlTextReaderImpl.cs`.
  Excluding the union of timeout-affected files across both scans took 793 vs
  798 to **793 vs 793, differing in nothing**. Excluding pairs would not have.
- **The floor is measured, never assumed.** The real corpus is scanned twice at
  baseline — the pack on disk, and the round-trip of it every ablated variant
  descends from, i.e. the same rules in different bytes. Any per-rule
  disagreement is measurement error by construction; it prints as
  `noise floor`, and a clause delta that does not clear its rule's floor reads
  **`INCONCLUSIVE`**, which is not a pass and exits non-zero. Measured floor on
  `mcp/src` and on `dotnet/runtime`: **0** — so axis 3 can resolve a per-rule
  delta of 1.

The blind spot this leaves has a printed size: a clause whose only real-code
effect is inside a file that times out is invisible to axis 3. The report says
how many files that is (`excluded files`) on every run.

`--timeout` is deliberately **not** pinned. The timeout set is unstable at the
default (28 timeout errors and 10 affected files on one run, 9 and 3 on the
next), and a value large enough to make it stable was never established — the
exclusion was measured to be sufficient instead, which is the claim the harness
actually makes.

**Invariants worth knowing before you change it.**

- **The pack is never written to.** The source is read once, hashed, and
  ablated variants go to a temp dir. That is what makes it byte-identical
  after a crash or a Ctrl-C, without a restore path that can itself fail. The
  on-disk hash is re-checked before every ablation, which also catches the
  pack being edited mid-run.
- **Clauses are named by body text, never by line number.** A previous
  hand-rolled run was discarded because a *comment* was edited while it ran:
  every line shifted, and since all 86 `- pattern-not-inside:` first lines in
  `bugfix-java.yml` were identical, the one INERT verdict could not be
  attributed to any clause. (That file is at 49 such lines now — deleting
  `null-safety-map-get-deref` took 42 of them — and the hazard is unchanged.)
- **`paths.scanned == 0` is an exception, not a result.** This repo has five
  recorded ways for Semgrep to scan nothing while printing success and exit 0;
  two of them emit neither `RuleParseError` nor `Invalid YAML`, so matching on
  error strings does not cover the set. The **sixth** mode is not one of these
  and this gate cannot see it: the rule loads, `paths.scanned` is healthy,
  `errors` is empty, and the rule simply matches nothing. Only axis 0 catches
  that one. **Necessary, and not sufficient** — the gate is also blind to a
  scan that opened every file and *finished* only some of them:
  `paths.scanned` counts files opened, and semgrep-core's per-rule timeout
  abandons rules without touching it. That count read 11 800 on both of the
  two `dotnet/runtime` runs that disagreed by five findings. What moved was in
  `errors`, which is why `ScanResult` now carries `abortedFiles`.
- **A round-trip control runs first.** Removal goes through the YAML AST, so
  the unmodified pack is re-serialised and scanned before anything is ablated;
  if it does not reproduce the on-disk result exactly, the run aborts rather
  than measure the serialiser. The **real** corpus gets the same control and
  does **not** abort on a disagreement — there, a disagreement is the machine's
  timeouts rather than the serialiser, so it becomes the printed noise floor.
  That is the one place the two controls differ, and it is deliberate: aborting
  would make the harness unusable on the large corpora it is most needed for.

Exit code is 1 when any clause is flagged, **is `INCONCLUSIVE`**, or any rule
fires on nothing in `hits/`; 0 when every clause passes axes 1–3 and every rule
passes axis 0. `INCONCLUSIVE` gates on purpose: if the corpus is noisier than
the deltas being measured, the run's *passes* are not evidence either.
Having no ablatable clauses is reported, never counted against a pack: it is a
fact about the rule, not a defect in it.

### `routes.yml` — registered, and the one pack whose corpus is named differently

It was unregistered for a long time on the grounds that it had no `hits/` +
`misses/` fixture pair. It has one; the directories are simply older than the
convention and named for what they hold, and they cannot be renamed because
`mcp/test/e2e/rulePackFixture.test.ts` and the surface tools address them by
name. So the registration in `packs.ts` maps them instead:

| harness role | directory | what it holds |
| --- | --- | --- |
| fixture root | `mcp/test/fixtures/surface/` | everything below, scanned in one pass |
| hits | `apps/`, `annotations/`, `frameworks/` | files that **must** produce routes |
| decoys | `frameworks/fp/` | ordinary code shaped like routes |
| real code | `mcp/src` | axis 3 — see the caveat below |

`hitsSubdir: '.'` makes the fixture **root** the hits corpus and
`decoySubdirs: ['frameworks/fp']` subtracts the decoy tree from it. Both knobs
exist for this pack; `--hits=` and `--decoys=` are their ad-hoc equivalents.

**The decoy baseline is 9, and pinning it is the point.** Four of those
are `guardian_kind: route` and every one is *undecidable*, not untried:
`Route::get('not/a/leading/slash')` on a class that merely happens to be called
`Route` is indistinguishable from Laravel's facade, and Ruby's
`get 'config/value'` is exactly what a Sinatra route looks like — requiring a
`do … end` block was tried and made every real Sinatra route match twice. The
other five are one real `app.use('/static', express.static(…))` mount and four
ordinary imports in the decoy files. The harness **prints** the number and
never gates on zero: a gate that is permanently red teaches the reader to skip
the line, and what actually matters is that a fifth route would move it.

It read 8 until the five decoys below were written. **None of the five moved
it** — that is what they are for: each is excluded by the guard it exercises,
so it contributes nothing until that guard is ablated. The +1 is one ordinary
`require('cors')` that the `app.use` decoy needs in order to be code someone
would really write.

**Why this pack matters more than its rule count suggests.** It is the only
pack whose errors send HTTP requests to invented paths — the next tool in the
series probes whatever path it is handed, so a fabricated path emitted with
`path_partial: false` reads as one that was verified (`mcp/src/surface/extract.ts`
says so in its own header). A rule that quietly matches nothing is the other
half of the same problem, and this pack has shipped it twice: chi entirely
invisible, and `mux.Handle` never matching.

**First full run** (sha256 `2634d21b…`, 4382 s wall clock, noise floor 0):

| axis | result |
| --- | --- |
| 0 fires on hits/ | **64/64 rules fire.** Nothing silent, in any of the nine languages |
| 1 live | 74/112 pass, **38 DEAD** |
| 2 keeps true positives | 96/112 pass, 16 "suppressing" |
| 3 no rise on `mcp/src` | 110/112 pass, 2 "raising" |

Axis 0 is the headline and it is clean — which is the one result that could
not be got any other way, since a route rule that matches nothing produces no
error anywhere. **Read the other three with their known false-alarm modes in
mind, because on this pack they dominate:**

- **All 16 axis-2 flags are the guard working.** Every one is a verb whitelist
  (`^(get|post|put|patch|delete)$`, `^Map(Get|…)$`) or a disambiguating
  `pattern-not`; removing it *widens* the rule, so new findings appear in
  files that are hits. Not one is a suppressed true positive. Axis 2 was built
  for narrowing clauses in a findings pack, where a reveal means a bug came
  back; in a route pack a reveal usually means a fabrication came back.
- **Both axis-3 flags are working positive branches** — `guardian-import-esm`'s
  named-import alternative (824 of the 830 baseline findings on `mcp/src`) and
  `guardian-env-node`'s `process.env.$NAME` (6 of 6). Removing a branch makes
  the rule match less; the axis reports it, and the report says so.
- **38 DEAD is not 38 dead clauses.** Almost all of them are one of the two
  non-deletable causes: a missing fixture, or redundancy with a sibling. Two
  patterns account for most of the count and neither was known before the run:
  - **Semgrep collapses spellings a reader thinks are distinct.** `$MUX.Handle`
    also matches `http.Handle`; `import { $S } from "m"` also matches a default
    import — the pack's own header had *measured* that and the verdict simply
    confirms it, hand-probed on a file whose only statement is
    `import def from "./m.js"`; `import $MODULE;` covers `import static …` and
    `import … .*`; `#[actix_web::post(…)]` and `#[post(…)]` are the same node
    once the `use` is resolved. `f($X, ...)` covers `f($X)` — which is why
    Flask's bare alternative and Rails' `$METHOD $PATH` read DEAD.
  - **A guard with no adversarial fixture in its own language.** Five were
    hand-probed and **every one turned out load-bearing**, so the fix is a
    fixture and never a deletion. **All five fixtures now exist**, in
    `frameworks/fp/decoys.go` (`F31`–`F33`) and `decoys.js` (`F07`, `F08`), and
    all five clauses read **live**:

    | clause | the decoy the corpus was missing | what it reports without the guard |
    | --- | --- | --- |
    | `go-chi` `pattern-not: $R.$METHOD($PATH)` | `keys.Get("/cache/one-arg")` | chi route `/cache/one-arg` |
    | `go-chi` `pattern-not: $R.$METHOD($PATH, nil)` | `reg.Get("/cache/key", nil)` | chi route `/cache/key` |
    | `go-chi` `$PATH` literal regex | `reg.Get(cacheKey, defaultEntry)` | chi route on a computed path |
    | `mount-express` `$PREFIX` literal regex | `app.use(cors(), apiRouter)` | a mount at prefix `cors()` |
    | `route-express` `pattern-not: $APP.$METHOD($PATH)` | `config.get('/site/title')` | a route at `confidence: high`, `path_partial: false` |

    All three chi guards read DEAD for one reason: the only Go decoy in the
    corpus, `reg.GET(…)`, is SCREAMING-case, so the *gin* rule absorbs it and
    the TitleCase rule's guards are never exercised. The express one is the
    same shape — the three decoys the pack's own header credits to that
    `pattern-not` (`cache.get`, `cache.delete`, `storage.get`) are all on the
    `$APP` denylist too, so the denylist decides first and the guard's unique
    job is invisible. Note the last row: the decoy is **not** `app.get('/title')`,
    the settings getter the rule's own comment names. A near-miss written from
    the clause proves only that the clause matches itself, and nobody names an
    Express setting `/title`; the shape that guard really stands between the
    surface and is an ordinary one-argument `Map` read on a receiver the
    denylist does not cover, so that is what the fixture carries.

    The third chi decoy's second argument is deliberately **not** `nil`: with
    `nil` there the row above it excludes the line first and the `$PATH` regex
    never decides anything, which would have left it DEAD for a second reason
    after being given a fixture for the first.

The pair pass re-ablated **30 same-rule DEAD pairs** and found **5 MOVES** —
four of them the actix `#[verb]` + `#[actix_web::verb]` pair (one per verb
except GET, whose fixture carries both spellings) and one the Go
`import "$MODULE"` + grouped-`import` pair. One pair ERRORed by construction:
removing both `guardian-import-rust` alternatives leaves the rule with no
pattern at all, which is the structural guard doing its job.

**Nothing was deleted.** Every DEAD verdict here is a fixture to write or a
redundancy to document, and the run's own value was axis 0 plus the two
hand-probes above.

**Follow-up** (same pack sha256, five decoys added to `frameworks/fp/`): the
five clauses in the table above go DEAD → **live**, measured by re-running the
two rules they belong to rather than the pack —
`npm run ablate -- routes --filter=go-chi` and `--filter=express`, 4 and 6
clauses, minutes instead of the ~73 a full `routes` run costs. The counts in
the axis table are the first full run's and were not re-measured; on a fresh
full run the DEAD count drops by those five, to 33. Every other verdict in
those two rules is unchanged, and the surface e2e still reports **zero** routes
out of either decoy file — the decoys have to be silent on the shipped pack and
loud only with the guard removed, or they are measuring something else.

## TypeScript conventions

Enforced by the compiler where possible, by review where not:

- **ESM `NodeNext`.** Every relative import ends in `.js`, including from
  `.ts` sources. `isolatedModules` is on, so `import type` is required for
  type-only imports.
- **`noUncheckedIndexedAccess` is on.** `arr[i]` is `T | undefined`. Narrow it
  (`const x = arr[i]; if (x === undefined) continue;`) rather than asserting.
- **No `!` non-null assertions, and no `any`.** Both are currently at zero
  across `mcp/src` and `mcp/test`, so any reappearance is a regression rather
  than the status quo. An assertion does not check anything — it only silences
  the compiler, and every one that was here restated something the code had
  *just* established (a `push` before re-indexing the array, a `filter` before
  a `map`, a length check before an index), which is exactly the case where
  narrowing costs nothing. The three that were load-bearing were hiding real
  gaps: a WP-CLI call that can succeed and print nothing, and a shell whose
  non-null-ness came from a check in a *different* file.
- **Type-check the tests too.** `npm run lint` runs `tsconfig.json` and
  `tsconfig.test.json`. The second exists because nothing ever type-checked
  `test/` — `tsconfig.json` excludes it and vitest's esbuild strips types
  without checking them. It excludes `test/fixtures`, which is deliberately
  broken sample code fed to scanners as input.
- Note what `tsc` does **not** catch: interpolating a non-string into a
  template (`` `--config=${someArray}` ``) types as `string` at any
  strictness. That needs `@typescript-eslint/restrict-template-expressions`,
  and this repo has no ESLint setup.

## Conventions that bite if ignored

- **Commit the compiled `mcp/dist/`.** The repo *is* the distribution — Claude
  Code runs `mcp/dist/server.js` directly, with no install-time build. `dist/` is
  gitignored globally *except* `mcp/dist/` (see [`.gitignore`](.gitignore)).
- **Rebuild before committing TS changes.** A stale `dist/` silently desyncs from
  `src/`. Run `npm run build` and stage `mcp/dist/` in the *same* commit.
- **Markdownlint stays clean** for `skills/`, `commands/` and `README.md`
  (config: [`.markdownlint.jsonc`](.markdownlint.jsonc)).
- **Two characters are banned from `configs/semgrep/*.yml`, messages and
  comments alike: `U+00C1` (A-acute) and `U+00CD` (I-acute)** — plus `U+00CF`,
  `U+00D0`, `U+00DD` for languages that use them. Semgrep loads a rule file with
  the **locale** codec, not UTF-8, and on a cp1252 locale the bytes `0x81`,
  `0x8D`, `0x8F`, `0x90`, `0x9D` are undefined; each of those characters encodes
  to one of them, so a single occurrence takes the whole pack down. Measured on
  a broken file: the scan returns `results: 0`, `paths.scanned: 0` **and
  `errors: 0`** — indistinguishable from a clean project. Rule messages in this
  repo are written in Portuguese, which is what makes this a live hazard.

  **Rule comments are Portuguese too**, not just the messages — measured, not
  asserted: six of the seven `bugfix-*` packs are roughly half Portuguese by
  comment line, and the outlier is `bugfix-js`, the first one written. Two
  independent implementers overruled a plan of mine that said otherwise, and
  both were right. Write comments in Portuguese and keep docs, commits and
  identifiers in English.

  **Only those characters.** `Ã À Â É Ê Ó Ô Õ Ú Ç` are all fine and every
  lowercase accented letter is fine — the broad version of this rule ("no
  uppercase accented letters") is wrong for ten of the twelve accented capitals
  Portuguese uses, so write the accented word in lower case rather than
  mangling its spelling. Enforced for every pack by
  `mcp/test/integration/semgrepPacks.test.ts`, which also runs
  `semgrep --validate` over each one and carries a positive control.
- **Releases** bump the version in
  [`.claude-plugin/plugin.json`](.claude-plugin/plugin.json),
  [`.claude-plugin/marketplace.json`](.claude-plugin/marketplace.json) and
  [`mcp/package.json`](mcp/package.json) (keep all three in lock-step — the MCP
  server reports the `plugin.json` version at runtime), add a `CHANGELOG.md`
  entry, and tag `vX.Y.Z`.

## In-repo AI host configs (dogfooding)

This repo ships its own host configs so opening it in any AI host wires up the
dev-guardian MCP server out of the box: `.mcp.json` (Claude Code), `.cursor/`,
`.gemini/`, `.vscode/`, `.windsurf/`, `.github/copilot-instructions.md`, plus root
`AGENTS.md` / `GEMINI.md`. They use **relative** paths (`mcp/dist/server.js`), so
run `npm run build` once first. To install the same into *another* project, use the
`mcp-config` CLI (`node cli/dev-guardian.mjs mcp-config <host> --write`) — it fills in absolute paths.

**Never put the CLI back in a top-level `bin/`.** Claude Desktop / claude.ai does not clone the repo:
it validates it on a remote Anthropic service that *rejects* any plugin shipping a top-level `bin/`
(those files land on PATH in the CLI but are invisible on the admin approval surface). The sync fails
with `status=failed_content` and the UI shows only "Marketplace sync failed. Check the repository
URL", which points nowhere near the cause. The local CLI (`/plugin marketplace add`) uses `git clone`
and does **not** apply this rule, so it passes even when Desktop refuses — it is not a valid pre-check.
Executable entry points belong in `hooks/`, `commands/` or `mcpServers`.

## Prefer MCP tools over raw scanners

When working here, invoke the dev-guardian MCP tools rather than shelling out to
Semgrep / Trivy / gitleaks directly — you keep baselines, diffing and the
SQLite-persisted history. The full intent → tool map lives in
[`host-rules/AGENTS.md`](host-rules/AGENTS.md).
