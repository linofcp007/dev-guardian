# Ablating a Semgrep rule pack

> Maintainer notes, moved from `CLAUDE.md` (the index). Not loaded into sessions: read this file before you
> change its area.

## Ablating a Semgrep rule pack (`npm run ablate`)

```bash
cd mcp
npm run ablate -- all                          # every registered pack
npm run ablate -- bugfix-js                    # one pack
npm run ablate -- bugfix-java --filter=optional-get # one rule, while iterating
npm run ablate -- bugfix-js --list             # enumerate clauses, no scanning
npm run ablate -- routes                       # the 73-rule route pack, ~73 min
```

Semgrep is found via `--semgrep=<path>`, then `GUARDIAN_SEMGREP`, then `PATH`.
Code lives in [`mcp/test/ablate/`](../../mcp/test/ablate/) — under `test/` because
it is developer tooling that must never reach `dist/`, and because
`tsconfig.test.json` already type-checks that tree at full strictness. It is
**not** a vitest test (`vitest.config.ts` only collects `*.test.ts`): a full
run is tens of minutes, and the report is the product. Its pure half — clause
enumeration and removal, the report's coverage arithmetic, and axis 3's
comparison and noise floor — *is* unit-tested, in
[`mcp/test/ablate/clauses.test.ts`](../../mcp/test/ablate/clauses.test.ts),
[`mcp/test/ablate/report.test.ts`](../../mcp/test/ablate/report.test.ts) and
[`mcp/test/ablate/axis3.test.ts`](../../mcp/test/ablate/axis3.test.ts).

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
nothing but positive terms. **42 of the 178 rules** across the fourteen packs are
one of those — 36 bare and 6 positive-only — and they used to appear
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
| `routes` | 73 | 53 | 20 |
| `rgpd` | 8 | 8 | 0 |
| `llm` | 9 | 8 | 1 |
| `web-js` | 3 | 3 | 0 |
| `mobile` | 14 | 2 | 12 |
| `wordpress` | 1 | 1 | 0 |

The same numbers, rule by rule, are in [`docs/rule-packs.md`](../../docs/rule-packs.md),
which `npm run build` generates; `mcp/test/docs/docs.test.ts` fails when this
table or the totals above stop matching the pack files.

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
[`mcp/test/ablate/packs.ts`](../../mcp/test/ablate/packs.ts), overridable with
`--real-code=<dir>` / `--no-real-code`, and reported as `N/A` (never silently
skipped) where none exists. **Every pack but `base` has one.** `bugfix-js` and
`routes` use this repo's `mcp/src`; `rgpd` reads `GUARDIAN_RGPD_SRC` and falls
back to `mcp/src`; the other nine read a path from an environment variable,
because the corpus cannot live in this tree — `GUARDIAN_RUST_SRC`,
`GUARDIAN_CS_SRC`, `GUARDIAN_JAVA_SRC`, `GUARDIAN_PY_SRC`, `GUARDIAN_GO_SRC`,
`GUARDIAN_PHP_SRC`, `GUARDIAN_LLM_SRC`, `GUARDIAN_WEBJS_SRC`,
`GUARDIAN_MOBILE_SRC`; unset means `N/A`, set-but-missing **throws**. `base` has
no real-code corpus registered and always prints `N/A` for axis 3. `rgpd` finds
nothing in `mcp/src`, so its axis 3 is vacuous there (its header records the
precision evidence it does have). Measured with the corpora below:

| pack | corpus | files | baseline findings | axis-3 flags |
| --- | --- | ---: | ---: | ---: |
| `bugfix-js` | this repo's `mcp/src` | 190 | 45 | 3 |
| `bugfix-py` | CPython `Lib/` | 5803 | 1078 | several, all positive branches |
| `bugfix-go` | Go stdlib `src/` | 6515 | 3101 | **1** |
| `bugfix-php` | WordPress core | 1512 | 40 | 8 |
| `bugfix-cs` | `dotnet/runtime` | 11800 | ~790 | 10 |
| `bugfix-java` | OpenJDK + Spring | 17347 | — | 5 |
| `bugfix-rs` | Rust stdlib | 1201 | 0 | 0 |
| `llm` | 29 LLM applications (a tree of their source) | 1914 | 235 (226 comparable) | 14, none a noise-adding clause |
| `web-js` | uptime-kuma, actual and outline (Node apps) | 4933 | 15 (14 comparable) | 3, all working positive branches |
| `wordpress` | WooCommerce 11.2.1, wp-statistics 13.0.7, Contact Form 7 6.2.3 | 4176 | 7 (5 comparable) | 0 |

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
TypeScript, and of the pack's 73 rules exactly **two** ever fire on it —
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
  The **seventh** mode is quieter still, and is not in `errors` at all: the
  **taint fixpoint timeout**. When a taint rule's dataflow analysis of one
  function runs past its budget, Semgrep gives that function up and whatever
  it had not yet found is lost; `errors` stays empty and `paths.scanned` full. It is
  reported only under `time.fixpoint_timeouts` — present on Semgrep 1.170+
  with or without `--time`, absent on 1.86 and 1.120 even with it (measured).
  The `llm` pack's second review measured one true positive dropping out of 3
  scans in 17, each with a fixpoint timeout on the function holding it; on
  this repo's `mcp/src` with `p/default`, two consecutive scans reported 77
  and 35 fixpoint timeouts and disagreed on one finding. A timeout marks the
  function *incomplete* rather than empty — one corpus scan timed out on the
  very function holding that true positive and still reported it — so it is
  a file whose result cannot be trusted, not a proof of a loss. The harness
  adds those files to `abortedFiles`, and the product's Semgrep judge
  (`mcp/src/runners/semgrepReport.ts`) reads the field from every run's plain
  report — never `--time`, which only adds profiling (94 MB against 1.7 MB on
  LibreChat): the run is partial with the files named, type `Fixpoint
  timeout`, and on an engine without the field the run carries a named note
  instead. The CI gate does NOT gate on them (3.3.0, review 8): no Semgrep
  setting tunes them, and dev-spec-driven's own tree had them in 49 files on
  every run, so no mid-size codebase could reach exit 0. They are notes there
  (`coverage_notes`, `coverage_gap_details` kind `taint_timeout`, `gating:
  false`), coverage still `partial`; a per-file `Timeout` still gates unless
  the project's committed `.guardian/scan.yml` accepts it (`docs/ci.md`). The exception is a timeout
  whose only rule is one of the plugin's own packs', as the pack's rule is
  spelled in that run (its config-path prefix, or `guardian-packs.` in
  Docker — never a bare id, which a project-root rule of the same name has):
  that is the pack's gap — its JS rules have no literal to prefilter
  on and time out on code with no model call in it — recorded as `Fixpoint
  timeout (plugin pack)`, noted, never the run's partial verdict nor the gate's.
  The **eighth** mode leaves no trace anywhere: semgrep-core tracks a fixed
  number of tainted l-values per function (`Flag_semgrep.max_tainted_vars`;
  its log says "Already tracking too many tainted l-values, will not track
  …"), and past it the flow is dropped — no finding, `errors: []`,
  `fixpoint_timeouts: []`, independent of load. Measured on 1.176.1 and
  1.86.0: a straight chain `v0 = llm.invoke(q); v1 = v0 + 'x'; …; exec(vN)`
  fires at N = 50 and reports nothing at N = 51 (carried through a loop, it
  drops at 50). No report field says so, so the judge cannot see it; the
  `llm` pack's blind spots record the reproduction.
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

**The decoy baseline is 9 (11 since; see the class-prefix run below), and
pinning it is the point.** Four of those
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

**Class-prefix run** (3.7.0, sha256 `6de0cd7f…`, 7570 s wall clock, Semgrep
1.182.0 without login, noise floor 0). The nine `guardian_kind: scope` rules
that let Spring and ASP.NET routes resolve their class-level prefix, and
`guardian-route-spring-request` rewritten to name the method it decorates —
73 rules, 143 clauses, 139 ablated after 4 collapsed as duplicates (a
`pattern-inside` and the `pattern-either` branch that holds nothing else):

| axis | result |
| --- | --- |
| 0 fires on hits/ | **73/73 rules fire** |
| 1 live | 105/139 pass, 34 DEAD — **33** the pre-existing ones (the predicted count, confirmed), 1 new |
| 2 keeps true positives | 115/139 pass, 24 "suppressing" — the 16 above plus 8 new |
| 3 no rise on `mcp/src` | 136/139 pass, 3 "raising" — all working positive branches |

Of the 30 new or rewritten clauses, 29 read live. The one DEAD was
`guardian-scope-spring-inherits`'s `@Controller` branch, for the reason five
clauses above read DEAD: no `@Controller` class in the corpus extended
anything, so nothing reached it. `LegacyPageController` in
`annotations/spring/PrefixForms.java` is that fixture, and
`--filter=guardian-scope-spring-inherits` then read 4/4 live. All 8 new
"suppressing" verdicts are the guard working and are each its own fixture: the
abstract-class `pattern-not`s (an abstract handler is no handler, an abstract
controller has no route or name of its own), `[ControllerName]` and
`[ActionName]`, and the `pattern-inside` that keeps the ASP.NET boundaries
and actions to `[Route]` classes (`JsonHelper` and `NoRouteController` appear
without it). Axis 3 is vacuous for all of them — `mcp/src` holds no Java or
C#. The pair pass found the same 5 MOVES and 1 structural ERROR as the first
run.

The decoy baseline read **11**, not 9, on this run — and on the 3.6.1 pack
too, measured by scanning `frameworks/fp/` with both: the same four undecidable
routes and one mount, and six imports rather than four (`decoys.go`'s grouped
import reports one match per item, and `decoys.py` has one). The class-prefix
rules added none.
