# Changelog

All notable changes to dev-guardian are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and the project uses
[Semantic Versioning](https://semver.org/). From 1.0.0 the MCP tool/resource
surface and default behaviours follow semver — breaking changes require a major
version bump.

## [Unreleased]

### Added — one Rust rule, and one rule is the whole answer

`configs/semgrep/bugfix-rs.yml`: **exactly one** hand-authored rule, always on
in `bug_hunt`, with a hits/misses fixture pair. Rule counts are now 13 JS/TS,
10 Python, 9 Go, 8 Java, 12 C# and **1 Rust**.

**This is not partial Rust coverage and must not be read as one.** The rule is
`bugfix-rs-race-condition-blocking-sleep-in-async` — a `std::thread::sleep`
inside an `async fn`, which blocks the executor *thread* and stalls every other
task scheduled on it. That is what dev-guardian finds in Rust. Everything else
is somebody else's job, and the file header says so at length so that the next
reader does not mistake a one-rule pack for abandoned work.

**Twelve of thirteen candidates were measured and killed**, which is why. Four
of the six bug classes are **compile errors** in Rust — `E0502` for
modify-during-iteration, `E0515` for use-after-free, `E0373`/`E0503` for a data
race on shared state, `E0599` for a null dereference. Not rare: impossible in
code that compiles. For the rest the answer is `cargo clippy`, whose type-aware
lints beat every Semgrep equivalent measured — default already catches
`await_holding_lock`, `-W clippy::pedantic` adds `float_cmp` and
`future_not_send`, and the `restriction` group adds `unwrap_used`,
`mem_forget`, `indexing_slicing`. The docs now say that to Rust users
explicitly rather than implying a gap dev-guardian intends to fill.

**Two candidates that passed their own fixtures were killed by real code**, and
this is the strongest evidence the rule-pack series has produced for the
real-code ablation axis: `mem-forget` scored **43 findings and zero true
positives** on ~1200 files of the actual Rust standard library, and
`unwrap-in-drop` flags `if !thread::panicking() { r.unwrap(); }` — the
canonical mitigation its own message prescribes. Both would have shipped under
a C#-style round, where that axis was permanently `N/A` for want of a corpus.
The ablation harness now accepts a Rust corpus for that axis, via
`GUARDIAN_RUST_SRC`.

**`WARNING`, not `ERROR`, and the call went against the probe's reading.** The
argument for `ERROR` was that the nearest legitimate shape — a deliberately
blocking helper — is not written as an `async fn`. True but incomplete: handing
the blocking work to another thread *is* written inside an `async fn`, and
`thread::spawn`, `tokio::task::spawn_blocking` (the fix the rule's own message
prescribes), `async_std::task::spawn_blocking`, `rt.spawn_blocking` and
`thread::Builder::new().spawn` all fired before the exclusion existed. The rule
excludes them by call *name* rather than by path — anchoring on the path let
the `async_std` spelling and the method call straight through — **and** by
closure rather than by name alone, because a name-only exclusion swallowed
`tokio::spawn(async move { … })`, which keeps the work on the executor and is a
genuine bug. Both halves have a fixture that fails without them: the two shapes
are symmetric, one bug per half. But a name list never closes, so correctness
still depends on a wrapper the matcher cannot enumerate. That is the `WARNING`
condition of the severity criterion word for word. The rule's one declared
false negative points the same way: a bare `async` block in a *sync* `fn` —
`tokio::spawn(async move { … })` in `main` — is not matched, because the anchor
is `async fn`.

**A measured Semgrep trap, running in two opposite directions in one pattern.**
`async fn $F(...) -> $R { ... }` is the NARROW form: `-> $R` requires a written
return type, so it found **2 of 4** bugs with `paths.scanned` healthy and zero
errors — C#'s `var` trap in a second language. For *paths* it inverts: the
engine resolves `use` declarations, so the fully-qualified
`std::thread::sleep(...)` matches all three spellings (`std::thread::sleep`,
`thread::sleep`, and a bare `sleep`) while the short `thread::sleep(...)`
matches only one. Both directions are pinned by the fixture's finding count.
A third member of the same family was found by the ablation harness rather than
by reading: the `move` on a closure is **ignored, symmetrically** —
`$F(|| { … })` matches `f(move || { … })` *and* vice versa — so enumerating
both spellings produces a mutually redundant pair in which each half reads
`DEAD` alone and removing both is a regression. The harness's pair pass named
it; the rule now writes one spelling and the near-miss fixture keeps both.

**Nothing ships for Ruby, also by measurement.** Semgrep's Ruby frontend erases
`&.` and the `..`/`...` distinction — `x&.a.b` and `x.a.b` produce
byte-identical ASTs — so every nil-safety and off-by-one rule matches the
correct code and the buggy code identically, in the language whose signature
runtime error is `NoMethodError` on nil. Five further candidates passed their
fixtures at 0 false positives and were killed by 1244 files of real Ruby.
RuboCop and the registry's `p/ruby` are the honest answer, and the docs say so.
The full measurement is in
`docs/superpowers/specs/2026-08-20-bugfix-rules-rust-and-ruby-decision.md`.

### Changed — `error-handling-empty-catch` drops to WARNING in Java and C#, measured

`bugfix-java.yml` and `bugfix-cs.yml` shipped this rule at `ERROR` on one
premise: **an empty catch that does not declare intent is a bug whatever the
author meant**, because the rule *reads* the intent — the Checkstyle / IntelliJ
`ignore` / `ignored` / `expected` binding name — so what it emits afterwards is
unmarked. Neither pack had ever tested that premise, because the ablation
harness reports its real-code axis as `N/A` for both: this repository contains
no Java and no C#. Three other languages had tested it and all three refuted it
(JS/TS 42 of 42 deliberate, PHP 10 of 10, Ruby's convention at 2.7 %), and the
PHP design recorded the gap as open rather than closing it.

Both are now measured against external corpora, and **both premises fail**.

**Java — OpenJDK (`openjdk/jdk` @ `e296cefb`, `src/*/share/classes`, 12 593
files scanned): 1589 findings in 770 files.** 903 of them — **56.8 %** — carry
an explanatory comment *inside* the empty catch, which is why they fire at all:
a comment-only block is empty to the AST. In the corpus's own words: `// ignore`,
`// Expected or ignored`, `// swallow, since it should never happen`, `// no op`,
`// Ignoring exception causes specified default to be returned`. Another 27
declare intent in a name the rule does not carry — `cannotHappen` ×13, **`_`
×10** (Java 21's *unnamed variable*, which means precisely "unused binding", the
same erosion ES2019 caused in JS/TS arriving from the other direction), `unused`
×2. An inverted-regex probe puts the recognised spelling at **139**, so the
convention the whole tier rested on covers **8.0 %** (139 of 1728) of the
corpus's empty catches. 45 findings were read one by one; about 39 were
deliberate — the Swing `PropertyVetoException` idiom, `close()` in a `finally`,
parse and reflection probes, try-the-next-provider loops. **Java's pack is now
0 of 8 at ERROR.**

**C# — `dotnet/runtime` (@ `6ecee4dd`, `src/libraries/*/src/**`, 11 800 files
scanned): 402 findings in 233 files**, and here the refutation is structural
rather than statistical. **374 of them — 93 % — are written `catch (Type) { }`
or `catch { }`: spellings with no identifier for a naming convention to attach
to.** Only 28 bind a name and not one uses the exempt vocabulary (`ex` ×15, `e`
×5). The inverted-regex probe finds `ignore` / `ignored` / `expected` **zero
times in 11 800 files**.

**The compiler is the oracle again, and this time it refutes a design
decision.** `dotnet build` on `mcr.microsoft.com/dotnet/sdk:8.0` emits **CS0168,
"The variable 'ignored' is declared but never used"** for
`catch (FormatException ignored) { }` — the exact spelling this rule's own
message prescribes — while `catch (FormatException) { }` and `catch { }` compile
clean. The escape hatch is the one spelling C# warns you off, which explains the
zero without appealing to taste. `CA2200` and `CA2002` confirmed this pack's
fixtures; `CS0168` contradicts its severity, and that is worth exactly as much.
**C#'s pack is now 1 of 12 at ERROR** — `rethrow-loses-stacktrace`, whose
correct form really is a different AST node.

**What this changes downstream.** The Semgrep parser maps `ERROR → high` and
`WARNING → medium`, and `create_fix_pr` defaults `severity_min` to `high`. The
**Java pack now contributes nothing at all to a default fix-PR run** and C#
contributes one rule; ask for `severity_min: "medium"`. `bug_hunt` does not
filter by default, so **nothing disappears from a scan** — only the fix PR is
affected. Patterns and recall are untouched: only the tier moved, and
`EXPECTED_SEVERITY` in both integration tests pins every rule exhaustively in
both directions, so the flips failed the tests before the YAML was edited.

The naming exemption stays in both rules. It is still the only way to silence
one case in code rather than with `// nosemgrep`; it simply is not evidence that
the rule is precise, and it no longer carries a tier. It was **not** widened to
`_`, `cannotHappen` or `unused` — every word added is another way for a real
swallow to escape by being well named.

### Added — a C# bug-finding rule pack, in the language where the registry is at zero

`configs/semgrep/bugfix-cs.yml`: **twelve** hand-authored rules across all six
bug subcategories, always on in `bug_hunt`, each with a hits/misses fixture
pair. Rule counts are now 13 JS/TS, 10 Python, 9 Go, 8 Java and **12 C#**.

**The registry gap is total, and it was measured with positive controls rather
than assumed.** `p/r2c-bug-scan` reports `paths.scanned = 0` on the C#
fixtures — it ships **no C# rules at all** — and `p/csharp` and
`p/security-audit` scan every file and find nothing. Because a pack that never
ran is indistinguishable from a clean result, the proof carries controls that
are asserted to have *fired*, and for `p/r2c-bug-scan` that control is a
**Python** file inside a C# fixture tree: there is no C# rule for a C# control
to trip.

**One of the twelve sits at `ERROR`**, and the reason is structural rather than
generous. C# contains one defect — `throw ex;` inside a `catch` — whose
*correct* form, `throw;`, is a **different AST node**. There is no guard to
recognise because there is nothing to guard, which is the only way to clear the
severity criterion in an engine without dataflow. (`empty-catch` shipped at
`ERROR` beside it in the first cut of this pack and was demoted in the same
release once it was measured — see the entry above.)

**A compiler as an independent oracle, which no round in this series has had
before.** `dotnet build` emits `CA2200` for `throw ex;` inside a catch, and it
fires at exactly the nine sites the rule fires on and zero in the near-miss
fixture — so the hit/miss split was not graded by the rule's own author.
`CA2002` does the same for the `lock` rule. Recorded just as deliberately:
`CA5394` is **not** an oracle for the `Random` rule, because it fires on all
four correct sites too — it is about cryptographic predictability, not a data
race. Confirming that an oracle is not an oracle is worth as much as
confirming that one is.

**The oracle immediately earned its place.** It found that a trailing
`finally` made both `error_handling` rules silent: a `try/catch/finally` is a
different AST node, and the two shapes are disjoint, so neither pattern
subsumes the other. `CA2200` fired on a `throw ex;` whose catch had a
finalizer and Semgrep did not. The same hole was found and fixed in
`bugfix-java.yml` in this release.

**Java's wave-4 unsoundness was ported already corrected, not rediscovered.**
Adding the loop-exit exclusions to `modify-during-iteration` closes five false
positives *and* deletes a real bug — a `Remove` inside a `switch` arm followed
by `break`, where the `break` leaves the switch rather than the loop. Measured
here: exclusions alone give 7 findings and lose it; with the
switch-inside-foreach re-inclusion, 9 and the false positives stay closed. The
same discipline caught the `as-cast-deref` else-arm swallow *before* it
shipped, by writing the guard-adjacent bugs as **hits** rather than misses —
the only place ablation can see an exclusion eating a true positive.

**Stated limitations, all measured:**

- `memory_leak` is carried by a single rule. The `IDisposable` one is **not
  expressible**: Semgrep's C# frontend erases the `using` modifier from a
  using-declaration, making the Microsoft-recommended idiom byte-identical to
  a leak. A rule that flags `using var` is worse than no rule.
- `blocking-on-task` misses `var t = GetAsync(); t.Result` (`metavariable-type`
  does not resolve through `var` plus a *call* initialiser, though it does
  through `var` plus a `new`), `Task.Run(...).Result`, and a dotted receiver
  such as `_source.Pending.Wait()`.
- `ordefault-deref` cannot see generic arguments, so a value-type sequence is
  an unfixable false positive in one direction or a false negative in the
  other; both spellings are stated rather than implied.
- `as-cast-deref` still loses the `else` arm when the `then` arm *also*
  dereferences — a narrower residual of the hole the then-block scoping closed,
  found by writing the real-bugs corpus.
- `off_by_one` keeps Java's sentinel false positive (`new int[a.Length + 1]`),
  whose obvious tightening was measured in the Java round and rejected for
  trading a false positive for a false negative.
- `.Count` covers six enumerated receiver types; anything outside that list is
  not matched, because `metavariable-type` is **not subtype-aware** — a
  receiver declared `List<int>` does not match `ICollection<$T>`.
- `Dictionary` is deliberately excluded from `modify-during-iteration`:
  removal during enumeration has been documented safe since .NET Core 3.0.
- These rules match syntax, not dataflow, and they complement the registry
  packs rather than replacing them — though here that is close to vacuous,
  since the registry has no C# bug rules at all. They do not replace the
  model-driven `/guardian-fix` path.

Every clause is ablated on both available axes — live, and does not suppress a
true positive — with one row per clause. Axis 3, which measures a clause's
width against code nobody wrote as a fixture, is `N/A` for the whole C# round
because this repo holds no C# outside the fixture tree; the real-bugs corpus
and the guard-adjacent hits are the compensation, and the gap is stated rather
than left silent. All twelve rules pass the prescribed-fix check: the fix each
message advises, applied to the code the rule fired on, silences it.


### Action required — the SAST rules this plugin installs were never actually run

**Until this release, `scan_sast` did not load the rules `init_project` writes
into your project.** It ran `semgrep --config=auto`, and `--config=auto` does
not pick up a project's `.semgrep.yml`. Measured on semgrep 1.164.0, against a
project containing the shipped pack and one line of
`<?php echo $_GET['name'];`:

| Command                   | Findings | Files scanned |
| ------------------------- | -------- | ------------- |
| `--config=<the pack>`     | 1        | 2             |
| `--config=auto`           | 0        | 2             |

So the thirteen security rules `init_project` installs as `.semgrep.yml` had no
consumer anywhere in the product. **The shipped pre-commit hook had the same
gap** — it also passed only `--config=auto` — so a project that installed our
hooks was not running our rules either.

This is why the `wp-unescaped-output` note below matters twice: that rule was
dead for two entirely independent reasons, and fixing the pattern in b51a2dc
could not have helped, because nothing loaded the file it lives in.

Both are fixed. `scan_sast` now passes the project's own config — from
`.dev-guardian/configs.json` where there is one, falling back to `.semgrep.yml`
/ `.semgrep.yaml` — and `configs/pre-commit/pre-commit-config.yaml` now passes
`--config=.semgrep.yml` alongside `--config=auto`. **If you already installed
our pre-commit hook, re-run `init_project` with `refresh=true` to pick up the
corrected hook config**, or add the flag by hand.

A guard comes with it, because loading a file the user owns is a new risk: a
`--config` Semgrep cannot load aborts the *whole* run (`paths.scanned: []`,
exit 7), not just that pack. Every candidate is parsed and shape-checked
first, and one that would abort the scan is dropped **and named in
`tools_run`** rather than passed through. A rule that merely fails to compile
is a different case — exit 2, everything still scanned — and now counts as a
real scan that lost one rule instead of flipping the whole result to `failed`.

### Privacy — the default SAST mode sends telemetry to Semgrep Inc

`SECURITY.md` said "Local-only, no telemetry" without qualification. That was
wrong, and it is corrected there.

`--config=auto` fetches its ruleset from the Semgrep registry and reports usage
metrics to Semgrep Inc. **as a condition of doing so**: passing `--metrics=off`
alongside it fails outright with `Cannot create auto config when metrics are
off`. Every default `scan_sast` run has therefore sent telemetry, and could not
have done otherwise. dev-guardian neither adds to that data nor sees it; what
Semgrep collects is documented at <https://semgrep.dev/docs/metrics>.

New in this release: **`scan_sast(local_only: true)`** drops the registry,
passes `--metrics=off`, and runs only rules already on disk — your project's
`.semgrep.yml` plus anything added with `register_custom_rules`. Nothing leaves
the machine, at the cost of the registry's rules. When the project has no local
rules it reports the scan as **skipped** rather than as a clean result, because
zero findings from zero rules is not a clean bill of health. That mode only
became coherent rather than empty once the project's own config started being
loaded, which is why the two arrived together.

### Action required — projects initialised before b51a2dc are running a dead XSS rule

**If you ran `init_project` before b51a2dc, your `.semgrep.yml` contains a
WordPress cross-site-scripting rule, `wp-unescaped-output`, that has never
matched anything.** Its pattern was `echo $_GET[$X]`, which is not valid PHP, so
Semgrep could not compile it; with `--quiet` the failure went to a JSON `errors`
array instead of stderr and nothing surfaced it. Every scan since has been
reporting zero WordPress XSS findings from a rule that could not have produced
one — a clean result that meant nothing. The rule was fixed in b51a2dc, and
because `init_project` never touched a config it had already copied, **the fix
has not reached any existing project.**

To get it, run `init_project` with `refresh` — as a dry run first:

```text
init_project(project_path=".", refresh=true, apply=false)   # show me what would change
init_project(project_path=".", refresh=true, apply=true)    # do it
```

Your own edits are safe. `apply=true` overwrites only a file you have never
touched; anything you customised is left exactly as it is and the new baseline
is written beside it as `.semgrep.yml.new` for you to merge. If you would rather
not run the tool at all, copying `configs/semgrep/base.yml` over your
`.semgrep.yml` by hand gets you the same rules.

This applies to all four baseline configs `init_project` installs
(`.gitleaks.toml`, `renovate.json`, `.semgrep.yml`, `.pre-commit-config.yaml`),
not just the Semgrep one — the same gap existed for every one of them.

### Removed

- **`bugfix-go-edge-case-append-discarded` is deleted.** The Go pack goes from
  ten rules to **nine**. The rule matched `append(xs, 1)` in *statement*
  position, which the Go spec's *Expression statements* section forbids and the
  compiler rejects outright:

  ```text
  ./main.go:4:2: append(xs, 1) (value of type []int) is not used
  ```

  Its true-positive set was therefore **empty in any project that compiles**,
  and everything it emitted in a real repository was a false positive — three
  were measured: `for _, v := range append(xs, 0)`, `ch <- append(xs, 1)` and
  `return &box{items: append(xs, 1)}` (the `$T{<... append ...>}` exclusion does
  not reach inside a `&T{...}`, and `&Foo{Items: append(...)}` is far more
  common than the bare form the fixture tested). Its own hit fixture,
  `mcp/test/fixtures/bugfix-go/hits/append_discarded.go`, did not compile, and
  had not for two releases.

  It was deleted rather than redesigned. The bug that *does* compile —
  `func addItem(xs []int) { xs = append(xs, 1) }`, where the caller's slice is
  unchanged — is only a bug when the reassigned slice never escapes the
  function, which is a dataflow property: every escape route (return, channel
  send, struct-field store, closure capture, pointer write, passing it on)
  would need its own exclusion clause, and this repo's Java round is the
  recorded evidence that an exclusion list of that shape eats real bugs before
  it stops emitting false ones. `staticcheck` and `ineffassign` already cover
  it with actual dataflow.

  **Every Go fixture in the pack is now compiled** with
  `docker run --rm -v "<dir>:/w" -w //w golang:1.22-alpine go build ./...` (and
  `gofmt -l`) as part of the change process. That check is what caught this,
  and it should have existed from the start.

- **`bugfix-js-error-handling-catch-returns-null` is gone.** It matched
  `try { ... } catch { return null|undefined|[]; }`. Two independent corpora
  now say the same thing: five instances of textbook-correct code and zero true
  positives on the auditor's probes, and **25 findings on this repo's own
  `mcp/src`, every one of them correct code** — the safe-`JSON.parse` helper, a
  `readdirSync` with a `[]` fallback, `runtimeMeta.getJson` with a `[]`
  fallback. Returning an empty value from a catch is a documented JavaScript
  idiom, not a defect shape, and there is no syntactic difference between the
  idiom and a genuine swallow — every candidate narrowing was measured and
  silences the rule's own hit fixture too. It had been demoted to INFO earlier
  in this same Unreleased block; that was the wrong call. INFO is not a tier for
  a rule that has never been right, it is a quieter way to keep being wrong, and
  it still costs everyone who reads the output. The rule and its three fixtures
  are deleted. The JS/TS pack is now **thirteen** rules.

### Added

- **Configuration-drift detection for the configs `init_project` installs.**
  `init_project` copied four baseline configs into a project and then never
  looked at them again — an existing target was skipped as `already_exists`,
  which is the right call, since the user owns and edits those files, but it
  meant a fix to a shipped config could never reach anyone who had already run
  init. Nothing recorded what had been copied, so nothing could notice. The
  `wp-unescaped-output` incident above is what that costs.

  Four parts:

  - **A provenance stamp.** `init_project` now records each file it copies in
    `.dev-guardian/configs.json` — target, source, plugin version, and a content
    hash at copy time — and stamps a comment header into the file itself where
    the format allows one. The manifest is the mechanism and the header is an
    affordance on top, because `renovate.json` is JSON and a `//` line would
    break the parser Renovate reads it with. It is a separate directory from
    `.guardian/`, which `gitignoreGuard` adds to `.gitignore` on every server
    start: a provenance record has to be committed alongside the configs it
    describes, or a teammate's clone and CI learn nothing.

  - **A drift advisory on the scan path.** Every scan tool now checks the
    manifest and emits at most **one** line into `warnings`. It is never a
    finding, never an error, and cannot move a scan's status or the CI exit
    code. Silence is the default: a user who edited their own config — the
    common case, and the intended one — is told nothing, because a warning that
    fires on almost every project is a warning nobody reads. Only two states
    speak, and they are worded differently because their remedies differ: *we
    shipped a newer baseline and your copy is unchanged* (a fix may be missing,
    here is how to get it), and *both sides moved* (the refresh will need a
    merge).

  - **`init_project(refresh=true)`.** Opt-in, never a default. With
    `apply=false` it reports the per-file action and writes nothing. With
    `apply=true` it updates a file you have provably never touched, and for
    anything else — edited, diverged, or of unknown provenance — writes the new
    baseline as `<name>.dev-guardian-<version>.new` beside your file and leaves
    yours closed. **No flag overwrites a modified file.** "Unknown provenance"
    is treated as modified on purpose: an old copy of ours and a config you
    wrote by hand are indistinguishable from the bytes, and the costs of
    guessing wrong are not symmetric.

    The delivered file is not called `<name>.new`, because that name is not
    ours — a user can be keeping their own `.semgrep.yml.new`, and writing over
    it is the same data loss the rule above exists to prevent. It carries
    `dev-guardian` and the plugin version, and even then a path that already
    exists and is not recorded as our own previous delivery is **refused**
    (`alongside_blocked`) rather than overwritten. Re-running a refresh while a
    delivery is still unmerged reports `pending_merge` and rewrites nothing:
    the user's half-finished merge lives in that file.

  - **Graceful degradation for projects with no manifest.** They get no warning
    at all rather than a wrong one — with nothing recorded, "an old copy of
    ours" cannot be told apart from "a file you wrote that happens to share the
    name". Two adoption paths close that: plain `init_project` now records
    provenance for any skipped file that is byte-identical to what we ship, and
    `refresh` adopts the rest as it delivers to them. That gap is precisely why
    the note at the top of this release exists in plain words.

  The hash is taken over a canonical form — CRLF/CR normalised to LF, leading
  BOM dropped, trailing newlines at EOF trimmed, our own header stripped — not
  over raw bytes. A byte hash gets the answer wrong on this project's own
  platform pair: git's `core.autocrlf` rewrites line endings on checkout, so the
  identical commit would read as "the user edited their copy" on Windows and
  "they did not" on Linux, and a false *local edit* silences the one state that
  matters. Trailing whitespace inside a line, indentation and comment text all
  still count as changes; erring toward "this changed" costs only a silent
  `local_edit`.

- **Java bug rules** — `configs/semgrep/bugfix-java.yml`, eight hand-authored
  Semgrep rules covering all six `bug_hunt` subcategories for Java: empty
  catch, catch that only calls `printStackTrace()`, dereference of
  `map.get()`, `Optional.get()` without `isPresent()`,
  `for (int i = 0; i <= a.length; i++)`, a stream opened outside
  try-with-resources, `SimpleDateFormat` in a static field, and removal from a
  collection during a for-each over it. Java is the emptiest language in the
  registry: of `p/r2c-bug-scan`'s 4 Java rules, **none** lands in a bug class.

- **Cross-pack invariants for every Semgrep rule file** —
  `mcp/test/integration/semgrepPacks.test.ts`. The locale-codec byte check and
  `semgrep --validate` now run over **every** pack in `configs/semgrep/`,
  discovered by reading the directory rather than from a list, so the C#, PHP,
  Ruby and Rust packs still to come are covered by existing on disk. Both checks
  were moved out of the Java-specific test rather than duplicated; what stays
  there is the one thing a cross-pack test cannot know — that the rule ids its
  fixtures exercise equal the `- id:` entries in that YAML.

  The banned set is **exactly** `U+00C1`, `U+00CD`, `U+00CF`, `U+00D0`,
  `U+00DD`, the characters whose UTF-8 encoding contains a byte cp1252 leaves
  undefined; in Portuguese only the first two occur. `Ã À Â É Ê Ó Ô Õ Ú Ç` and
  every lowercase accented letter are fine, and the rule is recorded that way in
  `CLAUDE.md` — the broad form, "no uppercase accented letters", is wrong for
  ten of the twelve accented capitals Portuguese uses.

  A **positive control** copies a real pack to a temp directory, injects one
  A-acute, and asserts the byte scan names the character, that `--validate`
  refuses it, and that a real scan then returns `results: 0`,
  `paths.scanned: 0`, `errors: 0`. Asserting that every pack is clean proves
  nothing if the check has quietly stopped working.

- **Fixture coverage for `base.yml`** — `mcp/test/integration/baseRules.test.ts`
  and a hits/misses pair per rule under `mcp/test/fixtures/base/`, asserting the
  exact rule-id set, the raw non-deduplicated finding count and `paths.scanned`
  per file. Every line in `misses/` was checked against a *deliberately broken*
  variant of the rule it is a near-miss for — a case-insensitive AWS regex, a
  `Math.random` with no call, a `$O.write($X)` with an unconstrained receiver,
  an `$X.eval(...)` that also matches PyTorch's `model.eval()`, a
  `wp-unescaped-output` with its `metavariable-regex` deleted — so that each one
  is silent for a reason belonging to the rule rather than by coincidence. The
  scan is run through `spawnSync`, not `execFileSync`, because `--quiet` leaves
  stderr **empty** for a rule that failed to compile and puts the id in the
  JSON `errors` array instead: the old form reported the dead PHP rule as a bare
  "Command failed: semgrep --config …" four times without naming it once.

### Changed

- **Severity re-assigned across the Python and Go bug packs, by what each rule
  EMITS rather than by bug class.** Both packs' headers defined the criterion
  correctly — *is what the rule emits always a bug?* — and then assigned the
  tier by the class the bug belongs to, which put five Python rules and seven Go
  rules at `ERROR`. Applied cold, the criterion leaves **one per pack**:
  `bugfix-py-null-safety-none-deref-match` (an accessor glued straight onto the
  result of `re.match`, where there is no guard to recognise) and
  `bugfix-go-error-handling-empty-err-block` (an error branch with a literally
  empty body). The other seventeen are `WARNING`. The headers are fixed too.

  This matters operationally: the Semgrep parser maps `ERROR` → `high` and
  `WARNING` → `medium`, and `create_fix_pr` defaults `severity_min` to `high`,
  so the two packs now contribute almost nothing to the *default* fix-PR set and
  a caller who wants those bugs fixed has to ask for `severity_min: "medium"`.
  `bug_hunt` itself still defaults to no filter, so nothing disappears from a
  scan.

  `EXPECTED_SEVERITY` now pins every tier exhaustively in both directions in
  `bugfixRulesPy.test.ts` and `bugfixRulesGo.test.ts`. Before this, **no test
  read `extra.severity` at all** — any tier could have been changed with a green
  suite.

- **A real-bugs corpus per pack, written by the auditor rather than by the
  rules' author** — `mcp/test/fixtures/bugfix-{py,go}/hits/real_bugs.{py,go}`,
  33 and 14 defects, at least one for **every** rule in each pack. Each sits
  next to the guard shape its rule's exclusions match — a leaked HTTP response
  in the same function as a correctly closed one, a discarded error beside a
  `sync.Map.Load`, an unguarded assertion on a *different* variable inside a
  type switch, an un-awaited coroutine beside an awaited one — so that widening
  any exclusion by one step turns the file red. A minimal per-rule hit fixture
  carries no guard shapes for an exclusion to catch on, which is how a wave of
  false-positive work can delete recall and still go green; the Java pack
  learned that with a fixture that went from 6 findings to 1 unnoticed.

  Both test files also gained the Java pack's two structural invariants: the
  **total** finding count (a finding landing in an unregistered file moves no
  per-file number) and **every declared `- id:` must be exercised by a hit
  fixture**, parsed out of the YAML rather than from a hand-maintained list.

### Fixed

- **A `finally` clause silenced two of the Java pack's rules outright — the
  third pack in a row with the identical hole.** A Java `try` statement *with*
  a finalizer is a different AST node, so `try { … } catch ($E $V) { … }` never
  matched a `try/catch/finally`: attaching `finally { cleanup(); }` to a
  swallowing catch made `error-handling-empty-catch` (the pack's only `ERROR`
  rule) and `error-handling-printstacktrace-only` report nothing at all.
  Measured per fixture, before → after: **3 of 6 → 6 of 6** in each. Both rules
  now carry the two try shapes as a `pattern-either`, which is the shape the
  JS/TS and Python packs already measured — JS closed the same `finally` hole
  in `empty-catch`, Python needed *three* shapes because it also has `else:`.

  `memory-leak-stream-not-closed` has it too, and in the **opposite
  direction**: there the try shape lives in an *exclusion*, so a shape the
  exclusion cannot match does not silence the rule, it makes the rule accuse
  correct code. Neither exclusion reached a try-with-resources that also has a
  `finally`, so **four correct shapes fired at WARNING on streams that are
  closed** — `try (r = …) { … } finally { … }`, the same with a `catch`, and
  both again in the Java 9 `try (r) { … }` form. Zero now.

  What was **measured and is not a hole**, rather than assumed from reading the
  patterns: a try-with-resources header, a second `catch` clause, and — the
  sibling shape Python's audit found broken — **multi-catch**. `catch (A | B e)
  { }` already matched, and `$V` still binds the name, so the Checkstyle
  `ignore`/`ignored`/`expected` escape hatch still applies to it; Java's
  multi-catch is not the false negative that `except (ValueError, TypeError):
  pass` was, where the metavariable did not bind a tuple. All three are pinned
  by fixtures now, in both directions, because "already matched" is a
  measurement with a date on it.

  The cost of the two new exclusion clauses was measured rather than asserted:
  `pattern-not-inside` excludes the whole node it matched, so a *second*,
  unmanaged stream opened inside a try-with-resources body stays invisible —
  which was already true of the two clauses that shipped, so the new ones make
  an existing blind spot consistent instead of adding one. No stated limitation
  changed: `open(); try { … } finally { close(); }` still fires, still for the
  reason the rule is `WARNING`.

- **The JS/TS pack, measured against this repo's own `mcp/src`** — 183 files of
  TypeScript nobody wrote as a fixture, chosen by neither the rule author nor
  the auditor. The check is cheap, needs no fixture, and caught two things that
  36 two-axis ablations did not, because "the clause is live" and "it does not
  reduce true positives" are **both true of a clause that only adds false
  positives**:

  | rule | before the audit wave | after it | now |
  | --- | --- | --- | --- |
  | `race-condition-floating-mutation` | 20 | 0 | 0 |
  | `null-safety-unchecked-match` | 0 | **13** | 0 |
  | `error-handling-catch-returns-null` | 25 | 25 | *deleted* |
  | `error-handling-empty-catch` | 42 | 42 | 42, now WARNING |
  | `error-handling-empty-promise-catch` | 3 | 3 | 3, now WARNING |
  | total | 90 | 83 | 45 |

  The `floating-mutation` column is the audit wave working exactly as intended
  on code none of us picked. The `unchecked-match` column is a **regression the
  audit wave introduced**: its new `RegExp#exec` branch did not inherit the
  optional-chaining exclusion the `match` branch already had, so guarded
  `exec(...)?.[1]` started firing — 13 of them, all correct, against the single
  true positive the branch was added for. Fixed with a second `pattern-not`
  mirroring the existing one, and pinned by two near-misses that came from the
  self-scan rather than from any probe corpus.

- **`empty-catch` and `empty-promise-catch` move ERROR → WARNING.** They produce
  **45 findings on `mcp/src` and all 45 are deliberate, comment-documented
  fail-open** — an empty `catch` whose comment says the process is already dead,
  the handle already closed, the cleanup best-effort. They were at ERROR on the
  reasoning that an *unmarked* silent swallow is a bug whatever the author
  meant. The self-scan refutes the premise, not the conclusion: they **are**
  marked, with a comment, which Semgrep cannot read. A declaration of intent the
  rule cannot recognise is the severity criterion exactly.

  This is the same reasoning that keeps the **Java** empty-catch at ERROR, not a
  contradiction of it: that rule can read its ecosystem's intent marker — the
  Checkstyle/IntelliJ convention of naming the binding `ignore`/`ignored`/
  `expected`. JS/TS has no equivalent of comparable standing, and the reason is
  structural rather than cultural: **ES2019 optional catch binding removed the
  identifier a naming convention would attach to.** 41 of those 42 are written
  `catch {`, with nothing to name; the ecosystem marks intent with a comment, or
  with ESLint's `no-empty` `allowEmptyCatch` switch, which is project
  configuration rather than an in-code marker. The nearest thing that *is*
  machine-readable is honoured anyway, so one case can be marked deliberate in
  code instead of with `// nosemgrep`: a binding named `_`/`_e`/`_err`
  (ESLint's `caughtErrorsIgnorePattern`, TypeScript's leading-underscore
  convention) or one of the three Checkstyle words. Stated rather than implied:
  **it removed zero of the 42.** `empty-promise-catch` gets no escape hatch at
  all, because `.catch(() => {})` has no binding to name.

  **One rule in the pack is now at ERROR** — `index-at-length`, which produces
  zero findings on `mcp/src`, the right number for a rule that narrow. Eleven
  are WARNING and one INFO. A default `create_fix_pr` run therefore takes almost
  nothing from this pack, which is the point: it must not open a PR rewriting 45
  deliberate fail-open handlers.

- **The JS/TS bug pack, audited against code written by someone who did not
  write the rules.** `configs/semgrep/bugfix-js.yml` shipped in 1.6.0 and had
  never been read by anybody but its author; every fixture behind it had been
  written by that author too, so each one tested the author's INTENT rather
  than what the pattern binds to. An independent auditor wrote ~600 lines of
  JS/TS against the rule TEXTS and found **~40 false positives across 14
  rules**. Three were catastrophic on real codebases:

  - **`null-safety-unchecked-find` had zero true positives.**
    `$A.find(...).$PROP` binds to any method named `find`, and `$PROP` matches
    method calls, not just property reads. In any Node backend on Mongoose or
    the Mongo driver, or any page using jQuery, it fired at **ERROR** on
    essentially every query — `User.find({}).sort(…)`, `User.find({}).lean()`,
    `collection.find({}).toArray()`, `$('#root').find('.item').addClass(…)`,
    `repo.find({}).length` — and advised `?.`, which is wrong advice for a
    Query object. Nine reproductions, none of them a bug. It now requires the
    single argument to be a **literal callback**, which is the only thing that
    separates `Array#find` from a Mongoose query (an object), a jQuery
    selector (a string) or Immutable's `find(fn, ctx, notSetValue)` (three
    arguments), with no type inference available. `findLast` added.
  - **`race-condition-floating-mutation` was wrong 12 times out of 15**,
    including on `res.send(rows)` — the most common line in an Express app —
    and on `void repo.save(a)`, **the fix its own message prescribes**. A rule
    whose prescribed fix does not silence it teaches people to ignore it. The
    receiver is now constrained by name as well as the method, and `void`,
    `Promise.all`/`allSettled`, `.catch`/`.then`/`.finally` continuation and
    capture-then-await are excluded, one clause per near-miss function.
  - **`off-by-one-loop-lte-length` told loops that never index anything that
    they read past the end.** `<= .length` is correct whenever a loop counts
    boundaries rather than elements (1-based iteration, insertion slots, string
    prefixes), and the rule fired at ERROR on all of them. It now matches the
    out-of-range **read** and uses the loop only as context, which makes the
    message true by construction — and picks up the braceless loop body that
    the old block-shaped pattern could not see.

  Also fixed: a `finally` clause silenced `empty-catch` outright; the listener
  rule's pattern took exactly two arguments, so `{ passive: true }`,
  `{ capture: true }`, `{ once: true }`, `{ signal }` and the legacy boolean
  third argument were all invisible; the interval rule required `const $T =`,
  so `setInterval(tick, 1000)` with no handle captured — an interval nobody can
  ever clear, the strongest form of the bug — was silent, along with `let t =`,
  `this.t =` and `ref.current =`; the same rule's exclusions keyed on the shape
  of the CONTAINER rather than on whether the timer was cleared, so an arrow
  function calling `clearInterval(t)` two lines later still fired while the
  byte-identical body in a `function` declaration was correctly silent; an
  early `return` of a cleanup suppressed the listener/subscription leak in the
  branch AFTER it; `unchecked-env` missed bracket access and property reads
  (`process.env['KEY'].trim()`, `process.env.KEY.length`); `unchecked-match`
  missed `RegExp#exec`; and `reduce-without-initial` fired on array literals,
  which cannot be empty.

- **Every JS/TS rule's severity tier is now pinned by a test, and five tiers
  changed.** Nothing read `extra.severity` anywhere in the suite, so changing
  any rule's tier — including promoting one to ERROR — was a mutation the whole
  pack passed green. `EXPECTED_SEVERITY` in `bugfixRulesJs.test.ts` asserts all
  fourteen exhaustively, in both directions. The tiers were re-derived from the
  criterion the Java pack settled on, asked of the OUTPUT rather than the
  pattern: **is what the rule emits always a bug?** Three of fourteen clear it
  and stay at ERROR (`empty-catch`, `empty-promise-catch`, `index-at-length` —
  the last because a *read* at `a[a.length]` is unconditionally `undefined`,
  which is a fact about the AST rather than a guard). `catch-returns-null`,
  `loop-lte-length`, `unchecked-find`, `unchecked-match` and
  `listener-without-cleanup` move to WARNING or INFO. This also settles a
  split that had no principle behind it: `listener-without-cleanup` (ERROR) and
  `subscribe-without-unsubscribe` (WARNING) are structurally identical rules
  and are now on the same tier.

  **This changes what a default `create_fix_pr` run does.** ERROR maps to
  `high`, WARNING to `medium`, INFO to `info`, and `create_fix_pr` defaults to
  `severity_min: "high"` — so the JS/TS pack now contributes three rules to the
  default fix-PR set, and a caller who wants the rest must ask for
  `severity_min: "medium"`. `bug_hunt` itself applies no filter, so nothing
  disappears from a scan.

- **`error-handling-catch-returns-null` had its CLAIM corrected rather than its
  pattern.** On the auditor's corpus it produced five instances of
  textbook-correct code and zero true positives: `safeJsonParse`, an
  optional-dependency `require` probe, a `new URL()` validity check, a lookup
  typed `| null`, and a config reader returning `[]`. Returning an empty value
  from a catch is idiomatic JavaScript with a documented contract, and there is
  no syntactic difference between those and a genuine swallow — every candidate
  narrowing was measured and silences the pack's own hit fixture too. So the
  rule dropped to INFO, and its message stopped saying "log and/or rethrow":
  that advice was **circular**, because adding the log made the rule go quiet
  while the stated complaint (an empty value the caller cannot distinguish from
  a real result) was untouched. `hits/catch-returns-null-idioms.ts` now pins
  those five idioms as hits, with the trade written down, so re-promoting the
  tier turns the severity assertion red with that file as the evidence.

- **The JS/TS near-miss corpus is now written by the auditor, not the rule
  author.** Eight new `misses/` files, credited in-file, reproducing every
  false-positive class above; plus `hits/` fixtures for every newly-covered
  shape. Each was RED before the corresponding rule change. Every clause added
  in this wave was then ablated on both axes — deleted to confirm a test goes
  red, and checked against the true-positive count to confirm it eats no real
  bugs — which removed **six clauses that turned out to be dead**: three
  optional-catch-binding branches (Semgrep's matcher already ignores the
  binding, so `catch ($E) { }` was matching `catch { }` all along, contrary to
  the audit's reading of the pattern text), an AbortSignal exclusion that the
  cleanup clause already covered, an expression-bodied-arrow exclusion that the
  pre-existing `return $O.$M(...)` clause already covered, and two
  returned-cleanup variants in the interval rule. It also caught a near-miss
  that this wave itself had silently disarmed: `misses/race-condition.ts`'s
  `bulkSave` exists to prove the verb list's trailing `$` anchor is
  load-bearing, and the new receiver constraint made it stop proving that, so
  its receiver was renamed. Two heuristics in one rule can each hide the
  other's regression unless the near-miss clears every constraint but the one
  it is aimed at.

- **`bugfixRulesJs.test.ts` gained the total-count and declared-rules
  assertions** the Java suite already had: a finding landing in an unregistered
  file moves no per-file number, and a rule that fails to LOAD (a
  `RuleParseError` branch, an unquoted `:` producing `Invalid YAML`) is
  indistinguishable in Semgrep's output from a rule that found nothing.

- **Python and Go bug rules: ~60 false positives closed, and the false
  negatives the fixes exposed.** Both packs shipped without an audit (1.7.0 and
  1.8.0) and were measured against a corpus written by someone who did not write
  the rules. Every clause below was ablated on both axes — deleting it has to
  turn a test red *and* must not increase the true-positive count.

  Python:

  - `none-deref-dict-get` bound **anything** with a one-argument `.get`, so
    `User.objects.get(user_id).delete()` (Django's `Manager.get` *raises*; it
    never returns `None`), `queue.Queue.get(True)`, an import-time registry
    keyed by an enum, and three HTTP clients all fired at `ERROR` — and the
    advice printed on the Django line, "pass a default", is advice
    `Manager.get` does not accept. The receiver *substring* allow-list also made
    real dict bugs invisible: a Flask/Django `session` **is** a dict. It now
    keys on the **key** — a string literal that is not a URL or path — which
    discriminates without guessing receiver names. Eight false positives to
    zero, and `session.get("user_id")` / `client_config.get("timeout")` now
    fire. Cost: a lookup with a variable key is a false negative.
  - `get-without-doesnotexist` recognised only handlers with no `as` binding, no
    tuple and no `else`, so **6 of 6** correctly guarded shapes fired. The
    exclusions now filter the caught type through **nested formulas** inside
    `pattern-not-inside` (a rule-level `metavariable-regex` cannot see it —
    negated patterns export no bindings), and they are scoped to the `try`
    **body**, which fixes the whole-node defect: an unguarded `.objects.get()`
    inside the `except` arm was silenced by the guard protecting the *other*
    arm, and now fires.
  - `except-pass` and `bare-except` were **silenced outright** by adding a
    `finally:` or an `else:` to the same swallowing `try`, and `except (A, B):
    pass` was silent while the `as` form fired. Nine and three try-shape
    branches respectively close both. `bare-except` no longer fires on
    cleanup-then-`raise`, the dominant legitimate use (3 of the auditor's 4
    functions). `except ImportError: pass` — the optional-dependency probe — is
    excluded, and it is the only type carve-out, because `except
    FileNotFoundError: pass` is best-effort cleanup and a swallowed load in the
    same syntax.
  - `queryset-n-plus-one`: `$O.$REL.$FIELD` bound **any** two-deep chain, so
    `book.title.strip()`, `user.email.lower()`, `ev.created_at.isoformat()` and
    `line.amount.quantize(2)` all fired, each advised to add
    `.select_related("title")`. The finding is now the chain rather than the
    loop, which is what lets `pattern-not-inside: $O.$REL.$FIELD(...)` remove
    them (at loop scope it was a measured no-op). The anchor widened to any
    `<... $M.objects ...>` queryset, so `.exclude(...)` and `.only(...)` now
    fire — and `select_related`/`prefetch_related` became *real* exclusions,
    which is what makes those near-misses discriminating: they used to be silent
    only because any chained call broke the `.all()` anchor, so they would have
    stayed green against a deliberately broken rule.
  - `range-len-plus-one` fired on `d[len(d)] = v`, the standard
    index-a-dict-by-its-own-size idiom, in *assignment target* position; and
    `range(0, len(x) + 1)` was invisible.
  - `open-without-context` fired on five kinds of ownership transfer — a factory
    that returns the handle, `stack.enter_context(...)`, `contextlib.closing`,
    a `yield`, a pooled handle — and on a module-level log handle.
  - `toctou-exists-open` knew two exact function names. It now covers
    `os.path.isfile`, `os.access`, `pathlib.Path.exists()` and the very common
    negated guard, and it no longer fires on a test-then-**write**, where the
    check guards against clobbering and the advice does not apply.
  - `none-deref-match` knew only `.group(...)`. `.groups()`, `.groupdict()`,
    `.start()`, `.end()`, `.span()` and subscripting blow up identically.
  - `asyncio-not-awaited` fired on `yield asyncio.sleep(1)`.

  Go:

  - `off-by-one-loop-lte-len` required **nothing** of the loop body — the fix
    the Python rule has carried since it shipped was never applied here — so
    every DP seed, prefix-sum array, split enumeration and insert-position loop
    in a Go codebase fired at `ERROR`: **4 of 4** correct `n+1` loops in the
    corpus. Requiring `<... $XS[$I] ...>` takes that to zero with the true
    positive intact. Unlike the analogous Java tightening, the discrimination is
    clean here, because `dp[i]` is not `xs[i]`.
  - `err-discarded` assumed the second return value is an error. `sync.Map.Load`
    alone made it fire across most concurrent Go; `strings.CutPrefix` and
    `utf8.DecodeRune` return `(string, bool)` and `(rune, int)`. A short
    standard-library deny-list closes those. A project function returning
    `(T, bool)` is still indistinguishable, which is why it is `WARNING`.
  - `body-not-closed` was anchored to `http.Get` alone, so `client.Do(req)` —
    what every real client uses — plus `http.Post`, `http.PostForm`,
    `http.Head` and `http.DefaultClient.Get` leaked silently. It also fired on
    three *correct* closes: the errcheck-safe
    `defer func() { _ = resp.Body.Close() }()`, an explicit non-deferred close,
    and `defer closeQuietly(resp.Body)`. Ownership transfer (`return resp, nil`)
    is excluded too.
  - `lock-without-defer` was **redesigned around the bug** instead of the idiom.
    It fired on the two shapes where a `defer` would *be* the bug — a
    fine-grained critical section, and `for { mu.Lock(); …; mu.Unlock() }` — and
    on a file lock, because `$MU.Lock()` binds any receiver. It now looks for a
    `return` *between* the `Lock` and the `Unlock`, which is the actual defect,
    and gained an `RLock`/`RUnlock` branch that was entirely missing.
  - `nil-map-write` could not see the classic: `c := &config{}` leaves every map
    field nil and `c.Labels["env"] = "prod"` panics. It also fired on a correct
    init through a pointer (`json.Unmarshal(b, &m)`).
  - `type-assert-no-ok` fired on a `v.(fmt.Stringer)` inside a `switch v.(type)`
    arm that proves it safe. The rule file claimed that exclusion was
    unnecessary; what did not work was the spelling — `switch $V.(type) { ... }`
    is a Go syntax error as a pattern, and `case $C:` makes it compile.
  - `err-blank-assign` fired on `var _ io.Writer = newWriter()`, the
    compile-time interface assertion, and on `_ = copy(dst, src)`.
  - `empty-err-block` fired on `if p != nil { }` for a `*os.File`, because
    `$ERR` bound any identifier.

- **Dead clauses removed, measured by ablation rather than by reading.** In Go:
  `err-discarded`'s `$X, _ := $F(...)` branch (the `=` branch matches the same
  set — the redundancy this file's own header documented for `append` and never
  applied here); one of `type-assert-no-ok`'s two mutually redundant
  `pattern-not-inside` clauses; `lock-without-defer`'s trailing `...`;
  `err-blank-assign`'s `var _ $T = $F(...)`; `err-discarded`'s `strings.Cut`
  (three return values, so it never matched); and three of
  `body-not-closed`'s seven close exclusions, which the bare
  `$RESP.Body.Close()` statement already covers inside a `defer func(){}()`. In
  Python: `queryset-n-plus-one`'s second `pattern-inside` anchor. Every
  remaining clause in both packs is now live on both axes, and where a live
  clause had no fixture behind it — five `except-pass` try-shape branches, three
  `re` accessors, `http.PostForm`/`http.Head`, the `yield` handle transfer, the
  negated `isfile` guard, three write modes — a fixture was added rather than
  the clause deleted.

- **The three annotation route families now match the form their framework
  documents.** `configs/semgrep/routes.yml`'s 16 annotation-based route rules
  each demanded an argument that the canonical form does not supply, so the
  most ordinary controller in each framework lost routes — silently, because a
  route this pack does not match produces no error anywhere and simply never
  enters the attack surface.

  Measured on a corpus written by an auditor who did not write the rules
  (`mcp/test/fixtures/surface/annotations/`, 52 endpoints): **18 of 52** were
  reported before this change. ASP.NET 5 of 15 — a controller scaffolded by
  `dotnet new webapi`, whose actions carry a bare `[HttpGet]` and whose path
  lives on the class `[Route("api/[controller]")]`, mapped to **zero routes**,
  i.e. "this C# API exposes nothing". NestJS 6 of 12: `@Get()` and `@Post()`,
  the forms docs.nestjs.com uses for index and create actions, matched
  nothing. Spring 7 of 25: only a lone string literal matched, so
  `@GetMapping(value = "/x", produces = "…")`, `@GetMapping(path = "/x")` and
  a bare `@GetMapping` were all absent. All 52 are reported now.

  - **Spring's named-argument forms are matched, and the note in the previous
    release saying they could not be is withdrawn.** `@GetMapping($PATH, ...)`
    is indeed rejected as "Invalid pattern for Java" — but only because the
    ellipsis follows a bare metavariable. `@GetMapping(value = $PATH, ...)`
    parses cleanly and binds `$PATH` to the path literal alone, whatever order
    the arguments are written in.
  - **The six Spring rules are now `focus-metavariable: $PATH`.** A named
    argument need not be the first one, and the recovery path that rebuilds
    captures from byte offsets reads the FIRST argument: measured with the
    focus removed, `@PutMapping(produces = "application/json", value = "/x")`
    reports as `PUT produces = "application/json" [partial]` on a redacting
    Semgrep while a Semgrep that emits metavariables reports `/x`. Nothing is
    fabricated (the extractor refuses that text as a path), but the answer
    would depend on the reader's Semgrep version, which nothing else in this
    pack does.
  - **ASP.NET reads a `[Route("…")]` companion attribute** on a method whose
    verb attribute carries no path, in either attribute order (Semgrep matches
    both with one alternative). The bare rules exclude that shape with a
    `pattern-not`, so such a method is reported once, at the path `[Route]`
    names, rather than twice.
  - **A bare annotation is reported with an empty own-path, flagged
    `path_partial` at 'low' confidence** — the endpoint exists, and its full
    URL, being the class-level prefix, is honestly unknown. Such a rule
    captures nothing, so it declares `metadata.guardian_path: inherited`,
    which `surface/extract.ts` reads to build the record and
    `surface/recoverMetavars.ts` reads to hand the match back unscanned (a new
    `noCaptures` counter, so it is neither counted as recovered nor as
    unreadable — the latter would flip the language's `coverage` to "routes
    here could not be read" when nothing was lost).

    A companion `mount` rule for `@Controller('users')` was considered and
    rejected: nothing consumes a mount for these frameworks
    (`resolvers/node.ts` resolves one only through an import binding its
    `$ROUTER` in the same file, and a controller class is not imported into
    its own file), and `resolveNodeMounts` treats any route declared in a
    file that mounts something as attached to the app directly — so adding
    one would flip every route in that controller from honestly partial to
    confidently wrong, at its un-prefixed path, which `scan_dast` would then
    send requests to. Resolving class-level prefixes is a follow-up in
    `resolvers/node.ts`, not a rule-pack change.
  - **Two new invariants in `mcp/test/unit/surface/rulePack.test.ts`.** A route
    rule that binds no `$PATH` must declare the flag (without it the rule
    matches perfectly and yields nothing — the defect above, as a test), and a
    rule whose pattern spans a declaration must either focus `$PATH` or
    capture no path at all, so no declaration-spanning span is ever scanned for
    a path.
  - **50 ablations, zero dead clauses.** Every alternative and operator added
    here was removed on its own and the fixture set checked: each removal loses
    exactly the endpoints it should, and removing an ASP.NET `pattern-not`
    duplicates exactly one endpoint. The decoy corpus is unchanged
    (14 matches before and after), and the old and new packs differ over the
    whole corpus by 36 added matches, 0 removed.

- **`wp-unescaped-output` stops flagging `echo (int) $_GET['id'];`, and now
  matches the subscript rather than the statement.** A cast is not a call, and
  Semgrep sees straight through the cast node — `$SUPER[...]` binds to the
  subscript inside it and `metavariable-regex` reads the text of the subscript,
  not of the cast. So the standard safe way to emit a numeric request parameter
  in WordPress was an ERROR-severity finding, in all eleven PHP cast spellings
  and in every branch of the rule.

  The first fix was a `pattern-not-regex` over the matched text. It was wrong in
  a way worth recording, because a text guard suppresses everything the match
  covers and the match was a whole statement:

  - **Recall.** Of nine real-XSS lines carrying a cast somewhere in the same
    statement, two fired. `printf("%d %s", (int) $_GET['id'], $_GET['name']);`
    and all four polarities of `echo $f ? (int) $_GET['a'] : $_GET['b'];` were
    silent — the branches that match at statement level have the widest
    suppression window of all.
  - **A suppression vector.** `pattern-not-regex` reads source text, so
    `echo 'use (int)$_GET for numbers: ' . $_GET['x'];` turned the rule off with
    no cast executed anywhere. In a security pack that is not a documented
    trade; it is a switch any helpful — or hostile — string literal can carry.

  The rule is now a `pattern-either` of `pattern-inside` SCOPES plus a narrow
  `pattern: $SUPER[...]`, so a finding points at the offending subscript and one
  statement can report one operand while staying quiet about another. The cast
  guard is six `pattern-not-inside` clauses, which can only remove the operand
  actually wrapped in a cast; six entries cover all eleven spellings because
  int/integer, float/double/real, bool/boolean and string/binary collapse to the
  same node. Enumerating them is legitimate because PHP's cast set is closed by
  the language, unlike a list of escaping functions. Measured: eleven real-XSS
  lines fire, the seven safe casts stay silent, a trailing `//` comment with the
  same spelling never suppressed anything, and `echo (int) $_GET['a'] .
  $_GET['b'];` — recorded as an accepted loss one commit earlier — fires again.

- **The pinned `wp-unescaped-output` false positive is gone, and both halves of
  its recorded justification were wrong.** `echo esc_html($a . $_GET['b']) . "x";`
  was recorded as unfixable because `echo` lowers to a call node, so any
  exclusion naming the escaping call names the echo too. True of the AST, false
  of the filter: `metavariable-regex` matches the **source text** of the
  metavariable, which is `echo`/`print`/`<?=` for the language constructs and an
  identifier for a real call. Requiring identifier shape of `$F` costs nothing —
  12/12 true positives kept, both false positives gone, `errors: 0`. The
  measurement in the old comment was wrong too: the two exclusions said to take
  the rule "to zero findings, true positives included" actually took it from 12
  to 8. `mcp/test/fixtures/base/known-false-positives/` is deleted.

- **`wp-unescaped-output` sees eight more shapes of real XSS.** Measured against
  a reviewer's probe of fourteen, six fired. Now thirteen do: comma-separated
  `echo`, nested subscript (`$_GET['user']['name']`), a ternary operand,
  `printf`, an interpolated string used as a concatenation operand, and
  `$_SERVER` / `$_COOKIE` — `$_SERVER['PHP_SELF']` being the canonical reflected
  XSS in PHP, which the old `GET|POST|REQUEST` regex could not reach. The
  fourteenth needs data flow (a heredoc assigned to a variable, echoed later)
  and is recorded as a limitation rather than guessed at.

- **A superglobal used as an array KEY no longer fires.**
  `echo $labels[$_GET['lang']] . "</b>";` is ordinary i18n code — the lookup
  table is the developer's and the request only picks the element — and the
  narrowed anchor introduced it as an ERROR-tier false positive, five findings
  on correct code. Twelve of the fourteen scopes bind `$SUPER` themselves, so
  the comma, `printf` and ternary lookups were never at risk; the two
  CONCATENATION scopes do not, which left the narrow `pattern: $SUPER[...]`
  free to match a subscript in index position. Guarded by
  `pattern-not-inside: $ARR[$SUPER[...]]`, which tells the two apart by what is
  INSIDE the brackets rather than by nesting depth — so
  `echo $_GET['user']['name'];`, whose index is a literal, still fires, and
  there is a fixture saying so. `isset()` needs a clause of its own because
  Semgrep does not model it as a call; a matching `empty()` clause was proposed,
  measured to move nothing at all — `$G(...)` already covers it, because
  `empty` IS a call node — and dropped rather than kept for symmetry.

- **`wp-unescaped-output`'s "inside any call = handled" is now written down.**
  Not a regression — the old operand patterns needed a direct operand, so none
  of these ever fired — but a far stronger claim than "an escaper handles it",
  and it was implied rather than stated. Measured silent: `wp_unslash()`,
  `stripslashes()`, `trim()`, `sprintf()`, `implode()`, `nl2br()`,
  `str_replace()`, `strtoupper()`, `strrev()`, none of which escape HTML. The
  sharpest case is WordPress's own idiom — `echo wp_unslash($_GET['x']);` is
  textbook XSS and is syntactically indistinguishable from the correct
  `echo esc_html(wp_unslash($_GET['x']));`. Enumerating the non-escapers is the
  open-set problem inverted, so the limitation stays and is named instead, in
  the rule comment and the test header. The other half of the same trade is
  pinned rather than described: a PARENTHESISED operand
  (`echo "x" . ($_GET['h']);`) fires now, where the old operand patterns could
  not reach it.

- **`yaml.load(stream=f, Loader=yaml.SafeLoader)` was an ERROR on safe code.**
  The `Loader=` exclusions were written `yaml.load($X, Loader=...)`, which
  requires a POSITIONAL first argument; passing the stream by keyword is legal
  Python and perfectly safe. Widened to `yaml.load(..., Loader=...)`. Measured
  on the reviewer's probe: seven findings, exactly the seven unsafe spellings,
  all eight safe forms silent, no recall lost.

- **`wp-unescaped-output`'s message now names the `$_SERVER` keys that carry
  risk** — `PHP_SELF`, `REQUEST_URI`, `QUERY_STRING`, `PATH_INFO` and the
  `HTTP_*` family. All twelve keys still fire and that is deliberate: an
  allowlist would have to rule on `SERVER_NAME` and `HTTP_HOST`, which an
  attacker can influence on a misconfigured vhost. But a developer told "XSS"
  about `$_SERVER['DOCUMENT_ROOT']` concludes the rule is wrong and stops
  reading it on `PHP_SELF` too, so the message says which is which.

- **`py-yaml-load` caught one unsafe spelling in six.** The rule was
  `pattern: yaml.load($X)`, a one-argument match — but what makes the call safe
  is the **loader class**, not the arity. `Loader=yaml.Loader`,
  `Loader=yaml.UnsafeLoader`, the positional `yaml.load(f, yaml.Loader)`,
  `yaml.unsafe_load` and `yaml.full_load` all executed arbitrary code unseen.
  All six now fire and the safe forms stay silent, excluded by loader name in
  both the keyword and positional position and for both the pure-Python and
  libyaml classes.

- **`pattern-inside: print $A . $B;` was dead by fixture** — correct, live
  against real code, and deletable with the suite still green, inside the very
  branch of work that audits for clauses nobody measures. Pinned by a hit rather
  than removed.

- **The load-failure invariant is stated rather than accidental.** Ablating the
  only `pattern:` of `py-yaml-load` produced `scanned=0` with **neither** a
  `RuleParseError` **nor** an `Invalid YAML` — a fifth spelling of the silent
  failure family, caught only because the id-set assertion pins the exact set of
  ids the `hits/` fixtures produce. `baseRules.test.ts` now says so in a comment
  and adds a count comparison beside the set comparison, which also catches a
  `- id:` written twice.

- **`php-sql-injection-direct`'s reach is written down.** It targets
  `mysql_query`, removed in PHP 7, and `mysqli_query`; the canonical WordPress
  form `$wpdb->query("..." . $id)` is a different API surface and is left to a
  rule of its own rather than bolted onto this id.

- **The Java rules no longer fire on correct Java.** The first two review
  sweeps found 19 findings on correct code across five of the eight rules; all
  19 are gone, and every one is pinned by a near-miss fixture. A third and a
  fourth sweep are recorded below.
  - `null-safety-optional-get-no-ispresent` was never about `Optional`:
    `$O.get()` matched **any** zero-argument `get()`, so `AtomicInteger.get()`,
    `ThreadLocal.get()` and `Supplier.get()` all fired at ERROR. Restricted by
    declared type, and the early-exit guard shapes
    (`return`/`throw`/`continue`/`break` under `!isPresent()` or `isEmpty()`)
    are now recognised alongside `if (isPresent())`.
  - `null-safety-map-get-deref` was never about `Map`: `$M.get($K).$METHOD(...)`
    matched **any** one-argument `get` chained with a method, so
    `list.get(0).trim()` fired at ERROR and advised `getOrDefault`, a method
    `List` does not have. Restricted to `Map`, `HashMap`, `TreeMap`,
    `LinkedHashMap` and `ConcurrentHashMap` — which also *gains* the
    `HashMap`-, `TreeMap`- and `var`-declared receivers the old rule matched
    only by accident.
  - `memory-leak-stream-not-closed` now recognises Java 9's
    `try (alreadyDeclared) { ... }` resource form, which closes the stream.
  - `edge-case-modify-during-iteration` is re-anchored on the `remove` call
    (the finding now points at the mutation, not the loop header) and no longer
    fires on the find-remove-`return`/`break` idiom, where no
    `ConcurrentModificationException` is possible, nor on
    `CopyOnWriteArrayList`, which iterates a snapshot by design.
  - `error-handling-empty-catch` honours the Checkstyle / IntelliJ naming
    convention: an exception variable named `ignore`, `ignored` or `expected`
    is a deliberate ignore. Every other name still fires.
  - `null-safety-optional-get-no-ispresent` no longer fires on a **ternary**
    guard. All three forms were firing at ERROR on correct code —
    `o.isPresent() ? o.get() : d`, `!o.isPresent() ? d : o.get()` and
    `o.isEmpty() ? d : o.get()` — because a ternary is a conditional
    *expression*, a different AST node from an `if` statement, so none of the
    statement-shaped exclusions reached it. Twelve guard shapes are now
    recognised, up from nine.
  - `null-safety-optional-get-no-ispresent` no longer fires on
    `if (o.filter(p).isPresent()) { … o.get() … }`. `filter` on an empty
    `Optional` returns empty, so a present filter result proves the original is
    present; the `isPresent()` exclusion missed it only because it binds the
    receiver to exactly `$O`, and here the receiver is `o.filter(p)`.
- **A fourth review sweep found 16 more findings on correct Java, plus one
  false negative that hid a real bug.** All 17 are gone. The near-miss fixtures
  behind them deliberately vary the *shape* — an extra statement, a compound
  condition, a different exit, a label, a chained call, a different declared
  receiver type — rather than instantiating each exclusion pattern minimally,
  which is what made the previous round's "every clause is live" measurement
  true and uninformative.
  - **`edge-case-modify-during-iteration` was hiding a real
    `ConcurrentModificationException`.** A `remove()` inside a `switch`
    followed by `break;` was excluded by the paired `remove(); break;` clause —
    but that `break` leaves the *switch*, not the loop, so the for-each calls
    `next()` again on a mutated collection. The plain-`break` exclusion now
    applies only outside a `switch`; `return`, `throw` and a **labelled**
    `break` do leave the method or the loop from inside one and stay excluded
    everywhere. Fixed regardless of the false positives below, because a false
    negative that hides a real bug is worse than a false positive.
  - `null-safety-map-get-deref` had **no guard exclusion at all**, so the
    canonical Java guard `if (m.containsKey(k)) { … m.get(k).trim() … }` fired
    at ERROR and advised `getOrDefault` on already-guarded code. It now
    excludes the measured shapes that prove the key present: the inline
    `containsKey` and `get() != null` tests, alone or as either operand of a
    conjunction; all four ternary polarities; an early
    `return`/`throw`/`continue` under `!containsKey` or `get() == null`; and
    population by `put`, `putIfAbsent`, `computeIfAbsent` or
    `if (!containsKey) { put(); }`. A **disjunction** is deliberately not
    excluded — `a || m.containsKey(k)` proves nothing inside the body.
  - `edge-case-modify-during-iteration` no longer fires when one statement sits
    between the removal and its exit (`list.remove(s); removed = 1; break;`),
    nor on a **labelled** `break`, nor on `remove(); throw …;`.
  - `null-safety-optional-get-no-ispresent` no longer fires on a **compound**
    guard (`if (a.isPresent() && b.isPresent())` fired twice, at the exact
    point where both were proven present), on a `while (o.isPresent())` guard,
    on an early exit with one statement before it
    (`if (!o.isPresent()) { log(); return ""; }`), or on an
    `Optional<T> o = Optional.of(…)` construction, which cannot be empty —
    `ofNullable` can, and still fires.
  - `off-by-one-loop-lte-length` restricts its array metavariable to an
    **array type**. `$A.length` matched any `int` field named `length`, so a
    domain object's deliberately inclusive `for (int i = 0; i <= seg.length;
    i++)` fired at ERROR on a loop with no array in it. Measured, the
    restriction costs no recall: parameter, local, field, `this.`-qualified
    field and `var`-inferred local arrays are all still matched.
  - **Two recall gaps closed.** `map-get-deref` and `modify-during-iteration`
    now bind the receiver through a `metavariable-pattern` accepting a bare
    name **or** a `this.`-qualified one, so `this.cache.get(k).trim()` is seen
    where `cache.get(k).trim()` already was — same class, same field, same bug.
    And `race-condition-static-dateformat` now ships a single **fully-qualified**
    pattern, so a `static final java.text.SimpleDateFormat` field in a file
    with no import is seen; measured across four import shapes, the qualified
    pattern matches the short forms too whenever an import lets Semgrep resolve
    them, while the short pattern never matched the qualified one — so the
    short branch was inert and was deleted.
  - **Two inert clauses deleted, found by ablating every clause alone.** The
    two `switch` re-inclusion disjuncts each repeated
    `- pattern: $COLL.remove(...)` next to their `pattern-inside`, copied from
    the third disjunct where it *is* load-bearing. It is not load-bearing
    there: `pattern-inside` is already a positive term and the enclosing
    conjunction already anchors on the removal, so the repeat changed nothing —
    measured, identical findings with and without it. Sixth occurrence of this
    defect class in the rule-pack series, and the first caught before shipping.
  - **The exit-terminated exclusions are bounded on purpose.** Across
    `map-get-deref`, `optional-get-no-ispresent` and
    `modify-during-iteration`, they tolerate exactly **one** statement between
    the guard (or the removal) and the exit rather than a statement ellipsis.
    Measured: the ellipsis matches *deep*, so
    `if (!m.containsKey(k)) { if (strict) { return ""; } }` and
    `items.remove(s); if (done) { break; }` both stop firing — and both are
    real bugs. The price is accepted false positive (5) below.
- **A fifth review sweep found that closing the false positives had opened a
  FALSE NEGATIVE, and the harness went green through all of it.** Wave 4's
  guard exclusions silenced the branch the guard proves is *unsafe*. On a file
  of eight guaranteed `NullPointerException`s / `NoSuchElementException`s —
  the dereference in the `else` arm of the guard, or in the ternary arm the
  condition rules out — **6 fired before wave 4, 1 after, 8 now.**
  - **`pattern-not-inside` excludes the whole node it matched.**
    `if ($M.containsKey($K)) { ... }` matches the entire **if-else statement**,
    and `"$M.containsKey($K) ? ... : ..."` the entire **conditional
    expression**, so both arms were excluded. Every guard exclusion in
    `map-get-deref` and `optional-get-no-ispresent` is now **scoped to the arm
    the guard actually proves**: the deep expression operator inside the
    guarded ternary arm, and a dereference requirement inside the `if` body
    (two clauses per shape — one reaching a multi-statement or nested body, one
    reaching the braceless form).
  - **A REAL-BUGS CORPUS, so this class of regression cannot recur silently.**
    `mcp/test/fixtures/bugfix-java/hits/RealBugs.java` (14 defects at the
    wave-7 count) and `hits/ElseArm.java` (8) were written by the reviewer, not by the rule
    author, and their counts are asserted per file plus a total. Every future
    exclusion now has to prove — while it is being ablated — that it does not
    eat a real bug, not merely that it silences the shape it was written for.
  - **Both rules honour a guard used as an EXPRESSION, not only as the
    condition of an `if`.** `return m.containsKey(k) && m.get(k).isEmpty();`
    and `return o.isPresent() && o.get().isEmpty();` are the normal way to
    write "absent or blank" in Java and fired on correct code; so did the same
    guard assigned to a local.
  - **The negative-first disjunction is now excluded.** `m.get(k) == null || …`,
    `!m.containsKey(k) || …`, `!o.isPresent() || …` and `o.isEmpty() || …` are
    the De Morgan duals of the conjunction already excluded, `||`
    short-circuits identically, and all four fired on correct code.
    `force || m.containsKey(k)` still fires and always will — it proves
    nothing — and `b8` in `hits/RealBugs.java` measures that every run.
  - **`map-get-deref` now excludes `while (m.containsKey(k))`.** The `Optional`
    rule had excluded its `while` counterpart since the first wave; the map
    rule had none, so a correct drain loop fired.
  - **The `switch` re-inclusion in `edge-case-modify-during-iteration` was
    lexical, not scoped.** `pattern-inside: switch ($S) { case $C: ... }`
    re-armed the rule on any removal anywhere inside a case — including one
    inside a **loop** written in that case, where a plain `break` exits the
    loop and the code is correct. A `switch` dispatching a command with a
    search-and-remove loop in one arm fired three times. Both disjuncts now
    nest the `switch` **inside the for-each over that collection**, so the
    clause tests the nesting ORDER; the two `switch` hit fixtures still fire,
    and ablating either disjunct drops exactly one of them.
  - **Nine clauses came back INERT on the first ablation** — the braceless half
    of each pair, covered by its twin because the only near-miss for that guard
    shape was a braced one. Nine near-miss functions were added rather than
    nine clauses deleted, since the braceless guard is real Java that fires
    without them. Final ablation: 34 exclusion clauses, all live, none moving
    the real-bugs count.
- **A sixth review sweep closed the last false-positive class and made the
  silent-rule-failure family self-enforcing.** The merge was approved with these
  four follow-ups.
  - **`map-get-deref` no longer fires on iteration over the map's own
    `keySet()`.** `for (String k : m.keySet()) { … m.get(k).trim() … }` is the
    commonest map-iteration idiom in Java: the loop header binds the key **from
    the map itself**, so presence is guaranteed on every syntactic path reaching
    the dereference — the same standard by which `containsKey` is accepted as a
    guard — and it was not in the accepted-limitations table either. The clause
    unifies **both** metavariables, the map iterated with the map dereferenced
    and the loop variable with the key passed to `get`, and `b13` / `b14` in
    `hits/RealBugs.java` break one unification each and must keep firing.
    Measured over the five correct-code shapes the reviewer wrote: it closes the
    plain loop, the `this.`-qualified loop and the loop whose dereference is
    nested inside an `if`; the `entrySet()` form and the form that copies the
    key set to a local first remain, and are now **accepted limitation (11)**
    rather than an implication.

    **One clause, not the braced/braceless pair every `if` guard carries**, and
    that was measured in four forms first: the deref-requiring pair and the
    plain `for (…) { … }` both close the braced shapes and leave the braceless
    one firing, while writing the body as a bare statement ellipsis closes both
    at once. A pair would have been half inert, which is the defect class this
    series has now caught six times. Nor is it scoped to a branch: a for-each
    has no `else` arm, the whole body runs with the key present, so excluding
    the whole node is exactly right here — the arm-scoping lesson does not transfer.
  - **The accepted-limitations table had nine rows and every one was a false
    positive.** That asymmetry is the shape of the defect the previous two waves
    were about: nobody was looking in the recall direction, so nothing was ever
    written down there. Every row now states its direction, and three rows are
    new — the **invalidated-guarantee** false-negative class (9), five measured
    guaranteed throws where the guard's guarantee is destroyed *inside the
    region the exclusion covers*, which is the fifth sweep's whole-node bug on the
    **temporal** axis instead of the branch axis; the local-boolean guard (10),
    agreed in review five waves ago and never written down; and the two
    `keySet()` residue shapes (11).
  - **The real-bugs corpus covered 4 of the 8 rules, and the gap was the
    riskiest one.** Measured: `map-get-deref` 9, `optional-get` 6,
    `loop-lte-length` 4, `static-dateformat` 1, and **nothing** for
    `modify-during-iteration` — the rule carrying eight exclusion clauses over a
    seven-branch receiver enumeration and the file's only nested re-inclusion, and the rule whose exclusion swallowed a real
    `ConcurrentModificationException` in wave 4. Its real bugs lived only in
    `hits/ModifyDuringIteration.java`, written by the rule's own author, which
    is exactly the artefact the corpus exists to compensate for.
    `hits/IterationBugs.java` adds six reviewer-written CMEs — a `switch` under
    an `if`, a `switch` in an inner loop, a `switch` in a `try`, a braced `case`
    block, two statements between removal and `break`, a removal in a nested
    `if`. The integration test now **states** which rules the corpus covers and
    which it does not: the three it does not (`empty-catch`,
    `printstacktrace-only`, `stream-not-closed`) are the three that carry no
    guard exclusions, so they are low-risk by construction — a decision now,
    not an accident.
  - **Three silent-failure modes are now caught by one enforced invariant.** A
    `pattern-either` branch with no positive term (`RuleParseError`), an
    unquoted `?` (`Invalid YAML file`) and `... <... e ...> ...` inside a block
    have each shipped through this file, and all three print a successful scan.
    They are one family: **fewer rules load than the file declares, exit 0.**
    The total-hits assertion that came with the real-bugs corpus is already the
    family-wide catch, but only
    while every rule has a hit fixture, which nothing stated. Two assertions
    close it: the set of rule ids the `hits/` fixtures exercise must equal the
    `- id:` entries parsed out of the YAML itself, and
    `semgrep --validate --quiet` must exit 0 with **both** streams empty — which
    also catches a clause-level compile failure that happens not to change any
    finding, the one thing no finding-count assertion can see. Measured against
    all three traps: exit 2, 5 and 2.
  - **Accepted false positive (9) was falsified by its own instance.** Its
    justification — an extra last-but-one-operand clause "removes one of two
    findings, the line still fires" — was measured on
    `flag && a.isPresent() && b.isPresent() && a.get().equals(b.get())`, a line
    carrying **two** `get()` calls. On the far commoner single-`get()` chain
    that clause silences the line outright. The row was rewritten here and then
    **deleted** in the next sweep, once re-measurement showed the conclusion was
    wrong too and the clause was applied.
- **A seventh review sweep applied the clause the sixth had deferred, and
  deleted the row that argued against it.** One item, and the smallest diff of
  any sweep, but it retires the longest-standing wrong answer in the pack.
  - **Both null-safety rules now honour an expression guard used in a CHAIN.**
    `flag && m.containsKey(k) && m.get(k).isEmpty()`,
    `flag && o.isPresent() && o.get().isEmpty()`, and the `||` duals, are
    ordinary correct Java — a feature flag or a cheap test short-circuiting in
    front of the guard — and all of them fired. Seven clauses, one per
    expression guard the two rules already excluded at two operands
    (`containsKey &&`, `get() != null &&`, `!containsKey ||`, `get() == null ||`,
    `isPresent() &&`, `!isPresent() ||`, `isEmpty() ||`). Measured: nine
    near-miss shapes silenced, hit fixtures unmoved at 69, and each of the seven
    ablates live on its own shape.
  - **`$X` matches the whole left-nested subtree, and that is the finding.** A
    Java conjunction nests to the left — `a && b && c` is `(a && b) && c` — so
    `$X && GUARD && DEREF` matches a chain of **any length** whose last-but-one
    operand is the guard. One clause per guard is therefore enough, and a second
    clause "for longer chains" would be inert; the four-operand shapes are
    closed by the same clause as the three-operand ones.
  - **Accepted false positive (9) is deleted rather than reworded.** It had
    carried two successive justifications, and both were reasoning about
    variables that do not control the outcome: the first measured "removes one
    of two findings" on a line that happened to carry two `get()` calls, the
    second generalised to "one clause leaves 4+ operand chains firing" when
    chain length is not the discriminator at all. A row recording a deferred
    decision on a false premise is worse than no row, because it reads as
    considered. The remaining rows renumber; the reasoning is now in the rule
    file, next to the clauses, where the next person will hit it.
  - **What still fires, and is pinned.** Six new corpus entries (`b15`–`b20`)
    cover the three ways a chain can look like a guard without being one: a
    chain guarding a **different** key or Optional; a **positive-first**
    disjunction, where the dereference runs precisely when the test was false;
    and a **negated** guard in a conjunction, where the value is proven absent
    at the point it is read. Also still firing, and no longer a table row: a
    chain whose guard is not the last-but-one operand because it guards two
    different things at once.
  - **A fourth member of the silent-rule-failure family, found by walking into
    it.** Semgrep's config loader decodes the rule file with the **locale**
    codec, not UTF-8. On a Windows cp1252 locale the bytes `0x81`, `0x8D`,
    `0x8F`, `0x90` and `0x9D` are undefined, and they are exactly the second
    UTF-8 byte of five characters (U+00C1, U+00CD, U+00CF, U+00D0, U+00DD), so
    **one** of them in a Portuguese comment takes the entire file down — while
    lowercase is always fine (`á` is `0xC3 0xA1`), which is why this pack's
    prose has always worked. It presents exactly like the other three: the scan
    returns `results: 0`, `paths.scanned: 0` and `errors: 0`, so a caller
    reading only the findings sees a clean scan. Both wave-6/7 guards caught it
    — the `paths.scanned` assertion and `semgrep --validate` — which is the
    first time that machinery has caught a trap nobody had seen before. The
    rule file now says so in its header, and the comment cannot spell the
    offending characters, because spelling them breaks the file that describes
    them. The rule is stated **narrowly and measured**: only two of the twelve
    accented capitals Portuguese uses are affected, and the first version of the
    warning — "no uppercase accented letters" — was wrong by excess, which is
    the same defect this sweep set out to fix. All six packs in
    `configs/semgrep/` are clean of those bytes today.


### Changed

- **BREAKING for `create_fix_pr` users: seven of the eight Java rules are now
  `WARNING`. Only `error-handling-empty-catch` remains `ERROR`.** Nothing
  disappears from a **scan** — `bug_hunt` does not filter by default — but
  `create_fix_pr` defaults `severity_min` to `high`, so **the Java pack now
  contributes almost nothing to the default fix-PR set.** If a Java fix PR
  comes back empty, this is why; ask for the findings explicitly with
  `severity_min: "medium"`.

  `create_fix_pr`'s own default was deliberately **not** changed. It affects
  all four language packs and is a separate decision.

  **The criterion, restated as a question about the output.** The tier rule
  used to be phrased about the *pattern* — "`ERROR` where the pattern is a bug
  regardless of intent" — which invites an argument about how good the pattern
  is, and this pack lost that argument four times. It is now:

  > **Is what the rule EMITS always a bug?**

  A rule whose correctness depends on having recognised a **guard** emits a
  false positive every single time it meets a guard shape nobody enumerated,
  and no exclusion list ever closes that, because the guard can always be one
  method away where a syntactic matcher cannot follow. The length of the
  exclusion list is evidence *for* the demotion, not against it.

  **`empty-catch` is the only rule that clears the bar**, for the one reason
  available: its escape hatch is not a guard at all but a *declaration of
  intent that the rule itself reads* — the Checkstyle / IntelliJ `ignore` /
  `ignored` / `expected` convention. What it emits after honouring that is an
  **unmarked** silent swallow, which is a bug whatever the author meant. One
  rule in eight is the honest result for a syntactic matcher with no dataflow,
  not a failure of the pack.

  Demoted this round, each with its reasoning written into the rule's own
  comment: `null-safety-map-get-deref` (26 guard exclusions, every one added
  because correct code was firing at `ERROR`),
  `edge-case-modify-during-iteration` (correctness depends entirely on having
  recognised the exit; two statements between removal and exit is enough to
  accuse correct code), `race-condition-static-dateformat` (a shared formatter
  behind `synchronized` access is correct, and proving *all* accesses are
  synchronized is whole-program analysis — the old "flagging it is defensible
  anyway" was a **product** argument, not the criterion), and
  `off-by-one-loop-lte-length`.

  **`loop-lte-length` was measured before it was demoted**, because if the
  obvious tightening had worked the rule could have stayed at `ERROR` honestly.
  Requiring the body to actually index the array — `<... $A[$I] ...>` — fixes
  the inclusive loop that never indexes `a`, does **not** fix the sentinel loop
  that fills a longer array (`b[i] = (i < a.length) ? a[i] : -1` is correct, and
  the already-guarded `a[i]` sits right there inside the ternary), and **loses**
  a real bug where the out-of-bounds index is passed to a helper
  (`sum += at(a, i)`). A false positive traded for a false negative without
  fixing the main case, so the patterns were left exactly as they were and only
  the tier moved. Recorded in the design of record §8 so it does not have to be
  rediscovered.

  `null-safety-optional-get-no-ispresent` was demoted a round earlier by
  precisely this argument; applying it to that rule and not to its twin
  `map-get-deref` was the inconsistency this closes.

  The tier of every Java rule is pinned by the integration test, and this change
  was made **RED first** — the four flips failed `EXPECTED_SEVERITY` before the
  YAML was touched, which is the whole point of having pinned it.

### Known gaps

- **No `Integer ==` rule.** Expressing it needs type inference Semgrep OSS does
  not have; the attempt fired on `v == null` and on primitive comparison.
- `stream-not-closed` only recognises `new FileInputStream(...)`, and only by
  that simple name: `FileOutputStream`, `FileReader`, `Socket` and every other
  closeable leak identically and are not covered, and neither is a
  fully-qualified `new java.io.FileInputStream(...)` (measured).
- `static-dateformat` only recognises `SimpleDateFormat`, so a shared
  `Calendar` or `Matcher` in a static field is not covered. It is no longer
  blind to the fully-qualified declaration; `stream-not-closed` is now the only
  rule in the pack with that gap.
- `map-get-deref` has no dataflow, so a key whose presence is established
  outside the guard and population shapes the rule enumerates is still flagged
  — a map filled in a static initialiser, or a total enum mapping declared as a
  `Map`. A map populated by `put` / `putIfAbsent` / `computeIfAbsent` above the
  read is no longer flagged.
- `map-get-deref` does not cover an `EnumMap`: the receiver enumeration is by
  declared type, and `EnumMap` is not in it.
- `modify-during-iteration` only matches the enhanced-for form.
- **Declared-type restriction costs recall.** `metavariable-type` matches the
  exact declared type with **no subtyping** — measured: `type: List` does not
  match a `CopyOnWriteArrayList`, which is exactly what makes the enumeration
  work. So `map-get-deref` is silent on a map behind a project interface or a
  generic type parameter (`<M extends Map<K,V>> ... m.get(k).f()`) — a raw
  `Map` still fires — and `modify-during-iteration` is silent on a `Deque`, a
  `Queue`, a `SortedSet` or a project collection type.
- **The empty-catch naming escape hatch cuts both ways.** A genuinely swallowed
  exception escapes the rule simply by being named `ignored`. And in the other
  direction — which matters more now that `empty-catch` is the only rule left at
  `ERROR` — the JUnit expected-exception idiom (call the code, `throw new
  AssertionError` if it did not throw, empty `catch`) fires at `ERROR` when the
  caught variable is named `e`, and is silent when it is named `expected`. The
  test idiom has to use the conventional name.
- `optional-get-no-ispresent` recognises exactly these guard shapes:
  `if (o.isPresent())` alone or as either operand of a **conjunction**, in the
  condition of an `if`, with the `get()` in the **then** branch, braced or
  braceless — the `else` arm still fires, and so does the ternary arm the
  condition rules out;
  `while (o.isPresent())`; the same test used as an **expression**
  (`return o.isPresent() && o.get().isEmpty();`) and the negative-first
  disjunctions `!o.isPresent() || …` and `o.isEmpty() || …`; each of those three
  again as a **chain**, with something short-circuiting in front of the guard
  (`flag && o.isPresent() && o.get()…`), for a conjunction of any length —
  a positive-first disjunction and a **negated** guard still fire, and are bugs;
  an early `return`/`throw`/`continue`/`break` under
  `!isPresent()` or `isEmpty()`, with or without one statement before the exit;
  the three ternary forms, with the `get()` in the guarded arm;
  `if (o.filter(p).isPresent())`; and an
  `Optional<T> o = Optional.of(…)` construction. It misses **any guard that
  reaches the check through another method** — the concrete case is a guard
  delegated to a helper, `if (!present(o)) { return d; }`, which needs
  interprocedural analysis Semgrep OSS does not do — and it deliberately does
  not treat `a.isPresent() || b` as a guard, since that proves
  nothing inside the body. Enumerated rather than summarised: the summary that
  stood here ("inline against the same `Optional` variable") was falsifiable,
  and was falsified by a compound condition, a multi-statement exit, a `while`
  and an `Optional.of`; the next version of it, which said "as either operand of
  a conjunction" without saying **where**, was falsified in turn by four
  expression-form guards; and the version after that, which said "exactly two
  operands is the shape excluded", was falsified by the chain clauses, since the
  count of operands was never what decided it. The rule is `WARNING` precisely
  because this class of miss has no end.

- **`base.yml`'s `wp-unescaped-output` had never worked**, found by the
  cross-pack test on its first run. `pattern: echo $_GET[$X]` does not parse as
  PHP (`Stdlib.Parsing.Parse_error`), so the WordPress XSS rule could not match
  anything — measured against a file containing a real `echo $_GET['name'];`:
  `results: 0`, `errors: 1`, exit 2. Quarantined for one wave, then **fixed**:
  see the entry below. The quarantine machinery in `semgrepPacks.test.ts` went
  with its last entry rather than staying behind as an empty map.

- **`base.yml` audited rule by rule, and three of the thirteen were doing
  nothing.** The pack `init_project` copies into a user's project as
  `.semgrep.yml` is the only rule file here that ships to somebody else's
  repository, and it had **no fixture coverage of any kind**. All thirteen rules
  were run against hand-written vulnerable code and against the correct code
  that most resembles it; the ten not listed here fire on the bug and are silent
  on the near-miss, measured.
  - `wp-unescaped-output` rewritten and fixture-backed. It now covers the whole
    echoed/printed expression, string interpolation, and a superglobal as a
    literal operand of a concatenation the statement emits — twelve shapes, one
    fixture each. It carries **no list of escaping functions**: what it emits is
    a superglobal in the raw on an output path, so anything that passes through
    a call — `esc_html()`, `wp_kses()`, `intval()`, or a house escaper nobody
    could have enumerated — stops matching without needing to be predicted.
    `pattern-inside: echo $A . $B;` is what keeps the concatenation branch off
    `echo esc_html($a . $_GET['b']);`, which is correct code the looser scope
    flags. The `metavariable-regex` on `$SUPER` is load-bearing rather than
    decorative: `$SUPER[...]` alone matches **any** array access, so without it
    every `echo $row['title'];` in every WordPress template becomes an
    ERROR-tier finding — pinned by near-miss fixtures that fire when it is
    deleted.

    It ships with **one known false positive**, pinned by line in
    `mcp/test/fixtures/base/known-false-positives/` rather than described in a
    comment: a superglobal concatenated *inside* an escaping call that is
    itself an operand of a concatenation the echo emits
    (`echo esc_html($a . $_GET['b']) . "x";`). It is not removable in Semgrep
    OSS syntax — `echo` is a CALL node in the PHP AST, so
    `pattern-not-inside: $F($C . $D)` excludes the echo along with the escaper
    and takes the rule to zero on everything. The alternative is to anchor the
    concatenation branch at a bounded set of depths, which trades this for a
    silent recall cliff at the first echo with one more term than somebody
    enumerated; in a security pack the missed XSS is the worse failure.
  - `js-eval-of-user-input` matched `new Function($X)`, the **one-argument**
    form. The canonical Function constructor names its parameters first and
    passes the body last, so the shape the rule was written for is the shape
    real code least often has: measured, 0 findings on
    `new Function('a', 'b', body)`. Now `new Function(...)`.
  - `js-document-write` saw `document.write` and not `document.writeln`.

  Neither of the last two would have been caught by `--validate`: both compiled
  perfectly and matched nothing. The assertion that catches the whole family is
  the one comparing the rule ids the fixtures exercise against the `- id:`
  entries parsed out of the YAML — a rule with no hit fixture behind it is a
  rule nobody has measured.

### Accepted limitations

Reproduced against the review fixtures that exist today, and kept rather than
fixed. **Every row states its DIRECTION**, because for six waves this table had
nine rows and all nine were false positives — the shape of the defect the last
two waves were about. Nobody was looking in the recall direction, so nothing was
ever written down there, and a wave could close a false positive, silently
delete recall, and still go green. Rows (9) and (10) are the first entries on
the other side; the real-bugs corpus in `hits/` is the machinery that keeps them
honest.

One row also **left** this table, which is the other half of the lesson. The
conjunction-chain false positive sat here for four waves under two successive
justifications, and both were reasoning about variables that did not control the
outcome; re-measured, it was not a limitation at all, just an unexamined
metavariable, and the clause that closes it costs nothing. A row here is an
assertion with no test behind it — unlike every other claim in this pack, which
has a fixture that fails when it goes stale — so a row that has never been
re-measured is exactly as trustworthy as the day someone wrote it, and no more.

- **(1)** *False positive.* `memory-leak-stream-not-closed` on
  `open(); try { … } finally { close(); }` — already the rule's stated
  limitation, and already why it is `WARNING`.
- **(2)** *False positive.* `race-condition-static-dateformat` on a `static final
  SimpleDateFormat` whose every access goes through a `synchronized` method —
  proving *all* accesses are synchronized is whole-program analysis, which
  Semgrep OSS does not do. This entry used to end "and a shared formatter
  serialises every caller anyway"; that is a **product** argument rather than
  the tier criterion, and it is why the rule sat at `ERROR` for four rounds
  while carrying a documented un-fixable false positive. The finding stays; the
  tier is now `WARNING`.
- **(3)** *False positive.* `off-by-one-loop-lte-length` on `i <= a.length` where the body guards
  with `i < a.length`, or never indexes `a` — the obvious tightening was tried
  and rejected (it trades this false positive for a false negative on a real
  bug without fixing the main case), so the patterns stayed and the tier moved.
- **(4)** *False positive.* `error-handling-printstacktrace-only` on `printStackTrace()` as the
  fallback when the logger itself threw — the one place the call is right;
  already `WARNING`; too narrow to encode.
- **(5)** *False positive.* `null-safety-map-get-deref`, `null-safety-optional-get-no-ispresent`
  and `edge-case-modify-during-iteration` where **two or more** statements sit
  between the guard (or the removal) and the exit —
  `if (!m.containsKey(k)) { log(); metric(); return ""; }`,
  `items.remove(s); log(s); n++; break;`. The deliberate price of bounding the
  exclusions instead of using a statement ellipsis: the ellipsis matches deep
  and would swallow `if (!m.containsKey(k)) { if (strict) { return ""; } }` and
  `items.remove(s); if (done) { break; }`, which are real bugs. A false
  negative that hides a bug is worse than this false positive.
- **(6)** *False positive.* The same three rules on any guard reached **through a helper
  method** — `if (!present(o)) { return d; }` — which needs interprocedural
  analysis Semgrep OSS does not do. Already the stated reason
  `optional-get-no-ispresent` is `WARNING`.
- **(7)** *False positive.* `null-safety-map-get-deref` on a key whose presence is established
  outside the shapes the rule enumerates: a map filled in a static initialiser,
  or a total enum mapping declared as a `Map`. Excluding "any map that ever
  received a `put`" anywhere in the file would erase the rule.
- **(8)** *False positive.* `null-safety-map-get-deref` and `null-safety-optional-get-no-ispresent`
  on a guard held in a **local boolean** —
  `boolean present = m.containsKey(k); if (!present) { return ""; }` — which is
  dataflow rather than syntax, and outside Semgrep OSS.
- **(9)** *False **negative** — the invalidated-guarantee class.* A guarantee
  the guard establishes and the code then **destroys**, inside the very region
  the exclusion covers. Five measured reproductions, every one a guaranteed
  throw, every one silent:

  ```java
  if (m.containsKey(k)) { m.remove(k); return m.get(k).trim(); }
  if (o.isPresent())    { o = Optional.empty(); return o.get(); }
  if (m.containsKey(k)) { m.clear(); … m.get(k).trim() … }
  m.put(k, "v"); m.remove(k); return m.get(k).trim();
  while (m.containsKey(k)) { m.remove(k); … m.get(k).trim() … }
  ```

  Same root cause as the `else`-arm bug of the fifth sweep — **`pattern-not-inside` excludes
  the whole node it matched** — but on the **temporal** axis instead of the
  branch axis. That sweep scoped every guard exclusion to the arm the guard proves,
  which fixed the branch axis; the sequence axis inside that arm was never
  examined, and the guard shapes are exactly the ones that carry it: an
  exclusion that covers a block covers every statement in the block, including
  the ones that undo the guarantee. Not fixable in Semgrep OSS — knowing that
  `m.remove(k)` invalidates `m.containsKey(k)` is dataflow — so this is a row
  and not a clause. The `keySet()` exclusion added in wave 7 inherits it
  unchanged: `for (String k : m.keySet()) { m.remove(k); m.get(k).trim(); }` is
  silent for the same reason.
- **(10)** *False **negative**.* `null-safety-map-get-deref` and
  `null-safety-optional-get-no-ispresent` where the deref is guarded by a
  **local boolean** holding the test —
  `boolean present = m.containsKey(k); if (present) { m.get(k).trim(); }`. The
  mirror of row (8), which records the same shape as an accepted false
  positive when the boolean guards an early exit. Both directions are the same
  missing capability (this is dataflow, not syntax), and having only the
  false-positive half written down for six waves is precisely the asymmetry
  this section's preamble is about. Agreed in review and undocumented until
  wave 7.
- **(11)** *False positive.* `null-safety-map-get-deref` on the two
  `keySet()`-adjacent iteration idioms the wave-7 exclusion does **not** reach,
  measured rather than assumed:
  `for (Map.Entry<K,V> e : m.entrySet()) { … m.get(e.getKey()) … }`, where the
  key is `e.getKey()` and not the loop variable, and the key set copied to a
  local first — `Set<String> keys = m.keySet(); for (String k : keys) { …
  m.get(k) … }` — where the loop header no longer mentions `keySet()` at all.
  Both are correct Java and both still fire. The exclusion unifies the map
  **and** the key on purpose; widening it to reach these two means giving up one
  of those unifications, and the two neighbouring real bugs that would then be
  swallowed are pinned as `b13` and `b14` in `hits/RealBugs.java`. Stated
  explicitly rather than left implied: of the five correct-code shapes the
  reviewer measured, the clause closes three — the plain `keySet()` loop, the
  `this.`-qualified one, and the one with the dereference nested inside an `if`
  — and these two remain.

## [1.8.0] - 2026-08-18

### Added

- **Go bug rules** — `configs/semgrep/bugfix-go.yml`, ten hand-authored Semgrep
  rules covering all six `bug_hunt` subcategories for Go: error discarded with
  `_`, return assigned to `_`, empty `if err != nil` branch, type assertion
  without `, ok`, `for i := 0; i <= len(xs)`, HTTP response body never closed,
  ticker never stopped, `Lock()` without `defer Unlock()`, discarded `append`
  result, and writing to a nil map. Go is where the registry pack leaves the
  biggest hole: `p/r2c-bug-scan` ships 5 Go rules and only 2 land in a bug
  class, both integer-overflow. Each rule ships a hit fixture and a near-miss
  that must stay silent, and the no-duplication test carries a positive
  control — a file that trips the pack's own Go rule — so "the pack found
  nothing" cannot be confused with "the pack never ran".

### Known gaps

- No goroutine-leak rule.
- **No loop-variable-capture rule, deliberately.** It was built and verified
  working, then excluded: Go 1.22 made loop variables per-iteration, and
  Semgrep cannot read `go.mod`, so on any module declaring `go 1.22` or later
  it would fire on correct code.
- `body-not-closed` only recognises `http.Get`; `http.Post` and `client.Do`
  leak identically and are not covered.
- `body-not-closed` and `ticker-not-stopped` match only the `:=` declaration
  form; `var resp *http.Response; resp, err = http.Get(url)` and
  `var t *time.Ticker; t = time.NewTicker(...)` are silent. `err-discarded`
  covers both forms, so this is an inconsistency rather than a stated
  policy.
- `lock-without-defer` accepts any `defer mu.Unlock()` in the block. It also
  does not cover `sync.RWMutex` read locks: the pattern matches the literal
  `Lock()`/`Unlock()` method names, not `RLock()`/`RUnlock()`, so a read-lock
  without `defer` — a common Go idiom — is entirely outside its reach. The
  write lock (`Lock()`/`Unlock()`) on a `*sync.RWMutex` is covered.
- `nil-map-write` only catches a locally `var`-declared map. A nil map
  arriving as a function parameter, a struct field, or a return value panics
  identically on write and is not covered — arguably the commoner
  real-world shape.
- `err-blank-assign` fires on deliberate discards, which is why it is `WARNING`.

## [1.7.2] - 2026-08-18

### Fixed

- **`wp_vuln_check` could run `wpscan --url undefined`.** When only
  `wp_install_path` was given, the target URL is read from WP-CLI — which can
  exit successfully and print nothing. Two call sites asserted the URL was
  present rather than checking it. It is now resolved once and, if still
  empty, the tool returns `scanner_failed` instead of invoking the scanner
  with a bad target.


### Changed

- **No non-null assertions anywhere.** 31 `!` assertions across 22 files
  removed; `mcp/src` and `mcp/test` are both at zero, as is explicit `any`, so
  a reappearance is a regression rather than the status quo. Most restated
  something the code had just established — a `push` before re-indexing the
  array's tail, a `filter` before a `map`, a length check before an index —
  and narrowing costs nothing there. Two others were hiding couplings worth
  making explicit: three tools asserted a shell whose non-null-ness is
  guaranteed by a check in a *different* file, and `perf_check` asserted a URL
  because its guard set a boolean that told the reader everything and the
  compiler nothing.
- `CLAUDE.md` now documents the TypeScript conventions this repo actually
  applies, including what `tsc` does **not** catch: interpolating a non-string
  into a template types as `string` at any strictness, so that class is still
  only caught by a human reading the diff.

## [1.7.1] - 2026-08-18

### Fixed

- **`register_custom_rules` never actually did anything.** It discovered a
  project's own Semgrep rules and persisted them, and its description promised
  "scan_sast / bug_hunt will then pick them up" — but nothing in the codebase
  ever read the key back. `scan_sast` passed `--config=auto` only; `bug_hunt`
  built its own pack list. The single other reference to the key anywhere was a
  test asserting it had been *written*, so the write half was covered and the
  read half had never been built, while the product surface claimed the feature
  worked. Both scanners now run the registered rules as extra `--config` packs,
  and a registered path that has since been deleted is skipped rather than
  aborting the whole scan — Semgrep fails the entire run on one bad `--config`,
  so a stale registration would otherwise break every later scan in the project.

- **Three tools were missing from the intent→tool maps** that tell an AI host
  which tool to reach for. `scan_skill` — which vets a third-party AI skill,
  MCP server or agent *before* installation and returns SAFE / REVIEW /
  CAUTION / DO_NOT_INSTALL — was absent from all nine host-config files, so no
  host had any way to learn it exists, despite it having its own command and
  skill. `check_toolchain` was missing from six, `scan_sast` from one. All 54
  registered tools are now present in all nine files, checked programmatically.

## [1.7.0] - 2026-08-18

### Added

- **Python bug rules** — `configs/semgrep/bugfix-py.yml`, ten hand-authored
  Semgrep rules covering all six `bug_hunt` subcategories for Python: bare
  `except:`, `except: pass`, unguarded `.objects.get()`, `None` dereference from
  `re.match()` and `dict.get()`, `range(len(x) + 1)`, files opened without a
  context manager, discarded `asyncio` coroutines, TOCTOU between
  `os.path.exists()` and `open()`, and Django queryset N+1. Each ships a hit
  fixture and a near-miss fixture that must stay silent, and each was measured
  against the 32 Python rules `p/r2c-bug-scan` already runs: none duplicates one
  of them.

### Changed

- `resolveBugfixRules()` returns every `configs/semgrep/bugfix-*.yml` instead of
  just the JS one, so a new language ships by adding its rule file — no wiring.

### Known gaps

Measured against the shipped rules, not inferred:

- No general "coroutine not awaited" rule: it is not expressible in Semgrep OSS.
  Only `asyncio.sleep/gather/wait/wait_for` are covered, so a forgotten `await`
  on a project's own `async def` is not caught.
- The Django N+1 rule matches `for` statements, not list comprehensions; is
  Django-specific (never SQLAlchemy or Peewee); and needs the queryset **inline
  in the `for` header** — `qs = Book.objects.all()` followed by `for book in qs:`
  is silent, which is arguably the commoner shape.
- `toctou-exists-open` keys only on `os.path.exists`. `os.path.isfile`,
  `os.path.isdir` and `pathlib.Path(p).exists()` are all silent.
- `none-deref-dict-get` excludes HTTP clients by receiver-name **substring**, so
  any receiver containing `requests`, `session`, `client`, `httpx`, `aiohttp` or
  `urllib` is skipped — `session_data`, `clients` and `urllib_cache` are false
  negatives too, not only a dict named exactly `client`.

## [1.6.0] - 2026-08-18

### Added

- **Fourteen locally-authored Semgrep rules that find JS/TS implementation
  bugs**, at `configs/semgrep/bugfix-js.yml` — the path
  `skills/guardian-bugfix` had been promising to a file that never existed.
  `bug_hunt` loads them **by default**, and unlike a registry pack a local file
  cannot 404.

  They cover **six** of the seven classes `/guardian-fix` names: swallowed error
  handling, off-by-one, null safety, memory leaks, race conditions and edge
  cases. **"Broken happy paths" is not covered** — it is a category of
  consequence, not a syntactic shape; `floating-mutation` covers its commonest
  concrete form and nothing covers the rest.

  Why they exist, measured rather than assumed: Semgrep retired `p/bugs`, its
  replacement covers those classes only for Python and Go, and a purpose-built
  TypeScript fixture returned **zero** findings with all seven registry packs
  enabled.

### Fixed

- **A malformed local rule file now degrades instead of taking the scan down**,
  in both shapes — broken YAML, and a single rule with a broken pattern, which
  is valid YAML and needs different handling so the other rules’ findings
  survive. Verified against the built server, not the source tree.
- A coverage warning no longer says a scanner "did not run" when the same
  result reports it ran.

### Known limitations

- **JS/TS only.** Python, Go, Java, C#, PHP, Ruby and Rust have no local rules
  yet; each gets its own design.
- **Semgrep OSS matches syntax, not dataflow.** These rules find the shapes bugs
  take. A null dereference two functions from its guard is invisible to them.
- **The heuristic tier produces false positives by construction.** That is why
  it is `WARNING` and why `severity_min` exists.
- **`floating-mutation` does not cover async function expressions** — a Semgrep
  engine limitation, not an oversight. Declarations, arrow functions, class
  methods and object methods are covered.
- **They do not replace the model-driven `/guardian-fix` path.** Rules catch
  shapes; reading the code catches reasons.

### Added

- **`bug_hunt` now runs fourteen local, hand-authored Semgrep rules for JS/TS by default** —
  `configs/semgrep/bugfix-js.yml`, alongside the always-on `p/r2c-bug-scan` +
  `p/security-audit`. They cover six bug classes: race conditions (`floating-mutation`, one
  rule), null/undefined safety (three), off-by-one (two), memory/resource leaks (three),
  swallowed error handling (three), and two edge cases (`reduce` without an initial value,
  `parseInt` without a radix). Unlike `include_language_packs`, a local file cannot 404, so
  this also keeps `bug_hunt` reporting something true even when the Semgrep registry is
  entirely unreachable. Every rule ships with a fixture pair under
  `mcp/test/fixtures/bugfix-js/` — one file that must fire, one near-miss that must not —
  asserted by exact rule-id set *and* raw finding count per file, so a rule that starts
  matching its own near-miss fails the suite instead of quietly widening. Design of record:
  `docs/superpowers/specs/2026-08-17-bugfix-rules-jsts-design.md`.
  - **Six named classes — "broken happy paths" isn't one of them as a pattern.** It's a
    category of consequence, not a syntactic shape; `floating-mutation` covers its commonest
    concrete form — an un-awaited mutating call inside an `async` function (declarations,
    arrow functions, class/object methods — NOT async function expressions, a Semgrep engine
    limitation) — and nothing covers the rest of it.
  - **Semgrep OSS matches syntax, not dataflow.** These rules find the shapes bugs take, not
    bugs proven by analysis — a null dereference two functions from its guard is invisible to
    them.
  - **The heuristic tier produces false positives by construction.** `floating-mutation`
    matches on the method name alone, so it can't tell a real mutation like `repo.save()`
    from an unrelated call that just shares the name, like `ctx.save()` (Canvas 2D's
    synchronous state-stack push) — both fire identically; that's why it's `WARNING`, not
    `ERROR`, and why `severity_min` exists.
  - **JS/TS only.** Python, Go, Java, C#, PHP, Ruby and Rust are unchanged: `p/r2c-bug-scan`
    still covers these classes only for Python and Go, and none of those languages has a
    local rule pack yet.
  - **Not a substitute for the model-driven `/guardian-fix` path.** These rules catch shapes;
    reading the code catches reasons.

### Fixed

- **A malformed `configs/semgrep/bugfix-js.yml` degrades instead of failing the whole
  `bug_hunt` scan.** Two distinct ways a hand-edited local rule file can break, both handled:
  invalid YAML is now recognised the same way a dead registry pack is and dropped from a
  retry; a single bad rule *pattern* inside an otherwise-valid file is dropped alone, with
  every other rule's findings still returned, instead of the whole run reporting `failed`
  with no reason and a misleading "install semgrep" warning. Verified live against the real
  built `dist/server.js`, not only unit-tested.
- **`skills/guardian-bugfix/SKILL.md` and `bug_hunt`'s own `title`/`description` stated the
  JS/TS bug-class gap as a permanent fact.** Both now describe the local rules above instead
  of the gap they close.

## [1.5.0] - 2026-08-17

### Fixed

- **`bug_hunt` was failing outright: Semgrep retired the `p/bugs` pack.** A dead
  `--config` makes Semgrep exit 7 and scan *nothing* -- including with
  `p/security-audit`, which was still valid -- so the whole tool died. Replaced
  with `p/r2c-bug-scan`, and the failure mode underneath is fixed: a config that
  fails to download is detected from Semgrep's structured `errors[]`, the
  surviving packs are re-run, and the gap is reported as coverage. **A scan that
  did not run can no longer read as clean.**
- **`mapSubcategory`'s fallback was a no-op**, so findings rarely landed in a
  canonical bug class. Fixed and validated against real rule ids.
- **The `categories` input was dead code** -- declared, never read. It now filters.
- **`skills/guardian-bugfix` pointed the model at `configs/semgrep/bugfix-*.yml`**,
  which does not exist. Corrected to describe what is actually there.

### Added

- **`include_language_packs`** (default `false`) on `bug_hunt`: adds
  `p/javascript`, `p/typescript`, `p/python`, `p/java` or `p/golang` by detected
  stack. **Measured rather than assumed:** 401 rules across the five packs (327
  distinct), 100% `category: security`, and a purpose-built TypeScript fixture
  returns zero findings. They add per-language *security* coverage -- overlap
  with `p/security-audit` is 9% for JS/TS, 20% Python, 43% Java, 40% Go -- and
  **do not** address the bug classes. Off by default for that reason.
- **`CoverageState.partial_tools`**: the dashboard now distinguishes "ran with
  reduced coverage" from "did not run this scan", which it previously could not.

### Known gap

- **No live Semgrep registry pack covers JS/TS logic bugs** -- null-safety,
  off-by-one, race conditions, memory leaks, swallowed error handling.
  `p/r2c-bug-scan` covers them for Python and Go only. For JS/TS the
  model-driven `/guardian-fix` path is what finds these today.

## [1.4.0] - 2026-08-17

### Added

- **`dev-guardian status` and `dev-guardian dashboard` — two read-only views over a
  project's own scan history, for a developer at their own laptop.** `status` prints
  a one-screen terminal summary (risk score and band, open findings and CVEs by
  severity, both deltas, up to 3 finding hotspots, missing-scanner consequences,
  active suppressions); `dashboard` writes a self-contained `.guardian/dashboard.html`
  — no CDN, no font fetch, no network call of any kind — with the same data, filterable
  and sortable client-side, opened automatically only when stdout is a TTY (`--no-open`
  suppresses that, `--out <path>` relocates the file). Both are computed by a single
  query pass (`mcp/src/dashboard/snapshot.ts#buildSnapshot`) so the two views cannot
  disagree, and neither runs a scan, mutates the database, or opens a socket. New CLI
  subcommands `node cli/dev-guardian.mjs status [--project <path>]` and
  `dashboard [--project <path>] [--out <path>] [--no-open]` — no MCP connection
  needed, matching `scan`/`baseline update`'s existing shape. `/guardian-status` now
  shows this deterministic output and adds interpretation on top, instead of
  improvising the numbers itself.
  - **The page is a snapshot, not live.** It is accurate as of the moment it was
    generated and does not change when a later scan runs — regenerate it. This is the
    cost of shipping with no server, the trade that keeps the feature dependency-free
    and fully offline.
  - **The window is the latest scan plus two deltas — still no multi-week trend.**
    `/guardian-trend` continues to ask for chronic-finding history and a debt
    half-life nothing in this project computes; this feature does not change that.
  - **The risk score is the existing `risk_score` heuristic**, extracted into a pure
    function (`risk.ts`) with its wire output kept byte-for-byte identical (a
    characterisation test pins it) — a prioritisation aid, not a measurement, and
    unchanged by this work.
  - **Coverage is only as honest as `missing_tools`.** Both views refuse an all-clear
    verdict whenever a scanner the scan intended to run did not run, and name what the
    numbers therefore don't contain. What neither view — nor the scan that fed them —
    can detect is a scanner that ran and silently produced nothing (a broken rule pack,
    an unreadable path): that is indistinguishable from a genuinely clean result at
    this layer.
  - **Hotspots rank by finding count, not severity.** A file with 11 low-severity
    findings outranks one with 2 criticals; the severity breakdown sits alongside for
    context, but the ranking itself stays deliberately simple.
  - Both commands exit `0` whenever they render — including over a project full of
    criticals, or one that has never been scanned (they name the scan command to run
    instead of showing empty numbers) — because they report; `scan` is what gates. The
    only non-zero exit either produces is `3`, on a usage error.
- **`create_fix_pr` — applies fixes the scanners themselves already produced, proves
  them, and opens a pull request.** New tool, and the first code in this repository
  that writes through git (branch, commit, push) rather than only reading it. It takes
  `deps_update_plan`'s pinned upgrade commands and Semgrep `--autofix`, applies them
  inside an isolated git worktree branched from committed `HEAD` — the user's working
  tree is never read or required to be clean — and verifies the result twice before
  anything leaves the machine: a **scan differential** re-runs the originating scanner
  inside the worktree and requires both that every target finding is gone and that no
  new finding appeared, and a (lazy) **test differential** runs the project's own
  derived test command — never accepted as a parameter, the same reasoning that keeps
  `scan_dast` from accepting a start command from repository-controlled config — and
  only re-runs it against the base commit, to tell a pre-existing failure from a
  regression, when the post-fix run fails. Fixes are grouped one pull request per
  ecosystem or scanner (all npm bumps together, all Semgrep rewrites together), branch
  names are deterministic (`dev-guardian/fix-<ecosystem-or-scanner>-<hash>`) so a
  repeat run is recognisable, and a pull-request-existence check that cannot be
  resolved (a failed `gh` call, unparsable output) makes the tool **refuse**, never
  assume no PR exists. Transport is the local `gh` CLI, as `create_github_issues`
  already uses — no tokens, no REST, no Octokit. The worktree is removed on every path,
  including every failure path, verified by observing `git worktree list` afterwards
  rather than by trusting a `finally` block to have run; the local branch follows it
  unless a human may need to find it by hand — a created PR, a push that failed, or a
  `gh pr create` that failed after a successful push.
  - **`apply` defaults to `false`, and that is the whole safety story.** Everything
    expensive and everything verifiable still runs on every call — candidates are
    computed, the worktree is created, the fix is applied, both differentials execute —
    but a dry run **leaves nothing behind: not a branch, not a commit, not a
    worktree**. Only `apply: true` commits, pushes and opens the pull request. The dry
    run's own verification re-scan is excluded from the server's unscoped "latest scan"
    queries, so it can never become the project's latest scan: nothing a dry run does
    can change what `guardian://findings/open`, `risk_score` or any other tool reading
    those queries report.
  - **Only what a scanner already produces.** Semgrep rules with no `fix:` field, and
    findings from gitleaks, bandit, jscpd, the DAST passes and the .NET tools — none of
    which set `fix_available` — are out of reach. This tool is not a patch author
    (`suggest_fix` remains the way to gather context for a model- or human-written
    patch) and does not become one here.
  - **`deps_update_plan`'s ecosystem gaps are inherited: maven and gradle are
    unsupported.**
  - **Semgrep's autofix quality is Semgrep's.** The scan differential verifies the
    outcome — the target finding gone, nothing new introduced — it does not review the
    rewrite itself. A rule with a careless `fix:` produces a careless patch, and the
    differential will call it resolved.
  - **A second instance of the same rule in the same file is not seen as new.** The scan
    differential's two halves compare on different keys on purpose (an amendment to
    design §4.1/§10 made during implementation): the target finding by fingerprint,
    "no new finding" by `(rule_id, file_path)`. A fingerprint hashes the line and the
    snippet, so any fix that shifts a line gives every other finding in that file a
    fresh fingerprint — measured at one inserted line changing four other findings'
    fingerprints on a real repo — and comparing "no new finding" by fingerprint would
    therefore fail the differential on every multi-finding file and blame pre-existing,
    untouched findings for it. The accepted cost of the fix: a genuine second instance
    of the same rule newly appearing in a file that already had one does not register
    as new.
  - **The test differential is only as good as the project's tests.** A green suite
    with no coverage of the changed code proves very little, and the tool cannot tell
    the difference.
  - **`fix_applied` remains a dead column.** It is `NOT NULL DEFAULT 0` on `findings`,
    nothing has ever written `1` to it, and this feature adds no `UPDATE` and no new
    table — the pull request is the record.

## [1.3.0] — 2026-08-14

### Added

- **`map_attack_surface` — static route/env-var/port inventory across all 8 stacks.**
  New tool that runs a dedicated Semgrep rule pack (`configs/semgrep/routes.yml`) over
  the project to extract HTTP routes, referenced environment variables, declared ports
  and webhook endpoints, resolving Express-style router mount prefixes and WordPress
  REST namespaces to their effective path. Reports per-language `coverage`
  (`ok` / `no_rules` / ...) so an uncovered framework shows up as a gap rather than a
  silent zero. Persists one snapshot per run to a new `surface_snapshots` SQLite table,
  keyed by a tree hash so an unchanged working tree reuses the previous snapshot instead
  of re-scanning. The tool result itself returns a summary plus a 20-route sample and a
  `snapshot_id` — the full route list is deliberately kept out of the tool response (see
  the new resources below) so a project with hundreds of routes cannot exhaust the
  agent's context window on a single call.
  - **Validation status, per rule.** Every rule in `configs/semgrep/routes.yml` now
    matches real code in `mcp/test/fixtures/surface/apps/`, checked capture-by-capture
    against Semgrep **1.86.0** (the last version that still emits `extra.metavars`, so
    what a rule binds is directly observable) and re-run end to end through the tool on
    Semgrep **1.164.0** (which redacts them, exercising the byte-offset recovery). Both
    versions produce the same 81 matches — 64 routes — with no rule errors. (1.164.0 also
    emits one `warn`-level `PartialParsing` on `php-wordpress/rest-controller.php:20`,
    where its PHP parser rejects `const NAMESPACE`; 1.86.0 parses it. That is a target-file
    parse warning, not a rule error, it predates every change here, and both `wp-rest`
    matches in that file still fire.) Verified
    working: `express` + its `mount` and `import` rules, `nestjs` (5), `flask`, `fastapi`,
    `django`, `wp-rest` (literal *and* `self::NAMESPACE` namespaces), `laravel`,
    `go-nethttp`, `gin`, `rails` (bare and `to:` forms), `spring` (all 6, including
    `@RequestMapping`, in their single-argument form), `aspnet-minimal`, `aspnet`
    attribute routing (5), `actix` (5), and all 5 `env` rules. Four rule families were
    **broken** and are fixed below.
  - **What is still not covered.** The verb alternations absent from the fixture —
    `OPTIONS`, `HEAD`, `ALL`/`ANY`, and `PUT`/`PATCH` for some frameworks — are
    untested, being extra literals in an already-verified `metavariable-regex`. A
    parameterless decorator (`@Get()`, `[HttpGet]`) is deliberately not reported: there
    is no path to capture, and neither the NestJS `@Controller` prefix nor an ASP.NET
    `MapGroup` prefix is resolved, so those routes are reported at their own
    registration path. Go's `os.Getenv` is not collected — no `env` rule covers Go.
    The Docker fallback path of `map_attack_surface` is still only exercised by mocks.
    Two **named-argument** forms are measured as unmatched and pinned as fixture bait:
    Spring's `@GetMapping(value = "/x", produces = "…")` — common in real code, and not
    fixable by adding `, ...`, which Semgrep rejects as "Invalid pattern for Java" —
    and Rocket's `#[post("/x", data = "<t>")]` (see the actix entry below). Both are
    absent from the inventory rather than reported at a guessed path.
- **`map_attack_surface` imports OpenAPI 3.x and Swagger 2.0 documents and diffs them
  against the code.** Discovery walks the project for conventionally-named files
  (`openapi.*`, `swagger.*`, `api-docs.*`, or anything under an `openapi/` directory
  inside the project — never matched against the absolute filesystem path, so a
  checkout nested under an ancestor directory happening to be named `openapi` does not
  pull in unrelated files) or reads exactly the paths passed as `spec_paths`. Both JSON
  and YAML are accepted for either version; **Postman collections are not supported** —
  the parser only recognises an `openapi: 3.x` or `swagger: 2.0` document. Every
  imported route carries `provenance: 'spec'` alongside the code-extracted routes'
  `provenance: 'code'` (routes read back from a snapshot persisted before this feature
  default to `'code'`, so old data is never mistaken for spec data), and
  `auth_hint: 'none'` is now emitted for an operation or document declaring
  `security: []` — an explicit "this route is public" — never inferred from the field
  being absent, which stays `'unknown'`.
  - **The diff has two honesty rules, not one.** First: with no spec discovered, or every
    discovered spec failing to parse, `spec_diff` is `null` — never a diff in which
    every code route reads as undocumented, which is a different claim than "there is no
    spec to compare against." Second: a route whose full path could not be resolved (an
    unresolved router-mount prefix on the code side, a templated `servers[].url` /
    `basePath` on the spec side) is **never** reported as a shadow endpoint or as dead
    documentation — it lands in a fourth bucket, `unmatchable`, together with a reason,
    and is never surfaced as a finding. This costs real findings when an unresolved
    route happens to be the very shadow/dead one, so the counts of findings withheld for
    that reason (`code_only_withheld`, `spec_only_withheld`) are reported alongside the
    diff rather than the gap being silent.
  - `routes_total` and `coverage[]` stay code-only, unchanged by this feature: a spec
    importing 200 paths must not make `coverage` claim a `'spec'` language exists, and
    must not inflate the code-route count a consumer already relies on.
  - Discovery is capped at 20 candidate files and 5 MB per file, both reported
    (`truncated`, `oversized`) rather than silently applied, and an unresolved external
    `$ref` (a whole path item, or a parameter, pointing outside the document) is counted
    in `unresolved_refs` rather than the path item vanishing with no trace — which would
    read as "the spec never declared this," a false claim about a real route this module
    simply could not follow to its file.
  - New runtime dependency: [`yaml`](https://www.npmjs.com/package/yaml), used to parse
    YAML specs and to recover the source line each path is declared on (JSON specs
    always report `line: 0`, since `JSON.parse` carries no position information).
- **`guardian://surface/latest` and `guardian://surface/{id}` resources.** Serve the
  full persisted attack-surface snapshot (every route, env var, port, webhook and the
  coverage report) by snapshot id or the most recent one. Return `{ snapshot: null }`
  when nothing has been captured yet, consistent with the rest of the resource surface.
- **A multi-language fixture and an end-to-end rule-pack test.**
  `mcp/test/fixtures/surface/apps/` is a small twelve-directory application tree — one
  framework per directory — carrying the route shapes every rule targets plus realistic
  surrounding code that must *not* match: a Python module whose local helper is named
  `path`, a Ruby class calling `Rails.cache.delete 'orders/index'`, `cache.get(...)` in
  the Express app, `Route::middleware(...)`, `r.Use(...)`, `@app.on_event(...)`,
  `app.MapGroup(...)`. It also carries the cases that must survive *as* partial results:
  a computed Django path, a computed WordPress namespace next to a literal one, and a
  non-ASCII comment sitting before every match in two files so the byte-offset recovery
  is exercised rather than assumed. `mcp/test/e2e/rulePackFixture.test.ts` runs the real
  `map_attack_surface` handler over it and asserts the **complete** route set — all 64
  routes by framework, method, resolved path and `path_partial` — because a count
  assertion passes when one rule breaks and another over-matches. One expected set, not
  one per Semgrep version: that the answer no longer depends on whether match content was
  redacted is asserted rather than assumed. It skips (visibly, via `it.skipIf`) when
  Semgrep is absent, and copies the tree out of `test/` first, which Semgrep's default
  ignore list would otherwise skip entirely.
  - **A companion `openapi.yaml` exercises the spec-diff against the same real Semgrep
    run**, rather than against hand-written `RouteRecord`s. It documents three routes
    copied verbatim from the fixture's expected set (so `matched` is non-empty), omits
    the rest of the 51 resolvable code routes on purpose (asserted as the exact
    `code_only` set — shadow endpoints), and declares one path,
    `/deprecated/v0/orders`, that no code route implements (asserted as `spec_only` —
    dead documentation). The comparison is an exact sorted set on both buckets, the same
    style as the route-set assertion above and for the same reason: a count passes when
    one rule breaks and another over-matches by the same amount.
- **`scan_dast` — active DAST that probes a *running* application against the
  `map_attack_surface` route inventory.** New tool that sends real HTTP requests to an
  application the caller already has running — it never starts, builds or stops
  anything — and reports what is actually reachable, what is served without credentials,
  and what leaks. It **requires a prior `map_attack_surface` run**: with no persisted
  snapshot it refuses with `no_surface_snapshot` naming the tool to run first, and a
  target that answers nothing refuses with `target_not_found`; neither refusal persists a
  scan row, so an empty `dast` history entry can never be read by `diff_scans` /
  `risk_score` as "this scan found nothing." Findings land in the existing `findings`
  table (`scan_type: 'dast'`) with a fingerprint stable over `(check, method, path,
  file)` — deliberately excluding the HTTP status, so a fixed app flipping 500→200 on
  restart is not a "new" finding — so DAST findings dedupe, diff and baseline exactly
  like every other finding.
  - **Own engine, eight checks.** `reachability` (confirms the static spec diff's shadow
    endpoints / dead documentation against the live server, and reports an extractor
    coverage gap — never a project bug — when a documented route is live but no code
    route was ever found for it), `anonymous_exposure` (a route the inventory marked
    `auth_hint: 'required'` answering an anonymous request with `2xx` — the strongest
    finding the tool can produce; `high` rather than `critical` because that hint can be
    inherited from a document-level OpenAPI default rather than declared per-operation),
    `differential_authz` (with credentials supplied, a byte-identical response with and
    without them — equality only, never a similarity score, so response noise like
    timestamps or CSRF tokens can only cause a missed finding, never a fabricated one),
    `cors` (a reflected `Origin` **and** `Access-Control-Allow-Credentials: true`
    together — either alone is inert and not reported), `security_headers` (missing CSP /
    `X-Content-Type-Options` / `X-Frame-Options` / HSTS-on-HTTPS, one finding **per
    origin** rather than per route), `info_disclosure` (stack-trace signatures and
    versioned `Server` / `X-Powered-By` banners), `method_surface` (`OPTIONS`'s `Allow`
    header advertising a verb the static extractor never saw, with framework-default
    `HEAD`/`OPTIONS` carved out so it does not fire on nearly every `GET` route in
    existence), and `open_redirect` (a `3xx` whose `Location` leaves the target origin —
    free from `probe.ts` never following a redirect). Plus an opt-in `probe_rate_limit`
    burst (30 requests, synthetic un-ownable credentials, stops early on the first `429`)
    and an optional nuclei pass.
  - **The safety envelope is the design, not a feature of it.** Target classification is
    purely lexical (no DNS, so it cannot be rebound mid-scan): loopback (`localhost` /
    `127.0.0.0/8` / `::1`) probes directly; anything else — including a hostname that
    merely *resolves* to loopback — refuses with `target_not_authorized` unless the
    caller passes `authorized_target: true`, recorded in the scan for audit. Read-only by
    default (`GET`/`HEAD`/`OPTIONS`); `allow_write_methods` opens `POST`/`PUT`/`PATCH`/
    `DELETE`, always with an empty body, so the `400`/`422`-vs-`401`/`403` split answers
    the authorization question without writing. The one exception to read-only-by-default
    is the opt-in `probe_rate_limit` burst, which sends `POST` to exactly one route — the
    flag is its own authorization and opens nothing for any other check. Redirects are
    never followed (`redirect: 'manual'`). Bounds — concurrency 4, a 5s per-request timeout, a 750-request ceiling,
    a 10-minute wall-clock ceiling — are reported when they cut a run, never silently
    applied; a run the wall-clock ceiling cut records its unsent probes `cancelled`,
    distinct from `timeout`, because the target didn't fail to answer — this tool stopped
    asking.
  - **Credentials are opt-in, never persisted, always redacted.** `auth_header_env`
    (recommended — the *name* of an environment variable; the secret never enters the
    conversation or the MCP request log) or `auth_header` (the literal value, documented
    as landing in the transcript). Neither is written to SQLite or an evidence file, and
    both are redacted from every finding, evidence file and result field through a single
    redaction choke-point applied to the whole response, not a hand-picked set of fields.
    Naming a variable via `auth_header_env` keeps it out of nuclei specifically — nuclei is
    spawned with an allowlisted environment and `extendEnv: false` for exactly that reason
    — but not out of this server process, nor out of the other scanners (Semgrep, Trivy,
    gitleaks, git) the same session spawns with the operator's full environment by design.
    That is a deliberate, unchanged posture (those tools read `SEMGREP_*` / `DOCKER_CONFIG`
    / `SSH_AUTH_SOCK` and the like), not an oversight; the parameter description now says
    so directly.
  - **A deliberately-vulnerable fixture app** (`mcp/test/fixtures/dast-app/server.mjs`,
    plain `node:http`, no framework) exercises every check end to end: an auth-required
    route served anonymously, reflected-credentialed CORS, missing security headers, a
    stack-trace leak, an open redirect, and a route with no rate limit.
  - **Per-check status, not just findings.** Every check reports `ok` /
    `skipped_envelope` / `no_candidate` / `needs_credentials` / `scanner_missing` /
    `target_error`, so a check that never ran (wrong envelope, no credentials, nuclei
    absent, the wall-clock ceiling cut it) is visible as such rather than reading as a
    check that found nothing — the same `coverage: 'full' | 'partial' | 'none'`
    discipline every other scan tool in this server already carries.
  - **The known limits — read before trusting a clean result.**
    - **No injection testing in the own engine.** No SQLi or XSS probes are sent; real
      XSS needs a browser and blind SQLi needs timing or destructive probes, and a
      fabricated injection finding is worse than none. That class is delegated entirely
      to nuclei's `-dast` fuzzing mode, which the default envelope excludes — **a clean
      `scan_dast` result is not evidence of injection safety.**
    - **nuclei tests the origin, not this project's routes.** Most of nuclei's HTTP
      templates use `{{BaseURL}}` and append their own known paths; the route inventory
      only genuinely feeds nuclei once `-dast` fuzzing is turned on, and the default
      envelope excludes that mode. nuclei still brings real value (component CVEs,
      exposed panels, misconfigurations) — it is just not what confirms the project's own
      endpoints; the own engine is. The result labels which findings came from which so
      the two are never conflated.
    - **The rate-limit finding is named `no_rate_limit_observed`, never "rate limiting is
      missing."** A limiter whose threshold sits above the burst size (30) is
      indistinguishable from no limiter at all at this sample size, and the finding name
      says so on purpose — do not reword it into a stronger claim.
    - **Synthetic path parameters give parametric routes a best-effort reachability
      signal, never a definitive one.** `/users/{id}` is probed as `/users/1`; a `404`
      there is ambiguous between "no such route" and "no such record 1," so it is never
      reported as "unreachable" — the ambiguity is surfaced, not resolved.
    - **nuclei has no verified Windows package manager install.** scoop, choco and winget
      were all checked and none carry it, so `install_toolchain`'s catalogue has no win32
      entry for it — Windows users install manually from nuclei's GitHub releases page
      (macOS gets a `brew` formula; Linux gets a curl installer, also pointed at GitHub
      releases). Consistent with that gap, nuclei is `default: false`: it never installs
      silently, and a requested-but-absent nuclei is reported as `scanner_missing` in
      `tools_run`, never a silent skip.
  - Discoverable via the `map_attack_surface` → `scan_dast` two-step, now documented in
    `host-rules/AGENTS.md` and in both tools' own descriptions.
- **`validate_finding` — reachability qualification for findings, the follow-up to
  `map_attack_surface`.** New tool that answers, per finding, whether anything outside
  the process can reach the file it lives in: builds a file-level import graph from the
  same Semgrep rule pack `map_attack_surface` already runs, roots it at the
  route-declaring files in the latest surface snapshot, and returns one verdict per
  finding — `reachable` / `unreachable` / `unknown` — with concrete evidence (the
  nearest reaching route, its hop count, how many routes reach the file in total, and
  any live-confirmed anonymous exposure cross-referenced against a persisted
  `scan_dast` run) plus the coverage gaps behind it. **`unknown` is the default and
  every path must earn its way out of it** — absence of evidence is never
  `unreachable`. **Report only**: no auto-suppression, no severity mutation, no flag to
  enable either — closing a finding stays a human decision. Validates every open
  finding by default (batch is the point); pass `fingerprint` for one, and an unknown
  fingerprint is a refusal, never a silently empty batch — the same applies to a
  missing surface snapshot (`no_surface_snapshot`, naming `map_attack_surface`) and to
  a project with no open findings (its own `note`, never a bare empty array standing in
  for "nothing to worry about"). Verdicts persist to a new `finding_validations` table
  keyed by `(project_path, fingerprint, provider)`, stamped with the snapshot id and
  tree hash they were computed against; a `stale` flag is derived at read time by
  comparing that stored tree hash to the current working tree, so a verdict for code
  that has since moved is never served as current.
  - **`configs/semgrep/routes.yml` gains import rules for all eight stacks** (JS/TS,
    Python, Go, Rust, Ruby, Java, C#, PHP), and closes a real gap in the existing ESM
    rule: `guardian-import-esm` previously matched only a default import or
    `require(...)` and missed `import { foo } from "./bar"` — the dominant form in
    modern TypeScript — which was also silently weakening `map_attack_surface`'s own
    mount resolution.
  - **The negative verdict is the tool's strongest claim and its most dangerous, so
    `unreachable` is gated on six independent conditions, checked in order, ALL of
    which must hold, or the answer is `unknown` with the blocking reason named in
    `coverage_gaps`:** the import graph holds at least one edge at all (an empty graph
    is missing DATA, not missing reachability — a pre-existing snapshot backfills
    `imports: []`, and without this gate every file in it would read `unreachable` on
    zero evidence); the finding's file path and language are determinable; the
    snapshot's per-language coverage is `ok` or `no_matches` (never `no_rules` or
    `unreadable`, where the route list for that language is known to be incomplete);
    the language does not resolve code at runtime (see below); the import graph was
    not truncated at its edge cap; and **the finding's language contributed at least
    one resolved import edge whenever some of its imports failed to resolve** — the
    first gate's reasoning one language down, so a language whose resolver produces
    nothing can never have that emptiness spent as evidence (see *Fixed* below for the
    defect that earned this gate). None of this gates the *positive* direction — any
    discovered import path is reported as `reachable` regardless, down to a finding in
    a route file itself, which reads `reachable` at 0 hops with `high` confidence, the
    only case that earns it.
  - **Known limits — read before trusting a clean `unreachable`:**
    - **`unreachable` is never emitted for Ruby, Java, C#, or PHP.** All four resolve
      code at runtime — autoload convention, annotation-driven injection, a DI
      container, a service container — not by static import, so "nothing imports this
      file" is true of nearly every file in them and proves nothing. The positive
      direction is unaffected: a discovered import edge is still evidence in all eight
      stacks.
    - **Nothing here detects a dynamic import.** `import(expr)`, `require(variable)`,
      reflection, and plugin registries are invisible to any import graph, in every
      stack — including the four above. **In a codebase using them, `unreachable` can
      be wrong, and this tool cannot tell you when.** This is not a gate — there is no
      signal to gate on — it is a limitation, stated in the tool description and here,
      in the same breath as the feature rather than as a weaker or separate account of
      it.
    - **Reachability is computed from HTTP route entry points only.** A file reached
      solely by a CLI entry point, a cron job, or a queue consumer reads as
      unreachable-by-route. That is what it is, and what the evidence says — it is
      **not** a claim that the code never runs.
    - **Granularity is the file, not the function.** A finding inside an uncalled
      helper in an otherwise-imported file reads `reachable`. Correct for what an
      import graph knows; an over-report in the safe direction, not the dangerous one.
    - **The anonymous-exposure cross-reference is only as fresh as the last `scan_dast`
      run for the project**, and that age is reported alongside it — absent a DAST scan
      for the project, the clause is simply absent from the evidence, never assumed in
      either direction.
    - **The batch is whichever scan completed most recently, of any type — not new
      here, but newly relevant.** `validate_finding` reads open findings the same way
      `triage_findings` and `prioritize_findings` already do (`listOpen()`, which is
      not project- or scan-type-scoped): run it right after `scan_dast` and it
      validates the DAST findings, not your last SAST run. The summary now names that
      scan — `findings_from_scan` carries its `scan_id`, `scan_type`, `tree_hash` and
      whether that tree matches the surface snapshot's — so the confusion is
      detectable in the result instead of only documented here.
  - Discoverable via the `map_attack_surface` → `validate_finding` two-step, now
    documented in `host-rules/AGENTS.md` (and its paired host-context files) and in
    both tools' own descriptions.
- **`dev-guardian scan` / `dev-guardian baseline update` — headless CI entry point, no
  MCP host required.** New `cli/dev-guardian.mjs` commands run the exact scan pipeline
  the MCP tools run — `detect_stack` → `security_scan_full` → `license_compatibility` →
  `map_attack_surface` → `scan_dast` (only when `--base-url` is given) →
  `validate_finding` — in that fixed order, because `map_attack_surface` persists the
  route inventory the last two refuse to run without. There is no second implementation
  of any scan: `runScans.ts` calls the very tool handlers `server.ts` registers for an
  interactive session, against an ephemeral SQLite database (a fresh temp directory,
  discarded at exit) — the portable state is the baseline file, not the database. A step
  that refuses (a missing prerequisite, an uninstalled scanner) is recorded, not fatal:
  the rest of the pipeline still runs, and the gap feeds the coverage signal below.
  - **The baseline**, `.guardian/baseline.json`, is committed to the user's repository —
    reviewable in a pull request, no cache needed. `scan` only ever reads it; `baseline
    update` is the one command that writes it, and only on request. An **absent**
    baseline is not an **empty** one: on a repository's first run, `scan` says so, names
    `baseline update` as the fix, and reports every finding as new rather than quietly
    treating the current state as clean.
  - **The gate fails on regressions, never on historical debt.** A finding already in
    the baseline never blocks, however severe; a finding **absent** from it at or above
    `--fail-on` (default `high`) does. Four exit codes carry the verdict: `0` pass, `1`
    gate failed, `2` **incomplete scan** — an expected scanner did not run, reusing
    `computeCoverage`'s existing `full` / `partial` / `none` signal rather than
    re-deriving a second one that could disagree with what the tools themselves already
    report — `3` usage or configuration error. `2` exists because a missing scanner and a
    genuinely clean scan both say "zero new findings" unless something tells them apart,
    and a pipeline must be able to, whether it then treats `2` as a warning or a failure.
  - **Three report formats — human (default), JSON, SARIF** — SARIF being why this
    exists at all: GitHub, GitLab and Azure DevOps code-scanning render it **on the
    lines of the pull request diff**, not in a log nobody opens. SARIF's
    `invocation.executionSuccessful` is set to `false` whenever coverage isn't `full` —
    the two states (`partial`, `none`) where a "0 new findings" result is least
    trustworthy — so a consumer reading only the uploaded SARIF can already tell an
    incomplete run from a clean one, without cross-referencing the exit code. What SARIF
    still cannot say is **which** scanner was missing or why: it has no general-purpose
    home for that prose, so a dropped, unreadable baseline entry is the one exception
    (carried as a `toolExecutionNotifications` line), and everything else — the scanner
    names, the reasons — stays exit-code-and-human/JSON-only. Read the exit code (or
    `coverage` in `--format json`) before trusting an uploaded SARIF that shows nothing:
    a clean pass and an unrun scanner can produce the identical empty results list.
  - **`--start-command` starts the target application for the DAST pass — from argv
    only, never from a repository file.** `scan_dast`'s own MCP tool deliberately has no
    way to start an app, because that parameter could be filled by a model reading the
    very repository under scan, and an injected comment would have somewhere to point.
    That reasoning holds only because a *human* types a CLI flag — a config file inside
    the repository has no such property, so if `.guardian/ci.json` ever declares
    `start_command`, the CLI **refuses outright, regardless of what argv says**: a pull
    request from a fork editing that file must never buy code execution on the CI
    runner (the classic "pwn request"). No shell (`shell: false`, argv stays an array
    end to end); the whole process tree is torn down on every exit path — normal
    completion, a thrown scan, SIGINT, SIGTERM. `--start-command` requires `--base-url`:
    nothing on the command line says which port the app will bind, so the same URL
    serves as both the health-check target and the `scan_dast` origin once it is up.
  - **A CI run leaves `.guardian/` in the workspace.** `security_scan_full`,
    `map_attack_surface` and `scan_dast` write their raw scanner output under
    `.guardian/reports/` in the project being scanned, exactly as they do interactively
    — only the SQLite database is ephemeral. The MCP server gitignores `.guardian/`
    automatically every time it starts against a project — not `init_project`
    specifically, the bootstrap itself (`server.ts`'s own boot sequence) — so that
    never fires from the CLI, and a repository that only ever scans through CI does
    not get the entry for free. A later pipeline step asserting a clean working tree
    fails for a reason that looks like nothing. Add `.guardian/` to `.gitignore` by
    hand.
  - **Known limits.** Distribution is `git clone --depth 1` of this plugin repository
    against a pinned tag, not an `npx` one-liner — heavier, but there is no TypeScript
    build step: `mcp/dist/` ships committed. `mcp/node_modules` does **not** ship
    (gitignored, same as everywhere else in this repo) and is still required — the
    committed `dist/ci/*` and `dist/tools/mapAttackSurface.js` import `execa` and `yaml`
    at the top level, unbundled, so `scan`/`baseline update` fail on a bare clone until
    `npm ci` has run once — a publishable package is being investigated separately,
    gated on a real pass through the Claude Desktop plugin validator rather than
    promised ahead of one. Nor does a stock CI runner carry Semgrep, gitleaks or Trivy
    — `ubuntu-latest` ships none of them — so the pipeline must install them itself
    (the README's CI job does; the scanners are not part of this repository or the
    npm dependency tree). Skipping that leaves every step reporting a missing scanner:
    `coverage` never reaches `full`, exit `2` on every run, correctly, because nothing
    was actually scanned — not a defect in the gate, the absence of the gate's own
    inputs. The scan database is ephemeral by design, so CI carries no trend history
    of its own — the baseline is the only state meant to survive a run, deliberately.
    `scan_dast` in CI reaches only what the runner itself can reach; an application
    behind a private network is out of scope, same as it is interactively.

### Fixed

- **`validate_finding` fabricated `unreachable` for every Python, Go and Rust file.**
  `map_attack_surface` resolved import edges against the *absolute* paths Semgrep
  reports for the absolute target it always passes, while every candidate a resolver
  builds from an import specifier is project-relative (`app.helpers` can only ever name
  `app/helpers.py`). Only the JS/TS resolver survived, because it anchors on the
  importing file's own path; Python, Go and Rust resolved **zero** edges, and every
  finding in those three languages came back `unreachable` — "no route imports this
  file" — on a graph that had never held one of their edges. Every gate passed: the
  graph was non-empty (JS/TS resolved) and coverage read `ok` (route extraction was
  fine). Measured end to end on a four-language project where each helper is imported
  directly by a route in its own language: three `unreachable`, one `reachable`. Both
  sides are now relativized *before* resolution rather than after it, the in-repo
  fixture carries one genuinely resolvable intra-project import per language (there was
  none in Python, Go or Rust, so no test could see the defect), and the new sixth gate
  above blocks the negative verdict for any language that resolved nothing while some
  of its imports failed to resolve — turning a silent, confident falsehood into
  `unknown` with the reason named.
- **Go import resolution matched a file basename instead of the package directory.**
  `import "myapp/pkg/util"` names the *directory* `pkg/util`, and every `.go` file in
  it belongs to the imported package. Matching the extension-stripped file path instead
  resolved only the accidental `pkg/util/util.go` spelling — so an ordinary
  `pkg/util/service.go` read as imported by nothing — and, in the other direction,
  claimed an edge into `pkg/handler.go` for a specifier (`myapp/pkg/handler`) that does
  not import it. Resolution is now by package directory, and returns **every** file in
  it, so no file in a multi-file package is left without the inbound edge its package
  actually has.
- **An absolute POSIX path lost its leading `/` during import resolution.** The
  path-joining helper dropped empty segments, and an absolute path's leading slash *is*
  an empty first segment, so `/src/api` + `./helper.js` normalised to
  `src/api/helper.js` and matched no file. On Linux, macOS and every Docker-Semgrep run
  — where absolute POSIX paths are all Semgrep reports — the import graph came back
  entirely empty and every verdict was `unknown`. `map_attack_surface`'s own
  `resolveModuleFile`, which the helper mirrors, carried the same defect and silently
  degraded Node mount resolution on those hosts; both are fixed.
- **`validate_finding` read the newest surface snapshot in the database, from any
  project.** Everything else in the tool is keyed to the resolved `project_path` —
  routes and findings are relativized against it, verdicts are persisted under it, the
  DAST cross-reference filters by it — so a snapshot mapped for a *different* project
  produced a graph in a foreign key space where no root matched any node, and, because
  that graph is non-empty, `unreachable` for every finding rather than an error. The
  read is now project-scoped (`SurfaceRepo.getLatestForProject`); `getLatest()` remains
  for the callers whose contract really is "whatever this server last mapped" (the
  `guardian://surface/latest` resource and `scan_dast`).
- **`validate_finding`'s `summary.snapshot.routes_total` counted routes that were never
  roots.** Spec-provenance routes are deliberately excluded from the reachability roots
  (a spec route's `file` is the OpenAPI document, which no code import graph contains),
  but the summary counted them anyway — so a project whose routes came only from an
  imported spec read `routes_total: 40` beside a batch of `unreachable` verdicts
  computed from zero roots, and disagreed with `map_attack_surface`'s own code-only
  `routes_total`. It now counts the code routes actually used, alongside `root_files`
  (the deduplicated files the traversal starts from) and `spec_routes_excluded`.
- **A duplicate in `spec_paths` could hide an unreadable spec document.** `discoverSpecs`
  deduplicates the explicit paths and *then* applies the 20-file cap, while
  `map_attack_surface`'s own "which named paths were not read" accounting capped the raw
  list. With duplicates present the caller's window ended earlier than the one discovery
  used, and a genuinely missing path landing in the gap was reported by neither side: no
  `parse_error` row (outside the caller's window) and no truncation row (the deduplicated
  set never exceeded the cap). It vanished — the same "could not be read" reading as "there
  is no spec" conflation the rest of the feature exists to prevent. Both call sites now
  share one deduplicated list, which also stops a duplicated document from double-counting
  its routes in `spec_routes_total`.

- **The Rust route rules fabricated four routes for every real one.** The five per-verb
  actix rules were `#[get($PATH)]`, `#[post($PATH)]` and so on. A bare attribute is not a
  Rust item, and Semgrep degraded each of them to a pattern that matched *every node in
  the file* while binding `metavars: {}` — measured on 1.86.0, a three-route file produced
  95 matches, spans including `use` lines and function bodies, with all five rules
  reporting the same spans. So one `#[get("/x")]` yielded the correct GET plus four
  invented POST/PUT/PATCH/DELETE routes at the same path, and `map_attack_surface` feeds
  a DAST tool that would send a request to each. The fix is the trailing
  `fn $F(...) { ... }`: the pattern now includes the item the attribute is attached to, so
  it matches the seven real routes and nothing else. (The rules were briefly collapsed into
  a single `#[$METHOD($PATH, ...)]` rule, because Semgrep's Rust engine does bind the
  attribute name once the pattern is well-formed. They are five again — one per verb, each
  declaring `metadata.method` — because `focus-metavariable: $PATH` discards `$METHOD`; see
  the redaction entry below.) Verified: exactly seven matches for seven routes, each with
  the right verb and path, and the `#[allow(...)]` attribute stacked on two of them
  correctly ignored. It does **not** cover Rocket's multi-argument attributes:
  `#[post("/x", data = "<t>")]` and `#[get("/x", rank = 2)]` produce zero matches on
  both 1.164.0 and 1.86.0 despite the `, ...`, and so does an explicit
  `#[$METHOD($PATH, $EXTRA)]`. Only a bare `#[$METHOD(...)]` matches them, and it binds
  no `$PATH` — a route with no path is worse than a route we did not report. Pinned as
  fixture bait in `rust-actix/rocket.rs` so the limitation stays measured.
- **The five ASP.NET attribute-routing rules matched nothing at all.**
  `[HttpGet($PATH)]` parses as a C# collection expression, not an attribute, so every
  `[HttpGet("/orders")]` in a controller was invisible — a whole style of ASP.NET routing
  silently missing from the inventory while `coverage` reported `ok` for C# on the
  strength of the minimal-API rules alone. Fixed by extending each pattern to include the
  method the attribute decorates.
- **The five NestJS rules were rule *errors*, not merely unmatched.** `@Get($PATH)` is not
  a parseable TypeScript pattern ("Invalid pattern for TypeScript"), so every single run
  of `map_attack_surface` on any project emitted five rule-parse errors and reported zero
  NestJS routes. Same fix: the pattern now includes the decorated method. The decorator
  name cannot be a metavariable in TypeScript (`@$DEC($PATH)` does not parse either), so
  these stay one rule per verb.
- **The Django rule reported filesystem-path helpers as HTTP routes.** `path($PATH, ...)`
  keys on the callee *spelling*, and `path` is an ordinary function name. Measured against
  a module doing nothing worse than `def path(*parts): return os.path.join(*parts)`, the
  rule produced three routes, two of which (`etc`, `var`) passed the extractor's literal
  test and were therefore emitted as resolved URLs that exist nowhere. The rule now names
  the callee in full — `django.urls.path` / `django.urls.re_path` — so Semgrep resolves
  the import instead of the spelling. This is **not** a `$PATH` literal guard: a computed
  path (`path(settings.ADMIN_URL, ...)`) still matches and is still reported, flagged
  `path_partial`. The Ruby rule was checked for the same failure and does not have it:
  `Rails.cache.delete 'orders/index'` and `store.get 'orders/index'` produce no matches,
  because `$METHOD $PATH` does not match a call with an explicit receiver.
- **Express/Fastify mount resolution never worked on Windows.** Semgrep reports paths in
  the host's native separator and this tool always hands it an absolute target, so on
  Windows a match arrives as `C:\project\src\routes\users.js` while the import specifier
  is `./routes/users`. `resolveModuleFile` split on `/` only, so a Windows path was one
  segment, matched no known file, and every route in a mounted router silently degraded to
  `path_partial` — the tool looked healthy and quietly stopped resolving prefixes on a
  supported platform. Paths are now normalised before comparison, and the known file is
  still returned verbatim so it continues to match `RouteRecord.file`.
- **All thirteen route families are now read on every Semgrep version, logged in or not.**
  NestJS, ASP.NET attribute routing and actix are the families whose Semgrep pattern must
  match the attribute *plus the declaration it decorates* — the attribute alone does not
  parse, or matches every node in the file. The reported span therefore begins at whatever
  attribute comes first, and **four** successive attempts to read a route out of it each
  **invented** one: anchoring on the first argument list turned `#[allow(dead_code)]` into a
  route named `dead_code` and `[Produces("application/json")]` into `application/json`;
  anchoring on the route attribute by name turned a commented-out
  `// [HttpGet("/orders/legacy")]` into `/orders/legacy` while the live `/orders`
  disappeared. Both passed `isLiteralPath`, so each was emitted as a **resolved** path — a
  URL `scan_dast` would request — and both were silent, because reconstruction *succeeded*:
  `tools_run` reported `ok` with zero unrecoverable matches. The families were then refused
  outright, which was correct against those options but left 21 real routes out of the
  inventory whenever Semgrep redacted match content.
  - **The fix removes the question rather than answering it.** Deciding whether text is
    code, a comment or a string literal is **not local information** — it depends on
    everything from the start of the file, and the span starts in the middle. So no
    predicate over the span decides it: the three rules now carry
    `focus-metavariable: $PATH`, which makes Semgrep narrow its own **reported range** to
    the metavariable, using a real parser for the language. The byte offsets then point at
    the path literal itself, and recovery is "the span is the value" — no anchoring, no
    argument parsing, nothing searched for. A decoy cannot be picked out of a span it is not
    in, which is what makes the defect class structurally unreachable rather than merely
    unobserved.
  - **Measured on both Semgrep versions, against the adversarial fixtures.** 1.164.0
    (redacts match content) and 1.86.0 (still emits `extra.metavars`) produce the **same 64
    routes** over `mcp/test/fixtures/surface/apps/` — 81 matches each, zero rule errors on
    either (1.164.0 emits one pre-existing PHP parse warning; see above), zero unrecoverable on
    either — and the reported spans on 1.164.0 are byte-for-byte equal to 1.86.0's `$PATH`
    captures, quotes included. Every planted decoy is absent from both: `dead_code`,
    `application/json`, `204`, the commented-out `/rust/legacy`, `/aspnet/orders/legacy` and
    `legacy/:id`, and the attribute-shaped `FABRICATED` text inside method bodies. Coverage
    no longer depends on the Semgrep version, or on being logged in.
  - **A truncated range can no longer become a resolved path.** The focused branch trusts
    Semgrep's range by design — validating it would mean re-deriving what Semgrep already
    decided, the mistake of all four earlier rounds — so the safety argument has to be that
    every way a range can be wrong degrades to *incomplete*. One shape did not: a range
    ending **inside** the string literal left the opening quote unmatched, and `stripQuotes`
    in `extract.ts` removed it anyway, so `"/orders/secret` cut six bytes short read as the
    clean path `/orders/s` at full confidence — a URL that exists nowhere, published as
    verified, while the real one was absent. `stripQuotes` now strips only a **matched**
    pair, so the stray quote reaches `isLiteralPath`, which rejects it: the route survives
    as `path_partial` at `low` confidence with its raw text visible. Unreached by anything
    measured — 115 captures (81 fixture + 34 probe) were byte-exact against 1.86.0 — but
    truncation is not hypothetical: a TypeScript template literal was observed arriving two
    bytes short of its closing backtick. Pinned for all three quote styles.
  - **actix is five rules again, one per verb.** Focusing on `$PATH` discards every other
    capture, `$METHOD` included, so the verb has to come from `metadata.method` — the shape
    NestJS, ASP.NET attribute routing and Spring already use. Per-verb discrimination was
    re-measured across all three languages (six rules over three files, each matching only
    its own attribute), so the reason actix was once collapsed into a single
    `$METHOD`-binding rule no longer holds.
  - **The refusal machinery is deleted, including its fail-open default.**
    `UNRECOVERABLE_FRAMEWORKS` / `UNREADABLE_UNDER_REDACTION` listed the frameworks to
    refuse, so a fourth declaration-spanning family added without being listed would have
    silently fabricated again. There is no list any more, and therefore no wrong path for an
    unlisted framework to fall into. What replaces it is a lock-step assertion in
    `rulePack.test.ts`: a rule declaring `metadata.guardian_focus: path` without
    `focus-metavariable` (or the reverse) fails the suite, as does a route rule whose
    pattern spans a declaration without focusing. The flag is deliberately read from the
    rule pack rather than inferred from the framework name — the pack is the thing that
    knows whether it focused.
  - **Only these three are focused.** The other ten route families (express + its
    mount/import rules, flask, fastapi, django, laravel, gin, net/http, spring, wp-rest,
    aspnet-minimal) and all five `env` rules have spans that begin at the call or annotation
    that matched, so the capture sits at a known place. They are verified slot-for-slot
    against Semgrep 1.86.0 — every capture the extractor reads, identical — and several
    capture `$METHOD` as a metavariable that focusing would discard. Noted in the module
    docs as a possible future simplification, not a pending fix.
  - **`CoverageEntry.status: 'unreadable'` stays, and no longer describes a rule family.**
    `'ok' | 'no_matches' | 'no_rules' | 'unreadable'` with a companion `unreadable_matches`
    count, so a language whose routes were matched but not read can never collapse into
    `no_matches` — "this language exposes nothing", the exact inverse of the truth. It is
    now reachable only for a genuinely unreadable match: source rewritten or deleted
    mid-scan, not valid UTF-8, or offsets past end-of-file. The `tools_run` reason and the
    degraded `note` were rewritten to say that, instead of naming three families that are no
    longer affected.
  - The fixture keeps every adversarial case that caught this — a commented-out route
    attribute, anchor text inside a string, attribute-shaped text in a method body, an
    apostrophe in a comment, a Rust lifetime — for all three frameworks. The assertions that
    pinned their **absence** are inverted to pin the **real** route, and the
    `FABRICATION_DECOYS` check that has caught this class every time is unchanged: no decoy
    path may appear in the output, ever.
- **`recoverMetavars` could throw, contradicting its own contract.** `metadata.method` was
  interpolated raw into `new RegExp`, so a rule declaring `method: "a("` raised a
  `SyntaxError` out of a module documented as never throwing, and out of an unguarded call
  site in `mapAttackSurface.ts`. That path is gone with the anchoring, and a
  `metadata.method` that is not a plain word is rejected outright.
- **The rule-pack drift assertion was a substring sniff.** It tested for the literal text
  `{ ... }`, so the same rule written `{ $BODY }` — which Semgrep treats identically —
  widened a family past the guard while the test stayed green. It now parses each rule's
  patterns and detects a brace-delimited body structurally, and asserts that the pack's
  declaration-spanning route rules are exactly the ones carrying `focus-metavariable`.
- **A skipped end-to-end test reported as a passing one.** Both e2e files —
  `rulePackFixture.test.ts` and `evalVulnFixture.test.ts`, the only tests that run a real
  Semgrep — used `console.warn` plus a bare `return` when Semgrep was absent, which vitest
  counts as a pass. On Windows, Semgrep installs to
  `%APPDATA%\Roaming\Python\Python3xx\Scripts`, which is not on `PATH`, so both gates
  silently measured nothing and route-fabrication defects reached a green suite through
  them twice. They now use `it.skipIf`, so a skip reads as a skip, and
  `GUARDIAN_REQUIRE_SEMGREP=1` turns absence into a hard failure that distinguishes "not on
  PATH" from "fixture tree missing".
- **`map_attack_surface` extracted zero routes on every current Semgrep.** Semgrep changed
  behaviour between 1.95.0 and 1.120.1: unless the user has run `semgrep login` it redacts
  match content, so `extra.metavars` is absent entirely and `extra.lines` reads
  `"requires login"`. The extractor reads `extra.metavars.$PATH.abstract_content`, so the
  tool reported *no routes at all* while Semgrep itself reported matches — nothing looked
  broken, and the persisted snapshot said the application exposes nothing. Requiring an
  account is not an option for a tool whose stated position is 100% open-source and local.
  What redaction does not remove is the position: `start.offset` / `end.offset` survive, so
  a new pure module `mcp/src/surface/recoverMetavars.ts` slices the matched source out of
  the file and reconstructs the captures the rules would have bound, keyed off
  `guardian_kind` and `framework`. It synthesizes into the shape the extractor already
  reads, so `mcp/src/surface/extract.ts` is untouched. Measured end to end against Semgrep
  1.164.0 over `mcp/test/fixtures/surface/apps/`: **all 64** of the fixture's routes and all
  8 environment variables recovered, where the tool previously found none at all. (43 of the
  64 at first — the other 21 were the three decorated-declaration families, which were
  refused until `focus-metavariable` made their spans readable; see the entry above.)
  Verified capture-by-capture against Semgrep 1.86.0 — the last version that still emits
  metavariables, and which finds the same 64 — as ground truth.
  - Offsets are **byte** offsets, so the span is sliced from a `Buffer`; a source file with
    any non-ASCII character before the match desyncs a plain `String.prototype.slice` and
    yields a confidently wrong path. Source quoting is preserved verbatim, because that is
    exactly how `isLiteralPath` separates `'/items'` from `self::NAMESPACE` — and
    `register_rest_route(self::NAMESPACE, '/computed', …)`, the dominant idiom in real
    WordPress plugins, survives as a `path_partial` route rather than vanishing.
  - The module is pure and never throws: a file it cannot read, an offset past
    end-of-file, or a span with nothing to capture is counted `unrecoverable` and skipped.
    Reading the files stays in the tool, which is already the impure layer.
  - **Honest degradation.** If Semgrep reported matches and *not one* could be recovered,
    that is a broken toolchain, not a project without routes: the tool now persists
    nothing and says why — naming the redacting-Semgrep cause and that `map_attack_surface`
    does not require an account — instead of writing a zero-route snapshot that later reads
    as "this application exposes nothing". A partial recovery is persisted but reported, via
    a `semgrep-metavar-recovery` entry in `tools_run` carrying the counts, so it is visible
    rather than silent.
- **A path we could not resolve is never emitted as a resolved path.** Only one route rule
  in the pack constrained its path capture to a string literal; the other thirteen let a
  Semgrep metavariable that had bound a *code expression* through as a confident path —
  `self::NAMESPACE`, `$this->namespace`, `SETTINGS.users_path`, `Paths.ORDERS`, a bare
  `routeVar`. The first two are the dominant idioms in real WordPress plugins, not edge
  cases, and the next tool in this series will send HTTP requests to whatever path it is
  handed. A new `isLiteralPath` predicate in `mcp/src/surface/extract.ts` now gates every
  route, in the one place they all flow through, so it also covers rules users add via
  `register_custom_rules`. A capture that fails it keeps its route — a route we cannot
  name is still evidence of surface — but is flagged `path_partial: true`, keeps the raw
  text in `path_resolved`, and drops to `low` confidence. Both resolvers now honour that
  flag instead of clearing it when they prepend a mount prefix or a `/wp-json` namespace.
  A `metavariable-regex` guard in the rule pack would be the wrong second layer here: it
  *drops* the match, so the extractor never sees it, and a route registered with a computed
  path is still surface — dropping it would make `coverage` report `no_matches` for the
  language, which is the same "this application exposes nothing" falsehood in a different
  place. `$PATH` literal guards are therefore confined to the two rules whose pattern does
  not identify a route on its own (`guardian-route-express`, `guardian-route-rails`), where
  the literal disambiguates rather than discards, and the pack header now states that rule
  so it is not re-added by pattern-matching.
- **`params` is derived from the path alone.** It was gated on both the path and the
  namespace being literal, so `register_rest_route(self::NAMESPACE, '/items/(?P<id>\d+)')`
  reported `params: []` — an assertion that the route takes no parameters — when `id` is
  plainly knowable from the path. Where the route is served stays unknown
  (`path_partial: true`); the parameters no longer do.
- **The HTTP method was lost for five of thirteen route rules.** `aspnet-minimal`,
  `aspnet`, `spring`, `nestjs` and `actix` all reported `ANY`. Semgrep never reports which
  `pattern-either` alternative fired, so a rule whose verb is encoded in the alternative
  cannot recover it — those families are now one rule per verb, each declaring
  `metadata.method` (which the extractor already read as a fallback, until now dead code).
  `normalizeMethod` also understands ASP.NET's `MapGet` / `MapPost` builder names.
- **A cached snapshot no longer hides the failed run that produced it.** The cache path
  reported a hardcoded `tools_run: [{semgrep, skipped, cached}]`, so the one case where a
  failing run is still persisted (Semgrep exited non-zero but left parseable JSON) carried
  its warning for exactly one call. Every later call on the same tree hash presented a
  snapshot that was empty *because the scan died* as "this application exposes nothing" —
  the falsehood this tool exists to prevent. The persisted `tools_run` entries are now
  reported alongside the cache marker.
- **`auth_hint` is no longer advertised as a feature.** No rule sets `metadata.auth`, so
  the field is always `unknown`. The claim was removed from the tool description, and the
  reason is recorded at `normalizeAuth` so the constant reads as deliberate rather than
  broken. Detecting auth properly needs to see the handler, not the registration site;
  that is its own piece of work.
- Regression coverage for the Semgrep exit-code gate (`exitCode === 1` means *matches
  found*, i.e. success), which previously could be deleted with the suite staying green.
- The Docker fallback in `map_attack_surface` no longer re-implements
  `buildSemgrepDockerArgs`; the shared builder takes a `configs` option (default
  `['auto']`) so both callers inherit anything added to it later.
- **A spec's `trace` operation no longer suppresses shadow-endpoint findings.** Spec
  import mapped `trace` (an OpenAPI/Swagger operation key with no matching `HttpMethod`
  member) onto the `'ANY'` routing sentinel, which `specDiff.ts` treats as matching every
  method at a path. A document declaring only `trace: /foo` therefore made both
  `GET /foo` and `POST /foo` in the code read as documented — two genuine shadow
  endpoints silently suppressed. `trace` operations are now excluded from import
  entirely rather than folded into `'ANY'`; the alternative (adding a `TRACE` member to
  the persisted `HttpMethod` union) was rejected to avoid touching a type serialized into
  every stored snapshot for the sake of an operation this feature does not otherwise need
  to represent.
- **The installers advertised a scanner this plugin has never integrated, and omitted the
  one it can install.** `scripts/install/install-linux.sh` carried an OWASP ZAP banner
  (`docker pull zaproxy/zap-stable`) held over from before `scan_dast` existed — `ZAP`
  appears nowhere in `mcp/src`, is not in `TOOL_CATALOG`, and `install_toolchain` cannot
  install it, so the banner advertised a capability the plugin does not have. Meanwhile
  nuclei, which *is* in `TOOL_CATALOG` (`required_by: ['scan_dast']`, `default: false`)
  and is what `scan_dast`'s `use_nuclei` actually drives, appeared in neither installer.
  Both scripts now carry an honest nuclei banner instead: `install-linux.sh` states plainly
  that Linux has no automatic install path (`TOOL_CATALOG`'s linux bucket for nuclei is
  empty) and points at ProjectDiscovery's own install docs — `install_toolchain` is named
  only as confirming the same gap, not as a working alternative. `install-macos.sh` gained
  the equivalent banner naming the real `brew install nuclei` formula `TOOL_CATALOG` already
  verifies for that platform, where `install_toolchain` genuinely installs it. Neither
  banner reproduces `TOOL_CATALOG`'s linux `curl` fallback, which resolves to a GitHub
  releases HTML page rather than a raw install script.
- **`TOOL_CATALOG`'s linux install command for gitleaks and nuclei piped an HTML page into
  `sh`.** `curlInstaller`'s contract is a raw install script, but the `gitleaks` and
  `nuclei` linux entries pointed it at `.../releases/latest`, which redirects to the
  release's HTML tag page. `curl -f` only fails on HTTP error status, so the fetch
  "succeeded" and handed `sh` a full HTML document — a wall of shell syntax errors, not an
  install. Because gitleaks is `default: true`, this sat on a supported path: `check_toolchain`
  printed that broken one-liner as `install_command` for every caller on Linux regardless of
  whether they ever called `install_toolchain`, and an explicit
  `install_toolchain(tools: ["gitleaks"])` (or `["nuclei"]`) actually ran it. The default
  bootstrap flow (`install_toolchain` with no `tools` filter) was unaffected — on Linux it
  delegates to `install-linux.sh`, which resolves gitleaks's real download URL itself — so
  the breakage was reachable only through the per-tool path and through `check_toolchain`'s
  advisory output. Confirmed with `curl -sSIL` rather than assumed: gitleaks and nuclei both
  returned `Content-Type: text/html` on the final `200`, while trivy's and syft's linux
  entries (real `install.sh` scripts on `raw.githubusercontent.com`) returned `text/plain`,
  confirming they were never affected. Both broken entries are removed rather than replaced
  — neither tool ships a stable install script, and a hand-written per-arch downloader would
  be new, unverified machinery — so `pickInstallSpec` now returns `null` for gitleaks and
  nuclei on Linux and both degrade to `manual_steps` / no `install_command`, the same honest
  gap nuclei's win32 entry already relied on. `curlInstaller` now carries a doc comment
  stating the precondition the next caller must meet.

## [1.2.1] — 2026-08-10

### Fixed

- **Marketplace sync failed on Claude Desktop / claude.ai.** The top-level `bin/` directory is now
  `cli/`. Desktop does not clone the repository — it delegates validation to a remote Anthropic
  service, which rejected the plugin with `status=failed_content`: *"Plugin contains a top-level
  bin/ directory ('bin/dev-guardian.mjs'). claude.ai-hosted plugins may not ship bin/ executables
  because they are added to PATH on the CLI but are not shown on the admin approval surface. Declare
  executable entry points via hooks, commands, or mcpServers instead."* The UI surfaced this only as
  **"Marketplace sync failed. Check the repository URL"**, which is misleading — the URL was always
  correct. Installing through the Claude Code CLI was never affected, because it uses a local
  `git clone` and skips this validation, so a passing CLI install is not evidence that Desktop will
  accept the plugin.
- The CLI is now `node cli/dev-guardian.mjs` — same commands (`mcp-config`, `check`), same
  behaviour. References updated in `README.md` (EN/PT/ES), `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`,
  `.cursor/rules/` and every `host-rules/` template.

## [1.2.0] — 2026-07-15

### Added

- **`guardian-grill` — the understanding gate.** A new front-end skill (with
  `/guardian-grill` and the `/gg` alias) that grills *you* on the
  domain-significant decisions a diff/PR introduced before you merge — for the
  long autonomous loops where you no longer read every line. Complements the code
  gates (lint / Semgrep / tests / review): those check the code, this checks that
  a human still understands the branches and rules the AI wrote. Records its
  verdict to `.guardian/last-grill.md` so the status and report gates can show an
  Understanding-gate row. Adapts the `dev-grill` engine when installed, runs the
  loop inline otherwise.
- **`guardian-improve` — from measured debt to improvement specs.** A new skill
  (with `/guardian-improve` and the `/gi` alias) that converts the ROI-ranked
  hotspots, quality-rule violations, oversized files, duplication and coverage
  gaps from the quality gate into metric-anchored **improvement spec seeds**
  (problem → affected files → current metric → target metric → draft EARS
  criteria) ready to hand to `dev-spec-driven`. Closes the loop:
  measure → spec → fix → re-measure. Targets are derived per project from
  `.guardian/budgets.yml`, the stack, or the baseline — never invented.

### Changed

- **`guardian-status`** now shows an **Understanding gate** row from
  `.guardian/last-grill.md` (🟢 / 🟡 / 🔴, or ⚪ when not run for the current diff).
- **`guardian-report`** includes the latest `guardian-grill` verdict in its
  Quality section — a green gate means the metrics passed *and* a human understood
  the change.
- **`guardian-budget`** now also audits code-quality budgets (max file / function
  lines, cyclomatic complexity, duplication %, coverage floor) from
  `.guardian/budgets.yml` — the single source of truth shared by the quality gate
  and `guardian-improve`, proposed per stack.
- README and CLAUDE.md counts updated to **13 skills + 48 slash commands**.

## [1.1.4] — 2026-07-09

### Added

- **Scan coverage trust signal.** Every scan now reports a `coverage` value
  (`full` / `partial` / `none`) derived from which scanners actually ran, so a
  "0 findings" result that scanned nothing can never read as "all clear". At
  coverage `none` a loud warning states plainly that nothing was scanned;
  `audit_executive` rolls up the worst coverage across its sub-scans and
  surfaces each gap. (`tools/scanCoverage.ts`)
- **Semgrep Docker fallback for SAST.** When `semgrep` is not on PATH but a
  Docker daemon is reachable, `scan_sast` runs the official `semgrep/semgrep`
  image (bind-mounted via `--mount` so it tolerates Windows drive letters and
  spaces in the path). A failed container run is recorded as a real coverage
  gap, never a silent empty scan. (`runners/dockerScanner.ts`)
- **`npm audit` findings are now counted.** `deps_audit` parses
  `npm audit --json` (npm 6 and 7+) into Findings, complementing Trivy's CVE
  coverage with GitHub advisories. (`runners/scannerParsers/npmAudit.ts`)

### Fixed

- **No double-counting of the same dependency CVE.** When Trivy already reports
  a package by CVE, the overlapping `npm audit` finding for that package is
  dropped (Trivy is the canonical CVE source); npm findings for packages Trivy
  missed are kept. Stops inflated severity counts from flowing into the
  executive roll-up.
- **An `npm audit` error is no longer treated as a clean scan.** A missing
  lockfile makes npm exit non-zero with an `{ error }` object rather than a
  report — previously counted as a successful "0 findings". It is now recorded
  as a failed auditor and a coverage gap.
- **A missing native auditor is a coverage gap.** When `npm` / `pip-audit` is
  expected (the manifest exists) but absent, it is added to `missing_tools` so
  coverage reflects the gap instead of reporting `full`.

## [1.1.3] — 2026-06-10

### Fixed

- **MCP server now starts on a fresh install — no `npm install` required.** The
  server imported `@modelcontextprotocol/sdk`, `better-sqlite3`, `execa` and
  `zod` as runtime dependencies, but the plugin ships git-first with
  `mcp/node_modules` git-ignored, so the *installed* server crashed on its first
  import with `ERR_MODULE_NOT_FOUND` and none of the 50 MCP tools came up (the
  zero-dependency hooks were unaffected).
  - Replaced the native **`better-sqlite3`** engine with the built-in
    **`node:sqlite`** (`DatabaseSync`), behind a thin adapter in
    `mcp/src/storage/db.ts` (`prepare/run/get/all/exec/pragma` + a nesting-aware
    `transaction`) — no native module to compile or ship.
  - The build now **bundles** `dist/server.js` with esbuild
    (`mcp/scripts/bundle.mjs`), inlining the remaining pure-JS deps, so the
    server runs with **zero** runtime `node_modules`.
  - The server is launched with `--experimental-sqlite` and now requires Node
    **>=22.5**. No change to the MCP tool/resource surface (still 50 tools,
    16 resources); the full test suite now exercises the `node:sqlite` engine.

### Changed

- Removed `better-sqlite3` / `@types/better-sqlite3`; bumped `@types/node` to
  22.x and added `esbuild` as the bundler. Verified the bundled server boots
  from a `node_modules`-free sandbox and lists all 50 tools.

## [1.1.2] — 2026-06-10

### Fixed

- **MCP server now loads when the plugin is enabled.** The plugin manifest
  (`.claude-plugin/plugin.json`) launched the server via the invalid
  `${pluginDir}` placeholder, which Claude Code does not recognise — it rejected
  the config with `Invalid MCP server config for "dev-guardian": Missing
  environment variables: pluginDir` and the 51 MCP tools never came up. Switched
  to the documented **`${CLAUDE_PLUGIN_ROOT}`** placeholder (already used by the
  guardrail hooks). Same fix applied to the docs that quoted the old form
  (`README.md`, `mcp/README.md`, `mcp/src/hostsetup/mcpConfig.ts`). No change to
  the MCP tool/resource surface or plugin behaviour.

## [1.1.1] — 2026-06-07

### Changed

- **Dropped the GitHub Actions CI workflow** (`.github/workflows/ci.yml`).
  dev-guardian is distributed git-first and the maintainer avoids the recurring
  Actions cost, so the quality gates now run **locally**: `npm test`,
  `npm run build` (rebuild `mcp/dist/` before committing — no CI to catch
  drift), markdownlint, the guardrail hooks, and the `dev-guardian check` CLI.
  No npm publishing either (unchanged — never set up). No change to the plugin
  behaviour or the MCP tool/resource surface.

## [1.1.0] — 2026-06-06

### Added

- **Guardrail hooks** (`hooks/hooks.json` + `hooks/guardian-hook.mjs`),
  auto-loaded when the plugin is enabled — **dependency-free** (only `node:`
  builtins + pure compiled detectors; no native modules, so they run in the
  installed plugin where `mcp/node_modules` isn't shipped) and **fail-open**
  (any error → exit 0, never breaks the host):
  - **SessionStart** — briefs the agent with the project's security posture
    (branch, uncommitted changes, last-scan age, init state).
  - **PostToolUse (Write/Edit/MultiEdit/NotebookEdit)** — warns, with a
    **redacted** preview, when freshly written text contains a hard-coded
    secret. The authoritative full scan stays `scan_secrets` (gitleaks).
  - **PreToolUse (Bash)** — denies catastrophic commands by default
    (`rm -rf /`, `curl … | sh`, raw-disk `dd`/`mkfs`, fork bombs); warns on
    risky ones (force-push, hard reset, `sudo`, `chmod 777`).
  - Configurable via `.guardian/hooks.config.json` (opt-in secret-write
    blocking with `secrets.block`), `.guardian/hooks-allowlist.json` for false
    positives, and the `GUARDIAN_HOOKS=off` kill switch.
- `mcp/src/hooks/secretScan.ts` + `bashGuard.ts` — pure, unit-tested detection
  engines (31 new tests) shared by the hooks and the CLI.
- `dev-guardian check` CLI subcommand (`--file <path>` / `--bash "<command>"`,
  `--min`, `--json`) — run the same guardrail detectors from a terminal or CI;
  exit code 1 on a finding.

### Fixed

- The MCP server no longer reports a hard-coded `0.1.0`; it reads its version
  from `.claude-plugin/plugin.json` at startup (falling back to the MCP
  `package.json`), keeping its reported identity in lock-step with the release.
- `mcp/package.json` version aligned with the plugin release (was stale at
  `0.1.0`).

## [1.0.0] — 2026-06-05

First stable release. Everything below was already shipped in 0.x; 1.0.0 marks
the point where the surface is proven and held to semver.

### Added

- **CI pipeline** (GitHub Actions): markdownlint; build + test on Linux, macOS
  and Windows; a dist-sync gate (committed `mcp/dist` must equal a fresh build);
  coverage thresholds; an e2e job running real Semgrep against a vulnerable
  fixture; and a dogfood self-audit (Syft SBOM + gitleaks + Semgrep SARIF).
- **Stability snapshot** — the exact 50 tools + 16 resources are pinned in
  `toolSurface.test.ts`; accidental surface drift fails CI.
- `SECURITY.md` (responsible disclosure), `CONTRIBUTING.md`, this `CHANGELOG.md`.

### Changed

- **First stable release.** The MCP tool/resource surface and default
  behaviours are now covered by semver.

### Fixed

- README counts corrected (44 commands, 16 resources).

## [0.6.0] — 2026-06-05

### Added

- `mcp-config` CLI (`bin/dev-guardian.mjs`) — bootstrap dev-guardian into any AI
  host from a plain terminal, with the absolute server path filled in. Prints a
  paste-ready block or, with `--write`, merges it into the project.
- `mcp/src/hostsetup/setup.ts` — context-free host-setup core (`setupHost`,
  `previewMcpConfig`) shared by the CLI.

### Removed

- **BREAKING:** the `install_host_context` MCP tool. Use the `mcp-config` CLI
  instead. MCP tool count: 51 → 50.

## [0.5.1] — 2026-06-05

### Added

- In-repo AI host configs (dogfooding): `.mcp.json`, `.cursor/`, `.gemini/`,
  `.vscode/`, `.windsurf/`, `.github/copilot-instructions.md`, root `AGENTS.md`
  / `GEMINI.md`, and a `CLAUDE.md` contributor guide. Open the repo in any host
  and the MCP server + rules load out of the box (relative paths).

## [0.5.0] — 2026-06-05

### Added

- Branded Pro Digital Key HTML reports for `report_export` and
  `/guardian-report`: a self-contained shell with a dark/light toggle (system
  default, persisted), 100% offline, print-friendly, and trilingual chrome via
  a `lang` input.

### Changed

- **BREAKING:** `report_export` default format changed from `html` to
  `markdown`. `html` / `sarif` / `json` remain available explicitly.

## [0.4.0] — 2026-06-05

### Added

- Multi-host MCP installer: register the server (merging, never clobbering) plus
  the rules file across Cursor, Windsurf, GitHub Copilot, Cline, Codex CLI,
  Gemini CLI and Claude Desktop. Adds a `GEMINI.md` rules template.

## [0.3.0] — 2026-06-04

### Added

- `scan_skill` — vet a third-party skill / MCP server / agent before install
  (16 threat categories, YARA-style signatures, taint-light, OSV.dev lookups,
  0–100 risk score).

### Fixed

- Ship the compiled `mcp/dist/` so the plugin's MCP server starts without an
  install-time build.

## [0.2.1] — 2026-05-27

### Fixed

- MCP server startup.

## [0.2.0] — 2026-05-27

### Added

- First public release: open-source security / bugfix / quality / deps /
  observability / performance / compliance plugin with an MCP server, SQLite
  state, and trilingual (EN/PT/ES) triggers.

[1.1.0]: https://github.com/linofcp007/dev-guardian/releases/tag/v1.1.0
[1.0.0]: https://github.com/linofcp007/dev-guardian/releases/tag/v1.0.0
[0.6.0]: https://github.com/linofcp007/dev-guardian/releases/tag/v0.6.0
[0.5.1]: https://github.com/linofcp007/dev-guardian/releases/tag/v0.5.1
[0.5.0]: https://github.com/linofcp007/dev-guardian/releases/tag/v0.5.0
[0.4.0]: https://github.com/linofcp007/dev-guardian/releases/tag/v0.4.0
[0.3.0]: https://github.com/linofcp007/dev-guardian/releases/tag/v0.3.0
[0.2.1]: https://github.com/linofcp007/dev-guardian/releases/tag/v0.2.1
[0.2.0]: https://github.com/linofcp007/dev-guardian/releases/tag/v0.2.0
