# Local bug-finding Semgrep rules — C# — design of record

**Date:** 2026-08-20
**Status:** approved
**Fifth in the per-language sequence**, after JS/TS (1.6.0), Python (1.7.0),
Go (1.8.0) and Java (merged, unreleased).

## 1. C# is emptier than Java, and this time the number is zero

Measured, with a positive control, because a zero that means "the pack never
ran" is worth nothing:

| Pack | On the 9 hit fixtures | Positive control |
| --- | --- | --- |
| `p/r2c-bug-scan` | `paths.scanned = 0` — **the pack ships no C# rules at all** | fires `useless-eqeq` on a Python control, so the pack is live |
| `p/csharp` | `scanned = 9`, **0 findings** | fires `csharp-sqli` on a concatenated-SQL control |
| `p/security-audit` | `scanned = 9`, **0 findings** | **none — see below** |

Java was "4 rules, none in a bug class". C# is **no rules**. Every rule below is
additive by measurement, not by assumption.

**One correction to an earlier draft, made during Task 5.** This document
claimed `p/security-audit` fires `csharp-sqli` on a concatenated-SQL control.
It does not — measured against eleven classic vulnerable C# shapes across two
batteries, it fires on **none** of them. So that pack has **no positive
control**, and the honest remaining claim is the weaker one: `paths.scanned > 0`
proves it has C# rules and ran them. Said plainly rather than fudged, because a
control that does not control is worse than an acknowledged gap.

## 2. The three rules that govern every rule

All inherited. The third earned its place in the Java round and earned it again
here — it killed two candidates before this document existed.

> **Every rule ships with two fixtures: one that makes it fire, and one that
> looks like it and must not.**

And:

> **Every rule must be shown not to duplicate what the registry pack already
> finds.**

And:

> **Write the correct code that most resembles the bug BEFORE writing the
> fixture that fires.**

## 3. A fourth governing rule, new for this round

> **Every fixture must compile.**

The Go round shipped `append-discarded`, whose hit fixture was not buildable Go
— `append(xs, 1)` as a statement is rejected by the compiler, so the rule's
true-positive set was empty in any project that builds. It survived two
releases. All 18 C# fixtures were built with
`docker run --rm mcr.microsoft.com/dotnet/sdk:8.0 dotnet build`: `0 Error(s)`.

For `rethrow-loses-stacktrace` the compiler is more than a gate — it is an
**independent oracle**. `dotnet build` emits `CA2200` at exactly the 8 sites the
rule fires on and nowhere else. The hit/miss split was not graded by its author.

## 4. Two severity tiers, and C# has the best ratio in the series

Unchanged: **`ERROR`** where what the rule *emits* is always a bug;
**`WARNING`** where it is usually a bug but has legitimate uses. The deciding
question is what the rule emits, not what class of defect it targets.

**2 ERROR of 12.** For scale: Java 1 of 8, JS/TS 1 of 13, Python + Go 2 of 19.

(An earlier draft of this document said eleven and then enumerated twelve in
this very section. The arithmetic was mine; the pack has twelve `- id:` entries
and no rule is missing.)

That is not generosity. C# contains one defect — `throw ex;` inside a `catch` —
whose *correct* form (`throw;`) is a **different AST node**. That is the only
shape that clears §4 in an engine without dataflow: there is no guard to
recognise, because there is nothing to guard. Everywhere else, correctness
depends on a guard the rule cannot see, and the tier follows.

## 5. The twelve rules

Ids follow `bugfix-cs-<class-token>-<name>`, because `mapSubcategory` classifies
by regex over the lowercased id. All 17 candidate ids were run through the
**built** classifier in `dist/tools/bugHunt.js`.

**Three words are hazardous in C# ids, not two.** Java's `unchecked` and
`concurren` still apply, and both are worse here: `unchecked` is a C# *keyword*,
and `concurren` matches `ConcurrentDictionary` and `ConcurrentBag`, which are
live type names. A third: `disposed` matches `memory_leak` before
`error_handling` ever sees `exception`.

### `error_handling` — 2 rules

- **rethrow-loses-stacktrace** (ERROR) — `throw ex;` inside `catch (E ex)`,
  which resets the stack trace to the rethrow point. Fires 9 of 9, including
  nested inside an `if`, inside a `for`, and under an exception filter; and in
  the first of two catch clauses while the second's correct bare `throw;` on the
  next line stays silent — the `$V` unification is load-bearing and was measured
  as such. Silent on all eight correct shapes.
  **The ninth site is a `finally` case and it was found by the oracle, not by
  the author** — see the amendment at the end of this section.
  **It duplicates the toolchain, not the registry**, and the design should say
  so plainly: `dotnet build` warns on this by default as `CA2200`. It earns its
  place because dev-guardian scans without building, and because a compiler
  warning that scrolls past is not a tracked, fingerprinted, baselined finding.
- **empty-catch** (ERROR) — Java's rule, and it needs **six** patterns, not
  one: three catch spellings × two try shapes. C# has two spellings Java does
  not (`catch (Exception) { }` with no identifier, and a bare `catch { }`), and
  a single-branch port loses both. The `ignore`/`ignored`/`expected` naming
  exemption applies to the two branches that bind a name, written as one
  `metavariable-regex` over a nested `pattern-either` rather than copied into
  each. `try { ... } catch (...) { }` **does not parse** — there is no "any
  catch" wildcard. The × 2 is the `finally` amendment below.

#### Amendment, measured after Task 1 shipped: the try shape is a DIMENSION

A try statement **with a finalizer is a different AST node**, and the patterns
are disjoint in both directions: `try { ... } catch (...) { ... }` matches only
the no-`finally` form, and the `finally` spelling matches only the other. Neither
contains the other, so the fix is to enumerate both, not to widen one. A
`try { ... } finally { ... }` with **no** catch still matches nothing — measured,
so an empty `finally { }` is not mistaken for an empty catch.

Both rules in §5's `error_handling` pair were blind to it. **CA2200 is what
found it**, which is the strongest argument in this document for §3's claim that
an independent oracle is worth more than a second fixture: the original fixtures
did not carry the shape, and a fixture that does not carry a shape can never
test it. The rule and the oracle now agree on all 9 sites and on 0 sites in
`misses/`.

This was **not** a defect of the C# port. It came from the Java pack, which is
where the port took its shape from. JS/TS and Python had already closed the same
hole — Python by exactly this cross product, {handler} × {try, try+finally,
try+else} — so the family was two packs, not five, and C# is now the third fixed.
`bugfix-java` is being corrected separately.

### `race_condition` — 4 rules, WARNING

C# supports this class better than any language in the series so far.

- **async-void** — `async void` outside an event handler. **The probe's reading
  of the exclusion was wrong, and Task 2 measured it:** a `pattern-not` naming
  `EventArgs` literally closes only the exactly-typed handler, and
  `metavariable-type: EventArgs` does not close it either — it is not
  subtype-aware here. Binding the args type as a metavariable `$T` is what
  works. Since `ElapsedEventArgs`, `PropertyChangedEventArgs` and every
  `EventHandler<T>` are subclasses, the literal version would have fired on
  nearly every real handler in a codebase. The cost of the working form —
  any `async void (object, X)` is exempt — is stated in the rule.
  Both bugs still fire, the second being `static async void`, since modifiers
  match by subset exactly as in Java.
- **blocking-on-task** — `.Result` / `.Wait()` on a `Task`, **only in its
  four-branch form**. This is the §2 rule working: untyped `$T.Result` fires on
  a POCO with a `bool Result` property *and* on `Regex.Match.Result(string)`,
  which is a real BCL method — so `$T.Result` matches a method call's receiver,
  not just a property. Untyped `$T.Wait()` fires on `SemaphoreSlim.Wait()` and
  `CountdownEvent.Wait()`, both correct blocking code.
  `metavariable-type: Task` kills all four false positives *and* kills
  `GetAsync().Result`, the commonest spelling; the recovery branch is
  `$F(...).Result` with `metavariable-regex: ".*Async"`.
- **static-random** — `static Random` shared across threads. 2 of 2, no false
  positives; `Random.Shared` and an instance field stay silent.
  **CA5394 is not an oracle for this rule** — measured: it fires on all four
  correct sites too, including `Random.Shared`, because it is about
  cryptographic predictability rather than a race. Recorded so nobody later
  reads agreement into a coincidence.
- **lock-on-shared-instance** — `lock (this)` and `lock ("literal")`. Low
  volume, 2 of 2, no false positives. **A second independent oracle:** `CA2002`
  fires at exactly the sites this rule does and nowhere in the near-misses.

### `off_by_one` — 2 rules, WARNING

- **loop-lte-length** and **loop-lte-count** — `<=` against `.Length` or
  `.Count`. Untyped, `.Length` fires on a domain object with an `int Length`
  field, which is the exact Java defect reproduced; `metavariable-type` with
  `"$T[]"`, `string` and `List` closes it. `metavariable-type` works in C#.

### `memory_leak` — 1 rule, WARNING

- **httpclient-per-call** — `new HttpClient(...)` outside a static field. 4 of
  4, silent on `static readonly HttpClient` and on `factory.CreateClient(...)`.
  Note the inversion in §7: disposing an `HttpClient` per call *is* the bug, so
  this rule *wants* to fire inside a `using`, and does.

### `null_safety` — 2 rules, WARNING, both needing Java's full exclusion battery

- **as-cast-deref** — a dereference of `x as T` without a null guard. 2 of 2
  hits, no false positives across 12 correct shapes; two of those are free,
  because `if (o is string s)` is a different node and `o as string ?? "d"` does
  not match the bare-`as` initialiser. But its positive pattern is `$V.$M`,
  meaning every later use of `$V` in scope is a candidate, and the guard list is
  one conjunction and one ternary short of Java's twenty-six.
- **ordefault-deref** — a dereference of `FirstOrDefault()` and friends. 4 of 4,
  no false positives across 12 correct shapes. Carries one unfixable class: on a
  sequence of *value* types `FirstOrDefault()` returns `default(T)`, never null,
  so `List<int>.FirstOrDefault().ToString()` is correct — and the member
  deny-list that closes that instance now silently misses
  `List<Cust>.FirstOrDefault().ToString()`, a real NRE. Generic-argument
  inference is not available.

### `edge_case` — 1 rule, WARNING

- **modify-during-iteration** — and it must be ported with Java's full
  `switch`-inside-`foreach` re-inclusion, because it reproduces Java's wave-4
  unsoundness verbatim: adding the two exit exclusions closes the two false
  positives *and swallows a real bug*, where `break` leaves a `switch` rather
  than the loop. **Drop the `Dictionary.Keys` branch** — removing from a
  `Dictionary` during enumeration has been documented safe since .NET Core 3.0,
  so that branch would fire on correct code.

### Three candidates killed at the probe, which is what §2's third rule is for

- **disposable-not-disposed.** Not expressible. Semgrep's C# frontend **erases
  the `using` modifier** from a using-declaration — confirmed by `dump-ast`
  (`DefStmt(VarDef …)`, `attrs = []`, no `WithUsingResource`), behaviourally
  (`pattern-not: using var $V = …` silences 100 % of matches), and by match
  span (the match starts at the identifier, so `pattern-not-regex` cannot see
  the keyword either). The Microsoft-recommended C# 8 idiom is byte-identical to
  a leak, and the only exclusion that names it deletes the rule.
- **event-subscribe-without-unsubscribe.** `$P.$E += $H;` fires on correct code
  that unsubscribes in `Dispose()`, and the pairing exclusion
  `class $C { ... $P.$E -= $H; ... }` **does not parse**.
- **`==` on strings.** Killed before a fixture was written: in C# `==` is
  *overloaded* on `string` and is the correct comparison. This was a Java reflex.

## 6. Where the rules live and how they load

`configs/semgrep/bugfix-cs.yml`. `resolveBugfixRules()` globs every
`configs/semgrep/bugfix-*.yml`, so **no wiring is required** — except the one
thing that is not automatic and has bitten every round since:
`mcp/test/unit/platform/configsDir.test.ts` pins the exact expected array. That
is a task step, not an accident.

## 7. Traps, measured — including a sixth silent-failure mode

The series had five ways Semgrep does nothing while printing a green summary.
C# adds a sixth, and it is the first that **`paths.scanned` does not catch**.

1. **`var` is the wildcard; `$T $V` is the narrow form.** `$T $V = new
   FileStream(...)` matches only explicitly-typed declarations and misses `var
   fs = ...` entirely. `foreach ($T $X in $C)` found **0 of 5** real bugs;
   `foreach (var $X in $C)` found all five. **Always write `var` in a C#
   pattern.** A rule ported from the Java pack by textual analogy finds nothing,
   with `paths.scanned` healthy, zero errors and every gate green. The only
   check that sees it is an ablation asserting the hits count is non-zero.
2. **`using var x = …` is indistinguishable from `var x = …`.** See §5. The
   failure reports `results: 0, errors: 0, paths.scanned: 2` — worse than the
   four Java traps, because `paths.scanned` is healthy.
3. **`metavariable-regex` is anchored at the start.** `regex: "Async$"` matched
   nothing on `GetDataAsync`, with no error and no warning. Use `".*Async"`.
   Java's `^(?!…$)` worked only because it was already start-anchored — any
   `$`-only-anchored regex is a dead clause that looks live.
4. **Assignment without declaration is invisible.** `$V = new FileStream(...)`
   matches nothing; `this._fs = new FileStream(…)` needs its own pattern.
5. **Patterns that do not parse** — and these are the *safe* failures, since
   they raise `RuleParseError` and exit 2: `try { ... } catch (...) { }`;
   `foreach (...) { ... }`; a deep-expression operator wrapped around a
   statement; `var $V = $O as $T; ... $V.$M` as one sequence. But **a bare
   `catch ($E $V) { ... }` with no `try` parses and matches nothing** — silent.
6. **Java's "positive term" trap reproduced.** A `pattern-either` holding only
   `metavariable-type` branches loads **zero rules for the whole file**. Repeat
   the positive pattern in every branch.

## 8. Limitations, stated plainly

- **Five of the seven classes, and `memory_leak` is thin.** One rule carries it,
  because the `IDisposable` rule is not expressible. Saying so is better than
  shipping a rule that flags `using var`.
- **Semgrep OSS matches syntax, not dataflow.** A null three methods away is
  invisible.
- **`ordefault-deref` cannot see generic arguments**, so a value-type sequence
  is either a false positive or, with the deny-list, a false negative. Both
  spellings are stated rather than implied.
- **`blocking-on-task` misses the two-step form** — `var t = GetAsync(); t.Result`.
  `metavariable-type: Task` does not resolve through `var` plus a call
  initialiser, though it does resolve through `var` plus a `new` (which is why
  Java's `var m = new HashMap<>()` worked).
- **`off_by_one` keeps Java's sentinel-array false positive** — a loop filling
  `new int[a.Length + 1]`. Java measured the obvious tightening and rejected it
  because it traded a false positive for a false negative; that measurement is
  carried forward rather than repeated.
- **`rethrow-loses-stacktrace` duplicates a compiler warning** (`CA2200`), not a
  registry rule. Stated in §5.
- **These rules complement the registry packs, they do not replace them** — and
  here that is nearly vacuous, since the registry has no C# bug rules at all.
- **They do not replace the model-driven `/guardian-fix` path.**

## 9. Testing

The harness from the Java round, unchanged in shape, plus what the audits added:
a fixture pair per rule under `mcp/test/fixtures/bugfix-cs/{hits,misses}/`,
copied to a temp directory before scanning; the exact id set **and** the raw
non-deduplicated count **and** `paths.scanned` asserted per file;
`EXPECTED_SEVERITY` pinning every tier exhaustively in both directions; a
no-duplication test with a positive control that is asserted to have run; ids
checked against the built `mapSubcategory`; `makeTempDir`/`cleanupTempDirs`.

Three additions this round, each of which cost a shipped defect elsewhere:

- **A real-bugs corpus** written by someone other than the rule author, with at
  least one entry per rule, so the ablation has its second axis.
- **The prescribed-fix check** — write the fix each rule's own message
  prescribes and confirm the rule goes silent. Three rules across four packs
  failed this.
- **`dotnet build` over every fixture**, per §3.

### The one axis this round cannot run, stated rather than left silent

The ablation harness grades every clause on three axes. **Axis 3 — "does
removing this clause *lower* the finding count on code nobody wrote as a
fixture?" — is `N/A` for the whole C# round, and will stay that way.** It needs
a real-code corpus in a language the pack matches, and this repo contains no C#
at all: `mcp/src` is TypeScript, which is why the JS/TS pack is the only one
that has ever had axis 3.

That is worth naming because axis 3 is not redundant with the other two. It is
the axis that caught `unchecked-match` going 0 → 13 false positives on this
repo's own TypeScript **while axes 1 and 2 both passed** — "live" and "keeps
true positives" are both true of a clause that only *adds* false positives.
For this round, nothing measures rule width against code that was not written
to be measured.

**Where it bites: `as-cast-deref` in Task 4.** Its positive pattern is `$V.$M`,
the broadest in the pack — every later use of `$V` in scope is a candidate —
and axis 3 is exactly the axis that would have shown how wide. The
compensation is a deliberately oversized `misses/` corpus there, written **from
the shape of the pattern** rather than from the exclusions already in the rule:
a near-miss derived from an exclusion can prove that exclusion exists, but
never that it is the right *width*, because it was chosen to be caught by it.
That distinction is what the JS round learned expensively, and it is the only
substitute available here.
