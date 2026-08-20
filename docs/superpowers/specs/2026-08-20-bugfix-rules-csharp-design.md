# Local bug-finding Semgrep rules — C# — design of record

**Date:** 2026-08-20
**Status:** approved; **amended 2026-08-21** — `as-cast-deref` deleted and
ablation axis 3 wired up for the pack. See §4b and §8.
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

## 4. Two severity tiers, and one rule of eleven clears the bar

Unchanged: **`ERROR`** where what the rule *emits* is always a bug;
**`WARNING`** where it is usually a bug but has legitimate uses. The deciding
question is what the rule emits, not what class of defect it targets.

**1 ERROR of 11.** For scale: Java 0 of 8, JS/TS 1 of 13, Python + Go 2 of 19,
PHP 0 of 6.

(It was 1 of 12 when this document was approved. An earlier draft before that
said eleven and then enumerated twelve in this very section; the arithmetic was
mine. The pack is now genuinely eleven — see §4b.)

C# contains one defect — `throw ex;` inside a `catch` — whose *correct* form
(`throw;`) is a **different AST node**. That is the only shape in this pack
that clears §4 in an engine without dataflow: there is no guard to recognise,
because there is nothing to guard. Everywhere else, correctness depends on a
guard the rule cannot see, and the tier follows.

`empty-catch` shipped at `ERROR` beside it, ported from Java with Java's
argument. §4a is the round that measured that argument.

## 4a. The `empty-catch` premise, measured against `dotnet/runtime`

The premise, stated the way Java's design states it: *an empty catch that does
not declare intent is a bug whatever the author meant*, because the rule reads
the intent — the Checkstyle / IntelliJ `ignore` / `ignored` / `expected`
binding name — and what it emits afterwards is *unmarked*. It shipped
unmeasured, because axis 3 of the ablation harness was `N/A` for this pack:
there is no C# in this repository to scan. (That is no longer true — see §4b
and §9 — and the corpus below is the one axis 3 now uses.)

**Corpus.** `github.com/dotnet/runtime` at `6ecee4dd`, shallow sparse clone of
`src/libraries/*/src/**` — 11 802 `.cs` files of product source (no tests),
written and picked by nobody here. Semgrep 1.164.0 scanned **11 800**;
`paths.scanned > 0` was asserted before any count was read.

**Raw count: 402 findings in 233 files.**

**The spelling is the whole answer, and it is decisive.**

| spelling | count | share | has a name to declare intent in? |
| --- | ---: | ---: | --- |
| `catch (Type) { }` — no identifier | 219 | 54.5 % | **no** |
| `catch { }` — bare | 153 | 38.1 % | **no** |
| `catch (Type v) { }` | 28 | 7.0 % | yes |

**374 of 402 — 93 % — are written in a spelling with nothing to name.** This is
the structural hole ES2019 optional catch binding opened in JS/TS, except that
in C# both nameless spellings have existed since 1.0 and are the idiomatic
ones. Of the 28 that do bind a name, **not one** uses the exempt vocabulary:
`ex` ×15, `e` ×5, `exception` ×2, then singletons (`tie`, `jse`, `qex`, `hex`,
`se`, `exc`).

**The inverted-regex probe closes it from the other side: `ignore` / `ignored`
/ `expected` appear in ZERO empty catches across 11 800 files.** Java's
equivalent probe found 139. The convention is not weakly adopted in C#; it is
not adopted at all.

A zero is exactly the shape this repo has five recorded ways of producing by
accident, so **the probe carries a positive control**: run against a
three-method file holding `catch (FormatException ignored) { }`,
`catch (FormatException expected) { }` and `catch (FormatException e) { }`, it
reports `paths.scanned: 1` and fires on the first two and not the third. The
zero is a measurement, not a silent failure.

**And the compiler says why — the same independent oracle that found this
pack's `finally` hole.** Built with `dotnet build` on
`mcr.microsoft.com/dotnet/sdk:8.0`:

```csharp
try { int.Parse("x"); } catch (FormatException ignored) { }  // warning CS0168
try { int.Parse("x"); } catch (FormatException) { }          // clean
try { int.Parse("x"); } catch { }                            // clean
```

`CS0168: The variable 'ignored' is declared but never used`. **The escape hatch
this rule's own message prescribes is a spelling the C# compiler warns on**,
and both spellings it does not cover compile clean. That is not a cultural
preference to be argued with; it is the language telling its users to write the
form the rule cannot exempt. Recording that an oracle *refutes* a design
decision is worth as much as recording that one confirms it — §3 already says
so about `CA5394`.

**Intent is declared anyway, where Semgrep cannot see it.** 140 of the 402
carry an explanatory comment *inside* the empty catch — a comment-only block is
empty to the AST, which is why they fire — and another 46 carry one on the line
immediately before the `try`. A further 35 use a `when` exception filter, a
machine-readable narrowing the rule ignores.

**Read individually: about 45, spread across a systematic sample of all 402 and
a second pass over the 229 that carry no comment at all.** Roughly 42 are
deliberate. Comment-marked, in the corpus's own words: `// Swallow exceptions
on dispose` (`Microsoft.Extensions.Logging/src/LoggerFactory.cs:288`), `//
Obtaining this information is best effort and should not throw`
(`System.Diagnostics.FileVersionInfo/.../FileVersionInfo.Unix.cs:63`), `// the
process could be gone`
(`System.Diagnostics.Process/.../ProcessManager.SunOS.cs:188`), `// Ignore any
errors, encoding will remain null`
(`System.Configuration.ConfigurationManager/.../MgmtConfigurationRecord.cs:1041`),
`// Suppress the exception, treat the store as empty`
(`System.Security.Cryptography/.../OpenSslDirectoryBasedStoreProvider.cs:402`),
`// never fail...` (`System.Private.Xml/.../XmlSubtreeReader.cs:563`).
Deliberate by shape rather than by prose: a delegate fan-out that must not let
one subscriber kill the rest
(`System.Management/.../ManagementOperationWatcher.cs:429`), a cleanup
`File.Delete` before a rethrow
(`System.Private.CoreLib/.../SharedMemoryManager.Unix.cs:565`), a logging call
inside `catch (ObjectDisposedException)`
(`System.Net.Sockets/.../SocketAsyncEventArgs.cs:1045`), a method whose *name*
declares it (`LoadAssemblyFromStringNoThrow`,
`System.Runtime.Serialization.Formatters/.../FormatterServices.cs:305`), a
`catch (OutOfMemoryException) when (!throwOnFail)` whose filter is the
declaration (`System.Private.CoreLib/.../GenericCache.cs:210`), and a
documented API contract — `GetDirectoryContents` returns
`NotFoundDirectoryContents` and its XML doc says so
(`Microsoft.Extensions.FileProviders.Physical/src/PhysicalFileProvider.cs:326`).
The genuine swallows: `System.ComponentModel.TypeConverter/.../MemberDescriptor.cs:336`
(`catch (Exception) { }` leaves the attribute list half-filled),
`System.Management/.../ManagementOperationWatcher.cs:183` (a partial copy of a
sink table, silently), and `System.Net.Sockets/src/System/Net/Sockets/Socket.cs:1713`
(the endpoint is left stale).

**The verdict: `WARNING`.** C# is the *strongest* refutation in the series, not
a marginal one. Java's convention at least exists at 8 %; C#'s is at 0 %, on
11 800 files, for a reason the compiler will state on request. A declaration of
intent the rule cannot recognise is exactly what `WARNING` means, and here the
rule cannot recognise 93 % of the syntax it fires on.

The exemption clause stays in the rule. It is still the only way to silence one
case in code rather than with `// nosemgrep`, and its near-miss fixture
(`IgnoredNameWithFinally`) is what distinguishes the one-regex assembly from the
copied-regex one. It simply does not carry a tier. The message now says CS0168
out loud, so anyone taking the advice knows what they are trading.

**The tier is pinned, and the pin was demonstrated rather than assumed:** with
the YAML at `WARNING`, putting `'ERROR'` back into `EXPECTED_SEVERITY` fails
`reports each rule at its DESIGNED severity tier`, and restoring `'WARNING'`
passes. Recall is untouched — the patterns did not move, only the tier — so the
`hits/EmptyCatch.cs` count of 8 is unchanged.

## 4b. `as-cast-deref`, deleted against the same corpus — and the axis that would have caught it

Amendment, 2026-08-21. §8 below used to record ablation **axis 3** as
permanently `N/A` for this round, and §5 flagged `as-cast-deref` as the rule
where that would bite: its positive pattern is `$V.$M`, the broadest in the
pack. Both were right. A corpus was obtained and the rule did not survive it.

**Corpus.** The same one §4a used: `dotnet/runtime` at `6ecee4dd`, shallow
sparse clone of the `src/libraries` product source, **11 800 `.cs` files
scanned** (`paths.scanned` asserted before any count was read). The control
rules reproduce §4a exactly — `empty-catch` 402, `lock-on-shared-instance` 322
— so the measurement below is on the same footing.

**Raw count: 6490 findings in 818 files across 101 assemblies**, roughly one
per two files and sixteen times `empty-catch`. The count is not the argument.
Two measurements are.

### The rule's premise is not expressible in Semgrep's C# frontend

`o as T` and `(T)o` are **the same node**. Two probes, on one 8-method file:

- `pattern: var $V = $O as $T;` and `pattern: var $V = ($T)$O;` fire on
  **exactly the same seven sites**, line for line, whichever spelling the
  source uses — as do the bare expression forms `$O as $T` and `($T)$O`.
- `patterns:` combining `pattern: var $V = $O as $T;` with
  `pattern-not: var $V = ($T)$O;` returns **zero**. The negation annihilates
  every match, which is what happens when both describe one node.

There is no spelling that catches the `as` and lets the direct cast through.
And that distinction was the whole rule: its own message said so — "the `as`
returns null when the cast fails, that is the difference from a direct cast".
A direct cast throws `InvalidCastException` **at the cast site** and never
yields null, so on top of one the rule accuses a defect that cannot occur.

By textual attribution over the corpus — walk up from each finding to the
nearest declaration of the dereferenced receiver — **4385 of 6490 findings
(67.6 %) come from a direct cast** and only **1122 (17.3 %) from an `as`**
(429 from some other assignment form, 554 unresolved).

### The `as` share was not right either

**75 findings read by hand**, in four batches: 20 spread across the twenty
largest assemblies with no filter at all; then 15 and 20 more restricted to the
`as`-derived subset, one per assembly across 35 different assemblies; then 20
drawn from the findings most likely to be genuine (below). **Zero live bugs.**

The guards real C# uses are not the eleven in the exclusion list:

| shape | why the clause misses it | example |
| --- | --- | --- |
| `if (null != x) { … }` | reversed operands are a different node | `System.Data.OleDb/src/OleDbConnectionFactory.cs:123` |
| multi-statement then-block | `if ($V != null) { <… $V.$M …>; }` requires a block of **one** statement | `System.Private.Xml/.../XPathDocumentNavigator.cs:474` |
| `while (x != null) { … }` | no `while` clause | `System.Private.Xml.Linq/.../Extensions.cs:369` |
| `&&`/`\|\|` chain of 3+ terms | associates left, so `$V != null` is never the direct left operand | `System.IO.Pipes/src/System/IO/Pipes/PipeSecurity.cs:55` |
| `if (x is null \|\| …) { throw …; }` | no `is null` disjunction clause | `System.Speech/src/Result/SemanticValue.cs:41` |
| `Debug.Assert(x != null)` | assertion is not in the list | `System.Resources.Extensions/.../PreserializedResourceWriter.cs:247` |
| `ContractUtils.Requires(x != null, …)` | project helper, invisible | `System.Linq.Expressions/src/System/Dynamic/DynamicObject.cs:466` |
| a `[DoesNotReturn]` throw helper | `ThrowHelper.Throw…(…)` is a call, not a `throw` | `System.Private.CoreLib/src/System/Array.cs:215` |
| reassignment in the null branch | the variable is provably non-null by the deref | `System.DirectoryServices.AccountManagement/.../SAMQuerySet.cs:341` |

The multi-statement one is the largest, and it is the exact failure the design
warned about in §9: *"a near-miss derived from an exclusion can prove that
exclusion exists, but never that it is the right width, because it was chosen
to be caught by it."* Every guard in `misses/AsCast.cs` was written as
`if (s != null) { return s.Length; }` — a single statement — which is the only
width the clause has.

A deliberately generous filter — the receiver's name appears in **no** null
test, pattern test, assertion, `?.`, `??` or reassignment anywhere between its
declaration and 40 lines past the finding — leaves **70 of 6490, 1.1 %**.
Reading those 20 leaves five variables carrying the genuine shape
(`System.Configuration.ConfigurationManager/.../ConfigurationElementCollection.cs:292`,
`System.DirectoryServices.Protocols/.../LdapConnection.Windows.cs:43`,
`System.Private.Xml/.../XmlQueryTypeFactory.cs:1725`,
`System.Runtime.Caching/.../MemoryCache.cs:120`,
`Microsoft.CSharp/.../Tree/MethodInfo.cs:38`), every one of them latent and
dependent on an invariant the surrounding code holds, none a live defect.

### Verdict: deleted

`WARNING` is not a tier for a rule that has never been right; it is a quieter
way to keep being wrong, and it costs everyone who reads the output. The same
call, on the same reasoning, retired `catch-returns-null` from the JS/TS pack.

**Axes 0, 1 and 2 all passed, throughout.** Nine hits, fifteen near-misses, the
largest `misses/` file in the pack, all green, all written from the shape of
the pattern exactly as §9 prescribed. None of it could see either defect,
because all of it was written by the person who wrote the rule. That is the
case for axis 3 in one sentence.

Deleted with it: `hits/AsCast.cs`, `misses/AsCast.cs`, and the as-cast entry in
`hits/RealBugs.cs` (now 12 defects over 11 rules). A deletion note in
`configs/semgrep/bugfix-cs.yml` records both probes, so the rule cannot come
back without a way to tell an `as` from a cast.

## 5. The eleven rules

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
- **empty-catch** (**WARNING**, demoted in §4a) — Java's rule, and it needs
  **six** patterns, not one: three catch spellings × two try shapes. C# has two
  spellings Java does not (`catch (Exception) { }` with no identifier, and a
  bare `catch { }`), and a single-branch port loses both. The
  `ignore`/`ignored`/`expected` naming exemption applies to the two branches
  that bind a name, written as one `metavariable-regex` over a nested
  `pattern-either` rather than copied into each. `try { ... } catch (...) { }`
  **does not parse** — there is no "any catch" wildcard. The × 2 is the
  `finally` amendment below.
  **The two nameless spellings are also why this rule is not `ERROR`:** they
  are 93 % of what it emits on real .NET code and they have nowhere to declare
  intent, and the one spelling that does emits `CS0168`. §4a has the numbers.

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

### `null_safety` — 1 rule, WARNING

It was 2. **as-cast-deref** — a dereference of `x as T` without a null guard —
scored 2 of 2 hits and no false positives across 12 correct shapes at design
time, and its positive pattern `$V.$M` was flagged right here as the broadest
in the pack. It is **deleted**: §4b has the measurement. The remaining rule:

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
- **`null_safety` is down to one rule.** `as-cast-deref` was deleted against
  `dotnet/runtime` (§4b): Semgrep's C# frontend puts `o as T` and `(T)o` on the
  same node, so the rule's distinguishing premise is not expressible here at
  all. No narrowing recovers it — the two spellings cannot be told apart.
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
- **Ablation axis 3 is opt-in, not automatic.** It runs for this pack only when
  `GUARDIAN_CS_SRC` names a C# tree; unset, the report prints `N/A`. That is a
  verdict rather than a silent skip, but it is still a gap somebody has to
  close deliberately before a rule change here is measured against real code.

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

### The axis this round could not run, and now can — `GUARDIAN_CS_SRC`

*Amended 2026-08-21. What this section said, and what happened next, are both
kept: the prediction was right and the compensation was not enough.*

**What it said.** The ablation harness grades every clause on three axes.
**Axis 3 — "does removing this clause *lower* the finding count on code nobody
wrote as a fixture?" — was `N/A` for the whole C# round, and this section said
it would stay that way.** It needs a real-code corpus in a language the pack
matches, and this repo contains no C# at all: `mcp/src` is TypeScript, which is
why the JS/TS pack was for a long time the only one that ever had axis 3.

That was worth naming because axis 3 is not redundant with the other two. It is
the axis that caught `unchecked-match` going 0 → 13 false positives on this
repo's own TypeScript **while axes 1 and 2 both passed** — "live" and "keeps
true positives" are both true of a clause that only *adds* false positives.

**Where it said it would bite: `as-cast-deref` in Task 4.** Its positive
pattern is `$V.$M`, the broadest in the pack — every later use of `$V` in scope
is a candidate — and axis 3 is exactly the axis that would have shown how wide.
The compensation was a deliberately oversized `misses/` corpus there, written
**from the shape of the pattern** rather than from the exclusions already in
the rule: a near-miss derived from an exclusion can prove that exclusion
exists, but never that it is the right *width*, because it was chosen to be
caught by it.

**It bit exactly there, and the compensation did not hold.** §4b has the
measurement: 6490 findings on 11 800 files of `dotnet/runtime`, no true
positives in a 75-finding hand-read sample, and the rule deleted. The oversized
`misses/` file was fifteen near-misses and all fifteen passed — but every `if`
guard in it was written as a **single-statement** block, so it certified a
clause whose real width is one statement wide. Written from the shape of the
pattern, by the person who wrote the pattern, and still blind in the same
direction. That is the limit of a fixture corpus, stated as plainly as the
round can state it: *the compensation for axis 3 is not a substitute for axis
3.*

**Axis 3 now runs for this pack.** `mcp/test/ablate/packs.ts` reads the corpus
path from `GUARDIAN_CS_SRC`, on the same terms as the Rust pack's
`GUARDIAN_RUST_SRC`:

- **unset** → axis 3 reports `N/A` for the pack, printed, never silently
  skipped;
- **set to a path that does not exist** → it **throws**. A typo'd corpus that
  quietly becomes "not measured" is the failure mode this whole harness exists
  to prevent.

Any tree of real C# works. What produced §4a and §4b:
`git clone --filter=blob:none --no-checkout --depth 1` of `dotnet/runtime`,
then a non-cone sparse checkout of each library area's `src` subtree (tests
excluded). Keep it at a **short** path: on a long Windows path semgrep-core
scans zero files and says `Failed to obtain target files`, which points nowhere
near its cause.
