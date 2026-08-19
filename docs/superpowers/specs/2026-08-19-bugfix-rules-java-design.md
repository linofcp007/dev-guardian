# Local bug-finding Semgrep rules — Java — design of record

**Date:** 2026-08-19
**Status:** approved
**Fourth in the per-language sequence**, after JS/TS (1.6.0), Python (1.7.0) and
Go (1.8.0).

## 1. Java is the emptiest of them all

Measured, not assumed. `p/r2c-bug-scan` ships **4 Java rules**. Running every id
through the shipped `mapSubcategory`, **none** of them lands in a bug class:

| Rule in the pack | Classifies as |
| --- | --- |
| `eqeq` | (unclassified) |
| `no-string-eqeq` | (unclassified) |
| `hardcoded-conditional` | (unclassified) |
| `assignment-comparison` | (unclassified) |

All four are equality and comparison style. So every one of the six
subcategories is at **zero** — in the language whose most famous defect is the
`NullPointerException`, whose standard library ships a `SimpleDateFormat` that
is not thread-safe, and whose collections throw
`ConcurrentModificationException` by design.

The sequence so far, for scale: JS/TS zero of 3, Python 10 of 32, Go 2 of 5,
Java **0 of 4**.

The per-language registry packs do not help either: measured during the 1.5.0
work, they are 401 rules, **100 % `category: security`**, zero in any bug class.

## 2. The two rules that govern every rule

Both inherited, both unchanged:

> **Every rule ships with two fixtures: one that makes it fire, and one that
> looks like it and must not.**

And:

> **Every rule must be shown not to duplicate what the registry pack already
> finds.** Measured before this document was written: `p/r2c-bug-scan` produces
> **zero** findings on every Java hit fixture, while firing `eqeq` on a control
> file written to trip it — so the zero means the rules are additive, not that
> the pack never ran.

## 3. A third governing rule, new for this round

> **Write the correct code that most resembles the bug BEFORE writing the
> fixture that fires.**

This is the Go round's lesson made procedural. There, all ten rules were
measured before the spec and the final review still found **six ERROR findings
on correct Go**, because every fixture had been chosen by the same person who
wrote the rule. Choosing your own exam is not being examined.

It earned its place immediately — see §8, where it killed a rule before the
spec existed rather than after the branch was built.

## 4. Two severity tiers

**`ERROR`** where the pattern is a bug regardless of intent; **`WARNING`**
where it is usually a bug but has legitimate uses. `bug_hunt`'s `severity_min`
already filters on this.

### The criterion, generalised

The wording above is about the *pattern*, and that turned out to be the wrong
place to look — it invites an argument about how good the pattern is, which is
unfalsifiable and which this series lost four times. The criterion is now a
question about the **output**:

> **Is what the rule EMITS always a bug?**

Not "is the shape it looks for usually wrong". A rule whose correctness depends
on having recognised a **guard** emits a false positive every single time it
meets a guard shape nobody enumerated — and no exclusion list ever closes that,
because the guard can always be one method away, where a syntactic matcher
cannot follow. Such a rule is `WARNING` by construction, however long its
exclusion list gets. Indeed the length of the list is the evidence *for* the
demotion, not against it: **an exclusion list that keeps growing is a severity
signal, not a backlog.**

### One rule in eight clears the bar, and that is the honest result

Applied cold, the criterion leaves **`empty-catch` alone at `ERROR` and the
other seven at `WARNING`.** That ratio looks alarming until you notice what it
is measuring: Semgrep OSS matches syntax and has no dataflow, so *almost
nothing* clears a bar that says "always a bug". One in eight is what this
engine can honestly claim, not a failure of the pack.

`empty-catch` clears it for a reason worth stating precisely, because it is the
only reason available: **its escape hatch is not a guard.** It is a
*declaration of intent* that the rule itself reads — the Checkstyle / IntelliJ
convention of naming the variable `ignore`, `ignored` or `expected`. Having
honoured that, what the rule emits is an *unmarked* silent swallow, and that is
a bug whatever the author meant. Every other rule in the pack depends on having
seen a guard, and none of them can see all guards.

The four demotions this applies, each with its own reasoning in the rule's own
comment: `map-get-deref`, `modify-during-iteration`, `static-dateformat` and
`loop-lte-length`. `optional-get-no-ispresent` was demoted a round earlier by
the same argument, and applying that argument to one rule and not its twin was
the inconsistency this closes.

**`loop-lte-length` was measured before it was demoted**, because if the
obvious tightening worked the rule could have stayed at `ERROR` honestly. It
does not work — the measurement is in §8 — and the patterns were left alone.
Demoting without trying the fix first would have been giving up, not applying a
criterion.

### Pinned, and expensive to get wrong

The tier split is **pinned by a test**. It was decided here and asserted
nowhere until fix wave 1, which made it documented and unfalsifiable — exactly
the shape of every other defect in this series. `EXPECTED_SEVERITY` in the Java
integration test pins all eight rules, exhaustive in both directions, and this
round's change was made **RED first**: the four flips failed the test before the
YAML was touched, which is the entire point of having pinned it.

The tier is not cosmetic, and with seven of eight at `WARNING` the consequence
is now the headline rather than a footnote. The parser maps `ERROR → high` and
`WARNING → medium`. `bug_hunt`'s `severity_min` is optional, so **nothing
vanishes from a scan**. But `create_fix_pr` defaults `severity_min` to `high`,
so the Java pack now contributes **almost nothing to the default fix-PR set** —
one rule. A caller who wants Java bugs fixed has to ask for them:
`severity_min: "medium"`.

`create_fix_pr`'s default was deliberately **not** changed here. It affects all
four language packs and is a separate decision, queued for the round that
sweeps the shipped packs together.

## 5. The eight rules

Ids follow `bugfix-java-<class-token>-<name>`, because `mapSubcategory`
classifies by regex over the lowercased id rather than a lookup table. All eight
were run through the real classifier and land in their own class.

**Two words are forbidden in these ids, not one.** `unchecked` was already known
— the `error_handling` regex matches it. This round found a second: the
`race_condition` regex matches `concurren`, and it is tested *first* in the
if-chain, so `edge-case-concurrent-modification` classified as
`race_condition`. The rule is named `modify-during-iteration` instead. Caught by
running the classifier over the proposed ids before writing this document.

**Tiers at a glance**, after §4's criterion was applied cold to all eight:

| rule | tier | why |
| --- | --- | --- |
| `empty-catch` | **ERROR** | The only one that does not depend on recognising a guard. Its escape hatch is a *declaration of intent* the rule reads (`ignore`/`ignored`/`expected`); what it emits after that is an unmarked silent swallow, a bug whatever was meant. |
| `printstacktrace-only` | WARNING | In a throwaway `main`, printing and continuing is a legitimate choice. |
| `map-get-deref` | WARNING | Correctness depends on 26 guard exclusions. Each exists because correct code was firing; the list closes the shapes someone enumerated, never the next one. |
| `optional-get-no-ispresent` | WARNING | Same, demoted a round earlier. Applying the argument to one of these two and not the other was the inconsistency §4 closes. |
| `loop-lte-length` | WARNING | An inclusive loop that never indexes the array, or that fills a longer one, is correct. The tightening was tried and rejected — see §8. |
| `stream-not-closed` | WARNING | A stream closed in a `finally` is correct and this rule cannot see it. |
| `static-dateformat` | WARNING | A shared formatter behind `synchronized` access is correct, and proving *all* accesses are synchronized is whole-program analysis. |
| `modify-during-iteration` | WARNING | Correctness depends entirely on having recognised the exit that makes the removal safe; two statements between removal and exit is enough to accuse correct code. |

### `error_handling` — 2 rules, one ERROR and one WARNING

- **empty-catch** (**ERROR**, and the only one) — `try { … } catch (E e) { }`.
  The exception was caught and discarded with no log, no rethrow, no handling.
  **Except when the variable is named `ignore`, `ignored` or `expected`.**
  A deliberate, documented empty catch is a real idiom, but the comment that
  documents it is not in the AST — so a commented ignore and a silent swallow
  are byte-identical to Semgrep, and the comment can never be the escape hatch.
  The *name* can: those three are Checkstyle's and IntelliJ's conventions for
  exactly this, so honouring them gives users a tool-standard way to say
  "deliberate" without a suppression comment. Every other name still fires.
- **printstacktrace-only** (WARNING) — a catch whose only statement is
  `e.printStackTrace()`. It goes to stderr, not to the log, and execution
  continues as though nothing happened. `WARNING` because in a throwaway
  `main` it is a deliberate choice.

### `null_safety` — 2 rules

Both shipped untyped, and **neither was about the type in its name.** That is
the round's central finding and it is written up in §10.

- **map-get-deref** (**WARNING**, demoted from ERROR — see §4) — a method
  called directly on `map.get(k)`, which
  returns `null` for a missing key. The receiver is constrained by
  `metavariable-type` across a `pattern-either` enumerating `Map`, `HashMap`,
  `TreeMap`, `LinkedHashMap` and `ConcurrentHashMap`; **each branch repeats the
  positive pattern**, because a branch holding only a `metavariable-type` is
  rejected outright. Untyped, the rule fired on `List.get(0).trim()` and then
  advised `getOrDefault`, which `List` does not have.
  **No `getOrDefault` exclusion**, deliberately: Semgrep requires the literal
  method identifier, so `getOrDefault` never matches `$M.get($K)` in the first
  place. A clause excluding it was specified, shipped into Task 2, and measured
  inert — see §9.
  Each receiver is bound through a `metavariable-pattern` whose inner
  `pattern-either` accepts a bare name **or** `this.$F`, and only then typed:
  without that, `metavariable-type` cannot resolve a qualified field, so
  `cache.get(k).trim()` fired while `this.cache.get(k).trim()` was invisible on
  the same field in the same class.
  **Guard exclusions**, added in fix wave 4 after the rule shipped
  with none at all and fired at ERROR on `if (m.containsKey(k)) { …
  m.get(k).trim() … }` — the canonical Java guard — while advising
  `getOrDefault`. They are: the inline `containsKey` and `get() != null` tests
  **in the condition of an `if`**, each alone and as either operand of a
  **conjunction**, with the dereference in the *then* branch — two clauses per
  shape, one reaching a multi-statement or nested body and one reaching the
  braceless form, measured separately (12); `while (m.containsKey(k))` (1); the
  same two tests used as an **expression** rather than as a condition, plus
  their De Morgan duals `!containsKey || …` and `get() == null || …` (4); the
  four ternary polarities, quoted, with the dereference in the **guarded arm**
  (4); an early `return` / `throw` / `continue` under `!containsKey` or
  `get() == null`, each with and without one interposed
  statement (12); and population by `putIfAbsent`, `computeIfAbsent`, a plain
  `put`, or `if (!containsKey) { put(); }` (4).

  The **arm scoping** is wave 6, and it closed a false negative wave 4 opened.
  `pattern-not-inside: if ($M.containsKey($K)) { ... }` matches the whole
  **if-else statement**, and a quoted `"$M.containsKey($K) ? ... : ..."` matches
  the whole **conditional expression** — so `pattern-not-inside` excluded *both*
  arms, including the one the guard proves is a guaranteed
  `NullPointerException`. Measured on the reviewer's eight-bug file: 6 findings
  before wave 4, **1** after it, **8** now.

  `X || m.containsKey(k)` is still *not* excluded: `force` true with the key
  absent is an NPE. The negative-first disjunction is a different structure and
  is excluded; the two do not collapse into each other, and `b8` in
  `hits/RealBugs.java` measures that every run.
- **optional-get-no-ispresent** (**WARNING**, demoted from ERROR a round
  earlier than the rest — see §4) —
  `optional.get()` outside a guard. Throws `NoSuchElementException`; `orElse`
  does not. The receiver is constrained to `Optional`; untyped, `$O.get()`
  matched `AtomicInteger.get()`, `ThreadLocal.get()` and `Supplier.get()`.
  The exclusions cover these guard shapes, and only these: the inline
  `if (o.isPresent())` and the same test as either operand of a **conjunction**,
  in the condition of an `if`, with the `get()` in the *then* branch — two
  clauses per shape, braced and braceless (6); `while (o.isPresent())` (1); the
  same test as an **expression** rather than a condition, plus the negative-first
  disjunctions `!isPresent() || …` and `isEmpty() || …` (3); the early-exit forms
  of both
  `!isPresent()` and `isEmpty()` — `return`, `throw`, `continue`, `break` —
  each with and without one interposed statement (16); the three ternaries, with
  the `get()` in the **guarded arm** (3);
  `filter(...).isPresent()` (1); and `Optional<T> o = Optional.of(...)` (1),
  which cannot be empty, while `ofNullable` can and still fires. The ternaries
  needed their own clauses because a ternary is a conditional *expression* — a
  different AST node, which no statement-shaped clause reaches — and they must
  be **quoted**, or YAML reads the `?` as a complex-key indicator and the
  config silently fails to load. The arm scoping is wave 6 and has the same
  cause as in `map-get-deref`: unscoped, the `else` arm of an `isPresent()`
  guard and the false arm of an `isPresent()` ternary are guaranteed
  `NoSuchElementException`s and were both excluded. `a.isPresent() || b` is
  deliberately *not* excluded, for the same reason as in `map-get-deref`; the
  negative-first form is.

### `off_by_one` — 1 rule, WARNING

- **loop-lte-length** — `for (int i = 0; i <= a.length; i++)`, with `$A`
  restricted to an **array type** by `metavariable-type: "$T[]"` (quoted, or
  the `[` opens a YAML flow sequence and the file will not load). Without the
  restriction `$A.length` matched any `int` field named `length`, so a domain
  object's deliberately inclusive fence-post loop fired at ERROR on a loop with
  no array in it. Measured, the restriction costs no recall: parameter, local,
  field, `this.`-qualified field and `var`-inferred local arrays are all still
  matched.

### `memory_leak` — 1 rule, WARNING

- **stream-not-closed** — `new FileInputStream(...)` assigned outside a
  try-with-resources. `WARNING` because a stream closed in a `finally` is
  correct and this rule cannot see it. Two exclusions, not one: the classic
  `try ($T $V = new FileInputStream(...))` and the **Java 9 effectively-final
  short form** `try ($V)`, which is genuine try-with-resources that the first
  exclusion does not recognise. The second is shaped over the declaration →
  `try` *sequence*, because the declaration sits outside the `try` body and a
  plain `pattern-not-inside` cannot reach it.

### `race_condition` — 1 rule, WARNING

- **static-dateformat** — a `SimpleDateFormat` held in a `static` field.
  It is not thread-safe, and a static field is the definition of shared. A
  **single** pattern covers both the `static final` and plain `static` forms,
  because Semgrep matches Java modifiers as a subset — a `pattern-either` with
  a branch for each was specified, shipped, and measured redundant (§9). That
  single pattern is now written with the **fully-qualified**
  `java.text.SimpleDateFormat`, and the short-name branch was deleted as a
  *second* inert clause: measured across four import shapes (explicit import,
  wildcard import, `package` declaration, no import), the qualified pattern
  matches the short forms whenever an import lets Semgrep resolve the name,
  while the short pattern never matched the qualified form — so a
  `static final java.text.SimpleDateFormat` field in a file with no import, the
  exact shape you get when there is no import, was invisible. A local instance
  and a per-instance field are both correct and stay silent.

### `edge_case` — 1 rule, WARNING

- **modify-during-iteration** — `coll.remove(...)` inside a `for (T x : coll)`
  over that same collection. Throws `ConcurrentModificationException`. The
  `Iterator.remove()` and `removeIf` forms are correct and stay silent, as does
  removing from a *different* collection.

  Fix wave 4 corrected the exclusions in **both** directions. The
  exit-terminated exclusions were adjacency-only, so `list.remove(s);
  removed = 1; break;` — correct Java, and the first thing anyone writes when
  the caller needs to know whether anything was removed — fired at ERROR; they
  now cover `return`, `throw`, a **labelled** `break` and a plain `break`,
  each with and without one interposed statement. And the plain-`break`
  exclusion was **unsound**: inside a `switch`, `break` leaves the switch and
  not the loop, so `case "x": items.remove(s); break;` is a real
  `ConcurrentModificationException` that the exclusion swallowed whole. It now
  sits behind a `pattern-either` re-inclusion that fires when the removal is
  inside a `switch` — one disjunct for `case`-labelled and one for
  `default`-labelled switches, because measured, neither pattern matches a
  switch written only with the other, and both match Java 14 arrow switches.
  `return`, `throw` and a labelled `break` leave the method or the loop from
  inside a switch too, so those stay excluded everywhere.

  Wave 6 corrected the **scope** of that re-inclusion. It was written
  `pattern-inside: switch ($S) { case $C: ... }`, which is plain lexical
  containment: any removal anywhere inside a case re-armed the rule, including
  one inside a **loop** written in that case, where a plain `break` exits the
  loop and the code is correct. A `switch` dispatching a command with a
  search-and-remove loop in one arm fired three times on correct Java. Both
  disjuncts now nest the `switch` **inside the for-each over `$COLL`**, so what
  the clause tests is the nesting ORDER — switch-inside-loop is the unsound
  `break`, loop-inside-switch is the sound one. Measured: the three false
  positives go, and both `hits/` switch fixtures still fire (ablating either
  disjunct drops exactly one of them). The receiver is bound
  through the same `metavariable-pattern` as `map-get-deref`, so a
  `this.`-qualified field is seen.

  Two corrections this round, both from false positives on correct Java. The
  rule now **anchors on the `remove` call** rather than on the whole `for` —
  the Go round's lesson, that a positive pattern ending in `...` plus a paired
  exclusion produces overlapping spans the exclusion only half-cancels — which
  also makes it report the mutation rather than the loop header. On that anchor
  it excludes the **exit-terminated** shape, `remove()` followed by `return` or
  `break`: the loop stops before `next()` is called again, so no
  `ConcurrentModificationException` is possible, and find-remove-return is one
  of the most common list idioms in Java. And `$COLL` is constrained to the
  collection types where mutation during iteration is genuinely unsafe, which
  excludes `CopyOnWriteArrayList` — whose iteration over a snapshot makes this
  exact shape the textbook *safe* removal idiom — by omission rather than by
  negation.

### One rule killed in the probe, which is what §3 is for

**`Integer == Integer`** — comparing boxed integers by reference rather than
`equals`, a classic Java defect — was in the candidate set and is **not
shipped**. Expressing it needs `metavariable-type`, and Semgrep OSS has no type
inference without compilation, so the rule as written fired on:

- `v == null`, the single most common and most necessary idiom in the language;
- `a == b` where both are primitive `int`, which is simply correct.

A rule that flags `v == null` would be uninstalled within a day. Killed before
the spec rather than in the final review — which is the whole point of §3.

## 6. Where the rules live and how they load

`configs/semgrep/bugfix-java.yml`, beside the JS/TS, Python and Go packs: plain
Semgrep YAML, one `rules:` list, messages in Portuguese.

**No wiring is required.** `resolveBugfixRules()` became plural in 1.7.0 and
returns every `configs/semgrep/bugfix-*.yml` it finds. Note the one thing that
is NOT automatic and bit the Go round: `mcp/test/unit/platform/configsDir.test.ts`
pins the **exact** expected array, deliberately, so a resolver returning only
some files fails. Adding a pack necessarily updates that list, and that is a
task step, not an accident.

## 7. Testing

The harness from the Go round, unchanged in shape: a fixture pair per rule under
`mcp/test/fixtures/bugfix-java/{hits,misses}/`, copied to a temp directory
before scanning; the exact id set **and** the raw non-deduplicated count **and**
`paths.scanned` asserted per file; a no-duplication test with a positive
control; ids asserted against `mapSubcategory`; `makeTempDir`/`cleanupTempDirs`
rather than a bare `mkdtempSync`; skips when Semgrep is absent and fails hard
under `GUARDIAN_REQUIRE_SEMGREP=1`.

**And, from wave 6, a REAL-BUGS CORPUS.** That harness has one structural hole,
and it cost a shipped false negative before anyone saw it: a minimal hit fixture
per rule proves the rule fires *at all*, and a near-miss per exclusion proves the
exclusion silences *the shape it was written for*. Neither measures whether an
exclusion added later also eats a real bug, because a minimal hit carries no
guard shapes for an exclusion to catch on. So five waves of false-positive work
could — and did — delete recall with the suite green.

`hits/RealBugs.java` (12 defects) and `hits/ElseArm.java` (8) close it. Both were
written by the **reviewer**, not by the rule author, which is §3 applied to hits
rather than to misses: they are dense files of defects placed deliberately
*next to* the guard shapes the exclusions match — the `else` arm of a guard, the
arm a ternary condition rules out, a disjunction that proves nothing, a guard on
a different key. Their counts are asserted per file like any other, and the
per-file assertions are backed by a **total**, so a finding landing in a file
nobody registered moves a number too.

The ablation step gains a second axis with them: deleting a clause must make a
near-miss fire (the clause is live) **and** must leave the hits count unmoved (the
clause does not eat a real bug). A clause being live proves it does something; it
never proved it does not also do that.

## 8. Limitations, stated plainly

- **Six of the seven classes.** "Broken happy paths" is a category of
  consequence, not a syntactic shape — unchanged from the three prior rounds.
- **Semgrep OSS matches syntax, not dataflow.** A null that becomes one three
  methods away is invisible.
- **No `Integer ==` rule** — see §5.
- **`stream-not-closed` only recognises `new FileInputStream(...)`.**
  `FileOutputStream`, `FileReader`, `Socket`, `Connection` and every other
  closeable leak identically and are not covered.
- **`static-dateformat` only recognises `SimpleDateFormat`.** A shared
  `Calendar`, a shared `Matcher`, or any other non-thread-safe object in a
  static field is not covered. It is no longer blind to the fully-qualified
  declaration; `stream-not-closed` is now the only rule in the pack that is.
- **`map-get-deref` cannot tell a nullable map from one whose keys are
  guaranteed present by anything outside the shapes it enumerates.** A map
  populated by `put`, `putIfAbsent` or `computeIfAbsent` above the read is
  excluded, but a map filled in a static initialiser, or a total mapping over
  an enum declared as a `Map`, is still flagged; that is the price of having no
  dataflow. An `EnumMap` receiver is outside the type enumeration entirely.
- **`modify-during-iteration` only matches the enhanced-for form.** An indexed
  `for` loop removing from the list it indexes has the same defect and is not
  covered.
- **Type restriction buys precision and costs recall, and the cost is
  permanent.** `metavariable-type` is exact *declared*-type matching with **no
  subtyping** — `type: List` does not match a variable declared
  `CopyOnWriteArrayList`. That is simultaneously the mechanism (concurrent
  collections are excluded for free) and the whole of the price: the two
  type-restricted rules go blind to a receiver held behind an interface the
  list does not name, or a generic type parameter. Measured exception worth
  knowing: a **raw `Map` still fires**, and a `var m = new HashMap<>()` local
  fires too, because Semgrep reads the initialiser.
- **`optional-get-no-ispresent` recognises the guard shapes enumerated in §3
  and no others**, and misses any guard that reaches the check through another
  method — `if (!present(o)) { return d; }` needs interprocedural analysis and
  is not expressible in Semgrep OSS at all. Two earlier attempts to state this
  compactly were both falsified by measurement: "any guard outside these
  twelve" was true when written and stale one round later, and "guards written
  inline against the same variable" was simply wrong — a compound condition, a
  multi-statement exit, a `while` and an `Optional.of` all fired. The shapes
  are therefore listed rather than summarised, and the list lives next to the
  clauses it describes.
- **The exit-terminated exclusions tolerate exactly ONE interposed
  statement**, in `map-get-deref`, `optional-get-no-ispresent` and
  `modify-during-iteration` alike. A statement ellipsis would cover any number
  — and was measured to match *deep*, silencing
  `if (!m.containsKey(k)) { if (strict) { return ""; } }` and
  `items.remove(s); if (done) { break; }`, both of which are real bugs. Two or
  more interposed statements therefore still fire; that is accepted false
  positive (5) below, and it is the deliberate side of the trade.
- **`stream-not-closed` matches the simple constructor name only.** A
  fully-qualified `new java.io.FileInputStream(...)` is invisible to it.

Nine more shapes were reproduced on correct Java and **ruled not fixable**
rather than left unstated. Each fires, each is correct code, and each stays.
The list is exhaustive against the review fixtures that exist today, not
against all Java:

| # | Rule | Correct code it flags | Why it stays |
| --- | --- | --- | --- |
| 1 | `stream-not-closed` | `open(); try { … } finally { close(); }` | The pre-Java-7 idiom, and already the rule's stated reason for being `WARNING`. |
| 2 | `race-condition-static-dateformat` | a `static final SimpleDateFormat` whose every access goes through a `synchronized` method | Proving *all* accesses are synchronized is whole-program analysis, which Semgrep OSS does not do. This row used to end "a shared formatter also serialises every caller, so flagging it is defensible" — that is a **product** argument, not §4's criterion, and it is why the rule sat at `ERROR` for four rounds while carrying a documented, un-fixable false positive. The criterion wins: the finding stays, the tier is now `WARNING`. |
| 3 | `off-by-one-loop-lte-length` | `i <= a.length` where the body guards with `i < a.length`, or never indexes `a` | The obvious tightening was **tried and rejected** — measurement immediately below the table. It trades this false positive for a false negative without fixing the main case, so the patterns were left alone and only the tier moved. |
| 4 | `printstacktrace-only` | `printStackTrace()` as the fallback when the logger itself threw | The one place the call is right; already `WARNING`; too narrow to encode. |
| 5 | `map-get-deref`, `optional-get-no-ispresent`, `modify-during-iteration` | **two or more** statements between the guard (or the removal) and the exit: `if (!m.containsKey(k)) { log(); metric(); return ""; }`, `items.remove(s); log(s); n++; break;` | The deliberate price of bounding the exclusions. A statement ellipsis matches deep and swallows guards that do not cover every path, which are real bugs; a false negative that hides a bug is worse than this. |
| 6 | the same three | a guard reached **through a helper method**: `if (!present(o)) { return d; }` | Needs interprocedural analysis, which Semgrep OSS does not do. Already the stated reason `optional-get-no-ispresent` is `WARNING`. |
| 7 | `map-get-deref` | a key guaranteed present outside the enumerated shapes: a map filled in a static initialiser, a total enum mapping declared as a `Map` | The guarantee is not on the syntactic path reaching the `get`. Excluding "any map that ever received a `put` anywhere in the file" would erase the rule. |
| 8 | `map-get-deref`, `optional-get-no-ispresent` | a guard held in a **local boolean**: `boolean present = m.containsKey(k); if (!present) { return ""; }` | Dataflow, not syntax. Semgrep OSS does not connect the local's value to the test that produced it, and no pattern shape reaches it. |
| 9 | the same two | a conjunction **chain** of three or more operands: `flag && a.isPresent() && b.isPresent() && a.get().equals(b.get())` | The expression clause binds the conjunction's LEFT operand to the guard test itself, and a Java conjunction nests to the left, so in a chain that left operand is another conjunction rather than the guard. Exactly two operands is the shape excluded. An extra clause for the last-but-one operand was **measured**: it removes one of the two findings on that line, and the line still fires from the other, so it changes nothing a caller sees. Not applied. |

### The `loop-lte-length` tightening: measured, then rejected

Recorded here so nobody has to rediscover it. Before demoting the rule, the
obvious fix was tried: require the loop body to actually index the array, with

```yaml
- pattern: "for (int $I = 0; $I <= $A.length; $I++) { <... $A[$I] ...> }"
```

Measured against three functions:

```java
int[] sentinel(int[] a) {                       // correct: fills a LONGER array
    int[] b = new int[a.length + 1];
    for (int i = 0; i <= a.length; i++) { b[i] = (i < a.length) ? a[i] : -1; }
    return b;
}
int sumIdx(int[] a) {                           // correct: never indexes a
    int sum = 0; for (int i = 0; i <= a.length; i++) { sum += i; } return sum;
}
int viaHelper(int[] a) {                        // BUG, via a helper
    int sum = 0; for (int i = 0; i <= a.length; i++) { sum += at(a, i); } return sum;
}
```

The result:

| function | correct? | tightening's effect |
| --- | --- | --- |
| `sumIdx` | correct | **fixed** — stops firing |
| `sentinel` | correct | **still fires** — the guarded `a[i]` sits inside the ternary, and the deep-expression form finds it |
| `viaHelper` | **bug** | **lost** — the index never appears as `a[i]`, so the rule goes silent on a real out-of-bounds |

So it fixes one false positive, leaves the other, and buys a **new false
negative on a real bug**. Not worth shipping. The patterns are unchanged and
the rule is `WARNING` because what it emits is not always a bug — which was
true before the experiment and stayed true after it.

Two more, for completeness:

- **These rules complement `p/r2c-bug-scan`, they do not replace it.** Both run.
- **They do not replace the model-driven `/guardian-fix` path.**

## 9. What measurement changed before any of this was built

Every rule was written as a probe and run against a hit and a near-miss fixture
with Semgrep 1.164.0 **before this document existed**.

| What happened | Rules affected |
| --- | --- |
| **Killed outright** — needs type inference Semgrep OSS does not have; fired on `v == null` and on primitive comparison. | `Integer ==` |
| **Did not parse.** `try (...) { ... }` is not a valid Java pattern; the try-with-resources exclusion had to name the resource. | `stream-not-closed` |
| **Did not parse.** `static $MOD SimpleDateFormat …` and `static ... SimpleDateFormat …` are both invalid; the working form spells the modifiers literally. (It went into a `pattern-either` covering `static final` and plain `static`; both of those branches were later measured redundant — see the two rows below.) | `static-dateformat` |
| **Misclassified by its own name.** `concurrent-modification` → `race_condition`, because that regex matches `concurren` and runs first. Renamed. | `modify-during-iteration` |
| **A specified exclusion was inert.** `pattern-not: $M.getOrDefault($K, ...).$METHOD(...)` excluded nothing — measured with and without it, zero findings both times, because Semgrep's Java matcher requires the literal identifier `get`. Found by Task 2's implementer, who measured instead of reporting the result the brief predicted. Third occurrence of this defect class in the rule-pack series, and the third time the origin was my own planning document. | `map-get-deref` |
| **A specified `pattern-either` branch was redundant.** The `static final SimpleDateFormat …` branch changed nothing: Semgrep matches Java modifiers as a SUBSET, so the plain `static` branch alone produces the same two findings. Measured all three variants — both branches: 2; plain alone: 2; final alone: 1. Found by Task 4's reviewer. **Fourth** occurrence of this defect class in the series, and the fourth time the cause was identical: I measured the whole and one part, never each part alone. | `static-dateformat` |
| **The short-name branch was redundant too, and the whole rule was written the wrong way round.** Measured across four import shapes: the FULLY-QUALIFIED pattern matches the short forms whenever an import lets Semgrep resolve them, the short pattern never matches the qualified form. So the short branch was inert AND the rule was blind to `static final java.text.SimpleDateFormat` in a file with no import. **Fifth** occurrence. Found in fix wave 4, by scanning a probe file the reviewer wrote rather than one I wrote. | `static-dateformat` |
| **Two positive terms inside a `pattern-either` were inert.** The two `switch` re-inclusion disjuncts each repeated `- pattern: $COLL.remove(...)` beside their `pattern-inside`, copied from the third disjunct where it IS load-bearing — `pattern-inside` is already a positive term, `pattern-not-inside` is not. **Sixth** occurrence, and the FIRST caught before shipping: by ablating all 164 clauses one at a time in fix wave 4 rather than waiting for the next reviewer. | `modify-during-iteration` |

**One near-miss was measuring nothing, and only a second look found it.** The
first `static-dateformat` near-miss used a fully-qualified
`java.text.SimpleDateFormat` local, which the unqualified pattern could never
have matched — so it would have passed against a badly broken rule. Replaced
with an unqualified local plus a per-instance field, and both were then verified
silent while both static forms fire.

## 10. What the final review found, and why it took three waves

All eight rules were probed before the spec, every task was reviewed, the suite
was green, and **seven of the eight rules fired on correct Java.** Nineteen
findings on code with no defect in it, most at `ERROR`. That is the largest gap
between "verified" and "correct" in the series so far, and it is worth being
precise about why.

**The rules were never about the types in their names.** `$O.get()` matches any
zero-argument `get()` — `AtomicInteger`, `ThreadLocal`, `Supplier` all fired.
`$M.get($K).$METHOD(...)` matches any `.get(x)` with a method chained on it, so
it fired on a `List` and then advised `getOrDefault`, a method `List` does not
have. Every fixture written for these rules used a `Map` and an `Optional`,
because the person writing the fixture knew what the rule was *for*. The rule
did not. **A fixture chosen by the rule's author tests the author's intent, not
the pattern** — the §3 rule was written for exactly this and still was not
enough, because §3 asks for correct code that *resembles the bug*, and none of
these look like the bug at all.

**A reported count of false positives is a floor, never the total.** Three times
in this round, measuring found more than whoever reported: a reviewer said two
and there were six; a sweep said fifteen and the fixtures pinned nineteen; an
implementer flagged one ternary and there were three. Every report is bounded by
the set its author thought to look at. Re-measure the report.

**Two Semgrep failures are invisible in its own summary.** On `RuleParseError`
*and* on `Invalid YAML file`, Semgrep still prints `✅ Scan completed
successfully` and counts the rule under "Rules run". A rule that fails to load
and a rule that finds nothing are byte-identical there. Both were hit in this
round — the first by a `pattern-either` branch holding only a
`metavariable-type` ("you need at least one positive term"), the second by an
unquoted `?` in a ternary pattern. Grep stderr for both strings; trust
`paths.scanned`, never the summary.

**The one thing that worked.** The ablation step — delete each clause alone,
watch a test go red, restore — caught the **fifth** dead clause in this series
*before* it shipped, the first time that has happened rather than a later
reviewer finding it. Every clause in the final file is live. That
step is now the non-negotiable part of the process, and it is cheap: it is the
only check here that scales with the rule file rather than with imagination.

### Wave 6: closing a false positive is a change to RECALL, and nobody measured it

The one thing ablation could not see. Waves 1–5 closed 35 false positives on
correct Java, each one measured, each one with a near-miss fixture, the suite
green throughout. Wave 4's guard exclusions did that *and* deleted five of six
findings on a file of guaranteed `NullPointerException`s, because
`pattern-not-inside: if ($M.containsKey($K)) { ... }` excludes the whole
**if-else statement** and `"$M.containsKey($K) ? ... : ..."` excludes the whole
**conditional expression** — both arms, including the one the guard proves is
the bug. Measured on the reviewer's file: 6 findings before wave 4, 1 after.

Three things follow, and they generalise past this pack:

1. **An exclusion is a recall change written as a precision change.** Every
   `pattern-not-inside` deletes findings. The near-miss fixture proves it
   deleted the *intended* ones; nothing proved it stopped there. The fix is
   structural, not procedural: a real-bugs corpus (§7) that every clause has to
   pass while it is being ablated.
2. **`pattern-not-inside` excludes the whole matched node, not the part that
   matched.** Scoping has to be built into the *pattern* — the deep expression
   operator in the guarded ternary arm, a dereference requirement in the `if`
   body — because there is no way to say "not inside this sub-part of the match".
3. **`pattern-inside` for a re-inclusion is lexical containment and nothing
   more.** The `switch` disjuncts read as if they knew what `break` binds to;
   they knew only that the removal appeared somewhere inside a `case`. The
   distinction that mattered was the NESTING ORDER — switch inside loop, or loop
   inside switch — and expressing it meant nesting the two patterns.

A fourth, smaller, that only ablation catches: **two clauses can each be live
against the whole fixture set and inert against each other.** The arm-scoped
`if` guard needed two clauses per shape — one reaching a multi-statement or
nested body, one reaching the braceless form — and nine of them came back INERT
on the first ablation because their twin already covered the only near-miss for
that shape. Nine near-miss functions were added rather than nine clauses
deleted, because the braceless guard is real Java that fires without them.
