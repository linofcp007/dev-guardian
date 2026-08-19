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

Unchanged. **`ERROR`** where the pattern is a bug regardless of intent;
**`WARNING`** where it is usually a bug but has legitimate uses.
`bug_hunt`'s `severity_min` already filters on this.

**This round is the first to apply that criterion against a rule rather than
merely alongside one**, and it cost `optional-get-no-ispresent` its tier — see
§5. The useful generalisation: **an exclusion list that keeps growing is a
severity signal, not a backlog.** Thirteen guard-shape exclusions in, with new
shapes still arriving and one of them not expressible at all, the rule was
demonstrably unable to separate bug from correct code. By the definition above
it was never `ERROR`. Demoting it applies the criterion; it does not change it.

The tier split is now **pinned by a test**. It was decided here and asserted
nowhere until this round, which made it documented and unfalsifiable — exactly
the shape of every other defect in this series. `EXPECTED_SEVERITY` in the Java
integration test pins all eight rules, exhaustive in both directions.

The tier is not cosmetic. The parser maps `ERROR → high` and `WARNING → medium`.
`bug_hunt`'s `severity_min` is optional, so nothing vanishes from a scan — but
`create_fix_pr` defaults to `high`, so a `WARNING` finding leaves the default
fix-PR set and needs `severity_min: "medium"` to come back.

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

### `error_handling` — 2 rules

- **empty-catch** (ERROR) — `try { … } catch (E e) { }`. The exception was
  caught and discarded with no log, no rethrow, no handling.
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

- **map-get-deref** (ERROR) — a method called directly on `map.get(k)`, which
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
- **optional-get-no-ispresent** (**WARNING**, demoted from ERROR — see §4) —
  `optional.get()` outside a guard. Throws `NoSuchElementException`; `orElse`
  does not. The receiver is constrained to `Optional`; untyped, `$O.get()`
  matched `AtomicInteger.get()`, `ThreadLocal.get()` and `Supplier.get()`.
  Thirteen exclusions cover the guard shapes: the inline `if (o.isPresent())`,
  the early-exit forms of both `!isPresent()` and `isEmpty()` (`return`,
  `throw`, `continue`, `break`), the three ternaries, and
  `filter(...).isPresent()`. The ternaries needed their own clauses because a
  ternary is a conditional *expression* — a different AST node, which no
  statement-shaped clause reaches — and they must be **quoted**, or YAML reads
  the `?` as a complex-key indicator and the config silently fails to load.

### `off_by_one` — 1 rule, ERROR

- **loop-lte-length** — `for (int i = 0; i <= a.length; i++)`.

### `memory_leak` — 1 rule, WARNING

- **stream-not-closed** — `new FileInputStream(...)` assigned outside a
  try-with-resources. `WARNING` because a stream closed in a `finally` is
  correct and this rule cannot see it. Two exclusions, not one: the classic
  `try ($T $V = new FileInputStream(...))` and the **Java 9 effectively-final
  short form** `try ($V)`, which is genuine try-with-resources that the first
  exclusion does not recognise. The second is shaped over the declaration →
  `try` *sequence*, because the declaration sits outside the `try` body and a
  plain `pattern-not-inside` cannot reach it.

### `race_condition` — 1 rule, ERROR

- **static-dateformat** — a `SimpleDateFormat` held in a `static` field.
  It is not thread-safe, and a static field is the definition of shared. A
  **single** pattern covers both the `static final` and plain `static` forms,
  because Semgrep matches Java modifiers as a subset — a `pattern-either` with
  a branch for each was specified, shipped, and measured redundant (§9). A
  local instance and a per-instance field are both correct and stay silent.

### `edge_case` — 1 rule, ERROR

- **modify-during-iteration** — `coll.remove(...)` inside a `for (T x : coll)`
  over that same collection. Throws `ConcurrentModificationException`. The
  `Iterator.remove()` and `removeIf` forms are correct and stay silent, as does
  removing from a *different* collection.

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
  static field is not covered.
- **`map-get-deref` cannot tell a nullable map from one whose keys are
  guaranteed present.** A `Map` populated immediately above the read will still
  be flagged; that is the price of having no dataflow.
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
- **`optional-get-no-ispresent` recognises guards written inline against the
  same variable**, and misses any guard that reaches the check through another
  method or another variable — `if (!present(o)) { return d; }` needs
  interprocedural analysis and is not expressible in Semgrep OSS at all. This
  is stated as a shape rather than a count deliberately: an earlier draft said
  "any guard outside these twelve", which was true when written and stale one
  round later.
- **`stream-not-closed` matches the simple constructor name only.** A
  fully-qualified `new java.io.FileInputStream(...)` is invisible to it.

Four more shapes were reproduced on correct Java and **ruled not fixable**
rather than left unstated. Each fires, each is correct code, and each stays:

| Rule | Correct code it flags | Why it stays |
| --- | --- | --- |
| `stream-not-closed` | `open(); try { … } finally { close(); }` | The pre-Java-7 idiom, and already the rule's stated reason for being `WARNING`. |
| `race-condition-static-dateformat` | a `static final SimpleDateFormat` whose every access goes through a `synchronized` method | Proving *all* accesses are synchronized is whole-program analysis. A shared formatter also serialises every caller, so flagging it is defensible. |
| `off-by-one-loop-lte-length` | `i <= a.length` where the body guards with `i < a.length`, or never indexes `a` | Genuinely rare, and the loop still deserves a human look. |
| `printstacktrace-only` | `printStackTrace()` as the fallback when the logger itself threw | The one place the call is right; already `WARNING`; too narrow to encode. |

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
| **Did not parse.** `static $MOD SimpleDateFormat …` and `static ... SimpleDateFormat …` are both invalid; the working form spells the modifiers literally, in a `pattern-either` covering `static final` and plain `static`. | `static-dateformat` |
| **Misclassified by its own name.** `concurrent-modification` → `race_condition`, because that regex matches `concurren` and runs first. Renamed. | `modify-during-iteration` |
| **A specified exclusion was inert.** `pattern-not: $M.getOrDefault($K, ...).$METHOD(...)` excluded nothing — measured with and without it, zero findings both times, because Semgrep's Java matcher requires the literal identifier `get`. Found by Task 2's implementer, who measured instead of reporting the result the brief predicted. Third occurrence of this defect class in the rule-pack series, and the third time the origin was my own planning document. | `map-get-deref` |
| **A specified `pattern-either` branch was redundant.** The `static final SimpleDateFormat …` branch changed nothing: Semgrep matches Java modifiers as a SUBSET, so the plain `static` branch alone produces the same two findings. Measured all three variants — both branches: 2; plain alone: 2; final alone: 1. Found by Task 4's reviewer. **Fourth** occurrence of this defect class in the series, and the fourth time the cause was identical: I measured the whole and one part, never each part alone. | `static-dateformat` |

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
reviewer finding it. Forty-four clauses in the final file, forty-four live. That
step is now the non-negotiable part of the process, and it is cheap: it is the
only check here that scales with the rule file rather than with imagination.
