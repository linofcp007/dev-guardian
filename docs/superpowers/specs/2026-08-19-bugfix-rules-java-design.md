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
- **printstacktrace-only** (WARNING) — a catch whose only statement is
  `e.printStackTrace()`. It goes to stderr, not to the log, and execution
  continues as though nothing happened. `WARNING` because in a throwaway
  `main` it is a deliberate choice.

### `null_safety` — 2 rules, ERROR

- **map-get-deref** — a method called directly on `map.get(k)`, which returns
  `null` for a missing key. **No `getOrDefault` exclusion**, deliberately:
  Semgrep requires the literal method identifier, so `getOrDefault` never
  matches `$M.get($K)` in the first place. A clause excluding it was specified,
  shipped into Task 2, and measured to be inert — see §9.
- **optional-get-no-ispresent** — `optional.get()` outside an
  `if (o.isPresent())`. Throws `NoSuchElementException`; `orElse` does not.

### `off_by_one` — 1 rule, ERROR

- **loop-lte-length** — `for (int i = 0; i <= a.length; i++)`.

### `memory_leak` — 1 rule, WARNING

- **stream-not-closed** — `new FileInputStream(...)` assigned outside a
  try-with-resources. `WARNING` because a stream closed in a `finally` is
  correct and this rule cannot see it.

### `race_condition` — 1 rule, ERROR

- **static-dateformat** — a `SimpleDateFormat` held in a `static` field.
  It is not thread-safe, and a static field is the definition of shared. Covers
  both the `static final` and plain `static` forms; a local instance and a
  per-instance field are both correct and stay silent.

### `edge_case` — 1 rule, ERROR

- **modify-during-iteration** — `coll.remove(...)` inside a `for (T x : coll)`
  over that same collection. Throws `ConcurrentModificationException`. The
  `Iterator.remove()` and `removeIf` forms are correct and stay silent, as does
  removing from a *different* collection.

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

**One near-miss was measuring nothing, and only a second look found it.** The
first `static-dateformat` near-miss used a fully-qualified
`java.text.SimpleDateFormat` local, which the unqualified pattern could never
have matched — so it would have passed against a badly broken rule. Replaced
with an unqualified local plus a per-instance field, and both were then verified
silent while both static forms fire.
