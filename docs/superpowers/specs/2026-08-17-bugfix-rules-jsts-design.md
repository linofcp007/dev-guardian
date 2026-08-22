# Local bug-finding Semgrep rules — JS/TS — design of record

**Date:** 2026-08-17
**Status:** approved; **amended 2026-08-21** — `catch-returns-null` was deleted
and the pack is thirteen rules, not fourteen. It produced **zero true positives
on two independent corpora**: five idiomatic instances on an auditor's probes,
and 25 findings on this repo's own `mcp/src`, every one a safe-`JSON.parse`
helper or a `readdirSync` with a fallback. The reasoning for deleting rather
than demoting is recorded in the CHANGELOG: a lower tier is not a fix for a rule
that has never been right, it is a quieter way to keep being wrong. §4 below
still describes the rule as shipping and is kept as written, because this
document is the record of what was designed.
**First of a sequence**, one design per language family. JS/TS is first because it
is the only stack with **zero** coverage of these classes today, and because the
rules were empirically shown to fire before this design was written.

## 1. Why this exists

`bug_hunt` is meant to find implementation bugs: `commands/guardian-fix.md` names
race conditions, null/undefined safety, edge cases, off-by-one, memory leaks,
missing or swallowed error handling, and broken happy paths.

It cannot, for JS/TS. Measured during the 1.5.0 work:

- Semgrep retired `p/bugs`. Its replacement, `p/r2c-bug-scan`, has 44 rules, all
  `category: correctness` — but only **12** land in those classes, and all 12 are
  **Python and Go** (python=10, go=2). JS/TS: zero.

  > **Corrected 2026-08-18.** This line originally said **8**. The figure moved
  > because `mapSubcategory` was *widened* later in the same 1.5.0 fix round that
  > produced this measurement, so the number was already stale by the time the
  > branch merged — not because the pack changed. Re-measured by running all 44
  > ids through the shipped classifier: 12 classify (off_by_one=2, edge_case=4,
  > error_handling=2, null_safety=2, race_condition=1, memory_leak=1). **The
  > conclusion this section rests on is unchanged: zero of them are JS/TS.**
  > Recorded rather than quietly overwritten, because a design of record that
  > silently edits its own measurements is not a record.
- The five per-language packs add 401 rules (327 distinct), **100 %
  `category: security`**, zero in any bug class. A purpose-built TypeScript
  fixture containing null-safety, off-by-one, edge-case and swallowed-error bugs
  returns **zero findings** with all seven packs enabled.
- `skills/guardian-bugfix/SKILL.md` used to promise ready-made rules at
  `configs/semgrep/bugfix-*.yml`. **Those files never existed.** This design is
  what makes that promise true instead of deleting it.

So the gap is real, it is not covered anywhere in the live registry, and writing
it ourselves is filling a hole rather than duplicating a pack.

**It is also viable**, and that was established before committing to the work.
Four candidate rules were written and run against a realistic TypeScript file;
three fired correctly on the first attempt:

| Probe rule | Fired |
| --- | --- |
| empty `catch` / `.catch(() => {})` | line 2 |
| `for (…; i <= arr.length; …)` | line 4 |
| mutating async call with no `await` | line 5 |
| `addEventListener` in `useEffect` with no cleanup | not exercised — the fixture had no React |

## 2. The rule that governs every rule

> **Every rule ships with two fixtures: one that makes it fire, and one that
> looks like it but must not.**

Proving a rule catches the bug is half a proof. The half that decides whether
this feature helps or hurts is proving it does **not** fire on correct code that
resembles the bug — an empty `catch` that rethrows, a loop that legitimately
indexes to `length` because it writes rather than reads, a `logger.write()` that
is deliberately not awaited.

A scanner that cries wolf is worse than no scanner: people stop reading it, and
then it is worse than nothing precisely when it is finally right. This is not a
testing preference; it is the feature's success criterion, and a rule without a
near-miss fixture is not finished.

## 3. Two severity tiers

Chosen deliberately, because these rules divide cleanly into two kinds.

**`ERROR` — context-free.** The pattern is a bug regardless of intent. An empty
`catch` block discards an error no matter what the author meant. `i <= arr.length`
reads past the end no matter why the loop exists. A reader can act on these
without knowing the codebase.

**`WARNING` / `INFO` — intent-dependent heuristics.** The pattern is *usually*
a bug but has legitimate uses. A mutating call without `await` is the most
valuable rule in this set and also the noisiest: `repo.save()` unawaited is a
bug, `logger.write()` unawaited is a decision.

The tiers are what make one rule set serve two audiences: a CI gate can fail on
`ERROR` alone, while a developer hunting bugs reads everything. `bug_hunt`'s
`severity_min` already filters this way, so no new mechanism is needed.

## 4. The rules

Fourteen to start, grouped by the canonical class `mapSubcategory` assigns.

**Rule ids carry the class token, because that is literally how classification
works.** `mapSubcategory` (`mcp/src/tools/bugHunt.ts:317`) runs regexes over the
lowercased rule id; it is not a lookup table. So the id must contain a token the
matching regex accepts, and these are the six that do:

| Class | Token the id must contain |
| --- | --- |
| `race_condition` | `race-condition` |
| `null_safety` | `null-safety` |
| `off_by_one` | `off-by-one` |
| `memory_leak` | `memory-leak` |
| `error_handling` | `error-handling` |
| `edge_case` | `edge-case` |

Giving the format `bugfix-js-<token>-<name>`.

**One collision to be aware of, and it is load-bearing.** The `error_handling`
regex matches the bare word `unchecked`, which appears in two `null_safety` rule
names below (`unchecked-find`, `unchecked-match`). They classify correctly today
only because `null_safety` is tested *earlier* in the if-chain than
`error_handling`. Reordering those checks would silently reclassify both rules,
with nothing failing. §6 requires every rule id to be asserted against
`mapSubcategory` for exactly this reason.

### `error_handling` — 3 rules, all ERROR

- **empty-catch** — `try { … } catch ($E) { }`. The single highest-value pattern
  in the set: it is unambiguous and common.
- **empty-promise-catch** — `$P.catch(() => {})`, `.catch(function () {})`.
- **catch-returns-null** — a `catch` whose only statement is `return null` /
  `return undefined` / `return []`, which converts a failure into a value the
  caller cannot distinguish from a legitimate empty result.

### `off_by_one` — 2 rules, ERROR

- **loop-lte-length** — `for (…; $I <= $A.length; …)`.
- **index-at-length** — `$A[$A.length]`, which is always `undefined`.

### `null_safety` — 3 rules

- **unchecked-find** (ERROR) — the result of `.find(…)` dereferenced in the same
  expression: `$A.find(…).$PROP`. `find` returns `undefined` when nothing
  matches, and this is the most common way that becomes a runtime crash.
- **unchecked-match** (ERROR) — `$S.match(…)[$I]`, same shape.
- **unchecked-env** (WARNING) — `process.env.$X.$M(…)`, calling a method on an
  environment variable that may be undefined.

### `memory_leak` — 3 rules

- **listener-without-cleanup** (ERROR) — `useEffect` that calls
  `addEventListener` and returns no cleanup function.
- **interval-without-clear** (WARNING) — `setInterval` whose handle is never
  passed to `clearInterval` in the same scope.
- **subscribe-without-unsubscribe** (WARNING) — `.subscribe(…)` in a `useEffect`
  with no returned teardown.

### `race_condition` — 1 rule, WARNING

- **floating-mutation** — inside an `async` function, a call to a method whose
  name is a mutating verb (`save`, `update`, `delete`, `create`, `insert`,
  `commit`, `send`) that is neither awaited nor returned.

  **`write` is deliberately NOT in that list**, and the omission is the rule’s
  own near-miss: `logger.write()` is the canonical legitimate fire-and-forget.
  An earlier draft of this design listed `write` as a mutating verb *and* used
  `logger.write()` as the example of correct code — a contradiction inside one
  section, caught only when the rule fired on its own near-miss fixture.

  Note also that `pattern-not: await .(...)` does **not** work here: a call
  and the `await` enclosing it never share a span, so the exclusion is a
  structural no-op. It needs `pattern-not-inside`. Both a race
  and a broken happy path: the caller proceeds as though the write happened.

  This is the noisiest rule here and the most valuable. It is `WARNING`
  precisely because the verb list is a heuristic about intent.

### `edge_case` — 2 rules

- **reduce-without-initial** (WARNING) — `.reduce($F)` with no initial value,
  which throws on an empty array.
- **parseint-without-radix** (INFO) — `parseInt($S)` with no radix.

### Not a rule class: "broken happy paths"

`guardian-fix` names it, and it is not expressible as a pattern — it describes a
category of *consequence*, not a syntactic shape. `floating-mutation` covers its
most common concrete form. **The docs must say this rather than implying seven
classes are covered when six are**, which is the failure mode this repo has now
shipped three times.

## 5. Where the rules live and how they load

`configs/semgrep/bugfix-js.yml` — the path
`skills/guardian-bugfix/SKILL.md` originally promised, in the directory that
already holds `base.yml` and `routes.yml`, and in their style: plain Semgrep
YAML, one `rules:` list, messages in Portuguese to match `base.yml`.

`bug_hunt` passes it as an additional `--config` with an absolute path resolved
from the plugin root, alongside `p/r2c-bug-scan` and `p/security-audit`. It is
**on by default** — unlike `include_language_packs`, because unlike those packs
it delivers exactly what the tool exists for.

A local file cannot 404, so this also removes the single point of failure that
took `bug_hunt` down: even with the registry unreachable, the local rules still
run and the tool still reports something true.

## 6. Testing

- **A fixture pair per rule**, under `mcp/test/fixtures/bugfix-js/`: one file
  that must produce the finding, one near-miss that must not. §2 is the
  requirement; this is where it is discharged.
- **One test runs Semgrep against the fixture directory** and asserts the exact
  set of rule ids that fired. Not "at least one finding" — the **exact set**, so
  a rule that starts matching its own near-miss fails the suite rather than
  quietly widening.
- **The test skips when Semgrep is absent** and fails hard under
  `GUARDIAN_REQUIRE_SEMGREP=1`, matching every other Semgrep-dependent test here.
- **Rule ids are asserted against `mapSubcategory`**, so a rule whose id stops
  mapping to its class is caught at test time rather than by a user seeing an
  unclassified finding.

## 7. Limitations, stated plainly

- **Six of the seven named classes are addressed.** "Broken happy paths" is not
  a syntactic pattern; `floating-mutation` covers its commonest form and nothing
  covers the rest.
- **Semgrep OSS matches syntax, not dataflow.** These rules find the shapes
  bugs take, not bugs proven by analysis. A null dereference two functions away
  from its guard is invisible to them.
- **The heuristic tier will produce false positives by construction** —
  `floating-mutation` matches on the method name alone, so it cannot distinguish a
  real mutation like `repo.save()` from an unrelated call that shares the name,
  like `ctx.save()` (Canvas 2D's synchronous state-stack push) — both fire
  identically. That is why it is `WARNING` and why `severity_min` exists.
- **JS/TS only.** Python, Go, Java, C#, PHP, Ruby and Rust each get their own
  design; a rule set is only as good as the idioms its author knows, and one
  file covering eight languages would be eight shallow rule sets.
- **These rules do not make `bug_hunt` a substitute for the model-driven
  `/guardian-fix` path.** They catch shapes; reading the code catches reasons.
