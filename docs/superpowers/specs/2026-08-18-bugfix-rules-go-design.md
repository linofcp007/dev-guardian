# Local bug-finding Semgrep rules — Go — design of record

**Date:** 2026-08-18
**Status:** approved
**Third in the per-language sequence**, after JS/TS (1.6.0) and Python (1.7.0).

## 1. Why Go is the biggest hole in the sequence so far

Measured, not assumed. `p/r2c-bug-scan` ships **5 Go rules**. Running every id
through the shipped `mapSubcategory` puts **2** of them in a bug class:

| Class | Go rules in the pack | What that leaves |
| --- | --- | --- |
| `error_handling` | **0** | everything — in the language where `if err != nil` *is* the error model |
| `null_safety` | **0** | everything — nil deref and failed type assertions are Go's canonical panics |
| `race_condition` | **0** | everything — in the language people pick *for* concurrency |
| `memory_leak` | **0** | everything — goroutine leaks, unclosed response bodies, live tickers |
| `edge_case` | **0** | everything |
| `off_by_one` | 2 — `integer-overflow-int16`, `integer-overflow-int32` | loop bounds |

The other three Go rules are `incorrect-default-permission`, `eqeq-is-bad` and
`hardcoded-eq-true-or-false` — style and permissions, not bug classes.

For comparison: JS/TS had zero coverage across the board, and Python had 10 of
its 32 pack rules classifying. Go is the sparsest yet relative to how much of
its idiom is *about* these exact failures.

The five per-language registry packs do not help either: measured during the
1.5.0 work, they are 401 rules, **100 % `category: security`**, zero in any bug
class.

## 2. The two rules that govern every rule

Both inherited, both unchanged:

> **Every rule ships with two fixtures: one that makes it fire, and one that
> looks like it and must not.**

> **Every rule must be shown not to duplicate what the registry pack already
> finds.** Measured for this language before the design was written:
> `p/r2c-bug-scan` produces **zero** findings on every Go hit fixture, so all
> ten rules are additive.

## 3. Two severity tiers

Unchanged. **`ERROR`** where the pattern is a bug regardless of intent;
**`WARNING`** where it is usually a bug but has legitimate uses.
`bug_hunt`'s `severity_min` already filters on this.

## 4. The ten rules

Ids follow `bugfix-go-<class-token>-<name>`, because `mapSubcategory`
classifies by regex over the lowercased id rather than a lookup table. All ten
were run through the real classifier and land in their own class; **none
contains the word `unchecked`**, so the branch-order dependency the JS/TS set
carries is again avoided.

### `error_handling` — 3 rules

- **err-discarded** (ERROR) — `x, _ := f()`. The canonical Go smell.
- **err-blank-assign** (WARNING) — `_ = f()`. Frequently deliberate in cleanup
  paths (`_ = os.Remove(tmp)`), which is why it is not ERROR.
- **empty-err-block** (ERROR) — `if err != nil {}` with an empty body. The
  error was noticed and then discarded, which is worse than not checking.

### `null_safety` — 1 rule

- **type-assert-no-ok** (ERROR) — `v.(T)` outside the comma-ok form. A failed
  assertion panics; `v, ok := x.(T)` does not.

### `off_by_one` — 1 rule

- **loop-lte-len** (ERROR) — `for i := 0; i <= len(xs); i++`.

### `memory_leak` — 2 rules

- **body-not-closed** (ERROR) — `resp, err := http.Get(...)` with no
  `defer resp.Body.Close()` in the same block. Leaks the connection.
- **ticker-not-stopped** (WARNING) — `time.NewTicker(...)` with no
  `defer t.Stop()`. The runtime keeps firing it.

### `race_condition` — 1 rule

- **lock-without-defer** (WARNING) — `mu.Lock()` with no `defer mu.Unlock()`.
  An unlock on the happy path only is an unlock that an early `return` or a
  panic skips, and the next caller blocks forever.

### `edge_case` — 2 rules

- **append-discarded** (ERROR) — `append(xs, y)` as a bare statement. `append`
  may reallocate, so the result is the only reliable handle on the data.
- **nil-map-write** (ERROR) — writing to a `var m map[K]V` that was never
  `make`d. Reads of a nil map are fine; writes panic.

### One rule built, measured, and deliberately excluded

**goroutine captures the loop variable** — `for _, v := range xs { go func(){ …
v … }() }` — works as a Semgrep rule and was verified firing on the bug and
silent on the parameterised fix. It is **excluded** anyway.

Go 1.22 changed loop-variable semantics: each iteration now gets its own
variable, so the pattern stopped being a bug in any module declaring `go 1.22`
or later. Semgrep cannot read `go.mod`, so the rule cannot tell a genuinely
broken pre-1.22 module from correct modern code, and on modern code it accuses
the correct form. That fails this project's stated success criterion — a
scanner that cries wolf is worse than no scanner, because people stop reading
it and then it is worse than nothing precisely when it is finally right.

Recorded rather than silently omitted, for the same reason Python's
`coroutine-not-awaited` is: a reader should be able to see that the gap is
known and deliberate, not overlooked.

## 5. Where the rules live and how they load

`configs/semgrep/bugfix-go.yml`, beside `bugfix-js.yml` and `bugfix-py.yml`:
plain Semgrep YAML, one `rules:` list, messages in Portuguese matching the
existing packs.

**No wiring is required.** `resolveBugfixRules()` became plural in 1.7.0 and
returns every `configs/semgrep/bugfix-*.yml` it finds; `buildPackList` splices
them into `bug_hunt`'s `--config` list, and `scan_sast` picks up the project's
own registered rules separately. Dropping this file in is the whole
integration, which is what that change was for.

## 6. Testing

The harness from the Python round, unchanged in shape:

- **A fixture pair per rule** under `mcp/test/fixtures/bugfix-go/{hits,misses}/`,
  copied to a temp directory before scanning — the in-repo path contains a
  `test/` segment, which Semgrep's default ignore list skips wholesale,
  reporting `paths.scanned: []` and zero results regardless of the rules.
- **Exact id set per file AND the raw non-deduplicated finding count**, because
  the deduplicated set cannot prove a particular instance still matches while a
  sibling instance of the same rule survives in the same file.
- **`paths.scanned` asserted against the fixture count**, so "found nothing" can
  never be confused with "looked at nothing".
- **A no-duplication test** scanning the hit fixtures with `p/r2c-bug-scan`
  alone, asserting zero.
- **Rule ids asserted against `mapSubcategory`.**
- Uses `makeTempDir`/`cleanupTempDirs` from `test/helpers/tempDir.ts`; never a
  bare `mkdtempSync`.
- Skips when Semgrep is absent; `GUARDIAN_REQUIRE_SEMGREP=1` makes absence a
  hard failure.

## 7. Limitations, stated plainly

- **Six of the seven classes.** "Broken happy paths" is a category of
  consequence, not a syntactic shape — unchanged from the previous two rounds.
- **Semgrep OSS matches syntax, not dataflow.** A nil that becomes one three
  functions away is invisible.
- **No goroutine-leak rule**, and no loop-variable-capture rule — see §4.
- **`body-not-closed` only recognises `http.Get`.** `http.Post`,
  `client.Do(req)` and a `*http.Client`'s other methods leak identically and
  are not covered.
- **`lock-without-defer` accepts any `defer mu.Unlock()` in the block**, so it
  cannot tell a correctly scoped unlock from one deferred in the wrong branch.
  It is `WARNING` for that reason.
- **`lock-without-defer` does not cover `sync.RWMutex` read locks.** The
  pattern is the literal `$MU.Lock()` / `defer $MU.Unlock()`, not a
  metavariable over the method name, so `RLock()`/`RUnlock()` — a common Go
  idiom for read access — is entirely outside the rule's reach. The write
  lock is covered: a `*sync.RWMutex` with `mu.Lock()` and no defer fires
  correctly. Measured against the shipped rule, not assumed.
- **`body-not-closed` and `ticker-not-stopped` match only the `:=` form.**
  Both patterns anchor on `$RESP, $ERR := http.Get(...)` and
  `$T := time.NewTicker(...)`; the `var`-then-assign form —
  `var resp *http.Response; resp, err = http.Get(url)` and
  `var t *time.Ticker; t = time.NewTicker(...)` — is silent for both rules.
  `err-discarded` covers both forms via `pattern-either`, so this is an
  undocumented internal inconsistency rather than a stated policy.
- **`nil-map-write` only catches a locally `var`-declared map.** The pattern
  requires `var $M map[$K]$V` followed by an indexed write; a nil map
  arriving as a function parameter, a struct field, or a return value panics
  identically on write and is not covered — arguably the commoner
  real-world shape. Directly analogous to `open-without-context`'s
  attribute-target gap in the Python round.
- **`err-blank-assign` fires on deliberate discards.** `_ = os.Remove(tmp)` in
  a cleanup path is intentional and will be flagged; that is why it is
  `WARNING` and not `ERROR`.
- **These rules complement `p/r2c-bug-scan`, they do not replace it.** Both run.
- **They do not replace the model-driven `/guardian-fix` path.**

## 8. What measurement changed before any of this was built

Eleven candidate rules were written and run against hit and near-miss fixtures
with Semgrep 1.164.0 **before this document existed**. Three rounds were needed,
and only four of the original nine survived the first one untouched.

| What happened | Rules affected |
| --- | --- |
| **Did not parse at all** — my Go was wrong, not Semgrep's limits. `switch $V.($T) { ... }` is not Go (the type switch is `switch v := x.(type)`), and `func($P ...)` is not a valid parameter list. | type-assert, goroutine-capture |
| **Fired on their own near-miss.** `pattern` + trailing `...` generates many overlapping spans and the paired `pattern-not` cancels only one of them. Re-anchoring on the single call and excluding with `pattern-not-inside` over the sequence fixed all three. | body-not-closed, lock-without-defer, ticker-not-stopped |
| **Matched the assigned form too.** `append($XS, ...)` also matched `xs = append(xs, 1)`; excluded the assigned (`=`), returned and passed-as-argument forms. Same shape as Python's asyncio rule. | append-discarded |

**Twice, exclusions assumed necessary were measured to be no-ops**, and both are
worth recording because a clause that reads as a guard and does nothing is this
project's signature defect:

- The type-assertion rule needs **no** type-switch exclusion. `v.(type)` inside
  a `switch` simply does not match `$V.($T)`. The exclusion clauses were both
  unnecessary *and* unparseable.
- `err-discarded` needs **no** map / channel / type-assertion exclusions.
  `$X, _ := $F(...)` requires a function *call*, and `v, _ := m["k"]`,
  `v, _ := <-ch` and `s, _ := x.(string)` are not calls, so the idiomatic
  ok-forms never matched in the first place. A broad and a narrowed variant
  were run side by side against a file of idiomatic Go and produced identical
  results.

Both simple forms are therefore deliberate. **Do not "harden" them later**
without first measuring that the added clause changes a result.

**A third instance of the same defect surfaced after this document was
written, in Task 4's review.** `append-discarded` shipped with four
`pattern-not-inside` exclusions, the fourth being
`$X := append($XS, ...)`. It was dead: Semgrep's Go matcher treats
`$X = append($XS, ...)` as covering the `:=` form too, so the `=` clause
alone already excluded `ys := append(xs, 1)` — the `:=` clause changed zero
results and was removed. The rule now ships three clauses (assigned,
returned, passed-as-argument), each proven load-bearing on its own.

The comment this rule shipped with originally read "as quatro exclusões são
todas necessárias … Medido" — "measured". What had actually been measured was
that the *set* of four exclusions, together, produced the correct fixture
result; no one had measured each clause individually, so a redundant one hid
inside a comment that claimed the opposite. That is exactly the failure this
section exists to name: a clause that reads as a guard and does nothing. The
fix is the same discipline recorded above for `type-assert` and
`err-discarded` — after this finding, verify each exclusion clause
separately (remove it, re-run the fixtures, confirm a result changes) before
a "Medido" comment may claim the whole set is necessary.
