# Local bug-finding Semgrep rules — Python — design of record

**Date:** 2026-08-18
**Status:** approved
**Second in the per-language sequence**, after JS/TS shipped in 1.6.0.

## 1. Why this exists, and why it is smaller than the JS/TS set

JS/TS had **zero** coverage of these classes, so that design wrote fourteen rules
from nothing. Python is different, and the difference was measured rather than
assumed.

`p/r2c-bug-scan` carries **32 Python rules**. Running every id through the
shipped `mapSubcategory` puts **10** of them in a bug class:

| Class | Existing | What that leaves |
| --- | --- | --- |
| `edge_case` | 4 — mutation during iteration, mutable defaults | reasonably covered |
| `error_handling` | 2 — unchecked `subprocess`, `raise` of a non-exception | **the biggest Python case is absent: bare `except:`** |
| `null_safety` | 2 — **both Django model-field conventions**, not dereference | **nothing about `None` being dereferenced**, which is Python's commonest crash |
| `memory_leak` | 1 — file object redefined before close | the rest |
| `race_condition` | 1 — uncaught executor exceptions | the rest |
| `off_by_one` | **0** | everything |

The other 22 are framework and style conventions — and the label needs care:
they are a **mix of Django, Flask and SQLAlchemy**, not "Django rules".
`bad-operator-in-filter` is SQLAlchemy; `avoid-accessing-request-in-wrong-handler`
is Flask.

So Python does not need fourteen rules. It needs **nine, aimed at measured
holes**.

## 2. The two rules that govern every rule

**The first is inherited from the JS/TS design and is unchanged:**

> **Every rule ships with two fixtures: one that makes it fire, and one that
> looks like it and must not.**

**The second is new, and this design's scope is what makes it necessary:**

> **Every rule must be shown not to duplicate one of the 32 rules already
> running.** Measured: run the existing pack and the local rule against the same
> fixture, and confirm ours fires where theirs does not.

Without that, a Python rule set silently re-reports what `p/r2c-bug-scan` already
finds, doubling the noise while appearing to add coverage. The framework half of
this scope is where that risk concentrates — one rule was already dropped from
this design for it, below.

## 3. Two severity tiers

Unchanged from JS/TS. **`ERROR`** where the pattern is a bug regardless of
intent; **`WARNING`/`INFO`** where it is usually a bug but has legitimate uses.
`bug_hunt`'s `severity_min` already filters on this.

## 4. The nine rules

Ids carry the class token, because `mapSubcategory`
(`mcp/src/tools/bugHunt.ts`) classifies by regex over the lowercased id — not by
a lookup table. Format: `bugfix-py-<token>-<name>`, tokens as in the JS/TS
design.

**Avoid the word `unchecked` in `null_safety` names.** The `error_handling`
regex matches it, and the JS/TS set relied on `null_safety` being tested earlier
in the if-chain to win. That is a real dependency on branch order and there is
no reason to take it on again here.

### `error_handling` — 3 rules

- **bare-except** (ERROR) — `try: … except: …`. Catches `SystemExit` and
  `KeyboardInterrupt` along with everything else. The single highest-value
  Python pattern, and absent from the existing 32.
- **except-pass** (ERROR) — `except …: pass`, and `except …: ...` (a literal
  Ellipsis body). The error is discarded with no log, no re-raise, no handling.
- **get-without-doesnotexist** (WARNING) — `.objects.get(…)` not inside a
  `try` that catches `DoesNotExist`. Django raises rather than returning
  `None`, so an unguarded `get` is an uncaught 500 on the first missing row.
  Verified absent from the existing pack.

### `null_safety` — 2 rules, ERROR

- **none-deref-match** — `re.match(…).group(…)` / `re.search(…).group(…)`.
  Returns `None` when nothing matches; this is how it becomes an
  `AttributeError` in production.
- **none-deref-dict-get** — a method or attribute accessed directly on
  `$D.get($K)`, which returns `None` for a missing key.

### `off_by_one` — 1 rule, ERROR

- **range-len-plus-one** — `range(len($X) + 1)` used to index `$X`, and
  `$X[len($X)]`. Zero coverage today.

### `memory_leak` — 1 rule, WARNING

- **open-without-context** — `open(…)` whose result is neither bound by a `with`
  statement nor closed in the same scope.

### `race_condition` — 1 rule, WARNING

- **coroutine-not-awaited** — a call to a function defined `async def` in the
  same file, appearing as a bare statement rather than awaited, returned, or
  passed to `asyncio.create_task` / `gather` / `ensure_future`.

  The direct analogue of JS/TS's `floating-mutation`, which was that set's most
  valuable rule. Python makes it more tractable: `async def` is visible in the
  source, so this does not need the verb-name heuristic that made the JS/TS
  version noisy — which is why this one can key on the definition rather than on
  a guessed list of mutating verbs.

### `edge_case` — 1 rule, WARNING

- **queryset-n-plus-one** — a Django queryset iterated where the loop body
  accesses a related field, without `select_related` or `prefetch_related` on
  the queryset. Verified absent: the pack contains **zero** occurrences of
  `DoesNotExist`, `select_related`, `prefetch_related` or N+1.

### One rule dropped before implementation, which is what §2 is for

**`request` accessed outside its handler context** was in the draft and is
**dropped**: `avoid-accessing-request-in-wrong-handler` already covers it,
confirmed by id in the fetched pack.

It is worth naming rather than quietly omitting, because it is the only reason
§2's no-duplication rule exists as a *tested* requirement instead of an
intention. One of ten draft rules was already redundant before a line was
written; the nine that remain are the ones the measurement supports.

## 5. Where the rules live and how they load

`configs/semgrep/bugfix-py.yml`, beside `bugfix-js.yml`, in the same style:
plain Semgrep YAML, one `rules:` list, messages in Portuguese matching
`base.yml`.

`bug_hunt` already resolves and passes `bugfix-js.yml` through
`resolveBugfixRules()` in `mcp/src/platform/configsDir.ts`. **That resolver
becomes plural** — it returns every `bugfix-*.yml` it finds, so the seven
languages after this one need no further wiring. A missing file is omitted
rather than passed as a bad `--config`, and a malformed one degrades, both as
already built and tested for JS/TS.

## 6. Testing

Identical harness to JS/TS, extended:

- **A fixture pair per rule** under `mcp/test/fixtures/bugfix-py/`, copied to a
  temp directory before scanning — Semgrep's default ignore skips any path named
  `test/`, and scanning in place scans zero files, which makes every assertion
  vacuous.
- **Exact id set per file, plus a raw non-deduplicated finding count per file.**
  The id set alone cannot prove a particular instance still matches while
  another instance of the same rule survives in the same file. That was found
  the hard way on JS/TS.
- **A no-duplication test**, new for this language: for each rule, scan its hit
  fixture with `p/r2c-bug-scan` alone and confirm it produces **no** finding
  there. If it does, the rule is redundant and must be dropped or narrowed.
- **Rule ids asserted against `mapSubcategory`.**
- Skips when Semgrep is absent; fails hard under `GUARDIAN_REQUIRE_SEMGREP=1`.

## 7. Limitations, stated plainly

- **Six of the seven classes.** "Broken happy paths" is a category of
  consequence, not a syntactic shape — unchanged from JS/TS.
- **Semgrep OSS matches syntax, not dataflow.** A `None` that becomes one three
  functions away is invisible.
- **The heuristic tier produces false positives by construction**, which is why
  it is `WARNING`.
- **`queryset-n-plus-one` is Django-specific** and will not fire on SQLAlchemy,
  Peewee or raw DB-API code, where the same bug is just as common.
- **`coroutine-not-awaited` only sees `async def` in the same file.** A
  coroutine imported from elsewhere is not recognised, because Semgrep OSS has
  no cross-file resolution.
- **These rules complement `p/r2c-bug-scan`, they do not replace it.** Both run.
- **They do not replace the model-driven `/guardian-fix` path.**
