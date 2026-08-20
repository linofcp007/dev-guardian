# Local bug-finding Semgrep rules — Python — design of record

**Date:** 2026-08-18
**Status:** approved, then corrected by measurement (§8), then **partly
superseded by the 2026-08 audit** — still ten rules, but severity was
re-assigned across the whole pack by what each rule EMITS rather than by bug
class, leaving `none-deref-match` as the only `ERROR`, and six rules were
re-worked to close ~22 measured false positives. See `CHANGELOG.md` and the
rule comments in `configs/semgrep/bugfix-py.yml`.
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

So Python does not need fourteen rules. It needs **ten, aimed at measured
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

**Both were discharged before this document was finalised**, not deferred to
implementation — see §8.

## 3. Two severity tiers

Unchanged from JS/TS. **`ERROR`** where the pattern is a bug regardless of
intent; **`WARNING`/`INFO`** where it is usually a bug but has legitimate uses.
`bug_hunt`'s `severity_min` already filters on this.

## 4. The ten rules

Ids carry the class token, because `mapSubcategory`
(`mcp/src/tools/bugHunt.ts`) classifies by regex over the lowercased id — not by
a lookup table. Format: `bugfix-py-<token>-<name>`, tokens as in the JS/TS
design.

**Avoid the word `unchecked` in `null_safety` names.** The `error_handling`
regex matches it, and the JS/TS set relied on `null_safety` being tested earlier
in the if-chain to win. That is a real dependency on branch order and there is
no reason to take it on again here. **Verified**: no id below contains
`unchecked`, and all ten were run through the real `mapSubcategory` and land in
their own class.

### `error_handling` — 3 rules

- **bare-except** (ERROR) — `try: … except: …`. Catches `SystemExit` and
  `KeyboardInterrupt` along with everything else. The single highest-value
  Python pattern, and absent from the existing 32.
- **except-pass** (ERROR) — an `except` clause whose entire body is `pass`, or
  is a literal `...`. Covers the bare, plain and `as`-bound clause forms —
  **five pattern branches**, because `except $E:` does not match
  `except $E as $V:` and the literal-Ellipsis body needs a different
  construct entirely (§8).
- **get-without-doesnotexist** (WARNING) — `.objects.get(…)` not inside a
  `try` that catches the miss. Django raises rather than returning `None`, so
  an unguarded `get` is an uncaught 500 on the first missing row. **Three**
  exclusion clauses, not one: `except $X.DoesNotExist`, bare
  `except ObjectDoesNotExist` (the `django.core.exceptions` import form) and
  `except Exception`. All three are correct code and all three must stay
  silent.

### `null_safety` — 2 rules, ERROR

- **none-deref-match** — `re.match(…).group(…)`, `re.search(…).group(…)`,
  `re.fullmatch(…).group(…)`. Returns `None` when nothing matches; this is how
  it becomes an `AttributeError` in production.
- **none-deref-dict-get** — a method called directly on `$D.get($K)`, which
  returns `None` for a missing key. Excludes the two-argument (defaulted) form,
  and excludes HTTP clients by receiver name — `requests.get(url).json()` is
  the same syntax and is not a bug.

### `off_by_one` — 1 rule, ERROR

- **range-len-plus-one** — `for … in range(len($X) + 1):` **where the index
  subscripts that same sequence**, and `$X[len($X)]`. Zero coverage today.

### `memory_leak` — 1 rule, WARNING

- **open-without-context** — a local variable bound to `open(…)` that is
  neither inside a `with` nor closed in the same scope. Attribute targets
  (`self.handle = open(…)`) are excluded: the close lives in another method,
  which is out of a syntactic rule's reach, so firing there would be a guess.

### `race_condition` — 2 rules, WARNING

- **asyncio-not-awaited** — `asyncio.sleep/gather/wait/wait_for` appearing as a
  bare statement: not awaited, not returned, not assigned. The forgotten
  `await` is Python's closest analogue to JS/TS's `floating-mutation`, and
  keying on these four names rather than on a guessed verb list makes it
  precise instead of heuristic.
- **toctou-exists-open** — `if os.path.exists($P):` with `open($P, …)`
  anywhere inside the branch, whether or not other statements precede it. A
  textbook time-of-check/time-of-use race, and the reason the correct idiom is
  to open and catch `FileNotFoundError`.

  **These two replace a rule that could not be built** — see §8.

### `edge_case` — 1 rule, WARNING

- **queryset-n-plus-one** — a Django queryset iterated by a `for` statement
  where the loop body reaches through a relation, without `select_related` or
  `prefetch_related`. Covers both `.all()` and `.filter(…)`. Verified absent
  from the pack: **zero** occurrences of `DoesNotExist`, `select_related`,
  `prefetch_related` or N+1 anywhere in its 32 rules.

### Two rules dropped before implementation, which is what §2 is for

**`request` accessed outside its handler context** was in the draft and is
**dropped**: `avoid-accessing-request-in-wrong-handler` already covers it,
confirmed by id in the fetched pack.

**`coroutine-not-awaited` as originally specified is dropped too**, for a
different reason — it is not expressible in Semgrep OSS (§8).

Both are worth naming rather than quietly omitting. The first is the only
reason §2's no-duplication rule exists as a *tested* requirement instead of an
intention: one of ten draft rules was already redundant before a line was
written. The second is the reason §8 exists at all.

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
- **A no-duplication test**, new for this language: scan the hit fixtures with
  `p/r2c-bug-scan` alone and confirm it produces **no** finding on any of them.
  A finding there means either the rule is redundant (drop or narrow it) or the
  fixture carries an incidental second bug (make the fixture minimal). Which of
  the two it was must be stated, not assumed.
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
  Peewee or raw DB-API code, where the same bug is just as common. It also
  **only matches `for` statements** — the same N+1 written as a list
  comprehension is not caught, measured directly. It also **requires the
  queryset inline in the `for` header** — `qs = Book.objects.all()` followed
  by `for book in qs:` is silent, and that variable-bound form is arguably
  the commoner real-world shape.
- **`toctou-exists-open` keys only on `os.path.exists`.**
  `os.path.isfile(...)`, `os.path.isdir(...)` and `pathlib.Path(p).exists()`
  are all silent, measured directly.
- **No general "coroutine not awaited" rule exists**, only the four named
  `asyncio` primitives. A forgotten `await` on a project's own `async def` is
  the commonest form of this bug and is **not** covered — §8 explains why not.
- **`none-deref-dict-get` excludes HTTP clients by receiver name SUBSTRING,
  not name.** The `metavariable-regex` is
  `^(?!.*(requests|session|client|httpx|aiohttp|urllib)).*$`, which matches
  on substring, not identifier equality — so any receiver whose name
  *contains* one of those six substrings is skipped, not only a receiver
  named exactly one of them. Measured: `session_data.get("a").strip()` and
  `clients.get("a").strip()` are both silently skipped, so `session_data`,
  `clients` and `urllib_cache` are false negatives too, not only a dict bound
  to the bare name `client`.
- **`get-without-doesnotexist` treats a broad `except Exception:` as a guard.**
  Its three exclusions are `except $X.DoesNotExist`, bare
  `except ObjectDoesNotExist` and `except Exception`. The third is deliberate —
  a broad handler really does catch the miss — but it means a `.objects.get()`
  wrapped in `except Exception: pass` is silent here, even though that is worse
  code than an unguarded `get`. `bugfix-py-error-handling-except-pass` catches
  the swallowing separately; nothing joins the two observations up.
- **`open-without-context` never flags attribute targets.**
  `self.handle = open(path)` is excluded by design, because its `close()`
  usually lives in another method and a syntactic rule cannot see across
  methods. The cost is that a class which genuinely never closes its handle is
  a false negative, and that is the commonest way a long-lived file leak
  actually looks.
- **These rules complement `p/r2c-bug-scan`, they do not replace it.** Both run.
- **They do not replace the model-driven `/guardian-fix` path.**

## 8. What measurement changed, before any of it was built

Every rule above was written as a probe and run against a hit fixture and a
near-miss fixture with Semgrep 1.164.0 **before this document was finalised**.
Seven of the nine originally specified rules fired correctly first time. The
other two did not, and one of those turned out to be impossible. The JS/TS round
shipped six constructs that read as guards and did nothing; probing first is the
answer to that, and it changed seven things here.

**One rule is not expressible and was replaced.** `coroutine-not-awaited` —
"a call to a function defined `async def` in the same file, appearing as a bare
statement" — was to be the analogue of JS/TS's most valuable rule. Semgrep OSS
cannot express it. The sequence pattern (`async def $F: …` / `…` / `$F(…)`)
*does* match, which is exactly the trap: it reports at the **definition** line
rather than the call, and no exclusion clause bites, so it fires identically on
`await persist(r)`, `return persist(r)` and `asyncio.create_task(persist(r))`.
A `focus-metavariable` + `metavariable-pattern` formulation fixes the span and
still fires on all three. Both were measured, not reasoned about. The two
`race_condition` rules in §4 are what replaced it — narrower, but real.

**Six rules needed correcting, and each correction came from a near-miss that
fired:**

| Rule | As designed | What measurement forced |
| --- | --- | --- |
| `except-pass` | one pattern | five branches — `except $E:` does not match `except $E as $V:`, and a literal `...` body needs `metavariable-regex` on a `$BODY` metavariable (I had assumed it was inexpressible; it is not) |
| `get-without-doesnotexist` | exclude `except $X.DoesNotExist` | exclude `ObjectDoesNotExist` and `except Exception` too — both fired, both are correct code |
| `queryset-n-plus-one` | `.all()` | `.filter(…)` as well, which is the commoner form |
| `none-deref-dict-get` | `$D.get($K).$M(…)` | a receiver-name exclusion — `requests.get(url).json()` fired |
| `open-without-context` | not closed in scope | exclude attribute targets — `self.handle = open(…)` fired, and its `close()` is unreachable to a syntactic rule |
| `range-len-plus-one` | `range(len($X) + 1)` **used to index** `$X` | **the design was right and my correction was wrong** — I dropped the indexing requirement citing zero false positives, but no near-miss fixture contained `range(len(x) + 1)` at all, so the measurement was vacuous. The loose form fires on `for i in range(len(a) + 1): dp[i] = i`, the ordinary DP-seeding idiom. Restored, and a near-miss now covers it. |

**Final state, measured on the ten-rule set:** 18 findings across 10 hit
fixtures, each firing exactly its own rule and nothing else; **zero** findings
across all 10 near-miss fixtures; **zero** findings from `p/r2c-bug-scan` on any
hit fixture, so every one of the ten is additive rather than duplicative; and
all ten ids classify into their own class through the real `mapSubcategory`.
