# Local bug-finding Semgrep rules — PHP — design of record

**Date:** 2026-08-20
**Status:** approved
**Sixth language probed**, after JS/TS, Python, Go, Java and C#. Rust ships one
rule and Ruby ships nothing — see the
[Rust and Ruby decision](2026-08-20-bugfix-rules-rust-and-ruby-decision.md).

## 1. Six rules ship, six were killed

Measured against a real corpus from the start: **WordPress 6.9 core, 1467 files
scanned**. That is the axis that was permanently `N/A` for C#, and it changed
four verdicts here.

Registry baseline, every control asserted to have fired:

| Pack | On the 12 hit fixtures | Positive control |
| --- | --- | --- |
| `p/r2c-bug-scan` | **`paths.scanned = 0`** — ships no PHP rules at all | fires on a Python control |
| `p/php` | `scanned = 12`, **0 findings** | **9 findings** on 12 classic vulnerable shapes — live and PHP-aware |
| `p/security-audit` | `scanned = 12`, 0 findings | **0 on the vulnerable control too — no positive control** |

`p/security-audit` producing nothing on deliberately vulnerable code is now
measured in **two** languages, C# and PHP. Treat it as a property of that pack,
not a quirk: the only claim it supports is `paths.scanned > 0`.

In-repo overlap: `base.yml`'s PHP rules are all security (`php-eval`,
`php-sql-injection-direct`, `wp-unescaped-output`) and intersect none of the six.

## 2. A fifth governing rule, and it is new

The four inherited ones stand: two fixtures per rule; no duplication of the
registry; write the correct code before the fixture that fires; every fixture
must compile. Added here:

> **Run the whole pack against the prescribed-fix file, not each rule against
> its own.**

The `@`-suppression candidate passed every per-rule check and was killed by
this one. The `toctou-file` rule's own message prescribes "act first and inspect
the return value", whose idiomatic PHP is `@mkdir(...)` / `@unlink(...)`. So in
the file where every bug is rewritten with the fix its own message prescribes,
the pack is silent **except** for three `@`-rule findings, all three on the
`toctou` fix. **One rule firing on another rule's prescribed fix is not a
tuning problem**, and no per-rule check can see it.

## 3. Severity: zero of six at ERROR, and the reason indicts two shipped packs

For scale: Java 1 of 8, JS/TS 1 of 13, Python + Go 2 of 19, C# 2 of 12, PHP
**0 of 6**.

C# reached ERROR twice because one defect (`throw ex;`) has a correct form that
is a *different AST node* — there is no guard to recognise. **No PHP candidate
has that property.**

The closest was `empty-catch`, and real code refuted it. All **10** WordPress
findings are deliberate empty catches carrying explanatory comments — `//Do
nothing` in PHPMailer, `// Do nothing if we cannot memzero` in sodium_compat, a
full paragraph in php-ai-client. Semgrep cannot read comments, and PHP's naming
convention for deliberate silence is *weaker* than Java's or C#'s: modern PHP
declares intent with the **non-capturing** `catch (\Foo) { }`, which this rule
cannot match at all (§5, trap 2) and therefore self-exempts — leaving only the
capturing spelling that real code uses for deliberate silence.

**This has a consequence for work already shipped.** Java and C# both ship
`empty-catch` at ERROR on the premise that an unmarked swallow is a bug whatever
the author meant. Neither measured that premise against real code, because axis
3 was `N/A` for both. PHP is the third language to test it and the first with
data, and the data refutes it. The JS/TS round reached the same conclusion by
the same route — 42 findings on this repo's own source, every one deliberate —
and demoted. **Java and C# should be re-measured against an external corpus
before their ERROR tier is trusted.** Recorded here rather than acted on,
because it is a separate change with its own fixture counts.

## 4. The six rules

Ids follow `bugfix-php-<class-token>-<name>`, checked against the **built**
`mapSubcategory` in `dist/`. Hazardous words: `unchecked` and `concurren` as
always, plus one that is the natural name for a killed rule — **`dangling`
classifies as `memory_leak`**, and "dangling reference" is the PHP manual's own
term for the `foreach`-by-reference bug.

- **`error-handling-empty-catch`** (WARNING) — 6 of 8 spellings, including the
  union catch and the `finally` form. The `finally` dimension is real in PHP
  exactly as in C#: the two try shapes are disjoint nodes, measured before the
  rule was written rather than after. Misses the PHP 8 non-capturing catch,
  which is unmatchable.
- **`off-by-one-loop-lte-count`** (WARNING) — the strongest rule in the pack:
  6 of 6, one known inherited false positive (the sentinel array, whose
  tightening Java already measured and rejected), and **0 on 1467 real files**.
  **PHP is strictly easier here than C# or Java, and this is the round's free
  win:** `count()` is a *global function*, so the domain-object false positive
  that forced `metavariable-type` enumeration in both prior packs cannot arise.
  Measured against a class with both `->length` and a `->count()` method inside
  `<=` loops: silent on both. **No type list is needed and none should be
  added.**
- **`edge-case-strpos-truthiness`** (WARNING) — 7 of 8 spellings. The function
  name filter is load-bearing: without it the same patterns fire on
  `str_contains()`, `str_starts_with()` and `preg_match()` in conditions, all
  correct. 26 findings on WordPress, inspected individually — most are correct
  *by a domain invariant* (a version string cannot start with `-`; an email
  cannot start with `@`), which is the WARNING profile exactly.
- **`race-condition-toctou-file`** (WARNING) — 4 of 4, 0 of 5 near-misses,
  2 true-positive-shaped findings on WordPress. The near-miss corpus carries the
  atomic idioms it must not flag.
- **`null-safety-json-decode-deref`** (WARNING) — with `isset`/`empty`
  exclusions it reaches 4 of 4 hits, 0 of 6 misses and **0 on 1467 files**.
  Note the zero cuts both ways: no false positives *and* no true positives; the
  shape is rare in WordPress.
- **`null-safety-loose-null-compare`** (WARNING) — the weakest claim in the
  pack, and stated as such. WPCS's `WordPress.PHP.StrictComparisons` already
  covers it, so the additive claim holds only where phpcs+WPCS is absent (which
  `scan_wordpress` treats as optional) or outside WordPress entirely.

## 5. What was killed, and by what

| Candidate | Killed by |
| --- | --- |
| `fopen-not-closed` | **inexpressible.** The two ends of the dial are "fires on correct code" (4 false positives of 4 correct shapes) and "fires on nothing" — adding the escape exclusions takes hits to **0 of 3**, because a leaked handle is always *used* by something, so `$F(..., $H, ...)` swallows every true positive. Measured in both directions. |
| `error-suppression-operator` | 420 findings on 1467 files, and it fires on another rule's prescribed fix (§2) |
| `preg-match-groups` | 132 on 1467 files; widening the guard battery only reached 110. The real guards cannot be enumerated — `if (empty($m[0]) &#124;&#124; !is_string($m[0]))`, `isset($match[8])` on a different key — and some regexes cannot fail at all |
| `foreach-ref-not-unset` | 46 findings on WordPress, every sampled one latent rather than live: a style rule, not a bug rule. Narrowing to "reference used after the loop" gives 3 findings, **all 3 false**, and loses the PHP manual's own canonical example (§6, trap 5) |
| `in-array-loose` | 117 on 1467 files, every sampled one string-vs-string. PHP 8 already fixed the famous half (`in_array('abc',[0])` is now false); what remains is numeric-string collision, far rarer than the volume |
| `modify-during-iteration` | **the bug does not exist in PHP.** `foreach` iterates a copy — interpreter-confirmed: unsetting during iteration produces the right array and no exception, appending runs exactly 3 times on a 3-element array, and even `ArrayObject` mutation throws nothing |

**`memory_leak` is an empty class in this pack.** That is worse than C#'s thin
one and is stated rather than implied: resource tracking needs escape analysis
Semgrep OSS does not have.

## 6. Traps, measured

1. **`catch ($E $V)` crashes the Semgrep matcher** on any file containing a PHP 8
   non-capturing `catch (T) { }` — `Internal matching error … NoTokenLocation`,
   exit 2. Matches elsewhere in the file survive, so it reads as partial success
   while the bug in the crashing clause is invisible. **Adding a
   `metavariable-regex` on `$V` suppresses the crash entirely**, measured both
   ways — which is what the shipping rule does, and a fragile thing to depend on.
2. **The PHP 8 non-capturing catch is unmatchable.** Every spelling fails to
   parse. A `pattern-regex` does find them, but cannot carry the naming
   exemption.
3. **A fully-qualified type name matches nothing, silently.**
   `catch (\RuntimeException $E)` found **0** occurrences of source reading
   `catch (\RuntimeException $e)`. Bind the type to a metavariable instead. This
   is the PHP twin of C#'s "always write `var`": every gate green,
   `paths.scanned` healthy, `errors: 0`, answer zero.
4. **`?->` and `->` are the same node** — confirmed behaviourally in both
   directions and by `--dump-ast`. So `pattern-not: $V?->$M` deletes the rule
   instead of excluding the safe idiom; the only escape is
   `pattern-not-regex: '\?->'`. Identical in shape to Ruby's erased `&.` and
   C#'s erased `using`.
5. **A metavariable bound in a `foreach … as $V` header will not unify with a
   second `foreach … as $V` header** — the loop variable is a definition
   position. This is what makes the PHP manual's own dangling-reference example
   inexpressible.
6. **The deep-expression operator does not parse inside a PHP block.** Use
   `{ ... stmt; ... }`.
7. **Prefer the statement ellipsis to a braced body.** `for (...) ...` matches
   the braced body, the brace-less body **and** the `for(): … endfor;`
   alternative syntax; `for (...) { ... }` matches only the first. Free recall.
8. **Two more YAML routes to `paths.scanned = 0`:** an unquoted ternary (` : `
   reads as a mapping), and `\R` inside a double-quoted scalar (unknown escape,
   invalidates the whole config).
9. **A long Windows path scans nothing.** The corpus at a deep scratchpad path
   gave `Failed to obtain target files from semgrep-core`, `paths.scanned = 0`,
   exit 2; copying the identical tree to a shorter path fixed it. Since this
   repo's gate is "fail on `paths.scanned == 0`", it is worth knowing a long
   path trips it and the message points nowhere near the cause.
10. **Semgrep's PHP parser is behind the language** — `const VOID = 'void';`
    inside a class is a syntax error, so one real WordPress file is invisible.
    Reported in `errors[]`, so not silent.

## 7. Testing

The C# harness shape, unchanged: fixture pair per rule, exact id set and raw
non-deduplicated count and `paths.scanned` asserted per file,
`EXPECTED_SEVERITY` exhaustive in both directions, ids checked against the built
classifier, a no-duplication proof whose positive control is asserted to have
fired, and `php -l` over every fixture (`php:8.3-cli`) — which already caught one
fixture defining a function named `pos()`, a PHP builtin.

Plus, new this round and per §2: **a whole-pack scan of the prescribed-fix
file**, asserted to produce zero findings.
