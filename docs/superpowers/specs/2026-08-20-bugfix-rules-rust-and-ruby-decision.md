# Local bug-finding Semgrep rules — Rust and Ruby — decision of record

**Date:** 2026-08-20
**Status:** decided — **no Ruby pack; a single-rule Rust pack**
**Last in the per-language sequence**, after JS/TS, Python, Go, Java and C#.

## The decision

Twenty-four candidates were measured across the two languages. **Twenty-three
were killed.** One ships.

- **Ruby: nothing ships.** Four of the six subcategories cannot be covered at
  all, and the three rules that survive precision testing find **zero findings
  across 1244 files of real Ruby**.
- **Rust: one rule ships**, `blocking-sleep-in-async`, in a
  `configs/semgrep/bugfix-rs.yml` whose header says plainly what it is.

Neither is a scoping or budget decision. Both are measurements, and this
document exists mainly to record what was measured, because "we did not get to
it" and "we measured it and the answer is no" are different claims and only one
of them is true here.

## 1. Rust: the flagship classes are compile errors

Written out and fed to `rustc --edition 2021`:

| The rule that anchors this class in Java / C# / Go | Rust |
| --- | --- |
| modify-during-iteration | **E0502** — cannot borrow `*v` as mutable |
| use-after-free / dangling reference | **E0515** — cannot return reference to local |
| data race on shared mutable state | **E0373** + **E0503** |
| null dereference | **E0599** — no method `len` on `Option` |

The flagship rule of `edge_case`, of `memory_leak`, of `race_condition` and of
`null_safety` are each rejected by the compiler. Not rare — impossible.

### What ships, and why exactly one thing does

**`bugfix-rs-race-condition-blocking-sleep-in-async`** — `std::thread::sleep`
inside an `async fn`, which blocks the executor thread and stalls every other
task scheduled on it.

- Fires 4 of 4. Silent on the same call in a sync `fn`, and silent on the fix
  its own message prescribes.
- **Invisible to the entire Rust toolchain** — nothing at default, pedantic,
  nursery or restriction level catches it.
- What it emits is always a bug. The nearest legitimate shape, a deliberately
  blocking helper, is not written as an `async fn`.

A single-rule pack is a strange artifact, so the file header says it is the
residue of a probe that killed twelve candidates, and points Rust users at
`cargo clippy` for everything else.

### The two candidates that would have passed a full round

This is the strongest evidence the series has produced for the real-code axis.
Both had clean fixtures, silent near-misses, and a prescribed fix that works:

- **`mem-forget`** — **43 findings on 870 files of real standard library, zero
  true positives.** The spot checks are `alloc/rc.rs` (`Rc::into_raw`) and
  `std/thread/mod.rs`: the textbook ownership transfer.
- **`unwrap-in-drop`** — on real code it flags
  `if !thread::panicking() { result.unwrap(); }`, which is the **canonical
  mitigation** for panicking in a `Drop`. The rule accuses the fix.

Both would have shipped under a C#-style round, where axis 3 was permanently
`N/A` for lack of C# source in this repo. For Rust the axis is free —
`rustup component add rust-src` yields 870 files — and it is what turned the
answer from "three rules" into "one".

### The Rust near-miss worth naming

`guard-across-await` is *more precise* than the clippy lint it duplicates: 5
true positives and 0 false, against `clippy::await_holding_lock`'s 5 and 2. It
still does not ship. Duplicating a **default-on** lint to win two false
positives is not worth a rule that has never been measured against real async
Rust, and the corpus contains none.

## 2. Ruby: the frontend erases the operators that write the correct code

`metavariable-type` **does not exist for Ruby** — `Rule parse error`, exit 2. So
every type-restricted rule that carried the C# pack is unavailable: no receiver
typing, no way to tell an Array from a Hash from a domain object.

That alone would have been survivable. These two are not:

- **`&.` is erased.** `x&.ccc.ddd` and `x.ccc.ddd` produce **byte-identical**
  ASTs. Since `&.` is Ruby's canonical nil guard, every unguarded-deref rule
  fires on the fix its own message prescribes. In a language whose signature
  runtime error is `NoMethodError: undefined method for nil`, `null_safety` is
  closed.
- **`..` versus `...` is erased.** Both become the same range node with no
  inclusivity flag, so an off-by-one rule for `(0..a.length)` fires on
  `(0...a.length)` — again, on the correct form.

### Five candidates that passed their fixtures and were killed by real code

| Candidate | Fixtures | On 1244 real files |
| --- | --- | --- |
| empty-rescue | 14/14, 0 FP | **150**, overwhelmingly correct |
| rescue Exception | 5/5, 0 FP | **79** — 32 re-raise or wrap, 6 exit |
| `rescue nil` | 6/6, 0 FP | **52** — best-effort cleanup and coercion probes |
| File.open unclosed | 3/3 | **28** — including `File.open(path, "rb", &block)`, the correct block form |
| unsynchronised thread state | 3/3 | **4, all false** — `thread[:k] = v` is thread-*local* storage, the safe idiom |

**Empty-rescue is the one that decides it**, because it is the rule C# earned
`ERROR` with. C# clears the bar because its escape hatch is a declaration of
intent the rule can read: `catch (E ignored)`. Ruby has a *better* hatch in
principle — `rescue => _e`, the language's own unused-variable convention, and
it was measured working. But **146 of the 150 real findings use the anonymous
spelling** (`rescue LoadError`, bare `rescue`), where there is no variable to
name. The hatch covers **2.7 %** of real occurrences.

### And the C# ERROR rule that has no Ruby analogue at all

`rethrow-loses-stacktrace` does not port, because **the bug does not exist**.
Interpreter-verified: both `raise e` and a bare `raise` preserve the original
backtrace. The one rule in the series that cleared the severity bar for a reason
that was not a guard has nothing to match in Ruby.

### The three precise rules that find nothing

`modify-during-iteration`, `$A[$A.length]`, and `while $I <= $A.length` are all
precise — 0 or 1 false positives across eleven correct methods — and all three
return **zero findings on 1244 files**. Three rules that find nothing is not a
pack.

Worth recording from that work: Ruby block-parameter **arity is respected**
(`|$X|` does not match `|k, v|`), which is the only type proxy the language
offers Semgrep. It is what makes the `modify-during-iteration` rule precise, by
excluding two-parameter Hash iteration — which the interpreter confirms is legal.

## 3. Three more silent-failure modes, and one is the most transferable yet

The series had six. These take it to nine, and the third belongs in every future
round.

- **Rust: the trait name in `impl Trait for Type` is ignored.**
  `impl ThisTraitDoesNotExist for $T` matches the same 14 blocks as
  `impl Drop for $T`, inherent impls included, with healthy `paths.scanned` and
  zero errors. Any rule anchored on `impl Drop` / `impl Iterator` /
  `impl Future` silently applies to the whole codebase. Anchor on the method.
- **Ruby: `&.` and `..`/`...` are erased**, as above — the rule matches the
  correct code and the buggy code identically.
- **An `AND` of mutually exclusive patterns validates clean and matches
  nothing.** A `patterns:` block assembled with one clause mis-indented produced
  `Configuration is valid — found 0 configuration error(s), and 9 rule(s)`,
  healthy `paths.scanned`, `errors: 0` — and **0 of 14 bugs** that its own
  individual patterns had just matched. Nothing diagnoses it.

That last one is why the ablation harness now asserts **non-empty hits per
rule**. `paths.scanned` cannot see it; `--validate` cannot see it; only "did this
rule fire on its own hit fixture at all" can.

Two further Rust notes for whoever revisits: `PartialParsing` files count as
scanned (16 of 870, at `level=warn`, clean exit — macro-heavy Rust degrades
silently), and `async fn $F(...) -> $R` is the **narrow** form, finding 2 of 4
bugs where `async fn $F(...)` finds all four. That is C#'s `$T $V` versus `var`
trap in a second language, which makes it a rule rather than a curiosity:
**before porting a rule to a new language, check whether the pattern's optional
syntax is acting as a filter.**

## 4. Registry, with positive controls

| Pack | Rust | Ruby |
| --- | --- | --- |
| `p/r2c-bug-scan` | `paths.scanned = 0` — no Rust rules | `paths.scanned = 0` — no Ruby rules |
| `p/rust` / `p/ruby` | scanned, 0 findings; control fired | scanned, 0 findings; control fired **8 times** |
| `p/security-audit` | 0 findings, **and no working control** | 3 on the control |

Both packs *would* have been additive against the registry. It is the compiler,
`clippy`, and Semgrep's own Ruby frontend that leave no room — not the registry.
That distinction is why this document says "no" rather than "already covered".

Note `p/security-audit` failing to fire on a deliberately vulnerable file for the
**second** language running, after C#. Two languages now where that pack has no
demonstrable positive control.

## 5. What to tell users instead

- **Rust:** configure `clippy`. Default already covers `await_holding_lock`;
  `-W clippy::pedantic` adds `float_cmp`, `future_not_send`,
  `missing_panics_doc`; the restriction group, opt-in lint by lint, adds
  `unwrap_used`, `mem_forget`, `indexing_slicing`, `string_slice`,
  `let_underscore_must_use`. The type-aware ones beat every Semgrep equivalent
  measured here. dev-guardian adds exactly one rule clippy does not have.
- **Ruby:** RuboCop, and the registry's `p/ruby`, which fired 8 times on an
  11-shape vulnerable file and is a genuinely live pack. dev-guardian adds
  nothing, and says so.

## 6. Where this leaves the series

Five packs ship: JS/TS 13 rules, Python 10, Go 9, Java 8, C# 12 — plus one Rust
rule. Three languages were probed and two of them returned "no".

The series ends with more measured negatives than the first four rounds
produced, which is the intended direction. The Java round shipped eight rules
and then needed nine fix waves; the C# round shipped twelve and needed none; the
Rust and Ruby rounds shipped almost nothing, on purpose, because the probes
found out before the specs did.
