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

### Zero rules in eight clear the bar, and that is the honest result

Applied cold, the criterion leaves **all eight at `WARNING`.** That looks
alarming until you notice what it is measuring: Semgrep OSS matches syntax and
has no dataflow, so *almost nothing* clears a bar that says "always a bug".
Zero in eight is what this engine can honestly claim here, not a failure of the
pack.

`empty-catch` was the last one at `ERROR`, and it held that tier for three
rounds on a reason worth stating precisely, because it was the only reason
available: **its escape hatch is not a guard.** It is a *declaration of intent*
that the rule itself reads — the Checkstyle / IntelliJ convention of naming the
variable `ignore`, `ignored` or `expected`. Having honoured that, what the rule
emits would be an *unmarked* silent swallow, and that is a bug whatever the
author meant.

The argument is sound and the premise is false. See
[§4a](#4a-the-empty-catch-premise-measured-against-openjdk) — the round that
finally measured it.

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
integration test pins all eight rules, exhaustive in both directions, and that
round's change was made **RED first**: the four flips failed the test before the
YAML was touched, which is the entire point of having pinned it.

The §4a flip was verified the same way, in the other direction: with the YAML
already at `WARNING`, putting `'ERROR'` back into `EXPECTED_SEVERITY` fails
`reports each rule at its DESIGNED severity tier`, and restoring `'WARNING'`
passes. The pin is load-bearing rather than decorative, demonstrated rather than
asserted.

The tier is not cosmetic, and with eight of eight at `WARNING` the consequence
is now the headline rather than a footnote. The parser maps `ERROR → high` and
`WARNING → medium`. `bug_hunt`'s `severity_min` is optional, so **nothing
vanishes from a scan**. But `create_fix_pr` defaults `severity_min` to `high`,
so the Java pack now contributes **nothing at all to the default fix-PR set**.
A caller who wants Java bugs fixed has to ask for them:
`severity_min: "medium"`.

`create_fix_pr`'s default was deliberately **not** changed here. It affects all
four language packs and is a separate decision, queued for the round that
sweeps the shipped packs together.

## 4a. The `empty-catch` premise, measured against OpenJDK

`empty-catch` shipped at `ERROR` on this premise: *an empty catch that does not
declare intent is a bug whatever the author meant.* Three rounds accepted it
without measuring it, because the ablation harness reported axis 3 as `N/A` for
this pack — there is no Java in this repository to use as a real-code corpus.
This round got one.

**Corpus.** OpenJDK, `github.com/openjdk/jdk` at `e296cefb`, shallow sparse
clone of `src/*/share/classes` — 12 596 `.java` files of product source that
nobody here wrote or picked for its shapes. Semgrep 1.164.0 scanned **12 593**
of them; the three-file gap is unexplained — the run reports only 12
`PartialParsing` warnings and no hard error. `paths.scanned > 0` was asserted,
because a zero there is a broken run and not a clean result. The first attempt, running
the whole pack, was killed by the OS for memory and reported
`paths.scanned: []` with exit 2 — caught by that assertion, not by reading the
finding count.

**Raw count: 1589 findings in 770 files.** That is one empty catch per eight
files of the Java standard library.

**The split, and it is not close.**

| | count | share |
| --- | ---: | ---: |
| findings carrying an explanatory **comment inside** the empty catch | 903 | 56.8 % |
| findings with a comment on the line immediately **before the `try`** | 169 | 10.6 % |
| findings declaring intent in a **name the rule does not read** | 27 | 1.7 % |

A block containing only a comment is *empty to the AST*, which is why those 903
fire at all. Sampled from the comment-bearing stratum, in the corpus's own
words: `// ignore` (`com/sun/jndi/ldap/Ber.java:63`), `// Expected or ignored`
(`sun/security/pkcs/SignerInfo.java:350`), `// swallow, since it should never
happen` (`sun/security/krb5/internal/crypto/DesMacCksumType.java:104`), `//
Ignoring exception causes specified default to be returned`
(`java/util/prefs/AbstractPreferences.java:693`), `// All exceptions are
ignored.`
(`com/sun/org/apache/xerces/internal/dom/DocumentImpl.java:814`), `// no op`
(`.../XML11DTDConfiguration.java:811`), `// fall through`
(`java/beans/PropertyDescriptor.java:590`). Two of the 25 sampled comments are
*not* declarations of deliberate silence and are the genuine article: `// Should
do something reasonable`
(`javax/swing/text/html/HTMLDocument.java:3842`) and `// TODO should this
throw?` (`.../bcel/internal/classfile/CodeException.java:130`) — an
acknowledged defect is still a defect.

The 27 that name their intent name it in a vocabulary this rule does not carry:
**`cannotHappen` ×13, `_` ×10, `unused` ×2, `ignored0` / `ignored1` ×1** (the
regex is anchored, so a suffix fires). `_` is Java 21's *unnamed variable*, and
it means precisely "I do not use this binding" — the same erosion ES2019
optional catch binding caused in JS/TS, arriving in Java from the other
direction.

**How much does the convention the tier rested on actually cover?** Measured
rather than assumed, with an inverted-regex probe (`^(ignore|ignored|expected)$`)
over the same corpus: **139** intent-named empty catches — `java/lang/
ClassLoader.java:715`, `java/lang/Module.java:1669`,
`java/net/HttpCookie.java:1000` among them. So the corpus holds 139 + 1589 =
1728 empty catches, and the convention covers **8.0 %** of them. It is real,
unlike JS/TS's, and it is not how Java is written. (Ruby's equivalent spelling
measured 2.7 %.)

**Read individually: 20 from the no-comment stratum (643 findings, the hardest
case for "deliberate"), 25 from the comment-bearing one.** Roughly 39 of the 45
are deliberate. The no-comment ones are deliberate by *shape* rather than by
prose — the Swing veto idiom (`javax/swing/DefaultDesktopManager.java:247`,
`javax/swing/plaf/basic/BasicInternalFrameUI.java:870`: a
`PropertyVetoException` means "do not select", and there is nothing to log), a
`close()` in a `finally` (`sun/awt/image/ImageDecoder.java:171`,
`sun/jvm/hotspot/HotSpotTypeDataBase.java:383`), a parse probe that falls
through to a default (`com/sun/java/swing/plaf/gtk/PangoFonts.java:224`), a
reflection probe (`com/sun/org/apache/xpath/internal/XPathContext.java:323`),
a try-the-next-provider loop (`java/security/SecureRandom.java:979`), a
checked-exception ceremony on a constant that cannot throw
(`sun/print/ServiceDialog.java:390`), and exceptions used as loop control
(`com/sun/org/apache/xerces/internal/impl/xs/XSConstraints.java:1376`). The
genuine swallows in that stratum: `jdk/internal/access/SharedSecrets.java:503`
(a failed `ensureInitialized` vanishes),
`com/sun/org/apache/xerces/internal/dom/DOMConfigurationImpl.java:777` (a
resolver silently not set), `sun/tools/jconsole/inspector/XTextFieldEditor.java:148`
(`catch(Exception e) {}` around an initialiser), and
`sun/font/Type1Font.java:224` (an empty `FileNotFoundException` catch that
leaves `raf` null and relies on the `NullPointerException` catch below it).

**The verdict.** The premise fails on its own terms. The intent *is* declared —
903 times, in a comment Semgrep cannot read, and 27 more times in a name it does
not carry. "Unmarked" was the load-bearing word and it is wrong. That is the
severity criterion applied, not an exception to it: a declaration of intent the
rule cannot recognise is exactly what `WARNING` is for. Java is the fourth
language to test this premise and the fourth to refute it.

**What was *not* done.** The exemption list was not widened to `_`,
`cannotHappen` and `unused`, though `_` is a strong candidate. Every word added
is another way for a real swallow to escape by being well named, and with the
tier moved the list no longer has to carry the argument. The patterns were not
touched either: the rule's recall is unchanged and only its tier moved.

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
| `empty-catch` | WARNING | Demoted in §4a, after the first external corpus this pack has ever had. It does not depend on recognising a guard, and that argument held it at `ERROR` for three rounds — but on OpenJDK 903 of its 1589 findings declare their intent in a **comment**, which Semgrep cannot read, and the name it *can* read covers 8.0 % of the corpus's empty catches. "Unmarked" was the load-bearing word and it is wrong. |
| `printstacktrace-only` | WARNING | In a throwaway `main`, printing and continuing is a legitimate choice. |
| `map-get-deref` | WARNING | Correctness depends on 26 guard exclusions. Each exists because correct code was firing; the list closes the shapes someone enumerated, never the next one. |
| `optional-get-no-ispresent` | WARNING | Same, demoted a round earlier. Applying the argument to one of these two and not the other was the inconsistency §4 closes. |
| `loop-lte-length` | WARNING | An inclusive loop that never indexes the array, or that fills a longer one, is correct. The tightening was tried and rejected — see §8. |
| `stream-not-closed` | WARNING | A stream closed in a `finally` is correct and this rule cannot see it. |
| `static-dateformat` | WARNING | A shared formatter behind `synchronized` access is correct, and proving *all* accesses are synchronized is whole-program analysis. |
| `modify-during-iteration` | WARNING | Correctness depends entirely on having recognised the exit that makes the removal safe; two statements between removal and exit is enough to accuse correct code. |

### `error_handling` — 2 rules, both WARNING

- **empty-catch** (**WARNING**, demoted in §4a) — `try { … } catch (E e) { }`.
  The exception was caught and discarded with no log, no rethrow, no handling.
  **Except when the variable is named `ignore`, `ignored` or `expected`.**
  A deliberate, documented empty catch is a real idiom, but the comment that
  documents it is not in the AST — so a commented ignore and a silent swallow
  are byte-identical to Semgrep, and the comment can never be the escape hatch.
  The *name* can: those three are Checkstyle's and IntelliJ's conventions for
  exactly this, so honouring them gives users a tool-standard way to say
  "deliberate" without a suppression comment. Every other name still fires.
  **That escape hatch is why the rule sat at `ERROR`, and §4a is why it no
  longer does**: on OpenJDK the convention covers 8.0 % of empty catches while
  56.8 % of the findings declare intent in a comment instead. The hatch stays —
  it is still the only way to silence one case in code rather than with
  `// nosemgrep` — but it does not carry a tier.
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
  their De Morgan duals `!containsKey || …` and `get() == null || …` (4), each
  of those four again as a **chain** with something short-circuiting in front
  of the guard (4, wave 8); the
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

  **Iteration over the map's own `keySet()`** is wave 7, and it is the last
  false-positive class the review found: `for (String k : m.keySet()) { …
  m.get(k).trim() … }` is the commonest map-iteration idiom in Java, the loop
  header binds the key *from the map itself* — so presence is guaranteed on
  every syntactic path reaching the dereference, by the same standard that makes
  `containsKey` an acceptable guard — and it was neither excluded nor listed as
  an accepted limitation. **One clause** (1), not the braced/braceless pair
  every `if` guard carries, and that is measured rather than assumed: the
  deref-requiring pair and a plain `for (…) { … }` each close the braced shapes
  and leave the braceless one firing, while writing the body as a bare statement
  ellipsis — `"for ($T $K : $M.keySet()) ..."` — closes both at once, so a pair
  would have been half inert. It is also *not* arm-scoped, and that is the
  difference from every `if` guard above: a for-each has no `else` arm, the
  whole body runs with the key present, so excluding the matched node entirely
  is exactly right here.

  It **unifies both metavariables** — `$M` forces the map iterated to be the map
  dereferenced, `$K` forces the loop variable to be the key passed to `get` —
  and `b13` / `b14` in `hits/RealBugs.java` break one unification each and must
  keep firing. Measured over the five correct-code shapes the reviewer wrote, it
  closes three (the plain loop, the `this.`-qualified loop, and the loop whose
  dereference is nested inside an `if`) and leaves two, which are accepted
  limitation (11): `for (Map.Entry<K,V> e : m.entrySet()) { … m.get(e.getKey())
  … }`, where the key is not the loop variable, and the key set copied to a
  local first, where the loop header no longer mentions `keySet()`.

  **The chain clauses are wave 8, and the finding under them is worth more than
  the clauses.** `flag && m.containsKey(k) && m.get(k).isEmpty()` is ordinary
  correct Java, and it fired, because every expression clause bound the guard to
  one operand of a *two*-operand expression. What makes ONE extra clause per
  guard sufficient is that **`$X` matches the whole left-nested subtree, not an
  operand**: a Java conjunction nests to the left, so `$X && GUARD && DEREF`
  matches a chain of *any length* whose last-but-one operand is the guard. A
  second clause for longer chains would be inert — measured, the four-operand
  shapes are closed by the same clause as the three-operand ones.

  This sat in the limitations table as an accepted false positive for several
  waves, under two successive justifications, and **both were reasoning about a
  variable that does not control the outcome**: first "an extra clause removes
  one of two findings and the line still fires", measured on a line that
  happened to carry two `get()` calls; then "one clause leaves 4+ operand chains
  firing", which made chain *length* the discriminator. Nobody had looked at what
  `$X` matches. The row was deleted rather than reworded — a row recording a
  deferred decision on a false premise reads as considered, which is worse than
  no row. What still fires and is genuinely a bug: a chain guarding a **different**
  key or Optional, a **positive-first** disjunction (the dereference runs
  precisely when the test was false), a **negated** guard in a conjunction, and
  a chain whose guard is not last-but-one because it guards two things at once.
  All pinned as `b15`–`b20` in `hits/RealBugs.java`.

  A note that cost a measurement: `metavariable-type` resolves a `this.`-
  qualified field only when the field's **declaration precedes** the method in
  source order. The `this.`-qualified `keySet()` near-miss was silent under the
  *pre-fix* rule until it was moved below the field declaration, which would
  have made it a fixture that could never fail.
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
  disjunctions `!isPresent() || …` and `isEmpty() || …` (3), each again as a
  **chain** (3, wave 8); the early-exit forms
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

`hits/RealBugs.java` (14 defects), `hits/ElseArm.java` (8) and
`hits/IterationBugs.java` (6) close it. All three were written by the
**reviewer**, not by the rule author, which is §3 applied to hits rather than to
misses: they are dense files of defects placed deliberately *next to* the guard
shapes the exclusions match — the `else` arm of a guard, the arm a ternary
condition rules out, a disjunction that proves nothing, a guard on a different
key, a `switch` whose `break` leaves only the switch. Their counts are asserted
per file like any other, and the per-file assertions are backed by a **total**,
so a finding landing in a file nobody registered moves a number too.

The ablation step gains a second axis with them: deleting a clause must make a
near-miss fire (the clause is live) **and** must leave the hits count unmoved (the
clause does not eat a real bug). A clause being live proves it does something; it
never proved it does not also do that.

**Which rules the corpus covers is now stated, because it was measured and it
was not all of them.** Wave 7 counted it: `map-get-deref` 9, `optional-get` 6,
`loop-lte-length` 4, `static-dateformat` 1, and **nothing at all** for
`modify-during-iteration` — the rule carrying eight exclusion clauses over a
seven-branch receiver enumeration and the file's only nested re-inclusion, and the rule whose exclusion swallowed a real
`ConcurrentModificationException` in wave 4. Its real bugs lived only in
`hits/ModifyDuringIteration.java`, written by the rule's own author: exactly the
artefact the corpus exists to compensate for, and the worst of the four gaps to
have. `hits/IterationBugs.java` closes it with six reviewer-written CMEs at
nesting depths a future tightening of the `break` exclusions would plausibly
swallow. The three rules still at zero — `empty-catch`,
`printstacktrace-only`, `stream-not-closed` — are the three that carry no guard
exclusions worth the name, so they are low-risk *by construction*; saying so in
the test file turns an accident into a decision, and the first guard exclusion
added to any of them needs corpus entries with it.

**The trap family, and the two assertions that catch it without anyone
noticing.** Four silent-failure modes have now shipped through, or been caught
in, this rule file: a `pattern-either` branch with no positive term
(`RuleParseError`), an unquoted `?` in a ternary exclusion (`Invalid YAML
file`), `... <... e ...> ...` written inside a block, and an **uppercase
accented letter in a comment**. They look unrelated and were each found the hard way,
but they share one signature — **fewer rules load than the file declares, and
the run exits 0 printing a successful scan**. Semgrep's summary output cannot
distinguish a broken rule from a rule that found nothing, which is what makes
the family dangerous rather than merely annoying.

The wave-6 total-hits assertion is already the family-wide catch, since a rule
that fails to load loses its findings and the total moves — but only while every
rule has at least one hit fixture, which nothing stated and nothing enforced.
Wave 7 makes it self-enforcing with two cheap additions: the set of rule ids the
`hits/` fixtures exercise must equal the `- id:` entries **parsed out of the
YAML itself** (not a list maintained by hand beside it), and
`semgrep --validate --quiet` must exit 0 with both streams empty. The second
catches the one thing no finding-count assertion can see: a clause-level compile
failure that happens not to change any finding. Measured against all three
traps: exit 2, 5 and 2. `--disable-version-check` is passed because the upgrade
notice is network state, and an empty-stderr assertion hostage to network state
is a flake waiting to happen.

**The fourth trap is the first one this machinery caught before a human saw
it**, and it is worth stating concretely because it is invisible on review and
platform-dependent. Semgrep's config loader decodes the rule file with the
**locale** codec rather than UTF-8. On a Windows cp1252 locale the second byte
of an uppercase accented letter — U+00C1 is `0xC3 0x81`, and `0x81` is
undefined in that table — takes the whole file down, while the lowercase form
(`0xC3 0xA1`) is fine, which is why this pack's Portuguese prose has always
worked. Measured on the broken file: `results: 0`, `paths.scanned: 0`,
`errors: 0` — a caller reading only the findings sees a clean scan. Both
assertions fired. The rule file's header now warns about it and deliberately
cannot spell the character, since spelling it breaks the file that describes
it. The forbidden bytes are `0x81`, `0x8D`, `0x8F`, `0x90` and `0x9D`; in
practice the rule is: write the accented word in lower case.

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

Eleven more shapes were reproduced and **ruled not fixable** rather than left
unstated. The list is exhaustive against the review fixtures that exist today,
not against all Java.

**Every row states its DIRECTION**, and that is wave 7's structural finding
rather than a formatting choice. For six waves this table had nine rows and all
nine were false positives — which is exactly the shape of the defect waves 5 and
6 were about. Nobody was looking in the recall direction, so nothing was ever
written down there, and a wave could close a false positive, silently delete
recall, and still go green. Rows 9 and 10 are the first entries on the other
side. One row LEFT the table in wave 8: the conjunction-chain false positive
was not a limitation at all, only an unexamined `$X`.

| # | Dir | Rule | Code it gets wrong | Why it stays |
| --- | --- | --- | --- | --- |
| 1 | FP | `stream-not-closed` | `open(); try { … } finally { close(); }` | The pre-Java-7 idiom, and already the rule's stated reason for being `WARNING`. |
| 2 | FP | `race-condition-static-dateformat` | a `static final SimpleDateFormat` whose every access goes through a `synchronized` method | Proving *all* accesses are synchronized is whole-program analysis, which Semgrep OSS does not do. This row used to end "a shared formatter also serialises every caller, so flagging it is defensible" — that is a **product** argument, not §4's criterion, and it is why the rule sat at `ERROR` for four rounds while carrying a documented, un-fixable false positive. The criterion wins: the finding stays, the tier is now `WARNING`. |
| 3 | FP | `off-by-one-loop-lte-length` | `i <= a.length` where the body guards with `i < a.length`, or never indexes `a` | The obvious tightening was **tried and rejected** — measurement immediately below the table. It trades this false positive for a false negative without fixing the main case, so the patterns were left alone and only the tier moved. |
| 4 | FP | `printstacktrace-only` | `printStackTrace()` as the fallback when the logger itself threw | The one place the call is right; already `WARNING`; too narrow to encode. |
| 5 | FP | `map-get-deref`, `optional-get-no-ispresent`, `modify-during-iteration` | **two or more** statements between the guard (or the removal) and the exit: `if (!m.containsKey(k)) { log(); metric(); return ""; }`, `items.remove(s); log(s); n++; break;` | The deliberate price of bounding the exclusions. A statement ellipsis matches deep and swallows guards that do not cover every path, which are real bugs; a false negative that hides a bug is worse than this. |
| 6 | FP | the same three | a guard reached **through a helper method**: `if (!present(o)) { return d; }` | Needs interprocedural analysis, which Semgrep OSS does not do. Already the stated reason `optional-get-no-ispresent` is `WARNING`. |
| 7 | FP | `map-get-deref` | a key guaranteed present outside the enumerated shapes: a map filled in a static initialiser, a total enum mapping declared as a `Map` | The guarantee is not on the syntactic path reaching the `get`. Excluding "any map that ever received a `put` anywhere in the file" would erase the rule. |
| 8 | FP | `map-get-deref`, `optional-get-no-ispresent` | a guard held in a **local boolean**: `boolean present = m.containsKey(k); if (!present) { return ""; }` | Dataflow, not syntax. Semgrep OSS does not connect the local's value to the test that produced it, and no pattern shape reaches it. |
| 9 | **FN** | `map-get-deref`, `optional-get-no-ispresent` | the **invalidated-guarantee** class: a guarantee the guard establishes and the code then destroys, inside the region the exclusion covers — `if (m.containsKey(k)) { m.remove(k); return m.get(k).trim(); }`, `if (o.isPresent()) { o = Optional.empty(); return o.get(); }`, `if (m.containsKey(k)) { m.clear(); … m.get(k) … }`, `m.put(k,"v"); m.remove(k); m.get(k).trim();`, `while (m.containsKey(k)) { m.remove(k); … m.get(k) … }` | Five measured reproductions, all guaranteed throws, all silent. Same root cause as the wave-6 `else`-arm bug — **`pattern-not-inside` excludes the whole node it matched** — but on the **temporal** axis instead of the branch axis. Wave 6 scoped every guard exclusion to the arm the guard proves and fixed the branch axis; the sequence axis *inside* that arm was never examined, and an exclusion covering a block covers every statement in it, including the ones that undo the guarantee. Knowing that `m.remove(k)` invalidates `m.containsKey(k)` is dataflow, so this is a row and not a clause. The wave-7 `keySet()` exclusion inherits it unchanged. |
| 10 | **FN** | `map-get-deref`, `optional-get-no-ispresent` | a deref guarded by a **local boolean**: `boolean present = m.containsKey(k); if (present) { m.get(k).trim(); }` | The mirror of row 8, which records the same shape as an accepted false positive when the boolean guards an early exit. Both directions are the same missing capability — dataflow, not syntax — and having only the false-positive half written down for six waves is the asymmetry this table's preamble is about. Agreed in review and undocumented until wave 7. |
| 11 | FP | `map-get-deref` | the two `keySet()`-adjacent idioms the wave-7 exclusion does not reach: `for (Map.Entry<K,V> e : m.entrySet()) { … m.get(e.getKey()) … }`, and the key set copied to a local first, `Set<String> keys = m.keySet(); for (String k : keys) { … m.get(k) … }` | In the first the key is `e.getKey()` and not the loop variable; in the second the loop header no longer mentions `keySet()`. The clause unifies the map **and** the key on purpose, and widening it to reach these means giving up one unification — the two real bugs that would then be swallowed are pinned as `b13` and `b14` in `hits/RealBugs.java`. Of the five correct-code shapes measured, the clause closes three and these two remain. |

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

## 10. What the final review found, and why it took seven waves

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

### Wave 7: the table only had one direction, and nobody noticed for six waves

The re-review approved the merge and left four follow-ups. Only the first
changed rule behaviour; the other three are the interesting ones, because none
of them is a bug in a rule.

1. **One false-positive class was left: iteration over the map's own
   `keySet()`.** The commonest map-iteration idiom in Java, firing on correct
   code, and not in the accepted-limitations table either — so it was neither
   fixed nor known. Closed by a single clause, written against the body as a
   statement ellipsis after measuring that the braced/braceless pair every `if`
   guard carries would have been half inert here. §5 has the measurement.

2. **The accepted-limitations table had nine rows and every one was a false
   positive.** That asymmetry is the *shape* of the defect waves 5 and 6 were
   about, sitting in plain sight in the documentation the whole time: nobody was
   looking in the recall direction, so nothing was ever written down there, and
   a wave could close a false positive, delete recall, and still go green.
   Three rows were added and every row now states its direction. The sharpest of
   the new ones is the **invalidated-guarantee** class (row 10): five measured,
   guaranteed throws, all silent, and the same root cause as the wave-6 `else`-arm
   bug — `pattern-not-inside` excludes the whole node it matched — but on the
   **temporal** axis instead of the branch axis. Wave 6 fixed the branch axis
   and nobody asked whether the same defect had a second axis.

3. **The real-bugs corpus covered 4 of 8 rules, and the gap was the riskiest
   one.** The corpus was built in wave 6 to stop exclusions eating real bugs and
   was never measured for coverage. It carried nothing for
   `modify-during-iteration` — the rule with eight exclusion clauses over a
   seven-branch receiver enumeration, the file's only nested re-inclusion, and the wave-4 swallowed CME. A safety net has to be measured
   for holes, or it is a claim rather than a net. §7 records what it covers now
   and why the three rules still at zero are a decision.

4. **Row 9's justification was falsified by its own instance.** It generalised
   from a line carrying two `get()` calls to all conjunction chains, and the
   generalisation is false on the far commoner single-`get()` line. This is the
   same measurement habit the whole series has been paying for — the fix is not
   "measure more" but "state what was measured *on*", which is now what the row
   does.

The generalisable lesson from 2, 3 and 4 together: **the artefacts built to
catch a defect class inherit the blind spot of whoever built them.** The
near-miss fixtures only measured precision, so the corpus was built to measure
recall — and then the corpus itself was never measured for coverage, and the
limitations table was never checked for whether it had two sides. Each safety
net needs the question asked of it that it was built to ask of the code.

And one that is purely mechanical but cost the wave a measurement:
`metavariable-type` resolves a `this.`-qualified field only when the field's
**declaration precedes** the method in source order. A near-miss placed above
the declaration is silent under the *pre-fix* rule, which makes it a fixture
that can never fail — the near-miss equivalent of an inert clause.

### Wave 8: the row was the defect

One item, the smallest diff of any sweep, and it retires the longest-standing
wrong answer in the pack. The conjunction-**chain** false positive —
`flag && m.containsKey(k) && m.get(k).isEmpty()`, ordinary correct Java — had
been in the limitations table since wave 4 under two successive justifications,
and both were wrong in the same way: they reasoned about variables that do not
control the outcome. The first measured "removes one of two findings, the line
still fires" on a line that happened to carry two `get()` calls; the second
generalised it to "one clause leaves 4+ operand chains firing", making chain
*length* the discriminator. The actual mechanism is that **`$X` matches the whole
left-nested subtree**, so one clause per guard covers a chain of any length —
which nobody had checked, through four waves of people reading the row and
agreeing with it.

Three things generalise:

1. **A documented limitation is an untested assertion with social proof.** Every
   other claim in this pack has a fixture behind it that fails when the claim
   goes stale. A limitations row has nothing — it is prose asserting that
   something cannot be done, and the longer it sits the more it reads as
   settled. This one survived four waves and two reviewers. Rows describing a
   *decision not to fix* deserve the same scepticism as a rule, and the cheapest
   version of that scepticism is to re-measure the row rather than re-read it.
2. **Rewording a falsified justification is the wrong repair.** The first
   instinct — and the wave-7 instruction — was to reword the row to "the reason
   that actually holds". But a row recording a deferred decision on a false
   premise reads as considered, which is worse than no row at all: it actively
   discourages the next person from checking. Deleting it and moving the
   mechanism into the rule file, next to the clauses, is what makes the finding
   survive.
3. **Scope discipline and correctness can conflict, and the measurement settles
   it.** Wave 7 was scoped to one rule change and correctly refused to apply
   this one; what made that refusal safe was that the refusal came *with* the
   measurement, so the decision could be reversed by someone with the authority
   to widen the scope, without redoing the work. An unmeasured deferral would
   have ended the round.

And a fourth trap found by walking into it: **one uppercase accented letter in a
comment breaks the whole rule file**, because Semgrep's config loader decodes
with the locale codec rather than UTF-8. It presents exactly like the other
three — clean scan, no findings, no errors — and was caught by the `paths.scanned`
and `--validate` assertions added in waves 6 and 7. That is the first time the
family-wide machinery has caught a member nobody had seen before, which is the
only evidence that a general catch is general.
