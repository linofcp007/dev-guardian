# Changelog

All notable changes to dev-guardian are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and the project uses
[Semantic Versioning](https://semver.org/). From 1.0.0 the MCP tool/resource
surface and default behaviours follow semver — breaking changes require a major
version bump.

## [Unreleased]

### Removed

- **`bugfix-java-null-safety-map-get-deref` deleted. The Java pack goes from
  eight rules to seven.** The external-corpus round below read all 55 of its
  OpenJDK + Spring findings, found no live defect, and kept it anyway on one
  explicit condition, written into the rule itself: both corpora are mature
  *library* code, where a dereferenced map is nearly always one the reading
  class filled itself, and the evidence that would decide the rule was a corpus
  of **application** Java. That corpus was run, and it deleted the rule.

  | corpus | findings | `.java` scanned | per 1000 |
  | --- | --- | --- | --- |
  | Jenkins | 1 | 1 274 | 0.8 |
  | Kafka | 224 | 3 892 | 57.5 |
  | Elasticsearch | 749 | 20 485 | 36.6 |

  973 new findings, **45 read by hand** — spread across modules and weighted
  toward the shapes a cheap triage could not explain — and **five** defensible
  defects (`EnterpriseGeoIpDownloader.java:589`, `GeoIpDownloader.java:160`,
  `JvmOption.java:63`, `RemotePartitionMetadataStore.java:175`,
  `OsProbe.java:811`).

  **The count decided nothing; this did.** 88% of the Elasticsearch findings and
  97% of the Kafka ones have **no guard of any kind anywhere near the
  dereference**. They are correct for *semantic* reasons — parallel maps kept in
  sync, a map the class filled in another method, a constant key, an API
  contract — and no `pattern-not-inside` reaches any of that, so **narrowing was
  never available**. That was measured before the decision rather than assumed:
  the one mechanically closable family is Elasticsearch's `containsKey(k) ==
  false` negation style, which every `!containsKey` exclusion misses, and it is
  worth **34 of 749** and **zero** on Kafka.

  Two findings that outlive the rule. It was **blind to the more dangerous
  idiom** — `X v = m.get(k); v.foo();` never matched, because the dereference is
  not chained, so at `KafkaAdminClient.java:2375` and
  `AbstractStickyAssignor.java:268` it reported the *derived* lookup (safe,
  precisely because the earlier one did not throw) and was silent on the
  original. And **all five true positives have one shape**: a map produced by
  parsing external input — HTTP JSON, `/sys/fs/cgroup`, JVM output — read with a
  literal key. That is provenance, not syntax, and it is outside Semgrep OSS;
  it is recorded as a candidate for a future rule measured from scratch, never
  as a tightening of this one.

  Same criterion as C#'s `as-cast-deref` and `catch-returns-null`, with one
  difference recorded on purpose so the precedent stays honest: **this rule's
  true-positive rate was not zero, it was about 1%.** A user with 5 000 files of
  Java got roughly 200 findings and perhaps two worth acting on. Counts decide
  nothing in either direction — `empty-catch` produces 1589 on the OpenJDK and
  is right nearly every time.

  Also gone: three of the eleven accepted Java limitations, which belonged to
  this one rule; 42 of the pack's 91 `pattern-not-inside` clauses; and the
  fixtures `hits/MapGetDeref.java` and `misses/MapGetDeref.java`.
  `hits/ElseArm.java` drops 12 to 7 and `hits/RealBugs.java` 20 to 11 — measured
  old pack against new over the whole `hits/` tree as **25 findings removed, 0
  added, no other file moved**, which is what makes it a deletion and not a
  regression. Nothing they fenced is unfenced: every clause shape they measured
  has an `optional-get-no-ispresent` twin still in the pack (`b12`, `b15`,
  `b17`, `b19`, `F5`-`F7`). Written up in section 12 of the Java design doc.

### Changed

- **`bugfix-java` audited against real Java for the first time.** It was the
  only pack in the series never measured against code nobody here wrote: eight
  rules, nine fix waves, every one of them found by reading fixtures. The one
  thing that *had* been measured — `empty-catch` on the OpenJDK — refuted the
  premise its `ERROR` tier stood on. This round pointed all eight rules at
  **12 593 OpenJDK files** (`openjdk/jdk`, `src/<module>/share/classes`) and at
  **4 754 Spring Framework files** (`spring-*/src/main/java`), and read the
  findings one by one. Four rules of eight changed, **in both directions**, and
  the pack still declares eight rules with the same ids.

  | rule | JDK before | JDK after | Spring |
  | --- | --- | --- | --- |
  | `error-handling-empty-catch` | 1589 | 1589 | 193 |
  | `error-handling-printstacktrace-only` | 78 | 78 | 0 |
  | `null-safety-map-get-deref` | 43 | 43 | 12 |
  | `null-safety-optional-get-no-ispresent` | 26 | **11** | 0 |
  | `memory-leak-stream-not-closed` | 12 | **4** | 0 |
  | `edge-case-modify-during-iteration` | 1 | 1 | 0 |
  | `off-by-one-loop-lte-length` | 0 | 0 | 0 |
  | `race-condition-static-dateformat` | 0 | 0 | 0 |

- **`memory-leak-stream-not-closed` (Java) was two-thirds false positive, and
  the cause was the shape of its exclusions rather than their content.** Eight
  of its twelve OpenJDK findings were **two-resource try-with-resources
  headers** — `try (FileInputStream fis = ...; BufferedInputStream bis = new
  BufferedInputStream(fis))`, which is simply how a file gets read with a
  buffer. The rule excluded try headers by naming the resource, and a header
  with two resources is a different AST node. Enumerating the lengths was
  measured and rejected (two clauses for two resources, three for three, doubled
  again by the finalizer), and `try (...)`, `try ($...RES)` and
  `try (...; $R; ...)` are all `Invalid pattern for Java`. The rule now anchors
  positively on a **statement sequence** instead: a resource in a try header is
  not a statement, so no header of any length reaches it. Four exclusion clauses
  became two. Of the four findings that remain, **two are genuine descriptor
  leaks** (`COFFFileParser`, `Commands`) and two are the documented
  helper-closes and `finally`-closes limitations.

- **`null-safety-optional-get-no-ispresent` (Java) 26 → 11 on the OpenJDK**, and
  the fifteen closed were two shapes, not fifteen. Nine were the **`else` arm of
  an `if (o.isEmpty())`** — the way the check has been written since Java 11,
  and the exact dual of the `isPresent()` guard the rule already honoured; the
  four new clauses cover the bare condition and the disjunction, and therefore
  also the `else if` chain. Six were **`assert o.isPresent();`**, which is the
  JDK's own way of writing down an invariant it established elsewhere: unlike a
  comment it is in the AST, and it is an intention rather than a runtime guard,
  since assertions are off by default. The neighbouring shapes that must keep
  firing are pinned as F9–F12 in `hits/ElseArm.java`: the THEN arm of
  `isEmpty()`, the `else` of a **conjunction** with `isEmpty()` (which proves
  nothing), an assert on a *different* Optional, and `assert o.isEmpty()`.

- **`race-condition-static-dateformat` (Java) was blind to the only real race
  either corpus contained.** Zero candidates in 12 593 OpenJDK files, exactly
  one across 4 754 Spring files — a `private static final SimpleDateFormat`
  declared with no initializer and assigned in a `static { … }` block, formatted
  later with no lock at all. The rule demanded the `new` on the declaration
  itself. A second pattern branch matches the split declaration; measured
  silent on an instance field, an uninitialized instance field, and a static
  method whose *return type* is `SimpleDateFormat`.

- **`off-by-one-loop-lte-length` (Java) was blind to `++i`, `i += 1`, a
  braceless body and `for (var i = 0;`.** Optional syntax spelled out in a
  pattern acts as a **filter**: writing the increment `$I++` excluded the other
  two spellings of the same loop, and writing the body `{ ... }` excluded the
  braceless one. Same defect the C# pack found in `i++` versus `++i`. The
  increment and the body are now ellipses and `var` has its own branch. It costs
  no precision to widen here: **zero** `<= ....length` loop headers of any
  spelling exist in either corpus, so what the rule had was false negatives and
  nothing else.

- **`bugfix-java` is registered with the ablation harness's axis 3**, reading a
  corpus path from `GUARDIAN_JAVA_SRC` on the same terms as `GUARDIAN_RUST_SRC`
  and `GUARDIAN_CS_SRC`: unset prints `N/A`, set-but-missing **throws**. Making
  `static-dateformat` a `pattern-either` also took the pack from 7 of 8 rules
  with ablatable clauses to 8 of 8. Two things were caught by ablating the new
  clauses before they shipped, and both are the classes this series keeps
  meeting: an **inert clause** — `assert $O.isPresent();` written beside
  `assert $O.isPresent() : ...;` on the assumption that they are different AST
  nodes, which they are, except that `: ...` also matches the *absent* message,
  so the first covered nothing the second did not (seventh occurrence in the
  series, second caught before release) — and **four fixtures that proved
  nothing**, because they were written with an early exit in the then-arm and
  the pre-existing early-exit clause silenced them before any new clause was
  consulted. All four `else`-arm clauses read `DEAD` against them. The
  replacements have a non-exit then-arm, which is also what the nine OpenJDK
  findings looked like, and each maps to exactly one clause.

### Known gaps

Every row of the Java **Accepted limitations** table under 1.9.0 was
reproduced against the shipped pack before anything was decided. Rows (2),
(3), (5), (6), (7) and (8) stand unchanged. Row (1) is now **half** the
limitation it was: a stream closed by a `finally` or by a helper still reports,
but the multi-resource try-with-resources that dominated it does not. Row (4)
reproduces and is **rare**: not one of the 78 OpenJDK
`printstacktrace-only` findings was the deliberate-fallback shape. What the
round added:

- **A false negative on the branch axis, in the early-exit exclusions
  themselves.** `if (o.isEmpty()) { return o.get(); }` is silent, and so are
  `if (!o.isPresent()) { throw new IllegalStateException(o.get()); }` and
  `if (!m.containsKey(k)) { return m.get(k).trim(); }`. All three are
  guaranteed throws, all three read the value inside the very branch the guard
  proves is unsafe, and all three are swallowed because `pattern-not-inside`
  excludes the whole `if` node — including the exit branch the clause was
  written to describe. Same root cause as row (9), on the branch axis rather
  than the temporal one, and not fixable in Semgrep OSS. Predates this round
  and is unchanged by it; measured against both packs.
- **`null-safety-map-get-deref` scored 55 findings across the two corpora
  (43 + 12) and a hand-read of all 55 found no live defect.** *(This rule has
  since been DELETED — see the Removed entry above. The paragraph below is the
  record of the round that kept it, and the condition it set is the one the
  application-corpus round discharged.)* They fall into
  families Semgrep OSS cannot close, and every one is already a documented
  limitation: the total map filled in a constructor or a static initializer for
  every key of an enum (the largest group, and all 7 Spring sites); presence
  established by a method (`addNode(u); … edges.get(u)`); a key from a
  `keySet()` walked with a lambda or a stream rather than a for-each; a key
  filtered by `.filter($M::containsKey)`; and an invariant held between two
  objects. **No clause was written for any of it.** The two families that are
  syntactically closable — the `keySet()` lambda and the method-reference
  filter — are worth 7 of 55, and neither closing form can unify the **key**,
  which is precisely the unification that keeps the existing for-each clause
  from swallowing `b13` and `b14`. What this does not settle: both corpora are
  mature *library* code, where a dereferenced map is nearly always one the
  reading class filled itself. Application Java, keyed on external input, is a
  different distribution and was not measured. The rule stays, at `WARNING`,
  with the measurement written down; a third corpus of application Java is the
  evidence that decides it.
- **The eleven `optional-get` findings that remain on the OpenJDK** are four
  shapes, all of them enumerable and none of them closed: a ternary whose
  condition is a conjunction of two `isPresent()` calls, a ternary whose
  condition is `isEmpty() || …`, `if (!o.isEmpty())` (the double negative), and
  an `else if` chain whose `else` is another `if` statement rather than a
  block. Each is worth one to three findings; the stopping point is a judgement
  about clause count, not a claim that they are unreachable.
- **`empty-catch` re-measured identically**: 1589 findings in 770 OpenJDK
  files, 56 % of them carrying an explanatory comment inside the catch, and the
  caught-variable names are `e` (890), `ex` (158), `ioe` (44) — with
  `cannotHappen` at 13 and `_` at 10 still outside the three names the rule
  recognises. Nothing changed; the rule is precise about what it matches and
  silent about whether it is a defect, which is why it is `WARNING`.
- **`edge-case-modify-during-iteration` scored 1 finding in 17 347 files**, too
  few to say anything about. `off-by-one-loop-lte-length` and
  `race-condition-static-dateformat` scored 0 on the OpenJDK because the shapes
  are absent from it, not because the rules are broken — verified by grep in
  both directions.

### Added

- **Every rule pack now has a real-code ablation corpus.** Axis 3 — does removing
  a clause *raise* the finding count on code nobody here wrote — has changed more
  verdicts than any other check in this series: it deleted the two largest rules
  ever removed from these packs, killed two Rust candidates that had passed every
  other check, and caught a JS regression both other axes let through. It had
  never run on `bugfix-py`, `bugfix-go` or `bugfix-php`. It does now, via
  `GUARDIAN_PY_SRC`, `GUARDIAN_GO_SRC` and `GUARDIAN_PHP_SRC`, on the same terms
  as the existing three: unset prints `N/A`, set-but-missing **throws**, never a
  silent skip. Measured on CPython's `Lib/` (5803 files, 1078 findings), the Go
  standard library (6515, 3101) and WordPress core (1512, 40) — noise floor 0 on
  all three, every rule firing on its own fixtures, and **one** axis-3 flag
  across the whole Go pack. The PHP number is a cross-check: 40 is exactly what
  the PHP probe measured by hand, rule by rule, by a different method.

- **`configs/semgrep/routes.yml` is under the ablation harness**, the last pack
  that was not. It was excluded for having no `hits/` + `misses/` fixture pair;
  it has one, under older names — `mcp/test/fixtures/surface/` is the hits
  corpus and `frameworks/fp/` the decoys — so the harness gained
  `hitsSubdir: '.'` (the fixture root) and `decoySubdirs` rather than the
  fixtures being renamed out from under the surface e2e tests. First full run
  over its **112 clauses in 64 rules**: **axis 0 is 64/64 — every rule fires**,
  which is the check this pack most needed, having twice shipped a rule that
  matched nothing. 38 clauses read DEAD and **none was deleted**: they are
  Semgrep collapsing spellings a reader thinks are distinct (`$MUX.Handle`
  matches `http.Handle`; `#[actix_web::post]` and `#[post]` are one node) or a
  guard whose adversarial fixture does not exist. Two of the latter were
  hand-probed and are load-bearing — without them `app.use(cors(), router)`
  reports a mount at prefix `cors()` and Express's settings getter
  `app.get('/title')` reports as a route at full confidence. The decoy tree's
  baseline is **pinned, not gated at 0**: four of those are routes that
  are genuinely undecidable. Axis 3 runs on `mcp/src` and reaches only 2 of the
  64 rules, so the report now prints each rule's real-code baseline and marks
  the other 62 `real 0 -- axis 3 vacuous here`.

- **Five decoys for the `routes.yml` guards nothing was measuring.** Of the 38
  DEAD clauses above, five were hand-probed and found load-bearing: all three
  `guardian-route-go-chi` exclusions, `guardian-mount-express`'s `$PREFIX`
  literal regex and `guardian-route-express`'s one-argument `pattern-not`.
  They read DEAD because no fixture reached them, so the fix is a fixture and
  never a deletion — the corpus's only Go decoy was SCREAMING-case `reg.GET`,
  which the *gin* rule absorbs before chi is consulted, and the three JS decoys
  the pack's header credits to the express guard are on its `$APP` denylist
  too, so the denylist always decided first. `frameworks/fp/decoys.go` gains a
  TitleCase `Get` in each of its three excluded forms (`F31`-`F33`) and
  `decoys.js` a one-argument read on a receiver the denylist misses plus an
  `app.use` whose first argument is a call (`F07`, `F08`). All five clauses now
  read **live**; not one of the decoys is reported by the shipped pack, and the
  decoy baseline moves 8 → 9 only for the ordinary `require('cors')` the
  `app.use` decoy needs to be plausible code.

- **`create_fix_pr` now says what it filtered out.** `severity_min` defaults to
  `high`, and 1.9.0 took the Semgrep `ERROR` tier — the only tier the parser
  maps to `high` — from 20 rules of 34 to 4 of 58. A default run against a
  project whose findings all come from the local packs therefore selected
  nothing, and said so only by returning `groups: []`, which is exactly what a
  project with nothing to fix returns. Two new fields close that: `filtered`
  (structured — `considered`, `candidates`, `excluded`, counts per reason, and
  a per-tier breakdown of the severity floor's own share) and `filtered_reason`
  (one line, `null` iff nothing was excluded, on the same contract
  `deferred_reason` already keeps with `deferred`). Reported whenever
  *anything* was excluded, not only when everything was — a run that fixes 2 of
  42 is nearly as opaque as one that fixes 0.

  **No default changed and no rule's severity changed.** The `high` floor is
  correct: lowering it would open pull requests from rules that are heuristic
  by construction — `floating-mutation` matches on a method name alone and
  cannot tell `repo.save()` from Canvas 2D's `ctx.save()`. The silence was the
  bug.

  The report also corrects a piece of advice this repo had been giving in three
  places. `create_fix_pr` requires `fix_available`, which for Semgrep means the
  rule carries a `fix:` — and **no rule in any of the nine packs here does**
  (measured: `bugfix-js` over its own `hits/` fixtures gives 39 findings across
  13 files, zero carrying `fix` or `fixed_lines`). So "pass `severity_min:
  medium` to get the Java/JS/Python pack into a fix PR" was never going to
  work at any floor. The suggestion is therefore emitted **only** for findings
  a lower floor genuinely recovers, never for `fix_available: false` ones,
  where it would have cost a second run to discover it changed nothing.
  `skills/guardian-bugfix/SKILL.md` is corrected accordingly.

- **`create_github_issues` reports the same two fields**, for the same defect:
  its `severity_min` also defaults to `high` (a default that was not stated in
  the schema at all until now) and `max_issues` to 10, and the result listed
  only the survivors — so a scan of nothing but `medium` findings produced
  `candidates: 0`, indistinguishable from a clean one. `filtered.by_reason`
  separates the severity floor from the cap. Neither default changed; both are
  now documented in the input schema.

### Fixed

- **The Bash guardrail matched text where it should have matched commands, and
  four families of false positive came out of that.** Every one of the twelve
  pattern rules in `mcp/src/hooks/bashGuard.ts` was a regex run against the
  whole command string. Measured over **25 071 distinct shell commands** taken
  from this machine's own Claude Code transcripts (342 sessions), **23 of the
  27 non-`rm` warnings were wrong**, and one of them was a *block*:

  | defect | example from the corpus | rules affected |
  | --- | --- | --- |
  | matched across a separator | `git push origin main && git worktree remove … --force` | 8 of 12 (every rule carrying a `[^\n]*` span) |
  | matched inside quotes | `echo 'git push --force 2>&1'` | all 12 |
  | matched inside a heredoc body | `git commit -F - <<'EOF' … EOF` | all 12, plus the `rm` tokeniser |
  | matched a word, not a command | `apt-get install -y git sudo pipx` | `sudo` |

  The heredoc one is the sharp end: a real commit was **denied** as
  `rm -rf ~` because its message contained a lone `~` on a line, and the
  `rm` tokeniser split on `;`, `|` and `&` but **never on newlines** — so
  an `rm -rf ./.playwright-mcp` three lines earlier swept the whole commit
  message up as its target list.

  The obvious repair — dropping `&` from the character classes — is the wrong
  trade. A genuine force-push is very often `git push --force 2>&1 | tee log`,
  and `2>&1` contains `&`; narrowing on the character buys a false positive
  back with a false negative, which for a guardrail is the worse direction. So
  `bashGuard.ts` now **segments before it matches**: a small quote-aware,
  escape-aware, heredoc-aware scan yields statements (split on `&&`, `||`,
  `;`, newline, a background `&`, `(`, `)` and backticks) each holding its
  pipeline members as words. A statement **keeps its pipeline**, because
  `curl … | sh` is one hazard spanning a pipe — splitting on `|` would have
  silently disarmed `remote-pipe-to-shell` and `powershell-iex-download`, the
  two block rules that need the pipe to match at all.

- **No block rule was narrowed, and three now reach further.** Quoted spans
  stop being matchable, so `sh -c '…'`, `bash -c '…'` (including behind
  `docker exec … bash -c`), `su … -c '…'` and `eval …` are re-entered and
  assessed as commands in their own right, to depth 3. That is strictly more
  than the old text matching had: `bash -c 'rm -rf /'`, `eval "rm -rf /"`,
  `(cd /tmp && rm -rf /)` and `sudo -u www-data rm -rf /` were **all missed
  before** and all block now. Every block rule is pinned by a test three ways
  — alone, as the second statement after `echo hi &&`, and on the second line
  of a script — and the pin list is checked against `BASH_RULES` so a rule
  added without one fails the suite.

- **Splitting on newlines also recovered 86 recursive force-deletes the guard
  had been blind to.** `rm -rf "$WORK"` on line four of a script was invisible,
  because the old tokeniser required `rm` to be the first token of a
  `;|&`-delimited segment and a multi-line script has no such separator. On the
  25 071-command corpus: `rm-rf-broad` 177 → 262, and every one of the 86 new
  findings was hand-checked back to a real `rm -rf`. Total warnings therefore
  go **up**, 203 → 266, while the non-`rm` rules go from 4 true positives out
  of 27 firings to **4 out of 4**. `git rm -r --cached` is correctly not one
  of them.

- **Auditing the twelve rules also found `disk-overwrite` half asleep.** Its
  `\b` sat in front of the whole alternation, and a leading `\b` before `>`
  demands a word character immediately to its left — so the redirect branch
  matched `cat x>/dev/sda` and never the `cat x > /dev/sda` anybody actually
  writes. Each alternative anchors itself now; `> /dev/null` and
  `> /dev/stdout` are untouched, and the corpus count did not move.

- **`sudo` is decided on command position now**, like `rm` already was:
  `apt-get install -y git sudo pipx` installs a package, and a commit message
  that mentions sudo runs nothing. `find … | xargs sudo rm -f` and
  `env FOO=1 sudo systemctl restart nginx` still warn, because `xargs`, `env`,
  `timeout`, `nice` and friends are walked through to the real command word.

  Shared, unchanged, between the `PreToolUse(Bash)` hook and
  `dev-guardian check --bash`; still dependency-free, still fail-open, and
  still not a shell parser — command substitution inside double quotes
  (`echo "$(rm -rf /)"`) stays invisible, exactly as it was.

- **`bugfix-cs` `off-by-one-loop-lte-length` no longer fires on a sentinel
  loop.** Both of the rule's findings on 11 800 files of `dotnet/runtime` were
  loops that run one position past the end **on purpose** and guard the extra
  pass inside the body — `ConfigPathUtility.cs:26` and `XslNumber.cs:151`, a
  measured precision of 0 of 2. The new exclusion is **not** the tightening
  Java measured and rejected (require the body to index the bounded receiver,
  which trades a false positive for a false negative in every loop that reads
  `a[i]` to write elsewhere): it asks whether the body **re-compares the index
  against the bound**, which is what makes a sentinel loop one. Corpus count
  2 → 0, all five `hits/` unchanged, two crossed near-misses added and each of
  the four new clauses mutation-tested to fire exactly one of them.
  `loop-lte-count` deliberately did **not** get the same exclusion: it produces
  zero findings on the same corpus, so nothing measures it there.

- **`severity_min` was deleting findings, not hiding them.** The shared scan
  pipeline (`tools/scanToolFactory.ts` — twelve tools) applied the severity
  floor *before* `bulkInsert`, so a caller who passed `severity_min: "high"`
  did not merely fail to see the medium findings: they were never written to
  SQLite. Everything downstream inherited the hole. A `set_baseline` taken
  from that scan silently omitted them; `diff_scans` compared against data
  that was never recorded; the next **unfiltered** scan reported them as
  `new`, which is the opposite of true — they had been there all along; and
  the trend showed an improvement that never happened. The floor now shapes
  the response only, and the scan row records the whole tree.

  **The two halves of a `deps` scan already disagreed with each other.**
  `cves.bulkUpsert` on the very next line ran on the *unfiltered* array, so a
  medium CVE below the floor kept its `cves` row — and its place in
  `guardian://cves/active` — while the matching Finding was dropped. Trivy,
  npm-audit and WPScan all emit the pair. The two are now consistent because
  both are stored whole.

  Two more instances of the same shape, found while checking the downstream
  consumers: `audit_executive` persisted its *filtered* aggregate onto the
  parent `audit` row that `diff_scans` reads, and measured its `deltas`
  filtered-present against unfiltered-past (so every below-floor finding
  counted as `resolved`); `scan_skill` filtered before the `bulkInsert` its
  own comment justifies with "so status / trend / diff / report_export see
  it". Both now store what they found.

  No default changed — `severity_min` is still include-all on every tool that
  takes it, and `create_fix_pr` / `create_github_issues` keep their `high`
  default (those select what to act on; they never persisted a scan).

- **A cache hit ignored the floor the caller had just passed.** Now that the
  stored set is the whole tree, `severity_min` is re-applied per call, so a
  cached reply is shaped like a fresh one. Previously the cached path returned
  whatever the *first* call had stored, in both directions.

- **Ablation axis 3 was measuring noise and charging it to the wrong clause.**
  1.9.0 shipped this as a known defect; it is fixed here. The axis compared
  whole-corpus totals across separate scans, and on `dotnet/runtime` that made
  four clauses in **four different rules** each read "raises the count by 8" —
  the same 8 findings every time, all in `Task.cs`, belonging to three *other*
  rules. The same run flagged one clause and cleared its byte-identical twin.
  The mechanism: Semgrep names the rule in its timeout message, which makes
  `(rule, file)` look like the unit, but `--timeout-threshold` drops the **whole
  file** for every rule still to run and names none of them. Axis 3 now compares
  only the ablated rule's own findings, on files every scan finished, and
  measures a per-rule noise floor rather than assuming one; a delta that does not
  clear its floor reads `INCONCLUSIVE` instead of passing. Proven with two full
  C# runs under deliberately different machine load — 28 excluded files against
  16 — with all 44 verdicts identical. C# flags go 15 → 11; the four cleared are
  recorded as *unmeasured*, not vindicated.

## [1.9.0] - 2026-08-21

The release where the rule packs were measured against code nobody here wrote.
Three new languages ship (C# 11 rules, PHP 6, Rust 1), **three rules are deleted**
for having no measurable true-positive rate, roughly **130 false positives** are
closed across the four packs that already existed, and the `ERROR` tier drops
from **20 rules of 34 to 4 of 58**. What you may have to act on is directly
below; everything after it can be read at leisure.

### Action required

- **If you ran `init_project` before this release, your configs are stale and
  your pre-commit hook does not load them.** Two independent defects, one
  remedy:

  1. **`scan_sast` never ran the rules `init_project` installs.** It passed
     `semgrep --config=auto`, and `--config=auto` does not pick up a project's
     `.semgrep.yml`. Measured on semgrep 1.164.0 against a project holding the
     shipped pack and one line of `<?php echo $_GET['name'];` —
     `--config=<the pack>`: **1 finding, 2 files scanned**; `--config=auto`:
     **0 findings, 2 files scanned**. So the thirteen security rules
     `init_project` writes as `.semgrep.yml` had no consumer anywhere in the
     product, and the shipped pre-commit hook had the same gap: it also passed
     only `--config=auto`.
  2. **The `.semgrep.yml` you were given contains a dead XSS rule.**
     `wp-unescaped-output`'s pattern was `echo $_GET[$X]`, which is not valid
     PHP, so Semgrep could not compile it; with `--quiet` the failure went to a
     JSON `errors` array instead of stderr and nothing surfaced it. Every scan
     since has reported zero WordPress XSS findings from a rule that could not
     have produced one. It was fixed in b51a2dc, and because `init_project`
     never touched a config it had already copied, **that fix has not reached
     any existing project**.

  Both are fixed in the product; the copy in *your* project needs a refresh:

  ```text
  init_project(project_path=".", refresh=true, apply=false)   # show me what would change
  init_project(project_path=".", refresh=true, apply=true)    # do it
  ```

  **Your own edits are safe.** `apply=true` overwrites only a file you have
  provably never touched; anything you customised — or anything of unknown
  provenance, which is treated as modified on purpose — is left exactly as it
  is, with the new baseline written beside it as
  `<name>.dev-guardian-1.9.0.new` for you to merge. This applies to all four
  configs `init_project` installs (`.gitleaks.toml`, `renovate.json`,
  `.semgrep.yml`, `.pre-commit-config.yaml`), not just the Semgrep one. If you
  would rather not run the tool at all, copying `configs/semgrep/base.yml` over
  your `.semgrep.yml` by hand gets you the same rules, and adding
  `--config=.semgrep.yml` to your hook config by hand gets you the other half.

- **A default `create_fix_pr` run now returns far less, and for Java it returns
  nothing at all.** That is deliberate, measured, and reversible with one
  argument: `severity_min: "medium"`. See *Changed* immediately below.
  `bug_hunt` applies no severity filter by default, so **nothing disappears
  from a scan** — only the fix PR is affected. Java is not a regression against
  any released version: the Java pack ships for the first time here, and ships
  at `WARNING`.

- **The default `scan_sast` mode has always sent telemetry to Semgrep Inc.**,
  and `SECURITY.md` said otherwise. See *Privacy*.

### Changed

- **The `ERROR` tier was re-derived from what a rule EMITS, and it emptied
  out.** The criterion was always written correctly in the pack headers — *is
  what the rule emits always a bug?* — and then applied to the bug **class**
  instead. Applied cold, a rule whose correctness depends on having recognised
  a **guard** cannot clear it: it emits a false positive the first time it meets
  a guard shape nobody enumerated, and no exclusion list ever closes that,
  because the guard can be one method away where a syntactic matcher cannot
  follow. The length of the exclusion list is evidence *for* the demotion.

  | pack | rules | `ERROR` at 1.8.0 | `ERROR` now |
  | --- | --- | --- | --- |
  | `bugfix-js` | 13 | 8 of 14 | 1 — `off-by-one-index-at-length` |
  | `bugfix-py` | 10 | 5 of 10 | 1 — `null-safety-none-deref-match` |
  | `bugfix-go` | 9 | 7 of 10 | 1 — `error-handling-empty-err-block` |
  | `bugfix-java` | 8 | *unreleased* | 0 |
  | `bugfix-cs` | 11 | *new* | 1 — `error-handling-rethrow-loses-stacktrace` |
  | `bugfix-php` | 6 | *new* | 0 |
  | `bugfix-rs` | 1 | *new* | 0 |
  | **total** | **58** | **20 of 34** | **4** |

  The four survivors are the four with no guard to recognise: a read at
  `a[a.length]` is unconditionally `undefined`; an accessor glued straight onto
  `re.match`; a literally empty error branch; and `throw ex;` in a `catch`,
  whose *correct* form `throw;` is a **different AST node**.

  **Downstream, and this is the whole reason it is in Action required.** The
  Semgrep parser maps `ERROR → high`, `WARNING → medium`, `INFO → info`, and
  `create_fix_pr` defaults `severity_min` to `high`. So the Java pack now
  contributes **nothing** to a default fix-PR run, and every other pack
  contributes at most one rule. Ask for `severity_min: "medium"` to get the
  rest. `create_fix_pr`'s own default was deliberately **not** changed: it
  affects all seven packs and is a separate decision. Every tier in every pack
  is now pinned exhaustively in both directions by `EXPECTED_SEVERITY` in the
  per-pack integration tests — before this release **no test read
  `extra.severity` at all**, so any tier could have been changed with a green
  suite, and each of these flips was made RED first.

- **`error-handling-empty-catch` drops to `WARNING` in Java and C#, and the
  premise it rested on was refuted in both.** Both packs carried it at `ERROR`
  on the claim that the rule can *read* its ecosystem's declaration of intent —
  the Checkstyle / IntelliJ `ignore` / `ignored` / `expected` binding name — so
  what it emits afterwards is an **unmarked** silent swallow. Neither pack had
  ever tested that claim, because this repository contains no Java and no C#.
  Three other languages had tested it and all three refuted it (JS/TS 42 of 42
  deliberate, PHP 10 of 10, Ruby's convention at 2.7 %). Now measured against
  external corpora:

  - **OpenJDK** (`openjdk/jdk` @ `e296cefb`, `src/*/share/classes`, 12 593 files
    scanned): **1589 findings in 770 files**, of which **903 — 56.8 %** carry an
    explanatory comment *inside* the empty catch, which is precisely why they
    fire at all: a comment-only block is empty to the AST. Another 27 declare
    intent in a name the rule does not carry — `cannotHappen` ×13, **`_` ×10**
    (Java 21's *unnamed variable*, meaning exactly "unused binding"), `unused`
    ×2. An inverted-regex probe puts the recognised spelling at **139**, so the
    convention the whole tier rested on covers **8.0 %** (139 of 1728) of the
    corpus's empty catches. 45 findings read one by one: about 39 deliberate.
  - **`dotnet/runtime`** (@ `6ecee4dd`, `src/libraries/*/src/**`, 11 800 files
    scanned): **402 findings in 233 files**, and here the refutation is
    structural rather than statistical. **374 — 93 % — are written
    `catch (Type) { }` or `catch { }`**: spellings with no identifier for a
    naming convention to attach to. Only 28 bind a name and not one uses the
    exempt vocabulary (`ex` ×15, `e` ×5). The inverted-regex probe finds
    `ignore` / `ignored` / `expected` **zero times in 11 800 files**.
  - **The compiler is the oracle, and it contradicts the rule's own advice.**
    `dotnet build` on `mcr.microsoft.com/dotnet/sdk:8.0` emits **CS0168, "The
    variable 'ignored' is declared but never used"** for
    `catch (FormatException ignored) { }` — the exact spelling this rule's
    message prescribes — while `catch (FormatException) { }` and `catch { }`
    compile clean. The escape hatch is the one spelling C# warns you off, which
    explains the zero without appealing to taste.

  The naming exemption stays in both rules: it is still the only way to silence
  one case in code rather than with `// nosemgrep`. It simply is not evidence
  that the rule is precise, and it no longer carries a tier. It was **not**
  widened to `_`, `cannotHappen` or `unused` — every word added is another way
  for a real swallow to escape by being well named. Patterns and recall are
  untouched; only the tier moved.

- **`scan_sast` now loads the project's own rules**, from
  `.dev-guardian/configs.json` where there is one, falling back to
  `.semgrep.yml` / `.semgrep.yaml` — and `configs/pre-commit/pre-commit-config.yaml`
  now passes `--config=.semgrep.yml` alongside `--config=auto`. A guard comes
  with it, because loading a file the user owns is a new risk: a `--config`
  Semgrep cannot load aborts the **whole** run (`paths.scanned: []`, exit 7),
  not just that pack, so every candidate is parsed and shape-checked first and
  one that would abort the scan is dropped **and named in `tools_run`** rather
  than passed through. A rule that merely fails to compile is a different case
  — exit 2, everything still scanned — and now counts as a real scan that lost
  one rule instead of flipping the whole result to `failed`.

- **Every scan tool now emits at most one config-drift line into `warnings`.**
  It is never a finding, never an error, and cannot move a scan's status or the
  CI exit code. **Silence is the default**: a user who edited their own config —
  the common case, and the intended one — is told nothing, because a warning
  that fires on almost every project is a warning nobody reads. Only two states
  speak, worded differently because their remedies differ: *we shipped a newer
  baseline and your copy is unchanged* (a fix may be missing, here is how to get
  it), and *both sides moved* (the refresh will need a merge). A project with no
  provenance manifest gets no warning at all rather than a wrong one.

- **`map_attack_surface` stops fabricating routes, which changes what
  `scan_dast` will send requests to.** `guardian-route-express` matched any
  two-token method call whose first argument was a `/`-leading string, so
  `cache.get('/etc/passwd')`, `cache.delete(...)`, `storage.get(...)`, an
  axios-style `api.get(..., {timeout: 1})` and `http.post('/webhook/out', body)`
  were all reported as routes at `confidence: high`, `path_partial: false`. That
  inverts the bias `extract.ts` states — emitting a path we did not read is
  worse than emitting nothing. Three guards, each ablated on both axes: reject a
  one-argument call (no framework registers a route without a handler, and
  Express's own one-argument form is the settings getter), reject a two-argument
  call whose second argument is an object literal (a handler never is), and a
  short `$APP` denylist of Node core modules, HTTP clients and Web Storage
  globals for `http.post`, which is syntactically identical to a real route.
  Decoy routes went **10 to 4**, and the four that remain are undecidable rather
  than untried, and pinned as such.

### Removed

Three rules are deleted. None was deleted for firing too much; each was deleted
because nobody could produce a true positive for it.

- **`bugfix-cs-null-safety-as-cast-deref`** — the C# pack is **eleven** rules,
  not twelve. It matched `var $V = $O as $T;` followed by `$V.$M` and fired
  **6490 times** on `dotnet/runtime` (`src/libraries/*/src`, 11 800 `.cs` files,
  `paths.scanned` asserted before any count was read). For scale, on the same
  corpus `empty-catch` fires 402 times and `lock-on-shared-instance` 322. **The
  count is not the argument; two measurements are.**
  - **The rule's premise is not expressible in this engine.** Semgrep's C#
    frontend puts `o as T` and `(T)o` on the **same node**. `pattern: var $V =
    $O as $T;` and `pattern: var $V = ($T)$O;` match exactly the same sites,
    line for line, and a `patterns:` group combining the first with
    `pattern-not:` the second returns **zero**, because the negation annihilates
    every match. There is no spelling that catches the `as` and lets the direct
    cast through — and that distinction *was* the rule, since a direct cast
    throws `InvalidCastException` at the cast site and never yields null. By
    textual attribution over the corpus, **4385 of the 6490 findings (67.6 %)
    come from a direct cast** and only 1122 (17.3 %) from an `as`.
  - **The remaining 17.3 % were not true positives either.** 75 findings read by
    hand across dozens of assemblies: **zero live bugs**. Real C# guards are not
    the eleven in the exclusion list: `null != x`, `while (x != null)`,
    `x is null || …`, `Debug.Assert(x != null)`, a reassignment in the null
    branch, a `[DoesNotReturn]` helper, any `&&`/`||` chain of three or more
    terms (it associates left, so `$V != null && <… $V.$M …>` never matches),
    and — the largest — **any `if (x != null) { … }` whose block holds more than
    one statement**, because the exclusion requires a single-statement block and
    every `misses/` fixture had one. A deliberately generous filter ("the name is
    not in any null test anywhere nearby") leaves **70 of 6490 findings, 1.1 %**,
    and reading those leaves five variables with the genuine shape, all latent,
    none a live bug.

  Ablation axes 0, 1 and 2 all passed throughout, on nine hits and fifteen
  near-misses written by the rule's own author — the largest `misses/` file in
  the pack. None of that could see either defect. Gone with it: `hits/AsCast.cs`,
  `misses/AsCast.cs`, and the as-cast entry in `hits/RealBugs.cs` (now 12 defects
  over 11 rules). A deletion note in the pack records both probes, so nobody
  re-adds it without a way to tell `as` from a cast.

- **`bugfix-go-edge-case-append-discarded`** — the Go pack goes from ten rules
  to **nine**. It matched `append(xs, 1)` in *statement* position, which the Go
  spec's *Expression statements* section forbids and the compiler rejects
  outright (`append(xs, 1) (value of type []int) is not used`). Its
  true-positive set was therefore **empty in any project that compiles**, and
  everything it emitted in a real repository was a false positive — three
  measured: `for _, v := range append(xs, 0)`, `ch <- append(xs, 1)` and
  `return &box{items: append(xs, 1)}`. Its own hit fixture did not compile, and
  had not for two releases. Deleted rather than redesigned: the bug that *does*
  compile is only a bug when the reassigned slice never escapes the function,
  which is a dataflow property, and `staticcheck` / `ineffassign` already cover
  it with actual dataflow. **Every Go fixture in the pack is now compiled** with
  `go build ./...` (and `gofmt -l`) in `golang:1.22-alpine` as part of the change
  process; that check is what caught this.

- **`bugfix-js-error-handling-catch-returns-null`** — the JS/TS pack is now
  **thirteen** rules. It matched `try { … } catch { return null|undefined|[]; }`.
  Two independent corpora say the same thing: five instances of textbook-correct
  code and zero true positives on the auditor's probes, and **25 findings on this
  repo's own `mcp/src`, every one of them correct code** — the safe-`JSON.parse`
  helper, a `readdirSync` with a `[]` fallback, `runtimeMeta.getJson` with a `[]`
  fallback. Returning an empty value from a catch is a documented JavaScript
  idiom, not a defect shape, and there is no syntactic difference between the
  idiom and a genuine swallow — every candidate narrowing was measured and
  silences the rule's own hit fixture too. It had been demoted to `INFO` earlier
  in this same cycle; that was the wrong call. **`INFO` is not a tier for a rule
  that has never been right, it is a quieter way to keep being wrong**, and it
  still costs everyone who reads the output.

### Added

- **A C# bug pack — `configs/semgrep/bugfix-cs.yml`, eleven rules** across all
  six `bug_hunt` subcategories, always on, each with a hits/misses fixture pair.
  **The registry gap here is total, and it was measured with positive controls
  rather than assumed**: `p/r2c-bug-scan` reports `paths.scanned = 0` on the C#
  fixtures — it ships **no C# rules at all** — and `p/csharp` and
  `p/security-audit` scan every file and find nothing. Because a pack that never
  ran is indistinguishable from a clean result, that control is a **Python** file
  inside a C# fixture tree: there is no C# rule for a C# control to trip.
  - **A compiler as an independent oracle, which no round in this series had
    before.** `dotnet build` emits `CA2200` for `throw ex;` inside a catch, at
    exactly the nine sites the rule fires on and zero in the near-miss fixture,
    so the hit/miss split was not graded by the rule's own author; `CA2002` does
    the same for the `lock` rule. Recorded just as deliberately: **`CA5394` is
    not an oracle** for the `Random` rule, because it fires on all four correct
    sites too — it is about cryptographic predictability, not a data race.
    Confirming that an oracle is not an oracle is worth as much as confirming
    that one is.
  - **The oracle immediately earned its place**, finding that a trailing
    `finally` made both `error_handling` rules silent: a `try/catch/finally` is
    a different AST node and the two shapes are disjoint, so neither pattern
    subsumes the other. `CA2200` fired on a `throw ex;` whose catch had a
    finalizer and Semgrep did not. The same hole was found and fixed in
    `bugfix-java.yml` in this release.
  - Stated limitations, all measured: `memory_leak` is carried by a single rule
    (the `IDisposable` one is **not expressible** — Semgrep's C# frontend erases
    the `using` modifier from a using-declaration, making the
    Microsoft-recommended idiom byte-identical to a leak, and a rule that flags
    `using var` is worse than no rule); `blocking-on-task` misses
    `var t = GetAsync(); t.Result`, `Task.Run(...).Result` and a dotted receiver;
    `ordefault-deref` cannot see generic arguments; `off_by_one` keeps Java's
    sentinel false positive; `.Count` covers eight enumerated receiver types and
    nothing outside them, because `metavariable-type` is **not subtype-aware**;
    and `Dictionary` is deliberately excluded from `modify-during-iteration`,
    removal during enumeration having been documented safe since .NET Core 3.0.

- **A PHP bug pack — `configs/semgrep/bugfix-php.yml`, six rules**, always on,
  each with a hits/misses fixture pair: off-by-one, TOCTOU, empty catch,
  `strpos()` truthiness, `json_decode()` dereference and loose null comparison.
  **This is the first round in the series measured against an external corpus
  from the start** — WordPress 6.9, 1467 files scanned — and that axis changed
  four verdicts. Six candidates were killed by measurement rather than by
  argument: an error-suppression (`@`) rule at **420** findings, `preg_match`
  groups at 132, loose `in_array` at 117, `foreach`-by-reference at 46 (every
  sampled one latent rather than live — a style rule, not a bug rule), an
  `fopen` leak rule that is inexpressible, and one whose bug **does not exist in
  PHP**: `foreach` iterates a copy, confirmed in the interpreter.
  - **`memory_leak` is an EMPTY class in this pack, and that is stated rather
    than implied.** Both ends of the dial were measured: with the escape
    exclusions the rule finds **0 of 3** hits, because a leaked handle is always
    *used* by something and `$F(..., $H, ...)` swallows every true positive;
    without them it fires on **4 of 4** correct shapes.
  - **A fifth governing rule for the series, and it is new: run the WHOLE PACK
    against the prescribed-fix file, not each rule against its own.** The
    `@`-suppression candidate passed every per-rule check and was killed only
    here. `toctou-file`'s own message prescribes "act first and inspect the
    return value", whose idiomatic PHP is `@mkdir(...)` / `@unlink(...)` — so in
    the file where every bug is rewritten with the fix its own message asked for,
    that candidate fired three times, all three on another rule's prescribed fix.
    One rule firing on another rule's prescribed fix is not a tuning problem, and
    no per-rule check can see it.
  - **PHP is strictly easier than C# or Java in one place, and it is the round's
    free win.** Both of those packs needed an enumerated `metavariable-type` list
    to keep the off-by-one rule off domain objects carrying a `.Count`/`.length`
    member. In PHP that false positive cannot arise: `count()` is a **global
    function** and `$obj->count()` is a method call, a different node. Verified
    against a class carrying both a `->length` property and a `->count()` method
    inside `<=` loops — silent on both. No type list is present and none should
    be added.
  - Traps, measured, all stated in the pack: **a fully-qualified type name in a
    PHP pattern matches nothing, silently** (`catch (\RuntimeException $E)` found
    **zero** occurrences of source reading exactly that — the PHP twin of C#'s
    `var` trap; bind the type to a metavariable); the `metavariable-regex` on the
    catch variable **suppresses a CRASH** rather than being redundant (without
    it, `catch ($E $V)` breaks the matcher on any file containing a PHP 8
    non-capturing `catch (T) { }` — `Internal matching error … NoTokenLocation`
    — while matches elsewhere in the file survive, and the process exits **0**);
    **`?->` and `->` are the same AST node**, so a `pattern-not: $V?->$M` does not
    exclude the safe idiom, it deletes the rule; **the PHP 8 non-capturing catch
    is unmatchable** by any AST pattern, which is also a self-exemption, since it
    is how modern PHP declares deliberate silence; **the try shape is a
    dimension** (`try{}catch(){}` and `try{}catch(){}finally{}` are disjoint
    nodes, and the no-finally pattern alone scores 5 of 6 fixture sites —
    enumerated before the rule was written this time, not after); and prefer
    `for (...) ...` to `for (...) { ... }`, since the statement ellipsis matches
    the braced body, the brace-less body **and** the `for(): … endfor;`
    alternative syntax.

- **A Rust pack of exactly one rule — `configs/semgrep/bugfix-rs.yml` — and one
  rule is the whole answer.** `bugfix-rs-race-condition-blocking-sleep-in-async`
  matches a `std::thread::sleep` inside an `async fn`, which blocks the executor
  *thread* and stalls every other task scheduled on it. **This is not partial
  Rust coverage and must not be read as one**; the file header says so at length
  so the next reader does not mistake it for abandoned work.
  - **Twelve of thirteen candidates were measured and killed.** Four of the six
    bug classes are **compile errors** in Rust — `E0502` for
    modify-during-iteration, `E0515` for use-after-free, `E0373`/`E0503` for a
    data race on shared state, `E0599` for a null dereference. Not rare:
    impossible in code that compiles. For the rest the answer is `cargo clippy`,
    whose type-aware lints beat every Semgrep equivalent measured — default
    already catches `await_holding_lock`, `-W clippy::pedantic` adds `float_cmp`
    and `future_not_send`, and the `restriction` group adds `unwrap_used`,
    `mem_forget`, `indexing_slicing`. The docs now tell Rust users that
    explicitly rather than implying a gap dev-guardian intends to fill.
  - **Two candidates that passed their own fixtures were killed by real code**,
    and this is the strongest evidence the series has produced for the real-code
    ablation axis: `mem-forget` scored **43 findings and zero true positives** on
    ~1200 files of the actual Rust standard library, and `unwrap-in-drop` flags
    `if !thread::panicking() { r.unwrap(); }` — the canonical mitigation its own
    message prescribes. Both would have shipped under a C#-style round, where
    that axis was permanently `N/A` for want of a corpus.
  - **A measured Semgrep trap running in two opposite directions in one
    pattern.** `async fn $F(...) -> $R { ... }` is the NARROW form: `-> $R`
    requires a written return type, so it found **2 of 4** bugs with
    `paths.scanned` healthy and zero errors. For *paths* it inverts: the engine
    resolves `use` declarations, so the fully-qualified `std::thread::sleep(...)`
    matches all three spellings while the short `thread::sleep(...)` matches only
    one.
  - The rule is `WARNING`, against the probe's reading, because handing blocking
    work to another thread *is* written inside an `async fn`:
    `thread::spawn`, `tokio::task::spawn_blocking` (the fix the rule's own
    message prescribes), `async_std::task::spawn_blocking`, `rt.spawn_blocking`
    and `thread::Builder::new().spawn` all fired before the exclusion existed. It
    excludes them by call *name* rather than by path, **and** by closure rather
    than by name alone, because a name-only exclusion swallowed
    `tokio::spawn(async move { … })`, which keeps the work on the executor and is
    a genuine bug. A name list never closes, which is the `WARNING` condition
    word for word.

- **Nothing ships for Ruby, also by measurement.** Semgrep's Ruby frontend
  erases `&.` and the `..`/`...` distinction — `x&.a.b` and `x.a.b` produce
  byte-identical ASTs — so every nil-safety and off-by-one rule matches the
  correct code and the buggy code identically, in the language whose signature
  runtime error is `NoMethodError` on nil. Five further candidates passed their
  fixtures at 0 false positives and were killed by 1244 files of real Ruby.
  RuboCop and the registry's `p/ruby` are the honest answer, and the docs say so.
  The full measurement is in

- **`scan_sast(local_only: true)`** drops the registry, passes `--metrics=off`,
  and runs only rules already on disk — your project's `.semgrep.yml` plus
  anything added with `register_custom_rules`. Nothing leaves the machine, at the
  cost of the registry's rules. When the project has no local rules it reports
  the scan as **skipped** rather than as a clean result, because zero findings
  from zero rules is not a clean bill of health. That mode only became coherent
  rather than empty once the project's own config started being loaded, which is
  why the two arrived together.

- **Configuration-drift detection for the configs `init_project` installs.**
  `init_project` copied four baseline configs into a project and then never
  looked at them again — an existing target was skipped as `already_exists`,
  which is the right call, since the user owns and edits those files, but it
  meant a fix to a shipped config could never reach anyone who had already run
  init. Nothing recorded what had been copied, so nothing could notice. The
  `wp-unescaped-output` incident above is what that costs. Four parts:
  - **A provenance stamp.** `init_project` records each file it copies in
    `.dev-guardian/configs.json` — target, source, plugin version, and a content
    hash at copy time — and stamps a comment header into the file itself where
    the format allows one. The manifest is the mechanism and the header is an
    affordance on top, because `renovate.json` is JSON and a `//` line would
    break the parser Renovate reads it with. It is a separate directory from
    `.guardian/`, which `gitignoreGuard` adds to `.gitignore` on every server
    start: a provenance record has to be committed alongside the configs it
    describes, or a teammate's clone and CI learn nothing.
  - **`init_project(refresh=true)`**, opt-in, never a default — see *Action
    required* for the semantics. **No flag overwrites a modified file.** The
    delivered file is not called `<name>.new`, because that name is not ours: a
    user can be keeping their own `.semgrep.yml.new`, and writing over it is the
    same data loss the rule exists to prevent. Even the versioned path is
    **refused** (`alongside_blocked`) rather than overwritten if it exists and is
    not recorded as our own previous delivery, and re-running a refresh while a
    delivery is still unmerged reports `pending_merge` and rewrites nothing.
  - **Graceful degradation for projects with no manifest**, plus two adoption
    paths that close the gap: plain `init_project` now records provenance for any
    skipped file that is byte-identical to what we ship, and `refresh` adopts the
    rest as it delivers to them.
  - The hash is taken over a **canonical form** — CRLF/CR normalised to LF,
    leading BOM dropped, trailing newlines trimmed, our own header stripped — not
    over raw bytes. A byte hash gets the answer wrong on this project's own
    platform pair: git's `core.autocrlf` rewrites line endings on checkout, so the
    identical commit would read as "the user edited their copy" on Windows and
    "they did not" on Linux, and a false *local edit* silences the one state that
    matters.

- **An ablation harness for the rule packs — `npm run ablate -- <pack|all>`**,
  in `mcp/test/ablate/`. Ablation — delete one clause, re-run the pack, see
  whether the result moves — is how every one of the six do-nothing exclusion
  clauses in this series was found; it had been written from scratch three times
  in a scratchpad and thrown away three times. Four verdicts, each added after a
  defect escaped the previous ones:
  - **axis 0, fires on `hits/` at all** — a property of the *rule*, and the only
    one that reaches a rule with no clauses. A rule that matches nothing is the
    sixth silent-failure mode: in C#, `foreach ($T $X in $C)` found **0 of 5**
    real bugs where `foreach (var $X in $C)` found all five, with
    `paths.scanned` healthy, zero errors and every gate green.
  - **axis 1, live** — removing the clause changes the result somewhere.
  - **axis 2, keeps true positives** — removal must not *reveal* findings in
    `hits/`, since `pattern-not-inside` excludes the whole node it matched and a
    guard written for an `if` also swallowed the `else` arm, where the bug was.
  - **axis 3, no rise in the real-code count** — scan a corpus nobody wrote as a
    fixture and compare. This is the axis that caught `unchecked-match` going
    0 → 13 false positives on our own TypeScript while axes 1 and 2 both passed,
    and the axis that deleted `as-cast-deref` once C# finally had a corpus. It is
    a property of the invocation, registered per pack, overridable with
    `--real-code=<dir>` / `--no-real-code`, and reported as `N/A` — never a
    silent skip — where none exists. Two packs read theirs from an environment
    variable because the corpus cannot live in this tree, `GUARDIAN_RUST_SRC` and
    `GUARDIAN_CS_SRC`: unset means `N/A`, **set-but-missing throws**.

  **The report leads with a coverage line, because the fractions lied.**
  `44/44 live, 0 DEAD` read as "the pack was checked" while covering 10 rules of
  11. Axes 1–3 are properties of a *clause*, and two rule shapes have none — a
  bare `pattern:`/`pattern-regex:` with no `patterns:` group and no
  `pattern-either:`, and a `patterns:` group holding nothing but positive terms.
  **30 of the 135 rules across the nine packs** are one of those, and they used
  to appear nowhere in the report, not even under `skipped`. The capability was
  never missing — there is genuinely nothing to ablate; the *reporting* was
  dishonest, in exactly the way axis 3 refuses to be when it prints `N/A`. Every
  rule is now listed under `RULE COVERAGE` with its clause count and its `hits/`
  count, and each clauseless rule is named with the reason it has none.

  Four invariants, each of which cost something to learn: **the pack is never
  written to** (read once, hashed, variants go to a temp dir — byte-identical
  after a crash or a Ctrl-C, with no restore path that can itself fail, and the
  on-disk hash re-checked before every ablation); **clauses are named by body
  text, never by line number** (all 86 `- pattern-not-inside:` first lines in
  `bugfix-java.yml` are identical, so a line-numbered verdict is unattributable
  once a comment edit shifts the file — which is exactly how a previous
  hand-rolled run was lost); **`paths.scanned == 0` is an exception, not a
  result**; and **a round-trip control runs first**, re-serialising and scanning
  the unmodified pack before anything is ablated, so the run aborts rather than
  measure the serialiser. Exit code is 1 when any clause is flagged or any rule
  fires on nothing.

- **Cross-pack invariants for every Semgrep rule file** —
  `mcp/test/integration/semgrepPacks.test.ts`. The locale-codec byte check and
  `semgrep --validate` now run over **every** pack in `configs/semgrep/`,
  discovered by reading the directory rather than from a list, so packs still to
  come are covered by existing on disk. The banned set is **exactly** `U+00C1`,
  `U+00CD`, `U+00CF`, `U+00D0`, `U+00DD` — the characters whose UTF-8 encoding
  contains a byte cp1252 leaves undefined, of which only the first two occur in
  Portuguese; the broad form of the rule, "no uppercase accented letters", is
  wrong for ten of the twelve accented capitals Portuguese uses. A **positive
  control** copies a real pack to a temp directory, injects one A-acute, and
  asserts the byte scan names the character, that `--validate` refuses it, and
  that a real scan then returns `results: 0`, `paths.scanned: 0`, `errors: 0` —
  asserting that every pack is clean proves nothing if the check has quietly
  stopped working.

- **A real-bugs corpus per pack, written by the auditor rather than by the
  rules' author** — `mcp/test/fixtures/bugfix-*/hits/real_bugs.*`, with at least
  one defect for **every** rule in each pack, and counts asserted per file plus a
  total. Each defect sits next to the guard shape its rule's exclusions match — a
  leaked HTTP response in the same function as a correctly closed one, a
  discarded error beside a `sync.Map.Load`, an unguarded assertion on a
  *different* variable inside a type switch, an un-awaited coroutine beside an
  awaited one — so that widening any exclusion by one step turns the file red. A
  minimal per-rule hit fixture carries no guard shapes for an exclusion to catch
  on, which is how a wave of false-positive work can delete recall and still go
  green; the Java pack learned that with a fixture that went from 6 findings to 1
  unnoticed.

- **Fixture coverage for `base.yml`** — `mcp/test/integration/baseRules.test.ts`
  and a hits/misses pair per rule, asserting the exact rule-id set, the raw
  non-deduplicated finding count and `paths.scanned` per file. Every line in
  `misses/` was checked against a *deliberately broken* variant of the rule it is
  a near-miss for, so each one is silent for a reason belonging to the rule rather
  than by coincidence. The scan runs through `spawnSync`, not `execFileSync`,
  because `--quiet` leaves stderr **empty** for a rule that failed to compile and
  puts the id in the JSON `errors` array instead: the old form reported the dead
  PHP rule as a bare "Command failed: semgrep --config …" four times without
  naming it once.

### Fixed

- **The JS/TS pack, read by someone who did not write it: ~40 false positives
  across 14 rules.** `configs/semgrep/bugfix-js.yml` shipped in 1.6.0 and had
  never been read by anybody but its author; every fixture behind it had been
  written by that author too, so each one tested the author's INTENT rather than
  what the pattern binds to. Three were catastrophic on real codebases:
  - **`null-safety-unchecked-find` had zero true positives.**
    `$A.find(...).$PROP` binds to any method named `find`, and `$PROP` matches
    method calls, not just property reads. In any Node backend on Mongoose or the
    Mongo driver, or any page using jQuery, it fired at **ERROR** on essentially
    every query — `User.find({}).sort(…)`, `collection.find({}).toArray()`,
    `$('#root').find('.item').addClass(…)` — and advised `?.`, which is wrong
    advice for a Query object. Nine reproductions, none of them a bug. It now
    requires the single argument to be a **literal callback**, the only thing
    that separates `Array#find` from a Mongoose query (an object), a jQuery
    selector (a string) or Immutable's `find(fn, ctx, notSetValue)` (three
    arguments), with no type inference available.
  - **`race-condition-floating-mutation` was wrong 12 times out of 15**,
    including on `res.send(rows)` — the most common line in an Express app — and
    on `void repo.save(a)`, **the fix its own message prescribes**. A rule whose
    prescribed fix does not silence it teaches people to ignore it.
  - **`off-by-one-loop-lte-length` told loops that never index anything that they
    read past the end.** `<= .length` is correct whenever a loop counts
    boundaries rather than elements, and the rule fired at ERROR on all of them.
    It now matches the out-of-range **read** and uses the loop only as context,
    which makes the message true by construction.

  Also closed: a `finally` clause silenced `empty-catch` outright; the listener
  rule's pattern took exactly two arguments, so `{ passive: true }`,
  `{ once: true }`, `{ signal }` and the legacy boolean third argument were
  invisible; the interval rule required `const $T =`, so `setInterval(tick, 1000)`
  with no handle captured — an interval nobody can ever clear, the strongest form
  of the bug — was silent; that rule's exclusions keyed on the shape of the
  CONTAINER rather than on whether the timer was cleared; an early `return` of a
  cleanup suppressed the leak in the branch AFTER it; `unchecked-env` missed
  bracket access and property reads; `unchecked-match` missed `RegExp#exec`; and
  `reduce-without-initial` fired on array literals, which cannot be empty.

- **The JS/TS pack, then measured against this repo's own `mcp/src`** — 183 files
  of TypeScript nobody wrote as a fixture, chosen by neither the rule author nor
  the auditor. The check is cheap, needs no fixture, and caught two things that
  36 two-axis ablations did not, because "the clause is live" and "it does not
  reduce true positives" are **both true of a clause that only adds false
  positives**:

  | rule | before the audit wave | after it | now |
  | --- | --- | --- | --- |
  | `race-condition-floating-mutation` | 20 | 0 | 0 |
  | `null-safety-unchecked-match` | 0 | **13** | 0 |
  | `error-handling-catch-returns-null` | 25 | 25 | *deleted* |
  | `error-handling-empty-catch` | 42 | 42 | 42, now WARNING |
  | `error-handling-empty-promise-catch` | 3 | 3 | 3, now WARNING |
  | total | 90 | 83 | 45 |

  The `floating-mutation` column is the audit wave working exactly as intended on
  code none of us picked. The `unchecked-match` column is a **regression the
  audit wave introduced**: its new `RegExp#exec` branch did not inherit the
  optional-chaining exclusion the `match` branch already had, so guarded
  `exec(...)?.[1]` started firing — 13 of them, all correct, against the single
  true positive the branch was added for. The 45 remaining `empty-catch` findings
  are **all deliberate, comment-documented fail-open**, which Semgrep cannot read
  — the measurement that moved both rules to `WARNING`. JS/TS has no
  machine-readable intent marker of comparable standing, and the reason is
  structural rather than cultural: **ES2019 optional catch binding removed the
  identifier a naming convention would attach to**, and 41 of those 42 are
  written `catch {`, with nothing to name. The `_`/`_e`/`_err` escape hatch is
  honoured anyway so one case can be marked in code instead of with
  `// nosemgrep`, and stated rather than implied: **it removed zero of the 42.**

- **Python and Go: ~60 false positives closed, and the false negatives the fixes
  exposed.** Both packs shipped without an audit (1.7.0 and 1.8.0). Every clause
  below was ablated on both axes — deleting it has to turn a test red *and* must
  not increase the true-positive count.
  - `none-deref-dict-get` bound **anything** with a one-argument `.get`, so
    `User.objects.get(user_id).delete()` (Django's `Manager.get` *raises*; it
    never returns `None`), `queue.Queue.get(True)` and three HTTP clients all
    fired at `ERROR` — and the advice printed on the Django line, "pass a
    default", is advice `Manager.get` does not accept. The receiver *substring*
    allow-list also made real dict bugs invisible: a Flask/Django `session` **is**
    a dict. It now keys on the **key** — a string literal that is not a URL or
    path. Eight false positives to zero, and `session.get("user_id")` now fires;
    the cost is a lookup with a variable key.
  - `get-without-doesnotexist` recognised only handlers with no `as` binding, no
    tuple and no `else`, so **6 of 6** correctly guarded shapes fired. The
    exclusions now filter the caught type through **nested formulas** inside
    `pattern-not-inside` (a rule-level `metavariable-regex` cannot see it —
    negated patterns export no bindings), scoped to the `try` **body**, which
    also fixes the whole-node defect that silenced an unguarded `.objects.get()`
    in the `except` arm.
  - `except-pass` and `bare-except` were **silenced outright** by adding a
    `finally:` or an `else:` to the same swallowing `try`, and `except (A, B):
    pass` was silent while the `as` form fired. `bare-except` no longer fires on
    cleanup-then-`raise`, the dominant legitimate use.
  - `queryset-n-plus-one`: `$O.$REL.$FIELD` bound **any** two-deep chain, so
    `book.title.strip()`, `user.email.lower()` and `line.amount.quantize(2)` all
    fired, each advised to add `.select_related("title")`. The finding is now the
    chain rather than the loop, and `select_related`/`prefetch_related` became
    *real* exclusions — they used to be silent only because any chained call
    broke the `.all()` anchor, so they would have stayed green against a
    deliberately broken rule.
  - Also: `range-len-plus-one` on `d[len(d)] = v` in *assignment target*
    position; `open-without-context` on five kinds of ownership transfer;
    `toctou-exists-open` knowing exactly two function names;
    `none-deref-match` knowing only `.group(...)`; `asyncio-not-awaited` on
    `yield asyncio.sleep(1)`.
  - `off-by-one-loop-lte-len` (Go) required **nothing** of the loop body — the
    fix the Python rule has carried since it shipped was never applied here — so
    every DP seed, prefix-sum array and insert-position loop fired at `ERROR`:
    **4 of 4** correct `n+1` loops in the corpus. Requiring `<... $XS[$I] ...>`
    takes that to zero with the true positive intact.
  - `err-discarded` (Go) assumed the second return value is an error.
    `sync.Map.Load` alone made it fire across most concurrent Go;
    `strings.CutPrefix` and `utf8.DecodeRune` return `(string, bool)` and
    `(rune, int)`. `body-not-closed` was anchored to `http.Get` alone, so
    `client.Do(req)` — what every real client uses — plus `http.Post`,
    `http.PostForm`, `http.Head` and `http.DefaultClient.Get` leaked silently,
    while three *correct* closes fired. `lock-without-defer` was **redesigned
    around the bug** instead of the idiom: it fired on the two shapes where a
    `defer` would *be* the bug, and now looks for a `return` *between* the `Lock`
    and the `Unlock`, gaining the `RLock`/`RUnlock` branch that was entirely
    missing. `nil-map-write` could not see the classic `c := &config{}` followed
    by `c.Labels["env"] = "prod"`. `err-blank-assign` fired on
    `var _ io.Writer = newWriter()`, the compile-time interface assertion.
  - **Dead clauses removed, measured by ablation rather than by reading**: in Go,
    `err-discarded`'s `$X, _ := $F(...)` branch, one of `type-assert-no-ok`'s two
    mutually redundant `pattern-not-inside` clauses, `lock-without-defer`'s
    trailing `...`, `err-blank-assign`'s `var _ $T = $F(...)`, `err-discarded`'s
    `strings.Cut` (three return values, so it never matched), and three of
    `body-not-closed`'s seven close exclusions; in Python,
    `queryset-n-plus-one`'s second `pattern-inside` anchor. Where a live clause
    had no fixture behind it, a **fixture was added rather than the clause
    deleted**.

- **Java: the pack no longer fires on correct Java, and the exclusions that
  closed those false positives no longer eat real bugs.** Seven review sweeps,
  the last four of which are the interesting ones. The first two found **19**
  findings on correct code across five of the eight rules; a fourth found **16**
  more plus a false negative; the sixth and seventh closed the `keySet()` and
  conjunction-chain classes below. All are gone, every one pinned by a near-miss
  fixture, and so are the two recall regressions that closing them introduced.
  - `null-safety-optional-get-no-ispresent` was never about `Optional`:
    `$O.get()` matched **any** zero-argument `get()`, so `AtomicInteger.get()`,
    `ThreadLocal.get()` and `Supplier.get()` all fired at ERROR.
    `null-safety-map-get-deref` was never about `Map`: `$M.get($K).$METHOD(...)`
    matched **any** one-argument `get` chained with a method, so
    `list.get(0).trim()` fired at ERROR and advised `getOrDefault`, a method
    `List` does not have. Both are restricted by declared type now.
  - **`map-get-deref` shipped with no guard exclusion at all**, so the canonical
    Java guard `if (m.containsKey(k)) { … m.get(k).trim() … }` fired at ERROR on
    already-guarded code. It now excludes the measured shapes that prove the key
    present, including **iteration over the map's own `keySet()`** — the
    commonest map-iteration idiom in Java — with the clause unifying **both** the
    map iterated and the key passed to `get`, so iterating one map while
    dereferencing another still fires.
  - **`pattern-not-inside` excludes the whole node it matched, and that was a
    shipped regression before it was a lesson.** `if ($M.containsKey($K)) { ... }`
    matches the entire **if-else statement**, so both arms were excluded. On a
    file of eight guaranteed `NullPointerException`s / `NoSuchElementException`s
    — the dereference in the `else` arm of the guard, or in the ternary arm the
    condition rules out — **6 fired before the guard wave, 1 after, 8 now**.
    Every guard exclusion is now scoped to the arm the guard actually proves.
  - **`edge-case-modify-during-iteration` was hiding a real
    `ConcurrentModificationException`.** A `remove()` inside a `switch` followed
    by `break;` was excluded by the paired `remove(); break;` clause — but that
    `break` leaves the *switch*, not the loop, so the for-each calls `next()`
    again on a mutated collection. The plain-`break` exclusion now applies only
    outside a `switch`, and the `switch` re-inclusion nests the `switch`
    **inside the for-each over that collection**, so the clause tests the nesting
    ORDER rather than matching lexically anywhere inside a `case`.
  - **A `finally` clause silenced two of the pack's rules outright — the third
    pack in a row with the identical hole.** A Java `try` *with* a finalizer is a
    different AST node, so attaching `finally { cleanup(); }` to a swallowing
    catch made `empty-catch` and `printstacktrace-only` report nothing at all:
    **3 of 6 → 6 of 6** in each. `memory-leak-stream-not-closed` had it in the
    **opposite direction** — there the try shape lives in an *exclusion*, so
    **four correct shapes fired at WARNING on streams that are closed**. Zero
    now.
  - **The accepted-limitations table had nine rows and every one was a false
    positive.** That asymmetry is the shape of the defect the last sweeps were
    about: nobody was looking in the recall direction, so nothing was ever
    written down there, and a wave could close a false positive, silently delete
    recall, and still go green. Every row now states its **direction**, and the
    recall-side rows are new — the **invalidated-guarantee** class (a guarantee
    the guard establishes and the code then *destroys* inside the region the
    exclusion covers, which is the whole-node problem on the **temporal** axis
    instead of the branch axis; five measured reproductions, every one a
    guaranteed throw, every one silent) and the local-boolean guard.
  - **One row left the table, which is the other half of the lesson.** The
    conjunction-chain false positive sat there for four waves under two
    successive justifications, and both were reasoning about variables that did
    not control the outcome. Re-measured, it was not a limitation at all, and the
    clause that closes it costs nothing: `flag && m.containsKey(k) &&
    m.get(k).isEmpty()` and its `||` duals are ordinary correct Java, and a Java
    conjunction nests to the left, so **one clause per guard covers a chain of
    any length**. A row here is an assertion with no test behind it — unlike
    every other claim in these packs — so a row that has never been re-measured
    is exactly as trustworthy as the day someone wrote it, and no more.

- **The three C# rules that found NOTHING on 11 800 files: two were right, two
  were reading one spelling.** `rethrow-loses-stacktrace`,
  `off-by-one-loop-lte-count` and `edge-case-modify-during-iteration` scored
  **0** on `dotnet/runtime` next to `lock-on-shared-instance` 322. **A zero has
  two readings and they are opposite** — the bug is absent, or the rule is
  silently broken — and this series has nine recorded ways for Semgrep to report
  success while matching nothing. Each was probed with a file carrying the exact
  bug in every idiomatic spelling.
  - **`rethrow-loses-stacktrace` — correct, and confirmed independently.** A
    brace-depth textual oracle with no Semgrep in it finds **201
    `throw <ident>;` statements in the corpus and 0 that rethrow the caught
    variable**, while finding all 10 fixture sites as its positive control.
  - **The two off-by-one rules — correct, but each read one spelling of two
    dimensions.** The prime suspect was `var`, and **the reverse of the pack's
    own warning does not hold**: `var` in a *pattern* is a wildcard for the
    declared type, so `for (var $I = 0; …)` matches `for (int i = 0; …)` exactly.
    Two other dimensions did bite, and **neither had a fixture, so neither could
    ever have moved a number**: `i++` matched and **`++i` did not** (a different
    node), and `{ … }` did not match a **braceless** body. Both are ordinary C#;
    `dotnet/runtime` writes `++i` in a `<=` header itself. Closed with a
    two-branch `pattern-either` and an ellipsis body on both rules.
  - **Receiver types added on the same measurement**: `Collection<T>` and
    `ObservableCollection<T>`, to `loop-lte-count` (six types → eight) and
    `modify-during-iteration` (four → six). `metavariable-type` is not
    subtype-aware, so each type is an independent claim, probed one at a time.
    **The widening cost zero findings on the same 11 800 files** — shipped pack
    against widened pack, compared per rule, every delta 0 — and the three zeros
    stay zero, which is now a measurement rather than a silence.

- **A caveat this corpus needed and did not have: these counts are noisy.**
  `empty-catch` came back 407 in one run and 402 in the next — the *same pack*
  over the *same corpus* — because semgrep-core's per-rule timeout is not
  deterministic and it gives up on a handful of very large files. Thirteen
  timeouts versus eighteen accounts for all five findings, exactly.
  `paths.scanned` reads 11 800 either way, so it is necessary and **not
  sufficient**: the timeouts live in `errors`. A count from this pack is
  comparable only to a count from the same run, which is why every C# number
  above is an A/B compared per rule rather than a before-and-after of a total.
  **The same noise reaches ablation axis 3**, and there it is worse: two runs of
  the same pack over the same corpus disagreed on 6 of the 12 clauses they both
  measured, and all 14 findings the harness attributed to clauses of
  `modify-during-iteration` were `empty-catch` findings in two of the timing-out
  files — a different rule entirely, which is structurally impossible as an
  attribution. Axis 3 compares whole-corpus totals across separately executed
  scans, and the jitter (±5) is bigger than the deltas it reports (2–3).
  Documented, not changed: the fix is to scope the comparison to the ablated
  rule's own findings, and the axis-3 verdicts other packs already carry were
  computed the present way.

- **`routes.yml`: sixteen annotation route rules that never matched the form
  their framework documents.** Each demanded an argument the canonical form does
  not supply, so the most ordinary controller in each framework lost routes —
  silently, because a route this pack does not match produces no error anywhere
  and simply never enters the attack surface. Measured on a corpus written by an
  auditor who did not write the rules (52 endpoints): **18 of 52** were reported
  before this change. **ASP.NET 5 of 15** — a controller scaffolded by
  `dotnet new webapi`, whose actions carry a bare `[HttpGet]` and whose path
  lives on the class `[Route("api/[controller]")]`, mapped to **zero routes**,
  i.e. "this C# API exposes nothing". **NestJS 6 of 12**: `@Get()` and `@Post()`,
  the forms docs.nestjs.com uses for index and create actions, matched nothing.
  **Spring 7 of 25**. All 52 are reported now.
  - **Spring's named-argument forms are matched, and the note in the previous
    release saying they could not be is withdrawn.** `@GetMapping($PATH, ...)` is
    indeed rejected as "Invalid pattern for Java" — but only because the ellipsis
    follows a bare metavariable. `@GetMapping(value = $PATH, ...)` parses cleanly
    and binds `$PATH` to the path literal alone, whatever order the arguments are
    written in. The six Spring rules are now `focus-metavariable: $PATH`, because
    the recovery path that rebuilds captures from byte offsets reads the FIRST
    argument.
  - **A bare annotation is reported with an empty own-path, flagged
    `path_partial` at 'low' confidence** — the endpoint exists, and its full URL,
    being the class-level prefix, is honestly unknown. A companion `mount` rule
    was considered and **rejected**: nothing consumes a mount for these
    frameworks, and adding one would flip every route in that controller from
    honestly partial to confidently wrong, at its un-prefixed path, which
    `scan_dast` would then send requests to.
  - Frameworks that were invisible and are not now: `app.use(prefix, middleware,
    router)` (which cost every route in the mounted file its resolved path), chi
    entirely, `mux.Handle`, qualified `#[actix_web::get]` / `#[rocket::get]`,
    Laravel's fluent / resource / match forms, destructured `process.env` reads,
    the two-argument .NET env overload, and Laravel's `env()` helper. A fluent
    chain reported the first path twice and lost the second — `routePath`
    anchored on the first `(` and now anchors on the call that CLOSES at the end
    of the span, which fixes Hono's canonical style and Laravel's fluent chain in
    one.

- **`base.yml` audited rule by rule, and three of the thirteen were doing
  nothing.** The pack `init_project` copies into a user's project as
  `.semgrep.yml` is the only rule file here that ships to somebody else's
  repository, and it had **no fixture coverage of any kind**.
  - `wp-unescaped-output` had never worked (see *Action required*) and is
    rewritten: a `pattern-either` of `pattern-inside` SCOPES plus a narrow
    `pattern: $SUPER[...]`, so a finding points at the offending subscript and one
    statement can report one operand while staying quiet about another. It now
    sees eight more shapes of real XSS — comma-separated `echo`, nested
    subscript, a ternary operand, `printf`, an interpolated string as a
    concatenation operand, and `$_SERVER` / `$_COOKIE`, `$_SERVER['PHP_SELF']`
    being the canonical reflected XSS in PHP, which the old `GET|POST|REQUEST`
    regex could not reach.
  - **The first fix for its cast false positive was a `pattern-not-regex`, and it
    was wrong in a way worth recording.** A text guard suppresses everything the
    match covers, and the match was a whole statement: of nine real-XSS lines
    carrying a cast somewhere in the same statement, **two fired** — and worse,
    `echo 'use (int)$_GET for numbers: ' . $_GET['x'];` turned the rule off with
    no cast executed anywhere. **In a security pack that is not a documented
    trade; it is a switch any helpful — or hostile — string literal can carry.**
    The cast guard is now six `pattern-not-inside` clauses, which can only remove
    the operand actually wrapped in a cast; six entries cover all eleven
    spellings because int/integer, float/double/real, bool/boolean and
    string/binary collapse to the same node, and enumerating them is legitimate
    because PHP's cast set is closed by the language.
  - `js-eval-of-user-input` matched `new Function($X)`, the **one-argument**
    form. The canonical Function constructor names its parameters first and
    passes the body last, so the shape the rule was written for is the shape real
    code least often has: measured, **0 findings** on
    `new Function('a', 'b', body)`. Now `new Function(...)`.
  - `js-document-write` saw `document.write` and not `document.writeln`.
  - `py-yaml-load` caught one unsafe spelling in six. The rule was
    `pattern: yaml.load($X)`, a one-argument match — but what makes the call safe
    is the **loader class**, not the arity. `Loader=yaml.Loader`,
    `Loader=yaml.UnsafeLoader`, the positional `yaml.load(f, yaml.Loader)`,
    `yaml.unsafe_load` and `yaml.full_load` all executed arbitrary code unseen.
    Separately, `yaml.load(stream=f, Loader=yaml.SafeLoader)` was an ERROR on
    safe code, because the `Loader=` exclusions required a POSITIONAL first
    argument.

  Neither of the two dead JS rules would have been caught by `--validate`: both
  compiled perfectly and matched nothing. The assertion that catches that whole
  family is the one comparing the rule ids the fixtures exercise against the
  `- id:` entries parsed out of the YAML — **a rule with no hit fixture behind it
  is a rule nobody has measured.**

- **Semgrep's per-user settings file was making a third of the test suite fail
  under concurrent load, and it read as a broken rule pack.** Semgrep keeps one
  settings file per USER and every invocation reads it and then WRITES it back.
  The write path is careful (`mkstemp` + `os.replace`, with a comment in
  Semgrep's own source saying this exists to avoid concurrent-write races); the
  **read** path is not — `get_default_contents` does an `os.access` check and
  then `self.path.open()` with no `try`, so on Windows another process's
  `os.replace` landing in that window makes the open fail with
  `PermissionError: [Errno 13]`, which nothing catches. Semgrep dies with a
  Python traceback and the test reports `Command failed: semgrep --config …`.
  Measured: **3 failures in 288 invocations at 24-way concurrency, and 0 in 288
  with per-worker isolation in place** — the mechanism behind "42 test files
  failed / 86 passed" during three concurrent agent runs, and behind those same
  files passing instantly when run alone. Note what it is **not**: capping
  vitest's worker count lowers the collision *rate* and leaves the defect with a
  longer fuse. Only the test environment is redirected; `mcp/src` deliberately
  does not do this, because overriding a user's Semgrep settings location from
  inside a scanner would discard their login state, which is theirs to manage.

- **Four tests asserted the stopwatch rather than the property**, and failed on
  green code when the machine was busy. Each was reproduced deliberately (60 CPU
  burners on a 24-core box) before anything was changed, then re-run under the
  same load. `expectWellUnderDeadline` asserted 2500ms against a 5s budget for a
  fast path that takes ~200ms idle, reproduced at 4379ms; it is replaced by a
  race against a budget wide enough that only the regression can lose. "A worker
  does not keep issuing live requests after the caller cancels" was inferred from
  `Date.now() - start < 1000` and is now observed at the target, which counts
  `/slow` hits and asserts exactly one. `createFixPr.test.ts` was diagnosed
  rather than trimmed: instrumenting `runProcess` shows **~95s of the file's 132s
  is network round-trips** — six `semgrep --config auto` invocations (48.6s; it
  refetches the registry every time), eleven `npm audit` (19.9s) and twelve
  `npm install` runs — so its per-test timeouts were 2–3× a measured 8–18s, which
  is no margin at all.

- **The `fixprWorktree` flake was a whole-temp-dir sweep, not a deletion
  failure.** Seven misfires under full-suite parallelism, never one in isolation;
  the retry hardening shipped in 1.7.2 could not have helped, because nothing was
  failing to delete. `createWorktree` builds its directory with
  `mkdtempSync(join(tmpdir(), WORKTREE_DIR_PREFIX))` — the OS temp dir and a
  prefix shared with every caller — and two tests snapshot every directory with
  that prefix before and after a call and compare with `toEqual`, while a sibling
  test file drives real `create_fix_pr` runs using the same prefix and holds one
  for ~20s. `TMPDIR`/`TEMP`/`TMP` now point at a per-file sandbox, which
  `os.tmpdir()` re-reads on every call, so both the worktrees and the sweeps
  looking for them are confined where no sibling can reach.

### Privacy

- **`SECURITY.md` said "Local-only, no telemetry" without qualification. That
  was wrong**, and it is corrected there. `--config=auto` fetches its ruleset
  from the Semgrep registry and reports usage metrics to Semgrep Inc. **as a
  condition of doing so**: passing `--metrics=off` alongside it fails outright
  with `Cannot create auto config when metrics are off`. Every default
  `scan_sast` run has therefore sent telemetry, and could not have done
  otherwise. dev-guardian neither adds to that data nor sees it; what Semgrep
  collects is documented at <https://semgrep.dev/docs/metrics>. Use
  `scan_sast(local_only: true)` for a run that sends nothing.

### Known gaps

Measured against the shipped rules, not inferred.

- **No `Integer ==` rule in Java or C#.** Expressing it needs type inference
  Semgrep OSS does not have; the attempt fired on `v == null` and on primitive
  comparison.
- `stream-not-closed` (Java) only recognises `new FileInputStream(...)`, and only
  by that simple name: `FileOutputStream`, `FileReader`, `Socket` and every other
  closeable leak identically, as does a fully-qualified
  `new java.io.FileInputStream(...)` (measured).
- `static-dateformat` (Java) only recognises `SimpleDateFormat`, so a shared
  `Calendar` or `Matcher` in a static field is not covered. It is no longer blind
  to the fully-qualified declaration.
- `map-get-deref` (Java) has no dataflow, so a key whose presence is established
  outside the guard and population shapes the rule enumerates is still flagged —
  a map filled in a static initialiser, or a total enum mapping declared as a
  `Map` — and it does not cover an `EnumMap`, the receiver enumeration being by
  declared type. `modify-during-iteration` only matches the enhanced-for form.
- **Declared-type restriction costs recall, and that is what makes it work.**
  `metavariable-type` matches the exact declared type with **no subtyping** —
  measured: `type: List` does not match a `CopyOnWriteArrayList`. So
  `map-get-deref` is silent on a map behind a project interface or a generic type
  parameter, and `modify-during-iteration` is silent on a `Deque`, a `Queue`, a
  `SortedSet` or a project collection type.
- **The empty-catch naming escape hatch cuts both ways.** A genuinely swallowed
  exception escapes the rule by being named `ignored`; and in the other
  direction, the JUnit expected-exception idiom fires when the caught variable is
  named `e` and is silent when it is named `expected`.
- `optional-get-no-ispresent` (Java) misses **any guard that reaches the check
  through another method** — `if (!present(o)) { return d; }` needs
  interprocedural analysis Semgrep OSS does not do — and deliberately does not
  treat `a.isPresent() || b` as a guard, since that proves nothing inside the
  body. The enumeration of the guard shapes it *does* recognise lives in the rule
  file; the summary that used to stand here was falsified four times running, and
  the rule is `WARNING` precisely because this class of miss has no end.
- `wp-unescaped-output` (base) treats **inside any call as handled**, which is a
  far stronger claim than "an escaper handles it": `wp_unslash()`,
  `stripslashes()`, `trim()`, `sprintf()`, `implode()`, `nl2br()`,
  `str_replace()` are all measured silent and none of them escapes HTML. The
  sharpest case is WordPress's own idiom — `echo wp_unslash($_GET['x']);` is
  textbook XSS and is syntactically indistinguishable from the correct
  `echo esc_html(wp_unslash($_GET['x']));`. Enumerating the non-escapers is the
  open-set problem inverted, so the limitation is named instead of closed. It
  also cannot follow data flow: a heredoc assigned to a variable and echoed later
  is not matched.
- `php-sql-injection-direct` (base) targets `mysql_query`, removed in PHP 7, and
  `mysqli_query`; the canonical WordPress form `$wpdb->query("..." . $id)` is a
  different API surface and is left to a rule of its own.
- `routes.yml` is **not registered with the ablation harness**: it has no
  `hits/` + `misses/` fixture pair, so axes 0, 1 and 2 have nothing to measure
  against, and 20 of its 64 rules have no ablatable clause, so registering it
  would need fixtures before the report said anything about two thirds of it.
- **Resolving class-level route prefixes** (`@Controller('users')` and
  `[Route("api/[controller]")]`) is a follow-up in `resolvers/node.ts`, not a
  rule-pack change. Until then those endpoints are honestly `path_partial`.

### Accepted limitations

Reproduced against the review fixtures that exist today, and kept rather than
fixed. **Every row states its DIRECTION**, because for six waves the Java table
had nine rows and all nine were false positives.

- **(1)** *False positive.* `memory-leak-stream-not-closed` (Java) on
  `open(); try { … } finally { close(); }` — already the rule's stated
  limitation, and already why it is `WARNING`.
- **(2)** *False positive.* `race-condition-static-dateformat` (Java) on a
  `static final SimpleDateFormat` whose every access goes through a
  `synchronized` method — proving *all* accesses are synchronized is
  whole-program analysis. This row used to end "and a shared formatter serialises
  every caller anyway"; that is a **product** argument rather than the tier
  criterion, and it is why the rule sat at `ERROR` for four rounds while carrying
  a documented un-fixable false positive.
- **(3)** *False positive.* `off-by-one-loop-lte-length` (Java, C#) on
  `i <= a.length` where the body guards with `i < a.length`, or never indexes
  `a`. The obvious tightening — requiring `<... $A[$I] ...>` — was measured and
  **rejected**: it fixes the inclusive loop that never indexes, does **not** fix
  the sentinel loop that fills a longer array, and **loses** a real bug where the
  out-of-bounds index is passed to a helper. A false positive traded for a false
  negative without fixing the main case. The C# pack inherits the row, and adds
  one of its own: `loop-lte-length` scores 2 on `dotnet/runtime` and **both are
  false positives** of the sentinel shape.
- **(4)** *False positive.* `error-handling-printstacktrace-only` (Java) on
  `printStackTrace()` as the fallback when the logger itself threw — the one
  place the call is right; too narrow to encode.
- **(5)** *False positive.* The three Java guard rules where **two or more**
  statements sit between the guard (or the removal) and the exit. The deliberate
  price of bounding the exclusions instead of using a statement ellipsis: the
  ellipsis matches deep and would swallow
  `if (!m.containsKey(k)) { if (strict) { return ""; } }` and
  `items.remove(s); if (done) { break; }`, which are real bugs. **A false
  negative that hides a bug is worse than this false positive.**
- **(6)** *False positive.* The same three rules on any guard reached **through
  a helper method**, which needs interprocedural analysis.
- **(7)** *False positive.* `map-get-deref` on a key whose presence is
  established outside the shapes the rule enumerates. Excluding "any map that
  ever received a `put`" anywhere in the file would erase the rule.
- **(8)** *False positive.* `map-get-deref` and `optional-get-no-ispresent` on a
  guard held in a **local boolean** — dataflow rather than syntax.
- **(9)** *False **negative** — the invalidated-guarantee class.* A guarantee the
  guard establishes and the code then **destroys**, inside the very region the
  exclusion covers. Five measured reproductions, every one a guaranteed throw,
  every one silent:

  ```java
  if (m.containsKey(k)) { m.remove(k); return m.get(k).trim(); }
  if (o.isPresent())    { o = Optional.empty(); return o.get(); }
  if (m.containsKey(k)) { m.clear(); … m.get(k).trim() … }
  m.put(k, "v"); m.remove(k); return m.get(k).trim();
  while (m.containsKey(k)) { m.remove(k); … m.get(k).trim() … }
  ```

  Same root cause as the `else`-arm bug — `pattern-not-inside` excludes the whole
  node it matched — but on the **temporal** axis instead of the branch axis. Not
  fixable in Semgrep OSS, so this is a row and not a clause.
- **(10)** *False **negative**.* The same two rules where the deref is guarded by
  a **local boolean** holding the test — the mirror of row (8). Both directions
  are the same missing capability, and having only the false-positive half
  written down for six waves is precisely the asymmetry this section is about.
- **(11)** *False positive.* `map-get-deref` on the two `keySet()`-adjacent
  idioms the exclusion does **not** reach, measured rather than assumed:
  `for (Map.Entry<K,V> e : m.entrySet()) { … m.get(e.getKey()) … }`, where the
  key is `e.getKey()` and not the loop variable, and the key set copied to a
  local first. The exclusion unifies the map **and** the key on purpose; widening
  it means giving up one of those unifications, and the two neighbouring real
  bugs that would then be swallowed are pinned as `b13` and `b14` in
  `hits/RealBugs.java`.
- **(12)** *Undecidable.* Four decoy "routes" in the attack-surface corpus still
  report. They are undecidable from syntax rather than untried, and are pinned as
  such so a later widening cannot quietly add a fifth.

## [1.8.0] - 2026-08-18

### Added

- **Go bug rules** — `configs/semgrep/bugfix-go.yml`, ten hand-authored Semgrep
  rules covering all six `bug_hunt` subcategories for Go: error discarded with
  `_`, return assigned to `_`, empty `if err != nil` branch, type assertion
  without `, ok`, `for i := 0; i <= len(xs)`, HTTP response body never closed,
  ticker never stopped, `Lock()` without `defer Unlock()`, discarded `append`
  result, and writing to a nil map. Go is where the registry pack leaves the
  biggest hole: `p/r2c-bug-scan` ships 5 Go rules and only 2 land in a bug
  class, both integer-overflow. Each rule ships a hit fixture and a near-miss
  that must stay silent, and the no-duplication test carries a positive
  control — a file that trips the pack's own Go rule — so "the pack found
  nothing" cannot be confused with "the pack never ran".

### Known gaps

- No goroutine-leak rule.
- **No loop-variable-capture rule, deliberately.** It was built and verified
  working, then excluded: Go 1.22 made loop variables per-iteration, and
  Semgrep cannot read `go.mod`, so on any module declaring `go 1.22` or later
  it would fire on correct code.
- `body-not-closed` only recognises `http.Get`; `http.Post` and `client.Do`
  leak identically and are not covered.
- `body-not-closed` and `ticker-not-stopped` match only the `:=` declaration
  form; `var resp *http.Response; resp, err = http.Get(url)` and
  `var t *time.Ticker; t = time.NewTicker(...)` are silent. `err-discarded`
  covers both forms, so this is an inconsistency rather than a stated
  policy.
- `lock-without-defer` accepts any `defer mu.Unlock()` in the block. It also
  does not cover `sync.RWMutex` read locks: the pattern matches the literal
  `Lock()`/`Unlock()` method names, not `RLock()`/`RUnlock()`, so a read-lock
  without `defer` — a common Go idiom — is entirely outside its reach. The
  write lock (`Lock()`/`Unlock()`) on a `*sync.RWMutex` is covered.
- `nil-map-write` only catches a locally `var`-declared map. A nil map
  arriving as a function parameter, a struct field, or a return value panics
  identically on write and is not covered — arguably the commoner
  real-world shape.
- `err-blank-assign` fires on deliberate discards, which is why it is `WARNING`.

## [1.7.2] - 2026-08-18

### Fixed

- **`wp_vuln_check` could run `wpscan --url undefined`.** When only
  `wp_install_path` was given, the target URL is read from WP-CLI — which can
  exit successfully and print nothing. Two call sites asserted the URL was
  present rather than checking it. It is now resolved once and, if still
  empty, the tool returns `scanner_failed` instead of invoking the scanner
  with a bad target.


### Changed

- **No non-null assertions anywhere.** 31 `!` assertions across 22 files
  removed; `mcp/src` and `mcp/test` are both at zero, as is explicit `any`, so
  a reappearance is a regression rather than the status quo. Most restated
  something the code had just established — a `push` before re-indexing the
  array's tail, a `filter` before a `map`, a length check before an index —
  and narrowing costs nothing there. Two others were hiding couplings worth
  making explicit: three tools asserted a shell whose non-null-ness is
  guaranteed by a check in a *different* file, and `perf_check` asserted a URL
  because its guard set a boolean that told the reader everything and the
  compiler nothing.
- `CLAUDE.md` now documents the TypeScript conventions this repo actually
  applies, including what `tsc` does **not** catch: interpolating a non-string
  into a template types as `string` at any strictness, so that class is still
  only caught by a human reading the diff.

## [1.7.1] - 2026-08-18

### Fixed

- **`register_custom_rules` never actually did anything.** It discovered a
  project's own Semgrep rules and persisted them, and its description promised
  "scan_sast / bug_hunt will then pick them up" — but nothing in the codebase
  ever read the key back. `scan_sast` passed `--config=auto` only; `bug_hunt`
  built its own pack list. The single other reference to the key anywhere was a
  test asserting it had been *written*, so the write half was covered and the
  read half had never been built, while the product surface claimed the feature
  worked. Both scanners now run the registered rules as extra `--config` packs,
  and a registered path that has since been deleted is skipped rather than
  aborting the whole scan — Semgrep fails the entire run on one bad `--config`,
  so a stale registration would otherwise break every later scan in the project.

- **Three tools were missing from the intent→tool maps** that tell an AI host
  which tool to reach for. `scan_skill` — which vets a third-party AI skill,
  MCP server or agent *before* installation and returns SAFE / REVIEW /
  CAUTION / DO_NOT_INSTALL — was absent from all nine host-config files, so no
  host had any way to learn it exists, despite it having its own command and
  skill. `check_toolchain` was missing from six, `scan_sast` from one. All 54
  registered tools are now present in all nine files, checked programmatically.

## [1.7.0] - 2026-08-18

### Added

- **Python bug rules** — `configs/semgrep/bugfix-py.yml`, ten hand-authored
  Semgrep rules covering all six `bug_hunt` subcategories for Python: bare
  `except:`, `except: pass`, unguarded `.objects.get()`, `None` dereference from
  `re.match()` and `dict.get()`, `range(len(x) + 1)`, files opened without a
  context manager, discarded `asyncio` coroutines, TOCTOU between
  `os.path.exists()` and `open()`, and Django queryset N+1. Each ships a hit
  fixture and a near-miss fixture that must stay silent, and each was measured
  against the 32 Python rules `p/r2c-bug-scan` already runs: none duplicates one
  of them.

### Changed

- `resolveBugfixRules()` returns every `configs/semgrep/bugfix-*.yml` instead of
  just the JS one, so a new language ships by adding its rule file — no wiring.

### Known gaps

Measured against the shipped rules, not inferred:

- No general "coroutine not awaited" rule: it is not expressible in Semgrep OSS.
  Only `asyncio.sleep/gather/wait/wait_for` are covered, so a forgotten `await`
  on a project's own `async def` is not caught.
- The Django N+1 rule matches `for` statements, not list comprehensions; is
  Django-specific (never SQLAlchemy or Peewee); and needs the queryset **inline
  in the `for` header** — `qs = Book.objects.all()` followed by `for book in qs:`
  is silent, which is arguably the commoner shape.
- `toctou-exists-open` keys only on `os.path.exists`. `os.path.isfile`,
  `os.path.isdir` and `pathlib.Path(p).exists()` are all silent.
- `none-deref-dict-get` excludes HTTP clients by receiver-name **substring**, so
  any receiver containing `requests`, `session`, `client`, `httpx`, `aiohttp` or
  `urllib` is skipped — `session_data`, `clients` and `urllib_cache` are false
  negatives too, not only a dict named exactly `client`.

## [1.6.0] - 2026-08-18

### Added

- **Fourteen locally-authored Semgrep rules that find JS/TS implementation
  bugs**, at `configs/semgrep/bugfix-js.yml` — the path
  `skills/guardian-bugfix` had been promising to a file that never existed.
  `bug_hunt` loads them **by default**, and unlike a registry pack a local file
  cannot 404.

  They cover **six** of the seven classes `/guardian-fix` names: swallowed error
  handling, off-by-one, null safety, memory leaks, race conditions and edge
  cases. **"Broken happy paths" is not covered** — it is a category of
  consequence, not a syntactic shape; `floating-mutation` covers its commonest
  concrete form and nothing covers the rest.

  Why they exist, measured rather than assumed: Semgrep retired `p/bugs`, its
  replacement covers those classes only for Python and Go, and a purpose-built
  TypeScript fixture returned **zero** findings with all seven registry packs
  enabled.

### Fixed

- **A malformed local rule file now degrades instead of taking the scan down**,
  in both shapes — broken YAML, and a single rule with a broken pattern, which
  is valid YAML and needs different handling so the other rules’ findings
  survive. Verified against the built server, not the source tree.
- A coverage warning no longer says a scanner "did not run" when the same
  result reports it ran.

### Known limitations

- **JS/TS only.** Python, Go, Java, C#, PHP, Ruby and Rust have no local rules
  yet; each gets its own design.
- **Semgrep OSS matches syntax, not dataflow.** These rules find the shapes bugs
  take. A null dereference two functions from its guard is invisible to them.
- **The heuristic tier produces false positives by construction.** That is why
  it is `WARNING` and why `severity_min` exists.
- **`floating-mutation` does not cover async function expressions** — a Semgrep
  engine limitation, not an oversight. Declarations, arrow functions, class
  methods and object methods are covered.
- **They do not replace the model-driven `/guardian-fix` path.** Rules catch
  shapes; reading the code catches reasons.

### Added

- **`bug_hunt` now runs fourteen local, hand-authored Semgrep rules for JS/TS by default** —
  `configs/semgrep/bugfix-js.yml`, alongside the always-on `p/r2c-bug-scan` +
  `p/security-audit`. They cover six bug classes: race conditions (`floating-mutation`, one
  rule), null/undefined safety (three), off-by-one (two), memory/resource leaks (three),
  swallowed error handling (three), and two edge cases (`reduce` without an initial value,
  `parseInt` without a radix). Unlike `include_language_packs`, a local file cannot 404, so
  this also keeps `bug_hunt` reporting something true even when the Semgrep registry is
  entirely unreachable. Every rule ships with a fixture pair under
  `mcp/test/fixtures/bugfix-js/` — one file that must fire, one near-miss that must not —
  asserted by exact rule-id set *and* raw finding count per file, so a rule that starts
  matching its own near-miss fails the suite instead of quietly widening. Design of record:
  - **Six named classes — "broken happy paths" isn't one of them as a pattern.** It's a
    category of consequence, not a syntactic shape; `floating-mutation` covers its commonest
    concrete form — an un-awaited mutating call inside an `async` function (declarations,
    arrow functions, class/object methods — NOT async function expressions, a Semgrep engine
    limitation) — and nothing covers the rest of it.
  - **Semgrep OSS matches syntax, not dataflow.** These rules find the shapes bugs take, not
    bugs proven by analysis — a null dereference two functions from its guard is invisible to
    them.
  - **The heuristic tier produces false positives by construction.** `floating-mutation`
    matches on the method name alone, so it can't tell a real mutation like `repo.save()`
    from an unrelated call that just shares the name, like `ctx.save()` (Canvas 2D's
    synchronous state-stack push) — both fire identically; that's why it's `WARNING`, not
    `ERROR`, and why `severity_min` exists.
  - **JS/TS only.** Python, Go, Java, C#, PHP, Ruby and Rust are unchanged: `p/r2c-bug-scan`
    still covers these classes only for Python and Go, and none of those languages has a
    local rule pack yet.
  - **Not a substitute for the model-driven `/guardian-fix` path.** These rules catch shapes;
    reading the code catches reasons.

### Fixed

- **A malformed `configs/semgrep/bugfix-js.yml` degrades instead of failing the whole
  `bug_hunt` scan.** Two distinct ways a hand-edited local rule file can break, both handled:
  invalid YAML is now recognised the same way a dead registry pack is and dropped from a
  retry; a single bad rule *pattern* inside an otherwise-valid file is dropped alone, with
  every other rule's findings still returned, instead of the whole run reporting `failed`
  with no reason and a misleading "install semgrep" warning. Verified live against the real
  built `dist/server.js`, not only unit-tested.
- **`skills/guardian-bugfix/SKILL.md` and `bug_hunt`'s own `title`/`description` stated the
  JS/TS bug-class gap as a permanent fact.** Both now describe the local rules above instead
  of the gap they close.

## [1.5.0] - 2026-08-17

### Fixed

- **`bug_hunt` was failing outright: Semgrep retired the `p/bugs` pack.** A dead
  `--config` makes Semgrep exit 7 and scan *nothing* -- including with
  `p/security-audit`, which was still valid -- so the whole tool died. Replaced
  with `p/r2c-bug-scan`, and the failure mode underneath is fixed: a config that
  fails to download is detected from Semgrep's structured `errors[]`, the
  surviving packs are re-run, and the gap is reported as coverage. **A scan that
  did not run can no longer read as clean.**
- **`mapSubcategory`'s fallback was a no-op**, so findings rarely landed in a
  canonical bug class. Fixed and validated against real rule ids.
- **The `categories` input was dead code** -- declared, never read. It now filters.
- **`skills/guardian-bugfix` pointed the model at `configs/semgrep/bugfix-*.yml`**,
  which does not exist. Corrected to describe what is actually there.

### Added

- **`include_language_packs`** (default `false`) on `bug_hunt`: adds
  `p/javascript`, `p/typescript`, `p/python`, `p/java` or `p/golang` by detected
  stack. **Measured rather than assumed:** 401 rules across the five packs (327
  distinct), 100% `category: security`, and a purpose-built TypeScript fixture
  returns zero findings. They add per-language *security* coverage -- overlap
  with `p/security-audit` is 9% for JS/TS, 20% Python, 43% Java, 40% Go -- and
  **do not** address the bug classes. Off by default for that reason.
- **`CoverageState.partial_tools`**: the dashboard now distinguishes "ran with
  reduced coverage" from "did not run this scan", which it previously could not.

### Known gap

- **No live Semgrep registry pack covers JS/TS logic bugs** -- null-safety,
  off-by-one, race conditions, memory leaks, swallowed error handling.
  `p/r2c-bug-scan` covers them for Python and Go only. For JS/TS the
  model-driven `/guardian-fix` path is what finds these today.

## [1.4.0] - 2026-08-17

### Added

- **`dev-guardian status` and `dev-guardian dashboard` — two read-only views over a
  project's own scan history, for a developer at their own laptop.** `status` prints
  a one-screen terminal summary (risk score and band, open findings and CVEs by
  severity, both deltas, up to 3 finding hotspots, missing-scanner consequences,
  active suppressions); `dashboard` writes a self-contained `.guardian/dashboard.html`
  — no CDN, no font fetch, no network call of any kind — with the same data, filterable
  and sortable client-side, opened automatically only when stdout is a TTY (`--no-open`
  suppresses that, `--out <path>` relocates the file). Both are computed by a single
  query pass (`mcp/src/dashboard/snapshot.ts#buildSnapshot`) so the two views cannot
  disagree, and neither runs a scan, mutates the database, or opens a socket. New CLI
  subcommands `node cli/dev-guardian.mjs status [--project <path>]` and
  `dashboard [--project <path>] [--out <path>] [--no-open]` — no MCP connection
  needed, matching `scan`/`baseline update`'s existing shape. `/guardian-status` now
  shows this deterministic output and adds interpretation on top, instead of
  improvising the numbers itself.
  - **The page is a snapshot, not live.** It is accurate as of the moment it was
    generated and does not change when a later scan runs — regenerate it. This is the
    cost of shipping with no server, the trade that keeps the feature dependency-free
    and fully offline.
  - **The window is the latest scan plus two deltas — still no multi-week trend.**
    `/guardian-trend` continues to ask for chronic-finding history and a debt
    half-life nothing in this project computes; this feature does not change that.
  - **The risk score is the existing `risk_score` heuristic**, extracted into a pure
    function (`risk.ts`) with its wire output kept byte-for-byte identical (a
    characterisation test pins it) — a prioritisation aid, not a measurement, and
    unchanged by this work.
  - **Coverage is only as honest as `missing_tools`.** Both views refuse an all-clear
    verdict whenever a scanner the scan intended to run did not run, and name what the
    numbers therefore don't contain. What neither view — nor the scan that fed them —
    can detect is a scanner that ran and silently produced nothing (a broken rule pack,
    an unreadable path): that is indistinguishable from a genuinely clean result at
    this layer.
  - **Hotspots rank by finding count, not severity.** A file with 11 low-severity
    findings outranks one with 2 criticals; the severity breakdown sits alongside for
    context, but the ranking itself stays deliberately simple.
  - Both commands exit `0` whenever they render — including over a project full of
    criticals, or one that has never been scanned (they name the scan command to run
    instead of showing empty numbers) — because they report; `scan` is what gates. The
    only non-zero exit either produces is `3`, on a usage error.
- **`create_fix_pr` — applies fixes the scanners themselves already produced, proves
  them, and opens a pull request.** New tool, and the first code in this repository
  that writes through git (branch, commit, push) rather than only reading it. It takes
  `deps_update_plan`'s pinned upgrade commands and Semgrep `--autofix`, applies them
  inside an isolated git worktree branched from committed `HEAD` — the user's working
  tree is never read or required to be clean — and verifies the result twice before
  anything leaves the machine: a **scan differential** re-runs the originating scanner
  inside the worktree and requires both that every target finding is gone and that no
  new finding appeared, and a (lazy) **test differential** runs the project's own
  derived test command — never accepted as a parameter, the same reasoning that keeps
  `scan_dast` from accepting a start command from repository-controlled config — and
  only re-runs it against the base commit, to tell a pre-existing failure from a
  regression, when the post-fix run fails. Fixes are grouped one pull request per
  ecosystem or scanner (all npm bumps together, all Semgrep rewrites together), branch
  names are deterministic (`dev-guardian/fix-<ecosystem-or-scanner>-<hash>`) so a
  repeat run is recognisable, and a pull-request-existence check that cannot be
  resolved (a failed `gh` call, unparsable output) makes the tool **refuse**, never
  assume no PR exists. Transport is the local `gh` CLI, as `create_github_issues`
  already uses — no tokens, no REST, no Octokit. The worktree is removed on every path,
  including every failure path, verified by observing `git worktree list` afterwards
  rather than by trusting a `finally` block to have run; the local branch follows it
  unless a human may need to find it by hand — a created PR, a push that failed, or a
  `gh pr create` that failed after a successful push.
  - **`apply` defaults to `false`, and that is the whole safety story.** Everything
    expensive and everything verifiable still runs on every call — candidates are
    computed, the worktree is created, the fix is applied, both differentials execute —
    but a dry run **leaves nothing behind: not a branch, not a commit, not a
    worktree**. Only `apply: true` commits, pushes and opens the pull request. The dry
    run's own verification re-scan is excluded from the server's unscoped "latest scan"
    queries, so it can never become the project's latest scan: nothing a dry run does
    can change what `guardian://findings/open`, `risk_score` or any other tool reading
    those queries report.
  - **Only what a scanner already produces.** Semgrep rules with no `fix:` field, and
    findings from gitleaks, bandit, jscpd, the DAST passes and the .NET tools — none of
    which set `fix_available` — are out of reach. This tool is not a patch author
    (`suggest_fix` remains the way to gather context for a model- or human-written
    patch) and does not become one here.
  - **`deps_update_plan`'s ecosystem gaps are inherited: maven and gradle are
    unsupported.**
  - **Semgrep's autofix quality is Semgrep's.** The scan differential verifies the
    outcome — the target finding gone, nothing new introduced — it does not review the
    rewrite itself. A rule with a careless `fix:` produces a careless patch, and the
    differential will call it resolved.
  - **A second instance of the same rule in the same file is not seen as new.** The scan
    differential's two halves compare on different keys on purpose (an amendment to
    design §4.1/§10 made during implementation): the target finding by fingerprint,
    "no new finding" by `(rule_id, file_path)`. A fingerprint hashes the line and the
    snippet, so any fix that shifts a line gives every other finding in that file a
    fresh fingerprint — measured at one inserted line changing four other findings'
    fingerprints on a real repo — and comparing "no new finding" by fingerprint would
    therefore fail the differential on every multi-finding file and blame pre-existing,
    untouched findings for it. The accepted cost of the fix: a genuine second instance
    of the same rule newly appearing in a file that already had one does not register
    as new.
  - **The test differential is only as good as the project's tests.** A green suite
    with no coverage of the changed code proves very little, and the tool cannot tell
    the difference.
  - **`fix_applied` remains a dead column.** It is `NOT NULL DEFAULT 0` on `findings`,
    nothing has ever written `1` to it, and this feature adds no `UPDATE` and no new
    table — the pull request is the record.

## [1.3.0] — 2026-08-14

### Added

- **`map_attack_surface` — static route/env-var/port inventory across all 8 stacks.**
  New tool that runs a dedicated Semgrep rule pack (`configs/semgrep/routes.yml`) over
  the project to extract HTTP routes, referenced environment variables, declared ports
  and webhook endpoints, resolving Express-style router mount prefixes and WordPress
  REST namespaces to their effective path. Reports per-language `coverage`
  (`ok` / `no_rules` / ...) so an uncovered framework shows up as a gap rather than a
  silent zero. Persists one snapshot per run to a new `surface_snapshots` SQLite table,
  keyed by a tree hash so an unchanged working tree reuses the previous snapshot instead
  of re-scanning. The tool result itself returns a summary plus a 20-route sample and a
  `snapshot_id` — the full route list is deliberately kept out of the tool response (see
  the new resources below) so a project with hundreds of routes cannot exhaust the
  agent's context window on a single call.
  - **Validation status, per rule.** Every rule in `configs/semgrep/routes.yml` now
    matches real code in `mcp/test/fixtures/surface/apps/`, checked capture-by-capture
    against Semgrep **1.86.0** (the last version that still emits `extra.metavars`, so
    what a rule binds is directly observable) and re-run end to end through the tool on
    Semgrep **1.164.0** (which redacts them, exercising the byte-offset recovery). Both
    versions produce the same 81 matches — 64 routes — with no rule errors. (1.164.0 also
    emits one `warn`-level `PartialParsing` on `php-wordpress/rest-controller.php:20`,
    where its PHP parser rejects `const NAMESPACE`; 1.86.0 parses it. That is a target-file
    parse warning, not a rule error, it predates every change here, and both `wp-rest`
    matches in that file still fire.) Verified
    working: `express` + its `mount` and `import` rules, `nestjs` (5), `flask`, `fastapi`,
    `django`, `wp-rest` (literal *and* `self::NAMESPACE` namespaces), `laravel`,
    `go-nethttp`, `gin`, `rails` (bare and `to:` forms), `spring` (all 6, including
    `@RequestMapping`, in their single-argument form), `aspnet-minimal`, `aspnet`
    attribute routing (5), `actix` (5), and all 5 `env` rules. Four rule families were
    **broken** and are fixed below.
  - **What is still not covered.** The verb alternations absent from the fixture —
    `OPTIONS`, `HEAD`, `ALL`/`ANY`, and `PUT`/`PATCH` for some frameworks — are
    untested, being extra literals in an already-verified `metavariable-regex`. A
    parameterless decorator (`@Get()`, `[HttpGet]`) is deliberately not reported: there
    is no path to capture, and neither the NestJS `@Controller` prefix nor an ASP.NET
    `MapGroup` prefix is resolved, so those routes are reported at their own
    registration path. Go's `os.Getenv` is not collected — no `env` rule covers Go.
    The Docker fallback path of `map_attack_surface` is still only exercised by mocks.
    Two **named-argument** forms are measured as unmatched and pinned as fixture bait:
    Spring's `@GetMapping(value = "/x", produces = "…")` — common in real code, and not
    fixable by adding `, ...`, which Semgrep rejects as "Invalid pattern for Java" —
    and Rocket's `#[post("/x", data = "<t>")]` (see the actix entry below). Both are
    absent from the inventory rather than reported at a guessed path.
- **`map_attack_surface` imports OpenAPI 3.x and Swagger 2.0 documents and diffs them
  against the code.** Discovery walks the project for conventionally-named files
  (`openapi.*`, `swagger.*`, `api-docs.*`, or anything under an `openapi/` directory
  inside the project — never matched against the absolute filesystem path, so a
  checkout nested under an ancestor directory happening to be named `openapi` does not
  pull in unrelated files) or reads exactly the paths passed as `spec_paths`. Both JSON
  and YAML are accepted for either version; **Postman collections are not supported** —
  the parser only recognises an `openapi: 3.x` or `swagger: 2.0` document. Every
  imported route carries `provenance: 'spec'` alongside the code-extracted routes'
  `provenance: 'code'` (routes read back from a snapshot persisted before this feature
  default to `'code'`, so old data is never mistaken for spec data), and
  `auth_hint: 'none'` is now emitted for an operation or document declaring
  `security: []` — an explicit "this route is public" — never inferred from the field
  being absent, which stays `'unknown'`.
  - **The diff has two honesty rules, not one.** First: with no spec discovered, or every
    discovered spec failing to parse, `spec_diff` is `null` — never a diff in which
    every code route reads as undocumented, which is a different claim than "there is no
    spec to compare against." Second: a route whose full path could not be resolved (an
    unresolved router-mount prefix on the code side, a templated `servers[].url` /
    `basePath` on the spec side) is **never** reported as a shadow endpoint or as dead
    documentation — it lands in a fourth bucket, `unmatchable`, together with a reason,
    and is never surfaced as a finding. This costs real findings when an unresolved
    route happens to be the very shadow/dead one, so the counts of findings withheld for
    that reason (`code_only_withheld`, `spec_only_withheld`) are reported alongside the
    diff rather than the gap being silent.
  - `routes_total` and `coverage[]` stay code-only, unchanged by this feature: a spec
    importing 200 paths must not make `coverage` claim a `'spec'` language exists, and
    must not inflate the code-route count a consumer already relies on.
  - Discovery is capped at 20 candidate files and 5 MB per file, both reported
    (`truncated`, `oversized`) rather than silently applied, and an unresolved external
    `$ref` (a whole path item, or a parameter, pointing outside the document) is counted
    in `unresolved_refs` rather than the path item vanishing with no trace — which would
    read as "the spec never declared this," a false claim about a real route this module
    simply could not follow to its file.
  - New runtime dependency: [`yaml`](https://www.npmjs.com/package/yaml), used to parse
    YAML specs and to recover the source line each path is declared on (JSON specs
    always report `line: 0`, since `JSON.parse` carries no position information).
- **`guardian://surface/latest` and `guardian://surface/{id}` resources.** Serve the
  full persisted attack-surface snapshot (every route, env var, port, webhook and the
  coverage report) by snapshot id or the most recent one. Return `{ snapshot: null }`
  when nothing has been captured yet, consistent with the rest of the resource surface.
- **A multi-language fixture and an end-to-end rule-pack test.**
  `mcp/test/fixtures/surface/apps/` is a small twelve-directory application tree — one
  framework per directory — carrying the route shapes every rule targets plus realistic
  surrounding code that must *not* match: a Python module whose local helper is named
  `path`, a Ruby class calling `Rails.cache.delete 'orders/index'`, `cache.get(...)` in
  the Express app, `Route::middleware(...)`, `r.Use(...)`, `@app.on_event(...)`,
  `app.MapGroup(...)`. It also carries the cases that must survive *as* partial results:
  a computed Django path, a computed WordPress namespace next to a literal one, and a
  non-ASCII comment sitting before every match in two files so the byte-offset recovery
  is exercised rather than assumed. `mcp/test/e2e/rulePackFixture.test.ts` runs the real
  `map_attack_surface` handler over it and asserts the **complete** route set — all 64
  routes by framework, method, resolved path and `path_partial` — because a count
  assertion passes when one rule breaks and another over-matches. One expected set, not
  one per Semgrep version: that the answer no longer depends on whether match content was
  redacted is asserted rather than assumed. It skips (visibly, via `it.skipIf`) when
  Semgrep is absent, and copies the tree out of `test/` first, which Semgrep's default
  ignore list would otherwise skip entirely.
  - **A companion `openapi.yaml` exercises the spec-diff against the same real Semgrep
    run**, rather than against hand-written `RouteRecord`s. It documents three routes
    copied verbatim from the fixture's expected set (so `matched` is non-empty), omits
    the rest of the 51 resolvable code routes on purpose (asserted as the exact
    `code_only` set — shadow endpoints), and declares one path,
    `/deprecated/v0/orders`, that no code route implements (asserted as `spec_only` —
    dead documentation). The comparison is an exact sorted set on both buckets, the same
    style as the route-set assertion above and for the same reason: a count passes when
    one rule breaks and another over-matches by the same amount.
- **`scan_dast` — active DAST that probes a *running* application against the
  `map_attack_surface` route inventory.** New tool that sends real HTTP requests to an
  application the caller already has running — it never starts, builds or stops
  anything — and reports what is actually reachable, what is served without credentials,
  and what leaks. It **requires a prior `map_attack_surface` run**: with no persisted
  snapshot it refuses with `no_surface_snapshot` naming the tool to run first, and a
  target that answers nothing refuses with `target_not_found`; neither refusal persists a
  scan row, so an empty `dast` history entry can never be read by `diff_scans` /
  `risk_score` as "this scan found nothing." Findings land in the existing `findings`
  table (`scan_type: 'dast'`) with a fingerprint stable over `(check, method, path,
  file)` — deliberately excluding the HTTP status, so a fixed app flipping 500→200 on
  restart is not a "new" finding — so DAST findings dedupe, diff and baseline exactly
  like every other finding.
  - **Own engine, eight checks.** `reachability` (confirms the static spec diff's shadow
    endpoints / dead documentation against the live server, and reports an extractor
    coverage gap — never a project bug — when a documented route is live but no code
    route was ever found for it), `anonymous_exposure` (a route the inventory marked
    `auth_hint: 'required'` answering an anonymous request with `2xx` — the strongest
    finding the tool can produce; `high` rather than `critical` because that hint can be
    inherited from a document-level OpenAPI default rather than declared per-operation),
    `differential_authz` (with credentials supplied, a byte-identical response with and
    without them — equality only, never a similarity score, so response noise like
    timestamps or CSRF tokens can only cause a missed finding, never a fabricated one),
    `cors` (a reflected `Origin` **and** `Access-Control-Allow-Credentials: true`
    together — either alone is inert and not reported), `security_headers` (missing CSP /
    `X-Content-Type-Options` / `X-Frame-Options` / HSTS-on-HTTPS, one finding **per
    origin** rather than per route), `info_disclosure` (stack-trace signatures and
    versioned `Server` / `X-Powered-By` banners), `method_surface` (`OPTIONS`'s `Allow`
    header advertising a verb the static extractor never saw, with framework-default
    `HEAD`/`OPTIONS` carved out so it does not fire on nearly every `GET` route in
    existence), and `open_redirect` (a `3xx` whose `Location` leaves the target origin —
    free from `probe.ts` never following a redirect). Plus an opt-in `probe_rate_limit`
    burst (30 requests, synthetic un-ownable credentials, stops early on the first `429`)
    and an optional nuclei pass.
  - **The safety envelope is the design, not a feature of it.** Target classification is
    purely lexical (no DNS, so it cannot be rebound mid-scan): loopback (`localhost` /
    `127.0.0.0/8` / `::1`) probes directly; anything else — including a hostname that
    merely *resolves* to loopback — refuses with `target_not_authorized` unless the
    caller passes `authorized_target: true`, recorded in the scan for audit. Read-only by
    default (`GET`/`HEAD`/`OPTIONS`); `allow_write_methods` opens `POST`/`PUT`/`PATCH`/
    `DELETE`, always with an empty body, so the `400`/`422`-vs-`401`/`403` split answers
    the authorization question without writing. The one exception to read-only-by-default
    is the opt-in `probe_rate_limit` burst, which sends `POST` to exactly one route — the
    flag is its own authorization and opens nothing for any other check. Redirects are
    never followed (`redirect: 'manual'`). Bounds — concurrency 4, a 5s per-request timeout, a 750-request ceiling,
    a 10-minute wall-clock ceiling — are reported when they cut a run, never silently
    applied; a run the wall-clock ceiling cut records its unsent probes `cancelled`,
    distinct from `timeout`, because the target didn't fail to answer — this tool stopped
    asking.
  - **Credentials are opt-in, never persisted, always redacted.** `auth_header_env`
    (recommended — the *name* of an environment variable; the secret never enters the
    conversation or the MCP request log) or `auth_header` (the literal value, documented
    as landing in the transcript). Neither is written to SQLite or an evidence file, and
    both are redacted from every finding, evidence file and result field through a single
    redaction choke-point applied to the whole response, not a hand-picked set of fields.
    Naming a variable via `auth_header_env` keeps it out of nuclei specifically — nuclei is
    spawned with an allowlisted environment and `extendEnv: false` for exactly that reason
    — but not out of this server process, nor out of the other scanners (Semgrep, Trivy,
    gitleaks, git) the same session spawns with the operator's full environment by design.
    That is a deliberate, unchanged posture (those tools read `SEMGREP_*` / `DOCKER_CONFIG`
    / `SSH_AUTH_SOCK` and the like), not an oversight; the parameter description now says
    so directly.
  - **A deliberately-vulnerable fixture app** (`mcp/test/fixtures/dast-app/server.mjs`,
    plain `node:http`, no framework) exercises every check end to end: an auth-required
    route served anonymously, reflected-credentialed CORS, missing security headers, a
    stack-trace leak, an open redirect, and a route with no rate limit.
  - **Per-check status, not just findings.** Every check reports `ok` /
    `skipped_envelope` / `no_candidate` / `needs_credentials` / `scanner_missing` /
    `target_error`, so a check that never ran (wrong envelope, no credentials, nuclei
    absent, the wall-clock ceiling cut it) is visible as such rather than reading as a
    check that found nothing — the same `coverage: 'full' | 'partial' | 'none'`
    discipline every other scan tool in this server already carries.
  - **The known limits — read before trusting a clean result.**
    - **No injection testing in the own engine.** No SQLi or XSS probes are sent; real
      XSS needs a browser and blind SQLi needs timing or destructive probes, and a
      fabricated injection finding is worse than none. That class is delegated entirely
      to nuclei's `-dast` fuzzing mode, which the default envelope excludes — **a clean
      `scan_dast` result is not evidence of injection safety.**
    - **nuclei tests the origin, not this project's routes.** Most of nuclei's HTTP
      templates use `{{BaseURL}}` and append their own known paths; the route inventory
      only genuinely feeds nuclei once `-dast` fuzzing is turned on, and the default
      envelope excludes that mode. nuclei still brings real value (component CVEs,
      exposed panels, misconfigurations) — it is just not what confirms the project's own
      endpoints; the own engine is. The result labels which findings came from which so
      the two are never conflated.
    - **The rate-limit finding is named `no_rate_limit_observed`, never "rate limiting is
      missing."** A limiter whose threshold sits above the burst size (30) is
      indistinguishable from no limiter at all at this sample size, and the finding name
      says so on purpose — do not reword it into a stronger claim.
    - **Synthetic path parameters give parametric routes a best-effort reachability
      signal, never a definitive one.** `/users/{id}` is probed as `/users/1`; a `404`
      there is ambiguous between "no such route" and "no such record 1," so it is never
      reported as "unreachable" — the ambiguity is surfaced, not resolved.
    - **nuclei has no verified Windows package manager install.** scoop, choco and winget
      were all checked and none carry it, so `install_toolchain`'s catalogue has no win32
      entry for it — Windows users install manually from nuclei's GitHub releases page
      (macOS gets a `brew` formula; Linux gets a curl installer, also pointed at GitHub
      releases). Consistent with that gap, nuclei is `default: false`: it never installs
      silently, and a requested-but-absent nuclei is reported as `scanner_missing` in
      `tools_run`, never a silent skip.
  - Discoverable via the `map_attack_surface` → `scan_dast` two-step, now documented in
    `host-rules/AGENTS.md` and in both tools' own descriptions.
- **`validate_finding` — reachability qualification for findings, the follow-up to
  `map_attack_surface`.** New tool that answers, per finding, whether anything outside
  the process can reach the file it lives in: builds a file-level import graph from the
  same Semgrep rule pack `map_attack_surface` already runs, roots it at the
  route-declaring files in the latest surface snapshot, and returns one verdict per
  finding — `reachable` / `unreachable` / `unknown` — with concrete evidence (the
  nearest reaching route, its hop count, how many routes reach the file in total, and
  any live-confirmed anonymous exposure cross-referenced against a persisted
  `scan_dast` run) plus the coverage gaps behind it. **`unknown` is the default and
  every path must earn its way out of it** — absence of evidence is never
  `unreachable`. **Report only**: no auto-suppression, no severity mutation, no flag to
  enable either — closing a finding stays a human decision. Validates every open
  finding by default (batch is the point); pass `fingerprint` for one, and an unknown
  fingerprint is a refusal, never a silently empty batch — the same applies to a
  missing surface snapshot (`no_surface_snapshot`, naming `map_attack_surface`) and to
  a project with no open findings (its own `note`, never a bare empty array standing in
  for "nothing to worry about"). Verdicts persist to a new `finding_validations` table
  keyed by `(project_path, fingerprint, provider)`, stamped with the snapshot id and
  tree hash they were computed against; a `stale` flag is derived at read time by
  comparing that stored tree hash to the current working tree, so a verdict for code
  that has since moved is never served as current.
  - **`configs/semgrep/routes.yml` gains import rules for all eight stacks** (JS/TS,
    Python, Go, Rust, Ruby, Java, C#, PHP), and closes a real gap in the existing ESM
    rule: `guardian-import-esm` previously matched only a default import or
    `require(...)` and missed `import { foo } from "./bar"` — the dominant form in
    modern TypeScript — which was also silently weakening `map_attack_surface`'s own
    mount resolution.
  - **The negative verdict is the tool's strongest claim and its most dangerous, so
    `unreachable` is gated on six independent conditions, checked in order, ALL of
    which must hold, or the answer is `unknown` with the blocking reason named in
    `coverage_gaps`:** the import graph holds at least one edge at all (an empty graph
    is missing DATA, not missing reachability — a pre-existing snapshot backfills
    `imports: []`, and without this gate every file in it would read `unreachable` on
    zero evidence); the finding's file path and language are determinable; the
    snapshot's per-language coverage is `ok` or `no_matches` (never `no_rules` or
    `unreadable`, where the route list for that language is known to be incomplete);
    the language does not resolve code at runtime (see below); the import graph was
    not truncated at its edge cap; and **the finding's language contributed at least
    one resolved import edge whenever some of its imports failed to resolve** — the
    first gate's reasoning one language down, so a language whose resolver produces
    nothing can never have that emptiness spent as evidence (see *Fixed* below for the
    defect that earned this gate). None of this gates the *positive* direction — any
    discovered import path is reported as `reachable` regardless, down to a finding in
    a route file itself, which reads `reachable` at 0 hops with `high` confidence, the
    only case that earns it.
  - **Known limits — read before trusting a clean `unreachable`:**
    - **`unreachable` is never emitted for Ruby, Java, C#, or PHP.** All four resolve
      code at runtime — autoload convention, annotation-driven injection, a DI
      container, a service container — not by static import, so "nothing imports this
      file" is true of nearly every file in them and proves nothing. The positive
      direction is unaffected: a discovered import edge is still evidence in all eight
      stacks.
    - **Nothing here detects a dynamic import.** `import(expr)`, `require(variable)`,
      reflection, and plugin registries are invisible to any import graph, in every
      stack — including the four above. **In a codebase using them, `unreachable` can
      be wrong, and this tool cannot tell you when.** This is not a gate — there is no
      signal to gate on — it is a limitation, stated in the tool description and here,
      in the same breath as the feature rather than as a weaker or separate account of
      it.
    - **Reachability is computed from HTTP route entry points only.** A file reached
      solely by a CLI entry point, a cron job, or a queue consumer reads as
      unreachable-by-route. That is what it is, and what the evidence says — it is
      **not** a claim that the code never runs.
    - **Granularity is the file, not the function.** A finding inside an uncalled
      helper in an otherwise-imported file reads `reachable`. Correct for what an
      import graph knows; an over-report in the safe direction, not the dangerous one.
    - **The anonymous-exposure cross-reference is only as fresh as the last `scan_dast`
      run for the project**, and that age is reported alongside it — absent a DAST scan
      for the project, the clause is simply absent from the evidence, never assumed in
      either direction.
    - **The batch is whichever scan completed most recently, of any type — not new
      here, but newly relevant.** `validate_finding` reads open findings the same way
      `triage_findings` and `prioritize_findings` already do (`listOpen()`, which is
      not project- or scan-type-scoped): run it right after `scan_dast` and it
      validates the DAST findings, not your last SAST run. The summary now names that
      scan — `findings_from_scan` carries its `scan_id`, `scan_type`, `tree_hash` and
      whether that tree matches the surface snapshot's — so the confusion is
      detectable in the result instead of only documented here.
  - Discoverable via the `map_attack_surface` → `validate_finding` two-step, now
    documented in `host-rules/AGENTS.md` (and its paired host-context files) and in
    both tools' own descriptions.
- **`dev-guardian scan` / `dev-guardian baseline update` — headless CI entry point, no
  MCP host required.** New `cli/dev-guardian.mjs` commands run the exact scan pipeline
  the MCP tools run — `detect_stack` → `security_scan_full` → `license_compatibility` →
  `map_attack_surface` → `scan_dast` (only when `--base-url` is given) →
  `validate_finding` — in that fixed order, because `map_attack_surface` persists the
  route inventory the last two refuse to run without. There is no second implementation
  of any scan: `runScans.ts` calls the very tool handlers `server.ts` registers for an
  interactive session, against an ephemeral SQLite database (a fresh temp directory,
  discarded at exit) — the portable state is the baseline file, not the database. A step
  that refuses (a missing prerequisite, an uninstalled scanner) is recorded, not fatal:
  the rest of the pipeline still runs, and the gap feeds the coverage signal below.
  - **The baseline**, `.guardian/baseline.json`, is committed to the user's repository —
    reviewable in a pull request, no cache needed. `scan` only ever reads it; `baseline
    update` is the one command that writes it, and only on request. An **absent**
    baseline is not an **empty** one: on a repository's first run, `scan` says so, names
    `baseline update` as the fix, and reports every finding as new rather than quietly
    treating the current state as clean.
  - **The gate fails on regressions, never on historical debt.** A finding already in
    the baseline never blocks, however severe; a finding **absent** from it at or above
    `--fail-on` (default `high`) does. Four exit codes carry the verdict: `0` pass, `1`
    gate failed, `2` **incomplete scan** — an expected scanner did not run, reusing
    `computeCoverage`'s existing `full` / `partial` / `none` signal rather than
    re-deriving a second one that could disagree with what the tools themselves already
    report — `3` usage or configuration error. `2` exists because a missing scanner and a
    genuinely clean scan both say "zero new findings" unless something tells them apart,
    and a pipeline must be able to, whether it then treats `2` as a warning or a failure.
  - **Three report formats — human (default), JSON, SARIF** — SARIF being why this
    exists at all: GitHub, GitLab and Azure DevOps code-scanning render it **on the
    lines of the pull request diff**, not in a log nobody opens. SARIF's
    `invocation.executionSuccessful` is set to `false` whenever coverage isn't `full` —
    the two states (`partial`, `none`) where a "0 new findings" result is least
    trustworthy — so a consumer reading only the uploaded SARIF can already tell an
    incomplete run from a clean one, without cross-referencing the exit code. What SARIF
    still cannot say is **which** scanner was missing or why: it has no general-purpose
    home for that prose, so a dropped, unreadable baseline entry is the one exception
    (carried as a `toolExecutionNotifications` line), and everything else — the scanner
    names, the reasons — stays exit-code-and-human/JSON-only. Read the exit code (or
    `coverage` in `--format json`) before trusting an uploaded SARIF that shows nothing:
    a clean pass and an unrun scanner can produce the identical empty results list.
  - **`--start-command` starts the target application for the DAST pass — from argv
    only, never from a repository file.** `scan_dast`'s own MCP tool deliberately has no
    way to start an app, because that parameter could be filled by a model reading the
    very repository under scan, and an injected comment would have somewhere to point.
    That reasoning holds only because a *human* types a CLI flag — a config file inside
    the repository has no such property, so if `.guardian/ci.json` ever declares
    `start_command`, the CLI **refuses outright, regardless of what argv says**: a pull
    request from a fork editing that file must never buy code execution on the CI
    runner (the classic "pwn request"). No shell (`shell: false`, argv stays an array
    end to end); the whole process tree is torn down on every exit path — normal
    completion, a thrown scan, SIGINT, SIGTERM. `--start-command` requires `--base-url`:
    nothing on the command line says which port the app will bind, so the same URL
    serves as both the health-check target and the `scan_dast` origin once it is up.
  - **A CI run leaves `.guardian/` in the workspace.** `security_scan_full`,
    `map_attack_surface` and `scan_dast` write their raw scanner output under
    `.guardian/reports/` in the project being scanned, exactly as they do interactively
    — only the SQLite database is ephemeral. The MCP server gitignores `.guardian/`
    automatically every time it starts against a project — not `init_project`
    specifically, the bootstrap itself (`server.ts`'s own boot sequence) — so that
    never fires from the CLI, and a repository that only ever scans through CI does
    not get the entry for free. A later pipeline step asserting a clean working tree
    fails for a reason that looks like nothing. Add `.guardian/` to `.gitignore` by
    hand.
  - **Known limits.** Distribution is `git clone --depth 1` of this plugin repository
    against a pinned tag, not an `npx` one-liner — heavier, but there is no TypeScript
    build step: `mcp/dist/` ships committed. `mcp/node_modules` does **not** ship
    (gitignored, same as everywhere else in this repo) and is still required — the
    committed `dist/ci/*` and `dist/tools/mapAttackSurface.js` import `execa` and `yaml`
    at the top level, unbundled, so `scan`/`baseline update` fail on a bare clone until
    `npm ci` has run once — a publishable package is being investigated separately,
    gated on a real pass through the Claude Desktop plugin validator rather than
    promised ahead of one. Nor does a stock CI runner carry Semgrep, gitleaks or Trivy
    — `ubuntu-latest` ships none of them — so the pipeline must install them itself
    (the README's CI job does; the scanners are not part of this repository or the
    npm dependency tree). Skipping that leaves every step reporting a missing scanner:
    `coverage` never reaches `full`, exit `2` on every run, correctly, because nothing
    was actually scanned — not a defect in the gate, the absence of the gate's own
    inputs. The scan database is ephemeral by design, so CI carries no trend history
    of its own — the baseline is the only state meant to survive a run, deliberately.
    `scan_dast` in CI reaches only what the runner itself can reach; an application
    behind a private network is out of scope, same as it is interactively.

### Fixed

- **`validate_finding` fabricated `unreachable` for every Python, Go and Rust file.**
  `map_attack_surface` resolved import edges against the *absolute* paths Semgrep
  reports for the absolute target it always passes, while every candidate a resolver
  builds from an import specifier is project-relative (`app.helpers` can only ever name
  `app/helpers.py`). Only the JS/TS resolver survived, because it anchors on the
  importing file's own path; Python, Go and Rust resolved **zero** edges, and every
  finding in those three languages came back `unreachable` — "no route imports this
  file" — on a graph that had never held one of their edges. Every gate passed: the
  graph was non-empty (JS/TS resolved) and coverage read `ok` (route extraction was
  fine). Measured end to end on a four-language project where each helper is imported
  directly by a route in its own language: three `unreachable`, one `reachable`. Both
  sides are now relativized *before* resolution rather than after it, the in-repo
  fixture carries one genuinely resolvable intra-project import per language (there was
  none in Python, Go or Rust, so no test could see the defect), and the new sixth gate
  above blocks the negative verdict for any language that resolved nothing while some
  of its imports failed to resolve — turning a silent, confident falsehood into
  `unknown` with the reason named.
- **Go import resolution matched a file basename instead of the package directory.**
  `import "myapp/pkg/util"` names the *directory* `pkg/util`, and every `.go` file in
  it belongs to the imported package. Matching the extension-stripped file path instead
  resolved only the accidental `pkg/util/util.go` spelling — so an ordinary
  `pkg/util/service.go` read as imported by nothing — and, in the other direction,
  claimed an edge into `pkg/handler.go` for a specifier (`myapp/pkg/handler`) that does
  not import it. Resolution is now by package directory, and returns **every** file in
  it, so no file in a multi-file package is left without the inbound edge its package
  actually has.
- **An absolute POSIX path lost its leading `/` during import resolution.** The
  path-joining helper dropped empty segments, and an absolute path's leading slash *is*
  an empty first segment, so `/src/api` + `./helper.js` normalised to
  `src/api/helper.js` and matched no file. On Linux, macOS and every Docker-Semgrep run
  — where absolute POSIX paths are all Semgrep reports — the import graph came back
  entirely empty and every verdict was `unknown`. `map_attack_surface`'s own
  `resolveModuleFile`, which the helper mirrors, carried the same defect and silently
  degraded Node mount resolution on those hosts; both are fixed.
- **`validate_finding` read the newest surface snapshot in the database, from any
  project.** Everything else in the tool is keyed to the resolved `project_path` —
  routes and findings are relativized against it, verdicts are persisted under it, the
  DAST cross-reference filters by it — so a snapshot mapped for a *different* project
  produced a graph in a foreign key space where no root matched any node, and, because
  that graph is non-empty, `unreachable` for every finding rather than an error. The
  read is now project-scoped (`SurfaceRepo.getLatestForProject`); `getLatest()` remains
  for the callers whose contract really is "whatever this server last mapped" (the
  `guardian://surface/latest` resource and `scan_dast`).
- **`validate_finding`'s `summary.snapshot.routes_total` counted routes that were never
  roots.** Spec-provenance routes are deliberately excluded from the reachability roots
  (a spec route's `file` is the OpenAPI document, which no code import graph contains),
  but the summary counted them anyway — so a project whose routes came only from an
  imported spec read `routes_total: 40` beside a batch of `unreachable` verdicts
  computed from zero roots, and disagreed with `map_attack_surface`'s own code-only
  `routes_total`. It now counts the code routes actually used, alongside `root_files`
  (the deduplicated files the traversal starts from) and `spec_routes_excluded`.
- **A duplicate in `spec_paths` could hide an unreadable spec document.** `discoverSpecs`
  deduplicates the explicit paths and *then* applies the 20-file cap, while
  `map_attack_surface`'s own "which named paths were not read" accounting capped the raw
  list. With duplicates present the caller's window ended earlier than the one discovery
  used, and a genuinely missing path landing in the gap was reported by neither side: no
  `parse_error` row (outside the caller's window) and no truncation row (the deduplicated
  set never exceeded the cap). It vanished — the same "could not be read" reading as "there
  is no spec" conflation the rest of the feature exists to prevent. Both call sites now
  share one deduplicated list, which also stops a duplicated document from double-counting
  its routes in `spec_routes_total`.

- **The Rust route rules fabricated four routes for every real one.** The five per-verb
  actix rules were `#[get($PATH)]`, `#[post($PATH)]` and so on. A bare attribute is not a
  Rust item, and Semgrep degraded each of them to a pattern that matched *every node in
  the file* while binding `metavars: {}` — measured on 1.86.0, a three-route file produced
  95 matches, spans including `use` lines and function bodies, with all five rules
  reporting the same spans. So one `#[get("/x")]` yielded the correct GET plus four
  invented POST/PUT/PATCH/DELETE routes at the same path, and `map_attack_surface` feeds
  a DAST tool that would send a request to each. The fix is the trailing
  `fn $F(...) { ... }`: the pattern now includes the item the attribute is attached to, so
  it matches the seven real routes and nothing else. (The rules were briefly collapsed into
  a single `#[$METHOD($PATH, ...)]` rule, because Semgrep's Rust engine does bind the
  attribute name once the pattern is well-formed. They are five again — one per verb, each
  declaring `metadata.method` — because `focus-metavariable: $PATH` discards `$METHOD`; see
  the redaction entry below.) Verified: exactly seven matches for seven routes, each with
  the right verb and path, and the `#[allow(...)]` attribute stacked on two of them
  correctly ignored. It does **not** cover Rocket's multi-argument attributes:
  `#[post("/x", data = "<t>")]` and `#[get("/x", rank = 2)]` produce zero matches on
  both 1.164.0 and 1.86.0 despite the `, ...`, and so does an explicit
  `#[$METHOD($PATH, $EXTRA)]`. Only a bare `#[$METHOD(...)]` matches them, and it binds
  no `$PATH` — a route with no path is worse than a route we did not report. Pinned as
  fixture bait in `rust-actix/rocket.rs` so the limitation stays measured.
- **The five ASP.NET attribute-routing rules matched nothing at all.**
  `[HttpGet($PATH)]` parses as a C# collection expression, not an attribute, so every
  `[HttpGet("/orders")]` in a controller was invisible — a whole style of ASP.NET routing
  silently missing from the inventory while `coverage` reported `ok` for C# on the
  strength of the minimal-API rules alone. Fixed by extending each pattern to include the
  method the attribute decorates.
- **The five NestJS rules were rule *errors*, not merely unmatched.** `@Get($PATH)` is not
  a parseable TypeScript pattern ("Invalid pattern for TypeScript"), so every single run
  of `map_attack_surface` on any project emitted five rule-parse errors and reported zero
  NestJS routes. Same fix: the pattern now includes the decorated method. The decorator
  name cannot be a metavariable in TypeScript (`@$DEC($PATH)` does not parse either), so
  these stay one rule per verb.
- **The Django rule reported filesystem-path helpers as HTTP routes.** `path($PATH, ...)`
  keys on the callee *spelling*, and `path` is an ordinary function name. Measured against
  a module doing nothing worse than `def path(*parts): return os.path.join(*parts)`, the
  rule produced three routes, two of which (`etc`, `var`) passed the extractor's literal
  test and were therefore emitted as resolved URLs that exist nowhere. The rule now names
  the callee in full — `django.urls.path` / `django.urls.re_path` — so Semgrep resolves
  the import instead of the spelling. This is **not** a `$PATH` literal guard: a computed
  path (`path(settings.ADMIN_URL, ...)`) still matches and is still reported, flagged
  `path_partial`. The Ruby rule was checked for the same failure and does not have it:
  `Rails.cache.delete 'orders/index'` and `store.get 'orders/index'` produce no matches,
  because `$METHOD $PATH` does not match a call with an explicit receiver.
- **Express/Fastify mount resolution never worked on Windows.** Semgrep reports paths in
  the host's native separator and this tool always hands it an absolute target, so on
  Windows a match arrives as `C:\project\src\routes\users.js` while the import specifier
  is `./routes/users`. `resolveModuleFile` split on `/` only, so a Windows path was one
  segment, matched no known file, and every route in a mounted router silently degraded to
  `path_partial` — the tool looked healthy and quietly stopped resolving prefixes on a
  supported platform. Paths are now normalised before comparison, and the known file is
  still returned verbatim so it continues to match `RouteRecord.file`.
- **All thirteen route families are now read on every Semgrep version, logged in or not.**
  NestJS, ASP.NET attribute routing and actix are the families whose Semgrep pattern must
  match the attribute *plus the declaration it decorates* — the attribute alone does not
  parse, or matches every node in the file. The reported span therefore begins at whatever
  attribute comes first, and **four** successive attempts to read a route out of it each
  **invented** one: anchoring on the first argument list turned `#[allow(dead_code)]` into a
  route named `dead_code` and `[Produces("application/json")]` into `application/json`;
  anchoring on the route attribute by name turned a commented-out
  `// [HttpGet("/orders/legacy")]` into `/orders/legacy` while the live `/orders`
  disappeared. Both passed `isLiteralPath`, so each was emitted as a **resolved** path — a
  URL `scan_dast` would request — and both were silent, because reconstruction *succeeded*:
  `tools_run` reported `ok` with zero unrecoverable matches. The families were then refused
  outright, which was correct against those options but left 21 real routes out of the
  inventory whenever Semgrep redacted match content.
  - **The fix removes the question rather than answering it.** Deciding whether text is
    code, a comment or a string literal is **not local information** — it depends on
    everything from the start of the file, and the span starts in the middle. So no
    predicate over the span decides it: the three rules now carry
    `focus-metavariable: $PATH`, which makes Semgrep narrow its own **reported range** to
    the metavariable, using a real parser for the language. The byte offsets then point at
    the path literal itself, and recovery is "the span is the value" — no anchoring, no
    argument parsing, nothing searched for. A decoy cannot be picked out of a span it is not
    in, which is what makes the defect class structurally unreachable rather than merely
    unobserved.
  - **Measured on both Semgrep versions, against the adversarial fixtures.** 1.164.0
    (redacts match content) and 1.86.0 (still emits `extra.metavars`) produce the **same 64
    routes** over `mcp/test/fixtures/surface/apps/` — 81 matches each, zero rule errors on
    either (1.164.0 emits one pre-existing PHP parse warning; see above), zero unrecoverable on
    either — and the reported spans on 1.164.0 are byte-for-byte equal to 1.86.0's `$PATH`
    captures, quotes included. Every planted decoy is absent from both: `dead_code`,
    `application/json`, `204`, the commented-out `/rust/legacy`, `/aspnet/orders/legacy` and
    `legacy/:id`, and the attribute-shaped `FABRICATED` text inside method bodies. Coverage
    no longer depends on the Semgrep version, or on being logged in.
  - **A truncated range can no longer become a resolved path.** The focused branch trusts
    Semgrep's range by design — validating it would mean re-deriving what Semgrep already
    decided, the mistake of all four earlier rounds — so the safety argument has to be that
    every way a range can be wrong degrades to *incomplete*. One shape did not: a range
    ending **inside** the string literal left the opening quote unmatched, and `stripQuotes`
    in `extract.ts` removed it anyway, so `"/orders/secret` cut six bytes short read as the
    clean path `/orders/s` at full confidence — a URL that exists nowhere, published as
    verified, while the real one was absent. `stripQuotes` now strips only a **matched**
    pair, so the stray quote reaches `isLiteralPath`, which rejects it: the route survives
    as `path_partial` at `low` confidence with its raw text visible. Unreached by anything
    measured — 115 captures (81 fixture + 34 probe) were byte-exact against 1.86.0 — but
    truncation is not hypothetical: a TypeScript template literal was observed arriving two
    bytes short of its closing backtick. Pinned for all three quote styles.
  - **actix is five rules again, one per verb.** Focusing on `$PATH` discards every other
    capture, `$METHOD` included, so the verb has to come from `metadata.method` — the shape
    NestJS, ASP.NET attribute routing and Spring already use. Per-verb discrimination was
    re-measured across all three languages (six rules over three files, each matching only
    its own attribute), so the reason actix was once collapsed into a single
    `$METHOD`-binding rule no longer holds.
  - **The refusal machinery is deleted, including its fail-open default.**
    `UNRECOVERABLE_FRAMEWORKS` / `UNREADABLE_UNDER_REDACTION` listed the frameworks to
    refuse, so a fourth declaration-spanning family added without being listed would have
    silently fabricated again. There is no list any more, and therefore no wrong path for an
    unlisted framework to fall into. What replaces it is a lock-step assertion in
    `rulePack.test.ts`: a rule declaring `metadata.guardian_focus: path` without
    `focus-metavariable` (or the reverse) fails the suite, as does a route rule whose
    pattern spans a declaration without focusing. The flag is deliberately read from the
    rule pack rather than inferred from the framework name — the pack is the thing that
    knows whether it focused.
  - **Only these three are focused.** The other ten route families (express + its
    mount/import rules, flask, fastapi, django, laravel, gin, net/http, spring, wp-rest,
    aspnet-minimal) and all five `env` rules have spans that begin at the call or annotation
    that matched, so the capture sits at a known place. They are verified slot-for-slot
    against Semgrep 1.86.0 — every capture the extractor reads, identical — and several
    capture `$METHOD` as a metavariable that focusing would discard. Noted in the module
    docs as a possible future simplification, not a pending fix.
  - **`CoverageEntry.status: 'unreadable'` stays, and no longer describes a rule family.**
    `'ok' | 'no_matches' | 'no_rules' | 'unreadable'` with a companion `unreadable_matches`
    count, so a language whose routes were matched but not read can never collapse into
    `no_matches` — "this language exposes nothing", the exact inverse of the truth. It is
    now reachable only for a genuinely unreadable match: source rewritten or deleted
    mid-scan, not valid UTF-8, or offsets past end-of-file. The `tools_run` reason and the
    degraded `note` were rewritten to say that, instead of naming three families that are no
    longer affected.
  - The fixture keeps every adversarial case that caught this — a commented-out route
    attribute, anchor text inside a string, attribute-shaped text in a method body, an
    apostrophe in a comment, a Rust lifetime — for all three frameworks. The assertions that
    pinned their **absence** are inverted to pin the **real** route, and the
    `FABRICATION_DECOYS` check that has caught this class every time is unchanged: no decoy
    path may appear in the output, ever.
- **`recoverMetavars` could throw, contradicting its own contract.** `metadata.method` was
  interpolated raw into `new RegExp`, so a rule declaring `method: "a("` raised a
  `SyntaxError` out of a module documented as never throwing, and out of an unguarded call
  site in `mapAttackSurface.ts`. That path is gone with the anchoring, and a
  `metadata.method` that is not a plain word is rejected outright.
- **The rule-pack drift assertion was a substring sniff.** It tested for the literal text
  `{ ... }`, so the same rule written `{ $BODY }` — which Semgrep treats identically —
  widened a family past the guard while the test stayed green. It now parses each rule's
  patterns and detects a brace-delimited body structurally, and asserts that the pack's
  declaration-spanning route rules are exactly the ones carrying `focus-metavariable`.
- **A skipped end-to-end test reported as a passing one.** Both e2e files —
  `rulePackFixture.test.ts` and `evalVulnFixture.test.ts`, the only tests that run a real
  Semgrep — used `console.warn` plus a bare `return` when Semgrep was absent, which vitest
  counts as a pass. On Windows, Semgrep installs to
  `%APPDATA%\Roaming\Python\Python3xx\Scripts`, which is not on `PATH`, so both gates
  silently measured nothing and route-fabrication defects reached a green suite through
  them twice. They now use `it.skipIf`, so a skip reads as a skip, and
  `GUARDIAN_REQUIRE_SEMGREP=1` turns absence into a hard failure that distinguishes "not on
  PATH" from "fixture tree missing".
- **`map_attack_surface` extracted zero routes on every current Semgrep.** Semgrep changed
  behaviour between 1.95.0 and 1.120.1: unless the user has run `semgrep login` it redacts
  match content, so `extra.metavars` is absent entirely and `extra.lines` reads
  `"requires login"`. The extractor reads `extra.metavars.$PATH.abstract_content`, so the
  tool reported *no routes at all* while Semgrep itself reported matches — nothing looked
  broken, and the persisted snapshot said the application exposes nothing. Requiring an
  account is not an option for a tool whose stated position is 100% open-source and local.
  What redaction does not remove is the position: `start.offset` / `end.offset` survive, so
  a new pure module `mcp/src/surface/recoverMetavars.ts` slices the matched source out of
  the file and reconstructs the captures the rules would have bound, keyed off
  `guardian_kind` and `framework`. It synthesizes into the shape the extractor already
  reads, so `mcp/src/surface/extract.ts` is untouched. Measured end to end against Semgrep
  1.164.0 over `mcp/test/fixtures/surface/apps/`: **all 64** of the fixture's routes and all
  8 environment variables recovered, where the tool previously found none at all. (43 of the
  64 at first — the other 21 were the three decorated-declaration families, which were
  refused until `focus-metavariable` made their spans readable; see the entry above.)
  Verified capture-by-capture against Semgrep 1.86.0 — the last version that still emits
  metavariables, and which finds the same 64 — as ground truth.
  - Offsets are **byte** offsets, so the span is sliced from a `Buffer`; a source file with
    any non-ASCII character before the match desyncs a plain `String.prototype.slice` and
    yields a confidently wrong path. Source quoting is preserved verbatim, because that is
    exactly how `isLiteralPath` separates `'/items'` from `self::NAMESPACE` — and
    `register_rest_route(self::NAMESPACE, '/computed', …)`, the dominant idiom in real
    WordPress plugins, survives as a `path_partial` route rather than vanishing.
  - The module is pure and never throws: a file it cannot read, an offset past
    end-of-file, or a span with nothing to capture is counted `unrecoverable` and skipped.
    Reading the files stays in the tool, which is already the impure layer.
  - **Honest degradation.** If Semgrep reported matches and *not one* could be recovered,
    that is a broken toolchain, not a project without routes: the tool now persists
    nothing and says why — naming the redacting-Semgrep cause and that `map_attack_surface`
    does not require an account — instead of writing a zero-route snapshot that later reads
    as "this application exposes nothing". A partial recovery is persisted but reported, via
    a `semgrep-metavar-recovery` entry in `tools_run` carrying the counts, so it is visible
    rather than silent.
- **A path we could not resolve is never emitted as a resolved path.** Only one route rule
  in the pack constrained its path capture to a string literal; the other thirteen let a
  Semgrep metavariable that had bound a *code expression* through as a confident path —
  `self::NAMESPACE`, `$this->namespace`, `SETTINGS.users_path`, `Paths.ORDERS`, a bare
  `routeVar`. The first two are the dominant idioms in real WordPress plugins, not edge
  cases, and the next tool in this series will send HTTP requests to whatever path it is
  handed. A new `isLiteralPath` predicate in `mcp/src/surface/extract.ts` now gates every
  route, in the one place they all flow through, so it also covers rules users add via
  `register_custom_rules`. A capture that fails it keeps its route — a route we cannot
  name is still evidence of surface — but is flagged `path_partial: true`, keeps the raw
  text in `path_resolved`, and drops to `low` confidence. Both resolvers now honour that
  flag instead of clearing it when they prepend a mount prefix or a `/wp-json` namespace.
  A `metavariable-regex` guard in the rule pack would be the wrong second layer here: it
  *drops* the match, so the extractor never sees it, and a route registered with a computed
  path is still surface — dropping it would make `coverage` report `no_matches` for the
  language, which is the same "this application exposes nothing" falsehood in a different
  place. `$PATH` literal guards are therefore confined to the two rules whose pattern does
  not identify a route on its own (`guardian-route-express`, `guardian-route-rails`), where
  the literal disambiguates rather than discards, and the pack header now states that rule
  so it is not re-added by pattern-matching.
- **`params` is derived from the path alone.** It was gated on both the path and the
  namespace being literal, so `register_rest_route(self::NAMESPACE, '/items/(?P<id>\d+)')`
  reported `params: []` — an assertion that the route takes no parameters — when `id` is
  plainly knowable from the path. Where the route is served stays unknown
  (`path_partial: true`); the parameters no longer do.
- **The HTTP method was lost for five of thirteen route rules.** `aspnet-minimal`,
  `aspnet`, `spring`, `nestjs` and `actix` all reported `ANY`. Semgrep never reports which
  `pattern-either` alternative fired, so a rule whose verb is encoded in the alternative
  cannot recover it — those families are now one rule per verb, each declaring
  `metadata.method` (which the extractor already read as a fallback, until now dead code).
  `normalizeMethod` also understands ASP.NET's `MapGet` / `MapPost` builder names.
- **A cached snapshot no longer hides the failed run that produced it.** The cache path
  reported a hardcoded `tools_run: [{semgrep, skipped, cached}]`, so the one case where a
  failing run is still persisted (Semgrep exited non-zero but left parseable JSON) carried
  its warning for exactly one call. Every later call on the same tree hash presented a
  snapshot that was empty *because the scan died* as "this application exposes nothing" —
  the falsehood this tool exists to prevent. The persisted `tools_run` entries are now
  reported alongside the cache marker.
- **`auth_hint` is no longer advertised as a feature.** No rule sets `metadata.auth`, so
  the field is always `unknown`. The claim was removed from the tool description, and the
  reason is recorded at `normalizeAuth` so the constant reads as deliberate rather than
  broken. Detecting auth properly needs to see the handler, not the registration site;
  that is its own piece of work.
- Regression coverage for the Semgrep exit-code gate (`exitCode === 1` means *matches
  found*, i.e. success), which previously could be deleted with the suite staying green.
- The Docker fallback in `map_attack_surface` no longer re-implements
  `buildSemgrepDockerArgs`; the shared builder takes a `configs` option (default
  `['auto']`) so both callers inherit anything added to it later.
- **A spec's `trace` operation no longer suppresses shadow-endpoint findings.** Spec
  import mapped `trace` (an OpenAPI/Swagger operation key with no matching `HttpMethod`
  member) onto the `'ANY'` routing sentinel, which `specDiff.ts` treats as matching every
  method at a path. A document declaring only `trace: /foo` therefore made both
  `GET /foo` and `POST /foo` in the code read as documented — two genuine shadow
  endpoints silently suppressed. `trace` operations are now excluded from import
  entirely rather than folded into `'ANY'`; the alternative (adding a `TRACE` member to
  the persisted `HttpMethod` union) was rejected to avoid touching a type serialized into
  every stored snapshot for the sake of an operation this feature does not otherwise need
  to represent.
- **The installers advertised a scanner this plugin has never integrated, and omitted the
  one it can install.** `scripts/install/install-linux.sh` carried an OWASP ZAP banner
  (`docker pull zaproxy/zap-stable`) held over from before `scan_dast` existed — `ZAP`
  appears nowhere in `mcp/src`, is not in `TOOL_CATALOG`, and `install_toolchain` cannot
  install it, so the banner advertised a capability the plugin does not have. Meanwhile
  nuclei, which *is* in `TOOL_CATALOG` (`required_by: ['scan_dast']`, `default: false`)
  and is what `scan_dast`'s `use_nuclei` actually drives, appeared in neither installer.
  Both scripts now carry an honest nuclei banner instead: `install-linux.sh` states plainly
  that Linux has no automatic install path (`TOOL_CATALOG`'s linux bucket for nuclei is
  empty) and points at ProjectDiscovery's own install docs — `install_toolchain` is named
  only as confirming the same gap, not as a working alternative. `install-macos.sh` gained
  the equivalent banner naming the real `brew install nuclei` formula `TOOL_CATALOG` already
  verifies for that platform, where `install_toolchain` genuinely installs it. Neither
  banner reproduces `TOOL_CATALOG`'s linux `curl` fallback, which resolves to a GitHub
  releases HTML page rather than a raw install script.
- **`TOOL_CATALOG`'s linux install command for gitleaks and nuclei piped an HTML page into
  `sh`.** `curlInstaller`'s contract is a raw install script, but the `gitleaks` and
  `nuclei` linux entries pointed it at `.../releases/latest`, which redirects to the
  release's HTML tag page. `curl -f` only fails on HTTP error status, so the fetch
  "succeeded" and handed `sh` a full HTML document — a wall of shell syntax errors, not an
  install. Because gitleaks is `default: true`, this sat on a supported path: `check_toolchain`
  printed that broken one-liner as `install_command` for every caller on Linux regardless of
  whether they ever called `install_toolchain`, and an explicit
  `install_toolchain(tools: ["gitleaks"])` (or `["nuclei"]`) actually ran it. The default
  bootstrap flow (`install_toolchain` with no `tools` filter) was unaffected — on Linux it
  delegates to `install-linux.sh`, which resolves gitleaks's real download URL itself — so
  the breakage was reachable only through the per-tool path and through `check_toolchain`'s
  advisory output. Confirmed with `curl -sSIL` rather than assumed: gitleaks and nuclei both
  returned `Content-Type: text/html` on the final `200`, while trivy's and syft's linux
  entries (real `install.sh` scripts on `raw.githubusercontent.com`) returned `text/plain`,
  confirming they were never affected. Both broken entries are removed rather than replaced
  — neither tool ships a stable install script, and a hand-written per-arch downloader would
  be new, unverified machinery — so `pickInstallSpec` now returns `null` for gitleaks and
  nuclei on Linux and both degrade to `manual_steps` / no `install_command`, the same honest
  gap nuclei's win32 entry already relied on. `curlInstaller` now carries a doc comment
  stating the precondition the next caller must meet.

## [1.2.1] — 2026-08-10

### Fixed

- **Marketplace sync failed on Claude Desktop / claude.ai.** The top-level `bin/` directory is now
  `cli/`. Desktop does not clone the repository — it delegates validation to a remote Anthropic
  service, which rejected the plugin with `status=failed_content`: *"Plugin contains a top-level
  bin/ directory ('bin/dev-guardian.mjs'). claude.ai-hosted plugins may not ship bin/ executables
  because they are added to PATH on the CLI but are not shown on the admin approval surface. Declare
  executable entry points via hooks, commands, or mcpServers instead."* The UI surfaced this only as
  **"Marketplace sync failed. Check the repository URL"**, which is misleading — the URL was always
  correct. Installing through the Claude Code CLI was never affected, because it uses a local
  `git clone` and skips this validation, so a passing CLI install is not evidence that Desktop will
  accept the plugin.
- The CLI is now `node cli/dev-guardian.mjs` — same commands (`mcp-config`, `check`), same
  behaviour. References updated in `README.md` (EN/PT/ES), `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`,
  `.cursor/rules/` and every `host-rules/` template.

## [1.2.0] — 2026-07-15

### Added

- **`guardian-grill` — the understanding gate.** A new front-end skill (with
  `/guardian-grill` and the `/gg` alias) that grills *you* on the
  domain-significant decisions a diff/PR introduced before you merge — for the
  long autonomous loops where you no longer read every line. Complements the code
  gates (lint / Semgrep / tests / review): those check the code, this checks that
  a human still understands the branches and rules the AI wrote. Records its
  verdict to `.guardian/last-grill.md` so the status and report gates can show an
  Understanding-gate row. Adapts the `dev-grill` engine when installed, runs the
  loop inline otherwise.
- **`guardian-improve` — from measured debt to improvement specs.** A new skill
  (with `/guardian-improve` and the `/gi` alias) that converts the ROI-ranked
  hotspots, quality-rule violations, oversized files, duplication and coverage
  gaps from the quality gate into metric-anchored **improvement spec seeds**
  (problem → affected files → current metric → target metric → draft EARS
  criteria) ready to hand to `dev-spec-driven`. Closes the loop:
  measure → spec → fix → re-measure. Targets are derived per project from
  `.guardian/budgets.yml`, the stack, or the baseline — never invented.

### Changed

- **`guardian-status`** now shows an **Understanding gate** row from
  `.guardian/last-grill.md` (🟢 / 🟡 / 🔴, or ⚪ when not run for the current diff).
- **`guardian-report`** includes the latest `guardian-grill` verdict in its
  Quality section — a green gate means the metrics passed *and* a human understood
  the change.
- **`guardian-budget`** now also audits code-quality budgets (max file / function
  lines, cyclomatic complexity, duplication %, coverage floor) from
  `.guardian/budgets.yml` — the single source of truth shared by the quality gate
  and `guardian-improve`, proposed per stack.
- README and CLAUDE.md counts updated to **13 skills + 48 slash commands**.

## [1.1.4] — 2026-07-09

### Added

- **Scan coverage trust signal.** Every scan now reports a `coverage` value
  (`full` / `partial` / `none`) derived from which scanners actually ran, so a
  "0 findings" result that scanned nothing can never read as "all clear". At
  coverage `none` a loud warning states plainly that nothing was scanned;
  `audit_executive` rolls up the worst coverage across its sub-scans and
  surfaces each gap. (`tools/scanCoverage.ts`)
- **Semgrep Docker fallback for SAST.** When `semgrep` is not on PATH but a
  Docker daemon is reachable, `scan_sast` runs the official `semgrep/semgrep`
  image (bind-mounted via `--mount` so it tolerates Windows drive letters and
  spaces in the path). A failed container run is recorded as a real coverage
  gap, never a silent empty scan. (`runners/dockerScanner.ts`)
- **`npm audit` findings are now counted.** `deps_audit` parses
  `npm audit --json` (npm 6 and 7+) into Findings, complementing Trivy's CVE
  coverage with GitHub advisories. (`runners/scannerParsers/npmAudit.ts`)

### Fixed

- **No double-counting of the same dependency CVE.** When Trivy already reports
  a package by CVE, the overlapping `npm audit` finding for that package is
  dropped (Trivy is the canonical CVE source); npm findings for packages Trivy
  missed are kept. Stops inflated severity counts from flowing into the
  executive roll-up.
- **An `npm audit` error is no longer treated as a clean scan.** A missing
  lockfile makes npm exit non-zero with an `{ error }` object rather than a
  report — previously counted as a successful "0 findings". It is now recorded
  as a failed auditor and a coverage gap.
- **A missing native auditor is a coverage gap.** When `npm` / `pip-audit` is
  expected (the manifest exists) but absent, it is added to `missing_tools` so
  coverage reflects the gap instead of reporting `full`.

## [1.1.3] — 2026-06-10

### Fixed

- **MCP server now starts on a fresh install — no `npm install` required.** The
  server imported `@modelcontextprotocol/sdk`, `better-sqlite3`, `execa` and
  `zod` as runtime dependencies, but the plugin ships git-first with
  `mcp/node_modules` git-ignored, so the *installed* server crashed on its first
  import with `ERR_MODULE_NOT_FOUND` and none of the 50 MCP tools came up (the
  zero-dependency hooks were unaffected).
  - Replaced the native **`better-sqlite3`** engine with the built-in
    **`node:sqlite`** (`DatabaseSync`), behind a thin adapter in
    `mcp/src/storage/db.ts` (`prepare/run/get/all/exec/pragma` + a nesting-aware
    `transaction`) — no native module to compile or ship.
  - The build now **bundles** `dist/server.js` with esbuild
    (`mcp/scripts/bundle.mjs`), inlining the remaining pure-JS deps, so the
    server runs with **zero** runtime `node_modules`.
  - The server is launched with `--experimental-sqlite` and now requires Node
    **>=22.5**. No change to the MCP tool/resource surface (still 50 tools,
    16 resources); the full test suite now exercises the `node:sqlite` engine.

### Changed

- Removed `better-sqlite3` / `@types/better-sqlite3`; bumped `@types/node` to
  22.x and added `esbuild` as the bundler. Verified the bundled server boots
  from a `node_modules`-free sandbox and lists all 50 tools.

## [1.1.2] — 2026-06-10

### Fixed

- **MCP server now loads when the plugin is enabled.** The plugin manifest
  (`.claude-plugin/plugin.json`) launched the server via the invalid
  `${pluginDir}` placeholder, which Claude Code does not recognise — it rejected
  the config with `Invalid MCP server config for "dev-guardian": Missing
  environment variables: pluginDir` and the 51 MCP tools never came up. Switched
  to the documented **`${CLAUDE_PLUGIN_ROOT}`** placeholder (already used by the
  guardrail hooks). Same fix applied to the docs that quoted the old form
  (`README.md`, `mcp/README.md`, `mcp/src/hostsetup/mcpConfig.ts`). No change to
  the MCP tool/resource surface or plugin behaviour.

## [1.1.1] — 2026-06-07

### Changed

- **Dropped the GitHub Actions CI workflow** (`.github/workflows/ci.yml`).
  dev-guardian is distributed git-first and the maintainer avoids the recurring
  Actions cost, so the quality gates now run **locally**: `npm test`,
  `npm run build` (rebuild `mcp/dist/` before committing — no CI to catch
  drift), markdownlint, the guardrail hooks, and the `dev-guardian check` CLI.
  No npm publishing either (unchanged — never set up). No change to the plugin
  behaviour or the MCP tool/resource surface.

## [1.1.0] — 2026-06-06

### Added

- **Guardrail hooks** (`hooks/hooks.json` + `hooks/guardian-hook.mjs`),
  auto-loaded when the plugin is enabled — **dependency-free** (only `node:`
  builtins + pure compiled detectors; no native modules, so they run in the
  installed plugin where `mcp/node_modules` isn't shipped) and **fail-open**
  (any error → exit 0, never breaks the host):
  - **SessionStart** — briefs the agent with the project's security posture
    (branch, uncommitted changes, last-scan age, init state).
  - **PostToolUse (Write/Edit/MultiEdit/NotebookEdit)** — warns, with a
    **redacted** preview, when freshly written text contains a hard-coded
    secret. The authoritative full scan stays `scan_secrets` (gitleaks).
  - **PreToolUse (Bash)** — denies catastrophic commands by default
    (`rm -rf /`, `curl … | sh`, raw-disk `dd`/`mkfs`, fork bombs); warns on
    risky ones (force-push, hard reset, `sudo`, `chmod 777`).
  - Configurable via `.guardian/hooks.config.json` (opt-in secret-write
    blocking with `secrets.block`), `.guardian/hooks-allowlist.json` for false
    positives, and the `GUARDIAN_HOOKS=off` kill switch.
- `mcp/src/hooks/secretScan.ts` + `bashGuard.ts` — pure, unit-tested detection
  engines (31 new tests) shared by the hooks and the CLI.
- `dev-guardian check` CLI subcommand (`--file <path>` / `--bash "<command>"`,
  `--min`, `--json`) — run the same guardrail detectors from a terminal or CI;
  exit code 1 on a finding.

### Fixed

- The MCP server no longer reports a hard-coded `0.1.0`; it reads its version
  from `.claude-plugin/plugin.json` at startup (falling back to the MCP
  `package.json`), keeping its reported identity in lock-step with the release.
- `mcp/package.json` version aligned with the plugin release (was stale at
  `0.1.0`).

## [1.0.0] — 2026-06-05

First stable release. Everything below was already shipped in 0.x; 1.0.0 marks
the point where the surface is proven and held to semver.

### Added

- **CI pipeline** (GitHub Actions): markdownlint; build + test on Linux, macOS
  and Windows; a dist-sync gate (committed `mcp/dist` must equal a fresh build);
  coverage thresholds; an e2e job running real Semgrep against a vulnerable
  fixture; and a dogfood self-audit (Syft SBOM + gitleaks + Semgrep SARIF).
- **Stability snapshot** — the exact 50 tools + 16 resources are pinned in
  `toolSurface.test.ts`; accidental surface drift fails CI.
- `SECURITY.md` (responsible disclosure), `CONTRIBUTING.md`, this `CHANGELOG.md`.

### Changed

- **First stable release.** The MCP tool/resource surface and default
  behaviours are now covered by semver.

### Fixed

- README counts corrected (44 commands, 16 resources).

## [0.6.0] — 2026-06-05

### Added

- `mcp-config` CLI (`bin/dev-guardian.mjs`) — bootstrap dev-guardian into any AI
  host from a plain terminal, with the absolute server path filled in. Prints a
  paste-ready block or, with `--write`, merges it into the project.
- `mcp/src/hostsetup/setup.ts` — context-free host-setup core (`setupHost`,
  `previewMcpConfig`) shared by the CLI.

### Removed

- **BREAKING:** the `install_host_context` MCP tool. Use the `mcp-config` CLI
  instead. MCP tool count: 51 → 50.

## [0.5.1] — 2026-06-05

### Added

- In-repo AI host configs (dogfooding): `.mcp.json`, `.cursor/`, `.gemini/`,
  `.vscode/`, `.windsurf/`, `.github/copilot-instructions.md`, root `AGENTS.md`
  / `GEMINI.md`, and a `CLAUDE.md` contributor guide. Open the repo in any host
  and the MCP server + rules load out of the box (relative paths).

## [0.5.0] — 2026-06-05

### Added

- Branded Pro Digital Key HTML reports for `report_export` and
  `/guardian-report`: a self-contained shell with a dark/light toggle (system
  default, persisted), 100% offline, print-friendly, and trilingual chrome via
  a `lang` input.

### Changed

- **BREAKING:** `report_export` default format changed from `html` to
  `markdown`. `html` / `sarif` / `json` remain available explicitly.

## [0.4.0] — 2026-06-05

### Added

- Multi-host MCP installer: register the server (merging, never clobbering) plus
  the rules file across Cursor, Windsurf, GitHub Copilot, Cline, Codex CLI,
  Gemini CLI and Claude Desktop. Adds a `GEMINI.md` rules template.

## [0.3.0] — 2026-06-04

### Added

- `scan_skill` — vet a third-party skill / MCP server / agent before install
  (16 threat categories, YARA-style signatures, taint-light, OSV.dev lookups,
  0–100 risk score).

### Fixed

- Ship the compiled `mcp/dist/` so the plugin's MCP server starts without an
  install-time build.

## [0.2.1] — 2026-05-27

### Fixed

- MCP server startup.

## [0.2.0] — 2026-05-27

### Added

- First public release: open-source security / bugfix / quality / deps /
  observability / performance / compliance plugin with an MCP server, SQLite
  state, and trilingual (EN/PT/ES) triggers.

[1.1.0]: https://github.com/linofcp007/dev-guardian/releases/tag/v1.1.0
[1.0.0]: https://github.com/linofcp007/dev-guardian/releases/tag/v1.0.0
[0.6.0]: https://github.com/linofcp007/dev-guardian/releases/tag/v0.6.0
[0.5.1]: https://github.com/linofcp007/dev-guardian/releases/tag/v0.5.1
[0.5.0]: https://github.com/linofcp007/dev-guardian/releases/tag/v0.5.0
[0.4.0]: https://github.com/linofcp007/dev-guardian/releases/tag/v0.4.0
[0.3.0]: https://github.com/linofcp007/dev-guardian/releases/tag/v0.3.0
[0.2.1]: https://github.com/linofcp007/dev-guardian/releases/tag/v0.2.1
[0.2.0]: https://github.com/linofcp007/dev-guardian/releases/tag/v0.2.0
