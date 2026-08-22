# C# bug-finding rule pack — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `configs/semgrep/bugfix-cs.yml` — eleven measured C# bug-finding rules — with a test harness that would catch every defect class this series has shipped.

> **Boxes reconciled against the code on 2026-08-22, not ticked during
> execution.** Nothing here was ticked while the work was done; every box was
> checked afterwards against the pack, the fixtures, the harness and the git
> history, so the ticks are an audit. Steps whose only product was a transient
> run — "Expected: FAIL", a `dotnet build`, an ablation report — are ticked on
> the artefact they were meant to leave behind (the clause, the fixture, the
> assertion, the measurement written into a rule comment or into the design of
> record), never on the run itself, which leaves no trace.
>
> **This plan is not current, and is kept as the record of what was intended.**
> Read the goal line above with care: it says eleven, the five tasks below
> enumerate **twelve**, and twelve shipped — the arithmetic in the spec was
> wrong, not the plan's contents. The pack now holds **eleven** for an unrelated
> reason: `null-safety-as-cast-deref` was deleted on 2026-08-21 after the pack's
> first real-code corpus scored it at 6490 findings on `dotnet/runtime` — against
> 402 for `empty-catch` — with no true positive in a 75-finding hand-read, and
> 67.6% of them not even about `as`, because Semgrep's C# frontend puts `o as T`
> and `(T)o` on the same node. §4b of
> [the design of record](../specs/2026-08-20-bugfix-rules-csharp-design.md)
> carries the measurement; the `AsCast.cs` fixtures went with the rule.
> `empty-catch` dropped from ERROR to WARNING against the same corpus (§4a),
> leaving `rethrow-loses-stacktrace` as the pack's only ERROR. And axis 3,
> recorded throughout this round as permanently `N/A`, is now opt-in via
> `GUARDIAN_CS_SRC` — wiring it up is what deleted the rule.

**Architecture:** One Semgrep YAML pack, discovered by the existing `resolveBugfixRules()` glob. A fixture tree of hits, misses and a real-bugs corpus. One integration test mirroring `bugfixRulesJava.test.ts`.

**Tech Stack:** Semgrep 1.164.0 (PowerShell only — it cannot be invoked through the Bash tool), TypeScript/vitest, Docker for `dotnet build`.

**Design of record:** [`docs/superpowers/specs/2026-08-20-bugfix-rules-csharp-design.md`](../specs/2026-08-20-bugfix-rules-csharp-design.md). Read it before Task 1; the probe measurements it records are not repeated here.

## Global Constraints

Every task's requirements implicitly include this section.

- **Always write `var` in a C# pattern.** `$T $V = …` matches only explicitly-typed declarations. Measured: `foreach ($T $X in $C)` found 0 of 5 real bugs; `foreach (var $X in $C)` found all five. This is the sixth silent-failure mode and the first that `paths.scanned` does **not** catch — the scan runs, the files are scanned, errors are zero, and the answer is 0.
- **Fail every hand-driven scan on `paths.scanned == 0`**, not on error strings. Two of the six silent-failure modes emit neither `RuleParseError` nor `Invalid YAML`.
- **`metavariable-regex` is anchored at the start.** `"Async$"` matches nothing; use `".*Async"`.
- **Every `pattern-either` branch must repeat the positive pattern.** A branch holding only a `metavariable-type` loads zero rules for the whole file.
- **No `Á` or `Í` in any comment.** Semgrep's config loader decodes with the locale codec; on cp1252 one uppercase accented letter kills the file with `results: 0, errors: 0`. Lowercase accents and `Ã À Â É Ê Ó Ô Õ Ú Ç` are all fine.
- Rule ids follow `bugfix-cs-<class-token>-<name>`. **Three words are hazardous:** `unchecked` (a C# keyword, matched by the `error_handling` regex), `concurren` (matches `ConcurrentDictionary`, and `race_condition` is tested first), and `disposed` (matches `memory_leak` before `error_handling` sees `exception`).
- Rule messages in Portuguese. Comments, docs, commits in English.
- No `!` non-null assertions, no `any` — both at zero across `mcp/src` and `mcp/test`.
- ESM `NodeNext`: every relative import ends in `.js`. `noUncheckedIndexedAccess` is on — narrow, never assert.
- `makeTempDir`/`cleanupTempDirs` from `test/helpers/tempDir.ts`; `okResult<T>()` from `test/helpers/toolResult.ts`.
- Semgrep binary: `C:\Users\Administrator\AppData\Roaming\Python\Python314\Scripts\semgrep.exe`, **PowerShell only**.
- `dotnet build` via `docker run --rm -v "<abs>:/w" -w //w mcr.microsoft.com/dotnet/sdk:8.0 dotnet build` (note `//w`).
- Rebuild `mcp/dist/` and stage it in the **same commit** as any `src/` change.

---

### Task 1: Harness, `configsDir`, and the two `error_handling` rules

**Files:**

- Create: `configs/semgrep/bugfix-cs.yml`
- Create: `mcp/test/fixtures/bugfix-cs/hits/{Rethrow,EmptyCatch}.cs`
- Create: `mcp/test/fixtures/bugfix-cs/misses/{Rethrow,EmptyCatch}.cs`
- Create: `mcp/test/integration/bugfixRulesCs.test.ts`
- Modify: `mcp/test/unit/platform/configsDir.test.ts`

**Interfaces:**

- Produces: `EXPECTED_HITS_BY_FILE`, `EXPECTED_SEVERITY`, `EXPECTED_CLASS` — later tasks extend all three.

- [x] **Step 1: Update `configsDir.test.ts` FIRST.** It pins the exact expected array of `bugfix-*.yml` files. Add `bugfix-cs.yml`. Run it and watch it fail before the file exists, then pass once it does. Doing this first is deliberate — it has bitten every round in this series.

- [x] **Step 2: Write the harness, mirroring `bugfixRulesJava.test.ts`.** It must assert, per fixture file: the exact rule-id set, the **raw non-deduplicated** finding count, and `paths.scanned`. Plus `EXPECTED_SEVERITY` exhaustive in both directions, `EXPECTED_CLASS` against the built `mapSubcategory`, and the count of distinct rule ids seen across `hits/` equal to the number of `- id:` entries in the YAML. Skips when Semgrep is absent; `GUARDIAN_REQUIRE_SEMGREP=1` makes absence a hard failure.

- [x] **Step 3: Write the fixtures, correct code first.** For each rule write the *correct* C# that most resembles the bug before the code that fires. `misses/Rethrow.cs` needs: `throw;`, `throw new AppEx(m, ex)`, `throw ae.Flatten()`, `throw Wrap(ex)`, and `throw pending;` where `pending` was captured and thrown outside the catch. `misses/EmptyCatch.cs` needs the `ignore`/`ignored`/`expected` names, `catch … when (…) { Log(ex); }`, and `try/finally` with no catch.

- [x] **Step 4: Run the test. Expected: FAIL** — no rule file.

- [x] **Step 5: Write the two rules.**

> **Tier superseded (2026-08-20).** `empty-catch` ships at WARNING, not ERROR:
> 402 findings on `dotnet/runtime`, overwhelmingly deliberate — design of record
> §4a. `rethrow-loses-stacktrace` is unchanged at ERROR and is now the pack's
> only one. The shipped `empty-catch` also has six branches rather than the
> three below: `try/catch` and `try/catch/finally` are disjoint nodes.

```yaml
  - id: bugfix-cs-error-handling-rethrow-loses-stacktrace
    patterns:
      - pattern: throw $V;
      - pattern-inside: try { ... } catch ($E $V) { ... }
    severity: ERROR
    languages: [csharp]

  - id: bugfix-cs-error-handling-empty-catch
    pattern-either:
      - patterns:
          - pattern: try { ... } catch ($E $V) { }
          - metavariable-regex:
              metavariable: $V
              regex: ^(?!(ignore|ignored|expected)$)
      - pattern: try { ... } catch ($E) { }
      - pattern: try { ... } catch { }
    severity: ERROR
    languages: [csharp]
```

  Note the three branches: C# has two spellings Java does not, and a single-branch port loses both. `try { ... } catch (...) { }` does not parse — there is no "any catch" wildcard.

- [x] **Step 6: GREEN**, with `GUARDIAN_REQUIRE_SEMGREP=1`.

- [x] **Step 7: Compile every fixture.** `dotnet build` must report `0 Error(s)`.

- [x] **Step 8: The independent oracle.** Confirm `dotnet build` emits `CA2200` at exactly the sites `rethrow-loses-stacktrace` fires on and nowhere else. Report any divergence — it means one of the two is wrong, and it is worth knowing which.

- [x] **Step 9: Ablate each clause alone**, on both axes: live, and does not reduce the hits count. Report one row per clause.

- [x] **Step 10: Commit** with a `feat(bugfix-rules):` subject.

---

### Task 2: The four `race_condition` rules

**Files:**

- Modify: `configs/semgrep/bugfix-cs.yml`
- Create: `mcp/test/fixtures/bugfix-cs/{hits,misses}/{AsyncVoid,BlockingOnTask,StaticRandom,LockShared}.cs`
- Modify: `mcp/test/integration/bugfixRulesCs.test.ts`

- [x] **Step 1: Write the near-misses first.** These four carry the round's sharpest false positives, all measured in the probe: two event handlers for `async-void` including one with a *derived* `ElapsedArgs`; for `blocking-on-task`, a POCO with a `bool Result` property, `Regex.Match.Result(string)` (a real BCL method), `SemaphoreSlim.Wait()` and `CountdownEvent.Wait()`; for `static-random`, `Random.Shared` and an instance `readonly Random`; for `lock-on-shared-instance`, a lock on a private `object` field.

- [x] **Step 2: RED.**

- [x] **Step 3: Write the rules.** `blocking-on-task` ships **only** in its four-branch form: `metavariable-type: Task` kills the four false positives *and* kills `GetAsync().Result`, so the recovery branch is `$F(...).Result` with `metavariable-regex: ".*Async"` — which also covers the dotted `_svc.LoadAsync(1).Result`, since `$F` binds the whole dotted name. `async-void` needs exactly one `pattern-not` on the `(object, EventArgs)` shape.

- [x] **Step 4: GREEN**, `dotnet build` clean, ablate both axes.

- [x] **Step 5: Record the two measured false negatives** in the rule comment: `var t = GetAsync(); t.Result` (`metavariable-type: Task` does not resolve through `var` plus a *call* initialiser, though it does through `var` plus a `new`), and `Task.Run(() => 1).Result`, which needs its own literal branch.

- [x] **Step 6: Commit.**

---

### Task 3: `off_by_one` (2 rules) and `memory_leak` (1 rule)

**Files:**

- Modify: `configs/semgrep/bugfix-cs.yml`
- Create: `mcp/test/fixtures/bugfix-cs/{hits,misses}/{LoopLte,HttpClient}.cs`
- Modify: `mcp/test/integration/bugfixRulesCs.test.ts`

- [x] **Step 1: Near-misses first.** `LoopLte` misses must include a domain object with an `int Length` field and one with an `int Count` — untyped, the rules fire on both, which is the exact Java defect reproduced. `HttpClient` misses: `static readonly HttpClient Shared` and `factory.CreateClient(…)`.

- [x] **Step 2: RED.**

- [x] **Step 3: Write the rules.** `metavariable-type` with `"$T[]"`, `string` and `List` closes the `Length`/`Count` false positives. For `httpclient-per-call`, use `pattern-not-inside: static $T $F = new HttpClient(...)` rather than `pattern-inside: $R $M(...) { ... }` — measured, the latter silently excludes constructors, so `_f = new HttpClient()` in a ctor escapes it.

- [x] **Step 4: Keep Java's sentinel false positive and say so.** A loop filling `new int[a.Length + 1]` still fires. Java measured the obvious tightening (requiring the body to index the same array) and rejected it because it traded a false positive for a false negative. Carry that measurement forward in the comment; do **not** re-run the experiment.

- [x] **Step 5: GREEN**, `dotnet build`, ablate both axes, commit.

---

### Task 4: `null_safety` (2 rules) and `edge_case` (1 rule)

These three need the largest exclusion lists in the pack. Budget accordingly.

**Files:**

- Modify: `configs/semgrep/bugfix-cs.yml`
- Create: `mcp/test/fixtures/bugfix-cs/{hits,misses}/{AsCast,OrDefault,ModifyDuringIteration}.cs`
- Modify: `mcp/test/integration/bugfixRulesCs.test.ts`

- [x] **Step 1: Near-misses first, and expect to need many.** `as-cast-deref`'s positive pattern is `$V.$M`, so every later use of `$V` in scope is a candidate; Java's equivalent needed twenty-six exclusions. Cover at minimum: `if (v != null) { … }`, the early-exit `return` and `throw` forms, `v?.M`, `o is string s`, and `o as string ?? "d"`.

> **Superseded with its rule.** The exclusions and their near-misses were
> written as specified, and `as-cast-deref` shipped. It was **deleted** on
> 2026-08-21 against the pack's first axis-3 corpus — 6490 findings on
> `dotnet/runtime`, no true positive in 75 read, and 67.6% of them not about
> `as` at all, because Semgrep's C# frontend puts `o as T` and `(T)o` on the
> same node. Design of record §4b. The `AsCast.cs` fixtures went with it.

- [x] **Step 2: For `modify-during-iteration`, port Java's full `switch`-inside-`foreach` machinery.** Measured in the probe: adding the two exit exclusions closes the two false positives **and swallows a real bug** — a `Remove` inside a `switch` arm followed by `break`, where the `break` leaves the switch rather than the loop. This is Java's wave-4 unsoundness reproduced verbatim, and it must be fixed here rather than rediscovered.

- [x] **Step 3: Drop the `Dictionary.Keys` branch.** Removing from a `Dictionary` during enumeration has been documented safe since .NET Core 3.0, so that branch would fire on correct code.

- [x] **Step 4: RED, write, GREEN**, `dotnet build`, ablate both axes.

- [x] **Step 5: State `ordefault-deref`'s unfixable class in the comment.** On a sequence of *value* types `FirstOrDefault()` returns `default(T)`, never null — so `List<int>.FirstOrDefault().ToString()` is correct code. The member deny-list that closes that instance silently misses `List<Cust>.FirstOrDefault().ToString()`, a real NRE, and does not close `List<DateTime>.FirstOrDefault().Year`. Generic-argument inference is not available. State both directions.

- [x] **Step 6: Commit.**

---

### Task 5: The real-bugs corpus, the no-duplication proof, and the prescribed-fix check

**Files:**

- Create: `mcp/test/fixtures/bugfix-cs/hits/RealBugs.cs`
- Create: `mcp/test/fixtures/bugfix-cs/control/Control.cs`
- Modify: `mcp/test/integration/bugfixRulesCs.test.ts`

- [x] **Step 1: Write a real-bugs corpus with at least one entry per rule.** It exists to give the ablation its second axis — a clause must be live *and* must not eat a real bug. Java left three rules at zero corpus coverage and it was the riskiest gap in that pack. Every rule gets an entry here.

- [x] **Step 2: The no-duplication proof, with a positive control that is asserted to have run.** Scan the hit fixtures with `p/r2c-bug-scan`, `p/csharp` and `p/security-audit` alone and assert zero. **`p/r2c-bug-scan` reports `paths.scanned = 0` on C# because it ships no C# rules at all** — so for that pack the control is the only thing distinguishing "additive" from "never ran". A Go-round defect was a control directory nothing enumerated, deleted silently, leaving the test skipping while the suite stayed green.

- [x] **Step 3: The prescribed-fix check.** For each of the eleven rules, write the fix its own message prescribes against the exact code it fired on, and confirm the rule goes silent. Three rules across four packs failed this: Java's `map-get-deref` advised `getOrDefault` on a `List`, JS's `floating-mutation` said "make it explicit with `void`" and `void repo.save(a)` still fired, Python's `none-deref-dict-get` advised a default parameter Django's `Manager.get` does not have. Report per rule.

> **Done per rule, and later superseded by a stronger check.** The per-rule
> pass is recorded in the design of record §9 and in the rule comments (the
> `catch (FormatException ignored)` fix that emits CS0168 is called out in the
> harness). It is not pinned by a committed fixture: the whole-pack `fixed/`
> scan that pins it — and that killed a candidate every per-rule check had
> passed — arrived in the PHP round, Task 4 Step 2.

- [x] **Step 4: Full ablation over the finished pack**, both axes, one row per clause. Freeze the file and print its hash; identify clauses by body text, not line number — a previous run was discarded because someone edited a comment mid-run and every line shifted.

- [x] **Step 5: Docs.** README (EN/PT/ES), `skills/guardian-bugfix/SKILL.md`, `mcp/src/tools/bugHunt.ts`, `CHANGELOG.md`. Rule counts become 13 JS/TS, 10 Python, 9 Go, 8 Java, **11 C#**. Every stated limitation real, every real limitation stated — including that the registry has no C# bug rules at all, that `memory_leak` is carried by one rule because the `IDisposable` rule is not expressible, and that `rethrow-loses-stacktrace` duplicates a compiler warning rather than a registry rule.

> **Two of those counts have moved.** Java is **7**, not 8
> (`map-get-deref` deleted), and C# is **11**, not the 12 that actually
> shipped under this plan (`as-cast-deref` deleted). `bug_hunt`'s own
> description still says "eight rules" for Java — the one place the Java
> deletion did not reach.

- [x] **Step 6: `cd mcp && npm run build`, `npm run lint`, full `npm test`** with `GUARDIAN_REQUIRE_SEMGREP=1`. Stage `mcp/dist/`; `git status --porcelain` empty. Markdownlint clean for `skills/`, `commands/`, `README.md`.

- [x] **Step 7: Commit.**
