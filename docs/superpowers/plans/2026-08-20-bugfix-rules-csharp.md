# C# bug-finding rule pack — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `configs/semgrep/bugfix-cs.yml` — eleven measured C# bug-finding rules — with a test harness that would catch every defect class this series has shipped.

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

- [ ] **Step 1: Update `configsDir.test.ts` FIRST.** It pins the exact expected array of `bugfix-*.yml` files. Add `bugfix-cs.yml`. Run it and watch it fail before the file exists, then pass once it does. Doing this first is deliberate — it has bitten every round in this series.

- [ ] **Step 2: Write the harness, mirroring `bugfixRulesJava.test.ts`.** It must assert, per fixture file: the exact rule-id set, the **raw non-deduplicated** finding count, and `paths.scanned`. Plus `EXPECTED_SEVERITY` exhaustive in both directions, `EXPECTED_CLASS` against the built `mapSubcategory`, and the count of distinct rule ids seen across `hits/` equal to the number of `- id:` entries in the YAML. Skips when Semgrep is absent; `GUARDIAN_REQUIRE_SEMGREP=1` makes absence a hard failure.

- [ ] **Step 3: Write the fixtures, correct code first.** For each rule write the *correct* C# that most resembles the bug before the code that fires. `misses/Rethrow.cs` needs: `throw;`, `throw new AppEx(m, ex)`, `throw ae.Flatten()`, `throw Wrap(ex)`, and `throw pending;` where `pending` was captured and thrown outside the catch. `misses/EmptyCatch.cs` needs the `ignore`/`ignored`/`expected` names, `catch … when (…) { Log(ex); }`, and `try/finally` with no catch.

- [ ] **Step 4: Run the test. Expected: FAIL** — no rule file.

- [ ] **Step 5: Write the two rules.**

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

- [ ] **Step 6: GREEN**, with `GUARDIAN_REQUIRE_SEMGREP=1`.

- [ ] **Step 7: Compile every fixture.** `dotnet build` must report `0 Error(s)`.

- [ ] **Step 8: The independent oracle.** Confirm `dotnet build` emits `CA2200` at exactly the sites `rethrow-loses-stacktrace` fires on and nowhere else. Report any divergence — it means one of the two is wrong, and it is worth knowing which.

- [ ] **Step 9: Ablate each clause alone**, on both axes: live, and does not reduce the hits count. Report one row per clause.

- [ ] **Step 10: Commit** with a `feat(bugfix-rules):` subject.

---

### Task 2: The four `race_condition` rules

**Files:**

- Modify: `configs/semgrep/bugfix-cs.yml`
- Create: `mcp/test/fixtures/bugfix-cs/{hits,misses}/{AsyncVoid,BlockingOnTask,StaticRandom,LockShared}.cs`
- Modify: `mcp/test/integration/bugfixRulesCs.test.ts`

- [ ] **Step 1: Write the near-misses first.** These four carry the round's sharpest false positives, all measured in the probe: two event handlers for `async-void` including one with a *derived* `ElapsedArgs`; for `blocking-on-task`, a POCO with a `bool Result` property, `Regex.Match.Result(string)` (a real BCL method), `SemaphoreSlim.Wait()` and `CountdownEvent.Wait()`; for `static-random`, `Random.Shared` and an instance `readonly Random`; for `lock-on-shared-instance`, a lock on a private `object` field.

- [ ] **Step 2: RED.**

- [ ] **Step 3: Write the rules.** `blocking-on-task` ships **only** in its four-branch form: `metavariable-type: Task` kills the four false positives *and* kills `GetAsync().Result`, so the recovery branch is `$F(...).Result` with `metavariable-regex: ".*Async"` — which also covers the dotted `_svc.LoadAsync(1).Result`, since `$F` binds the whole dotted name. `async-void` needs exactly one `pattern-not` on the `(object, EventArgs)` shape.

- [ ] **Step 4: GREEN**, `dotnet build` clean, ablate both axes.

- [ ] **Step 5: Record the two measured false negatives** in the rule comment: `var t = GetAsync(); t.Result` (`metavariable-type: Task` does not resolve through `var` plus a *call* initialiser, though it does through `var` plus a `new`), and `Task.Run(() => 1).Result`, which needs its own literal branch.

- [ ] **Step 6: Commit.**

---

### Task 3: `off_by_one` (2 rules) and `memory_leak` (1 rule)

**Files:**

- Modify: `configs/semgrep/bugfix-cs.yml`
- Create: `mcp/test/fixtures/bugfix-cs/{hits,misses}/{LoopLte,HttpClient}.cs`
- Modify: `mcp/test/integration/bugfixRulesCs.test.ts`

- [ ] **Step 1: Near-misses first.** `LoopLte` misses must include a domain object with an `int Length` field and one with an `int Count` — untyped, the rules fire on both, which is the exact Java defect reproduced. `HttpClient` misses: `static readonly HttpClient Shared` and `factory.CreateClient(…)`.

- [ ] **Step 2: RED.**

- [ ] **Step 3: Write the rules.** `metavariable-type` with `"$T[]"`, `string` and `List` closes the `Length`/`Count` false positives. For `httpclient-per-call`, use `pattern-not-inside: static $T $F = new HttpClient(...)` rather than `pattern-inside: $R $M(...) { ... }` — measured, the latter silently excludes constructors, so `_f = new HttpClient()` in a ctor escapes it.

- [ ] **Step 4: Keep Java's sentinel false positive and say so.** A loop filling `new int[a.Length + 1]` still fires. Java measured the obvious tightening (requiring the body to index the same array) and rejected it because it traded a false positive for a false negative. Carry that measurement forward in the comment; do **not** re-run the experiment.

- [ ] **Step 5: GREEN**, `dotnet build`, ablate both axes, commit.

---

### Task 4: `null_safety` (2 rules) and `edge_case` (1 rule)

These three need the largest exclusion lists in the pack. Budget accordingly.

**Files:**

- Modify: `configs/semgrep/bugfix-cs.yml`
- Create: `mcp/test/fixtures/bugfix-cs/{hits,misses}/{AsCast,OrDefault,ModifyDuringIteration}.cs`
- Modify: `mcp/test/integration/bugfixRulesCs.test.ts`

- [ ] **Step 1: Near-misses first, and expect to need many.** `as-cast-deref`'s positive pattern is `$V.$M`, so every later use of `$V` in scope is a candidate; Java's equivalent needed twenty-six exclusions. Cover at minimum: `if (v != null) { … }`, the early-exit `return` and `throw` forms, `v?.M`, `o is string s`, and `o as string ?? "d"`.

- [ ] **Step 2: For `modify-during-iteration`, port Java's full `switch`-inside-`foreach` machinery.** Measured in the probe: adding the two exit exclusions closes the two false positives **and swallows a real bug** — a `Remove` inside a `switch` arm followed by `break`, where the `break` leaves the switch rather than the loop. This is Java's wave-4 unsoundness reproduced verbatim, and it must be fixed here rather than rediscovered.

- [ ] **Step 3: Drop the `Dictionary.Keys` branch.** Removing from a `Dictionary` during enumeration has been documented safe since .NET Core 3.0, so that branch would fire on correct code.

- [ ] **Step 4: RED, write, GREEN**, `dotnet build`, ablate both axes.

- [ ] **Step 5: State `ordefault-deref`'s unfixable class in the comment.** On a sequence of *value* types `FirstOrDefault()` returns `default(T)`, never null — so `List<int>.FirstOrDefault().ToString()` is correct code. The member deny-list that closes that instance silently misses `List<Cust>.FirstOrDefault().ToString()`, a real NRE, and does not close `List<DateTime>.FirstOrDefault().Year`. Generic-argument inference is not available. State both directions.

- [ ] **Step 6: Commit.**

---

### Task 5: The real-bugs corpus, the no-duplication proof, and the prescribed-fix check

**Files:**

- Create: `mcp/test/fixtures/bugfix-cs/hits/RealBugs.cs`
- Create: `mcp/test/fixtures/bugfix-cs/control/Control.cs`
- Modify: `mcp/test/integration/bugfixRulesCs.test.ts`

- [ ] **Step 1: Write a real-bugs corpus with at least one entry per rule.** It exists to give the ablation its second axis — a clause must be live *and* must not eat a real bug. Java left three rules at zero corpus coverage and it was the riskiest gap in that pack. Every rule gets an entry here.

- [ ] **Step 2: The no-duplication proof, with a positive control that is asserted to have run.** Scan the hit fixtures with `p/r2c-bug-scan`, `p/csharp` and `p/security-audit` alone and assert zero. **`p/r2c-bug-scan` reports `paths.scanned = 0` on C# because it ships no C# rules at all** — so for that pack the control is the only thing distinguishing "additive" from "never ran". A Go-round defect was a control directory nothing enumerated, deleted silently, leaving the test skipping while the suite stayed green.

- [ ] **Step 3: The prescribed-fix check.** For each of the eleven rules, write the fix its own message prescribes against the exact code it fired on, and confirm the rule goes silent. Three rules across four packs failed this: Java's `map-get-deref` advised `getOrDefault` on a `List`, JS's `floating-mutation` said "make it explicit with `void`" and `void repo.save(a)` still fired, Python's `none-deref-dict-get` advised a default parameter Django's `Manager.get` does not have. Report per rule.

- [ ] **Step 4: Full ablation over the finished pack**, both axes, one row per clause. Freeze the file and print its hash; identify clauses by body text, not line number — a previous run was discarded because someone edited a comment mid-run and every line shifted.

- [ ] **Step 5: Docs.** README (EN/PT/ES), `skills/guardian-bugfix/SKILL.md`, `mcp/src/tools/bugHunt.ts`, `CHANGELOG.md`. Rule counts become 13 JS/TS, 10 Python, 9 Go, 8 Java, **11 C#**. Every stated limitation real, every real limitation stated — including that the registry has no C# bug rules at all, that `memory_leak` is carried by one rule because the `IDisposable` rule is not expressible, and that `rethrow-loses-stacktrace` duplicates a compiler warning rather than a registry rule.

- [ ] **Step 6: `cd mcp && npm run build`, `npm run lint`, full `npm test`** with `GUARDIAN_REQUIRE_SEMGREP=1`. Stage `mcp/dist/`; `git status --porcelain` empty. Markdownlint clean for `skills/`, `commands/`, `README.md`.

- [ ] **Step 7: Commit.**
