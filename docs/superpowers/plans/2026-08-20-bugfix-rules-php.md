# PHP bug-finding rule pack — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `configs/semgrep/bugfix-php.yml` — six measured PHP bug-finding rules — with a harness that carries every check this series has paid for.

**Architecture:** One Semgrep YAML pack, discovered by the existing `resolveBugfixRules()` glob. A fixture tree of hits, misses, a real-bugs corpus and a prescribed-fix file. One integration test mirroring `bugfixRulesCs.test.ts`.

**Tech Stack:** Semgrep 1.164.0 (PowerShell only), TypeScript/vitest, Docker for `php -l`.

**Design of record:** [`docs/superpowers/specs/2026-08-20-bugfix-rules-php-design.md`](../specs/2026-08-20-bugfix-rules-php-design.md). Read it before Task 1; the probe's measurements are there and are not repeated here.

## Global Constraints

Every task's requirements implicitly include this section.

- **Never write a fully-qualified type name in a PHP pattern.** `catch (\RuntimeException $E)` found **zero** occurrences of source reading `catch (\RuntimeException $e)`. Bind the type to a metavariable. Every gate stays green, `paths.scanned` is healthy, `errors: 0`, and the answer is nothing — this is the PHP twin of C#'s `$T`/`var` trap.
- **`?->` and `->` are the same AST node.** A `pattern-not: $V?->$M` deletes the rule instead of excluding the safe idiom. The only escape is `pattern-not-regex: '\?->'`.
- **A `metavariable-regex` on the catch variable is load-bearing beyond filtering.** Without it, `catch ($E $V)` *crashes the Semgrep matcher* on any file containing a PHP 8 non-capturing `catch (T) { }` — `Internal matching error … NoTokenLocation`, exit 2, with matches elsewhere in the file surviving so it reads as partial success. Do not remove it as "redundant".
- **Prefer the statement ellipsis to a braced body.** `for (...) ...` matches the braced body, the brace-less body *and* the `for(): … endfor;` alternative syntax. `for (...) { ... }` matches only the first. Free recall, no measured cost.
- **The deep-expression operator does not parse inside a PHP block.** Use `{ ... stmt; ... }`.
- **Fail every hand-driven scan on `paths.scanned == 0`.** Nine silent-failure modes are recorded; several emit no error at all. Note two PHP-specific routes to it: an unquoted ternary (` : ` parses as a mapping) and `\R` in a double-quoted YAML scalar. And one environmental route: **a long Windows path** gives `Failed to obtain target files from semgrep-core` with `paths.scanned = 0` and a message pointing nowhere near the cause. Keep the corpus path short.
- Rule ids follow `bugfix-php-<class-token>-<name>`. Hazardous words: `unchecked` → `error_handling`, `concurren` → `race_condition`, and **`dangling` → `memory_leak`** — which matters because "dangling reference" is the PHP manual's own term for a rule killed in the probe. Check ids against the **built** classifier in `dist/`.
- Rule messages in Portuguese. Comments, docs, commits in English. **No `Á` or `Í` in any comment** — the locale codec kills the file with `results: 0, errors: 0`.
- No `!` non-null assertions, no `any` — both at zero across `mcp/src` and `mcp/test`.
- ESM `NodeNext`: relative imports end in `.js`. `noUncheckedIndexedAccess` is on — narrow, never assert.
- `makeTempDir`/`cleanupTempDirs` from `test/helpers/tempDir.ts`.
- Semgrep at `C:\Users\Administrator\AppData\Roaming\Python\Python314\Scripts\semgrep.exe`, **PowerShell only**. Set `SEMGREP_SETTINGS_FILE` to your own path — concurrent runs race over the shared one and die with `PermissionError`, which reads as a broken pack.
- `php -l` via `docker run --rm -v "<abs>:/w" -w //w php:8.3-cli php -l <file>` (note `//w`).
- Rebuild `mcp/dist/` and stage it in the **same commit** as any `src/` change.

---

### Task 1: Harness, `configsDir`, and the two strongest rules

Start with `off-by-one-loop-lte-count` and `race-condition-toctou-file` — the two cleanest in the pack (6/6 and 4/4, one known inherited false positive between them).

**Files:**

- Create: `configs/semgrep/bugfix-php.yml`
- Create: `mcp/test/fixtures/bugfix-php/hits/{off_by_one,toctou}.php`
- Create: `mcp/test/fixtures/bugfix-php/misses/{off_by_one,toctou}.php`
- Create: `mcp/test/integration/bugfixRulesPhp.test.ts`
- Modify: `mcp/test/unit/platform/configsDir.test.ts`

- [ ] **Step 1: Update `configsDir.test.ts` FIRST**, and watch it fail before the YAML exists. It pins the exact expected array, and forgetting it has bitten every round in this series.

- [ ] **Step 2: Write the harness**, mirroring `bugfixRulesCs.test.ts`: exact rule-id set, raw non-deduplicated count and `paths.scanned` per fixture file; `EXPECTED_SEVERITY` exhaustive in both directions; ids checked against the built `mapSubcategory`; distinct rule ids across `hits/` equal to the number of `- id:` entries. Skips when Semgrep is absent, hard-fails under `GUARDIAN_REQUIRE_SEMGREP=1`.

- [ ] **Step 3: Near-misses first.** For `off-by-one`, the miss file must contain a class with **both** a `->length` property and a `->count()` method inside `<=` loops. The probe measured the rule silent on both, and that is the round's one free win: `count()` is a global function in PHP, so the domain-object false positive that forced `metavariable-type` enumeration in Java and C# cannot arise. **Do not add a type list.** For `toctou`, the miss file carries the atomic idioms — `@mkdir(...) === false && !is_dir()`, `fopen($f,'xb')`, `@unlink` with the return inspected, and `file_exists` used for a *report* rather than as a guard.

- [ ] **Step 4: RED.**

- [ ] **Step 5: Write the two rules.** `off-by-one` spans {`count`, `sizeof`, `strlen`, `mb_strlen`} × {`$i++`, `++$i`}, plus a hoisted branch anchored on `$n = count($a);`. `toctou` needs four sibling shapes: `file_exists`→`unlink`, `!is_dir`→`mkdir`, `!file_exists`→`file_put_contents`, `is_writable`→`fopen`.

- [ ] **Step 6: GREEN**, `php -l` clean on every fixture, ablate with `npm run ablate -- bugfix-php`.

- [ ] **Step 7: Keep the sentinel false positive and say so.** `array_fill(0, count($xs)+1, 0)` still fires. Java measured the obvious tightening and rejected it because it traded a false positive for a false negative; carry that forward in the comment rather than re-running it.

- [ ] **Step 8: Commit**, `feat(bugfix-rules):`.

---

### Task 2: `empty-catch` and `strpos-truthiness`

**Files:**

- Modify: `configs/semgrep/bugfix-php.yml`, `mcp/test/integration/bugfixRulesPhp.test.ts`
- Create: `mcp/test/fixtures/bugfix-php/{hits,misses}/{empty_catch,strpos}.php`

- [ ] **Step 1: The try shape is a dimension, not a detail.** `try{}catch(){}` and `try{}catch(){}finally{}` are **disjoint** nodes in PHP exactly as in C# — neither contains the other, so enumerate both rather than widening one. This hole shipped in Java and cost a separate fix round; do not reproduce it.

- [ ] **Step 2: Near-misses first.** For `strpos`, the miss file must contain `str_contains()`, `str_starts_with()` and `preg_match()` in boolean positions — the probe measured 3 false positives without the function-name filter, so the filter is load-bearing and the fixture must prove it. For `empty-catch`, include the `$ignored` naming exemption **both with and without `finally`**.

- [ ] **Step 3: RED, write, GREEN.**

- [ ] **Step 4: Record the two measured limits in the rule comments.** `empty-catch` reaches 6 of 8 spellings; the PHP 8 non-capturing `catch (\Foo) { }` is **unmatchable by any AST pattern** and is therefore invisible — which matters because that is the spelling modern PHP uses to declare deliberate silence. `strpos-truthiness` reaches 7 of 8; the store-then-test form (`$at = strpos(...); if ($at)`) is not covered.

- [ ] **Step 5: Both are WARNING.** The design's §3 explains why `empty-catch` does not clear the ERROR bar in PHP even though Java and C# ship it at ERROR. Do not change those two packs here — that question is being measured separately.

- [ ] **Step 6: Ablate, `php -l`, commit.**

---

### Task 3: The two `null_safety` rules

**Files:**

- Modify: `configs/semgrep/bugfix-php.yml`, `mcp/test/integration/bugfixRulesPhp.test.ts`
- Create: `mcp/test/fixtures/bugfix-php/{hits,misses}/{json_decode,loose_null}.php`

- [ ] **Step 1: `json-decode-deref` needs `isset`/`empty` exclusions to reach zero on real code.** Without them the probe measured 4 false positives on WordPress, all guarded by `isset($res->error)`. With them: 4 of 4 hits, 0 of 6 misses, 0 on 1467 files.

- [ ] **Step 2: The `pattern-not-regex: '\?->'` is the only thing that makes this rule possible.** `?->` and `->` are the same node, so the AST exclusion deletes the rule. Write a comment saying this is a *text* guard on an AST rule and why there is no alternative — `base.yml` documents `pattern-not-regex` as a hazard, and this is a deliberate exception, not an oversight.

- [ ] **Step 3: `loose-null-compare` is the weakest rule in the pack and its comment must say so.** WPCS's `WordPress.PHP.StrictComparisons` already covers it, so the additive claim holds only where phpcs+WPCS is absent or outside WordPress. Note `null` in a pattern is case-insensitive, so `NULL` and `Null` are covered.

- [ ] **Step 4: RED, write, GREEN, ablate, `php -l`, commit.**

---

### Task 4: The corpus, the proofs, and the new governing check

**Files:**

- Create: `mcp/test/fixtures/bugfix-php/hits/real_bugs.php`
- Create: `mcp/test/fixtures/bugfix-php/fixed/fixed.php`
- Create: `mcp/test/fixtures/bugfix-php/control/vulnerable.php`
- Modify: `mcp/test/integration/bugfixRulesPhp.test.ts`

- [ ] **Step 1: A real-bugs corpus with at least one entry per rule**, written beside the guard shape each rule's exclusions match. It exists to give the ablation its second axis.

- [ ] **Step 2: The whole-pack prescribed-fix check — this is the new governing rule and the reason Task 4 exists.** Write every hit rewritten with the fix its own message prescribes into `fixed/fixed.php`, then scan that file with **the entire pack** and assert **zero** findings. Per-rule checking is not enough: the `@`-suppression candidate passed every per-rule check and was killed only here, because `toctou`'s prescribed fix ("act first and inspect the return value") is idiomatically `@mkdir(...)`, so one rule fired on another rule's fix.

- [ ] **Step 3: The no-duplication proof, with a control asserted to have fired.** `p/r2c-bug-scan` reports `paths.scanned = 0` on PHP — it ships no PHP rules — so for that pack the control is the only thing separating "additive" from "never ran". `p/php` is live and PHP-aware (9 findings on 12 classic vulnerable shapes). **`p/security-audit` has no working positive control** in PHP or C#; assert only `paths.scanned > 0` for it and say why.

- [ ] **Step 4: Full ablation**, `npm run ablate -- bugfix-php`, including the new axis 0 (does each rule fire on `hits/` at all). Register the pack in `mcp/test/ablate/packs.ts`. Axis 3 needs a real PHP corpus — WordPress core is what the probe used; wire it if it is obtainable at a short path, or register axis 3 as an explicit `N/A` and say so. Never silently omit it.

- [ ] **Step 5: Docs.** README (EN/PT/ES), `skills/guardian-bugfix/SKILL.md`, `mcp/src/tools/bugHunt.ts`, `CHANGELOG.md`. Counts become 13 JS/TS, 10 Python, 9 Go, 8 Java, 12 C#, **6 PHP**. **State that `memory_leak` is an empty class in this pack** — `fopen`/`curl` tracking needs escape analysis Semgrep OSS lacks, and the probe measured both ends of the dial: with escape exclusions the rule finds *nothing*, without them it fires on correct code.

- [ ] **Step 6: `npm run build`, `npm run lint`, full `npm test`** with `GUARDIAN_REQUIRE_SEMGREP=1`. Stage `mcp/dist/`. `git status --porcelain` empty. Markdownlint clean.

- [ ] **Step 7: Commit.**
