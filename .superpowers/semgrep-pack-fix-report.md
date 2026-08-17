# `bug_hunt`: retired-pack fix report

Branch `fix/semgrep-retired-pack`, base `4fe1d06`.

## What changed

### 1. Replaced the dead pack

`mcp/src/tools/bugHunt.ts` used `--config=p/bugs` + `--config=p/security-audit`.
`p/bugs` 404s (`https://semgrep.dev/c/p/bugs`, confirmed via `curl`) — retired from
Semgrep's registry with no warning to callers.

Replaced with **`p/r2c-bug-scan`** (confirmed live: `https://semgrep.dev/c/p/r2c-bug-scan`
returns 200). Updated everywhere the old name appeared: the `title`, the
`description`, the `--config=` argument (now built from a new exported
`BUG_HUNT_PACKS` constant), and the file's header comment (which still *mentions*
`p/bugs` once, deliberately, to explain why `p/r2c-bug-scan` replaced it).

**Verification, not just registry-name trust** — I did not take "the natural
successor" on faith:

- Fetched the pack's raw rule YAML (`curl https://semgrep.dev/c/p/r2c-bug-scan`):
  **44 rules total**, every one tagged `category: correctness` (not security —
  confirmed it isn't a rebrand of a security pack). Breakdown by rule-ID
  language prefix, counted programmatically (not by eye): 32 Python, 5 Go,
  4 Java, 3 JavaScript — no separately-prefixed TypeScript rules, but the 3
  JavaScript rules each declare `languages: [javascript, typescript]`, so
  they also run against `.ts` files rather than adding distinct coverage.
- Built a small fixture (`app.js`, `app.py`, `targeted.py`) covering `bug_hunt`'s
  own subcategory vocabulary (race_condition, null_safety, edge_case,
  off_by_one, memory_leak, error_handling) and ran real Semgrep 1.164.0 against
  it with `--config=p/r2c-bug-scan`.
  - First pass (generic bugs: unguarded `.find()`, empty catch, off-by-one loop
    bound, unsynchronized counter, unclosed file handle, bare `except:`): **0
    hits**. The pack did not recognise any of these as written.
  - Second pass, deliberately shaped to the pack's own rule IDs: a list mutated
    while iterating over it, and a subprocess call whose result is never
    checked. **2 hits**, both real:
    `python.lang.correctness.list-modify-iterating.list-modify-while-iterate`
    (an `edge_case` per `bugHunt.ts`'s own `mapSubcategory`) and
    `python.lang.correctness.unchecked-returns.unchecked-subprocess-call`
    (`error_handling`).
- **Honest assessment: the pack is real, is correctness-focused (matches
  `bug_hunt`'s purpose), but is thin and Python-heavy.** JS/TypeScript get only
  3 rules total (`useless-assignment`, `no-replaceall`, `eqeq-is-bad`) — none of
  which match the seven focus areas `commands/guardian-fix.md` names. A
  TypeScript-heavy project (like this repo) gets materially less from this pack
  than a Python one does.
- **Checked for something better and didn't find one.** Every other
  plausible-sounding pack I could find in the registry
  (`p/javascript`, `p/typescript`, `p/golang`, `p/trailofbits`) turned out to be
  100% (or ~97%) `category: security` when I fetched and inspected their raw
  YAML — i.e. duplicates of what `p/security-audit`/`scan_sast`'s `--config=auto`
  already cover, not bug/correctness packs. `p/r2c-bug-scan` is the only live
  pack in the registry that is actually correctness-tagged and multi-language. I
  did not find, and am not proposing, a second pack to pair with it — there
  isn't a better candidate to add today, only a documented gap for a future
  retirement to fill (which the fix below now degrades instead of breaking on).

### 2. The failure mode: a dead pack no longer takes the tool down

New module `mcp/src/tools/semgrepConfigFailure.ts` (pure, unit-tested,
no I/O):

- `findConfigDownloadFailures(raw)` — reads a Semgrep JSON report's `errors[]`
  for `"Failed to download configuration from <url>"` entries (structured JSON
  field access, not stderr pattern-matching) and recovers the failed
  `--config=` value from the registry URL. Verified against real 1.164.0 output
  captured with a deliberately nonexistent pack — both the single-failure and
  two-simultaneous-failures shapes (Semgrep emits one `errors[]` entry per dead
  config, plus one summary entry with no attributable URL, which is correctly
  *not* treated as its own failure).
- `survivingPacks(configured, failures)` — set difference.
- `describeConfigFailures(failures)` — human-readable `pack (message)` list for
  `tools_run[].reason`.

`bugHunt.ts`'s `invoke` now:

1. Runs Semgrep with all of `BUG_HUNT_PACKS`.
2. Reads `errors[]` from the JSON output (already parsed nearby via
   `readJsonSafe`) regardless of exit code.
3. If nothing failed to download: unchanged behaviour (`ok = outcome ===
   'completed' || exitCode === 1`).
4. If something failed and at least one (but not all) configured packs
   survive: **re-runs Semgrep with only the surviving packs** (confirmed
   empirically: a single dead `--config=` aborts the *whole* Semgrep
   invocation — `results` and `paths.scanned` come back empty even for the
   pack that is still valid — so the first attempt's output can't be reused).
   The retry's own `errors[]` gets the same scrutiny (not just its exit code),
   so a survivor that itself fails mid-retry (registry outage) is still caught.
5. Reports the gap: `missing_tools` gets `semgrep:<pack>` for every pack that
   didn't resolve, and the `semgrep` `tools_run` entry's `reason` names which
   pack and why (the exact "Failed to download configuration from ... HTTP
   404." text). This trips `scanCoverage.ts`'s existing `assessCoverage` into
   `'partial'` (some results, but incomplete) or `'none'` (nothing usable),
   with its loud "0 findings is NOT a clean bill of health" warning — no new
   coverage mechanism needed, the fix just feeds the existing one honestly.
6. Never trusts exit code/outcome alone to mean "clean": the `errors[]` check
   runs unconditionally, so a hypothetical future Semgrep that exits 0 with an
   empty result when a config fails would still be caught (see test 5 in
   `qualityTools.test.ts`'s `bug_hunt` block, described below).

## Tests (TDD, with mutation verification)

New: `mcp/test/unit/tools/semgrepConfigFailure.test.ts` (13 tests, pure
functions, real captured JSON shapes, zero network/process dependency).

Extended `mcp/test/integration/qualityTools.test.ts`'s `bug_hunt` describe
block (mocks `runProcess`/`scannerAvailable`, zero network dependency) from 1
test to 5:

1. Happy path — both packs resolve (updated for the new pack names; asserts
   `coverage: 'full'` as the control case).
2. One config 404s → retries with the survivor → still reports the
   survivor's real findings, `coverage: 'partial'`, gap named in
   `missing_tools` and `warnings`.
3. The retry's own pack also fails (simulated registry outage) → both
   failures reported, not just the first one caught.
4. **Every configured pack fails → zero findings, `coverage: 'none'`,
   `missing_tools` non-empty, warning matches "not a clean bill of health".**
   This is the primary regression case from the brief.
5. Same as (4) but with `outcome: 'completed', exitCode: 0` (the "future
   Semgrep exits clean" adversarial case) — same assertions. This is the one
   that specifically closes the exitCode-trust gap.

All pack names in these tests come from `bugHunt.ts`'s own exported
`BUG_HUNT_PACKS`, not hardcoded literals — the tests pin *unavailable config*
behaviour generically, not `p/bugs` specifically.

**Mutation verification performed (not just asserted):**

- Reverted `findConfigDownloadFailures(raw)` to always return `[]`
  (simulating "pre-fix code that never inspected `errors[]`") → tests 2, 4
  and 5 went RED (retry never attempted / gap unattributed / clean exit code
  silently trusted → `coverage: 'full'` instead of `'none'`). Reverted, back
  to green.
- Inverted `survivingPacks`' filter (`!failedNames.has(p)` →
  `failedNames.has(p)`) → all 4 `survivingPacks` unit tests went RED. Reverted,
  back to green.
- Dropped `retryFailures.length === 0` from `retryOk` (trusting the retry's
  exit code alone) → my first version of test 3 did NOT catch this (it used a
  nonzero exit code for the retry, which the old exit-code check also flags).
  Sharpened the test to use a *clean* exit code for the failing retry
  (mirroring test 5's shape) → then correctly went RED
  (`coverage: 'partial'` instead of `'none'`). Reverted, back to green.

Final state: 21/21 new tests green (13 unit + 8 integration, including the two
pre-existing `quality_check`/`review_pr` tests in the same file, unaffected).

## Self-review

1. **Can `bug_hunt` still report zero findings when nothing was scanned?**
   Traced every return path in `invoke`: the "no semgrep" early return marks
   `missing_tools: ['semgrep']`; the normal path is unchanged (`errors[]`
   empty, so exit code is trustworthy there); the retry-succeeds path returns
   real findings from the survivor with the gap explicitly named; both
   failure branches (`reportGap`) run whenever `errors[]` shows a download
   failure and return zero findings with `missing_tools` populated and
   `tools_run` status `'failed'`, regardless of what exit code Semgrep
   reported. `assessCoverage` (unmodified, existing code) turns that into
   `coverage: 'none'` or `'partial'` and a warning every caller already reads.
   There is no path left where `errors[]` names a download failure and the
   result still claims `coverage: 'full'`.
2. **Does the replacement pack actually find the class of thing `bug_hunt`
   exists for?** Yes, with real examples caught against my fixture:
   `list-modify-while-iterate` (mutating a list while iterating it — an
   `edge_case`) and `unchecked-subprocess-call` (a subprocess result never
   checked — `error_handling`). Caveat, stated above and in the source
   comment: it is Python-heavy and thin for JS/TS (3 rules, none matching the
   seven focus areas) — I did not find a better live alternative to close
   that gap.
3. **Does anything in this change require network access at test time?** No.
   `semgrepConfigFailure.test.ts` uses literal JSON strings captured earlier
   from a real run, not a live call. `qualityTools.test.ts` mocks
   `runProcess` and `scannerAvailable` entirely — no process is spawned, no
   network touched. I deliberately did **not** add a new e2e fixture that
   calls the real `semgrep.dev` registry (unlike `rulePackFixture.test.ts` /
   `evalVulnFixture.test.ts`, which depend only on the semgrep *binary*, not
   the registry) — the brief was explicit that tests "must not require the
   Semgrep registry to be reachable," and unlike local-binary absence, a
   registry-reachability check has no existing `GUARDIAN_REQUIRE_SEMGREP`-style
   opt-in-hard-failure precedent in this repo to fall back on. The pack's
   real-world content was verified manually (commands captured above) instead
   of pinned as an automated, network-dependent regression test. If
   `p/r2c-bug-scan` is retired in the future, the fix in this branch means
   that shows up as a reported coverage gap, not a silent clean scan — so a
   human/agent revisiting the pack choice will have real signal to act on,
   the same way this task's investigation did for `p/bugs`.

## Verification run

- `npm run typecheck` — clean, no errors.
- `npm run build` — clean; `mcp/dist/` rebuilt and staged in the same commit.
  `mcp/dist/server.js`/`bugHunt.js` no longer contain `p/bugs` as a
  `--config=` value (only the header comment's historical mention survives,
  as intended); new `mcp/dist/tools/semgrepConfigFailure.js` present.
- `GUARDIAN_REQUIRE_SEMGREP=1 npm test` (full suite): **1402/1410 passed, 8
  failed across 3 files, 108/111 files fully green.** All real semgrep-registry
  e2e tests passed (`rulePackFixture`, `evalVulnFixture`,
  `validateFindingFixture`), confirming the registry is reachable from this
  machine and nothing about the pack swap disturbed the surface/eval tooling
  that also runs real Semgrep.
  - `test/e2e/ciCliFixture.test.ts` (1 failure) — the pre-documented exception:
    needs the Docker daemon, which is down on this machine.
  - `test/integration/createFixPr.test.ts` (5 failures) and
    `test/unit/ci/appRunner.test.ts` (2 failures) — **not pre-documented, so I
    verified rather than assumed.** Both files are unrelated to `bug_hunt` in
    every way that matters: neither imports `bugHunt.ts` or
    `semgrepConfigFailure.ts` (confirmed via `git status` — the changed-file
    sets are disjoint), and neither touches Semgrep/rule-pack code at all
    (`create_fix_pr` is git-worktree/PR machinery; `appRunner` is DAST-target
    process spawning). The failures themselves are textbook Windows
    concurrency symptoms: `EPERM, Permission denied` on `rmSync` cleanup of a
    temp git repo (a held file handle racing a synchronous `afterEach`), and
    two hard-coded timing thresholds (`expected 3338 to be less than 2500`,
    a 10000ms timeout) — both while running as 2 of ~111 files' worth of
    concurrent workers, alongside my own `npm run build` running at the same
    moment. Re-ran both files **in isolation** (nothing else concurrent):
    `createFixPr.test.ts` → **18/18 pass** (241s — genuinely slow due to real
    git operations, not hung); `appRunner.test.ts` → **11/11 pass** (22s vs.
    the 10s+ timeout it hit under load). Confirms both were contention flakes,
    not regressions.
- Re-ran the four files that actually reference `bug_hunt`/the new module in
  a final, isolated pass: `qualityTools.test.ts`, `semgrepConfigFailure.test.ts`,
  `toolSurface.test.ts`, `toolchainTools.test.ts` → **30/30 pass.**

## Concerns to flag

- `p/r2c-bug-scan`'s thinness for JS/TypeScript (see above) is a real,
  pre-existing gap in bug-finding coverage for this repo's own dominant
  language and likely a meaningful share of users' projects. It is not a
  regression from this fix (the old `p/bugs` pack is not inspectable now that
  it's 404ing, so I can't compare its historical content directly) but it is
  worth a follow-up: either a second, more JS/TS-focused correctness pack if
  one appears in the registry later, or a small set of custom
  `register_custom_rules` rules for this repo's own most common bug shapes.
- ~~`missing_tools` now sometimes carries pack-scoped entries...~~ **Confirmed
  real and fixed in fix round 1 below** — the dashboard was the consumer this
  note said it hadn't found.

## Fix round 1 (coordinator review)

Review approved the core fix. Three items to close, addressed below in order.
Also: two adjacent bugs found while verifying item 1, deliberately **not**
fixed here (out of scope for this round); a correction to a wrong claim in
this report's own §1; and the suite-count note.

### 1. `title`/`description` overpromised — rewritten

The independently-confirmed fact (44 rules, all `correctness`, Python 32 / Go
5 / Java 4 / JS+TS 3, the three JS/TS rules being a dead-store check,
`.replaceAll` browser-compatibility, and literal `x==x`) is now stated
directly in both `title` and `description`, including the explicit
consequence: on a JS/TS project, expect few or no findings from this tool,
and an empty result is not evidence of a clean project. `title` gained a
`; Python-strong, JS/TS-thin` suffix so the skew is visible without reading
the full description. `description` also stopped claiming the optional
`categories` input "restricts the returned subcategories" — see the first
adjacent-bug note below for why.

**Correction to my own earlier report:** §1 above claimed
`list-modify-while-iterate` maps to `edge_case` and `unchecked-subprocess-call`
maps to `error_handling` "per `bugHunt.ts`'s own `mapSubcategory`". I traced
that by hand and got it wrong; running the actual function shows neither
matches any of the six regexes — both fall through to the raw, tool-specific
tag (`list-modify-while-iterate`, `unchecked-subprocess-call` respectively),
not a canonical subcategory. The new description no longer implies these
specific mappings; it says subcategories are "attached where the matching
rule's own id says so" — true, and no longer over-specific.

### 2. `missing_tools` colon-qualified entries — fixed at the `bug_hunt` end

**Chose: keep `missing_tools` bare, carry pack detail in `reason`.** Not the
alternative (teaching `TOOL_CATEGORIES`/`omittedCategoriesFor` to parse a
qualified name), because `missing_tools` is a repo-wide contract with readers
beyond the three cited dashboard call sites (`assessCoverage`'s own warning
text does the same bare-name join; I'd already flagged a hypothetical
`install_toolchain`-shaped consumer in this report before the dashboard one
turned out to be real). Teaching the category map a new qualified-name
convention would only patch the sites already found, leave every other
current and future reader exposed to a shape it doesn't expect, and require
documenting a new cross-cutting convention. Un-conflating "which tool" from
"which pack, and why" is the more correct fix, not a patch — `tools_run[]
.reason` is the field the codebase already uses for exactly this kind of
free-text diagnostic (`scanSast.ts`'s own docker-fallback `reason` strings
are the precedent).

Changed: all three `missing_tools.push(...)` sites in `bugHunt.ts` (the
partial-retry-success branch, `reportGap`, and the new cancelled/timed-out
branch from item 3) now push the bare `'semgrep'` once, never
`semgrep:<pack>`, never once per failed pack. The pack name(s) and the
"Failed to download configuration..." message still reach the caller — on
the `semgrep` `tools_run` entry's `reason`.

**Tests — pinning the rendered sentence, not just the array, at all three
cited call sites:**

- `mcp/test/unit/dashboard/snapshot.test.ts` — new test asserts
  `buildSnapshot` (the real `omittedCategoriesFor`, not a hand-built
  `CoverageState`) maps `missing_tools: ['semgrep']` to
  `omitted_categories: ['static-analysis']` — the real `TOOL_CATEGORIES`
  branch, not the unknown-tool fallback a qualified name would hit.
- `mcp/test/unit/dashboard/renderStatus.test.ts` — new test asserts the
  actual CLI line contains `'semgrep — static-analysis findings are NOT in
  these numbers'` and does not match `/semgrep:p\//`.
- `mcp/test/unit/dashboard/renderHtml.test.ts` — new test asserts the
  visible HTML banner (stripped of the inlined JSON data island, matching
  this file's own established idiom for why an un-stripped assertion is
  hollow) contains the equivalent sentence and, again, no `semgrep:p/`.

**Mutation verification:** for each of the three new dashboard tests, I fed
the test the pre-fix shape (`missing_tools: ['semgrep:p/r2c-bug-scan']`)
instead of the real fixed one — all three failed, and `renderStatus`'s
failure output shows the exact nonsense line the coordinator described:
`MISSING      semgrep:p/r2c-bug-scan — static-analysis findings are NOT in
these numbers` (the `omitted_categories` half only reads `static-analysis`
here because that specific test hand-builds `CoverageState`; the
`snapshot.test.ts` test proves the REAL mapping self-references on both
halves, the same way the pre-existing "names an unknown missing tool"
test already demonstrated for a genuinely-unknown name). Restored after
confirming red. Separately, reverted the two `bugHunt.ts` call sites
exercised by `qualityTools.test.ts` back to per-failure qualified pushes —
4 tests there went red (`toEqual(['semgrep'])` failures showing the
qualified strings). Restored; all green again.

### 3. Cancelled/timed-out retry reporting `completed` — fixed

Root cause: the retry branch's `!retryOk` path unconditionally called
`findConfigDownloadFailures(retryRaw)` and unconditionally returned
`outcome: 'completed'`, regardless of *why* the retry wasn't ok. When the
retry process was cancelled or timed out (as opposed to running to a real
exit and hitting another download failure), two things went wrong: `outFile`
could still hold attempt one's stale content (semgrep never got to overwrite
it), so re-reading it double-counted attempt one's own failure; and
`outcome: 'completed'` was reported even though the run had not, in fact,
completed.

Fix: before touching `retryRaw` at all, check `retry.outcome`. When it is
neither `'completed'` nor `'failed'` (i.e. `'cancelled'`, `'timed_out'`, or
`'output_too_large'`), short-circuit — report only attempt one's
already-known failure (bare `missing_tools`, `reason` naming the retry
didn't finish and why), and propagate `retry.outcome` verbatim instead of
`'completed'`. `outFile` is never read in this branch, so the stale-file
double-count is structurally impossible, not just avoided by luck. Only when
`retry.outcome` is a real exit (`'completed'` or `'failed'`) does the
existing `retryRaw`/`retryFailures`/`retryOk` logic run.

**Tests**, both driving the retry mock to a non-`'completed'`/non-`'failed'`
outcome while deliberately NOT writing a fresh `--output` (leaving attempt
one's stale file in place, to prove the fix never reads it):

- `'propagates a cancelled retry as cancelled, not as a completed clean
  scan'` — `scanToolFactory.ts` special-cases a `'cancelled'` outcome as a
  domain error; asserts `r.ok === false, r.error.code === 'cancelled'`.
- `'propagates a timed-out retry as failed, without duplicating the first
  attempt's failure'` — `'timed_out'` doesn't get the factory's early-return,
  so this asserts the normal shape: `r.ok === true, r.status === 'failed'`
  (never `'completed'`), `coverage: 'none'`, `missing_tools: ['semgrep']`,
  and — the duplication check — exactly one `"Failed to download
  configuration from"` occurrence in the `reason` text. (Counting that
  phrase, not `PRIMARY_PACK` occurrences: `describeConfigFailures` already
  mentions a pack's name twice for a SINGLE failure — once as the label,
  once inside that failure's own message, which is the download URL — so a
  raw substring count of the pack name is the wrong signal for "how many
  distinct failures got concatenated in." First draft of this test used the
  wrong signal and false-failed against the correct implementation; caught
  by running it, not just reasoning about it.)

**Mutation verification:** disabled the new outcome check (`if (false && ...)`)
— both new tests went red: the cancelled case returned `ok: true` instead of
`false`; the timed-out case returned `status: 'completed'` instead of
`'failed'`. Restored; both green again.

### Adjacent bugs found, not fixed (out of scope for this round)

Found while re-verifying §1's subcategory claims for accuracy — both
pre-existing, neither introduced by this branch, neither touched:

1. **`bug_hunt`'s `categories` input parameter is dead.** It's declared in
   the input schema and described ("Restrict to these bug subcategories"),
   but nothing in `bugHunt.ts` or `scanToolFactory.ts` ever reads
   `input.categories` — confirmed by grepping the whole `mcp/src` tree for
   any consumer; the only other `.categories` hit in the codebase is an
   unrelated field on `perfCheck.ts`. The parameter has always been inert.
   I removed the specific false claim about it from the description (see
   §1) but left the schema and its own `.describe()` untouched — implementing
   real filtering is a functional code change with its own test surface, not
   a truthful-description fix, and wasn't asked for in this round.
2. **`mapSubcategory`'s fallback line is dead code:**
   `return existing && BUG_SUBCATEGORIES.has(existing) ? existing : existing;`
   — both ternary branches are `existing`, so the `BUG_SUBCATEGORIES.has(...)`
   check has no effect; findings that don't match one of the six regexes keep
   whatever raw, tool-specific tag the generic Semgrep parser derived (e.g.
   `list-modify-while-iterate`), never `undefined`, never validated against
   the six canonical names. This is *why* my original report's subcategory
   claims were wrong, and it means the `categories` filter — if items 1 above
   were ever fixed to make it real — would need this fixed too, or it would
   filter against a vocabulary most findings don't actually use. Flagging
   both together for a follow-up; recommend fixing them in the same change.

### Suite-count note, acknowledged

My original report said "8 failed"; a full concurrent run reproduces 11 on
this commit and (per the coordinator) on `main` too, and I hadn't listed
`phase14Tools.test.ts`. I didn't re-derive this — taking it as reported:
the count is a property of a given concurrent run (contention-sensitive, as
the `createFixPr`/`appRunner` isolation re-runs in my own report already
showed), not of the branch, and every failure reproduces on `main`
regardless of count, so the conclusion (none of them are this change) holds
either way.

### Verification run, fix round 1

- `npm run typecheck` — clean.
- Covering tests, isolated: `qualityTools.test.ts` (10, was 8 — +2 for item
  3), `semgrepConfigFailure.test.ts` (13, unchanged), `snapshot.test.ts` (23,
  was 22 — +1), `renderStatus.test.ts` (17, was 16 — +1), `renderHtml.test.ts`
  (42, was 41 — +1), `toolSurface.test.ts` (3), `toolchainTools.test.ts` (6)
  — **114/114 pass.**
- `npm run build` — clean; `mcp/dist/` rebuilt (this time with no concurrent
  build racing the test run, learning from fix round 0's contention
  flakes).
- `GUARDIAN_REQUIRE_SEMGREP=1 npm test` (full suite), run with **no**
  concurrent build this time (fix round 0's `createFixPr.test.ts`/
  `appRunner.test.ts` flakes were traced to exactly that contention — see
  fix round 0's own verification section): **1414/1415 passed, 1 failed.**
  The one failure is `test/e2e/ciCliFixture.test.ts` — the pre-documented
  Docker-down exception, nothing else. No `createFixPr`/`appRunner` flakes
  this run, confirming they were contention, not a latent issue. Test count
  1410 → 1415 (+5) matches the 5 new tests added this round exactly (2 in
  `qualityTools.test.ts`, 1 each in `snapshot`/`renderStatus`/`renderHtml`
  .test.ts).

## Fix round 2 (coordinator + user): classify, filter, broaden — and the plain answer

The two "concerns" flagged at the end of round 1 turned out to be prerequisites,
not follow-ups: the user (a TypeScript backend) approved adding five
stack-detected language packs on the strength of "the tool classifies by
subcategory, so style could be separated from bugs" — which round 1 had just
shown was **not currently true**. This round, in order: fix the classifier for
real, wire `categories` to actually filter, add the packs, update the
description to match whatever turns out to be true.

**Read this section first if reading nothing else: item 3 does NOT deliver
real JS/TS bug-class coverage.** Full findings below.

### 1. `mapSubcategory` — fixed, then validated against real content, not assumed

The no-op ternary (`return existing && BUG_SUBCATEGORIES.has(existing) ?
existing : existing`) is gone. But the coordinator's framing was exactly
right: the ternary was a symptom, not the disease — the six regex patterns
themselves were too narrow to match real rule ids. Both `list-modify-while-
iterate` and `unchecked-subprocess-call`, cited as working examples in round 1's
own report, matched **neither** the old patterns **nor** `BUG_SUBCATEGORIES`
— that citation was wrong, caught this round by actually calling the function
instead of tracing it by hand again (a second instance of the same mistake
class this whole task exists to catch; see the correction filed in round 1's
own section above).

Fix: broadened all six patterns (added `overflow`/`underflow` to off-by-one,
`unchecked`/`uncaught`/`unhandled` to error-handling, `modify.*iterat`/
`mutable.*default` to edge-case, etc.), grounded in real rule ids, not
guessed. Validated by writing a script that runs the classifier against
**every rule id in every pack `bug_hunt` can now run** — 670 rules across
`r2c-bug-scan`, `security-audit`, and the five new language packs:

- **13 correctly land in a canonical bucket** (up from a number close to zero
  under the old code — verified by literally reverting to the old
  implementation and re-running the new test file: 9 of 22 tests went red).
- **657 correctly fall through** untouched — expected and correct, not a
  shortfall: the vast majority of these 670 rules are security rules, not
  bug_hunt's six classes.
- **Two real false-positive near-misses found and fixed**, not hypothesised:
  `java...crypto.no-null-cipher` (flags the literal `NullCipher` algorithm —
  matched a bare `null` keyword, is not a null-safety bug) and
  `python...logger-credential-leak` (flags secrets written to logs — matched
  a bare `leak` keyword, is not a memory leak). Both required a
  safety/resource-relevant qualifier alongside the bare word, not just the
  word itself, to exclude correctly. Found by testing against every rule id
  in every pack, not a hand-picked example set — the same lesson as always,
  applied to my own new code this time.

New export `BUG_SUBCATEGORIES` (was module-private) and `mapSubcategory`
itself, both for direct testing. New test file
`mcp/test/unit/tools/bugHuntClassify.test.ts` (22 tests): every true-positive
case above, both false-positive guards, and the six-canonical-name guarantee.

### 2. `categories` — was dead code, now wired

Read the schema first, as asked: `categories: z.array(z.string()).optional()`
— shape was already right (`string[] | undefined`); nothing needed bending.
The gap was purely that nothing downstream ever read `input.categories`.

Fix: `bugCategoryParser` (a module-level constant) is now
`makeBugCategoryParser(categories)`, a per-invoke factory that filters
`recategoriseAsBug`'s output to findings whose `subcategory` is in the
caller's list (canonical or raw — a caller can filter to a security tag too,
not only the six bug classes) before anything is persisted or counted.
Filtering lives inside the parser, not as a generic post-filter in
`scanToolFactory.ts`: `categories` is a `bug_hunt` concept, not something
every scan tool has.

Tests: a 3-finding fixture (two canonical subcategories + one non-canonical
security finding) asserts `categories: ['null_safety']` returns exactly 1,
and `categories: ['null_safety', 'edge_case']` returns exactly 2 and drops
the security finding. **Mutation-verified**: disabled the filter (`const
findings = recategorised`) — both tests went red (3 returned instead of 1;
the security finding's raw tag `'express-xss'` leaked into a filtered-for-
canonical result). Reverted, green again.

### 3. Language packs — added exactly as specified, and empirically found to add zero bug-class coverage

**Design, following `scanSast.ts:70`'s conditional-pack shape, sourced from
`StackSnapshot`'s real fields as asked** (checked, not assumed: `languages:
string[]`, confirmed against `types.ts` and `detect-stack.sh`'s own
`LANGUAGES+=("javascript")`-style emission):

- `languagePacksFor(languages)` — pure, exported, maps `StackSnapshot
  .languages` entries to pack names (`javascript`→`p/javascript`, …,
  `go`→`p/golang`).
- `detectLanguagePacks(ctx)` — prefers `ctx.plugin.storage.stack.getLatest()
  ?.snapshot.languages` (the persisted `detect_stack` snapshot) when one
  exists; falls back to a cheap, top-level filesystem check
  (`package.json`+`tsconfig.json`/`pyproject.toml`/`pom.xml`/`go.mod`) —
  same two-tier shape as `observabilitySetup.ts`'s own `inferStack`, not a
  third pattern — so `bug_hunt` gets stack-aware coverage even the first
  time it runs against a project that has never had `detect_stack` run
  against it.
- `configuredPacks = [...BUG_HUNT_BASE_PACKS, ...detectLanguagePacks(ctx)]`,
  threaded through the existing retry/gap-reporting logic from rounds 0–1
  unchanged (that logic only cares about `readonly string[]`, not how many
  packs or their names).

**Liveness verified, all five, before shipping** (`curl -o /dev/null -w
'%{http_code}' https://semgrep.dev/c/p/<name>`): `p/javascript` 200,
`p/typescript` 200, `p/python` 200, `p/java` 200, `p/golang` 200.

**Content verified, all five, three independent ways — and this is the
answer that changes what you owe the user:**

1. **Metadata**: fetched and inspected all 401 of their rules
   (74+74+42+151+60). Every single one is `category: security`.
   `vulnerability_class` breakdown across all five: Cryptographic Issues (91),
   XSS (38), SQL Injection (36), Code Injection (29), Command Injection (27),
   Mishandled Sensitive Information (20), Improper Authentication (20), XML
   Injection (16), Cookie Security (16), SSRF (14), Hard-coded Secrets (13),
   Improper Validation (12, and inspected — means missing
   sanitisation-before-a-sink, e.g. SQL/XSS/log injection, not missing
   null/bounds checks), Path Traversal (11), Insecure Deserialization (10),
   Insecure Hashing (9), Open Redirect (8), Improper Authorization (5), CSRF
   (4), Improper Encoding (2). **Zero representation of any of the six bug_hunt
   classes.** Rule-id and message keyword searches for
   null/undefined/off-by-one/overflow/leak/exception/unchecked/uncaught
   across all 401 rules: zero genuine hits (the one `null` hit and the one
   `leak` hit are exactly the two false positives fixed in §1 above).
2. **Live execution**: built a real TypeScript fixture
   (`ts-bugfixture/app.ts`) with five real instances — an unguarded
   `.find()!.profile.email` (null safety), a `for (i=0; i<=arr.length;
   i++)` loop (off-by-one), an array spliced while being iterated (edge
   case), an empty `catch` block (swallowed error handling), and a
   fire-and-forget `fetch(...).then(...)` with no `.catch` (unhandled
   rejection). Ran `semgrep --config=p/r2c-bug-scan --config=p/security-audit
   --config=p/javascript --config=p/typescript --config=p/python
   --config=p/java --config=p/golang` against it: **exit 0, `results: []`,
   `errors: []`.** Zero matches, from any of the seven configured packs.
3. **Classifier test**: the same 670-rule sweep from §1 — of the 13 rules
   that land in a canonical bucket, **zero are from any of the five new
   packs**; all 13 are from `r2c-bug-scan` (12) and `security-audit` (1,
   `use-after-free` → `memory_leak`).

**Plain answer to "did item 3 deliver real JS/TS coverage": no.** Adding
`p/javascript`/`p/typescript` widens JS/TS *security* coverage (much of it
likely redundant with `p/security-audit`, not measured precisely here) and
adds zero rules toward race-condition, null/undefined-safety, off-by-one,
memory-leak or swallowed-error-handling in JS/TS or in any of the other four
languages either. `p/r2c-bug-scan`'s existing 3 JS/TS rules (dead-store,
`.replaceAll` compatibility, literal `x==x`) remain the entire JS/TS bug-class
surface after this round — unchanged from round 1. **I did not find a better
pack to substitute** — see round 1's report for the registry sweep
(`p/javascript`, `p/typescript`, `p/golang`, `p/trailofbits` were already
known security-only; this round additionally ruled out `p/python`, `p/java`,
`p/eslint`, `p/nodejsscan`, `p/react`, `p/nextjs`, `p/r2c-CI` the same way).
**No live Semgrep registry pack covers these four classes for JS/TS today.**

Tests (`qualityTools.test.ts`, network-independent — mocked `runProcess`
throughout, per the instruction to keep this the same as the existing
pattern):

- Stack-detection: snapshot-driven pack selection, filesystem fallback when
  no snapshot exists, snapshot-over-filesystem precedence when they disagree,
  and a package.json-without-tsconfig case (JS only, not TS). **Mutation-
  verified**: `detectLanguagePacks` forced to return `[]` — 5 tests went red
  (the 4 stack-detection tests plus the honest-negative test below, which
  also depends on the language packs actually being requested). Reverted.
- The classification-machinery test: 5 real rule ids (one per canonical
  class reachable from currently-configured packs; `race_condition` is
  covered in the unit test file instead, since no currently-configured pack
  exposes a second real race-condition example to pair with it here) through
  the full pipeline, asserting each lands in its correct subcategory.
- **The honest negative result, made permanent and machine-checked, not
  just asserted in prose**: a JS/TS project (stack snapshot:
  `['javascript','typescript']`) scanned with all seven configured packs,
  mocked to return the *exact* JSON real semgrep produced against the real
  fixture (`results: [], errors: [], paths.scanned: ['app.ts']`, exit 0) —
  asserts `coverage: 'full'` (every pack ran; this is not a gap — round 1's
  fix is about scans that DIDN'T run looking clean, which is a different
  failure from a scan that ran fine and genuinely found nothing) and 0
  findings, with all five configured packs' `--config=` args confirmed
  present. If a future pack update ever adds real JS/TS bug-class rules,
  this test will need deliberate revisiting — which is the point: a stale
  comment could rot silently, a failing test cannot.

### 4. Description — rewritten again, now including the language-pack caveat

`title` gained `+ stack-detected language packs`, keeping the existing
`Python-strong, JS/TS-thin` qualifier (now describing the *bug-class* surface
specifically, since it's still true and now easy to conflate with the
broader — but security-only — per-language coverage).

`description` states plainly: what packs get added and from where (snapshot
or filesystem check), that all five are Semgrep's per-language SECURITY
bundles verified against all their rules and a live scan to add zero bug-class
rules in any language, and that `categories` now really filters (with an
example: `categories: ["null_safety", "edge_case"]` to strip the language
packs' security volume back out). Also documents that most findings — from
the five language packs and from `p/security-audit` — keep their own raw,
non-canonical subcategory tag rather than being forced into one of the six,
which is what makes `categories` filtering meaningful in the first place.

### Verification, fix round 2

- `npm run typecheck` — clean. (Test files are excluded from this repo's
  `tsconfig.json` — `"exclude": ["test", "**/*.test.ts"]` — so test-file
  correctness here rests on actually running vitest, not `tsc`; every test
  file change in this round was run, not just written.)
- Constraint check across every file touched this round (`bugHunt.ts`,
  `qualityTools.test.ts`, `bugHuntClassify.test.ts`): zero non-null
  assertions, zero `any`.
- Covering tests, isolated: `qualityTools.test.ts` (18, was 10 — +8),
  `bugHuntClassify.test.ts` (22, new file), plus the four files from round 1
  re-run unchanged — **144/144 pass.**
- `npm run build` — clean; `mcp/dist/` rebuilt, no concurrent build running
  this time (learning applied from round 1's own contention flakes).
- `GUARDIAN_REQUIRE_SEMGREP=1 npm test`, no concurrent build: **1444/1445
  passed, 1 failed** — again exactly `test/e2e/ciCliFixture.test.ts`'s
  pre-documented Docker-down case, nothing else. Test count 1415 → 1445
  (+30) matches this round's additions exactly (22 in the new
  `bugHuntClassify.test.ts` + 8 in `qualityTools.test.ts`).

### Concerns carried forward

- **The core user-facing gap is unchanged by this round: JS/TS (and Python/
  Java/Go) still have no live-registry bug-class coverage for race
  conditions, null/undefined safety, off-by-one, memory leaks or swallowed
  error handling, beyond `p/r2c-bug-scan`'s existing 3/5/4/32 rules.** The
  language packs add real value (per-language security depth) but not the
  value the user was told to expect. Recommend: either commission/curate a
  small custom rule pack for the four classes via `register_custom_rules`
  (this repo already has that tool), or set the user's expectation that
  `bug_hunt` for JS/TS today means "3 style rules + broad security scanning
  via the new packs," not "logic-bug detection," until such a pack exists
  somewhere live.
- ~~Scan cost/noise: five more packs... Likely meaningful overlap... not
  precisely measured this round~~ **Measured in round 3 below: real but
  partial, not "largely," and the language packs are now off by default
  regardless.**

## Fix round 3 (coordinator + user): gate the language packs, fix a dangling reference

The user decided: keep the language packs, but **off by default, explicitly
requestable**. Two independent pieces of work — the gating mechanism, and an
unrelated dangling-reference bug the coordinator found while checking round
2's result.

### Mechanism chosen: a new boolean input, not `categories`

The user phrased the request as "behind the `categories` parameter." I did
not bend the implementation to that phrasing, per the instruction, because
it conflates two different axes:

- `categories` filters **output** — which already-found findings are
  returned.
- Pack selection is **input** — which scanners run at all.

Folding pack selection into `categories` would mean requesting
`categories: ['null_safety']` could silently change which scanners ran (or
requesting the language packs' own security tags would silently turn
scanners on) — coupling that is hard to reason about later: a caller could
not ask "give me only null-safety findings" without ALSO deciding whether
Semgrep spends time scanning with five extra packs, and vice versa.

**Chose a separate, explicit boolean: `include_language_packs`** (zod:
`z.boolean().optional().default(false)`, same shape as this schema's
existing `Force`/`AutoFix`/`AllowDirty`). Gates a single line:
`...(input.include_language_packs === true ? detectLanguagePacks(ctx) : [])`
— `detectLanguagePacks` itself (snapshot-preferred, filesystem-fallback
stack detection) is completely unchanged from round 2; only whether it gets
*called* is new. `categories` and `include_language_packs` compose freely
and independently — e.g. `include_language_packs: true` with
`categories: ['null_safety']` still returns only null-safety findings, now
possibly including any the language packs happened to produce (none do,
per round 2's finding, but the mechanism doesn't special-case that).

**Test**: a stack snapshot with `languages: ['javascript', 'typescript']`
persisted, `bug_hunt` called with **no** `include_language_packs` — asserts
neither `--config=p/javascript` nor `--config=p/typescript` appears, and
that the full `--config=` arg list is exactly `BUG_HUNT_BASE_PACKS`, nothing
more. **Mutation-verified**: reverted the gate to always call
`detectLanguagePacks(ctx)` unconditionally — this one test went red (`to not
include '--config=p/javascript'` failed); the other 18 tests in the file
stayed green because they now all pass `include_language_packs: true`
explicitly, which is the correct, narrow blast radius for this mutation.
Reverted, green again. The four pre-existing stack-detection tests and the
JS/TS honest-negative test (round 2) were updated to pass
`include_language_packs: true` — each already had a comment explaining why
the flag is load-bearing for what the test is proving, not just plumbing.

### The redundancy claim: measured, and it isn't "largely"

The instruction said the description must state the packs are "largely
redundant with p/security-audit," attributing that to my own measurements.
Round 2's report had explicitly flagged this as *not* measured
("likely... not precisely measured this round"). Rather than write "largely
redundant" into a string a model reads on the strength of an assumption —
exactly the failure mode this whole task has been about — I measured it:
exact rule-id overlap between each language pack and `p/security-audit`.

```text
p/javascript: 74 rules,  7 exact-id overlap with p/security-audit (9%)
p/typescript: 74 rules,  7 exact-id overlap with p/security-audit (9%)
p/python:    151 rules, 30 exact-id overlap with p/security-audit (20%)
p/java:       60 rules, 26 exact-id overlap with p/security-audit (43%)
p/golang:     42 rules, 17 exact-id overlap with p/security-audit (40%)
TOTAL:       401 rules, 87 exact-id overlap (22%)
Distinct ids across all 5 packs: 327; NOT already in p/security-audit: 247 (76% net new)
```

**Real, but partial — and lopsided in exactly the direction that matters for
this user.** Overlap is heaviest for Java/Go (40–43%) and lightest for
JS/TS (9%) — the user's own stack. "Largely redundant" would have
understated how much genuinely new security scanning the JS/TS packs add,
for the one language the user actually cares about. The description states
the real numbers instead of the flat framing (22% overall / ~9% JS/TS / up
to 40–43% Java-Go), and I'm flagging the discrepancy here explicitly rather
than silently overriding your framing without comment.

### Description and title — all four required clauses, with real numbers

`title`: `optional language packs, off by default` (was `+ stack-detected
language packs`, which read as always-on).

`description` now states, in order: `include_language_packs` exists and is
off by default; what it turns on and how (snapshot or filesystem-detected,
per language); that all five are Semgrep's per-language SECURITY bundles,
verified against all 401 rules and a live fixture scan (round 2); the real
overlap numbers above, explicitly contradicting "largely redundant"; that
they add no bug-class coverage; that `p/r2c-bug-scan` remains the only
bug-class source and is thin outside Python; that `categories` and
`include_language_packs` are independent axes (input vs output), with an
example of composing them.

### The dangling reference

`skills/guardian-bugfix/SKILL.md:62` said: "Regras prontas em
`${CLAUDE_PLUGIN_ROOT}/configs/semgrep/bugfix-*.yml`." Confirmed absent:
`ls configs/semgrep/` → `base.yml`, `routes.yml` only, nothing matching
`bugfix-*`. Same shape of defect as `p/bugs`, one layer in — a model reading
this skill as instruction would look for rule files that were never written.

Per the instruction: did not write the missing rule files (the user has
separately approved that as its own piece of work). Replaced the sentence
with an accurate one: no ready-made Semgrep pack for these bug classes
exists yet, in this skill or in the live registry — citing `bug_hunt`'s own
verified finding (rounds 2–3) that no live pack covers null-safety,
off-by-one, race conditions, memory leaks or swallowed error handling in any
language — and points the reader at this same skill's own model-guided
reasoning (§1 scope, §4 patterns-and-fixes) as the reliable path today,
per the instruction to point at `/guardian-fix`'s own model-driven path
rather than any Semgrep pack (`/guardian-fix` *is* this skill —
`commands/guardian-fix.md` just invokes it — so the correction points
inward, to sections of this same document, not to a different feature).

### Verification, fix round 3

- `npm run typecheck` — clean.
- Constraint check (`bugHunt.ts`, `qualityTools.test.ts`): zero non-null
  assertions, zero `any`.
- `npx markdownlint-cli2 skills/**/*.md commands/**/*.md README.md` — 62
  files, 0 issues (touched exactly one: `guardian-bugfix/SKILL.md`).
- Covering tests, isolated: `qualityTools.test.ts` (19, was 18 — +1),
  `bugHuntClassify.test.ts` (22, unchanged), plus the six files from rounds
  1–2 re-run unchanged — **145/145 pass.**
- `npm run build` — clean; `mcp/dist/` rebuilt, no concurrent build.
- `GUARDIAN_REQUIRE_SEMGREP=1 npm test`, no concurrent build: **1445/1446
  passed, 1 failed** — again exactly `test/e2e/ciCliFixture.test.ts`'s
  pre-documented Docker-down case, nothing else. Test count 1445 → 1446 (+1)
  matches this round's one new test exactly.

## Fix round 4 (final review): a false claim replacing a false pointer, and a precise falsehood on the dashboard

Every overlap number from round 3 was independently re-derived by the
reviewer and confirmed exact. Two required fixes before merge, plus a
ledger of deferred, pre-existing items (same defect class, out of scope for
this branch).

### Important 1: the SKILL.md fix itself made a new false claim

`skills/guardian-bugfix/SKILL.md:62`'s corrected text (round 3) said no live
pack covers the five bug classes **"em nenhuma linguagem"** (in no
language). False: `p/r2c-bug-scan` — always on, not optional — has rules in
all five (confirmed by this same branch's own classifier sweep: 1
race_condition, 2 null_safety, 2 off_by_one, 2 memory_leak, 2
error_handling, from `r2c-bug-scan` itself). It also cited
`.superpowers/semgrep-pack-fix-report.md`, which is untracked (`git status`
confirms — `.superpowers/` has never been staged in any commit on this
branch) and will not exist for anyone who did not run this exact session.

**This was the same failure one turn later**: a dangling pointer to
nonexistent rules, replaced by an overbroad claim about where rules don't
exist, sourced from a citation that doesn't ship. Fixed by narrowing to what
is actually true and already stated correctly elsewhere in this same commit
(`bugHunt.ts`'s own description: "Only p/r2c-bug-scan ... covers the six bug
classes today, and thinly outside Python"): the gap is **JS/TS
specifically** — `p/r2c-bug-scan`'s coverage of these classes is real but
Python/Go-heavy, and none of it matches JS/TS source; the optional language
packs (`include_language_packs`) add security rules, not more of these
classes, in any language. Dropped the report citation entirely; nothing in
the corrected text depends on a file the reader may not have.

The identical over-broad claim ("in any language") was repeated in
`qualityTools.test.ts:715-716`'s comment for the honest-negative test — same
fix applied there, citing `bugHuntClassify.test.ts`'s real true-positive
cases (Python/Go rule ids that DO classify into these subcategories) as the
concrete evidence the narrower claim is true and testable, "so it cannot
drift back" as asked. No test assertions changed — this was a comment-only
defect in both files — but the correction is now anchored to specific,
existing tests a future reader can actually check.

### Important 2: retry-success reported a precise falsehood, not the nonsense string it replaced

`bugHunt.ts`'s retry-success path (unchanged since round 1) pushes bare
`'semgrep'` into `missing_tools` — correct, per round 1's own fix, to signal
"one pack was unavailable" without the pack-qualified nonsense the dashboard
can't render sensibly. But `missing_tools` and `tools_run` (status `'ok'`,
real findings) both name `semgrep` at once, and neither renderer could tell
"ran, but flagged a narrower gap" apart from "never ran at all" — both
rendered identically as **"semgrep did not run this scan"**, false for a
scan whose `by_tool: {semgrep: 1}` and risk score are on the same screen.

**Root cause, traced to source**: `dashboard/snapshot.ts`'s `buildCoverage`
reduces the persisted `tools_run: ToolRun[]` (which DOES carry `status`) down
to bare names (`tools_run.map(t => t.name)`) before it ever reaches
`CoverageState` — the only structure the renderers see. `status` was
discarded at that step for every tool, not only `bug_hunt`'s; nothing
downstream could have recovered the distinction no matter how the renderers
were written, because the data was already gone.

**Fix, carried through every layer it touches:**

1. `dashboard/types.ts` — `CoverageState` gains `partial_tools?: string[]`:
   the subset of `missing_tools` whose `tools_run` entry is `status: 'ok'`.
   Optional, so it defaults to "nothing partial" (the old, fully-missing-only
   behaviour) for any hand-built fixture that predates the field, rather
   than crashing on a missing property — test files in this repo are not
   type-checked by `tsc` (`tsconfig.json` excludes `test/`), so a required
   field would have been a silent runtime risk, not a caught compile error.
2. `dashboard/snapshot.ts` — `buildCoverage` computes it from the full,
   already-persisted `ToolRun[]` (the one place in the pipeline that still
   has `status` at this point) before reducing to bare names.
3. `dashboard/renderStatus.ts` (`renderMissingLine`) and
   `dashboard/renderHtml.ts` (`coverageBanner`) — split `missing_tools` into
   fully-missing (still "X did not run this scan") and partial (new: "X ran
   with reduced coverage — some ... findings may be missing"), each naming
   only the tools its own claim is true for. The pre-existing cveGap-only
   fallback (`missing_tools` empty, `omitted_categories` not — no scanner
   failed, there's simply no deps-flavoured scan in history) is unchanged
   byte-for-byte from before this fix, in both renderers.

**Tests, at every layer, mirroring round 1's pattern for the equivalent
case:**

- `snapshot.test.ts` — two new tests: a `ToolRun` with `status: 'ok'` that's
  also in `missing_tools` produces `partial_tools: ['semgrep']` AND
  `coverage.level` stays `'partial'` (the gap is still real); a `status:
  'failed'` entry in the same shape produces `partial_tools: []` (genuinely
  absent, not partial).
- `renderStatus.test.ts` / `renderHtml.test.ts` — one new test each pinning
  the rendered "ran with reduced coverage" sentence and asserting "did not
  run this scan" is ABSENT; `renderStatus.test.ts` adds a second test for
  the mixed case (one fully-missing tool + one partial tool in the same
  scan), asserting each gets its own, individually accurate line.
- The round-1 tests for both renderers asserted a narrower substring than
  the sentence now produced (`renderHtml.test.ts`'s already included "did
  not run this scan"; `renderStatus.test.ts`'s didn't) — widened
  `renderStatus.test.ts`'s assertion to match; no assertion became looser,
  only more complete.

**Mutation-verified at every layer:**

- `snapshot.ts`: forced `partialTools` to always be `[]` — the new
  "flags a tool that ran ok..." `snapshot.test.ts` test went red (`[]` vs
  `['semgrep']`); the renderer tests, which build `CoverageState` by hand
  and never call `buildCoverage`, correctly did NOT catch this — proof the
  two test layers guard different things, not duplicate coverage.
- `renderStatus.ts` / `renderHtml.ts`: reverted both to their pre-round-4
  bodies (ignoring `partial_tools` entirely) — 4 tests went red across the
  two files (the widened round-1 assertion plus the 3 new partial/mixed
  tests), 0 false failures elsewhere.
- Reverted; **150/150 covering tests green.**

### Ledger — corrected while already editing the same text

`p/javascript` and `p/typescript` are byte-identical rule sets (74 ids each,
zero unique either way) and both get requested for a TS-stack project, so
"401 rules" (the language packs) and "670 rules" (all seven packs, used in
`mapSubcategory`'s own validation claim) both double-count that overlap.
Recomputed the true distinct totals rather than hand-adjust the arithmetic
(the exact mistake this task keeps catching): **327 distinct** across the
five language packs, **516 distinct** across all seven configured packs.
Corrected every occurrence — `bugHunt.ts`'s header comment (×2), the
`LANGUAGE_PACKS` doc comment, `mapSubcategory`'s own doc comment (13 land in
a canonical bucket unchanged; the "657 fall through" denominator becomes
"503", from 516 − 13), the `description` string, and
`qualityTools.test.ts`'s matching comment.

### Ledger — deferred, not touched (pre-existing, same defect class, separate follow-up)

Per the instruction, acknowledged and left alone:

- A pre-existing path where semgrep exits 0 with no `--output` file yields
  `coverage: 'full'` and zero findings silently — contradicts the new
  header comment at `bugHunt.ts:17-18`'s "never lets a run that scanned
  nothing get reported as a clean bug report" for that specific case. Not
  touched this round.
- `categories` can only ever return zero findings on a JS/TS project (no
  currently-configured pack has JS/TS rules in the six classes at all, so
  there is nothing for `categories: [...]` to select). Not touched.
- `skills/guardian-init/SKILL.md:61-65` names four template sources that do
  not exist — same defect class as the `guardian-bugfix` fix, in a
  different skill. Not touched.

### Note for future verification in this environment

The reviewer found Semgrep cannot be invoked through the Bash tool in this
session's environment; PowerShell can. Re-ran this round's full suite via
PowerShell (`$env:PATH += ...; $env:GUARDIAN_REQUIRE_SEMGREP = "1"; npm
test`) rather than Bash's `export PATH=...`. Every real-Semgrep e2e test
(`rulePackFixture`, `evalVulnFixture`, `validateFindingFixture`) passed
either way in every round of this branch's own testing, so this may be
session-specific rather than a hard Bash-tool limitation — noted as told,
not independently root-caused.

### Verification, fix round 4

- `npm run typecheck` — clean.
- Constraint check across every file touched this round (`dashboard/
  types.ts`, `dashboard/snapshot.ts`, `dashboard/renderStatus.ts`,
  `dashboard/renderHtml.ts`, `bugHunt.ts`, and their tests): zero non-null
  assertions, zero `any` (one regex false-positive on the English word
  "any" in a pre-existing, untouched comment — checked, not a type).
- `npx markdownlint-cli2 skills/guardian-bugfix/SKILL.md` — clean (the only
  `skills/`/`commands/`/`README.md` file touched this round).
- Covering tests, isolated: `renderStatus.test.ts` (19, was 17 — +2),
  `renderHtml.test.ts` (43, was 42 — +1), `snapshot.test.ts` (25, was 23 —
  +2), plus the five files from rounds 1–3 re-run unchanged —
  **150/150 pass.**
- `npm run build` — clean; `mcp/dist/` rebuilt, no concurrent build.
- Full suite, PowerShell, `GUARDIAN_REQUIRE_SEMGREP=1`, no concurrent
  build: **1450/1451 passed, 1 failed** — again exactly
  `test/e2e/ciCliFixture.test.ts`'s pre-documented Docker-down case, nothing
  else (the run's own process exit code was 1, as it is every round: `npm
  test` exits non-zero whenever any test fails, including this expected
  one — not itself a signal of a new problem). Test count 1446 → 1451 (+5)
  matches this round's five new tests exactly. Every real-Semgrep e2e test
  (`rulePackFixture`, `evalVulnFixture`, `validateFindingFixture`) passed
  running through PowerShell, same as every prior round running through
  Bash.
