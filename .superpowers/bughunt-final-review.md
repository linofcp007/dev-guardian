# `fix/semgrep-retired-pack` — final review before merge

Branch `fix/semgrep-retired-pack` (`7daf379`), 4 commits over `main` (`4fe1d06`).
Reviewer method: everything below was **executed or mutated**, not read. Semgrep
1.164.0 (real registry, live 404s), real `dist/` modules, real argv capture.

**Verdict: approve with one required change.** The core fix is sound and holds
end to end against the live registry. One Important finding (a false claim newly
introduced in `skills/guardian-bugfix/SKILL.md:62`) is the exact defect class
this branch exists to eliminate and should be corrected before merge; it is a
one-sentence edit. A second Important finding (a user-facing dashboard sentence
that is now precisely false) errs conservatively and is strictly better than both
the pre-branch and round-0 states — file it, fix it next, do not block on it.

---

## Method note: the Bash tool cannot run Semgrep here

`semgrep` invoked through the Bash tool returns the literal string
`<ERROR: missing output>` (23 bytes) — to stdout *and* into any `--output` file —
for every scan, including a trivial local-rule scan that exits 0, and with the
sandbox disabled. `semgrep --version` works. Every Semgrep result below was
therefore produced through the **PowerShell** tool, where it behaves normally.
Anyone re-verifying this branch through Bash will get phantom failures that are
not the branch's.

---

## Doubt-by-doubt results

### 1. The core guarantee — CONFIRMED (live 404, not a fixture)

Real `bug_hunt`, real `dist/`, real registry, `p/definitely-not-a-real-pack-xyz`
injected alongside the two live packs.

First, the premise the whole fix rests on reproduces exactly:

```text
semgrep --config=p/definitely-not-a-real-pack-xyz --config=p/security-audit --json --quiet
exit=7   results=0   paths.scanned=0   errors=2
  [0] "Failed to download configuration from https://semgrep.dev/c/p/definitely-not-a-real-pack-xyz HTTP 404."
  [1] "invalid configuration file found (1 configs were invalid)"
```

One dead `--config=` aborts the whole invocation — the *valid* pack scanned
nothing. `findConfigDownloadFailures` run against that real file returns exactly
1 failure (the summary entry at `[1]` is correctly not attributed), and
`survivingPacks` returns `['p/security-audit']`.

End to end, one pack dead of three:

```text
coverage: partial      missing_tools: ["semgrep"]
tools_run: [{"name":"semgrep","status":"ok","reason":"ran with p/r2c-bug-scan, p/security-audit only — p/definitely-not-a-real-pack-xyz (Failed to download configuration from https://semgrep.dev/c/p/definitely-not-a-real-pack-xyz HTTP 404.)"}]
semgrep invocations: call 1 = all three packs;  call 2 = the two survivors
```

Every pack dead:

```text
coverage: none    0 findings    missing_tools: ["semgrep"]    1 invocation (no pointless retry)
warning: '⚠️ bugs: NO scanner ran (unavailable/failed: semgrep). A "0 findings" result is NOT a
          clean bill of health — nothing was actually scanned.'
```

That is the original incident (`p/bugs` 404 → scanned nothing → reported clean)
now correctly reported as a gap.

**Mutation:** `findConfigDownloadFailures` neutered to always return `[]` →
**11 committed tests RED**, including
`'never reports a clean result when every configured pack fails to download'`
and `'does not trust a clean exit code alone'`. Restored, green.

### 2. The retry genuinely retries — CONFIRMED

The survivors' findings really do come back: the retry produced
`python.lang.correctness.list-modify-iterating.list-modify-while-iterate`
(1 high), identical to a control run configured with only the survivors. The
retry is a real second scan, not a cosmetic re-report.

### 3. The overlap percentages — RE-DERIVED INDEPENDENTLY, ALL CORRECT

Fetched all seven packs myself and counted exact rule-id set intersection
against `p/security-audit` (225 rules):

```text
p/javascript:  74 rules,  7 overlap  ( 9.5% → 9%)
p/typescript:  74 rules,  7 overlap  ( 9.5% → 9%)
p/python:     151 rules, 30 overlap  (19.9% → 20%)
p/java:        60 rules, 26 overlap  (43.3% → 43%)
p/golang:      42 rules, 17 overlap  (40.5% → 40%)
TOTAL:        401 rules, 87 overlap  (21.7% → 22%)
Distinct ids across all 5 packs: 327; not already in p/security-audit: 247 (76% net new)
```

Every number in the shipped description reproduces: **22% overall, ~9% JS/TS,
40–43% Java/Go, 401 rules, 247 net new.** The description is accurate. (See
Minor 3 for what the `401` figure quietly double-counts.)

### 4. The gating — CONFIRMED at argv level, not return value

`include_language_packs` parses `undefined → false` (zod `.default(false)`;
`invoke` additionally tests `=== true`, so it is off even if the default is
bypassed). With a persisted stack snapshot naming `javascript, typescript,
python`:

```text
default (flag absent):  --config=p/r2c-bug-scan  --config=p/security-audit
include_language_packs: --config=p/r2c-bug-scan  --config=p/security-audit
                        --config=p/javascript  --config=p/typescript  --config=p/python
```

Captured from a PATH shim recording what Semgrep actually received. The packs
genuinely do not run by default even when the snapshot would select them.

**Mutation:** gate reverted to unconditional → the
`'does not add any language pack by default…'` test RED (only that one — correct
blast radius). Restored, green.

### 5. `categories` actually filters — CONFIRMED live

Live end-to-end against the real fixture:

```text
categories: ['edge_case']                 → 1 finding (the edge_case one)
categories: ['null_safety']               → 0 findings
categories: ['edge_case','error_handling'] → 1 finding
```

**Mutation:** filter removed (`const findings = recategorised`) → 2 tests RED.
Restored, green. It was dead code before this branch; it is live now.

### 6. `mapSubcategory` classifies — CONFIRMED by independent sweep

Swept the real function over every rule id in all seven packs (670 instances).
Reproduced the implementer's numbers exactly — **13 canonical, 657 fall through**
— and, importantly, they are spread across all six classes, not bucketed:

```text
off_by_one     r2c-bug-scan  go...overflow.integer-overflow-int16 / -int32
edge_case      r2c-bug-scan  list-modify-while-iterate / dict-del-while-iterate
                             default-mutable-dict / default-mutable-list
race_condition r2c-bug-scan  python...concurrent.uncaught-executor-exceptions
memory_leak    r2c-bug-scan  file-object-redefined-before-close
memory_leak    security-audit c.lang.security.use-after-free
error_handling r2c-bug-scan  unchecked-subprocess-call / raise-not-base-exception
null_safety    r2c-bug-scan  string-field-null-checks (×2)
by pack: {r2c-bug-scan: 12, security-audit: 1}   from the 5 language packs: 0
```

And live, through the whole pipeline, a real finding landed correctly:
`list-modify-while-iterate → [bug/edge_case]`.

**Mutation:** classifier short-circuited → 13 tests RED. Restored, green.

### 7. The dashboard sentence — nonsense gone, but see Important 2

Rendered the **real** dashboard from a **real** `bug_hunt` gap (not a hand-built
`CoverageState`): `buildSnapshot` → `renderStatus` → `renderDashboard`.

```text
MISSING  semgrep — static-analysis, container and dependency findings are NOT in these numbers
HTML:    semgrep did not run this scan — static-analysis, … findings are NOT in these numbers.
"semgrep:p/" present anywhere?  false
```

The self-referential `MISSING semgrep:p/x — semgrep:p/x findings…` is gone, and
the three call sites are each pinned by a committed test (`snapshot.test.ts`
pins the real `TOOL_CATEGORIES` branch; `renderStatus`/`renderHtml` pin the
rendered strings and assert `not.toMatch(/semgrep:p\//)`). But the sentence that
replaced it is itself false — Important 2.

### 8. The skill's replacement text — Important 1 (see below)

### 9. Repo conventions — ALL CLEAN

- `mcp/dist/` in sync: `npm run build` twice produced **zero** drift
  (`git status` clean both times). Bundle and tsc tree both current.
- No `any`, no non-null assertions in any changed source or test file.
- All relative imports carry `.js` specifiers.
- No dependency changes (`package.json` / lockfile untouched by the diff).
- `markdownlint-cli2 skills/**/*.md commands/**/*.md README.md` → **62 files,
  0 issues.**

### 10. Suite failures — ONE, and it reproduces on `main`

`GUARDIAN_REQUIRE_SEMGREP=1 npm test` on the branch, nothing else running:

```text
Test Files  1 failed | 111 passed (112)
Tests       1 failed | 1445 passed (1446)
```

The single failure is `test/e2e/ciCliFixture.test.ts > 'writes the baseline,
warns by name, and exits 2 when a scanner is missing'`:
`expected 'baseline updated: 0 entries…' not to match /fail(ed)?|refus(ed|ing)|abort(ed)?/i`
— stdout contains `map_attack_surface: semgrep failed (ran via docker
(semgrep/semgrep))`. Docker confirmed down (`docker version` → 500 on the
named pipe).

**Checked out `main` at `4fe1d06` and ran the same file: identical failure,
identical assertion, identical message** (1 failed | 33 passed). Not a
regression.

No `scanDast` rate-limit flake, no `createFixPr`/`appRunner` Windows contention
flakes appeared in this run — those files were fully green here. All Semgrep
registry e2e suites (`rulePackFixture`, `evalVulnFixture`,
`validateFindingFixture`) passed, so the rule-pack path was genuinely exercised.

---

## Findings

### Important 1 — the skill's replacement text states a falsehood the branch's own measurements refute

**`skills/guardian-bugfix/SKILL.md:62`**

The old sentence pointed at `configs/semgrep/bugfix-*.yml`, which does not exist.
The replacement removes the dead path but asserts something stronger and untrue:

> …a tool `bug_hunt` já verificou isso … e **não encontrou, no registo, nenhum
> pack live que cubra null-safety, off-by-one, race conditions, memory leaks ou
> error handling engolido, em nenhuma linguagem.**

("found no live pack in the registry covering null-safety, off-by-one, race
conditions, memory leaks or swallowed error handling, **in any language**.")

My own sweep (doubt 6) shows `p/r2c-bug-scan` — which `bug_hunt` runs **by
default** — contains rules in **all five** of those named classes:
null_safety ×2, off_by_one ×2, race_condition ×1, memory_leak ×1 (+1 in
`p/security-audit`), error_handling ×2.

It also directly contradicts the tool description shipped in the *same commit*,
`mcp/src/tools/bugHunt.ts:359-360`:

> 'Only p/r2c-bug-scan (44 rules: 32 Python, 5 Go, 4 Java, 3 JS/TS) covers the
> six bug classes today, and thinly outside Python'

One commit, two artifacts, opposite claims.

**Concrete failure a user hits:** a model running `/guardian-fix` (which *is*
this skill) on a Python or Go project reads that no Semgrep automation exists for
these bug classes in any language, so it does not run `bug_hunt` or discounts its
output — and loses detection that demonstrably works. I caught
`list-modify-while-iterate → [bug/edge_case]` on a live run of exactly this
tool against exactly these classes.

The true statement is the narrow one the branch actually measured: *for JS/TS*
there are no bug-class rules (0 of 670); the Python/Go coverage is real but thin.

Two secondary weaknesses in the same sentence:

- It cites "o seu relatório de correção" as evidence.  That is
  `.superpowers/semgrep-pack-fix-report.md`, which is **untracked and not in
  commit `7daf379`** (`git ls-tree` finds nothing; it is not gitignored, just
  uncommitted). A reader following the citation finds nothing — a softer
  instance of the very defect being fixed.
- The same over-broad claim is repeated in a test comment,
  `mcp/test/integration/qualityTools.test.ts:715-716` ("None of the seven packs
  contain a rule for any of these four classes, in any language").

**Fix:** scope both to JS/TS, and drop or make resolvable the report citation.

### Important 2 — the partial-coverage banner now tells the user the findings are excluded when they are included

**`mcp/src/tools/bugHunt.ts:552`** (`missing_tools.push('semgrep')` in the
retry-succeeded branch), surfacing via `mcp/src/dashboard/renderHtml.ts:155`.

Round 1 correctly removed the pack-qualified `missing_tools` entry. But the
retry-**success** branch still pushes bare `'semgrep'` into `missing_tools`
while simultaneously recording `tools_run: [{name:'semgrep', status:'ok'}]`.
`missing_tools` is what the dashboard renders as "did not run".

Real dashboard, built from a real partial `bug_hunt` run that **did** produce a
finding:

```text
snapshot.findings.by_tool: {"semgrep": 1}          ← the finding IS counted
snapshot.risk.score: 13                            ← vs 8 for the same run with 0 findings
CLI:  MISSING  semgrep — static-analysis, … findings are NOT in these numbers
HTML: semgrep did not run this scan — static-analysis, … findings are NOT in these numbers.
```

Both halves of that sentence are false in this state: semgrep **did** run (its
own `tools_run.reason` says `"ran with p/r2c-bug-scan, p/security-audit only"`),
and its static-analysis findings **are** in the numbers — the snapshot
attributes one to it by name and the risk score moved because of it.

**Concrete failure a user hits:** a user (or model) reading the dashboard after
one pack retires is told semgrep did not run and that its findings are excluded,
so they discount or re-run a scan whose findings were in fact complete for the
two surviving packs. The gap is "one pack of three didn't resolve", not "semgrep
didn't run", and no field currently expresses that.

Direction of error is **conservative** (over-warns rather than under-warns), and
it is strictly better than the round-0 nonsense string, which is why this does
not block the merge. But it replaces vague nonsense with a precise falsehood, so
it should not be left standing. A correct fix is a design change (a
partial-degradation signal distinct from `missing_tools`), not a one-liner —
`computeCoverage` derives gaps from `missing_tools`/`failed` only, so simply
dropping the push would hide the gap entirely.

### Minor 3 — `p/javascript` and `p/typescript` are the same 74 rules; the "401 rules" figure double-counts them

**`mcp/src/tools/bugHunt.ts:158-164`, `:186-199`, `:352`**

Their rule-id sets are **identical** — 74 ids each, 0 unique to either
(verified by set difference in both directions). `fallbackLanguages` pushes
`javascript` *and* `typescript` for any project with `package.json` +
`tsconfig.json`, and `languagePacksFor` maps both, so an opted-in TS project
passes two `--config=` args for one rule set. Confirmed in real argv:
`--config=p/javascript --config=p/typescript`.

Consequence is wasted registry fetch and rule loading per scan, not wrong
results. But the description's "verified against **all 401** of their rules"
counts those 74 twice — the distinct surface is **327**. (The branch's own
report gives the 327 figure; the shipped user-facing string does not.)

### Minor 4 — pre-existing: a scan that produces no output file still reads as a clean bill of health

**`mcp/src/tools/bugHunt.ts:478-487`**

`if (raw) parser_inputs.push(...)` with `ok` derived from exit code alone. Forced
with a stub `semgrep` that exits 0 writing no `--output` file:

```text
coverage: full    missing_tools: []    tools_run: [{"name":"semgrep","status":"ok"}]
0 findings    warnings: []
```

A run that scanned nothing, reported as clean — the governing defect class.

**Not a regression:** byte-identical logic exists at `4fe1d06`, and the actual
`p/bugs` incident does not travel this path (semgrep exits 7 *and* writes the
`errors[]` JSON, which this branch now handles). The trigger is narrow and I had
to fake the binary to reach it. Flagged because the new header comment,
`bugHunt.ts:17-18`, states the guarantee absolutely — "never lets a run that
scanned nothing get reported as a clean bug report" — and this path still
violates it. Either narrow the comment or add a `raw === null` gap.

### Minor 5 — `categories` on a JS/TS project can only ever return zero

**`mcp/src/tools/bugHunt.ts:381-384`**

Across all 670 rules in all seven configurable packs, **zero** canonical
bug-class rules apply to JS/TS (doubt 6 sweep). So on this repo's own dominant
language, `categories: ['null_safety']` returns 0 findings with `coverage:
'full'` and no warning — indistinguishable from "no null-safety bugs". The
input's own `.describe()` uses `null_safety` as its worked example, which is
precisely the category that can never match there. The tool `description` does
warn in prose ("a quiet or security-only result … is not evidence of a bug-free
project"), which is why this is Minor rather than Important.

### Minor 6 — the same dangling-reference defect survives one file away (pre-existing, out of scope)

**`skills/guardian-init/SKILL.md:61,63,64,65`** — a "copy these templates" table
naming four sources that do not exist:

```text
configs/semgrep/<linguagem>.yml       → configs/semgrep/ has only base.yml, routes.yml
configs/pre-commit/<linguagem>.yaml   → configs/pre-commit/ has only pre-commit-config.yaml
workflows/github-actions/dev-guardian.yml → workflows/ does not exist at all
workflows/github-actions/e2e.yml          → workflows/ does not exist at all
```

Untouched by this branch and not its responsibility, but it is the identical
defect the branch set out to eliminate, and a model following `guardian-init`
hits it the same way.

---

## What I verified clean

- Working tree left clean; branch `fix/semgrep-retired-pack`; the only untracked
  path is `.superpowers/`, which was untracked before this review.
- Every mutation applied during review was reverted and the covering suite
  re-run green afterwards (136/136 across the six covering files).
