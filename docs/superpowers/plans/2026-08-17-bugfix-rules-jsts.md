# JS/TS Bug-Finding Rules Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fourteen locally-authored Semgrep rules that find JS/TS implementation bugs in the six classes that are expressible, loaded by `bug_hunt` by default, each proven by a fixture that makes it fire and a near-miss that must not.

> **Boxes reconciled against the code on 2026-08-22, not ticked during
> execution.** Nothing here was ticked while the work was done; every box was
> checked afterwards against the pack, the fixtures, the harness and the git
> history, so the ticks are an audit. Steps whose only product was a transient
> run — "Expected: FAIL", a mutation pasted into a task report — are ticked on
> the artefact they were meant to leave behind (the rule, the fixture, the
> assertion, the commit), never on the run itself, which leaves no trace.
>
> **This plan is not current, and is kept as the record of what was intended.**
> The pack shipped fourteen rules and has **thirteen**:
> `error-handling-catch-returns-null` was deleted in the audit wave of
> 2026-08-20 for having no measurable true-positive rate, and its fixture went
> with it. The deletion is recorded in the pack header
> (`configs/semgrep/bugfix-js.yml`, "DELETED (self-scan)") and in `CHANGELOG.md`;
> [the design of record](../specs/2026-08-17-bugfix-rules-jsts-design.md) still
> describes the rule and was never amended. The same wave dropped every tier in
> the pack to WARNING or INFO except `off-by-one-index-at-length`, so the
> `severity: ERROR` lines below are as-planned, not as-shipped, and it added the
> real-code ablation axis (`mcp/src` as the corpus) that caught
> `unchecked-match` at 0 → 13 false positives.

**Architecture:** One YAML file, `configs/semgrep/bugfix-js.yml`, in the style of the `base.yml` beside it. `bug_hunt` passes it as an additional absolute-path `--config`. Fixtures live in pairs under `mcp/test/fixtures/bugfix-js/`, and one test runs Semgrep against them asserting the **exact set** of rule ids that fire.

**Tech Stack:** Semgrep OSS (syntactic patterns; no taint mode required), TypeScript, vitest. No new runtime dependencies.

## Global Constraints

From the design of record (`docs/superpowers/specs/2026-08-17-bugfix-rules-jsts-design.md`) and `CLAUDE.md`:

- **Every rule ships with two fixtures: one that makes it fire, and one that looks like it and must not.** A rule without a near-miss fixture is not finished. This is the feature's success criterion, not a testing preference.
- **The test asserts the EXACT set of rule ids that fired**, never "at least one". A rule that starts matching its own near-miss must fail the suite rather than quietly widening.
- **Rule ids carry the class token**, because `mapSubcategory` (`mcp/src/tools/bugHunt.ts:317`) classifies by running regexes over the lowercased id. The six tokens: `race-condition`, `null-safety`, `off-by-one`, `memory-leak`, `error-handling`, `edge-case`. Format: `bugfix-js-<token>-<name>`.
- **Two severity tiers.** `ERROR` = the pattern is a bug regardless of intent. `WARNING`/`INFO` = usually a bug, but has legitimate uses.
- **Six of the seven classes are covered.** "Broken happy paths" is a category of consequence, not a syntactic shape; the docs say so rather than implying seven.
- Messages in **Portuguese**, matching `configs/semgrep/base.yml`.
- ESM `.js` import specifiers; `noUncheckedIndexedAccess`; **no `!`, no `any`** (tests too); **no new runtime dependencies**; `mcp/dist/` rebuilt and staged in the SAME commit as any `mcp/src/` change.

## Codebase facts, verified before this plan was written

- `BUG_HUNT_BASE_PACKS` is exported at `mcp/src/tools/bugHunt.ts:145` as `['p/r2c-bug-scan', 'p/security-audit']`; args are built at `:461` with `packs.map((pack) => '--config=' + pack)`. A local file joins that list as an absolute path.
- `bug_hunt` already handles a config that fails to load (`:518`) — a local file cannot 404, but the machinery is there.
- `resolveScriptsDir()` (`mcp/src/platform/scriptsDir.ts:49`) resolves a plugin-root-relative directory and **probes two candidates by marker file**, because callers differ by build (bundled vs unbundled). `configs/` needs the same treatment; do not hand-roll a second `..`-counting scheme.
- Semgrep-dependent tests use `const REQUIRE_SEMGREP = process.env['GUARDIAN_REQUIRE_SEMGREP'] === '1'` with `it.skipIf(!TOOLCHAIN_AVAILABLE)` and a `it.runIf(REQUIRE_SEMGREP)` guard test (`mcp/test/e2e/ciCliFixture.test.ts:110,802,813`). Follow that exactly.
- **Semgrep cannot be invoked through the Bash tool in this environment** — it returns `<ERROR: missing output>`. Use PowerShell. It is installed but not on PATH: `%APPDATA%\Roaming\Python\Python314\Scripts`.

## A deliberate limit on this plan's precision

Three of the fourteen patterns were **written and run** before this plan; those appear verbatim below. The other eleven are specified by **behaviour** — what must match, what must not — rather than by a pattern I have not tested.

That is deliberate. Writing an untested Semgrep pattern into a plan as though it were verified would be fabricating precision, which is the exact defect this whole feature exists to avoid. The fixture pair is what proves each rule; the implementer authors the pattern and the fixtures prove it.

---

## File Structure

| File | Responsibility |
| --- | --- |
| `configs/semgrep/bugfix-js.yml` | The fourteen rules. |
| `mcp/test/fixtures/bugfix-js/hits/*.ts` | One file per rule that must fire. |
| `mcp/test/fixtures/bugfix-js/misses/*.ts` | The near-miss for each rule, which must not. |
| `mcp/src/platform/configsDir.ts` | Resolve `configs/` from the plugin root, both builds. |
| `mcp/src/tools/bugHunt.ts` | Add the local config to the pack list. |
| `mcp/test/integration/bugfixRulesJs.test.ts` | Run Semgrep over the fixtures; assert the exact id set. |

---

### Task 1: The three proven rules, with their fixture pairs

**Files:**

- Create: `configs/semgrep/bugfix-js.yml`
- Create: `mcp/test/fixtures/bugfix-js/hits/error-handling.ts`, `off-by-one.ts`, `race-condition.ts`
- Create: `mcp/test/fixtures/bugfix-js/misses/error-handling.ts`, `off-by-one.ts`, `race-condition.ts`
- Test: `mcp/test/integration/bugfixRulesJs.test.ts`

**Interfaces:**

- Produces: the rule ids `bugfix-js-error-handling-empty-catch`, `bugfix-js-off-by-one-loop-lte-length`, `bugfix-js-race-condition-floating-mutation`, and the fixture-directory layout every later task extends.

- [x] **Step 1: Write the fixture pairs first**

The hits, `mcp/test/fixtures/bugfix-js/hits/error-handling.ts`:

```ts
export function swallows(): void {
  try { risky(); } catch (e) { }
}
function risky(): void { throw new Error('x'); }
```

`hits/off-by-one.ts`:

```ts
export function readsPastEnd(items: number[]): void {
  for (let i = 0; i <= items.length; i++) { console.log(items[i]); }
}
```

`hits/race-condition.ts`:

```ts
export async function handler(repo: { save(v: unknown): Promise<void> }): Promise<string> {
  repo.save({ id: 1 });
  return 'ok';
}
```

The near-misses — **these are the half that decides whether the feature helps**.
`misses/error-handling.ts`:

```ts
export function rethrows(): void {
  try { risky(); } catch (e) { throw e; }          // handled, not swallowed
}
export function logsAndHandles(): void {
  try { risky(); } catch (e) { console.error(e); recover(); }
}
function risky(): void { throw new Error('x'); }
function recover(): void {}
```

`misses/off-by-one.ts`:

```ts
export function correct(items: number[]): void {
  for (let i = 0; i < items.length; i++) { console.log(items[i]); }
}
export function writesToLength(items: number[]): void {
  items[items.length] = 4;                          // appending, legitimate
}
```

`misses/race-condition.ts`:

```ts
export async function awaited(repo: { save(v: unknown): Promise<void> }): Promise<void> {
  await repo.save({ id: 1 });
}
export async function returned(repo: { save(v: unknown): Promise<void> }): Promise<void> {
  return repo.save({ id: 1 });
}
export async function deliberate(logger: { write(v: string): Promise<void> }): Promise<void> {
  logger.write('fire and forget');                  // NOT a mutating verb
}
```

- [x] **Step 2: Write the failing test**

`mcp/test/integration/bugfixRulesJs.test.ts`:

```ts
import { describe, expect, it } from 'vitest';
import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = resolve(fileURLToPath(new URL('../../..', import.meta.url)));
const RULES = resolve(REPO_ROOT, 'configs', 'semgrep', 'bugfix-js.yml');
const FIXTURES = resolve(REPO_ROOT, 'mcp', 'test', 'fixtures', 'bugfix-js');
const REQUIRE_SEMGREP = process.env['GUARDIAN_REQUIRE_SEMGREP'] === '1';

function semgrepAvailable(): boolean {
  try { execFileSync('semgrep', ['--version'], { stdio: 'ignore' }); return true; }
  catch { return false; }
}
const AVAILABLE = semgrepAvailable();

interface SemgrepResult { check_id: string; path: string }

function run(dir: string): SemgrepResult[] {
  const out = execFileSync(
    'semgrep',
    ['--config', RULES, '--json', '--quiet', '--no-git-ignore', dir],
    { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 },
  );
  const parsed: unknown = JSON.parse(out);
  const results = (parsed as { results?: unknown[] }).results ?? [];
  return results as SemgrepResult[];
}

/** Last dot-separated segment — semgrep prefixes the config path onto ids. */
function ids(rows: readonly SemgrepResult[]): string[] {
  return [...new Set(rows.map((r) => r.check_id.split('.').pop() ?? r.check_id))].sort();
}

describe('bugfix-js rules', () => {
  it.runIf(REQUIRE_SEMGREP)('the toolchain must be usable when the flag is set', () => {
    expect(AVAILABLE).toBe(true);
  });

  it('the rule file exists where bug_hunt will look for it', () => {
    expect(existsSync(RULES)).toBe(true);
  });

  it.skipIf(!AVAILABLE)('fires exactly the expected rules on the hit fixtures', () => {
    // EXACT set, not "at least". A rule that widens to catch something it was
    // not written for fails here rather than reaching a user as noise.
    expect(ids(run(resolve(FIXTURES, 'hits')))).toEqual([
      'bugfix-js-error-handling-empty-catch',
      'bugfix-js-off-by-one-loop-lte-length',
      'bugfix-js-race-condition-floating-mutation',
    ]);
  });

  it.skipIf(!AVAILABLE)('fires NOTHING on the near-miss fixtures', () => {
    // The half of the proof that decides whether this feature helps or hurts.
    // A rethrowing catch, an append at index length, an awaited save and a
    // deliberate fire-and-forget log are all correct code that looks like a bug.
    expect(ids(run(resolve(FIXTURES, 'misses')))).toEqual([]);
  });
});
```

- [x] **Step 3: Run to verify it fails**

Run (PowerShell): `cd mcp; npx vitest run test/integration/bugfixRulesJs.test.ts`
Expected: FAIL — the rule file does not exist.

- [x] **Step 4: Write the three rules**

> **Tiers superseded (2026-08-20 audit wave).** `empty-catch` and
> `loop-lte-length` both ship at WARNING now, not ERROR: the wave replaced
> "is this a bug regardless of intent?" with a criterion measured against real
> code. See the header of `configs/semgrep/bugfix-js.yml`.

`configs/semgrep/bugfix-js.yml`, header comment in the style of `base.yml`, then:

```yaml
rules:
  - id: bugfix-js-error-handling-empty-catch
    patterns:
      - pattern-either:
          - pattern: try { ... } catch ($E) { }
          - pattern: $P.catch(() => {})
          - pattern: $P.catch(function ($E) {})
    message: >-
      Erro engolido em silêncio. O bloco catch está vazio, por isso a falha
      desaparece sem log, sem rethrow e sem tratamento.
    severity: ERROR
    languages: [javascript, typescript]

  - id: bugfix-js-off-by-one-loop-lte-length
    pattern: for (...; $I <= $A.length; ...) { ... }
    message: >-
      Provável off-by-one: a condição usa <= com .length, por isso a última
      iteração lê $A[$A.length], que é sempre undefined.
    severity: ERROR
    languages: [javascript, typescript]

  - id: bugfix-js-race-condition-floating-mutation
    patterns:
      - pattern: $O.$M(...)
      - pattern-inside: |
          async function $F(...) { ... }
      - metavariable-regex:
          metavariable: $M
          regex: ^(save|update|delete|create|insert|write|commit|send)$
      - pattern-not: await $O.$M(...)
      - pattern-not: return $O.$M(...)
    message: >-
      Chamada que altera estado sem await. Quem chama continua como se a
      escrita tivesse terminado — é ao mesmo tempo uma race e um happy path
      partido. Se for intencional, torne-o explícito com void.
    severity: WARNING
    languages: [javascript, typescript]
```

- [x] **Step 5: Run to verify it passes**

Run (PowerShell): `cd mcp; npx vitest run test/integration/bugfixRulesJs.test.ts`
Expected: PASS, both fixture assertions.

**If the near-miss test fails, the rule is wrong — not the fixture.** Narrow the
pattern. The `misses` file is the specification of what correct code looks like.

- [x] **Step 6: Commit**

```bash
git add configs/semgrep mcp/test
git commit -m "feat(bugfix-rules): the three proven JS/TS rules, with near-miss fixtures"
```

---

### Task 2: The remaining eleven rules

**Files:**

- Modify: `configs/semgrep/bugfix-js.yml`
- Create: fixture pairs under `mcp/test/fixtures/bugfix-js/hits/` and `misses/`
- Modify: `mcp/test/integration/bugfixRulesJs.test.ts` (extend the expected id set)

**Interfaces:**

- Consumes: the file and fixture layout from Task 1.
- Produces: the full fourteen-rule set.

Each rule below is specified by **what must fire and what must not**. Author the
pattern, then let the fixture pair prove it. Add each rule's id to the expected
set in the exact-match test as you go, so the set is always complete.

- [x] **Step 1: `error_handling`, two more (ERROR)**

> **Half superseded.** Both rules were written, with their fixtures, and
> `empty-promise-catch` still ships (at WARNING). `catch-returns-null` was
> **deleted** in the 2026-08-20 audit wave — no measurable true-positive rate —
> together with `hits/catch-returns-null.ts`. The deletion note sits where the
> rule used to be, in `configs/semgrep/bugfix-js.yml`.

`bugfix-js-error-handling-empty-promise-catch` — already folded into Task 1's
`empty-catch` via `pattern-either`. **Split it into its own rule** so its id is
distinct and its classification is independently asserted; Task 1 grouped them
only to keep the first test small.

`bugfix-js-error-handling-catch-returns-null` — a `catch` whose only statement
is `return null`, `return undefined` or `return []`.
Must fire: `try { … } catch (e) { return null; }`.
Must not: a `catch` that logs *and* returns null; a `catch` that returns a
typed error result. The near-miss matters because "log then return null" is a
deliberate pattern.

- [x] **Step 2: `off_by_one`, one more (ERROR)**

`bugfix-js-off-by-one-index-at-length` — `$A[$A.length]`.
Must fire: `const last = items[items.length];`.
Must not: `items[items.length] = 4;` — an append. **Read, not write.** This is
the distinction the rule turns on, and Task 1's `misses/off-by-one.ts` already
contains the write case, so it will catch a rule that ignores it.

- [x] **Step 3: `null_safety`, three rules**

`bugfix-js-null-safety-unchecked-find` (ERROR) — `$A.find(...).$PROP`.
Must fire: `users.find((u) => u.id === id).name`.
Must not: `users.find(...)?.name`; a `find` result assigned and guarded before use.

`bugfix-js-null-safety-unchecked-match` (ERROR) — `$S.match(...)[$I]`.
Must fire: `s.match(/x/)[1]`.
Must not: `s.match(/x/)?.[1]`; a match result checked before indexing.

`bugfix-js-null-safety-unchecked-env` (WARNING) — a method called on
`process.env.$X`.
Must fire: `process.env.API_URL.trim()`.
Must not: `process.env.API_URL?.trim()`; `(process.env.API_URL ?? '').trim()`.

**Note the id collision the design records:** these three contain the word
`unchecked`, which `mapSubcategory`'s `error_handling` regex also matches. They
classify as `null_safety` only because that branch is tested first. Step 6's
classification test is what keeps that true.

- [x] **Step 4: `memory_leak`, three rules**

`bugfix-js-memory-leak-listener-without-cleanup` (ERROR) — a `useEffect` that
calls `addEventListener` and returns no cleanup.
Must fire: `useEffect(() => { window.addEventListener('resize', onResize); }, []);`.
Must not: the same with `return () => window.removeEventListener('resize', onResize);`.

`bugfix-js-memory-leak-interval-without-clear` (WARNING) — `setInterval` whose
handle is never passed to `clearInterval` in the same function.
Must fire: `const t = setInterval(tick, 1000);` with no `clearInterval(t)`.
Must not: the same followed by a `clearInterval(t)`, and a `useEffect` returning one.

`bugfix-js-memory-leak-subscribe-without-unsubscribe` (WARNING) — `.subscribe(…)`
inside a `useEffect` with no returned teardown.
Must fire / must not: mirror the listener rule.

- [x] **Step 5: `edge_case`, two rules**

`bugfix-js-edge-case-reduce-without-initial` (WARNING) — `.reduce($F)` with no
second argument, which throws on an empty array.
Must fire: `items.reduce((a, b) => a + b)`.
Must not: `items.reduce((a, b) => a + b, 0)`.

`bugfix-js-edge-case-parseint-without-radix` (INFO) — `parseInt($S)` with one
argument.
Must fire: `parseInt(raw)`.
Must not: `parseInt(raw, 10)`; `Number(raw)`.

- [x] **Step 6: Assert every id classifies as its class**

> **Superseded in one entry.** The test exists and is exhaustive, but it maps
> **thirteen** ids today, not fourteen: the
> `bugfix-js-error-handling-catch-returns-null` line below went when the rule
> did. The `unchecked` collision test it also specifies is unchanged and still
> guards the ordering in `mapSubcategory`.

Add to `bugfixRulesJs.test.ts`:

```ts
import { mapSubcategory } from '../../src/tools/bugHunt.js';

const EXPECTED_CLASS: Readonly<Record<string, string>> = {
  'bugfix-js-error-handling-empty-catch': 'error_handling',
  'bugfix-js-error-handling-empty-promise-catch': 'error_handling',
  'bugfix-js-error-handling-catch-returns-null': 'error_handling',
  'bugfix-js-off-by-one-loop-lte-length': 'off_by_one',
  'bugfix-js-off-by-one-index-at-length': 'off_by_one',
  'bugfix-js-null-safety-unchecked-find': 'null_safety',
  'bugfix-js-null-safety-unchecked-match': 'null_safety',
  'bugfix-js-null-safety-unchecked-env': 'null_safety',
  'bugfix-js-memory-leak-listener-without-cleanup': 'memory_leak',
  'bugfix-js-memory-leak-interval-without-clear': 'memory_leak',
  'bugfix-js-memory-leak-subscribe-without-unsubscribe': 'memory_leak',
  'bugfix-js-race-condition-floating-mutation': 'race_condition',
  'bugfix-js-edge-case-reduce-without-initial': 'edge_case',
  'bugfix-js-edge-case-parseint-without-radix': 'edge_case',
};

describe('every rule id classifies as its own class', () => {
  it('maps all fourteen', () => {
    for (const [id, cls] of Object.entries(EXPECTED_CLASS)) {
      expect(mapSubcategory(id, undefined)).toBe(cls);
    }
  });

  it('the three "unchecked" ids classify as null_safety, not error_handling', () => {
    // mapSubcategory's error_handling regex matches the bare word `unchecked`.
    // These three win only because null_safety is tested earlier in the chain.
    // If that order ever changes, this fails instead of silently reclassifying.
    for (const id of [
      'bugfix-js-null-safety-unchecked-find',
      'bugfix-js-null-safety-unchecked-match',
      'bugfix-js-null-safety-unchecked-env',
    ]) {
      expect(mapSubcategory(id, undefined)).toBe('null_safety');
    }
  });
});
```

- [x] **Step 7: Run everything, then commit**

Run (PowerShell): `cd mcp; npx vitest run test/integration/bugfixRulesJs.test.ts`
Expected: PASS — fourteen ids on `hits`, **zero** on `misses`, fourteen correct classes.

```bash
git add configs/semgrep mcp/test
git commit -m "feat(bugfix-rules): the remaining eleven rules and their near-misses"
```

---

### Task 3: Load the rules from `bug_hunt`

**Files:**

- Create: `mcp/src/platform/configsDir.ts`
- Modify: `mcp/src/tools/bugHunt.ts`
- Test: `mcp/test/unit/platform/configsDir.test.ts`, `mcp/test/unit/tools/bugHuntConfigs.test.ts`

**Interfaces:**

```ts
// configsDir.ts — mirrors resolveScriptsDir's two-candidate probe
export function resolveConfigsDir(): string;
/** Absolute path to configs/semgrep/bugfix-js.yml, or null if absent. */
export function resolveBugfixRules(): string | null;
```

- [x] **Step 1: Write the failing tests**

```ts
import { describe, expect, it } from 'vitest';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { resolveConfigsDir, resolveBugfixRules } from '../../../src/platform/configsDir.js';

describe('resolveConfigsDir', () => {
  it('resolves to a directory that actually holds base.yml', () => {
    // The marker-file probe, not a `..` count: resolveScriptsDir exists because
    // the same code runs bundled and unbundled, at different depths.
    expect(existsSync(resolve(resolveConfigsDir(), 'semgrep', 'base.yml'))).toBe(true);
  });

  it('returns the bugfix rule path when the file is there', () => {
    const p = resolveBugfixRules();
    expect(p).not.toBeNull();
    expect(existsSync(p ?? '')).toBe(true);
  });
});
```

And in `bugHuntConfigs.test.ts`:

```ts
import { describe, expect, it } from 'vitest';
import { isAbsolute } from 'node:path';
import { buildPackList, BUG_HUNT_BASE_PACKS } from '../../../src/tools/bugHunt.js';

describe('bug_hunt config list', () => {
  it('includes the local bugfix rules by default, as an absolute path', () => {
    // Registry packs can 404 -- one did, and it took the whole tool down. A
    // local file cannot, so these rules must be in the DEFAULT set.
    const packs = buildPackList({ includeLanguagePacks: false, languages: ['typescript'] });
    const local = packs.find((p) => p.includes('bugfix-js.yml'));
    expect(local).toBeTruthy();
    expect(isAbsolute(local ?? '')).toBe(true);
  });

  it('still lists the base registry packs alongside it', () => {
    const packs = buildPackList({ includeLanguagePacks: false, languages: ['typescript'] });
    expect(packs).toEqual(expect.arrayContaining([...BUG_HUNT_BASE_PACKS]));
  });

  it('omits the local rules rather than passing a bad path when the file is missing', () => {
    // A --config pointing at a nonexistent file aborts the whole semgrep run --
    // exactly the p/bugs failure, reproduced locally.
    const packs = buildPackList({ includeLanguagePacks: false, languages: ['typescript'],
      bugfixRulesPath: null });
    expect(packs.some((p) => p.includes('bugfix-js.yml'))).toBe(false);
  });
});
```

- [x] **Step 2: Run to verify they fail**

Run (PowerShell): `cd mcp; npx vitest run test/unit/platform/configsDir.test.ts test/unit/tools/bugHuntConfigs.test.ts`
Expected: FAIL — modules/exports not found.

- [x] **Step 3: Implement**

`configsDir.ts` follows `mcp/src/platform/scriptsDir.ts:49`'s **two-candidate
marker probe** — `semgrep/base.yml` is the marker. Do not count `..` segments;
that is what the probe exists to avoid.

In `bugHunt.ts`, extract the pack-list construction into an exported
`buildPackList` so it is testable without running Semgrep, and append the local
rules path when `resolveBugfixRules()` returns non-null.

- [x] **Step 4: Run to verify they pass, then the suite**

Run (PowerShell): `cd mcp; npx vitest run test/unit; npm test`
Expected: PASS.

- [x] **Step 5: Build and commit**

```bash
cd mcp && npm run build
cd .. && git add mcp/src mcp/test mcp/dist
git commit -m "feat(bugfix-rules): bug_hunt loads the local rules by default"
```

---

### Task 4: Documentation and the gate

**Files:**

- Modify: `skills/guardian-bugfix/SKILL.md`, `README.md` (EN/PT/ES), `CHANGELOG.md`, `mcp/src/tools/bugHunt.ts` (description)

- [x] **Step 1: Make the skill's original promise true**

`skills/guardian-bugfix/SKILL.md` was corrected in 1.5.0 to say no such rule
pack existed. It does now. Update it to name `configs/semgrep/bugfix-js.yml`,
say which six classes it covers **and that JS/TS is the only language so far**.

- [x] **Step 2: Update `bug_hunt`'s description**

It currently states the JS/TS bug-class gap as a fact, with measurements. That
is about to be partly false. Rewrite it to say what the local rules now cover,
that the registry packs still contribute nothing in these classes for JS/TS, and
that other languages remain uncovered by local rules.

- [x] **Step 3: README in all three languages, and the CHANGELOG**

State plainly: six of the seven named classes; "broken happy paths" is not a
syntactic shape; Semgrep OSS matches syntax, not dataflow; the heuristic tier
produces false positives by construction, which is why it is `WARNING`; JS/TS
only so far.

- [x] **Step 4: Full verification gate**

```bash
cd mcp; npm run build
cd mcp; $env:GUARDIAN_REQUIRE_SEMGREP=1; npm test
cd mcp; $env:GUARDIAN_REQUIRE_SEMGREP=1; npm run test:coverage
cd ..; npx markdownlint-cli2 "skills/**/*.md" "commands/**/*.md" "README.md"
```

PowerShell, because Semgrep cannot be invoked through Bash here. Report the exact
skip count (**target zero**) and all four coverage numbers against 70/62/72/70.

- [x] **Step 5: Commit**

```bash
git add -A
git commit -m "docs(bugfix-rules): document what the JS/TS rules cover and what they do not"
```

---

## Self-Review Notes

Checked against the spec:

- §1 the gap and its measurements → Task 4's docs carry them.
- §2 the two-fixture rule → Tasks 1 and 2, enforced by the exact-set assertions
  in both directions.
- §3 two tiers → the `severity:` field on each rule in Tasks 1 and 2.
- §4 fourteen rules, the token table, the `unchecked` collision → Tasks 1, 2 and
  Task 2 Step 6's dedicated classification test.
- §5 file location and default loading → Task 3, including the missing-file case,
  because a bad `--config` path reproduces the exact `p/bugs` failure locally.
- §6 testing, exact set, skip behaviour → Task 1 Step 2's harness.
- §7 limitations → Task 4 Step 3.

Type consistency: `mapSubcategory` is imported in Task 2 with the signature it
has today, `(ruleId: string, existing: string | undefined) => string | undefined`.
`buildPackList` is created in Task 3 and used only there. `resolveBugfixRules`
returns `string | null`, and Task 3's third test pins the `null` path.

One deliberate imprecision, recorded rather than hidden: eleven of the fourteen
patterns are specified by behaviour rather than given verbatim, because they have
not been run. Writing an untested pattern as though it were verified is the
defect this feature exists to prevent.
