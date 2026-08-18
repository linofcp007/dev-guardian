# Go bug-finding Semgrep rules — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `configs/semgrep/bugfix-go.yml` — ten hand-authored Semgrep rules
covering all six `bug_hunt` bug subcategories for Go.

**Architecture:** A plain Semgrep YAML rule file beside `bugfix-js.yml` and
`bugfix-py.yml`, with a hit fixture and a near-miss fixture per rule, and an
integration test asserting the exact rule ids, the raw finding count, and the
scanned-file count per file. **No wiring is needed**: `resolveBugfixRules()`
became plural in 1.7.0 and returns every `configs/semgrep/bugfix-*.yml`.

**Tech Stack:** Semgrep OSS 1.164.0 (pattern rules, no dataflow), TypeScript
(ESM, NodeNext), vitest.

**Spec:** `docs/superpowers/specs/2026-08-18-bugfix-rules-go-design.md` — read
it, especially §8, which records what measurement changed and which two
"defensive" exclusions were proven to be no-ops.

## Global Constraints

- **Every rule's YAML and every fixture in this plan has been run against the
  others with Semgrep 1.164.0 and verified.** Use them verbatim. Changing a
  pattern means you own re-proving both halves: it fires on the hit fixture and
  is silent on the near-miss.
- **Do NOT add "defensive" exclusion clauses.** Two were measured to be no-ops
  (spec §8): the type-assertion rule needs no type-switch exclusion, and
  `err-discarded` needs no map/channel/type-assert exclusion because
  `$F(...)` requires a function *call*. A clause that reads as a guard and does
  nothing is this repo's signature defect.
- **Semgrep is installed but NOT on PATH:**
  `C:\Users\Administrator\AppData\Roaming\Python\Python314\Scripts\semgrep.exe`.
  Prepend that directory to `PATH` before running the suite, or every Semgrep
  test SKIPS and you read a green suite that proved nothing.
- **Semgrep cannot be invoked through the Bash tool** (returns
  `<ERROR: missing output>`). Use PowerShell for any direct Semgrep run.
- **Verify with `GUARDIAN_REQUIRE_SEMGREP=1`.** Report pass and skip counts; a
  run with skips is not a passing run.
- **Rule id format** `bugfix-go-<class-token>-<name>`, where `<class-token>` is
  one of exactly `race-condition`, `null-safety`, `off-by-one`, `memory-leak`,
  `error-handling`, `edge-case`. `mapSubcategory` classifies by regex over the
  lowercased id, not a lookup table.
- **No id may contain `unchecked`** — the `error_handling` regex matches it.
- **Rule messages in Portuguese**, matching `base.yml`, `bugfix-js.yml`,
  `bugfix-py.yml`.
- **Temp directories:** use `makeTempDir(prefix)` and `afterAll(cleanupTempDirs)`
  from `mcp/test/helpers/tempDir.ts`. Never a bare `mkdtempSync` — 28 of 36
  files once leaked 48,719 directories in a week.
- **TypeScript:** ESM `NodeNext` (`.js` specifiers), `noUncheckedIndexedAccess`,
  **no `!` non-null assertions, no `any`** — both are at zero repo-wide, so a
  reappearance is a regression. See CLAUDE.md's "TypeScript conventions".
- **`npm run lint` runs both `tsconfig.json` and `tsconfig.test.json`** and must
  stay clean.
- Build and test from `mcp/`. **Tasks 1-4 touch no `mcp/src/`**, so they need no
  `dist/` rebuild — confirm that is still true of your actual changes before
  committing. **Task 5 is the exception**: it edits `mcp/src/tools/bugHunt.ts`,
  so it MUST run `npm run build` and stage `mcp/dist/` in the same commit. The
  repo is the distribution and Claude Code runs `mcp/dist/server.js` directly, so
  a stale `dist/` silently desyncs from `src/`.

---

### Task 1: Rule file, test harness, and the three `error_handling` rules

**Files:**
- Create: `configs/semgrep/bugfix-go.yml`
- Create: `mcp/test/fixtures/bugfix-go/hits/err_discarded.go`
- Create: `mcp/test/fixtures/bugfix-go/misses/err_discarded.go`
- Create: `mcp/test/fixtures/bugfix-go/hits/err_blank_assign.go`
- Create: `mcp/test/fixtures/bugfix-go/misses/err_blank_assign.go`
- Create: `mcp/test/fixtures/bugfix-go/hits/empty_err_block.go`
- Create: `mcp/test/fixtures/bugfix-go/misses/empty_err_block.go`
- Create: `mcp/test/integration/bugfixRulesGo.test.ts`

**Interfaces:**
- Consumes: `mapSubcategory(ruleId: string, existing: string | undefined): string | undefined`
  from `../../src/tools/bugHunt.js`; `makeTempDir(prefix: string): string` and
  `cleanupTempDirs(): void` from `../helpers/tempDir.js`.
- Produces: `configs/semgrep/bugfix-go.yml` with one `rules:` list, extended by
  Tasks 2-4. `mcp/test/integration/bugfixRulesGo.test.ts` owning two
  module-level maps that Tasks 2-4 extend:
  `EXPECTED_HITS_BY_FILE: Readonly<Record<string, { ids: readonly string[]; count: number }>>`
  and `EXPECTED_CLASS: Readonly<Record<string, string>>`, plus a
  `run(config: string, dir: string): SemgrepRun` helper returning
  `{ rows: SemgrepResult[]; scanned: number }`.

- [ ] **Step 1: Write the three hit fixtures**

`mcp/test/fixtures/bugfix-go/hits/err_discarded.go`:

```go
package hits

import "os"

func readIgnoringError(path string) []byte {
	data, _ := os.ReadFile(path)
	return data
}
```

`mcp/test/fixtures/bugfix-go/hits/err_blank_assign.go`:

```go
package hits

import "os"

func removeIgnoringError(path string) {
	_ = os.Remove(path)
}
```

`mcp/test/fixtures/bugfix-go/hits/empty_err_block.go`:

```go
package hits

import "os"

func swallowError(path string) {
	err := os.Remove(path)
	if err != nil {
	}
}
```

- [ ] **Step 2: Write the three near-miss fixtures**

`mcp/test/fixtures/bugfix-go/misses/err_discarded.go`. The last three functions
are the load-bearing part: Go uses `x, _ :=` idiomatically where the discarded
value is an ok-bool, not an error.

```go
package misses

import "os"

func readCheckingError(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func mapLookupOk(m map[string]int) int {
	v, _ := m["k"]
	return v
}

func channelRecvOk(ch chan int) int {
	v, _ := <-ch
	return v
}

func typeAssertOk(x interface{}) string {
	s, _ := x.(string)
	return s
}
```

`mcp/test/fixtures/bugfix-go/misses/err_blank_assign.go`:

```go
package misses

import "os"

func removeLoggingError(path string) {
	if err := os.Remove(path); err != nil {
		println(err.Error())
	}
}
```

`mcp/test/fixtures/bugfix-go/misses/empty_err_block.go`:

```go
package misses

import "os"

func handleError(path string) error {
	err := os.Remove(path)
	if err != nil {
		return err
	}
	return nil
}
```

- [ ] **Step 3: Write the test harness with only the Task 1 expectations**

Create `mcp/test/integration/bugfixRulesGo.test.ts`. Read
`mcp/test/integration/bugfixRulesPy.test.ts` first — this mirrors it, and its
module comment records why each assertion exists.

```typescript
/**
 * Runs the local `bugfix-go.yml` rules against the fixture pairs in
 * `mcp/test/fixtures/bugfix-go/{hits,misses}/` and asserts, per file, the
 * EXACT set of rule ids, the RAW non-deduplicated finding count, and the
 * number of files Semgrep actually scanned.
 *
 * All three matter, and each was added because the weaker version passed for
 * the wrong reason at least once in this repo:
 *
 *  - The id set alone cannot prove a particular instance still matches while
 *    a sibling instance of the same rule survives in the same file.
 *  - `paths.scanned` closes the worst case: Semgrep exits 0 with empty
 *    results when it scans nothing, so "found nothing" and "looked at
 *    nothing" are otherwise byte-identical. Pointed at the in-repo fixture
 *    path — which contains a `test/` segment that Semgrep's default ignore
 *    list skips wholesale — it reports `paths.scanned: []` and zero results
 *    regardless of the rules. That is why fixtures are copied to a temp dir
 *    first, and asserting the count is what proves the copy still works.
 *
 * SKIPPED, not silently passed, when Semgrep is absent;
 * `GUARDIAN_REQUIRE_SEMGREP=1` turns that absence into a hard failure.
 */

import { afterAll, describe, expect, it } from 'vitest';
import { execFileSync } from 'node:child_process';
import { cpSync, existsSync, readdirSync } from 'node:fs';
import { basename, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { mapSubcategory } from '../../src/tools/bugHunt.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

afterAll(cleanupTempDirs);

const REPO_ROOT = resolve(fileURLToPath(new URL('../../..', import.meta.url)));
const RULES = resolve(REPO_ROOT, 'configs', 'semgrep', 'bugfix-go.yml');
const FIXTURES = resolve(REPO_ROOT, 'mcp', 'test', 'fixtures', 'bugfix-go');
const REQUIRE_SEMGREP = process.env['GUARDIAN_REQUIRE_SEMGREP'] === '1';

function semgrepAvailable(): boolean {
  try { execFileSync('semgrep', ['--version'], { stdio: 'ignore' }); return true; }
  catch { return false; }
}
const AVAILABLE = semgrepAvailable();

interface SemgrepResult { check_id: string; path: string }

interface SemgrepRun {
  readonly rows: SemgrepResult[];
  /** Files Semgrep actually scanned — asserted by every caller. */
  readonly scanned: number;
}

function run(config: string, dir: string): SemgrepRun {
  const work = makeTempDir('guardian-bugfix-go-');
  cpSync(dir, work, { recursive: true });
  const out = execFileSync(
    'semgrep',
    ['--config', config, '--json', '--quiet', '--no-git-ignore', work],
    { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 },
  );
  const parsed: unknown = JSON.parse(out);
  const results = (parsed as { results?: unknown[] }).results ?? [];
  const scanned = (parsed as { paths?: { scanned?: unknown[] } }).paths?.scanned ?? [];
  return { rows: results as SemgrepResult[], scanned: scanned.length };
}

/** Last dot-separated segment — semgrep prefixes the config path onto ids. */
function ids(rows: readonly SemgrepResult[]): string[] {
  return [...new Set(rows.map((r) => r.check_id.split('.').pop() ?? r.check_id))].sort();
}

/** Groups RAW rows (no dedup) by basename — the full path is a fresh temp dir. */
function rowsByFile(rows: readonly SemgrepResult[]): Record<string, SemgrepResult[]> {
  const byFile: Record<string, SemgrepResult[]> = {};
  for (const row of rows) {
    const file = basename(row.path);
    const existing = byFile[file];
    if (existing) existing.push(row);
    else byFile[file] = [row];
  }
  return byFile;
}

function fixtureFiles(dir: string): string[] {
  return readdirSync(dir).filter((name) => name.endsWith('.go')).sort();
}

interface FileExpectation {
  readonly ids: readonly string[];
  readonly count: number;
}

const EXPECTED_HITS_BY_FILE: Readonly<Record<string, FileExpectation>> = {
  'empty_err_block.go': { ids: ['bugfix-go-error-handling-empty-err-block'], count: 1 },
  'err_blank_assign.go': { ids: ['bugfix-go-error-handling-err-blank-assign'], count: 1 },
  'err_discarded.go': { ids: ['bugfix-go-error-handling-err-discarded'], count: 1 },
};

describe('bugfix-go rules', () => {
  it.runIf(REQUIRE_SEMGREP)('the toolchain must be usable when the flag is set', () => {
    expect(AVAILABLE).toBe(true);
  });

  it('the rule file exists where bug_hunt will look for it', () => {
    expect(existsSync(RULES)).toBe(true);
  });

  it.skipIf(!AVAILABLE)(
    'Step 0: every hits/ fixture on disk has a registered expectation, and vice versa',
    () => {
      expect(fixtureFiles(resolve(FIXTURES, 'hits'))).toEqual(
        Object.keys(EXPECTED_HITS_BY_FILE).sort(),
      );
    },
  );

  it.skipIf(!AVAILABLE)(
    'fires exactly the expected rule, exactly the expected number of times, in EACH hit fixture',
    () => {
      const hitsDir = resolve(FIXTURES, 'hits');
      const { rows, scanned } = run(RULES, hitsDir);
      expect(scanned).toBe(fixtureFiles(hitsDir).length);
      const grouped = rowsByFile(rows);
      for (const [file, expected] of Object.entries(EXPECTED_HITS_BY_FILE)) {
        const fileRows = grouped[file] ?? [];
        expect(ids(fileRows)).toEqual(expected.ids);
        expect(fileRows.length).toBe(expected.count);
      }
    },
  );

  it.skipIf(!AVAILABLE)('fires NOTHING in EACH near-miss fixture', () => {
    const missesDir = resolve(FIXTURES, 'misses');
    const { rows, scanned } = run(RULES, missesDir);
    expect(scanned).toBe(fixtureFiles(missesDir).length);
    const grouped = rowsByFile(rows);
    for (const file of fixtureFiles(missesDir)) {
      expect(grouped[file] ?? []).toEqual([]);
    }
  });
});

/** Rule ids carry the class token because `mapSubcategory` classifies by regex
 *  over the lowercased id. Runs unconditionally — pure function, no Semgrep. */
const EXPECTED_CLASS: Readonly<Record<string, string>> = {
  'bugfix-go-error-handling-err-discarded': 'error_handling',
  'bugfix-go-error-handling-err-blank-assign': 'error_handling',
  'bugfix-go-error-handling-empty-err-block': 'error_handling',
};

describe('every rule id classifies as its own class', () => {
  it('maps every id in the file', () => {
    for (const [id, cls] of Object.entries(EXPECTED_CLASS)) {
      expect(mapSubcategory(id, undefined)).toBe(cls);
    }
  });

  it('no id contains the word "unchecked"', () => {
    // The error_handling regex matches a bare `unchecked`. The JS/TS set has
    // three null_safety ids that classify correctly only because null_safety
    // is tested earlier in the if-chain. Not taken on again here.
    for (const id of Object.keys(EXPECTED_CLASS)) {
      expect(id).not.toContain('unchecked');
    }
  });
});
```

- [ ] **Step 4: Run the test to verify it fails**

```powershell
$env:PATH = "C:\Users\Administrator\AppData\Roaming\Python\Python314\Scripts;$env:PATH"
$env:GUARDIAN_REQUIRE_SEMGREP = "1"
cd mcp
npx vitest run test/integration/bugfixRulesGo.test.ts
```

Expected: FAIL — `configs/semgrep/bugfix-go.yml` does not exist yet.

- [ ] **Step 5: Write the rule file with the three `error_handling` rules**

```yaml
# dev-guardian Semgrep config bugfix-go.
# Bugs de implementação em Go. É a linguagem com o maior buraco de toda a
# sequência: o p/r2c-bug-scan traz 5 regras Go e só 2 caem numa classe de bug,
# ambas de integer overflow. error_handling está vazia — na linguagem em que
# `if err != nil` É o modelo de erros — e o mesmo vale para race_condition,
# null_safety, memory_leak e edge_case. Medições em
# docs/superpowers/specs/2026-08-18-bugfix-rules-go-design.md.
#
# Cada regra tem um par de fixtures em
# mcp/test/fixtures/bugfix-go/{hits,misses}/: um ficheiro que tem de disparar
# a regra, outro parecido que NÃO pode. O ficheiro misses/ é a especificação
# do que é código correto — se ele disparar, a regra é que está errada.
#
# Os ids seguem bugfix-go-<classe>-<nome>, em que <classe> tem de ser um dos
# seis tokens que o mapSubcategory reconhece por regex sobre o id em
# minúsculas. Nenhum id usa a palavra `unchecked`.
#
# NÃO acrescentar cláusulas de exclusão "defensivas" sem medir primeiro: duas
# que pareciam obrigatórias foram medidas e não faziam nada (§8 do design).
rules:
  # Sem exclusões para mapa/canal/type-assertion, e isso é deliberado:
  # `$F(...)` exige uma CHAMADA de função, e `v, _ := m["k"]`, `v, _ := <-ch`
  # e `s, _ := x.(string)` não são chamadas, por isso as formas idiomáticas
  # com ok-bool nunca casaram. Medido com uma variante larga e outra estreita
  # lado a lado contra Go idiomático: resultado idêntico.
  - id: bugfix-go-error-handling-err-discarded
    pattern-either:
      - pattern: $X, _ := $F(...)
      - pattern: $X, _ = $F(...)
    message: >-
      Erro descartado com `_`. O segundo valor de retorno é o erro e está a ser
      deitado fora, por isso a falha segue silenciosa e o valor devolvido pode
      ser o zero-value em vez de dados reais.
    severity: ERROR
    languages: [go]

  # WARNING e não ERROR: `_ = os.Remove(tmp)` num caminho de limpeza é
  # deliberado e vai disparar. É o preço de apanhar os casos em que não é.
  - id: bugfix-go-error-handling-err-blank-assign
    pattern: _ = $F(...)
    message: >-
      Retorno atribuído a `_`. Se for um erro, foi descartado de propósito —
      confirme que é mesmo essa a intenção e não um `if err != nil` esquecido.
    severity: WARNING
    languages: [go]

  - id: bugfix-go-error-handling-empty-err-block
    pattern: |
      if $ERR != nil {
      }
    message: >-
      Ramo de erro vazio. O erro foi testado e depois deitado fora, o que é
      pior do que não o testar: o código diz que trata a falha e não trata.
    severity: ERROR
    languages: [go]
```

- [ ] **Step 6: Run the test to verify it passes**

```powershell
$env:PATH = "C:\Users\Administrator\AppData\Roaming\Python\Python314\Scripts;$env:PATH"
$env:GUARDIAN_REQUIRE_SEMGREP = "1"
cd mcp
npx vitest run test/integration/bugfixRulesGo.test.ts
```

Expected: PASS, **no skips**. Each of the three hit fixtures at count 1;
`scanned` equal to 3 on both sides; zero findings across the near-misses.

- [ ] **Step 7: Prove the near-miss half is real, not vacuous**

Two mutations, both required, both pasted into the report:

1. Temporarily change `run()` to scan `dir` directly instead of the temp copy.
   The suite must go **RED on the scanned-count assertions** — that is what
   stops "found nothing" from passing as "scanned nothing". Restore.
2. Temporarily replace `err-discarded`'s two patterns with the bare
   `pattern: $X, _ := $ANY`. The suite must go **RED on
   `misses/err_discarded.go`**, because the map, channel and type-assertion
   ok-forms start matching. Restore, and confirm GREEN.

The second is the one that matters: it demonstrates the three idiomatic
near-miss functions are load-bearing rather than decorative.

- [ ] **Step 8: Commit**

```bash
git add configs/semgrep/bugfix-go.yml mcp/test/fixtures/bugfix-go mcp/test/integration/bugfixRulesGo.test.ts
git commit -m "feat(bugfix-rules): the three Go error_handling rules"
```

---

### Task 2: `null_safety` (1 rule) and `off_by_one` (1 rule)

**Files:**
- Modify: `configs/semgrep/bugfix-go.yml` (append two rules)
- Create: `mcp/test/fixtures/bugfix-go/hits/type_assert_no_ok.go`
- Create: `mcp/test/fixtures/bugfix-go/misses/type_assert_no_ok.go`
- Create: `mcp/test/fixtures/bugfix-go/hits/loop_lte_len.go`
- Create: `mcp/test/fixtures/bugfix-go/misses/loop_lte_len.go`
- Modify: `mcp/test/integration/bugfixRulesGo.test.ts`

**Interfaces:**
- Consumes: `configs/semgrep/bugfix-go.yml` holding the three `error_handling`
  rules; the test's `EXPECTED_HITS_BY_FILE` and `EXPECTED_CLASS` maps.
- Produces: ids `bugfix-go-null-safety-type-assert-no-ok` and
  `bugfix-go-off-by-one-loop-lte-len`.

- [ ] **Step 1: Write the two hit fixtures**

`mcp/test/fixtures/bugfix-go/hits/type_assert_no_ok.go`:

```go
package hits

func mustBeString(v interface{}) string {
	return v.(string)
}
```

`mcp/test/fixtures/bugfix-go/hits/loop_lte_len.go`:

```go
package hits

func sumPastEnd(xs []int) int {
	sum := 0
	for i := 0; i <= len(xs); i++ {
		sum += xs[i]
	}
	return sum
}
```

- [ ] **Step 2: Write the two near-miss fixtures**

`mcp/test/fixtures/bugfix-go/misses/type_assert_no_ok.go`. Both type-switch
forms are included because they *look* like they need excluding and do not —
see Step 5's comment.

```go
package misses

func maybeString(v interface{}) string {
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

func switchPlain(v interface{}) string {
	switch v.(type) {
	case string:
		return "s"
	}
	return ""
}

func switchBound(v interface{}) string {
	switch s := v.(type) {
	case string:
		return s
	}
	return ""
}
```

`mcp/test/fixtures/bugfix-go/misses/loop_lte_len.go`:

```go
package misses

func sumInBounds(xs []int) int {
	sum := 0
	for i := 0; i < len(xs); i++ {
		sum += xs[i]
	}
	return sum
}

func sumRange(xs []int) int {
	sum := 0
	for _, x := range xs {
		sum += x
	}
	return sum
}
```

- [ ] **Step 3: Register the expectations**

Add to `EXPECTED_HITS_BY_FILE`:

```typescript
  'loop_lte_len.go': { ids: ['bugfix-go-off-by-one-loop-lte-len'], count: 1 },
  'type_assert_no_ok.go': { ids: ['bugfix-go-null-safety-type-assert-no-ok'], count: 1 },
```

Add to `EXPECTED_CLASS`:

```typescript
  'bugfix-go-null-safety-type-assert-no-ok': 'null_safety',
  'bugfix-go-off-by-one-loop-lte-len': 'off_by_one',
```

- [ ] **Step 4: Run the test to verify it fails**

```powershell
$env:PATH = "C:\Users\Administrator\AppData\Roaming\Python\Python314\Scripts;$env:PATH"
$env:GUARDIAN_REQUIRE_SEMGREP = "1"
cd mcp
npx vitest run test/integration/bugfixRulesGo.test.ts
```

Expected: FAIL — the two new hit fixtures produce no findings, and
`mapSubcategory` is asserted for ids no rule defines.

- [ ] **Step 5: Append the two rules**

```yaml
  # Duas cláusulas, e mais nenhuma. A exclusão do type switch parece
  # obrigatória e não é: `v.(type)` dentro de um `switch` nunca casa
  # `$V.($T)`. As tentativas de a escrever nem sequer compilavam — em Go o
  # type switch é `switch v := x.(type)`, não `switch x.(T)`. Medido: com e
  # sem a exclusão o resultado é o mesmo, e as fixtures de near-miss cobrem
  # as duas formas.
  - id: bugfix-go-null-safety-type-assert-no-ok
    patterns:
      - pattern: $V.($T)
      - pattern-not-inside: $X, $OK := $V.($T)
      - pattern-not-inside: $X, $OK = $V.($T)
    message: >-
      Type assertion sem a forma `, ok`. Se o valor não for do tipo esperado
      isto entra em panic; `v, ok := x.(T)` devolve o zero-value e um booleano
      em vez de rebentar.
    severity: ERROR
    languages: [go]

  - id: bugfix-go-off-by-one-loop-lte-len
    pattern: |
      for $I := 0; $I <= len($XS); $I++ {
        ...
      }
    message: >-
      Off-by-one. `i <= len(xs)` corre uma posição para lá do fim e o índice
      `len(xs)` está sempre fora dos limites — é um panic de index out of
      range. Queria provavelmente `i < len(xs)`.
    severity: ERROR
    languages: [go]
```

- [ ] **Step 6: Run the test to verify it passes**

```powershell
$env:PATH = "C:\Users\Administrator\AppData\Roaming\Python\Python314\Scripts;$env:PATH"
$env:GUARDIAN_REQUIRE_SEMGREP = "1"
cd mcp
npx vitest run test/integration/bugfixRulesGo.test.ts
```

Expected: PASS, no skips. Five hit fixtures, five near-misses, `scanned` = 5
on both sides.

- [ ] **Step 7: Prove the type-switch near-misses are not decorative**

`switchPlain` and `switchBound` are in the fixture precisely because the design
claims they need no exclusion. Verify that claim rather than trusting it:
temporarily narrow the rule to `pattern: $V.($T)` alone (drop both
`pattern-not-inside` clauses), re-run, and record what happens. The
comma-ok form (`maybeString`) must start firing — proving those two clauses
are load-bearing — while `switchPlain` and `switchBound` must stay silent,
proving the type-switch exclusion really is unnecessary. Restore and confirm
GREEN. Paste both outputs.

- [ ] **Step 8: Commit**

```bash
git add configs/semgrep/bugfix-go.yml mcp/test/fixtures/bugfix-go mcp/test/integration/bugfixRulesGo.test.ts
git commit -m "feat(bugfix-rules): Go null_safety and off_by_one rules"
```

---

### Task 3: `memory_leak` (2 rules)

**Files:**
- Modify: `configs/semgrep/bugfix-go.yml` (append two rules)
- Create: `mcp/test/fixtures/bugfix-go/hits/body_not_closed.go`
- Create: `mcp/test/fixtures/bugfix-go/misses/body_not_closed.go`
- Create: `mcp/test/fixtures/bugfix-go/hits/ticker_not_stopped.go`
- Create: `mcp/test/fixtures/bugfix-go/misses/ticker_not_stopped.go`
- Modify: `mcp/test/integration/bugfixRulesGo.test.ts`

**Interfaces:**
- Consumes: `configs/semgrep/bugfix-go.yml` holding five rules; the test's two maps.
- Produces: ids `bugfix-go-memory-leak-body-not-closed` and
  `bugfix-go-memory-leak-ticker-not-stopped`.

- [ ] **Step 1: Write the two hit fixtures**

`mcp/test/fixtures/bugfix-go/hits/body_not_closed.go`:

```go
package hits

import "net/http"

func fetchLeaking(url string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	_ = resp.StatusCode
	return nil
}
```

`mcp/test/fixtures/bugfix-go/hits/ticker_not_stopped.go`:

```go
package hits

import "time"

func tickLeaking() {
	t := time.NewTicker(time.Second)
	for range t.C {
		return
	}
}
```

- [ ] **Step 2: Write the two near-miss fixtures**

`mcp/test/fixtures/bugfix-go/misses/body_not_closed.go`:

```go
package misses

import "net/http"

func fetchClosing(url string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}
```

`mcp/test/fixtures/bugfix-go/misses/ticker_not_stopped.go`:

```go
package misses

import "time"

func tickStopping() {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for range t.C {
		return
	}
}
```

- [ ] **Step 3: Register the expectations**

Add to `EXPECTED_HITS_BY_FILE`:

```typescript
  'body_not_closed.go': { ids: ['bugfix-go-memory-leak-body-not-closed'], count: 1 },
  'ticker_not_stopped.go': { ids: ['bugfix-go-memory-leak-ticker-not-stopped'], count: 1 },
```

Add to `EXPECTED_CLASS`:

```typescript
  'bugfix-go-memory-leak-body-not-closed': 'memory_leak',
  'bugfix-go-memory-leak-ticker-not-stopped': 'memory_leak',
```

- [ ] **Step 4: Run the test to verify it fails**

```powershell
$env:PATH = "C:\Users\Administrator\AppData\Roaming\Python\Python314\Scripts;$env:PATH"
$env:GUARDIAN_REQUIRE_SEMGREP = "1"
cd mcp
npx vitest run test/integration/bugfixRulesGo.test.ts
```

Expected: FAIL — the two new hit fixtures produce no findings.

- [ ] **Step 5: Append the two rules**

Both anchor on the single call and exclude with `pattern-not-inside` over the
sequence. The obvious alternative — a positive `pattern` ending in `...` with a
paired `pattern-not` — was measured and fires on its own near-miss: the
trailing `...` generates many overlapping spans and the `pattern-not` cancels
only one of them.

```yaml
  - id: bugfix-go-memory-leak-body-not-closed
    patterns:
      - pattern: $RESP, $ERR := http.Get(...)
      - pattern-not-inside: |
          $RESP, $ERR := http.Get(...)
          ...
          defer $RESP.Body.Close()
    message: >-
      Corpo da resposta HTTP nunca fechado. Sem `defer resp.Body.Close()` a
      ligação não volta ao pool e o ficheiro fica aberto — em código que corre
      em ciclo, esgota os descritores.
    severity: ERROR
    languages: [go]

  - id: bugfix-go-memory-leak-ticker-not-stopped
    patterns:
      - pattern: $T := time.NewTicker(...)
      - pattern-not-inside: |
          $T := time.NewTicker(...)
          ...
          defer $T.Stop()
    message: >-
      Ticker nunca parado. O runtime continua a disparar o canal depois de a
      função sair, e nem o ticker nem a goroutine associada são libertados.
      Acrescente `defer t.Stop()`.
    severity: WARNING
    languages: [go]
```

- [ ] **Step 6: Run the test to verify it passes**

```powershell
$env:PATH = "C:\Users\Administrator\AppData\Roaming\Python\Python314\Scripts;$env:PATH"
$env:GUARDIAN_REQUIRE_SEMGREP = "1"
cd mcp
npx vitest run test/integration/bugfixRulesGo.test.ts
```

Expected: PASS, no skips. Seven hit fixtures, seven near-misses.

- [ ] **Step 7: Prove the exclusion operator choice is load-bearing**

Temporarily rewrite `body-not-closed` in the shape that was measured to fail —

```yaml
    patterns:
      - pattern: |
          $RESP, $ERR := http.Get(...)
          ...
      - pattern-not: |
          $RESP, $ERR := http.Get(...)
          ...
          defer $RESP.Body.Close()
          ...
```

— re-run, and show the suite going **RED on `misses/body_not_closed.go`**, with
multiple findings on the hit fixture rather than one. Then restore the shipped
form and show GREEN. Paste both outputs. This is the trap the spec's §8 records,
and the near-miss is the only thing standing between it and shipping.

- [ ] **Step 8: Commit**

```bash
git add configs/semgrep/bugfix-go.yml mcp/test/fixtures/bugfix-go mcp/test/integration/bugfixRulesGo.test.ts
git commit -m "feat(bugfix-rules): Go memory_leak rules"
```

---

### Task 4: `race_condition` (1), `edge_case` (2), and the no-duplication test

**Files:**
- Modify: `configs/semgrep/bugfix-go.yml` (append three rules)
- Create: `mcp/test/fixtures/bugfix-go/hits/lock_without_defer.go`
- Create: `mcp/test/fixtures/bugfix-go/misses/lock_without_defer.go`
- Create: `mcp/test/fixtures/bugfix-go/hits/append_discarded.go`
- Create: `mcp/test/fixtures/bugfix-go/misses/append_discarded.go`
- Create: `mcp/test/fixtures/bugfix-go/hits/nil_map_write.go`
- Create: `mcp/test/fixtures/bugfix-go/misses/nil_map_write.go`
- Modify: `mcp/test/integration/bugfixRulesGo.test.ts`

**Interfaces:**
- Consumes: `configs/semgrep/bugfix-go.yml` holding seven rules; the test's
  `run(config, dir)` helper, whose first parameter is the config precisely so a
  registry pack name can be passed instead of the local file.
- Produces: the last three ids, and the no-duplication test.

- [ ] **Step 1: Write the three hit fixtures**

`mcp/test/fixtures/bugfix-go/hits/lock_without_defer.go` — the early `return`
is the point: it skips the `Unlock` entirely.

```go
package hits

import "sync"

func writeUnlockedOnHappyPathOnly(mu *sync.Mutex, m map[string]int, key string) error {
	mu.Lock()
	if key == "" {
		return nil
	}
	m[key] = 1
	mu.Unlock()
	return nil
}
```

`mcp/test/fixtures/bugfix-go/hits/append_discarded.go`:

```go
package hits

func growDiscarding(xs []int) []int {
	append(xs, 1)
	return xs
}
```

`mcp/test/fixtures/bugfix-go/hits/nil_map_write.go`:

```go
package hits

func writeToNilMap() {
	var m map[string]int
	m["k"] = 1
}
```

- [ ] **Step 2: Write the three near-miss fixtures**

`mcp/test/fixtures/bugfix-go/misses/lock_without_defer.go`:

```go
package misses

import "sync"

func writeWithDefer(mu *sync.Mutex, m map[string]int, key string) error {
	mu.Lock()
	defer mu.Unlock()
	if key == "" {
		return nil
	}
	m[key] = 1
	return nil
}
```

`mcp/test/fixtures/bugfix-go/misses/append_discarded.go` — four forms, because
`append($XS, ...)` matched the assigned form until each was excluded:

```go
package misses

func growAssigning(xs []int) []int {
	xs = append(xs, 1)
	return xs
}

func growDeclaring(xs []int) []int {
	ys := append(xs, 1)
	return ys
}

func growReturning(xs []int) []int {
	return append(xs, 1)
}

func growPassing(xs []int) {
	println(len(append(xs, 1)))
}
```

`mcp/test/fixtures/bugfix-go/misses/nil_map_write.go` — the third function is
the subtle one: reading a nil map is legal Go and must not fire.

```go
package misses

func writeToMadeMap() map[string]int {
	m := make(map[string]int)
	m["k"] = 1
	return m
}

func writeToAssignedMap() map[string]int {
	var m map[string]int
	m = make(map[string]int)
	m["k"] = 1
	return m
}

func readFromNilMapIsFine() int {
	var m map[string]int
	return m["k"]
}
```

- [ ] **Step 3: Register the expectations**

Add to `EXPECTED_HITS_BY_FILE`:

```typescript
  'append_discarded.go': { ids: ['bugfix-go-edge-case-append-discarded'], count: 1 },
  'lock_without_defer.go': { ids: ['bugfix-go-race-condition-lock-without-defer'], count: 1 },
  'nil_map_write.go': { ids: ['bugfix-go-edge-case-nil-map-write'], count: 1 },
```

Add to `EXPECTED_CLASS`:

```typescript
  'bugfix-go-race-condition-lock-without-defer': 'race_condition',
  'bugfix-go-edge-case-append-discarded': 'edge_case',
  'bugfix-go-edge-case-nil-map-write': 'edge_case',
```

- [ ] **Step 4: Write the no-duplication test**

Append this `describe` block to `mcp/test/integration/bugfixRulesGo.test.ts`.

```typescript
/**
 * Design of record §2: no local rule may re-report what `p/r2c-bug-scan`
 * already finds. For Go the pack ships only 5 rules and just 2 land in a bug
 * class, so overlap is unlikely — but "unlikely" is not "measured", and this
 * is the test that measures it.
 *
 * It carries a POSITIVE CONTROL, which the Python version lacks. Asserting
 * that a pack found nothing proves nothing on its own if the pack never ran
 * for this language: a Go-specific rule failing to load would look identical
 * to a clean result. So a second scan runs the same pack against a file
 * written to trip one of its own Go rules, and asserts it fires. Only then
 * does the zero above mean anything.
 */
const R2C_PACK = 'p/r2c-bug-scan';

function r2cRunOrNull(config: string, dir: string): SemgrepRun | null {
  if (!AVAILABLE) return null;
  try {
    return run(config, dir);
  } catch {
    return null;
  }
}
const R2C_ON_HITS = r2cRunOrNull(R2C_PACK, resolve(FIXTURES, 'hits'));
const R2C_ON_CONTROL = r2cRunOrNull(R2C_PACK, resolve(FIXTURES, 'control'));

describe('no local Go rule duplicates p/r2c-bug-scan', () => {
  it.runIf(REQUIRE_SEMGREP)('the registry pack must be reachable when the flag is set', () => {
    expect(R2C_ON_HITS).not.toBeNull();
  });

  it.skipIf(R2C_ON_CONTROL === null)('positive control: the pack IS live for Go', () => {
    // Without this, "the pack found nothing" is indistinguishable from "the
    // pack never ran". The control file trips the pack's own
    // `incorrect-default-permission` rule.
    expect(R2C_ON_CONTROL?.scanned).toBe(1);
    expect(R2C_ON_CONTROL?.rows.length).toBeGreaterThan(0);
  });

  it.skipIf(R2C_ON_HITS === null)('the existing pack finds NOTHING in any hit fixture', () => {
    expect(R2C_ON_HITS?.scanned).toBe(fixtureFiles(resolve(FIXTURES, 'hits')).length);
    const grouped = rowsByFile(R2C_ON_HITS?.rows ?? []);
    for (const file of fixtureFiles(resolve(FIXTURES, 'hits'))) {
      expect(grouped[file] ?? []).toEqual([]);
    }
  });
});
```

Create the control file at `mcp/test/fixtures/bugfix-go/control/permissions.go`:

```go
package control

import "os"

// Exists only to trip p/r2c-bug-scan's own `incorrect-default-permission`
// rule, proving that pack is live for Go. None of our rules fire here, and
// this directory is not part of the hits/misses fixture pairs.
func widenPermissions(path string) error {
	return os.Chmod(path, 0777)
}
```

- [ ] **Step 5: Run the test to verify it fails**

```powershell
$env:PATH = "C:\Users\Administrator\AppData\Roaming\Python\Python314\Scripts;$env:PATH"
$env:GUARDIAN_REQUIRE_SEMGREP = "1"
cd mcp
npx vitest run test/integration/bugfixRulesGo.test.ts
```

Expected: FAIL — the three new hit fixtures produce no findings yet.

- [ ] **Step 6: Append the three rules**

```yaml
  - id: bugfix-go-race-condition-lock-without-defer
    patterns:
      - pattern: $MU.Lock()
      - pattern-not-inside: |
          $MU.Lock()
          ...
          defer $MU.Unlock()
          ...
    message: >-
      `Lock()` sem `defer Unlock()`. Um unlock só no caminho feliz é um unlock
      que qualquer `return` antecipado ou panic salta — e a partir daí todos os
      outros acessos bloqueiam para sempre.
    severity: WARNING
    languages: [go]

  # Três exclusões, e cada uma foi medida à parte. A quarta que aqui esteve —
  # `pattern-not-inside: $X := append($XS, ...)` — era morta: o Semgrep trata
  # `$X = append(...)` como cobrindo também a forma `:=`, por isso a cláusula
  # `=` sozinha já exclui `ys := append(xs, 1)`. Removê-la não muda um único
  # resultado. Sem estas três, a regra casa `xs = append(xs, 1)`, que é a
  # forma correta.
  - id: bugfix-go-edge-case-append-discarded
    patterns:
      - pattern: append($XS, ...)
      - pattern-not-inside: $X = append($XS, ...)
      - pattern-not-inside: return append($XS, ...)
      - pattern-not-inside: $F(..., append($XS, ...), ...)
    message: >-
      Resultado de `append` descartado. O `append` pode realocar o array de
      suporte, por isso o valor devolvido é a única referência fiável aos
      dados — descartá-lo perde tudo o que foi acrescentado.
    severity: ERROR
    languages: [go]

  - id: bugfix-go-edge-case-nil-map-write
    patterns:
      - pattern: |
          var $M map[$K]$V
          ...
          $M[$IDX] = $X
      - pattern-not-inside: |
          var $M map[$K]$V
          ...
          $M = make(...)
          ...
    message: >-
      Escrita num mapa nil. Um `var m map[K]V` sem `make` é nil: ler dele é
      legal e devolve o zero-value, mas escrever entra em panic.
    severity: ERROR
    languages: [go]
```

- [ ] **Step 7: Run the test to verify it passes**

```powershell
$env:PATH = "C:\Users\Administrator\AppData\Roaming\Python\Python314\Scripts;$env:PATH"
$env:GUARDIAN_REQUIRE_SEMGREP = "1"
cd mcp
npx vitest run test/integration/bugfixRulesGo.test.ts
```

Expected: PASS, no skips. **Ten hit fixtures totalling 10 findings** (one each),
ten near-misses with zero, `scanned` = 10 on both sides, and `p/r2c-bug-scan`
silent on every hit fixture while firing on the control file.

- [ ] **Step 8: Run the full suite**

```powershell
$env:PATH = "C:\Users\Administrator\AppData\Roaming\Python\Python314\Scripts;$env:PATH"
$env:GUARDIAN_REQUIRE_SEMGREP = "1"
cd mcp
npm run lint
npm test
```

Expected: lint exit 0; suite green with **0 skipped**. Report both counts.

- [ ] **Step 9: Commit**

```bash
git add configs/semgrep/bugfix-go.yml mcp/test/fixtures/bugfix-go mcp/test/integration/bugfixRulesGo.test.ts
git commit -m "feat(bugfix-rules): Go race_condition and edge_case rules, and the no-duplication proof"
```

---

### Task 5: Documentation

**Files:**
- Modify: `README.md` (three language sections: EN, PT, ES)
- Modify: `skills/guardian-bugfix/SKILL.md`
- Modify: `mcp/src/tools/bugHunt.ts` (tool `title` and `description`, header comment)
- Modify: `CHANGELOG.md`
- Modify: `mcp/dist/` (rebuilt, staged in the same commit)

**Interfaces:**
- Consumes: nothing at runtime. Every statement must match what Tasks 1-4
  shipped.
- Produces: no code interface.

- [ ] **Step 1: Verify the rule counts before writing any number**

```bash
grep -c "^  - id:" configs/semgrep/bugfix-js.yml configs/semgrep/bugfix-py.yml configs/semgrep/bugfix-go.yml
```

Expected: 14, 10, 10. Use the numbers this prints, not the numbers in this
plan — if they disagree, the plan is wrong and you should say so in your report.

- [ ] **Step 2: Update the three README language sections**

Each `bug_hunt` bullet currently ends with a claim that only JS/TS and Python
have local packs. In each of the three sections, add the Go pack and **its
limitations in the same breath**, which is this repo's documentation
convention. English:

```markdown
Go has one too — `configs/semgrep/bugfix-go.yml`, ten hand-authored rules across the same six classes, and Go is the language where the registry pack leaves the biggest hole: `p/r2c-bug-scan` ships 5 Go rules and only 2 land in a bug class, both integer-overflow, so `error_handling` — in the language where `if err != nil` *is* the error model — `race_condition`, `null_safety`, `memory_leak` and `edge_case` were all empty. Its gaps are stated rather than implied: there is **no goroutine-leak rule**, and **no loop-variable-capture rule** — that one was built and verified working, then deliberately excluded, because Go 1.22 made loop variables per-iteration and Semgrep cannot read `go.mod`, so on any modern module it would accuse correct code; `body-not-closed` only recognises `http.Get`, so `http.Post` and `client.Do(req)` leak identically and are not covered; `lock-without-defer` accepts any `defer mu.Unlock()` in the block, so it cannot tell a correctly scoped unlock from one deferred in the wrong branch; and `err-blank-assign` fires on deliberate discards like `_ = os.Remove(tmp)` in a cleanup path, which is why it is `WARNING`. **JS/TS, Python and Go**: the remaining languages have no local pack yet.
```

Portuguese, in the PT section:

```markdown
O Go também tem o seu — `configs/semgrep/bugfix-go.yml`, dez regras hand-authored nas mesmas seis classes, e o Go é a linguagem onde o pack do registo deixa o maior buraco: o `p/r2c-bug-scan` traz 5 regras Go e só 2 caem numa classe de bug, ambas de integer overflow, por isso `error_handling` — na linguagem em que `if err != nil` É o modelo de erros — `race_condition`, `null_safety`, `memory_leak` e `edge_case` estavam todas vazias. As lacunas são ditas em vez de subentendidas: **não há regra para goroutines que ficam penduradas** nem **regra para a captura da variável do ciclo** — essa foi construída e verificada a funcionar, e depois deliberadamente excluída, porque o Go 1.22 passou a dar a cada iteração a sua própria variável e o Semgrep não lê o `go.mod`, por isso em qualquer módulo moderno acusaria código correto; a `body-not-closed` só reconhece `http.Get`, portanto `http.Post` e `client.Do(req)` perdem ligações da mesma maneira e não são apanhados; a `lock-without-defer` aceita qualquer `defer mu.Unlock()` no bloco, por isso não distingue um unlock bem colocado de um adiado no ramo errado; e a `err-blank-assign` dispara em descartes deliberados como `_ = os.Remove(tmp)` numa limpeza, e é por isso que é `WARNING`. **JS/TS, Python e Go**: as restantes linguagens ainda não têm pack local.
```

Spanish, in the ES section:

```markdown
Go también tiene el suyo — `configs/semgrep/bugfix-go.yml`, diez reglas hand-authored en las mismas seis clases, y Go es el lenguaje donde el pack del registro deja el mayor hueco: `p/r2c-bug-scan` trae 5 reglas Go y solo 2 caen en una clase de bug, ambas de integer overflow, así que `error_handling` — en el lenguaje donde `if err != nil` ES el modelo de errores — `race_condition`, `null_safety`, `memory_leak` y `edge_case` estaban todas vacías. Sus carencias se dicen en vez de insinuarse: **no hay regla para goroutines colgadas** ni **regla para la captura de la variable del bucle** — esa se construyó, se verificó funcionando y luego se excluyó deliberadamente, porque Go 1.22 pasó a dar a cada iteración su propia variable y Semgrep no lee el `go.mod`, así que en cualquier módulo moderno acusaría código correcto; `body-not-closed` solo reconoce `http.Get`, así que `http.Post` y `client.Do(req)` filtran igual y no se cubren; `lock-without-defer` acepta cualquier `defer mu.Unlock()` en el bloque, así que no distingue un unlock bien colocado de uno diferido en la rama equivocada; y `err-blank-assign` dispara en descartes deliberados como `_ = os.Remove(tmp)` en una limpieza, y por eso es `WARNING`. **JS/TS, Python y Go**: los demás lenguajes aún no tienen pack local.
```

- [ ] **Step 3: Update the guardian-bugfix skill**

Add after the Python paragraph in `skills/guardian-bugfix/SKILL.md`:

```markdown
Para Go, o `bug_hunt` corre também por default
`configs/semgrep/bugfix-go.yml` — dez regras hand-authored, cada uma com o seu
par de fixtures — cobrindo as mesmas seis classes: erro descartado com `_`,
retorno atribuído a `_`, ramo `if err != nil` vazio, type assertion sem a
forma `, ok`, `for i := 0; i <= len(xs)`, corpo de resposta HTTP nunca
fechado, ticker nunca parado, `Lock()` sem `defer Unlock()`, resultado de
`append` descartado, e escrita em mapa nil. É a linguagem com o maior buraco
no registo: o `p/r2c-bug-scan` só tem 5 regras Go e apenas 2 caem numa classe
de bug.

Não cobrem goroutines que ficam penduradas, nem a captura da variável do
ciclo. A segunda foi construída e verificada a funcionar, e depois excluída de
propósito: o Go 1.22 passou a dar a cada iteração a sua própria variável, e o
Semgrep não lê o `go.mod` para saber que versão o módulo declara — em código
moderno acusaria a forma correta. Para essas duas classes, leia o código.
```

- [ ] **Step 4: Update the `bug_hunt` tool title and description**

In `mcp/src/tools/bugHunt.ts`, the registered tool's `title` and `description`
name only the JS/TS and Python packs. Update both to name all three, and
update the file's header comment the same way. Keep the counts consistent with
what Step 1 printed.

- [ ] **Step 5: Add the CHANGELOG entry**

Add a new `## [Unreleased]` section at the top of `CHANGELOG.md`:

```markdown
## [Unreleased]

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
- `lock-without-defer` accepts any `defer mu.Unlock()` in the block.
- `err-blank-assign` fires on deliberate discards, which is why it is `WARNING`.
```

- [ ] **Step 6: Build, lint, test, and verify markdownlint**

```powershell
$env:PATH = "C:\Users\Administrator\AppData\Roaming\Python\Python314\Scripts;$env:PATH"
$env:GUARDIAN_REQUIRE_SEMGREP = "1"
cd mcp
npm run build
npm run lint
npm test
```

Then from the **repo root**:

```bash
npx --yes markdownlint-cli2 "README.md" "skills/**/*.md" "commands/**/*.md"
```

Expected: build ok; lint exit 0; suite green with 0 skipped; markdownlint 0
issues. `mcp/src/tools/bugHunt.ts` changed, so `mcp/dist/` MUST be rebuilt and
staged in this commit — the repo is the distribution and Claude Code runs
`mcp/dist/server.js` directly.

- [ ] **Step 7: Commit**

```bash
git add README.md skills/guardian-bugfix/SKILL.md mcp/src/tools/bugHunt.ts CHANGELOG.md mcp/dist
git commit -m "docs(bugfix-rules): the Go pack, and what it does not cover"
```

---

## Verification summary

What the finished branch must show — all of it already measured on the rule set
this plan carries:

| Check | Expected |
| --- | --- |
| Hit fixtures | 10 files, **10 findings**, each file firing exactly its own rule once |
| Near-miss fixtures | 10 files, **0 findings** |
| `paths.scanned` | 10 on both sides — asserted, not assumed |
| `p/r2c-bug-scan` on the hit fixtures | **0 findings**, with a positive control proving the pack is live for Go |
| `mapSubcategory` | all 10 ids land in their own class; none contains `unchecked` |
| Wiring | none — `resolveBugfixRules()` is already plural |
| Full suite | green with `GUARDIAN_REQUIRE_SEMGREP=1`, **no skips**; `npm run lint` exit 0 |
