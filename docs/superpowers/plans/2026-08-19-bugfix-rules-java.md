# Java bug-finding Semgrep rules — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `configs/semgrep/bugfix-java.yml` — eight hand-authored Semgrep
rules covering all six `bug_hunt` bug subcategories for Java.

**Architecture:** A plain Semgrep YAML rule file beside the JS/TS, Python and Go
packs, with a hit fixture and a near-miss fixture per rule, and an integration
test asserting the exact rule ids, the raw finding count, and the scanned-file
count per file.

**Tech Stack:** Semgrep OSS 1.164.0 (pattern rules, no dataflow), TypeScript
(ESM, NodeNext), vitest.

**Spec:** `docs/superpowers/specs/2026-08-19-bugfix-rules-java-design.md` — read
it, especially §3 (the new governing rule), §5's killed rule, and §9.

## Global Constraints

- **Every rule's YAML and every fixture in this plan has been run against the
  others with Semgrep 1.164.0 and verified.** Use them verbatim. Changing a
  pattern means you own re-proving both halves: it fires on the hit fixture and
  is silent on the near-miss.
- **Do NOT add "defensive" exclusion clauses.** A clause that reads as a guard
  and does nothing is this repo's signature defect; the Go round shipped one
  with a "Medido" label that had never been measured per-clause.
- **Two words are forbidden in rule ids.** `unchecked` (the `error_handling`
  regex matches it) and `concurren` (the `race_condition` regex matches it, and
  runs first). That is why the edge-case rule is `modify-during-iteration` and
  not `concurrent-modification`.
- **Semgrep is installed but NOT on PATH:**
  `C:\Users\Administrator\AppData\Roaming\Python\Python314\Scripts\semgrep.exe`.
  Prepend that directory to `PATH` before running the suite, or every Semgrep
  test SKIPS and you read a green suite that proved nothing.
- **Semgrep cannot be invoked through the Bash tool** (returns
  `<ERROR: missing output>`). Use PowerShell for any direct Semgrep run.
- **Verify with `GUARDIAN_REQUIRE_SEMGREP=1`.** Report pass and skip counts; a
  run with skips is not a passing run.
- **Rule id format** `bugfix-java-<class-token>-<name>`, `<class-token>` one of
  exactly `race-condition`, `null-safety`, `off-by-one`, `memory-leak`,
  `error-handling`, `edge-case`.
- **Rule messages in Portuguese**, matching `base.yml` and the three existing
  packs.
- **Temp directories:** `makeTempDir(prefix)` + `afterAll(cleanupTempDirs)` from
  `mcp/test/helpers/tempDir.ts`. Never a bare `mkdtempSync`.
- **TypeScript:** ESM `NodeNext` (`.js` specifiers), `noUncheckedIndexedAccess`,
  **no `!`, no `any`** — both at zero repo-wide, so a reappearance is a
  regression. See CLAUDE.md's "TypeScript conventions".
- **`npm run lint` runs both tsconfigs** and must stay clean.
- Build and test from `mcp/`. **Tasks 1-4 touch no `mcp/src/`**; **Task 5 does**
  (`bugHunt.ts`), so it MUST run `npm run build` and stage `mcp/dist/` in the
  same commit — the repo is the distribution.

---

### Task 1: Rule file, harness, the two `error_handling` rules, and the resolver test

**Files:**
- Create: `configs/semgrep/bugfix-java.yml`
- Create: `mcp/test/fixtures/bugfix-java/hits/EmptyCatch.java`
- Create: `mcp/test/fixtures/bugfix-java/misses/EmptyCatch.java`
- Create: `mcp/test/fixtures/bugfix-java/hits/PrintStackTraceOnly.java`
- Create: `mcp/test/fixtures/bugfix-java/misses/PrintStackTraceOnly.java`
- Create: `mcp/test/integration/bugfixRulesJava.test.ts`
- Modify: `mcp/test/unit/platform/configsDir.test.ts`

**Interfaces:**
- Consumes: `mapSubcategory` from `../../src/tools/bugHunt.js`; `makeTempDir` and
  `cleanupTempDirs` from `../helpers/tempDir.js`.
- Produces: `configs/semgrep/bugfix-java.yml` with one `rules:` list, extended by
  Tasks 2-4; `mcp/test/integration/bugfixRulesJava.test.ts` owning
  `EXPECTED_HITS_BY_FILE: Readonly<Record<string, { ids: readonly string[]; count: number }>>`,
  `EXPECTED_CLASS: Readonly<Record<string, string>>`, and
  `run(config: string, dir: string): SemgrepRun` returning `{ rows, scanned }`.

- [ ] **Step 1: Update the resolver test FIRST**

This is not housekeeping and it is not optional. `resolveBugfixRules()` globs
`configs/semgrep/bugfix-*.yml`, and `mcp/test/unit/platform/configsDir.test.ts`
pins the **exact** expected array — deliberately, so a resolver returning only
some files fails loudly. The moment `bugfix-java.yml` exists, that test goes
red. The Go round discovered this mid-branch; here it is a first step.

In that file's `resolveBugfixRules` describe block, add `bugfix-java.yml` to the
expected array, in the sorted position it belongs (`go`, `java`, `js`, `py`):

```typescript
    expect(resolveBugfixRules()).toEqual([
      join(dir, 'bugfix-go.yml'),
      join(dir, 'bugfix-java.yml'),
      join(dir, 'bugfix-js.yml'),
      join(dir, 'bugfix-py.yml'),
    ]);
```

- [ ] **Step 2: Write the two hit fixtures**

`mcp/test/fixtures/bugfix-java/hits/EmptyCatch.java`:

```java
public class EmptyCatch {
    void swallow(String p) {
        try { Integer.parseInt(p); } catch (NumberFormatException e) { }
    }
}
```

`mcp/test/fixtures/bugfix-java/hits/PrintStackTraceOnly.java`:

```java
public class PrintStackTraceOnly {
    void onlyPrints(String p) {
        try { Integer.parseInt(p); } catch (NumberFormatException e) { e.printStackTrace(); }
    }
}
```

- [ ] **Step 3: Write the two near-miss fixtures**

`mcp/test/fixtures/bugfix-java/misses/EmptyCatch.java`:

```java
public class EmptyCatch {
    void logs(String p) {
        try { Integer.parseInt(p); } catch (NumberFormatException e) { log(e); }
    }
    void rethrows(String p) {
        try { Integer.parseInt(p); } catch (NumberFormatException e) { throw new IllegalStateException(e); }
    }
    void log(Exception e) { }
}
```

`mcp/test/fixtures/bugfix-java/misses/PrintStackTraceOnly.java` — both functions
print AND do something else, which is the distinction the rule turns on:

```java
public class PrintStackTraceOnly {
    void printsThenRethrows(String p) {
        try { Integer.parseInt(p); } catch (NumberFormatException e) { e.printStackTrace(); throw new IllegalStateException(e); }
    }
    void printsThenRecovers(String p) {
        try { Integer.parseInt(p); } catch (NumberFormatException e) { e.printStackTrace(); fallback(); }
    }
    void fallback() { }
}
```

- [ ] **Step 4: Write the test harness with only the Task 1 expectations**

Create `mcp/test/integration/bugfixRulesJava.test.ts`. Read
`mcp/test/integration/bugfixRulesGo.test.ts` first — this mirrors it exactly,
including its no-duplication block (which Task 4 adds here).

```typescript
/**
 * Runs the local `bugfix-java.yml` rules against the fixture pairs in
 * `mcp/test/fixtures/bugfix-java/{hits,misses}/` and asserts, per file, the
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
 *    nothing" are otherwise byte-identical. The in-repo fixture path contains
 *    a `test/` segment, which Semgrep's default ignore list skips wholesale —
 *    which is why fixtures are copied to a temp dir first, and why asserting
 *    the count is what proves the copy still works.
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
const RULES = resolve(REPO_ROOT, 'configs', 'semgrep', 'bugfix-java.yml');
const FIXTURES = resolve(REPO_ROOT, 'mcp', 'test', 'fixtures', 'bugfix-java');
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
  const work = makeTempDir('guardian-bugfix-java-');
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
  return readdirSync(dir).filter((name) => name.endsWith('.java')).sort();
}

interface FileExpectation {
  readonly ids: readonly string[];
  readonly count: number;
}

const EXPECTED_HITS_BY_FILE: Readonly<Record<string, FileExpectation>> = {
  'EmptyCatch.java': { ids: ['bugfix-java-error-handling-empty-catch'], count: 1 },
  'PrintStackTraceOnly.java': {
    ids: ['bugfix-java-error-handling-printstacktrace-only'],
    count: 1,
  },
};

describe('bugfix-java rules', () => {
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
  'bugfix-java-error-handling-empty-catch': 'error_handling',
  'bugfix-java-error-handling-printstacktrace-only': 'error_handling',
};

describe('every rule id classifies as its own class', () => {
  it('maps every id in the file', () => {
    for (const [id, cls] of Object.entries(EXPECTED_CLASS)) {
      expect(mapSubcategory(id, undefined)).toBe(cls);
    }
  });

  it('no id contains a word another class\'s regex claims first', () => {
    // Two are known. `unchecked` is matched by the error_handling regex.
    // `concurren` is matched by the race_condition regex, which runs FIRST in
    // the if-chain — so `edge-case-concurrent-modification` classified as
    // race_condition, which is why that rule is named modify-during-iteration.
    for (const id of Object.keys(EXPECTED_CLASS)) {
      expect(id).not.toContain('unchecked');
      expect(id).not.toContain('concurren');
    }
  });
});
```

- [ ] **Step 5: Run the test to verify it fails**

```powershell
$env:PATH = "C:\Users\Administrator\AppData\Roaming\Python\Python314\Scripts;$env:PATH"
$env:GUARDIAN_REQUIRE_SEMGREP = "1"
cd mcp
npx vitest run test/integration/bugfixRulesJava.test.ts test/unit/platform/configsDir.test.ts
```

Expected: FAIL — `configs/semgrep/bugfix-java.yml` does not exist yet, so both
the "rule file exists" test and the resolver's exact-array test fail.

- [ ] **Step 6: Write the rule file with the two `error_handling` rules**

```yaml
# dev-guardian Semgrep config bugfix-java.
# Bugs de implementação em Java. É a linguagem mais vazia de toda a sequência:
# o p/r2c-bug-scan traz 4 regras Java e NENHUMA cai numa classe de bug — são
# todas de igualdade e comparação. As seis subcategorias estavam todas a zero,
# na linguagem cujo defeito mais famoso é o NullPointerException. Medições em
# docs/superpowers/specs/2026-08-19-bugfix-rules-java-design.md.
#
# Cada regra tem um par de fixtures em
# mcp/test/fixtures/bugfix-java/{hits,misses}/: um ficheiro que tem de disparar
# a regra, outro parecido que NÃO pode. O ficheiro misses/ é a especificação
# do que é código correto — se ele disparar, a regra é que está errada.
#
# Duas palavras são proibidas nos ids: `unchecked`, que a regex de
# error_handling casa, e `concurren`, que a de race_condition casa e é testada
# primeiro no if-chain. É por isso que a regra de edge_case se chama
# modify-during-iteration e não concurrent-modification.
rules:
  - id: bugfix-java-error-handling-empty-catch
    pattern: |
      try { ... } catch ($E $V) { }
    message: >-
      Catch vazio. A exceção foi apanhada e deitada fora sem log, sem rethrow e
      sem tratamento, por isso a falha desaparece e o código segue como se
      nada fosse.
    severity: ERROR
    languages: [java]

  # WARNING e não ERROR: num `main` descartável imprimir o stack trace e seguir
  # é uma escolha legítima. Em serviço não é — vai para o stderr, não para o
  # log, e a execução continua como se a exceção não tivesse acontecido.
  - id: bugfix-java-error-handling-printstacktrace-only
    pattern: |
      try { ... } catch ($E $V) { $V.printStackTrace(); }
    message: >-
      O catch só faz `printStackTrace()`. Isso escreve no stderr em vez do log
      e não trata nada — a execução continua como se a exceção não tivesse
      acontecido. Registe no logger e trate ou relance.
    severity: WARNING
    languages: [java]
```

- [ ] **Step 7: Run the tests to verify they pass**

```powershell
$env:PATH = "C:\Users\Administrator\AppData\Roaming\Python\Python314\Scripts;$env:PATH"
$env:GUARDIAN_REQUIRE_SEMGREP = "1"
cd mcp
npx vitest run test/integration/bugfixRulesJava.test.ts test/unit/platform/configsDir.test.ts
```

Expected: PASS, **no skips**. Both hit fixtures at count 1; `scanned` = 2 on
both sides; zero findings across the near-misses; the resolver returns all four
packs.

- [ ] **Step 8: Prove the near-miss half is real, not vacuous**

Two mutations, both required, both pasted into the report:

1. Make `run()` scan `dir` directly instead of the temp copy. The suite must go
   **RED on the scanned-count assertions** — that is what stops "found nothing"
   passing as "scanned nothing". Restore.
2. Widen `printstacktrace-only` to `try { ... } catch ($E $V) { ... }`. The
   suite must go **RED on `misses/PrintStackTraceOnly.java`**, because both
   near-miss methods print AND then do something else. That is the distinction
   the rule turns on, and this proves the fixture tests it.

- [ ] **Step 9: Commit**

```bash
git add configs/semgrep/bugfix-java.yml mcp/test/fixtures/bugfix-java mcp/test/integration/bugfixRulesJava.test.ts mcp/test/unit/platform/configsDir.test.ts
git commit -m "feat(bugfix-rules): the two Java error_handling rules"
```

---

### Task 2: `null_safety` (2 rules)

**Files:**
- Modify: `configs/semgrep/bugfix-java.yml` (append two rules)
- Create: `mcp/test/fixtures/bugfix-java/hits/MapGetDeref.java`
- Create: `mcp/test/fixtures/bugfix-java/misses/MapGetDeref.java`
- Create: `mcp/test/fixtures/bugfix-java/hits/OptionalGet.java`
- Create: `mcp/test/fixtures/bugfix-java/misses/OptionalGet.java`
- Modify: `mcp/test/integration/bugfixRulesJava.test.ts`

**Interfaces:**
- Consumes: `configs/semgrep/bugfix-java.yml` holding the two `error_handling`
  rules; the test's `EXPECTED_HITS_BY_FILE` and `EXPECTED_CLASS` maps.
- Produces: ids `bugfix-java-null-safety-map-get-deref` and
  `bugfix-java-null-safety-optional-get-no-ispresent`.

- [ ] **Step 1: Write the two hit fixtures**

`mcp/test/fixtures/bugfix-java/hits/MapGetDeref.java`:

```java
import java.util.Map;

public class MapGetDeref {
    int deref(Map<String, Integer> m) {
        return m.get("k").intValue();
    }
}
```

`mcp/test/fixtures/bugfix-java/hits/OptionalGet.java`:

```java
import java.util.Optional;

public class OptionalGet {
    String unchecked(Optional<String> o) {
        return o.get();
    }
}
```

- [ ] **Step 2: Write the two near-miss fixtures**

`mcp/test/fixtures/bugfix-java/misses/MapGetDeref.java` — the third method is
the subtle one: `m.get(k)` with no dereference is correct and must not fire.

```java
import java.util.Map;

public class MapGetDeref {
    int checked(Map<String, Integer> m) {
        Integer v = m.get("k");
        if (v == null) { return 0; }
        return v.intValue();
    }
    int withDefault(Map<String, Integer> m) {
        return m.getOrDefault("k", 0).intValue();
    }
    Integer justGet(Map<String, Integer> m) {
        return m.get("k");
    }
}
```

`mcp/test/fixtures/bugfix-java/misses/OptionalGet.java`:

```java
import java.util.Optional;

public class OptionalGet {
    String guarded(Optional<String> o) {
        if (o.isPresent()) { return o.get(); }
        return "";
    }
    String orElse(Optional<String> o) {
        return o.orElse("");
    }
    String orElseThrowExplicit(Optional<String> o) {
        return o.orElseThrow(() -> new IllegalStateException("missing"));
    }
}
```

- [ ] **Step 3: Register the expectations**

Add to `EXPECTED_HITS_BY_FILE`:

```typescript
  'MapGetDeref.java': { ids: ['bugfix-java-null-safety-map-get-deref'], count: 1 },
  'OptionalGet.java': {
    ids: ['bugfix-java-null-safety-optional-get-no-ispresent'],
    count: 1,
  },
```

Add to `EXPECTED_CLASS`:

```typescript
  'bugfix-java-null-safety-map-get-deref': 'null_safety',
  'bugfix-java-null-safety-optional-get-no-ispresent': 'null_safety',
```

- [ ] **Step 4: Run the test to verify it fails**

```powershell
$env:PATH = "C:\Users\Administrator\AppData\Roaming\Python\Python314\Scripts;$env:PATH"
$env:GUARDIAN_REQUIRE_SEMGREP = "1"
cd mcp
npx vitest run test/integration/bugfixRulesJava.test.ts
```

Expected: FAIL — the two new hit fixtures produce no findings yet.

- [ ] **Step 5: Append the two rules**

```yaml
  # Sem cláusula de exclusão para `getOrDefault`, e isso é deliberado: o
  # Semgrep exige o identificador literal `get`, por isso
  # `m.getOrDefault(k, d).intValue()` nunca casa este padrão. Uma cláusula a
  # excluí-lo foi especificada e medida: não excluía nada, zero findings com e
  # sem ela. O que a regra exige mesmo é o DEREFERENCE.
  - id: bugfix-java-null-safety-map-get-deref
    pattern: $M.get($K).$METHOD(...)
    message: >-
      Método chamado diretamente sobre `map.get()`. O `get` devolve `null`
      quando a chave não existe, por isso isto é um NullPointerException na
      primeira chave em falta. Guarde o resultado e teste-o, ou use
      `getOrDefault`.
    severity: ERROR
    languages: [java]

  - id: bugfix-java-null-safety-optional-get-no-ispresent
    patterns:
      - pattern: $O.get()
      - pattern-not-inside: if ($O.isPresent()) { ... }
    message: >-
      `Optional.get()` sem `isPresent()`. Lança `NoSuchElementException` quando
      está vazio — que é exatamente aquilo que o Optional existia para evitar.
      Use `orElse`, `orElseThrow` com mensagem, ou guarde com `isPresent()`.
    severity: ERROR
    languages: [java]
```

- [ ] **Step 6: Run the test to verify it passes**

```powershell
$env:PATH = "C:\Users\Administrator\AppData\Roaming\Python\Python314\Scripts;$env:PATH"
$env:GUARDIAN_REQUIRE_SEMGREP = "1"
cd mcp
npx vitest run test/integration/bugfixRulesJava.test.ts
```

Expected: PASS, no skips. Four hit fixtures, four near-misses, `scanned` = 4.

- [ ] **Step 7: Prove the near-miss discriminates**

Mutate the rule to `pattern: $M.get($K)` — dropping the `.$METHOD(...)` deref
requirement — re-run, and show the suite going **RED on
`misses/MapGetDeref.java`**. Measured: `checked` and `justGet` both fire,
`withDefault` does not. Restore and show GREEN. Paste both outputs.

Mark the roles in the fixture while you are there. `checked` and `justGet` are
DISCRIMINATING; `withDefault` is DOCUMENTARY and cannot fire under any mutation
of this pattern, because `getOrDefault` is a different identifier. Say so in
the file, the way `mcp/test/fixtures/bugfix-go/misses/loop_lte_len.go` does — a
reader should not have to guess which near-misses carry weight.

- [ ] **Step 8: Commit**

```bash
git add configs/semgrep/bugfix-java.yml mcp/test/fixtures/bugfix-java mcp/test/integration/bugfixRulesJava.test.ts
git commit -m "feat(bugfix-rules): Java null_safety rules"
```

---

### Task 3: `off_by_one` (1 rule) and `memory_leak` (1 rule)

**Files:**
- Modify: `configs/semgrep/bugfix-java.yml` (append two rules)
- Create: `mcp/test/fixtures/bugfix-java/hits/LoopLteLength.java`
- Create: `mcp/test/fixtures/bugfix-java/misses/LoopLteLength.java`
- Create: `mcp/test/fixtures/bugfix-java/hits/StreamNotClosed.java`
- Create: `mcp/test/fixtures/bugfix-java/misses/StreamNotClosed.java`
- Modify: `mcp/test/integration/bugfixRulesJava.test.ts`

**Interfaces:**
- Consumes: `configs/semgrep/bugfix-java.yml` holding four rules; the test's maps.
- Produces: ids `bugfix-java-off-by-one-loop-lte-length` and
  `bugfix-java-memory-leak-stream-not-closed`.

- [ ] **Step 1: Write the two hit fixtures**

`mcp/test/fixtures/bugfix-java/hits/LoopLteLength.java`:

```java
public class LoopLteLength {
    int sumPastEnd(int[] xs) {
        int s = 0;
        for (int i = 0; i <= xs.length; i++) { s += xs[i]; }
        return s;
    }
}
```

`mcp/test/fixtures/bugfix-java/hits/StreamNotClosed.java`:

```java
import java.io.FileInputStream;
import java.io.IOException;

public class StreamNotClosed {
    void leaks(String path) throws IOException {
        FileInputStream in = new FileInputStream(path);
        in.read();
    }
}
```

- [ ] **Step 2: Write the two near-miss fixtures**

`mcp/test/fixtures/bugfix-java/misses/LoopLteLength.java` — three correct forms,
and `toLenMinusOne` is the one that discriminates a widened bound:

```java
public class LoopLteLength {
    int inBounds(int[] xs) {
        int s = 0;
        for (int i = 0; i < xs.length; i++) { s += xs[i]; }
        return s;
    }
    int toLenMinusOne(int[] xs) {
        int s = 0;
        for (int i = 0; i <= xs.length - 1; i++) { s += xs[i]; }
        return s;
    }
    int enhanced(int[] xs) {
        int s = 0;
        for (int x : xs) { s += x; }
        return s;
    }
}
```

`mcp/test/fixtures/bugfix-java/misses/StreamNotClosed.java`:

```java
import java.io.FileInputStream;
import java.io.IOException;

public class StreamNotClosed {
    void withResources(String path) throws IOException {
        try (FileInputStream in = new FileInputStream(path)) { in.read(); }
    }
}
```

- [ ] **Step 3: Register the expectations**

Add to `EXPECTED_HITS_BY_FILE`:

```typescript
  'LoopLteLength.java': { ids: ['bugfix-java-off-by-one-loop-lte-length'], count: 1 },
  'StreamNotClosed.java': { ids: ['bugfix-java-memory-leak-stream-not-closed'], count: 1 },
```

Add to `EXPECTED_CLASS`:

```typescript
  'bugfix-java-off-by-one-loop-lte-length': 'off_by_one',
  'bugfix-java-memory-leak-stream-not-closed': 'memory_leak',
```

- [ ] **Step 4: Run the test to verify it fails**

```powershell
$env:PATH = "C:\Users\Administrator\AppData\Roaming\Python\Python314\Scripts;$env:PATH"
$env:GUARDIAN_REQUIRE_SEMGREP = "1"
cd mcp
npx vitest run test/integration/bugfixRulesJava.test.ts
```

Expected: FAIL — the two new hit fixtures produce no findings yet.

- [ ] **Step 5: Append the two rules**

Note the try-with-resources exclusion names the resource explicitly. The obvious
form `try (...) { ... }` is **not a valid Java pattern** and does not parse —
measured during the probe.

```yaml
  - id: bugfix-java-off-by-one-loop-lte-length
    pattern: |
      for (int $I = 0; $I <= $A.length; $I++) { ... }
    message: >-
      Off-by-one. `i <= a.length` corre uma posição para lá do fim, e o índice
      `a.length` está sempre fora dos limites — é um
      ArrayIndexOutOfBoundsException. Queria provavelmente `i < a.length`.
    severity: ERROR
    languages: [java]

  # WARNING e não ERROR: um stream fechado num `finally` está correto e esta
  # regra não o vê. A exclusão nomeia o recurso porque `try (...) { ... }` não
  # é um padrão Java válido — medido, não suposto.
  - id: bugfix-java-memory-leak-stream-not-closed
    patterns:
      - pattern: $T $V = new FileInputStream(...);
      - pattern-not-inside: try ($T2 $V2 = new FileInputStream(...)) { ... }
    message: >-
      Stream aberto fora de um try-with-resources. Se algo lançar antes do
      `close()`, o descritor fica aberto — e em código que corre em ciclo isso
      esgota os descritores do processo.
    severity: WARNING
    languages: [java]
```

- [ ] **Step 6: Run the test to verify it passes**

```powershell
$env:PATH = "C:\Users\Administrator\AppData\Roaming\Python\Python314\Scripts;$env:PATH"
$env:GUARDIAN_REQUIRE_SEMGREP = "1"
cd mcp
npx vitest run test/integration/bugfixRulesJava.test.ts
```

Expected: PASS, no skips. Six hit fixtures, six near-misses, `scanned` = 6.

- [ ] **Step 7: Prove both near-misses discriminate**

Two mutations:

1. Widen the loop bound to `for (int $I = 0; $I <= $BOUND; $I++) { ... }`. The
   suite must go **RED on `misses/LoopLteLength.java`** because `toLenMinusOne`
   starts firing — proving that function is not decoration.
2. Remove the `pattern-not-inside` from `stream-not-closed`. The suite must go
   **RED on `misses/StreamNotClosed.java`**.

Restore both, show GREEN, paste all outputs.

- [ ] **Step 8: Commit**

```bash
git add configs/semgrep/bugfix-java.yml mcp/test/fixtures/bugfix-java mcp/test/integration/bugfixRulesJava.test.ts
git commit -m "feat(bugfix-rules): Java off_by_one and memory_leak rules"
```

---

### Task 4: `race_condition` (1), `edge_case` (1), and the no-duplication test

**Files:**
- Modify: `configs/semgrep/bugfix-java.yml` (append two rules)
- Create: `mcp/test/fixtures/bugfix-java/hits/StaticDateFormat.java`
- Create: `mcp/test/fixtures/bugfix-java/misses/StaticDateFormat.java`
- Create: `mcp/test/fixtures/bugfix-java/hits/ModifyDuringIteration.java`
- Create: `mcp/test/fixtures/bugfix-java/misses/ModifyDuringIteration.java`
- Create: `mcp/test/fixtures/bugfix-java/control/Control.java`
- Modify: `mcp/test/integration/bugfixRulesJava.test.ts`

**Interfaces:**
- Consumes: `configs/semgrep/bugfix-java.yml` holding six rules; the test's
  `run(config, dir)` helper, whose first parameter is the config precisely so a
  registry pack name can be passed instead of the local file.
- Produces: the last two ids, and the no-duplication test.

- [ ] **Step 1: Write the two hit fixtures**

`mcp/test/fixtures/bugfix-java/hits/StaticDateFormat.java` — **both** static
forms, which is why this file's expected count is 2 and not 1:

```java
import java.text.SimpleDateFormat;

public class StaticDateFormat {
    static final SimpleDateFormat SHARED_FINAL = new SimpleDateFormat("yyyy-MM-dd");
    static SimpleDateFormat SHARED_PLAIN = new SimpleDateFormat("yyyy");
}
```

`mcp/test/fixtures/bugfix-java/hits/ModifyDuringIteration.java`:

```java
import java.util.List;

public class ModifyDuringIteration {
    void removeWhileIterating(List<String> items) {
        for (String s : items) {
            if (s.isEmpty()) { items.remove(s); }
        }
    }
}
```

- [ ] **Step 2: Write the two near-miss fixtures**

`mcp/test/fixtures/bugfix-java/misses/StaticDateFormat.java`. The local instance
must be written **unqualified**: the probe's first attempt used
`java.text.SimpleDateFormat` fully qualified, which the unqualified pattern
could never have matched — so it would have passed against a badly broken rule.

```java
import java.text.SimpleDateFormat;
import java.util.Date;

public class StaticDateFormat {
    private final SimpleDateFormat perInstance = new SimpleDateFormat("yyyy");

    String localInstance() {
        SimpleDateFormat local = new SimpleDateFormat("yyyy");
        return local.format(new Date());
    }

    String useInstanceField() {
        return perInstance.format(new Date());
    }

    static final java.time.format.DateTimeFormatter THREAD_SAFE =
        java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd");
}
```

`mcp/test/fixtures/bugfix-java/misses/ModifyDuringIteration.java`:

```java
import java.util.Iterator;
import java.util.List;

public class ModifyDuringIteration {
    void viaIterator(List<String> items) {
        Iterator<String> it = items.iterator();
        while (it.hasNext()) {
            if (it.next().isEmpty()) { it.remove(); }
        }
    }
    void viaRemoveIf(List<String> items) {
        items.removeIf(String::isEmpty);
    }
    void removeFromOther(List<String> a, List<String> b) {
        for (String s : a) { b.remove(s); }
    }
    void readOnly(List<String> items) {
        for (String s : items) { System.out.println(s); }
    }
}
```

`mcp/test/fixtures/bugfix-java/control/Control.java`:

```java
public class Control {
    // Existe só para acionar a regra `eqeq` do próprio p/r2c-bug-scan,
    // provando que esse pack corre mesmo para Java. Nenhuma regra nossa
    // dispara aqui, e este diretório não faz parte dos pares hits/misses.
    boolean alwaysTrue(int x) {
        return x == x;
    }
}
```

- [ ] **Step 3: Register the expectations**

Add to `EXPECTED_HITS_BY_FILE`:

```typescript
  'ModifyDuringIteration.java': {
    ids: ['bugfix-java-edge-case-modify-during-iteration'],
    count: 1,
  },
  'StaticDateFormat.java': {
    // Two: the rule covers `static final` and plain `static`, and this fixture
    // carries one of each so neither branch can die unnoticed.
    ids: ['bugfix-java-race-condition-static-dateformat'],
    count: 2,
  },
```

Add to `EXPECTED_CLASS`:

```typescript
  'bugfix-java-race-condition-static-dateformat': 'race_condition',
  'bugfix-java-edge-case-modify-during-iteration': 'edge_case',
```

- [ ] **Step 4: Write the no-duplication test**

Append this to `mcp/test/integration/bugfixRulesJava.test.ts`:

```typescript
/**
 * Design of record §2: no local rule may re-report what `p/r2c-bug-scan`
 * already finds. For Java the pack ships 4 rules and NONE of them lands in a
 * bug class, so overlap is very unlikely — but "unlikely" is not "measured".
 *
 * It carries a POSITIVE CONTROL. Asserting that a pack found nothing proves
 * nothing on its own if the pack never ran for this language: a Java rule
 * failing to load would look identical to a clean result. So a second scan
 * runs the same pack against a file written to trip one of its own Java rules
 * (`eqeq`), and asserts it fires. Only then does the zero above mean anything.
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

describe('no local Java rule duplicates p/r2c-bug-scan', () => {
  it.runIf(REQUIRE_SEMGREP)('the registry pack must be reachable when the flag is set', () => {
    expect(R2C_ON_HITS).not.toBeNull();
    // Asserted too, and deliberately: without this the control fixture could
    // be deleted and this whole describe block would go on passing, with the
    // control test merely SKIPPING. That exact hole shipped in the Go round
    // and was caught by renaming the directory away.
    expect(R2C_ON_CONTROL).not.toBeNull();
  });

  it.skipIf(R2C_ON_CONTROL === null)('positive control: the pack IS live for Java', () => {
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

- [ ] **Step 5: Run the test to verify it fails**

```powershell
$env:PATH = "C:\Users\Administrator\AppData\Roaming\Python\Python314\Scripts;$env:PATH"
$env:GUARDIAN_REQUIRE_SEMGREP = "1"
cd mcp
npx vitest run test/integration/bugfixRulesJava.test.ts
```

Expected: FAIL — the two new hit fixtures produce no findings yet.

- [ ] **Step 6: Append the two rules**

```yaml
  # Um único pattern, e o `final` NÃO precisa de ramo próprio: o Semgrep casa
  # os modificadores Java por subconjunto, por isso `static SimpleDateFormat`
  # apanha também `static final SimpleDateFormat`. Um `pattern-either` com os
  # dois esteve aqui e o segundo ramo não mudava um único resultado — medido.
  # As tentativas de usar um metavariable nos modificadores
  # (`static $MOD SimpleDateFormat …`) não compilam sequer.
  - id: bugfix-java-race-condition-static-dateformat
    pattern: static SimpleDateFormat $N = new SimpleDateFormat(...);
    message: >-
      `SimpleDateFormat` num campo estático. A classe não é thread-safe e um
      campo estático é a definição de partilhado — sob concorrência devolve
      datas trocadas ou lança. Use `DateTimeFormatter`, que é imutável, ou uma
      instância por chamada.
    severity: ERROR
    languages: [java]

  - id: bugfix-java-edge-case-modify-during-iteration
    pattern: |
      for ($T $X : $COLL) { ... $COLL.remove(...); ... }
    message: >-
      Remoção da coleção durante o for-each sobre ela própria. Lança
      `ConcurrentModificationException` na iteração seguinte. Use
      `Iterator.remove()` ou `removeIf(...)`.
    severity: ERROR
    languages: [java]
```

- [ ] **Step 7: Run the test to verify it passes**

```powershell
$env:PATH = "C:\Users\Administrator\AppData\Roaming\Python\Python314\Scripts;$env:PATH"
$env:GUARDIAN_REQUIRE_SEMGREP = "1"
cd mcp
npx vitest run test/integration/bugfixRulesJava.test.ts
```

Expected: PASS, no skips. **Eight hit fixtures totalling 9 findings**
(`StaticDateFormat.java` contributes 2), eight near-misses with zero, `scanned`
= 8 on both sides, and `p/r2c-bug-scan` silent on every hit fixture while firing
on the control.

- [ ] **Step 8: Prove the count assertion catches what the id set cannot**

Narrow the rule to `pattern: static final SimpleDateFormat $N = new SimpleDateFormat(...);`,
re-run, and show `StaticDateFormat.java`'s count dropping from 2 to 1 —
**caught by the count assertion, not by the id set**, which stays identical.
That is exactly why the raw count is asserted alongside the ids. Restore, show
GREEN, paste both.

- [ ] **Step 9: Run the full suite**

```powershell
$env:PATH = "C:\Users\Administrator\AppData\Roaming\Python\Python314\Scripts;$env:PATH"
$env:GUARDIAN_REQUIRE_SEMGREP = "1"
cd mcp
npm run lint
npm test
```

Expected: lint exit 0; suite green with **0 skipped**. Report both counts.

- [ ] **Step 10: Commit**

```bash
git add configs/semgrep/bugfix-java.yml mcp/test/fixtures/bugfix-java mcp/test/integration/bugfixRulesJava.test.ts
git commit -m "feat(bugfix-rules): Java race_condition and edge_case rules, and the no-duplication proof"
```

---

### Task 5: Documentation

**Files:**
- Modify: `README.md` (three language sections: EN, PT, ES)
- Modify: `skills/guardian-bugfix/SKILL.md`
- Modify: `mcp/src/tools/bugHunt.ts` (tool `title`/`description`, header comment)
- Modify: `CHANGELOG.md`
- Modify: `mcp/dist/` (rebuilt, staged in the same commit)

**Interfaces:**
- Consumes: nothing at runtime. Every statement must match what Tasks 1-4
  shipped.
- Produces: no code interface.

- [ ] **Step 1: Verify the rule counts before writing any number**

```bash
grep -c "^  - id:" configs/semgrep/bugfix-js.yml configs/semgrep/bugfix-py.yml configs/semgrep/bugfix-go.yml configs/semgrep/bugfix-java.yml
```

Expected: 14, 10, 10, 8. Use what it prints. If it disagrees with this plan, the
plan is wrong and you should say so in your report.

- [ ] **Step 2: Update the three README language sections**

Each `bug_hunt` bullet currently ends by naming JS/TS, Python and Go as the
languages with local packs. Add Java and **its limitations in the same breath**,
which is this repo's documentation convention. English:

```markdown
Java has one too — `configs/semgrep/bugfix-java.yml`, eight hand-authored rules across the same six classes, and Java is the emptiest language of the four: `p/r2c-bug-scan` ships 4 Java rules and **none** of them lands in a bug class — all four are equality and comparison style — so every subcategory was at zero, in the language whose most famous defect is the `NullPointerException`. Its gaps are stated rather than implied: there is **no `Integer ==` rule**, because expressing it needs type inference Semgrep OSS does not have and the attempt fired on `v == null` and on primitive comparison — a rule that flags `v == null` would be uninstalled within a day; `stream-not-closed` only recognises `new FileInputStream(...)`, so `FileOutputStream`, `FileReader`, `Socket` and every other closeable leak identically and are not covered; `static-dateformat` only recognises `SimpleDateFormat`, so a shared `Calendar` or `Matcher` in a static field is not covered; `map-get-deref` cannot tell a nullable map from one whose keys are guaranteed present, so a map populated immediately above the read is still flagged; and `modify-during-iteration` only matches the enhanced-for form, so an indexed loop removing from the list it indexes has the same defect and is missed. **JS/TS, Python, Go and Java**: the remaining languages have no local pack yet.
```

Portuguese, in the PT section:

```markdown
O Java também tem o seu — `configs/semgrep/bugfix-java.yml`, oito regras hand-authored nas mesmas seis classes, e o Java é a linguagem mais vazia das quatro: o `p/r2c-bug-scan` traz 4 regras Java e **nenhuma** cai numa classe de bug — são todas de igualdade e comparação — por isso todas as subcategorias estavam a zero, na linguagem cujo defeito mais famoso é o `NullPointerException`. As lacunas são ditas em vez de subentendidas: **não há regra para `Integer ==`**, porque exprimi-la exige inferência de tipos que o Semgrep OSS não tem e a tentativa disparava em `v == null` e em comparação de primitivos — uma regra que acusa `v == null` seria desinstalada no primeiro dia; a `stream-not-closed` só reconhece `new FileInputStream(...)`, por isso `FileOutputStream`, `FileReader`, `Socket` e todos os outros closeables perdem descritores da mesma maneira e não são apanhados; a `static-dateformat` só reconhece `SimpleDateFormat`, por isso um `Calendar` ou um `Matcher` partilhados num campo estático não são apanhados; a `map-get-deref` não distingue um mapa que pode ter nulos de um cujas chaves estão garantidas, por isso um mapa preenchido na linha acima é marcado na mesma; e a `modify-during-iteration` só casa a forma for-each, por isso um ciclo indexado que remove da lista que indexa tem o mesmo defeito e escapa. **JS/TS, Python, Go e Java**: as restantes linguagens ainda não têm pack local.
```

Spanish, in the ES section:

```markdown
Java también tiene el suyo — `configs/semgrep/bugfix-java.yml`, ocho reglas hand-authored en las mismas seis clases, y Java es el lenguaje más vacío de los cuatro: `p/r2c-bug-scan` trae 4 reglas Java y **ninguna** cae en una clase de bug — todas son de igualdad y comparación — así que todas las subcategorías estaban a cero, en el lenguaje cuyo defecto más famoso es el `NullPointerException`. Sus carencias se dicen en vez de insinuarse: **no hay regla para `Integer ==`**, porque expresarla exige inferencia de tipos que Semgrep OSS no tiene y el intento disparaba en `v == null` y en comparación de primitivos — una regla que señala `v == null` se desinstalaría el primer día; `stream-not-closed` solo reconoce `new FileInputStream(...)`, así que `FileOutputStream`, `FileReader`, `Socket` y los demás closeables filtran igual y no se cubren; `static-dateformat` solo reconoce `SimpleDateFormat`, así que un `Calendar` o un `Matcher` compartidos en un campo estático no se cubren; `map-get-deref` no distingue un mapa que puede tener nulos de uno con claves garantizadas, así que un mapa poblado en la línea anterior se marca igual; y `modify-during-iteration` solo casa la forma for-each, así que un bucle indexado que elimina de la lista que indexa tiene el mismo defecto y se escapa. **JS/TS, Python, Go y Java**: los demás lenguajes aún no tienen pack local.
```

- [ ] **Step 3: Update the guardian-bugfix skill**

Add after the Go paragraph in `skills/guardian-bugfix/SKILL.md`:

```markdown
Para Java, o `bug_hunt` corre também por default
`configs/semgrep/bugfix-java.yml` — oito regras hand-authored, cada uma com o
seu par de fixtures — cobrindo as mesmas seis classes: catch vazio, catch que
só faz `printStackTrace()`, dereference de `map.get()`, `Optional.get()` sem
`isPresent()`, `for (int i = 0; i <= a.length; i++)`, stream aberto fora de um
try-with-resources, `SimpleDateFormat` num campo estático, e remoção de uma
coleção durante o for-each sobre ela própria. É a linguagem mais vazia no
registo: das 4 regras Java do `p/r2c-bug-scan`, nenhuma cai numa classe de bug.

Não cobrem a comparação de `Integer` com `==`. Essa regra foi tentada e
descartada: exprimi-la exige inferência de tipos que o Semgrep OSS não faz sem
compilar, e a tentativa acusava `v == null` e a comparação de primitivos. Para
essa classe, leia o código.
```

- [ ] **Step 4: Update the `bug_hunt` tool title and description**

In `mcp/src/tools/bugHunt.ts`, the registered tool's `title` and `description`
name the JS/TS, Python and Go packs. Add Java to both, and to the file's header
comment, keeping the counts consistent with what Step 1 printed.

- [ ] **Step 5: Add the CHANGELOG entry**

Add to the existing `## [Unreleased]` section (or create one at the top):

```markdown
### Added

- **Java bug rules** — `configs/semgrep/bugfix-java.yml`, eight hand-authored
  Semgrep rules covering all six `bug_hunt` subcategories for Java: empty
  catch, catch that only calls `printStackTrace()`, dereference of
  `map.get()`, `Optional.get()` without `isPresent()`,
  `for (int i = 0; i <= a.length; i++)`, a stream opened outside
  try-with-resources, `SimpleDateFormat` in a static field, and removal from a
  collection during a for-each over it. Java is the emptiest language in the
  registry: of `p/r2c-bug-scan`'s 4 Java rules, **none** lands in a bug class.

### Known gaps

- **No `Integer ==` rule.** Expressing it needs type inference Semgrep OSS does
  not have; the attempt fired on `v == null` and on primitive comparison.
- `stream-not-closed` only recognises `new FileInputStream(...)`.
- `static-dateformat` only recognises `SimpleDateFormat`.
- `map-get-deref` has no dataflow, so a map populated on the line above is
  still flagged.
- `modify-during-iteration` only matches the enhanced-for form.
```

- [ ] **Step 6: Build, lint, test, markdownlint**

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
issues. `bugHunt.ts` changed, so `mcp/dist/` MUST be rebuilt and staged in this
commit.

- [ ] **Step 7: Commit**

```bash
git add README.md skills/guardian-bugfix/SKILL.md mcp/src/tools/bugHunt.ts CHANGELOG.md mcp/dist
git commit -m "docs(bugfix-rules): the Java pack, and what it does not cover"
```

---

## Verification summary

All of it already measured on the rule set this plan carries:

| Check | Expected |
| --- | --- |
| Hit fixtures | 8 files, **9 findings** — one each, except `StaticDateFormat.java` at 2 |
| Near-miss fixtures | 8 files, **0 findings** |
| `paths.scanned` | 8 on both sides — asserted, not assumed |
| `p/r2c-bug-scan` on the hit fixtures | **0 findings**, with a positive control firing `eqeq` |
| `mapSubcategory` | all 8 ids land in their own class; none contains `unchecked` or `concurren` |
| Resolver | `configsDir.test.ts` pins all four packs, `bugfix-java.yml` included |
| Full suite | green with `GUARDIAN_REQUIRE_SEMGREP=1`, **no skips**; `npm run lint` exit 0 |
