# Python bug-finding Semgrep rules — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `configs/semgrep/bugfix-py.yml` — ten hand-authored Semgrep rules
covering all six bug subcategories for Python — and make `bug_hunt`'s rule-file
resolver plural so every later language needs no further wiring.

**Architecture:** A plain Semgrep YAML rule file beside the existing
`bugfix-js.yml`, with a hit/near-miss fixture pair per rule and an integration
test that asserts the exact rule ids AND the raw finding count per file.
`resolveBugfixRules()` changes from returning one path-or-`null` to returning
every `bugfix-*.yml` it finds, and `buildPackList` splices that array into the
`--config=` list.

**Tech Stack:** Semgrep OSS 1.164.0 (pattern rules, no dataflow), TypeScript
(ESM, NodeNext), vitest.

**Source of truth:** `docs/superpowers/specs/2026-08-18-bugfix-rules-python-design.md`.
Read §8 before writing any rule — it records seven things measurement changed,
including one rule that is **not expressible in Semgrep** and was replaced.

## Global Constraints

- **Every rule's YAML in this plan has been run against its own fixtures with
  Semgrep 1.164.0 and verified.** Use it verbatim. If you change a pattern, you
  own re-proving both halves: it fires on the hit fixture and is silent on the
  near-miss.
- **Semgrep is installed but NOT on PATH on this machine.** It is at
  `C:\Users\Administrator\AppData\Roaming\Python\Python314\Scripts\semgrep.exe`.
  Prepend that directory to `PATH` before running the suite. If you do not, every
  Semgrep test SKIPS and you will read a green suite that proved nothing.
- **Semgrep cannot be invoked through the Bash tool** (it returns
  `<ERROR: missing output>`). Use PowerShell for any direct Semgrep run.
- **Verify with `GUARDIAN_REQUIRE_SEMGREP=1`** at least once per task — it turns
  Semgrep's absence into a hard failure instead of a silent skip.
- **Rule id format:** `bugfix-py-<class-token>-<name>`, where `<class-token>` is
  one of exactly `race-condition`, `null-safety`, `off-by-one`, `memory-leak`,
  `error-handling`, `edge-case`. `mapSubcategory` classifies by regex over the
  lowercased id, not a lookup table.
- **No id may contain the word `unchecked`** — the `error_handling` regex matches
  it, and relying on `null_safety` being tested earlier in the if-chain is a
  branch-order dependency this language does not need to take on.
- **Rule messages in Portuguese**, matching `configs/semgrep/base.yml` and
  `bugfix-js.yml`.
- **TypeScript:** ESM `NodeNext` (`.js` import specifiers), `noUncheckedIndexedAccess`
  on, **no `!` non-null assertions, no `any`** — in tests too. No new runtime
  dependencies.
- **Commit the compiled `mcp/dist/`** in the SAME commit as any `mcp/src/` change.
  Run `npm run build` from `mcp/` first. A stale `dist/` silently desyncs.
- **Markdownlint stays clean** for `skills/`, `commands/` and `README.md`.
- Build and test from `mcp/`: `npm run build`, `npm test`.

---

### Task 1: Rule file, test harness, and the three `error_handling` rules

**Files:**
- Create: `configs/semgrep/bugfix-py.yml`
- Create: `mcp/test/fixtures/bugfix-py/hits/bare_except.py`
- Create: `mcp/test/fixtures/bugfix-py/misses/bare_except.py`
- Create: `mcp/test/fixtures/bugfix-py/hits/except_pass.py`
- Create: `mcp/test/fixtures/bugfix-py/misses/except_pass.py`
- Create: `mcp/test/fixtures/bugfix-py/hits/get_without_doesnotexist.py`
- Create: `mcp/test/fixtures/bugfix-py/misses/get_without_doesnotexist.py`
- Create: `mcp/test/integration/bugfixRulesPy.test.ts`

**Interfaces:**
- Consumes: `mapSubcategory(ruleId: string, existing: string | undefined): string | undefined`
  from `../../src/tools/bugHunt.js`.
- Produces: `configs/semgrep/bugfix-py.yml` with a single top-level `rules:` list,
  extended by Tasks 2–4. `mcp/test/integration/bugfixRulesPy.test.ts` exporting
  nothing, but owning two module-level constant maps that Tasks 2–4 extend:
  `EXPECTED_HITS_BY_FILE: Readonly<Record<string, { ids: readonly string[]; count: number }>>`
  and `EXPECTED_CLASS: Readonly<Record<string, string>>`.

- [ ] **Step 1: Write the three hit fixtures**

`mcp/test/fixtures/bugfix-py/hits/bare_except.py`:

```python
def load(path):
    try:
        return read_file(path)
    except:
        return None
```

`mcp/test/fixtures/bugfix-py/hits/except_pass.py` — four functions, one per
clause form the rule must cover:

```python
def a(conn):
    try:
        conn.commit()
    except ValueError:
        pass


def b(conn):
    try:
        conn.commit()
    except ValueError as exc:
        pass


def c(conn):
    try:
        conn.commit()
    except ValueError as exc:
        ...


def d(conn):
    try:
        conn.commit()
    except ValueError:
        ...


def e(conn):
    try:
        conn.commit()
    except:
        pass
```

`mcp/test/fixtures/bugfix-py/hits/get_without_doesnotexist.py`:

```python
def profile(user_id):
    return User.objects.get(pk=user_id)
```

- [ ] **Step 2: Write the three near-miss fixtures**

These are the specification of what correct code looks like. If one of them
fires, the rule is wrong — not the fixture.

`mcp/test/fixtures/bugfix-py/misses/bare_except.py`:

```python
def load(path):
    try:
        return read_file(path)
    except OSError as exc:
        log(exc)
        raise
```

`mcp/test/fixtures/bugfix-py/misses/except_pass.py` — the third function is the
one that matters: a `pass` followed by another statement is NOT an empty handler,
and the rule must not fire on it:

```python
def a(conn):
    try:
        conn.commit()
    except ValueError as exc:
        log(exc)


def b(conn):
    try:
        conn.commit()
    except ValueError:
        raise


def c(conn):
    try:
        conn.commit()
    except ValueError:
        pass
        log("recovered")
```

`mcp/test/fixtures/bugfix-py/misses/get_without_doesnotexist.py` — all three
guard forms, all correct code:

```python
from django.core.exceptions import ObjectDoesNotExist


def dotted(user_id):
    try:
        return User.objects.get(pk=user_id)
    except User.DoesNotExist:
        return None


def imported(user_id):
    try:
        return User.objects.get(pk=user_id)
    except ObjectDoesNotExist:
        return None


def broad(user_id):
    try:
        return User.objects.get(pk=user_id)
    except Exception:
        return None
```

- [ ] **Step 3: Write the test harness with only the Task 1 expectations**

Create `mcp/test/integration/bugfixRulesPy.test.ts`. This mirrors
`mcp/test/integration/bugfixRulesJs.test.ts` — read that file first; its module
comment explains why the fixtures are copied to a temp dir (Semgrep's default
ignore list skips any path containing a `test/` directory, so scanning in place
scans zero files and makes every assertion vacuous) and why the count matters
alongside the id set.

```typescript
/**
 * Runs the local `bugfix-py.yml` Semgrep rules against the fixture pairs in
 * `mcp/test/fixtures/bugfix-py/{hits,misses}/` and asserts, per file, the
 * EXACT set of rule ids that fired AND the raw non-deduplicated finding
 * count. Never "at least one": a rule that starts matching its own
 * near-miss must fail the suite rather than quietly widening (design of
 * record §2 and §6:
 * docs/superpowers/specs/2026-08-18-bugfix-rules-python-design.md).
 *
 * The count is load-bearing alongside the id set, for the reason
 * `bugfixRulesJs.test.ts`'s module comment records at length: a
 * deduplicated id set is unchanged whether one or several instances of the
 * same rule still fire in a file, so it cannot prove a specific instance is
 * still caught. Several fixtures here have more than one function expected
 * to produce the same id.
 *
 * Fixtures are copied to a temp dir outside any `test/`-named path before
 * scanning — pointed straight at the in-repo fixture, Semgrep reports
 * `paths.scanned: []` and zero results REGARDLESS of the rules, which would
 * make the near-miss half of this proof pass for the wrong reason.
 *
 * SKIPPED, not silently passed, when Semgrep is not on PATH;
 * `GUARDIAN_REQUIRE_SEMGREP=1` turns that absence into a hard failure.
 */

import { describe, expect, it } from 'vitest';
import { execFileSync } from 'node:child_process';
import { cpSync, existsSync, mkdtempSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { mapSubcategory } from '../../src/tools/bugHunt.js';

const REPO_ROOT = resolve(fileURLToPath(new URL('../../..', import.meta.url)));
const RULES = resolve(REPO_ROOT, 'configs', 'semgrep', 'bugfix-py.yml');
const FIXTURES = resolve(REPO_ROOT, 'mcp', 'test', 'fixtures', 'bugfix-py');
const REQUIRE_SEMGREP = process.env['GUARDIAN_REQUIRE_SEMGREP'] === '1';

function semgrepAvailable(): boolean {
  try { execFileSync('semgrep', ['--version'], { stdio: 'ignore' }); return true; }
  catch { return false; }
}
const AVAILABLE = semgrepAvailable();

interface SemgrepResult { check_id: string; path: string }

function run(config: string, dir: string): SemgrepResult[] {
  const work = mkdtempSync(join(tmpdir(), 'guardian-bugfix-py-'));
  cpSync(dir, work, { recursive: true });
  const out = execFileSync(
    'semgrep',
    ['--config', config, '--json', '--quiet', '--no-git-ignore', work],
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

/** Groups RAW rows (no dedup) by the BASENAME of their path — the full path
 *  is a fresh mkdtempSync directory on every run. Kept raw because the count
 *  per file is itself load-bearing. */
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
  return readdirSync(dir).filter((name) => name.endsWith('.py')).sort();
}

interface FileExpectation {
  readonly ids: readonly string[];
  readonly count: number;
}

const EXPECTED_HITS_BY_FILE: Readonly<Record<string, FileExpectation>> = {
  'bare_except.py': { ids: ['bugfix-py-error-handling-bare-except'], count: 1 },
  'except_pass.py': {
    // A bare `except:` whose body is `pass` is genuinely BOTH bugs, so this
    // file legitimately produces two ids. Measured, not assumed.
    ids: [
      'bugfix-py-error-handling-bare-except',
      'bugfix-py-error-handling-except-pass',
    ],
    count: 6,
  },
  'get_without_doesnotexist.py': {
    ids: ['bugfix-py-error-handling-get-without-doesnotexist'],
    count: 1,
  },
};

describe('bugfix-py rules', () => {
  it.runIf(REQUIRE_SEMGREP)('the toolchain must be usable when the flag is set', () => {
    expect(AVAILABLE).toBe(true);
  });

  it('the rule file exists where bug_hunt will look for it', () => {
    expect(existsSync(RULES)).toBe(true);
  });

  it.skipIf(!AVAILABLE)(
    'Step 0: every hits/ fixture file on disk has a registered expectation, and vice versa',
    () => {
      expect(fixtureFiles(resolve(FIXTURES, 'hits'))).toEqual(
        Object.keys(EXPECTED_HITS_BY_FILE).sort(),
      );
    },
  );

  it.skipIf(!AVAILABLE)(
    'fires exactly the expected rule, exactly the expected number of times, in EACH hit fixture file',
    () => {
      const grouped = rowsByFile(run(RULES, resolve(FIXTURES, 'hits')));
      for (const [file, expected] of Object.entries(EXPECTED_HITS_BY_FILE)) {
        const rows = grouped[file] ?? [];
        expect(ids(rows)).toEqual(expected.ids);
        expect(rows.length).toBe(expected.count);
      }
    },
  );

  it.skipIf(!AVAILABLE)('fires NOTHING in EACH near-miss fixture file', () => {
    const grouped = rowsByFile(run(RULES, resolve(FIXTURES, 'misses')));
    for (const file of fixtureFiles(resolve(FIXTURES, 'misses'))) {
      expect(grouped[file] ?? []).toEqual([]);
    }
  });
});

/** Rule ids carry the class token because `mapSubcategory` classifies by
 *  regex over the lowercased id, not by lookup table. Runs unconditionally —
 *  it calls the pure classifier, no Semgrep involved. */
const EXPECTED_CLASS: Readonly<Record<string, string>> = {
  'bugfix-py-error-handling-bare-except': 'error_handling',
  'bugfix-py-error-handling-except-pass': 'error_handling',
  'bugfix-py-error-handling-get-without-doesnotexist': 'error_handling',
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
    // is tested earlier in the if-chain. This language does not take on that
    // branch-order dependency (design of record §4).
    for (const id of Object.keys(EXPECTED_CLASS)) {
      expect(id).not.toContain('unchecked');
    }
  });
});
```

- [ ] **Step 4: Run the test to verify it fails**

```powershell
$env:PATH = "C:\Users\Administrator\AppData\Roaming\Python\Python314\Scripts;$env:PATH"
cd mcp
npx vitest run test/integration/bugfixRulesPy.test.ts
```

Expected: FAIL — `configs/semgrep/bugfix-py.yml` does not exist yet, so the
"rule file exists" test fails and the Semgrep runs error.

- [ ] **Step 5: Write the rule file with the three `error_handling` rules**

Create `configs/semgrep/bugfix-py.yml`. The header comment mirrors
`bugfix-js.yml`'s. **The YAML below is verified** — `except-pass` needs five
branches because `except $E:` does not match `except $E as $V:`, and a literal
`...` body is not matchable by an AST pattern (`...` in pattern position is
always the ellipsis operator) and needs `metavariable-regex` over a `$BODY`
metavariable instead.

```yaml
# dev-guardian Semgrep config bugfix-py.
# Bugs de implementação em Python. Ao contrário do JS/TS, aqui já correm 32
# regras Python do p/r2c-bug-scan — mas só 10 caem numa classe de bug, e
# nenhuma cobre bare except, dereference de None, ou off-by-one. Cada regra
# abaixo foi medida contra o pack existente: nenhuma duplica o que ele já
# encontra. Detalhe e medições em
# docs/superpowers/specs/2026-08-18-bugfix-rules-python-design.md.
#
# Cada regra tem um par de fixtures em
# mcp/test/fixtures/bugfix-py/{hits,misses}/: um ficheiro que tem de disparar
# a regra, outro parecido que NÃO pode. O ficheiro misses/ é a especificação
# do que é código correto — se ele disparar, a regra é que está errada.
#
# Os ids seguem o formato bugfix-py-<classe>-<nome>, em que <classe> tem de
# ser um dos seis tokens que mapSubcategory (mcp/src/tools/bugHunt.ts)
# reconhece por regex sobre o id em minúsculas: race-condition, null-safety,
# off-by-one, memory-leak, error-handling, edge-case. Nenhum id usa a palavra
# `unchecked`: a regex de error_handling casa-a, e depender da ordem do
# if-chain para desempatar é uma dependência que esta linguagem não precisa
# de assumir.
#
# Duas severidades: ERROR quando o padrão é sempre um bug, independentemente
# da intenção; WARNING quando é normalmente um bug mas tem usos legítimos.
rules:
  - id: bugfix-py-error-handling-bare-except
    pattern: |
      try:
          ...
      except:
          ...
    message: >-
      `except:` sem tipo apanha tudo, incluindo SystemExit e
      KeyboardInterrupt, por isso engole sinais de paragem além de erros
      reais. Apanhe a exceção concreta, ou pelo menos `except Exception:`.
    severity: ERROR
    languages: [python]

  # Cinco branches, e cada uma é necessária: `except $E:` NÃO casa
  # `except $E as $V:`, e um corpo que é literalmente `...` não é
  # exprimível como padrão AST — `...` em posição de padrão é sempre o
  # operador de elipse do Semgrep, nunca o literal Ellipsis. A única forma
  # de o apanhar é ligar o corpo a um metavariable e testar o TEXTO com
  # metavariable-regex. Ambas as coisas foram medidas, não assumidas.
  #
  # Um corpo com mais do que uma instrução (`pass` seguido de outra coisa)
  # não casa nenhuma branch, e é isso que se quer: já não é um handler
  # vazio. Confirmado com fixture própria em misses/except_pass.py.
  - id: bugfix-py-error-handling-except-pass
    pattern-either:
      - pattern: |
          try:
              ...
          except $E:
              pass
      - pattern: |
          try:
              ...
          except $E as $V:
              pass
      - pattern: |
          try:
              ...
          except:
              pass
      - patterns:
          - pattern-either:
              - pattern: |
                  try:
                      ...
                  except $E:
                      $BODY
              - pattern: |
                  try:
                      ...
                  except $E as $V:
                      $BODY
          - metavariable-regex:
              metavariable: $BODY
              regex: ^\.\.\.$
    message: >-
      Erro engolido em silêncio. O corpo do `except` é apenas `pass` (ou
      `...`), por isso a falha desaparece sem log, sem re-raise e sem
      tratamento.
    severity: ERROR
    languages: [python]

  # Três exclusões, não uma. As três formas de guardar são código correto e
  # as três dispararam com a versão de uma exclusão só:
  #   - except User.DoesNotExist       (a forma do modelo)
  #   - except ObjectDoesNotExist      (import de django.core.exceptions)
  #   - except Exception               (largo, mas apanha o miss na mesma)
  - id: bugfix-py-error-handling-get-without-doesnotexist
    patterns:
      - pattern: $M.objects.get(...)
      - pattern-not-inside: |
          try:
              ...
          except $X.DoesNotExist:
              ...
      - pattern-not-inside: |
          try:
              ...
          except ObjectDoesNotExist:
              ...
      - pattern-not-inside: |
          try:
              ...
          except Exception:
              ...
    message: >-
      `.objects.get()` sem guardar o miss. O Django levanta DoesNotExist em
      vez de devolver None, por isso a primeira linha em falta é um 500 não
      tratado. Envolva num try/except DoesNotExist, ou use `.filter().first()`.
    severity: WARNING
    languages: [python]
```

- [ ] **Step 6: Run the test to verify it passes**

```powershell
$env:PATH = "C:\Users\Administrator\AppData\Roaming\Python\Python314\Scripts;$env:PATH"
$env:GUARDIAN_REQUIRE_SEMGREP = "1"
cd mcp
npx vitest run test/integration/bugfixRulesPy.test.ts
```

Expected: PASS, with **no skipped tests**. `bare_except.py` count 1,
`except_pass.py` count 4, `get_without_doesnotexist.py` count 1, and zero
findings across all three near-miss files.

- [ ] **Step 7: Prove the near-miss half is real, not vacuous**

This is the step that separates a proof from a green tick. Temporarily delete
the three `pattern-not-inside` clauses from
`bugfix-py-error-handling-get-without-doesnotexist`, re-run, and confirm the
suite goes **RED** on `misses/get_without_doesnotexist.py`. Then restore them
and confirm GREEN again. Record the RED output in your task report. If deleting
the guard leaves the suite green, the test is not testing what it claims.

- [ ] **Step 8: Commit**

```bash
git add configs/semgrep/bugfix-py.yml mcp/test/fixtures/bugfix-py mcp/test/integration/bugfixRulesPy.test.ts
git commit -m "feat(bugfix-rules): the three Python error_handling rules"
```

---

### Task 2: `null_safety` (2 rules) and `off_by_one` (1 rule)

**Files:**
- Modify: `configs/semgrep/bugfix-py.yml` (append three rules to the `rules:` list)
- Create: `mcp/test/fixtures/bugfix-py/hits/none_deref_match.py`
- Create: `mcp/test/fixtures/bugfix-py/misses/none_deref_match.py`
- Create: `mcp/test/fixtures/bugfix-py/hits/none_deref_dict_get.py`
- Create: `mcp/test/fixtures/bugfix-py/misses/none_deref_dict_get.py`
- Create: `mcp/test/fixtures/bugfix-py/hits/range_len_plus_one.py`
- Create: `mcp/test/fixtures/bugfix-py/misses/range_len_plus_one.py`
- Modify: `mcp/test/integration/bugfixRulesPy.test.ts` (`EXPECTED_HITS_BY_FILE`, `EXPECTED_CLASS`)

**Interfaces:**
- Consumes: `configs/semgrep/bugfix-py.yml` with a `rules:` list holding the three
  `error_handling` rules from Task 1; `bugfixRulesPy.test.ts`'s
  `EXPECTED_HITS_BY_FILE: Readonly<Record<string, { ids: readonly string[]; count: number }>>`
  and `EXPECTED_CLASS: Readonly<Record<string, string>>`.
- Produces: three more ids —
  `bugfix-py-null-safety-none-deref-match`,
  `bugfix-py-null-safety-none-deref-dict-get`,
  `bugfix-py-off-by-one-range-len-plus-one`.

- [ ] **Step 1: Write the three hit fixtures**

`mcp/test/fixtures/bugfix-py/hits/none_deref_match.py`:

```python
import re


def version(text):
    return re.match(r"v(\d+)", text).group(1)


def build(text):
    return re.search(r"b(\d+)", text).group(0)
```

`mcp/test/fixtures/bugfix-py/hits/none_deref_dict_get.py`:

```python
def name(payload):
    return payload.get("name").strip()


def nested(payload):
    return payload.get("meta").get("id")
```

`mcp/test/fixtures/bugfix-py/hits/range_len_plus_one.py`:

```python
def total(values):
    acc = 0
    for i in range(len(values) + 1):
        acc += values[i]
    return acc


def last(values):
    return values[len(values)]
```

- [ ] **Step 2: Write the three near-miss fixtures**

`mcp/test/fixtures/bugfix-py/misses/none_deref_match.py`:

```python
import re


def version(text):
    found = re.match(r"v(\d+)", text)
    if found is None:
        return "0"
    return found.group(1)


def compiled(pattern, text):
    return pattern.finditer(text)
```

`mcp/test/fixtures/bugfix-py/misses/none_deref_dict_get.py` — the four HTTP-client
functions are the whole point of the receiver-name exclusion. `requests.get(url)`
is the same syntax as a dict lookup and never returns `None`:

```python
import requests


def defaulted(payload):
    return payload.get("name", "").strip()


def http_var(url):
    return requests.get(url).json()


def http_literal():
    return requests.get("https://example.test/x").json()


def http_session(session):
    return session.get("/x").json()


def http_client(self):
    return self.client.get("/x").json()


def guarded(payload):
    value = payload.get("name")
    if value is None:
        return ""
    return value.strip()
```

`mcp/test/fixtures/bugfix-py/misses/range_len_plus_one.py`:

```python
def total(values):
    acc = 0
    for i in range(len(values)):
        acc += values[i]
    return acc


def last(values):
    return values[len(values) - 1]


def pairs(values):
    return [(i, values[i]) for i in range(len(values) - 1)]
```

- [ ] **Step 3: Register the expectations in the test**

In `mcp/test/integration/bugfixRulesPy.test.ts`, add these three entries to
`EXPECTED_HITS_BY_FILE`:

```typescript
  'none_deref_dict_get.py': { ids: ['bugfix-py-null-safety-none-deref-dict-get'], count: 2 },
  'none_deref_match.py': { ids: ['bugfix-py-null-safety-none-deref-match'], count: 2 },
  'range_len_plus_one.py': { ids: ['bugfix-py-off-by-one-range-len-plus-one'], count: 2 },
```

and these three to `EXPECTED_CLASS`:

```typescript
  'bugfix-py-null-safety-none-deref-match': 'null_safety',
  'bugfix-py-null-safety-none-deref-dict-get': 'null_safety',
  'bugfix-py-off-by-one-range-len-plus-one': 'off_by_one',
```

- [ ] **Step 4: Run the test to verify it fails**

```powershell
$env:PATH = "C:\Users\Administrator\AppData\Roaming\Python\Python314\Scripts;$env:PATH"
$env:GUARDIAN_REQUIRE_SEMGREP = "1"
cd mcp
npx vitest run test/integration/bugfixRulesPy.test.ts
```

Expected: FAIL — the three new hit fixtures produce zero findings because the
rules do not exist yet, so `ids(rows)` is `[]` against the expected id, and
`mapSubcategory` is asserted for ids no rule defines.

- [ ] **Step 5: Append the three rules to `configs/semgrep/bugfix-py.yml`**

```yaml
  - id: bugfix-py-null-safety-none-deref-match
    pattern-either:
      - pattern: re.match(...).group(...)
      - pattern: re.search(...).group(...)
      - pattern: re.fullmatch(...).group(...)
    message: >-
      `.group()` direto no resultado de re.match/search/fullmatch. Quando o
      padrão não casa, o retorno é None e isto é um AttributeError em
      produção. Guarde o match numa variável e teste-a antes.
    severity: ERROR
    languages: [python]

  # A exclusão por nome do receiver não é cosmética: `requests.get(url).json()`
  # é sintaticamente idêntico a um lookup de dicionário e NÃO devolve None.
  # Sem ela a regra dispara em todo o código que fala HTTP — medido, não
  # suposto. O custo é conhecido e está nas limitações do design: um cliente
  # HTTP com outro nome é falso positivo, um dicionário chamado `client` é
  # falso negativo.
  - id: bugfix-py-null-safety-none-deref-dict-get
    patterns:
      - pattern: $D.get($K).$M(...)
      - pattern-not: $D.get($K, $DEF).$M(...)
      - metavariable-regex:
          metavariable: $D
          regex: ^(?!.*(requests|session|client|httpx|aiohttp|urllib)).*$
    message: >-
      Método chamado diretamente sobre `.get()` de um dicionário. `.get()`
      devolve None quando a chave não existe, por isso isto é um
      AttributeError na primeira chave em falta. Passe um default
      (`.get(k, ...)`) ou teste o resultado.
    severity: ERROR
    languages: [python]

  # O índice TEM de subscrever a mesma sequência de onde veio o len(). Uma
  # versão anterior desta regra dispensava essa exigência, alegando zero
  # falsos positivos contra as near-miss — alegação vazia, porque nenhuma
  # near-miss continha sequer `range(len(x) + 1)`. Medido depois: a forma
  # solta dispara em `for i in range(len(a) + 1): dp[i] = i`, o idioma
  # normal de semear um array de DP com n+1 posições, onde o índice
  # subscreve OUTRO array, do tamanho certo. Isso é código correto, e a
  # severidade deste ficheiro define ERROR como "sempre um bug,
  # independentemente da intenção".
  - id: bugfix-py-off-by-one-range-len-plus-one
    pattern-either:
      - pattern: |
          for $I in range(len($X) + 1):
              <... $X[$I] ...>
      - pattern: $X[len($X)]
    message: >-
      Off-by-one. `range(len(x) + 1)` itera uma posição a mais do que a
      sequência tem, e `x[len(x)]` está sempre fora dos limites — ambos são
      IndexError. Queria provavelmente `range(len(x))` e `x[len(x) - 1]`.
    severity: ERROR
    languages: [python]
```

- [ ] **Step 6: Run the test to verify it passes**

```powershell
$env:PATH = "C:\Users\Administrator\AppData\Roaming\Python\Python314\Scripts;$env:PATH"
$env:GUARDIAN_REQUIRE_SEMGREP = "1"
cd mcp
npx vitest run test/integration/bugfixRulesPy.test.ts
```

Expected: PASS, no skips. Six hit files now, six near-miss files, all silent.

- [ ] **Step 7: Prove the receiver-name exclusion is load-bearing**

Temporarily delete the `metavariable-regex` clause from
`bugfix-py-null-safety-none-deref-dict-get`, re-run, and confirm **RED** on
`misses/none_deref_dict_get.py` (the four HTTP functions fire). Restore it,
confirm GREEN. Record the RED output in your task report.

- [ ] **Step 8: Commit**

```bash
git add configs/semgrep/bugfix-py.yml mcp/test/fixtures/bugfix-py mcp/test/integration/bugfixRulesPy.test.ts
git commit -m "feat(bugfix-rules): Python null_safety and off_by_one rules"
```

---

### Task 3: `memory_leak` (1 rule) and `race_condition` (2 rules)

Read §8 of the design of record before starting. The `race_condition` slot
originally held one rule — "a call to a function defined `async def` in the same
file, appearing as a bare statement" — and it is **not expressible in Semgrep
OSS**. The two rules below replaced it. Do not attempt to reinstate the original:
the sequence pattern matches but reports at the definition line and fires
identically on `await f(x)`, `return f(x)` and `asyncio.create_task(f(x))`.

**Files:**
- Modify: `configs/semgrep/bugfix-py.yml` (append three rules)
- Create: `mcp/test/fixtures/bugfix-py/hits/open_without_context.py`
- Create: `mcp/test/fixtures/bugfix-py/misses/open_without_context.py`
- Create: `mcp/test/fixtures/bugfix-py/hits/asyncio_not_awaited.py`
- Create: `mcp/test/fixtures/bugfix-py/misses/asyncio_not_awaited.py`
- Create: `mcp/test/fixtures/bugfix-py/hits/toctou_exists_open.py`
- Create: `mcp/test/fixtures/bugfix-py/misses/toctou_exists_open.py`
- Modify: `mcp/test/integration/bugfixRulesPy.test.ts`

**Interfaces:**
- Consumes: `configs/semgrep/bugfix-py.yml` with six rules; the test's
  `EXPECTED_HITS_BY_FILE` and `EXPECTED_CLASS` maps.
- Produces: three more ids —
  `bugfix-py-memory-leak-open-without-context`,
  `bugfix-py-race-condition-asyncio-not-awaited`,
  `bugfix-py-race-condition-toctou-exists-open`.

- [ ] **Step 1: Write the three hit fixtures**

`mcp/test/fixtures/bugfix-py/hits/open_without_context.py`:

```python
def dump(path, rows):
    handle = open(path, "w")
    for row in rows:
        handle.write(row)
```

`mcp/test/fixtures/bugfix-py/hits/asyncio_not_awaited.py`:

```python
import asyncio


async def throttle():
    asyncio.sleep(1)
    return "done"


async def fan_out(items):
    asyncio.gather(*[work(i) for i in items])
    return "done"
```

`mcp/test/fixtures/bugfix-py/hits/toctou_exists_open.py`:

```python
import os


def read_if_present(path):
    if os.path.exists(path):
        return open(path).read()
    return ""
```

- [ ] **Step 2: Write the three near-miss fixtures**

`mcp/test/fixtures/bugfix-py/misses/open_without_context.py` — the `Writer` class
is the reason attribute targets are excluded: its `close()` lives in another
method, which a syntactic rule cannot see:

```python
def managed(path, rows):
    with open(path, "w") as handle:
        for row in rows:
            handle.write(row)


def explicit(path, rows):
    handle = open(path, "w")
    try:
        for row in rows:
            handle.write(row)
    finally:
        handle.close()


class Writer:
    def __init__(self, path):
        self.handle = open(path, "w")

    def close(self):
        self.handle.close()
```

`mcp/test/fixtures/bugfix-py/misses/asyncio_not_awaited.py`:

```python
import asyncio


async def throttle():
    await asyncio.sleep(1)
    return "done"


async def fan_out(items):
    await asyncio.gather(*[work(i) for i in items])
    return "done"


async def scheduled():
    asyncio.create_task(work(1))
    return "done"


async def deferred():
    return asyncio.sleep(1)


async def stored():
    pending = asyncio.gather(work(1))
    return await pending
```

`mcp/test/fixtures/bugfix-py/misses/toctou_exists_open.py`:

```python
import os


def read_guarded(path):
    try:
        return open(path).read()
    except FileNotFoundError:
        return ""


def check_only(path):
    if os.path.exists(path):
        return True
    return False
```

- [ ] **Step 3: Register the expectations in the test**

Add to `EXPECTED_HITS_BY_FILE`:

```typescript
  'asyncio_not_awaited.py': { ids: ['bugfix-py-race-condition-asyncio-not-awaited'], count: 2 },
  'open_without_context.py': { ids: ['bugfix-py-memory-leak-open-without-context'], count: 1 },
  'toctou_exists_open.py': { ids: ['bugfix-py-race-condition-toctou-exists-open'], count: 1 },
```

Add to `EXPECTED_CLASS`:

```typescript
  'bugfix-py-memory-leak-open-without-context': 'memory_leak',
  'bugfix-py-race-condition-asyncio-not-awaited': 'race_condition',
  'bugfix-py-race-condition-toctou-exists-open': 'race_condition',
```

- [ ] **Step 4: Run the test to verify it fails**

```powershell
$env:PATH = "C:\Users\Administrator\AppData\Roaming\Python\Python314\Scripts;$env:PATH"
$env:GUARDIAN_REQUIRE_SEMGREP = "1"
cd mcp
npx vitest run test/integration/bugfixRulesPy.test.ts
```

Expected: FAIL — the three new hit fixtures produce no findings.

- [ ] **Step 5: Append the three rules to `configs/semgrep/bugfix-py.yml`**

```yaml
  # A exclusão de targets que são atributos (`self.handle = open(...)`) é
  # deliberada: nesse caso o close() vive noutro método, fora do alcance de
  # uma regra sintática, por isso disparar ali seria um palpite. Sem a
  # exclusão a regra dispara na classe Writer da fixture de near-miss, que é
  # código correto.
  - id: bugfix-py-memory-leak-open-without-context
    patterns:
      - pattern: $F = open(...)
      - pattern-not: $S.$A = open(...)
      - pattern-not-inside: |
          $F = open(...)
          ...
          $F.close()
    message: >-
      Ficheiro aberto sem context manager e sem close() no mesmo scope. O
      descritor fica preso até o garbage collector o apanhar, o que em
      CPython é cedo e noutras implementações não é. Use `with open(...) as
      f:`.
    severity: WARNING
    languages: [python]

  # Este é o análogo Python do floating-mutation do JS/TS — o `await`
  # esquecido — mas fixado nos quatro primitivos do asyncio em vez de numa
  # lista adivinhada de verbos, o que o torna preciso em vez de heurístico.
  # A regra geral ("chamada a qualquer função definida com async def no
  # mesmo ficheiro") não é exprimível em Semgrep OSS: ver §8 do design.
  #
  # As três exclusões são pattern-not-INSIDE, não pattern-not. Uma chamada e
  # o `await`/`return`/atribuição que a envolve nunca partilham o mesmo span,
  # por isso um pattern-not seria um no-op silencioso — a mesma armadilha
  # que o design do JS/TS documenta.
  - id: bugfix-py-race-condition-asyncio-not-awaited
    patterns:
      - pattern-either:
          - pattern: asyncio.sleep(...)
          - pattern: asyncio.gather(...)
          - pattern: asyncio.wait(...)
          - pattern: asyncio.wait_for(...)
      - pattern-not-inside: await $ANY
      - pattern-not-inside: return $ANY
      - pattern-not-inside: $V = $ANY
    message: >-
      Corotina do asyncio criada e descartada: não é aguardada, nem
      devolvida, nem atribuída. Não corre nada e o chamador segue como se
      tivesse corrido. Falta um `await` (ou `asyncio.create_task(...)`, se a
      intenção for mesmo não esperar).
    severity: WARNING
    languages: [python]

  - id: bugfix-py-race-condition-toctou-exists-open
    pattern: |
      if os.path.exists($P):
          <... open($P, ...) ...>
    message: >-
      Race entre o teste e o uso (TOCTOU): o ficheiro pode desaparecer entre
      o `os.path.exists()` e o `open()`. Abra diretamente e apanhe
      `FileNotFoundError` em vez de testar antes.
    severity: WARNING
    languages: [python]
```

- [ ] **Step 6: Run the test to verify it passes**

```powershell
$env:PATH = "C:\Users\Administrator\AppData\Roaming\Python\Python314\Scripts;$env:PATH"
$env:GUARDIAN_REQUIRE_SEMGREP = "1"
cd mcp
npx vitest run test/integration/bugfixRulesPy.test.ts
```

Expected: PASS, no skips. Nine hit files, nine near-miss files, all silent.

- [ ] **Step 7: Prove the `pattern-not-inside` operators are not no-ops**

Change the three `pattern-not-inside` clauses in
`bugfix-py-race-condition-asyncio-not-awaited` to `pattern-not` (same operands),
re-run, and confirm **RED** on `misses/asyncio_not_awaited.py` — the awaited,
returned and assigned forms all start firing, because a call and its enclosing
`await` never share a span. Restore `pattern-not-inside`, confirm GREEN. Record
both outputs in your task report. This is the exact defect class that shipped
six times in the JS/TS round; demonstrating it here is the point of the step.

- [ ] **Step 8: Commit**

```bash
git add configs/semgrep/bugfix-py.yml mcp/test/fixtures/bugfix-py mcp/test/integration/bugfixRulesPy.test.ts
git commit -m "feat(bugfix-rules): Python memory_leak and race_condition rules"
```

---

### Task 4: `edge_case` (1 rule) and the no-duplication test

**Files:**
- Modify: `configs/semgrep/bugfix-py.yml` (append one rule)
- Create: `mcp/test/fixtures/bugfix-py/hits/queryset_n_plus_one.py`
- Create: `mcp/test/fixtures/bugfix-py/misses/queryset_n_plus_one.py`
- Modify: `mcp/test/integration/bugfixRulesPy.test.ts`

**Interfaces:**
- Consumes: `configs/semgrep/bugfix-py.yml` with nine rules; the test's
  `run(config: string, dir: string): SemgrepResult[]` helper, which already takes
  the config as its first parameter precisely so a second config can be scanned.
- Produces: the tenth id, `bugfix-py-edge-case-queryset-n-plus-one`, and the
  no-duplication test that closes design §2's second governing rule.

- [ ] **Step 1: Write the hit fixture**

`mcp/test/fixtures/bugfix-py/hits/queryset_n_plus_one.py` — both queryset forms,
because `.filter(...)` is the commoner one and the `.all()`-only pattern misses it:

```python
def titles():
    names = []
    for book in Book.objects.all():
        names.append(book.author.name)
    return names


def active_titles():
    names = []
    for book in Book.objects.filter(active=True):
        names.append(book.author.name)
    return names
```

- [ ] **Step 2: Write the near-miss fixture**

`mcp/test/fixtures/bugfix-py/misses/queryset_n_plus_one.py`:

```python
def selected():
    names = []
    for book in Book.objects.all().select_related("author"):
        names.append(book.author.name)
    return names


def prefetched():
    names = []
    for book in Book.objects.filter(active=True).prefetch_related("author"):
        names.append(book.author.name)
    return names


def own_field_only():
    return [book.title for book in Book.objects.all()]
```

- [ ] **Step 3: Register the expectations in the test**

Add to `EXPECTED_HITS_BY_FILE`:

```typescript
  'queryset_n_plus_one.py': { ids: ['bugfix-py-edge-case-queryset-n-plus-one'], count: 2 },
```

Add to `EXPECTED_CLASS`:

```typescript
  'bugfix-py-edge-case-queryset-n-plus-one': 'edge_case',
```

- [ ] **Step 4: Write the no-duplication test**

Append this `describe` block to `mcp/test/integration/bugfixRulesPy.test.ts`.
It is the second governing rule of the design (§2), and it is the one that does
not exist in the JS/TS harness: JS/TS started from zero coverage, Python has 32
rules already running.

```typescript
/**
 * Design of record §2, second governing rule: no local rule may re-report
 * what `p/r2c-bug-scan` already finds. Python is the first language where
 * this can happen at all — the pack ships 32 Python rules, and one rule was
 * already dropped from the design for duplicating
 * `avoid-accessing-request-in-wrong-handler`.
 *
 * A finding here means one of exactly two things, and which one it was must
 * be stated in the task report rather than assumed:
 *   - the pack reports the SAME bug on the SAME line -> our rule is
 *     redundant; drop or narrow it.
 *   - the pack reports a DIFFERENT rule elsewhere in the file -> the
 *     fixture carries an incidental second bug; make the fixture minimal.
 * "Adjust the fixture until the pack is quiet" is only legitimate in the
 * second case.
 *
 * This test needs the Semgrep registry. It skips when the pack cannot be
 * fetched, and `GUARDIAN_REQUIRE_SEMGREP=1` turns that into a hard failure
 * like every other skip here.
 */
const R2C_PACK = 'p/r2c-bug-scan';

/** Scanned once at module load and reused — this run downloads a registry
 *  pack, so doing it in both a reachability probe and the assertion would
 *  pay the network cost twice. `null` means the pack could not be fetched. */
function r2cRowsOrNull(): SemgrepResult[] | null {
  if (!AVAILABLE) return null;
  try {
    return run(R2C_PACK, resolve(FIXTURES, 'hits'));
  } catch {
    return null;
  }
}
const R2C_ROWS = r2cRowsOrNull();

describe('no local rule duplicates p/r2c-bug-scan', () => {
  it.runIf(REQUIRE_SEMGREP)('the registry pack must be reachable when the flag is set', () => {
    expect(R2C_ROWS).not.toBeNull();
  });

  it.skipIf(R2C_ROWS === null)('the existing pack finds NOTHING in any hit fixture', () => {
    // Every one of our ten rules is therefore additive: it fires where the
    // pack does not. Asserted per file so a failure names the rule whose
    // fixture overlaps, not merely that the directory does.
    const grouped = rowsByFile(R2C_ROWS ?? []);
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
npx vitest run test/integration/bugfixRulesPy.test.ts
```

Expected: FAIL — `queryset_n_plus_one.py` produces no findings because the rule
does not exist yet. The no-duplication test should already pass at this point;
that is fine and expected.

- [ ] **Step 6: Append the rule to `configs/semgrep/bugfix-py.yml`**

```yaml
  # Cobre `.all()` e `.filter(...)`: a versão só com `.all()` não apanhava a
  # forma mais comum. O segundo pattern usa o operador de expressão profunda
  # `<... ...>` para exigir que o corpo do ciclo atravesse uma relação —
  # iterar um queryset só é N+1 se alguma coisa lá dentro for buscar o
  # objeto relacionado.
  #
  # Limitação conhecida e medida: só casa ciclos `for`. A mesma N+1 escrita
  # como list comprehension não é apanhada.
  - id: bugfix-py-edge-case-queryset-n-plus-one
    patterns:
      - pattern-either:
          - pattern: |
              for $O in $M.objects.all():
                  ...
          - pattern: |
              for $O in $M.objects.filter(...):
                  ...
      - pattern: |
          for $O in $QS:
              <... $O.$REL.$FIELD ...>
    message: >-
      Provável N+1: o queryset é iterado e o corpo do ciclo atravessa uma
      relação, por isso cada volta faz a sua própria query. Acrescente
      `.select_related("...")` (ForeignKey/OneToOne) ou
      `.prefetch_related("...")` (ManyToMany/reverse) ao queryset.
    severity: WARNING
    languages: [python]
```

- [ ] **Step 7: Run the test to verify it passes**

```powershell
$env:PATH = "C:\Users\Administrator\AppData\Roaming\Python\Python314\Scripts;$env:PATH"
$env:GUARDIAN_REQUIRE_SEMGREP = "1"
cd mcp
npx vitest run test/integration/bugfixRulesPy.test.ts
```

Expected: PASS, no skips. Ten hit files totalling **20 findings**, ten near-miss
files with zero, and `p/r2c-bug-scan` silent on every hit fixture.

- [ ] **Step 8: Run the whole suite**

```powershell
$env:PATH = "C:\Users\Administrator\AppData\Roaming\Python\Python314\Scripts;$env:PATH"
$env:GUARDIAN_REQUIRE_SEMGREP = "1"
cd mcp
npm test
```

Expected: PASS. Report the total count in your task report.

- [ ] **Step 9: Commit**

```bash
git add configs/semgrep/bugfix-py.yml mcp/test/fixtures/bugfix-py mcp/test/integration/bugfixRulesPy.test.ts
git commit -m "feat(bugfix-rules): the Django N+1 rule, and the no-duplication proof"
```

---

### Task 5: Make `resolveBugfixRules()` plural and wire it through

The resolver returns one path today. It becomes a list of every
`configs/semgrep/bugfix-*.yml`, so Go, Java, C#, PHP, Ruby and Rust need no
wiring at all — dropping the file in is enough.

**Files:**
- Modify: `mcp/src/platform/configsDir.ts` (`resolveBugfixRules`, and the doc comment above it)
- Modify: `mcp/src/tools/bugHunt.ts` (`BuildPackListOptions.bugfixRulesPath`, `buildPackList`, the header comment, the tool `title`/`description`)
- Modify: `mcp/test/unit/platform/configsDir.test.ts` (the `resolveBugfixRules` describe block)
- Modify: `mcp/test/unit/tools/bugHuntConfigs.test.ts`
- Modify: `mcp/test/integration/qualityTools.test.ts`
- Modify: `mcp/dist/` (rebuilt, staged in this same commit)

**Interfaces:**
- Consumes: `resolveConfigsDir(): string` from `mcp/src/platform/configsDir.ts`,
  unchanged.
- Produces:
  - `resolveBugfixRules(): string[]` — absolute paths to every
    `configs/semgrep/bugfix-*.yml`, sorted by filename, `[]` when the directory
    is unreadable. **Breaking change**: was `string | null`.
  - `BuildPackListOptions.bugfixRulesPaths?: readonly string[]` — **breaking
    change**: was `bugfixRulesPath?: string | null`. Omitting the field means
    "resolve for real"; passing `[]` means "omit them", which is what explicit
    `null` used to mean.

- [ ] **Step 1: Write the failing resolver test**

Replace the whole `describe('resolveBugfixRules', ...)` block in
`mcp/test/unit/platform/configsDir.test.ts` with this. The exact-array assertion
is the discriminating part: an implementation that globbed `*.yml` would return
`base.yml` and `routes.yml` too and pass any "contains bugfix-py.yml" check.

```typescript
describe('resolveBugfixRules', () => {
  it('returns every bugfix-*.yml in configs/semgrep, sorted, as absolute paths', () => {
    const dir = join(resolveConfigsDir(), 'semgrep');
    expect(resolveBugfixRules()).toEqual([
      join(dir, 'bugfix-js.yml'),
      join(dir, 'bugfix-py.yml'),
    ]);
  });

  it('every returned path exists on disk', () => {
    for (const p of resolveBugfixRules()) {
      expect(existsSync(p)).toBe(true);
    }
  });

  it('returns ONLY bugfix-*.yml — never base.yml or routes.yml, which are real too', () => {
    // A glob over `*.yml` would also return these and would satisfy any
    // "contains bugfix-py.yml" assertion. They must not be passed as
    // bug_hunt --config values.
    const names = resolveBugfixRules().map((p) => basename(p));
    expect(names).not.toContain('base.yml');
    expect(names).not.toContain('routes.yml');
    for (const name of names) {
      expect(name.startsWith('bugfix-')).toBe(true);
      expect(name.endsWith('.yml')).toBe(true);
    }
  });

  it('is stable across repeated calls', () => {
    expect(resolveBugfixRules()).toEqual(resolveBugfixRules());
  });
});
```

Add `basename` to the existing `node:path` import in that file:

```typescript
import { basename, dirname, join, resolve } from 'node:path';
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd mcp
npx vitest run test/unit/platform/configsDir.test.ts
```

Expected: FAIL — TypeScript errors, because `resolveBugfixRules()` returns
`string | null` and `.map`/iteration on it does not type-check.

- [ ] **Step 3: Make the resolver plural**

In `mcp/src/platform/configsDir.ts`, add `readdirSync` to the `node:fs` import:

```typescript
import { existsSync, readdirSync } from 'node:fs';
```

Then replace the `BUGFIX_JS_RULES` constant and the `resolveBugfixRules`
function with:

```typescript
const BUGFIX_PREFIX = 'bugfix-';
const BUGFIX_SUFFIX = '.yml';

/**
 * Absolute paths to every `configs/semgrep/bugfix-*.yml` on disk, sorted by
 * filename so the `--config=` order is deterministic across platforms.
 *
 * Plural rather than a single path because the rule files are per-language
 * (`bugfix-js.yml`, `bugfix-py.yml`, and one per language after that). A
 * prefix match means a new language ships by adding its file — no wiring,
 * no constant to update, nothing that can be forgotten. It also means
 * `base.yml` and `routes.yml`, which live in the same directory and are
 * NOT bug_hunt rule packs, are never picked up.
 *
 * Returns `[]` when the directory cannot be read — a damaged or unusually
 * pruned checkout. `bug_hunt` must never pass a `--config` that does not
 * resolve: Semgrep aborts the WHOLE scan when any `--config` fails to load,
 * which is exactly the failure mode that took `bug_hunt` down when the
 * `p/bugs` registry pack was retired (see `bugHunt.ts`'s header comment and
 * `semgrepConfigFailure.ts`). An empty list lets `buildPackList` omit them
 * rather than pass a bad path.
 */
export function resolveBugfixRules(): string[] {
  const dir = join(resolveConfigsDir(), 'semgrep');
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return [];
  }
  return entries
    .filter((name) => name.startsWith(BUGFIX_PREFIX) && name.endsWith(BUGFIX_SUFFIX))
    .sort()
    .map((name) => join(dir, name));
}
```

Also update the file's top doc comment, which names `configs/semgrep/bugfix-js.yml`
in the singular — change that phrase to `configs/semgrep/bugfix-*.yml`.

- [ ] **Step 4: Run the resolver test to verify it passes**

```bash
cd mcp
npx vitest run test/unit/platform/configsDir.test.ts
```

Expected: PASS.

- [ ] **Step 5: Update `buildPackList`**

In `mcp/src/tools/bugHunt.ts`, replace the `bugfixRulesPath` field in
`BuildPackListOptions` with:

```typescript
  /**
   * Absolute paths to the local `configs/semgrep/bugfix-*.yml` rule files,
   * or `[]` to omit them. Defaults to `resolveBugfixRules()`'s real, on-disk
   * answer whenever the caller does not pass this field at all (production
   * code, in `invoke` below, always takes that default). Passing it
   * explicitly — including an explicit empty array — is how tests exercise
   * both the inclusion and the omission path without touching the
   * filesystem or Semgrep.
   */
  readonly bugfixRulesPaths?: readonly string[];
```

and replace the body of `buildPackList` with:

```typescript
export function buildPackList(opts: BuildPackListOptions): string[] {
  const bugfixRulesPaths = opts.bugfixRulesPaths ?? resolveBugfixRules();
  return [
    ...BUG_HUNT_BASE_PACKS,
    ...bugfixRulesPaths,
    ...(opts.includeLanguagePacks ? languagePacksFor(opts.languages) : []),
  ];
}
```

- [ ] **Step 6: Update the three call-site test files**

In `mcp/test/unit/tools/bugHuntConfigs.test.ts`:

- the "omits the local rules rather than passing a bad path" test: change
  `bugfixRulesPath: null` to `bugfixRulesPaths: []`, and change the assertion to
  cover both languages:

```typescript
    expect(packs.some((p) => p.includes('bugfix-'))).toBe(false);
```

- the "passes an explicit override path through verbatim" test: change
  `bugfixRulesPath: fake` to `bugfixRulesPaths: [fake]`.
- the "the default local-rules entry is resolveBugfixRules()'s real result" test:
  replace the `.find(...)`/`toBe` pair with an array comparison, so it pins BOTH
  files rather than only the first one found:

```typescript
    const packs = buildPackList({ includeLanguagePacks: false, languages: [] });
    const local = packs.filter((p) => p.includes('bugfix-'));
    expect(local).toEqual(resolveBugfixRules());
    expect(local.length).toBeGreaterThan(1);
    for (const p of local) expect(existsSync(p)).toBe(true);
```

- the "includes the local bugfix rules by default, as an absolute path" test:
  assert every returned local path is absolute, not just the first:

```typescript
    const packs = buildPackList({ includeLanguagePacks: false, languages: ['typescript'] });
    const local = packs.filter((p) => p.includes('bugfix-'));
    expect(local.length).toBeGreaterThan(1);
    for (const p of local) expect(isAbsolute(p)).toBe(true);
```

`mcp/test/integration/qualityTools.test.ts` has **ten** sites, in three tests.
Several interpolate the value into a template string (`` `--config=${bugfixRules}` ``).
That is the dangerous kind: with an array, `${bugfixRules}` stringifies to
`"/a/bugfix-js.yml,/b/bugfix-py.yml"` — valid JavaScript that compiles, runs, and
asserts something that was never true. Fix every one; do not rely on the type
checker to find them.

**Test A — "the local rules survive a total registry outage" (lines ~249–274).**
Replace the guard:

```typescript
    const bugfixRules = resolveBugfixRules();
    if (bugfixRules.length === 0) {
      throw new Error('configs/semgrep/bugfix-*.yml are missing from this checkout');
    }
```

and both interpolated assertions (lines ~264 and ~274) become loops:

```typescript
        for (const rules of bugfixRules) expect(opts.args).toContain(`--config=${rules}`);
```

**Test B — "a whole-file-broken local rule config is dropped and retried"
(lines ~355–426).** This one fabricates a Semgrep error naming a specific broken
file, so it needs ONE path, not the list. Replace the guard with:

```typescript
    const bugfixRules = resolveBugfixRules();
    const [brokenRules] = bugfixRules;
    if (brokenRules === undefined) {
      throw new Error('configs/semgrep/bugfix-*.yml are missing from this checkout');
    }
```

`noUncheckedIndexedAccess` makes the destructured element `string | undefined`,
and the `undefined` guard narrows it — do not reach for `!`.

Then: line ~367 (`--config=${bugfixRules}` in the first attempt) becomes the same
`for (const rules of bugfixRules)` loop as Test A. Lines ~384 (the fabricated
`Invalid YAML file ${bugfixRules}:` message) and ~426
(`expect(reason).toContain(bugfixRules)`) both become `brokenRules`.

Line ~403 asserts the broken config was dropped on retry. Strengthen it, because
with two local files there is now something to say that could not be said before —
that only the broken one is dropped:

```typescript
      expect(opts.args).not.toContain(`--config=${brokenRules}`);
      for (const rules of bugfixRules.filter((p) => p !== brokenRules)) {
        expect(opts.args).toContain(`--config=${rules}`);
      }
```

Also fix that test's comment, which says "the OTHER thirteen rules never even get
a chance in THIS retry" — with a second file present the surviving pack does still
run, so the sentence is now wrong. Say instead that the whole broken file is
dropped and every other `--config`, local or registry, survives.

**Test C — the default-packs test (lines ~752–759).** Replace the
`expect(bugfixRules).not.toBeNull()` / single `toContain` / count-of-`+ 1` trio
with:

```typescript
    const bugfixRules = resolveBugfixRules();
    expect(bugfixRules.length).toBeGreaterThan(1);
    for (const rules of bugfixRules) expect(getArgs()).toContain(`--config=${rules}`);
    // Exact count: base packs + every local bugfix-*.yml, nothing else.
    expect(getArgs().filter((a) => a.startsWith('--config='))).toHaveLength(
      BUG_HUNT_BASE_PACKS.length + bugfixRules.length,
    );
```

When you are done, re-run `grep -n "bugfixRules" mcp/test/integration/qualityTools.test.ts`
and confirm no remaining line interpolates the bare array into a string.

- [ ] **Step 7: Update the `bug_hunt` tool title and description**

In `mcp/src/tools/bugHunt.ts`, the registered tool's `title` and `description`
say "always-on local JS/TS bug rules" and "fourteen hand-authored rules ...
for JS/TS". Both are now wrong. Change `title` to:

```typescript
      'Bug hunt (Semgrep r2c-bug-scan + security-audit + always-on local JS/TS and Python ' +
      'bug rules; optional language packs, off by default; other languages still registry-only)',
```

and in `description`, replace the sentence naming `configs/semgrep/bugfix-js.yml`
and "fourteen hand-authored rules ... for JS/TS" with:

```typescript
      'JS/TS and Python rule packs: `configs/semgrep/bugfix-js.yml` (fourteen rules) and ' +
      '`configs/semgrep/bugfix-py.yml` (ten rules), each covering all six subcategories ' +
      'below for its language — race_condition, null_safety, off_by_one, memory_leak, ' +
      'error_handling, edge_case. ' +
```

Also update the header comment near the top of the file, which names
`bugfix-js.yml` in the singular and says "fourteen".

- [ ] **Step 8: Build and run the full suite**

```powershell
$env:PATH = "C:\Users\Administrator\AppData\Roaming\Python\Python314\Scripts;$env:PATH"
$env:GUARDIAN_REQUIRE_SEMGREP = "1"
cd mcp
npm run build
npm test
```

Expected: PASS, no skips, no TypeScript errors.

- [ ] **Step 9: Verify the bundled path resolves both files**

`configsDir.ts` runs at two different depths — bundled into `dist/server.js`, and
unbundled as its own module in tests. Vitest only ever exercises the unbundled
one. Confirm the bundle finds both files:

```powershell
cd mcp
node -e "import('./dist/server.js').then(() => {})" 2>&1 | Select-Object -First 5
node --input-type=module -e "import { resolveBugfixRules } from './dist/platform/configsDir.js'; console.log(resolveBugfixRules());"
```

The second command prints the unbundled answer; for the bundled one, run
`bug_hunt` end-to-end against a real fixture through `dist/server.js` and confirm
both `--config` values appear. Record what you ran and what it printed in your
task report — a claim without an output is not evidence.

- [ ] **Step 10: Commit, with `dist/` in the same commit**

```bash
git add mcp/src mcp/test mcp/dist
git commit -m "feat(bugfix-rules): resolve every bugfix-*.yml, not just the JS one"
```

---

### Task 6: Documentation

**Files:**
- Modify: `README.md` (three language sections: EN ~line 38, PT ~line 344, ES ~line 650)
- Modify: `skills/guardian-bugfix/SKILL.md` (~line 64)
- Modify: `mcp/src/tools/semgrepConfigFailure.ts` (doc comment only)
- Modify: `CHANGELOG.md`
- Modify: `mcp/dist/` (rebuilt, staged in this same commit)

**Interfaces:**
- Consumes: nothing at runtime. Every statement below must match what Tasks 1–5
  actually shipped — ten rules, six classes, the file at
  `configs/semgrep/bugfix-py.yml`.
- Produces: no code interface.

- [ ] **Step 1: Update the three README language sections**

Each of the three `bug_hunt` bullets says the local pack is **JS/TS only** and
that "no other language has a local pack yet". Both clauses are now false. In
each section, after the existing JS/TS sentence, add the Python pack and carry
its limitations across — the same discipline the JS/TS entry follows, where the
limitation is stated in the same breath as the capability.

English (~line 38), insert after the JS/TS sentence and replace the
"**JS/TS only**: no other language has a local pack yet." clause with:

```markdown
Python has its own pack too — `configs/semgrep/bugfix-py.yml`, ten hand-authored rules across the same six classes, each measured against the 32 Python rules `p/r2c-bug-scan` already runs and confirmed to fire where those do not. Its known gaps are stated rather than implied: there is no general "coroutine not awaited" rule (that is not expressible in Semgrep OSS — only the four named `asyncio` primitives are covered, so a forgotten `await` on your own `async def` is not caught), the Django N+1 rule matches `for` statements but not list comprehensions and does not know SQLAlchemy or Peewee, and `none-deref-dict-get` excludes HTTP clients by receiver name, so a client bound to some other name is a false positive and a dict named `client` is a false negative. **JS/TS and Python only**: the remaining languages have no local pack yet.
```

Portuguese (~line 344), same position:

```markdown
Python tem também o seu pack — `configs/semgrep/bugfix-py.yml`, dez regras hand-authored nas mesmas seis classes, cada uma medida contra as 32 regras Python que o `p/r2c-bug-scan` já corre e confirmada a disparar onde essas não disparam. As lacunas conhecidas são ditas em vez de subentendidas: não há regra geral de "corotina não aguardada" (não é exprimível em Semgrep OSS — só os quatro primitivos `asyncio` nomeados são cobertos, por isso um `await` esquecido numa `async def` do próprio projeto não é apanhado), a regra de N+1 do Django casa ciclos `for` mas não list comprehensions e não conhece SQLAlchemy nem Peewee, e a `none-deref-dict-get` exclui clientes HTTP pelo nome do receiver, por isso um cliente com outro nome é falso positivo e um dicionário chamado `client` é falso negativo. **Só JS/TS e Python**: as restantes linguagens ainda não têm pack local.
```

Spanish (~line 650), same position:

```markdown
Python tiene también su propio pack — `configs/semgrep/bugfix-py.yml`, diez reglas hand-authored en las mismas seis clases, cada una medida contra las 32 reglas Python que `p/r2c-bug-scan` ya ejecuta y confirmada que dispara donde esas no lo hacen. Sus carencias conocidas se dicen en vez de insinuarse: no hay regla general de "corrutina no esperada" (no es expresable en Semgrep OSS — solo se cubren los cuatro primitivos `asyncio` nombrados, así que un `await` olvidado en un `async def` propio no se detecta), la regla de N+1 de Django casa bucles `for` pero no list comprehensions y no conoce SQLAlchemy ni Peewee, y `none-deref-dict-get` excluye clientes HTTP por el nombre del receptor, así que un cliente con otro nombre es un falso positivo y un diccionario llamado `client` es un falso negativo. **Solo JS/TS y Python**: los demás lenguajes aún no tienen pack local.
```

- [ ] **Step 2: Update the guardian-bugfix skill**

`skills/guardian-bugfix/SKILL.md` around line 64 tells the model that the JS/TS
pack exists and, implicitly, that Python has nothing. Add the Python pack
immediately after the JS/TS paragraph:

```markdown
Para Python, o `bug_hunt` corre também por default
`configs/semgrep/bugfix-py.yml` — dez regras hand-authored, cada uma com o seu
par de fixtures — cobrindo as mesmas seis classes: `bare except:` e `except:
pass`, `.objects.get()` sem guardar o `DoesNotExist`, dereference de `None`
vindo de `re.match(...)` e de `dict.get(...)`, `range(len(x) + 1)`, ficheiros
abertos sem context manager, corotinas `asyncio` criadas e descartadas, TOCTOU
entre `os.path.exists()` e `open()`, e N+1 de querysets Django. Estas regras
somam-se às 32 regras Python que o `p/r2c-bug-scan` já corre — nenhuma duplica
nenhuma delas, medido contra as fixtures.

Não cobrem um `await` esquecido numa `async def` do próprio projeto: essa regra
geral não é exprimível em Semgrep OSS, e só os primitivos `asyncio` nomeados são
apanhados. Para essa classe, leia o código.
```

- [ ] **Step 3: Update the `semgrepConfigFailure.ts` doc comment**

Its comment says a local `--config=` is `configs/semgrep/bugfix-js.yml`, "wired
in by bugfix-rules-jsts Task 3". There are two such files now. Change the phrase
`configs/semgrep/bugfix-js.yml` to `configs/semgrep/bugfix-*.yml` in the two
places it appears there (lines ~19 and ~69). The described behaviour — a
hand-broken local file degrades exactly like a dead registry pack — is unchanged
and still correct, so do not restate it.

- [ ] **Step 4: Add the CHANGELOG entry**

Add a new `## [Unreleased]` section at the top of `CHANGELOG.md` (or extend the
existing one), matching the style of the 1.6.0 entry:

```markdown
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

- No general "coroutine not awaited" rule: it is not expressible in Semgrep OSS.
  Only `asyncio.sleep/gather/wait/wait_for` are covered, so a forgotten `await`
  on a project's own `async def` is not caught.
- The Django N+1 rule matches `for` statements, not list comprehensions, and is
  Django-specific.
- `none-deref-dict-get` excludes HTTP clients by receiver name.
```

- [ ] **Step 5: Verify markdownlint is clean**

Run this from the **repo root**, not from `mcp/` — `.markdownlint.jsonc` lives at
the root and is auto-discovered from the working directory:

```bash
npx --yes markdownlint-cli2 "README.md" "skills/**/*.md" "commands/**/*.md"
```

There is no root `package.json` and markdownlint is not a declared dependency, so
`--yes` is what lets `npx` fetch it on demand. Expected: no errors.

Note that MD013 (line-length) is **disabled** in `.markdownlint.jsonc`, so the
long single-line README bullets above are fine — the README already has 96 lines
over 200 characters. The rules that do bite here are MD032 (lists need blank
lines around them) and MD031 (fenced blocks need blank lines around them).

- [ ] **Step 6: Build, run the full suite, and commit**

```powershell
$env:PATH = "C:\Users\Administrator\AppData\Roaming\Python\Python314\Scripts;$env:PATH"
$env:GUARDIAN_REQUIRE_SEMGREP = "1"
cd mcp
npm run build
npm test
```

Expected: PASS, no skips.

```bash
git add README.md skills/guardian-bugfix/SKILL.md mcp/src/tools/semgrepConfigFailure.ts CHANGELOG.md mcp/dist
git commit -m "docs(bugfix-rules): the Python pack, and what it does not cover"
```

---

## Verification summary

What the finished branch must show, all of it already measured on the rule set
this plan carries:

| Check | Expected |
| --- | --- |
| Hit fixtures | 10 files, **20 findings** — each firing its own rule, plus `except_pass.py`, whose bare `except: pass` is genuinely both bugs |
| Near-miss fixtures | 10 files, **0 findings** |
| `p/r2c-bug-scan` on the hit fixtures | **0 findings** — every rule is additive |
| `mapSubcategory` | all 10 ids land in their own class; none contains `unchecked` |
| `resolveBugfixRules()` | exactly `[bugfix-js.yml, bugfix-py.yml]`, sorted, absolute |
| Full suite | green with `GUARDIAN_REQUIRE_SEMGREP=1` and Semgrep on PATH — **no skips** |
