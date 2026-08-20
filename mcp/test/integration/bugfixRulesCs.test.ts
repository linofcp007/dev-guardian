/**
 * Runs the local `bugfix-cs.yml` rules against the fixture pairs in
 * `mcp/test/fixtures/bugfix-cs/{hits,misses}/` and asserts, per file, the
 * EXACT set of rule ids, the RAW non-deduplicated finding count, and the
 * number of files Semgrep actually scanned.
 *
 * Mirrors `bugfixRulesJava.test.ts`, for the reasons documented there:
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
 * ---------------------------------------------------------------------------
 * AND THE SIXTH SILENT-FAILURE MODE, which is C#-specific and which NONE of
 * the three assertions above catches.
 *
 * `$T $V = ...` matches only an EXPLICITLY-TYPED declaration. `var x = ...`
 * is a different node, and it is how most C# is written. Measured in the
 * probe: `foreach ($T $X in $C)` found 0 of 5 real bugs; `foreach (var $X in
 * $C)` found all five. A rule ported from the Java pack by textual analogy
 * finds nothing while `paths.scanned` is healthy, `errors` is 0, and every
 * gate in this file is green — because the fixtures were written to match the
 * pattern rather than the language.
 *
 * The only thing that sees it is a non-zero hits count on code somebody wrote
 * the way C# is actually written, which is what the per-file `count`
 * assertions below and the real-bugs corpus are for. **Always write `var` in
 * a C# pattern.**
 *
 * SKIPPED, not silently passed, when Semgrep is absent;
 * `GUARDIAN_REQUIRE_SEMGREP=1` turns that absence into a hard failure.
 */

import { afterAll, describe, expect, it } from 'vitest';
import { execFileSync } from 'node:child_process';
import { cpSync, existsSync, readdirSync, readFileSync } from 'node:fs';
import { basename, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { mapSubcategory } from '../../src/tools/bugHunt.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

afterAll(cleanupTempDirs);

const REPO_ROOT = resolve(fileURLToPath(new URL('../../..', import.meta.url)));
const RULES = resolve(REPO_ROOT, 'configs', 'semgrep', 'bugfix-cs.yml');
const FIXTURES = resolve(REPO_ROOT, 'mcp', 'test', 'fixtures', 'bugfix-cs');
const REQUIRE_SEMGREP = process.env['GUARDIAN_REQUIRE_SEMGREP'] === '1';

function semgrepAvailable(): boolean {
  try { execFileSync('semgrep', ['--version'], { stdio: 'ignore' }); return true; }
  catch { return false; }
}
const AVAILABLE = semgrepAvailable();

interface SemgrepResult {
  check_id: string;
  path: string;
  /** Semgrep's own tier. `extra.severity` is optional in the schema, so it is
   *  narrowed rather than asserted at every use. */
  extra?: { severity?: string };
}

interface SemgrepRun {
  readonly rows: SemgrepResult[];
  /** Files Semgrep actually scanned — asserted by every caller. */
  readonly scanned: number;
}

function run(config: string, dir: string): SemgrepRun {
  const work = makeTempDir('guardian-bugfix-cs-');
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
  return readdirSync(dir).filter((name) => name.endsWith('.cs')).sort();
}

/**
 * Every `- id:` the rule file DECLARES, read out of the YAML text rather than
 * out of a list maintained here. It is the left-hand side of the invariant
 * below: what the file declares must equal what the fixtures exercise.
 */
function declaredRuleIds(): string[] {
  const declared: string[] = [];
  for (const line of readFileSync(RULES, 'utf8').split('\n')) {
    const id = /^\s*-\s+id:\s*(\S+)\s*$/.exec(line)?.[1];
    if (id !== undefined) declared.push(id);
  }
  return declared.sort();
}

interface FileExpectation {
  readonly ids: readonly string[];
  readonly count: number;
}

/**
 * The exact rule ids and the RAW finding count expected in each `hits/`
 * fixture. Extended by every later task in this round; a fixture on disk with
 * no entry here fails Step 0 below rather than being silently unmeasured.
 */
const EXPECTED_HITS_BY_FILE: Readonly<Record<string, FileExpectation>> = {
  'EmptyCatch.cs': {
    // Eight = three catch spellings x two try shapes, minus one: the five
    // no-finally sites (one named, one with no identifier, one bare, plus two
    // names that only LOOK like the intent markers) and three `finally`
    // twins, one per spelling.
    //
    // Branches 2 and 3 are the C# spellings Java has no equivalent of, and a
    // single-branch port scores 1 here instead of 8. The `finally` dimension
    // is worth another 3: a try statement with a finalizer is a different AST
    // node, so the rule was blind to it entirely until it enumerated both
    // shapes. Neither gap is visible in the id set — only in this count.
    ids: ['bugfix-cs-error-handling-empty-catch'],
    count: 8,
  },
  'Rethrow.cs': {
    // Nine, and each one is also a CA2200 site under `dotnet build`. The
    // count is cross-checked against an independent oracle, which no other
    // fixture in this series has: see the file header.
    //
    // It was eight until the `finally` shape was closed, and the ninth is the
    // one the oracle found: CA2200 fired on a `throw ex;` whose catch had a
    // finalizer and this rule did not. That disagreement is what a second
    // opinion is FOR, and it is the only reason the gap was not shipped.
    ids: ['bugfix-cs-error-handling-rethrow-loses-stacktrace'],
    count: 9,
  },
  'AsyncVoid.cs': {
    // Two: a no-parameter fire-and-forget and a `static` one. The second is
    // there to keep modifier-subset matching measured — the pattern names
    // `async void` and nothing else, and it matches `static async void`
    // because Semgrep matches modifiers by subset.
    ids: ['bugfix-cs-race-condition-async-void'],
    count: 2,
  },
  'BlockingOnTask.cs': {
    // Six, laid out one-or-two per branch across the rule's four branches.
    // This is the rule where a per-branch count matters most: the four
    // branches exist because the one-line version produced four separate
    // false positives on real, correct code, and each branch is the narrow
    // recovery of one shape the tightening cost.
    ids: ['bugfix-cs-race-condition-blocking-on-task'],
    count: 6,
  },
  'StaticRandom.cs': {
    // Two: `static readonly` and plain `static`, for the same
    // modifier-subset reason as AsyncVoid.
    ids: ['bugfix-cs-race-condition-static-random'],
    count: 2,
  },
  'LockShared.cs': {
    // Two: `lock (this)` and `lock ("literal")`, one per branch.
    ids: ['bugfix-cs-race-condition-lock-on-shared-instance'],
    count: 2,
  },
  'LoopLte.cs': {
    // Eight over two rules: two `.Length` receivers (array, string) and SIX
    // `.Count` receivers, one per enumerated type.
    //
    // The six are not padding. `metavariable-type` is NOT subtype-aware —
    // measured: a receiver declared `List<int>` does not match
    // `ICollection<$T>`, and vice versa — so each type in the rule's list is
    // an independent claim. A type with no fixture behind it could be
    // deleted, or could silently never have worked, without a number moving.
    ids: [
      'bugfix-cs-off-by-one-loop-lte-count',
      'bugfix-cs-off-by-one-loop-lte-length',
    ],
    count: 8,
  },
  'AsCast.cs': {
    // Nine, and only TWO of them are the plain shape. The other seven are
    // guaranteed NREs sitting right next to a guard that does not protect
    // them — the `else` arm, a ternary's ruled-out arm, a disjunction that
    // proves nothing, a guard on a different variable.
    //
    // They are in hits/ rather than misses/ because of what ablation axis 2
    // measures: removing a clause must not REVEAL a finding here. An
    // exclusion that swallows a real bug is invisible unless that bug is in
    // this file. Measured: writing the two `if` exclusions with the obvious
    // `if ($V != null) { ... }` spelling closes every correct case in misses/
    // AND swallows two of these. Axis 3, which would have measured the same
    // width on real code, is unavailable all round.
    ids: ['bugfix-cs-null-safety-as-cast-deref'],
    count: 9,
  },
  'OrDefault.cs': {
    // Four: one per enumerated LINQ method plus a chained receiver.
    ids: ['bugfix-cs-null-safety-ordefault-deref'],
    count: 4,
  },
  'ModifyDuringIteration.cs': {
    // Eight: four enumerated receiver types, `RemoveAt`, a plain field, the
    // `this.`-qualified twin, and — the one that matters — a removal inside a
    // `switch` arm followed by `break`, which is the real bug Java's fourth
    // wave deleted. The exit exclusions alone swallow it; the
    // switch-inside-foreach re-inclusion is what keeps it.
    //
    // NINE, not eight, and the ninth is an ablation result rather than a
    // hunch: the re-inclusion is two `pattern-inside` branches, one per switch
    // label kind, and a single fixture carrying BOTH a `case` and a `default`
    // satisfied either branch alone. Both read DEAD while removing the pair
    // was a regression — CLAUDE.md's third cause of DEAD, mutual redundancy,
    // caught by the harness re-ablating DEAD siblings in pairs. One switch of
    // each label kind makes each branch independently measurable.
    ids: ['bugfix-cs-edge-case-modify-during-iteration'],
    count: 9,
  },
  'RealBugs.cs': {
    // THE REAL-BUGS CORPUS — 13 defects over all TWELVE rules, so every rule
    // in the pack has corpus coverage. The Java round left three rules at zero
    // and that was the riskiest gap in that pack.
    //
    // It exists to give the ablation its second axis. Everything else in hits/
    // is one minimal instantiation per rule, written by whoever wrote the
    // rule: that proves a rule fires, but it cannot prove an exclusion added
    // later did not eat a real bug, because a minimal fixture carries no guard
    // shapes for an exclusion to catch on. Every defect here sits where it
    // would sit in real code — inside a `try`, in a constructor, under a
    // `finally`, next to a guard on a different variable.
    //
    // It carries extra weight this round: ablation axis 3, which measures a
    // clause's width on code nobody wrote as a fixture, is N/A for the whole
    // C# pack because this repo holds no C# outside this tree.
    //
    // AND IT ALREADY EARNED ITS KEEP. Written with the as-cast entry
    // dereferencing in BOTH arms of the guard, it did not fire, and finding
    // out why exposed a residual of the else-arm swallow that reasoning had
    // missed: when the THEN arm also dereferences, the exclusion matches the
    // whole `if` and takes the else arm with it. Narrower than the original
    // hole, but real, and now stated in the rule.
    ids: [
      'bugfix-cs-edge-case-modify-during-iteration',
      'bugfix-cs-error-handling-empty-catch',
      'bugfix-cs-error-handling-rethrow-loses-stacktrace',
      'bugfix-cs-memory-leak-httpclient-per-call',
      'bugfix-cs-null-safety-as-cast-deref',
      'bugfix-cs-null-safety-ordefault-deref',
      'bugfix-cs-off-by-one-loop-lte-count',
      'bugfix-cs-off-by-one-loop-lte-length',
      'bugfix-cs-race-condition-async-void',
      'bugfix-cs-race-condition-blocking-on-task',
      'bugfix-cs-race-condition-lock-on-shared-instance',
      'bugfix-cs-race-condition-static-random',
    ],
    count: 13,
  },
  'HttpClient.cs': {
    // Four: a constructor assignment, a plain per-call local, `using var`,
    // and a `using` block. The constructor one is the site that chose the
    // rule's scoping clause — `pattern-inside: $R $M(...) { ... }` silently
    // excludes constructors, so it would have escaped.
    ids: ['bugfix-cs-memory-leak-httpclient-per-call'],
    count: 4,
  },
};

/**
 * The severity tier each rule is DESIGNED to carry, per the design of record
 * §4, whose criterion is a question about the OUTPUT: **is what the rule
 * EMITS always a bug?** A rule whose correctness depends on having recognised
 * a guard emits a false positive every time it meets a guard shape nobody
 * enumerated, and no exclusion list closes that, because the guard can always
 * be one method away.
 *
 * Both of Task 1's rules clear that bar, which is unusual and worth saying
 * why. `empty-catch` clears it the way the Java rule does: its escape hatch is
 * not a guard but a DECLARATION OF INTENT the rule itself reads. And
 * `rethrow-loses-stacktrace` clears it for a reason no other rule in the
 * series has — the CORRECT form of the code it flags (`throw;`) is a
 * DIFFERENT AST NODE, so there is no guard to recognise, because there is
 * nothing to guard.
 *
 * Pinned here because nothing else pins it. The tier is not cosmetic: the
 * Semgrep parser maps ERROR -> `high` and WARNING -> `medium`
 * (`src/runners/scannerParsers/semgrep.ts`), and `create_fix_pr` defaults
 * `severity_min` to `high`, so the tier decides whether a rule contributes to
 * the default fix-PR set at all.
 */
const EXPECTED_SEVERITY: Readonly<Record<string, string>> = {
  'bugfix-cs-error-handling-empty-catch': 'ERROR',
  'bugfix-cs-error-handling-rethrow-loses-stacktrace': 'ERROR',
  // The four race_condition rules are all WARNING, and every one fails the
  // ERROR test for the same reason: what they emit is correct code whenever a
  // guard the rule cannot see is present. `async void` is right in an event
  // handler; `.Wait()` is right when nothing above you holds a context;
  // a `static Random` is right in a single-threaded program; `lock (this)` is
  // right if nothing else ever locks the instance. None of those is visible to
  // a syntactic matcher.
  'bugfix-cs-race-condition-async-void': 'WARNING',
  'bugfix-cs-race-condition-blocking-on-task': 'WARNING',
  'bugfix-cs-race-condition-static-random': 'WARNING',
  'bugfix-cs-race-condition-lock-on-shared-instance': 'WARNING',
  // off_by_one and memory_leak, both WARNING for the same §4 reason: an
  // inclusive bound is correct when the loop counts rather than indexes, and
  // a per-call HttpClient is correct in a one-shot console program. Neither
  // condition is visible to a syntactic matcher.
  'bugfix-cs-off-by-one-loop-lte-length': 'WARNING',
  'bugfix-cs-off-by-one-loop-lte-count': 'WARNING',
  'bugfix-cs-memory-leak-httpclient-per-call': 'WARNING',
  // null_safety and edge_case. All WARNING, and these three are the clearest
  // illustration of the §4 criterion in the pack: their correctness depends
  // ENTIRELY on having recognised a guard, and a guard can always be one
  // method away, outside any syntactic matcher's reach.
  'bugfix-cs-null-safety-as-cast-deref': 'WARNING',
  'bugfix-cs-null-safety-ordefault-deref': 'WARNING',
  'bugfix-cs-edge-case-modify-during-iteration': 'WARNING',
};

describe('bugfix-cs rules', () => {
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
      // The TOTAL, asserted on top of the per-file counts, and not redundant:
      // the loop above only visits files that have an expectation, so a
      // finding landing in a file nobody registered — or in no file at all —
      // would not move any per-file number.
      expect(rows.length).toBe(
        Object.values(EXPECTED_HITS_BY_FILE).reduce((n, e) => n + e.count, 0),
      );
    },
  );

  /**
   * THE TRAP FAMILY. Six ways Semgrep does nothing while printing a green
   * summary have now been found in this series, and they share one signature:
   * **fewer rules actually load, or actually match, than the file declares,
   * and nothing in the findings says so.**
   *
   * The total-hits assertion above is the family-wide catch for the load
   * half: a rule that fails to load loses its findings and the total moves.
   * But it only works while EVERY rule has at least one hit fixture behind
   * it, which nothing else states and nothing else enforces. The assertion
   * below closes that, comparing the ids the fixtures exercise against the
   * `- id:` entries parsed out of the YAML itself rather than against a list
   * maintained by hand next to it.
   *
   * `semgrep --validate` and the locale-codec byte check are NOT here: they
   * run over every pack in `configs/semgrep/`, discovered by directory
   * listing, in `semgrepPacks.test.ts`, which picks up `bugfix-cs.yml` by its
   * existing on disk. Two mechanisms for one invariant is how they drift
   * apart. What that file cannot do is the fixture-to-rule mapping below.
   */
  it.skipIf(!AVAILABLE)('every rule the YAML declares is exercised by a hit fixture', () => {
    const { rows } = run(RULES, resolve(FIXTURES, 'hits'));
    expect(ids(rows)).toEqual(declaredRuleIds());
  });

  it.skipIf(!AVAILABLE)('fires NOTHING in EACH near-miss fixture', () => {
    const missesDir = resolve(FIXTURES, 'misses');
    const { rows, scanned } = run(RULES, missesDir);
    expect(scanned).toBe(fixtureFiles(missesDir).length);
    const grouped = rowsByFile(rows);
    for (const file of fixtureFiles(missesDir)) {
      expect(grouped[file] ?? []).toEqual([]);
    }
  });

  it.skipIf(!AVAILABLE)('reports each rule at its DESIGNED severity tier', () => {
    const { rows } = run(RULES, resolve(FIXTURES, 'hits'));
    const seen = new Map<string, Set<string>>();
    for (const row of rows) {
      const id = row.check_id.split('.').pop() ?? row.check_id;
      const severity = row.extra?.severity;
      if (severity === undefined) throw new Error(`no severity on ${id}`);
      const set = seen.get(id);
      if (set) set.add(severity);
      else seen.set(id, new Set([severity]));
    }
    for (const [id, tier] of Object.entries(EXPECTED_SEVERITY)) {
      expect([id, [...(seen.get(id) ?? [])]]).toEqual([id, [tier]]);
    }
    expect([...seen.keys()].sort()).toEqual(Object.keys(EXPECTED_SEVERITY).sort());
  });
});

/** Rule ids carry the class token because `mapSubcategory` classifies by regex
 *  over the lowercased id. Runs unconditionally — pure function, no Semgrep. */
const EXPECTED_CLASS: Readonly<Record<string, string>> = {
  'bugfix-cs-error-handling-empty-catch': 'error_handling',
  'bugfix-cs-error-handling-rethrow-loses-stacktrace': 'error_handling',
  'bugfix-cs-race-condition-async-void': 'race_condition',
  'bugfix-cs-race-condition-blocking-on-task': 'race_condition',
  'bugfix-cs-race-condition-static-random': 'race_condition',
  'bugfix-cs-race-condition-lock-on-shared-instance': 'race_condition',
  'bugfix-cs-off-by-one-loop-lte-length': 'off_by_one',
  'bugfix-cs-off-by-one-loop-lte-count': 'off_by_one',
  'bugfix-cs-memory-leak-httpclient-per-call': 'memory_leak',
  'bugfix-cs-null-safety-as-cast-deref': 'null_safety',
  'bugfix-cs-null-safety-ordefault-deref': 'null_safety',
  'bugfix-cs-edge-case-modify-during-iteration': 'edge_case',
};

describe('every rule id classifies as its own class', () => {
  it('maps every id in the file', () => {
    for (const [id, cls] of Object.entries(EXPECTED_CLASS)) {
      expect(mapSubcategory(id, undefined)).toBe(cls);
    }
  });

  it("no id contains a word another class's regex claims first", () => {
    // THREE words are hazardous in C#, not the Java pack's two.
    //
    //  - `unchecked` is matched by the error_handling regex, and in C# it is
    //    also a keyword, so it is a plausible thing to name a rule after.
    //  - `concurren` is matched by the race_condition regex, which runs FIRST
    //    in the if-chain — and in C# it is a live type-name fragment
    //    (`ConcurrentDictionary`, `ConcurrentBag`), so it is far likelier to
    //    end up in an id here than it was in Java.
    //  - `disposed` is matched by the memory_leak regex, which runs BEFORE
    //    error_handling — so an id about a disposed object's exception
    //    classifies as memory_leak, silently.
    for (const id of Object.keys(EXPECTED_CLASS)) {
      expect(id).not.toContain('unchecked');
      expect(id).not.toContain('concurren');
      expect(id).not.toContain('disposed');
    }
  });
});

/**
 * DESIGN OF RECORD §2: no local rule may re-report what the registry packs
 * already find. For C# the answer is stronger than for any other language in
 * the series — and one third of it cannot be proved at all, which is said here
 * rather than papered over.
 *
 * Measured, and reproduced by these tests:
 *
 *   | pack               | on the hit fixtures       | positive control          |
 *   | ------------------ | ------------------------- | ------------------------- |
 *   | p/r2c-bug-scan     | paths.scanned = 0         | control_r2c.py (Python)   |
 *   | p/csharp           | scanned = N, 0 findings   | Control.cs (DES)          |
 *   | p/security-audit   | scanned = N, 0 findings   | NONE FOUND                |
 *
 * `p/r2c-bug-scan` SHIPS NO C# RULES AT ALL. It does not merely find nothing —
 * it scans nothing, reporting `paths.scanned = 0`. So for that pack a zero
 * finding count is not evidence of anything, and no C# control could rescue it
 * either, because there is no C# rule for a C# control to trip. The only way
 * to distinguish "additive" from "never ran" is to prove the pack is alive in
 * a language it does cover, which is why there is a PYTHON file in a C#
 * fixture tree. A Go-round defect was a control directory nothing enumerated,
 * deleted silently, leaving the test skipping while the suite stayed green —
 * so the controls are asserted to have RUN, not merely to have been clean.
 *
 * `p/security-audit` HAS NO POSITIVE CONTROL, and that is a measured gap
 * rather than an oversight. It was probed against eleven classic vulnerable C#
 * shapes across two batteries — concatenated SQL, MD5, SHA1, DES, command
 * injection, hardcoded password, insecure Random, disabled TLS validation,
 * XXE, path traversal, BinaryFormatter — and fired on NONE of them, while
 * `p/csharp` fired on two of the same file. The design of record claims it
 * fires `csharp-sqli` on a concatenated-SQL control; measured, it does not.
 *
 * What is left for that pack is weaker but not nothing: `paths.scanned > 0`
 * proves it HAS C# rules and enumerated our files, since a pack with no rules
 * for a language reports 0 — which is exactly how `p/r2c-bug-scan` behaves
 * three lines up. That is asserted below, and labelled as the weaker claim it
 * is.
 */
const REGISTRY_PACKS = ['p/r2c-bug-scan', 'p/csharp', 'p/security-audit'] as const;

function registryRunOrNull(config: string, dir: string): SemgrepRun | null {
  if (!AVAILABLE) return null;
  try {
    return run(config, dir);
  } catch {
    return null;
  }
}

const HITS_DIR = resolve(FIXTURES, 'hits');
const CONTROL_DIR = resolve(FIXTURES, 'control');

/** Run once at module load, not inside a test: a registry scan takes far
 *  longer than vitest's 10s per-test timeout allows. */
const ON_HITS = new Map<string, SemgrepRun | null>(
  REGISTRY_PACKS.map((p) => [p, registryRunOrNull(p, HITS_DIR)]),
);
const R2C_ON_CONTROL = registryRunOrNull('p/r2c-bug-scan', CONTROL_DIR);
const CSHARP_ON_CONTROL = registryRunOrNull('p/csharp', CONTROL_DIR);

describe('no local C# rule duplicates the registry packs', () => {
  it.runIf(REQUIRE_SEMGREP)('every registry pack must be reachable when the flag is set', () => {
    for (const pack of REGISTRY_PACKS) {
      expect([pack, ON_HITS.get(pack) ?? null]).not.toEqual([pack, null]);
    }
    // Asserted too, and deliberately: without this the control fixtures could
    // be deleted and this whole describe block would go on passing, with the
    // control tests merely SKIPPING. That exact hole shipped in the Go round.
    expect(R2C_ON_CONTROL).not.toBeNull();
    expect(CSHARP_ON_CONTROL).not.toBeNull();
  });

  it.skipIf(R2C_ON_CONTROL === null)(
    'positive control: p/r2c-bug-scan is LIVE — proved in Python, because it has no C# rules',
    () => {
      expect(R2C_ON_CONTROL?.scanned).toBe(1);
      expect(R2C_ON_CONTROL?.rows.length).toBeGreaterThan(0);
    },
  );

  it.skipIf(CSHARP_ON_CONTROL === null)('positive control: p/csharp is LIVE for C#', () => {
    expect(CSHARP_ON_CONTROL?.scanned).toBe(1);
    expect(CSHARP_ON_CONTROL?.rows.length).toBeGreaterThan(0);
  });

  it.skipIf(ON_HITS.get('p/r2c-bug-scan') === null)(
    'p/r2c-bug-scan scans ZERO C# files — the pack has no C# rules at all',
    () => {
      // Pinned as an equality rather than "found nothing", because the two are
      // different facts and only this one explains why the Python control has
      // to exist. If this ever becomes non-zero the pack has gained C# rules
      // and the whole overlap question must be re-measured.
      expect(ON_HITS.get('p/r2c-bug-scan')?.scanned).toBe(0);
      expect(ON_HITS.get('p/r2c-bug-scan')?.rows.length).toBe(0);
    },
  );

  it.skipIf(ON_HITS.get('p/security-audit') === null)(
    'p/security-audit DID look at every hit fixture — the weaker liveness claim, stated as such',
    () => {
      // No positive control exists for this pack (see the block comment), so
      // this is the strongest available evidence that its zero below means
      // "found nothing" rather than "never ran": a pack with no rules for a
      // language reports scanned = 0, as p/r2c-bug-scan does above.
      expect(ON_HITS.get('p/security-audit')?.scanned).toBe(
        fixtureFiles(HITS_DIR).length,
      );
    },
  );

  for (const pack of ['p/csharp', 'p/security-audit'] as const) {
    it.skipIf(ON_HITS.get(pack) === null)(
      `${pack} finds NOTHING in any hit fixture — every local rule is additive`,
      () => {
        expect(ON_HITS.get(pack)?.scanned).toBe(fixtureFiles(HITS_DIR).length);
        const grouped = rowsByFile(ON_HITS.get(pack)?.rows ?? []);
        for (const file of fixtureFiles(HITS_DIR)) {
          expect(grouped[file] ?? []).toEqual([]);
        }
      },
    );
  }
});
