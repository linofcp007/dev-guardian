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
import { execFileSync, spawnSync } from 'node:child_process';
import { cpSync, existsSync, readdirSync, readFileSync } from 'node:fs';
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

/**
 * Every `- id:` the rule file DECLARES, read out of the YAML text rather than
 * out of a list maintained here. It is the left-hand side of the wave-7
 * invariant below: what the file declares must equal what the fixtures exercise.
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
 * THE REAL-BUGS CORPUS — the three entries written by the REVIEWER, and the
 * structural answer to how five waves of false-positive work opened a
 * false-negative hole with a green suite.
 *
 * Everything else in `hits/` is one minimal instantiation per rule, written by
 * whoever wrote the rule. That proves a rule fires at all. It cannot prove that
 * an exclusion added later did not eat a real bug, because a minimal hit
 * fixture carries no guard shapes for an exclusion to catch on — and the
 * near-miss fixtures only ever measure the direction the exclusion was written
 * for. So a wave could close a false positive, silently delete recall, and
 * still go green. Wave 4 did exactly that: `ElseArm.java` produced 6 findings
 * before it and 1 after.
 *
 * `RealBugs.java`, `ElseArm.java` and `IterationBugs.java` close that. They are
 * dense files of defects chosen to sit next to the guard shapes the exclusions
 * match — the `else` arm of a guard, the false arm of a ternary, a disjunction
 * that proves nothing, a guard on a different key, a `switch` whose `break`
 * leaves only the switch. Their counts are asserted like any other, so every
 * future exclusion has to prove it does not eat a real bug before it can be
 * merged.
 *
 * WHICH RULES THE CORPUS COVERS, stated rather than left to accident. Measured
 * over the three corpus files at the wave-7 counts:
 *
 *   | rule                          | corpus defects |
 *   | ----------------------------- | -------------- |
 *   | `null-safety-map-get-deref`   | 11             |
 *   | `null-safety-optional-get`    |  6             |
 *   | `edge-case-modify-during-iteration` | 6        |
 *   | `off-by-one-loop-lte-length`  |  4             |
 *   | `race-condition-static-dateformat` | 1         |
 *   | `error-handling-empty-catch`  |  0             |
 *   | `error-handling-printstacktrace-only` | 0      |
 *   | `memory-leak-stream-not-closed` | 0            |
 *
 * Five of eight, and the three at zero are a DECISION, not an oversight: they
 * are the three rules that carry no guard exclusions worth speaking of —
 * `empty-catch` has one metavariable-regex, `printstacktrace-only` has none at
 * all, `stream-not-closed` has two, and none of the three has ever had a
 * clause added to silence correct code. The corpus exists to catch an exclusion
 * eating a real bug; a rule with nothing to eat with is low-risk by
 * construction. Add a guard exclusion to any of the three and it needs corpus
 * entries before that clause can be merged.
 *
 * `modify-during-iteration` was at zero until wave 7 and was the OPPOSITE of
 * low-risk: eight exclusion clauses over a seven-branch receiver enumeration, the
 * file's only nested re-inclusion, and the rule whose
 * exclusion swallowed a real `ConcurrentModificationException` in wave 4. Its
 * real bugs lived only in `hits/ModifyDuringIteration.java`, written by the
 * rule's own author — precisely the artefact the corpus exists to compensate
 * for. `IterationBugs.java` closes it.
 */
const EXPECTED_HITS_BY_FILE: Readonly<Record<string, FileExpectation>> = {
  'ElseArm.java': {
    // Eight, and this number is the whole point of wave 6. Every method is a
    // guaranteed NPE or NoSuchElementException whose dereference sits on the
    // branch the guard proves is UNSAFE: the `else` arm of an `if` guard (map
    // containsKey, map != null, Optional isPresent, Optional conjunction), the
    // arm of a ternary the condition rules out (both polarities, map and
    // Optional), plus one unguarded control. Measured against the shipped rule
    // at 3392a0d: 1 of 8. Against b30499d, before wave 4: 6 of 8.
    ids: [
      'bugfix-java-null-safety-map-get-deref',
      'bugfix-java-null-safety-optional-get-no-ispresent',
    ],
    count: 8,
  },
  'RealBugs.java': {
    // Fourteen, spread over four rules, each one chosen to be the defect that a
    // specific tightening plausibly swallows: the short-form
    // `SimpleDateFormat` the qualified pattern has to resolve through the
    // import; four array shapes the `"$T[]"` restriction has to keep seeing;
    // `force || containsKey`, the disjunction that proves NOTHING, which the
    // wave-6 negative-first `||` exclusions must NOT reach; a guard on a
    // different key and a guard on a different Optional; and `ofNullable`,
    // which the `Optional.of` exclusion must not cover.
    //
    // `b13` and `b14`, added in wave 7, are the near-misses for the `keySet()`
    // exclusion, one per metavariable it unifies: `b13` iterates one map's
    // keys and dereferences ANOTHER map, `b14` iterates the map's own keys and
    // dereferences a DIFFERENT key. Drop either unification from that clause
    // and the matching function stops firing — which is the only thing that
    // distinguishes a scoped exclusion from a blanket one.
    ids: [
      'bugfix-java-null-safety-map-get-deref',
      'bugfix-java-null-safety-optional-get-no-ispresent',
      'bugfix-java-off-by-one-loop-lte-length',
      'bugfix-java-race-condition-static-dateformat',
    ],
    count: 14,
  },
  'IterationBugs.java': {
    // Six, all `ConcurrentModificationException`, all in the rule that had
    // ZERO corpus coverage until wave 7 while carrying eight exclusion clauses
    // over a seven-branch receiver enumeration and the file's only nested
    // re-inclusion. Each puts the `remove()` at a nesting
    // depth or behind a statement shape a future tightening of the `break`
    // exclusions plausibly swallows: a `switch` under an `if`, a `switch` in an
    // inner loop, a `switch` in a `try`, a braced `case` block, two statements
    // between the removal and the `break`, and a removal inside a nested `if`.
    ids: ['bugfix-java-edge-case-modify-during-iteration'],
    count: 6,
  },
  'EmptyCatch.java': { ids: ['bugfix-java-error-handling-empty-catch'], count: 1 },
  'PrintStackTraceOnly.java': {
    ids: ['bugfix-java-error-handling-printstacktrace-only'],
    count: 1,
  },
  'MapGetDeref.java': {
    // Eleven: the rule restricts the receiver by DECLARED type, so it carries
    // one function per `pattern-either` branch (Map, HashMap, TreeMap,
    // LinkedHashMap, ConcurrentHashMap), one `this.`-qualified twin per
    // branch — each branch binds its receiver through a
    // `metavariable-pattern` that accepts a bare name or a qualified one, and
    // before that wrapper went in the qualified form was invisible — plus a
    // `var`-inferred receiver. A branch, or a receiver form, with no fixture
    // behind it could be deleted without a test moving.
    ids: ['bugfix-java-null-safety-map-get-deref'],
    count: 11,
  },
  'OptionalGet.java': {
    ids: ['bugfix-java-null-safety-optional-get-no-ispresent'],
    count: 1,
  },
  'LoopLteLength.java': { ids: ['bugfix-java-off-by-one-loop-lte-length'], count: 1 },
  'StreamNotClosed.java': { ids: ['bugfix-java-memory-leak-stream-not-closed'], count: 1 },
  'ModifyDuringIteration.java': {
    // Sixteen, for the same reason as MapGetDeref: one function per
    // enumerated receiver type (List, ArrayList, LinkedList, Set, HashSet,
    // LinkedHashSet, Collection), one `this.`-qualified twin each, and two
    // `switch` cases. The enumeration is what keeps the rule off
    // CopyOnWriteArrayList, so every branch has to stay measured.
    //
    // The two `switch` cases are HITS and are the point of the whole
    // re-inclusion disjunct: inside a `switch`, `break` leaves the switch and
    // not the loop, so `remove(); break;` in a `case` is a real
    // ConcurrentModificationException that the paired exclusion used to
    // swallow. A `switch` written with only `case` labels does not match the
    // `default:` pattern and vice versa, so there is one of each.
    ids: ['bugfix-java-edge-case-modify-during-iteration'],
    count: 16,
  },
  'StaticDateFormat.java': {
    // Three: `static final`, plain `static`, and a fully-qualified
    // `java.text.SimpleDateFormat`. The rule ships a single pattern written
    // with the qualified name — measured, it matches the short forms too
    // whenever an import lets Semgrep resolve them, while the short pattern
    // never matched the qualified one, so the qualified field was invisible
    // for as long as the short pattern was the only one.
    ids: ['bugfix-java-race-condition-static-dateformat'],
    count: 3,
  },
};

/**
 * The severity tier each rule is DESIGNED to carry, per the design of record
 * §4, whose criterion is now stated as a question about the OUTPUT rather than
 * about the pattern: **is what the rule EMITS always a bug?** Not "is the
 * shape it looks for usually wrong" — a rule whose correctness depends on
 * having recognised a guard emits a false positive every time it meets a guard
 * shape nobody enumerated, and no exclusion list closes that, because the
 * guard can always be one method away.
 *
 * Seven of the eight are `WARNING` on that test, and only `empty-catch`
 * survives at `ERROR`. That ratio is the honest result for a syntactic matcher
 * with no dataflow, not a failure of the pack: almost nothing clears the bar.
 * `empty-catch` clears it because its escape hatch is not a guard at all — it
 * is a DECLARATION OF INTENT the rule itself reads, the Checkstyle / IntelliJ
 * `ignore` / `ignored` / `expected` convention. What it emits after honouring
 * that is an unmarked silent swallow, which is a bug whatever the author meant.
 *
 * Pinned here because nothing else pinned it. The tier is not cosmetic: the
 * Semgrep parser maps ERROR → `high` and WARNING → `medium`
 * (`src/runners/scannerParsers/semgrep.ts`), and `create_fix_pr` defaults
 * `severity_min` to `high`. With seven of eight at `WARNING`, the Java pack
 * now contributes almost nothing to the DEFAULT fix-PR set, and a caller who
 * wants Java bugs fixed has to ask: `severity_min: "medium"`. `bug_hunt` itself
 * defaults to no filter, so nothing disappears from a scan.
 */
const EXPECTED_SEVERITY: Readonly<Record<string, string>> = {
  'bugfix-java-error-handling-empty-catch': 'ERROR',
  'bugfix-java-error-handling-printstacktrace-only': 'WARNING',
  'bugfix-java-null-safety-map-get-deref': 'WARNING',
  'bugfix-java-null-safety-optional-get-no-ispresent': 'WARNING',
  'bugfix-java-off-by-one-loop-lte-length': 'WARNING',
  'bugfix-java-memory-leak-stream-not-closed': 'WARNING',
  'bugfix-java-race-condition-static-dateformat': 'WARNING',
  'bugfix-java-edge-case-modify-during-iteration': 'WARNING',
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
      // The TOTAL, asserted on top of the per-file counts, and not redundant:
      // the loop above only visits files that have an expectation, so a finding
      // landing in a file nobody registered — or in no file at all — would not
      // move any per-file number. 63 = 35 from the eight per-rule fixtures plus
      // the 28 of the real-bugs corpus.
      expect(rows.length).toBe(
        Object.values(EXPECTED_HITS_BY_FILE).reduce((n, e) => n + e.count, 0),
      );
    },
  );

  /**
   * THE TRAP FAMILY, and the two assertions that make catching it automatic
   * instead of a matter of somebody noticing.
   *
   * Three separate silent-failure modes have now shipped through this rule
   * file: a `pattern-either` branch with no positive term (`RuleParseError`),
   * an unquoted `?` in a ternary exclusion (`Invalid YAML file`), and
   * `... <... e ...> ...` written inside a block. They look nothing alike and
   * were each found the hard way, but they are ONE family, because they share
   * a signature: **fewer rules actually load than the file declares, and the
   * run still exits 0 printing `Scan completed successfully`.** Semgrep's
   * summary output cannot be trusted to tell a broken rule from a rule that
   * found nothing — that is the whole trap.
   *
   * The total-hits assertion above is already the family-wide catch: a rule
   * that fails to load loses its findings and the total moves. But it only
   * works while EVERY rule has at least one hit fixture behind it, which
   * nothing stated and nothing enforced. These two assertions close that:
   *
   *  - the first makes the "every rule has a fixture" precondition
   *    self-enforcing, by comparing the ids the fixtures exercise against the
   *    `- id:` entries parsed out of the YAML itself rather than against a list
   *    maintained by hand next to it;
   *  - the second catches what no finding-count assertion can see: a
   *    clause-level compile failure that happens not to change any finding.
   *    `--validate --quiet` is silent on success and non-zero on failure —
   *    measured against all three traps above, which return 2, 5 and 2. The
   *    empty-stream half of the assertion is what catches a rule that merely
   *    WARNS while still exiting 0. `--disable-version-check` is there because
   *    the upgrade notice is network state, and an empty-stderr assertion
   *    hostage to network state is a flake waiting to happen.
   */
  it.skipIf(!AVAILABLE)(
    'every rule the YAML declares is exercised by a hit fixture',
    () => {
      const { rows } = run(RULES, resolve(FIXTURES, 'hits'));
      expect(ids(rows)).toEqual(declaredRuleIds());
    },
  );

  it.skipIf(!AVAILABLE)('the rule file compiles clean, silently, and exits 0', () => {
    const validated = spawnSync(
      'semgrep',
      ['--validate', '--quiet', '--disable-version-check', '--config', RULES],
      { encoding: 'utf8' },
    );
    expect([validated.status, validated.stdout, validated.stderr]).toEqual([0, '', '']);
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
  'bugfix-java-error-handling-empty-catch': 'error_handling',
  'bugfix-java-error-handling-printstacktrace-only': 'error_handling',
  'bugfix-java-null-safety-map-get-deref': 'null_safety',
  'bugfix-java-null-safety-optional-get-no-ispresent': 'null_safety',
  'bugfix-java-off-by-one-loop-lte-length': 'off_by_one',
  'bugfix-java-memory-leak-stream-not-closed': 'memory_leak',
  'bugfix-java-race-condition-static-dateformat': 'race_condition',
  'bugfix-java-edge-case-modify-during-iteration': 'edge_case',
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
