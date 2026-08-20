/**
 * Runs the local `bugfix-php.yml` rules against the fixture pairs in
 * `mcp/test/fixtures/bugfix-php/{hits,misses}/` and asserts, per file, the
 * EXACT set of rule ids, the RAW non-deduplicated finding count, and the
 * number of files Semgrep actually scanned.
 *
 * Mirrors `bugfixRulesCs.test.ts`, for the reasons documented there:
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
 * AND THE SILENT-FAILURE MODE THIS ROUND ADDS, which is PHP's twin of the C#
 * `var` trap and which NONE of the three assertions above catches on its own.
 *
 * **A FULLY-QUALIFIED TYPE NAME IN A PHP PATTERN MATCHES NOTHING, SILENTLY.**
 * `catch (\RuntimeException $E)` found ZERO occurrences of source that reads
 * exactly `catch (\RuntimeException $e)`. The scan runs, `paths.scanned` is
 * healthy, `errors` is empty, every gate in this file stays green, and the
 * answer is nothing. Bind the type to a metavariable — `catch ($E $V)` — and
 * the rule exists.
 *
 * The only thing that sees it is a non-zero hits count on code somebody wrote
 * the way PHP is actually written, which is what the per-file `count`
 * assertions below and the real-bugs corpus are for.
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
const RULES = resolve(REPO_ROOT, 'configs', 'semgrep', 'bugfix-php.yml');
const FIXTURES = resolve(REPO_ROOT, 'mcp', 'test', 'fixtures', 'bugfix-php');
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
  const work = makeTempDir('guardian-bugfix-php-');
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
  return readdirSync(dir).filter((name) => name.endsWith('.php')).sort();
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
  'empty_catch.php': {
    // SIX of the eight catch spellings in the file, and the two it misses are
    // the same one twice: the PHP 8 NON-CAPTURING `catch (\Foo) { }`, with and
    // without a `finally`. Every pattern spelling of that form fails to parse,
    // so the rule cannot reach it at all. It is in hits/ and annotated rather
    // than omitted, because a spelling nobody wrote down is a spelling nobody
    // notices is missing.
    //
    // The six that do fire are one plain, one `\Throwable`, one with a
    // FINALLY, one union catch type, one first-of-two-catch-clauses, and one
    // whose body holds only a comment.
    //
    // The `finally` one is not padding: `try{}catch(){}` and
    // `try{}catch(){}finally{}` are DISJOINT AST nodes, and the no-finally
    // pattern alone scores 5 here instead of 6. Measured before the rule was
    // written rather than after — this exact hole shipped in the Java pack.
    //
    // The union catch is what proves the type metavariable is load-bearing:
    // a pattern naming `\RuntimeException` matches neither it nor the
    // `\Throwable` one, and — per the file header — matches nothing at all.
    ids: ['bugfix-php-error-handling-empty-catch'],
    count: 6,
  },
  'json_decode.php': {
    // SIX, and the last two are the ones that matter under ablation.
    //
    // Four are the plain shapes: a dereference straight off the call, the
    // same through a local, a subscript off the call, and a method call on
    // the decoded value.
    //
    // The fifth and sixth are guarded bugs, in hits/ deliberately. Ablation
    // axis 2 asks whether removing an exclusion REVEALS a finding here, and
    // an exclusion that swallows a real bug is invisible unless the bug sits
    // beside the guard shape that exclusion matches. One has a null check on
    // a DIFFERENT variable; the other has an `isset()` on a DIFFERENT
    // property than the one it goes on to read. Both are unguarded reads, and
    // both would be swallowed by an exclusion keyed one notch too wide.
    ids: ['bugfix-php-null-safety-json-decode-deref'],
    count: 6,
  },
  'loose_null.php': {
    // Six over four patterns: `$x == null`, `$x != null` and both with `null`
    // on the left, plus two shouty spellings. `null` in a Semgrep pattern is
    // CASE-INSENSITIVE, so `NULL` and `Null` need no branches of their own —
    // the two extra fixtures are the measurement of that, not padding.
    ids: ['bugfix-php-null-safety-loose-null-compare'],
    count: 6,
  },
  'real_bugs.php': {
    // THE REAL-BUGS CORPUS — six defects over all SIX rules, so every rule in
    // the pack has corpus coverage. The Java round left three rules at zero
    // and that was the riskiest gap in that pack.
    //
    // It exists to give the ablation its second axis. Everything else in hits/
    // is one minimal instantiation per rule, written by whoever wrote the
    // rule: that proves a rule fires, but it cannot prove an exclusion added
    // later did not eat a real bug, because a minimal fixture carries no guard
    // shapes for an exclusion to catch on. Every defect here sits BESIDE the
    // guard shape its rule's exclusions match — an atomic `@mkdir` next to the
    // check-then-act, an `isset()` on another property next to the unguarded
    // read, a strict `< $n` loop next to the inclusive one, a `$ignored` catch
    // next to the swallow.
    //
    // Those neighbours are marked `// excluded:` in the file. A reveal on one
    // of them under ablation is the clause working; a reveal on a `// BUG:`
    // line is the defect axis 2 exists for.
    ids: [
      'bugfix-php-edge-case-strpos-truthiness',
      'bugfix-php-error-handling-empty-catch',
      'bugfix-php-null-safety-json-decode-deref',
      'bugfix-php-null-safety-loose-null-compare',
      'bugfix-php-off-by-one-loop-lte-count',
      'bugfix-php-race-condition-toctou-file',
    ],
    count: 6,
  },
  'off_by_one.php': {
    // THIRTEEN, and the breakdown is the point: the rule has two branches
    // (the count in the condition, and the count hoisted into a local) and
    // both of them cross {`$i++`, `++$i`}, because those are different AST
    // nodes and a rule written for one is blind to the other.
    //
    //  - direct branch, 10: four counting builtins (count, sizeof, strlen,
    //    mb_strlen), a counted property, a loop variable that is not `$i`,
    //    the pre-increment twin, a BRACE-LESS body, the `for(): ... endfor;`
    //    alternative syntax, and the one known false positive.
    //  - hoisted branch, 3: `$n = count(...)`, its pre-increment twin, and
    //    `$len = strlen(...)`, which is what makes the hoisted branch's own
    //    copy of the function-name filter measurable.
    //
    // The brace-less and `endfor` entries are not padding. `for (...) ...`
    // matches all three body shapes and `for (...) { ... }` matches only the
    // braced one; the recall is free, and these two fixtures are the only
    // thing that would notice it being given up.
    //
    // ONE OF THE THIRTEEN IS A KNOWN FALSE POSITIVE and is annotated as such
    // in the fixture: an inclusive loop over an array deliberately allocated
    // with count+1 slots. It is here rather than in misses/ because it really
    // does fire, and misses/ is a promise that nothing in it fires.
    ids: ['bugfix-php-off-by-one-loop-lte-count'],
    count: 13,
  },
  'strpos.php': {
    // TEN, one per branch plus two extra receivers on the `if` branch, and
    // ELEVEN bug sites in the file: the eleventh is the store-then-test
    // spelling (`$at = strpos(...); if ($at)`), which the rule cannot reach
    // because once the result is bound to a local there is no call left in
    // the boolean position to name. It is in hits/ and annotated, on the same
    // principle as the non-capturing catch above.
    //
    // Every one of the eight branches has a fixture behind it, deliberately:
    // a `pattern-either` branch with nothing exercising it reads DEAD under
    // ablation and cannot be told apart from a branch that never worked.
    ids: ['bugfix-php-edge-case-strpos-truthiness'],
    count: 10,
  },
  'toctou.php': {
    // Five over four branches: file_exists->unlink, !is_dir->mkdir,
    // !file_exists->file_put_contents, and TWO is_writable->fopen sites, one
    // binding the handle to a local and one not.
    //
    // The two fopen sites share ONE branch, which is a measurement rather
    // than an assumption: the probe carried a separate `$H = fopen(...)`
    // branch, and the statement-ellipsis branch was measured to match that
    // site as well, so the second branch was dead weight and did not ship.
    ids: ['bugfix-php-race-condition-toctou-file'],
    count: 5,
  },
};

/**
 * The severity tier each rule is DESIGNED to carry, per the design of record
 * §3, whose criterion is a question about the OUTPUT: **is what the rule
 * EMITS always a bug?** A rule whose correctness depends on having recognised
 * a guard emits a false positive every time it meets a guard shape nobody
 * enumerated, and no exclusion list closes that, because the guard can always
 * be one call away.
 *
 * **ZERO OF THE PHP RULES CLEAR THAT BAR**, against 2 of 12 in C#, 1 of 8 in
 * Java and 1 of 13 in JS/TS. C# reached ERROR twice because one defect
 * (`throw ex;`) has a correct form that is a DIFFERENT AST NODE, so there is
 * no guard to recognise. No PHP candidate has that property, and the closest
 * one — `empty-catch`, which Java and C# both ship at ERROR — was refuted by
 * real code rather than by argument. See its entry below.
 *
 * Pinned here because nothing else pins it. The tier is not cosmetic: the
 * Semgrep parser maps ERROR -> `high` and WARNING -> `medium`
 * (`src/runners/scannerParsers/semgrep.ts`), and `create_fix_pr` defaults
 * `severity_min` to `high`, so the tier decides whether a rule contributes to
 * the default fix-PR set at all.
 */
const EXPECTED_SEVERITY: Readonly<Record<string, string>> = {
  // An inclusive bound is correct whenever the loop COUNTS rather than
  // indexes, and correct again when the array was deliberately allocated one
  // longer. Neither condition is visible to a syntactic matcher — the known
  // false positive in hits/off_by_one.php is exactly that second case.
  'bugfix-php-off-by-one-loop-lte-count': 'WARNING',
  // A check-then-act pair is correct in any single-process program, and most
  // PHP bootstrap scripts are one. The rule cannot see concurrency.
  'bugfix-php-race-condition-toctou-file': 'WARNING',
  // WARNING, AND THIS ONE IS THE INTERESTING CALL. Java and C# both ship
  // `empty-catch` at ERROR, on the premise that an unmarked swallow is a bug
  // whatever the author meant. Neither measured that premise against code
  // nobody wrote as a fixture, because a real-code corpus was N/A for both.
  //
  // PHP has one, and it refutes the premise: all TEN findings on WordPress 6.9
  // are deliberate empty catches carrying an explanatory comment. Semgrep
  // cannot read comments, and PHP's naming convention for deliberate silence
  // is weaker than Java's or C#'s — modern PHP declares intent with the
  // non-capturing `catch (\Foo) { }`, which this rule cannot match at all and
  // which therefore self-exempts, leaving only the capturing spelling that
  // real code uses for exactly the same intent.
  //
  // So what this rule emits is NOT always a bug, and it is WARNING here. The
  // consequence for the two packs already shipping it at ERROR is recorded in
  // the design of record §3 rather than acted on: it is a separate change,
  // with its own fixture counts.
  'bugfix-php-error-handling-empty-catch': 'WARNING',
  // WARNING. Most of the 26 findings on WordPress are correct BY A DOMAIN
  // INVARIANT — a version string cannot start with `-`, an email cannot start
  // with `@` — and an invariant is not visible to a syntactic matcher. That is
  // the WARNING profile exactly.
  'bugfix-php-edge-case-strpos-truthiness': 'WARNING',
  // The two null_safety rules, and they are the clearest illustration of the
  // §3 criterion in the pack: `json-decode-deref` is correct ONLY where it has
  // recognised a guard, and a guard can always be one call away, outside any
  // syntactic matcher's reach. `loose-null-compare` fails the bar from the
  // other side — `== null` is the RIGHT comparison when the domain really
  // means "empty or absent", and that intent is not in the syntax.
  'bugfix-php-null-safety-json-decode-deref': 'WARNING',
  'bugfix-php-null-safety-loose-null-compare': 'WARNING',
};

describe('bugfix-php rules', () => {
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
   * THE TRAP FAMILY. Several ways Semgrep does nothing while printing a green
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
   * listing, in `semgrepPacks.test.ts`, which picks up `bugfix-php.yml` by its
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

  /**
   * THE FIFTH GOVERNING RULE OF THIS SERIES, AND IT IS NEW THIS ROUND.
   *
   * > Run the WHOLE PACK against the prescribed-fix file, not each rule
   * > against its own.
   *
   * `fixed/fixed.php` holds every bug in `hits/` rewritten with the fix its
   * OWN message prescribes. The entire pack is run over it and asserted to
   * find nothing.
   *
   * Per-rule checking is not enough, and the difference is not theoretical:
   * the `error-suppression-operator` candidate passed every per-rule check in
   * the probe and was killed HERE. `toctou-file`'s own message prescribes
   * "act first and inspect the return value", whose idiomatic PHP is
   * `@mkdir(...)` / `@unlink(...)` — so in the file where every bug carries
   * the fix its own rule asked for, that candidate fired three times, all
   * three on ANOTHER rule's prescribed fix.
   *
   * **One rule firing on another rule's prescribed fix is not a tuning
   * problem**, and no per-rule check can see it. A pack that fails this test
   * tells its user to make a change it will then complain about.
   */
  it.skipIf(!AVAILABLE)('finds NOTHING in the whole-pack prescribed-fix file', () => {
    const fixedDir = resolve(FIXTURES, 'fixed');
    const { rows, scanned } = run(RULES, fixedDir);
    // `paths.scanned` first: a zero here would make the zero below meaningless
    // in exactly the way this repo has recorded nine separate times.
    expect(scanned).toBe(fixtureFiles(fixedDir).length);
    expect(scanned).toBeGreaterThan(0);
    expect(rows.map((r) => `${basename(r.path)}: ${r.check_id}`)).toEqual([]);
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
  'bugfix-php-off-by-one-loop-lte-count': 'off_by_one',
  'bugfix-php-race-condition-toctou-file': 'race_condition',
  'bugfix-php-error-handling-empty-catch': 'error_handling',
  'bugfix-php-edge-case-strpos-truthiness': 'edge_case',
  'bugfix-php-null-safety-json-decode-deref': 'null_safety',
  'bugfix-php-null-safety-loose-null-compare': 'null_safety',
};

describe('every rule id classifies as its own class', () => {
  it('maps every id in the file', () => {
    for (const [id, cls] of Object.entries(EXPECTED_CLASS)) {
      expect(mapSubcategory(id, undefined)).toBe(cls);
    }
  });

  it("no id contains a word another class's regex claims first", () => {
    // THREE words are hazardous here, and the third is the one that matters.
    //
    //  - `unchecked` is matched by the error_handling regex, and "unchecked
    //    return value" is the natural name for half of what `toctou` is about.
    //  - `concurren` is matched by the race_condition regex, which runs FIRST
    //    in the if-chain.
    //  - `dangling` is matched by the memory_leak regex, which runs BEFORE
    //    error_handling — and "dangling reference" is the PHP MANUAL'S OWN
    //    term for the foreach-by-reference defect. That candidate was killed
    //    (design §5), but the name is the one a future round would reach for
    //    first, and it would classify as memory_leak, silently.
    for (const id of Object.keys(EXPECTED_CLASS)) {
      expect(id).not.toContain('unchecked');
      expect(id).not.toContain('concurren');
      expect(id).not.toContain('dangling');
    }
  });
});

/**
 * DESIGN OF RECORD §1: no local rule may re-report what the registry packs
 * already find. For PHP the answer has three shapes, and one of them cannot be
 * proved at all — which is said here rather than papered over.
 *
 * Measured, and reproduced by these tests:
 *
 *   | pack               | on the hit fixtures       | positive control          |
 *   | ------------------ | ------------------------- | ------------------------- |
 *   | p/r2c-bug-scan     | paths.scanned = 0         | control_r2c.py (Python)   |
 *   | p/php              | scanned = N, 0 findings   | vulnerable.php, 9 hits    |
 *   | p/security-audit   | scanned = N, 0 findings   | NONE — 0 on the control   |
 *
 * `p/r2c-bug-scan` SHIPS NO PHP RULES AT ALL. It does not merely find nothing —
 * it scans nothing, reporting `paths.scanned = 0`. So for that pack a zero
 * finding count is not evidence of anything, and no PHP control could rescue
 * it either, because there is no PHP rule for a PHP control to trip. The only
 * way to distinguish "additive" from "never ran" is to prove the pack is alive
 * in a language it does cover, which is why there is a PYTHON file in a PHP
 * fixture tree. A Go-round defect was a control directory nothing enumerated,
 * deleted silently, leaving the test skipping while the suite stayed green —
 * so the controls are asserted to have RUN, not merely to have been clean.
 *
 * `p/security-audit` HAS NO POSITIVE CONTROL, and this is now the SECOND
 * language in which that has been measured rather than assumed. It finds
 * nothing on twelve classic PHP vulnerabilities — eval of `$_GET`, `system()`
 * of `$_GET`, concatenated SQL through PDO and mysqli, reflected XSS, local
 * file inclusion, `unserialize()` of a cookie, MD5 of a password, open
 * redirect, path traversal, an insecure cookie — while `p/php` fires NINE
 * times on the same file. Treat it as a property of that pack, not a quirk of
 * one language: the same was measured in C#.
 *
 * What is left for that pack is weaker but not nothing: `paths.scanned > 0`
 * proves it HAS PHP rules and enumerated our files, since a pack with no rules
 * for a language reports 0 — which is exactly how `p/r2c-bug-scan` behaves two
 * paragraphs up. That is asserted below, and labelled as the weaker claim it
 * is.
 *
 * `base.yml`'s own PHP rules are not here because they are all SECURITY —
 * `php-eval`, `php-sql-injection-direct`, `wp-unescaped-output` — and intersect
 * none of the six.
 */
const REGISTRY_PACKS = ['p/r2c-bug-scan', 'p/php', 'p/security-audit'] as const;

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
const PHP_ON_CONTROL = registryRunOrNull('p/php', CONTROL_DIR);
const AUDIT_ON_CONTROL = registryRunOrNull('p/security-audit', CONTROL_DIR);

describe('no local PHP rule duplicates the registry packs', () => {
  it.runIf(REQUIRE_SEMGREP)('every registry pack must be reachable when the flag is set', () => {
    for (const pack of REGISTRY_PACKS) {
      expect([pack, ON_HITS.get(pack) ?? null]).not.toEqual([pack, null]);
    }
    // Asserted too, and deliberately: without this the control fixtures could
    // be deleted and this whole describe block would go on passing, with the
    // control tests merely SKIPPING. That exact hole shipped in the Go round.
    expect(R2C_ON_CONTROL).not.toBeNull();
    expect(PHP_ON_CONTROL).not.toBeNull();
    expect(AUDIT_ON_CONTROL).not.toBeNull();
  });

  it.skipIf(R2C_ON_CONTROL === null)(
    'positive control: p/r2c-bug-scan is LIVE — proved in Python, because it has no PHP rules',
    () => {
      // One, not two: the pack has no PHP rules, so it enumerates only the
      // Python file in a directory holding one of each.
      expect(R2C_ON_CONTROL?.scanned).toBe(1);
      expect(R2C_ON_CONTROL?.rows.length).toBeGreaterThan(0);
    },
  );

  it.skipIf(PHP_ON_CONTROL === null)('positive control: p/php is LIVE for PHP', () => {
    expect(PHP_ON_CONTROL?.scanned).toBe(1);
    expect(PHP_ON_CONTROL?.rows.length).toBeGreaterThan(0);
  });

  it.skipIf(AUDIT_ON_CONTROL === null)(
    'p/security-audit has NO positive control — it finds nothing on the vulnerable file either',
    () => {
      // Pinned as a measured fact rather than left as a gap in the comments.
      // It DID enumerate both control files, so this is "found nothing", not
      // "never ran" — and it is the second language in which that has been
      // measured. If this ever becomes non-zero the pack has gained something
      // and the claim below can be strengthened from `scanned > 0` to a real
      // additivity proof.
      expect(AUDIT_ON_CONTROL?.scanned).toBe(2);
      expect(AUDIT_ON_CONTROL?.rows.length).toBe(0);
    },
  );

  it.skipIf(ON_HITS.get('p/r2c-bug-scan') === null)(
    'p/r2c-bug-scan scans ZERO PHP files — the pack has no PHP rules at all',
    () => {
      // Pinned as an equality rather than "found nothing", because the two are
      // different facts and only this one explains why the Python control has
      // to exist. If this ever becomes non-zero the pack has gained PHP rules
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
      expect(ON_HITS.get('p/security-audit')?.scanned).toBe(fixtureFiles(HITS_DIR).length);
    },
  );

  for (const pack of ['p/php', 'p/security-audit'] as const) {
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
