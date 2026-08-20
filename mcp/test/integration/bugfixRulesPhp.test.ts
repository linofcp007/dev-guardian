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
 * one was refuted by real code rather than by argument: see the block above
 * `EXPECTED_SEVERITY`'s entry for `empty-catch` when Task 2 adds it.
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
