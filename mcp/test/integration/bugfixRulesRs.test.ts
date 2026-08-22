/**
 * Runs the local `bugfix-rs.yml` rule against the fixture pair in
 * `mcp/test/fixtures/bugfix-rs/{hits,misses}/` and asserts, per file, the
 * EXACT set of rule ids, the RAW non-deduplicated finding count, and the
 * number of files Semgrep actually scanned.
 *
 * Mirrors `bugfixRulesCs.test.ts`, scaled to a ONE-RULE pack. The pack really
 * is one rule; `configs/semgrep/bugfix-rs.yml`'s header says why at length,
 * and the short version is that Rust's compiler takes the four flagship bug
 * classes outright (E0502, E0515, E0373, E0599) and `clippy`'s type-aware
 * restriction lints beat every Semgrep equivalent measured for the rest. The
 * decision of record is
 *
 * Why each assertion, unchanged from the C# and Java rounds:
 *
 *  - The id set alone cannot prove a particular instance still matches while
 *    a sibling instance of the same rule survives in the same file. With one
 *    rule the id set is nearly vacuous, so the COUNT is doing almost all the
 *    work here.
 *  - `paths.scanned` closes the worst case: Semgrep exits 0 with empty
 *    results when it scans nothing, so "found nothing" and "looked at
 *    nothing" are otherwise byte-identical. The in-repo fixture path contains
 *    a `test/` segment, which Semgrep's default ignore list skips wholesale —
 *    which is why fixtures are copied to a temp dir first, and why asserting
 *    the count is what proves the copy still works.
 *
 * ---------------------------------------------------------------------------
 * THE RUST-SPECIFIC SILENT FAILURE, which none of the three assertions above
 * catches on its own, and which the per-file COUNT below is the only guard
 * against.
 *
 * `async fn $F(...) -> $R { ... }` is the NARROW form of the pattern. `-> $R`
 * is not optional to the engine: it requires a written return type, so every
 * `async fn` without one stops matching. Measured in the probe: the narrow
 * form found 2 of 4 bugs, with `paths.scanned` healthy and `errors: 0`. This
 * is C#'s `$T $V` versus `var $V` trap in a second language.
 *
 * The hits fixture is laid out against exactly that: FOUR of its six bugs are
 * in `async fn`s with no return type. A regression to the narrow form takes
 * this file from 6 to 2 and moves no other number in the suite.
 *
 * A THIRD spelling of the same family, found by the ablation harness rather
 * than by reading: the `move` on a closure is IGNORED, symmetrically —
 * `$F(|| { ... })` matches `f(move || { ... })` and `$F(move || { ... })`
 * matches `f(|| { ... })`. Enumerating both spellings therefore produces a
 * MUTUALLY REDUNDANT pair in which each half reads DEAD alone and removing
 * both is a regression. The rule writes one spelling; the near-miss fixture
 * keeps both, because both are correct code and they are what proves the
 * symmetry.
 *
 * And the same trap runs the OTHER WAY for paths, which is why the rule's
 * positive term is the fully-qualified `std::thread::sleep(...)`: the engine
 * resolves `use` declarations, so the qualified spelling matches
 * `std::thread::sleep(d)`, `thread::sleep(d)` and a bare `sleep(d)`, while
 * `thread::sleep(...)` matches only the middle one. All three spellings are
 * in the hits fixture.
 *
 * ---------------------------------------------------------------------------
 * NOT HERE, deliberately: the registry-overlap block that `bugfixRulesCs.ts`
 * carries. The measurements exist — `p/r2c-bug-scan` reports
 * `paths.scanned = 0` for Rust (it ships no Rust rules at all) and `p/rust`
 * scans the files and finds nothing — and they are recorded in the decision of
 * record §4. They are not re-run here because a registry scan needs the
 * network on every run of the suite, and this pack has one rule whose
 * additivity was settled by a stronger argument than a registry diff: nothing
 * in the Rust toolchain catches it at any lint level, which is the claim that
 * actually justifies shipping it.
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
const RULES = resolve(REPO_ROOT, 'configs', 'semgrep', 'bugfix-rs.yml');
const FIXTURES = resolve(REPO_ROOT, 'mcp', 'test', 'fixtures', 'bugfix-rs');
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
  const work = makeTempDir('guardian-bugfix-rs-');
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
  return readdirSync(dir).filter((name) => name.endsWith('.rs')).sort();
}

/**
 * Every `- id:` the rule file DECLARES, read out of the YAML text rather than
 * out of a list maintained here. It is the left-hand side of the invariant
 * below: what the file declares must equal what the fixtures exercise.
 *
 * It also pins the pack's SIZE. One rule is the decision, not an accident, so
 * a second `- id:` appearing here has to arrive with a fixture and an entry in
 * `EXPECTED_SEVERITY` and `EXPECTED_CLASS` — and with a reason, since the
 * pack header's whole argument is that the twelve other candidates were
 * measured and killed.
 */
function declaredRuleIds(): string[] {
  const declared: string[] = [];
  for (const line of readFileSync(RULES, 'utf8').split('\n')) {
    const id = /^\s*-\s+id:\s*(\S+)\s*$/.exec(line)?.[1];
    if (id !== undefined) declared.push(id);
  }
  return declared.sort();
}

const BLOCKING_SLEEP = 'bugfix-rs-race-condition-blocking-sleep-in-async';

interface FileExpectation {
  readonly ids: readonly string[];
  readonly count: number;
}

/**
 * The exact rule ids and the RAW finding count expected in each `hits/`
 * fixture. A fixture on disk with no entry here fails Step 0 below rather
 * than being silently unmeasured.
 */
const EXPECTED_HITS_BY_FILE: Readonly<Record<string, FileExpectation>> = {
  'blocking_sleep_in_async.rs': {
    // SIX, and the number is the whole test. See the header: FOUR of the six
    // are in `async fn`s with NO return type, so the narrow `-> $R` form of
    // the pattern scores 2 here and nothing else in the suite notices. A
    // second dimension is the spelling of the call — `std::thread::sleep`,
    // `thread::sleep`, and a bare `sleep` imported by `use std::thread::sleep`
    // — all three of which the qualified pattern matches and only one of which
    // the short pattern does.
    //
    // The last two are a symmetric pair, and each one guards one half of the
    // exclusion. The rule excludes blocking work handed to another thread, and
    // both obvious spellings of that exclusion swallow a real bug:
    //
    //   - anchored on the NAME alone (any call whose name contains `spawn`) it
    //     swallows `spawn(async move { thread::sleep(d); })`, which schedules
    //     the future on the SAME executor and is a genuine bug — hits' BUG 5;
    //   - anchored on the CLOSURE alone (any call taking a closure) it
    //     swallows `retry(|| { thread::sleep(d); })`, which runs the closure
    //     inline on the executor thread — hits' BUG 6.
    //
    // Both were measured. The exclusion needs both halves, and without these
    // two fixtures the `metavariable-regex` half reads DEAD in the ablation
    // for want of a shape rather than for want of a purpose. If this file
    // drops to 5, one half of the exclusion just went too wide.
    ids: [BLOCKING_SLEEP],
    count: 6,
  },
};

/**
 * The severity tier the rule is DESIGNED to carry, per the C# design of record
 * §4, whose criterion is a question about the OUTPUT: **is what the rule
 * EMITS always a bug?** A rule whose correctness depends on having recognised
 * a guard emits a false positive every time it meets a guard shape nobody
 * enumerated, and no exclusion list closes that, because the guard can always
 * be one method away.
 *
 * WARNING, and the call is worth stating because the probe read it the other
 * way. The probe's argument for ERROR was that the nearest legitimate shape —
 * a deliberately blocking helper — is not written as an `async fn`. True, but
 * incomplete: there is a second legitimate shape that IS written inside an
 * `async fn`, namely handing the blocking work to another thread. Measured, all
 * inside an `async fn`, all correct, all firing before the exclusion existed:
 * `thread::spawn(|| ...)`, `tokio::task::spawn_blocking(|| ...)`,
 * `async_std::task::spawn_blocking(|| ...)`, `rt.spawn_blocking(|| ...)` and
 * `thread::Builder::new().spawn(|| ...)`. The second of those is the fix the
 * rule's own message prescribes.
 *
 * So the rule excludes them — by NAME rather than by path, since anchoring on
 * the path let the `async_std` spelling and the method call straight through,
 * and by CLOSURE rather than by name alone, since a name-only exclusion also
 * swallowed `tokio::spawn(async move { ... })`, which keeps the work on the
 * executor and is a genuine bug. But a name list never closes: an application
 * helper called `run_off_thread` taking a closure does the same job and still
 * emits. That is the WARNING condition of §4 word for word — correctness
 * depending on a wrapper the matcher cannot enumerate. ERROR would need there
 * to be no wrapper to recognise at all, as in C#'s `throw ex;`, whose correct
 * form is a different AST node.
 *
 * The rule's declared FALSE NEGATIVE points the same way: a bare `async` block
 * in a SYNC `fn` — `tokio::spawn(async move { thread::sleep(d); })` in `main`
 * — is not matched at all, because the anchor is `async fn`. Measured, stated
 * in the rule, and deliberately not closed by guesswork in a pack whose whole
 * argument is that the twelve candidates it does not ship were measured.
 *
 * Pinned here because nothing else pins it. The tier is not cosmetic: the
 * Semgrep parser maps ERROR -> `high` and WARNING -> `medium`
 * (`src/runners/scannerParsers/semgrep.ts`), and `create_fix_pr` defaults
 * `severity_min` to `high`, so the tier decides whether a rule contributes to
 * the default fix-PR set at all.
 */
const EXPECTED_SEVERITY: Readonly<Record<string, string>> = {
  [BLOCKING_SLEEP]: 'WARNING',
};

describe('bugfix-rs rules', () => {
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
   * THE TRAP FAMILY. Nine ways Semgrep does nothing while printing a green
   * summary have now been found across this series, and they share one
   * signature: **fewer rules actually load, or actually match, than the file
   * declares, and nothing in the findings says so.**
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
   * listing, in `semgrepPacks.test.ts`, which picks up `bugfix-rs.yml` by its
   * existing on disk. Two mechanisms for one invariant is how they drift
   * apart.
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
    // Both directions: every designed tier is what Semgrep reports, AND no id
    // reports that nobody designed a tier for.
    for (const [id, tier] of Object.entries(EXPECTED_SEVERITY)) {
      expect([id, [...(seen.get(id) ?? [])]]).toEqual([id, [tier]]);
    }
    expect([...seen.keys()].sort()).toEqual(Object.keys(EXPECTED_SEVERITY).sort());
  });
});

/** Rule ids carry the class token because `mapSubcategory` classifies by regex
 *  over the lowercased id. Runs unconditionally — pure function, no Semgrep. */
const EXPECTED_CLASS: Readonly<Record<string, string>> = {
  [BLOCKING_SLEEP]: 'race_condition',
};

describe('every rule id classifies as its own class', () => {
  it('maps every id in the file', () => {
    for (const [id, cls] of Object.entries(EXPECTED_CLASS)) {
      expect(mapSubcategory(id, undefined)).toBe(cls);
    }
  });

  it("no id contains a word another class's regex claims first", () => {
    // The hazard list is per-language, and Rust's is the longest so far.
    //
    //  - `unchecked` is matched by the error_handling regex — and in Rust it
    //    is a live identifier fragment (`unchecked_add`, `get_unchecked`,
    //    `from_utf8_unchecked`), so it is a very plausible thing to name a
    //    rule after.
    //  - `concurren` is matched by the race_condition regex, which runs FIRST
    //    in the if-chain.
    //  - `edge_case` is checked LAST, so `boundary`, `overflow`, `underflow`
    //    and `out.of.range` are all claimed by off_by_one first — and every
    //    one of those four is ordinary Rust vocabulary (`overflowing_add`,
    //    `checked_sub`, slice bounds), which is what makes this list longer
    //    here than it was for C# or Java.
    for (const id of Object.keys(EXPECTED_CLASS)) {
      expect(id).not.toContain('unchecked');
      expect(id).not.toContain('concurren');
      expect(id).not.toContain('boundary');
      expect(id).not.toContain('overflow');
      expect(id).not.toContain('underflow');
      expect(id).not.toContain('out-of-range');
    }
  });
});
