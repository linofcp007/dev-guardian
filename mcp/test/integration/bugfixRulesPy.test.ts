/**
 * Runs the local `bugfix-py.yml` Semgrep rules against the fixture pairs in
 * `mcp/test/fixtures/bugfix-py/{hits,misses}/` and asserts, per file, the
 * EXACT set of rule ids that fired AND the raw non-deduplicated finding
 * count. Never "at least one": a rule that starts matching its own
 * near-miss must fail the suite rather than quietly widening (design of
 * record §2 and §6:
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
import { cpSync, existsSync, mkdtempSync, readdirSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { mapSubcategory } from '../../src/tools/bugHunt.js';
import { rmDir } from '../helpers/tempDir.js';

const REPO_ROOT = resolve(fileURLToPath(new URL('../../..', import.meta.url)));
const RULES = resolve(REPO_ROOT, 'configs', 'semgrep', 'bugfix-py.yml');
const FIXTURES = resolve(REPO_ROOT, 'mcp', 'test', 'fixtures', 'bugfix-py');
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
  /**
   * How many files Semgrep actually scanned. Asserted by every caller, not
   * merely carried: pointed at the in-repo fixture path (which contains a
   * `test/` segment, skipped by Semgrep's default ignore list), Semgrep
   * reports `paths.scanned: []` with zero results and exit 0 — identical in
   * every observable way to "scanned everything, found nothing". Measured
   * directly against this rule file, not inferred.
   */
  readonly scanned: number;
}

function run(config: string, dir: string): SemgrepRun {
  const work = mkdtempSync(join(tmpdir(), 'guardian-bugfix-py-'));
  try {
    return scan(config, dir, work);
  } finally {
    // Removed in `finally`, so it goes even when Semgrep throws — a dead
    // registry pack exits non-zero and `execFileSync` raises. Every call
    // used to leak its directory: 402 of them had accumulated under the OS
    // temp dir by the time this was noticed. `rmDir` rather than a bare
    // `rmSync` because Semgrep can still hold the copy open on Windows —
    // see `helpers/tempDir.ts`.
    rmDir(work);
  }
}

function scan(config: string, dir: string, work: string): SemgrepRun {
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

/** Every rule the pack declares. Spelled once, used by `real_bugs.py`. */
const ALL_RULES = [
  'bugfix-py-edge-case-queryset-n-plus-one',
  'bugfix-py-error-handling-bare-except',
  'bugfix-py-error-handling-except-pass',
  'bugfix-py-error-handling-get-without-doesnotexist',
  'bugfix-py-memory-leak-open-without-context',
  'bugfix-py-null-safety-none-deref-dict-get',
  'bugfix-py-null-safety-none-deref-match',
  'bugfix-py-off-by-one-range-len-plus-one',
  'bugfix-py-race-condition-asyncio-not-awaited',
  'bugfix-py-race-condition-toctou-exists-open',
] as const;

const EXPECTED_HITS_BY_FILE: Readonly<Record<string, FileExpectation>> = {
  /**
   * THE REAL-BUGS CORPUS, written by the AUDITOR rather than by the rules'
   * author. Thirty-three defects, at least one per rule, every one of them
   * SILENT before the 2026-08 audit and every one placed next to the guard
   * shape its rule's exclusions match.
   *
   * It exists because a minimal per-rule hit fixture carries no guard shapes
   * for an exclusion to catch on, so a wave of false-positive work can delete
   * recall and still go green — which is exactly what happened in the Java
   * pack (wave 4 took one fixture from 6 findings to 1 with a green suite).
   *
   * What it covers, and why each entry is a defect the old pack could not see:
   * four TOCTOU spellings the two-exact-function-names version missed; two
   * real dict bugs the receiver-name SUBSTRING allow-list silenced
   * (`session.get("user_id")`, `client_config.get("timeout")`); six `re` match
   * accessors beyond `.group()`; the explicit-start `range(0, n + 1)`; two
   * genuine N+1s behind a chained call, which broke the `.objects.all()`
   * anchor; an unguarded `.objects.get()` inside an `except` arm, silenced by
   * the guard that protects the OTHER arm; three `.objects.get()` calls in a
   * try whose handler does not guard the miss at all; nine swallows that were
   * silenced by adding a `finally:`, an `else:` or a second exception type;
   * and one leaked file handle and one un-awaited coroutine, each sitting in
   * the same function as the correct shape their rule excludes.
   */
  'real_bugs.py': { ids: [...ALL_RULES], count: 33 },
  'asyncio_not_awaited.py': {
    // All FOUR pattern-either branches (sleep, gather, wait, wait_for) are
    // exercised, so a branch that silently stops matching drops the count.
    ids: ['bugfix-py-race-condition-asyncio-not-awaited'],
    count: 4,
  },
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
  'none_deref_dict_get.py': { ids: ['bugfix-py-null-safety-none-deref-dict-get'], count: 2 },
  'none_deref_match.py': { ids: ['bugfix-py-null-safety-none-deref-match'], count: 3 },
  'open_without_context.py': { ids: ['bugfix-py-memory-leak-open-without-context'], count: 1 },
  'queryset_n_plus_one.py': { ids: ['bugfix-py-edge-case-queryset-n-plus-one'], count: 2 },
  'range_len_plus_one.py': { ids: ['bugfix-py-off-by-one-range-len-plus-one'], count: 2 },
  'toctou_exists_open.py': { ids: ['bugfix-py-race-condition-toctou-exists-open'], count: 2 },
};

/**
 * The severity tier each rule is DESIGNED to carry, and the criterion applied
 * to the OUTPUT rather than to the bug class: **is what the rule EMITS always
 * a bug?** Not "is the shape it looks for usually wrong" — a rule whose
 * correctness depends on having recognised a guard emits a false positive
 * every time it meets a guard shape nobody enumerated, and no exclusion list
 * closes that, because the guard can always be one line away.
 *
 * Nine of the ten are `WARNING` on that test, and only `none-deref-match`
 * survives at `ERROR`: its output is an accessor glued straight onto the
 * result of `re.match/search/fullmatch`, where the dereference is
 * unconditional on a value that is None whenever the pattern does not match,
 * and there is no guard to recognise. The pack's header used to define this
 * criterion correctly and then assign the tier by bug CLASS ("null-safety is
 * always serious"), which is how five rules ended up at ERROR; the 2026-08
 * audit applied it cold.
 *
 * Pinned here because nothing pinned it before — no test read
 * `extra.severity`, so any tier could be changed with a green suite. The tier
 * is not cosmetic: the Semgrep parser maps ERROR -> `high` and WARNING ->
 * `medium` (`src/runners/scannerParsers/semgrep.ts`), and `create_fix_pr`
 * defaults `severity_min` to `high`. With nine of ten at WARNING the Python
 * pack contributes almost nothing to the DEFAULT fix-PR set, and a caller who
 * wants Python bugs fixed has to ask: `severity_min: "medium"`. `bug_hunt`
 * itself defaults to no filter, so nothing disappears from a scan.
 */
const EXPECTED_SEVERITY: Readonly<Record<string, string>> = {
  'bugfix-py-null-safety-none-deref-match': 'ERROR',
  'bugfix-py-error-handling-bare-except': 'WARNING',
  'bugfix-py-error-handling-except-pass': 'WARNING',
  'bugfix-py-error-handling-get-without-doesnotexist': 'WARNING',
  'bugfix-py-null-safety-none-deref-dict-get': 'WARNING',
  'bugfix-py-off-by-one-range-len-plus-one': 'WARNING',
  'bugfix-py-memory-leak-open-without-context': 'WARNING',
  'bugfix-py-race-condition-asyncio-not-awaited': 'WARNING',
  'bugfix-py-race-condition-toctou-exists-open': 'WARNING',
  'bugfix-py-edge-case-queryset-n-plus-one': 'WARNING',
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
      const dir = resolve(FIXTURES, 'hits');
      const { rows, scanned } = run(RULES, dir);
      // Guards against the temp-copy step silently scanning zero files —
      // see SemgrepRun.scanned. Without this, an empty scan and a genuine
      // clean-of-findings scan are indistinguishable.
      expect(scanned).toBe(fixtureFiles(dir).length);
      const grouped = rowsByFile(rows);
      for (const [file, expected] of Object.entries(EXPECTED_HITS_BY_FILE)) {
        const fileRows = grouped[file] ?? [];
        expect(ids(fileRows)).toEqual([...expected.ids].sort());
        expect(fileRows.length).toBe(expected.count);
      }
      // The TOTAL, on top of the per-file counts, and not redundant: the loop
      // above only visits files that HAVE an expectation, so a finding landing
      // in a file nobody registered would not move any per-file number.
      expect(rows.length).toBe(
        Object.values(EXPECTED_HITS_BY_FILE).reduce((n, e) => n + e.count, 0),
      );
    },
  );

  /**
   * The trap family: a `pattern-either` branch with no positive term
   * (`RuleParseError`), an unquoted `?` in an exclusion (`Invalid YAML`), and
   * an UPPERCASE ACCENTED LETTER in a Portuguese comment all share one
   * signature — fewer rules load than the file declares, and nothing in the
   * findings says so. The third bit during the 2026-08 audit: Semgrep's config
   * loader decodes the rule file with the LOCALE codec, so on a Windows cp1252
   * locale the second byte of `Á` (U+00C1 -> 0xC3 0x81) is undefined and one
   * letter takes the whole file down, reporting `results: 0`,
   * `paths.scanned: 0` and `errors: 0`.
   *
   * The total-hits assertion above is the family-wide catch, but only while
   * EVERY rule has a hit fixture behind it. This closes that, comparing the ids
   * the fixtures exercise against the `- id:` entries parsed out of the YAML
   * itself rather than a hand-maintained list. (`semgrep --validate` and the
   * locale-codec byte check run over every pack in `semgrepPacks.test.ts`.)
   */
  it.skipIf(!AVAILABLE)('every rule the YAML declares is exercised by a hit fixture', () => {
    const { rows } = run(RULES, resolve(FIXTURES, 'hits'));
    expect(ids(rows)).toEqual(declaredRuleIds());
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

  it.skipIf(!AVAILABLE)('fires NOTHING in EACH near-miss fixture file', () => {
    const dir = resolve(FIXTURES, 'misses');
    const { rows, scanned } = run(RULES, dir);
    // This is the half of the proof most exposed to a silent zero-file
    // scan: a broken temp copy would make every near-miss fixture read as
    // "correctly silent" for the wrong reason. Ruled out directly.
    expect(scanned).toBe(fixtureFiles(dir).length);
    const grouped = rowsByFile(rows);
    for (const file of fixtureFiles(dir)) {
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
  'bugfix-py-null-safety-none-deref-match': 'null_safety',
  'bugfix-py-null-safety-none-deref-dict-get': 'null_safety',
  'bugfix-py-off-by-one-range-len-plus-one': 'off_by_one',
  'bugfix-py-memory-leak-open-without-context': 'memory_leak',
  'bugfix-py-race-condition-asyncio-not-awaited': 'race_condition',
  'bugfix-py-race-condition-toctou-exists-open': 'race_condition',
  'bugfix-py-edge-case-queryset-n-plus-one': 'edge_case',
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
function r2cRunOrNull(): SemgrepRun | null {
  if (!AVAILABLE) return null;
  try {
    return run(R2C_PACK, resolve(FIXTURES, 'hits'));
  } catch {
    return null;
  }
}
const R2C_RUN = r2cRunOrNull();

describe('no local rule duplicates p/r2c-bug-scan', () => {
  it.runIf(REQUIRE_SEMGREP)('the registry pack must be reachable when the flag is set', () => {
    expect(R2C_RUN).not.toBeNull();
  });

  it.skipIf(R2C_RUN === null)('the existing pack finds NOTHING in any hit fixture', () => {
    // Every one of our ten rules is therefore additive: it fires where the
    // pack does not. Asserted per file so a failure names the rule whose
    // fixture overlaps, not merely that the directory does. `scanned` is
    // asserted too — this test has no partner to fail loudly if the temp
    // copy silently scanned zero files, since nothing else runs this pack.
    const dir = resolve(FIXTURES, 'hits');
    expect(R2C_RUN?.scanned).toBe(fixtureFiles(dir).length);
    const grouped = rowsByFile(R2C_RUN?.rows ?? []);
    for (const file of fixtureFiles(dir)) {
      expect(grouped[file] ?? []).toEqual([]);
    }
  });
});
