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
import { cpSync, existsSync, readdirSync, readFileSync } from 'node:fs';
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

/** Every rule the pack declares. Spelled once, used by `real_bugs.go`. */
const ALL_RULES = [
  'bugfix-go-edge-case-nil-map-write',
  'bugfix-go-error-handling-empty-err-block',
  'bugfix-go-error-handling-err-blank-assign',
  'bugfix-go-error-handling-err-discarded',
  'bugfix-go-memory-leak-body-not-closed',
  'bugfix-go-memory-leak-ticker-not-stopped',
  'bugfix-go-null-safety-type-assert-no-ok',
  'bugfix-go-off-by-one-loop-lte-len',
  'bugfix-go-race-condition-lock-without-defer',
] as const;

const EXPECTED_HITS_BY_FILE: Readonly<Record<string, FileExpectation>> = {
  /**
   * THE REAL-BUGS CORPUS, written by the AUDITOR rather than by the rules'
   * author. Fourteen defects, at least one per rule, each placed NEXT TO the
   * guard shape its rule's exclusions match — a leak beside a correct close, a
   * discarded error beside a `sync.Map.Load`, an assertion on a different
   * variable inside a type switch, a leaked ticker beside a stopped one, a
   * discarded error beside the Close idiom, an off-by-one beside a correct n+1
   * DP seed.
   *
   * It exists because a minimal per-rule hit fixture carries no guard shapes
   * for an exclusion to catch on, so a wave of false-positive work can delete
   * recall and still go green. The Java pack learned that the hard way (wave 4
   * took one of its fixtures from 6 findings to 1 with a green suite).
   *
   * Six of the fourteen belong to `body-not-closed`, and that is the shape of
   * the fix: the shipped rule was anchored to `http.Get` alone, so
   * `client.Do(req)`, `http.Post`, `http.PostForm`, `http.Head` and
   * `http.DefaultClient.Get` — everything a real client uses — leaked silently.
   */
  'real_bugs.go': { ids: [...ALL_RULES], count: 14 },
  'body_not_closed.go': { ids: ['bugfix-go-memory-leak-body-not-closed'], count: 1 },
  'empty_err_block.go': { ids: ['bugfix-go-error-handling-empty-err-block'], count: 1 },
  'err_blank_assign.go': { ids: ['bugfix-go-error-handling-err-blank-assign'], count: 1 },
  'err_discarded.go': { ids: ['bugfix-go-error-handling-err-discarded'], count: 1 },
  'lock_without_defer.go': { ids: ['bugfix-go-race-condition-lock-without-defer'], count: 1 },
  'loop_lte_len.go': { ids: ['bugfix-go-off-by-one-loop-lte-len'], count: 1 },
  'nil_map_write.go': { ids: ['bugfix-go-edge-case-nil-map-write'], count: 1 },
  'ticker_not_stopped.go': { ids: ['bugfix-go-memory-leak-ticker-not-stopped'], count: 1 },
  'type_assert_no_ok.go': { ids: ['bugfix-go-null-safety-type-assert-no-ok'], count: 1 },
};

/**
 * The severity tier each rule is DESIGNED to carry, and the criterion applied
 * to the OUTPUT rather than to the bug class: **is what the rule EMITS always
 * a bug?** Not "is the shape it looks for usually wrong" — a rule whose
 * correctness depends on having recognised a guard emits a false positive
 * every time it meets a guard shape nobody enumerated, and no exclusion list
 * closes that, because the guard can always be one line away.
 *
 * Eight of the nine are `WARNING` on that test, and only `empty-err-block`
 * survives at `ERROR`: its output is an error branch with a literally empty
 * body, where there is no guard to recognise and no legitimate intent to
 * distinguish. The pack's header used to define this criterion correctly and
 * then assign the tier by bug CLASS, which is how seven rules ended up at
 * ERROR; the 2026-08 audit applied it cold.
 *
 * Pinned here because nothing pinned it before — no test read
 * `extra.severity`, so any tier could be changed with a green suite. The tier
 * is not cosmetic: the Semgrep parser maps ERROR -> `high` and WARNING ->
 * `medium` (`src/runners/scannerParsers/semgrep.ts`), and `create_fix_pr`
 * defaults `severity_min` to `high`. With eight of nine at WARNING the Go pack
 * contributes almost nothing to the DEFAULT fix-PR set, and a caller who wants
 * Go bugs fixed has to ask: `severity_min: "medium"`. `bug_hunt` itself
 * defaults to no filter, so nothing disappears from a scan.
 */
const EXPECTED_SEVERITY: Readonly<Record<string, string>> = {
  'bugfix-go-error-handling-empty-err-block': 'ERROR',
  'bugfix-go-error-handling-err-discarded': 'WARNING',
  'bugfix-go-error-handling-err-blank-assign': 'WARNING',
  'bugfix-go-null-safety-type-assert-no-ok': 'WARNING',
  'bugfix-go-off-by-one-loop-lte-len': 'WARNING',
  'bugfix-go-memory-leak-body-not-closed': 'WARNING',
  'bugfix-go-memory-leak-ticker-not-stopped': 'WARNING',
  'bugfix-go-race-condition-lock-without-defer': 'WARNING',
  'bugfix-go-edge-case-nil-map-write': 'WARNING',
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
   * findings says so. The third bit this very round: Semgrep's config loader
   * decodes the rule file with the LOCALE codec, so on a Windows cp1252 locale
   * the second byte of `Á` (U+00C1 -> 0xC3 0x81) is undefined and one letter
   * takes the whole file down, reporting `results: 0`, `paths.scanned: 0` and
   * `errors: 0`.
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
  'bugfix-go-memory-leak-body-not-closed': 'memory_leak',
  'bugfix-go-memory-leak-ticker-not-stopped': 'memory_leak',
  'bugfix-go-null-safety-type-assert-no-ok': 'null_safety',
  'bugfix-go-off-by-one-loop-lte-len': 'off_by_one',
  'bugfix-go-race-condition-lock-without-defer': 'race_condition',
  'bugfix-go-edge-case-nil-map-write': 'edge_case',
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
    expect(R2C_ON_CONTROL).not.toBeNull();
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
