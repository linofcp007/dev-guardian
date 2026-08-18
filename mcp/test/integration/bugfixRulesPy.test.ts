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
