/**
 * Runs the local `bugfix-js.yml` Semgrep rules against the hand-built
 * fixture pairs in `mcp/test/fixtures/bugfix-js/{hits,misses}/` and asserts
 * the EXACT set of rule ids that fired — never "at least one". A rule that
 * starts matching its own near-miss must fail the suite rather than quietly
 * widening (design of record, §2 and §6:
 * docs/superpowers/specs/2026-08-17-bugfix-rules-jsts-design.md).
 *
 * ---- Why the assertion is PER FILE, not one set over the whole directory -
 *
 * The original version of this test asserted one flat, deduplicated id set
 * over the entire `hits/` directory. That proves a rule fires *somewhere*
 * and that nothing fires on the misses — it does NOT prove any particular
 * fixture *instance* still matches, as long as another instance of the same
 * rule id survives elsewhere in the directory. Concretely:
 * `hits/unchecked-match.ts` has two functions producing the same id
 * (`firstGroup`, the original hit, and `firstGroupFromConfig`, a
 * regression fixture added later); with the regex-based exclusion this
 * rule shipped with in an earlier round, `firstGroupFromConfig` silently
 * stopped matching and the directory-wide set was UNCHANGED — `firstGroup`
 * alone kept the id in the set, so the suite stayed green. Proven directly:
 * deleting the fix's `metavariable-comparison` clause left the whole file
 * fully green.
 *
 * Grouping results by file closes the CROSS-FILE half of this — a fixture
 * cannot be diluted by a *different* file's instance of the same rule, and
 * it also catches a rule firing on a DIFFERENT rule's dedicated fixture
 * file, which the old directory-wide set silently permitted (a cross-fire
 * onto an id that's already expected elsewhere in the set is invisible to
 * a flat set comparison).
 *
 * It does NOT, on its own, close the WITHIN-FILE half — proven, not
 * assumed: grouping by file and asserting only the deduplicated id set per
 * file, then re-deleting the fix's `metavariable-comparison` clause,
 * stayed fully green, because `hits/unchecked-match.ts` has two functions
 * (`firstGroup`, `firstGroupFromConfig`) producing the SAME id, and the
 * file's own id set is unchanged whether one or both still fire. Four of
 * these fourteen fixture files have more than one function sharing an
 * expected id (`catch-returns-null.ts`, `empty-promise-catch.ts`,
 * `interval-without-clear.ts`, `unchecked-match.ts`), so this is not a
 * one-off. The id set alone was re-diluted one level down.
 * Closed by asserting a raw (non-deduplicated) finding COUNT per file
 * alongside its id set (`EXPECTED_HITS_BY_FILE`'s `count`) — a fixture
 * whose own instance silently stops firing now changes that file's count
 * even when a sibling instance in the SAME file keeps the id set intact.
 * Confirmed by re-deleting `metavariable-comparison` a second time after
 * adding the count check: RED (see task-2-report.md's fix-round-2 section
 * for the transcript).
 *
 * Every fixture filename on disk must appear in `EXPECTED_HITS_BY_FILE`
 * and vice versa (`Step 0` below), so a new file added without registering
 * its expected id fails loudly instead of being silently skipped.
 *
 * The `misses/` side stays a single directory-wide concept in spirit — "no
 * fixture anywhere produces a finding" — but is now also asserted per file.
 * This is a strictly EQUIVALENT reformulation, not a strengthening: the
 * union of per-file result sets over the whole directory is empty if and
 * only if every individual file's own result set is empty (a union of sets
 * is empty exactly when every constituent set is), so nothing about what
 * this half of the proof catches has changed — only *where* a failure
 * points, which now names the specific near-miss file that regressed.
 *
 * ---- Why the fixtures are copied to a temp dir before scanning -----------
 *
 * Semgrep's built-in default ignore list skips any path containing a `test/`
 * directory — confirmed here the same way `rulePackFixture.test.ts` /
 * `evalVulnFixture.test.ts` / `validateFindingFixture.test.ts` already
 * documented it: pointed straight at the in-repo fixture
 * (`mcp/test/fixtures/bugfix-js/...`), Semgrep reports `paths.scanned: []`
 * and zero results, REGARDLESS of the rules. That would not just fail the
 * "hits" assertion, it would make the "misses" assertion — the half of this
 * feature that decides whether it helps or hurts — pass for the wrong
 * reason: zero results because nothing was scanned, not because the rules
 * are precise. So each fixture directory is copied to a fresh temp dir
 * outside any `test/`-named path first, mirroring the same workaround this
 * repo already uses in three other places.
 *
 * ---- Skip discipline -------------------------------------------------
 *
 * Same shape as every other Semgrep-dependent test here
 * (`mcp/test/e2e/ciCliFixture.test.ts`, `rulePackFixture.test.ts`): SKIPPED,
 * not silently passed, when Semgrep is not on PATH; `GUARDIAN_REQUIRE_
 * SEMGREP=1` turns that absence into a hard failure instead of a quiet skip.
 */

import { describe, expect, it } from 'vitest';
import { execFileSync } from 'node:child_process';
import { cpSync, existsSync, mkdtempSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { mapSubcategory } from '../../src/tools/bugHunt.js';

const REPO_ROOT = resolve(fileURLToPath(new URL('../../..', import.meta.url)));
const RULES = resolve(REPO_ROOT, 'configs', 'semgrep', 'bugfix-js.yml');
const FIXTURES = resolve(REPO_ROOT, 'mcp', 'test', 'fixtures', 'bugfix-js');
const REQUIRE_SEMGREP = process.env['GUARDIAN_REQUIRE_SEMGREP'] === '1';

function semgrepAvailable(): boolean {
  try { execFileSync('semgrep', ['--version'], { stdio: 'ignore' }); return true; }
  catch { return false; }
}
const AVAILABLE = semgrepAvailable();

interface SemgrepResult { check_id: string; path: string }

function run(dir: string): SemgrepResult[] {
  // Outside any `test/`-named path — see the module comment. `dir` itself
  // (e.g. `.../mcp/test/fixtures/bugfix-js/hits`) is never passed to
  // Semgrep directly.
  const work = mkdtempSync(join(tmpdir(), 'guardian-bugfix-js-'));
  cpSync(dir, work, { recursive: true });
  const out = execFileSync(
    'semgrep',
    ['--config', RULES, '--json', '--quiet', '--no-git-ignore', work],
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

/**
 * Groups RAW rows (no dedup) by the BASENAME of their `path` — never the
 * full temp-dir path, which is a fresh `mkdtempSync` directory on every run
 * and would never match a literal expectation. Kept raw, not reduced
 * through `ids`, because the raw count per file is itself load-bearing —
 * see `EXPECTED_HITS_BY_FILE`'s `count` field and the module comment.
 */
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

/** `.ts` fixture filenames actually on disk in `hits/` or `misses/`. */
function fixtureFiles(dir: string): string[] {
  return readdirSync(dir)
    .filter((name) => name.endsWith('.ts'))
    .sort();
}

interface FileExpectation {
  /** The distinct rule id(s) this file must produce, deduplicated. */
  readonly ids: readonly string[];
  /**
   * The RAW, non-deduplicated finding count — required in addition to
   * `ids` because four of these fourteen files have more than one function
   * expected to fire the SAME rule (see the module comment): the
   * deduplicated id set is unchanged whether one or all of those functions
   * still match, so it alone cannot prove a specific instance is still
   * being caught. Count can.
   */
  readonly count: number;
}

/**
 * Every `hits/` fixture filename, mapped to what it must produce. `Step 0`
 * of the hits test asserts this map's keys are EXACTLY the filenames on
 * disk, in both directions: a new fixture file added without an entry here
 * fails loudly, and a stale entry for a deleted file does too.
 */
const EXPECTED_HITS_BY_FILE: Readonly<Record<string, FileExpectation>> = {
  'catch-returns-null.ts': {
    ids: ['bugfix-js-error-handling-catch-returns-null'],
    count: 3, // findUser, findUserOrUndefined, findAllUsers
  },
  'empty-promise-catch.ts': {
    ids: ['bugfix-js-error-handling-empty-promise-catch'],
    count: 3, // fireAndIgnore, fireAndIgnoreNamed, fireAndIgnoreArrowWithParam
  },
  'error-handling.ts': { ids: ['bugfix-js-error-handling-empty-catch'], count: 1 },
  'index-at-length.ts': { ids: ['bugfix-js-off-by-one-index-at-length'], count: 1 },
  'interval-without-clear.ts': {
    ids: ['bugfix-js-memory-leak-interval-without-clear'],
    count: 2, // startPolling, startsPollingWithoutClearing (unrelatedCleanup does not fire)
  },
  'listener-without-cleanup.ts': {
    ids: ['bugfix-js-memory-leak-listener-without-cleanup'],
    count: 1,
  },
  'off-by-one.ts': { ids: ['bugfix-js-off-by-one-loop-lte-length'], count: 1 },
  'parseint-without-radix.ts': { ids: ['bugfix-js-edge-case-parseint-without-radix'], count: 1 },
  'race-condition.ts': {
    ids: ['bugfix-js-race-condition-floating-mutation'],
    count: 3, // handler (decl), arrowHandler (assignment-form arrow), app.post(...) callback (call-arg-form arrow)
  },
  'reduce-without-initial.ts': { ids: ['bugfix-js-edge-case-reduce-without-initial'], count: 1 },
  'subscribe-without-unsubscribe.ts': {
    ids: ['bugfix-js-memory-leak-subscribe-without-unsubscribe'],
    count: 1,
  },
  'unchecked-env.ts': { ids: ['bugfix-js-null-safety-unchecked-env'], count: 1 },
  'unchecked-find.ts': { ids: ['bugfix-js-null-safety-unchecked-find'], count: 1 },
  'unchecked-match.ts': {
    ids: ['bugfix-js-null-safety-unchecked-match'],
    count: 2, // firstGroup, firstGroupFromConfig — see the module comment
  },
};

describe('bugfix-js rules', () => {
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
      // Both halves matter, per the module comment: the id set alone is
      // blind to a specific instance silently dropping out as long as a
      // sibling instance of the SAME rule — in the same file or a
      // different one — keeps the id present. Count closes the same-file
      // case; grouping by file (rather than the old directory-wide pool)
      // closes the different-file case.
      const grouped = rowsByFile(run(resolve(FIXTURES, 'hits')));
      for (const [file, expected] of Object.entries(EXPECTED_HITS_BY_FILE)) {
        const rows = grouped[file] ?? [];
        expect(ids(rows)).toEqual(expected.ids);
        expect(rows.length).toBe(expected.count);
      }
    },
  );

  it.skipIf(!AVAILABLE)('fires NOTHING in EACH near-miss fixture file', () => {
    // Equivalent to the old directory-wide "toEqual([])" — a union of sets
    // is empty iff every constituent set is — but pinpoints which near-miss
    // file regressed instead of only that the directory did. No count
    // check needed here: zero raw rows and zero deduplicated ids are the
    // same fact for an empty set. A rethrowing catch, an append at index
    // length, an awaited save and a deliberate fire-and-forget log are all
    // correct code that looks like a bug.
    const grouped = rowsByFile(run(resolve(FIXTURES, 'misses')));
    for (const file of fixtureFiles(resolve(FIXTURES, 'misses'))) {
      expect(grouped[file] ?? []).toEqual([]);
    }
  });
});

/**
 * Rule ids carry the class token because `mapSubcategory` classifies by
 * running regexes over the lowercased id, not by lookup table (design of
 * record §4). This runs unconditionally — it calls the pure classifier
 * directly, no Semgrep involved — so it is never skipped for lack of the
 * toolchain.
 */
const EXPECTED_CLASS: Readonly<Record<string, string>> = {
  'bugfix-js-error-handling-empty-catch': 'error_handling',
  'bugfix-js-error-handling-empty-promise-catch': 'error_handling',
  'bugfix-js-error-handling-catch-returns-null': 'error_handling',
  'bugfix-js-off-by-one-loop-lte-length': 'off_by_one',
  'bugfix-js-off-by-one-index-at-length': 'off_by_one',
  'bugfix-js-null-safety-unchecked-find': 'null_safety',
  'bugfix-js-null-safety-unchecked-match': 'null_safety',
  'bugfix-js-null-safety-unchecked-env': 'null_safety',
  'bugfix-js-memory-leak-listener-without-cleanup': 'memory_leak',
  'bugfix-js-memory-leak-interval-without-clear': 'memory_leak',
  'bugfix-js-memory-leak-subscribe-without-unsubscribe': 'memory_leak',
  'bugfix-js-race-condition-floating-mutation': 'race_condition',
  'bugfix-js-edge-case-reduce-without-initial': 'edge_case',
  'bugfix-js-edge-case-parseint-without-radix': 'edge_case',
};

describe('every rule id classifies as its own class', () => {
  it('maps all fourteen', () => {
    for (const [id, cls] of Object.entries(EXPECTED_CLASS)) {
      expect(mapSubcategory(id, undefined)).toBe(cls);
    }
  });

  it('the three "unchecked" ids classify as null_safety, not error_handling', () => {
    // mapSubcategory's error_handling regex matches the bare word `unchecked`.
    // These three win only because null_safety is tested earlier in the chain.
    // If that order ever changes, this fails instead of silently reclassifying.
    for (const id of [
      'bugfix-js-null-safety-unchecked-find',
      'bugfix-js-null-safety-unchecked-match',
      'bugfix-js-null-safety-unchecked-env',
    ]) {
      expect(mapSubcategory(id, undefined)).toBe('null_safety');
    }
  });
});
