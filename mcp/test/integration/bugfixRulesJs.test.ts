/**
 * Runs the local `bugfix-js.yml` Semgrep rules against the hand-built
 * fixture pairs in `mcp/test/fixtures/bugfix-js/{hits,misses}/` and asserts
 * the EXACT set of rule ids that fired — never "at least one". A rule that
 * starts matching its own near-miss must fail the suite rather than quietly
 * widening (design of record, §2 and §6:
 * docs/superpowers/specs/2026-08-17-bugfix-rules-jsts-design.md).
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
import { cpSync, existsSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
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

describe('bugfix-js rules', () => {
  it.runIf(REQUIRE_SEMGREP)('the toolchain must be usable when the flag is set', () => {
    expect(AVAILABLE).toBe(true);
  });

  it('the rule file exists where bug_hunt will look for it', () => {
    expect(existsSync(RULES)).toBe(true);
  });

  it.skipIf(!AVAILABLE)('fires exactly the expected rules on the hit fixtures', () => {
    // EXACT set, not "at least". A rule that widens to catch something it was
    // not written for fails here rather than reaching a user as noise.
    expect(ids(run(resolve(FIXTURES, 'hits')))).toEqual([
      'bugfix-js-edge-case-parseint-without-radix',
      'bugfix-js-edge-case-reduce-without-initial',
      'bugfix-js-error-handling-catch-returns-null',
      'bugfix-js-error-handling-empty-catch',
      'bugfix-js-error-handling-empty-promise-catch',
      'bugfix-js-memory-leak-interval-without-clear',
      'bugfix-js-memory-leak-listener-without-cleanup',
      'bugfix-js-memory-leak-subscribe-without-unsubscribe',
      'bugfix-js-null-safety-unchecked-env',
      'bugfix-js-null-safety-unchecked-find',
      'bugfix-js-null-safety-unchecked-match',
      'bugfix-js-off-by-one-index-at-length',
      'bugfix-js-off-by-one-loop-lte-length',
      'bugfix-js-race-condition-floating-mutation',
    ]);
  });

  it.skipIf(!AVAILABLE)('fires NOTHING on the near-miss fixtures', () => {
    // The half of the proof that decides whether this feature helps or hurts.
    // A rethrowing catch, an append at index length, an awaited save and a
    // deliberate fire-and-forget log are all correct code that looks like a bug.
    expect(ids(run(resolve(FIXTURES, 'misses')))).toEqual([]);
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
