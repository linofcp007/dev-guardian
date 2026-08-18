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
import { cpSync, existsSync, readdirSync } from 'node:fs';
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

interface SemgrepResult { check_id: string; path: string }

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

interface FileExpectation {
  readonly ids: readonly string[];
  readonly count: number;
}

const EXPECTED_HITS_BY_FILE: Readonly<Record<string, FileExpectation>> = {
  'empty_err_block.go': { ids: ['bugfix-go-error-handling-empty-err-block'], count: 1 },
  'err_blank_assign.go': { ids: ['bugfix-go-error-handling-err-blank-assign'], count: 1 },
  'err_discarded.go': { ids: ['bugfix-go-error-handling-err-discarded'], count: 1 },
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
        expect(ids(fileRows)).toEqual(expected.ids);
        expect(fileRows.length).toBe(expected.count);
      }
    },
  );

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
