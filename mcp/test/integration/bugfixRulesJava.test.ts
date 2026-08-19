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
import { execFileSync } from 'node:child_process';
import { cpSync, existsSync, readdirSync } from 'node:fs';
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

interface SemgrepResult { check_id: string; path: string }

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

interface FileExpectation {
  readonly ids: readonly string[];
  readonly count: number;
}

const EXPECTED_HITS_BY_FILE: Readonly<Record<string, FileExpectation>> = {
  'EmptyCatch.java': { ids: ['bugfix-java-error-handling-empty-catch'], count: 1 },
  'PrintStackTraceOnly.java': {
    ids: ['bugfix-java-error-handling-printstacktrace-only'],
    count: 1,
  },
  'MapGetDeref.java': { ids: ['bugfix-java-null-safety-map-get-deref'], count: 1 },
  'OptionalGet.java': {
    ids: ['bugfix-java-null-safety-optional-get-no-ispresent'],
    count: 1,
  },
  'LoopLteLength.java': { ids: ['bugfix-java-off-by-one-loop-lte-length'], count: 1 },
  'StreamNotClosed.java': { ids: ['bugfix-java-memory-leak-stream-not-closed'], count: 1 },
  'ModifyDuringIteration.java': {
    ids: ['bugfix-java-edge-case-modify-during-iteration'],
    count: 1,
  },
  'StaticDateFormat.java': {
    // Two: the rule covers `static final` and plain `static`, and this fixture
    // carries one of each so neither branch can die unnoticed.
    ids: ['bugfix-java-race-condition-static-dateformat'],
    count: 2,
  },
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
