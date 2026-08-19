/**
 * Runs `configs/semgrep/base.yml` against the fixture pairs in
 * `mcp/test/fixtures/base/{hits,misses}/` and asserts, per file, the EXACT set
 * of rule ids, the RAW non-deduplicated finding count, and the number of files
 * Semgrep actually scanned.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS FILE EXISTS
 *
 * `base.yml` is the pack `init_project` copies into a user's project as
 * `.semgrep.yml`. It is the only rule file in `configs/semgrep/` that ships to
 * somebody else's repository, and until this file was written it had **no
 * fixture coverage of any kind** — not one line of code had ever been run past
 * it in a test.
 *
 * What that cost: `wp-unescaped-output` was written as `pattern: echo $_GET[$X]`,
 * which is not parsable PHP, so the rule failed to compile and never matched
 * anything, in a plugin whose WordPress support is a headline feature. It was
 * found by `semgrepPacks.test.ts` — a cross-pack `--validate` check written for
 * an unrelated reason — and not by anything that measured what the pack finds.
 *
 * Two of the other twelve were quieter versions of the same defect, and neither
 * would have shown up in a `--validate` run because both compiled perfectly:
 *
 *  - `js-eval-of-user-input` matched `new Function($X)`, the ONE-argument form.
 *    The canonical Function constructor names its parameters first and passes
 *    the body last, so the shape the rule was written for is the shape real
 *    code least often has. Measured: 0 findings on `new Function('a','b',body)`.
 *  - `js-document-write` saw `document.write` and not `document.writeln`.
 *
 * The assertion that catches this whole family cheaply is the one below that
 * compares the ids the fixtures exercise against the `- id:` entries parsed out
 * of the YAML itself: a rule with no hit behind it is a rule nobody has
 * measured. It would have failed on day one of `wp-unescaped-output`.
 *
 * ---------------------------------------------------------------------------
 * THE NEAR-MISS STANDARD
 *
 * Every file in `misses/` must be silent for a reason that BELONGS TO THE RULE,
 * and every line in it was checked against a deliberately broken variant of the
 * rule that it is a near-miss for — a case-insensitive AWS regex, a
 * `Math.random` with no call, a `$O.write($X)` with an unconstrained receiver,
 * an `$X.eval(...)` that also matches PyTorch's `model.eval()`, a
 * `wp-unescaped-output` with the `metavariable-regex` deleted. Each broken
 * variant fires on the lines it should; the shipped rules fire on none of them.
 * A near-miss silent for an unrelated reason measures nothing, and the Java
 * round found several of those.
 *
 * ---------------------------------------------------------------------------
 * WHAT THIS PACK DELIBERATELY DOES NOT SEE — measured, not assumed, and left
 * here so nobody re-derives it from an empty result:
 *
 *  - `php-sql-injection-direct` needs a concatenation NODE. A query built into
 *    a variable first (`$sql = "..." . $id; mysql_query($sql);`), an
 *    interpolated query (`"... WHERE id=$id"`), and `$wpdb->query(...)` — the
 *    only one of the three that modern WordPress actually uses — are all
 *    invisible to it.
 *  - `py-yaml-load` matches one-argument calls only. That is right for
 *    `Loader=yaml.SafeLoader` and wrong for `Loader=yaml.UnsafeLoader` and
 *    `Loader=yaml.Loader`, which are unsafe and pass unseen.
 *  - `js-insecure-randomness` fires on EVERY `Math.random()`, including the
 *    ones used for jitter and animation. It is INFO for that reason.
 *  - `wp-unescaped-output` covers `echo`/`print`. `printf`, `_e()`,
 *    `wp_die()` and the other WordPress output helpers are not covered.
 *
 * And what it sees that it should not: ONE false-positive shape, measured and
 * pinned by line in `known-false-positives/`, with the reason it cannot be
 * removed and the trade that was refused written next to it.
 *
 * SKIPPED, not silently passed, when Semgrep is absent;
 * `GUARDIAN_REQUIRE_SEMGREP=1` turns that absence into a hard failure.
 */

import { afterAll, describe, expect, it } from 'vitest';
import { execFileSync, spawnSync } from 'node:child_process';
import { cpSync, existsSync, readdirSync, readFileSync } from 'node:fs';
import { basename, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

afterAll(cleanupTempDirs);

const REPO_ROOT = resolve(fileURLToPath(new URL('../../..', import.meta.url)));
const RULES = resolve(REPO_ROOT, 'configs', 'semgrep', 'base.yml');
const FIXTURES = resolve(REPO_ROOT, 'mcp', 'test', 'fixtures', 'base');
const REQUIRE_SEMGREP = process.env['GUARDIAN_REQUIRE_SEMGREP'] === '1';

function semgrepAvailable(): boolean {
  try { execFileSync('semgrep', ['--version'], { stdio: 'ignore' }); return true; }
  catch { return false; }
}
const AVAILABLE = semgrepAvailable();

interface SemgrepResult {
  check_id: string;
  path: string;
  /** Optional in the schema, so narrowed rather than asserted at every use. */
  start?: { line?: number };
  /** Semgrep's own tier. `extra.severity` is optional in the schema. */
  extra?: { severity?: string };
}

interface SemgrepRun {
  readonly rows: SemgrepResult[];
  /** Files Semgrep actually scanned — asserted by every caller. */
  readonly scanned: number;
}

/**
 * The in-repo fixture path contains a `test/` segment, which Semgrep's default
 * ignore list skips WHOLESALE. Scanning it in place returns zero findings and
 * zero scanned files, which is byte-identical to a clean result — so the
 * fixtures are copied out first, and the `paths.scanned` assertion in every
 * test below is what proves the copy still works.
 */
function run(config: string, dir: string): SemgrepRun {
  const work = makeTempDir('guardian-base-rules-');
  cpSync(dir, work, { recursive: true });
  const proc = spawnSync(
    'semgrep',
    ['--config', config, '--json', '--quiet', '--no-git-ignore', work],
    { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 },
  );
  const parsed: unknown = proc.stdout === '' ? {} : JSON.parse(proc.stdout);
  const results = (parsed as { results?: unknown[] }).results ?? [];
  const scanned = (parsed as { paths?: { scanned?: unknown[] } }).paths?.scanned ?? [];
  // `spawnSync` rather than `execFileSync`, and the difference is the failure
  // MESSAGE. A rule that does not compile makes semgrep exit 2, and
  // `execFileSync` reports that as a bare "Command failed: semgrep --config …"
  // — measured against the pre-fix `wp-unescaped-output`, that is exactly what
  // four of these tests printed, and not one of them named the rule.
  //
  // The reason has to be dug out of the JSON rather than off stderr: `--quiet`
  // leaves stderr EMPTY even for a rule that failed to compile, and puts the id
  // and the offending pattern in the `errors` array of the report instead. A
  // reader who trusts an empty stderr sees a silent failure.
  if (proc.status !== 0) {
    const errors = (parsed as { errors?: { message?: string }[] }).errors ?? [];
    throw new Error(
      `semgrep exited ${String(proc.status)} for ${basename(dir)}/.\n` +
      'A rule that fails to compile finds NOTHING, which is indistinguishable\n' +
      'from a clean scan if only the findings are read.\n' +
      errors.map((e) => e.message ?? '(no message)').join('\n'),
    );
  }
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

/**
 * Every FILE in the fixture directory, whatever its extension. Unlike the
 * per-language packs, `base.yml` covers four languages plus two `generic`
 * rules that apply to every file Semgrep walks — including the plain `.txt`
 * that carries the secrets fixtures. Filtering by extension here would quietly
 * drop a fixture from the `paths.scanned` comparison, which is the one
 * assertion that distinguishes "found nothing" from "looked at nothing".
 */
function fixtureFiles(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true })
    .filter((entry) => entry.isFile())
    .map((entry) => entry.name)
    .sort();
}

/**
 * Every `- id:` the rule file DECLARES, read out of the YAML text rather than
 * out of a list maintained here. It is the left-hand side of the invariant that
 * catches a rule which compiles and matches nothing.
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

const EXPECTED_HITS_BY_FILE: Readonly<Record<string, FileExpectation>> = {
  'View.jsx': {
    // Three, and the count is the point: the rule is written as a self-closing
    // element carrying exactly one attribute, and it was not readable from the
    // pattern whether the other two forms match. Measured, they do — Semgrep
    // treats JSX attributes as a set the pattern must be a subset of, and
    // closes an `<el></el>` pair into the same node. Pinned so a rewrite of the
    // pattern cannot silently drop one.
    ids: ['js-dangerouslySetInnerHTML'],
    count: 3,
  },
  'app.js': {
    // Five: `eval`, the THREE-argument `new Function`, one `Math.random()`,
    // `document.write` and `document.writeln`. Two of those five did not fire
    // before this branch; see the header.
    ids: ['js-document-write', 'js-eval-of-user-input', 'js-insecure-randomness'],
    count: 5,
  },
  'database.php': {
    // Four: one `eval`, and three concatenation shapes — two-term, left-nested
    // three-term, and the `mysqli_query($CONN, ...)` arity.
    ids: ['php-eval', 'php-sql-injection-direct'],
    count: 4,
  },
  'output.php': {
    // Twelve, one per branch of the rewritten `wp-unescaped-output`, and this
    // number is the whole reason the fixture directory exists. Measured against
    // the shipped rule at be01f78: 0 of 12, with `errors: 1` and exit 2.
    ids: ['wp-unescaped-output'],
    count: 12,
  },
  'secrets.txt': {
    // The two `generic` regex rules. A `.txt` file gives them a home no
    // language parser also claims — though measured, they fire in `.js`,
    // `.py`, `.php` and `.env` just the same.
    ids: ['hardcoded-aws-key', 'hardcoded-private-key'],
    count: 2,
  },
  'service.py': {
    // Eight: eval, exec, three `subprocess` shapes, `yaml.load`, and both
    // `pickle` entry points. The three subprocess calls exercise the leading
    // and trailing `...` of `subprocess.$F(..., shell=True, ...)` separately —
    // a `...` that never had to match anything is a clause that could be
    // deleted without a test moving.
    ids: ['py-eval-exec', 'py-pickle-load', 'py-shell-true', 'py-yaml-load'],
    count: 8,
  },
};

/**
 * The tier each rule reports at. Pinned because the tier is not cosmetic: the
 * Semgrep parser maps ERROR → `high`, WARNING → `medium` and INFO → `low`
 * (`src/runners/scannerParsers/semgrep.ts`), and `create_fix_pr` defaults
 * `severity_min` to `high` — so moving a rule from ERROR to WARNING silently
 * removes it from the default fix-PR set without removing it from any scan.
 */
const EXPECTED_SEVERITY: Readonly<Record<string, string>> = {
  'hardcoded-aws-key': 'ERROR',
  'hardcoded-private-key': 'ERROR',
  'js-eval-of-user-input': 'WARNING',
  'js-insecure-randomness': 'INFO',
  'js-document-write': 'WARNING',
  'js-dangerouslySetInnerHTML': 'WARNING',
  'py-eval-exec': 'ERROR',
  'py-shell-true': 'WARNING',
  'py-yaml-load': 'ERROR',
  'py-pickle-load': 'WARNING',
  'php-eval': 'ERROR',
  'php-sql-injection-direct': 'ERROR',
  'wp-unescaped-output': 'ERROR',
};

describe('base.yml rules', () => {
  it.runIf(REQUIRE_SEMGREP)('the toolchain must be usable when the flag is set', () => {
    expect(AVAILABLE).toBe(true);
  });

  it('the rule file exists where init_project will look for it', () => {
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
      // The TOTAL, on top of the per-file counts, and not redundant: the loop
      // above only visits files that have an expectation, so a finding landing
      // in a file nobody registered would not move any per-file number.
      expect(rows.length).toBe(
        Object.values(EXPECTED_HITS_BY_FILE).reduce((n, e) => n + e.count, 0),
      );
    },
  );

  /**
   * The assertion that would have caught `wp-unescaped-output` on the day it
   * was written, and the two silent recall gaps beside it on the day after.
   * A rule the YAML declares but no fixture fires is a rule nobody has
   * measured — whether it fails to compile, or compiles and matches a shape
   * real code never has.
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
   * The one shape `wp-unescaped-output` flags that is not a bug, pinned by LINE
   * so the boundary of the defect is a measurement and not a description.
   *
   * Recording a known false positive in a test rather than in a comment is the
   * difference between a limitation and a rumour: a comment saying "this fires
   * on X" is unfalsifiable once X changes, whereas this goes red both if the
   * defect spreads and if a rewrite fixes it. Fixing it is the good outcome —
   * delete the fixture and this block when it happens.
   *
   * The two lines are the body of `known_false_positives()`. Editing the
   * comment block above it moves them, and the numbers here have to move with
   * it; `extra.lines` cannot be asserted instead, because current Semgrep
   * redacts the matched text to "requires login" for a logged-out run.
   */
  it.skipIf(!AVAILABLE)('flags exactly the two KNOWN false positives, and nothing else', () => {
    const dir = resolve(FIXTURES, 'known-false-positives');
    const { rows, scanned } = run(RULES, dir);
    expect(scanned).toBe(fixtureFiles(dir).length);
    expect(ids(rows)).toEqual(['wp-unescaped-output']);
    expect(rows.map((row) => row.start?.line ?? 0).sort((a, b) => a - b)).toEqual([30, 31]);
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
