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
import { cpSync, existsSync, mkdtempSync, readdirSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { mapSubcategory } from '../../src/tools/bugHunt.js';
import { rmDir } from '../helpers/tempDir.js';

const REPO_ROOT = resolve(fileURLToPath(new URL('../../..', import.meta.url)));
const RULES = resolve(REPO_ROOT, 'configs', 'semgrep', 'bugfix-js.yml');
const FIXTURES = resolve(REPO_ROOT, 'mcp', 'test', 'fixtures', 'bugfix-js');
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

function run(dir: string): SemgrepRun {
  // Outside any `test/`-named path — see the module comment. `dir` itself
  // (e.g. `.../mcp/test/fixtures/bugfix-js/hits`) is never passed to
  // Semgrep directly.
  const work = mkdtempSync(join(tmpdir(), 'guardian-bugfix-js-'));
  try {
    return scan(RULES, dir, work);
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

/**
 * Every `- id:` the rule file DECLARES, read out of the YAML text rather than
 * out of a list maintained here. Left-hand side of the "what the file
 * declares must equal what the fixtures exercise" invariant below — the
 * family-wide catch for a rule that silently fails to LOAD (a `RuleParseError`
 * branch, an unquoted `?`/`:` producing `Invalid YAML`, an uppercase accented
 * letter tripping Semgrep's locale codec). All of those look identical to
 * "this rule found nothing" in the JSON output; none of them says so.
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
  'empty-promise-catch.ts': {
    ids: ['bugfix-js-error-handling-empty-promise-catch'],
    count: 3, // fireAndIgnore, fireAndIgnoreNamed, fireAndIgnoreArrowWithParam
  },
  'error-handling.ts': {
    ids: ['bugfix-js-error-handling-empty-catch'],
    count: 4, // bound, optional-binding, +finally, optional-binding +finally
  },
  'index-at-length.ts': { ids: ['bugfix-js-off-by-one-index-at-length'], count: 1 },
  'interval-without-clear.ts': {
    ids: ['bugfix-js-memory-leak-interval-without-clear'],
    // startPolling, startsPollingWithoutClearing, startsUnclearablePolling
    // (no handle), startsPollingLet, RefPoller, Leaky.start.
    // unrelatedCleanup does not fire.
    count: 6,
  },
  'listener-without-cleanup.ts': {
    ids: ['bugfix-js-memory-leak-listener-without-cleanup'],
    count: 4, // two-arg, options object, boolean capture, early-return branch
  },
  'off-by-one.ts': {
    ids: ['bugfix-js-off-by-one-loop-lte-length'],
    count: 2, // block body and braceless body
  },
  'parseint-without-radix.ts': { ids: ['bugfix-js-edge-case-parseint-without-radix'], count: 1 },
  'race-condition.ts': {
    ids: ['bugfix-js-race-condition-floating-mutation'],
    count: 3, // handler (decl), arrowHandler (assignment-form arrow), app.post(...) callback (call-arg-form arrow)
  },
  'reduce-without-initial.ts': { ids: ['bugfix-js-edge-case-reduce-without-initial'], count: 1 },
  'subscribe-without-unsubscribe.ts': {
    ids: ['bugfix-js-memory-leak-subscribe-without-unsubscribe'],
    // Watcher, BranchWatcher (cleanup returned from the other branch), and
    // MappedWatcher — a `.pipe(map(...)).subscribe()` that the pipe-operator
    // exclusion must NOT swallow. Added because ablation measured the
    // operator-name regex DEAD: the near-miss it was written for stays
    // silent whether or not the regex is there.
    count: 3,
  },
  'unchecked-env.ts': {
    ids: ['bugfix-js-null-safety-unchecked-env'],
    count: 3, // dot + method, bracket + method, dot + property
  },
  'unchecked-find.ts': {
    ids: ['bugfix-js-null-safety-unchecked-find'],
    count: 4, // expression body, block body, three-parameter predicate, findLast
  },
  'unchecked-match.ts': {
    ids: ['bugfix-js-null-safety-unchecked-match'],
    // firstGroup, firstGroupFromConfig (see the module comment), exec, and
    // firstGroupViaExecOfConfigValue — the `exec` twin of
    // firstGroupFromConfig, added because ablation measured the `$S2`
    // metavariable-comparison DEAD while its `$ARG` twin was live: nothing
    // exercised the exec branch's argument half.
    count: 4,
  },
};

/**
 * The severity tier each rule is DESIGNED to carry. Nothing pinned this
 * before: `extra.severity` was not read anywhere in the suite, so changing
 * ANY rule's tier — including promoting one to ERROR — was a mutation the
 * whole pack passed green.
 *
 * The criterion is a question about the OUTPUT, not the pattern: **is what
 * the rule EMITS always a bug?** Not "is the shape it looks for usually
 * wrong". A rule whose correctness depends on having recognised a guard —
 * or a DECLARATION OF INTENT — emits a false positive every time it meets
 * one it cannot read, and no exclusion list closes that.
 *
 * Applied cold, and then re-applied against 183 files of this repo's own
 * `mcp/src` (real TypeScript nobody wrote as a fixture), exactly ONE of
 * thirteen clears the bar:
 *
 *  - `index-at-length`, at ERROR: a READ at `a[a.length]` is
 *    unconditionally `undefined`. That is a fact about the AST, and the one
 *    shape that isn't (the append `a[a.length] = x`) is excluded
 *    structurally. It produces ZERO findings on `mcp/src`, which is the
 *    right number for a rule this narrow.
 *
 * `empty-catch` and `empty-promise-catch` were at ERROR on the reasoning
 * that an unmarked silent swallow is a bug whatever the author meant. The
 * self-scan refuted the premise rather than the conclusion: they produce
 * **45 findings on `mcp/src` and all 45 are deliberate, comment-documented
 * fail-open** — an empty `catch` holding only the words "ESRCH: already
 * dead", or "already closed, or never fully opened". They ARE marked, with
 * a comment, which Semgrep cannot read. That is a declaration of intent the rule
 * cannot recognise, which is the criterion, so both are WARNING. This is
 * the same reasoning that keeps the JAVA empty-catch at ERROR, not a
 * contradiction of it: that rule can read its ecosystem's intent marker
 * (the Checkstyle `ignore`/`ignored`/`expected` binding name) and this one
 * cannot, because ES2019 optional catch binding removed the identifier a
 * naming convention would attach to — 41 of those 42 are written `catch {`.
 *
 * `parseint-without-radix` sits at INFO; everything else at WARNING.
 *
 * Note what moved and why it matters downstream: the Semgrep parser maps
 * ERROR → `high`, WARNING → `medium`, INFO → `info`
 * (`src/runners/scannerParsers/semgrep.ts`), and `create_fix_pr` defaults
 * `severity_min` to `high`. With one rule at ERROR the pack contributes
 * almost nothing to the DEFAULT fix-PR set — which is the point: a default
 * run must not open a PR rewriting 45 deliberate fail-open handlers.
 * `bug_hunt` itself defaults to no filter, so nothing disappears from a
 * scan.
 *
 * Asserted exhaustively in BOTH directions: every id here must be seen at
 * exactly this tier, and every id seen must appear here.
 */
const EXPECTED_SEVERITY: Readonly<Record<string, string>> = {
  'bugfix-js-off-by-one-index-at-length': 'ERROR',
  'bugfix-js-edge-case-parseint-without-radix': 'INFO',
  'bugfix-js-error-handling-empty-catch': 'WARNING',
  'bugfix-js-error-handling-empty-promise-catch': 'WARNING',
  'bugfix-js-off-by-one-loop-lte-length': 'WARNING',
  'bugfix-js-race-condition-floating-mutation': 'WARNING',
  'bugfix-js-edge-case-reduce-without-initial': 'WARNING',
  'bugfix-js-null-safety-unchecked-find': 'WARNING',
  'bugfix-js-null-safety-unchecked-match': 'WARNING',
  'bugfix-js-null-safety-unchecked-env': 'WARNING',
  'bugfix-js-memory-leak-listener-without-cleanup': 'WARNING',
  'bugfix-js-memory-leak-interval-without-clear': 'WARNING',
  'bugfix-js-memory-leak-subscribe-without-unsubscribe': 'WARNING',
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
      const dir = resolve(FIXTURES, 'hits');
      const { rows, scanned } = run(dir);
      // Guards against the temp-copy step silently scanning zero files —
      // see SemgrepRun.scanned. Without this, an empty scan and a genuine
      // clean-of-findings scan are indistinguishable.
      expect(scanned).toBe(fixtureFiles(dir).length);
      const grouped = rowsByFile(rows);
      for (const [file, expected] of Object.entries(EXPECTED_HITS_BY_FILE)) {
        const fileRows = grouped[file] ?? [];
        expect(ids(fileRows)).toEqual(expected.ids);
        expect(fileRows.length).toBe(expected.count);
      }
      // The TOTAL, on top of the per-file counts, and not redundant: the
      // loop above only visits files that HAVE an expectation, so a finding
      // landing in a file nobody registered — or attributed to no file at
      // all — moves no per-file number.
      expect(rows.length).toBe(
        Object.values(EXPECTED_HITS_BY_FILE).reduce((n, e) => n + e.count, 0),
      );
    },
  );

  /**
   * The family-wide catch for a rule that fails to LOAD rather than to
   * match. Compares the ids the fixtures exercise against the `- id:`
   * entries parsed out of the YAML itself, rather than against a list
   * maintained by hand beside it — so a rule added without a fixture, or a
   * rule that silently stops loading, both fail here. (`semgrep --validate`
   * and the locale-codec byte check run over every pack in
   * `semgrepPacks.test.ts`; what they cannot do is the fixture-to-rule
   * mapping, which is why this lives here.)
   */
  it.skipIf(!AVAILABLE)('every rule the YAML declares is exercised by a hit fixture', () => {
    const { rows } = run(resolve(FIXTURES, 'hits'));
    expect(ids(rows)).toEqual(declaredRuleIds());
  });

  it.skipIf(!AVAILABLE)('fires NOTHING in EACH near-miss fixture file', () => {
    // Equivalent to the old directory-wide "toEqual([])" — a union of sets
    // is empty iff every constituent set is — but pinpoints which near-miss
    // file regressed instead of only that the directory did. No count
    // check needed here: zero raw rows and zero deduplicated ids are the
    // same fact for an empty set. A rethrowing catch, an append at index
    // length, an awaited save and a deliberate fire-and-forget log are all
    // correct code that looks like a bug.
    const dir = resolve(FIXTURES, 'misses');
    const { rows, scanned } = run(dir);
    // This is the half of the proof most exposed to a silent zero-file
    // scan: a broken temp copy would make every near-miss fixture read as
    // "correctly silent" for the wrong reason. Ruled out directly.
    expect(scanned).toBe(fixtureFiles(dir).length);
    const grouped = rowsByFile(rows);
    for (const file of fixtureFiles(dir)) {
      expect(grouped[file] ?? []).toEqual([]);
    }
  });

  it.skipIf(!AVAILABLE)('reports each rule at its DESIGNED severity tier', () => {
    const { rows } = run(resolve(FIXTURES, 'hits'));
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
  it('maps all thirteen', () => {
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
