/**
 * The one place the ablation harness talks to Semgrep.
 *
 * ---- Why `paths.scanned` is a hard gate, not a statistic -----------------
 *
 * This repo has five recorded ways for Semgrep to do nothing at all while
 * printing a successful, zero-finding JSON document and exiting 0:
 *
 *   1. a `pattern-either` branch with no positive term;
 *   2. an unquoted `?` in a pattern, read as a YAML tag;
 *   3. a deep-expression (`<... ... ...>`) placed directly inside a block;
 *   4. the config loader's locale codec tripping on an uppercase accented
 *      letter (an `A`-acute / `I`-acute in a Portuguese comment);
 *   5. a pattern that is not valid code in the target language.
 *
 * Two of those emit neither `RuleParseError` nor `Invalid YAML`, so matching
 * on error strings does not cover the set. `paths.scanned` is the one signal
 * all five share, and an ablation run that silently scans zero files reports
 * every clause DEAD -- the exact wrong answer, delivered confidently. So an
 * empty `paths.scanned` is an exception here, never a result.
 *
 * The same trap has a second entrance that has nothing to do with rules:
 * Semgrep's default ignore list skips any path containing a `test/` segment,
 * which is where every fixture in this repo lives. `harness.ts` copies the
 * fixtures out to a temp dir for that reason; this gate is what would catch
 * it if someone removed the copy.
 *
 * ---- And why `paths.scanned` is NOT sufficient --------------------------
 *
 * `paths.scanned` counts the files semgrep-core OPENED, not the files it
 * finished. Its per-rule timeout (`--timeout`, 5s by default) abandons one
 * rule on one file and carries on; after `--timeout-threshold` of those (3 by
 * default) it drops the WHOLE FILE for every rule still to run, including
 * rules that would have finished in milliseconds. None of that moves
 * `paths.scanned` -- it stays at the full count -- and none of it is an error
 * in the sense the gate above tests for. It lands in `errors[]` as
 * `type: "Timeout"` entries carrying a `rule_id` and a `path`.
 *
 * Measured on `dotnet/runtime` (11 800 C# files) with `bugfix-cs.yml`: the
 * same pack over the same tree returned 793 findings on one run and 798 on
 * the next, `paths.scanned` 11 800 both times and `errors` empty of anything
 * fatal. The five that moved were all `empty-catch` findings in the two files
 * that crossed the timeout threshold on the slower run -- `WMIGenerator.cs`
 * and `XmlTextReaderImpl.cs` -- and `empty-catch` never appeared in a timeout
 * message, because it was one of the rules dropped WITH the file. That is why
 * {@link ScanResult.abortedFiles} is a set of FILES and not of (rule, file)
 * pairs: the rules a threshold drop takes down are exactly the ones that go
 * unnamed. Excluding those files from both sides of a comparison took the two
 * runs to 793 and 793, differing in nothing.
 */

import { execFileSync } from 'node:child_process';
import { relative, sep } from 'node:path';

export interface Finding {
  /** Last dot-segment of `check_id`; Semgrep prefixes the config path on. */
  readonly ruleId: string;
  /** Slash-separated, relative to the scan root, so it survives temp dirs. */
  readonly file: string;
  readonly line: number;
  readonly col: number;
  readonly endLine: number;
  readonly endCol: number;
}

export interface ScanResult {
  readonly findings: readonly Finding[];
  readonly scanned: number;
  /** `errors[].message` from the JSON, surfaced but not fatal on its own. */
  readonly errors: readonly string[];
  /**
   * Files this scan did NOT finish: at least one rule was abandoned on them
   * for time or memory. Same normalisation as {@link Finding.file}, so the two
   * can be compared directly. Nondeterministic between runs by construction --
   * that is the point of collecting it.
   */
  readonly abortedFiles: readonly string[];
  /**
   * Aborts that named no file. Nothing can be excluded for these, so a scan
   * with any of them is not comparable to another scan at all; the harness
   * reports it rather than pretending the count is clean.
   */
  readonly unscopedAborts: number;
}

export class SemgrepFailure extends Error {}

interface RawResult {
  readonly check_id?: unknown;
  readonly path?: unknown;
  readonly start?: { readonly line?: unknown; readonly col?: unknown };
  readonly end?: { readonly line?: unknown; readonly col?: unknown };
}

interface RawError {
  readonly type?: unknown;
  readonly message?: unknown;
  readonly path?: unknown;
}

/**
 * Errors that mean "this file was not fully analysed", as opposed to "this
 * file does not parse". Parse failures (`Syntax error`, `PartialParsing`) are
 * a deterministic property of the file and repeat identically on every run, so
 * they need no exclusion; timeouts and memory caps are a property of the
 * machine's mood and do not.
 *
 * Matched on the error `type` rather than on the message, and by substring
 * rather than by an exact list, because the message wording has changed across
 * Semgrep releases and the abort types have not: `Timeout`,
 * `Timeout during interfile analysis`, `Out of memory`,
 * `Out of memory during interfile analysis`, `Maximum file size exceeded`.
 */
export function isAbortError(type: string): boolean {
  const t = type.toLowerCase();
  return t.includes('timeout') || t.includes('memory');
}

function num(value: unknown): number {
  return typeof value === 'number' ? value : -1;
}

function stringify(value: unknown): string {
  if (typeof value === 'string') return value;
  if (value === undefined || value === null) return '';
  return JSON.stringify(value);
}

/** Stable identity of one finding. Ablation compares multisets of these. */
export function findingKey(f: Finding): string {
  return `${f.ruleId}|${f.file}|${String(f.line)}:${String(f.col)}-${String(f.endLine)}:${String(f.endCol)}`;
}

export function sortedKeys(findings: readonly Finding[]): string[] {
  return findings.map(findingKey).sort();
}

export function sameFindings(a: readonly Finding[], b: readonly Finding[]): boolean {
  const ka = sortedKeys(a);
  const kb = sortedKeys(b);
  return ka.length === kb.length && ka.every((k, i) => k === kb[i]);
}

/**
 * Multiset difference `a \ b`, by finding key. Used for both directions of
 * the report: what an ablation REVEALED (present after removal, absent
 * before) and what the clause was ADDING (present before, absent after).
 */
export function findingsMissingFrom(a: readonly Finding[], b: readonly Finding[]): Finding[] {
  const remaining = new Map<string, number>();
  for (const f of b) {
    const k = findingKey(f);
    remaining.set(k, (remaining.get(k) ?? 0) + 1);
  }
  const out: Finding[] = [];
  for (const f of a) {
    const k = findingKey(f);
    const left = remaining.get(k) ?? 0;
    if (left > 0) remaining.set(k, left - 1);
    else out.push(f);
  }
  return out;
}

export interface ScanRequest {
  /** Absolute path to the semgrep executable, or just `semgrep` on PATH. */
  readonly bin: string;
  /** Absolute path to the rule pack to run. */
  readonly config: string;
  /** Absolute path to the directory to scan. */
  readonly target: string;
  /** Findings paths are reported relative to this. Defaults to `target`. */
  readonly root?: string;
  readonly timeoutMs?: number;
}

/**
 * `--metrics=off` and `--disable-version-check` are here for determinism and
 * speed, not privacy: an ablation run is hundreds of invocations, and both
 * flags remove a network round trip from each one.
 */
export function scan(req: ScanRequest): ScanResult {
  const root = req.root ?? req.target;
  let stdout: string;
  try {
    stdout = execFileSync(
      req.bin,
      [
        '--config',
        req.config,
        '--json',
        '--quiet',
        '--no-git-ignore',
        '--metrics=off',
        '--disable-version-check',
        req.target,
      ],
      {
        encoding: 'utf8',
        maxBuffer: 64 * 1024 * 1024,
        timeout: req.timeoutMs ?? 10 * 60 * 1000,
        windowsHide: true,
      },
    );
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    const stderr =
      typeof err === 'object' && err !== null && 'stderr' in err
        ? stringify((err as { stderr: unknown }).stderr).slice(-2000)
        : '';
    throw new SemgrepFailure(`semgrep exited non-zero: ${detail}\n${stderr}`);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    throw new SemgrepFailure(`semgrep did not emit JSON (first 500 chars): ${stdout.slice(0, 500)}`);
  }

  return parseScan(parsed, root, req.target);
}

/**
 * The pure half of {@link scan}: everything from Semgrep's JSON document to a
 * {@link ScanResult}, with no process to spawn. Separate so the
 * `paths.scanned` gate and the abort accounting can be unit-tested without
 * Semgrep installed -- the abort accounting is what axis 3 now rests on.
 */
export function parseScan(parsed: unknown, root: string, target: string): ScanResult {
  const doc = parsed as {
    results?: unknown;
    paths?: { scanned?: unknown };
    errors?: unknown;
  };
  const rawResults = Array.isArray(doc.results) ? doc.results : [];
  const scannedList = Array.isArray(doc.paths?.scanned) ? doc.paths.scanned : [];
  const rawErrors = Array.isArray(doc.errors) ? doc.errors : [];

  const errors = rawErrors.map((e) => {
    if (typeof e === 'object' && e !== null && 'message' in e) {
      return stringify((e as { message: unknown }).message);
    }
    return stringify(e);
  });

  if (scannedList.length === 0) {
    throw new SemgrepFailure(
      `semgrep scanned 0 files under ${target} -- the config loaded nothing, ` +
        `the target has no files in the pack's languages, or the path is on an ` +
        `ignore list. This is never a valid ablation measurement.` +
        (errors.length > 0 ? `\nsemgrep errors: ${errors.join(' | ')}` : ''),
    );
  }

  const rel = (path: string): string => relative(root, path).split(sep).join('/');

  const aborted = new Set<string>();
  let unscopedAborts = 0;
  for (const raw of rawErrors) {
    if (typeof raw !== 'object' || raw === null) continue;
    const e = raw as RawError;
    if (!isAbortError(stringify(e.type))) continue;
    const path = stringify(e.path);
    if (path === '') unscopedAborts += 1;
    else aborted.add(rel(path));
  }

  const findings: Finding[] = rawResults.map((raw) => {
    const r = raw as RawResult;
    const checkId = stringify(r.check_id);
    return {
      ruleId: checkId.split('.').pop() ?? checkId,
      file: rel(stringify(r.path)),
      line: num(r.start?.line),
      col: num(r.start?.col),
      endLine: num(r.end?.line),
      endCol: num(r.end?.col),
    };
  });

  return {
    findings,
    scanned: scannedList.length,
    errors,
    abortedFiles: [...aborted].sort(),
    unscopedAborts,
  };
}

/**
 * Findings whose relative path starts with `<subdir>/`, or EVERY finding when
 * `subdir` is `'.'` -- the fixture root itself.
 *
 * `'.'` exists for one pack and is not a convenience. `routes.yml`'s corpus
 * predates this harness by a long way and has no `hits/` directory: its true
 * positives are three sibling trees (`apps/`, `annotations/`, `frameworks/`)
 * and its decoys are ONE subdirectory inside the third. Renaming them to fit
 * the convention was not available -- `test/e2e/rulePackFixture.test.ts` and
 * the surface tools address those directories by name -- so the hits corpus is
 * the whole root minus the decoys. See {@link outside} and `PackSpec.decoySubdirs`.
 */
export function under(findings: readonly Finding[], subdir: string): Finding[] {
  if (subdir === '.') return [...findings];
  const prefix = `${subdir}/`;
  return findings.filter((f) => f.file.startsWith(prefix));
}

/**
 * The complement of {@link under} over several subdirectories at once:
 * findings that are under NONE of them.
 *
 * Used to subtract a decoy tree from the hits corpus. Kept separate from
 * `under` rather than folded into it as a "hits selector" because the two
 * answer different questions and the axis-2 reveal check needs both: the hits
 * set is `outside(under(all, hitsSubdir), decoySubdirs)`, and a finding that
 * leaves the first set for the second is not a suppressed true positive.
 */
export function outside(findings: readonly Finding[], subdirs: readonly string[]): Finding[] {
  if (subdirs.length === 0) return [...findings];
  const prefixes = subdirs.map((d) => `${d}/`);
  return findings.filter((f) => !prefixes.some((p) => f.file.startsWith(p)));
}
