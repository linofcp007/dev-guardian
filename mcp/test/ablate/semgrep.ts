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
}

export class SemgrepFailure extends Error {}

interface RawResult {
  readonly check_id?: unknown;
  readonly path?: unknown;
  readonly start?: { readonly line?: unknown; readonly col?: unknown };
  readonly end?: { readonly line?: unknown; readonly col?: unknown };
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
      `semgrep scanned 0 files under ${req.target} -- the config loaded nothing, ` +
        `the target has no files in the pack's languages, or the path is on an ` +
        `ignore list. This is never a valid ablation measurement.` +
        (errors.length > 0 ? `\nsemgrep errors: ${errors.join(' | ')}` : ''),
    );
  }

  const findings: Finding[] = rawResults.map((raw) => {
    const r = raw as RawResult;
    const checkId = stringify(r.check_id);
    const path = stringify(r.path);
    return {
      ruleId: checkId.split('.').pop() ?? checkId,
      file: relative(root, path).split(sep).join('/'),
      line: num(r.start?.line),
      col: num(r.start?.col),
      endLine: num(r.end?.line),
      endCol: num(r.end?.col),
    };
  });

  return { findings, scanned: scannedList.length, errors };
}

/** Findings whose relative path starts with `<subdir>/`. */
export function under(findings: readonly Finding[], subdir: string): Finding[] {
  const prefix = `${subdir}/`;
  return findings.filter((f) => f.file.startsWith(prefix));
}
