/**
 * Did one Semgrep run actually scan? — Global Constraint 3 for Semgrep.
 *
 * An exit code of 0 or 1 is necessary and never sufficient. Every one of these
 * has been observed to look like a clean run from the exit code alone:
 *
 *   - exit 7: a `--config` that could not be loaded (registry offline, pack
 *     retired, invalid YAML) aborts the WHOLE run with `paths.scanned: []`.
 *     `full-security-scan.sh` printed "Semgrep returned findings" for it.
 *   - exit 2: "Invalid scanning root" for a target that does not exist — one
 *     deleted file in a pull request made `review-scan.sh` scan nothing.
 *   - exit 0 with `paths.scanned: []`: a config with `rules: []`, or targets
 *     no rule applies to — measured on semgrep 1.176.1.
 *   - exit 0 with a non-empty `errors[]`: a target that failed to parse
 *     (`PartialParsing`) is only partly analysed.
 *
 * So a run counts as done (`ok`) only when the report exists, parses, scanned
 * at least one file when there were targets, and carries no errors. The
 * report's results are still worth reading when the check fails — they are
 * real findings — which is why this returns a verdict rather than throwing.
 *
 * ---- The verdict ------------------------------------------------------
 *
 * Every Semgrep call site used to read `ok` and nothing else, except
 * `map_attack_surface`, which had its own per-file classification. That
 * classification lives here now, so scan_sast, map_attack_surface and the
 * batched runs (`fileBatchScan.ts`) agree on the same four outcomes:
 *
 *   - `ok`: complete.
 *   - `partial`: a clean exit (0, or 1 for findings) that scanned files, where
 *     EVERY `errors[]` entry is a problem confined to one target file — a
 *     warn-level `PartialParsing` (PHP's legal `const NAMESPACE` on 1.176.1,
 *     measured), a syntax error in one file, a per-file timeout. Partial
 *     coverage, never `ok` and never `failed`: the caller records the scanner
 *     as run AND missing, with the files named (`partial`).
 *   - `scanned_nothing`: a clean exit, no error, nothing scanned although
 *     there were targets — a gap, `skipped`.
 *   - `failed`: everything fatal — an unclean exit, a run that did not
 *     finish, no or unparseable report, an error that is not tied to one
 *     target file (a rule or config error, an entry naming no file, one
 *     naming a YAML file, which cannot be told from the rule pack by name —
 *     a broken YAML target stays `failed`, the conservative reading), or
 *     per-file errors on a run that scanned nothing.
 *
 * `ok` stays true only for the first, so a caller that reads nothing else
 * (`fixpr/apply.ts`, `compliance_check`) keeps treating a partial run as
 * not done.
 */

import type { PartialParse } from '../types.js';
import type { ProcessOutcome } from './processRunner.js';
import { asArray, getProp, getString, parseInputAsJson, toRelativeIfPossible } from './scannerParsers/index.js';

export type SemgrepVerdict = 'ok' | 'partial' | 'scanned_nothing' | 'failed';

export interface SemgrepReportCheck {
  /** True only for a complete run (`verdict === 'ok'`). */
  ok: boolean;
  verdict: SemgrepVerdict;
  /** Files Semgrep reports as scanned (0 when unknown). */
  scanned: number;
  /** Entries in the report's `errors[]` (0 when unknown). */
  errors: number;
  /** Why the run does not count, when `ok` is false. */
  reason?: string;
  /**
   * `partial`: every file Semgrep could read only in part, one entry per
   * (file, error type), project-relative when `projectPath` was given. Also
   * on a `failed` verdict that carries `rules_not_loaded`, for the per-file
   * errors beside the rule errors.
   */
  partial?: PartialParse[];
  /**
   * `failed` only, when all that went wrong is that some RULES did not load
   * while the others ran: a settled exit 0, 1 or 2 that scanned files, where
   * every `errors[]` entry is either a rule error naming its `rule_id`
   * (`Rule parse error`, measured on 1.176.1: exit 2, the other rules still
   * run and `paths.scanned` is filled) or a per-file problem (in `partial`).
   * Semgrep is installed and scanned — not "semgrep missing". The verdict
   * stays `failed`, so a caller that reads nothing else is unchanged;
   * bug_hunt records it as a narrower gap (`ToolRun.failed_rules`).
   */
  rules_not_loaded?: RuleNotLoaded[];
}

/** A rule a Semgrep run did not load, by its stored id, and Semgrep's reason. */
export interface RuleNotLoaded {
  rule_id: string;
  message: string;
}

/** Longest error text carried into a reason. */
const MAX_ERROR_TEXT = 300;

/**
 * Error types that describe the rules or the configuration, never one target
 * file — fatal wherever they appear, even when the entry carries a path.
 * Measured on 1.176.1: `InvalidRuleSchemaError`, `Rule parse error` and
 * `SemgrepError` ("invalid configuration file found", "Invalid YAML file").
 */
const CONFIG_ERROR_TYPE = /rule|config|yaml|schema|plugin|SemgrepError|fatal/i;

export function checkSemgrepReport(args: {
  raw: string | null;
  exitCode: number | null;
  outcome: ProcessOutcome;
  /** How many explicit targets were passed (a whole-project run passes 1). */
  targets: number;
  /** Names a `partial` verdict's files relative to it. */
  projectPath?: string;
  /**
   * The stored id of a rule Semgrep names in `errors[]` — the parser's own
   * (`runners/semgrepRuleIds.ts#localRuleIdNormalizer`), so a rule that did
   * not load is named as its findings are. Identity when omitted.
   */
  ruleIdOf?: (checkId: string) => string;
}): SemgrepReportCheck {
  const { raw, exitCode, outcome, targets, projectPath } = args;
  const relative = (list: readonly PartialParse[]): PartialParse[] =>
    list.map((p) => ({ ...p, file: toRelativeIfPossible(p.file, projectPath) }));
  if (outcome === 'cancelled' || outcome === 'timed_out' || outcome === 'output_too_large') {
    return { ok: false, verdict: 'failed', scanned: 0, errors: 0, reason: `semgrep did not finish (${outcome})` };
  }
  if (raw === null) {
    return { ok: false, verdict: 'failed', scanned: 0, errors: 0, reason: `semgrep wrote no JSON report (exit ${String(exitCode)})` };
  }
  const root = parseInputAsJson(raw);
  if (root === null || typeof root !== 'object' || Array.isArray(root)) {
    return { ok: false, verdict: 'failed', scanned: 0, errors: 0, reason: `semgrep report is not valid JSON (exit ${String(exitCode)})` };
  }
  const scanned = asArray(getProp(getProp(root, 'paths'), 'scanned')).length;
  const errorEntries = asArray(getProp(root, 'errors'));
  const errors = describeErrors(errorEntries);
  const exitClean = exitCode === 0 || exitCode === 1;

  const problems: string[] = [];
  if (!exitClean) problems.push(`exit ${String(exitCode)}`);
  if (targets > 0 && scanned === 0) problems.push(`scanned 0 of ${targets} target(s)`);
  if (errors.length > 0) {
    problems.push(`${errors.length} Semgrep error(s): ${clip(errors.join('; '))}`);
  }
  if (problems.length === 0) return { ok: true, verdict: 'ok', scanned, errors: 0 };
  const reason = problems.join('; ');

  if (exitClean && scanned === 0 && errors.length === 0) {
    return { ok: false, verdict: 'scanned_nothing', scanned, errors: 0, reason };
  }
  if (exitClean && scanned > 0 && errors.length > 0) {
    const partial = perFileErrors(errorEntries);
    if (partial !== null) {
      return { ok: false, verdict: 'partial', scanned, errors: errors.length, reason, partial: relative(partial) };
    }
  }
  const failed: SemgrepReportCheck = { ok: false, verdict: 'failed', scanned, errors: errors.length, reason };
  if ((exitClean || exitCode === 2) && scanned > 0) {
    const ruleGap = rulesNotLoaded(errorEntries, args.ruleIdOf ?? ((id) => id));
    if (ruleGap !== null) {
      return {
        ...failed,
        rules_not_loaded: ruleGap.rules,
        ...(ruleGap.files.length > 0 ? { partial: relative(ruleGap.files) } : {}),
      };
    }
  }
  return failed;
}

/**
 * The reason a `partial` run carries: `partial: N file(s) only partly parsed
 * — <what may be missing> (PartialParsing: a.php; Syntax error: b.js)`.
 */
export function describePartialParse(partial: readonly PartialParse[], consequence: string): string {
  const listed = partial.map((p) => `${p.type}: ${p.file}`).join('; ');
  const files = new Set(partial.map((p) => p.file)).size;
  return `partial: ${files} file(s) only partly parsed — ${consequence} (${listed})`;
}

/** `type: message` per `errors[]` entry (`type` may be a string or `[name, …]`). */
function describeErrors(errors: readonly unknown[]): string[] {
  return errors.map((entry) => {
    const rawType = getProp(entry, 'type');
    const type = typeof rawType === 'string' ? rawType : Array.isArray(rawType) ? String(rawType[0]) : 'error';
    const message = getString(entry, 'message') ?? '(no message)';
    return `${type}: ${message.split(/\r?\n/)[0] ?? message}`;
  });
}

/** An `errors[]` entry's type name (`type` may be a string or `[name, …]`), or null. */
function errorType(entry: unknown): string | null {
  const rawType = getProp(entry, 'type');
  return typeof rawType === 'string' ? rawType : Array.isArray(rawType) && typeof rawType[0] === 'string' ? rawType[0] : null;
}

/**
 * One `errors[]` entry as a per-file problem, or null when it is not: a
 * config/rule error type, no target file named, or the file named is a YAML
 * file (it cannot be told from a rule pack by its name). The file comes from
 * the entry's `path`, else its first span, else the location list inside a
 * `["PartialParsing", [...]]` type. The message is its first line.
 */
function perFileError(entry: unknown): PartialParse | null {
  const type = errorType(entry);
  if (type === null || CONFIG_ERROR_TYPE.test(type)) return null;
  const file = targetFileOf(entry, getProp(entry, 'type'));
  if (file === null || /\.ya?ml$/i.test(file)) return null;
  const message = getString(entry, 'message') ?? type;
  return { file, type, message: message.split(/\r?\n/)[0] ?? message };
}

/**
 * Semgrep repeats an error per rule or per span, and a file is one file
 * however many times it was reported: one entry per (file, type). Its types
 * all stay, because the gate accepts parse types only (`ci/gate.ts`).
 */
function pushOnce(out: PartialParse[], p: PartialParse): void {
  if (!out.some((q) => q.file === p.file && q.type === p.type)) out.push(p);
}

/** Every `errors[]` entry as a per-file problem ({@link perFileError}), or null when any one is not. */
function perFileErrors(errors: readonly unknown[]): PartialParse[] | null {
  const out: PartialParse[] = [];
  for (const entry of errors) {
    const p = perFileError(entry);
    if (p === null) return null;
    pushOnce(out, p);
  }
  return out.length > 0 ? out : null;
}

/**
 * The rules that did not load and the per-file problems beside them, when
 * that is every `errors[]` entry and at least one is a rule — else null. A
 * rule entry is an error type naming a rule (`Rule parse error`) with the
 * `rule_id` it concerns, stored as `ruleIdOf` names it; its message is the
 * line that says what is wrong (Semgrep's second: the first repeats the
 * id), clipped.
 */
function rulesNotLoaded(
  errors: readonly unknown[],
  ruleIdOf: (checkId: string) => string,
): { rules: RuleNotLoaded[]; files: PartialParse[] } | null {
  const rules: RuleNotLoaded[] = [];
  const files: PartialParse[] = [];
  for (const entry of errors) {
    const type = errorType(entry);
    const ruleId = getString(entry, 'rule_id');
    if (type !== null && /rule/i.test(type) && ruleId !== undefined && ruleId.length > 0) {
      const lines = (getString(entry, 'message') ?? type).split(/\r?\n/).map((l) => l.trim()).filter((l) => l.length > 0);
      const id = ruleIdOf(ruleId);
      if (!rules.some((r) => r.rule_id === id)) rules.push({ rule_id: id, message: clip(lines[1] ?? lines[0] ?? type) });
      continue;
    }
    const p = perFileError(entry);
    if (p === null) return null;
    pushOnce(files, p);
  }
  return rules.length > 0 ? { rules, files } : null;
}

function targetFileOf(entry: unknown, rawType: unknown): string | null {
  const path = getString(entry, 'path');
  if (path !== undefined && path.length > 0) return path;
  const span = asArray(getProp(entry, 'spans'))[0];
  const spanFile = span === undefined ? undefined : getString(span, 'file');
  if (spanFile !== undefined && spanFile.length > 0) return spanFile;
  if (Array.isArray(rawType)) {
    const location = asArray(rawType[1])[0];
    const locationPath = location === undefined ? undefined : getString(location, 'path');
    if (locationPath !== undefined && locationPath.length > 0) return locationPath;
  }
  return null;
}

function clip(text: string): string {
  return text.length > MAX_ERROR_TEXT ? `${text.slice(0, MAX_ERROR_TEXT - 1)}…` : text;
}

/**
 * The environment every Semgrep (and Bandit) invocation gets: the caller's,
 * plus `PYTHONUTF8=1`. Semgrep's CLI is Python and writes `--output` in the
 * locale encoding otherwise — measured on Windows (cp1252), a target named
 * `日本.py` made semgrep 1.176.1 exit 2 without writing a report, and
 * `héllo.py` came back as `h�llo.py`. UTF-8 mode also reads rule files as
 * UTF-8, which is what they are.
 */
export function pythonUtf8Env(env: NodeJS.ProcessEnv | undefined): NodeJS.ProcessEnv {
  return { ...(env ?? process.env), PYTHONUTF8: '1' };
}
