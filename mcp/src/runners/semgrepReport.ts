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
 *     target file (a rule or config error — told by its TYPE, whatever path
 *     it names — or an entry naming no file), or per-file errors on a run
 *     that scanned nothing.
 *
 *     A YAML file named by a per-file type is a target when it lies inside
 *     the scanned project — a path Semgrep reports relative to its cwd (every
 *     caller runs it in the project), or an absolute one under `projectPath`.
 *     It used to be refused on its extension alone ("cannot be told from the
 *     rule pack by name"), and every repository with a GitHub Actions
 *     workflow a bash sub-pattern could not read went `failed` — OWASP Juice
 *     Shop's scan_sast reported coverage `none` over 969 files read and 68
 *     results. Measured on 1.176.1: a broken rule pack is `SemgrepError`
 *     (exit 7) or `Rule parse error` (exit 2), with no path and nothing
 *     scanned; a workflow target is a warn-level `PartialParsing` with its
 *     path, on exit 0, results intact. A YAML file OUTSIDE the project, or an
 *     absolute one when the project is not known, can only be a rule file:
 *     that stays fatal (the I3 ruling — "not the rule file").
 *
 * `ok` stays true only for the first, so a caller that reads nothing else
 * (`fixpr/apply.ts`, `compliance_check`) keeps treating a partial run as
 * not done.
 *
 * ---- Taint fixpoint timeouts --------------------------------------------
 *
 * One more way to look complete: a taint rule whose dataflow analysis of
 * one function runs past its budget is given up on that function, and what
 * it had not found yet is lost. Semgrep does not put that in `errors[]` —
 * `errors` stays empty and `paths.scanned` full — but only under
 * `time.fixpoint_timeouts` (`error_type: "Fixpoint timeout"`, the file and
 * the function's line in `location`). Measured: present on 1.170.1 and
 * 1.176.1 in every JSON report, with or without `--time` (an empty list on
 * a clean run); absent on 1.86.0, 1.95.0, 1.99.0 and 1.120.1 even with it.
 * `--time` is never needed, and never passed: it adds per-target profiling
 * (LibreChat: 94 MB against 1.7 MB). 644 of them on LibreChat and 77 on this
 * repo's own `mcp/src` under `p/default` + the plugin's packs, and a true
 * positive of the LLM pack dropped out of 3 scans in 17, each with a
 * fixpoint timeout on its function.
 *
 * A file named there was not fully analysed — the same class as a per-rule
 * `Timeout` in `errors[]` — so it joins the per-file problems: an otherwise
 * complete run is `partial`, one entry per file (type
 * {@link FIXPOINT_TIMEOUT_TYPE}, its function count in `functions`), and the
 * reason names a few files and counts the rest. A timeout marks the function
 * incomplete rather than empty — a scan once reported the very finding its
 * function timed out on — but the file's result cannot be trusted either
 * way. An entry that names no file cannot be scoped to one, and makes the
 * run `failed`, as an error naming no file does. A timeout of the plugin's
 * own pack alone is the pack's gap, never the verdict
 * ({@link PluginPackFixpoint}). An engine that does not
 * emit the field cannot say: {@link semgrepEngineOf}, and the note callers
 * add (`semgrepConfigs.ts#semgrepEngineNote`).
 */

import { isAbsolute, relative as relativePath, resolve as resolvePath } from 'node:path';
import type { FailedRule, PartialParse, ToolRun } from '../types.js';
import type { ProcessOutcome } from './processRunner.js';
import { asArray, getProp, getString, parseInputAsJson, toPosixPath, toRelativeIfPossible } from './scannerParsers/index.js';

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
   * while the others ran: a settled exit 0, 1 or 2 that scanned files (or a
   * batch judged with `targets: 0`, whose scanned count its caller judges
   * over the whole run), where every `errors[]` entry is either a rule
   * error naming its `rule_id` (`Rule parse error`, measured on 1.176.1:
   * exit 2, the other rules still run and `paths.scanned` is filled — also
   * when every rule failed, so "scanned" does not prove a rule ran) or a
   * per-file problem (in `partial`). Semgrep is installed and scanned — not
   * "semgrep missing". The verdict stays `failed`, so a caller that reads
   * nothing else is unchanged (compliance_check, fixpr, map_attack_surface);
   * scan_sast, bug_hunt and every batched run (`fileBatchScan.ts`) record
   * it as a narrower gap: Semgrep `ok` and missing, the rules in
   * `ToolRun.failed_rules` ({@link describeRulesNotLoaded}).
   */
  rules_not_loaded?: RuleNotLoaded[];
  /**
   * `failed` only, when the run failed because its rule configuration was
   * refused — every `errors[]` entry names a rule or a language
   * (`UnknownLanguageError`, measured on 1.176.1: exit 8, nothing scanned;
   * `InvalidRuleSchemaError`; a `Rule parse error` naming no rule), or is a
   * `SemgrepError` beside one: what went wrong, for the reason. Semgrep is
   * installed; the rules are the problem. Absent when `rules_not_loaded` is
   * set (some rules ran) and for every other failure (a registry download,
   * a crash, a target).
   */
  rule_config_error?: string;
  /**
   * `ok`, `partial` or `rules_not_loaded`: the plugin's pack's own fixpoint
   * timeouts ({@link PluginPackFixpoint}) — never part of the verdict.
   */
  plugin_pack_fixpoint?: PluginPackFixpoint;
}

/** A rule a Semgrep run did not load, by its stored id, and Semgrep's reason. */
export type RuleNotLoaded = FailedRule;

/** Longest error text carried into a reason. */
const MAX_ERROR_TEXT = 300;

/** The `error_type` of a `time.fixpoint_timeouts` entry, and the `PartialParse.type` its file is stored under. */
export const FIXPOINT_TIMEOUT_TYPE = 'Fixpoint timeout';

/**
 * The `PartialParse.type` of a file whose fixpoint timeouts are the plugin's
 * pack's alone ({@link PluginPackFixpoint}): kept for history, never the
 * scan's partial verdict nor the CI gate's (`ci/runScans.ts` leaves it out).
 */
export const FIXPOINT_TIMEOUT_PACK_TYPE = 'Fixpoint timeout (plugin pack)';

/** How many files a partial reason names before "+N more" — parse errors and fixpoint timeouts alike. The stored list keeps every one. */
export const FIXPOINT_FILES_NAMED = 5;

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
  /**
   * The plugin's own packs' rules (`configs/semgrep/`, what scan_sast and
   * review_pr append) as Semgrep spells them in THIS run, prefix included
   * (`semgrepRuleIds.ts#pluginPackCheckIds`) — matched against the raw id a
   * fixpoint timeout names, never a normalised one: a project rule named
   * like a pack rule is spelled bare, and is not the pack's (round 4, A-1).
   * A timeout whose only rule is one of them is the pack's gap, not the
   * scan's ({@link PluginPackFixpoint}). None when omitted.
   */
  pluginPackCheckIds?: ReadonlySet<string>;
  /**
   * Whether any config of the run besides the plugin's packs may hold a
   * taint rule (`semgrepRuleIds.ts#mayHoldTaintRules`: unless proven not
   * to). Default true. When false, a timeout that names a pack rule first
   * of several is the pack's too: every rule that can time out is the pack's.
   */
  nonPackTaintRules?: boolean;
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
  // Functions the taint analysis gave up on (the module comment): per file,
  // project-relative, beside `errors[]` rather than in it. Those of the
  // plugin's pack alone are its own gap, and never the verdict's.
  const all = fixpointTimeoutsOf(root, args.pluginPackCheckIds ?? new Set(), args.nonPackTaintRules ?? true);
  const fixpoint = all.scan;
  const fixpointFiles = relative(fixpoint.files);
  const packGap: PluginPackFixpoint | null =
    all.pack.functions > 0 ? { files: relative(all.pack.files), functions: all.pack.functions } : null;
  const withPackGap = (check: SemgrepReportCheck): SemgrepReportCheck =>
    packGap === null ? check : { ...check, plugin_pack_fixpoint: packGap };

  const problems: string[] = [];
  if (!exitClean) problems.push(`exit ${String(exitCode)}`);
  if (targets > 0 && scanned === 0) problems.push(`scanned 0 of ${targets} target(s)`);
  if (errors.length > 0) {
    problems.push(`${errors.length} Semgrep error(s): ${clip(errors.join('; '))}`);
  }
  if (fixpoint.functions > 0) problems.push(describeFixpointTimeouts(fixpointFiles, fixpoint.unscoped));
  if (problems.length === 0) return withPackGap({ ok: true, verdict: 'ok', scanned, errors: 0 });
  const reason = problems.join('; ');

  if (exitClean && scanned === 0 && errors.length === 0 && fixpoint.functions === 0) {
    return { ok: false, verdict: 'scanned_nothing', scanned, errors: 0, reason };
  }
  if (exitClean && scanned > 0 && fixpoint.unscoped === 0 && (errors.length > 0 || fixpoint.functions > 0)) {
    const partial = errors.length > 0 ? perFileErrors(errorEntries, projectPath) : [];
    if (partial !== null) {
      return withPackGap({
        ok: false,
        verdict: 'partial',
        scanned,
        errors: errors.length,
        reason,
        partial: [...relative(partial), ...fixpointFiles],
      });
    }
  }
  const failed: SemgrepReportCheck = { ok: false, verdict: 'failed', scanned, errors: errors.length, reason };
  const configError = ruleConfigError(errorEntries);
  if (configError !== null) failed.rule_config_error = configError;
  if ((exitClean || exitCode === 2) && (scanned > 0 || targets === 0) && fixpoint.unscoped === 0) {
    const ruleGap = rulesNotLoaded(errorEntries, args.ruleIdOf ?? ((id) => id), projectPath);
    if (ruleGap !== null) {
      const { rule_config_error: _whole, ...someRan } = failed;
      const files = [...relative(ruleGap.files), ...fixpointFiles];
      return withPackGap({
        ...someRan,
        rules_not_loaded: ruleGap.rules,
        ...(files.length > 0 ? { partial: files } : {}),
      });
    }
  }
  return failed;
}

/**
 * `a, b, c, d, e, +N more`: the first {@link FIXPOINT_FILES_NAMED} of
 * `names`, then how many were left out — for any reason or warning that
 * names files (round 3, N-2: a loaded run names hundreds).
 */
export function nameAFew(names: readonly string[], separator = ', '): string {
  const more = names.length - FIXPOINT_FILES_NAMED;
  return [...names.slice(0, FIXPOINT_FILES_NAMED), ...(more > 0 ? [`+${more} more`] : [])].join(separator);
}

/**
 * The plugin's pack's own taint gap: fixpoint timeouts whose only rule is
 * one of its rules (`[rules: 1, first: <a pack rule>]`). Measured on this
 * repo's `mcp/src`, a TypeScript tree with no model call in it: 6 to 22 per
 * run, every one from the pack's JS rules — their sources are names and
 * shapes, with no literal for Semgrep to prefilter on, so taint runs on
 * every function. Counted in the verdict, they made the scan partial and the
 * CI gate red on code the pack has nothing to say about, with nothing a user
 * could accept (review of the LLM pack, round 3, N-1). So they are the
 * PACK's gap: stored beside the scan's gaps under
 * {@link FIXPOINT_TIMEOUT_PACK_TYPE} (a finding in such a file still reads
 * not re-measured), named in a note, never the run's partial verdict and
 * never the gate's. A timeout that names another rule, more than one rule
 * (Semgrep names only the first), or no parseable rule stays the scan's.
 */
export interface PluginPackFixpoint {
  /** One entry per file, type {@link FIXPOINT_TIMEOUT_PACK_TYPE}; project-relative. */
  files: PartialParse[];
  /** Functions in all, those in no named file included. */
  functions: number;
}

/**
 * The files `time.fixpoint_timeouts` names (the module comment), one entry
 * per file in the order first reported, each with its function count; how
 * many functions in all; and how many entries named no file — split into
 * the scan's and the plugin's pack's ({@link PluginPackFixpoint}).
 */
function fixpointTimeoutsOf(
  root: unknown,
  packCheckIds: ReadonlySet<string>,
  nonPackTaintRules: boolean,
): { scan: FixpointTally; pack: FixpointTally } {
  const scan = new FixpointTally(FIXPOINT_TIMEOUT_TYPE);
  const pack = new FixpointTally(FIXPOINT_TIMEOUT_PACK_TYPE);
  for (const entry of asArray(getProp(getProp(root, 'time'), 'fixpoint_timeouts'))) {
    const rules = rulesOf(getString(entry, 'message'));
    // The pack's alone when its rule — as Semgrep spells the PACK's, raw,
    // prefix included — is the only one named, or is named first of several
    // and no other config of the run can hold a taint rule at all (then
    // every rule that can time out is the pack's).
    const firstIsPack = rules !== null && packCheckIds.has(rules.first);
    const isPack = firstIsPack && (rules.count === 1 || !nonPackTaintRules);
    (isPack ? pack : scan).add(getString(getProp(entry, 'location'), 'path'));
  }
  return { scan, pack };
}

/**
 * The rules a fixpoint timeout names, or null when its message does not say:
 * Semgrep writes `… [rules: N, first: <check id>]` (1.176.1) — how many rules
 * timed out on the function, and only the first of them.
 */
function rulesOf(message: string | undefined): { count: number; first: string } | null {
  const m = /\[rules: (\d+), first: ([^\]\s]+)\]/.exec(message ?? '');
  const first = m?.[2];
  if (m === null || first === undefined) return null;
  return { count: Number.parseInt(m[1] ?? '0', 10), first };
}

/** Fixpoint timeouts counted per file, in the order first reported. */
class FixpointTally {
  readonly files: PartialParse[] = [];
  functions = 0;
  unscoped = 0;
  private readonly byFile = new Map<string, PartialParse>();

  constructor(private readonly type: string) {}

  add(path: string | undefined): void {
    this.functions += 1;
    if (path === undefined || path.length === 0) {
      this.unscoped += 1;
      return;
    }
    const file = toPosixPath(path);
    const known = this.byFile.get(file);
    if (known !== undefined) {
      known.functions = (known.functions ?? 0) + 1;
      known.message = fixpointMessage(known.functions);
      return;
    }
    const entry: PartialParse = { file, type: this.type, message: fixpointMessage(1), functions: 1 };
    this.byFile.set(file, entry);
    this.files.push(entry);
  }
}

/** The one-line message a fixpoint file's entry carries — its own, never Semgrep's (which repeats the path and rule list per function). */
function fixpointMessage(functions: number): string {
  return `taint analysis gave up on ${functions} function(s) here (Semgrep fixpoint timeout)`;
}

/**
 * The note a run carries for {@link PluginPackFixpoint}: `the plugin's LLM
 * pack: taint analysis incomplete (Semgrep fixpoint timeout) in N
 * function(s) across M file(s): a.ts, +K more — its findings in those
 * functions may be missing; the rest of the scan is complete`.
 */
export function describePluginPackFixpoint(gap: PluginPackFixpoint): string {
  const unscoped = gap.functions - gap.files.reduce((n, f) => n + (f.functions ?? 1), 0);
  return (
    `the plugin's LLM pack: ${describeFixpointTimeouts(gap.files, Math.max(0, unscoped))} — ` +
    'its findings in those functions may be missing; the rest of the scan is not affected'
  );
}

/**
 * `run` with the plugin's pack's own gap recorded ({@link PluginPackFixpoint}):
 * its files added to `partially_parsed` under their own type — history reads
 * a finding there as not re-measured — the note appended to the reason, and
 * `plugin_packs.llm` partial. The run's status and the caller's
 * `missing_tools` are untouched: the pack's gap is not the scan's.
 */
export function withPluginPackFixpoint(run: ToolRun, gap: PluginPackFixpoint | undefined): ToolRun {
  if (gap === undefined || gap.functions === 0) return run;
  const note = describePluginPackFixpoint(gap);
  return {
    ...run,
    reason: [run.reason, note].filter((s) => s !== undefined).join('; '),
    ...(gap.files.length > 0 ? { partially_parsed: [...(run.partially_parsed ?? []), ...gap.files] } : {}),
    plugin_packs: { ...(run.plugin_packs ?? {}), llm: { status: 'partial', reason: note } },
  };
}

/**
 * `taint analysis incomplete (Semgrep fixpoint timeout) in N function(s)
 * across M file(s): a.py, b.ts, +K more` — at most
 * {@link FIXPOINT_FILES_NAMED} files named; with `unscoped`, how many
 * functions no file was named for.
 */
function describeFixpointTimeouts(files: readonly PartialParse[], unscoped = 0): string {
  const functions = files.reduce((n, f) => n + (f.functions ?? 1), 0) + unscoped;
  const list = nameAFew(files.map((f) => f.file));
  return (
    `taint analysis incomplete (Semgrep fixpoint timeout) in ${functions} function(s)` +
    (unscoped > 0 ? `, ${unscoped} of them in no named file` : '') +
    (files.length > 0 ? ` across ${files.length} file(s): ${list}` : '')
  );
}

/**
 * What the engine that wrote a Semgrep report says about itself: its
 * `version`, and whether it reports taint fixpoint timeouts — `true` when
 * the report carries `time.fixpoint_timeouts` (1.170.1, 1.176.1: always,
 * an empty list on a clean run), `false` when a report that names its
 * version and scanned files has none (1.86.0 … 1.120.1, measured), absent
 * when that cannot be told. Nothing at all for no report or no JSON.
 */
export interface SemgrepEngine {
  version?: string;
  fixpointTimeoutsReported?: boolean;
}

export function semgrepEngineOf(raw: unknown): SemgrepEngine {
  if (raw === null || raw === undefined) return {};
  const root = parseInputAsJson(raw);
  if (root === null || typeof root !== 'object' || Array.isArray(root)) return {};
  const version = getString(root, 'version');
  if (version === undefined || version.length === 0) return {};
  if (Array.isArray(getProp(getProp(root, 'time'), 'fixpoint_timeouts'))) return { version, fixpointTimeoutsReported: true };
  const scanned = asArray(getProp(getProp(root, 'paths'), 'scanned')).length;
  return scanned > 0 ? { version, fixpointTimeoutsReported: false } : { version };
}

/**
 * The reason a `partial` run carries: `partial: N file(s) only partly parsed
 * — <what may be missing> (PartialParsing: a.php; Syntax error: b.js)`, and
 * for the files a taint analysis gave up on, `partial: taint analysis
 * incomplete (Semgrep fixpoint timeout) in N function(s) across M file(s):
 * a.py, +K more — taint findings in those functions may be missing` (a few
 * named: there can be hundreds).
 */
export function describePartialParse(partial: readonly PartialParse[], consequence: string): string {
  // The plugin's pack's own gap has its own note (describePluginPackFixpoint).
  const parsed = partial.filter((p) => p.type !== FIXPOINT_TIMEOUT_TYPE && p.type !== FIXPOINT_TIMEOUT_PACK_TYPE);
  const fixpoint = partial.filter((p) => p.type === FIXPOINT_TIMEOUT_TYPE);
  const parts: string[] = [];
  if (parsed.length > 0) {
    // A few named, the rest counted (round 3, N-2): the full list is on the
    // run (`partially_parsed`), and a reason is read by a person.
    const listed = nameAFew(parsed.map((p) => `${p.type}: ${p.file}`), '; ');
    const files = new Set(parsed.map((p) => p.file)).size;
    parts.push(`partial: ${files} file(s) only partly parsed — ${consequence} (${listed})`);
  }
  if (fixpoint.length > 0) {
    parts.push(`partial: ${describeFixpointTimeouts(fixpoint)} — taint findings in those functions may be missing`);
  }
  return parts.join('; ');
}

/**
 * The reason a run whose rules did not all load carries — every caller's
 * wording, so none of them reads "semgrep failed" or "install semgrep" for a
 * Semgrep that ran: `Semgrep ran, but 1 rule(s) did not load: <id> — <why>.
 * Findings of the other rules over N file(s) are kept; fix or remove the
 * rule and re-run`. It stays true when no other rule loaded.
 */
export function describeRulesNotLoaded(rules: readonly RuleNotLoaded[], scanned: number): string {
  const named = rules.map((r) => `${r.rule_id} — ${r.message}`).join('; ');
  return (
    `Semgrep ran, but ${rules.length} rule(s) did not load: ${named}. Findings of the other rules over ` +
    `${scanned} file(s) are kept; fix or remove the rule and re-run`
  );
}

/**
 * The reason of a run in which no rule loaded (every local rule failed, no
 * registry pack ran): nothing was scanned for.
 */
export function describeNoRuleLoaded(rules: readonly RuleNotLoaded[]): string {
  const named = rules.map((r) => `${r.rule_id} — ${r.message}`).join('; ');
  return (
    `no rule loaded: Semgrep ran, but every one of its ${rules.length} rule(s) failed to load (${named}) — ` +
    'nothing was scanned for; fix or remove the rules and re-run'
  );
}

/**
 * An `errors[]` entry's text: `message`, else `short_msg`, else `long_msg`
 * — an `UnknownLanguageError` carries only the last two (1.176.1).
 */
function errorMessage(entry: unknown): string | undefined {
  return getString(entry, 'message') ?? getString(entry, 'short_msg') ?? getString(entry, 'long_msg');
}

/** `type: message` per `errors[]` entry (`type` may be a string or `[name, …]`). */
function describeErrors(errors: readonly unknown[]): string[] {
  return errors.map((entry) => {
    const rawType = getProp(entry, 'type');
    const type = typeof rawType === 'string' ? rawType : Array.isArray(rawType) ? String(rawType[0]) : 'error';
    const message = errorMessage(entry) ?? '(no message)';
    return `${type}: ${message.split(/\r?\n/)[0] ?? message}`;
  });
}

/** See `SemgrepReportCheck.rule_config_error`: the refused rule configuration, described, or null. */
function ruleConfigError(errors: readonly unknown[]): string | null {
  if (errors.length === 0) return null;
  const described: string[] = [];
  let rules = 0;
  for (const entry of errors) {
    const type = errorType(entry) ?? '';
    const text = (errorMessage(entry) ?? '').split(/\r?\n/)[0] ?? '';
    if (/rule|language/i.test(type)) {
      rules += 1;
      described.push(`${type}: ${text}`);
    } else if (type === 'SemgrepError') {
      described.push(`${type}: ${text}`);
    } else {
      return null;
    }
  }
  return rules > 0 ? clip(described.join('; ')) : null;
}

/** An `errors[]` entry's type name (`type` may be a string or `[name, …]`), or null. */
function errorType(entry: unknown): string | null {
  const rawType = getProp(entry, 'type');
  return typeof rawType === 'string' ? rawType : Array.isArray(rawType) && typeof rawType[0] === 'string' ? rawType[0] : null;
}

/**
 * Whether a file an error names can be a scan target (the module comment): any
 * non-YAML file; a YAML file only inside the scanned project.
 */
function canBeTarget(file: string, projectPath: string | undefined): boolean {
  if (!/\.ya?ml$/i.test(file)) return true;
  if (!isAbsolute(file)) return !file.split(/[\\/]/).includes('..');
  if (projectPath === undefined) return false;
  const rel = relativePath(resolvePath(projectPath), resolvePath(file));
  return rel.length > 0 && !rel.split(/[\\/]/).includes('..') && !isAbsolute(rel);
}

/**
 * One `errors[]` entry as a per-file problem, or null when it is not: a
 * config/rule error type (whatever file it names — the module comment), no
 * target file named, or a YAML file outside the project (a rule file). The
 * file comes from the entry's `path`, else its first span, else the location
 * list inside a `["PartialParsing", [...]]` type. The message is its first
 * line.
 */
function perFileError(entry: unknown, projectPath: string | undefined): PartialParse | null {
  const type = errorType(entry);
  if (type === null || CONFIG_ERROR_TYPE.test(type)) return null;
  const file = targetFileOf(entry, getProp(entry, 'type'));
  if (file === null || !canBeTarget(file, projectPath)) return null;
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
function perFileErrors(errors: readonly unknown[], projectPath: string | undefined): PartialParse[] | null {
  const out: PartialParse[] = [];
  for (const entry of errors) {
    const p = perFileError(entry, projectPath);
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
  projectPath: string | undefined,
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
    const p = perFileError(entry, projectPath);
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
