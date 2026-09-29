/**
 * Running a scanner over an explicit list of files: split below the command-
 * line budget (`argBatches.ts`), one report file per batch, every batch
 * checked on its own, results merged.
 *
 * The files always follow `--`, so a file named `-x.py` is a file — without
 * it Semgrep 1.176.1 answers `unknown option '-s'` (measured) and scans
 * nothing. They are passed as separate arguments with no shell in between, so
 * spaces and non-ASCII characters arrive intact.
 *
 * A batch whose check fails makes the whole tool `failed` with the batch's
 * reason; the results it did write are still kept, because they are real.
 * Nothing about one batch is ever inferred from another. A batch the check
 * calls partial (Semgrep: some files only partly parsed —
 * `semgrepReport.ts`) is not a failure: the run is `ok`, its reason and
 * `partially_parsed` name those files, and the result carries them in
 * `partial` for the caller to list the scanner missing as well. So is a
 * Semgrep batch whose only errors are rules that did not load (the judge's
 * `rules_not_loaded`): the rules go to `failed_rules` and `failedRules`,
 * once each however many batches reported them.
 */

import { rmSync } from 'node:fs';
import { join } from 'node:path';
import type { FailedRule, PartialParse, ToolRun } from '../types.js';
import { readJsonSafe } from '../tools/scanHelpers.js';
import { batchArgs } from './argBatches.js';
import { runProcess, type ProcessOutcome } from './processRunner.js';
import { semgrepSpawn } from './semgrepRun.js';
import { asArray, getProp, getString, parseInputAsJson } from './scannerParsers/index.js';
import {
  checkSemgrepReport,
  describeNoRuleLoaded,
  describePartialParse,
  describeRulesNotLoaded,
  pythonUtf8Env,
  withPluginPackFixpoint,
  type PluginPackFixpoint,
} from './semgrepReport.js';
import { localRuleIdNormalizer, noRuleLoaded, type RuleIdContext } from './semgrepRuleIds.js';
import { toRelativeIfPossible } from './scannerParsers/index.js';

export interface BatchCheck {
  ok: boolean;
  reason?: string;
  /** Files the batch's report says were analysed, when the scanner reports it. */
  scanned?: number;
  /**
   * Files this batch could only partly analyse, as the report names them —
   * the batch is then partial, not failed (`ok` is false only for a failure).
   */
  partial?: PartialParse[];
  /** Rules this batch did not load while its others ran — partial, not failed. */
  failedRules?: FailedRule[];
  /** A failure because the rule configuration was refused (`ToolRun.rule_config_error`). */
  ruleConfigError?: boolean;
  /** Semgrep: the plugin's pack's own fixpoint timeouts — its gap, never this batch's partial. */
  packFixpoint?: PluginPackFixpoint;
}

export interface FileBatchScanOptions {
  /** Name in `tools_run`. */
  name: string;
  command: string;
  /** Arguments before the report path and the files, e.g. `['--config=auto', '--json']`. */
  args: readonly string[];
  /** Arguments that name the report file, e.g. `(f) => ['--output', f]`. */
  reportArgs: (reportFile: string) => string[];
  files: readonly string[];
  cwd: string;
  reportDir: string;
  /** Report file name prefix: `<prefix>-<n>.json`. */
  reportPrefix: string;
  env: NodeJS.ProcessEnv;
  signal: AbortSignal;
  onLog?: (line: string) => void;
  /** Did this batch's run count? */
  check: (args: { raw: string | null; exitCode: number | null; outcome: ProcessOutcome; targets: number }) => BatchCheck;
  /**
   * Judge "scanned something" over the whole run rather than per batch: a
   * batch of files no rule applies to scans 0 on its own, which proves
   * nothing when another batch of the same run scanned files. A run that
   * scanned nothing at all is `skipped`, with `nothingScanned` set.
   */
  requireScanned?: boolean;
  /**
   * Whether the rules the batches did not load are ALL the run had (no
   * registry pack, every local rule): the run is then `failed` — nothing was
   * scanned for — never `ok` with a gap (fix round 3, M-1).
   */
  noRuleLoaded?: (failedRules: readonly FailedRule[]) => boolean;
}

export interface FileBatchScanResult {
  toolRun: ToolRun;
  /** Every report that parsed, including those of failed batches. */
  reports: string[];
  reportFiles: string[];
  cancelled: boolean;
  /** `requireScanned`, and no batch scanned a single file (`toolRun` is `skipped`). */
  nothingScanned: boolean;
  /**
   * Files some batch could only partly analyse (relative to `cwd`). Non-empty
   * on an `ok` run means partial coverage: the caller lists the scanner in
   * `missing_tools` too.
   */
  partial: PartialParse[];
  /** Rules some batch did not load, once each. Non-empty on an `ok` run: partial coverage, as `partial`. */
  failedRules: FailedRule[];
}

export async function scanFileBatches(opts: FileBatchScanOptions): Promise<FileBatchScanResult> {
  const probeReport = join(opts.reportDir, `${opts.reportPrefix}-000.json`);
  const batches = batchArgs(opts.files, {
    command: opts.command,
    fixedArgs: [...opts.args, ...opts.reportArgs(probeReport), '--'],
  });
  const reports: string[] = [];
  const reportFiles: string[] = [];
  const failures: string[] = [];
  let configFailures = 0;
  const partial: PartialParse[] = [];
  const failedRules: FailedRule[] = [];
  const packFiles: PartialParse[] = [];
  let packFunctions = 0;
  let cancelled = false;
  let scanned = 0;

  for (const [i, batch] of batches.entries()) {
    if (opts.signal.aborted) {
      cancelled = true;
      break;
    }
    const reportFile = join(opts.reportDir, `${opts.reportPrefix}-${String(i + 1).padStart(3, '0')}.json`);
    rmSync(reportFile, { force: true });
    const run = await runProcess({
      command: opts.command,
      args: [...opts.args, ...opts.reportArgs(reportFile), '--', ...batch],
      cwd: opts.cwd,
      env: opts.env,
      signal: opts.signal,
      onLog: opts.onLog,
    });
    if (run.outcome === 'cancelled') cancelled = true;
    const raw = readJsonSafe(reportFile);
    if (raw !== null && parseInputAsJson(raw) !== null) {
      reports.push(raw);
      reportFiles.push(reportFile);
    }
    const verdict = opts.check({
      raw,
      exitCode: run.exitCode,
      outcome: run.outcome,
      // With requireScanned the count is judged below, over every batch.
      targets: opts.requireScanned === true ? 0 : batch.length,
    });
    scanned += verdict.scanned ?? 0;
    for (const p of verdict.partial ?? []) {
      const file = toRelativeIfPossible(p.file, opts.cwd);
      if (!partial.some((q) => q.file === file && q.type === p.type)) partial.push({ ...p, file });
    }
    // The plugin's pack's own gap: one file is in one batch, so no two batches name it.
    if (verdict.packFixpoint !== undefined) {
      packFunctions += verdict.packFixpoint.functions;
      for (const p of verdict.packFixpoint.files) packFiles.push({ ...p, file: toRelativeIfPossible(p.file, opts.cwd) });
    }
    for (const r of verdict.failedRules ?? []) if (!failedRules.some((q) => q.rule_id === r.rule_id)) failedRules.push(r);
    if (!verdict.ok) {
      const label = batches.length > 1 ? `batch ${i + 1}/${batches.length}: ` : '';
      failures.push(`${label}${verdict.reason ?? 'failed'}`);
      if (verdict.ruleConfigError === true) configFailures += 1;
    }
    if (cancelled) break;
  }

  const described = `${opts.files.length} file(s)${batches.length > 1 ? ` in ${batches.length} batches` : ''}`;
  if (failures.length === 0 && !cancelled && failedRules.length > 0 && opts.noRuleLoaded?.(failedRules) === true) {
    return {
      toolRun: {
        name: opts.name,
        status: 'failed',
        reason: `${described}: ${describeNoRuleLoaded(failedRules)}`,
        failed_rules: failedRules,
        rule_config_error: true,
      },
      reports,
      reportFiles,
      cancelled,
      nothingScanned: false,
      partial,
      failedRules,
    };
  }
  if (opts.requireScanned === true && !cancelled && failures.length === 0 && batches.length > 0 && scanned === 0) {
    return {
      toolRun: {
        name: opts.name,
        status: 'skipped',
        reason:
          `${described}: ${opts.name} scanned none of them — no rule applies to these files, ` +
          'or the rules loaded nothing',
      },
      reports,
      reportFiles,
      cancelled,
      nothingScanned: true,
      partial,
      failedRules,
    };
  }
  let toolRun: ToolRun;
  if (failures.length === 0 && !cancelled) {
    toolRun = {
      name: opts.name,
      status: 'ok',
      reason: [
        `${described} scanned`,
        ...(failedRules.length > 0 ? [describeRulesNotLoaded(failedRules, scanned)] : []),
        ...(partial.length > 0 ? [describePartialParse(partial, 'findings in the unparsed spans may be missing')] : []),
      ].join('; '),
    };
    if (partial.length > 0) toolRun.partially_parsed = partial;
    if (failedRules.length > 0) toolRun.failed_rules = failedRules;
    // Not in `partial`: the plugin's pack's gap is never the caller's missing tool.
    if (packFunctions > 0) toolRun = withPluginPackFixpoint(toolRun, { files: packFiles, functions: packFunctions });
  } else {
    toolRun = {
      name: opts.name,
      status: 'failed',
      reason: cancelled && failures.length === 0 ? 'cancelled' : `${described}: ${failures.join('; ')}`,
    };
    // Every batch failed on its rule configuration: installed, the rules are the problem.
    if (!cancelled && failures.length > 0 && configFailures === failures.length) toolRun.rule_config_error = true;
  }
  return { toolRun, reports, reportFiles, cancelled, nothingScanned: false, partial, failedRules };
}

/** `scanFileBatches` for Semgrep: `--json --quiet --output <f> -- files`, UTF-8 mode, GC3 check. */
export function semgrepOnFiles(args: {
  configArgs: readonly string[];
  files: readonly string[];
  cwd: string;
  reportDir: string;
  env: NodeJS.ProcessEnv;
  signal: AbortSignal;
  onLog?: (line: string) => void;
  /**
   * The configs the run passed, and how its rule ids are stored
   * (`runners/semgrepRuleIds.ts`): a rule that did not load is named as its
   * findings are, and a run in which none loaded is failed. `loadedFrom`
   * narrows "none loaded" to the configs that make the scan (scan_sast's
   * project and registered rules — not the plugin's LLM pack); default: all.
   * `packCheckIds`: the plugin's packs' rules as Semgrep spells them in this
   * run (`semgrepRuleIds.ts#pluginPackCheckIds`), whose own fixpoint
   * timeouts are the pack's gap (`semgrepReport.ts`);
   * `nonPackTaintRules`: whether any other config may hold a taint rule.
   */
  rules?: {
    configs: readonly string[];
    ctx: RuleIdContext;
    loadedFrom?: readonly string[];
    packCheckIds?: ReadonlySet<string>;
    nonPackTaintRules?: boolean;
  };
}): Promise<FileBatchScanResult> {
  const rules = args.rules;
  const ruleIdOf = rules === undefined ? undefined : localRuleIdNormalizer(rules.configs, rules.ctx);
  const pack = {
    ...(rules?.packCheckIds !== undefined ? { pluginPackCheckIds: rules.packCheckIds } : {}),
    ...(rules?.nonPackTaintRules !== undefined ? { nonPackTaintRules: rules.nonPackTaintRules } : {}),
  };
  return scanFileBatches({
    name: 'semgrep',
    // The command and its UTF-8 environment, from the one helper (runners/semgrepRun.ts).
    ...semgrepSpawn(args.env),
    args: [...args.configArgs, '--json', '--quiet'],
    reportArgs: (f) => ['--output', f],
    files: args.files,
    cwd: args.cwd,
    reportDir: args.reportDir,
    reportPrefix: 'sast',
    signal: args.signal,
    ...(args.onLog ? { onLog: args.onLog } : {}),
    // The shared judge's `partial` verdict is no failure of the batch, and
    // neither are rules that did not load while the others ran.
    check: (args) => {
      const c = checkSemgrepReport({ ...args, ...(ruleIdOf !== undefined ? { ruleIdOf } : {}), ...pack });
      const packFixpoint = c.plugin_pack_fixpoint !== undefined ? { packFixpoint: c.plugin_pack_fixpoint } : {};
      if (c.verdict === 'partial' && c.partial !== undefined) {
        return { ok: true, scanned: c.scanned, partial: c.partial, ...packFixpoint };
      }
      if (c.rules_not_loaded !== undefined && c.rules_not_loaded.length > 0) {
        return { ok: true, scanned: c.scanned, partial: c.partial ?? [], failedRules: c.rules_not_loaded, ...packFixpoint };
      }
      return {
        ok: c.ok,
        scanned: c.scanned,
        ...packFixpoint,
        ...(c.rule_config_error !== undefined
          ? { reason: `the rule configuration did not load — ${c.rule_config_error} (semgrep exit ${String(args.exitCode)})` }
          : c.reason !== undefined
            ? { reason: c.reason }
            : {}),
        ...(c.rule_config_error !== undefined ? { ruleConfigError: true } : {}),
      };
    },
    requireScanned: true,
    ...(rules !== undefined
      ? { noRuleLoaded: (failed: readonly FailedRule[]) => noRuleLoaded(rules.loadedFrom ?? rules.configs, failed, rules.ctx) }
      : {}),
  });
}

/** `scanFileBatches` for Bandit: `-f json -o <f> -q -- files`. */
export function banditOnFiles(args: {
  files: readonly string[];
  cwd: string;
  reportDir: string;
  env: NodeJS.ProcessEnv;
  signal: AbortSignal;
  onLog?: (line: string) => void;
}): Promise<FileBatchScanResult> {
  return scanFileBatches({
    name: 'bandit',
    command: 'bandit',
    args: ['-f', 'json', '-q'],
    reportArgs: (f) => ['-o', f],
    files: args.files,
    cwd: args.cwd,
    reportDir: args.reportDir,
    reportPrefix: 'bandit',
    env: pythonUtf8Env(args.env),
    signal: args.signal,
    ...(args.onLog ? { onLog: args.onLog } : {}),
    check: checkBanditReport,
  });
}

/**
 * Bandit exits 0 (clean) or 1 (issues); its report lists files it could not
 * analyse under `errors`, which — like Semgrep's — means the run did not
 * cover what it was given.
 */
export function checkBanditReport(args: {
  raw: string | null;
  exitCode: number | null;
  outcome: ProcessOutcome;
}): BatchCheck {
  if (args.outcome === 'cancelled' || args.outcome === 'timed_out' || args.outcome === 'output_too_large') {
    return { ok: false, reason: `bandit did not finish (${args.outcome})` };
  }
  if (args.exitCode !== 0 && args.exitCode !== 1) return { ok: false, reason: `exit ${String(args.exitCode)}` };
  const root = args.raw === null ? null : parseInputAsJson(args.raw);
  if (root === null || typeof root !== 'object') return { ok: false, reason: 'bandit wrote no JSON report' };
  const errors = asArray(getProp(root, 'errors')).map(
    (e) => `${getString(e, 'filename') ?? '?'}: ${getString(e, 'reason') ?? 'error'}`,
  );
  if (errors.length > 0) return { ok: false, reason: `${errors.length} file(s) not analysed: ${errors.join('; ')}` };
  return { ok: true };
}
