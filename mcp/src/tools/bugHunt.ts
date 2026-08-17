/**
 * `bug_hunt` — bug-focused Semgrep scan using curated rule packs.
 *
 * Same shell-out pattern as `scan_sast` but with `--config=p/r2c-bug-scan`
 * and `--config=p/security-audit` instead of `--config=auto`. The
 * post-processing step re-tags findings so they land in the `bug` category
 * (instead of whatever the semgrep metadata says), so the model can ask for
 * "bug-category findings" via resources and get the right slice.
 *
 * `p/r2c-bug-scan` replaces the original `p/bugs`, which was retired from
 * Semgrep's registry (`https://semgrep.dev/c/p/bugs` now 404s) — see the
 * bug_hunt fix report. Registry packs can go away at any time, and a dead
 * `--config=` does not fail gracefully on its own: Semgrep aborts the WHOLE
 * invocation, including any *other* pack passed alongside it, and reports
 * the failure only inside the JSON's `errors[]` array. This file reads that
 * array (`semgrepConfigFailure.ts`) and re-runs with whatever packs still
 * resolve, so one retirement degrades coverage instead of erasing it — and
 * never lets a run that scanned nothing get reported as a clean bug report.
 *
 * `p/r2c-bug-scan`'s own content is Python-heavy (32 of 44 rules) and thin
 * for JS/TypeScript (3 rules, none of which are the race/null/off-by-one/
 * leak/error-handling classes the tool's category vocabulary names) — see
 * `title`/`description` below, which say this to the model reading them
 * rather than only in this comment.
 *
 * `missing_tools` entries stay bare (`'semgrep'`), never pack-qualified
 * (`'semgrep:p/r2c-bug-scan'`): the dashboard's `TOOL_CATEGORIES` map
 * (`dashboard/types.ts`) and every other reader of `missing_tools` key off
 * literal, installable tool names, and a colon-qualified name has no entry
 * there — it falls back to rendering itself as its own "category", producing
 * `MISSING semgrep:p/r2c-bug-scan — semgrep:p/r2c-bug-scan findings are NOT
 * in these numbers`. Which pack failed and why is real, useful detail, but
 * it belongs on the `semgrep` `tools_run` entry's `reason` (free text, meant
 * for exactly this) rather than smuggled through a field every consumer
 * assumes is a bare tool name.
 */

import { join } from 'node:path';
import { z } from 'zod';
import { semgrepParser } from '../runners/scannerParsers/semgrep.js';
import { runProcess, type ProcessRunResult } from '../runners/processRunner.js';
import {
  AllowDirty,
  AutoFix,
  Force,
  ProjectPath,
  SeverityMin,
} from '../schemas.js';
import { computeFingerprint } from '../fingerprint/findingFingerprint.js';
import type {
  Category,
  Finding,
  ToolRun,
} from '../types.js';
import {
  type ParserOutput,
  type ScannerParser,
} from '../runners/scannerParsers/index.js';
import { registerToolModule } from './index.js';
import {
  ensureReportDir,
  readJsonSafe,
  scannerAvailable,
} from './scanHelpers.js';
import {
  describeConfigFailures,
  findConfigDownloadFailures,
  survivingPacks,
  type ConfigDownloadFailure,
} from './semgrepConfigFailure.js';
import {
  makeScanTool,
  type ScannerInvocation,
} from './scanToolFactory.js';

/**
 * The rule packs `bug_hunt` runs, in the order passed to `--config=`.
 * Exported so tests can assert against the real, current list instead of
 * duplicating the literal pack names.
 */
export const BUG_HUNT_PACKS: readonly string[] = ['p/r2c-bug-scan', 'p/security-audit'];

const BUG_SUBCATEGORIES = new Set([
  'race_condition',
  'null_safety',
  'edge_case',
  'error_handling',
  'memory_leak',
  'off_by_one',
]);

/**
 * Wraps the semgrep parser to re-tag every finding as `category=bug` and
 * normalise the subcategory to the BUG_SUBCATEGORIES vocabulary when
 * possible. Fingerprints are recomputed because the original parser ran
 * with `category=security`/`quality`/etc — but tool, rule_id, file_path,
 * line range and snippet are unchanged, so the fingerprint identity stays
 * stable across `bug_hunt` invocations.
 */
const bugCategoryParser: ScannerParser = {
  name: semgrepParser.name,
  parse(input, ctx): ParserOutput {
    const out = semgrepParser.parse(input, ctx);
    const recategorised: Finding[] = out.findings.map((f) => recategoriseAsBug(f));
    return { findings: recategorised, cves: out.cves };
  },
};

function recategoriseAsBug(f: Finding): Finding {
  const category: Category = 'bug';
  const subcategory = mapSubcategory(f.rule_id ?? '', f.subcategory);
  const refingerprintInput: Parameters<typeof computeFingerprint>[0] = { tool: f.tool };
  if (f.rule_id !== undefined) refingerprintInput.rule_id = f.rule_id;
  if (f.file_path !== undefined) refingerprintInput.file_path = f.file_path;
  if (f.line_start !== undefined) refingerprintInput.line_start = f.line_start;
  if (f.line_end !== undefined) refingerprintInput.line_end = f.line_end;
  if (f.snippet !== undefined) refingerprintInput.snippet = f.snippet;
  // Fingerprint inputs are unchanged compared to the security parser, so the
  // hash is stable. Compute once for consistency with the type discipline.
  const fingerprint = computeFingerprint(refingerprintInput);
  return { ...f, category, subcategory, fingerprint };
}

function mapSubcategory(ruleId: string, existing: string | undefined): string | undefined {
  const lowered = ruleId.toLowerCase();
  if (/(race|concurren|thread.safety)/.test(lowered)) return 'race_condition';
  if (/(null|undefined|nullable|none-check)/.test(lowered)) return 'null_safety';
  if (/(off.by.one|boundary|index.out)/.test(lowered)) return 'off_by_one';
  if (/(leak|unreleased|unclosed|disposed)/.test(lowered)) return 'memory_leak';
  if (/(error.handling|swallow|catch.all|exception)/.test(lowered)) return 'error_handling';
  if (/(edge.case|edge|empty.input|boundary)/.test(lowered)) return 'edge_case';
  return existing && BUG_SUBCATEGORIES.has(existing) ? existing : existing;
}

registerToolModule(
  makeScanTool({
    name: 'bug_hunt',
    title: 'Bug hunt (Semgrep p/r2c-bug-scan + p/security-audit; Python-strong, JS/TS-thin)',
    description:
      'Semgrep with p/r2c-bug-scan (44 correctness rules: 32 Python, 5 Go, 4 Java, 3 JS/TS) ' +
      'plus p/security-audit. Coverage is uneven by language: strong for Python (mutating a ' +
      'collection while iterating it, unchecked subprocess results, mutable default arguments, ' +
      'and more); thin for JavaScript/TypeScript, where the only 3 rules are a dead-store check, ' +
      '`.replaceAll` browser-compatibility, and literal `x==x` — none of them race conditions, ' +
      'null/undefined safety, off-by-one, memory leaks, or swallowed error handling. On a JS/TS ' +
      'project, expect few or no findings from this tool specifically; an empty result here is ' +
      'not evidence the project has no bugs, only that this pack does not look for most bug ' +
      'shapes in this language — pair with `scan_sast` or a manual review for JS/TS logic bugs. ' +
      'Findings are categorised as `bug`, with subcategories (race_condition, null_safety, ' +
      'edge_case, error_handling, memory_leak, off_by_one) attached where the matching rule\'s ' +
      'own id says so. If a configured pack is retired from the Semgrep registry, the scan ' +
      're-runs with whichever packs still resolve and reports the gap via `missing_tools` ' +
      'instead of silently scanning nothing.',
    scan_type: 'bugs',
    category: 'bug',
    inputSchema: {
      project_path: ProjectPath,
      severity_min: SeverityMin,
      auto_fix: AutoFix,
      allow_dirty: AllowDirty,
      categories: z
        .array(z.string())
        .optional()
        .describe('Restrict to these bug subcategories (e.g. race_condition, null_safety).'),
      force: Force,
    },
    invoke: async (input, ctx): Promise<ScannerInvocation> => {
      const reportDir = ensureReportDir(ctx.projectPath, ctx.scanId, 'bugs');
      const tools_run: ToolRun[] = [];
      const missing_tools: string[] = [];
      const parser_inputs: ScannerInvocation['parser_inputs'] = [];

      const semgrepBin = await scannerAvailable('semgrep');
      if (!semgrepBin) {
        tools_run.push({ name: 'semgrep', status: 'skipped', reason: 'not_installed' });
        missing_tools.push('semgrep');
        return {
          outcome: 'completed',
          tools_run,
          missing_tools,
          parser_inputs,
          report_paths: [reportDir],
        };
      }

      const outFile = join(reportDir, 'bugs.json');
      const runWithPacks = (packs: readonly string[]): Promise<ProcessRunResult> => {
        const args = packs.map((pack) => `--config=${pack}`);
        args.push('--json', '--quiet', '--output', outFile);
        if (input.auto_fix === true) args.push('--autofix');
        args.push(ctx.projectPath);
        return runProcess({
          command: 'semgrep',
          args,
          cwd: ctx.projectPath,
          env: ctx.scriptEnv,
          signal: ctx.signal,
          onLog: ctx.onLog,
        });
      };
      // A gap that survives every retry attempt: nothing scanned, and that
      // must never be reported as a clean bug report. `outcome: 'completed'`
      // matches scan_sast's convention for an expected, named gap — the
      // signal lives in `missing_tools` / `coverage`, not in `outcome`.
      // `missing_tools` gets the bare tool name only (never
      // `semgrep:<pack>`) — see the header comment for why; the pack-level
      // detail lives in the `reason` string below instead.
      const reportGap = (failures: readonly ConfigDownloadFailure[]): ScannerInvocation => {
        tools_run.push({
          name: 'semgrep',
          status: 'failed',
          reason: `no configured pack could be scanned (${describeConfigFailures(failures)})`,
        });
        missing_tools.push('semgrep');
        return {
          outcome: 'completed',
          tools_run,
          missing_tools,
          parser_inputs,
          report_paths: [reportDir],
        };
      };

      const result = await runWithPacks(BUG_HUNT_PACKS);
      const raw = readJsonSafe(outFile);
      const failures = findConfigDownloadFailures(raw);

      if (failures.length === 0) {
        // The ordinary case: every configured pack resolved. Exit code /
        // outcome alone decide ok-ness here, same as before — there is
        // nothing in errors[] casting doubt on the result.
        if (raw) parser_inputs.push({ parser: bugCategoryParser, input: raw });
        const ok = result.outcome === 'completed' || result.exitCode === 1;
        tools_run.push({ name: 'semgrep', status: ok ? 'ok' : 'failed' });
        return {
          outcome: ok ? 'completed' : result.outcome,
          tools_run,
          missing_tools,
          parser_inputs,
          report_paths: [reportDir],
        };
      }

      // At least one configured pack failed to download (registry
      // retirement, outage, typo). A single bad `--config=` aborts the
      // WHOLE invocation — `raw` above has empty results/paths.scanned even
      // for packs that resolved fine — so it cannot be reused as-is. Re-run
      // with whatever survives rather than reporting a scan that covered
      // nothing.
      const survivors = survivingPacks(BUG_HUNT_PACKS, failures);
      if (survivors.length === 0 || survivors.length === BUG_HUNT_PACKS.length) {
        // Nothing to retry with (every pack failed), or the failure(s)
        // could not be attributed to a specific configured pack (so a retry
        // would just reproduce the same result).
        return reportGap(failures);
      }

      const retry = await runWithPacks(survivors);

      // A cancelled/timed-out/oversized retry never produced a genuine
      // second attempt — the child was killed before (or while) writing
      // `--output`, so `outFile` may still hold attempt one's STALE content,
      // or nothing at all. Reading that as "the retry also hit a download
      // failure" would duplicate attempt one's own failure, and forcing
      // `outcome: 'completed'` below would misreport a cancelled/timed-out
      // run as having finished normally — the same family of untruth this
      // whole fix exists to close. Propagate the retry's real outcome
      // instead, and report only what attempt one actually found (never
      // touching `outFile` in this branch at all).
      if (retry.outcome !== 'completed' && retry.outcome !== 'failed') {
        tools_run.push({
          name: 'semgrep',
          status: 'failed',
          reason:
            `retry with ${survivors.join(', ')} did not finish (${retry.outcome}) — ` +
            `original gap: ${describeConfigFailures(failures)}`,
        });
        missing_tools.push('semgrep');
        return {
          outcome: retry.outcome,
          tools_run,
          missing_tools,
          parser_inputs,
          report_paths: [reportDir],
        };
      }

      const retryRaw = readJsonSafe(outFile);
      const retryFailures = findConfigDownloadFailures(retryRaw);
      const retryOk =
        retryFailures.length === 0 && (retry.outcome === 'completed' || retry.exitCode === 1);

      if (!retryOk) {
        // The retry ran to a real exit but didn't help either (network
        // flake, or the "survivor" just got retired too) — combine every
        // failure we saw and refuse to trust either attempt's output.
        return reportGap([...failures, ...retryFailures]);
      }

      if (retryRaw) parser_inputs.push({ parser: bugCategoryParser, input: retryRaw });
      tools_run.push({
        name: 'semgrep',
        status: 'ok',
        reason: `ran with ${survivors.join(', ')} only — ${describeConfigFailures(failures)}`,
      });
      missing_tools.push('semgrep');
      return {
        outcome: 'completed',
        tools_run,
        missing_tools,
        parser_inputs,
        report_paths: [reportDir],
      };
    },
  }),
);
