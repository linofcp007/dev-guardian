/**
 * `scan_sast` — Semgrep static analysis, plus Bandit when Python is present,
 * gosec when Go is (`runners/gosecRun.ts`: through the Go toolchain, which
 * loads — and may download — the project's modules), cppcheck's error and
 * warning checks when C or C++ is (`runners/cppcheckRun.ts`), Psalm's taint
 * analysis when PHP is (`runners/psalmRun.ts`: never the project's own
 * configuration or autoloader), and the .NET SDK's security analyzers when
 * the project is .NET.
 *
 * Invokes Semgrep directly (no shell script), writing the JSON report to
 * `.guardian/reports/sast-<short-scan-id>/sast.json`.
 *
 * ---- The project's own rules are part of the scan --------------------
 *
 * `init_project` installs `configs/semgrep/base.yml` into a project as
 * `.semgrep.yml` and calls it the baseline SAST config. This tool used to run
 * `--config=auto` and nothing else, and `--config=auto` does not load it —
 * measured on semgrep 1.164.0 against a project holding that pack plus one
 * line of `<?php echo $_GET['name'];`, `--config=auto` reports 0 findings
 * where `--config=<the file>` reports 1.
 *
 * The rule sources come from ONE plan (`runners/semgrepConfigs.ts`,
 * `planSemgrepConfigs`), used for both the argv and the cache key — they were
 * built separately, and could drift.
 *
 * ---- Global Constraint 3, for every Semgrep run -----------------------
 *
 * An exit code of 0 or 1 is necessary and never sufficient
 * (`runners/semgrepReport.ts`): a config that did not load scans nothing, a
 * file that did not parse is only partly analysed. Every run — native or the
 * Docker fallback — is judged by its report (the shared judge's verdict): no
 * report, `paths.scanned` empty, or a non-empty `errors[]` is not complete. A
 * run that scanned nothing at all (no file any rule applies to) is `skipped`
 * and listed in `missing_tools`. A run whose only errors are per-file ones (a
 * warn-level `PartialParsing` — PHP's `const NAMESPACE` on 1.176.1 — a syntax
 * error in one file) is PARTIAL: `ok` and listed missing, the files named in
 * its reason and `partially_parsed` (what the CI gate's
 * `--accept-partial-parse` matches). So is a run whose taint analysis gave
 * up on a function (`time.fixpoint_timeouts`, never in `errors[]`): the file
 * is named with type `Fixpoint timeout`, which the gate never accepts — the
 * same as a per-rule `Timeout` — unless the plugin's LLM pack is its only
 * rule: that is the pack's gap, noted and kept for history under its own
 * type, never the run's partial verdict (`PluginPackFixpoint`). An engine
 * that cannot report those (before 1.170) carries a named note instead.
 * Anything fatal is `failed` with the
 * errors as its reason — except rules that did not load while the others
 * ran (a typo'd pattern in the project's `.semgrep.yml` or a registered
 * rule: exit 2, `paths.scanned` filled, the judge's `rules_not_loaded`).
 * That is a narrower gap, as in bug_hunt: `ok` and missing, the rules in
 * `failed_rules`, never coverage none and "install semgrep" for a Semgrep
 * that ran, and never a row the open set skips; the other rules' findings
 * resolve and the broken rule's earlier ones stay open, not re-measured
 * (`history/runCompare.ts`). The findings such a run did report are still
 * recorded — they are real.
 *
 * ---- .NET: the SDK's own security analyzers, read from SARIF -----------
 *
 * .NET SAST used to exist only for projects referencing the unmaintained
 * Security Code Scan, and scraped `dotnet build --verbosity:diag` stdout —
 * which exceeds the 5 MB output cap on real projects and killed the run. It
 * now restores every root solution/project in locked mode, builds it with the
 * SDK's own security analyzers switched on, and reads the compiler's SARIF
 * per project and target framework (`dotnetSarif.ts`) — see
 * `runDotnetAnalyzers` for the measured reasons behind each switch. Security
 * Code Scan, when the project references it, reports through the same
 * SARIF. `dotnet restore`/`build` EXECUTE the project's MSBuild — the
 * description says so.
 *
 * ---- Telemetry, and `local_only` -------------------------------------
 *
 * `--config=auto` fetches its rule set from the Semgrep registry and **sends
 * usage metrics to Semgrep Inc. as a condition of doing so**: passing
 * `--metrics=off` alongside it fails outright. `local_only: true` is the
 * alternative — no registry, `--metrics=off`, and only rules already on disk.
 * The choice is recorded on the scan (`local_only`), so `create_fix_pr` can
 * re-scan a fix with the same rules that found the target.
 *
 * ---- The scanners run side by side ----------------------------------
 *
 * Semgrep, Bandit, gosec, cppcheck, Psalm and the .NET analyzers ran one
 * after another, so a project in several languages waited for their sum;
 * they now run side by side (`runners/scannerPasses.ts`), at most
 * `GUARDIAN_MAX_PARALLEL_SCANNERS` (default 3) at once, each gathering its
 * own results, merged in that order. Two write into what another reads, and
 * wait for Semgrep: `--autofix` (then every other pass), and the .NET build,
 * whose `obj/` and `bin/` would appear in the tree Semgrep walks.
 *
 * ---- `scope`, and `.guardianignore` -------------------------------------
 *
 * With `scope` (`platform/scope.ts`), Semgrep and Bandit get the scoped files
 * as explicit targets (`runners/fileBatchScan.ts`: batched below the command-
 * line limit, every batch judged on its own report). The Docker fallback
 * mounts the whole project, so without a native Semgrep a scoped scan is a
 * named gap rather than a silently widened one. The .NET analyzers run inside
 * a build of the whole project: for a scope they are `skipped` as
 * project-level, and a gap whenever .NET sources are in the scope. Bandit
 * gets the whole-project run's `--ini` either way (`banditIni`). gosec reads
 * packages, not files: it gets the directories of the scope's Go files, and
 * the factory keeps the findings inside the scope. Unscoped, the project's
 * `.guardianignore` reaches Semgrep as `--exclude` and Bandit as `-x`
 * (`platform/guardianIgnore.ts`), and decides which package directories gosec
 * is handed; the factory filters the rest.
 */

import { lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, relative, resolve, sep } from 'node:path';
import { z } from 'zod';
import {
  classifyRestoreFailure,
  findDotnetTargets,
  planDotnetRestore,
  projectsForTarget,
  removeCreatedLockFiles,
} from '../deps/dotnetRestore.js';
import { gitSafetyFor } from '../platform/gitSafety.js';
import { banditExcludeArgs, listScannedFiles, semgrepExcludeArgs } from '../platform/guardianIgnore.js';
import { ScanScopeInput } from '../platform/scope.js';
import { banditOnFiles, checkBanditReport, semgrepOnFiles } from '../runners/fileBatchScan.js';
import { gosecOnPackages, isGoSource } from '../runners/gosecRun.js';
import { cppcheckSources, cppSources } from '../runners/cppcheckRun.js';
import { cppcheckParser } from '../runners/scannerParsers/cppcheck.js';
import { hasPhpSource, PSALM, psalmTaint } from '../runners/psalmRun.js';
import { maxParallelScanners, runScannerPasses, type ScannerPass } from '../runners/scannerPasses.js';
import { psalmParser } from '../runners/scannerParsers/psalm.js';
import { isWordPressProject } from '../runners/stackDetect.js';
import { banditParser } from '../runners/scannerParsers/bandit.js';
import { gosecParser } from '../runners/scannerParsers/gosec.js';
import { getProp, parseInputAsJson, toRelativeIfPossible } from '../runners/scannerParsers/index.js';
import { dotnetSarifParser, sarifSecurityRuleCount } from '../runners/scannerParsers/dotnetSarif.js';
import { semgrepParserFor } from '../runners/scannerParsers/semgrep.js';
import { runProcess, type ProcessRunResult } from '../runners/processRunner.js';
import { nameRepoConfig } from '../runners/repoConfig.js';
import { longDirsNote, metricsEnvProblem, runSemgrep as spawnSemgrep, semgrepErrorLine, semgrepScanFlags } from '../runners/semgrepRun.js';
import {
  localRuleIdNormalizer,
  mayHoldTaintRules,
  noRuleLoaded,
  pluginPackCheckIds,
  ruleIdsInFile,
} from '../runners/semgrepRuleIds.js';
import {
  buildSemgrepDockerArgs,
  CONTAINER_PROJECT_ROOT,
  DEFAULT_SEMGREP_IMAGE,
  fromContainerPath,
  toContainerPath,
} from '../runners/dockerScanner.js';
import {
  AllowDirty,
  AutoFix,
  Force,
  ProjectPath,
  SeverityMin,
} from '../schemas.js';
import type { PartialParse, ToolRun } from '../types.js';
import { hasFileWithExtension } from '../runners/projectFiles.js';
import {
  CONTAINER_PACKS_ROOT,
  hasDotnetProject,
  planSemgrepConfigs,
  PLUGIN_PACK_FILES,
  semgrepEngineNote,
} from '../runners/semgrepConfigs.js';
import {
  checkSemgrepReport,
  describeNoRuleLoaded,
  describePartialParse,
  describeRulesNotLoaded,
  pythonUtf8Env,
  semgrepEngineOf,
  withPluginPackFixpoint,
} from '../runners/semgrepReport.js';
import { legacyRegistrationNote, legacyRegistrationsNotApplied } from '../platform/customRules.js';
import { inspectProjectSemgrepConfigs } from '../platform/projectSemgrepConfig.js';
import { listProjectDir, presentInProject, readProjectTextOrUndefined } from '../platform/projectFs.js';
import { readSmallTextFile } from '../hooks/configFile.js';
import {
  applySemgrepCoverageGaps,
  describeTooLong,
  markMissing,
  PATH_TOO_LONG_TYPE,
  scannedNothingBecause,
  semgrepCoverageGaps,
  type SemgrepCoverageGaps,
} from '../runners/semgrepCoverageGaps.js';
import { registerToolModule } from './index.js';
import {
  ensureReportDir,
  readJsonSafe,
  scannerAvailable,
} from './scanHelpers.js';
import {
  makeScanTool,
  type InvokeContext,
  type ScannerInvocation,
} from './scanToolFactory.js';

/** The largest .NET solution, project or `.props` file read; a real one is well under this. */
const MAX_DOTNET_PROJECT_FILE_BYTES = 4 * 1024 * 1024;

/** How long one `dotnet build` of one target may take. */
const DOTNET_BUILD_TIMEOUT_MS = 10 * 60_000;

registerToolModule(
  makeScanTool({
    name: 'scan_sast',
    title: 'SAST scan (Semgrep)',
    description:
      "Semgrep with the registry rules, the project's own, register_custom_rules' and the plugin's web-JS, " +
      'mobile and LLM packs (`tools_run[].plugin_packs`: one that ran in part); Bandit for Python; gosec for ' +
      "Go, through the Go toolchain (it may download modules); cppcheck for C/C++; Psalm's taint analysis for PHP; for .NET, a " +
      'locked restore and `dotnet build` ' +
      "with the SDK analyzers, which runs the project's MSBuild. What a scanner could not process is partial " +
      'coverage. `tools_run[].honoured_config`: the project files that decided a run. local_only avoids the ' +
      'registry and its metrics.',
    scan_type: 'sast',
    category: 'security',
    supportsScope: true,
    // The cache key and the argv read the SAME plan (see the module comment).
    // `rulesProjectPath` is the scanned path, except when create_fix_pr
    // re-scans a worktree and needs the original project's rules.
    rulePacks: (input, { rulesProjectPath, plugin, projectPath }) =>
      planSemgrepConfigs(rulesProjectPath, plugin, input.local_only === true, projectPath).rulePacks,
    // `.guardian/scan.yml`'s Semgrep timeouts change what a run finds.
    cacheState: async (_input, { plugin, projectPath }) => {
      const flags = semgrepScanFlags(plugin.repoConfigFromRef?.root ?? projectPath);
      return { semgrep_flags: flags.args.join(' ') };
    },
    // 2.0.x custom rules outside the project are not run any more: say so on
    // every response, cached or not, not only in tools_run.
    configWarnings: (_input, { rulesProjectPath, plugin }) => {
      const note = legacyRegistrationNote(legacyRegistrationsNotApplied(plugin, rulesProjectPath));
      return note === null ? [] : [note];
    },
    inputSchema: {
      project_path: ProjectPath,
      severity_min: SeverityMin,
      auto_fix: AutoFix,
      allow_dirty: AllowDirty,
      force: Force,
      local_only: z
        .boolean()
        .optional()
        .describe(
          'Semgrep with rules on disk only, no metrics. With no project rules: skipped, not clean.',
        ),
      scope: ScanScopeInput,
    },
    invoke: async (input, ctx): Promise<ScannerInvocation> => {
      const reportDir = ensureReportDir(ctx.projectPath, ctx.scanId, 'sast');
      const autoFix = input.auto_fix === true;
      const localOnly = input.local_only === true;
      // What the scan reads, `.guardianignore` applied — listed once, when a pass needs it; gosec
      // still reads an ignored file of a kept package, and the factory drops its findings.
      let listing: Promise<readonly string[]> | null = null;
      const scanned = (): Promise<readonly string[]> =>
        (listing ??= ctx.exclusions !== null ? Promise.resolve(ctx.exclusions.keptFiles) : listScannedFiles(ctx.projectPath));

      // The scanners run side by side (see `runSastPasses`), in this order in `tools_run`. Semgrep's
      // --autofix rewrites the files the others read, and the .NET build writes obj/ and bin/ into
      // the tree Semgrep walks: each waits for Semgrep.
      const afterSemgrep = autoFix ? ['semgrep'] : [];
      let passes: ScannerPass[];
      if (ctx.scope !== null) {
        const files = ctx.scope.files;
        passes = [
          { name: 'semgrep', run: (c) => runSemgrepOnScope({ ctx, reportDir, autoFix, localOnly, files, ...c }) },
          { name: 'bandit', after: afterSemgrep, run: (c) => runBanditOnScope({ ctx, reportDir, files: files.filter(isPython), ...c }) },
          { name: 'gosec', after: afterSemgrep, run: (c) => runGosec({ ctx, reportDir, files: files.filter(isGoSource), ...c }) },
          { name: 'cppcheck', after: afterSemgrep, run: (c) => runCppcheck({ ctx, reportDir, files: cppSources(files), scoped: true, ...c }) },
          // Psalm reads the whole project's PHP for a scope's (a taint flow crosses files); the factory keeps the scope's findings.
          {
            name: PSALM,
            after: afterSemgrep,
            run: async (c) => {
              if (hasPhpSource(files)) await runPsalm({ ctx, reportDir, files: await scanned(), scopeFiles: files.length, ...c });
            },
          },
          { name: 'dotnet-analyzers', run: async (c) => dotnetNotApplicableToScope({ ctx, files, ...c }) },
        ];
      } else {
        passes = [
          { name: 'semgrep', run: (c) => runSemgrep({ ctx, reportDir, autoFix, localOnly, ...c }) },
          { name: 'bandit', after: afterSemgrep, run: (c) => runBandit({ ctx, reportDir, ...c }) },
          {
            name: 'gosec',
            after: afterSemgrep,
            run: async (c) => {
              if (looksGo(ctx.projectPath)) await runGosec({ ctx, reportDir, files: await scanned(), ...c });
            },
          },
          {
            name: 'cppcheck',
            after: afterSemgrep,
            run: async (c) => {
              if (hasFileWithExtension(ctx.projectPath, ['.c', '.cc', '.cpp', '.cxx', '.c++'])) {
                await runCppcheck({ ctx, reportDir, files: await scanned(), scoped: false, ...c });
              }
            },
          },
          {
            name: PSALM,
            after: afterSemgrep,
            run: async (c) => {
              if (hasFileWithExtension(ctx.projectPath, ['.php', '.phtml'])) await runPsalm({ ctx, reportDir, files: await scanned(), ...c });
            },
          },
          { name: 'dotnet-analyzers', after: ['semgrep'], run: (c) => runDotnetAnalyzers({ ctx, ...c }) },
        ];
      }
      const { tools_run, missing_tools, parser_inputs } = await runScannerPasses(passes, maxParallelScanners());

      // `failed` only when something failed and nothing ran: a scope with
      // no file in it skips every scanner, which is not a failure.
      const anyOk = tools_run.some((t) => t.status === 'ok');
      const anyFailed = tools_run.some((t) => t.status === 'failed');
      const outcome = anyOk || missing_tools.length > 0 || !anyFailed ? 'completed' : 'failed';

      return {
        outcome,
        tools_run,
        missing_tools,
        parser_inputs,
        report_paths: [reportDir],
        extras: { local_only: localOnly },
      };
    },
  }),
);

interface Collect {
  tools_run: ToolRun[];
  missing_tools: string[];
  parser_inputs: ScannerInvocation['parser_inputs'];
}

async function runSemgrep(args: Collect & {
  ctx: InvokeContext;
  reportDir: string;
  autoFix: boolean;
  localOnly: boolean;
}): Promise<void> {
  const { ctx, reportDir, autoFix, localOnly, tools_run, missing_tools, parser_inputs } = args;
  const outFile = join(reportDir, 'sast.json');
  const plan = planSemgrepConfigs(ctx.rulesProjectPath, ctx.plugin, localOnly, ctx.projectPath);

  // local_only with nothing on disk to run is not a clean scan, it is no
  // scan at all. Saying so beats reporting zero findings from zero rules.
  if (plan.nothingToRun) {
    tools_run.push({
      name: 'semgrep',
      status: 'skipped',
      reason:
        'local_only=true but this project has no local Semgrep rules — no .semgrep.yml, ' +
        'nothing registered with register_custom_rules (the plugin\'s own packs, ' +
        `${PLUGIN_PACK_FILES.join(', ')} are an addition and not run alone as a SAST scan). Run init_project, or drop ` +
        'local_only to use the Semgrep registry.',
    });
    missing_tools.push('semgrep');
    return;
  }

  // `.guardian/scan.yml`'s timeouts, and `.guardian/` never a target (runners/semgrepRun.ts).
  const flags = semgrepScanFlags(ctx.configRoot);
  const notes = [...plan.notes, ...(flags.warning !== null ? [flags.warning] : [])];
  const semgrepBin = await scannerAvailable('semgrep');
  if (semgrepBin) {
    const argv = [...plan.args, ...flags.args, ...semgrepExcludeArgs(ctx.exclusions), '--json', '--quiet', '--output', outFile];
    if (autoFix) argv.push('--autofix');
    argv.push(ctx.projectPath);
    // UTF-8 mode comes with the helper: a non-ASCII file name otherwise makes
    // Semgrep fail to write its report on Windows (runners/semgrepRun.ts).
    const result = await spawnSemgrep({
      args: argv,
      cwd: ctx.projectPath,
      env: ctx.scriptEnv,
      signal: ctx.signal,
      onLog: ctx.onLog,
    });
    // Windows: directories its walk could not list, left out on a second run (runners/semgrepLongDirs.ts).
    const longDirs = longDirsNote(result);
    recordSemgrepRun({
      ctx, result, outFile, notes: longDirs !== null ? [...notes, longDirs] : notes, via: null, configs: plan.rulePacks, loadedFrom: plan.ruleConfigs,
      packMissing: plan.packMissing, gaps: await semgrepCoverageGaps(ctx.projectPath, ignoreFrom(ctx)), tools_run, missing_tools, parser_inputs,
    });
    return;
  }

  // Semgrep not on PATH — fall back to the official Docker image when a
  // daemon is reachable. The container cannot see host paths, so a project
  // config is named by where it sits inside the /src mount; registered
  // custom rules (which may live anywhere on the host) are not passed. The
  // plugin's pack directory is mounted READ-ONLY at CONTAINER_PACKS_ROOT and
  // the LLM pack run from there.
  const dockerBin = await scannerAvailable('docker');
  if (!dockerBin) {
    tools_run.push({ name: 'semgrep', status: 'skipped', reason: 'not_installed (no docker fallback available)' });
    missing_tools.push('semgrep');
    return;
  }
  // The container sees the project through its mount, so it would read the
  // tree's own rules: never with the CI gate's --rules-ref, which takes them
  // from a ref (`ci/refConfig.ts`). A gap, named, rather than the tree's rules.
  const fromRef = ctx.plugin.repoConfigFromRef;
  if (fromRef !== undefined) {
    tools_run.push({
      name: 'semgrep',
      status: 'skipped',
      reason:
        `semgrep is not installed, and its Docker fallback reads the project's rules from the tree it mounts — ` +
        `this scan takes them from ${fromRef.ref} (--rules-ref): install semgrep`,
    });
    missing_tools.push('semgrep');
    return;
  }
  const image = process.env['GUARDIAN_SEMGREP_IMAGE'] || DEFAULT_SEMGREP_IMAGE;
  const dockerConfigs = localOnly ? [] : ['auto'];
  for (const cfg of inspectProjectSemgrepConfigs(ctx.projectPath).usable) {
    dockerConfigs.push(toContainerPath(ctx.projectPath, cfg.path));
  }
  if (dockerConfigs.length === 0) {
    tools_run.push({
      name: 'semgrep',
      status: 'skipped',
      reason: 'local_only=true and the Docker fallback sees no local Semgrep rules in the project',
    });
    missing_tools.push('semgrep');
    return;
  }
  // The configs that make the scan; the pack rides along and never counts
  // toward "a rule loaded" (runners/semgrepConfigs.ts).
  const loadedFrom = [...dockerConfigs];
  const packConfigs = plan.pluginPacks.map((p) => `${CONTAINER_PACKS_ROOT}/${basename(p)}`);
  const result = await runProcess({
    command: 'docker',
    args: buildSemgrepDockerArgs({
      projectPath: ctx.projectPath,
      outFileHost: outFile,
      hasCsproj: hasDotnetProject(ctx.projectPath) && !localOnly,
      autoFix,
      image,
      configs: [...dockerConfigs, ...packConfigs],
      metricsOff: localOnly,
      extraArgs: flags.args,
      ...(packConfigs.length > 0 ? { readOnlyMounts: [{ source: plan.pluginPacksDir, target: CONTAINER_PACKS_ROOT }] } : {}),
      git: await gitSafetyFor([ctx.projectPath]),
    }),
    cwd: ctx.projectPath,
    env: ctx.scriptEnv,
    signal: ctx.signal,
    onLog: ctx.onLog,
  });
  recordSemgrepRun({
    ctx, result, outFile, notes, via: `docker (${image})`, configs: [...dockerConfigs, ...packConfigs], loadedFrom,
    packMissing: plan.packMissing, packsHostDir: plan.pluginPacksDir,
    // Which listing Semgrep uses inside the container cannot be checked from
    // here (git, or a walk of the mount): the submodules are named all the
    // same — the safe direction (review M2, round 2).
    gaps: await semgrepCoverageGaps(ctx.projectPath),
    tools_run, missing_tools, parser_inputs,
  });
}

/**
 * One Semgrep run's `tools_run` entry, judged by its report (Global
 * Constraint 3) — never by the exit code alone. See the module comment.
 */
interface SemgrepRunRecord extends Collect {
  ctx: InvokeContext;
  result: ProcessRunResult;
  outFile: string;
  notes: readonly string[];
  /** `docker (<image>)` for the container fallback, else null. */
  via: string | null;
  /** The `--config` values the run passed: a local rule is stored under its canonical id (runners/semgrepRuleIds.ts). */
  configs: readonly string[];
  /** The configs "no rule loaded" is judged on: `configs` without the plugin's pack. */
  loadedFrom: readonly string[];
  /** The plugin's pack was not on disk: an otherwise-ok run is partial. */
  packMissing: boolean;
  /** Container runs: the host directory mounted at CONTAINER_PACKS_ROOT. */
  packsHostDir?: string;
  /**
   * What the run cannot see and does not say — files over Semgrep's size
   * limit, initialised submodules (review M1 / M2) — from the one shared
   * place, `runners/semgrepCoverageGaps.ts`: each a named gap.
   */
  gaps: SemgrepCoverageGaps;
}

function recordSemgrepRun(args: SemgrepRunRecord): void {
  judgeSemgrepRun(args);
  // The shared gaps (runners/semgrepCoverageGaps.ts), on the entry just judged.
  const last = args.tools_run.at(-1);
  if (last !== undefined && last.name === 'semgrep') {
    // Its report says which too-long paths it did open (long paths enabled).
    const report = args.gaps.longPaths !== undefined ? readJsonSafe(args.outFile) : null;
    const applied = applySemgrepCoverageGaps(last, args.gaps, { reports: report !== null ? [report] : [] });
    args.tools_run[args.tools_run.length - 1] = applied.toolRun;
    if (applied.missing) markMissing(args.missing_tools, 'semgrep');
  }
  // A damaged install ran without the pack: the note is on the run, and an
  // otherwise-complete run is partial (review of the LLM pack, M-3).
  if (args.packMissing && args.tools_run.at(-1)?.status === 'ok' && !args.missing_tools.includes('semgrep')) {
    args.missing_tools.push('semgrep');
  }
}

function judgeSemgrepRun(args: SemgrepRunRecord): void {
  const { ctx, result, outFile, notes, via, configs, loadedFrom, packsHostDir, tools_run, missing_tools, parser_inputs } = args;
  const raw = readJsonSafe(outFile);
  // Whatever the verdict, the findings the report holds are real. The
  // container's configs are named inside its /src mount, where it runs, and
  // the plugin's pack inside its read-only mount — whose rules come out bare.
  const rules =
    via !== null
      ? { projectPath: CONTAINER_PROJECT_ROOT, cwd: CONTAINER_PROJECT_ROOT, packsDir: CONTAINER_PACKS_ROOT }
      : { projectPath: ctx.rulesProjectPath, cwd: ctx.projectPath };
  if (raw) parser_inputs.push({ parser: semgrepParserFor(configs, rules), input: raw });
  // The container's configs are read on the host (`/src/…` is the project,
  // CONTAINER_PACKS_ROOT the plugin's pack directory).
  const readAt = (config: string): string => {
    if (via === null) return config;
    if (packsHostDir !== undefined && config.startsWith(`${CONTAINER_PACKS_ROOT}/`)) {
      return join(packsHostDir, ...config.slice(CONTAINER_PACKS_ROOT.length + 1).split('/'));
    }
    return fromContainerPath(ctx.projectPath, config);
  };
  const packConfigs = configs.filter((c) => !loadedFrom.includes(c)).map(readAt);
  const check = checkSemgrepReport({
    raw,
    exitCode: result.exitCode,
    outcome: result.outcome,
    targets: 1,
    // The container fallback reports paths under its mount, not the host's.
    projectPath: via !== null ? CONTAINER_PROJECT_ROOT : ctx.projectPath,
    // A rule that did not load is named as its findings are stored.
    ruleIdOf: localRuleIdNormalizer(configs, rules),
    // A fixpoint timeout of the plugin's pack alone is its gap, not the scan's.
    // Spelled as Semgrep spells the pack in this run (the container's mount
    // in Docker), read on the host.
    pluginPackCheckIds: pluginPackCheckIds(
      configs.filter((c) => !loadedFrom.includes(c)),
      { cwd: via !== null ? CONTAINER_PROJECT_ROOT : ctx.projectPath, readAt },
    ),
    nonPackTaintRules: mayHoldTaintRules(loadedFrom, readAt),
  });
  const packGap = check.plugin_pack_fixpoint;
  // What the engine that ran cannot do — report fixpoint timeouts, resolve
  // the pack's node: imports — said once (runners/semgrepConfigs.ts).
  const engineNote = semgrepEngineNote(semgrepEngineOf(raw), { llmPack: configs.length > loadedFrom.length });
  const reasons = [...(via !== null ? [`ran via ${via}`] : []), ...notes, ...(engineNote !== null ? [engineNote] : [])];

  if (check.verdict === 'ok') {
    const run: ToolRun = { name: 'semgrep', status: 'ok' };
    if (reasons.length > 0) run.reason = reasons.join('; ');
    // The plugin's pack's own gap (round 3, N-1): noted, never the scan's.
    tools_run.push(withPluginPackFixpoint(run, packGap));
    return;
  }
  if (check.verdict === 'partial' && check.partial !== undefined) {
    // Partial coverage (the module comment): ran, with a narrower gap inside
    // it — `ok` AND missing, the files named on the run for the CI gate's
    // --accept-partial-parse.
    tools_run.push(
      withPluginPackFixpoint(
        {
          name: 'semgrep',
          status: 'ok',
          reason: [
            ...reasons,
            describePartialParse(check.partial, 'findings in the unparsed spans may be missing'),
          ].join('; '),
          partially_parsed: check.partial,
        },
        packGap,
      ),
    );
    missing_tools.push('semgrep');
    return;
  }
  if (check.verdict === 'scanned_nothing') {
    // No file in the project is one any loaded rule applies to: a gap, not
    // a clean result — and not a broken scanner either. Unless the files it
    // would have read were only too large: that is the reason, then.
    tools_run.push({
      name: 'semgrep',
      status: 'skipped',
      reason: [
        ...reasons,
        scannedNothingBecause(args.gaps) ?? 'semgrep scanned 0 files — nothing here is a language its rules cover',
      ].join('; '),
    });
    missing_tools.push('semgrep');
    return;
  }
  const notLoaded = check.rules_not_loaded;
  if (notLoaded !== undefined && notLoaded.length > 0 && noRuleLoaded(loadedFrom, notLoaded, rules, readAt)) {
    // Every rule of the scan's own configs failed and no registry pack ran:
    // nothing was scanned for (M-1) — failed, the rules named, never
    // "install semgrep". The plugin's LLM pack does not count: it alone is
    // not a SAST scan, and its findings are recorded above either way.
    const run: ToolRun = {
      name: 'semgrep',
      status: 'failed',
      reason: [...reasons, describeNoRuleLoaded(notLoaded)].join('; '),
      failed_rules: notLoaded,
      rule_config_error: true,
    };
    if (onlyPluginPackRan(packConfigs, notLoaded)) run.plugin_pack_only = true;
    tools_run.push(run);
    return;
  }
  if (notLoaded !== undefined && notLoaded.length > 0) {
    // Rules that did not load while the others ran (the module comment): a
    // narrower gap — ran, `ok` AND missing, the rules named.
    const run: ToolRun = {
      name: 'semgrep',
      status: 'ok',
      reason: [
        ...reasons,
        describeRulesNotLoaded(notLoaded, check.scanned),
        ...(check.partial !== undefined ? [describePartialParse(check.partial, 'findings in the unparsed spans may be missing')] : []),
      ].join('; '),
      failed_rules: notLoaded,
    };
    if (check.partial !== undefined) run.partially_parsed = check.partial;
    tools_run.push(withPluginPackFixpoint(run, packGap));
    missing_tools.push('semgrep');
    return;
  }
  // Semgrep's own `[ERROR]` line goes with the reason whatever it is: "wrote
  // no JSON report (exit 2)" alone named no cause (review 11, finding 10) —
  // and SEMGREP_SEND_METRICS=off, the commonest one, is named outright.
  const errorLine = semgrepErrorLine(result.stderr);
  const said = check.reason ?? errorLine ?? result.stderr.split(/\r?\n/).find((l) => l.trim().length > 0) ?? 'semgrep failed';
  // The container fallback does not inherit the variable: only Semgrep run here.
  const metrics = via === null ? metricsEnvProblem(configs, ctx.scriptEnv) : null;
  const detail = [
    said,
    ...(check.reason !== undefined && errorLine !== null ? [`semgrep said: ${errorLine}`] : []),
    ...(metrics !== null ? [metrics] : []),
  ].join(' — ');
  if (check.rule_config_error !== undefined) {
    // Semgrep refused the rule configuration (an unknown language: exit 8):
    // installed, and the rules are what to fix.
    tools_run.push({
      name: 'semgrep',
      status: 'failed',
      reason: [...reasons, `the rule configuration did not load — ${check.rule_config_error} (semgrep exit ${String(result.exitCode)})`].join('; '),
      rule_config_error: true,
    });
    return;
  }
  tools_run.push({ name: 'semgrep', status: 'failed', reason: [...reasons, detail].join('; ') });
}

async function runBandit(args: Collect & { ctx: InvokeContext; reportDir: string }): Promise<void> {
  const { ctx, reportDir, tools_run, missing_tools, parser_inputs } = args;
  // Only attempt Bandit when the project has Python sources: a manifest,
  // or any `.py` file (a walk that stops at the first).
  const looksPython =
    presentInProject(ctx.projectPath, 'pyproject.toml') ||
    presentInProject(ctx.projectPath, 'requirements.txt') ||
    presentInProject(ctx.projectPath, 'setup.py') ||
    hasFileWithExtension(ctx.projectPath, ['.py']);
  if (!looksPython) return;
  const banditBin = await scannerAvailable('bandit');
  if (!banditBin) {
    tools_run.push({ name: 'bandit', status: 'skipped', reason: 'not_installed' });
    missing_tools.push('bandit');
    return;
  }
  // The project's root .bandit — the CI gate's --rules-ref copy of it when set (`ci/refConfig.ts`).
  const ini = banditIni(ctx.configRoot, reportDir);
  if ('error' in ini) {
    tools_run.push({ name: 'bandit', status: 'failed', reason: ini.error });
    return;
  }
  const outFile = join(reportDir, 'bandit.json');
  const result = await runProcess({
    command: 'bandit',
    args: [
      '-r',
      ctx.projectPath,
      '--ini',
      ini.path,
      ...banditExcludeArgs(ctx.exclusions, ctx.projectPath),
      '-f',
      'json',
      '-o',
      outFile,
      '-q',
    ],
    cwd: ctx.projectPath,
    env: pythonUtf8Env(ctx.scriptEnv),
    signal: ctx.signal,
    onLog: ctx.onLog,
  });
  const raw = readJsonSafe(outFile);
  if (raw) parser_inputs.push({ parser: banditParser, input: raw });
  // Exit 0 (clean) or 1 (issues) AND a report with no unanalysed files —
  // or, when every unanalysed file is named, a partial run: `ok` AND missing,
  // the files named (project-relative) for the CI gate's
  // --accept-partial-parse, exactly as a partial Semgrep run.
  const check = checkBanditReport({ raw, exitCode: result.exitCode, outcome: result.outcome });
  const parsed = (check.partial ?? []).map((p) => ({ ...p, file: toRelativeIfPossible(p.file, ctx.projectPath) }));
  // Windows: a Python file at a path too long to open that the walk did not
  // analyse — absent from its `metrics`, with no error at all — is read on its
  // own as an extended-length path; one still not read is a named gap, as it
  // is for Semgrep (review 8, finding 2).
  const long = check.ok ? await banditLongFiles({ ctx, raw, named: parsed, ini: ini.path, reportDir }) : NO_LONG_FILES;
  for (const report of long.reports) parser_inputs.push({ parser: banditParser, input: report });
  const unparsed = [...parsed, ...long.partial];
  const partial = [...unparsed, ...long.tooLong];
  const reason = [
    ...(unparsed.length > 0 ? [describePartialParse(unparsed, 'findings in the unparsed files may be missing')] : []),
    ...(long.tooLong.length > 0 ? [describeTooLong(long.tooLong.map((p) => p.file))] : []),
    ...(long.read > 0 ? [`${long.read} Python file(s) at a path too long for Windows read on their own, as extended-length paths`] : []),
  ].join('; ');
  const run: ToolRun = !check.ok
    ? { name: 'bandit', status: 'failed', reason: check.reason ?? 'bandit failed' }
    : partial.length > 0
      ? { name: 'bandit', status: 'ok', reason, partially_parsed: partial }
      : reason !== ''
        ? { name: 'bandit', status: 'ok', reason }
        : { name: 'bandit', status: 'ok' };
  if (partial.length > 0 && check.ok) missing_tools.push('bandit');
  // The root .bandit only — the one passed with --ini (`runners/repoConfig.ts`).
  tools_run.push(ini.honoured ? await nameRepoConfig(run, ctx.configRoot, 'bandit') : run);
}

/** The files a Bandit report's `metrics` lists as analysed: `/`-separated, lower case. */
function banditAnalysed(raw: string | null): string[] {
  const metrics = getProp(raw === null ? null : parseInputAsJson(raw), 'metrics');
  return metrics !== null && typeof metrics === 'object'
    ? Object.keys(metrics).filter((k) => k !== '_totals').map((k) => k.split('\\').join('/').toLowerCase())
    : [];
}

/** Whether `rel` is among {@link banditAnalysed}'s files (absolute or relative). */
const analysedIn = (analysed: readonly string[], rel: string): boolean => {
  const key = rel.toLowerCase();
  return analysed.some((a) => a === key || a.endsWith(`/${key}`));
};

interface BanditLongFiles {
  /** The second run's reports, its paths named as the project's. */
  reports: string[];
  /** How many files it read. */
  read: number;
  /** Files it read only in part (a syntax error). */
  partial: PartialParse[];
  /** Files still not analysed — each a `Path too long` gap. */
  tooLong: PartialParse[];
}

const NO_LONG_FILES: BanditLongFiles = { reports: [], read: 0, partial: [], tooLong: [] };

/**
 * Windows only: the project's Python files at a path too long for Windows
 * (`runners/semgrepLongDirs.ts#tooLongForWindows`) that the whole-project
 * run's report does not list in `metrics` (the files it analysed), and that
 * are not named already, read in a second run as extended-length explicit
 * targets (`runners/fileBatchScan.ts#banditOnFiles`) with the same `--ini`.
 * Measured in review 8: Bandit's walk sometimes reported such a file and
 * sometimes dropped it silently; on 1.9.4 it dropped it, and read it given as
 * `\\?\C:\…`. The candidates are the shared gaps' (`.guardianignore` and the
 * walk's own exclusions applied).
 */
async function banditLongFiles(a: {
  ctx: InvokeContext;
  raw: string | null;
  named: readonly PartialParse[];
  ini: string;
  reportDir: string;
}): Promise<BanditLongFiles> {
  const { ctx } = a;
  if (process.platform !== 'win32') return NO_LONG_FILES;
  const analysed = banditAnalysed(a.raw);
  const missed = ((await semgrepCoverageGaps(ctx.projectPath, ignoreFrom(ctx))).longPaths ?? []).filter(
    (f) => isPython(f) && !a.named.some((p) => p.file.toLowerCase() === f.toLowerCase()) && !analysedIn(analysed, f),
  );
  if (missed.length === 0) return NO_LONG_FILES;
  const pass = await banditOnFiles({
    files: missed,
    ini: a.ini,
    cwd: ctx.projectPath,
    reportDir: a.reportDir,
    reportPrefix: 'bandit-long',
    env: ctx.scriptEnv,
    signal: ctx.signal,
    ...(ctx.onLog ? { onLog: ctx.onLog } : {}),
  });
  const read = pass.reports.flatMap(banditAnalysed);
  const partial = pass.partial.filter((p) => missed.includes(p.file));
  return {
    reports: pass.reports,
    read: missed.filter((f) => analysedIn(read, f)).length,
    partial,
    tooLong: missed
      .filter((f) => !analysedIn(read, f) && !partial.some((p) => p.file === f))
      .map((file) => ({
        file,
        type: PATH_TOO_LONG_TYPE,
        message: 'the path is 260 characters or longer, and Bandit did not analyse the file, even as an extended-length path',
      })),
  };
}

/** The CI gate's `--rules-ref` copy of `.guardianignore`, for the shared coverage gaps; none otherwise. */
function ignoreFrom(ctx: InvokeContext): { guardianIgnoreFrom?: string } {
  return ctx.configRoot !== ctx.projectPath ? { guardianIgnoreFrom: ctx.configRoot } : {};
}

/** An empty `[bandit]` section: Bandit reads it and nothing else. */
export const NEUTRAL_BANDIT_INI = 'bandit-neutral.ini';

/**
 * The `--ini` of every Bandit run scan_sast makes, whole-project and scoped
 * alike (round 4, item 3; review 3.0, wave 2). Without one,
 * `bandit -r` walks the whole tree for a file named `.bandit` and applies it
 * to every file it scans — measured on 1.9.4: a `sub/.bandit`, or one in a
 * dependency's directory the scan excludes, with `skips: B101,B602,B404`
 * took a root `a.py` from 3 results to 0; two of them made Bandit exit 2.
 * `--ini` replaces that search: the project's own ROOT `.bandit` (its call,
 * like its `.trivyignore`) is passed explicitly and named; without one, an
 * empty `[bandit]` file this scan writes. Never run without it.
 */
function banditIni(projectPath: string, reportDir: string): { path: string; honoured: boolean } | { error: string } {
  const own = join(projectPath, '.bandit');
  try {
    if (lstatSync(own).isFile()) return { path: own, honoured: true };
  } catch {
    // None at the root.
  }
  const neutral = join(reportDir, NEUTRAL_BANDIT_INI);
  try {
    writeFileSync(neutral, '[bandit]\n', 'utf8');
  } catch (e) {
    return { error: `could not write the neutral Bandit configuration ${neutral}: ${e instanceof Error ? e.message : String(e)}` };
  }
  return { path: neutral, honoured: false };
}

const isPython = (f: string): boolean => f.toLowerCase().endsWith('.py');

/** Sources the .NET analyzers read when they compile the project. */
const DOTNET_SOURCE = /\.(cs|fs|vb|razor|cshtml)$/i;

/**
 * Semgrep over a scope's files, as explicit targets (see the module comment).
 * Same rule plan as a whole-project run; `.guardianignore` needs no flag here
 * — the scope never holds an excluded file.
 */
async function runSemgrepOnScope(args: Collect & {
  ctx: InvokeContext;
  reportDir: string;
  autoFix: boolean;
  localOnly: boolean;
  files: readonly string[];
}): Promise<void> {
  const { ctx, reportDir, autoFix, localOnly, files, tools_run, missing_tools, parser_inputs } = args;
  if (files.length === 0) {
    // Nothing asked for: not a gap (the scope's own warning says 0 files).
    tools_run.push({ name: 'semgrep', status: 'skipped', reason: 'the scope holds no file — nothing to scan' });
    return;
  }
  const plan = planSemgrepConfigs(ctx.rulesProjectPath, ctx.plugin, localOnly, ctx.projectPath);
  if (plan.nothingToRun) {
    tools_run.push({
      name: 'semgrep',
      status: 'skipped',
      reason:
        'local_only=true but this project has no local Semgrep rules — no .semgrep.yml, ' +
        'nothing registered with register_custom_rules.',
    });
    missing_tools.push('semgrep');
    return;
  }
  if (!(await scannerAvailable('semgrep'))) {
    tools_run.push({
      name: 'semgrep',
      status: 'skipped',
      reason:
        'not_installed — the Docker fallback mounts and scans the whole project, so it cannot run a ' +
        'scoped scan; install Semgrep, or drop scope',
    });
    missing_tools.push('semgrep');
    return;
  }
  const flags = semgrepScanFlags(ctx.configRoot);
  const run = await semgrepOnFiles({
    configArgs: [...plan.args, ...flags.args, ...(autoFix ? ['--autofix'] : [])],
    files,
    cwd: ctx.projectPath,
    reportDir,
    env: ctx.scriptEnv,
    signal: ctx.signal,
    ...(ctx.onLog ? { onLog: ctx.onLog } : {}),
    rules: {
      configs: plan.rulePacks,
      ctx: { projectPath: ctx.rulesProjectPath, cwd: ctx.projectPath },
      loadedFrom: plan.ruleConfigs,
      packCheckIds: pluginPackCheckIds(plan.pluginPacks, { cwd: ctx.projectPath }),
      nonPackTaintRules: mayHoldTaintRules(plan.ruleConfigs),
    },
  });
  const parser = semgrepParserFor(plan.rulePacks, { projectPath: ctx.rulesProjectPath, cwd: ctx.projectPath });
  for (const raw of run.reports) parser_inputs.push({ parser, input: raw });
  const entry: ToolRun = { ...run.toolRun };
  const engineNote = semgrepEngineNote(semgrepEngineOf(run.reports[0] ?? null), { llmPack: plan.pluginPacks.length > 0 });
  const scopeNotes = [...plan.notes, ...(flags.warning !== null ? [flags.warning] : []), ...(engineNote !== null ? [engineNote] : [])];
  if (scopeNotes.length > 0) entry.reason = [entry.reason, ...scopeNotes].filter((s) => s !== undefined).join('; ');
  if (entry.status === 'failed' && entry.rule_config_error === true && onlyPluginPackRan(plan.pluginPacks, run.failedRules)) {
    entry.plugin_pack_only = true;
  }
  tools_run.push(entry);
  // No rule applied to any file in scope: a gap, not a clean result. Files
  // only partly parsed, rules that did not load, the plugin's pack missing
  // from disk: ran, with a narrower gap inside it (`ok` + missing).
  const narrower = run.partial.length > 0 || run.failedRules.length > 0 || plan.packMissing;
  if (run.nothingScanned || (entry.status === 'ok' && narrower)) missing_tools.push('semgrep');
  // The scope's files over Semgrep's size limit, and submodules they reach
  // (runners/semgrepCoverageGaps.ts): named, a gap.
  const gapped = applySemgrepCoverageGaps(entry, await semgrepCoverageGaps(ctx.projectPath, { files, ...ignoreFrom(ctx) }), {
    scannedNothing: run.nothingScanned,
    reports: run.reports,
  });
  tools_run[tools_run.length - 1] = gapped.toolRun;
  if (gapped.missing) markMissing(missing_tools, 'semgrep');
}

/**
 * Bandit over a scope's `.py` files; no entry at all when it holds none.
 * With the whole-project run's `--ini` ({@link banditIni}): Bandit handed
 * explicit files looks for no `.bandit`, so without it a scoped run ignored
 * the project's root one (measured on 1.9.4: with a root `.bandit` skipping
 * B101, the same `a.py` read B404 and B602 whole-project and B101 too
 * scoped). Named the same way, too.
 */
async function runBanditOnScope(args: Collect & { ctx: InvokeContext; reportDir: string; files: readonly string[] }): Promise<void> {
  const { ctx, reportDir, files, tools_run, missing_tools, parser_inputs } = args;
  if (files.length === 0) return;
  if (!(await scannerAvailable('bandit'))) {
    tools_run.push({ name: 'bandit', status: 'skipped', reason: 'not_installed' });
    missing_tools.push('bandit');
    return;
  }
  const ini = banditIni(ctx.projectPath, reportDir);
  if ('error' in ini) {
    tools_run.push({ name: 'bandit', status: 'failed', reason: ini.error });
    return;
  }
  const run = await banditOnFiles({
    files,
    ini: ini.path,
    cwd: ctx.projectPath,
    reportDir,
    env: ctx.scriptEnv,
    signal: ctx.signal,
    ...(ctx.onLog ? { onLog: ctx.onLog } : {}),
  });
  for (const raw of run.reports) parser_inputs.push({ parser: banditParser, input: raw });
  tools_run.push(ini.honoured ? await nameRepoConfig(run.toolRun, ctx.projectPath, 'bandit') : run.toolRun);
}

/**
 * cppcheck over the C/C++ translation units of `files` (`runners/cppcheckRun.ts`):
 * the whole project's, or a scope's. No entry at all when there is none.
 */
async function runCppcheck(
  args: Collect & { ctx: InvokeContext; reportDir: string; files: readonly string[]; scoped: boolean },
): Promise<void> {
  const { ctx, reportDir, files, scoped, tools_run, missing_tools, parser_inputs } = args;
  if (files.length === 0) return;
  const pass = await cppcheckSources({
    projectPath: ctx.projectPath,
    files,
    scoped,
    reportDir,
    env: ctx.scriptEnv,
    signal: ctx.signal,
    ...(ctx.onLog ? { onLog: ctx.onLog } : {}),
  });
  for (const report of pass.reports) parser_inputs.push({ parser: cppcheckParser, input: report });
  if (pass.toolRun !== null) tools_run.push(pass.toolRun);
  for (const name of pass.missing) markMissing(missing_tools, name);
}

/**
 * Psalm's taint analysis over the project's PHP (`runners/psalmRun.ts`),
 * WordPress's APIs modelled when the project is WordPress. No entry when
 * there is no PHP outside `vendor/`.
 */
async function runPsalm(
  args: Collect & { ctx: InvokeContext; reportDir: string; files: readonly string[]; scopeFiles?: number },
): Promise<void> {
  const { ctx, reportDir, files, tools_run, missing_tools, parser_inputs } = args;
  const pass = await psalmTaint({
    projectPath: ctx.projectPath,
    files,
    wordpress: isWordPressProject(ctx.projectPath),
    ...(args.scopeFiles !== undefined ? { scopeFiles: args.scopeFiles } : {}),
    reportDir,
    env: ctx.scriptEnv,
    signal: ctx.signal,
    ...(ctx.onLog ? { onLog: ctx.onLog } : {}),
  });
  if (pass.report !== null) parser_inputs.push({ parser: psalmParser, input: pass.report });
  if (pass.toolRun !== null) tools_run.push(pass.toolRun);
  for (const name of pass.missing) markMissing(missing_tools, name);
}

/** A module file at the root, or any `.go` file (a walk that stops at the first): gosec has something to read. */
function looksGo(projectPath: string): boolean {
  return (
    presentInProject(projectPath, 'go.mod') ||
    presentInProject(projectPath, 'go.work') ||
    hasFileWithExtension(projectPath, ['.go'])
  );
}

/**
 * gosec over the Go packages of `files` (`runners/gosecRun.ts`): the whole
 * project's files, or a scope's — gosec reads a package whole, and the
 * factory keeps only the findings inside the scope. No entry at all when the
 * files hold no Go package; the Go toolchain absent is the `go` gap.
 */
async function runGosec(args: Collect & { ctx: InvokeContext; reportDir: string; files: readonly string[] }): Promise<void> {
  const { ctx, reportDir, files, tools_run, missing_tools, parser_inputs } = args;
  if (files.length === 0) return;
  const pass = await gosecOnPackages({
    files,
    cwd: ctx.projectPath,
    reportDir,
    env: ctx.scriptEnv,
    signal: ctx.signal,
    ...(ctx.onLog ? { onLog: ctx.onLog } : {}),
  });
  for (const raw of pass.reports) parser_inputs.push({ parser: gosecParser, input: raw });
  if (pass.toolRun !== null) tools_run.push(pass.toolRun);
  for (const name of pass.missing) markMissing(missing_tools, name);
}

/**
 * The .NET analyzers compile the whole project — there is no "build these
 * three files". For a scope they are `skipped` as project-level, never run
 * and never reported as covering it; when the scope holds .NET sources that
 * only they would have read, that is a named gap (`missing_tools`).
 */
function dotnetNotApplicableToScope(args: Collect & { ctx: InvokeContext; files: readonly string[] }): void {
  const { ctx, files, tools_run, missing_tools } = args;
  if (!hasRootDotnetSignal(ctx.projectPath)) return;
  const sources = files.filter((f) => DOTNET_SOURCE.test(f)).length;
  const reason =
    'project-level: the .NET analyzers run inside a build of the whole project, not over a file scope' +
    (sources > 0
      ? ` — ${sources} .NET source file(s) in the scope were not analysed by them (Semgrep's were); run ` +
        'scan_sast without scope for that'
      : '');
  tools_run.push({ name: 'dotnet-analyzers', status: 'skipped', reason });
  if (projectReferencesScs(ctx.projectPath)) tools_run.push({ name: 'security-code-scan', status: 'skipped', reason });
  if (sources > 0) missing_tools.push('dotnet-analyzers');
}

/**
 * The .NET pass — see the module comment. Per root target
 * (`findDotnetTargets`: the root solution, else every project file):
 *
 *   1. `dotnet restore --locked-mode`, planned by `../deps/dotnetRestore.ts`
 *      exactly as deps_audit does — it never creates or rewrites a
 *      `packages.lock.json`. A plain `dotnet build` restores implicitly and
 *      WITHOUT locked mode: it rewrote an out-of-date lock (and created one
 *      for an opted-in project) in the user's tree on every scan, and in
 *      create_fix_pr's re-scan the created lock went into the pull request.
 *      A restore that fails (`NU1004`: the lock is out of sync) is a named
 *      gap, and that target is not built.
 *   2. `dotnet build --no-restore` with the SDK's analyzers switched ON
 *      (`EnableNETAnalyzers=true` — they are off by default below .NET 5:
 *      measured, a netstandard2.0 library using MD5 built clean with an empty
 *      SARIF) at the latest security level, in security-all mode.
 *   3. The SARIF is written per project AND per target framework into a
 *      temp directory, by an imported targets file
 *      (`CustomAfterMicrosoftCommonTargets`): a global `-p:ErrorLog=` is not
 *      expanded (`$(TargetFramework)` stays literal), so every inner build of
 *      a multi-targeted project overwrote one file and only the last
 *      framework's results survived (measured: `net10.0;netstandard2.0`).
 *   4. A SARIF whose rule metadata lists no security rule means the
 *      analyzers did not load: a gap, never an ok with 0 findings.
 *
 * `CustomAfterMicrosoftCommonTargets` is a global property: a project that
 * sets its own is built without it for this scan, and the reason says so
 * (`customAfterTargetsSetters`) as reduced coverage.
 */
async function runDotnetAnalyzers(args: Collect & { ctx: InvokeContext }): Promise<void> {
  const { ctx, tools_run, missing_tools, parser_inputs } = args;
  if (!hasRootDotnetSignal(ctx.projectPath)) return;
  const referencesScs = projectReferencesScs(ctx.projectPath);

  const dotnetBin = await scannerAvailable('dotnet');
  if (!dotnetBin) {
    tools_run.push({ name: 'dotnet-analyzers', status: 'skipped', reason: 'dotnet SDK not installed' });
    if (referencesScs) {
      tools_run.push({ name: 'security-code-scan', status: 'skipped', reason: 'dotnet SDK not installed' });
    }
    missing_tools.push('dotnet-sdk');
    return;
  }

  const work = mkdtempSync(join(tmpdir(), 'guardian-sast-dotnet-'));
  const sarifDir = join(work, 'sarif');
  mkdirSync(sarifDir);
  const targetsFile = join(work, 'dev-guardian-sarif.targets');
  writeFileSync(targetsFile, SARIF_TARGETS, 'utf8');

  const failures: string[] = [];
  // Parsed together, so a result every target framework reports is one finding.
  const sarifs: string[] = [];
  let reports = 0;
  try {
    for (const target of findDotnetTargets(ctx.projectPath)) {
      const rel = relative(ctx.projectPath, target) || basename(target);
      const plan = planDotnetRestore(ctx.projectPath, target);
      if (plan.blocked) {
        failures.push(`${rel}: ${plan.blocked.reason}`);
        continue;
      }
      const restore = await runProcess({
        command: 'dotnet',
        args: plan.args,
        cwd: ctx.projectPath,
        env: ctx.scriptEnv,
        signal: ctx.signal,
        onLog: ctx.onLog,
        timeoutMs: DOTNET_BUILD_TIMEOUT_MS,
      });
      const created = removeCreatedLockFiles(plan);
      if (created.length > 0) {
        failures.push(
          `${rel}: restore created ${created.map((c) => relative(ctx.projectPath, c) || c).join(', ')} ` +
            '(a RestorePackagesWithLockFile opt-in this scan could not see) — deleted again, not built',
        );
        continue;
      }
      if (restore.outcome !== 'completed') {
        // Never retried without --locked-mode — that is the lock rewrite
        // this sequence exists to prevent.
        failures.push(`${rel}: ${classifyRestoreFailure(restore.stdout, restore.stderr).reason}`);
        continue;
      }

      const before = new Set(listSarif(sarifDir));
      const build = await runProcess({
        command: 'dotnet',
        args: [
          'build',
          target,
          '--no-restore',
          '--no-incremental',
          '--verbosity:minimal',
          '-nologo',
          '-p:EnableNETAnalyzers=true',
          '-p:AnalysisLevelSecurity=latest',
          '-p:AnalysisModeSecurity=All',
          `-p:CustomAfterMicrosoftCommonTargets=${targetsFile}`,
          `-p:DevGuardianSarifDir=${sarifDir}${sep}`,
        ],
        cwd: ctx.projectPath,
        env: ctx.scriptEnv,
        signal: ctx.signal,
        onLog: ctx.onLog,
        timeoutMs: DOTNET_BUILD_TIMEOUT_MS,
      });
      // Every project and framework the build compiled wrote its own SARIF.
      // Read what exists — a failed build's compiled projects still
      // reported real diagnostics.
      for (const name of listSarif(sarifDir).filter((n) => !before.has(n))) {
        let raw: string;
        try {
          raw = readFileSync(join(sarifDir, name), 'utf8');
        } catch {
          failures.push(`${rel}: SARIF ${name} unreadable`);
          continue;
        }
        if (sarifSecurityRuleCount(raw) === 0) {
          failures.push(`${rel}: ${sarifLabel(name)} — the security analyzers did not load (its SARIF lists no security rule)`);
          continue;
        }
        sarifs.push(raw);
        reports += 1;
      }
      if (build.outcome !== 'completed' || build.exitCode !== 0) {
        failures.push(`${rel}: ${describeBuildFailure(build)}`);
      }
    }
  } finally {
    rmSync(work, { recursive: true, force: true, maxRetries: 3, retryDelay: 50 });
  }
  if (sarifs.length > 0) parser_inputs.push({ parser: dotnetSarifParser, input: sarifs });
  if (failures.length === 0 && reports === 0) failures.push('the build wrote no analyzer report (SARIF)');

  const run: ToolRun =
    failures.length === 0
      ? { name: 'dotnet-analyzers', status: 'ok', reason: `${reports} SARIF report(s) read (one per project and target framework)` }
      : { name: 'dotnet-analyzers', status: 'failed', reason: failures.join('; ') };
  const ownTargets = customAfterTargetsSetters(ctx.projectPath);
  if (ownTargets.length > 0) {
    run.reason =
      `${run.reason ?? ''}; reduced coverage: ${ownTargets.join(', ')} set CustomAfterMicrosoftCommonTargets, ` +
      "which this scan's build replaces — the project's own imported targets did not run";
  }
  // The build's own configuration decides what the analyzers report: named
  // (`runners/repoConfig.ts` — .editorconfig severities, Directory.Build.*).
  tools_run.push(await nameRepoConfig(run, ctx.projectPath, 'dotnet-analyzers'));
  if (referencesScs) {
    // Security Code Scan is an analyzer of the same build: it reports through
    // the same SARIF, so it ran exactly as well as the build did.
    tools_run.push({ ...run, name: 'security-code-scan' });
  }
}

/**
 * Imported after the SDK's own targets (see `runDotnetAnalyzers`): the
 * ErrorLog path is evaluated per project instance, so `$(TargetFramework)`
 * and a fresh GUID make every inner build's SARIF its own file.
 */
const SARIF_TARGETS = [
  '<Project>',
  '  <PropertyGroup>',
  '    <ErrorLog>$(DevGuardianSarifDir)$(MSBuildProjectName)-$(TargetFramework)-$([System.Guid]::NewGuid().ToString(\'N\')).sarif,version=2.1</ErrorLog>',
  '  </PropertyGroup>',
  '</Project>',
  '',
].join('\n');

/**
 * Project files that set `CustomAfterMicrosoftCommonTargets` themselves —
 * every project a root target builds, and the `Directory.Build.props` /
 * `.targets` between it and the scanned root. The scan's build passes that
 * property globally (see `runDotnetAnalyzers`), which replaces theirs, so the
 * build it analyses is not quite theirs: named as reduced coverage.
 * Project-relative paths, POSIX, sorted.
 */
function customAfterTargetsSetters(projectPath: string): string[] {
  const sets = /<CustomAfterMicrosoftCommonTargets\b/i;
  const out = new Set<string>();
  // Bounded, regular files only (`hooks/configFile.ts`): the paths come from
  // the repository's solution and project files, which may name `/dev/zero`
  // or a FIFO. Not contained: a solution references projects beside the
  // scanned directory, and the build reads them whatever this does.
  const check = (file: string): void => {
    const text = readSmallTextFile(file, MAX_DOTNET_PROJECT_FILE_BYTES);
    if (text !== undefined && sets.test(text)) out.add(relative(projectPath, file).split(sep).join('/'));
  };
  const root = resolve(projectPath);
  for (const target of findDotnetTargets(projectPath)) {
    for (const project of projectsForTarget(target)) {
      check(project);
      for (let dir = dirname(resolve(project)); ; dir = dirname(dir)) {
        check(join(dir, 'Directory.Build.props'));
        check(join(dir, 'Directory.Build.targets'));
        if (dir === root || dirname(dir) === dir || relative(root, dir).startsWith('..')) break;
      }
    }
  }
  return [...out].sort();
}

/**
 * In a run where no rule of the scan's own configs loaded: whether the
 * plugin's pack (`packFiles`, read on the host) ran — it was passed and none
 * of its rules is among the failed ones (a pack rule's stored id is its own).
 */
function onlyPluginPackRan(packFiles: readonly string[], failed: ReadonlyArray<{ rule_id: string }>): boolean {
  if (packFiles.length === 0) return false;
  const failedIds = new Set(failed.map((f) => f.rule_id));
  return packFiles.every((file) => {
    const ids = ruleIdsInFile(file);
    return ids.length > 0 && !ids.some((id) => failedIds.has(id));
  });
}

function listSarif(dir: string): string[] {
  try {
    return readdirSync(dir).filter((n) => n.endsWith('.sarif'));
  } catch {
    return [];
  }
}

/** `App-net8.0-<guid>.sarif` → `App (net8.0)`. */
function sarifLabel(name: string): string {
  const m = /^(.*)-([^-]*)-[0-9a-f]{32}\.sarif$/.exec(name);
  return m === null ? name : `${m[1] ?? name} (${m[2] || 'no target framework'})`;
}


/** The first `error` line of a failed build, else its outcome. */
function describeBuildFailure(result: ProcessRunResult): string {
  if (result.outcome !== 'completed' && result.outcome !== 'failed') return `dotnet build ${result.outcome}`;
  const line = `${result.stdout}\n${result.stderr}`
    .split(/\r?\n/)
    .map((l) => l.trim())
    .find((l) => /\berror\b/i.test(l));
  return line ?? `dotnet build exited ${String(result.exitCode)}`;
}

/** A `.csproj` / `.fsproj` / `.sln` / `.slnx` at the project root. */
function hasRootDotnetSignal(projectPath: string): boolean {
  return listProjectDir(projectPath, projectPath).some(({ name }) => /\.(csproj|fsproj|sln|slnx)$/i.test(name));
}

/**
 * Whether the project references Security Code Scan: a root project file or
 * `Directory.Build.props` naming the package. We never add it to a project.
 */
function projectReferencesScs(projectPath: string): boolean {
  const files = listProjectDir(projectPath, projectPath)
    .map((e) => e.name)
    .filter((n) => /\.(csproj|fsproj)$/i.test(n) || n === 'Directory.Build.props');
  for (const file of files) {
    // The repository's file: bounded, never through a link out of the project.
    const text = readProjectTextOrUndefined(projectPath, file, MAX_DOTNET_PROJECT_FILE_BYTES);
    if (text !== undefined && /security[-_.]?code[-_.]?scan/i.test(text)) return true;
  }
  return false;
}
