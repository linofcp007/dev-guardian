/**
 * `scan_sast` — Semgrep-only static analysis (plus Bandit when Python is
 * present).
 *
 * Invokes Semgrep directly (no shell script), writing the JSON report to
 * `.guardian/reports/sast-<short-scan-id>/sast.json`. Bandit, if installed
 * and Python sources are detected, is run in the same pass.
 *
 * ---- The project's own rules are part of the scan --------------------
 *
 * `init_project` installs `configs/semgrep/base.yml` into a project as
 * `.semgrep.yml` and calls it the baseline SAST config. This tool used to run
 * `--config=auto` and nothing else, and `--config=auto` does not load it —
 * measured on semgrep 1.164.0 against a project holding that pack plus one
 * line of `<?php echo $_GET['name'];`, `--config=auto` reports 0 findings
 * where `--config=<the file>` reports 1. Thirteen shipped security rules had
 * no consumer anywhere in the product, which is how `wp-unescaped-output`
 * managed to be dead twice over for independent reasons.
 *
 * `platform/projectSemgrepConfig.ts` resolves those configs (from the
 * provenance manifest, falling back to the conventional filenames) and
 * refuses any that Semgrep could not load, because a `--config` that fails to
 * resolve aborts the WHOLE run — `paths.scanned: []`, exit 7 — not just that
 * pack. `test/e2e/projectRulesFixture.test.ts` is the end-to-end proof that
 * the rules `init_project` installs are the rules this tool runs.
 *
 * ---- Telemetry, and `local_only` -------------------------------------
 *
 * `--config=auto` fetches its rule set from the Semgrep registry and **sends
 * usage metrics to Semgrep Inc. as a condition of doing so**: passing
 * `--metrics=off` alongside it fails outright with "Cannot create auto config
 * when metrics are off". So every default scan this tool has ever run
 * reported telemetry, and it could not have done otherwise.
 *
 * That is a defensible default and an indefensible silent one in a security
 * tool, so it is stated in the tool description, the README and the skill.
 * `local_only: true` is the alternative — no registry, `--metrics=off`, and
 * only rules already on disk. It became a coherent mode rather than an empty
 * one the moment the project's own `.semgrep.yml` started being loaded.
 */

import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { z } from 'zod';
import { banditParser } from '../runners/scannerParsers/bandit.js';
import { semgrepParser } from '../runners/scannerParsers/semgrep.js';
import { securityCodeScanParser } from '../runners/scannerParsers/securityCodeScan.js';
import { runProcess } from '../runners/processRunner.js';
import {
  buildSemgrepDockerArgs,
  DEFAULT_SEMGREP_IMAGE,
  toContainerPath,
} from '../runners/dockerScanner.js';
import {
  AllowDirty,
  AutoFix,
  Force,
  ProjectPath,
  SeverityMin,
} from '../schemas.js';
import type { ToolRun } from '../types.js';
import { resolveCustomSemgrepConfigs } from '../platform/customRules.js';
import {
  inspectProjectSemgrepConfigs,
  type ProjectSemgrepInspection,
} from '../platform/projectSemgrepConfig.js';
import { registerToolModule } from './index.js';
import {
  ensureReportDir,
  readJsonSafe,
  scannerAvailable,
} from './scanHelpers.js';
import {
  makeScanTool,
  type ScannerInvocation,
  type ScanToolBaseInput,
} from './scanToolFactory.js';

registerToolModule(
  makeScanTool<ScanToolBaseInput & { local_only?: boolean }>({
    name: 'scan_sast',
    title: 'SAST scan (Semgrep)',
    description:
      'Static analysis with Semgrep against the project. Runs the Semgrep registry ruleset ' +
      "(--config=auto), the project's own rules (.semgrep.yml, or whatever " +
      '.dev-guardian/configs.json records as its target) and any rules added with ' +
      'register_custom_rules. Also runs Bandit when Python files are present and the CLI is ' +
      'installed. Output JSON is written to .guardian/reports/sast-<scan>/ and parsed into ' +
      'Findings. PRIVACY: --config=auto downloads rules from the Semgrep registry and sends ' +
      'usage metrics to Semgrep Inc.; Semgrep refuses to build an auto config with metrics ' +
      'off, so this is unavoidable in the default mode. Pass local_only=true for a scan that ' +
      'contacts nothing and runs with --metrics=off, using only rules already on disk.',
    scan_type: 'sast',
    category: 'security',
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
          "Run only rules already on disk (the project's own Semgrep config plus anything " +
            'registered with register_custom_rules), skip the Semgrep registry, and pass ' +
            '--metrics=off so no telemetry leaves the machine. Fewer rules than the default. ' +
            'When the project has no local rules the scan is reported as skipped rather than ' +
            'as a clean result. Default: false.',
        ),
    },
    invoke: async (input, ctx): Promise<ScannerInvocation> => {
      const reportDir = ensureReportDir(ctx.projectPath, ctx.scanId, 'sast');
      const tools_run: ToolRun[] = [];
      const missing_tools: string[] = [];
      const parser_inputs: ScannerInvocation['parser_inputs'] = [];
      const autoFix = input.auto_fix === true;

      // --- Semgrep -----------------------------------------------------
      // C# / .NET signal: when csproj exists, also pin p/csharp rule pack.
      const hasCsproj = anyCsprojInProject(ctx.projectPath);
      const outFile = join(reportDir, 'sast.json');
      const localOnly = input.local_only === true;

      // The project's OWN rules: the pack `init_project` installed, plus
      // anything `register_custom_rules` added. Both resolvers drop paths that
      // no longer exist, because a --config that fails to resolve aborts the
      // WHOLE semgrep run (`paths.scanned: []`, exit 7), not just that pack;
      // `inspectProjectSemgrepConfigs` additionally refuses a file whose
      // CONTENTS would do the same, which is newly load-bearing now that a
      // file the user owns and edits is on this list.
      const projectRules: ProjectSemgrepInspection = inspectProjectSemgrepConfigs(ctx.projectPath);
      const localConfigs = [
        ...projectRules.usable.map((c) => c.path),
        ...resolveCustomSemgrepConfigs(ctx.plugin),
      ];
      // A dropped config means the user's own rules silently stopped running.
      // Carried into `tools_run.reason` on success as well as on failure.
      const configNotes = projectRules.unusable.map((u) => `${u.target} not loaded (${u.reason})`);

      // local_only with nothing on disk to run is not a clean scan, it is no
      // scan at all. Saying so beats reporting zero findings from zero rules.
      const nothingToRun = localOnly && localConfigs.length === 0;
      const semgrepBin = nothingToRun ? null : await scannerAvailable('semgrep');
      if (nothingToRun) {
        tools_run.push({
          name: 'semgrep',
          status: 'skipped',
          reason:
            'local_only=true but this project has no local Semgrep rules — no .semgrep.yml, ' +
            'nothing registered with register_custom_rules. Run init_project, or drop ' +
            'local_only to use the Semgrep registry.',
        });
        missing_tools.push('semgrep');
      } else if (semgrepBin) {
        const args: string[] = [];
        if (localOnly) {
          // Only ever safe once --config=auto is gone: Semgrep refuses to
          // build an auto config with metrics off.
          args.push('--metrics=off');
        } else {
          args.push('--config=auto');
          if (hasCsproj) args.push('--config=p/csharp');
        }
        for (const cfg of localConfigs) {
          args.push(`--config=${cfg}`);
        }
        args.push('--json', '--quiet', '--output', outFile);
        if (autoFix) args.push('--autofix');
        args.push(ctx.projectPath);

        const result = await runProcess({
          command: 'semgrep',
          args,
          cwd: ctx.projectPath,
          env: ctx.scriptEnv,
          signal: ctx.signal,
          onLog: ctx.onLog,
        });
        const raw = readJsonSafe(outFile);
        if (raw) {
          parser_inputs.push({ parser: semgrepParser, input: raw });
        }
        // exit 0 = no findings; exit 1 = findings present; exit 2 = errors
        // were raised but the scan still ran. The third case only became
        // reachable when we started loading the user's own rules: one rule of
        // theirs that fails to compile must cost that rule, not the whole
        // scan's status and its coverage rating with it. Measured: a rule with
        // an uncompilable pattern gives exit 2 with `paths.scanned` non-empty,
        // where a config Semgrep cannot load at all gives exit 7 and scans
        // nothing — so the scanned list, not the exit code, is what separates
        // "lost a rule" from "lost the scan".
        const ok =
          result.outcome === 'completed' ||
          result.exitCode === 1 ||
          (result.exitCode === 2 && semgrepScannedFiles(raw));
        const semgrepRun: ToolRun = { name: 'semgrep', status: ok ? 'ok' : 'failed' };
        const notes = [...configNotes];
        if (result.exitCode === 2) {
          notes.push('semgrep raised rule errors (exit 2) — at least one rule did not load');
        }
        if (!ok && result.stderr) {
          // Surface the first stderr line for diagnostics. Held as a local
          // rather than re-indexed off the end of the array, which needed an
          // assertion to restate what `push` had just guaranteed.
          notes.push(result.stderr.split(/\r?\n/)[0] ?? 'unknown');
        }
        if (notes.length > 0) semgrepRun.reason = notes.join('; ');
        tools_run.push(semgrepRun);
      } else {
        // Semgrep not on PATH — fall back to the official Docker image when a
        // daemon is reachable. This is what makes a SAST scan actually run on
        // hosts where the user only has Semgrep via Docker. If the Docker
        // attempt fails (no image, offline, daemon down), we record it as
        // failed + missing so coverage is honestly 'none' rather than a silent
        // "0 findings".
        const dockerBin = await scannerAvailable('docker');
        if (dockerBin) {
          const image = process.env['GUARDIAN_SEMGREP_IMAGE'] || DEFAULT_SEMGREP_IMAGE;
          // The container cannot see host paths, so a project config has to be
          // named by where it sits inside the /src mount. Registered custom
          // rules are deliberately absent: they can point anywhere on the host,
          // including outside the project, and a path the container cannot
          // resolve would abort the whole containerised run.
          const dockerConfigs = localOnly ? [] : ['auto'];
          for (const cfg of projectRules.usable) {
            dockerConfigs.push(toContainerPath(ctx.projectPath, cfg.path));
          }
          const args = buildSemgrepDockerArgs({
            projectPath: ctx.projectPath,
            outFileHost: outFile,
            hasCsproj: hasCsproj && !localOnly,
            autoFix,
            image,
            configs: dockerConfigs,
            metricsOff: localOnly,
          });
          const result = await runProcess({
            command: 'docker',
            args,
            cwd: ctx.projectPath,
            env: ctx.scriptEnv,
            signal: ctx.signal,
            onLog: ctx.onLog,
          });
          const raw = readJsonSafe(outFile);
          if (raw) parser_inputs.push({ parser: semgrepParser, input: raw });
          // exit 0/1 AND a report file means Semgrep actually ran in the
          // container. Anything else (image pull failed, daemon down) is a
          // real coverage gap, not a clean scan.
          const ranInDocker = (result.outcome === 'completed' || result.exitCode === 1) && raw !== null;
          if (ranInDocker) {
            tools_run.push({
              name: 'semgrep',
              status: 'ok',
              reason: `ran via docker (${image})`,
            });
          } else {
            const reason =
              result.stderr.split(/\r?\n/).find((l) => l.trim().length > 0) ??
              'docker fallback failed';
            tools_run.push({ name: 'semgrep', status: 'failed', reason: `docker: ${reason}` });
            missing_tools.push('semgrep');
          }
        } else {
          tools_run.push({
            name: 'semgrep',
            status: 'skipped',
            reason: 'not_installed (no docker fallback available)',
          });
          missing_tools.push('semgrep');
        }
      }

      // --- Bandit ------------------------------------------------------
      // Only attempt Bandit when the project obviously has Python sources.
      const looksPython =
        existsSync(join(ctx.projectPath, 'pyproject.toml')) ||
        existsSync(join(ctx.projectPath, 'requirements.txt')) ||
        existsSync(join(ctx.projectPath, 'setup.py'));
      if (looksPython) {
        const banditBin = await scannerAvailable('bandit');
        if (banditBin) {
          const outFile = join(reportDir, 'bandit.json');
          const result = await runProcess({
            command: 'bandit',
            args: ['-r', ctx.projectPath, '-f', 'json', '-o', outFile, '-q'],
            cwd: ctx.projectPath,
            env: ctx.scriptEnv,
            signal: ctx.signal,
            onLog: ctx.onLog,
          });
          const raw = readJsonSafe(outFile);
          if (raw) parser_inputs.push({ parser: banditParser, input: raw });
          // Bandit returns 1 when issues are found; treat as ok.
          const ok = result.outcome === 'completed' || result.exitCode === 1;
          tools_run.push({ name: 'bandit', status: ok ? 'ok' : 'failed' });
        } else {
          tools_run.push({ name: 'bandit', status: 'skipped', reason: 'not_installed' });
          missing_tools.push('bandit');
        }
      }

      // --- security-code-scan (Roslyn analyzer) -----------------------
      // Only fires when csproj refs `security-code-scan` already — we never
      // mutate user .csproj files. If the project opted-in, run dotnet build
      // and harvest the SCS#### lines from the log.
      if (hasCsproj && csprojReferencesScs(ctx.projectPath)) {
        const dotnetBin = await scannerAvailable('dotnet');
        if (dotnetBin) {
          const result = await runProcess({
            command: 'dotnet',
            args: ['build', '--no-incremental', '--verbosity:diag', ctx.projectPath],
            cwd: ctx.projectPath,
            env: ctx.scriptEnv,
            signal: ctx.signal,
            onLog: ctx.onLog,
            timeoutMs: 10 * 60_000,
          });
          // Parse SCS lines from stdout (build log).
          parser_inputs.push({ parser: securityCodeScanParser, input: result.stdout });
          tools_run.push({
            name: 'security-code-scan',
            status: result.outcome === 'completed' || result.exitCode === 1 ? 'ok' : 'failed',
            reason:
              result.outcome === 'completed'
                ? undefined
                : (result.stderr.split(/\r?\n/)[0] ?? 'dotnet build failed'),
          } as ToolRun);
        } else {
          tools_run.push({
            name: 'security-code-scan',
            status: 'skipped',
            reason: 'dotnet SDK not installed',
          });
          missing_tools.push('dotnet-sdk');
        }
      }

      const anyOk = tools_run.some((t) => t.status === 'ok');
      const outcome = anyOk ? 'completed' : missing_tools.length > 0 ? 'completed' : 'failed';

      return {
        outcome,
        tools_run,
        missing_tools,
        parser_inputs,
        report_paths: [reportDir],
      };
    },
  }),
);

function anyCsprojInProject(projectPath: string): boolean {
  try {
    return readdirSync(projectPath).some(
      (n) => n.endsWith('.csproj') || n.endsWith('.fsproj'),
    );
  } catch {
    return false;
  }
}

function csprojReferencesScs(projectPath: string): boolean {
  // Cheap check: scan the first-level *.csproj files for the
  // security-code-scan package name. We don't recurse — projects opting in
  // typically put the analyzer ref at the root csproj or a Directory.Build.props.
  let csprojs: string[];
  try {
    csprojs = readdirSync(projectPath).filter((n) => n.endsWith('.csproj'));
  } catch {
    return false;
  }
  for (const file of csprojs) {
    try {
      const xml = readFileSync(join(projectPath, file), 'utf8');
      if (/security[-_]?code[-_]?scan/i.test(xml)) return true;
    } catch {
      /* ignore */
    }
  }
  // Also check Directory.Build.props if present.
  const dbProps = join(projectPath, 'Directory.Build.props');
  if (existsSync(dbProps)) {
    try {
      const xml = readFileSync(dbProps, 'utf8');
      if (/security[-_]?code[-_]?scan/i.test(xml)) return true;
    } catch {
      /* ignore */
    }
  }
  return false;
}

/**
 * Did Semgrep actually look at any files?
 *
 * `paths.scanned` is what separates the two failure shapes that share an
 * angry exit code. A rule whose pattern will not compile exits 2 with a
 * populated `scanned` list — every file was analysed, one rule was lost. A
 * `--config` Semgrep cannot load at all exits 7 with `scanned: []` — nothing
 * was analysed and a "0 findings" result would be a lie. Reading the report
 * is the only way to tell them apart.
 *
 * Takes the raw report text `readJsonSafe` returns; never throws, and answers
 * `false` for anything it cannot make sense of, so an unparseable report can
 * never be mistaken for a successful scan.
 */
function semgrepScannedFiles(raw: string | null): boolean {
  if (raw === null) return false;
  try {
    const parsed: unknown = JSON.parse(raw);
    if (typeof parsed !== 'object' || parsed === null) return false;
    const paths = (parsed as Record<string, unknown>)['paths'];
    if (typeof paths !== 'object' || paths === null) return false;
    const scanned = (paths as Record<string, unknown>)['scanned'];
    return Array.isArray(scanned) && scanned.length > 0;
  } catch {
    return false;
  }
}
