/**
 * One Semgrep run of one local rule file over a project — natively when
 * Semgrep is installed, through its Docker image otherwise.
 *
 * `map_attack_surface` runs the routes pack this way (`surface/scanSemgrep.ts`
 * judges the report), and `dev-guardian selftest` runs each of the plugin's
 * packs and its own probe rule the same way (`selftest/defaultRunners.ts`):
 * the selftest must run on the path a scan runs on, the Docker fallback
 * included, never on a second way of starting Semgrep.
 */

import { copyFileSync } from 'node:fs';
import { basename, join } from 'node:path';
import { gitSafetyFor } from '../platform/gitSafety.js';
import { scannerAvailable } from '../tools/scanHelpers.js';
import type { ToolRun } from '../types.js';
import { buildSemgrepDockerArgs, CONTAINER_PROJECT_ROOT, DEFAULT_SEMGREP_IMAGE, toContainerPath } from './dockerScanner.js';
import { runProcess, type ProcessRunResult } from './processRunner.js';
import { metricsEnvProblem, runSemgrep, semgrepErrorLine } from './semgrepRun.js';

interface SemgrepInvokeOptions {
  projectPath: string;
  rulesPath: string;
  outFile: string;
  reportDir: string;
  /** Flags after the config: the per-file timeouts, the jobs and the root `.guardian/` output excluded (`runners/semgrepRun.ts#semgrepScanFlags`). */
  extraArgs?: readonly string[];
  /** The run's own time limit. Default: the process runner's (`GUARDIAN_SCAN_TIMEOUT_MS`, ten minutes). */
  timeoutMs?: number;
  /** Stops the run (and its whole process tree) when aborted. */
  signal?: AbortSignal;
  /** The environment the run is given — and where `GUARDIAN_SEMGREP_IMAGE` is read. Default: this process's. */
  env?: NodeJS.ProcessEnv;
}

interface SemgrepInvocation {
  /** The PROCESS verdict alone (exit code, outcome) — never the report's; see `surface/scanSemgrep.ts#judgeSurfaceReport`. */
  toolRun: ToolRun;
  /** The process that ran, or null when the Docker fallback could not even stage the rules. */
  run: ProcessRunResult | null;
  /** `docker (<image>)` when the Docker fallback ran it, else null. */
  via: string | null;
  /**
   * The rule file as Semgrep was given it — the host path natively, its path
   * inside the mount through Docker — and the directory Semgrep ran in: what
   * Semgrep prefixes the file's rule ids from (`runners/semgrepRuleIds.ts`).
   */
  rules: { config: string; cwd: string };
}

/**
 * Run Semgrep against one rule file, natively if it's on PATH, otherwise via
 * Docker. Returns null only when neither is available — the caller treats
 * that as "cannot run at all" and persists nothing.
 *
 * Mirrors scan_sast's Docker fallback: probe `docker`, bind the project at
 * `/src`, run the container, and check for real output. The argv comes from
 * the shared `buildSemgrepDockerArgs` — this only differs in `--config`,
 * which the builder takes as an option, so the mount shape, the output
 * rewriting and anything added there later apply here too. The rule file
 * lives outside the project tree (in the dev-guardian install), so a copy is
 * staged inside the report dir — already inside the project, already inside
 * the bind mount — instead of adding a second `--mount`. The copy keeps the
 * rule file's own name (`routes.yml` for `map_attack_surface`, as it always
 * was): the selftest runs several packs at a time into one report directory,
 * and one fixed name had each run overwrite the rules of the others.
 */
export async function invokeSemgrep(options: SemgrepInvokeOptions): Promise<SemgrepInvocation | null> {
  const { projectPath, rulesPath, outFile, reportDir } = options;
  const limits = {
    ...(options.timeoutMs !== undefined ? { timeoutMs: options.timeoutMs } : {}),
    ...(options.signal !== undefined ? { signal: options.signal } : {}),
  };
  const semgrepBin = await scannerAvailable('semgrep');
  if (semgrepBin !== null) {
    // UTF-8 mode, like every other Semgrep call site: otherwise the locale
    // codec reads the rule pack and writes `--output` (runners/semgrepRun.ts).
    const run = await runSemgrep({
      args: ['--config', rulesPath, ...(options.extraArgs ?? []), '--json', '--output', outFile, '--quiet', projectPath],
      cwd: projectPath,
      env: options.env ?? process.env,
      ...limits,
    });
    return { toolRun: buildToolRun(run), run, via: null, rules: { config: rulesPath, cwd: projectPath } };
  }

  const dockerBin = await scannerAvailable('docker');
  if (dockerBin === null) return null;

  const image = (options.env ?? process.env)['GUARDIAN_SEMGREP_IMAGE'] || DEFAULT_SEMGREP_IMAGE;
  const via = `docker (${image})`;
  const stagedRules = join(reportDir, basename(rulesPath));
  const containerRules = toContainerPath(projectPath, stagedRules);
  const rules = { config: containerRules, cwd: CONTAINER_PROJECT_ROOT };
  try {
    copyFileSync(rulesPath, stagedRules);
  } catch (e) {
    return {
      toolRun: {
        name: 'semgrep',
        status: 'failed',
        reason: `docker: could not stage rule pack: ${(e as Error).message}`,
      },
      run: null,
      via,
      rules,
    };
  }

  const run = await runProcess({
    command: 'docker',
    args: buildSemgrepDockerArgs({
      projectPath,
      outFileHost: outFile,
      image,
      configs: [containerRules],
      ...(options.extraArgs !== undefined ? { extraArgs: options.extraArgs } : {}),
      git: await gitSafetyFor([projectPath]),
    }),
    cwd: projectPath,
    ...(options.env !== undefined ? { env: options.env } : {}),
    ...limits,
  });
  return { toolRun: buildToolRun(run, via), run, via, rules };
}

/**
 * The PROCESS half of the verdict. Semgrep exits 1 when it *finds* matches —
 * that is success, not failure; scan_sast, bug_hunt and scan_wordpress all
 * treat `outcome === 'completed' || exitCode === 1` as a clean exit. Reading
 * the raw outcome alone (as an earlier version of the surface tool did)
 * reported every successful route-finding run as `failed`.
 *
 * A clean exit is necessary and never sufficient: the report decides whether
 * the run actually scanned (`runners/semgrepReport.ts#checkSemgrepReport`).
 */
export function buildToolRun(run: ProcessRunResult, via?: string): ToolRun {
  const ok = run.outcome === 'completed' || run.exitCode === 1;
  if (ok) {
    return via ? { name: 'semgrep', status: 'ok', reason: `ran via ${via}` } : { name: 'semgrep', status: 'ok' };
  }
  const firstLine = failureCause(run.stderr) ?? undefined;
  const reason = via ? `${via}: ${firstLine ?? 'fallback failed'}` : (firstLine ?? 'unknown');
  return { name: 'semgrep', status: 'failed', reason };
}

/**
 * Why a Semgrep run failed, from its stderr: Semgrep's own message where it
 * printed one (`[ERROR]`, a command-line error, a network error — the first
 * line is often only `Usage: …`), and a `SEMGREP_SEND_METRICS` it refuses
 * (review 12, finding 13); else the first line, as before.
 */
export function failureCause(stderr: string): string | null {
  const said = semgrepErrorLine(stderr) ?? stderr.split(/\r?\n/).find((l) => l.trim().length > 0) ?? null;
  const metrics = metricsEnvProblem([], undefined);
  return said === null ? metrics : metrics === null ? said : `${said} — ${metrics}`;
}
