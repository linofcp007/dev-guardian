/**
 * Every Semgrep spawn in this codebase — one helper, so none can forget
 * Python's UTF-8 mode (review M3).
 *
 * Semgrep's CLI is Python and, without `PYTHONUTF8=1`, reads rule files and
 * writes `--output` in the locale's encoding (`semgrepReport.ts#pythonUtf8Env`
 * has the measurements). scan_sast, the RGPD pack, create_fix_pr and the
 * surface scan set it; bug_hunt and scan_wordpress did not — so with
 * PYTHONUTF8 unset, a project holding a file named `日本.py` made Semgrep
 * 1.176.1 exit 2 without a report on Windows (cp1252): bug_hunt read "report
 * is not valid JSON (exit 2)" and advised installing Semgrep.
 *
 * `test/unit/runners/semgrepRun.test.ts` fails when any file in `src/` names
 * Semgrep as a command outside this one. The toolchain probe
 * (`semgrep --version`, `runners/installCatalog.ts`) is the one exception:
 * it reads no project.
 *
 * Semgrep's own version check asks Semgrep's servers for a newer release on
 * every run — `--metrics=off` and `local_only` included, and
 * `semgrep --version` too — unless `SEMGREP_ENABLE_VERSION_CHECK=0` (review
 * 3.0, wave 2). {@link SEMGREP_NO_VERSION_CHECK_ENV} goes into every spawn
 * here, into the Docker fallback's container (`dockerScanner.ts`, `-e`) and
 * into check_toolchain's probe (`installCatalog.ts`); `init_project`'s status
 * script sets it as well.
 *
 * On Windows, a run whose own walk could not list the tree — a directory too
 * long for Windows anywhere in it — is run again with those directories
 * excluded (`runners/semgrepLongDirs.ts`), and says which.
 */

import { readFileSync } from 'node:fs';
import {
  DEFAULT_SEMGREP_TIMEOUT_S,
  DEFAULT_SEMGREP_TIMEOUT_THRESHOLD,
  loadScanSettings,
  semgrepTimeoutArgs,
} from '../platform/scanSettings.js';
import { semgrepGuardianOutputExcludes } from '../platform/guardianOutput.js';
import { runProcess, type ProcessRunOptions, type ProcessRunResult } from './processRunner.js';
import { pythonUtf8Env } from './semgrepReport.js';
import { failedToListTargets, longDirsUnder, semgrepExcludeForDir } from './semgrepLongDirs.js';

/** The command itself, for callers that describe a Semgrep spawn as data (`scanFileBatches`, `batchArgs`). */
export const SEMGREP_COMMAND = 'semgrep';

/**
 * The flags every Semgrep scan of a project takes besides its rules: the
 * per-file timeout and threshold from `.guardian/scan.yml` under `configRoot`
 * (the project, or the CI gate's `--rules-ref` copy — `platform/scanSettings.ts`)
 * and the exclusion of dev-guardian's own output in the root `.guardian/` —
 * reports of earlier scans (`sast.json`, `surface.json`: 1.5 MB a run), the
 * database, the dashboard: a project whose `.gitignore` lacks the lines (every
 * CLI-only and CI project) had Semgrep read its old reports (review 8, finding
 * 14). Only those paths: a `.guardian` folder below the root is the project's
 * code, and 3.3.0's unanchored `--exclude=.guardian` let a
 * `lib/.guardian/handler.js` through the gate unscanned (review 10, finding 1)
 * — the spelling, and why, is `platform/guardianOutput.ts`'s. `warning`: the
 * settings file was there but not applied, and why — the caller says so on
 * the run.
 */
export function semgrepScanFlags(configRoot: string): { args: string[]; warning: string | null } {
  const loaded = loadScanSettings(configRoot);
  return {
    args: [...semgrepTimeoutArgs(loaded.settings), ...semgrepGuardianOutputExcludes()],
    warning:
      loaded.kind === 'invalid'
        ? `${loaded.path} was not applied (${loaded.error}) — Semgrep ran with dev-guardian's defaults ` +
          `(--timeout ${DEFAULT_SEMGREP_TIMEOUT_S} --timeout-threshold ${DEFAULT_SEMGREP_TIMEOUT_THRESHOLD})`
        : null,
  };
}

/** Semgrep's version check off — whatever the caller's environment says. */
export const SEMGREP_NO_VERSION_CHECK_ENV: Readonly<Record<string, string>> = { SEMGREP_ENABLE_VERSION_CHECK: '0' };

/** The environment variable Semgrep reads its metrics setting from. */
const METRICS_VAR = 'SEMGREP_SEND_METRICS';

/** `SEMGREP_SEND_METRICS` in `env` — its key as spelt there, and its value. */
function metricsSetting(env: NodeJS.ProcessEnv): { key: string; value: string } | null {
  const key = Object.keys(env).find((k) => k.toUpperCase() === METRICS_VAR);
  const value = key !== undefined ? env[key] : undefined;
  return key !== undefined && value !== undefined && value !== '' ? { key, value } : null;
}

/**
 * What Semgrep would make of a `SEMGREP_SEND_METRICS` value: one of its own
 * three (`on`, `off`, `auto` — exactly, lower case), one that plainly means
 * one of them (`OFF`, `0`, `false`, `no`; `ON`, `1`, `true`, `yes`; `AUTO`),
 * or neither. Semgrep itself refuses every value but the three — `0`,
 * `false` and `OFF` made EVERY Semgrep run exit 2 with a usage message (review
 * 12, finding 13).
 */
function readMetrics(value: string): 'on' | 'off' | 'auto' | null {
  const v = value.trim().toLowerCase();
  if (v === 'off' || v === '0' || v === 'false' || v === 'no') return 'off';
  if (v === 'on' || v === '1' || v === 'true' || v === 'yes') return 'on';
  if (v === 'auto') return 'auto';
  return null;
}

/**
 * The command and environment of a Semgrep spawn: the caller's environment
 * (or the server's) plus `PYTHONUTF8=1` and {@link SEMGREP_NO_VERSION_CHECK_ENV}
 * — with a `SEMGREP_SEND_METRICS` that plainly means `on`, `off` or `auto`
 * spelt as Semgrep takes it ({@link readMetrics}): the user's choice kept,
 * never turned around, only made readable to Semgrep.
 */
export function semgrepSpawn(env: NodeJS.ProcessEnv | undefined): { command: string; env: NodeJS.ProcessEnv } {
  const out: NodeJS.ProcessEnv = { ...pythonUtf8Env(env), ...SEMGREP_NO_VERSION_CHECK_ENV };
  const metrics = metricsSetting(out);
  const meant = metrics !== null ? readMetrics(metrics.value) : null;
  if (metrics !== null && meant !== null && metrics.value !== meant) {
    delete out[metrics.key];
    out[METRICS_VAR] = meant;
  }
  return { command: SEMGREP_COMMAND, env: out };
}

/**
 * Semgrep's own account of a failed run, from its stderr, or null when it
 * gave none (review 11 finding 10, review 12 finding 13):
 *
 *   - its `[ERROR]` line — `[00.07][ERROR]: Cannot create auto config when
 *     metrics are off. …`;
 *   - a command-line error — `semgrep scan: environment variable
 *     'SEMGREP_SEND_METRICS': invalid value '0', expected one of …`, its
 *     continuation lines joined (the first stderr line is only `Usage: …`);
 *   - a network error from the registry download — a proxy that does not
 *     answer, a refused connection, TLS — which Python prints as a
 *     traceback, with no `[ERROR]` line at all.
 */
export function semgrepErrorLine(stderr: string): string | null {
  const clip = (text: string): string => {
    const one = text.replace(/\s+/g, ' ').trim();
    return one.length > 500 ? `${one.slice(0, 500)}…` : one;
  };
  const lines = stderr.split(/\r?\n/);
  for (const line of lines) {
    const message = /\[ERROR\]:?\s*(\S.*)$/.exec(line)?.[1]?.trim();
    if (message !== undefined && message !== '') return clip(message);
  }
  for (const [i, line] of lines.entries()) {
    const m = /^semgrep(?: [a-z-]+)?: (\S.*)$/.exec(line.trim());
    if (m?.[1] === undefined) continue;
    const continued = [m[1]];
    for (const next of lines.slice(i + 1)) {
      if (!/^\s+\S/.test(next)) break;
      continued.push(next.trim());
    }
    return clip(continued.join(' '));
  }
  const network = lines.find((l) => /ProxyError|Max retries exceeded|SSLError|NewConnectionError|ConnectionError|Name or service not known|getaddrinfo/.test(l));
  return network !== undefined ? clip(network) : null;
}

/**
 * What the environment's `SEMGREP_SEND_METRICS` does to a run with `configs`,
 * or null when nothing (review 11 finding 10, review 12 finding 13):
 *
 *   - a value Semgrep refuses and no reading of it is plain ({@link readMetrics})
 *     — every Semgrep run fails, whatever its rules;
 *   - metrics off (`off`, `OFF`, `0`, `false`, …) and the registry rules
 *     (`--config=auto`, passed when not local-only), which Semgrep refuses to
 *     build with metrics off.
 *
 * The setting is the user's, so it is named with its value, never overridden:
 * dev-guardian does not turn metrics back on.
 */
export function metricsEnvProblem(configs: readonly string[], env: NodeJS.ProcessEnv | undefined): string | null {
  const metrics = metricsSetting(env ?? process.env);
  if (metrics === null) return null;
  const meant = readMetrics(metrics.value);
  const shown = `${METRICS_VAR}=${metrics.value}`;
  if (meant === null) {
    return (
      `${shown} is set in the environment, a value Semgrep refuses (it takes on, off or auto) — every Semgrep run ` +
      'fails: unset it, or set it to one of those'
    );
  }
  if (meant !== 'off' || !configs.some((c) => c === 'auto' || c === '--config=auto')) return null;
  return (
    `${shown} is set in the environment (metrics off), and Semgrep cannot build its registry rules ` +
    "(--config=auto) with metrics off: unset it for the scan, or scan local-only (local_only: true, the CLI's --local-only)"
  );
}

type SemgrepRunOptions = Omit<ProcessRunOptions, 'command'>;

/** A Semgrep run, and — Windows — the directories its retry left out (see the module comment). */
interface SemgrepRunResult extends ProcessRunResult {
  /** Project-relative, `/`-separated: the retry's `--exclude`s. Absent: no retry. */
  excludedLongDirs?: string[];
}

/** The `--output` report a failed run wrote, for its error messages; null when there is none. */
function failedReport(args: readonly string[]): string | null {
  const at = args.indexOf('--output');
  const out = at >= 0 ? args[at + 1] : undefined;
  if (out === undefined) return null;
  try {
    return readFileSync(out, 'utf8');
  } catch {
    return null;
  }
}

/**
 * Run Semgrep — through `run` when the caller injects one (create_fix_pr's
 * worktree runner). The directory target, when there is one, is the last
 * argument: on Windows a run whose walk could not list it is run once more,
 * the directories too long for Windows excluded.
 */
export async function runSemgrep(
  opts: SemgrepRunOptions,
  run: (options: ProcessRunOptions) => Promise<ProcessRunResult> = runProcess,
  platform: NodeJS.Platform = process.platform,
): Promise<SemgrepRunResult> {
  const first = await run({ ...opts, ...semgrepSpawn(opts.env) });
  const args = opts.args ?? [];
  const target = args.at(-1);
  if (platform !== 'win32' || target === undefined || first.exitCode === 0 || first.exitCode === null) return first;
  if (!failedToListTargets(failedReport(args), first.stdout, first.stderr)) return first;
  const dirs = longDirsUnder(target, platform);
  if (dirs.length === 0) return first;
  const retry = await run({ ...opts, args: [...args.slice(0, -1), ...dirs.map(semgrepExcludeForDir), target], ...semgrepSpawn(opts.env) });
  return { ...retry, excludedLongDirs: dirs };
}

/** The note a run that left directories out carries, for its `reason`; null when it left none out. */
export function longDirsNote(result: SemgrepRunResult): string | null {
  const dirs = result.excludedLongDirs;
  if (dirs === undefined || dirs.length === 0) return null;
  const shown = dirs.slice(0, 3).join(', ');
  return (
    `Semgrep could not list the project on Windows: ${dirs.length} director${dirs.length === 1 ? 'y' : 'ies'} at a path of ` +
    `248 characters or more ${dirs.length === 1 ? 'was' : 'were'} left out and the run repeated — ${shown}` +
    `${dirs.length > 3 ? ', …' : ''}; their files are named below`
  );
}
