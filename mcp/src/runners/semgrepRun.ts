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

import { readFileSync, rmSync, writeFileSync } from 'node:fs';
import { win32 } from 'node:path';
import {
  DEFAULT_SEMGREP_TIMEOUT_S,
  DEFAULT_SEMGREP_TIMEOUT_THRESHOLD,
  loadScanSettings,
  semgrepTimeoutArgs,
} from '../platform/scanSettings.js';
import { semgrepGuardianOutputExcludes } from '../platform/guardianOutput.js';
import { runProcess, type ProcessRunOptions, type ProcessRunResult } from './processRunner.js';
import { effectiveTimeoutMs } from './processTimeout.js';
import { pythonUtf8Env } from './semgrepReport.js';
import { batchArgs } from './argBatches.js';
import { compileIgnore } from '../platform/guardianIgnore.js';
import {
  extendedLengthPath,
  failedToListTargets,
  longPathWalk,
  rewriteReportPaths,
  semgrepExcludeForDir,
  semgrepIgnores,
  windowsBase,
  windowsPathKey,
} from './semgrepLongDirs.js';

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

/** A Semgrep run, and — Windows — what was done about the paths too long for it (`runners/semgrepLongDirs.ts`). */
interface SemgrepRunResult extends ProcessRunResult {
  /** Project-relative, `/`-separated: the directories a repeated run excluded from its walk. Absent: none. */
  excludedLongDirs?: string[];
  /** How many files too long for the walk were read on their own, their findings merged into the report. Absent: none. */
  longFilesRead?: number;
  /** Why some of those were not read (the time ran out, a run wrote no report). Absent: none was left. */
  longFilesUnread?: string;
  /** The first run lost its report ({@link lostReport}) and this is the second. Absent: the first stood. */
  reportLostOnce?: true;
}

/**
 * pysemgrep has semgrep-core format its report, through an RPC child
 * (`semgrep/rpc_call.py#format`, 1.182.0); a child that does not answer —
 * it died, or did not exit within the second Semgrep gives it — leaves the
 * placeholder `<ERROR: missing output>` (SARIF: `<ERROR: no SARIF output>`)
 * where the report goes, and a scan that ran is lost. Seen under the test
 * suite's load, a run in a few hundred, a different scan each time: once
 * as "unparseable output: Unexpected token '<', \"<ERROR: mi\"…".
 */
const LOST_REPORT = /^\s*<ERROR: (?:missing output|no SARIF output)>/;

/** Whether `result` is a run whose report is Semgrep's placeholder: the `--output` file, else stdout. */
function lostReport(result: ProcessRunResult, out: string | undefined): boolean {
  const text = out !== undefined ? readReport(out) : result.stdout;
  return text !== null && LOST_REPORT.test(text);
}

/** The `--output` file the arguments name, if any. */
function outputOf(args: readonly string[]): string | undefined {
  const at = args.indexOf('--output');
  return at >= 0 ? args[at + 1] : undefined;
}

/** A report file's text; null when it cannot be read. */
function readReport(path: string | undefined): string | null {
  if (path === undefined) return null;
  try {
    return readFileSync(path, 'utf8');
  } catch {
    return null;
  }
}

function parsed(text: string | null): Record<string, unknown> | null {
  if (text === null) return null;
  try {
    const v: unknown = JSON.parse(text);
    return v !== null && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

const listOf = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);

/**
 * Run Semgrep — through `run` when the caller injects one (create_fix_pr's
 * worktree runner). The directory target, when there is one, is the last
 * argument. On Windows (see the module comment): a run whose walk could not
 * list it is run once more with the directories too long for Windows
 * excluded; then the source files too long for its walk are read on their own
 * as extended-length paths, and their findings merged into the run's
 * `--output` report.
 */
export async function runSemgrep(
  opts: SemgrepRunOptions,
  run: (options: ProcessRunOptions) => Promise<ProcessRunResult> = runProcess,
  platform: NodeJS.Platform = process.platform,
): Promise<SemgrepRunResult> {
  // One timeout for the whole call: the retry and the long files' runs get
  // what the first left of it, never the caller's whole budget again.
  const deadline = Date.now() + effectiveTimeoutMs(opts.timeoutMs);
  const args = opts.args ?? [];
  let first: SemgrepRunResult = await run({ ...opts, ...semgrepSpawn(opts.env) });
  // Once, in what is left of the timeout: a report the formatter lost says
  // nothing about the scan, and a second run is the only way to get it.
  if (first.outcome !== 'cancelled' && deadline > Date.now() && lostReport(first, outputOf(args))) {
    first = { ...(await run({ ...opts, timeoutMs: deadline - Date.now(), ...semgrepSpawn(opts.env) })), reportLostOnce: true };
  }
  const target = args.at(-1);
  if (platform !== 'win32' || target === undefined || first.exitCode === null || first.outcome === 'cancelled') return first;
  const out = outputOf(args);
  const listingFailed = first.exitCode !== 0 && failedToListTargets(readReport(out), first.stdout, first.stderr);
  // Searched only for what can be acted on: the long directories after a
  // walk that failed, the long files when there is a report to merge into.
  // Nothing for a file target: the search lists a directory.
  if (!listingFailed && out === undefined) return first;
  const walk = await longPathWalk(target, platform, { dirs: listingFailed });
  if (walk.dirs.length === 0 && walk.files.length === 0) return first;
  let result: SemgrepRunResult = first;
  if (listingFailed && walk.dirs.length > 0 && deadline > Date.now()) {
    const retry = await run({
      ...opts,
      args: [...args.slice(0, -1), ...walk.dirs.map(semgrepExcludeForDir), target],
      timeoutMs: deadline - Date.now(),
      ...semgrepSpawn(opts.env),
    });
    result = { ...retry, excludedLongDirs: walk.dirs };
  }
  if (walk.files.length === 0 || out === undefined || result.exitCode === null || result.outcome === 'cancelled') return result;
  const long = await readLongFiles({ opts, run, target, out, files: walk.files, semgrepignores: walk.semgrepignores, deadline });
  if (long.cancelled) return { ...result, outcome: 'cancelled' };
  return {
    ...result,
    ...(long.read > 0 ? { longFilesRead: long.read } : {}),
    ...(long.unread !== undefined ? { longFilesUnread: long.unread } : {}),
  };
}

/** What {@link readLongFiles} did. */
interface LongFilesRead {
  /** How many it read. */
  read: number;
  /** Why some it meant to read were not — they stay the long-path gap's to name. */
  unread?: string;
  /** A run of them was cancelled: so is the whole run. */
  cancelled?: boolean;
}

/**
 * The second run: the files the walk did not list for their length, each an
 * extended-length explicit target — never one the run's own `--exclude`s or a
 * `.semgrepignore` leave out, which explicit targets would bypass — merged
 * into `out` under the path the walk would have given (`target\rel`): their
 * results, errors, `paths` and taint timeouts (`time.fixpoint_timeouts`),
 * which make a run partial as an error does (`semgrepReport.ts`). Every batch
 * runs within what is left of the call's timeout; one cancelled stops them,
 * one cut short or failed stops them too, and the files left are named in
 * `unread` (the long-path gap names each). Nothing when there is nothing to
 * read, or the report is not one.
 */
async function readLongFiles(a: {
  opts: SemgrepRunOptions;
  run: (options: ProcessRunOptions) => Promise<ProcessRunResult>;
  target: string;
  out: string;
  files: readonly string[];
  semgrepignores: Parameters<typeof semgrepIgnores>[0]['semgrepignores'];
  deadline: number;
}): Promise<LongFilesRead> {
  const report = parsed(readReport(a.out));
  if (report === null) return { read: 0 };
  const paths = report['paths'];
  const base = windowsBase(a.target);
  // Semgrep names a target relative to its working directory, or absolute:
  // one set of project-relative keys, never a scan of the list per file.
  const prefixes = [a.target, base].map((p) => `${p.split('\\').join('/').replace(/\/+$/, '').toLowerCase()}/`);
  const scanned = new Set(
    listOf(paths !== null && typeof paths === 'object' ? (paths as Record<string, unknown>)['scanned'] : undefined)
      .filter((p): p is string => typeof p === 'string')
      .map((p) => {
        const key = p.split('\\').join('/').replace(/^\.\//, '').toLowerCase();
        const under = prefixes.find((prefix) => key.startsWith(prefix));
        return under === undefined ? key : key.slice(under.length);
      }),
  );
  const args = a.opts.args ?? [];
  const excludes = compileIgnore(args.filter((x) => x.startsWith('--exclude=')).map((x) => x.slice('--exclude='.length)).join('\n'));
  const wanted = a.files.filter((rel) => {
    if (scanned.has(rel.toLowerCase())) return false;
    // A `.semgrepignore` that could not be read may leave it out: not read
    // here, so the long-path gap names it rather than a finding in a file the
    // project excluded.
    return !excludes.ignores(rel) && semgrepIgnores({ semgrepignores: a.semgrepignores }, rel) === false;
  });
  if (wanted.length === 0) return { read: 0 };

  const norm = windowsPathKey;
  const given = new Map(wanted.map((rel) => [norm(win32.join(base, ...rel.split('/'))), win32.join(a.target, ...rel.split('/'))]));
  const targets = wanted.map((rel) => extendedLengthPath(win32.join(base, ...rel.split('/'))));
  // The run's own arguments, without its target and its report.
  const outAt = args.indexOf('--output');
  const fixed = args.slice(0, -1).filter((_x, i) => i !== outAt && i !== outAt + 1);
  const ownTime = report['time'];
  const merged = {
    results: listOf(report['results']),
    errors: listOf(report['errors']),
    scanned: [] as unknown[],
    skipped: [] as unknown[],
    fixpoint: [] as unknown[],
  };
  let read = 0;
  let unreadFiles = 0;
  let unreadWhy: string | undefined;
  const skip = (files: number, why: string): void => {
    unreadFiles += files;
    unreadWhy ??= why;
  };
  const spent = `the run's ${seconds(effectiveTimeoutMs(a.opts.timeoutMs))} timeout was spent`;
  const batches = batchArgs(targets, { command: SEMGREP_COMMAND, fixedArgs: [...fixed, '--output', a.out] });
  for (const [i, batch] of batches.entries()) {
    const after = batches.slice(i + 1).reduce((n, b) => n + b.length, 0);
    const left = a.deadline - Date.now();
    if (left <= 0) {
      skip(batch.length + after, spent);
      break;
    }
    const part = `${a.out}.long-${String(i + 1)}.json`;
    const r = await a.run({ ...a.opts, args: [...fixed, '--output', part, ...batch], timeoutMs: left, ...semgrepSpawn(a.opts.env) });
    const raw = parsed(readReport(part));
    rmSync(part, { force: true });
    if (r.outcome === 'cancelled') return { read, cancelled: true };
    if (raw === null) {
      skip(batch.length, r.outcome === 'timed_out' ? 'Semgrep timed out on them' : `Semgrep wrote no report on them (exit ${String(r.exitCode)})`);
    } else {
      const back = rewriteReportPaths(raw, (p) => given.get(norm(p)) ?? null) as Record<string, unknown>;
      const backPaths = back['paths'];
      const backTime = back['time'];
      const got = listOf(backPaths !== null && typeof backPaths === 'object' ? (backPaths as Record<string, unknown>)['scanned'] : undefined);
      merged.results.push(...listOf(back['results']));
      merged.errors.push(...listOf(back['errors']));
      merged.scanned.push(...got);
      merged.skipped.push(...listOf(backPaths !== null && typeof backPaths === 'object' ? (backPaths as Record<string, unknown>)['skipped'] : undefined));
      merged.fixpoint.push(...listOf(backTime !== null && typeof backTime === 'object' ? (backTime as Record<string, unknown>)['fixpoint_timeouts'] : undefined));
      read += got.length;
    }
    // Out of time: the batches after this one are not run.
    if (r.outcome === 'timed_out') {
      if (after > 0) skip(after, spent);
      break;
    }
  }
  const unread = unreadFiles > 0 && unreadWhy !== undefined ? `${String(unreadFiles)} file(s) at a path too long for Windows not read: ${unreadWhy}` : undefined;
  if (read === 0 && merged.errors.length === listOf(report['errors']).length && merged.fixpoint.length === 0) {
    return unread !== undefined ? { read: 0, unread } : { read: 0 };
  }
  const ownPaths = paths !== null && typeof paths === 'object' ? (paths as Record<string, unknown>) : {};
  const timeObj = ownTime !== null && typeof ownTime === 'object' ? (ownTime as Record<string, unknown>) : {};
  const next = {
    ...report,
    results: merged.results,
    errors: merged.errors,
    paths: {
      ...ownPaths,
      scanned: [...listOf(ownPaths['scanned']), ...merged.scanned],
      ...(merged.skipped.length > 0 || ownPaths['skipped'] !== undefined ? { skipped: [...listOf(ownPaths['skipped']), ...merged.skipped] } : {}),
    },
    ...(merged.fixpoint.length > 0 || ownTime !== undefined
      ? { time: { ...timeObj, fixpoint_timeouts: [...listOf(timeObj['fixpoint_timeouts']), ...merged.fixpoint] } }
      : {}),
  };
  writeFileSync(a.out, JSON.stringify(next), 'utf8');
  return unread !== undefined ? { read, unread } : { read };
}

/** `0.02 s`, `600 s`. */
function seconds(ms: number): string {
  return `${String(Math.round(ms / 10) / 100)} s`;
}

/** The note a run that worked around Windows' path limits carries, for its `reason`; null when it did not. */
export function longDirsNote(result: SemgrepRunResult): string | null {
  const dirs = result.excludedLongDirs ?? [];
  const files = result.longFilesRead ?? 0;
  const notes: string[] = [];
  if (dirs.length > 0) {
    const shown = dirs.slice(0, 3).join(', ');
    notes.push(
      `Semgrep could not list the project on Windows: ${dirs.length} director${dirs.length === 1 ? 'y' : 'ies'} at a path of ` +
        `248 characters or more ${dirs.length === 1 ? 'was' : 'were'} left out of its walk and the run repeated — ${shown}` +
        `${dirs.length > 3 ? ', …' : ''}`,
    );
  }
  if (files > 0) notes.push(`${files} file(s) at a path too long for Windows read on their own, as extended-length paths`);
  if (result.longFilesUnread !== undefined) notes.push(result.longFilesUnread);
  return notes.length > 0 ? notes.join('; ') : null;
}
