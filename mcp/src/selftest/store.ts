/**
 * Where a selftest's result lives, and how it is read back.
 *
 * Two JSON files per INSTALL, in `<data directory>/selftest/` — never in a
 * project's database, which is per project and trusted per registry entry: a
 * selftest says something about this machine, not about a repository.
 *
 *   - `history.json` — the runs, newest first, at most {@link HISTORY_MAX};
 *   - `last.json` — the newest run alone, so that `health_status` reads a few
 *     kilobytes on every call and not fifty runs.
 *
 * Each is written to a temporary name and renamed, `history.json` first: two
 * runs at once may lose one entry of the history, never leave half a file.
 *
 * Nothing in the scan pipeline reads these files; they only inform. What is
 * read back is still validated — by shape, by date — because the answer is put
 * in front of a model as "this install was verified": a file that cannot be
 * read, is not the shape written here, is larger than the cap or is dated in
 * the future is treated as NO RESULT, with a note, never as a verification.
 *
 * What is stored holds no path, no environment value, no scanner output and
 * never the canary secret: a control's id, its verdict, the scanner's
 * version and a reason written by this code.
 */

import { mkdirSync, renameSync, unlinkSync, writeFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { join } from 'node:path';
import { z } from 'zod';
import { readSmallJsonFile } from '../hooks/configFile.js';
import { VERDICTS, countVerdicts, worstVerdict, type Verdict } from './verdict.js';

/** The data directory's sub-directory the two files live in. */
export const SELFTEST_DIR = 'selftest';
export const LAST_FILE = 'last.json';
export const HISTORY_FILE = 'history.json';
/** The runs the history keeps: the newest. */
export const HISTORY_MAX = 50;
/** A result older than this is no longer a verification of the install as it is. */
export const STALE_AFTER_DAYS = 30;
/** `last.json` is read on every `health_status` call: one run is a few kilobytes. */
export const LAST_MAX_BYTES = 64 * 1024;
export const HISTORY_MAX_BYTES = 1024 * 1024;
/** A clock a little ahead of this one is a clock, not a forged date. */
const FUTURE_TOLERANCE_MS = 5 * 60 * 1000;
const DAY_MS = 24 * 60 * 60 * 1000;

/** The schema's version: what `--json` prints and what is stored. */
export const SELFTEST_SCHEMA = 1;

/**
 * The scanners a selftest has controls for — the ones a saved result can say
 * something about. Here, on the read side, because `check_toolchain` needs
 * the list and reads nothing else of the selftest; the registry of controls
 * (`controls.ts`) takes it from here.
 */
export const SELFTEST_SCANNERS = ['semgrep', 'gitleaks', 'trivy'] as const;
export type SelftestScanner = (typeof SELFTEST_SCANNERS)[number];

export interface ControlResult {
  id: string;
  /** The scanner's name in the catalogue, or `hooks`. */
  scanner: string;
  /** The version that ran; `null` when it could not be learnt (or the scanner is missing). */
  scanner_version: string | null;
  verdict: Verdict;
  reason?: string;
  /** What to check next, on a verdict that asks for it. */
  next?: string;
  /** `detected` in the run saved before this one, and not now. */
  regressed?: true;
  /** What differs between the two runs: `plugin 3.8.1 → 3.9.0`, `semgrep 1.182.0 → 1.190.0`, the platform. */
  changed?: string[];
}

export interface SelftestRun {
  schema: typeof SELFTEST_SCHEMA;
  /** UTC, ISO 8601. */
  ran_at: string;
  plugin_version: string;
  /** `process.platform` and the architecture: `win32-x64`. */
  platform: string;
  controls: ControlResult[];
  /** Installed scanners the selftest has no canary for: listed, never counted as verified. */
  no_canary: string[];
  summary: Record<Verdict, number>;
  exit_code: 0 | 1 | 2;
  /** What the hook checks prove and what they do not. */
  hooks_note: string;
}

const text = (max: number) => z.string().max(max);
const controlSchema = z.strictObject({
  id: text(80).min(1),
  scanner: text(40).min(1),
  scanner_version: text(80).nullable(),
  verdict: z.enum(VERDICTS),
  reason: text(600).optional(),
  next: text(600).optional(),
  regressed: z.literal(true).optional(),
  changed: z.array(text(160)).max(8).optional(),
});
const runSchema = z.strictObject({
  schema: z.literal(SELFTEST_SCHEMA),
  ran_at: z.iso.datetime(),
  plugin_version: text(40).min(1),
  platform: text(40).min(1),
  controls: z.array(controlSchema).max(200),
  no_canary: z.array(text(40)).max(200),
  summary: z.strictObject(Object.fromEntries(VERDICTS.map((v) => [v, z.number().int().min(0)])) as Record<Verdict, z.ZodNumber>),
  exit_code: z.union([z.literal(0), z.literal(1), z.literal(2)]),
  hooks_note: text(400),
});

/** A stored run, or `undefined` for anything that is not exactly the shape written here. */
export function parseRun(value: unknown): SelftestRun | undefined {
  const r = runSchema.safeParse(value);
  return r.success ? (r.data as SelftestRun) : undefined;
}

export const selftestDir = (dataDir: string): string => join(dataDir, SELFTEST_DIR);

export type LastRead =
  | { state: 'none' }
  /** There is a file and it is not a result: never a verification. */
  | { state: 'invalid'; note: string }
  | { state: 'ok'; run: SelftestRun };

/** The newest saved run. `now` is what "dated in the future" is measured against. */
export function readLast(dataDir: string, now: number = Date.now()): LastRead {
  const file = join(selftestDir(dataDir), LAST_FILE);
  const read = readSmallJsonFile(file, LAST_MAX_BYTES, dataDir);
  if (read.status === 'absent') return { state: 'none' };
  if (read.status === 'refused') return { state: 'invalid', note: `the saved selftest result was not read (${read.reason})` };
  if (read.status === 'invalid') return { state: 'invalid', note: 'the saved selftest result is not JSON' };
  const run = parseRun(read.value);
  if (run === undefined) return { state: 'invalid', note: 'the saved selftest result is not in the shape dev-guardian writes' };
  if (Date.parse(run.ran_at) > now + FUTURE_TOLERANCE_MS) {
    return { state: 'invalid', note: 'the saved selftest result is dated in the future' };
  }
  return { state: 'ok', run };
}

export interface HistoryRead {
  /** Newest first. Empty when there is none, or when it could not be read. */
  runs: SelftestRun[];
  /** Why a history that exists was not read. */
  problem?: string;
}

/** The saved runs, newest first. A history that is there and is not valid is a `problem`, with no runs. */
export function readHistory(dataDir: string): HistoryRead {
  const file = join(selftestDir(dataDir), HISTORY_FILE);
  const read = readSmallJsonFile(file, HISTORY_MAX_BYTES, dataDir);
  if (read.status === 'absent') return { runs: [] };
  if (read.status === 'refused') return { runs: [], problem: `the selftest history was not read (${read.reason})` };
  if (read.status === 'invalid') return { runs: [], problem: 'the selftest history is not JSON' };
  const parsed = z.strictObject({ schema: z.literal(SELFTEST_SCHEMA), runs: z.array(runSchema).max(HISTORY_MAX * 4) }).safeParse(read.value);
  if (!parsed.success) return { runs: [], problem: 'the selftest history is not in the shape dev-guardian writes' };
  return { runs: parsed.data.runs as SelftestRun[] };
}

/** The verdicts a control that used to detect has regressed to. */
const REGRESSED_TO: ReadonlySet<Verdict> = new Set<Verdict>(['silent', 'unverified', 'missing']);

/**
 * `run` with every control that was `detected` in `previous` and is `silent`,
 * `unverified` or `missing` now marked `regressed`, and what differs between
 * the two runs. With no previous run, or a control that was not `detected`
 * in it, nothing is marked: a first run has nothing to regress from.
 */
export function markRegressions(run: SelftestRun, previous: SelftestRun | undefined): SelftestRun {
  if (previous === undefined) return run;
  const before = new Map(previous.controls.map((c) => [c.id, c]));
  const controls = run.controls.map((c): ControlResult => {
    const was = before.get(c.id);
    if (was === undefined || was.verdict !== 'detected' || !REGRESSED_TO.has(c.verdict)) return c;
    const changed: string[] = [];
    if (previous.plugin_version !== run.plugin_version) changed.push(`plugin ${previous.plugin_version} → ${run.plugin_version}`);
    if (was.scanner_version !== c.scanner_version) {
      changed.push(`${c.scanner} ${was.scanner_version ?? 'unknown'} → ${c.scanner_version ?? 'unknown'}`);
    }
    if (previous.platform !== run.platform) changed.push(`platform ${previous.platform} → ${run.platform}`);
    return { ...c, regressed: true, changed };
  });
  return { ...run, controls };
}

export interface SaveResult {
  saved: boolean;
  /** The directory the two files are in, when saved. */
  dir?: string;
  /** Why it was not saved. */
  note?: string;
  /** What happened to a history that could not be read. */
  history_note?: string;
}

/** `data` at `file`, through a temporary name in the same directory: a reader sees the old file or the new one. */
function writeAtomic(file: string, data: string): void {
  const temp = `${file}.${process.pid}.${randomBytes(4).toString('hex')}.tmp`;
  try {
    writeFileSync(temp, data, { flag: 'wx', mode: 0o600 });
    renameSync(temp, file);
  } catch (error) {
    try {
      unlinkSync(temp);
    } catch {
      /* it was never created, or the rename already took it */
    }
    throw error;
  }
}

/**
 * Save `run`: first in the history (newest first, the newest
 * {@link HISTORY_MAX}), then as `last.json`. A history that is there and
 * cannot be read is put aside under another name and a new one begun. Never
 * throws: a data directory that cannot be written is `saved: false` with the
 * reason — the result was reported all the same.
 */
export function saveRun(dataDir: string, run: SelftestRun, now: number = Date.now()): SaveResult {
  const dir = selftestDir(dataDir);
  try {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    const history = readHistory(dataDir);
    let historyNote: string | undefined;
    if (history.problem !== undefined) {
      const aside = join(dir, `history.unreadable-${new Date(now).toISOString().replace(/[:.]/g, '-')}.json`);
      try {
        renameSync(join(dir, HISTORY_FILE), aside);
        historyNote = `${history.problem}: it was put aside as ${aside} and a new history begun`;
      } catch (error) {
        historyNote = `${history.problem}, and it could not be put aside (${messageOf(error)}): a new history replaces it`;
      }
    }
    const runs = [run, ...history.runs].slice(0, HISTORY_MAX);
    writeAtomic(join(dir, HISTORY_FILE), `${JSON.stringify({ schema: SELFTEST_SCHEMA, runs })}\n`);
    writeAtomic(join(dir, LAST_FILE), `${JSON.stringify(run, null, 2)}\n`);
    return { saved: true, dir, ...(historyNote !== undefined ? { history_note: historyNote } : {}) };
  } catch (error) {
    return { saved: false, note: `the result was not saved in ${dir}: ${messageOf(error)}` };
  }
}

const messageOf = (error: unknown): string => (error instanceof Error ? error.message : String(error));

/** What `health_status` says of the selftest. `command` is the line the user runs. */
export interface SelftestStatus {
  state: 'never_run' | 'ok' | 'stale';
  ran_at?: string;
  age_days?: number;
  plugin_version?: string;
  counts?: Record<Verdict, number>;
  /** The controls that read their canary and reported nothing. */
  silent?: string[];
  /** The controls that detected in the run before the last and did not in the last. */
  regressed?: string[];
  stale_because?: string[];
  command: string;
  note?: string;
}

export interface SelftestStatusOptions {
  dataDir: string;
  /** The plugin's version now: a result of another version verified another install. */
  pluginVersion: string;
  /** The runnable command line, with the plugin's root resolved. */
  command: string;
  now?: number;
}

/**
 * The saved result as `health_status` gives it, and the warning — `null`
 * unless the last run has a control that is `silent` or `regressed`. A result
 * of another plugin version, or older than {@link STALE_AFTER_DAYS} days, is
 * `stale`: shown, said to be old, never offered as a verification of the
 * install as it is.
 */
export function selftestStatus(opts: SelftestStatusOptions): { selftest: SelftestStatus; warning: string | null } {
  const now = opts.now ?? Date.now();
  const last = readLast(opts.dataDir, now);
  if (last.state !== 'ok') {
    return {
      selftest: { state: 'never_run', command: opts.command, ...(last.state === 'invalid' ? { note: last.note } : {}) },
      warning: null,
    };
  }
  const run = last.run;
  const ageDays = Math.max(0, Math.floor((now - Date.parse(run.ran_at)) / DAY_MS));
  const staleBecause: string[] = [];
  if (run.plugin_version !== opts.pluginVersion) {
    staleBecause.push(`it verified dev-guardian ${run.plugin_version}; this is ${opts.pluginVersion}`);
  }
  if (ageDays > STALE_AFTER_DAYS) staleBecause.push(`it is ${ageDays} days old (more than ${STALE_AFTER_DAYS})`);
  const silent = run.controls.filter((c) => c.verdict === 'silent').map((c) => c.id);
  const regressed = run.controls.filter((c) => c.regressed === true).map((c) => c.id);
  const stale = staleBecause.length > 0;
  const selftest: SelftestStatus = {
    state: stale ? 'stale' : 'ok',
    ran_at: run.ran_at,
    age_days: ageDays,
    plugin_version: run.plugin_version,
    counts: countVerdicts(run.controls.map((c) => c.verdict)),
    silent,
    regressed,
    ...(stale ? { stale_because: staleBecause } : {}),
    command: opts.command,
  };
  return { selftest, warning: warningFor(run, silent, regressed, stale, opts.command) };
}

function warningFor(run: SelftestRun, silent: string[], regressed: string[], stale: boolean, command: string): string | null {
  if (silent.length === 0 && regressed.length === 0) return null;
  const parts: string[] = [];
  if (silent.length > 0) parts.push(`read their canary and reported nothing: ${silent.join(', ')}`);
  const onlyRegressed = regressed.filter((id) => !silent.includes(id));
  if (onlyRegressed.length > 0) parts.push(`detected before and did not this time: ${onlyRegressed.join(', ')}`);
  return (
    `The last dev-guardian selftest (${run.ran_at.slice(0, 10)}${stale ? ', an old result' : ''}) found controls that ` +
    `${parts.join('; and controls that ')}. A scan of those areas with 0 findings proves nothing on this machine: tell the ` +
    `user, and that \`${command}\` shows what to check.`
  );
}

/** What `check_toolchain` says of one scanner. */
export type ScannerSelftest =
  | 'never_verified'
  | {
      /** The worst verdict of the scanner's controls. */
      verdict: Verdict;
      ran_at: string;
      /** The version installed now is not the one that was verified. */
      stale: boolean;
      /** The scanner's controls that were `silent`, when any. */
      silent?: string[];
    };

/**
 * The last selftest's verdict for `scanner`: the worst of its controls, the
 * silent ones named. `never_verified` when there is no result, or none of its
 * controls is in it. `stale` when `installedVersion` is not the version that
 * was verified.
 */
export function scannerSelftest(last: LastRead, scanner: string, installedVersion: string): ScannerSelftest {
  if (last.state !== 'ok') return 'never_verified';
  const controls = last.run.controls.filter((c) => c.scanner === scanner);
  const verdict = worstVerdict(controls.map((c) => c.verdict));
  if (verdict === undefined) return 'never_verified';
  const silent = controls.filter((c) => c.verdict === 'silent').map((c) => c.id);
  const verified = controls.map((c) => c.scanner_version).find((v) => v !== null);
  return {
    verdict,
    ran_at: last.run.ran_at,
    stale: verified !== undefined && installedVersion !== '' && verified !== installedVersion,
    ...(silent.length > 0 ? { silent } : {}),
  };
}
