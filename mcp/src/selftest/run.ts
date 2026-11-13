// @ts-nocheck -- Phase 4 scaffold (dev-spec-driven): the failing tests come first; the implementation replaces these bodies.
/**
 * `dev-guardian selftest` — does each core control DETECT on this machine?
 *
 * `check_toolchain` asks a scanner for its version: that proves it is
 * installed, not that it sees. This seeds a temporary project with canaries —
 * one small file per control, each with one known defect — runs every control
 * the way the scan tools run it, and gives each a verdict (`verdict.ts`).
 *
 * The order of a run:
 *
 *   1. a new private directory, the canaries copied into it (`canaries.ts`);
 *   2. each scanner's version;
 *   3. Semgrep: one PROBE run with the selftest's own rule over the whole
 *      tree — it says which canaries Semgrep can read on this path — then one
 *      run per pack, three at a time. A pack that does not report a canary
 *      the probe read is `silent`; one the probe never read is `unverified`.
 *      That is what tells a blind pack from an ignored path;
 *   4. gitleaks, Trivy's dependency audit, Trivy's IaC scan;
 *   5. the four hook checks, through the installed dispatcher
 *      (`hookChecks.ts`);
 *   6. the directory removed — also when a control throws, the run throws or
 *      it is interrupted — and only then the result saved (`store.ts`).
 *
 * It opens no database, reads no project of the user's and writes only in the
 * directory it made and in `<data directory>/selftest/`. Everything that
 * starts a process is behind {@link SelftestRunners}; the real ones are
 * `defaultRunners.ts`.
 */

import { readFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';
import { canaryPresent, createWorkspace, leftoverWorkspaces, PROBE_RULE_FILE, removeWorkspace, seedCanaries, type Workspace } from './canaries.js';
import { CORE_CONTROLS, PROBE_RULE_ID, SCANNERS_WITH_CONTROLS, type Control, type ScannerName } from './controls.js';
import { answersAsExpected, HOOK_CHECKS, SECRET_CANARY, softenedBy } from './hookChecks.js';
import { HOOKS_NOTE, nextStepFor, type SelftestReport } from './report.js';
import { markRegressions, readHistory, saveRun, SELFTEST_SCHEMA, type ControlResult, type SaveResult, type SelftestRun } from './store.js';
import { countVerdicts, exitCodeFor, judgeControl, type Observation, type RunEnd } from './verdict.js';

/** What one scanner run came to, in terms every control can be judged by. */
export interface ScanOutcome {
  ended: RunEnd;
  /** Why, when it did not end `ok` — or what is worth saying of a run that did. */
  reason?: string;
  /**
   * What was reported: the rule's id as the pack writes it (Semgrep), the
   * rule (gitleaks), the package's name (Trivy's dependency audit) or the
   * check's id (Trivy's IaC scan) — and the file, relative to the project,
   * with forward slashes.
   */
  findings: ReadonlyArray<{ rule: string; file: string }>;
  /** The files the scanner says it read (relative, forward slashes); `null` when it does not say. */
  read: readonly string[] | null;
}

export interface ScannerProbe {
  installed: boolean;
  /** The version that will run; `null` when it could not be read. */
  version: string | null;
  /** The scanner is there and could not say its version: nothing of it is run. */
  problem?: string;
  /** How it is installed on this system, for a scanner that is missing. */
  installCommand?: string | null;
}

export interface ScanArgs {
  /** The seeded project: the scan's root. */
  project: string;
  /** Where the scanner's report goes: inside the project, as a real scan's does. */
  reportDir: string;
  timeoutMs: number;
  signal: AbortSignal;
  env: NodeJS.ProcessEnv;
}

export interface HookRunArgs {
  /** The installed dispatcher, `hooks/guardian-hook.mjs`. */
  dispatcher: string;
  event: string;
  /** Written to the dispatcher's standard input as JSON — the only place a check's command is. */
  payload: Record<string, unknown>;
  cwd: string;
  env: NodeJS.ProcessEnv;
  timeoutMs: number;
  signal: AbortSignal;
}

export interface HookAnswer {
  exitCode: number | null;
  stdout: string;
  timedOut: boolean;
  /** The dispatcher never started. */
  spawnError?: string;
}

/** Everything a selftest does outside its own directory: every process it starts. */
export interface SelftestRunners {
  probe(scanner: ScannerName): Promise<ScannerProbe>;
  /** One Semgrep run with one local configuration file. */
  semgrep(args: ScanArgs & { rulesPath: string }): Promise<ScanOutcome>;
  gitleaks(args: ScanArgs): Promise<ScanOutcome>;
  trivy(args: ScanArgs & { mode: 'deps' | 'iac'; offline: boolean }): Promise<ScanOutcome>;
  hook(args: HookRunArgs): Promise<HookAnswer>;
  /** The catalogue's tools that are installed, by name. */
  installedTools(): Promise<string[]>;
}

export interface SelftestOptions {
  runners: SelftestRunners;
  /** `configs/semgrep/`: one control per pack. */
  packsDir: string;
  /** `configs/selftest/`: the shipped canaries. */
  canariesDir: string;
  /** `hooks/guardian-hook.mjs` of this install. */
  dispatcherPath: string;
  /** dev-guardian's per-user data directory. */
  dataDir: string;
  pluginVersion: string;
  /** Where the temporary directory is made. Default: the system's. */
  tmpRoot?: string;
  now?: () => Date;
  env?: NodeJS.ProcessEnv;
  /** The home directory the user-level hooks configuration is read from. Default: this user's. */
  homeDir?: string;
  signal?: AbortSignal;
  /** Keep the temporary directory and say where it is. */
  keep?: boolean;
  /** `false`: report, save nothing. */
  save?: boolean;
  onProgress?: (line: string) => void;
  controls?: readonly Control[];
  /** `process.platform` and the architecture. */
  platform?: string;
  /** Removes the workspace. Default: `removeWorkspace`. */
  remove?: (ws: Workspace) => void;
  /** Past a runner's own timeout, how long it is waited for before its control is given up as timed out. */
  timeoutGraceMs?: number;
}

export interface SelftestResult {
  report: SelftestReport;
  /** 0, 1 (a control is silent) or 2 (unverified or missing; or a directory that could not be removed). */
  exitCode: 0 | 1 | 2;
}

/** Semgrep runs at a time: each is a Python process that takes a core. */
const SEMGREP_CONCURRENCY = 3;
/** The probe run and a version query. */
const PROBE_RUN_TIMEOUT_MS = 120_000;
/** Past a runner's own timeout, how long it is waited for before the control is given up as timed out. */
const TIMEOUT_GRACE_MS = 5_000;

const messageOf = (error: unknown): string => (error instanceof Error ? error.message : String(error));
const sameFile = (a: string, b: string): boolean => a.replace(/\\/g, '/').replace(/^\.\//, '') === b;

interface Observed {
  control: Control;
  observation: Observation;
  version: string | null;
  installCommand?: string | null;
}

/**
 * `run`'s result, or a `timeout` outcome when it has not settled
 * {@link TIMEOUT_GRACE_MS} after its own time: a runner that ignores its
 * timeout does not hold the whole selftest.
 */
async function within<T>(run: Promise<T>, timeoutMs: number, onTimeout: () => T): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const late = new Promise<T>((resolve) => {
    timer = setTimeout(() => resolve(onTimeout()), timeoutMs + TIMEOUT_GRACE_MS);
    timer.unref();
  });
  try {
    return await Promise.race([run, late]);
  } finally {
    clearTimeout(timer);
  }
}

/** `items` through `fn`, at most `limit` at a time, results in order. */
async function mapLimited<T, R>(items: readonly T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const out = new Array<R>(items.length);
  let next = 0;
  const worker = async (): Promise<void> => {
    for (;;) {
      const i = next++;
      const item = items[i];
      if (item === undefined) return;
      out[i] = await fn(item);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return out;
}

const NOT_RUN = (reason: string): ScanOutcome => ({ ended: 'not_run', reason, findings: [], read: null });

/** What a scanner's outcome says of one control's canary. */
function observe(control: Control, outcome: ScanOutcome, canaryRead: boolean | null): Observation {
  const canary = control.canary;
  const reported =
    canary !== null && outcome.findings.some((f) => sameFile(f.file, canary) && (control.expect === '*' || f.rule === control.expect));
  return {
    installed: true,
    ended: outcome.ended,
    canaryRead,
    canaryReported: outcome.ended === 'ok' && reported,
    ...(outcome.reason !== undefined ? { reason: outcome.reason } : {}),
  };
}

const DEFAULT_REASON: Record<RunEnd, string> = {
  ok: 'the run ended, and whether it read the canary could not be learnt',
  partial: 'the scanner says it did not cover everything it was given',
  failed: 'the run failed',
  timeout: 'the run did not finish in its time',
  not_run: 'the control was not run',
};

function resultOf(o: Observed): ControlResult {
  const verdict = judgeControl(o.observation);
  let reason: string | undefined;
  if (verdict === 'missing') reason = o.observation.reason ?? `${o.control.scanner} is not installed`;
  else if (verdict === 'disabled_by_user') reason = `switched off by the user: ${o.observation.softenedBy ?? 'a setting of theirs'}`;
  else if (verdict === 'silent') reason = o.observation.reason ?? 'ran to the end, read the canary and did not report it';
  else if (verdict === 'unverified') reason = o.observation.reason ?? DEFAULT_REASON[o.observation.ended];
  const result: ControlResult = {
    id: o.control.id,
    scanner: o.control.scanner,
    scanner_version: o.version,
    verdict,
    ...(reason !== undefined ? { reason } : {}),
  };
  const next = nextStepFor(result, {
    ...(o.installCommand !== undefined ? { installCommand: o.installCommand } : {}),
    ...(o.control.pack !== undefined ? { pack: o.control.pack } : {}),
  });
  return next !== undefined ? { ...result, next } : result;
}

/** Run the selftest. Rejects only when it could not even begin (no temporary directory, no canaries): the directory is removed first. */
export async function runSelftest(opts: SelftestOptions): Promise<SelftestResult> {
  throw new Error('selftest: not implemented');
}
