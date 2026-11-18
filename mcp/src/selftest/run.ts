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
 *   5. the five hook checks, through the installed dispatcher
 *      (`hookChecks.ts`) — the install check, which asks the network, is
 *      started first and runs beside the other four;
 *   6. the directory removed — also when a control throws, the run throws or
 *      it is interrupted — and only then the result saved (`store.ts`).
 *
 * It opens no database, reads no project of the user's and writes only in the
 * directory it made and in `<data directory>/selftest/`. Everything that
 * starts a process is behind {@link SelftestRunners}; the real ones are
 * `defaultRunners.ts`.
 */

import { realpathSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import { canaryPresent, canaryToken, createWorkspace, isRegularFile, leftoverWorkspaces, PROBE_RULE_FILE, removeWorkspace, seedCanaries, type Workspace } from './canaries.js';
import { CORE_CONTROLS, PROBE_RULE_ID, SCANNERS_WITH_CONTROLS, type Control, type ScannerName } from './controls.js';
import { answersAsExpected, HOOK_CHECKS, notVerifiedLine, SECRET_CANARY, softenedBy } from './hookChecks.js';
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
 * `run`'s result, or a `timeout` outcome when it has not settled `graceMs`
 * after its own time: a runner that ignores its timeout does not hold the
 * whole selftest.
 */
async function within<T>(run: Promise<T>, timeoutMs: number, graceMs: number, onTimeout: () => T): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const late = new Promise<T>((resolve) => {
    timer = setTimeout(() => resolve(onTimeout()), timeoutMs + graceMs);
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
    // What was seen, as it was seen: whether a run that did not end well may count is the verdict's to say.
    canaryReported: reported,
    ...(outcome.reason !== undefined ? { reason: outcome.reason } : {}),
  };
}

/** The longest reason kept: the stored schema's own bound. */
const REASON_MAX = 600;
/** An environment value shorter than this is a word, not something to hide. */
const ENV_VALUE_MIN = 8;

/**
 * What takes this machine out of a reason before it is printed or kept: the
 * secret canary, the paths (in either separator, and without regard to case
 * where the filesystem has none), and every value of the environment — a
 * scanner's own error may quote any of them. The reason stays readable: each
 * is replaced by its name, the text is one line, and it is bounded.
 */
function scrubberFor(paths: ReadonlyArray<readonly [label: string, path: string]>, env: NodeJS.ProcessEnv): (text: string) => string {
  const fold = process.platform !== 'linux';
  const swaps: Array<{ what: string; label: string; isPath: boolean }> = [{ what: canaryToken(), label: '<canary>', isPath: false }];
  for (const [label, path] of paths) {
    if (path.length >= 4) swaps.push({ what: path, label, isPath: true });
  }
  for (const [key, value] of Object.entries(env)) {
    if (value !== undefined && value.length >= ENV_VALUE_MIN) swaps.push({ what: value, label: `$${key}`, isPath: false });
  }
  // Longest first: a path inside a longer one is not what gets named. The canary before everything.
  swaps.sort((a, b) => Number(b.label === '<canary>') - Number(a.label === '<canary>') || b.what.length - a.what.length);
  /** `text` with every occurrence of `what` replaced — for a path, in either separator and, where case does not count, in any case. */
  const swap = (text: string, what: string, label: string, isPath: boolean): string => {
    if (!isPath) return text.split(what).join(label);
    // Character for character, so that an index in the folded text is an index in the text itself.
    const norm = (s: string): string => {
      const slashed = s.replace(/\\/g, '/');
      const lowered = fold ? slashed.toLowerCase() : slashed;
      return lowered.length === slashed.length ? lowered : slashed;
    };
    const needle = norm(what);
    let out = '';
    let rest = text;
    for (;;) {
      const at = norm(rest).indexOf(needle);
      if (at < 0) return out + rest;
      out += rest.slice(0, at) + label;
      rest = rest.slice(at + what.length);
    }
  };
  return (text) => {
    let out = text;
    for (const s of swaps) out = swap(out, s.what, s.label, s.isPath);
    out = out.replace(/\s+/g, ' ').trim();
    return out.length > REASON_MAX ? `${out.slice(0, REASON_MAX - 1)}…` : out;
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
  const env = opts.env ?? process.env;
  const now = opts.now ?? ((): Date => new Date());
  const signal = opts.signal ?? new AbortController().signal;
  const progress = opts.onProgress ?? ((): void => undefined);
  const controls = opts.controls ?? CORE_CONTROLS;
  const tmpRoot = opts.tmpRoot ?? tmpdir();
  const offline = env['GUARDIAN_OFFLINE'] === '1';
  const runners = opts.runners;
  const graceMs = opts.timeoutGraceMs ?? TIMEOUT_GRACE_MS;
  const home = opts.homeDir ?? homedir();
  const observed: Observed[] = [];
  let noCanary: string[] = [];
  let ws: Workspace | undefined;
  let workspaceLeft: SelftestReport['workspace'];
  let leftovers: string[] = [];

  const interrupted = (): boolean => signal.aborted;
  /** Built when the first reason needs it: by then the workspace exists. */
  let scrub: ((text: string) => string) | undefined;
  const clean = (text: string): string => {
    if (scrub === undefined) {
      const real = (path: string): string => {
        try {
          return realpathSync.native(path);
        } catch {
          return path;
        }
      };
      const paths: Array<readonly [string, string]> = [];
      if (ws !== undefined) paths.push(['<selftest directory>', ws.dir], ['<selftest directory>', basename(ws.dir)]);
      // The temporary root and the data directory, also as the filesystem spells them; the others as given.
      for (const [label, path] of [['<temporary directory>', tmpRoot], ['<data directory>', opts.dataDir]] as const) {
        paths.push([label, path], [label, real(path)]);
      }
      paths.push(['<current directory>', process.cwd()], ['~', home]);
      scrub = scrubberFor(paths, env);
    }
    return scrub(text);
  };
  const record = (control: Control, seen: Observation, version: string | null, installCommand?: string | null): void => {
    const observation: Observation = seen.reason !== undefined ? { ...seen, reason: clean(seen.reason) } : seen;
    observed.push({ control, observation, version, ...(installCommand !== undefined ? { installCommand } : {}) });
    progress(`${control.id}: ${judgeControl(observation)}`);
  };
  /** One scanner run for one control: never throws, never outlives its time by much. */
  const scan = async (control: Pick<Control, 'timeoutMs'>, run: () => Promise<ScanOutcome>): Promise<ScanOutcome> => {
    if (interrupted()) return NOT_RUN('interrupted before this control ran');
    try {
      return await within(run(), control.timeoutMs, graceMs, () => ({
        ended: 'timeout',
        reason: `did not finish in ${Math.round(control.timeoutMs / 1000)} s`,
        findings: [],
        read: null,
      }));
    } catch (error) {
      return { ended: 'failed', reason: `the control failed: ${messageOf(error)}`, findings: [], read: null };
    }
  };

  try {
    ws = createWorkspace(tmpRoot);
    const workspace = ws;
    leftovers = leftoverWorkspaces(tmpRoot, workspace.dir, now().getTime());
    const seeded = seedCanaries(opts.canariesDir, workspace);
    const scanArgs = (control: Pick<Control, 'timeoutMs'>): ScanArgs => ({
      project: workspace.project,
      reportDir: workspace.reports,
      timeoutMs: control.timeoutMs,
      signal,
      env,
    });

    progress('checking which scanners are installed');
    const probes = new Map<ScannerName, ScannerProbe>();
    await Promise.all(
      SCANNERS_WITH_CONTROLS.map(async (name) => {
        try {
          probes.set(name, await runners.probe(name));
        } catch (error) {
          probes.set(name, { installed: true, version: null, problem: `its version could not be asked: ${messageOf(error)}` });
        }
      }),
    );
    /** The scanner cannot be run at all: every control of it gets the same answer. Returns whether it can. */
    const usable = (control: Control): boolean => {
      const probe = probes.get(control.scanner as ScannerName);
      if (probe === undefined) return true;
      if (!probe.installed) {
        record(control, { installed: false, ended: 'not_run', canaryRead: null, canaryReported: false }, null, probe.installCommand ?? null);
        return false;
      }
      if (probe.problem !== undefined) {
        record(
          control,
          { installed: true, ended: 'failed', canaryRead: null, canaryReported: false, reason: `${control.scanner} is there and could not say its version: ${probe.problem}` },
          null,
        );
        return false;
      }
      return true;
    };
    const versionOf = (control: Control): string | null => probes.get(control.scanner as ScannerName)?.version ?? null;
    /** A canary that is not there cannot be found: said, never called silent. */
    const gone = (control: Control): boolean => {
      if (control.canary === null || canaryPresent(workspace, control.canary)) return false;
      record(
        control,
        {
          installed: true,
          ended: 'not_run',
          canaryRead: false,
          canaryReported: false,
          reason: `the canary ${control.canary} was not in the temporary project when its scan began (removed by something else on this machine — an antivirus quarantine?)`,
        },
        versionOf(control),
      );
      return true;
    };

    /**
     * A Semgrep run's environment: its own settings file and its own log, in
     * the selftest's directory. Every Semgrep run rewrites its settings file
     * and truncates its log — in the user's `~/.semgrep` unless told
     * otherwise — and two runs at a time race on that one file (measured on
     * Windows, 1.182.0: about one run in a hundred dies of a permission
     * error, and each collision leaves a stray `settings<random>.yml` in the
     * user's directory). One pair per run: nothing of the user's is written,
     * and no run can meet another's file.
     */
    const semgrepEnv = (run: string): NodeJS.ProcessEnv => ({
      ...env,
      SEMGREP_SETTINGS_FILE: join(workspace.state, `semgrep-${run}.settings.yml`),
      SEMGREP_LOG_FILE: join(workspace.state, `semgrep-${run}.log`),
    });

    // --- Semgrep: the probe, then one run per pack -------------------------------------------
    const packs = controls.filter((c) => c.kind === 'semgrep-pack').filter(usable);
    if (packs.length > 0) {
      progress('semgrep: the probe run (which canaries can it read here?)');
      const probeRun = await scan({ timeoutMs: PROBE_RUN_TIMEOUT_MS }, () =>
        runners.semgrep({ ...scanArgs({ timeoutMs: PROBE_RUN_TIMEOUT_MS }), env: semgrepEnv('probe'), rulesPath: join(workspace.rules, PROBE_RULE_FILE) }),
      );
      const readByProbe = probeRun.ended === 'ok' ? probeRun.findings.filter((f) => f.rule === PROBE_RULE_ID).map((f) => f.file) : null;
      await mapLimited(packs, SEMGREP_CONCURRENCY, async (control) => {
        if (gone(control)) return;
        const pack = control.pack ?? '';
        const outcome = await scan(control, () =>
          runners.semgrep({ ...scanArgs(control), env: semgrepEnv(pack.replace(/\.ya?ml$/i, '')), rulesPath: join(opts.packsDir, pack) }),
        );
        const canary = control.canary ?? '';
        const read = readByProbe === null ? null : readByProbe.some((f) => sameFile(f, canary));
        const observation = observe(control, outcome, read);
        if (outcome.ended === 'ok' && !observation.canaryReported && read !== true) {
          observation.reason =
            readByProbe === null
              ? `the pack did not report its canary, and the probe run did not end well (${probeRun.reason ?? probeRun.ended}): whether Semgrep can read the canary here is not known`
              : 'neither the pack nor the probe rule read the canary: Semgrep does not scan this temporary directory (an ignored path?)';
        }
        record(control, observation, versionOf(control));
      });
    }

    // --- gitleaks, Trivy ----------------------------------------------------------------------
    for (const control of controls.filter((c) => c.kind === 'gitleaks' || c.kind === 'trivy-deps' || c.kind === 'trivy-iac')) {
      if (!usable(control) || gone(control)) continue;
      const canary = control.canary ?? '';
      if (control.kind === 'trivy-deps' && offline) {
        record(
          control,
          { installed: true, ended: 'not_run', canaryRead: null, canaryReported: false, reason: 'GUARDIAN_OFFLINE=1: the dependency audit needs the vulnerability database, and nothing is fetched offline' },
          versionOf(control),
        );
        continue;
      }
      progress(`${control.id}: running`);
      const outcome = await scan(control, () =>
        control.kind === 'gitleaks'
          ? runners.gitleaks(scanArgs(control))
          : runners.trivy({ ...scanArgs(control), mode: control.kind === 'trivy-deps' ? 'deps' : 'iac', offline }),
      );
      // A scanner that names what it read is believed; one that does not read every file it is pointed at.
      const read = outcome.ended !== 'ok' ? null : outcome.read !== null ? outcome.read.some((f) => sameFile(f, canary)) : canaryPresent(workspace, canary);
      const observation = observe(control, outcome, read);
      if (outcome.ended === 'ok' && !observation.canaryReported && read === false) {
        observation.reason = outcome.read !== null ? `${control.scanner} did not read ${canary}` : `the canary ${canary} was gone when the scan ended`;
      }
      record(control, observation, versionOf(control));
    }

    // --- the hooks -----------------------------------------------------------------------------
    const hookControls = controls.filter((c) => c.kind === 'hook');
    if (hookControls.length > 0) {
      const dispatcherThere = isRegularFile(opts.dispatcherPath);
      // What the secret check "writes" is what was seeded: the same text gitleaks is pointed at.
      const secretText = seeded.get(SECRET_CANARY) ?? '';
      const notRun = (reason: string, installed = true): Observation => ({ installed, ended: 'not_run', canaryRead: null, canaryReported: false, reason });

      /** One launch of the dispatcher for `check`, judged. Never throws. */
      const launchHook = async (control: Control, check: (typeof HOOK_CHECKS)[number]): Promise<Observation> => {
        try {
          const answer = await within(
            runners.hook({
              dispatcher: opts.dispatcherPath,
              event: check.event,
              payload: check.payload(workspace, secretText),
              cwd: workspace.project,
              env: { ...env, CLAUDE_PROJECT_DIR: workspace.project },
              timeoutMs: control.timeoutMs,
              signal,
            }),
            control.timeoutMs,
            graceMs,
            (): HookAnswer => ({ exitCode: null, stdout: '', timedOut: true }),
          );
          if (answer.spawnError !== undefined) {
            return { installed: true, ended: 'failed', canaryRead: null, canaryReported: false, reason: `the dispatcher could not be started: ${answer.spawnError}` };
          }
          if (answer.timedOut) {
            return { installed: true, ended: 'timeout', canaryRead: null, canaryReported: false, reason: `the dispatcher did not answer in ${Math.round(control.timeoutMs / 1000)} s` };
          }
          if (answersAsExpected(check, answer.stdout)) return { installed: true, ended: 'ok', canaryRead: true, canaryReported: true };
          // The install check hears from the network: the hook's own "could not vet" line is not a guard letting the canary through.
          const notVerified = check.id === 'hooks:install-vet' ? notVerifiedLine(answer.stdout) : undefined;
          if (notVerified !== undefined) return { installed: true, ended: 'failed', canaryRead: null, canaryReported: false, reason: notVerified };
          // The dispatcher fails open: a blank answer is what this install's guard does with that command.
          const soft = softenedBy(check, env, home);
          return {
            installed: true,
            ended: 'ok',
            canaryRead: true,
            canaryReported: false,
            ...(soft !== undefined ? { softenedBy: soft } : {}),
            reason:
              check.id === 'hooks:install-vet'
                ? // Two causes this run cannot tell apart: the guard, or a canary npm no longer serves as its placeholder.
                  'the dispatcher ran and did not deny the install: the guard lets it through — or the registry no longer serves the security placeholder for the canary package'
                : check.expect === 'deny'
                  ? 'the dispatcher ran and did not deny it: on this install the guard lets it through'
                  : 'the dispatcher ran and gave no secret warning for a write that holds one',
          };
        } catch (error) {
          return { installed: true, ended: 'failed', canaryRead: null, canaryReported: false, reason: `the control failed: ${messageOf(error)}` };
        }
      };

      /** What a control gets without being launched — or `undefined` when it is to be launched. */
      const unlaunched = (check: (typeof HOOK_CHECKS)[number]): { observation: Observation; version: string | null } | undefined => {
        if (!dispatcherThere) return { observation: notRun("the hooks' dispatcher is not in this install", false), version: null };
        if (interrupted()) return { observation: notRun('interrupted before this control ran'), version: opts.pluginVersion };
        if (check.id !== 'hooks:install-vet') return undefined;
        // Package vetting alone is the user's to switch off and, offline, never launched: it would only ask the registry.
        const soft = softenedBy(check, env, home);
        if (soft !== undefined) {
          return {
            observation: { installed: true, ended: 'ok', canaryRead: true, canaryReported: false, softenedBy: soft, reason: 'not launched: the user switched package vetting off' },
            version: opts.pluginVersion,
          };
        }
        if (offline) {
          return { observation: notRun('GUARDIAN_OFFLINE=1: the install check needs the package registry, and nothing is fetched offline'), version: opts.pluginVersion };
        }
        return undefined;
      };

      const turnOf = async (control: Control, check: (typeof HOOK_CHECKS)[number]): Promise<{ observation: Observation; version: string | null }> =>
        unlaunched(check) ?? { observation: await launchHook(control, check), version: opts.pluginVersion };

      // The install check waits on the network: it starts first and is awaited at its own turn, so the report keeps its order.
      const vetControl = hookControls.find((c) => c.id === 'hooks:install-vet');
      const vetCheck = HOOK_CHECKS.find((h) => h.id === 'hooks:install-vet');
      const vetTurn = vetControl !== undefined && vetCheck !== undefined ? turnOf(vetControl, vetCheck) : undefined;
      try {
        for (const control of hookControls) {
          const check = HOOK_CHECKS.find((h) => h.id === control.id);
          if (check === undefined) continue;
          const turn = control === vetControl && vetTurn !== undefined ? await vetTurn : await turnOf(control, check);
          record(control, turn.observation, turn.version);
        }
      } finally {
        // Whatever ended the loop: the dispatcher started above has ended before the directory it runs in is removed.
        await vetTurn;
      }
    }

    // --- installed scanners the selftest has no canary for -------------------------------------
    if (!interrupted()) {
      try {
        const covered = new Set<string>(SCANNERS_WITH_CONTROLS);
        noCanary = (await runners.installedTools()).filter((name) => !covered.has(name)).sort();
      } catch {
        noCanary = [];
      }
    }
  } finally {
    if (ws !== undefined) {
      if (opts.keep === true) workspaceLeft = { path: ws.dir, kept: true };
      else {
        try {
          (opts.remove ?? removeWorkspace)(ws);
        } catch (error) {
          workspaceLeft = { path: ws.dir, kept: false, note: messageOf(error) };
        }
      }
    }
  }

  // A control the run never reached (interrupted) is unverified, never absent from the report.
  const reached = new Set(observed.map((o) => o.control.id));
  for (const control of controls) {
    if (reached.has(control.id)) continue;
    observed.push({
      control,
      observation: { installed: true, ended: 'not_run', canaryRead: null, canaryReported: false, reason: 'interrupted before this control ran' },
      version: null,
    });
  }

  const results = observed.map(resultOf).sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  const verdicts = results.map((r) => r.verdict);
  let exitCode = exitCodeFor(verdicts);
  // A directory that could not be removed is never a clean exit.
  if (exitCode === 0 && workspaceLeft !== undefined && !workspaceLeft.kept) exitCode = 2;
  let run: SelftestRun = {
    schema: SELFTEST_SCHEMA,
    ran_at: now().toISOString(),
    plugin_version: opts.pluginVersion,
    platform: opts.platform ?? `${process.platform}-${process.arch}`,
    controls: results,
    no_canary: noCanary,
    summary: { ...countVerdicts(verdicts), no_canary: noCanary.length },
    exit_code: exitCode,
    hooks_note: HOOKS_NOTE,
  };

  const wasInterrupted = interrupted();
  const history = readHistory(opts.dataDir);
  if (history.problem === undefined) run = markRegressions(run, history.runs[0]);
  let saved: SaveResult & { skipped?: 'no-save' | 'interrupted' };
  if (wasInterrupted) saved = { saved: false, skipped: 'interrupted' };
  else if (opts.save === false) saved = { saved: false, skipped: 'no-save' };
  else saved = saveRun(opts.dataDir, run, now().getTime());
  if (!saved.saved && saved.history_note === undefined && history.problem !== undefined) saved.history_note = history.problem;

  return {
    report: {
      run,
      ...(workspaceLeft !== undefined ? { workspace: workspaceLeft } : {}),
      saved,
      ...(wasInterrupted ? { interrupted: true } : {}),
      ...(leftovers.length > 0 ? { leftovers } : {}),
    },
    exitCode,
  };
}
