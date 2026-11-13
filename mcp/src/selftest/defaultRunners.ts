/**
 * The selftest's real runners: every process a selftest starts.
 *
 * Each one is the scan tools' own — never a second way of running a scanner,
 * or the selftest would prove something about itself and nothing about a
 * scan:
 *
 *   - Semgrep: `invokeSemgrep` (native, or its Docker fallback) with the flags
 *     every scan passes, the report judged by `checkSemgrepReport`;
 *   - gitleaks: `runGitleaksScan`, whose pass over a directory that is no
 *     repository is the one the seeded project gets;
 *   - Trivy: `runTrivy`, judged by `judgeTrivyFs` (the dependency audit) and
 *     `judgeTrivyConfig` (the IaC scan);
 *   - the versions: `scannerAvailable` and the catalogue's own probes, as
 *     `check_toolchain` asks them;
 *   - the hooks: {@link runDispatcher}.
 *
 * What they return is only what the orchestrator judges by: how the run
 * ended, what it reported on which file — the rule's id as the configuration
 * file writes it, never as the machine's paths spell it — and which files the
 * scanner says it read.
 *
 * A run that ended well and read nothing is `ok` with nothing read, never a
 * failure: whether that is a blind control or an ignored path is the
 * orchestrator's to tell, with the probe run (`run.ts`).
 */

import { rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import { detectOs } from '../platform/osDetect.js';
import { compareSemver } from '../platform/semverCompare.js';
import { ensureUserBinOnPath } from '../platform/userBin.js';
import { CONTAINER_PROJECT_ROOT, DEFAULT_SEMGREP_IMAGE } from '../runners/dockerScanner.js';
import { repoState } from '../runners/git.js';
import { runGitleaksScan } from '../runners/gitleaksScan.js';
import { suggestedInstallCommandString, TOOL_CATALOG } from '../runners/installCatalog.js';
import { asArray, getProp, getString, parseInputAsJson, toRelativeIfPossible } from '../runners/scannerParsers/index.js';
import { semgrepParserFor } from '../runners/scannerParsers/semgrep.js';
import { failureCause, invokeSemgrep } from '../runners/semgrepInvoke.js';
import { checkSemgrepReport } from '../runners/semgrepReport.js';
import { localRuleIdNormalizer, semgrepConfigPrefix } from '../runners/semgrepRuleIds.js';
import { semgrepScanFlags } from '../runners/semgrepRun.js';
import { runVersionProbe, type ProbeResult } from '../runners/toolProbe.js';
import { iacLookingFiles, judgeTrivyConfig } from '../runners/trivyConfig.js';
import { judgeTrivyFs, runTrivy, trivyFailureReason } from '../runners/trivyRun.js';
import { readJsonSafe, scannerAvailable } from '../tools/scanHelpers.js';
import type { ScannerName } from './controls.js';
import { runDispatcher } from './hookRunner.js';
import type { ScanArgs, ScanOutcome, ScannerProbe, SelftestRunners } from './run.js';
import type { RunEnd } from './verdict.js';

/** A run that reported nothing the orchestrator can use, and why. */
const ended = (how: RunEnd, reason: string): ScanOutcome => ({ ended: how, reason, findings: [], read: null });
const seconds = (ms: number): string => `${Math.round(ms / 1000)} s`;
const offlineIn = (env: NodeJS.ProcessEnv): boolean => env['GUARDIAN_OFFLINE'] === '1';
const INTERRUPTED = 'interrupted while it ran';

/**
 * The environment a scanner is started with: the caller's, with the per-user
 * tools directory on its PATH — what `scannerAvailable` does to this
 * process's PATH before it looks a scanner up (`platform/userBin.ts`). The
 * environment a selftest is handed is often a copy taken before that lookup,
 * and a scanner the probe found in `~/.local/bin` was then "not found on
 * PATH" when it was run (measured: gitleaks and Trivy, on Windows). One
 * `PATH` key, since a copy of a Windows environment spells it `Path` and a
 * second spelling beside it would win or lose by sort order.
 */
export function scannerEnv(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const win = process.platform === 'win32';
  const isPath = (key: string): boolean => (win ? key.toUpperCase() === 'PATH' : key === 'PATH');
  const spelled = Object.keys(env).filter(isPath).sort()[0];
  const out: NodeJS.ProcessEnv = Object.fromEntries(Object.entries(env).filter(([key]) => !isPath(key)));
  out['PATH'] = spelled !== undefined ? env[spelled] : process.env['PATH'];
  ensureUserBinOnPath(out);
  return out;
}

/**
 * `file` as the orchestrator names a canary: relative to the project, with
 * forward slashes. A path under the container's mount is the Docker
 * fallback's (`/src/base/canary.js`) and reads as the native run's does.
 */
function inProject(file: string, project: string): string {
  const rel = toRelativeIfPossible(file, project);
  const mount = `${CONTAINER_PROJECT_ROOT}/`;
  return rel.startsWith(mount) ? rel.slice(mount.length) : rel;
}

// ---------------------------------------------------------------- the versions

/** Version commands run a few at a time, as `check_toolchain` runs them. */
const PROBE_CONCURRENCY = 6;

/** Where a version command runs: never a directory a project could have put a file in. */
const probeDir = (): string => tmpdir();

/**
 * One scanner, as a scan would find it: resolved by `scannerAvailable`, its
 * version asked with the catalogue's own command. A scanner that is there and
 * cannot say its version is NOT missing: it is named with what went wrong,
 * and nothing of it is run. Semgrep without a native install is still
 * installed when Docker is there, since that is how a scan would run it.
 */
async function probe(scanner: ScannerName): Promise<ScannerProbe> {
  const found = await scannerAvailable(scanner);
  if (found === null) {
    if (scanner === 'semgrep' && (await scannerAvailable('docker')) !== null) {
      const image = process.env['GUARDIAN_SEMGREP_IMAGE'] || DEFAULT_SEMGREP_IMAGE;
      return { installed: true, version: `docker (${image})` };
    }
    return { installed: false, version: null, installCommand: suggestedInstallCommandString(scanner, detectOs()) };
  }
  const meta = TOOL_CATALOG[scanner];
  if (meta === undefined) return { installed: true, version: null, problem: `${scanner} is not in the tool catalogue` };
  const asked: ProbeResult = await runVersionProbe(meta.probe, probeDir());
  if (asked.installed) return { installed: true, version: asked.version !== '' ? asked.version : null };
  return { installed: true, version: null, problem: asked.error ?? `found at ${found}, but its version command could not be run` };
}

/**
 * The catalogue's tools that are installed, by name — each asked for its
 * version with its own command, as `check_toolchain` asks. `dotnet format`
 * counts with an SDK that ships it (.NET 6 on), as it does there.
 */
async function installedTools(): Promise<string[]> {
  const catalogue = Object.values(TOOL_CATALOG);
  const answers = new Map<string, ProbeResult>();
  for (let at = 0; at < catalogue.length; at += PROBE_CONCURRENCY) {
    const batch = catalogue.slice(at, at + PROBE_CONCURRENCY);
    const probed = await Promise.all(batch.map((meta) => runVersionProbe(meta.probe, probeDir())));
    batch.forEach((meta, i) => {
      const answer = probed[i];
      if (answer !== undefined) answers.set(meta.name, answer);
    });
  }
  const sdk = answers.get('dotnet-sdk');
  const sdkShipsFormat = sdk?.installed === true && (compareSemver(sdk.version, '6.0.0') ?? -1) >= 0;
  return catalogue
    .filter((meta) => answers.get(meta.name)?.installed === true || (meta.name === 'dotnet-format' && sdkShipsFormat))
    .map((meta) => meta.name);
}

// ---------------------------------------------------------------- Semgrep

/**
 * A selftest's rules are local files: nothing is fetched for them, and with
 * this nothing is reported to Semgrep either — what a local-only scan passes
 * (`runners/semgrepConfigs.ts`).
 */
const SEMGREP_LOCAL_ONLY = '--metrics=off';

/** The directory of a rule file, in whichever path flavour it is spelled (a host path, or `/src/…` inside the mount). */
const dirOf = (file: string): string => file.replace(/[\\/]+[^\\/]*$/, '');

/**
 * A reason without the rule file's directory in the rule ids Semgrep's own
 * messages spell (`C.Users.<name>.….configs.semgrep.<rule id>`): that is this
 * machine's path, dotted, and a reason is printed and kept.
 */
function withoutConfigPrefix(text: string, config: string): string {
  const prefix = semgrepConfigPrefix(config);
  return prefix === '' ? text : text.split(`${prefix}.`).join('');
}

/**
 * What a Semgrep that died said. Of a Python traceback, that is its last
 * line — the exception — where the first is only `Traceback (most recent
 * call last):`.
 */
function semgrepSaid(stderr: string): string | null {
  const said = failureCause(stderr);
  if (said === null || !said.startsWith('Traceback (most recent call last)')) return said;
  const lines = stderr
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line !== '');
  return lines.at(-1) ?? said;
}

/**
 * One Semgrep run of one local rule file over the seeded project.
 *
 * The report is this run's own — named after the rule file, since three
 * packs run at a time into one report directory. A rule's id comes back as
 * the file writes it: Semgrep prefixes it with the file's directory, dotted
 * (`runners/semgrepRuleIds.ts`), and that prefix is taken off for the
 * directory the file is in, whichever it is — the plugin's packs, a
 * selftest's probe rule, the copy the Docker fallback stages.
 *
 * A run that ended cleanly and scanned no file is `ok` with nothing read (a
 * rule file that loaded no rule; a project Semgrep does not walk): it did
 * not fail, and the probe run tells which of the two it is.
 *
 * Several of these run at a time. Two Semgrep processes sharing one settings
 * file race on it (`test/setup/semgrepSettings.ts` has the account; measured
 * here on Windows with 1.182.0: about one run in a hundred died of a
 * permission error with no report), so the orchestrator gives each run its
 * own `SEMGREP_SETTINGS_FILE` and `SEMGREP_LOG_FILE` in `args.env` (`run.ts`)
 * and this passes the environment through.
 */
async function semgrep(args: ScanArgs & { rulesPath: string }): Promise<ScanOutcome> {
  const name = basename(args.rulesPath);
  if (offlineIn(args.env) && (await scannerAvailable('semgrep')) === null) {
    return ended('not_run', 'GUARDIAN_OFFLINE=1: Semgrep is not installed here and would run from its Docker image, which Docker may have to download');
  }
  const outFile = join(args.reportDir, `semgrep-${name.replace(/\.ya?ml$/i, '')}.json`);
  // Never an earlier run's report read as this one's.
  rmSync(outFile, { force: true });
  const invocation = await invokeSemgrep({
    projectPath: args.project,
    rulesPath: args.rulesPath,
    outFile,
    reportDir: args.reportDir,
    extraArgs: [SEMGREP_LOCAL_ONLY, ...semgrepScanFlags(args.project).args],
    timeoutMs: args.timeoutMs,
    signal: args.signal,
    env: scannerEnv(args.env),
  });
  if (invocation === null) return ended('not_run', 'neither Semgrep nor Docker is installed');
  const run = invocation.run;
  if (run === null) return ended('failed', invocation.toolRun.reason ?? 'Semgrep could not be started');
  if (run.outcome === 'timed_out') return ended('timeout', `Semgrep did not finish ${name} in ${seconds(args.timeoutMs)}`);
  if (run.outcome === 'cancelled') return ended('not_run', INTERRUPTED);

  const raw = readJsonSafe(outFile);
  const { config, cwd } = invocation.rules;
  // The rule file's own directory stands for "the packs": its rules keep their own ids.
  const ruleIds = { cwd, packsDir: dirOf(config) };
  const check = checkSemgrepReport({
    raw,
    exitCode: run.exitCode,
    outcome: run.outcome,
    targets: 1,
    projectPath: args.project,
    ruleIdOf: localRuleIdNormalizer([config], { ...ruleIds, projectPath: args.project }),
  });
  if (check.verdict === 'failed') {
    const said = semgrepSaid(run.stderr);
    return ended('failed', withoutConfigPrefix([check.reason ?? 'Semgrep failed', ...(said !== null ? [said] : [])].join('; '), config));
  }
  if (check.verdict === 'scanned_nothing') {
    return {
      ended: 'ok',
      reason: `Semgrep ran ${name} to the end and scanned no file with it: no rule it loaded from that file reads anything in the project`,
      findings: [],
      read: [],
    };
  }
  const findings = semgrepParserFor([config], ruleIds)
    .parse(raw, { project_path: args.project })
    .findings.flatMap((f) => (f.rule_id !== undefined && f.file_path !== undefined ? [{ rule: f.rule_id, file: f.file_path }] : []));
  const read = asArray(getProp(getProp(parseInputAsJson(raw), 'paths'), 'scanned')).flatMap((p) => (typeof p === 'string' ? [inProject(p, args.project)] : []));
  if (check.verdict === 'partial') {
    return { ended: 'partial', reason: withoutConfigPrefix(check.reason ?? 'Semgrep read some files only in part', config), findings, read };
  }
  return { ended: 'ok', findings, read };
}

// ---------------------------------------------------------------- gitleaks

/**
 * The secret scan, as `scan_secrets` runs it on a directory that is no
 * repository: gitleaks over the files in place, redacted.
 *
 * Only that pass is the selftest's. Were the temporary project inside a
 * repository (a temporary directory someone keeps in a work tree),
 * `runGitleaksScan` would read that repository's history — the user's, not
 * the selftest's to read — and the seeded files only where git lists them:
 * the control is not run there, and says why.
 *
 * `ok` only when gitleaks ran and its report is there: its exit code for
 * "found one" is also its exit code for a configuration it could not load.
 * gitleaks does not say which files it read, so `read` is null.
 */
async function gitleaks(args: ScanArgs): Promise<ScanOutcome> {
  const state = await repoState(args.project);
  if (state.kind === 'error') {
    return ended('failed', `git could not say whether the temporary project is inside a repository (${state.message})`);
  }
  if (state.kind !== 'not_git') {
    return ended(
      'not_run',
      "the temporary directory is inside a git repository: the secret scan there reads that repository's history and only the files git lists, " +
        "neither of which is the selftest's — set TMPDIR (TEMP on Windows) to a directory outside any repository and run it again",
    );
  }
  const limit = AbortSignal.timeout(args.timeoutMs);
  const result = await runGitleaksScan({
    projectPath: args.project,
    reportDir: args.reportDir,
    scope: { kind: 'project' },
    env: scannerEnv(args.env),
    signal: AbortSignal.any([args.signal, limit]),
  });
  if (args.signal.aborted) return ended('not_run', INTERRUPTED);
  // Only a pass that was stopped: a scan that finished as its time ran out is a scan that finished.
  if (result.cancelled && limit.aborted) return ended('timeout', `gitleaks did not finish in ${seconds(args.timeoutMs)}`);

  const said = (status: string): string =>
    result.tools_run
      .filter((t) => t.status === status)
      .map((t) => t.reason ?? t.status)
      .join('; ');
  if (result.tools_run.some((t) => t.status === 'failed')) return ended('failed', said('failed'));
  if (!result.tools_run.some((t) => t.status === 'ok')) {
    const why = said('skipped');
    return why === 'not_installed' ? ended('not_run', 'gitleaks is not installed') : ended('failed', `gitleaks read nothing: ${why !== '' ? why : 'no pass ran'}`);
  }
  const findings = result.parser_inputs.flatMap(({ parser, input }) =>
    parser
      .parse(input, { project_path: args.project })
      .findings.flatMap((f) => (f.rule_id !== undefined && f.file_path !== undefined ? [{ rule: f.rule_id, file: f.file_path }] : [])),
  );
  if (result.missing_tools.length > 0) return { ended: 'partial', reason: said('ok'), findings, read: null };
  return { ended: 'ok', findings, read: null };
}

// ---------------------------------------------------------------- Trivy

/** What Trivy's own error says when it has no vulnerability database and could not get one (measured on 0.74.0: `init error: DB error: failed to download vulnerability DB: …`). */
const NO_VULNERABILITY_DB = /DB error|vulnerability DB|trivy-db/i;

/**
 * Offline, the IaC scan uses the checks it has: the bundle in Trivy's cache,
 * else the ones built into it — measured on 0.74.0 with an empty cache and no
 * network: no request at all with this flag, the same two findings on the
 * canary. Without it Trivy asks its registry for a newer bundle whenever the
 * cached one is a day old.
 */
const NO_CHECKS_DOWNLOAD = '--skip-check-update';

interface TrivyTarget {
  /** The file, relative to the project, forward slashes. */
  file: string;
  /** The package of each vulnerability reported in it. */
  vulnerable: string[];
  /** The id of each check that failed on it. */
  failed: string[];
}

/**
 * What a Trivy report lists: every file it read is a `Results` entry — one
 * with no `Vulnerabilities` / no `Misconfigurations` was read and is clean —
 * and a report with no `Results` at all read nothing.
 */
function trivyTargets(raw: string | null, project: string): TrivyTarget[] {
  return asArray(getProp(parseInputAsJson(raw), 'Results')).flatMap((result) => {
    const target = getString(result, 'Target');
    if (target === undefined) return [];
    const vulnerable = asArray(getProp(result, 'Vulnerabilities')).flatMap((v) => {
      const pkg = getString(v, 'PkgName');
      return pkg !== undefined ? [pkg] : [];
    });
    const failed = asArray(getProp(result, 'Misconfigurations')).flatMap((m) => {
      const id = getString(m, 'ID') ?? getString(m, 'AVDID');
      return id !== undefined && getString(m, 'Status') === 'FAIL' ? [id] : [];
    });
    return [{ file: inProject(target, project), vulnerable, failed }];
  });
}

/**
 * Trivy's dependency audit (`scan_deps`) or its IaC scan (`scan_iac`) over
 * the seeded project, each with the argv, the neutral configuration and the
 * judgement the tool gives it.
 *
 * A dependency audit with no vulnerability database on the machine and none
 * to be had fails, and says that — never "no vulnerability found". The
 * orchestrator does not ask for it offline; asked anyway, it is not run.
 */
async function trivy(args: ScanArgs & { mode: 'deps' | 'iac'; offline: boolean }): Promise<ScanOutcome> {
  const deps = args.mode === 'deps';
  if (deps && args.offline) {
    return ended('not_run', 'GUARDIAN_OFFLINE=1: the dependency audit needs the vulnerability database, and nothing is fetched offline');
  }
  const outFile = join(args.reportDir, deps ? 'deps.json' : 'iac.json');
  rmSync(outFile, { force: true });
  const run = await runTrivy({
    // scan_deps' argv, and scan_iac's (no --quiet there: a file Trivy cannot parse is one line of its log).
    args: deps
      ? ['fs', '--scanners', 'vuln,license', '--format', 'json', '--output', outFile, '--quiet']
      : ['config', '--format', 'json', '--output', outFile, ...(args.offline ? [NO_CHECKS_DOWNLOAD] : [])],
    target: args.project,
    workDir: args.reportDir,
    ignoreFrom: args.project,
    env: scannerEnv(args.env),
    signal: args.signal,
    timeoutMs: args.timeoutMs,
  });
  if (run.outcome === 'timed_out') return ended('timeout', `Trivy did not finish in ${seconds(args.timeoutMs)}`);
  if (run.outcome === 'cancelled') return ended('not_run', INTERRUPTED);

  const raw = readJsonSafe(outFile);
  let judged: { toolRun: { status: string; reason?: string }; missing: string[] };
  if (deps) {
    judged = judgeTrivyFs({ projectPath: args.project, raw, run, exclusions: null });
  } else {
    const iac = run.outcome === 'completed' ? iacLookingFiles(args.project, null) : null;
    judged = judgeTrivyConfig({
      name: 'trivy-config',
      run,
      raw,
      iacFiles: iac?.files ?? [],
      ...(iac?.incomplete !== undefined ? { iacIncomplete: iac.incomplete } : {}),
    });
  }
  if (judged.toolRun.status === 'failed') {
    // A Trivy that never started says why in `notRun`; the judge's reason for it is the bare outcome.
    const why = run.notRun?.message ?? judged.toolRun.reason ?? trivyFailureReason(run);
    return deps && NO_VULNERABILITY_DB.test(run.stderr)
      ? ended('failed', `Trivy's vulnerability database is not available: there is none on this machine and it could not be downloaded (${why})`)
      : ended('failed', why);
  }
  const targets = trivyTargets(raw, args.project);
  const findings = targets.flatMap((t) => (deps ? t.vulnerable : t.failed).map((rule) => ({ rule, file: t.file })));
  const read = targets.map((t) => t.file);
  // `skipped`: Trivy ran and read no file it knows — nothing read, which the orchestrator says of the canary.
  if (judged.toolRun.status === 'ok' && judged.missing.length > 0) {
    return { ended: 'partial', reason: judged.toolRun.reason ?? `Trivy did not cover everything: ${judged.missing.join(', ')}`, findings, read };
  }
  return { ended: 'ok', findings, read };
}

export function defaultRunners(): SelftestRunners {
  return { probe, semgrep, gitleaks, trivy, hook: runDispatcher, installedTools };
}
