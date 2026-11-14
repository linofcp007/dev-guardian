/**
 * The session mark: how `health_status` knows that the guardrail hooks
 * started in this Claude Code session.
 *
 * A Claude Code older than 2.1.139 does not pass a hook entry's `args`, so no
 * hook starts at all and none can say so — not even SessionStart, which never
 * runs — while the MCP server keeps answering and the session looks guarded.
 * So SessionStart leaves a small mark in the user's data directory, outside
 * the project, and the server looks for the mark of the host process that
 * started it.
 *
 * Both sides use this module: the dispatcher through the session part of the
 * hooks bundle (`hooksSession.ts`), to write; `tools/healthStatus.ts`, to
 * read. Node built-ins, `userDataDir.ts` and `configFile.ts` only — the hooks
 * bundle carries no npm package and no storage layer.
 *
 * "This session" is the host process. Measured (Windows, Claude Code 2.1.322):
 * the plugin's MCP server and its hooks are both children of the same
 * `claude.exe`, and a hook entry in exec form is started with no shell. The
 * mark records the host as the hook sees it — `CLAUDE_PID` when it is a
 * number, and the hook's own parent — and the server compares with its own.
 * Where neither matches (a wrapper between the host and one of the two), a
 * mark of the same project written since shortly before the server started
 * counts, and `matched_by: "time"` says so.
 *
 * The mark INFORMS. Nothing reads it to decide a guard, the trust in a
 * database or a scan's result, and a mark that cannot be read, validated or
 * tied to this session counts as absent — never as proof that the hooks ran.
 *
 * Writing can never hold the session: nothing is asked of the filesystem
 * about a data directory on the network (an unreachable host held a hook
 * 21 s), no path that already exists is ever opened — a temporary file,
 * created exclusively, is renamed over whatever is there — and the caller
 * stops waiting after `timeoutMs`.
 */

import { createHash, randomBytes } from 'node:crypto';
import { accessSync, constants, readdirSync, realpathSync, statSync } from 'node:fs';
import * as nodeFs from 'node:fs/promises';
import { homedir } from 'node:os';
import { dirname, join, parse, resolve } from 'node:path';

import { isNetworkPath, MAX_HOOK_CONFIG_BYTES, readSmallText, walkLinksUnder } from './configFile.js';
import { userDataDir } from './userDataDir.js';

/** The subdirectory of the user's data directory that holds the marks. */
export const HEARTBEAT_DIR = 'hooks-heartbeat';

/** A server younger than this with no mark says `pending`, not `not_observed`. */
export const GRACE_MS = 30_000;

/** How far before the server's start a mark may be for the time rule, and how far in the future a mark's date may be. */
export const TOLERANCE_MS = 120_000;

/** A mark older than this is removed. */
export const MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000;

/** Marks removed by one SessionStart, at most. */
export const PRUNE_MAX = 64;

/** Names read from the marks' directory, at most. */
const LIST_MAX = 512;

/** Marks read to answer one `health_status`, at most. */
const READ_MAX = 32;

/** A mark's size, at most. */
export const MARK_MAX_BYTES = 1024;

/** The first Claude Code that passes a hook entry's `args`: an older one starts no hook. */
const HOOKS_MIN_CLAUDE_CODE: readonly [number, number, number] = [2, 1, 139];

const SOURCES = ['startup', 'resume', 'clear', 'compact', 'fork'] as const;
export type HeartbeatSource = (typeof SOURCES)[number];

/** What SessionStart writes. No path, no file name or content, no environment, no command, no secret. */
export interface HeartbeatMark {
  v: 1;
  /** UTC, ISO 8601. */
  at: string;
  plugin_version: string;
  source?: HeartbeatSource;
  /** `CLAUDE_PID` when it is a number, and the hook's own parent: the host process, as the hook sees it. */
  host_pids: number[];
  /** 16 hex of a SHA-256 of the project root, normalised — never the path. */
  project: string;
  state: 'active' | 'disabled';
  disabled_by?: 'GUARDIAN_HOOKS' | 'user-config';
}

export type HooksState = 'running' | 'pending' | 'not_observed' | 'disabled_by_user' | 'not_applicable' | 'unknown';

/** What `health_status` returns in `hooks`. */
export interface HooksStatus {
  state: HooksState;
  matched_by?: 'host_process' | 'time';
  last_seen_at?: string;
  age_seconds?: number;
  plugin_version?: string;
  source?: string;
  /** The MCP client's name and version, when known. */
  host?: string;
  disabled_by?: string;
  /** `not_applicable` and `unknown`: why. */
  reason?: string;
}

type Env = Readonly<Record<string, string | undefined>>;

/** The filesystem calls made to WRITE and PRUNE — injectable, so a test can see them, or prove none was made. */
export interface HeartbeatFs {
  mkdir(path: string, options: { recursive: true; mode: number }): Promise<unknown>;
  writeFile(path: string, data: string, options: { flag: 'wx'; mode: number }): Promise<void>;
  rename(from: string, to: string): Promise<void>;
  rm(path: string, options: { force: true }): Promise<void>;
  readdir(path: string): Promise<string[]>;
  lstat(path: string): Promise<{ isFile(): boolean; mtimeMs: number }>;
  unlink(path: string): Promise<void>;
}

export interface WriteHeartbeatOptions {
  /** Default: `userDataDir()`. */
  dataDir?: string;
  /** The link walk to the data directory starts below it (default: the home directory). */
  home?: string;
  projectRoot: string;
  pluginVersion: string;
  /** The payload's `source`; anything but a known value is left out. */
  source?: unknown;
  state: 'active' | 'disabled';
  disabledBy?: 'GUARDIAN_HOOKS' | 'user-config';
  env?: Env;
  ppid?: number;
  platform?: NodeJS.Platform;
  now?: number;
  /** How long the write may take before the hook stops waiting for it (default 1000). */
  timeoutMs?: number;
  fs?: HeartbeatFs;
  debug?: (message: string) => void;
}

interface WriteHeartbeatResult {
  written: boolean;
  /** The mark's path, when written. */
  file?: string;
  /** Why not, when not. */
  reason?: string;
}

interface PruneOptions {
  now?: number;
  /** Whether a process still exists. */
  isAlive?: (pid: number) => boolean;
  fs?: HeartbeatFs;
  /** A file to leave alone whatever its age: the mark just written. */
  keep?: string;
  /** How long the cleanup may take before the hook stops waiting for it (default 1000). */
  timeoutMs?: number;
}

export interface HooksStatusOptions {
  /** Whether this server was started as the plugin's own — see {@link pluginServerExpected}. */
  expected: { expected: boolean; reason: string };
  dataDir: string;
  projectRoot: string;
  /** The host process as the server sees it — see {@link hostPidsOf}. */
  hostPids: readonly number[];
  /** When the server started, in ms. */
  serverStartedAt: number;
  now?: number;
  /** The MCP client, when the server knows it. */
  client?: { name?: string; version?: string };
  platform?: NodeJS.Platform;
  /** Why a mark could not be written to `dataDir`, or null when it could (default: a real probe). */
  writable?: (dataDir: string) => string | null;
}

// ------------------------------------------------------------ the mark

const MARK_NAME = /^p([0-9a-f]{16})\.h(\d{1,10})\.json$/;
/** A temporary file of a write that never finished: this module's own, too. */
const TEMP_NAME = /^p[0-9a-f]{16}\.h\d{1,10}\.json\.\d+\.[0-9a-f]{8}\.tmp$/;

/** A path as both sides compare it: forward slashes, no trailing one, case folded where the filesystem folds it. */
function comparablePath(path: string, platform: NodeJS.Platform): string {
  let p = platform === process.platform ? resolve(path) : path;
  if (platform === 'win32') p = p.replace(/\\/g, '/');
  p = p.replace(/\/+$/, '');
  return platform === 'win32' || platform === 'darwin' ? p.toLowerCase() : p;
}

/** The project's key in a mark: 16 hex of a SHA-256 of its root, normalised the same way on both sides. */
export function projectKey(root: string, platform: NodeJS.Platform = process.platform): string {
  return createHash('sha256').update(comparablePath(root, platform)).digest('hex').slice(0, 16);
}

const isPid = (n: unknown): n is number => typeof n === 'number' && Number.isInteger(n) && n > 0 && n <= 0xffffffff;

/** The host process as this process sees it: `CLAUDE_PID` when it is a number, and the parent. */
export function hostPidsOf(env: Env, ppid: number): number[] {
  const given = env['CLAUDE_PID']?.trim() ?? '';
  const claude = /^\d{1,10}$/.test(given) ? Number(given) : undefined;
  const out: number[] = [];
  for (const pid of [claude, ppid]) if (isPid(pid) && !out.includes(pid)) out.push(pid);
  return out;
}

/** `p<project>.h<host pid>.json`. */
export function markFileName(project: string, hostPid: number): string {
  return `p${project}.h${String(hostPid)}.json`;
}

/** A mark as it is written: one line of JSON, at most {@link MARK_MAX_BYTES}. */
export function serializeMark(mark: HeartbeatMark): string {
  const out: HeartbeatMark = {
    v: 1,
    at: mark.at,
    plugin_version: mark.plugin_version.slice(0, 40),
    ...(mark.source !== undefined ? { source: mark.source } : {}),
    host_pids: mark.host_pids.slice(0, 2),
    project: mark.project,
    state: mark.state,
    ...(mark.disabled_by !== undefined ? { disabled_by: mark.disabled_by } : {}),
  };
  return `${JSON.stringify(out)}\n`;
}

/**
 * A mark read back, or null: not JSON, a field of the wrong type, a date more
 * than the tolerance in the future, or — with `fileName` — a file that is not
 * named for its own content (one renamed or copied into place).
 */
function parseMark(text: string, opts: { now: number; fileName?: string }): HeartbeatMark | null {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    return null;
  }
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const r = raw as Record<string, unknown>;
  if (r['v'] !== 1) return null;
  const at = r['at'];
  if (typeof at !== 'string') return null;
  const when = Date.parse(at);
  if (!Number.isFinite(when) || when > opts.now + TOLERANCE_MS) return null;
  const version = r['plugin_version'];
  if (typeof version !== 'string' || version.length > 64) return null;
  const pids = r['host_pids'];
  if (!Array.isArray(pids) || pids.length < 1 || pids.length > 2 || !pids.every(isPid)) return null;
  const project = r['project'];
  if (typeof project !== 'string' || !/^[0-9a-f]{16}$/.test(project)) return null;
  const state = r['state'];
  if (state !== 'active' && state !== 'disabled') return null;
  const by = r['disabled_by'];
  if (by !== undefined && by !== 'GUARDIAN_HOOKS' && by !== 'user-config') return null;
  const first = pids[0];
  if (first === undefined) return null;
  if (opts.fileName !== undefined && opts.fileName !== markFileName(project, first)) return null;
  const source = SOURCES.find((s) => s === r['source']);
  return {
    v: 1,
    at,
    plugin_version: version,
    ...(source !== undefined ? { source } : {}),
    host_pids: pids,
    project,
    state,
    ...(by !== undefined ? { disabled_by: by } : {}),
  };
}

// --------------------------------------------------------------- writing

function safeHome(): string | undefined {
  try {
    return homedir();
  } catch {
    return undefined;
  }
}

/** Resolves to `fallback` when `work` has not settled within `ms`; never rejects. */
function within<T>(work: Promise<T>, ms: number, fallback: T): Promise<T> {
  return new Promise<T>((done) => {
    const timer = setTimeout(() => done(fallback), ms);
    timer.unref?.();
    work.then(
      (value) => {
        clearTimeout(timer);
        done(value);
      },
      () => {
        clearTimeout(timer);
        done(fallback);
      },
    );
  });
}

const reasonOf = (error: unknown): string => {
  const code = (error as NodeJS.ErrnoException | undefined)?.code;
  return code !== undefined ? code : error instanceof Error ? error.message : String(error);
};

async function writeMark(opts: WriteHeartbeatOptions): Promise<WriteHeartbeatResult> {
  const fs = opts.fs ?? nodeFs;
  const dataDir = opts.dataDir ?? userDataDir(opts.env !== undefined ? { env: opts.env } : {});
  // Nothing at all is asked of the filesystem about a path on the network.
  if (isNetworkPath(dataDir)) return { written: false, reason: 'the data directory is on the network' };
  const home = opts.home ?? safeHome();
  if (home !== undefined) {
    // lstat and readlink only: a link on the way that leaves for the network is never followed.
    const walk = walkLinksUnder(home, dataDir);
    if (!walk.ok) {
      return {
        written: false,
        reason: walk.reason === 'remote-link' ? 'a link on the way to the data directory leaves for the network' : 'a link on the way to the data directory could not be read',
      };
    }
  }
  const pids = hostPidsOf(opts.env ?? process.env, opts.ppid ?? process.ppid);
  const first = pids[0];
  if (first === undefined) return { written: false, reason: 'there is no host process to name' };
  const source = SOURCES.find((s) => s === opts.source);
  const mark: HeartbeatMark = {
    v: 1,
    at: new Date(opts.now ?? Date.now()).toISOString(),
    plugin_version: opts.pluginVersion,
    ...(source !== undefined ? { source } : {}),
    host_pids: pids,
    project: projectKey(opts.projectRoot, opts.platform ?? process.platform),
    state: opts.state,
    ...(opts.state === 'disabled' && opts.disabledBy !== undefined ? { disabled_by: opts.disabledBy } : {}),
  };
  const dir = join(dataDir, HEARTBEAT_DIR);
  const final = join(dir, markFileName(mark.project, first));
  const temp = `${final}.${String(process.pid)}.${randomBytes(4).toString('hex')}.tmp`;
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  // Never the final name: whatever is there — a link, a FIFO — is replaced by the rename, not opened.
  await fs.writeFile(temp, serializeMark(mark), { flag: 'wx', mode: 0o600 });
  try {
    await fs.rename(temp, final);
  } catch (error) {
    await fs.rm(temp, { force: true }).catch(() => undefined);
    throw error;
  }
  return { written: true, file: final };
}

/** Writes this session's mark. Never rejects, and never waits longer than `timeoutMs`. */
export async function writeHeartbeat(opts: WriteHeartbeatOptions): Promise<WriteHeartbeatResult> {
  const say = opts.debug ?? ((): void => {});
  let work: Promise<WriteHeartbeatResult>;
  try {
    work = writeMark(opts).catch((error: unknown) => ({ written: false, reason: reasonOf(error) }));
  } catch (error) {
    work = Promise.resolve({ written: false, reason: reasonOf(error) });
  }
  const result = await within(work, opts.timeoutMs ?? 1_000, { written: false, reason: 'the write did not finish in time' });
  say(result.written ? 'heartbeat: written' : `heartbeat: not written — ${result.reason ?? 'unknown reason'}`);
  return result;
}

/** Whether a process exists: signal 0 reaches it, or reaching it is not permitted. */
function processAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === 'EPERM';
  }
}

async function prune(dir: string, opts: PruneOptions): Promise<number> {
  const fs = opts.fs ?? nodeFs;
  const now = opts.now ?? Date.now();
  const alive = opts.isAlive ?? processAlive;
  let names: string[];
  try {
    names = await fs.readdir(dir);
  } catch {
    return 0;
  }
  let removed = 0;
  for (const name of names.slice(0, LIST_MAX)) {
    if (removed >= PRUNE_MAX) break;
    // Its own marks, and the temporary files of writes that never finished — by their exact shape.
    const named = MARK_NAME.exec(name);
    if (named === null && !TEMP_NAME.test(name)) continue;
    const path = join(dir, name);
    if (path === opts.keep) continue;
    try {
      // lstat: a link or a directory with a mark's name is not this module's file.
      const st = await fs.lstat(path);
      if (!st.isFile()) continue;
      const old = now - st.mtimeMs > MAX_AGE_MS;
      // A host process that is gone leaves a mark a recycled id could match: it goes at once.
      const orphan = named !== null && !alive(Number(named[2]));
      if (!old && !orphan) continue;
      await fs.unlink(path);
      removed += 1;
    } catch {
      /* one that cannot be removed does not stop the others */
    }
  }
  return removed;
}

/** Removes old marks and those of host processes that no longer exist; returns how many. Never rejects. */
export function pruneHeartbeats(dir: string, opts: PruneOptions = {}): Promise<number> {
  return within(prune(dir, opts), opts.timeoutMs ?? 1_000, 0);
}

// --------------------------------------------------------------- reading

/**
 * Whether a path can be resolved without asking a host on the network: it is not there itself, and no
 * link on the way to it points there (lstat and readlink only, from the volume's root down — nothing
 * is followed before every link is known to be local).
 */
function resolvesLocally(path: string): boolean {
  const full = resolve(path);
  return !isNetworkPath(path) && !isNetworkPath(full) && walkLinksUnder(parse(full).root, full).ok;
}

/**
 * Whether this server was started as the plugin's own server, whose hooks should then be running.
 *
 * Claude Code names the root as it reaches it (`<its config directory>/plugins/cache/…`), and Node
 * named this server's own file with every link resolved. So the text is compared first, and where it
 * differs, what the two paths lead to: with several accounts sharing one `plugins` directory through
 * a junction, the text alone made the plugin's own server answer `not_applicable` — the state that
 * silences "no hook started" — in every session of that machine (3.9.0, 3.9.1). Resolving can only
 * make the hooks expected where the text did not; a root that cannot be resolved is another
 * directory, as before, and nothing on the network is asked.
 */
export function pluginServerExpected(
  env: Env,
  serverRoot: string,
  platform: NodeJS.Platform = process.platform,
  realpath: (path: string) => string = realpathSync.native,
): { expected: boolean; reason: string } {
  const given = env['CLAUDE_PLUGIN_ROOT']?.trim() ?? '';
  if (given === '') {
    return { expected: false, reason: "this server was not started as a Claude Code plugin's server, so no dev-guardian hook is expected here" };
  }
  const expected = { expected: true, reason: "started as the plugin's own server" };
  if (comparablePath(given, platform) === comparablePath(serverRoot, platform)) return expected;
  // A path of another platform than this process's (the tests') cannot be resolved here.
  if (platform === process.platform && resolvesLocally(given) && resolvesLocally(serverRoot)) {
    try {
      if (comparablePath(realpath(resolve(given)), platform) === comparablePath(realpath(resolve(serverRoot)), platform)) return expected;
    } catch {
      /* one that does not exist, or may not be read: not this server's root */
    }
  }
  return { expected: false, reason: 'this server runs from another directory than the plugin Claude Code started, so its hooks are not this session\'s' };
}

/** Why a mark could not be written to `dataDir`, or null. Looks at the directory, or at the nearest one that exists. */
function probeWritable(dataDir: string): string | null {
  let dir = resolve(dataDir);
  for (let i = 0; i < 64; i += 1) {
    let st;
    try {
      st = statSync(dir);
    } catch {
      const parent = dirname(dir);
      if (parent === dir) return 'it does not exist';
      dir = parent;
      continue;
    }
    if (!st.isDirectory()) return 'it is not a directory';
    try {
      accessSync(dir, constants.W_OK);
      return null;
    } catch (error) {
      return `it is not writable (${reasonOf(error)})`;
    }
  }
  return 'it does not exist';
}

interface ReadMark {
  mark: HeartbeatMark;
  at: number;
}

/** The marks that could be this session's: named for one of the host's ids, or for this project. */
function candidateMarks(dir: string, hostPids: readonly number[], project: string, now: number): ReadMark[] {
  let names: string[];
  try {
    names = readdirSync(dir);
  } catch {
    return [];
  }
  const out: ReadMark[] = [];
  for (const name of names.slice(0, LIST_MAX)) {
    if (out.length >= READ_MAX) break;
    const named = MARK_NAME.exec(name);
    if (named === null) continue;
    if (named[1] !== project && !hostPids.includes(Number(named[2]))) continue;
    // Opened as every file a hook reads: the descriptor checked, a regular file only, a capped read.
    const read = readSmallText(join(dir, name), MAX_HOOK_CONFIG_BYTES);
    if (read.status !== 'ok') continue;
    const mark = parseMark(read.text, { now, fileName: name });
    if (mark !== null) out.push({ mark, at: Date.parse(mark.at) });
  }
  return out;
}

const newest = (marks: readonly ReadMark[]): ReadMark | undefined => [...marks].sort((a, b) => b.at - a.at)[0];

/** `claude-code 2.1.322`, or undefined when the client named nothing. */
function clientLabel(client: HooksStatusOptions['client']): string | undefined {
  const label = [client?.name, client?.version].filter((s): s is string => typeof s === 'string' && s.trim() !== '').join(' ');
  return label === '' ? undefined : label;
}

/** A Claude Code whose version is known and older than the first that starts a plugin's hooks. */
function tooOld(client: HooksStatusOptions['client']): string | undefined {
  if (!/claude/i.test(client?.name ?? '')) return undefined;
  const m = /^(\d+)\.(\d+)\.(\d+)/.exec(client?.version ?? '');
  if (m === null) return undefined;
  const got = [Number(m[1]), Number(m[2]), Number(m[3])];
  for (let i = 0; i < 3; i += 1) {
    const a = got[i] ?? 0;
    const b = HOOKS_MIN_CLAUDE_CODE[i] ?? 0;
    if (a !== b) return a < b ? client?.version : undefined;
  }
  return undefined;
}

const MIN_VERSION = HOOKS_MIN_CLAUDE_CODE.join('.');

function notObservedWarning(client: HooksStatusOptions['client']): string {
  const old = tooOld(client);
  return (
    'No dev-guardian hook has started in this Claude Code session: shell commands, file writes and package installs ' +
    'are not being assessed, and there was no session briefing. Tell the user. ' +
    (old !== undefined ? `This Claude Code reports ${old}, older than ${MIN_VERSION}, which starts no plugin hook: updating it is the likely fix. ` : '') +
    `To check: the Claude Code version (the hooks need ${MIN_VERSION} or later), that the hooks find \`node\` on their PATH, ` +
    "and the hook settings of Claude Code itself."
  );
}

/** How a mark names what switched the hooks off — what is in force, never how to change it. */
const DISABLED_BY: Readonly<Record<NonNullable<HeartbeatMark['disabled_by']>, string>> = {
  GUARDIAN_HOOKS: 'the GUARDIAN_HOOKS environment variable',
  'user-config': "the user's own hooks configuration",
};

/** What `health_status` says about the hooks, and the warning when none started in this session. */
export function hooksStatus(opts: HooksStatusOptions): { hooks: HooksStatus; warning: string | null } {
  const now = opts.now ?? Date.now();
  const host = clientLabel(opts.client);
  const withHost = host !== undefined ? { host } : {};
  if (!opts.expected.expected) {
    return { hooks: { state: 'not_applicable', reason: opts.expected.reason, ...withHost }, warning: null };
  }

  const platform = opts.platform ?? process.platform;
  // Nothing is asked of the filesystem about a directory on the network, nor about one a link on the way
  // sends there: the server would wait on the host, as a hook once did.
  const onNetwork = isNetworkPath(opts.dataDir) || leavesForTheNetwork(opts.dataDir);
  const project = projectKey(opts.projectRoot, platform);
  // A data directory inside the project is one the project's own files can fill: a repository could ship
  // a mark for every plausible process id. Nothing there is proof, whatever it says — and nothing there
  // is even looked at, so that what the project put in its place cannot change the answer.
  const inProject = isInside(opts.dataDir, opts.projectRoot, platform);
  const marks = onNetwork || inProject ? [] : candidateMarks(join(opts.dataDir, HEARTBEAT_DIR), opts.hostPids, project, now);

  // This session's: a hook started by the host process that started this server …
  const byProcess = newest(marks.filter((m) => m.mark.host_pids.some((pid) => opts.hostPids.includes(pid))));
  // … or, said as such, one of this project since shortly before the server started.
  const byTime = byProcess ?? newest(marks.filter((m) => m.mark.project === project && m.at >= opts.serverStartedAt - TOLERANCE_MS));
  if (byTime !== undefined) {
    const { mark, at } = byTime;
    const disabled = mark.state === 'disabled';
    return {
      hooks: {
        state: disabled ? 'disabled_by_user' : 'running',
        matched_by: byProcess !== undefined ? 'host_process' : 'time',
        last_seen_at: mark.at,
        age_seconds: Math.max(0, Math.floor((now - at) / 1000)),
        plugin_version: mark.plugin_version,
        ...(mark.source !== undefined ? { source: mark.source } : {}),
        ...withHost,
        ...(disabled ? { disabled_by: DISABLED_BY[mark.disabled_by ?? 'user-config'] } : {}),
      },
      warning: null,
    };
  }

  // No mark. Could one have been written at all?
  const why = onNetwork
    ? 'it is on the network, where no mark is written'
    : inProject
      ? null
      : (opts.writable ?? probeWritable)(opts.dataDir);
  if (why !== null) {
    return { hooks: { state: 'unknown', reason: `the data directory cannot hold a session mark: ${why}`, ...withHost }, warning: null };
  }
  if (now - opts.serverStartedAt < GRACE_MS) return { hooks: { state: 'pending', ...withHost }, warning: null };
  return {
    hooks: { state: 'not_observed', ...withHost },
    warning:
      notObservedWarning(opts.client) +
      (inProject ? ' (The data directory is inside the project, so a session mark there is not taken as proof.)' : ''),
  };
}

/** Whether a link on the way from the home directory to `dataDir` points at the network (lstat and readlink only). */
function leavesForTheNetwork(dataDir: string): boolean {
  const home = safeHome();
  return home !== undefined && !walkLinksUnder(home, dataDir).ok;
}

/** Whether `path` is `dir` or lies below it, compared as the filesystem compares them. */
function isInside(path: string, dir: string, platform: NodeJS.Platform): boolean {
  const child = comparablePath(path, platform);
  const parent = comparablePath(dir, platform);
  return child === parent || child.startsWith(`${parent}/`);
}
