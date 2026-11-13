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
 * The mark INFORMS. Nothing reads it to decide a guard, the trust in a
 * database or a scan's result, and a mark that cannot be read, validated or
 * tied to this session counts as absent — never as proof that the hooks ran.
 */

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
export const LIST_MAX = 512;

/** A mark's size, at most. */
export const MARK_MAX_BYTES = 1024;

/** The first Claude Code that passes a hook entry's `args`: an older one starts no hook. */
export const HOOKS_MIN_CLAUDE_CODE = '2.1.139';

export type HeartbeatSource = 'startup' | 'resume' | 'clear' | 'compact' | 'fork';

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
  /** `userDataDir()`. */
  dataDir: string;
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
  /** Whether a process still exists — for the cleanup that follows the write. */
  isAlive?: (pid: number) => boolean;
  debug?: (message: string) => void;
}

export interface WriteHeartbeatResult {
  written: boolean;
  /** The mark's path, when written. */
  file?: string;
  /** Why not, when not. */
  reason?: string;
}

export interface PruneOptions {
  now?: number;
  isAlive?: (pid: number) => boolean;
  fs?: HeartbeatFs;
  /** A file to leave alone whatever its age: the mark just written. */
  keep?: string;
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

function todo(what: string): never {
  throw new Error(`not implemented: ${what} (hooks-heartbeat)`);
}

/** The project's key in a mark: 16 hex of a SHA-256 of its root, normalised the same way on both sides. */
export function projectKey(_root: string, _platform: NodeJS.Platform = process.platform): string {
  return todo('projectKey');
}

/** The host process as this process sees it: `CLAUDE_PID` when it is a number, and the parent. */
export function hostPidsOf(_env: Env, _ppid: number): number[] {
  return todo('hostPidsOf');
}

/** `p<project>.h<host pid>.json`. */
export function markFileName(_project: string, _hostPid: number): string {
  return todo('markFileName');
}

/** A mark as it is written: one line of JSON, at most {@link MARK_MAX_BYTES}. */
export function serializeMark(_mark: HeartbeatMark): string {
  return todo('serializeMark');
}

/** A mark read back, or null: not JSON, a field of the wrong type, a date too far in the future, a name that is not its own. */
export function parseMark(_text: string, _opts: { now: number; fileName?: string }): HeartbeatMark | null {
  return todo('parseMark');
}

/** Writes this session's mark. Never rejects, and never waits longer than `timeoutMs`. */
export function writeHeartbeat(_opts: WriteHeartbeatOptions): Promise<WriteHeartbeatResult> {
  return todo('writeHeartbeat');
}

/** Removes old marks and those of host processes that no longer exist; returns how many. Never rejects. */
export function pruneHeartbeats(_dir: string, _opts: PruneOptions = {}): Promise<number> {
  return todo('pruneHeartbeats');
}

/** Whether this server was started as the plugin's own server, whose hooks should then be running. */
export function pluginServerExpected(
  _env: Env,
  _serverRoot: string,
  _platform: NodeJS.Platform = process.platform,
): { expected: boolean; reason: string } {
  return todo('pluginServerExpected');
}

/** What `health_status` says about the hooks, and the warning when none started in this session. */
export function hooksStatus(_opts: HooksStatusOptions): { hooks: HooksStatus; warning: string | null } {
  return todo('hooksStatus');
}
