/**
 * Deciding how — and whether — a declared server may be started, before
 * anything is spawned.
 *
 * ## Remote entries (fix round 3, I2)
 *
 * `allow_remote` gates every way an entry reaches another machine, not only
 * the `url` shape. An entry is remote when:
 *
 *   - it has a URL (`url`, `serverUrl`, `httpUrl`) and no command;
 *   - its command is on a UNC or device-namespace path (`\\host\share\x.exe`,
 *     `\\?\…`, `\\.\…`): starting it contacts that host over SMB, which sends
 *     the user's NTLM credentials to it;
 *   - its command or any argument names an `http(s)://` or `ws(s)://` URL —
 *     `npx mcp-remote https://…`, `supergateway`, `mcp-proxy`, and any server
 *     told to talk to a URL (`mcp-remote` may also open a browser for OAuth);
 *   - any argument is, or ends in, a UNC path (`\\host\share\s.js`,
 *     `--config=\\host\share\c.json`).
 *
 * The check is textual and applies on every platform. What a local server
 * does on its own once started (a URL in its code, or in an `env` value) is
 * not visible here; SECURITY.md says so.
 *
 * ## Resolving a command without touching the network (C1)
 *
 * On Windows, `cross-spawn` resolves the command with `which.sync` over
 * `PATHEXT`, and `CreateProcess` runs synchronously: a UNC command blocked
 * this whole process from the first second (measured: zero timer ticks until
 * a kill at 1500 s). So on Windows the command is resolved HERE, with async
 * `stat` calls over the LOCAL entries of the launch environment's `PATH`
 * (UNC and device entries are skipped and named), and the absolute path is
 * what gets spawned; `cross-spawn` then has one local file to confirm. A UNC
 * command allowed as remote is first checked for reachability from a
 * short-lived child process, killed at the deadline, so neither this
 * process's event loop nor its thread pool waits on SMB; only a reachable one
 * is spawned. On POSIX the child's own `execvp` searches `PATH`, after the
 * fork, so there is nothing to resolve here.
 */

import { spawn } from 'node:child_process';
import { stat } from 'node:fs/promises';
import { delimiter, extname, isAbsolute, resolve } from 'node:path';
import type { McpServerEntry } from '../agentaudit/mcpServers.js';
import { isRemoteOrDeviceTarget } from '../hooks/configFile.js';

const URL_IN_TEXT = /\b(?:https?|wss?):\/\/[^\s"'<>]+/i;
/** A UNC path at the start of an argument or after `=` (`--config=\\host\…`); never a URL's `//`. */
const UNC_IN_ARG = /(?:^|=)(?:\\\\|\/\/)[^\\/\s]+[\\/]/;

/** Why an entry reaches another machine, or null when it is local. */
export function remoteReasonOf(entry: McpServerEntry): string | null {
  if (entry.command === undefined) {
    if (entry.url !== undefined) return `remote server at ${originOf(entry.url)}`;
    return null;
  }
  if (isRemoteOrDeviceTarget(entry.command)) {
    return 'its command is on a network or device path (starting it contacts that host)';
  }
  for (const part of [entry.command, ...(entry.args ?? [])]) {
    const url = URL_IN_TEXT.exec(part);
    if (url !== null) return `its command line names ${originOf(url[0])} (a proxy or client of a remote server)`;
    if (UNC_IN_ARG.test(part)) return 'its command line names a network path';
  }
  return null;
}

function originOf(url: string): string {
  try {
    return new URL(url).origin;
  } catch {
    return 'a URL';
  }
}

export type Resolved = { ok: true; command: string } | { ok: false; reason: string };

/** The value of `name` in `env`, whatever its case (Windows environment names are case-insensitive). */
function envValue(env: Record<string, string>, name: string): string | undefined {
  const key = Object.keys(env).find((k) => k.toUpperCase() === name);
  return key === undefined ? undefined : env[key];
}

async function isFile(path: string): Promise<boolean> {
  try {
    return (await stat(path)).isFile();
  } catch {
    return false;
  }
}

function raceDeadline<T>(p: Promise<T>, deadline: number, onTimeout: T): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<T>((done) => {
    timer = setTimeout(() => done(onTimeout), Math.max(0, deadline - Date.now()));
    timer.unref();
  });
  return Promise.race([p, timeout]).finally(() => {
    if (timer !== undefined) clearTimeout(timer);
  });
}

/**
 * Whether `path` (a UNC command) can be read, asked of a child process that
 * is killed at `deadline`: the wait on SMB happens there, not here.
 */
function reachableFromChild(path: string, deadline: number): Promise<boolean> {
  return new Promise((done) => {
    const child = spawn(process.execPath, ['-e', 'process.exit(require("fs").statSync(process.argv[1]).isFile() ? 0 : 1)', path], {
      stdio: 'ignore',
      windowsHide: true,
    });
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      done(false);
    }, Math.max(0, deadline - Date.now()));
    timer.unref();
    child.on('error', () => {
      clearTimeout(timer);
      done(false);
    });
    child.on('exit', (code) => {
      clearTimeout(timer);
      done(code === 0);
    });
  });
}

/**
 * The command to spawn for `command` under `env` (the launch environment),
 * with `cwd` for a relative one — resolved without any synchronous file-system
 * or network access. See the module doc.
 */
export async function resolveCommand(
  command: string,
  env: Record<string, string>,
  cwd: string,
  deadline: number,
): Promise<Resolved> {
  if (isRemoteOrDeviceTarget(command)) {
    const reachable = await reachableFromChild(command, deadline);
    return reachable
      ? { ok: true, command }
      : { ok: false, reason: 'its command is on a network path that could not be reached within its time budget' };
  }
  if (process.platform !== 'win32') return { ok: true, command };

  const exts = (envValue(env, 'PATHEXT') ?? process.env['PATHEXT'] ?? '.COM;.EXE;.BAT;.CMD')
    .split(';')
    .filter((e) => e !== '');
  const withExts = (base: string): string[] => (extname(base) !== '' ? [base, ...exts.map((e) => base + e)] : exts.map((e) => base + e));

  let candidates: string[];
  const skipped: string[] = [];
  if (/[\\/]/.test(command) || isAbsolute(command)) {
    candidates = withExts(resolve(cwd, command));
  } else {
    const dirs = (envValue(env, 'PATH') ?? '').split(delimiter).filter((d) => d !== '');
    candidates = [];
    for (const dir of dirs) {
      if (isRemoteOrDeviceTarget(dir)) {
        skipped.push(dir);
        continue;
      }
      candidates.push(...withExts(resolve(dir, command)));
    }
  }
  const search = (async (): Promise<string | null> => {
    for (const c of candidates) if (await isFile(c)) return c;
    return null;
  })();
  const found = await raceDeadline<string | null | 'timeout'>(search, deadline, 'timeout');
  if (found === 'timeout') return { ok: false, reason: `resolving '${command}' did not finish within its time budget` };
  if (found === null) {
    return {
      ok: false,
      reason:
        `could not start the server: '${command}' was not found on PATH` +
        (skipped.length > 0 ? ` (network PATH entries were not searched: ${skipped.join(', ')})` : ''),
    };
  }
  return { ok: true, command: found };
}
