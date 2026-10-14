/**
 * An npm cmd-shim — the `lighthouse.cmd`, `npx.cmd` npm writes for a package's
 * `bin` on Windows — read as what it runs: `node <the package's script>`.
 *
 * A `.cmd` runs through `cmd.exe`, and `runners/spawn.ts` refuses to hand
 * `cmd.exe` an argument holding `"` or `%` (review 10, finding 3,
 * "BatBadBut"). That broke legitimate runs: `perf_check` on any URL with a
 * percent-escape (`?q=a%20b`) through `lighthouse.cmd` (review 11, finding
 * 15b). An npm shim does nothing but start Node on one script with `%*`, so
 * it is run as that — Node started directly, the script and the arguments
 * handed through `CreateProcess`, which reads them literally — and `cmd.exe`
 * never parses anything.
 *
 * Only the two templates npm's `cmd-shim` writes are recognised, and only
 * when the program is Node: the current one (`SET "_prog=%dp0%\node.exe"`,
 * else `node` … `"%_prog%" <shebang args> "%dp0%\<script>" %*`) and the
 * older one (`"%~dp0\node.exe" <args> "%~dp0\<script>" %*`, else `node …`).
 * A shim of anything else (`sh`, a custom batch file) is still a batch file,
 * judged as one. The program is the shim's own choice: `node.exe` beside the
 * shim when there is one, else `node.exe` on the child's PATH.
 */

import { closeSync, fstatSync, openSync, readSync, statSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { findOnPath } from '../platform/binaryPath.js';

/** What a shim runs: the program, and the arguments before the caller's. */
interface ShimTarget {
  program: string;
  args: string[];
}

/** A shim is a few hundred bytes; anything larger is not one of npm's. */
const MAX_SHIM_BYTES = 8 * 1024;

/** Shebang arguments (`--harmony`, `--max-old-space-size=4096`): tokens with nothing cmd.exe or a quote reads. */
const PLAIN_ARGS = String.raw`((?:[ \t]+[^\s"%^&|<>()]+)*)`;

/** The current template's run line: `"%_prog%" <args> "%dp0%\<script>" %*`. */
const CURRENT_RUN = new RegExp(String.raw`"%_prog%"${PLAIN_ARGS}[ \t]+"%dp0%\\([^"%\r\n]+)"[ \t]+%\*[ \t]*$`, 'm');
/** The current template's choice of program: node.exe beside the shim, else node. */
const CURRENT_PROGRAM = [/^\s*IF EXIST "%dp0%\\node\.exe" \($/im, /^\s*SET "_prog=%dp0%\\node\.exe"\s*$/im, /^\s*SET "_prog=node"\s*$/im];

/** The older template: `"%~dp0\node.exe" <args> "%~dp0\<script>" %*`, else `node <args> "%~dp0\<script>" %*`. */
const OLDER_RUN = new RegExp(String.raw`^\s*"%~dp0\\node\.exe"${PLAIN_ARGS}[ \t]+"%~dp0\\([^"%\r\n]+)"[ \t]+%\*[ \t]*$`, 'm');
const OLDER_FALLBACK = new RegExp(String.raw`^\s*node${PLAIN_ARGS}[ \t]+"%~dp0\\([^"%\r\n]+)"[ \t]+%\*[ \t]*$`, 'm');

/** The first `MAX_SHIM_BYTES` of `file`, or null when it is larger or cannot be read. */
function readShim(file: string): string | null {
  let fd: number | undefined;
  try {
    fd = openSync(file, 'r');
    if (!fstatSync(fd).isFile() || fstatSync(fd).size > MAX_SHIM_BYTES) return null;
    const buf = Buffer.alloc(MAX_SHIM_BYTES);
    const n = readSync(fd, buf, 0, MAX_SHIM_BYTES, 0);
    return buf.subarray(0, n).toString('utf8');
  } catch {
    return null;
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

/** Whether `path` is a file. */
function isFile(path: string): boolean {
  try {
    return statSync(path).isFile();
  } catch {
    return false;
  }
}

/** The shebang arguments of a run line's capture, one per token. */
function splitArgs(captured: string | undefined): string[] {
  return (captured ?? '').trim().split(/[ \t]+/).filter((a) => a.length > 0);
}

/**
 * What the npm cmd-shim `file` runs, or null when `file` is not one (see the
 * module comment) or what it names is not there. Never throws.
 */
export function npmCmdShimTarget(file: string, env: NodeJS.ProcessEnv): ShimTarget | null {
  if (!/\.cmd$/i.test(file)) return null;
  const text = readShim(file);
  if (text === null) return null;
  let preArgs: string[];
  let script: string;
  const current = CURRENT_RUN.exec(text);
  if (current !== null && CURRENT_PROGRAM.every((re) => re.test(text))) {
    preArgs = splitArgs(current[1]);
    script = current[2] ?? '';
  } else {
    const older = OLDER_RUN.exec(text);
    const fallback = OLDER_FALLBACK.exec(text);
    if (older === null || fallback === null || older[2] !== fallback[2] || older[1] !== fallback[1]) return null;
    preArgs = splitArgs(older[1]);
    script = older[2] ?? '';
  }
  const dir = dirname(file);
  const target = join(dir, script);
  if (script === '' || !isFile(target)) return null;
  const beside = join(dir, 'node.exe');
  const program = isFile(beside) ? beside : findOnPath('node.exe', env, 'win32');
  if (program === null) return null;
  return { program, args: [...preArgs, target] };
}
