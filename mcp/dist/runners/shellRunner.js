/**
 * Run a `.sh` script under the probed shell.
 *
 * Thin wrapper over `runProcess` that translates a `ShellChoice` into
 * `(command, argsPrefix)`. WSL paths are converted before being passed to
 * the script via `toShellPath`.
 *
 * All the safety machinery (5 MB cap, SIGTERM/SIGKILL, timeout, stderr
 * streaming) lives in `runProcess` — this file only wires the shell.
 */
import { toShellPath } from '../platform/pathTranslate.js';
import { runProcess } from './processRunner.js';
export async function runShellScript(options) {
    const scriptArg = toShellPath(options.scriptPath, options.shell);
    const args = [...options.shell.args_prefix, scriptArg, ...(options.args ?? [])];
    const runOpts = {
        command: options.shell.command,
        args,
        cwd: options.cwd,
    };
    if (options.env !== undefined)
        runOpts.env = options.env;
    if (options.signal !== undefined)
        runOpts.signal = options.signal;
    if (options.timeoutMs !== undefined)
        runOpts.timeoutMs = options.timeoutMs;
    if (options.onLog !== undefined)
        runOpts.onLog = options.onLog;
    return runProcess(runOpts);
}
//# sourceMappingURL=shellRunner.js.map