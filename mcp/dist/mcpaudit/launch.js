/**
 * Deciding how — and whether — a declared server may be started, before
 * anything is spawned.
 *
 * ## Remote entries (fix rounds 3 and 4, I2)
 *
 * `allow_remote` gates every way an entry's CONFIGURATION says it reaches
 * another machine, not only the `url` shape. An entry is remote when:
 *
 *   - it has a URL (`url`, `serverUrl`, `httpUrl`) and no command;
 *   - a UNC or device-namespace path appears ANYWHERE in its command, an
 *     argument or an `env` value, as a substring (`\\host\share\x.exe`,
 *     `cmd /c "… type \\host\share\x"`, `-r\\host\…`, `/config:\\host\…`,
 *     `@\\host\…`, `\\?\…`, `\\.\…`, `//host/share/…`): touching it contacts
 *     that host over SMB, which sends the user's NTLM credentials to it;
 *   - any `scheme://host` with a non-empty host appears anywhere in the
 *     command, an argument or an `env` value — `npx mcp-remote https://…`,
 *     `supergateway`, `mcp-proxy`, `--import=file://host/x.mjs`,
 *     `NODE_OPTIONS`, `DOCKER_HOST=tcp://…`, a database URL; `file:///x`
 *     (no host) is local;
 *   - its command is `ssh`;
 *   - its command is `docker` or `podman` and it names another engine:
 *     `-H`/`--host`, `--context`/`-c` (anything but `default`), podman's
 *     `--remote`/`--connection`/`--url`, or `DOCKER_CONTEXT` in its `env`.
 *
 * The first cut matched a UNC path only at the start of an argument or after
 * `=`, and URLs only for http(s)/ws(s): the review started `cmd /c "echo
 * started> marker & type \\host\share\x"`, which wrote the marker and tried
 * SMB (fix round 4).
 *
 * This is a TEXTUAL gate on the shapes a configuration can take, not a
 * sandbox. A program that looks local still reaches the network by itself
 * once started — `npx` downloads the package, a server calls its own API, a
 * script builds a URL at run time — and nothing here sees that; SECURITY.md
 * says so. It applies on every platform.
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
 *
 * The limit, documented beside the process-tree ones in
 * `stdioTransport.ts`: a `PATH` entry that LOOKS local but reaches the
 * network — a mapped drive letter (`Z:\tools`), a junction or symlink to a
 * UNC share — is still `stat`ed. The stat runs in the thread pool, bounded by
 * the deadline, so it cannot block the event loop; it can still send an SMB
 * request, and while a share does not answer, a thread-pool thread waits.
 */
import { spawn } from 'node:child_process';
import { stat } from 'node:fs/promises';
import { delimiter, extname, isAbsolute, resolve } from 'node:path';
import { isRemoteOrDeviceTarget } from '../hooks/configFile.js';
/** `scheme://host…` with a non-empty host; `file:///x` has none. */
const URL_WITH_HOST = /\b[a-z][a-z0-9+.-]*:\/\/[^\s/\\"'<>|]+/i;
/**
 * A UNC or device path anywhere: `\\host\…`, `\\?\…`, `\\.\…`, or
 * `//host/…` not preceded by `:` or `/` (a URL's `://`, `file:///`).
 */
const UNC_ANYWHERE = /\\\\[^\\\s"'<>|]+\\|(?<![:/])\/\/[^/\s"'<>|]+\//;
/** A command's own name: `C:\…\ssh.exe` → `ssh`. */
function commandName(command) {
    const base = command.replace(/\\/g, '/').split('/').pop() ?? command;
    return base.replace(/\.(exe|cmd|bat|com)$/i, '').toLowerCase();
}
/** `docker`/`podman` told to use another engine (see the module doc), or null. */
function remoteEngine(entry, name) {
    if (name !== 'docker' && name !== 'podman')
        return null;
    const args = entry.args ?? [];
    for (let i = 0; i < args.length; i += 1) {
        const a = args[i] ?? '';
        if (/^(-H|--host)(=|$)/.test(a) || /^-H\S/.test(a))
            return `${name} is told to use another engine (${a.split('=')[0] ?? a})`;
        if (/^(--context|-c)(=|$)/.test(a)) {
            const value = a.includes('=') ? a.slice(a.indexOf('=') + 1) : (args[i + 1] ?? '');
            if (value !== 'default')
                return `${name} is told to use the context '${value}'`;
        }
        if (name === 'podman' && /^(--remote|--connection|--url)(=|$)/.test(a))
            return `podman is told to use a remote engine (${a})`;
    }
    const context = entry.env?.['DOCKER_CONTEXT'];
    if (typeof context === 'string' && context !== '' && context !== 'default') {
        return `${name} is told to use the context '${context}' (DOCKER_CONTEXT)`;
    }
    return null;
}
/**
 * Why an entry's configuration reaches another machine, or null when it
 * looks local — a textual gate, not a sandbox (see the module doc).
 */
export function remoteReasonOf(entry) {
    if (entry.command === undefined) {
        if (entry.url !== undefined)
            return `remote server at ${originOf(entry.url)}`;
        return null;
    }
    if (isRemoteOrDeviceTarget(entry.command)) {
        return 'its command is on a network or device path (starting it contacts that host)';
    }
    const name = commandName(entry.command);
    if (name === 'ssh')
        return 'its command is ssh (the server runs on another machine)';
    const engine = remoteEngine(entry, name);
    if (engine !== null)
        return engine;
    const envValues = Object.entries(entry.env ?? {}).flatMap(([k, v]) => (typeof v === 'string' ? [[k, v]] : []));
    const parts = [
        { where: 'its command line', text: entry.command },
        ...(entry.args ?? []).map((text) => ({ where: 'its command line', text })),
        ...envValues.map(([k, text]) => ({ where: `its env ${k}`, text })),
    ];
    for (const { where, text } of parts) {
        const url = URL_WITH_HOST.exec(text);
        if (url !== null)
            return `${where} names ${originOf(url[0])} (a proxy, a client or a source on another machine)`;
        if (UNC_ANYWHERE.test(text))
            return `${where} names a network or device path`;
    }
    return null;
}
function originOf(url) {
    try {
        return new URL(url).origin;
    }
    catch {
        return 'a URL';
    }
}
/** The value of `name` in `env`, whatever its case (Windows environment names are case-insensitive). */
function envValue(env, name) {
    const key = Object.keys(env).find((k) => k.toUpperCase() === name);
    return key === undefined ? undefined : env[key];
}
async function isFile(path) {
    try {
        return (await stat(path)).isFile();
    }
    catch {
        return false;
    }
}
function raceDeadline(p, deadline, onTimeout) {
    let timer;
    const timeout = new Promise((done) => {
        timer = setTimeout(() => done(onTimeout), Math.max(0, deadline - Date.now()));
        timer.unref();
    });
    return Promise.race([p, timeout]).finally(() => {
        if (timer !== undefined)
            clearTimeout(timer);
    });
}
/**
 * Whether `path` (a UNC command) can be read, asked of a child process that
 * is killed at `deadline`: the wait on SMB happens there, not here.
 */
function reachableFromChild(path, deadline) {
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
export async function resolveCommand(command, env, cwd, deadline) {
    if (isRemoteOrDeviceTarget(command)) {
        const reachable = await reachableFromChild(command, deadline);
        return reachable
            ? { ok: true, command }
            : { ok: false, reason: 'its command is on a network path that could not be reached within its time budget' };
    }
    if (process.platform !== 'win32')
        return { ok: true, command };
    const exts = (envValue(env, 'PATHEXT') ?? process.env['PATHEXT'] ?? '.COM;.EXE;.BAT;.CMD')
        .split(';')
        .filter((e) => e !== '');
    const withExts = (base) => (extname(base) !== '' ? [base, ...exts.map((e) => base + e)] : exts.map((e) => base + e));
    let candidates;
    const skipped = [];
    if (/[\\/]/.test(command) || isAbsolute(command)) {
        candidates = withExts(resolve(cwd, command));
    }
    else {
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
    const search = (async () => {
        for (const c of candidates)
            if (await isFile(c))
                return c;
        return null;
    })();
    const found = await raceDeadline(search, deadline, 'timeout');
    if (found === 'timeout')
        return { ok: false, reason: `resolving '${command}' did not finish within its time budget` };
    if (found === null) {
        return {
            ok: false,
            reason: `could not start the server: '${command}' was not found on PATH` +
                (skipped.length > 0 ? ` (network PATH entries were not searched: ${skipped.join(', ')})` : ''),
        };
    }
    return { ok: true, command: found };
}
//# sourceMappingURL=launch.js.map