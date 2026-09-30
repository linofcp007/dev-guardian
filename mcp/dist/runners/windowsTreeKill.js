/**
 * Kill a process tree on Windows — including the part `taskkill /T` cannot
 * see.
 *
 * `taskkill /PID <pid> /T /F` walks the Windows parent/child table. That is
 * enough for native programs, and NOT enough for anything Git Bash runs.
 * Measured on Git for Windows with `bash -c 'sleep 25 & wait'`: the MSYS
 * runtime implements `exec` by starting a new Windows process from a forked
 * one that then exits, so `sleep.exe`'s Windows parent is a pid that no longer
 * exists. taskkill killed the launcher and bash, reported success, and
 * `sleep` kept the stdout pipe open for the rest of its 25 seconds.
 *
 * MSYS itself still knows which processes are ours. Git's own `ps` lists
 * every MSYS process with its MSYS group and its Windows pid, and a process
 * bash starts stays in bash's group. What `ps` cannot say is which bash is
 * OURS — so the runner gives every Windows child a unique
 * `GUARDIAN_PROC_TREE_ID` in its environment, which every descendant
 * inherits, and Git's `grep` reads it back from `/proc/<pid>/environ`. At
 * kill time:
 *
 *   1. snapshot `ps`, then `grep` the environment of each MSYS process that
 *      a non-MSYS parent started (ppid 1 — the only possible roots of our
 *      MSYS subtree) for the token (~100–300 ms measured on a loaded
 *      machine, against ~2.5 s for ANY Windows process enumeration there —
 *      taskkill, tasklist and wmic alike);
 *   2. terminate every MSYS program in a group one of those roots leads,
 *      directly, by Windows pid;
 *   3. `taskkill /T /F` the root AND every native program found in step 2 in
 *      one call: a native program's own children ARE reachable through the
 *      Windows table, from it, even when its own parent chain is broken.
 *
 * Nothing here can reach the calling process: its own pid, its parent, and
 * any MSYS group containing either are excluded explicitly (node started from
 * a Git Bash terminal is itself a member of that terminal's group).
 *
 * Without Git for Windows there is no MSYS layer to handle and steps 1–2 are
 * skipped; step 3 alone is what the runner did before.
 */
import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { execa } from 'execa';
import { commandFor } from '../platform/binaryPath.js';
/** Environment variable carrying the per-child token. */
export const PROC_TREE_ENV = 'GUARDIAN_PROC_TREE_ID';
const TASKKILL_TIMEOUT_MS = 10_000;
const MSYS_PROBE_TIMEOUT_MS = 3_000;
/**
 * Parse the default output of Git for Windows' `ps`:
 *
 *       PID    PPID    PGID     WINPID   TTY         UID    STIME COMMAND
 *   S  291285  291284  291284      75080  ?         197108 00:54:54 /usr/bin/sleep
 *
 * A leading status letter (`S` stopped, `I` waiting for input, `O`) is
 * optional; STIME is either a clock time or a date with a space in it, so the
 * command is taken from the first ` /` after the UID column.
 */
export function parseMsysPs(output) {
    const out = [];
    for (const line of output.split(/\r?\n/)) {
        const m = /^\s*[A-Z]?\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+\S+\s+\d+\s+(.*)$/.exec(` ${line}`);
        if (!m)
            continue;
        const [, pid, ppid, pgid, winpid, rest] = m;
        if (pid === undefined ||
            ppid === undefined ||
            pgid === undefined ||
            winpid === undefined ||
            rest === undefined) {
            continue;
        }
        const slash = rest.indexOf(' /');
        out.push({
            pid: Number(pid),
            ppid: Number(ppid),
            pgid: Number(pgid),
            winpid: Number(winpid),
            command: slash >= 0 ? rest.slice(slash + 1).trim() : rest.trim(),
        });
    }
    return out;
}
/** MSYS pids from `grep -l` over `/proc/<pid>/environ`. */
export function parseEnvironMatches(output) {
    const pids = new Set();
    for (const line of output.split(/\r?\n/)) {
        const m = /^\/proc\/(\d+)\/environ\s*$/.exec(line.trim());
        if (m?.[1] !== undefined)
            pids.add(Number(m[1]));
    }
    return pids;
}
/**
 * The MSYS processes that are ours — carrying the token, or in the same MSYS
 * group as one that does (a descendant that scrubbed its environment is still
 * in its parent's group) — split by how they must be killed: an MSYS program
 * (`/usr/...`, `/bin/...`) directly, a native one through `taskkill /T` so its
 * own native children go too.
 */
export function selectOwnMsysProcesses(snapshot, tokenPids, self) {
    const protectedWinpids = new Set([self.pid, self.ppid]);
    const protectedGroups = new Set(snapshot.filter((p) => protectedWinpids.has(p.winpid)).map((p) => p.pgid));
    const groups = new Set(snapshot
        .filter((p) => tokenPids.has(p.pid) && p.pgid !== 0 && !protectedGroups.has(p.pgid))
        .map((p) => p.pgid));
    const msys = [];
    const native = [];
    for (const p of snapshot) {
        if (protectedWinpids.has(p.winpid) || protectedGroups.has(p.pgid))
            continue;
        if (!tokenPids.has(p.pid) && !groups.has(p.pgid))
            continue;
        if (/^\/(usr|bin)\//.test(p.command))
            msys.push(p.winpid);
        else
            native.push(p.winpid);
    }
    return { msys, native };
}
/**
 * Git for Windows' `usr/bin`, holding `ps.exe` and `grep.exe`: next to the
 * bash being run when the command is one, else the default install location.
 * Null when there is none — then there is no MSYS layer to handle.
 */
export function findMsysBin(command) {
    const candidates = [];
    const m = /^(.*)[\\/](?:usr[\\/])?bin[\\/]bash(?:\.exe)?$/i.exec(command);
    if (m?.[1] !== undefined)
        candidates.push(join(m[1], 'usr', 'bin'));
    const programFiles = process.env['ProgramFiles'];
    if (programFiles)
        candidates.push(join(programFiles, 'Git', 'usr', 'bin'));
    return (candidates.find((c) => existsSync(join(c, 'ps.exe')) && existsSync(join(c, 'grep.exe'))) ?? null);
}
/**
 * Kill `pid`'s whole tree. Resolves once every kill has been issued; the
 * caller's `child` promise is what reports the tree actually gone.
 * `fallback` runs when taskkill could not act on the root at all.
 */
export async function killWindowsTree(pid, command, token, fallback) {
    const own = await findOwnMsysProcesses(command, token);
    for (const winpid of own.msys)
        terminate(winpid);
    const ok = await taskkillTree([pid, ...own.native]);
    if (!ok) {
        fallback();
        for (const winpid of own.native)
            terminate(winpid);
    }
}
async function findOwnMsysProcesses(command, token) {
    const none = { msys: [], native: [] };
    const bin = findMsysBin(command);
    if (bin === null)
        return none;
    const self = { pid: process.pid, ppid: process.ppid };
    try {
        const opts = { reject: false, timeout: MSYS_PROBE_TIMEOUT_MS, cwd: dirname(bin) };
        const ps = await execa(join(bin, 'ps.exe'), [], opts);
        if (ps.exitCode !== 0)
            return none;
        const snapshot = parseMsysPs(ps.stdout);
        // Only an MSYS process started by a NON-MSYS parent (ppid 1) can be the
        // root of our MSYS subtree; everything below it is found by group.
        const roots = snapshot.filter((p) => p.ppid === 1).map((p) => `/proc/${p.pid}/environ`);
        if (roots.length === 0)
            return none;
        const needle = `${PROC_TREE_ENV}=${token}`;
        const grep = (files) => execa(join(bin, 'grep.exe'), ['-l', '-a', '-s', '-F', needle, ...files], opts);
        let matches;
        const all = await grep(roots);
        if (all.exitCode === 0 || all.exitCode === 1) {
            matches = parseEnvironMatches(all.stdout);
        }
        else {
            // Measured: MSYS grep can die outright ("cmalloc would have returned
            // NULL") reading one process's environ, taking every other file down
            // with it. One file per process isolates the bad one.
            const each = await Promise.all(roots.map((f) => grep([f])));
            matches = new Set(each.flatMap((r) => [...parseEnvironMatches(r.stdout)]));
        }
        return selectOwnMsysProcesses(snapshot, matches, self);
    }
    catch {
        return none;
    }
}
function terminate(winpid) {
    try {
        process.kill(winpid, 'SIGKILL');
    }
    catch {
        /* already gone */
    }
}
/** `taskkill /F /T` on every root in one call. False when it acted on none. */
async function taskkillTree(roots) {
    const args = ['/F', '/T'];
    for (const root of roots)
        args.push('/PID', String(root));
    try {
        const r = await execa(commandFor('taskkill'), args, { reject: false, timeout: TASKKILL_TIMEOUT_MS });
        // 0: every root handled. 128: some root was not found — expected when
        // the MSYS step above already ended it, which is success here too as
        // long as SOMETHING was reported terminated. Anything else: failure.
        return r.exitCode === 0 || /\d+\D+\d+/.test(r.stdout);
    }
    catch {
        return false;
    }
}
//# sourceMappingURL=windowsTreeKill.js.map