/**
 * Project paths stored in a database, and what they may be resolved to.
 *
 * A stored path is data: a database can hold any string. Two things are
 * asked of one, and both only of the user's OWN database — never of one
 * whose provenance is being judged (`storage/dbProvenance.ts` reads no
 * stored path at all):
 *
 *   - {@link spellingOnlyCanonical}: the startup rewrite of 2.0.0 spellings
 *     (`storage/maintenance.ts`) — a lower-case drive letter (2.0.0 stored
 *     `resolve(input)`: `c:\Users\…`), letter case, an 8.3 short name,
 *     separators. None of those can come to mean another directory; a link
 *     can (`~/work/current` repointed from project A to project B), so a
 *     path through one is never rewritten there.
 *   - `db adopt --rehome` (`storage/db.ts`), where the person adopting the
 *     database has seen the list and decides: a path that resolves, links
 *     included, to the project is rewritten to its canonical path.
 *
 * Both refuse, before any look, a path the file system would answer by going
 * to the network or a device, or whose meaning is the reader's
 * ({@link isUnresolvablePath}): `\\host\share` waits on the network — four
 * such paths held a server 60 s in round 5 of the 3.0 review — and sends the
 * user's NTLM credentials to the host.
 */
import { lstatSync, statSync } from 'node:fs';
import { isAbsolute, join, parse, resolve, sep } from 'node:path';
import { canonicalPath } from './projectPath.js';
/**
 * `\\server\share`, `//server/share`, `\\?\…`, `\\.\…` (devices, pipes) and
 * `\??\…` (the NT object namespace): paths the file system answers by going
 * to the network or to a device. Never looked at.
 */
export function isNetworkOrDevicePath(path) {
    return /^[\\/]{2}/.test(path) || path.startsWith('\\??\\');
}
/**
 * A path never resolved on the user's behalf: a network or device path
 * ({@link isNetworkOrDevicePath}); one whose meaning is the READING process's
 * (`/proc/self/cwd` is whatever directory the reader runs in, `/dev/fd/N`
 * whatever it has open) — a string anyone can write that "resolves to" every
 * project it is read in; and macOS's `/net/<host>` automount, which mounts a
 * host on a look.
 */
export function isUnresolvablePath(path) {
    return isNetworkOrDevicePath(path) || /^\/(?:proc|dev\/fd|net)(?:\/|$)/.test(path);
}
/**
 * The canonical spelling of `path` when it names an existing LOCAL directory,
 * differs from it, and reaches it through no link; null otherwise. For paths
 * in the user's own database only (see the module comment); a path
 * {@link isUnresolvablePath} names is refused before any look.
 */
export function spellingOnlyCanonical(path) {
    if (!isAbsolute(path) || isUnresolvablePath(path))
        return null;
    try {
        if (!statSync(path).isDirectory())
            return null;
    }
    catch {
        return null;
    }
    const canonical = canonicalPath(path);
    if (canonical === path)
        return null;
    // Every component, from the root down, must be a real directory entry.
    const resolved = resolve(path);
    const root = parse(resolved).root;
    let current = root;
    for (const part of resolved.slice(root.length).split(sep).filter((s) => s !== '')) {
        current = join(current, part);
        try {
            if (lstatSync(current).isSymbolicLink())
                return null;
        }
        catch {
            return null;
        }
    }
    return canonical;
}
/**
 * Where `stored` leads relative to `canonicalProject` (a {@link canonicalPath}).
 * Resolves `stored` on disk — for the user's own database, on their command
 * (see the module comment).
 */
export function storedPathTarget(stored, canonicalProject) {
    if (stored === canonicalProject)
        return 'canonical';
    if (!isAbsolute(stored) || isUnresolvablePath(stored))
        return 'unresolved';
    try {
        if (!statSync(stored).isDirectory())
            return 'elsewhere';
    }
    catch {
        return 'missing';
    }
    return canonicalPath(stored) === canonicalProject ? 'this-project' : 'elsewhere';
}
//# sourceMappingURL=pathSpelling.js.map