/**
 * Which version of an npm package some code loads — the dependency
 * provider's `NpmResolver`, and its only I/O.
 *
 * Node's own lookup: from the importing file's directory upwards, the first
 * `node_modules/<name>` wins. Read, per manifest directory, from
 * `npm-shrinkwrap.json` or `package-lock.json` (npm's precedence) — v2/v3
 * `packages` keys are exactly those install paths
 * (`node_modules/x/node_modules/lodash`, `packages/api/node_modules/lodash`
 * in a workspace), v1's nested `dependencies` build the same keys — and,
 * with no lockfile, from the installed `node_modules/<name>/package.json`.
 * Only the directories from the importing file up to the manifest's are
 * searched: that is the install the finding is about.
 *
 * Null whenever it cannot be told: no lockfile and nothing installed, a
 * lockfile that is not JSON or is over {@link MAX_LOCKFILE_BYTES}, a package
 * the lockfile does not install where the code looks. The provider then
 * claims no more than `imported` — never `reachable` on a version it could
 * not read. yarn.lock and pnpm-lock.yaml are not read (neither records where
 * a package is installed); the installed tree answers for them when present.
 */
import { readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
/** A lockfile larger than this is not read (a large monorepo's is a few MB). */
export const MAX_LOCKFILE_BYTES = 64 * 1024 * 1024;
const MAX_PACKAGE_JSON_BYTES = 1024 * 1024;
const LOCKFILES = ['npm-shrinkwrap.json', 'package-lock.json'];
export function makeNpmResolver(projectPath) {
    const locks = new Map();
    const lockOf = (rootDir) => {
        if (!locks.has(rootDir))
            locks.set(rootDir, readLock(projectPath, rootDir));
        return locks.get(rootDir) ?? null;
    };
    return (fromDir, rootDir, name) => {
        const lock = lockOf(rootDir);
        let dir = fromDir;
        for (;;) {
            const rel = relativeTo(rootDir, dir);
            if (rel === null)
                return null;
            if (lock !== null) {
                const version = lock.versions.get(`${rel === '' ? '' : `${rel}/`}node_modules/${name}`);
                if (version !== undefined)
                    return { version, source: lock.file };
            }
            else {
                const installed = readInstalled(projectPath, dir, name);
                if (installed !== null)
                    return installed;
            }
            if (dir === rootDir)
                return null;
            dir = parentOf(dir);
        }
    };
}
function readLock(projectPath, rootDir) {
    for (const candidate of LOCKFILES) {
        const parsed = readJson(join(projectPath, rootDir, candidate), MAX_LOCKFILE_BYTES);
        if (parsed === undefined)
            continue;
        if (parsed === null)
            return null; // present but unreadable: do not fall back to a lesser source
        const versions = new Map();
        const packages = record(parsed['packages']);
        if (packages !== null) {
            for (const [key, value] of Object.entries(packages)) {
                const entry = record(value);
                if (key === '' || entry === null || entry['link'] === true)
                    continue;
                if (typeof entry['version'] === 'string')
                    versions.set(key, entry['version']);
            }
        }
        else {
            walkV1(record(parsed['dependencies']), '', versions);
        }
        return { file: rootDir === '' ? candidate : `${rootDir}/${candidate}`, versions };
    }
    return null;
}
function walkV1(deps, prefix, out) {
    if (deps === null)
        return;
    for (const [name, value] of Object.entries(deps)) {
        const entry = record(value);
        if (entry === null)
            continue;
        const key = `${prefix}node_modules/${name}`;
        if (typeof entry['version'] === 'string')
            out.set(key, entry['version']);
        walkV1(record(entry['dependencies']), `${key}/`, out);
    }
}
function readInstalled(projectPath, dir, name) {
    const parsed = readJson(join(projectPath, dir, 'node_modules', ...name.split('/'), 'package.json'), MAX_PACKAGE_JSON_BYTES);
    const version = parsed?.['version'];
    if (typeof version !== 'string')
        return null;
    return { version, source: `${dir === '' ? '' : `${dir}/`}node_modules/${name}/package.json` };
}
/**
 * `undefined`: no such regular file. `null`: present, but too large or not a
 * JSON object.
 */
function readJson(path, maxBytes) {
    try {
        const stat = statSync(path);
        if (!stat.isFile())
            return undefined;
        if (stat.size > maxBytes)
            return null;
        return record(JSON.parse(readFileSync(path, 'utf8')));
    }
    catch (e) {
        return e.code === 'ENOENT' ? undefined : null;
    }
}
function record(value) {
    return value !== null && typeof value === 'object' && !Array.isArray(value)
        ? value
        : null;
}
/** `dir` relative to `rootDir` (both project-relative POSIX), or null when outside it. */
function relativeTo(rootDir, dir) {
    if (rootDir === '')
        return dir;
    if (dir === rootDir)
        return '';
    return dir.startsWith(`${rootDir}/`) ? dir.slice(rootDir.length + 1) : null;
}
function parentOf(dir) {
    const at = dir.lastIndexOf('/');
    return at === -1 ? '' : dir.slice(0, at);
}
//# sourceMappingURL=npmResolve.js.map