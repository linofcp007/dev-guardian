/**
 * Find OpenAPI / Swagger documents in a project and read their contents.
 *
 * This is the only I/O in the spec-import feature; `specImport.ts` (parsing)
 * and `specDiff.ts` (comparison) are both pure. Discovery walks the project
 * tree looking for conventionally-named documents, or — when the caller
 * supplies an explicit list — reads exactly those paths instead.
 *
 * Two caps keep this bounded on large or adversarial trees: at most
 * `MAX_SPEC_FILES` candidate files, and at most `MAX_SPEC_BYTES` per file.
 * Both caps are reported rather than silently applied — a truncated result
 * with no signal reads as "there were only 20 specs", and a vanished
 * oversized file reads as "that spec doesn't exist". `DiscoveryOutcome`
 * carries `truncated` and `oversized` so callers can surface both.
 *
 * Never throws: an unreadable file (permission error, path that doesn't
 * exist, race with a concurrent delete) is simply absent from the result.
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative, resolve, sep } from 'node:path';
import { FS_EXCLUDE } from '../treeHash/computeTreeHash.js';
export const MAX_SPEC_FILES = 20;
export const MAX_SPEC_BYTES = 5 * 1024 * 1024;
const SPEC_BASENAMES = new Set(['openapi', 'swagger', 'api-docs']);
const SPEC_EXTENSIONS = new Set(['.json', '.yaml', '.yml']);
/**
 * Find OpenAPI/Swagger documents under `projectPath`, or read exactly the
 * `explicit` paths when given. Never throws.
 */
export function discoverSpecs(projectPath, explicit) {
    const root = resolve(projectPath);
    const candidates = explicit && explicit.length > 0 ? [...explicit] : walk(root, root).sort();
    // The file cap applies on both entry paths: discovery can find more than
    // MAX_SPEC_FILES candidates, and a caller can just as easily hand in an
    // over-cap explicit list. Either way `truncated` must reflect it.
    const truncated = candidates.length > MAX_SPEC_FILES;
    const selected = candidates.slice(0, MAX_SPEC_FILES);
    const outcome = readCandidates(selected);
    outcome.truncated = truncated;
    return outcome;
}
function readCandidates(paths) {
    const specs = [];
    const oversized = [];
    for (const path of paths) {
        let size;
        try {
            size = statSync(path).size;
        }
        catch {
            // Path doesn't exist, isn't readable, or a race removed it — absent
            // from the result, not an error.
            continue;
        }
        if (size > MAX_SPEC_BYTES) {
            oversized.push(path);
            continue;
        }
        try {
            const text = readFileSync(path, 'utf8');
            specs.push({ file: path, text });
        }
        catch {
            // Unreadable (permissions, race between stat and read) — absent.
            continue;
        }
    }
    return { specs, oversized, truncated: false };
}
function walk(root, dir) {
    let entries;
    try {
        entries = readdirSync(dir, { withFileTypes: true });
    }
    catch {
        return [];
    }
    const out = [];
    for (const entry of entries) {
        if (entry.isDirectory()) {
            if (FS_EXCLUDE.has(entry.name))
                continue;
            out.push(...walk(root, join(dir, entry.name)));
        }
        else if (entry.isFile()) {
            if (isSpecCandidate(root, dir, entry.name)) {
                out.push(join(dir, entry.name));
            }
        }
    }
    return out;
}
/**
 * `dir` matches the "under an openapi/ directory" rule only when a
 * *project-relative* path segment is named `openapi` — i.e. relative to
 * `root`, not the absolute path. Checking the absolute path would also match
 * any project that merely happens to live beneath a directory named
 * `openapi` (a checkout path, a monorepo namespace), pulling in unrelated
 * files from outside the project entirely.
 */
function isSpecCandidate(root, dir, name) {
    const dot = name.lastIndexOf('.');
    if (dot <= 0)
        return false;
    const base = name.slice(0, dot);
    const ext = name.slice(dot).toLowerCase();
    if (!SPEC_EXTENSIONS.has(ext))
        return false;
    if (SPEC_BASENAMES.has(base.toLowerCase()))
        return true;
    const relDir = relative(root, dir);
    if (relDir === '')
        return false;
    return relDir.split(sep).some((segment) => segment.toLowerCase() === 'openapi');
}
//# sourceMappingURL=specDiscover.js.map