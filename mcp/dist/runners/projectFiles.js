/**
 * Walking a project directory without a shell.
 *
 * `find . -name "*.py" | head -1 | grep -q .` under `set -o pipefail` is how
 * `full-security-scan.sh` and `quality-scan.sh` decided whether a project had
 * Python: on a large tree `head` exits after the first line, `find` dies of
 * SIGPIPE, the pipeline "fails", and Bandit / ruff were silently skipped —
 * reproduced on a project with 3 000 `.py` files. The walk below stops at the
 * first match instead, and never asks a pipe for its exit status.
 */
import { readdirSync } from 'node:fs';
import { join } from 'node:path';
import { FS_EXCLUDE } from '../treeHash/computeTreeHash.js';
/**
 * Directories no scan of the project's OWN files should descend into: the
 * tree-hash denylist (`.git`, `.guardian`, `node_modules`, build output,
 * virtualenvs, caches) plus `vendor` (Composer / Go vendoring).
 */
export const PROJECT_WALK_EXCLUDE = new Set([...FS_EXCLUDE, 'vendor']);
function readDir(dir) {
    try {
        return readdirSync(dir, { withFileTypes: true });
    }
    catch {
        return [];
    }
}
/**
 * Whether any regular file under `root` ends with one of `extensions`
 * (lower-case, with the dot). Depth-first, stops at the first match; skips
 * `exclude` directories and hidden directories.
 */
export function hasFileWithExtension(root, extensions, exclude = PROJECT_WALK_EXCLUDE) {
    const stack = [root];
    while (stack.length > 0) {
        const dir = stack.pop();
        if (dir === undefined)
            break;
        for (const entry of readDir(dir)) {
            if (entry.isDirectory()) {
                if (!exclude.has(entry.name) && !entry.name.startsWith('.'))
                    stack.push(join(dir, entry.name));
            }
            else if (entry.isFile()) {
                const lower = entry.name.toLowerCase();
                if (extensions.some((ext) => lower.endsWith(ext)))
                    return true;
            }
        }
    }
    return false;
}
/**
 * How many regular files under `root` end with one of `extensions` — the
 * same walk as {@link hasFileWithExtension} (skipping `exclude` and hidden
 * directories), counted to the end.
 */
export function countFilesWithExtension(root, extensions, exclude = PROJECT_WALK_EXCLUDE) {
    let count = 0;
    const stack = [root];
    while (stack.length > 0) {
        const dir = stack.pop();
        if (dir === undefined)
            break;
        for (const entry of readDir(dir)) {
            if (entry.isDirectory()) {
                if (!exclude.has(entry.name) && !entry.name.startsWith('.'))
                    stack.push(join(dir, entry.name));
            }
            else if (entry.isFile()) {
                const lower = entry.name.toLowerCase();
                if (extensions.some((ext) => lower.endsWith(ext)))
                    count += 1;
            }
        }
    }
    return count;
}
/**
 * Every regular file under `root`, as a `/`-separated path relative to it,
 * skipping `exclude` directories (at any depth) and anything that is not a
 * regular file (symlinks, sockets, devices).
 */
export function listProjectFiles(root, exclude = PROJECT_WALK_EXCLUDE) {
    const out = [];
    const stack = [{ abs: root, rel: '' }];
    while (stack.length > 0) {
        const next = stack.pop();
        if (next === undefined)
            break;
        for (const entry of readDir(next.abs)) {
            const rel = next.rel === '' ? entry.name : `${next.rel}/${entry.name}`;
            if (entry.isDirectory()) {
                if (!exclude.has(entry.name))
                    stack.push({ abs: join(next.abs, entry.name), rel });
            }
            else if (entry.isFile()) {
                out.push(rel);
            }
        }
    }
    return out.sort();
}
//# sourceMappingURL=projectFiles.js.map