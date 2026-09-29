/**
 * Compute a stable hash of the working tree at `projectPath`.
 *
 * Inside a git repo we ask git for the file list: every tracked file plus
 * every untracked file that is not ignored (`--cached --others
 * --exclude-standard`), because a scanner reads an untracked source file just
 * the same, and a new file must invalidate a cached scan. Outside git we walk
 * the filesystem ourselves with a denylist of directories that change
 * frequently for reasons unrelated to source code (`.guardian/`,
 * `node_modules/`, `.git/`, build outputs, virtualenvs, caches).
 *
 * ---- Paths are relative to `projectPath`, never to the repository root ----
 *
 * The listing used to pass `--full-name`, which prints paths relative to the
 * REPOSITORY root. For a project that is a subdirectory of its repository —
 * every package of a monorepo — those paths were then joined to the
 * subdirectory, so every file read as `missing` and the hash ignored content
 * entirely: editing a file changed nothing, and a cached scan was served for
 * a tree that no longer existed. Without `--full-name`, `git -C root
 * ls-files` prints paths relative to `root`, which is what the join needs.
 *
 * ---- Untracked noise is excluded by the same denylist as the walk ----
 *
 * `--exclude=<dir>/` applies to UNTRACKED files only (git ls-files docs), so a
 * project with no `.gitignore` for `node_modules/` does not hash its whole
 * dependency tree, while a deliberately committed `dist/` still counts.
 * `.guardian/` is dropped from the listing even when tracked: it is this
 * tool's own output directory, and a hash that moved every time a scan wrote
 * its report would never produce a cache hit.
 *
 * The hash is order-independent: file paths are sorted before being joined.
 * Two identical project trees on different machines produce the same hash.
 */
import { execa } from 'execa';
import { createHash } from 'node:crypto';
import { readdir, stat } from 'node:fs/promises';
import { join, relative, resolve, sep } from 'node:path';
import { hashProjectFile } from '../platform/projectFs.js';
/**
 * Directories excluded from filesystem walks. Exported so other modules that
 * walk the project tree (e.g. `surface/specDiscover.ts`) share this exact
 * denylist instead of maintaining a second, driftable copy.
 */
export const FS_EXCLUDE = new Set([
    '.git',
    '.guardian',
    '.specs',
    '.kiro',
    'node_modules',
    'dist',
    'build',
    'target',
    '.venv',
    'venv',
    '__pycache__',
    '.next',
    '.nuxt',
    '.cache',
    'coverage',
    '.pytest_cache',
    '.tox',
]);
export async function computeTreeHash(projectPath, options = {}) {
    const root = resolve(projectPath);
    const files = options.forceFilesystemWalk
        ? await walkFiles(root)
        : (await tryGitListFiles(root)) ?? (await walkFiles(root));
    files.sort();
    const hash = createHash('sha256');
    for (const rel of files) {
        // `hashProjectFile` streams a regular file's content, hashes a link by its
        // target text without following it, and never opens anything else: git
        // lists a committed symlink as a file, and `readFile` on one to
        // `/dev/zero` read without end on every scan. A file that vanished
        // between listing and reading (race with the user) hashes as the stable
        // sentinel `missing`.
        const contentHash = await hashProjectFile(root, rel);
        hash.update(`${rel}:${contentHash}\n`);
    }
    return hash.digest('hex');
}
/** This tool's own output directory; never part of the hash, tracked or not. */
const TOOL_OUTPUT_DIR = '.guardian';
async function tryGitListFiles(root) {
    const excludes = [...FS_EXCLUDE].map((dir) => `--exclude=${dir}/`);
    try {
        const result = await execa('git', ['-C', root, 'ls-files', '-z', '--cached', '--others', '--exclude-standard', ...excludes], { reject: false, timeout: 30_000 });
        if (result.exitCode !== 0)
            return null;
        // A Set: an unmerged path is listed once per conflict stage.
        const files = new Set();
        for (const entry of result.stdout.split('\0')) {
            if (entry.length === 0)
                continue;
            if (entry.split('/').includes(TOOL_OUTPUT_DIR))
                continue;
            files.add(entry);
        }
        return [...files];
    }
    catch {
        return null;
    }
}
async function walkFiles(root) {
    const out = [];
    await walk(root, root, out);
    return out;
}
async function walk(root, dir, out) {
    let entries;
    try {
        entries = await readdir(dir, { withFileTypes: true });
    }
    catch {
        return;
    }
    for (const entry of entries) {
        if (entry.name.startsWith('.') && FS_EXCLUDE.has(entry.name))
            continue;
        if (FS_EXCLUDE.has(entry.name))
            continue;
        const abs = join(dir, entry.name);
        if (entry.isDirectory()) {
            await walk(root, abs, out);
        }
        else if (entry.isFile()) {
            try {
                const s = await stat(abs);
                if (s.isFile()) {
                    out.push(relative(root, abs).split(sep).join('/'));
                }
            }
            catch {
                // Skip transient files.
            }
        }
    }
}
//# sourceMappingURL=computeTreeHash.js.map