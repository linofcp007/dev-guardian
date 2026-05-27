/**
 * Compute a stable hash of the working tree at `projectPath`.
 *
 * Inside a git repo we ask git for the tracked file list (cheap, ignores
 * gitignored files automatically). Outside git we walk the filesystem
 * ourselves with a denylist of directories that change frequently for
 * reasons unrelated to source code (`.guardian/`, `node_modules/`, `.git/`,
 * build outputs, virtualenvs, caches).
 *
 * The hash is order-independent: file paths are sorted before being joined.
 * Two identical project trees on different machines produce the same hash.
 */
import { execa } from 'execa';
import { createHash } from 'node:crypto';
import { readFile, readdir, stat } from 'node:fs/promises';
import { join, relative, resolve, sep } from 'node:path';
const FS_EXCLUDE = new Set([
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
        const abs = join(root, rel);
        let contentHash;
        try {
            const bytes = await readFile(abs);
            contentHash = createHash('sha256').update(bytes).digest('hex');
        }
        catch {
            // File vanished between listing and reading (race with the user) —
            // hash a stable sentinel so the hash still reflects "this file was
            // expected but unreadable" deterministically.
            contentHash = 'missing';
        }
        hash.update(`${rel}:${contentHash}\n`);
    }
    return hash.digest('hex');
}
async function tryGitListFiles(root) {
    try {
        const result = await execa('git', ['-C', root, 'ls-files', '-z', '--full-name'], {
            reject: false,
            timeout: 30_000,
        });
        if (result.exitCode !== 0)
            return null;
        return result.stdout
            .split('\0')
            .map((p) => p.trim())
            .filter((p) => p.length > 0);
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