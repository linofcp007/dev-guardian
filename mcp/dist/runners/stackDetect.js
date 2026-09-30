/**
 * `detect_stack`'s detection engine — the TypeScript port of
 * `scripts/detect/detect-stack.sh`. Pure and synchronous: every check reads
 * the filesystem directly, with no shell, so a host with no bash/WSL can
 * still detect a stack (the shell script required one).
 *
 * Three defects the bash script reproduced, fixed here:
 *
 *   - PHP was only detected via `composer.json`. A typical WordPress site,
 *     theme or plugin ships no composer.json at all, so it reported
 *     `languages: []`. Fixed by detecting PHP from any `*.php` file, and
 *     WordPress from `wp-config.php`, a `wp-content/` directory, a theme's
 *     `style.css` "Theme Name:" header, or a plugin's own "Plugin Name:"
 *     header — any of which can be true with zero PHP package manifest.
 *   - Manifests were read at the project root ONLY, so a repo whose manifest
 *     lives one or more directories down (this repo: `mcp/package.json`)
 *     reported zero languages for itself. Fixed by walking to depth 3,
 *     excluding the directories no scan of the project's own files reads;
 *     each manifest-bearing directory becomes one entry in `projects`, and
 *     the top-level arrays are the union across all of them.
 *   - `build.gradle.kts` (a Kotlin Gradle *build script*) was folded into
 *     `java`. Fixed: it now reports `kotlin`.
 *
 * ## The repository is hostile input (review of 3.0, W2E)
 *
 * Every file and directory it reads goes through `platform/projectFs.ts`: a
 * `package.json` that is a link to `/dev/zero` OOM-killed the whole MCP
 * server, and a FIFO at that name hung it (measured in `node:22`, 768 MB).
 * Nothing on a repository path is `stat`ed or `exists`-checked through a link
 * either — presence is `projectEntryKindIn` (lstat and readlink, the links
 * below the project walked first): `existsSync` on a `package.json` linked to
 * `\\host\share\…` blocked the server for 157 s on Windows.
 *
 * A candidate that is there and was not read — a link out of the project, a
 * FIFO, a directory under a manifest's name, a file over its cap, a
 * directory link out of the project that the walk would have entered — is
 * named in the snapshot's `unread_files`, with why; it is never taken for
 * "no such file". A manifest that was not read still says its language.
 *
 * Reads are bounded twice: 8 MiB for one manifest (the first 8 KiB of a
 * plugin or theme header, 64 KiB of a YAML head), and {@link
 * DETECTION_BUDGET_BYTES} / {@link DETECTION_BUDGET_FILES} for the whole
 * detection, whatever the tree holds. Eighty `requirements-N.txt` of 8 MiB
 * each (one git blob, a few KB on the wire) were each under the per-file cap
 * and, concatenated, took a 768 MB server down; now each file is tested on
 * its own and dropped, and the reads past the budget are named.
 */
import { existsSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { readSmallText } from '../hooks/configFile.js';
import { describeReadRefusal, linkNotFollowed, listProjectDirOrNull, presentInProject, PROJECT_FILE_MAX_BYTES, ReadBudget, } from '../platform/projectFs.js';
import { hasFileWithExtension, PROJECT_WALK_EXCLUDE } from './projectFiles.js';
/** How many directories below the project root the manifest walk descends. */
const MAX_MANIFEST_DEPTH = 3;
/** A soft ceiling on directories visited by the manifest walk, so a
 *  pathological tree (thousands of tiny directories, none excluded) cannot
 *  make `detect_stack` hang. Never reached by an ordinary project. */
const MAX_DIRS_VISITED = 20_000;
/** A manifest (`package.json`, `pyproject.toml`, `composer.json`, a requirements file) is read whole up to this size. */
const MANIFEST_MAX_BYTES = PROJECT_FILE_MAX_BYTES;
/** A plugin's or theme's header is always near the top of its main file. */
const HEADER_BYTES = 8192;
/** A YAML file's head, read to tell a Kubernetes manifest. */
const YAML_SNIFF_BYTES = 64 * 1024;
/** What one detection may read in all — see the module doc. */
export const DETECTION_BUDGET_BYTES = 64 * 1024 * 1024;
export const DETECTION_BUDGET_FILES = 4_000;
/** `unread_files` lists at most this many; `unread_files_more` counts the rest. */
const MAX_UNREAD_LISTED = 50;
export function detectStack(projectPath) {
    const io = {
        root: projectPath,
        budget: new ReadBudget(DETECTION_BUDGET_BYTES, DETECTION_BUDGET_FILES),
        unread: new Map(),
    };
    const manifestDirs = walkManifestDirs(io);
    const projects = [];
    const rootDetected = detectManifestsIn(io, projectPath);
    const rootWp = detectWordPress(io, projectPath);
    const rootPhpByGlob = hasFileWithExtension(projectPath, ['.php']);
    const root = {
        path: '.',
        languages: unique([
            ...rootDetected.languages,
            ...(rootPhpByGlob || rootWp.isWordPress ? ['php'] : []),
        ]),
        package_managers: [...rootDetected.package_managers],
        frameworks: unique([...rootDetected.frameworks, ...rootWp.frameworks]),
    };
    if (root.languages.length > 0 || root.frameworks.length > 0)
        projects.push(root);
    for (const dir of manifestDirs) {
        if (dir.rel === '')
            continue; // the root is handled above, with the WP/PHP-glob signals folded in.
        const detected = detectManifestsIn(io, dir.abs);
        if (detected.languages.length === 0)
            continue;
        projects.push({
            path: dir.rel,
            languages: detected.languages,
            package_managers: detected.package_managers,
            frameworks: detected.frameworks,
        });
    }
    const languages = unique(projects.flatMap((p) => p.languages)).sort();
    const packageManagers = unique(projects.flatMap((p) => p.package_managers)).sort();
    const frameworks = unique(projects.flatMap((p) => p.frameworks)).sort();
    const has = (rel) => presentInProject(projectPath, rel);
    const hasTerraform = hasGlob(io, projectPath, /\.tf$/i);
    const hasKubernetes = detectKubernetes(io, projectPath);
    const hasAnsible = has('roles') || has('ansible.cfg');
    const existingTools = detectExistingTools(io, projectPath, rootDetected.pyprojectText).sort();
    const snapshot = {
        os: detectStackOs(),
        arch: detectStackArch(),
        languages,
        package_managers: packageManagers,
        frameworks,
        existing_tools: existingTools,
        has_docker: has('Dockerfile'),
        has_compose: has('docker-compose.yml') || has('compose.yml') || has('docker-compose.yaml'),
        has_terraform: hasTerraform,
        has_kubernetes: hasKubernetes,
        has_ansible: hasAnsible,
        has_github_actions: has(join('.github', 'workflows')),
        has_gitlab_ci: has('.gitlab-ci.yml'),
        has_iac: hasTerraform || hasKubernetes || hasAnsible,
        projects,
    };
    if (io.unread.size > 0) {
        const all = [...io.unread]
            .map(([path, reason]) => ({ path, reason }))
            .sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
        snapshot.unread_files = all.slice(0, MAX_UNREAD_LISTED);
        if (all.length > MAX_UNREAD_LISTED)
            snapshot.unread_files_more = all.length - MAX_UNREAD_LISTED;
    }
    return snapshot;
}
// ---------------------------------------------------------------------- reads
function relOf(io, abs) {
    return relative(io.root, abs).split(sep).join('/');
}
function noteUnread(io, abs, why) {
    const rel = relOf(io, abs);
    if (!io.unread.has(rel))
        io.unread.set(rel, why);
}
/** A file's text within the budget — whole (a manifest) or its first `head` bytes — or null, naming why. */
function readText(io, abs, head) {
    const r = head !== undefined ? io.budget.readHead(io.root, abs, head) : io.budget.readText(io.root, abs, MANIFEST_MAX_BYTES);
    if (r.status === 'ok')
        return r.text;
    if (r.status === 'refused')
        noteUnread(io, abs, describeReadRefusal(r.reason));
    return null;
}
/**
 * The entries of `dir`, typed without following them — or `[]`, naming the
 * directory, when it could not be listed. Only directories the walk reached
 * as directories are listed, so "could not" is a race or a permission.
 */
function listDir(io, dir) {
    const entries = listProjectDirOrNull(io.root, dir);
    if (entries !== null)
        return entries;
    if (presentInProject(io.root, dir))
        noteUnread(io, dir, 'this directory could not be listed');
    return [];
}
/** An entry that may hold a file's content: anything but a directory. A link or a FIFO is read, and refused by name. */
function fileLike(e) {
    return e.kind !== 'directory';
}
// ---------------------------------------------------------------------- OS / arch
function detectStackOs() {
    switch (process.platform) {
        case 'darwin':
            return 'macos';
        case 'win32':
            return 'windows';
        case 'linux':
            if (isWsl())
                return 'wsl';
            if (existsSync('/etc/debian_version'))
                return 'debian';
            if (existsSync('/etc/redhat-release'))
                return 'rhel';
            if (existsSync('/etc/arch-release'))
                return 'arch';
            return 'linux';
        default:
            return 'unknown';
    }
}
function isWsl() {
    // The system's own file, read the bounded way all the same.
    const r = readSmallText('/proc/version', 64 * 1024);
    return r.status === 'ok' && /microsoft/i.test(r.text);
}
/**
 * `arch`, in the same spelling the bash script's `uname -m` used — which is
 * NOT what `process.arch` spells 64-bit ARM as on every OS. Linux's `uname
 * -m` reports `aarch64`; Apple's own `uname -m` reports `arm64`; Node's
 * `process.arch` collapses both to `'arm64'`. `platform`/`arch` are
 * parameters (defaulting to the real `process.platform`/`process.arch`) so
 * this is directly unit-testable without stubbing globals.
 */
export function detectStackArch(platform = process.platform, arch = process.arch) {
    switch (arch) {
        case 'x64':
            return 'x86_64';
        case 'arm64':
            return platform === 'darwin' ? 'arm64' : 'aarch64';
        case 'ia32':
            return 'i686';
        case 'arm':
            return 'armv7l';
        default:
            return arch;
    }
}
/** Manifest file names that make a directory count as a (sub-)project. */
const MANIFEST_FILES = [
    'package.json',
    'pyproject.toml',
    'requirements.txt',
    'Pipfile',
    'setup.py',
    'setup.cfg',
    'composer.json',
    'go.mod',
    'Cargo.toml',
    'Gemfile',
    'pom.xml',
    'build.gradle',
    'build.gradle.kts',
];
/**
 * Every directory at depth 0..{@link MAX_MANIFEST_DEPTH} (root inclusive)
 * that holds an entry named in {@link MANIFEST_FILES} (a link or a FIFO
 * under that name counts: it is read, and refused by name), skipping
 * `node_modules`, `vendor`, `.git`, `dist`, `build` (and the rest of
 * `PROJECT_WALK_EXCLUDE`, a superset already used by every other walk of a
 * project's own files) and hidden directories at any depth. A directory link
 * is not descended; one that leads out of the project (or cannot be
 * resolved) where the walk would have entered it is named — a sub-project
 * behind it was not detected. One that stays inside is not named: what it
 * names is walked in its own place.
 */
function walkManifestDirs(io) {
    const found = [];
    const stack = [{ abs: io.root, rel: '', depth: 0 }];
    let visited = 0;
    while (stack.length > 0) {
        const cur = stack.pop();
        if (cur === undefined)
            break;
        if (visited >= MAX_DIRS_VISITED) {
            noteUnread(io, cur.abs, `the manifest walk stopped after ${MAX_DIRS_VISITED} directories; this one was not read`);
            break;
        }
        visited += 1;
        const entries = listDir(io, cur.abs);
        if (entries.some((e) => fileLike(e) && MANIFEST_FILES.includes(e.name))) {
            found.push({ rel: cur.rel, abs: cur.abs });
        }
        if (cur.depth >= MAX_MANIFEST_DEPTH)
            continue;
        for (const e of entries) {
            if (e.kind !== 'directory' && e.kind !== 'link')
                continue;
            if (PROJECT_WALK_EXCLUDE.has(e.name) || e.name.startsWith('.'))
                continue;
            const abs = join(cur.abs, e.name);
            if (e.kind === 'link') {
                const out = linkNotFollowed(io.root, abs);
                if (out !== null) {
                    noteUnread(io, abs, out.kind === 'directory' ? `${out.says}: a sub-project behind it was not detected` : out.says);
                }
                continue;
            }
            stack.push({ abs, rel: cur.rel === '' ? e.name : `${cur.rel}/${e.name}`, depth: cur.depth + 1 });
        }
    }
    return found;
}
/** Manifest-driven detection, scoped to one directory (root or a nested one). */
function detectManifestsIn(io, dir) {
    const languages = [];
    const packageManagers = [];
    const frameworks = [];
    const has = (rel) => presentInProject(io.root, join(dir, rel));
    const entries = listDir(io, dir);
    // JS/TS. A package.json that is there and was not read still says
    // JavaScript; only its frameworks go unknown (and it is named).
    if (has('package.json')) {
        const pkgJsonText = readText(io, join(dir, 'package.json'));
        languages.push('javascript');
        if (has('tsconfig.json') || hasTopLevelExtension(entries, '.ts'))
            languages.push('typescript');
        if (has('pnpm-lock.yaml'))
            packageManagers.push('pnpm');
        else if (has('yarn.lock'))
            packageManagers.push('yarn');
        else if (has('bun.lockb') || has('bun.lock'))
            packageManagers.push('bun');
        else
            packageManagers.push('npm');
        for (const [needle, framework] of JS_FRAMEWORK_MARKERS) {
            if (pkgJsonText?.includes(needle) === true)
                frameworks.push(framework);
        }
    }
    // Python. Each file is tested on its own and dropped — never concatenated.
    let pyprojectText = null;
    if (has('pyproject.toml') || has('requirements.txt') || has('Pipfile') || has('setup.py') || has('setup.cfg')) {
        languages.push('python');
        if (has('poetry.lock'))
            packageManagers.push('poetry');
        else if (has('uv.lock'))
            packageManagers.push('uv');
        else if (has('Pipfile.lock'))
            packageManagers.push('pipenv');
        else
            packageManagers.push('pip');
        const seen = new Set();
        const look = (text) => {
            if (text === null)
                return;
            for (const [re, framework] of PY_FRAMEWORK_MARKERS)
                if (re.test(text))
                    seen.add(framework);
        };
        if (has('pyproject.toml')) {
            pyprojectText = readText(io, join(dir, 'pyproject.toml'));
            look(pyprojectText);
        }
        for (const e of entries) {
            if (fileLike(e) && /^requirements.*\.txt$/i.test(e.name))
                look(readText(io, join(dir, e.name)));
        }
        frameworks.push(...PY_FRAMEWORK_MARKERS.map(([, f]) => f).filter((f) => seen.has(f)));
    }
    // PHP (composer-driven part; `*.php`-only and WordPress signals are layered
    // on at the root by the caller, since they are whole-project concerns).
    if (has('composer.json')) {
        const composerText = readText(io, join(dir, 'composer.json'));
        languages.push('php');
        packageManagers.push('composer');
        if (composerText?.includes('laravel/framework') === true)
            frameworks.push('laravel');
        if (composerText?.includes('symfony/') === true)
            frameworks.push('symfony');
    }
    // Go
    if (has('go.mod')) {
        languages.push('go');
        packageManagers.push('gomod');
    }
    // Rust
    if (has('Cargo.toml')) {
        languages.push('rust');
        packageManagers.push('cargo');
    }
    // Ruby
    if (has('Gemfile')) {
        languages.push('ruby');
        packageManagers.push('bundler');
    }
    // Java / Kotlin
    if (has('pom.xml')) {
        languages.push('java');
        packageManagers.push('maven');
    }
    if (has('build.gradle')) {
        languages.push('java');
        packageManagers.push('gradle');
    }
    if (has('build.gradle.kts')) {
        languages.push('kotlin');
        packageManagers.push('gradle');
    }
    if (hasTopLevelExtension(entries, '.kt'))
        languages.push('kotlin');
    return {
        languages: unique(languages),
        package_managers: unique(packageManagers),
        frameworks: unique(frameworks),
        pyprojectText,
    };
}
const JS_FRAMEWORK_MARKERS = [
    ['"react"', 'react'],
    ['"next"', 'nextjs'],
    ['"vue"', 'vue'],
    ['"@angular', 'angular'],
    ['"svelte"', 'svelte'],
    ['"express"', 'express'],
    ['"fastify"', 'fastify'],
    ['"@nestjs', 'nestjs'],
    ['"astro"', 'astro'],
];
const PY_FRAMEWORK_MARKERS = [
    [/django/i, 'django'],
    [/flask/i, 'flask'],
    [/fastapi/i, 'fastapi'],
];
/** Whether the listing (top level only) has a non-directory entry ending in `ext`. Names only. */
function hasTopLevelExtension(entries, ext) {
    return entries.some((e) => fileLike(e) && e.name.toLowerCase().endsWith(ext));
}
/**
 * WordPress/WooCommerce/Kadence detection, scoped to `dir` — deliberately a
 * whole-project concern (evaluated once, at the root), unlike the manifest
 * walk above: `wp-content/themes/*` conventionally lives at the site root,
 * not at an arbitrary nesting depth.
 */
function detectWordPress(io, dir) {
    const has = (rel) => presentInProject(io.root, join(dir, rel));
    let isWordPress = has('wp-config.php') || has('wp-config-sample.php') || has('wp-content');
    // A theme's header is at the top of its style.css, which may run long.
    const styleCss = has('style.css') ? readText(io, join(dir, 'style.css'), HEADER_BYTES) : null;
    if (styleCss !== null && /^\s*(?:\*\s*)?Theme Name:/im.test(styleCss))
        isWordPress = true;
    const pluginHeader = firstTopLevelPluginHeaderText(io, dir);
    if (pluginHeader !== null)
        isWordPress = true;
    const isKadence = has(join('wp-content', 'themes', 'kadence')) || has(join('wp-content', 'plugins', 'kadence-blocks'));
    const composer = has('composer.json') ? readText(io, join(dir, 'composer.json')) : null;
    const isWooCommerce = has(join('wp-content', 'plugins', 'woocommerce')) ||
        (composer?.includes('woocommerce/woocommerce') ?? false) ||
        /requires plugins:.*woocommerce|wc requires at least/i.test(`${styleCss ?? ''}\n${pluginHeader ?? ''}`);
    const frameworks = [];
    if (isWordPress || isWooCommerce)
        frameworks.push('wordpress');
    if (isWooCommerce)
        frameworks.push('woocommerce');
    if (isKadence)
        frameworks.push('kadence');
    return { isWordPress: isWordPress || isWooCommerce, frameworks: unique(frameworks) };
}
/** The text of the first top-level `*.php` file whose header names a plugin,
 *  or null when none does. Bounded to top-level files and the first 8 KB of
 *  each — a plugin header is always near the top of the main file. */
function firstTopLevelPluginHeaderText(io, dir) {
    for (const e of listDir(io, dir)) {
        if (!fileLike(e) || !e.name.toLowerCase().endsWith('.php'))
            continue;
        const text = readText(io, join(dir, e.name), HEADER_BYTES);
        if (text !== null && /^\s*(?:\*|\/\/)?\s*Plugin Name:/im.test(text))
            return text;
    }
    return null;
}
// ---------------------------------------------------------------------- IaC / CI / existing tools
/** Top-level entries only (mirrors the bash script's `compgen -G`, which never recursed). Names only. */
function hasGlob(io, dir, pattern) {
    return listDir(io, dir).some((e) => fileLike(e) && pattern.test(e.name));
}
function detectKubernetes(io, dir) {
    if (presentInProject(io.root, join(dir, 'k8s')) || presentInProject(io.root, join(dir, 'kubernetes')))
        return true;
    for (const e of listDir(io, dir)) {
        if (!fileLike(e) || !/\.ya?ml$/i.test(e.name))
            continue;
        const text = readText(io, join(dir, e.name), YAML_SNIFF_BYTES);
        if (text !== null && /apiVersion:\s/.test(text))
            return true;
    }
    return false;
}
function detectExistingTools(io, dir, pyprojectText) {
    const has = (rel) => presentInProject(io.root, join(dir, rel));
    const inPyproject = (needle) => (pyprojectText ?? '').includes(needle);
    const tools = [];
    if (has('.semgrep.yml') || has(join('.semgrep', 'semgrep.yml')))
        tools.push('semgrep');
    if (has('.gitleaks.toml'))
        tools.push('gitleaks');
    if (has('.trivyignore'))
        tools.push('trivy');
    if (has('renovate.json') || has('.renovaterc') || has('.renovaterc.json'))
        tools.push('renovate');
    if (has(join('.github', 'dependabot.yml')))
        tools.push('dependabot');
    if (has('.pre-commit-config.yaml'))
        tools.push('pre-commit');
    if (has('.eslintrc') || has('.eslintrc.json') || has('eslint.config.js'))
        tools.push('eslint');
    if (has('.prettierrc') || has('.prettierrc.json'))
        tools.push('prettier');
    if (has('ruff.toml') || inPyproject('[tool.ruff]'))
        tools.push('ruff');
    if (has('playwright.config.ts') || has('playwright.config.js'))
        tools.push('playwright');
    if (has('vitest.config.ts') || has('vitest.config.js'))
        tools.push('vitest');
    if (has('jest.config.js') || has('jest.config.ts'))
        tools.push('jest');
    if (has('pytest.ini') || inPyproject('[tool.pytest'))
        tools.push('pytest');
    return tools;
}
// ---------------------------------------------------------------------- shared helpers
function unique(values) {
    return [...new Set(values)];
}
//# sourceMappingURL=stackDetect.js.map