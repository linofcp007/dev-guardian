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
 * Every file and directory it reads is the scanned repository's, and goes
 * through `platform/projectFs.ts` (review of 3.0, W2E): a `package.json`
 * that is a link to `/dev/zero` OOM-killed the whole MCP server, and a FIFO
 * at that name hung it (measured in `node:22`, 768 MB). A file that is there
 * and was not read is named in the snapshot's `unread_files`, never taken for
 * "no such manifest".
 */
import { existsSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { readSmallText } from '../hooks/configFile.js';
import { describeReadRefusal, listProjectDir, PROJECT_FILE_MAX_BYTES, readProjectHead, readProjectText, } from '../platform/projectFs.js';
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
export function detectStack(projectPath) {
    const unread = new Map();
    const io = {
        root: projectPath,
        onRefused: (path, reason) => {
            const rel = relative(projectPath, path).split(sep).join('/');
            if (!unread.has(rel))
                unread.set(rel, describeReadRefusal(reason));
        },
    };
    const manifestDirs = walkManifestDirs(projectPath);
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
    const hasTerraform = hasGlob(projectPath, /\.tf$/i);
    const hasKubernetes = detectKubernetes(io, projectPath);
    const hasAnsible = existsSync(join(projectPath, 'roles')) || existsSync(join(projectPath, 'ansible.cfg'));
    const existingTools = detectExistingTools(io, projectPath).sort();
    const snapshot = {
        os: detectStackOs(),
        arch: detectStackArch(),
        languages,
        package_managers: packageManagers,
        frameworks,
        existing_tools: existingTools,
        has_docker: existsSync(join(projectPath, 'Dockerfile')),
        has_compose: hasComposeFile(projectPath),
        has_terraform: hasTerraform,
        has_kubernetes: hasKubernetes,
        has_ansible: hasAnsible,
        has_github_actions: existsSync(join(projectPath, '.github', 'workflows')),
        has_gitlab_ci: existsSync(join(projectPath, '.gitlab-ci.yml')),
        has_iac: hasTerraform || hasKubernetes || hasAnsible,
        projects,
    };
    if (unread.size > 0) {
        snapshot.unread_files = [...unread]
            .map(([path, reason]) => ({ path, reason }))
            .sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
    }
    return snapshot;
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
 * that holds at least one file in {@link MANIFEST_FILES}, skipping
 * `node_modules`, `vendor`, `.git`, `dist`, `build` (and the rest of
 * `PROJECT_WALK_EXCLUDE`, a superset already used by every other walk of a
 * project's own files) at any depth.
 */
function walkManifestDirs(root) {
    const found = [];
    const stack = [{ abs: root, rel: '', depth: 0 }];
    let visited = 0;
    while (stack.length > 0) {
        const cur = stack.pop();
        if (cur === undefined)
            break;
        if (visited >= MAX_DIRS_VISITED)
            break;
        visited += 1;
        const entries = readDirSafe(root, cur.abs);
        if (entries.some((e) => e.kind === 'file' && MANIFEST_FILES.includes(e.name))) {
            found.push({ rel: cur.rel, abs: cur.abs });
        }
        if (cur.depth >= MAX_MANIFEST_DEPTH)
            continue;
        for (const e of entries) {
            if (e.kind !== 'directory')
                continue;
            if (PROJECT_WALK_EXCLUDE.has(e.name) || e.name.startsWith('.'))
                continue;
            stack.push({
                abs: join(cur.abs, e.name),
                rel: cur.rel === '' ? e.name : `${cur.rel}/${e.name}`,
                depth: cur.depth + 1,
            });
        }
    }
    return found;
}
/**
 * Exported for `wordpress/sourceInventory.ts` (Task 18): the WordPress
 * source-vulnerability inventory reads the same directories this module's
 * own WordPress detection does (`wp-content/plugins/*`,
 * `wp-content/themes/*`), so it reuses this bounded, exception-safe walk
 * rather than re-implementing it. `platform/projectFs.ts#listProjectDir`:
 * each entry typed without following it (a link is `link`), and nothing
 * listed through a link out of `root`.
 */
export function readDirSafe(root, dir) {
    return listProjectDir(root, dir);
}
/** Manifest-driven detection, scoped to one directory (root or a nested one). */
function detectManifestsIn(io, dir) {
    const languages = [];
    const packageManagers = [];
    const frameworks = [];
    const has = (rel) => existsSync(join(dir, rel));
    const read = (rel) => readTextSafe(io.root, join(dir, rel), { onRefused: io.onRefused });
    // JS/TS. A package.json that is there and was not read still says
    // JavaScript; only its frameworks go unknown (and it is named).
    const pkgJsonText = read('package.json');
    if (pkgJsonText !== null || has('package.json')) {
        languages.push('javascript');
        if (has('tsconfig.json') || hasTopLevelExtension(io.root, dir, '.ts'))
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
    // Python
    const pyprojectText = read('pyproject.toml');
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
        const reqTexts = readRequirementsTxts(io, dir);
        const haystack = `${pyprojectText ?? ''}\n${reqTexts}`;
        if (/django/i.test(haystack))
            frameworks.push('django');
        if (/flask/i.test(haystack))
            frameworks.push('flask');
        if (/fastapi/i.test(haystack))
            frameworks.push('fastapi');
    }
    // PHP (composer-driven part; `*.php`-only and WordPress signals are layered
    // on at the root by the caller, since they are whole-project concerns).
    const composerText = read('composer.json');
    if (composerText !== null || has('composer.json')) {
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
    if (hasTopLevelExtension(io.root, dir, '.kt'))
        languages.push('kotlin');
    return {
        languages: unique(languages),
        package_managers: unique(packageManagers),
        frameworks: unique(frameworks),
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
/** `requirements*.txt` at this directory's top level, concatenated. */
function readRequirementsTxts(io, dir) {
    const entries = readDirSafe(io.root, dir);
    const texts = [];
    for (const e of entries) {
        if (e.kind === 'file' && /^requirements.*\.txt$/i.test(e.name)) {
            const text = readTextSafe(io.root, join(dir, e.name), { onRefused: io.onRefused });
            if (text !== null)
                texts.push(text);
        }
    }
    return texts.join('\n');
}
/** Whether `dir` (top level only, no recursion) has a file ending in `ext`. */
function hasTopLevelExtension(root, dir, ext) {
    return readDirSafe(root, dir).some((e) => e.kind === 'file' && e.name.toLowerCase().endsWith(ext));
}
/**
 * WordPress/WooCommerce/Kadence detection, scoped to `dir` — deliberately a
 * whole-project concern (evaluated once, at the root), unlike the manifest
 * walk above: `wp-content/themes/*` conventionally lives at the site root,
 * not at an arbitrary nesting depth.
 */
function detectWordPress(io, dir) {
    const has = (rel) => existsSync(join(dir, rel));
    let isWordPress = has('wp-config.php') || has('wp-config-sample.php') || has('wp-content');
    // A theme's header is at the top of its style.css, which may run long.
    const styleCss = readTextSafe(io.root, join(dir, 'style.css'), { maxBytes: HEADER_BYTES, onRefused: io.onRefused });
    if (styleCss !== null && /^\s*(?:\*\s*)?Theme Name:/im.test(styleCss))
        isWordPress = true;
    const pluginHeader = firstTopLevelPluginHeaderText(io, dir);
    if (pluginHeader !== null)
        isWordPress = true;
    const isKadence = has(join('wp-content', 'themes', 'kadence')) || has(join('wp-content', 'plugins', 'kadence-blocks'));
    const isWooCommerce = has(join('wp-content', 'plugins', 'woocommerce')) ||
        (readTextSafe(io.root, join(dir, 'composer.json'), { onRefused: io.onRefused })?.includes('woocommerce/woocommerce') ?? false) ||
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
    for (const e of readDirSafe(io.root, dir)) {
        if (e.kind !== 'file' || !e.name.toLowerCase().endsWith('.php'))
            continue;
        const text = readTextSafe(io.root, join(dir, e.name), { maxBytes: HEADER_BYTES, onRefused: io.onRefused });
        if (text !== null && /^\s*(?:\*|\/\/)?\s*Plugin Name:/im.test(text))
            return text;
    }
    return null;
}
// ---------------------------------------------------------------------- IaC / CI / existing tools
function hasComposeFile(dir) {
    return (existsSync(join(dir, 'docker-compose.yml')) ||
        existsSync(join(dir, 'compose.yml')) ||
        existsSync(join(dir, 'docker-compose.yaml')));
}
/** Top-level files only (mirrors the bash script's `compgen -G`, which never recursed). */
function hasGlob(dir, pattern) {
    return readDirSafe(dir, dir).some((e) => e.kind === 'file' && pattern.test(e.name));
}
function detectKubernetes(io, dir) {
    if (existsSync(join(dir, 'k8s')) || existsSync(join(dir, 'kubernetes')))
        return true;
    for (const e of readDirSafe(io.root, dir)) {
        if (e.kind !== 'file' || !/\.ya?ml$/i.test(e.name))
            continue;
        const text = readTextSafe(io.root, join(dir, e.name), { maxBytes: YAML_SNIFF_BYTES, onRefused: io.onRefused });
        if (text !== null && /apiVersion:\s/.test(text))
            return true;
    }
    return false;
}
function detectExistingTools(io, dir) {
    const has = (rel) => existsSync(join(dir, rel));
    const contains = (rel, needle) => (readTextSafe(io.root, join(dir, rel), { onRefused: io.onRefused }) ?? '').includes(needle);
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
    if (has('ruff.toml') || contains('pyproject.toml', '[tool.ruff]'))
        tools.push('ruff');
    if (has('playwright.config.ts') || has('playwright.config.js'))
        tools.push('playwright');
    if (has('vitest.config.ts') || has('vitest.config.js'))
        tools.push('vitest');
    if (has('jest.config.js') || has('jest.config.ts'))
        tools.push('jest');
    if (has('pytest.ini') || contains('pyproject.toml', '[tool.pytest'))
        tools.push('pytest');
    return tools;
}
// ---------------------------------------------------------------------- shared helpers
/**
 * A text file inside `root`, through `platform/projectFs.ts` — or null when
 * it is absent or was refused (a link out of `root` or to a network or
 * device path, a FIFO, a device, a directory, a file over the cap), and
 * `onRefused` hears of every refusal. With `maxBytes`: the first `maxBytes`
 * bytes of a file of any size (a header). Without: the whole file, up to
 * {@link MANIFEST_MAX_BYTES}. Exported for the same reason as
 * {@link readDirSafe} above.
 */
export function readTextSafe(root, path, opts = {}) {
    const r = opts.maxBytes !== undefined ? readProjectHead(root, path, opts.maxBytes) : readProjectText(root, path, MANIFEST_MAX_BYTES);
    if (r.status === 'ok')
        return r.text;
    if (r.status === 'refused')
        opts.onRefused?.(path, r.reason);
    return null;
}
function unique(values) {
    return [...new Set(values)];
}
//# sourceMappingURL=stackDetect.js.map