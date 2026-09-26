/**
 * Could anything OTHER than "it does not exist" explain a 404 from the
 * public registry?
 *
 * The vetting may DENY a name the public registry has never heard of — that
 * is how a hallucinated dependency is caught before anyone squats it. But a
 * company's own packages are ALSO absent from the public registry, by
 * design, and so are a monorepo's own workspace packages. When this file
 * finds an explanation, "not on the public registry" stops being evidence
 * of anything: the verdict becomes `unknown` (with this file's answer as the
 * reason) and never `block`. Three kinds (the controller ruling's (d)-(f)):
 *
 *   - `registry`  — a custom registry / index / source is configured;
 *   - `auth`      — an npmjs credential is configured and the name is
 *                   scoped: a private scoped package answers 404 anonymously;
 *   - `workspace` — the name is a local workspace package (package.json
 *                   `workspaces`, `pnpm-workspace.yaml`, uv workspace members
 *                   or `[tool.uv.sources]`; composer path repositories are
 *                   already `repositories`).
 *
 * Where `registry` is looked for, per ecosystem:
 *
 *   - npm / pnpm / yarn / bun: `registry=` (all names) or `@scope:registry=`
 *     (that scope) in a project `.npmrc`, the user npmrc
 *     (`NPM_CONFIG_USERCONFIG` or `~/.npmrc`), npm's global npmrc when
 *     `npm_config_globalconfig` names it, and pnpm's global rc (XDG,
 *     `%LOCALAPPDATA%\pnpm\config\rc`, macOS); `NPM_CONFIG_REGISTRY`;
 *     yarn's `.yarnrc.yml` `npmRegistryServer` (global or under
 *     `npmScopes.<scope>`, project or `~`) and classic `.yarnrc`
 *     `registry`; bun's `bunfig.toml` (project or `~/.bunfig.toml`)
 *     `[install] registry` / `[install.scopes]`.
 *   - pip / uv / poetry: `PIP_INDEX_URL`, `PIP_EXTRA_INDEX_URL`,
 *     `UV_INDEX_URL`, `UV_EXTRA_INDEX_URL`, `UV_INDEX`, `UV_DEFAULT_INDEX`,
 *     `PIP_FIND_LINKS`, `PIP_NO_INDEX`; `pip.conf` / `pip.ini` (user, venv,
 *     `PIP_CONFIG_FILE`, and global: `/etc/pip.conf`,
 *     `/etc/xdg/pip/pip.conf`, `XDG_CONFIG_DIRS`, `%ProgramData%\pip\pip.ini`);
 *     `uv.toml` (`UV_CONFIG_FILE`, `~/.config/uv`, `%APPDATA%\uv`,
 *     `/etc/uv`, and the project); `[[tool.uv.index]]`,
 *     `[[tool.poetry.source]]`, `[[tool.pdm.source]]` or a `[tool.uv]`
 *     index URL in `pyproject.toml`.
 *   - Composer: a `repositories` entry in the project `composer.json` or the
 *     user's global `config.json`.
 *   - NuGet: any `nuget.config` (any casing) from the project up to the
 *     repository root, or the user-level one, with a package source that is
 *     not nuget.org.
 *
 * Round 2 additions: npm's DEFAULT global npmrc (`%APPDATA%\npm\etc\npmrc`,
 * or `<node prefix>/etc/npmrc` from `process.execPath`, or
 * `npm_config_prefix`); macOS pip (`~/Library/Application Support/pip`);
 * every `nuget.config` up to the filesystem root, as NuGet itself reads
 * them; and the hook's environment, matched case-insensitively —
 * `YARN_NPM_REGISTRY_SERVER`, `YARN_REGISTRY`, `BUN_CONFIG_REGISTRY`,
 * `npm_config_*registry*` (incl. `npm_config_@scope:registry`),
 * `PIP_*INDEX*`, `UV_*INDEX*`, `NUGET_*`.
 *
 * A configured value that IS the public registry (`registry.npmjs.org`,
 * `pypi.org/simple`, `api.nuget.org`) is not custom.
 *
 * Reads files only (node built-ins); never the network. A file reached through
 * a link to a network or device path is refused before it is opened
 * (`walkRoot`, follow-up Part Y), as the hook configuration is. A
 * configuration that is THERE but could not be read — refused that way, or not
 * a regular file, too large, no permission — is UNKNOWN, never absent: when
 * nothing else explains the 404 it is reported as `unreadable` (Part Y fix
 * round 1, controller ruling), so a missing name warns instead of being denied.
 */
import { lstatSync, readdirSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, isAbsolute, join, parse, relative, resolve } from 'node:path';
import { isRemoteOrDeviceTarget, readSmallText, walkLinksUnder } from '../hooks/configFile.js';
const PUBLIC_HOSTS = {
    npm: /^(?:https?:)?\/\/(?:registry\.npmjs\.(?:org|com)|registry\.yarnpkg\.com)(?:[:/]|$)/i,
    pypi: /^(?:https?:)?\/\/(?:pypi\.org|pypi\.python\.org|files\.pythonhosted\.org)(?:[:/]|$)/i,
    packagist: /^(?:https?:)?\/\/(?:repo\.)?packagist\.org(?:[:/]|$)/i,
    nuget: /^(?:https?:)?\/\/(?:api\.nuget\.org|www\.nuget\.org|nuget\.org)(?:[:/]|$)/i,
};
function isPublic(ecosystem, url) {
    return PUBLIC_HOSTS[ecosystem].test(url.trim().replace(/^["']|["']$/g, ''));
}
/** True when `url` is the ecosystem's own public registry (so naming it changes nothing). */
export function isPublicRegistryUrl(ecosystem, url) {
    return isPublic(ecosystem, url);
}
/**
 * The largest registry configuration file read. These reads run inside the
 * install hook's 15 s budget: a FIFO or a device where `.npmrc` belongs is
 * opened non-blocking and refused on its descriptor, never read, and an
 * absurd file is never read (Task 23 fix round 2, N1) — see
 * `hooks/configFile.ts`. A file refused here is UNKNOWN — see `unreadable`.
 */
const MAX_REGISTRY_CONFIG_BYTES = 1024 * 1024;
/** `path` lies strictly below `dir`. */
function isInside(dir, path) {
    const rel = relative(dir, path);
    return rel !== '' && !rel.startsWith('..') && !isAbsolute(rel);
}
/**
 * The directory below which `path`'s components are walked for a link to a
 * network or device path before anything is opened (`walkLinksUnder`, as for
 * the hook configuration — follow-up Part Y): the project when the file is in
 * it; the file's own directory when that is one of the project's ancestors (a
 * parent `.npmrc`, a `nuget.config` up to the root); the home directory when
 * the file is in there; otherwise the filesystem root (`/etc/pip.conf`,
 * `%ProgramData%\pip\pip.ini`). Never the project or the home directory
 * themselves, nor their ancestors: those are the user's layout, and a project
 * that lives on a share through a link must keep its configuration readable —
 * so listing one of them is `undefined`, no walk; so is a path that itself
 * names a share (a roaming profile's `%APPDATA%`), the user's setting rather
 * than a link to judge.
 */
function walkRoot(path, ctx, under) {
    const abs = resolve(path);
    if (isRemoteOrDeviceTarget(abs))
        return undefined;
    if (under !== undefined)
        return under;
    /** `dir` is `base` or one of its ancestors. */
    const holds = (dir, base) => samePath(dir, base) || isInside(dir, base);
    const project = ctx.projectDir === undefined ? undefined : resolve(ctx.projectDir);
    const home = resolve(homeOf(ctx));
    if ((project !== undefined && holds(abs, project)) || holds(abs, home))
        return undefined;
    if (project !== undefined && isInside(project, abs))
        return project;
    const dir = dirname(abs);
    if (project !== undefined && holds(dir, project))
        return dir;
    if (isInside(home, abs))
        return home;
    return parse(abs).root;
}
/**
 * The first registry configuration path the current `customRegistryFor` call
 * found THERE but could not read. Reset at the start of each (synchronous)
 * call and read at its end: when nothing else explains a 404, this does.
 */
let firstUnread;
function noteUnread(path) {
    firstUnread = firstUnread ?? path;
}
/**
 * A registry configuration file's text, or `undefined`. A link on the way to
 * a network or device path (`\\host\share`, `\\?\…`) — the file itself or a
 * directory above it, below {@link walkRoot} — refuses the file unopened: an
 * open through a link to an unreachable host waits on the network for minutes,
 * and a hook that dies at its 15 s timeout lets the install through unvetted.
 * A refused file is recorded ({@link noteUnread}); an absent one is not.
 */
function read(path, ctx, under) {
    const r = readSmallText(path, MAX_REGISTRY_CONFIG_BYTES, walkRoot(path, ctx, under));
    if (r.status === 'refused')
        noteUnread(path);
    return r.status === 'ok' ? r.text : undefined;
}
/**
 * Whether `path` exists, WITHOUT following a link at it: `lstat` never touches
 * a link's target, where `existsSync` would open a `.git` linked to a share.
 */
function present(path) {
    try {
        lstatSync(path);
        return true;
    }
    catch {
        return false;
    }
}
/**
 * The entries of `dir` — none when it does not exist, and none, recorded as
 * unread ({@link noteUnread}), when a link on the way to it points at a network
 * or device path or it cannot be listed.
 */
function listDir(dir, ctx) {
    const under = walkRoot(dir, ctx);
    if (under !== undefined && !walkLinksUnder(under, dir).ok) {
        noteUnread(dir);
        return [];
    }
    try {
        return readdirSync(dir);
    }
    catch (e) {
        const code = e.code;
        if (code !== 'ENOENT' && code !== 'ENOTDIR')
            noteUnread(dir);
        return [];
    }
}
function samePath(a, b) {
    const norm = (p) => resolve(p).replace(/[\\/]+$/, '');
    return process.platform === 'win32' ? norm(a).toLowerCase() === norm(b).toLowerCase() : norm(a) === norm(b);
}
/**
 * The project directory and its ancestors, nearest first — up to and
 * including the first one holding `.git`, and never the user's home (that
 * is read separately, as user-level configuration) or anything above it.
 */
function ancestors(ctx) {
    if (ctx.projectDir === undefined)
        return [];
    const stops = [ctx.homeDir, homedir()].filter((x) => typeof x === 'string');
    const out = [];
    let dir = resolve(ctx.projectDir);
    for (let i = 0; i < 16; i += 1) {
        if (stops.some((s) => samePath(s, dir)))
            break;
        out.push(dir);
        if (present(join(dir, '.git')))
            break;
        const parent = dirname(dir);
        if (parent === dir)
            break;
        dir = parent;
    }
    return out;
}
function envOf(ctx) {
    return ctx.env ?? process.env;
}
function homeOf(ctx) {
    return ctx.homeDir ?? homedir();
}
function envValue(env, name) {
    const v = env[name] ?? env[name.toLowerCase()];
    return v !== undefined && v.trim() !== '' ? v.trim() : undefined;
}
// ─────────────────────────────────────────────────────────────── npm
function npmScope(name) {
    const m = /^@([^/]+)\//.exec(name);
    return m?.[1];
}
/** `.npmrc`: `registry=` and `@scope:registry=`. */
function fromNpmrc(text, scope) {
    let found;
    for (const raw of text.split(/\r?\n/)) {
        const line = raw.trim();
        if (line.startsWith('#') || line.startsWith(';'))
            continue;
        const m = /^(@[^:=\s]+:)?registry\s*=\s*(.+)$/i.exec(line);
        if (m === null)
            continue;
        const lineScope = m[1]?.slice(1, -1);
        const url = (m[2] ?? '').trim();
        if (lineScope === undefined)
            found = found ?? url;
        else if (scope !== undefined && lineScope.toLowerCase() === scope.toLowerCase())
            return url;
    }
    return found;
}
/** yarn berry `.yarnrc.yml`: top-level `npmRegistryServer`, or `npmScopes.<scope>.npmRegistryServer`. */
function fromYarnrcYml(text, scope) {
    let global;
    let inScopes = false;
    let currentScope;
    for (const raw of text.split(/\r?\n/)) {
        if (raw.trim() === '' || raw.trim().startsWith('#'))
            continue;
        const indent = raw.length - raw.trimStart().length;
        const line = raw.trim();
        if (indent === 0) {
            inScopes = /^npmScopes\s*:/.test(line);
            currentScope = undefined;
            const m = /^npmRegistryServer\s*:\s*(.+)$/.exec(line);
            if (m !== null)
                global = (m[1] ?? '').replace(/^["']|["']$/g, '');
            continue;
        }
        if (!inScopes)
            continue;
        const scopeKey = /^["']?@?([^"':]+)["']?\s*:\s*$/.exec(line);
        if (scopeKey !== null) {
            currentScope = scopeKey[1];
            continue;
        }
        const server = /^npmRegistryServer\s*:\s*(.+)$/.exec(line);
        if (server !== null && scope !== undefined && currentScope?.toLowerCase() === scope.toLowerCase()) {
            return (server[1] ?? '').replace(/^["']|["']$/g, '');
        }
    }
    return global;
}
/** yarn classic `.yarnrc`: `registry "url"` / `"@scope:registry" "url"`. */
function fromYarnrc(text, scope) {
    let found;
    for (const raw of text.split(/\r?\n/)) {
        const m = /^\s*["']?(@[^:"']+:)?registry["']?\s+["']?([^"'\s]+)["']?/.exec(raw);
        if (m === null)
            continue;
        const lineScope = m[1]?.slice(1, -1);
        if (lineScope === undefined)
            found = found ?? m[2];
        else if (scope !== undefined && lineScope.toLowerCase() === scope.toLowerCase())
            return m[2];
    }
    return found;
}
/** bun `bunfig.toml`: `[install] registry = …` and `[install.scopes] <scope> = …`. */
function fromBunfig(text, scope) {
    let section = '';
    let found;
    for (const raw of text.split(/\r?\n/)) {
        const line = raw.trim();
        const header = /^\[([^\]]+)\]$/.exec(line);
        if (header !== null) {
            section = (header[1] ?? '').trim();
            continue;
        }
        const url = /https?:\/\/[^"'\s}]+/.exec(line)?.[0] ?? '(configured)';
        if (section === 'install' && /^registry\s*=/.test(line))
            found = found ?? url;
        if (section === 'install.scopes' && scope !== undefined) {
            const key = /^["']?@?([^"'=\s]+)["']?\s*=/.exec(line)?.[1];
            if (key !== undefined && key.toLowerCase() === scope.toLowerCase())
                return url;
        }
    }
    return found;
}
/** An npmjs credential in an npmrc (`//registry.npmjs.org/:_authToken=`, `_auth=`, …) or `.yarnrc.yml`. */
const NPM_AUTH = /^\s*(?:\/\/registry\.(?:npmjs\.org|yarnpkg\.com)\/:)?_(?:authToken|auth|password)\s*=|^\s*npmAuth(?:Token|Ident)\s*:/m;
/**
 * Every npm-family configuration file that can apply, nearest first:
 * project ancestors (`.npmrc`, `.yarnrc.yml`, `.yarnrc`, `bunfig.toml`),
 * then user (`NPM_CONFIG_USERCONFIG` or `~/.npmrc`, `~/.yarnrc.yml`,
 * `~/.yarnrc`, `~/.bunfig.toml`), pnpm's global rc (XDG, `%LOCALAPPDATA%`,
 * macOS), and npm's global npmrc when `npm_config_globalconfig` names it.
 */
function npmConfigFiles(ctx) {
    const env = envOf(ctx);
    const home = homeOf(ctx);
    const files = [];
    const near = ancestors(ctx);
    for (const dir of near) {
        files.push({ path: join(dir, '.npmrc'), parse: fromNpmrc }, { path: join(dir, '.yarnrc.yml'), parse: fromYarnrcYml }, { path: join(dir, '.yarnrc'), parse: fromYarnrc }, { path: join(dir, 'bunfig.toml'), parse: fromBunfig });
    }
    // Yarn Berry reads `.yarnrc.yml` in EVERY ancestor up to the filesystem
    // root — past the repository root and the home directory (follow-up Part Y).
    const top = near[near.length - 1];
    if (top !== undefined) {
        for (let dir = dirname(top), i = 0; i < 64; dir = dirname(dir), i += 1) {
            files.push({ path: join(dir, '.yarnrc.yml'), parse: fromYarnrcYml });
            if (dirname(dir) === dir)
                break;
        }
    }
    const xdg = envValue(env, 'XDG_CONFIG_HOME') ?? join(home, '.config');
    const localAppData = envValue(env, 'LOCALAPPDATA') ?? join(home, 'AppData', 'Local');
    files.push({ path: envValue(env, 'NPM_CONFIG_USERCONFIG') ?? join(home, '.npmrc'), parse: fromNpmrc }, { path: join(home, '.yarnrc.yml'), parse: fromYarnrcYml }, { path: join(home, '.yarnrc'), parse: fromYarnrc }, { path: join(home, '.bunfig.toml'), parse: fromBunfig }, { path: join(xdg, '.bunfig.toml'), parse: fromBunfig }, { path: join(xdg, 'pnpm', 'rc'), parse: fromNpmrc }, { path: join(localAppData, 'pnpm', 'config', 'rc'), parse: fromNpmrc }, { path: join(home, 'Library', 'Preferences', 'pnpm', 'rc'), parse: fromNpmrc });
    const globalConfig = envValue(env, 'NPM_CONFIG_GLOBALCONFIG');
    if (globalConfig !== undefined)
        files.push({ path: globalConfig, parse: fromNpmrc });
    // npm's DEFAULT global npmrc, read even when nothing names it:
    // `<prefix>/etc/npmrc`, the prefix being `%APPDATA%\npm` on Windows and the
    // node installation's prefix (`<prefix>/bin/node`) elsewhere — or
    // `npm_config_prefix` when set.
    const prefix = envValue(env, 'NPM_CONFIG_PREFIX') ??
        ((ctx.platform ?? process.platform) === 'win32'
            ? join(envValue(env, 'APPDATA') ?? join(home, 'AppData', 'Roaming'), 'npm')
            : dirname(dirname(ctx.nodeExecPath ?? process.execPath)));
    files.push({ path: join(prefix, 'etc', 'npmrc'), parse: fromNpmrc });
    return files;
}
/**
 * Environment variables that point a package manager at a registry, matched
 * case-insensitively on the name. The first whose value is not the public
 * registry (or is not a URL at all — `UV_INDEX_STRATEGY`) counts.
 * `*NO_INDEX*` counts only when truthy. For NuGet, only a variable that names
 * a source, a feed or a configuration file (`NUGET_*SOURCE*`, `NUGET_*FEED*`,
 * `NUGET_*CONFIG*`) or a source's credentials
 * (`NuGetPackageSourceCredentials_<name>`): `NUGET_PACKAGES` (the package
 * cache) or `NUGET_XMLDOC_MODE` explain nothing (follow-up Part Y).
 */
const ENV_REGISTRY = {
    npm: /^(?:YARN_NPM_REGISTRY_SERVER|YARN_REGISTRY|BUN_CONFIG_REGISTRY|npm_config_.*registry.*)$/i,
    pypi: /^(?:(?:PIP|UV)_.*INDEX.*|PIP_FIND_LINKS|UV_FIND_LINKS)$/i,
    packagist: /^$/,
    nuget: /^(?:NUGET_\w*(?:SOURCE|FEED|CONFIG)\w*|NUGET_FALLBACK_PACKAGES|NuGetPackageSourceCredentials_.+)$/i,
};
function envRegistry(ecosystem, ctx) {
    for (const [key, raw] of Object.entries(envOf(ctx))) {
        if (raw === undefined || raw.trim() === '' || !ENV_REGISTRY[ecosystem].test(key))
            continue;
        const value = raw.trim();
        if (/NO_INDEX/i.test(key)) {
            if (/^(?:1|true|yes|on)$/i.test(value))
                return { kind: 'registry', source: key };
            continue;
        }
        if (value.split(/\s+/).some((u) => !isPublic(ecosystem, u.replace(/^[^=]+=(?=https?:)/, '')))) {
            return { kind: 'registry', source: key, url: value };
        }
    }
    return null;
}
function npmRegistry(name, ctx) {
    const scope = npmScope(name);
    const fromEnv = envRegistry('npm', ctx);
    if (fromEnv !== null)
        return fromEnv;
    let authSource;
    for (const { path, parse } of npmConfigFiles(ctx)) {
        const text = read(path, ctx);
        if (text === undefined)
            continue;
        const url = parse(text, scope);
        if (url !== undefined && !isPublic('npm', url))
            return { kind: 'registry', source: path, url };
        if (authSource === undefined && NPM_AUTH.test(text))
            authSource = path;
    }
    // Ruling (e): a private SCOPED package on npmjs answers 404 to an
    // anonymous request, so with credentials configured a scoped 404 proves
    // nothing. npmjs has no private unscoped packages.
    if (scope !== undefined && authSource !== undefined)
        return { kind: 'auth', source: authSource };
    const local = npmWorkspacePackage(name, ctx);
    return local === undefined ? null : { kind: 'workspace', source: local };
}
// ─────────────────────────────────────────────────────── workspaces
const SKIP_DIRS = new Set(['node_modules', '.git', '.venv', 'venv', '__pycache__', 'vendor', 'dist', 'build', 'target']);
const MAX_SCAN_DIRS = 3000;
const MAX_SCAN_DEPTH = 5;
/**
 * Every `file` under `root` (depth-limited, never into node_modules,
 * vendor, virtualenvs or dot-directories), for which `match` returns true.
 * Glob patterns in the workspace declaration are deliberately NOT
 * interpreted: any manifest under a workspace root with the name counts as
 * local — a false "local" only turns a deny into a warning.
 */
function findManifest(root, file, match, ctx) {
    const queue = [{ dir: root, depth: 0 }];
    let visited = 0;
    while (queue.length > 0 && visited < MAX_SCAN_DIRS) {
        const next = queue.shift();
        if (next === undefined)
            break;
        visited += 1;
        const manifest = join(next.dir, file);
        const text = read(manifest, ctx, root);
        if (text !== undefined && match(text))
            return manifest;
        if (next.depth >= MAX_SCAN_DEPTH)
            continue;
        let entries = [];
        try {
            entries = readdirSync(next.dir, { withFileTypes: true })
                .filter((e) => e.isDirectory() && !e.name.startsWith('.') && !SKIP_DIRS.has(e.name))
                .map((e) => e.name);
        }
        catch {
            continue;
        }
        for (const e of entries)
            queue.push({ dir: join(next.dir, e), depth: next.depth + 1 });
    }
    return undefined;
}
function hasWorkspaces(packageJson) {
    if (packageJson === undefined)
        return false;
    try {
        const w = JSON.parse(packageJson).workspaces;
        if (Array.isArray(w))
            return w.length > 0;
        return w !== null && typeof w === 'object' && Array.isArray(w.packages);
    }
    catch {
        return false;
    }
}
/** Ruling (f), npm/pnpm/yarn/bun: a package.json named `name` under a workspace root. */
function npmWorkspacePackage(name, ctx) {
    for (const dir of ancestors(ctx)) {
        const isRoot = hasWorkspaces(read(join(dir, 'package.json'), ctx)) || present(join(dir, 'pnpm-workspace.yaml'));
        if (!isRoot)
            continue;
        const hit = findManifest(dir, 'package.json', (text) => {
            try {
                return JSON.parse(text).name === name;
            }
            catch {
                return false;
            }
        }, ctx);
        if (hit !== undefined)
            return hit;
    }
    return undefined;
}
const pep503 = (n) => n.trim().toLowerCase().replace(/[-_.]+/g, '-');
/** Ruling (f), uv: a `[tool.uv.workspace]` member named `name`, or a `[tool.uv.sources]` entry for it. */
function uvWorkspacePackage(name, ctx) {
    const wanted = pep503(name);
    for (const dir of ancestors(ctx)) {
        const path = join(dir, 'pyproject.toml');
        const text = read(path, ctx);
        if (text === undefined)
            continue;
        const sources = /^\s*\[tool\.uv\.sources\]\s*$([\s\S]*?)(?=^\s*\[|(?![\s\S]))/m.exec(text)?.[1] ?? '';
        for (const m of sources.matchAll(/^\s*["']?([A-Za-z0-9._-]+)["']?\s*=/gm)) {
            if (pep503(m[1] ?? '') === wanted)
                return path;
        }
        if (!/^\s*\[tool\.uv\.workspace\]/m.test(text))
            continue;
        const hit = findManifest(dir, 'pyproject.toml', (t) => {
            const project = /^\s*\[project\]\s*$([\s\S]*?)(?=^\s*\[|(?![\s\S]))/m.exec(t)?.[1] ?? '';
            const n = /^\s*name\s*=\s*["']([^"']+)["']/m.exec(project)?.[1];
            return n !== undefined && pep503(n) === wanted;
        }, ctx);
        if (hit !== undefined)
            return hit;
    }
    return undefined;
}
// ────────────────────────────────────────────────────────────── PyPI
/** `index-url`, `extra-index-url`, `find-links` (any spelling) or `no-index` in a pip config file. */
function fromPipConf(text) {
    for (const raw of text.split(/\r?\n/)) {
        const m = /^\s*(index[-_]url|extra[-_]index[-_]url|find[-_]links)\s*[=:]\s*(\S+)/i.exec(raw);
        if (m !== null && !isPublic('pypi', m[2] ?? ''))
            return m[2];
        if (/^\s*no[-_]index\s*[=:]\s*(?:true|1|yes|on)\s*$/i.test(raw))
            return 'no-index';
    }
    return undefined;
}
function fromPyproject(text) {
    if (/^\s*\[\[\s*tool\.(?:uv\.index|poetry\.source|pdm\.source)\s*\]\]/m.test(text)) {
        return /https?:\/\/[^"'\s]+/.exec(text.slice(text.search(/\[\[\s*tool\.(?:uv\.index|poetry\.source|pdm\.source)/)))?.[0] ?? '(configured)';
    }
    const uv = /^\s*\[tool\.uv\]\s*$([\s\S]*?)(?=^\s*\[|(?![\s\S]))/m.exec(text);
    if (uv !== null) {
        const m = /^\s*(?:index-url|extra-index-url|find-links)\s*=\s*["']?([^"'\s\]]+)/m.exec(uv[1] ?? '');
        if (m !== null && !isPublic('pypi', m[1] ?? ''))
            return m[1];
    }
    return undefined;
}
function fromUvToml(text) {
    if (/^\s*\[\[\s*index\s*\]\]/m.test(text))
        return /https?:\/\/[^"'\s]+/.exec(text)?.[0] ?? '(configured)';
    const m = /^\s*(?:index-url|extra-index-url|find-links)\s*=\s*["']?([^"'\s\]]+)/m.exec(text);
    if (m !== null && !isPublic('pypi', m[1] ?? ''))
        return m[1];
    return undefined;
}
function pypiRegistry(name, ctx) {
    const env = envOf(ctx);
    const fromEnv = envRegistry('pypi', ctx);
    if (fromEnv !== null)
        return fromEnv;
    // pip: explicit file, user (XDG, ~/.pip, %APPDATA%), venv, and global
    // (/etc/pip.conf, /etc/xdg/pip/pip.conf and XDG_CONFIG_DIRS, %ProgramData%).
    const home = homeOf(ctx);
    const etc = ctx.etcDir ?? '/etc';
    const confs = [];
    const explicit = envValue(env, 'PIP_CONFIG_FILE');
    if (explicit !== undefined)
        confs.push(explicit);
    const xdg = envValue(env, 'XDG_CONFIG_HOME') ?? join(home, '.config');
    confs.push(join(xdg, 'pip', 'pip.conf'), join(home, '.pip', 'pip.conf'), join(home, 'Library', 'Application Support', 'pip', 'pip.conf'));
    const appdata = envValue(env, 'APPDATA') ?? join(home, 'AppData', 'Roaming');
    confs.push(join(appdata, 'pip', 'pip.ini'), join(home, 'pip', 'pip.ini'));
    // pip's "site" configuration lives in the environment's prefix: a venv's,
    // or a conda environment's (`$CONDA_PREFIX`).
    for (const prefix of [envValue(env, 'VIRTUAL_ENV'), envValue(env, 'CONDA_PREFIX')]) {
        if (prefix !== undefined)
            confs.push(join(prefix, 'pip.conf'), join(prefix, 'pip.ini'));
    }
    confs.push(join(etc, 'pip.conf'), join(etc, 'xdg', 'pip', 'pip.conf'));
    confs.push(join(ctx.systemLibraryDir ?? '/Library', 'Application Support', 'pip', 'pip.conf'));
    for (const d of (envValue(env, 'XDG_CONFIG_DIRS') ?? '').split(':').filter(Boolean))
        confs.push(join(d, 'pip', 'pip.conf'));
    const programData = envValue(env, 'ProgramData') ?? envValue(env, 'PROGRAMDATA');
    if (programData !== undefined)
        confs.push(join(programData, 'pip', 'pip.ini'));
    for (const path of confs) {
        const text = read(path, ctx);
        const url = text === undefined ? undefined : fromPipConf(text);
        if (url !== undefined)
            return { kind: 'registry', source: path, url };
    }
    // uv: UV_CONFIG_FILE, user (XDG / %APPDATA%) and system uv.toml.
    const uvConfs = [];
    const uvExplicit = envValue(env, 'UV_CONFIG_FILE');
    if (uvExplicit !== undefined)
        uvConfs.push(uvExplicit);
    uvConfs.push(join(xdg, 'uv', 'uv.toml'), join(appdata, 'uv', 'uv.toml'), join(etc, 'uv', 'uv.toml'));
    for (const path of uvConfs) {
        const text = read(path, ctx);
        const url = text === undefined ? undefined : fromUvToml(text);
        if (url !== undefined)
            return { kind: 'registry', source: path, url };
    }
    for (const dir of ancestors(ctx)) {
        const uvToml = join(dir, 'uv.toml');
        const uvText = read(uvToml, ctx);
        const uvUrl = uvText === undefined ? undefined : fromUvToml(uvText);
        if (uvUrl !== undefined)
            return { kind: 'registry', source: uvToml, url: uvUrl };
        const pyproject = join(dir, 'pyproject.toml');
        const text = read(pyproject, ctx);
        if (text === undefined)
            continue;
        const url = fromPyproject(text);
        if (url !== undefined)
            return { kind: 'registry', source: pyproject, url };
        break; // the nearest pyproject.toml is the project; its parents are not
    }
    const local = uvWorkspacePackage(name, ctx);
    return local === undefined ? null : { kind: 'workspace', source: local };
}
// ────────────────────────────────────────────────────────── Composer
function hasRepositories(text) {
    if (text === undefined)
        return false;
    try {
        const doc = JSON.parse(text);
        const r = doc.repositories;
        if (Array.isArray(r))
            return r.length > 0;
        return r !== null && typeof r === 'object' && Object.keys(r).length > 0;
    }
    catch {
        return false;
    }
}
function composerRegistry(ctx) {
    for (const dir of ancestors(ctx)) {
        const path = join(dir, 'composer.json');
        const text = read(path, ctx);
        if (text === undefined)
            continue;
        if (hasRepositories(text))
            return { kind: 'registry', source: path };
        break;
    }
    const env = envOf(ctx);
    const home = homeOf(ctx);
    const composerHome = envValue(env, 'COMPOSER_HOME');
    const globals = composerHome !== undefined
        ? [join(composerHome, 'config.json')]
        : [join(home, '.composer', 'config.json'), join(home, '.config', 'composer', 'config.json'), join(envValue(env, 'APPDATA') ?? join(home, 'AppData', 'Roaming'), 'Composer', 'config.json')];
    for (const path of globals)
        if (hasRepositories(read(path, ctx)))
            return { kind: 'registry', source: path };
    return null;
}
// ───────────────────────────────────────────────────────────── NuGet
function nugetConfigIn(dir, ctx) {
    const hit = listDir(dir, ctx).find((f) => f.toLowerCase() === 'nuget.config');
    return hit === undefined ? undefined : join(dir, hit);
}
/** Every package source in a NuGet config that is not nuget.org. */
function customNugetSources(text) {
    const sources = /<packageSources>([\s\S]*?)<\/packageSources>/i.exec(text)?.[1] ?? '';
    const out = [];
    for (const m of sources.matchAll(/<add\b[^>]*\bvalue\s*=\s*"([^"]+)"/gi)) {
        const url = m[1] ?? '';
        if (url !== '' && !isPublic('nuget', url))
            out.push(url);
    }
    return out;
}
/** A source that is a folder on this machine: not a URL, not a UNC share. */
function isLocalFolderSource(source) {
    return !/^[a-z][a-z0-9+.-]*:\/\//i.test(source) && !/^[\\/]{2}/.test(source);
}
/**
 * Whether a local folder feed holds `id` — flat (`<id>.<version>.nupkg`) or
 * hierarchical (`<id>/`), any casing. `%VAR%` in the folder is expanded, and
 * a relative folder is taken from the config file's directory.
 */
function localFeedHas(folder, configPath, id, ctx) {
    const env = envOf(ctx);
    const expanded = folder.replace(/%([^%]+)%/g, (whole, name) => envValue(env, name) ?? whole);
    // A config written on Windows (`…\NuGetPackages\`) names the same folder
    // on Linux and macOS, where NuGet reads its backslashes as separators.
    const portable = (ctx.platform ?? process.platform) === 'win32' ? expanded : expanded.replace(/\\/g, '/');
    const dir = resolve(dirname(configPath), portable.replace(/[\\/]+$/, ''));
    const lower = id.toLowerCase();
    return listDir(dir, ctx).some((entry) => {
        const e = entry.toLowerCase();
        return e === lower || (e.startsWith(`${lower}.`) && e.endsWith('.nupkg') && /^\d/.test(e.slice(lower.length + 1)));
    });
}
function nugetRegistry(name, ctx) {
    const fromEnv = envRegistry('nuget', ctx);
    if (fromEnv !== null)
        return fromEnv;
    // NuGet reads every nuget.config from the project up to the filesystem
    // root — past `.git` and past the home directory — so this walk does too.
    const files = [];
    if (ctx.projectDir !== undefined) {
        let dir = resolve(ctx.projectDir);
        for (let i = 0; i < 64; i += 1) {
            const f = nugetConfigIn(dir, ctx);
            if (f !== undefined)
                files.push(f);
            const parent = dirname(dir);
            if (parent === dir)
                break;
            dir = parent;
        }
    }
    const env = envOf(ctx);
    const home = homeOf(ctx);
    const appdata = envValue(env, 'APPDATA') ?? join(home, 'AppData', 'Roaming');
    for (const dir of [join(appdata, 'NuGet'), join(home, '.nuget', 'NuGet'), join(home, '.config', 'NuGet')]) {
        const f = nugetConfigIn(dir, ctx);
        if (f !== undefined)
            files.push(f);
    }
    // Every `*.config` in the additional user-wide directories and the
    // machine-wide ones, as NuGet reads them (follow-up Part Y).
    const userDirs = [join(appdata, 'NuGet', 'config'), join(home, '.nuget', 'config'), join(home, '.config', 'NuGet', 'config')];
    const machineDirs = [
        join(ctx.etcDir ?? '/etc', 'opt', 'NuGet', 'Config'),
        join(ctx.systemLibraryDir ?? '/Library', 'Application Support', 'NuGet', 'Config'),
    ];
    const programFilesX86 = envValue(env, 'ProgramFiles(x86)');
    if (programFilesX86 !== undefined)
        machineDirs.push(join(programFilesX86, 'NuGet', 'Config'));
    const machineWide = new Set();
    for (const dir of [...userDirs, ...machineDirs]) {
        for (const f of listDir(dir, ctx).filter((e) => /\.config$/i.test(e)).sort()) {
            files.push(join(dir, f));
            if (machineDirs.includes(dir))
                machineWide.add(join(dir, f));
        }
    }
    for (const path of files) {
        const text = read(path, ctx);
        if (text === undefined)
            continue;
        for (const url of customNugetSources(text)) {
            // A machine-wide config's LOCAL folder — Visual Studio's
            // Microsoft.VisualStudio.Offline.config is one on every VS machine —
            // explains a 404 only for a package it holds (fix round 1, M2).
            if (machineWide.has(path) && isLocalFolderSource(url) && !localFeedHas(url, path, name, ctx))
                continue;
            return { kind: 'registry', source: path, url };
        }
    }
    return null;
}
/**
 * The custom registry that would serve `name`, or `null` when only the
 * public registry is configured.
 */
export function customRegistryFor(ecosystem, name, ctx = {}) {
    firstUnread = undefined;
    let found;
    try {
        switch (ecosystem) {
            case 'npm':
                found = npmRegistry(name, ctx);
                break;
            case 'pypi':
                found = pypiRegistry(name, ctx);
                break;
            case 'packagist':
                found = composerRegistry(ctx);
                break;
            case 'nuget':
                found = nugetRegistry(name, ctx);
                break;
            default:
                found = null;
        }
    }
    catch {
        found = null;
    }
    // Nothing explains the 404 — unless a configuration that is there could not
    // be read: it may name a private registry (Part Y fix round 1).
    const unread = firstUnread;
    firstUnread = undefined;
    return found === null && unread !== undefined ? { kind: 'unreadable', source: unread } : found;
}
//# sourceMappingURL=privateRegistry.js.map