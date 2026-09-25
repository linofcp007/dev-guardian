/**
 * Is a registry other than the public one configured for this package?
 *
 * The vetting DENIES a name the public registry has never heard of — that is
 * how a hallucinated dependency is caught before anyone squats it. But a
 * company's own packages are ALSO absent from the public registry, by
 * design. When a custom registry is configured for the name, "not on the
 * public registry" stops being evidence of anything, so the verdict becomes
 * `unknown` (with this file's answer as the reason) and never `block`.
 *
 * What counts, per ecosystem:
 *
 *   - npm / pnpm / yarn / bun: `registry=` (all names) or `@scope:registry=`
 *     (that scope) in a project or user `.npmrc`; `NPM_CONFIG_REGISTRY`;
 *     yarn's `.yarnrc.yml` `npmRegistryServer` (global or under
 *     `npmScopes.<scope>`) and classic `.yarnrc` `registry`; bun's
 *     `bunfig.toml` `[install] registry` / `[install.scopes]`.
 *   - pip / uv / poetry: `PIP_INDEX_URL`, `PIP_EXTRA_INDEX_URL`,
 *     `UV_INDEX_URL`, `UV_EXTRA_INDEX_URL`, `UV_INDEX`, `UV_DEFAULT_INDEX`,
 *     `PIP_FIND_LINKS`, `PIP_NO_INDEX`; `pip.conf` / `pip.ini` (user, venv
 *     and `PIP_CONFIG_FILE`); `[[tool.uv.index]]`, `[[tool.poetry.source]]`,
 *     `[[tool.pdm.source]]` or a `[tool.uv]` index URL in `pyproject.toml`;
 *     `uv.toml`.
 *   - Composer: a `repositories` entry in the project `composer.json` or the
 *     user's global `config.json`.
 *   - NuGet: any `nuget.config` (any casing) from the project up to the
 *     repository root, or the user-level one, with a package source that is
 *     not nuget.org.
 *
 * A configured value that IS the public registry (`registry.npmjs.org`,
 * `pypi.org/simple`, `api.nuget.org`) is not custom.
 *
 * Reads files only (node built-ins); never the network. Every read is
 * best-effort: an unreadable file is simply not evidence.
 */
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
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
function read(path) {
    try {
        return existsSync(path) ? readFileSync(path, 'utf8') : undefined;
    }
    catch {
        return undefined;
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
        if (existsSync(join(dir, '.git')))
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
function npmRegistry(name, ctx) {
    const scope = npmScope(name);
    const env = envOf(ctx);
    const candidates = [];
    for (const dir of ancestors(ctx)) {
        for (const [file, parse] of [
            ['.npmrc', fromNpmrc],
            ['.yarnrc.yml', fromYarnrcYml],
            ['.yarnrc', fromYarnrc],
            ['bunfig.toml', fromBunfig],
        ]) {
            const path = join(dir, file);
            const text = read(path);
            if (text !== undefined)
                candidates.push({ source: path, url: parse(text, scope) });
        }
    }
    const userConfig = envValue(env, 'NPM_CONFIG_USERCONFIG') ?? join(homeOf(ctx), '.npmrc');
    const userText = read(userConfig);
    if (userText !== undefined)
        candidates.push({ source: userConfig, url: fromNpmrc(userText, scope) });
    const envRegistry = envValue(env, 'NPM_CONFIG_REGISTRY');
    if (envRegistry !== undefined)
        candidates.unshift({ source: 'NPM_CONFIG_REGISTRY', url: envRegistry });
    for (const c of candidates) {
        if (c.url !== undefined && !isPublic('npm', c.url))
            return { source: c.source, url: c.url };
    }
    return null;
}
// ────────────────────────────────────────────────────────────── PyPI
const PY_ENV = ['PIP_INDEX_URL', 'PIP_EXTRA_INDEX_URL', 'UV_INDEX_URL', 'UV_EXTRA_INDEX_URL', 'UV_INDEX', 'UV_DEFAULT_INDEX', 'PIP_FIND_LINKS', 'UV_FIND_LINKS'];
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
function pypiRegistry(ctx) {
    const env = envOf(ctx);
    for (const name of PY_ENV) {
        const v = envValue(env, name);
        if (v === undefined)
            continue;
        if (v.split(/\s+/).some((u) => !isPublic('pypi', u)))
            return { source: name, url: v };
    }
    const noIndex = envValue(env, 'PIP_NO_INDEX');
    if (noIndex !== undefined && /^(?:1|true|yes|on)$/i.test(noIndex))
        return { source: 'PIP_NO_INDEX' };
    const home = homeOf(ctx);
    const confs = [];
    const explicit = envValue(env, 'PIP_CONFIG_FILE');
    if (explicit !== undefined)
        confs.push(explicit);
    const xdg = envValue(env, 'XDG_CONFIG_HOME') ?? join(home, '.config');
    confs.push(join(xdg, 'pip', 'pip.conf'), join(home, '.pip', 'pip.conf'));
    const appdata = envValue(env, 'APPDATA') ?? join(home, 'AppData', 'Roaming');
    confs.push(join(appdata, 'pip', 'pip.ini'), join(home, 'pip', 'pip.ini'));
    const venv = envValue(env, 'VIRTUAL_ENV');
    if (venv !== undefined)
        confs.push(join(venv, 'pip.conf'), join(venv, 'pip.ini'));
    for (const path of confs) {
        const text = read(path);
        const url = text === undefined ? undefined : fromPipConf(text);
        if (url !== undefined)
            return { source: path, url };
    }
    for (const dir of ancestors(ctx)) {
        const uvToml = join(dir, 'uv.toml');
        const uvText = read(uvToml);
        const uvUrl = uvText === undefined ? undefined : fromUvToml(uvText);
        if (uvUrl !== undefined)
            return { source: uvToml, url: uvUrl };
        const pyproject = join(dir, 'pyproject.toml');
        const text = read(pyproject);
        if (text === undefined)
            continue;
        const url = fromPyproject(text);
        if (url !== undefined)
            return { source: pyproject, url };
        break; // the nearest pyproject.toml is the project; its parents are not
    }
    return null;
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
        const text = read(path);
        if (text === undefined)
            continue;
        if (hasRepositories(text))
            return { source: path };
        break;
    }
    const env = envOf(ctx);
    const home = homeOf(ctx);
    const composerHome = envValue(env, 'COMPOSER_HOME');
    const globals = composerHome !== undefined
        ? [join(composerHome, 'config.json')]
        : [join(home, '.composer', 'config.json'), join(home, '.config', 'composer', 'config.json'), join(envValue(env, 'APPDATA') ?? join(home, 'AppData', 'Roaming'), 'Composer', 'config.json')];
    for (const path of globals)
        if (hasRepositories(read(path)))
            return { source: path };
    return null;
}
// ───────────────────────────────────────────────────────────── NuGet
function nugetConfigIn(dir) {
    try {
        const hit = readdirSync(dir).find((f) => f.toLowerCase() === 'nuget.config');
        return hit === undefined ? undefined : join(dir, hit);
    }
    catch {
        return undefined;
    }
}
function customNugetSource(text) {
    const sources = /<packageSources>([\s\S]*?)<\/packageSources>/i.exec(text)?.[1] ?? '';
    for (const m of sources.matchAll(/<add\b[^>]*\bvalue\s*=\s*"([^"]+)"/gi)) {
        const url = m[1] ?? '';
        if (url !== '' && !isPublic('nuget', url))
            return url;
    }
    return undefined;
}
function nugetRegistry(ctx) {
    const files = [];
    for (const dir of ancestors(ctx)) {
        const f = nugetConfigIn(dir);
        if (f !== undefined)
            files.push(f);
    }
    const env = envOf(ctx);
    const home = homeOf(ctx);
    const appdata = envValue(env, 'APPDATA') ?? join(home, 'AppData', 'Roaming');
    for (const dir of [join(appdata, 'NuGet'), join(home, '.nuget', 'NuGet'), join(home, '.config', 'NuGet')]) {
        const f = nugetConfigIn(dir);
        if (f !== undefined)
            files.push(f);
    }
    for (const path of files) {
        const text = read(path);
        const url = text === undefined ? undefined : customNugetSource(text);
        if (url !== undefined)
            return { source: path, url };
    }
    return null;
}
/**
 * The custom registry that would serve `name`, or `null` when only the
 * public registry is configured.
 */
export function customRegistryFor(ecosystem, name, ctx = {}) {
    try {
        switch (ecosystem) {
            case 'npm':
                return npmRegistry(name, ctx);
            case 'pypi':
                return pypiRegistry(ctx);
            case 'packagist':
                return composerRegistry(ctx);
            case 'nuget':
                return nugetRegistry(ctx);
            default:
                return null;
        }
    }
    catch {
        return null;
    }
}
//# sourceMappingURL=privateRegistry.js.map