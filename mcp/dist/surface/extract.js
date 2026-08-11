/**
 * Semgrep `--json` → attack-surface records.
 *
 * Pure: takes already-parsed JSON, returns records. No filesystem, no
 * process spawning — which is what lets the whole extraction path be tested
 * without Semgrep installed.
 *
 * Only matches carrying `metadata.guardian_kind` are considered, so running
 * this over output from another rule pack yields nothing rather than noise.
 * Malformed or partial metadata degrades to a lower-confidence record; it
 * never throws, because the rule pack is user-extensible.
 */
const METHOD_NAMES = new Set([
    'get', 'post', 'put', 'patch', 'delete', 'options', 'head', 'all', 'any',
]);
const EXTENSION_LANGUAGES = {
    ts: 'typescript', tsx: 'typescript', mts: 'typescript', cts: 'typescript',
    js: 'javascript', jsx: 'javascript', mjs: 'javascript', cjs: 'javascript',
    py: 'python',
    php: 'php',
    go: 'go',
    rs: 'rust',
    rb: 'ruby',
    java: 'java',
    cs: 'csharp',
};
export function languageFromPath(file) {
    const ext = file.split('.').pop()?.toLowerCase();
    if (ext === undefined)
        return 'unknown';
    return EXTENSION_LANGUAGES[ext] ?? 'unknown';
}
/**
 * Normalise every path-parameter syntax we support to a bare name:
 *   :id  ·  :id?  ·  {id}  ·  <int:item_id>  →  id / item_id
 */
export function extractParams(path) {
    const params = [];
    for (const match of path.matchAll(/:([A-Za-z_][\w]*)\??/g)) {
        const name = match[1];
        if (name !== undefined)
            params.push(name);
    }
    for (const match of path.matchAll(/\{([^}]+)\}/g)) {
        const inner = match[1];
        if (inner === undefined)
            continue;
        const name = inner.split(':').pop()?.trim();
        if (name !== undefined && name.length > 0)
            params.push(name);
    }
    for (const match of path.matchAll(/<([^>]+)>/g)) {
        const inner = match[1];
        if (inner === undefined)
            continue;
        const name = inner.split(':').pop()?.trim();
        if (name !== undefined && name.length > 0)
            params.push(name);
    }
    return [...new Set(params)];
}
export function extractSurface(semgrepJson) {
    const routes = [];
    const mounts = [];
    for (const raw of asArray(prop(semgrepJson, 'results'))) {
        const extra = prop(raw, 'extra');
        const metadata = prop(extra, 'metadata');
        const kind = str(metadata, 'guardian_kind');
        const file = str(raw, 'path');
        const line = num(prop(raw, 'start'), 'line') ?? 0;
        if (file === undefined)
            continue;
        if (kind === 'route') {
            const route = toRoute(metadata, prop(extra, 'metavars'), file, line);
            if (route)
                routes.push(route);
        }
        else if (kind === 'mount') {
            const mount = toMount(prop(extra, 'metavars'), file, line);
            if (mount)
                mounts.push(mount);
        }
    }
    return { routes, mounts };
}
function toRoute(metadata, metavars, file, line) {
    // Namespaced frameworks (WordPress) capture $NS + $ROUTE instead of $PATH,
    // because Semgrep cannot concatenate metavariables into a third one. Keep
    // them as separate fields; the WP resolver composes the served path.
    const namespace = stripQuotes(metavar(metavars, '$NS'));
    const path = stripQuotes(metavar(metavars, '$PATH') ?? metavar(metavars, '$ROUTE'));
    if (path === undefined)
        return null;
    const route = {
        method: normalizeMethod(metavar(metavars, '$METHOD') ?? str(metadata, 'method')),
        path_raw: path,
        path_resolved: path,
        path_partial: false,
        file,
        line,
        framework: str(metadata, 'framework') ?? 'unknown',
        language: languageFromPath(file),
        auth_hint: normalizeAuth(str(metadata, 'auth')),
        params: extractParams(path),
        confidence: normalizeConfidence(str(metadata, 'confidence')),
    };
    if (namespace !== undefined)
        route.namespace = namespace;
    return route;
}
/**
 * Semgrep's `abstract_content` keeps the source quoting, so a captured path
 * arrives as `'/users'` rather than `/users`.
 */
function stripQuotes(value) {
    if (value === undefined)
        return undefined;
    return value.replace(/^['"`]|['"`]$/g, '');
}
function toMount(metavars, file, line) {
    const prefix = stripQuotes(metavar(metavars, '$PREFIX'));
    const routerVar = metavar(metavars, '$ROUTER');
    if (prefix === undefined || routerVar === undefined)
        return null;
    return { prefix, router_var: routerVar, file, line };
}
function normalizeMethod(raw) {
    if (raw === undefined)
        return 'ANY';
    const lowered = raw.toLowerCase();
    if (!METHOD_NAMES.has(lowered))
        return 'ANY';
    if (lowered === 'all' || lowered === 'any')
        return 'ANY';
    return lowered.toUpperCase();
}
function normalizeAuth(raw) {
    if (raw === 'required' || raw === 'none')
        return raw;
    return 'unknown';
}
function normalizeConfidence(raw) {
    if (raw === 'high' || raw === 'medium' || raw === 'low')
        return raw;
    return 'low';
}
/* ---- tiny structural accessors (kept local; the parser helpers in
   runners/scannerParsers are Finding-shaped and would not fit) ---- */
function prop(value, key) {
    if (value === null || typeof value !== 'object')
        return undefined;
    return value[key];
}
function str(value, key) {
    const v = prop(value, key);
    return typeof v === 'string' ? v : undefined;
}
function num(value, key) {
    const v = prop(value, key);
    return typeof v === 'number' ? v : undefined;
}
function asArray(value) {
    return Array.isArray(value) ? value : [];
}
/** Semgrep nests captures as `metavars.$NAME.abstract_content`. */
function metavar(metavars, name) {
    return str(prop(metavars, name), 'abstract_content');
}
//# sourceMappingURL=extract.js.map