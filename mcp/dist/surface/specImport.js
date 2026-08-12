/**
 * Parse one OpenAPI 3.x or Swagger 2.0 document into RouteRecords.
 *
 * Pure: the caller supplies the text. Never throws — a malformed document is a
 * report with `status: 'parse_error'`, because one bad spec in a repository
 * must not cost the diff of the good ones.
 *
 * The document is parsed at most once. `JSON.parse` is tried first (a spec
 * file may well be `.json`); only on failure does the module fall back to
 * `yaml`'s `parseDocument`, which also accepts JSON — it's a YAML subset —
 * but that path is the only one that carries source positions, which is why
 * `line` is `0` for every route pulled from a JSON document (see `parseRoot`).
 */
import { isMap, isScalar, parseDocument } from 'yaml';
const OPERATION_KEYS = [
    'get', 'put', 'post', 'delete', 'options', 'head', 'patch', 'trace',
];
/** Pure: `text` is the document, `file` is only used to label the output. */
export function importSpec(file, text) {
    const parsed = parseRoot(text);
    if (parsed.kind === 'parse_error') {
        return {
            routes: [],
            report: {
                file,
                format: 'unknown',
                status: 'parse_error',
                routes_found: 0,
                reason: parsed.reason,
                unresolved_refs: 0,
            },
        };
    }
    const { root, lineFor } = parsed;
    const format = detectFormat(root);
    if (format === 'unknown') {
        return {
            routes: [],
            report: {
                file,
                format,
                status: 'unsupported_version',
                routes_found: 0,
                reason: 'No supported "openapi" (3.x) or "swagger" (2.0) version field found.',
                unresolved_refs: 0,
            },
        };
    }
    const pathsRaw = prop(root, 'paths');
    const pathEntries = Object.entries(isPlainObject(pathsRaw) ? pathsRaw : {});
    if (pathEntries.length === 0) {
        return {
            routes: [],
            report: {
                file,
                format,
                status: 'no_paths',
                routes_found: 0,
                reason: 'The document declares no paths.',
                unresolved_refs: 0,
            },
        };
    }
    const { base, partial: basePartial } = format === 'openapi-3' ? openapiBasePath(root) : swaggerBasePath(root);
    const docSecurityRaw = prop(root, 'security');
    const docSecurityNonEmpty = Array.isArray(docSecurityRaw) && docSecurityRaw.length > 0;
    const routes = [];
    let unresolvedRefs = 0;
    for (const [pathTemplate, pathItem] of pathEntries) {
        // A path item that is itself a `$ref` (whole-item reference, distinct
        // from a `$ref` inside a `parameters` entry) is only ever resolvable when
        // this module has the referenced file to hand — and it never does; it
        // reads text, not a filesystem. Counting it (rather than silently
        // skipping it) is the whole point of `unresolved_refs`: a path item that
        // vanished with no trace would read as "the spec never declared this",
        // which is false. Internal path-item refs (`#/...`) get the same
        // treatment as external ones — this module resolves internal `$ref`s for
        // *parameters* only, never for a whole path item, so an internal
        // path-item ref is exactly as unresolved as an external one.
        if (str(pathItem, '$ref') !== undefined) {
            unresolvedRefs += 1;
            continue;
        }
        const line = lineFor(pathTemplate);
        const templateParams = paramsFromTemplate(pathTemplate);
        const pathItemParams = paramNamesInPath(root, prop(pathItem, 'parameters'));
        for (const opKey of OPERATION_KEYS) {
            const operation = prop(pathItem, opKey);
            if (operation === undefined)
                continue;
            const opParams = paramNamesInPath(root, prop(operation, 'parameters'));
            const params = [...new Set([...templateParams, ...pathItemParams, ...opParams])];
            routes.push({
                method: operationMethod(opKey),
                provenance: 'spec',
                path_raw: pathTemplate,
                path_resolved: basePartial ? pathTemplate : `${base}${pathTemplate}`,
                path_partial: basePartial,
                file,
                line,
                framework: format,
                language: 'spec',
                auth_hint: authHint(prop(operation, 'security'), docSecurityNonEmpty),
                params,
                confidence: 'high',
            });
        }
    }
    return {
        routes,
        report: {
            file,
            format,
            status: 'ok',
            routes_found: routes.length,
            unresolved_refs: unresolvedRefs,
        },
    };
}
/**
 * `parseDocument` does NOT throw on malformed YAML — it returns a `Document`
 * with a populated `errors` array, so a `try/catch` around it alone would
 * catch nothing and a corrupt file would sail through as an empty spec.
 * `doc.errors.length > 0` is the actual signal.
 */
function parseRoot(text) {
    try {
        return { kind: 'ok', root: JSON.parse(text), lineFor: () => 0 };
    }
    catch {
        // Not JSON — fall through to the YAML parser below.
    }
    const doc = parseDocument(text);
    if (doc.errors.length > 0) {
        return { kind: 'parse_error', reason: doc.errors[0]?.message ?? 'YAML parse error' };
    }
    // `doc.getIn(['paths', p], true)` returns the path item's VALUE node, whose
    // range starts at its first operation — a key on source line 7 would
    // compute to line 8. Reading `item.key.range` off each entry in the
    // `paths` map instead gives the key's own line. `doc.get(..., true)` walks
    // the AST without resolving aliases, so this loop is safe even when
    // `paths` (or something inside it) is itself an unresolved alias.
    const lineByPath = new Map();
    const pathsNode = doc.get('paths', true);
    if (isMap(pathsNode)) {
        for (const item of pathsNode.items) {
            const key = item.key;
            if (!isScalar(key) || typeof key.value !== 'string')
                continue;
            const range = key.range;
            if (range == null)
                continue;
            lineByPath.set(key.value, text.slice(0, range[0]).split('\n').length);
        }
    }
    // `doc.errors` only reports SYNTAX problems. `yaml` resolves aliases
    // lazily, so a reference to an anchor that doesn't exist — or an
    // alias-expansion bomb — is not a parse error: `doc.errors` stays empty,
    // and the throw (a `ReferenceError`) happens only here, inside `toJS()`,
    // when the document is actually materialised. The comment on
    // `parseDocument` above is true and answers a different question — this
    // is the guard that keeps the "never throws" promise at the top of this
    // file.
    try {
        return {
            kind: 'ok',
            root: doc.toJS(),
            lineFor: (pathKey) => lineByPath.get(pathKey) ?? 0,
        };
    }
    catch (err) {
        return { kind: 'parse_error', reason: err instanceof Error ? err.message : String(err) };
    }
}
/* ---- version + base path -------------------------------------------------
 *
 * A server/basePath URL "may be templated or relative": `{` makes the base
 * genuinely unknown (a templated host, e.g. `https://{env}.example.com/v2`),
 * so that check runs BEFORE `new URL` ever sees the string. A URL with no
 * `{` that `new URL` still rejects is relative in one of several distinct
 * RFC 3986 senses, only one of which is unambiguous enough to use: an
 * absolute-path reference (a leading `/`, e.g. `/v1`) IS the base path,
 * legal OpenAPI with nothing else to resolve it against. Anything else —
 * a scheme-less `host/path` (`api.example.com/v1`, the Swagger 2 `host:`
 * habit — a common authoring slip, not a path), a bare host
 * (`api.example.com`), a protocol-relative reference (`//api.example.com/v1`)
 * or a bare relative-path segment (`v1`) — is not a path this module
 * understands, so the base stays unknown rather than guessing. Guessing
 * would silently turn a typo into `path_resolved: 'api.example.com/v1/x'`,
 * `path_partial: false`, `confidence: 'high'` — a claim that the path is
 * verified, which for a request-sending consumer is worse than admitting
 * ignorance.
 */
function detectFormat(root) {
    const openapi = str(root, 'openapi');
    if (openapi !== undefined && openapi.startsWith('3.'))
        return 'openapi-3';
    if (str(root, 'swagger') === '2.0')
        return 'swagger-2';
    return 'unknown';
}
function openapiBasePath(root) {
    const servers = asArray(prop(root, 'servers'));
    const url = str(servers[0], 'url');
    if (url === undefined)
        return { base: '', partial: false };
    if (url.includes('{'))
        return { base: '', partial: true };
    try {
        return { base: stripTrailingSlash(new URL(url).pathname), partial: false };
    }
    catch {
        if (isAbsolutePathReference(url))
            return { base: stripTrailingSlash(url), partial: false };
        return { base: '', partial: true };
    }
}
/**
 * An RFC 3986 absolute-path reference: a single leading `/` with no scheme
 * or authority — unambiguous enough to use as a base path directly. A
 * leading `//` is a distinct reference form (network-path / protocol-
 * relative, e.g. `//api.example.com/v1`) that names a *host*, not a path,
 * and must not be mistaken for one just because `.startsWith('/')` is true.
 */
function isAbsolutePathReference(url) {
    return url.startsWith('/') && !url.startsWith('//');
}
function swaggerBasePath(root) {
    const basePath = str(root, 'basePath') ?? '';
    if (basePath.includes('{'))
        return { base: '', partial: true };
    return { base: stripTrailingSlash(basePath), partial: false };
}
function stripTrailingSlash(value) {
    return value.endsWith('/') ? value.slice(0, -1) : value;
}
/* ---- per-operation fields -------------------------------------------------- */
/**
 * `trace` is a recognised OpenAPI/Swagger operation key but has no matching
 * member in `HttpMethod` — mapped to `'ANY'` rather than dropping the route.
 * Every other key in `OPERATION_KEYS`, upper-cased, is itself a valid
 * `HttpMethod` member.
 */
function operationMethod(key) {
    if (key === 'trace')
        return 'ANY';
    return key.toUpperCase();
}
/**
 * Order: an operation-level `security: []` is an affirmative "this route is
 * public" and wins outright; a non-empty operation-level `security` requires
 * auth; only when the operation says nothing at all does the document-level
 * default apply; and only when neither says anything is the answer unknown.
 */
function authHint(rawOperationSecurity, docSecurityNonEmpty) {
    if (Array.isArray(rawOperationSecurity)) {
        return rawOperationSecurity.length === 0 ? 'none' : 'required';
    }
    return docSecurityNonEmpty ? 'required' : 'unknown';
}
/** `{id}` / `{format}` segments in the path template itself. */
function paramsFromTemplate(pathTemplate) {
    const names = [];
    for (const match of pathTemplate.matchAll(/\{([^}]+)\}/g)) {
        const name = match[1]?.trim();
        if (name !== undefined && name.length > 0)
            names.push(name);
    }
    return names;
}
/**
 * Names from a `parameters` array (path-item- or operation-level) whose
 * `in` is `path`. Each entry may be inline or a `$ref`; `resolveRef` only
 * follows refs starting with `#`, so an external parameter ref resolves to
 * `undefined` and is silently skipped rather than guessed at.
 */
function paramNamesInPath(root, rawList) {
    const names = [];
    for (const entry of asArray(rawList)) {
        const ref = str(entry, '$ref');
        const resolved = ref !== undefined ? resolveRef(root, ref) : entry;
        if (str(resolved, 'in') !== 'path')
            continue;
        const name = str(resolved, 'name');
        if (name !== undefined)
            names.push(name);
    }
    return names;
}
/**
 * Internal-only `$ref` resolution: `#/components/parameters/X` (OpenAPI 3)
 * or `#/parameters/X` (Swagger 2). Anything not starting with `#` is an
 * external reference this module has no filesystem access to follow.
 */
function resolveRef(root, ref) {
    if (!ref.startsWith('#'))
        return undefined;
    let current = root;
    for (const segment of ref.slice(1).split('/')) {
        if (segment.length === 0)
            continue;
        current = prop(current, segment);
        if (current === undefined)
            return undefined;
    }
    return current;
}
/* ---- tiny structural accessors (kept local; mirrors extract.ts) ---------- */
function prop(value, key) {
    if (value === null || typeof value !== 'object')
        return undefined;
    return value[key];
}
function str(value, key) {
    const v = prop(value, key);
    return typeof v === 'string' ? v : undefined;
}
function asArray(value) {
    return Array.isArray(value) ? value : [];
}
function isPlainObject(value) {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
}
//# sourceMappingURL=specImport.js.map