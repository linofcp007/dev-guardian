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
/**
 * The file extensions (with the dot) of every language the routes pack has
 * rules for — what `map_attack_surface` counts as Semgrep's targets. A
 * project with none has nothing for the pack to read: not applicable, never
 * a gap.
 */
export const ROUTE_PACK_EXTENSIONS = Object.keys(EXTENSION_LANGUAGES).map((ext) => `.${ext}`);
export function languageFromPath(file) {
    const ext = file.split('.').pop()?.toLowerCase();
    if (ext === undefined)
        return 'unknown';
    return EXTENSION_LANGUAGES[ext] ?? 'unknown';
}
/* ---- the path-literal guard ----------------------------------------------
 *
 * A Semgrep metavariable binds whatever expression sits in the argument
 * position. `register_rest_route($NS, $ROUTE)` matches the literal
 * `register_rest_route('myplugin/v1', '/items')` and, just as happily,
 * `register_rest_route(self::NAMESPACE, $route)` — the dominant idiom in real
 * WordPress plugins. Only two rules in the pack pin their capture to a string
 * literal, and a rule added to the pack later need not pin anything either. So
 * the guard lives here, in the one place every route flows through, rather than
 * being replicated per rule in YAML: `toRoute` applies it unconditionally, so a
 * new rule in `configs/semgrep/routes.yml` is covered the moment it is written,
 * with nothing to opt into and nothing to remember.
 *
 * (It is not covering rules from anywhere else: `map_attack_surface` runs that
 * one file as its only `--config`. `register_custom_rules` never reaches this
 * pipeline — it records paths in `runtime_meta` for the SAST tools, and as of
 * today nothing reads them back, so it reaches no scan at all.)
 *
 * This matters because the next tool in this series sends HTTP requests to
 * whatever path it is handed: emitting `Paths.ORDERS` with
 * `path_partial: false` is worse than emitting nothing, because it reads as
 * a path we verified.
 *
 * The predicate is deliberately biased towards rejection. A false "partial"
 * costs a consumer one skipped probe; a false "resolved" costs it a request
 * to a path that never existed — and hides the one that does.
 */
/**
 * Sigils and operators that appear in source expressions and never in a URL
 * path: PHP/shell variables, PHP/Rust/C++ scope resolution, member arrows,
 * and any quote left over after `stripQuotes` (an interior quote means the
 * capture was a concatenation, not a single literal).
 */
const CODE_TOKENS = /[$`'"]|::|->|=>|\|\||&&/;
/**
 * A call or an index — `getPath(`, `routes[`. Anchored on an identifier
 * immediately before the bracket so it does not fire on a WordPress regex
 * route (`/items/(?P<id>\d+)`, where `(` follows a slash) or a Next.js-style
 * `/posts/[id]` a custom rule might produce.
 */
const CALL_OR_INDEX = /[A-Za-z_]\w*\s*[([]/;
/**
 * A bare relative route, i.e. one with no path punctuation at all:
 * `register_rest_route('ns/v1', 'items')` is valid WordPress. This is the
 * only genuinely ambiguous shape — `items` is a route, `routeVar` is a Go
 * variable, and nothing but convention separates them. We split on case:
 * URL path segments are lower-case by convention, while identifiers in every
 * language the pack covers are camelCase, PascalCase or SCREAMING_SNAKE. A
 * capital letter (or a dot, i.e. member access) in a bare word is our
 * evidence of code.
 */
const BARE_ROUTE = /^[a-z0-9][a-z0-9_~-]*$/;
/**
 * Characters that turn a captured "path" into something that resolves to a
 * DIFFERENT HOST once `dast/plan.ts#buildProbeUrl` (or any less careful
 * caller) combines it with `origin`: `@` reads as a URL userinfo separator
 * ahead of a host when concatenated naively; `\` is accepted by the WHATWG
 * URL algorithm as a path-separator synonym for `/` on http(s) URLs, so
 * `/\evil.example/x` resolves exactly like `//evil.example/x` does. Neither
 * can appear in a same-origin HTTP path, so either one ANYWHERE in the
 * capture is disqualifying — unlike `CODE_TOKENS`, which is about
 * recognising source syntax, this is about recognising a host-confusion
 * shape regardless of syntax. The one real route this costs is WordPress's
 * `(?P<id>\d+)` regex-group syntax (a backslash escape inside a `preg`
 * pattern) — accepted, per this module's own rule above: a false `partial`
 * costs one skipped probe, a false `resolved` costs a request to a host that
 * was never the target.
 */
const HOST_CONFUSION_CHARS = /[@\\]/;
/**
 * Leading shapes with the same host-confusion property, checked separately
 * from `HOST_CONFUSION_CHARS` because position (not mere presence) is what
 * makes them dangerous: a `.` or `/` elsewhere in a path is completely
 * ordinary (`/files/report.pdf`, `/a/b`). Only at the START does either turn
 * into a different reference kind — a relative reference against a foreign
 * base for a leading `.`, a network-path (protocol-relative) reference
 * naming a NEW HOST for a leading `//` — so this checks `startsWith`, never
 * `includes`.
 */
function hasUnsafeLeadingShape(value) {
    return value.startsWith('.') || value.startsWith('//');
}
/**
 * The syntactic half of `isLiteralPath` — "does this look like path syntax
 * rather than a source expression?" — WITHOUT the host-confusion checks.
 * Kept separate because `toRoute` below reads params (`extractParams`) out
 * of a capture that fails ONLY the host-confusion half: `(?P<id>\d+)` is not
 * safe to treat as a resolved URL (see `HOST_CONFUSION_CHARS`), but `id` is
 * still a real, knowable parameter name, and there is nothing unsafe about
 * reading it out. Gating params on THIS function rather than skipping the
 * gate entirely still matters — `extractParams`'s own `<([^>]+)>` branch
 * would misread a generic call like `foo<T>()` as a path carrying param `T`
 * if ever handed a bare code expression.
 */
function looksLikePathSyntax(value) {
    if (value.trim().length === 0)
        return false;
    // Whitespace inside a capture means an expression (`base + '/users'`,
    // `ns . $route`); no route literal we support contains one.
    if (/\s/.test(value))
        return false;
    if (CODE_TOKENS.test(value))
        return false;
    if (CALL_OR_INDEX.test(value))
        return false;
    // Path punctuation is the positive signal; everything else must survive the
    // bare-word test above.
    if (value.includes('/'))
        return true;
    return BARE_ROUTE.test(value);
}
/**
 * Can this captured value be read as a path SAFE to treat as a resolved
 * URL? When false the caller keeps the route — a route we cannot name is
 * still evidence of surface — but flags it `path_partial` and drops its
 * confidence to 'low'. `looksLikePathSyntax` alone is not enough here: a
 * value can look exactly like path syntax and still not be one this module
 * is willing to resolve (see `HOST_CONFUSION_CHARS`).
 */
export function isLiteralPath(value) {
    if (HOST_CONFUSION_CHARS.test(value))
        return false;
    if (hasUnsafeLeadingShape(value))
        return false;
    return looksLikePathSyntax(value);
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
/**
 * The metadata key a route rule sets to declare that its framework's
 * annotation carries NO path of its own, so there is no metavariable to
 * capture and none is bound: `@Get()`, `[HttpGet]`, `@GetMapping`. The served
 * path is entirely the class-level prefix (`@Controller('users')`,
 * `[Route("api/[controller]")]`, a class `@RequestMapping`), which no resolver
 * in this codebase can follow today — see the "annotation with no path of its
 * own" section of `configs/semgrep/routes.yml` for why a companion `mount`
 * rule would make that worse rather than better.
 *
 * Exported so `test/unit/surface/rulePack.test.ts` can hold the flag and the
 * rules in lock-step, the same way FOCUS_METADATA_KEY is: a route rule that
 * binds no path and does NOT declare this yields nothing at all — it matches
 * perfectly and `toRoute` drops it, which is exactly how three whole
 * annotation families went missing from the inventory without an error
 * anywhere.
 */
export const INHERITED_PATH_KEY = 'guardian_path';
export const INHERITED_PATH = 'inherited';
function toRoute(metadata, metavars, file, line) {
    // Namespaced frameworks (WordPress) capture $NS + $ROUTE instead of $PATH,
    // because Semgrep cannot concatenate metavariables into a third one. Keep
    // them as separate fields; the WP resolver composes the served path.
    const namespace = stripQuotes(metavar(metavars, '$NS'));
    const captured = stripQuotes(metavar(metavars, '$PATH') ?? metavar(metavars, '$ROUTE'));
    // An empty own-path, not a missing route. `isLiteralPath('')` is false, so
    // the record below comes out `path_partial: true` at 'low' confidence
    // through the ordinary path — the endpoint is inventoried and its full URL
    // is declared unknown, which is the truth. The alternative that was in
    // place until now is that the route does not exist.
    const path = captured ?? (str(metadata, INHERITED_PATH_KEY) === INHERITED_PATH ? '' : undefined);
    if (path === undefined)
        return null;
    // A capture that is code, not a path, is kept but never presented as
    // resolved: `path_resolved` stays the raw text so a human can still read
    // what the source said, and the low confidence tells a consumer why.
    // The namespace gets the same treatment — a `self::NAMESPACE` prefix
    // concatenated into `/wp-json/self::NAMESPACE/items` is a fabricated URL
    // (resolvers/wordpress.ts honours the flag rather than clearing it).
    const literalPath = isLiteralPath(path);
    const usable = literalPath && (namespace === undefined || isLiteralPath(namespace));
    // Syntactic only — see `looksLikePathSyntax`'s own doc comment for why
    // params are read out of a capture even when it fails `isLiteralPath` on
    // the host-confusion checks alone (`(?P<id>\d+)`, WordPress's regex-group
    // syntax): reading a parameter name builds no URL and carries none of that
    // risk.
    const parseableForParams = looksLikePathSyntax(path);
    const route = {
        method: normalizeMethod(metavar(metavars, '$METHOD') ?? str(metadata, 'method')),
        provenance: 'code',
        path_raw: path,
        path_resolved: path,
        path_partial: !usable,
        file,
        line,
        framework: str(metadata, 'framework') ?? 'unknown',
        language: languageFromPath(file),
        auth_hint: normalizeAuth(str(metadata, 'auth')),
        // Gated on syntax alone, not on `usable`: for
        // `register_rest_route(self::NAMESPACE, '/items/(?P<id>\d+)')` we cannot
        // say where the route is served, but `id` is knowable from the path, and
        // emitting [] would assert "this route takes no parameters".
        params: parseableForParams ? extractParams(path) : [],
        confidence: usable ? normalizeConfidence(str(metadata, 'confidence')) : 'low',
    };
    if (namespace !== undefined)
        route.namespace = namespace;
    return route;
}
/**
 * Semgrep's `abstract_content` keeps the source quoting, so a captured path
 * arrives as `'/users'` rather than `/users`.
 *
 * Only a MATCHED pair is stripped, and that is load-bearing rather than tidy.
 * An unbalanced quote means the capture is not a whole string literal — the
 * likeliest cause being a reported range that ends inside one. Stripping the
 * lone opening quote turned such a fragment into a clean-looking path:
 * `"/orders/secret` cut six bytes short became `/orders/s`, which
 * `isLiteralPath` accepts, so a truncated PREFIX was published as a resolved
 * URL at full confidence. Keeping the quote makes `CODE_TOKENS` reject it, so
 * the route survives as `path_partial` with the raw text visible.
 *
 * This is the one guard behind `recoverMetavars`'s focused branch, which
 * deliberately trusts Semgrep's range and does no validation of its own: it
 * converts the only shape where a bad range yields a WRONG path into one that
 * yields an incomplete one. Truncation is not hypothetical — a TypeScript
 * template literal has been observed arriving two bytes short of its closing
 * backtick.
 */
function stripQuotes(value) {
    if (value === undefined)
        return undefined;
    const quote = value[0];
    if (quote === undefined || !QUOTES.test(quote))
        return value;
    // `"` alone is an opening quote with nothing after it, not an empty literal.
    if (value.length < 2 || !value.endsWith(quote))
        return value;
    return value.slice(1, -1);
}
const QUOTES = /^['"`]$/;
function toMount(metavars, file, line) {
    const prefix = stripQuotes(metavar(metavars, '$PREFIX'));
    const routerVar = metavar(metavars, '$ROUTER');
    if (prefix === undefined || routerVar === undefined)
        return null;
    return { prefix, router_var: routerVar, file, line };
}
/**
 * ASP.NET minimal APIs spell the verb `MapGet` / `MapPost` — the rule's
 * `$METHOD` capture is the whole builder name, so a plain lower-case lookup
 * reports every minimal-API route as ANY. Only strip `Map` when what remains
 * is itself a verb, so `MapGroup` and a bare `map` still fall through.
 */
function normalizeMethod(raw) {
    if (raw === undefined)
        return 'ANY';
    const lowered = raw.toLowerCase();
    const unmapped = lowered.startsWith('map') ? lowered.slice(3) : lowered;
    const verb = METHOD_NAMES.has(unmapped) ? unmapped : lowered;
    if (!METHOD_NAMES.has(verb))
        return 'ANY';
    if (verb === 'all' || verb === 'any')
        return 'ANY';
    return verb.toUpperCase();
}
/**
 * No rule in `configs/semgrep/routes.yml` sets `metadata.auth` today, so this
 * always returns 'unknown' — deliberately, not by omission. A route rule
 * matches the registration site and cannot see whether the handler carries
 * `[Authorize]`, a `permission_callback`, or a middleware chain; inferring
 * 'none' from the absence of a decorator would be exactly the false
 * reassurance this tool exists to avoid. The parsing lives here so that a
 * rule which *can* prove it (an affirmative public declaration such as
 * WordPress `permission_callback: '__return_true'`) only has to add the key.
 */
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