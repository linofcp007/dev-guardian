/**
 * Rebuild the Semgrep metavariables that modern Semgrep refuses to emit.
 *
 * Semgrep changed behaviour between 1.95.0 and 1.120.1: unless the user has
 * run `semgrep login`, match content is redacted — `extra.metavars` is absent
 * entirely and `extra.lines` reads "requires login". `surface/extract.ts`
 * reads `extra.metavars.$PATH.abstract_content`, so on any current Semgrep
 * install `map_attack_surface` extracts zero routes while Semgrep happily
 * reports matches: nothing looks broken, and the snapshot says the
 * application exposes nothing. Requiring an account is not an option —
 * dev-guardian is 100% open-source and runs locally.
 *
 * What survives redaction is the position: `start.offset` / `end.offset`.
 * Slicing the file between them yields the exact matched source text, from
 * which the captures can be reconstructed.
 *
 * Design: this module synthesizes into the *same shape the extractor already
 * reads* (`extra.metavars.$NAME.abstract_content`), so `extract.ts` — pure and
 * fully tested — needs no change at all. One new module, zero risk to code
 * that already passes.
 *
 * Pure: no filesystem, no process, no network. The caller supplies the source
 * text (see `tools/mapAttackSurface.ts`, which is already the impure layer).
 * It never throws: a file missing from the map, an offset past end-of-file, an
 * unparseable span all count as `unrecoverable` and the match is passed
 * through untouched.
 *
 * ---- Quoting is load-bearing -------------------------------------------
 *
 * Semgrep's `abstract_content` keeps the source quoting: a captured path
 * arrives as `'/items'`, while a computed one arrives as `self::NAMESPACE`.
 * That difference is precisely how `isLiteralPath` in `extract.ts` decides
 * whether a capture is a usable path or a code expression that must be flagged
 * `path_partial`. So every strategy below preserves the source quoting exactly
 * as it appears — adding a quote would fabricate a URL that exists nowhere,
 * stripping one would erase a route we can legitimately name.
 */
/**
 * The `guardian_kind`s we know how to reconstruct. A match carrying no
 * `guardian_kind`, or one we have no strategy for, is left alone and counted
 * in *none* of the three totals: `extract.ts` ignores those matches anyway, so
 * calling them "unrecoverable" would manufacture a broken-toolchain signal out
 * of a rule pack that simply contains other rules.
 */
const RECOVERABLE_KINDS = new Set(['route', 'mount', 'import', 'env']);
export function recoverMetavars(semgrepJson, sources) {
    const results = prop(semgrepJson, 'results');
    if (!isRecord(semgrepJson) || !Array.isArray(results)) {
        return { json: semgrepJson, intact: 0, recovered: 0, unrecoverable: 0 };
    }
    // One encode per file, not one per match: a busy file can carry hundreds.
    const buffers = new Map();
    let intact = 0;
    let recovered = 0;
    let unrecoverable = 0;
    const rebuilt = results.map((raw) => {
        const extra = prop(raw, 'extra');
        const metadata = prop(extra, 'metadata');
        const kind = str(metadata, 'guardian_kind');
        if (kind === undefined || !RECOVERABLE_KINDS.has(kind))
            return raw;
        // Real metavars are more precise than anything we can reconstruct — an
        // older Semgrep, or a logged-in one, must win.
        if (hasMetavars(extra)) {
            intact += 1;
            return raw;
        }
        const span = sliceSpan(raw, sources, buffers);
        const metavars = span === undefined ? undefined : synthesize(kind, span, metadata);
        if (metavars === undefined || !isRecord(raw)) {
            unrecoverable += 1;
            return raw;
        }
        recovered += 1;
        return { ...raw, extra: { ...(isRecord(extra) ? extra : {}), metavars } };
    });
    return { json: { ...semgrepJson, results: rebuilt }, intact, recovered, unrecoverable };
}
/**
 * The matched source text, sliced by BYTE offset.
 *
 * `offset` is a byte offset into the file; JavaScript string indices are
 * UTF-16 code units. Any non-ASCII character earlier in the file desyncs the
 * two, so a plain `text.slice(start, end)` silently returns the wrong span —
 * and a wrong span produces a confidently wrong route. Encode, then slice.
 */
function sliceSpan(raw, sources, buffers) {
    const path = str(raw, 'path');
    if (path === undefined)
        return undefined;
    const start = num(prop(raw, 'start'), 'offset');
    const end = num(prop(raw, 'end'), 'offset');
    if (start === undefined || end === undefined)
        return undefined;
    if (!Number.isInteger(start) || !Number.isInteger(end))
        return undefined;
    if (start < 0 || end <= start)
        return undefined;
    const text = sources.get(path);
    if (text === undefined)
        return undefined;
    let buffer = buffers.get(path);
    if (buffer === undefined) {
        buffer = Buffer.from(text, 'utf8');
        buffers.set(path, buffer);
    }
    // Past end-of-file: the file changed under us, or the offsets are not what
    // we think they are. Either way, guessing is worse than reporting nothing.
    if (end > buffer.length)
        return undefined;
    const span = buffer.subarray(start, end).toString('utf8');
    return span.trim().length === 0 ? undefined : span;
}
function synthesize(kind, span, metadata) {
    switch (kind) {
        case 'route':
            return synthesizeRoute(span, metadata);
        case 'mount':
            return synthesizeMount(span);
        case 'import':
            return synthesizeImport(span);
        case 'env':
            return synthesizeEnv(span);
        default:
            return undefined;
    }
}
/* ---- route ---------------------------------------------------------------
 *
 * Captured shapes (Semgrep 1.164.0, multi-language fixture):
 *   app.get('/health', (req, res) => res.send('ok'))
 *   @app.route('/flask-route')
 *   http.HandleFunc("/go-route", handler)
 *   @GetMapping("/spring-route")
 *   get '/ruby-route', to: 'users#index'
 *   path(settings.ADMIN_URL, flask_route)
 *
 * …and, for the three frameworks below, the attribute PLUS the declaration it
 * decorates:
 *   #[allow(dead_code)]\n#[get("/d")]\nasync fn d() -> String { … }
 */
function synthesizeRoute(span, metadata) {
    const framework = str(metadata, 'framework');
    if (framework === 'wp-rest')
        return synthesizeNamespacedRoute(span);
    const declaredMethod = str(metadata, 'method');
    if (framework !== undefined && DECORATED_DECLARATION_FRAMEWORKS.has(framework)) {
        return synthesizeAttributeRoute(span, framework, declaredMethod);
    }
    const path = routePath(span);
    if (path === undefined)
        return undefined;
    const metavars = { $PATH: { abstract_content: path } };
    // $METHOD only when the rule declares no `metadata.method`. That flag is the
    // rule pack's own record of where the verb lives: a rule has to declare it
    // precisely because the verb is NOT in the callee but in the rule identity
    // (@GetMapping — see the routes.yml header). For those, synthesizing the
    // callee would be actively harmful: `GetMapping` is not a verb,
    // `normalizeMethod` returns ANY, and because extract.ts reads
    // `$METHOD ?? metadata.method` our guess would *override* the correct GET.
    if (declaredMethod === undefined) {
        const verb = calleeIdentifier(span);
        if (verb !== undefined)
            metavars['$METHOD'] = { abstract_content: verb };
    }
    return metavars;
}
/* ---- attribute-anchored routes -------------------------------------------
 *
 * Three rule families in `configs/semgrep/routes.yml` cannot match the
 * attribute alone — Semgrep's Rust engine matches every node in the file, its
 * C# engine reads `[HttpGet($PATH)]` as a collection expression, and its
 * TypeScript engine rejects a bare decorator pattern outright. All three
 * therefore match the attribute *plus the declaration it decorates*.
 *
 * The consequence, measured on Semgrep 1.164.0: the reported span begins at
 * the FIRST attribute on that declaration, which is very often not the route
 * one. Anchoring on the first argument list in the span then reads the wrong
 * attribute's argument — and because that usually *succeeds*, the real route
 * is silently replaced rather than reported missing:
 *
 *   #[allow(dead_code)] / #[get("/d")]              →  route `dead_code`
 *   [Produces("application/json")] / [HttpGet("/o")] →  route `application/json`
 *   @Roles('admin') / @Get('/users')                 →  route `admin`
 *
 * Each of those passes `isLiteralPath`, so it is emitted as a RESOLVED path a
 * DAST tool would go on to request. That is the precise class of falsehood
 * this tool exists to prevent, so the route attribute is located by name
 * instead. The rule identity always carries enough to name it: `metadata.method`
 * for NestJS and ASP.NET, and the verb itself for Rust, whose attribute name IS
 * the HTTP verb.
 *
 * When the named attribute is not found in the span we recover NOTHING and
 * count the match `unrecoverable`. A route we cannot read is a gap in the
 * inventory; a route we invent is a lie acted on downstream.
 */
const DECORATED_DECLARATION_FRAMEWORKS = new Set([
    'actix',
    'nestjs',
    'aspnet',
]);
/**
 * Frameworks whose rule pattern spans the decorated declaration, exported so
 * `test/unit/surface/rulePack.test.ts` can assert the two stay in lock-step:
 * widening another family's pattern the same way without adding it here is
 * exactly how the defect above shipped.
 */
export const ATTRIBUTE_ANCHORED_FRAMEWORKS = DECORATED_DECLARATION_FRAMEWORKS;
/** actix/Rocket attribute names, which are themselves the HTTP verb. */
const ACTIX_VERBS = 'get|post|put|patch|delete|options|head';
/**
 * A sticky pattern matching the route attribute's own opening parenthesis.
 * `undefined` when the framework does not name its attribute in the rule
 * identity — we then have nothing to anchor on and must not guess.
 */
function routeAttributePattern(framework, method) {
    // Rust: `#[get(` / `#[post(` … the name is the verb, so no metadata.method.
    if (framework === 'actix')
        return new RegExp(`#\\[\\s*(${ACTIX_VERBS})\\s*\\(`, 'y');
    if (method === undefined)
        return undefined;
    const name = method.charAt(0).toUpperCase() + method.slice(1).toLowerCase();
    // NestJS: `@Get(`, `@Post(` …
    if (framework === 'nestjs')
        return new RegExp(`@\\s*(${name})\\s*\\(`, 'y');
    // C#: `HttpGet(`. No lead-in character is required, because Semgrep reports
    // the attribute *inside* the bracket list — a span starting at the route
    // attribute begins `HttpGet(`, with the `[` outside it. A preceding
    // identifier character is still excluded, so `MyHttpGet(` cannot match.
    if (framework === 'aspnet')
        return new RegExp(`(?<![A-Za-z0-9_])Http${name}\\s*\\(`, 'y');
    return undefined;
}
function synthesizeAttributeRoute(span, framework, declaredMethod) {
    const pattern = routeAttributePattern(framework, declaredMethod);
    if (pattern === undefined)
        return undefined;
    const match = scanOutsideStrings(span, pattern);
    if (match === undefined)
        return undefined;
    // The pattern ends at the `(`, so that is the last character it consumed.
    const open = match.index + match[0].length - 1;
    const path = argumentsAt(span, open)?.[0];
    if (path === undefined)
        return undefined;
    const metavars = { $PATH: { abstract_content: path } };
    // Rust binds the attribute name to $METHOD; the other two carry the verb in
    // `metadata.method`, which extract.ts already reads.
    const verb = match[1];
    if (declaredMethod === undefined && verb !== undefined) {
        metavars['$METHOD'] = { abstract_content: verb };
    }
    return metavars;
}
/**
 * The path a route rule captured: the FIRST ARGUMENT of the registration
 * call, not merely the first string literal in the span.
 *
 * The distinction is load-bearing, and measured. Semgrep can report a span far
 * wider than the call that matched — the Rust attribute rules report the whole
 * item, `#[get("/rust-route")]` *plus the function body* — and "first string
 * literal anywhere in the span" would happily pick a string out of that body.
 * Anchoring to the argument list keeps the capture where the rule bound it.
 *
 * Two deliberate exits:
 *
 *   - No bracket at all → the first string literal. Ruby's route DSL takes no
 *     parentheses (`get '/users', to: '…'`), and that is the only shape in the
 *     pack where the path is not syntactically an argument.
 *   - A call whose argument list is empty → nothing. There was no argument to
 *     capture, so any value we produced would be invented. Semgrep 1.86.0
 *     agrees: for those spans it reports `metavars: {}`.
 *
 * When the first argument is not a string literal the path was a code
 * expression (`path(settings.ADMIN_URL, …)`, `@PostMapping(Paths.ORDERS)`). It
 * is returned *unquoted*, exactly as it reads in source, so `isLiteralPath`
 * rejects it and the route is kept but flagged `path_partial`. Dropping it
 * instead would erase real surface — the failure this design exists to prevent.
 */
function routePath(span) {
    const args = argumentList(span);
    if (args !== undefined)
        return args[0];
    return findOpener(span) === undefined ? firstStringLiteral(span) : undefined;
}
/**
 * `register_rest_route($NS, $ROUTE, …)` — WordPress splits the namespace and
 * the route across two arguments (Semgrep cannot concatenate metavariables),
 * so both are captured verbatim, quotes included.
 *
 * `register_rest_route(self::NAMESPACE, '/computed', …)` is the dominant idiom
 * in real plugins and must survive as a `path_partial` route rather than
 * vanish — hence "verbatim": `self::NAMESPACE` stays unquoted so
 * `isLiteralPath` rejects it, and resolvers/wordpress.ts never fabricates
 * `/wp-json/self::NAMESPACE/items`.
 */
function synthesizeNamespacedRoute(span) {
    const args = argumentList(span);
    if (args === undefined)
        return undefined;
    const namespace = args[0];
    const route = args[1];
    if (namespace === undefined || route === undefined)
        return undefined;
    return {
        $NS: { abstract_content: namespace },
        $ROUTE: { abstract_content: route },
    };
}
/** `app.use('/api', usersRouter)` → the literal, then the next identifier. */
function synthesizeMount(span) {
    const literal = findStringLiteral(span);
    if (literal === undefined)
        return undefined;
    const router = IDENTIFIER.exec(span.slice(literal.end))?.[1];
    if (router === undefined)
        return undefined;
    return {
        $PREFIX: { abstract_content: literal.text },
        $ROUTER: { abstract_content: router },
    };
}
/**
 * `import usersRouter from './routes/users'` and
 * `const usersRouter = require('./routes/users')`.
 *
 * $MODULE is emitted UNQUOTED, matching what a real (pre-redaction) run
 * reports — the rule pattern writes the quotes itself (`from "$MODULE"`), so
 * the capture binds the string contents. It matters: `resolveModuleFile` in
 * mapAttackSurface.ts tests `specifier.startsWith('.')`, and a leading quote
 * would silently disable mount resolution.
 */
function synthesizeImport(span) {
    const literal = findStringLiteral(span);
    if (literal === undefined)
        return undefined;
    const module = stripQuotes(literal.text);
    if (module.length === 0)
        return undefined;
    const symbol = /\bimport\s+([A-Za-z_$][\w$]*)\s+from\b/.exec(span)?.[1] ??
        /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=/.exec(span)?.[1];
    if (symbol === undefined)
        return undefined;
    return {
        $SYMBOL: { abstract_content: symbol },
        $MODULE: { abstract_content: module },
    };
}
/**
 * `process.env.API_KEY` → `API_KEY` (unquoted, as the real run reports it);
 * `os.environ['DATABASE_URL']` / `getenv('SECRET_KEY')` /
 * `Environment.GetEnvironmentVariable("X")` → the first argument, quotes kept.
 * `collectEnvVars` strips quotes either way, so both forms land as one name.
 */
function synthesizeEnv(span) {
    const arg = firstArgument(span);
    if (arg !== undefined)
        return { $NAME: { abstract_content: arg } };
    const member = /\.([A-Za-z_$][\w$]*)\s*$/.exec(span.trim())?.[1];
    if (member === undefined)
        return undefined;
    return { $NAME: { abstract_content: member } };
}
/* ---- span scanning -------------------------------------------------------
 *
 * Deliberately a scanner, not a parser: it has to cope with nine languages
 * from one code path, and every strategy above degrades to `unrecoverable`
 * rather than to a wrong answer. It tracks exactly two things — string
 * literals (so a comma or bracket inside one is not punctuation) and bracket
 * depth.
 */
const IDENTIFIER = /([A-Za-z_$][\w$]*)/;
const CLOSERS = { '(': ')', '[': ']', '{': '}' };
function isQuote(ch) {
    return ch === "'" || ch === '"' || ch === '`';
}
/** Index just past the closing quote of the literal starting at `start`. */
function skipString(text, start) {
    const quote = text[start];
    let i = start + 1;
    while (i < text.length) {
        const ch = text[i];
        if (ch === undefined)
            break;
        if (ch === '\\') {
            i += 2;
            continue;
        }
        if (ch === quote)
            return i + 1;
        i += 1;
    }
    return text.length;
}
function findStringLiteral(span, from = 0) {
    let i = from;
    while (i < span.length) {
        const ch = span[i];
        if (ch === undefined)
            break;
        if (isQuote(ch)) {
            const end = skipString(span, i);
            return { text: span.slice(i, end), end };
        }
        i += 1;
    }
    return undefined;
}
function firstStringLiteral(span) {
    return findStringLiteral(span)?.text;
}
/**
 * Where the argument list starts: the first `(`, or the first `[` when the
 * span has no parentheses at all (`process.env['DB_URL']`, `$_ENV['KEY']`).
 * Preferring `(` is what makes an attribute span work — `#[get("/x")]` and
 * `[HttpGet("/x")]` both open with a bracket that is not the argument list.
 */
function findOpener(span) {
    let bracket = -1;
    let i = 0;
    while (i < span.length) {
        const ch = span[i];
        if (ch === undefined)
            break;
        if (isQuote(ch)) {
            i = skipString(span, i);
            continue;
        }
        if (ch === '(')
            return i;
        if (ch === '[' && bracket < 0)
            bracket = i;
        i += 1;
    }
    return bracket >= 0 ? bracket : undefined;
}
/** Index of the bracket closing the one at `open`, or undefined if unbalanced. */
function matchingClose(span, open) {
    const stack = [];
    let i = open;
    while (i < span.length) {
        const ch = span[i];
        if (ch === undefined)
            break;
        if (isQuote(ch)) {
            i = skipString(span, i);
            continue;
        }
        const closer = CLOSERS[ch];
        if (closer !== undefined) {
            stack.push(closer);
            i += 1;
            continue;
        }
        if (ch === ')' || ch === ']' || ch === '}') {
            const expected = stack.pop();
            if (expected !== ch)
                return undefined;
            if (stack.length === 0)
                return i;
        }
        i += 1;
    }
    return undefined;
}
/** Split at top-level commas — not those inside quotes, brackets or parens. */
function splitTopLevel(inner) {
    const parts = [];
    let depth = 0;
    let start = 0;
    let i = 0;
    while (i < inner.length) {
        const ch = inner[i];
        if (ch === undefined)
            break;
        if (isQuote(ch)) {
            i = skipString(inner, i);
            continue;
        }
        if (CLOSERS[ch] !== undefined)
            depth += 1;
        else if (ch === ')' || ch === ']' || ch === '}')
            depth -= 1;
        else if (ch === ',' && depth === 0) {
            parts.push(inner.slice(start, i).trim());
            start = i + 1;
        }
        i += 1;
    }
    parts.push(inner.slice(start).trim());
    return parts.filter((part) => part.length > 0);
}
/** The arguments of the bracket that opens at `open`. */
function argumentsAt(span, open) {
    const close = matchingClose(span, open);
    if (close === undefined)
        return undefined;
    const args = splitTopLevel(span.slice(open + 1, close));
    return args.length > 0 ? args : undefined;
}
function argumentList(span) {
    const open = findOpener(span);
    if (open === undefined)
        return undefined;
    return argumentsAt(span, open);
}
/**
 * First match of a sticky pattern that does not start inside a string literal.
 *
 * The string-skipping matters: an attribute argument can contain anything,
 * including text that looks like another attribute
 * (`#[doc = "use #[get(\"/x\")] to route"]`).
 */
function scanOutsideStrings(span, sticky) {
    let i = 0;
    while (i < span.length) {
        const ch = span[i];
        if (ch === undefined)
            break;
        if (isQuote(ch)) {
            i = skipString(span, i);
            continue;
        }
        sticky.lastIndex = i;
        const match = sticky.exec(span);
        if (match !== null)
            return match;
        i += 1;
    }
    return undefined;
}
function firstArgument(span) {
    return argumentList(span)?.[0];
}
/**
 * The verb when it lives in the callee: the identifier immediately before the
 * `(` that opens the matched call — `app.get(` → `get`, `Route::get(` → `get`,
 * `r.GET(` → `GET`, `app.MapGet(` → `MapGet`. `normalizeMethod` in extract.ts
 * handles case and the ASP.NET `Map*` form, so the raw identifier is emitted.
 *
 * Ruby's route DSL has no parentheses at all (`get '/users', to: '…'`), so the
 * leading word of the span is the fallback — without it every Rails route
 * would degrade to ANY, since that rule declares no `metadata.method`.
 */
function calleeIdentifier(span) {
    const open = findOpener(span);
    if (open !== undefined && span[open] === '(') {
        const callee = /([A-Za-z_$][\w$]*)\s*$/.exec(span.slice(0, open))?.[1];
        if (callee !== undefined)
            return callee;
    }
    return /^\s*([A-Za-z_][\w]*)\s+['"`]/.exec(span)?.[1];
}
function stripQuotes(value) {
    return value.replace(/^['"`]|['"`]$/g, '');
}
/* ---- structural accessors (same shape as extract.ts's, kept local so the
   two modules stay independently readable) ---- */
function isRecord(value) {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
}
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
/** An empty `metavars: {}` counts as missing — there is nothing to preserve. */
function hasMetavars(extra) {
    const metavars = prop(extra, 'metavars');
    if (!isRecord(metavars))
        return false;
    return Object.keys(metavars).length > 0;
}
//# sourceMappingURL=recoverMetavars.js.map