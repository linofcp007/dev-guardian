# Changelog

All notable changes to dev-guardian are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and the project uses
[Semantic Versioning](https://semver.org/). From 1.0.0 the MCP tool/resource
surface and default behaviours follow semver — breaking changes require a major
version bump.

## [Unreleased]

### Added

- **`map_attack_surface` — static route/env-var/port inventory across all 8 stacks.**
  New tool that runs a dedicated Semgrep rule pack (`configs/semgrep/routes.yml`) over
  the project to extract HTTP routes, referenced environment variables, declared ports
  and webhook endpoints, resolving Express-style router mount prefixes and WordPress
  REST namespaces to their effective path. Reports per-language `coverage`
  (`ok` / `no_rules` / ...) so an uncovered framework shows up as a gap rather than a
  silent zero. Persists one snapshot per run to a new `surface_snapshots` SQLite table,
  keyed by a tree hash so an unchanged working tree reuses the previous snapshot instead
  of re-scanning. The tool result itself returns a summary plus a 20-route sample and a
  `snapshot_id` — the full route list is deliberately kept out of the tool response (see
  the new resources below) so a project with hundreds of routes cannot exhaust the
  agent's context window on a single call.
  - **Validation status, per rule.** Every rule in `configs/semgrep/routes.yml` now
    matches real code in `mcp/test/fixtures/surface/apps/`, checked capture-by-capture
    against Semgrep **1.86.0** (the last version that still emits `extra.metavars`, so
    what a rule binds is directly observable) and re-run end to end through the tool on
    Semgrep **1.164.0** (which redacts them, exercising the byte-offset recovery). Both
    versions produce the same 81 matches — 64 routes — with no rule errors. (1.164.0 also
    emits one `warn`-level `PartialParsing` on `php-wordpress/rest-controller.php:20`,
    where its PHP parser rejects `const NAMESPACE`; 1.86.0 parses it. That is a target-file
    parse warning, not a rule error, it predates every change here, and both `wp-rest`
    matches in that file still fire.) Verified
    working: `express` + its `mount` and `import` rules, `nestjs` (5), `flask`, `fastapi`,
    `django`, `wp-rest` (literal *and* `self::NAMESPACE` namespaces), `laravel`,
    `go-nethttp`, `gin`, `rails` (bare and `to:` forms), `spring` (all 6, including
    `@RequestMapping`, in their single-argument form), `aspnet-minimal`, `aspnet`
    attribute routing (5), `actix` (5), and all 5 `env` rules. Four rule families were
    **broken** and are fixed below.
  - **What is still not covered.** The verb alternations absent from the fixture —
    `OPTIONS`, `HEAD`, `ALL`/`ANY`, and `PUT`/`PATCH` for some frameworks — are
    untested, being extra literals in an already-verified `metavariable-regex`. A
    parameterless decorator (`@Get()`, `[HttpGet]`) is deliberately not reported: there
    is no path to capture, and neither the NestJS `@Controller` prefix nor an ASP.NET
    `MapGroup` prefix is resolved, so those routes are reported at their own
    registration path. Go's `os.Getenv` is not collected — no `env` rule covers Go.
    The Docker fallback path of `map_attack_surface` is still only exercised by mocks.
    Two **named-argument** forms are measured as unmatched and pinned as fixture bait:
    Spring's `@GetMapping(value = "/x", produces = "…")` — common in real code, and not
    fixable by adding `, ...`, which Semgrep rejects as "Invalid pattern for Java" —
    and Rocket's `#[post("/x", data = "<t>")]` (see the actix entry below). Both are
    absent from the inventory rather than reported at a guessed path.
- **`map_attack_surface` imports OpenAPI 3.x and Swagger 2.0 documents and diffs them
  against the code.** Discovery walks the project for conventionally-named files
  (`openapi.*`, `swagger.*`, `api-docs.*`, or anything under an `openapi/` directory
  inside the project — never matched against the absolute filesystem path, so a
  checkout nested under an ancestor directory happening to be named `openapi` does not
  pull in unrelated files) or reads exactly the paths passed as `spec_paths`. Both JSON
  and YAML are accepted for either version; **Postman collections are not supported** —
  the parser only recognises an `openapi: 3.x` or `swagger: 2.0` document. Every
  imported route carries `provenance: 'spec'` alongside the code-extracted routes'
  `provenance: 'code'` (routes read back from a snapshot persisted before this feature
  default to `'code'`, so old data is never mistaken for spec data), and
  `auth_hint: 'none'` is now emitted for an operation or document declaring
  `security: []` — an explicit "this route is public" — never inferred from the field
  being absent, which stays `'unknown'`.
  - **The diff has two honesty rules, not one.** First: with no spec discovered, or every
    discovered spec failing to parse, `spec_diff` is `null` — never a diff in which
    every code route reads as undocumented, which is a different claim than "there is no
    spec to compare against." Second: a route whose full path could not be resolved (an
    unresolved router-mount prefix on the code side, a templated `servers[].url` /
    `basePath` on the spec side) is **never** reported as a shadow endpoint or as dead
    documentation — it lands in a fourth bucket, `unmatchable`, together with a reason,
    and is never surfaced as a finding. This costs real findings when an unresolved
    route happens to be the very shadow/dead one, so the counts of findings withheld for
    that reason (`code_only_withheld`, `spec_only_withheld`) are reported alongside the
    diff rather than the gap being silent.
  - `routes_total` and `coverage[]` stay code-only, unchanged by this feature: a spec
    importing 200 paths must not make `coverage` claim a `'spec'` language exists, and
    must not inflate the code-route count a consumer already relies on.
  - Discovery is capped at 20 candidate files and 5 MB per file, both reported
    (`truncated`, `oversized`) rather than silently applied, and an unresolved external
    `$ref` (a whole path item, or a parameter, pointing outside the document) is counted
    in `unresolved_refs` rather than the path item vanishing with no trace — which would
    read as "the spec never declared this," a false claim about a real route this module
    simply could not follow to its file.
  - New runtime dependency: [`yaml`](https://www.npmjs.com/package/yaml), used to parse
    YAML specs and to recover the source line each path is declared on (JSON specs
    always report `line: 0`, since `JSON.parse` carries no position information).
- **`guardian://surface/latest` and `guardian://surface/{id}` resources.** Serve the
  full persisted attack-surface snapshot (every route, env var, port, webhook and the
  coverage report) by snapshot id or the most recent one. Return `{ snapshot: null }`
  when nothing has been captured yet, consistent with the rest of the resource surface.
- **A multi-language fixture and an end-to-end rule-pack test.**
  `mcp/test/fixtures/surface/apps/` is a small twelve-directory application tree — one
  framework per directory — carrying the route shapes every rule targets plus realistic
  surrounding code that must *not* match: a Python module whose local helper is named
  `path`, a Ruby class calling `Rails.cache.delete 'orders/index'`, `cache.get(...)` in
  the Express app, `Route::middleware(...)`, `r.Use(...)`, `@app.on_event(...)`,
  `app.MapGroup(...)`. It also carries the cases that must survive *as* partial results:
  a computed Django path, a computed WordPress namespace next to a literal one, and a
  non-ASCII comment sitting before every match in two files so the byte-offset recovery
  is exercised rather than assumed. `mcp/test/e2e/rulePackFixture.test.ts` runs the real
  `map_attack_surface` handler over it and asserts the **complete** route set — all 64
  routes by framework, method, resolved path and `path_partial` — because a count
  assertion passes when one rule breaks and another over-matches. One expected set, not
  one per Semgrep version: that the answer no longer depends on whether match content was
  redacted is asserted rather than assumed. It skips (visibly, via `it.skipIf`) when
  Semgrep is absent, and copies the tree out of `test/` first, which Semgrep's default
  ignore list would otherwise skip entirely.
  - **A companion `openapi.yaml` exercises the spec-diff against the same real Semgrep
    run**, rather than against hand-written `RouteRecord`s. It documents three routes
    copied verbatim from the fixture's expected set (so `matched` is non-empty), omits
    the rest of the 51 resolvable code routes on purpose (asserted as the exact
    `code_only` set — shadow endpoints), and declares one path,
    `/deprecated/v0/orders`, that no code route implements (asserted as `spec_only` —
    dead documentation). The comparison is an exact sorted set on both buckets, the same
    style as the route-set assertion above and for the same reason: a count passes when
    one rule breaks and another over-matches by the same amount.
- **`scan_dast` — active DAST that probes a *running* application against the
  `map_attack_surface` route inventory.** New tool that sends real HTTP requests to an
  application the caller already has running — it never starts, builds or stops
  anything — and reports what is actually reachable, what is served without credentials,
  and what leaks. It **requires a prior `map_attack_surface` run**: with no persisted
  snapshot it refuses with `no_surface_snapshot` naming the tool to run first, and a
  target that answers nothing refuses with `target_not_found`; neither refusal persists a
  scan row, so an empty `dast` history entry can never be read by `diff_scans` /
  `risk_score` as "this scan found nothing." Findings land in the existing `findings`
  table (`scan_type: 'dast'`) with a fingerprint stable over `(check, method, path,
  file)` — deliberately excluding the HTTP status, so a fixed app flipping 500→200 on
  restart is not a "new" finding — so DAST findings dedupe, diff and baseline exactly
  like every other finding.
  - **Own engine, eight checks.** `reachability` (confirms the static spec diff's shadow
    endpoints / dead documentation against the live server, and reports an extractor
    coverage gap — never a project bug — when a documented route is live but no code
    route was ever found for it), `anonymous_exposure` (a route the inventory marked
    `auth_hint: 'required'` answering an anonymous request with `2xx` — the strongest
    finding the tool can produce; `high` rather than `critical` because that hint can be
    inherited from a document-level OpenAPI default rather than declared per-operation),
    `differential_authz` (with credentials supplied, a byte-identical response with and
    without them — equality only, never a similarity score, so response noise like
    timestamps or CSRF tokens can only cause a missed finding, never a fabricated one),
    `cors` (a reflected `Origin` **and** `Access-Control-Allow-Credentials: true`
    together — either alone is inert and not reported), `security_headers` (missing CSP /
    `X-Content-Type-Options` / `X-Frame-Options` / HSTS-on-HTTPS, one finding **per
    origin** rather than per route), `info_disclosure` (stack-trace signatures and
    versioned `Server` / `X-Powered-By` banners), `method_surface` (`OPTIONS`'s `Allow`
    header advertising a verb the static extractor never saw, with framework-default
    `HEAD`/`OPTIONS` carved out so it does not fire on nearly every `GET` route in
    existence), and `open_redirect` (a `3xx` whose `Location` leaves the target origin —
    free from `probe.ts` never following a redirect). Plus an opt-in `probe_rate_limit`
    burst (30 requests, synthetic un-ownable credentials, stops early on the first `429`)
    and an optional nuclei pass.
  - **The safety envelope is the design, not a feature of it.** Target classification is
    purely lexical (no DNS, so it cannot be rebound mid-scan): loopback (`localhost` /
    `127.0.0.0/8` / `::1`) probes directly; anything else — including a hostname that
    merely *resolves* to loopback — refuses with `target_not_authorized` unless the
    caller passes `authorized_target: true`, recorded in the scan for audit. Read-only by
    default (`GET`/`HEAD`/`OPTIONS`); `allow_write_methods` opens `POST`/`PUT`/`PATCH`/
    `DELETE`, always with an empty body, so the `400`/`422`-vs-`401`/`403` split answers
    the authorization question without writing. The one exception to read-only-by-default
    is the opt-in `probe_rate_limit` burst, which sends `POST` to exactly one route — the
    flag is its own authorization and opens nothing for any other check. Redirects are
    never followed (`redirect: 'manual'`). Bounds — concurrency 4, a 5s per-request timeout, a 750-request ceiling,
    a 10-minute wall-clock ceiling — are reported when they cut a run, never silently
    applied; a run the wall-clock ceiling cut records its unsent probes `cancelled`,
    distinct from `timeout`, because the target didn't fail to answer — this tool stopped
    asking.
  - **Credentials are opt-in, never persisted, always redacted.** `auth_header_env`
    (recommended — the *name* of an environment variable; the secret never enters the
    conversation or the MCP request log) or `auth_header` (the literal value, documented
    as landing in the transcript). Neither is written to SQLite or an evidence file, and
    both are redacted from every finding, evidence file and result field through a single
    redaction choke-point applied to the whole response, not a hand-picked set of fields.
    Naming a variable via `auth_header_env` keeps it out of nuclei specifically — nuclei is
    spawned with an allowlisted environment and `extendEnv: false` for exactly that reason
    — but not out of this server process, nor out of the other scanners (Semgrep, Trivy,
    gitleaks, git) the same session spawns with the operator's full environment by design.
    That is a deliberate, unchanged posture (those tools read `SEMGREP_*` / `DOCKER_CONFIG`
    / `SSH_AUTH_SOCK` and the like), not an oversight; the parameter description now says
    so directly.
  - **A deliberately-vulnerable fixture app** (`mcp/test/fixtures/dast-app/server.mjs`,
    plain `node:http`, no framework) exercises every check end to end: an auth-required
    route served anonymously, reflected-credentialed CORS, missing security headers, a
    stack-trace leak, an open redirect, and a route with no rate limit.
  - **Per-check status, not just findings.** Every check reports `ok` /
    `skipped_envelope` / `no_candidate` / `needs_credentials` / `scanner_missing` /
    `target_error`, so a check that never ran (wrong envelope, no credentials, nuclei
    absent, the wall-clock ceiling cut it) is visible as such rather than reading as a
    check that found nothing — the same `coverage: 'full' | 'partial' | 'none'`
    discipline every other scan tool in this server already carries.
  - **The known limits — read before trusting a clean result.**
    - **No injection testing in the own engine.** No SQLi or XSS probes are sent; real
      XSS needs a browser and blind SQLi needs timing or destructive probes, and a
      fabricated injection finding is worse than none. That class is delegated entirely
      to nuclei's `-dast` fuzzing mode, which the default envelope excludes — **a clean
      `scan_dast` result is not evidence of injection safety.**
    - **nuclei tests the origin, not this project's routes.** Most of nuclei's HTTP
      templates use `{{BaseURL}}` and append their own known paths; the route inventory
      only genuinely feeds nuclei once `-dast` fuzzing is turned on, and the default
      envelope excludes that mode. nuclei still brings real value (component CVEs,
      exposed panels, misconfigurations) — it is just not what confirms the project's own
      endpoints; the own engine is. The result labels which findings came from which so
      the two are never conflated.
    - **The rate-limit finding is named `no_rate_limit_observed`, never "rate limiting is
      missing."** A limiter whose threshold sits above the burst size (30) is
      indistinguishable from no limiter at all at this sample size, and the finding name
      says so on purpose — do not reword it into a stronger claim.
    - **Synthetic path parameters give parametric routes a best-effort reachability
      signal, never a definitive one.** `/users/{id}` is probed as `/users/1`; a `404`
      there is ambiguous between "no such route" and "no such record 1," so it is never
      reported as "unreachable" — the ambiguity is surfaced, not resolved.
    - **nuclei has no verified Windows package manager install.** scoop, choco and winget
      were all checked and none carry it, so `install_toolchain`'s catalogue has no win32
      entry for it — Windows users install manually from nuclei's GitHub releases page
      (macOS gets a `brew` formula; Linux gets a curl installer, also pointed at GitHub
      releases). Consistent with that gap, nuclei is `default: false`: it never installs
      silently, and a requested-but-absent nuclei is reported as `scanner_missing` in
      `tools_run`, never a silent skip.
  - Discoverable via the `map_attack_surface` → `scan_dast` two-step, now documented in
    `host-rules/AGENTS.md` and in both tools' own descriptions.

### Fixed

- **A duplicate in `spec_paths` could hide an unreadable spec document.** `discoverSpecs`
  deduplicates the explicit paths and *then* applies the 20-file cap, while
  `map_attack_surface`'s own "which named paths were not read" accounting capped the raw
  list. With duplicates present the caller's window ended earlier than the one discovery
  used, and a genuinely missing path landing in the gap was reported by neither side: no
  `parse_error` row (outside the caller's window) and no truncation row (the deduplicated
  set never exceeded the cap). It vanished — the same "could not be read" reading as "there
  is no spec" conflation the rest of the feature exists to prevent. Both call sites now
  share one deduplicated list, which also stops a duplicated document from double-counting
  its routes in `spec_routes_total`.

- **The Rust route rules fabricated four routes for every real one.** The five per-verb
  actix rules were `#[get($PATH)]`, `#[post($PATH)]` and so on. A bare attribute is not a
  Rust item, and Semgrep degraded each of them to a pattern that matched *every node in
  the file* while binding `metavars: {}` — measured on 1.86.0, a three-route file produced
  95 matches, spans including `use` lines and function bodies, with all five rules
  reporting the same spans. So one `#[get("/x")]` yielded the correct GET plus four
  invented POST/PUT/PATCH/DELETE routes at the same path, and `map_attack_surface` feeds
  a DAST tool that would send a request to each. The fix is the trailing
  `fn $F(...) { ... }`: the pattern now includes the item the attribute is attached to, so
  it matches the seven real routes and nothing else. (The rules were briefly collapsed into
  a single `#[$METHOD($PATH, ...)]` rule, because Semgrep's Rust engine does bind the
  attribute name once the pattern is well-formed. They are five again — one per verb, each
  declaring `metadata.method` — because `focus-metavariable: $PATH` discards `$METHOD`; see
  the redaction entry below.) Verified: exactly seven matches for seven routes, each with
  the right verb and path, and the `#[allow(...)]` attribute stacked on two of them
  correctly ignored. It does **not** cover Rocket's multi-argument attributes:
  `#[post("/x", data = "<t>")]` and `#[get("/x", rank = 2)]` produce zero matches on
  both 1.164.0 and 1.86.0 despite the `, ...`, and so does an explicit
  `#[$METHOD($PATH, $EXTRA)]`. Only a bare `#[$METHOD(...)]` matches them, and it binds
  no `$PATH` — a route with no path is worse than a route we did not report. Pinned as
  fixture bait in `rust-actix/rocket.rs` so the limitation stays measured.
- **The five ASP.NET attribute-routing rules matched nothing at all.**
  `[HttpGet($PATH)]` parses as a C# collection expression, not an attribute, so every
  `[HttpGet("/orders")]` in a controller was invisible — a whole style of ASP.NET routing
  silently missing from the inventory while `coverage` reported `ok` for C# on the
  strength of the minimal-API rules alone. Fixed by extending each pattern to include the
  method the attribute decorates.
- **The five NestJS rules were rule *errors*, not merely unmatched.** `@Get($PATH)` is not
  a parseable TypeScript pattern ("Invalid pattern for TypeScript"), so every single run
  of `map_attack_surface` on any project emitted five rule-parse errors and reported zero
  NestJS routes. Same fix: the pattern now includes the decorated method. The decorator
  name cannot be a metavariable in TypeScript (`@$DEC($PATH)` does not parse either), so
  these stay one rule per verb.
- **The Django rule reported filesystem-path helpers as HTTP routes.** `path($PATH, ...)`
  keys on the callee *spelling*, and `path` is an ordinary function name. Measured against
  a module doing nothing worse than `def path(*parts): return os.path.join(*parts)`, the
  rule produced three routes, two of which (`etc`, `var`) passed the extractor's literal
  test and were therefore emitted as resolved URLs that exist nowhere. The rule now names
  the callee in full — `django.urls.path` / `django.urls.re_path` — so Semgrep resolves
  the import instead of the spelling. This is **not** a `$PATH` literal guard: a computed
  path (`path(settings.ADMIN_URL, ...)`) still matches and is still reported, flagged
  `path_partial`. The Ruby rule was checked for the same failure and does not have it:
  `Rails.cache.delete 'orders/index'` and `store.get 'orders/index'` produce no matches,
  because `$METHOD $PATH` does not match a call with an explicit receiver.
- **Express/Fastify mount resolution never worked on Windows.** Semgrep reports paths in
  the host's native separator and this tool always hands it an absolute target, so on
  Windows a match arrives as `C:\project\src\routes\users.js` while the import specifier
  is `./routes/users`. `resolveModuleFile` split on `/` only, so a Windows path was one
  segment, matched no known file, and every route in a mounted router silently degraded to
  `path_partial` — the tool looked healthy and quietly stopped resolving prefixes on a
  supported platform. Paths are now normalised before comparison, and the known file is
  still returned verbatim so it continues to match `RouteRecord.file`.
- **All thirteen route families are now read on every Semgrep version, logged in or not.**
  NestJS, ASP.NET attribute routing and actix are the families whose Semgrep pattern must
  match the attribute *plus the declaration it decorates* — the attribute alone does not
  parse, or matches every node in the file. The reported span therefore begins at whatever
  attribute comes first, and **four** successive attempts to read a route out of it each
  **invented** one: anchoring on the first argument list turned `#[allow(dead_code)]` into a
  route named `dead_code` and `[Produces("application/json")]` into `application/json`;
  anchoring on the route attribute by name turned a commented-out
  `// [HttpGet("/orders/legacy")]` into `/orders/legacy` while the live `/orders`
  disappeared. Both passed `isLiteralPath`, so each was emitted as a **resolved** path — a
  URL `scan_dast` would request — and both were silent, because reconstruction *succeeded*:
  `tools_run` reported `ok` with zero unrecoverable matches. The families were then refused
  outright, which was correct against those options but left 21 real routes out of the
  inventory whenever Semgrep redacted match content.
  - **The fix removes the question rather than answering it.** Deciding whether text is
    code, a comment or a string literal is **not local information** — it depends on
    everything from the start of the file, and the span starts in the middle. So no
    predicate over the span decides it: the three rules now carry
    `focus-metavariable: $PATH`, which makes Semgrep narrow its own **reported range** to
    the metavariable, using a real parser for the language. The byte offsets then point at
    the path literal itself, and recovery is "the span is the value" — no anchoring, no
    argument parsing, nothing searched for. A decoy cannot be picked out of a span it is not
    in, which is what makes the defect class structurally unreachable rather than merely
    unobserved.
  - **Measured on both Semgrep versions, against the adversarial fixtures.** 1.164.0
    (redacts match content) and 1.86.0 (still emits `extra.metavars`) produce the **same 64
    routes** over `mcp/test/fixtures/surface/apps/` — 81 matches each, zero rule errors on
    either (1.164.0 emits one pre-existing PHP parse warning; see above), zero unrecoverable on
    either — and the reported spans on 1.164.0 are byte-for-byte equal to 1.86.0's `$PATH`
    captures, quotes included. Every planted decoy is absent from both: `dead_code`,
    `application/json`, `204`, the commented-out `/rust/legacy`, `/aspnet/orders/legacy` and
    `legacy/:id`, and the attribute-shaped `FABRICATED` text inside method bodies. Coverage
    no longer depends on the Semgrep version, or on being logged in.
  - **A truncated range can no longer become a resolved path.** The focused branch trusts
    Semgrep's range by design — validating it would mean re-deriving what Semgrep already
    decided, the mistake of all four earlier rounds — so the safety argument has to be that
    every way a range can be wrong degrades to *incomplete*. One shape did not: a range
    ending **inside** the string literal left the opening quote unmatched, and `stripQuotes`
    in `extract.ts` removed it anyway, so `"/orders/secret` cut six bytes short read as the
    clean path `/orders/s` at full confidence — a URL that exists nowhere, published as
    verified, while the real one was absent. `stripQuotes` now strips only a **matched**
    pair, so the stray quote reaches `isLiteralPath`, which rejects it: the route survives
    as `path_partial` at `low` confidence with its raw text visible. Unreached by anything
    measured — 115 captures (81 fixture + 34 probe) were byte-exact against 1.86.0 — but
    truncation is not hypothetical: a TypeScript template literal was observed arriving two
    bytes short of its closing backtick. Pinned for all three quote styles.
  - **actix is five rules again, one per verb.** Focusing on `$PATH` discards every other
    capture, `$METHOD` included, so the verb has to come from `metadata.method` — the shape
    NestJS, ASP.NET attribute routing and Spring already use. Per-verb discrimination was
    re-measured across all three languages (six rules over three files, each matching only
    its own attribute), so the reason actix was once collapsed into a single
    `$METHOD`-binding rule no longer holds.
  - **The refusal machinery is deleted, including its fail-open default.**
    `UNRECOVERABLE_FRAMEWORKS` / `UNREADABLE_UNDER_REDACTION` listed the frameworks to
    refuse, so a fourth declaration-spanning family added without being listed would have
    silently fabricated again. There is no list any more, and therefore no wrong path for an
    unlisted framework to fall into. What replaces it is a lock-step assertion in
    `rulePack.test.ts`: a rule declaring `metadata.guardian_focus: path` without
    `focus-metavariable` (or the reverse) fails the suite, as does a route rule whose
    pattern spans a declaration without focusing. The flag is deliberately read from the
    rule pack rather than inferred from the framework name — the pack is the thing that
    knows whether it focused.
  - **Only these three are focused.** The other ten route families (express + its
    mount/import rules, flask, fastapi, django, laravel, gin, net/http, spring, wp-rest,
    aspnet-minimal) and all five `env` rules have spans that begin at the call or annotation
    that matched, so the capture sits at a known place. They are verified slot-for-slot
    against Semgrep 1.86.0 — every capture the extractor reads, identical — and several
    capture `$METHOD` as a metavariable that focusing would discard. Noted in the module
    docs as a possible future simplification, not a pending fix.
  - **`CoverageEntry.status: 'unreadable'` stays, and no longer describes a rule family.**
    `'ok' | 'no_matches' | 'no_rules' | 'unreadable'` with a companion `unreadable_matches`
    count, so a language whose routes were matched but not read can never collapse into
    `no_matches` — "this language exposes nothing", the exact inverse of the truth. It is
    now reachable only for a genuinely unreadable match: source rewritten or deleted
    mid-scan, not valid UTF-8, or offsets past end-of-file. The `tools_run` reason and the
    degraded `note` were rewritten to say that, instead of naming three families that are no
    longer affected.
  - The fixture keeps every adversarial case that caught this — a commented-out route
    attribute, anchor text inside a string, attribute-shaped text in a method body, an
    apostrophe in a comment, a Rust lifetime — for all three frameworks. The assertions that
    pinned their **absence** are inverted to pin the **real** route, and the
    `FABRICATION_DECOYS` check that has caught this class every time is unchanged: no decoy
    path may appear in the output, ever.
- **`recoverMetavars` could throw, contradicting its own contract.** `metadata.method` was
  interpolated raw into `new RegExp`, so a rule declaring `method: "a("` raised a
  `SyntaxError` out of a module documented as never throwing, and out of an unguarded call
  site in `mapAttackSurface.ts`. That path is gone with the anchoring, and a
  `metadata.method` that is not a plain word is rejected outright.
- **The rule-pack drift assertion was a substring sniff.** It tested for the literal text
  `{ ... }`, so the same rule written `{ $BODY }` — which Semgrep treats identically —
  widened a family past the guard while the test stayed green. It now parses each rule's
  patterns and detects a brace-delimited body structurally, and asserts that the pack's
  declaration-spanning route rules are exactly the ones carrying `focus-metavariable`.
- **A skipped end-to-end test reported as a passing one.** Both e2e files —
  `rulePackFixture.test.ts` and `evalVulnFixture.test.ts`, the only tests that run a real
  Semgrep — used `console.warn` plus a bare `return` when Semgrep was absent, which vitest
  counts as a pass. On Windows, Semgrep installs to
  `%APPDATA%\Roaming\Python\Python3xx\Scripts`, which is not on `PATH`, so both gates
  silently measured nothing and route-fabrication defects reached a green suite through
  them twice. They now use `it.skipIf`, so a skip reads as a skip, and
  `GUARDIAN_REQUIRE_SEMGREP=1` turns absence into a hard failure that distinguishes "not on
  PATH" from "fixture tree missing".
- **`map_attack_surface` extracted zero routes on every current Semgrep.** Semgrep changed
  behaviour between 1.95.0 and 1.120.1: unless the user has run `semgrep login` it redacts
  match content, so `extra.metavars` is absent entirely and `extra.lines` reads
  `"requires login"`. The extractor reads `extra.metavars.$PATH.abstract_content`, so the
  tool reported *no routes at all* while Semgrep itself reported matches — nothing looked
  broken, and the persisted snapshot said the application exposes nothing. Requiring an
  account is not an option for a tool whose stated position is 100% open-source and local.
  What redaction does not remove is the position: `start.offset` / `end.offset` survive, so
  a new pure module `mcp/src/surface/recoverMetavars.ts` slices the matched source out of
  the file and reconstructs the captures the rules would have bound, keyed off
  `guardian_kind` and `framework`. It synthesizes into the shape the extractor already
  reads, so `mcp/src/surface/extract.ts` is untouched. Measured end to end against Semgrep
  1.164.0 over `mcp/test/fixtures/surface/apps/`: **all 64** of the fixture's routes and all
  8 environment variables recovered, where the tool previously found none at all. (43 of the
  64 at first — the other 21 were the three decorated-declaration families, which were
  refused until `focus-metavariable` made their spans readable; see the entry above.)
  Verified capture-by-capture against Semgrep 1.86.0 — the last version that still emits
  metavariables, and which finds the same 64 — as ground truth.
  - Offsets are **byte** offsets, so the span is sliced from a `Buffer`; a source file with
    any non-ASCII character before the match desyncs a plain `String.prototype.slice` and
    yields a confidently wrong path. Source quoting is preserved verbatim, because that is
    exactly how `isLiteralPath` separates `'/items'` from `self::NAMESPACE` — and
    `register_rest_route(self::NAMESPACE, '/computed', …)`, the dominant idiom in real
    WordPress plugins, survives as a `path_partial` route rather than vanishing.
  - The module is pure and never throws: a file it cannot read, an offset past
    end-of-file, or a span with nothing to capture is counted `unrecoverable` and skipped.
    Reading the files stays in the tool, which is already the impure layer.
  - **Honest degradation.** If Semgrep reported matches and *not one* could be recovered,
    that is a broken toolchain, not a project without routes: the tool now persists
    nothing and says why — naming the redacting-Semgrep cause and that `map_attack_surface`
    does not require an account — instead of writing a zero-route snapshot that later reads
    as "this application exposes nothing". A partial recovery is persisted but reported, via
    a `semgrep-metavar-recovery` entry in `tools_run` carrying the counts, so it is visible
    rather than silent.
- **A path we could not resolve is never emitted as a resolved path.** Only one route rule
  in the pack constrained its path capture to a string literal; the other thirteen let a
  Semgrep metavariable that had bound a *code expression* through as a confident path —
  `self::NAMESPACE`, `$this->namespace`, `SETTINGS.users_path`, `Paths.ORDERS`, a bare
  `routeVar`. The first two are the dominant idioms in real WordPress plugins, not edge
  cases, and the next tool in this series will send HTTP requests to whatever path it is
  handed. A new `isLiteralPath` predicate in `mcp/src/surface/extract.ts` now gates every
  route, in the one place they all flow through, so it also covers rules users add via
  `register_custom_rules`. A capture that fails it keeps its route — a route we cannot
  name is still evidence of surface — but is flagged `path_partial: true`, keeps the raw
  text in `path_resolved`, and drops to `low` confidence. Both resolvers now honour that
  flag instead of clearing it when they prepend a mount prefix or a `/wp-json` namespace.
  A `metavariable-regex` guard in the rule pack would be the wrong second layer here: it
  *drops* the match, so the extractor never sees it, and a route registered with a computed
  path is still surface — dropping it would make `coverage` report `no_matches` for the
  language, which is the same "this application exposes nothing" falsehood in a different
  place. `$PATH` literal guards are therefore confined to the two rules whose pattern does
  not identify a route on its own (`guardian-route-express`, `guardian-route-rails`), where
  the literal disambiguates rather than discards, and the pack header now states that rule
  so it is not re-added by pattern-matching.
- **`params` is derived from the path alone.** It was gated on both the path and the
  namespace being literal, so `register_rest_route(self::NAMESPACE, '/items/(?P<id>\d+)')`
  reported `params: []` — an assertion that the route takes no parameters — when `id` is
  plainly knowable from the path. Where the route is served stays unknown
  (`path_partial: true`); the parameters no longer do.
- **The HTTP method was lost for five of thirteen route rules.** `aspnet-minimal`,
  `aspnet`, `spring`, `nestjs` and `actix` all reported `ANY`. Semgrep never reports which
  `pattern-either` alternative fired, so a rule whose verb is encoded in the alternative
  cannot recover it — those families are now one rule per verb, each declaring
  `metadata.method` (which the extractor already read as a fallback, until now dead code).
  `normalizeMethod` also understands ASP.NET's `MapGet` / `MapPost` builder names.
- **A cached snapshot no longer hides the failed run that produced it.** The cache path
  reported a hardcoded `tools_run: [{semgrep, skipped, cached}]`, so the one case where a
  failing run is still persisted (Semgrep exited non-zero but left parseable JSON) carried
  its warning for exactly one call. Every later call on the same tree hash presented a
  snapshot that was empty *because the scan died* as "this application exposes nothing" —
  the falsehood this tool exists to prevent. The persisted `tools_run` entries are now
  reported alongside the cache marker.
- **`auth_hint` is no longer advertised as a feature.** No rule sets `metadata.auth`, so
  the field is always `unknown`. The claim was removed from the tool description, and the
  reason is recorded at `normalizeAuth` so the constant reads as deliberate rather than
  broken. Detecting auth properly needs to see the handler, not the registration site;
  that is its own piece of work.
- Regression coverage for the Semgrep exit-code gate (`exitCode === 1` means *matches
  found*, i.e. success), which previously could be deleted with the suite staying green.
- The Docker fallback in `map_attack_surface` no longer re-implements
  `buildSemgrepDockerArgs`; the shared builder takes a `configs` option (default
  `['auto']`) so both callers inherit anything added to it later.
- **A spec's `trace` operation no longer suppresses shadow-endpoint findings.** Spec
  import mapped `trace` (an OpenAPI/Swagger operation key with no matching `HttpMethod`
  member) onto the `'ANY'` routing sentinel, which `specDiff.ts` treats as matching every
  method at a path. A document declaring only `trace: /foo` therefore made both
  `GET /foo` and `POST /foo` in the code read as documented — two genuine shadow
  endpoints silently suppressed. `trace` operations are now excluded from import
  entirely rather than folded into `'ANY'`; the alternative (adding a `TRACE` member to
  the persisted `HttpMethod` union) was rejected to avoid touching a type serialized into
  every stored snapshot for the sake of an operation this feature does not otherwise need
  to represent.
- **The installers advertised a scanner this plugin has never integrated, and omitted the
  one it can install.** `scripts/install/install-linux.sh` carried an OWASP ZAP banner
  (`docker pull zaproxy/zap-stable`) held over from before `scan_dast` existed — `ZAP`
  appears nowhere in `mcp/src`, is not in `TOOL_CATALOG`, and `install_toolchain` cannot
  install it, so the banner advertised a capability the plugin does not have. Meanwhile
  nuclei, which *is* in `TOOL_CATALOG` (`required_by: ['scan_dast']`, `default: false`)
  and is what `scan_dast`'s `use_nuclei` actually drives, appeared in neither installer.
  Both scripts now carry an honest nuclei banner instead: `install-linux.sh` points at the
  `install_toolchain` MCP tool (nuclei is opt-in, so a bare default install does not fetch
  it) and ProjectDiscovery's own install docs; `install-macos.sh` gained the equivalent
  banner naming the real `brew install nuclei` formula `TOOL_CATALOG` already verifies for
  that platform. Neither banner reproduces `TOOL_CATALOG`'s linux `curl` fallback, which
  resolves to a GitHub releases HTML page rather than a raw install script.
- **`TOOL_CATALOG`'s linux install command for gitleaks and nuclei piped an HTML page into
  `sh`.** `curlInstaller`'s contract is a raw install script, but the `gitleaks` and
  `nuclei` linux entries pointed it at `.../releases/latest`, which redirects to the
  release's HTML tag page. `curl -f` only fails on HTTP error status, so the fetch
  "succeeded" and handed `sh` a full HTML document — a wall of shell syntax errors, not an
  install. Because gitleaks is `default: true`, this sat on a supported path: `check_toolchain`
  printed that broken one-liner as `install_command` for every caller on Linux regardless of
  whether they ever called `install_toolchain`, and an explicit
  `install_toolchain(tools: ["gitleaks"])` (or `["nuclei"]`) actually ran it. The default
  bootstrap flow (`install_toolchain` with no `tools` filter) was unaffected — on Linux it
  delegates to `install-linux.sh`, which resolves gitleaks's real download URL itself — so
  the breakage was reachable only through the per-tool path and through `check_toolchain`'s
  advisory output. Confirmed with `curl -sSIL` rather than assumed: gitleaks and nuclei both
  returned `Content-Type: text/html` on the final `200`, while trivy's and syft's linux
  entries (real `install.sh` scripts on `raw.githubusercontent.com`) returned `text/plain`,
  confirming they were never affected. Both broken entries are removed rather than replaced
  — neither tool ships a stable install script, and a hand-written per-arch downloader would
  be new, unverified machinery — so `pickInstallSpec` now returns `null` for gitleaks and
  nuclei on Linux and both degrade to `manual_steps` / no `install_command`, the same honest
  gap nuclei's win32 entry already relied on. `curlInstaller` now carries a doc comment
  stating the precondition the next caller must meet.

## [1.2.1] — 2026-08-10

### Fixed

- **Marketplace sync failed on Claude Desktop / claude.ai.** The top-level `bin/` directory is now
  `cli/`. Desktop does not clone the repository — it delegates validation to a remote Anthropic
  service, which rejected the plugin with `status=failed_content`: *"Plugin contains a top-level
  bin/ directory ('bin/dev-guardian.mjs'). claude.ai-hosted plugins may not ship bin/ executables
  because they are added to PATH on the CLI but are not shown on the admin approval surface. Declare
  executable entry points via hooks, commands, or mcpServers instead."* The UI surfaced this only as
  **"Marketplace sync failed. Check the repository URL"**, which is misleading — the URL was always
  correct. Installing through the Claude Code CLI was never affected, because it uses a local
  `git clone` and skips this validation, so a passing CLI install is not evidence that Desktop will
  accept the plugin.
- The CLI is now `node cli/dev-guardian.mjs` — same commands (`mcp-config`, `check`), same
  behaviour. References updated in `README.md` (EN/PT/ES), `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`,
  `.cursor/rules/` and every `host-rules/` template.

## [1.2.0] — 2026-07-15

### Added

- **`guardian-grill` — the understanding gate.** A new front-end skill (with
  `/guardian-grill` and the `/gg` alias) that grills *you* on the
  domain-significant decisions a diff/PR introduced before you merge — for the
  long autonomous loops where you no longer read every line. Complements the code
  gates (lint / Semgrep / tests / review): those check the code, this checks that
  a human still understands the branches and rules the AI wrote. Records its
  verdict to `.guardian/last-grill.md` so the status and report gates can show an
  Understanding-gate row. Adapts the `dev-grill` engine when installed, runs the
  loop inline otherwise.
- **`guardian-improve` — from measured debt to improvement specs.** A new skill
  (with `/guardian-improve` and the `/gi` alias) that converts the ROI-ranked
  hotspots, quality-rule violations, oversized files, duplication and coverage
  gaps from the quality gate into metric-anchored **improvement spec seeds**
  (problem → affected files → current metric → target metric → draft EARS
  criteria) ready to hand to `dev-spec-driven`. Closes the loop:
  measure → spec → fix → re-measure. Targets are derived per project from
  `.guardian/budgets.yml`, the stack, or the baseline — never invented.

### Changed

- **`guardian-status`** now shows an **Understanding gate** row from
  `.guardian/last-grill.md` (🟢 / 🟡 / 🔴, or ⚪ when not run for the current diff).
- **`guardian-report`** includes the latest `guardian-grill` verdict in its
  Quality section — a green gate means the metrics passed *and* a human understood
  the change.
- **`guardian-budget`** now also audits code-quality budgets (max file / function
  lines, cyclomatic complexity, duplication %, coverage floor) from
  `.guardian/budgets.yml` — the single source of truth shared by the quality gate
  and `guardian-improve`, proposed per stack.
- README and CLAUDE.md counts updated to **13 skills + 48 slash commands**.

## [1.1.4] — 2026-07-09

### Added

- **Scan coverage trust signal.** Every scan now reports a `coverage` value
  (`full` / `partial` / `none`) derived from which scanners actually ran, so a
  "0 findings" result that scanned nothing can never read as "all clear". At
  coverage `none` a loud warning states plainly that nothing was scanned;
  `audit_executive` rolls up the worst coverage across its sub-scans and
  surfaces each gap. (`tools/scanCoverage.ts`)
- **Semgrep Docker fallback for SAST.** When `semgrep` is not on PATH but a
  Docker daemon is reachable, `scan_sast` runs the official `semgrep/semgrep`
  image (bind-mounted via `--mount` so it tolerates Windows drive letters and
  spaces in the path). A failed container run is recorded as a real coverage
  gap, never a silent empty scan. (`runners/dockerScanner.ts`)
- **`npm audit` findings are now counted.** `deps_audit` parses
  `npm audit --json` (npm 6 and 7+) into Findings, complementing Trivy's CVE
  coverage with GitHub advisories. (`runners/scannerParsers/npmAudit.ts`)

### Fixed

- **No double-counting of the same dependency CVE.** When Trivy already reports
  a package by CVE, the overlapping `npm audit` finding for that package is
  dropped (Trivy is the canonical CVE source); npm findings for packages Trivy
  missed are kept. Stops inflated severity counts from flowing into the
  executive roll-up.
- **An `npm audit` error is no longer treated as a clean scan.** A missing
  lockfile makes npm exit non-zero with an `{ error }` object rather than a
  report — previously counted as a successful "0 findings". It is now recorded
  as a failed auditor and a coverage gap.
- **A missing native auditor is a coverage gap.** When `npm` / `pip-audit` is
  expected (the manifest exists) but absent, it is added to `missing_tools` so
  coverage reflects the gap instead of reporting `full`.

## [1.1.3] — 2026-06-10

### Fixed

- **MCP server now starts on a fresh install — no `npm install` required.** The
  server imported `@modelcontextprotocol/sdk`, `better-sqlite3`, `execa` and
  `zod` as runtime dependencies, but the plugin ships git-first with
  `mcp/node_modules` git-ignored, so the *installed* server crashed on its first
  import with `ERR_MODULE_NOT_FOUND` and none of the 50 MCP tools came up (the
  zero-dependency hooks were unaffected).
  - Replaced the native **`better-sqlite3`** engine with the built-in
    **`node:sqlite`** (`DatabaseSync`), behind a thin adapter in
    `mcp/src/storage/db.ts` (`prepare/run/get/all/exec/pragma` + a nesting-aware
    `transaction`) — no native module to compile or ship.
  - The build now **bundles** `dist/server.js` with esbuild
    (`mcp/scripts/bundle.mjs`), inlining the remaining pure-JS deps, so the
    server runs with **zero** runtime `node_modules`.
  - The server is launched with `--experimental-sqlite` and now requires Node
    **>=22.5**. No change to the MCP tool/resource surface (still 50 tools,
    16 resources); the full test suite now exercises the `node:sqlite` engine.

### Changed

- Removed `better-sqlite3` / `@types/better-sqlite3`; bumped `@types/node` to
  22.x and added `esbuild` as the bundler. Verified the bundled server boots
  from a `node_modules`-free sandbox and lists all 50 tools.

## [1.1.2] — 2026-06-10

### Fixed

- **MCP server now loads when the plugin is enabled.** The plugin manifest
  (`.claude-plugin/plugin.json`) launched the server via the invalid
  `${pluginDir}` placeholder, which Claude Code does not recognise — it rejected
  the config with `Invalid MCP server config for "dev-guardian": Missing
  environment variables: pluginDir` and the 51 MCP tools never came up. Switched
  to the documented **`${CLAUDE_PLUGIN_ROOT}`** placeholder (already used by the
  guardrail hooks). Same fix applied to the docs that quoted the old form
  (`README.md`, `mcp/README.md`, `mcp/src/hostsetup/mcpConfig.ts`). No change to
  the MCP tool/resource surface or plugin behaviour.

## [1.1.1] — 2026-06-07

### Changed

- **Dropped the GitHub Actions CI workflow** (`.github/workflows/ci.yml`).
  dev-guardian is distributed git-first and the maintainer avoids the recurring
  Actions cost, so the quality gates now run **locally**: `npm test`,
  `npm run build` (rebuild `mcp/dist/` before committing — no CI to catch
  drift), markdownlint, the guardrail hooks, and the `dev-guardian check` CLI.
  No npm publishing either (unchanged — never set up). No change to the plugin
  behaviour or the MCP tool/resource surface.

## [1.1.0] — 2026-06-06

### Added

- **Guardrail hooks** (`hooks/hooks.json` + `hooks/guardian-hook.mjs`),
  auto-loaded when the plugin is enabled — **dependency-free** (only `node:`
  builtins + pure compiled detectors; no native modules, so they run in the
  installed plugin where `mcp/node_modules` isn't shipped) and **fail-open**
  (any error → exit 0, never breaks the host):
  - **SessionStart** — briefs the agent with the project's security posture
    (branch, uncommitted changes, last-scan age, init state).
  - **PostToolUse (Write/Edit/MultiEdit/NotebookEdit)** — warns, with a
    **redacted** preview, when freshly written text contains a hard-coded
    secret. The authoritative full scan stays `scan_secrets` (gitleaks).
  - **PreToolUse (Bash)** — denies catastrophic commands by default
    (`rm -rf /`, `curl … | sh`, raw-disk `dd`/`mkfs`, fork bombs); warns on
    risky ones (force-push, hard reset, `sudo`, `chmod 777`).
  - Configurable via `.guardian/hooks.config.json` (opt-in secret-write
    blocking with `secrets.block`), `.guardian/hooks-allowlist.json` for false
    positives, and the `GUARDIAN_HOOKS=off` kill switch.
- `mcp/src/hooks/secretScan.ts` + `bashGuard.ts` — pure, unit-tested detection
  engines (31 new tests) shared by the hooks and the CLI.
- `dev-guardian check` CLI subcommand (`--file <path>` / `--bash "<command>"`,
  `--min`, `--json`) — run the same guardrail detectors from a terminal or CI;
  exit code 1 on a finding.

### Fixed

- The MCP server no longer reports a hard-coded `0.1.0`; it reads its version
  from `.claude-plugin/plugin.json` at startup (falling back to the MCP
  `package.json`), keeping its reported identity in lock-step with the release.
- `mcp/package.json` version aligned with the plugin release (was stale at
  `0.1.0`).

## [1.0.0] — 2026-06-05

First stable release. Everything below was already shipped in 0.x; 1.0.0 marks
the point where the surface is proven and held to semver.

### Added

- **CI pipeline** (GitHub Actions): markdownlint; build + test on Linux, macOS
  and Windows; a dist-sync gate (committed `mcp/dist` must equal a fresh build);
  coverage thresholds; an e2e job running real Semgrep against a vulnerable
  fixture; and a dogfood self-audit (Syft SBOM + gitleaks + Semgrep SARIF).
- **Stability snapshot** — the exact 50 tools + 16 resources are pinned in
  `toolSurface.test.ts`; accidental surface drift fails CI.
- `SECURITY.md` (responsible disclosure), `CONTRIBUTING.md`, this `CHANGELOG.md`.

### Changed

- **First stable release.** The MCP tool/resource surface and default
  behaviours are now covered by semver.

### Fixed

- README counts corrected (44 commands, 16 resources).

## [0.6.0] — 2026-06-05

### Added

- `mcp-config` CLI (`bin/dev-guardian.mjs`) — bootstrap dev-guardian into any AI
  host from a plain terminal, with the absolute server path filled in. Prints a
  paste-ready block or, with `--write`, merges it into the project.
- `mcp/src/hostsetup/setup.ts` — context-free host-setup core (`setupHost`,
  `previewMcpConfig`) shared by the CLI.

### Removed

- **BREAKING:** the `install_host_context` MCP tool. Use the `mcp-config` CLI
  instead. MCP tool count: 51 → 50.

## [0.5.1] — 2026-06-05

### Added

- In-repo AI host configs (dogfooding): `.mcp.json`, `.cursor/`, `.gemini/`,
  `.vscode/`, `.windsurf/`, `.github/copilot-instructions.md`, root `AGENTS.md`
  / `GEMINI.md`, and a `CLAUDE.md` contributor guide. Open the repo in any host
  and the MCP server + rules load out of the box (relative paths).

## [0.5.0] — 2026-06-05

### Added

- Branded Pro Digital Key HTML reports for `report_export` and
  `/guardian-report`: a self-contained shell with a dark/light toggle (system
  default, persisted), 100% offline, print-friendly, and trilingual chrome via
  a `lang` input.

### Changed

- **BREAKING:** `report_export` default format changed from `html` to
  `markdown`. `html` / `sarif` / `json` remain available explicitly.

## [0.4.0] — 2026-06-05

### Added

- Multi-host MCP installer: register the server (merging, never clobbering) plus
  the rules file across Cursor, Windsurf, GitHub Copilot, Cline, Codex CLI,
  Gemini CLI and Claude Desktop. Adds a `GEMINI.md` rules template.

## [0.3.0] — 2026-06-04

### Added

- `scan_skill` — vet a third-party skill / MCP server / agent before install
  (16 threat categories, YARA-style signatures, taint-light, OSV.dev lookups,
  0–100 risk score).

### Fixed

- Ship the compiled `mcp/dist/` so the plugin's MCP server starts without an
  install-time build.

## [0.2.1] — 2026-05-27

### Fixed

- MCP server startup.

## [0.2.0] — 2026-05-27

### Added

- First public release: open-source security / bugfix / quality / deps /
  observability / performance / compliance plugin with an MCP server, SQLite
  state, and trilingual (EN/PT/ES) triggers.

[1.1.0]: https://github.com/linofcp007/dev-guardian/releases/tag/v1.1.0
[1.0.0]: https://github.com/linofcp007/dev-guardian/releases/tag/v1.0.0
[0.6.0]: https://github.com/linofcp007/dev-guardian/releases/tag/v0.6.0
[0.5.1]: https://github.com/linofcp007/dev-guardian/releases/tag/v0.5.1
[0.5.0]: https://github.com/linofcp007/dev-guardian/releases/tag/v0.5.0
[0.4.0]: https://github.com/linofcp007/dev-guardian/releases/tag/v0.4.0
[0.3.0]: https://github.com/linofcp007/dev-guardian/releases/tag/v0.3.0
[0.2.1]: https://github.com/linofcp007/dev-guardian/releases/tag/v0.2.1
[0.2.0]: https://github.com/linofcp007/dev-guardian/releases/tag/v0.2.0
