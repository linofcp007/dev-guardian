/**
 * End-to-end test of the attack-surface pipeline against the in-repo
 * multi-language fixture (`test/fixtures/surface/apps/`).
 *
 * This is the only test in the suite that runs a real Semgrep. Everything else
 * feeds `extractSurface` / `recoverMetavars` hand-written JSON, which proves
 * the code handles the shape it is given but says nothing about whether
 * `configs/semgrep/routes.yml` matches real code. This one exercises the rule
 * pack, the byte-offset metavariable recovery and both resolvers together, so
 * a rule that silently stops matching — or starts matching too much — fails
 * here rather than in a user's repository.
 *
 * ---- When Semgrep is missing ------------------------------------------
 *
 * These tests are SKIPPED, not passed, when Semgrep is not installed:
 * `map_attack_surface` would fall back to Docker, and pulling an image is not
 * something a unit-test runner should do.
 *
 * The distinction is load-bearing and was learned the hard way. This file used
 * to `console.warn` and `return`, which vitest reports as a **passing** test —
 * so on a machine where Semgrep is installed but not on PATH (Windows puts it
 * in `%APPDATA%\Roaming\Python\Python314\Scripts`), the only test that runs a
 * real Semgrep reported green while measuring nothing at all. A Critical
 * route-fabrication defect reached a green suite that way. `it.skipIf` makes the
 * skip visible in the run output as a skip.
 *
 * Set `GUARDIAN_REQUIRE_SEMGREP=1` to turn absence into a hard failure, so at
 * least one gate cannot silently pass:
 *
 *     GUARDIAN_REQUIRE_SEMGREP=1 npm test
 *
 * Use it in any environment that is supposed to have Semgrep — a release check,
 * or a machine where you have just added it to PATH and want proof.
 *
 * ---- Why the fixture is copied out of the repo -------------------------
 *
 * Semgrep's built-in default ignore list skips any path containing a `test/`
 * directory. Pointed straight at `mcp/test/fixtures/surface/apps` it scans zero
 * files and reports zero routes — a green-looking pass that measures nothing
 * (evalVulnFixture.test.ts hit exactly this and works around it the same way).
 * So the tree is copied to a temp directory whose path contains no `test`
 * segment, and the tool runs against that.
 *
 * ---- Why an explicit route set, not a count ----------------------------
 *
 * A count assertion passes when one rule breaks and another over-matches by
 * the same amount — which is precisely the failure mode this fixture exists to
 * catch. Every route is therefore pinned by framework, method, resolved path
 * and `path_partial`, and the comparison is an equality on the whole sorted
 * set, so an extra route fails just as loudly as a missing one.
 */

import { cpSync, existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';

import type { PluginContext } from '../../src/context.js';
import { languageFromPath } from '../../src/surface/extract.js';
import { invokeSemgrep } from '../../src/surface/scanSemgrep.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { Storage } from '../../src/storage/index.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { ensureReportDir, readJsonSafe } from '../../src/tools/scanHelpers.js';
import { TOOLS } from '../../src/tools/index.js';
import '../../src/tools/mapAttackSurface.js';
import type { AttackSurfaceSnapshot, RouteRecord, SpecDiffEntry } from '../../src/types.js';
import { okResult } from '../helpers/toolResult.js';
import { makeTempDir, cleanupTempDirs } from '../helpers/tempDir.js';
import { isInstalled } from '../helpers/toolchain.js';

afterAll(cleanupTempDirs);

const here = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(here, '..', '..', '..');
const FIXTURE = resolve(here, '..', 'fixtures', 'surface', 'apps');
const ANNOTATION_FIXTURE = resolve(here, '..', 'fixtures', 'surface', 'annotations');
const FRAMEWORK_FIXTURE = resolve(here, '..', 'fixtures', 'surface', 'frameworks');
const SCRIPTS_DIR = resolve(ROOT, 'scripts');
const RULES_PATH = resolve(ROOT, 'configs', 'semgrep', 'routes.yml');

/**
 * `framework method path_resolved` plus a `[partial]` marker.
 *
 * The framework is part of the key on purpose: it names the rule that produced
 * the route, so a route that survives because a *different* rule started
 * matching it still fails the comparison.
 */
function describeRoute(route: RouteRecord): string {
  return `${route.framework} ${route.method} ${pathLabel(route)}${route.path_partial ? ' [partial]' : ''}`;
}

/**
 * An empty own-path reads as `<inherited>` rather than as nothing at all.
 *
 * A route from a bare `@Get()` / `[HttpGet]` / `@GetMapping` has no path of
 * its own — the served URL is the class-level prefix — so where that prefix is
 * not resolved (NestJS always; Spring and ASP.NET when the class gives none we
 * can read) `path_resolved` is the empty string by design (see the
 * "annotation with no path of its own" section of configs/semgrep/routes.yml).
 * Interpolated raw, that produces a row with two spaces in it, which reads as
 * a typo and invites someone to "fix" the expected value rather than the rule.
 */
function pathLabel(route: RouteRecord): string {
  return route.path_resolved === '' ? '<inherited>' : route.path_resolved;
}

/** Same shape as the file's existing `describeRoute`, for diff entries. */
function describeDiffEntry(e: SpecDiffEntry): string {
  return `${e.method} ${e.path}`;
}

/* The surface of test/fixtures/surface/apps/, verified capture-by-capture
   against Semgrep 1.86.0 (which still emits `extra.metavars`) and reproduced
   through the byte-offset recovery on 1.164.0 (which redacts them).

   Still split in two, but no longer because the answer depends on the Semgrep
   version — it does not, and this file now asserts that. See FOCUSED_ROUTES. */
const BASE_ROUTES = [
  // ---- ASP.NET minimal API. `/stats` is registered on a MapGroup("/admin")
  // builder; route groups are not resolved, so it is reported at the path the
  // registration itself names.
  'aspnet-minimal DELETE /minimal/orders/{id}',
  'aspnet-minimal GET /minimal/health',
  'aspnet-minimal GET /stats',
  'aspnet-minimal POST /minimal/orders',
  // ---- Django. The computed path survives as a route and is flagged, never
  // resolved; the regex route is flagged too, because a regex is not a URL.
  // Nothing from py-django/helpers.py, whose local `path()` helper is bait.
  //
  // `django/api/` is deliberately ABSENT. It is the fixture's
  // `path("django/api/", include("api.urls"))` — a mount point, not an
  // endpoint: Django serves what the included module declares, and the prefix
  // itself normally is not one of them. It used to be reported as an ordinary
  // route at `confidence: medium`, `path_partial: false`, i.e. handed on as a
  // path we verified. Nothing is lost by the exclusion — mount resolution is
  // Node-only, so the included module's routes were never prefixed with it
  // either way. See the `pattern-not` on `guardian-route-django`.
  'django ANY django/orders/',
  'django ANY django/orders/<int:order_id>/',
  // Python raw string, kept whole. `stripQuotes` removes only a MATCHED pair,
  // so the closing quote of `r"…"` is no longer chopped off on its own — the
  // raw text a human reads is now complete. Still partial: a regex is not a URL.
  'django ANY r"^django/legacy/(?P<slug>[\\w-]+)/$" [partial]',
  'django ANY settings.ADMIN_URL [partial]',
  // ---- Express. The four mounted routes carry their mount prefix; the two
  // declared in the mounting file itself do not.
  'express DELETE /api/users/:id',
  'express GET /admin/reports',
  'express GET /api/users/list',
  'express GET /health',
  'express POST /api/users/create',
  'express POST /login',
  // node-mount-forms/ is DELIBERATELY absent from this array. Its two routes
  // (a router bound by a named import, one by a namespace import, each
  // mounted) resolve differently depending on whether Semgrep reports real
  // metavariables — see the `redacting`-conditioned assertion inside "maps
  // every route the fixture declares, and nothing else" below, and
  // guardian-import-esm's comment in routes.yml for the mechanism. Folding
  // either possible value in here would contradict this array's own
  // promise, two lines up, of ONE expected set on any Semgrep version.
  'fastapi DELETE /fastapi/items/{item_id}',
  'fastapi GET /fastapi/items',
  'fastapi POST /fastapi/items',
  // ---- Flask. @app.route carries no verb, and the pack does not read
  // `methods=[...]`, so ANY is the honest answer.
  'flask ANY /flask/health',
  'flask ANY /flask/items/<int:item_id>',
  'gin DELETE /gin/items/:id',
  'gin GET /gin/ping',
  'gin POST /gin/items',
  'net-http ANY /go/health',
  'net-http ANY /go/orders',
  'laravel DELETE /laravel/orders/{order}',
  'laravel GET /laravel/orders',
  'laravel PATCH /laravel/orders/{order}/status',
  'laravel POST /laravel/orders',
  'laravel PUT /laravel/orders/{order}',
  // ---- Rails. Both the bare form and the `to:` form; nothing from
  // rb-rails/cache_warmer.rb, whose `Rails.cache.delete 'orders/index'` is the
  // shape `$METHOD $PATH` would over-match on.
  'rails DELETE /rails/orders/:id',
  'rails GET /rails/orders',
  'rails GET /rails/orders/:id',
  'rails POST /rails/orders',
  // ---- Spring. @RequestMapping declares no verb, so the method-level one is
  // reported as ANY.
  //
  // The six Spring rules are focused on $PATH now — for a reason of their own
  // (a named annotation argument, see routes.yml's Java section), not the
  // declaration-spanning one FOCUSED_ROUTES below is about — so their rows
  // stay here rather than moving.
  //
  // Every one carries the class-level `@RequestMapping("/spring/orders")`,
  // resolved: the controller is a concrete @RestController with one literal
  // prefix, joined by resolvers/classPrefix.ts. 3.6.1 reported them all
  // [partial] at the method's own path (`GET /list`), and the class-level
  // annotation itself as a route, `ANY /spring/orders` — a prefix, which
  // serves nothing; that row is gone, and no rule matches a type-level
  // @RequestMapping any more.
  'spring ANY /spring/orders/legacy',
  'spring DELETE /spring/orders/{id}',
  'spring GET /spring/orders/list',
  // `@GetMapping(value = "/named", produces = "application/json")`. This one
  // was pinned in java-spring/OrderController.java as a KNOWN LIMITATION —
  // "the named-argument form is not matched" — on the strength of
  // `@GetMapping($PATH, ...)` being an invalid Java pattern. The ellipsis is
  // rejected only after a bare metavariable; `(value = $PATH, ...)` parses.
  'spring GET /spring/orders/named',
  'spring PATCH /spring/orders/{id}/status',
  'spring POST /spring/orders/create',
  'spring PUT /spring/orders/{id}',
  // ---- WordPress. The literal namespace resolves to the served /wp-json
  // path; the `self::NAMESPACE` one cannot, and is flagged rather than
  // concatenated into a URL that exists nowhere.
  'wp-rest ANY /items/(?P<id>\\d+) [partial]',
  'wp-rest ANY /wp-json/guardian/v1/items',
].sort();

/**
 * The 21 routes from the three families whose Semgrep pattern must span the
 * decorated declaration: actix, NestJS and ASP.NET attribute routing.
 *
 * These were absent on a redacting Semgrep for four rounds. The reported span
 * started at whatever attribute came first, and every attempt to find the route
 * attribute inside it fabricated paths, so `surface/recoverMetavars.ts` refused
 * them outright and `coverage` reported `unreadable` for their languages.
 *
 * They now declare `focus-metavariable: $PATH`, which makes Semgrep narrow its
 * own reported range to the path literal — so they recover on every version and
 * are part of the one expected set below, not a version-dependent addendum.
 *
 * The fixture files for all three carry deliberate decoys (a commented-out old
 * route, anchor text inside a string, attribute-shaped text in a method body).
 * The assertion that matters most in this file is that NONE of those decoys
 * ever appears as a route: earlier reconstructions emitted them as resolved
 * paths, which is the failure this whole tool exists to prevent.
 */
const FOCUSED_ROUTES = [
  'actix DELETE /rust/items/{id}',
  'actix GET /rust/documented',
  'actix GET /rust/gated',
  'actix GET /rust/health',
  'actix PATCH /rust/items/{id}/status',
  'actix POST /rust/items',
  'actix PUT /rust/items/{id}',
  'aspnet DELETE /aspnet/orders/{id}',
  'aspnet GET /aspnet/orders',
  'aspnet GET /aspnet/orders/audit',
  'aspnet GET /aspnet/orders/{id}',
  'aspnet PATCH /aspnet/orders/{id}/status',
  'aspnet POST /aspnet/orders',
  'aspnet PUT /aspnet/orders/{id}',
  'nestjs DELETE :id [partial]',
  'nestjs DELETE purge/:id [partial]',
  'nestjs GET :id [partial]',
  'nestjs GET audit/:id [partial]',
  'nestjs PATCH :id/status [partial]',
  'nestjs POST /create [partial]',
  'nestjs PUT :id [partial]',
].sort();

/**
 * The two routes this tree declares with a bare annotation — `@Get()` in
 * node-nest/users.controller.ts and `[HttpGet]` in
 * dotnet-api/OrdersController.cs.
 *
 * Both files USED to carry a comment saying the pack does not report them
 * ("No argument: there is no path to capture"), which described the defect
 * rather than a decision: `@Get()` is what docs.nestjs.com uses for an index
 * action and `[HttpGet]` is what `dotnet new webapi` scaffolds, so a real
 * controller loses its collection endpoints entirely and says nothing about
 * it. They are reported, and their full URL is the class-level prefix:
 * `[HttpGet]` under `[Route("api/orders")]` is served at `/api/orders` and
 * resolved there (resolvers/classPrefix.ts), while NestJS's controller prefix
 * is not followed, so `@Get()` keeps an empty own-path at `path_partial:
 * true`. `test/fixtures/surface/annotations/` is where that behaviour is
 * pinned in depth; these two rows are here so this tree's own set stays exact.
 */
const INHERITED_ROUTES = [
  'aspnet GET /api/orders',
  'nestjs GET <inherited> [partial]',
].sort();

/**
 * The whole expected surface — one set, on any Semgrep version.
 *
 * That it no longer forks on the version is the point of the focus change, so
 * the tests below assert the version-independence explicitly rather than
 * letting a single-version run imply it.
 */
const EXPECTED_ROUTES = [...BASE_ROUTES, ...FOCUSED_ROUTES, ...INHERITED_ROUTES].sort();

/**
 * node-mount-forms/'s two routes, held out of EXPECTED_ROUTES because their
 * resolution is genuinely Semgrep-version-dependent (see the "maps every
 * route..." test below and guardian-import-esm's comment in routes.yml).
 * The count is version-independent even though the resolved paths are not —
 * both routes exist on every Semgrep version, only their `path_partial`
 * differs — so `routes_total` can still be asserted exactly.
 */
const MOUNT_FORM_ROUTE_COUNT = 2;

/** Paths that must NEVER appear: every decoy planted in the fixture. */
const FABRICATION_DECOYS = [
  'dead_code',
  '/rust/legacy',
  'application/json',
  '/aspnet/orders/legacy',
  '/aspnet/FABRICATED',
  '204',
  'legacy/:id',
  'audit/FABRICATED',
];

/**
 * The exact set of Semgrep languages (javascript and typescript counted
 * separately, matching `languageFromPath` and the route-coverage assertion
 * below) with at least one `guardian_kind: import` match in the fixture —
 * all nine, one per `configs/semgrep/routes.yml` import rule.
 *
 * A SET, not a count: a count passes when one language's rule silently stops
 * matching while an unrelated one over-matches by the same amount — the
 * exact failure this fixture exists to catch (see the module comment). Each
 * language's presence is checked independently here, so a rule that goes
 * quiet cannot be masked by another rule matching more than it should.
 */
const EXPECTED_IMPORT_LANGUAGES = [
  'csharp',
  'go',
  'java',
  'javascript',
  'php',
  'python',
  'ruby',
  'rust',
  'typescript',
].sort();

/**
 * The code-vs-spec diff produced against `openapi.yaml` sitting alongside
 * the fixture app tree (see that file's own comments for which three
 * intentions each path serves).
 *
 * `EXPECTED_SHADOW` is every non-partial route in `EXPECTED_ROUTES` that
 * `openapi.yaml` does not document — not just the one route called out by
 * name in the fixture's comment, but the whole remainder, because the
 * diff itself is asserted as an exact set (see the module comment on "why
 * an explicit route set, not a count"). `EXPECTED_DEAD` is the one path
 * `openapi.yaml` declares that no code route implements.
 *
 * Filled from the tool's own output, then checked entry-by-entry against
 * `EXPECTED_ROUTES` and `openapi.yaml` before being kept here — see Task 7
 * step 3: pasting output in without reading it is how a wrong result
 * becomes a regression test.
 */
const EXPECTED_SHADOW = [
  // No `ANY /django/api`: the `include()` mount point is no longer reported as
  // a route at all, so it cannot be an undocumented one. See EXPECTED_ROUTES.
  'ANY /django/orders',
  'ANY /django/orders/{}',
  'ANY /flask/health',
  'ANY /flask/items/{}',
  'ANY /go/health',
  'ANY /go/orders',
  // The Spring and ASP.NET class-prefixed routes, resolved since the class
  // prefix is joined, and undocumented in openapi.yaml like the rest.
  'ANY /spring/orders/legacy',
  'ANY /wp-json/guardian/v1/items',
  'DELETE /api/users/{}',
  'DELETE /aspnet/orders/{}',
  'DELETE /fastapi/items/{}',
  'DELETE /gin/items/{}',
  'DELETE /laravel/orders/{}',
  'DELETE /minimal/orders/{}',
  'DELETE /rails/orders/{}',
  'DELETE /rust/items/{}',
  'DELETE /spring/orders/{}',
  'GET /admin/reports',
  'GET /api/orders',
  'GET /api/users/list',
  'GET /aspnet/orders',
  'GET /aspnet/orders/audit',
  'GET /aspnet/orders/{}',
  'GET /fastapi/items',
  'GET /laravel/orders',
  'GET /minimal/health',
  // Newly extracted (the Spring named-argument form) and undocumented in
  // openapi.yaml, so it is a shadow endpoint like every other route here.
  'GET /rails/orders',
  'GET /rails/orders/{}',
  'GET /rust/documented',
  'GET /rust/gated',
  'GET /rust/health',
  'GET /spring/orders/list',
  'GET /spring/orders/named',
  'GET /stats',
  'PATCH /aspnet/orders/{}/status',
  'PATCH /laravel/orders/{}/status',
  'PATCH /rust/items/{}/status',
  'PATCH /spring/orders/{}/status',
  'POST /api/users/create',
  'POST /aspnet/orders',
  'POST /fastapi/items',
  'POST /gin/items',
  'POST /laravel/orders',
  'POST /minimal/orders',
  'POST /rails/orders',
  'POST /rust/items',
  'POST /spring/orders/create',
  'PUT /aspnet/orders/{}',
  'PUT /laravel/orders/{}',
  'PUT /rust/items/{}',
  'PUT /spring/orders/{}',
].sort();

const EXPECTED_DEAD = ['GET /deprecated/v0/orders'];


/**
 * Resolved once, at collection time, so `it.skipIf` can report a skip as a
 * skip rather than each test deciding for itself and returning early.
 */
const FIXTURE_PRESENT =
  existsSync(FIXTURE) && existsSync(ANNOTATION_FIXTURE) && existsSync(FRAMEWORK_FIXTURE);
const SEMGREP_INSTALLED = await isInstalled('semgrep');
const SEMGREP_AVAILABLE = FIXTURE_PRESENT && SEMGREP_INSTALLED;
const REQUIRE_SEMGREP = process.env['GUARDIAN_REQUIRE_SEMGREP'] === '1';

function makeContext(): PluginContext {
  const db = new Database(':memory:');
  runMigrations(db);
  return {
    storage: new Storage(db),
    shell: null,
    scriptsDir: SCRIPTS_DIR,
    progressNotifier: { send: () => {} } as unknown as PluginContext['progressNotifier'],
  };
}

interface SurfaceResult {
  ok: boolean;
  routes_total: number;
  snapshot_id: number | null;
  coverage: { language: string; routes_found: number; status: string }[];
  env_vars_total: number;
  ports: { port: number; source: string }[];
  webhooks_total: number;
  tools_run: { name: string; status: string; reason?: string }[];
}

describe('E2E — attack-surface rule pack against the multi-language fixture', () => {
  // Present in every run so the gate itself is visible; only *executed* when
  // the caller has asked for it. Without this, "Semgrep is missing" and
  // "Semgrep ran and agreed" are indistinguishable in the suite output.
  it.runIf(REQUIRE_SEMGREP)('GUARDIAN_REQUIRE_SEMGREP=1 — this suite must be runnable', () => {
    // Two distinct reasons the suite can be skipped; saying "check your PATH"
    // when the fixture tree is missing sends the reader the wrong way.
    expect(
      SEMGREP_INSTALLED,
      'GUARDIAN_REQUIRE_SEMGREP=1 but semgrep is not on PATH, so the only test that ' +
        'exercises the real rule pack would have been skipped. On Windows it is usually ' +
        'in %APPDATA%\\Roaming\\Python\\Python3xx\\Scripts.',
    ).toBe(true);
    expect(
      FIXTURE_PRESENT,
      `GUARDIAN_REQUIRE_SEMGREP=1 but the fixture tree is missing at ${FIXTURE}.`,
    ).toBe(true);
  });

  it.skipIf(!SEMGREP_AVAILABLE)('maps every route the fixture declares, and nothing else', async () => {
    // Outside any `test/` path — see the module comment.
    const work = makeTempDir('guardian-rulepack-');
    cpSync(FIXTURE, work, { recursive: true });

    const ctx = makeContext();
    const tool = TOOLS.find((t) => t.name === 'map_attack_surface');
    expect(tool).toBeDefined();
    if (!tool) return;

    const result = okResult<SurfaceResult>(
      await tool.handler({ project_path: work, force: true }, ctx),
    );

    // A degraded run persists nothing and returns snapshot_id: null. Fail here
    // rather than on an empty route set, whose message would not say why.
    expect(result.tools_run.map((t) => `${t.name}:${t.status}`)).toContain('semgrep:ok');
    expect(result.snapshot_id).not.toBeNull();
    const snapshotId = result.snapshot_id;
    if (snapshotId === null) return;

    const snapshot: AttackSurfaceSnapshot | undefined =
      ctx.storage.surface.getById(snapshotId)?.snapshot;
    expect(snapshot).toBeDefined();
    if (!snapshot) return;

    // `redacting` is true on any Semgrep >= ~1.120 without `semgrep login`.
    // Named explicitly so a regression reads as what it is, and reused below
    // for the one pair of routes this fixture cannot make version-independent.
    const redacting = result.tools_run.some((t) => t.name === 'semgrep-metavar-recovery');

    // ONE expected set, whichever Semgrep is installed. This used to fork on
    // whether match content was redacted, because the three decorated-
    // declaration families were then absent; `focus-metavariable: $PATH` makes
    // Semgrep report a span that is the path itself, so they recover either way.
    // The fork is deliberately gone rather than made version-aware — a test that
    // accepts two answers cannot notice one of them silently becoming wrong.
    //
    // Code routes only: the fixture tree now also carries `openapi.yaml` (see
    // that file), whose imported routes land in `snapshot.routes` too, tagged
    // `provenance: 'spec'`. EXPECTED_ROUTES is the code-extracted surface, so
    // the comparison filters to `'code'` the same way `routes_total` does.
    //
    // node-mount-forms/ is excluded here and asserted separately below: unlike
    // every other route in this fixture, its resolution genuinely cannot be
    // made version-independent without touching resolvers/node.ts or
    // recoverMetavars.ts (out of scope — see guardian-import-esm's comment in
    // routes.yml), so folding it into a "same on any version" array would be
    // exactly the silent-wrongness risk the paragraph above warns about.
    const isMountForm = (r: RouteRecord): boolean => r.file.includes('node-mount-forms');
    const actual = snapshot.routes
      .filter((r) => r.provenance === 'code' && !isMountForm(r))
      .map(describeRoute)
      .sort();
    expect(actual).toEqual(EXPECTED_ROUTES);
    expect(result.routes_total).toBe(EXPECTED_ROUTES.length + MOUNT_FORM_ROUTE_COUNT);

    expect(FOCUSED_ROUTES.every((r) => actual.includes(r)), `redacting=${redacting}`).toBe(true);
    expect(FOCUSED_ROUTES).toHaveLength(21);

    // The Semgrep-version-dependent pair, pinned exactly rather than merely
    // documented: on a redacting Semgrep (this project's actual pipeline)
    // BOTH resolve, each by a different coincidence in pre-existing,
    // untouched code (recoverMetavars.ts's synthesizeMount truncates
    // "ns.router" to "ns", and never sees Semgrep's own constant-propagation
    // doubling of a destructured name at all, since recovery slices raw
    // bytes instead of reading `abstract_content`). On a Semgrep reporting
    // real metavariables NEITHER resolves — verified via
    // `docker run semgrep/semgrep:1.86.0` against this exact fixture file
    // (see the fix report): the named case's $ROUTER doubles to
    // "namedRouter namedRouter" and the namespace case's is the whole
    // "ns.router" expression, so buildPrefixIndex's exact-string match fails
    // for both and each route stays at its raw, unprefixed path.
    const mountFormActual = snapshot.routes
      .filter((r) => r.provenance === 'code' && isMountForm(r))
      .map(describeRoute)
      .sort();
    const mountFormExpected = (
      redacting
        ? ['express GET /named/status', 'express GET /ns/ns-status']
        : ['express GET /ns-status [partial]', 'express GET /status [partial]']
    ).sort();
    expect(mountFormActual, `redacting=${redacting}`).toEqual(mountFormExpected);

    // The load-bearing assertion. Every decoy planted in the fixture — a
    // commented-out old route, anchor text inside a string, attribute-shaped
    // text in a method body — must be absent. Two earlier reconstructions
    // emitted them as RESOLVED paths while the real route vanished.
    for (const decoy of FABRICATION_DECOYS) {
      expect(
        snapshot.routes.filter((r) => r.path_resolved.includes(decoy)),
        `fabricated route containing ${decoy}`,
      ).toEqual([]);
    }
  }, 6 * 60_000);

  it.skipIf(!SEMGREP_AVAILABLE)(
    'matches an import in every one of the nine languages, and parses without a rule error',
    async () => {
      // Runs the rule pack directly against the fixture — the same technique
      // as the plan's manual validation command — rather than through
      // map_attack_surface: this test pins the RULE PACK's raw matching
      // behaviour only (every language produces at least one
      // guardian_kind:import match, and no rule fails to parse), independent
      // of extraction and resolution. Imports ARE part of the persisted
      // snapshot shape as of Task 3b (AttackSurfaceSnapshot.imports) — see
      // 'reports env vars, ports and per-language coverage from the same
      // run' below, which exercises extraction, resolution and persistence
      // together through the real map_attack_surface tool.
      const work = makeTempDir('guardian-rulepack-import-');
      cpSync(FIXTURE, work, { recursive: true });
      const reportDir = ensureReportDir(work, 'import-rule-check', 'surface');
      const outFile = join(reportDir, 'surface.json');

      const invocation = await invokeSemgrep({
        projectPath: work,
        rulesPath: RULES_PATH,
        outFile,
        reportDir,
      });
      expect(invocation).not.toBeNull();
      if (invocation === null) return;
      expect(invocation.toolRun.status, invocation.toolRun.reason).toBe('ok');

      const raw = readJsonSafe(outFile);
      expect(raw).not.toBeNull();
      if (raw === null) return;
      const parsed = JSON.parse(raw) as {
        results: { path: string; extra: { metadata: { guardian_kind?: string } } }[];
        errors: { level: string }[];
      };

      // The bar from item 1's five-NestJS-rules incident: a rule that fails
      // to parse matches nothing on every run while the suite stays green.
      // `level: 'warn'` is tolerated — the one pre-existing entry here is a
      // PartialParsing note on php-wordpress/rest-controller.php's
      // `const NAMESPACE` (see that file's own comment), unrelated to any
      // import rule. `level: 'error'` — a genuine rule parse error, like the
      // one Rust's `use $MODULE::{ ..., $SYMBOL, ... };` produced during this
      // rule's own development — is not.
      const hardErrors = parsed.errors.filter((e) => e.level === 'error');
      expect(hardErrors, JSON.stringify(hardErrors)).toEqual([]);

      const languages = new Set(
        parsed.results
          .filter((r) => r.extra.metadata.guardian_kind === 'import')
          .map((r) => languageFromPath(r.path)),
      );
      expect([...languages].sort()).toEqual(EXPECTED_IMPORT_LANGUAGES);
    },
    6 * 60_000,
  );

  // Controller ruling on I3: php-wordpress/rest-controller.php's
  // `const NAMESPACE` is legal PHP that current Semgrep only partly parses
  // (a warn-level PartialParsing entry). That is partial coverage, not a
  // failed scan: the snapshot persists, Semgrep reads ok with a named gap,
  // and the warned file is listed. Refusing the whole snapshot left
  // scan_dast probing nothing on real WordPress projects.
  it.skipIf(!SEMGREP_AVAILABLE)(
    'a warn-level PartialParsing file: the snapshot persists as partial and names the file',
    async () => {
      const work = makeTempDir('guardian-rulepack-wp-');
      cpSync(join(FIXTURE, 'php-wordpress'), work, { recursive: true });
      const ctx = makeContext();
      const tool = TOOLS.find((t) => t.name === 'map_attack_surface');
      if (!tool) throw new Error('map_attack_surface is not registered');

      const result = okResult<
        SurfaceResult & {
          missing_tools: string[];
          partially_parsed?: Array<{ file: string; type: string; message: string }>;
        }
      >(await tool.handler({ project_path: work, force: true }, ctx));

      const semgrep = result.tools_run.find((t) => t.name === 'semgrep');
      expect(semgrep?.status, semgrep?.reason).toBe('ok');
      expect(semgrep?.reason).toMatch(/^partial: 1 file\(s\) only partly parsed/);
      expect(result.missing_tools).toEqual(['semgrep']);
      expect(result.partially_parsed).toEqual([
        expect.objectContaining({ file: 'rest-controller.php', type: 'PartialParsing' }),
      ]);
      expect(result.snapshot_id).not.toBeNull();
      const snapshotId = result.snapshot_id;
      if (snapshotId === null) return;
      const snapshot = ctx.storage.surface.getById(snapshotId)?.snapshot;
      expect(snapshot?.partially_parsed?.map((p) => p.file)).toEqual(['rest-controller.php']);
      // Both register_rest_route() calls still match — the literal one resolved.
      expect(snapshot?.routes.map((r) => r.path_resolved)).toContain('/wp-json/guardian/v1/items');
    },
    6 * 60_000,
  );

  it.skipIf(!SEMGREP_AVAILABLE)('reports env vars, ports and per-language coverage from the same run', async () => {
    const work = makeTempDir('guardian-rulepack-');
    cpSync(FIXTURE, work, { recursive: true });

    const ctx = makeContext();
    const tool = TOOLS.find((t) => t.name === 'map_attack_surface');
    if (!tool) throw new Error('map_attack_surface is not registered');

    const result = okResult<SurfaceResult>(
      await tool.handler({ project_path: work, force: true }, ctx),
    );
    const snapshotId = result.snapshot_id;
    expect(snapshotId).not.toBeNull();
    if (snapshotId === null) return;
    const snapshot = ctx.storage.surface.getById(snapshotId)?.snapshot;
    if (!snapshot) throw new Error('snapshot was not persisted');

    // Go's os.Getenv is deliberately absent: no `env` rule covers Go, and the
    // pack would rather under-report than pretend to.
    expect(snapshot.env_vars.map((v) => v.name).sort()).toEqual([
      'API_TOKEN',
      'APP_ENV',
      'DATABASE_URL',
      'LOG_LEVEL',
      'PORT',
      'SESSION_SECRET',
      'SQL_CONNECTION',
      'WP_API_KEY',
    ]);

    expect(snapshot.ports).toEqual([{ port: 8080, source: 'Dockerfile' }]);
    expect(snapshot.webhooks).toEqual([]);

    // Semgrep matched routes in all nine languages, and every one of them is now
    // READ — `ok`, on any Semgrep version. Never `no_matches`, which a consumer
    // reads as "this language exposes nothing"; never `no_rules`, which would
    // mean a rule family stopped firing; and no longer `unreadable` either.
    const matched = snapshot.coverage.filter(
      (c) => c.routes_found > 0 || c.unreadable_matches > 0,
    );
    expect(matched.map((c) => c.language).sort()).toEqual([
      'csharp',
      'go',
      'java',
      'javascript',
      'php',
      'python',
      'ruby',
      'rust',
      'typescript',
    ]);
    expect(matched.every((c) => c.status === 'ok')).toBe(true);
    expect(snapshot.coverage.every((c) => c.unreadable_matches === 0)).toBe(true);

    // Rust and TypeScript are the sharpest cases: every route the fixture
    // declares in them comes from actix / NestJS, the families that were
    // refused. Both reported `unreadable` with zero routes on a redacting
    // Semgrep — a Rust web service described as exposing nothing readable.
    // They now report their routes on either version.
    const redacting = result.tools_run.some((t) => t.name === 'semgrep-metavar-recovery');
    for (const language of ['rust', 'typescript', 'csharp']) {
      const entry = snapshot.coverage.find((c) => c.language === language);
      expect(entry?.status, `${language} coverage status (redacting=${redacting})`).toBe('ok');
      expect(entry?.routes_found, `${language} routes_found`).toBeGreaterThan(0);
      expect(entry?.unreadable_matches, `${language} unreadable_matches`).toBe(0);
    }

    // Task 3b: AttackSurfaceSnapshot.imports, exercised through the real
    // tool rather than moduleEdges.ts's own unit tests — this is the only
    // place that verifies buildSnapshot actually calls extractModuleEdges /
    // resolveModuleEdges, unions scannedFiles with the match-bearing file
    // set, and reaches persistence. An explicit set, not a count, for the
    // same reason EXPECTED_ROUTES is above: a resolver that silently drops
    // or duplicates an edge changes this list's shape, not just its length.
    const importEdges = snapshot.imports
      .map((e) => `${e.file} -> ${e.module_file}`)
      .sort();
    expect(importEdges).toEqual([
      // One resolvable intra-project import per non-JS resolvable language.
      // Until these three existed, EVERY edge in this list was JS/TS — the
      // one family whose resolver anchors on the importing file's own path
      // and therefore kept working when the whole module-edge stage was fed
      // absolute paths while building project-relative candidates. Python,
      // Go and Rust silently resolved nothing in production, and this list
      // could not tell: it had nothing in them to lose. Removing any of
      // these three re-hides that entire class of defect.
      'go-api/main.go -> go-api/pkg/util/shout.go',
      'node-express/server.js -> node-express/routes/users.js',
      'node-legacy/app.js -> node-legacy/admin-router.js',
      // The CommonJS destructuring-require form (`const { $SYMBOL, ... } =
      // require("$MODULE")`), guardian-import-esm's counterpart to the ESM
      // named-import alternative right above it in routes.yml. Absent before
      // that alternative existed — a destructuring require produced NO
      // guardian_kind:import match at all, not merely an unresolved one.
      'node-legacy/app.js -> node-legacy/format-utils.js',
      'node-mount-forms/app.js -> node-mount-forms/named-router.js',
      'node-mount-forms/app.js -> node-mount-forms/ns-router.js',
      // Task 6's three-hop chain for validate_finding's e2e test — see
      // slug.util.ts's doc comment. node-nest/orphan.util.ts deliberately
      // contributes NO edge (neither side): that absence is the point.
      'node-nest/identifiers.util.ts -> node-nest/slug.util.ts',
      'node-nest/users.controller.ts -> node-nest/users.service.ts',
      'node-nest/users.service.ts -> node-nest/identifiers.util.ts',
      'py-fastapi/main.py -> pylib/textutil.py',
      // `crate::`-anchored, not `self::`: the anchor is derived from the
      // specifier alone (Cargo's `src/` crate root), so unlike an anchor
      // taken from the importing file's own path it cannot survive being
      // resolved in the wrong path space. Both a route file and a non-route
      // file contribute one.
      'rust-actix/config.rs -> src/settings.rs',
      'rust-actix/main.rs -> src/settings.rs',
    ]);

    // The same three, stated as the property that matters rather than as
    // membership of the list above: each of Python, Go and Rust resolved at
    // least one edge. This is the assertion the coverage gate in
    // `validate/staticProvider.ts` is the runtime counterpart of — a language
    // with zero resolved edges cannot certify that nothing imports a file.
    for (const language of ['python', 'go', 'rust']) {
      const resolvedInLanguage = snapshot.imports.filter(
        (e) => languageFromPath(e.file) === language,
      );
      expect(resolvedInLanguage.length, `${language} resolved import edges`).toBeGreaterThan(0);
    }

    // Concern 1 of the Task 3b report: snapshot.imports must be
    // project-relative POSIX (unlike routes[].file, which stays absolute
    // and native-separator — a separate, pre-existing inconsistency).
    // Pinning it here through the real tool is what stops the
    // toRelativeIfPossible call in buildSnapshot silently reverting.
    for (const entry of [...snapshot.imports]) {
      expect(entry.file, entry.file).not.toMatch(/^[A-Za-z]:/);
      expect(entry.file, entry.file).not.toContain('\\');
      expect(entry.module_file, entry.module_file).not.toMatch(/^[A-Za-z]:/);
      expect(entry.module_file, entry.module_file).not.toContain('\\');
    }

    // java/csharp/ruby/php can never resolve an import (the design of record) —
    // every guardian_kind:import match the rule pack produced for them (the
    // "matches an import in every one of the nine languages" test above
    // proves each language matched at least one) must land in
    // unresolved_imports, not vanish silently.
    for (const language of ['java', 'csharp', 'ruby', 'php']) {
      const entry = snapshot.coverage.find((c) => c.language === language);
      expect(entry?.unresolved_imports, `${language} unresolved_imports`).toBeGreaterThan(0);
    }
  }, 6 * 60_000);

  it.skipIf(!SEMGREP_AVAILABLE)('recovers the captures Semgrep redacts, or says so in tools_run', async () => {
    const work = makeTempDir('guardian-rulepack-');
    cpSync(FIXTURE, work, { recursive: true });

    const ctx = makeContext();
    const tool = TOOLS.find((t) => t.name === 'map_attack_surface');
    if (!tool) throw new Error('map_attack_surface is not registered');

    const result = okResult<SurfaceResult>(
      await tool.handler({ project_path: work, force: true }, ctx),
    );

    // Either Semgrep emitted metavariables (older / logged-in) and there is no
    // recovery entry at all, or it redacted them — in which case every family
    // was rebuilt from byte offsets and the step reports `ok` with no losses.
    // A loss here would now mean a genuinely unreadable file, not a rule family
    // we decline to reconstruct; it stays legitimate but must never be SILENT,
    // so the entry still has to name the count and the remedy.
    const recovery = result.tools_run.find((t) => t.name === 'semgrep-metavar-recovery');
    if (recovery !== undefined) {
      expect(recovery.reason ?? '').toMatch(/recovered \d+ redacted match/);
      expect(recovery.status, recovery.reason ?? '').toBe('ok');
      if (recovery.status === 'failed') {
        expect(recovery.reason ?? '').toMatch(/MISSING/);
        expect(recovery.reason ?? '').toMatch(/semgrep login/);
        expect(recovery.reason ?? '').toMatch(/does not require an account/);
      }
    }

    // The whole point, stated as one assertion: the same number of routes on a
    // redacting Semgrep as on one that emits metavariables. node-mount-forms/'s
    // two routes exist on both — only their resolved path and path_partial
    // differ by version (see that test's own comment) — so the count still
    // includes them.
    expect(result.routes_total).toBe(EXPECTED_ROUTES.length + MOUNT_FORM_ROUTE_COUNT);
  }, 6 * 60_000);

  it.skipIf(!SEMGREP_AVAILABLE)('reports shadow endpoints and dead documentation', async () => {
    // Outside any `test/` path — see the module comment. `openapi.yaml`
    // ships alongside the rest of the fixture tree and is copied with it.
    const work = makeTempDir('guardian-rulepack-');
    cpSync(FIXTURE, work, { recursive: true });

    const ctx = makeContext();
    const tool = TOOLS.find((t) => t.name === 'map_attack_surface');
    if (!tool) throw new Error('map_attack_surface is not registered');

    const result = okResult<SurfaceResult>(
      await tool.handler({ project_path: work, force: true }, ctx),
    );
    const snapshotId = result.snapshot_id;
    expect(snapshotId).not.toBeNull();
    if (snapshotId === null) return;
    const snapshot = ctx.storage.surface.getById(snapshotId)?.snapshot;
    if (!snapshot) throw new Error('snapshot was not persisted');

    const diff = snapshot.spec_diff;
    expect(diff).not.toBeNull();
    if (!diff) return;

    // node-mount-forms/'s two routes are excluded the same way, and for the
    // same reason, as the "maps every route..." test above: neither is in
    // openapi.yaml, so both land in code_only regardless of Semgrep version,
    // but WHICH path string they land under (prefixed or raw) is
    // version-dependent — see that test for the covering assertion.
    const codeOnly = diff.code_only.filter((e) => !e.code_route?.file.includes('node-mount-forms'));
    expect(codeOnly.map(describeDiffEntry).sort()).toEqual(EXPECTED_SHADOW);
    expect(diff.spec_only.map(describeDiffEntry).sort()).toEqual(EXPECTED_DEAD);
  }, 6 * 60_000);
});

/* ---- the annotation fixture ---------------------------------------------
 *
 * A SECOND tree, `test/fixtures/surface/annotations/`, written by someone who
 * did not write the rules — which is the finding it exists to close. Every
 * file under `apps/` was written alongside the rule that reads it, so each
 * rule was only ever exercised against the syntax it was written for: there
 * was not one `@Get()`, `[HttpGet]` or `@GetMapping(value = …)` anywhere in
 * this repository, and those are the forms NestJS, `dotnet new webapi` and
 * spring.io's guides emit by default. The measured cost was 3 of 7 NestJS
 * endpoints, every route in a C# controller, and 4 of 8 Spring mappings —
 * missing with no error, since a route this pack does not match simply never
 * enters the inventory.
 *
 * It is a separate tree rather than more files under `apps/` so that the two
 * expected sets stay independently readable: `apps/` pins the whole pipeline
 * across nine languages (mount resolution, spec diff, import edges), while
 * this one pins one question — does each annotation family match the form its
 * framework actually documents — and can be read end to end while looking at
 * three files.
 */

/**
 * `file:line framework METHOD path` plus a `[partial]` marker.
 *
 * The line number is part of the key here, unlike `describeRoute` above,
 * because this fixture deliberately contains several routes that extract to
 * the SAME record: a bare `@Get()` and a `@Get('')` are both an empty
 * own-path, and there are three bare `@Get()`s in one file. Without the line,
 * a rule that stopped matching one of them would show up only as a shorter
 * array, and the failure would not say which declaration went quiet.
 */
function describeAnnotationRoute(route: RouteRecord): string {
  const file = route.file.replace(/\\/g, '/').split('/').slice(-2).join('/');
  const path = route.path_resolved === '' ? '<inherited>' : route.path_resolved;
  return `${file}:${route.line} ${route.framework} ${route.method} ${path}${route.path_partial ? ' [partial]' : ''}`;
}

/**
 * Every route the three annotation fixtures declare, checked declaration by
 * declaration against the files rather than pasted from a run.
 *
 * `<inherited>` is an empty own-path: the annotation carries no path and the
 * served URL is the class-level prefix. NestJS's is not followed, so the
 * endpoint is inventoried and flagged `partial` rather than dropped (which is
 * what used to happen) or guessed (which would be worse); a Spring or ASP.NET
 * one under a literal class prefix is reported AT the prefix, resolved. See the
 * "annotation with no path of its own" section of configs/semgrep/routes.yml.
 *
 * Two line numbers point one line ABOVE the route annotation
 * (`users.controller.ts:69` is `@UseGuards(AuthGuard)`, `OrderController.java:69`
 * is `@Deprecated`). That is correct and is the whole reason the bare rules
 * read nothing out of their span: an unfocused declaration-spanning match
 * starts at the FIRST annotation on the declaration, which is routinely not
 * the route one. The line is where the match begins; the route is the
 * declaration it decorates.
 *
 * Measured against the shipped pack before the fix, this same fixture produced
 * 18 of the 52 rows then expected: ASP.NET 5 of 15, NestJS 6 of 12, Spring 7
 * of 25. What was missing was every bare annotation in all three frameworks,
 * every Spring named-argument mapping, and every ASP.NET path carried by a
 * `[Route]` companion attribute. (Spring's 25th row was the class-level
 * @RequestMapping, reported as a route until its prefix was resolved.)
 */
const EXPECTED_ANNOTATION_ROUTES = [
  // ---- NestJS: every verb bare and with a path. EVERY route here is
  // `[partial]`, including the ones with a literal path — resolvers/node.ts
  // flags any JS/TS route whose file is not mounted anywhere, and a NestJS
  // controller is mounted by a module, not by `app.use`. That is pre-existing
  // and correct: the controller prefix really is unknown.
  'nest/users.controller.ts:48 nestjs GET <inherited> [partial]',
  'nest/users.controller.ts:54 nestjs GET :id [partial]',
  // `@Get('')` — a different source form, the same extracted record as the
  // bare `@Get()` two rows up.
  'nest/users.controller.ts:60 nestjs GET <inherited> [partial]',
  'nest/users.controller.ts:66 nestjs POST <inherited> [partial]',
  'nest/users.controller.ts:72 nestjs POST bulk [partial]',
  // Line 79 is `@UseGuards(AuthGuard)`, not the `@Put()` below it — see the
  // note above about where a declaration-spanning match starts.
  'nest/users.controller.ts:79 nestjs PUT <inherited> [partial]',
  'nest/users.controller.ts:85 nestjs PUT :id [partial]',
  'nest/users.controller.ts:90 nestjs PATCH <inherited> [partial]',
  'nest/users.controller.ts:95 nestjs PATCH :id/status [partial]',
  'nest/users.controller.ts:101 nestjs DELETE <inherited> [partial]',
  'nest/users.controller.ts:106 nestjs DELETE :id [partial]',
  // The arrow-property handler, bare.
  'nest/users.controller.ts:112 nestjs GET <inherited> [partial]',
  // ---- ASP.NET: every verb in all three forms, under the class's
  // `[Route("api/[controller]")]` — `[controller]` is `Orders`, the class
  // name less its `Controller` suffix, with the case as written (ASP.NET
  // routing ignores case). A path from a `[Route]` companion is reported at
  // the line of the `[Route]` attribute, which is where the focused span is.
  // `{id}` alone was never path syntax to isLiteralPath; joined to the
  // prefix, `/api/Orders/{id}` is. The bare forms are served AT the prefix.
  'aspnet/OrdersController.cs:31 aspnet GET /api/Orders/all',
  'aspnet/OrdersController.cs:35 aspnet GET /api/Orders/get-named',
  'aspnet/OrdersController.cs:39 aspnet GET /api/Orders',
  'aspnet/OrdersController.cs:43 aspnet POST /api/Orders/post-attr',
  'aspnet/OrdersController.cs:47 aspnet POST /api/Orders/submit',
  'aspnet/OrdersController.cs:51 aspnet POST /api/Orders',
  'aspnet/OrdersController.cs:55 aspnet PUT /api/Orders/put-attr',
  'aspnet/OrdersController.cs:60 aspnet PUT /api/Orders/before',
  'aspnet/OrdersController.cs:64 aspnet PUT /api/Orders',
  'aspnet/OrdersController.cs:68 aspnet PATCH /api/Orders/{id}/status',
  'aspnet/OrdersController.cs:72 aspnet PATCH /api/Orders/patch-named',
  'aspnet/OrdersController.cs:76 aspnet PATCH /api/Orders',
  'aspnet/OrdersController.cs:81 aspnet DELETE /api/Orders/{id}',
  'aspnet/OrdersController.cs:85 aspnet DELETE /api/Orders/delete-named',
  'aspnet/OrdersController.cs:89 aspnet DELETE /api/Orders',
  // ---- ASP.NET named arguments (aspnet/NamedArguments.cs), every verb in
  // three shapes. The pack matched 5 of these 17 before 3.7.0 (measured on
  // 1.182.0: the five with a path before a named argument). An attribute
  // whose arguments are all named — `dotnet new webapi`'s `[HttpGet(Name =
  // "GetWeatherForecast")]`, `Order = 1` — matched no rule, nor did a
  // template passed as `template: "…"`. Named-only is served at the
  // controller's route, like a bare attribute — `WithCompanion` too, beside
  // its `[Route("companion")]` (ASP.NET makes that a second selector, with no
  // verb, which no rule reports). A path before a named argument is the path
  // rule's, at the path, never `Name = …`.
  'aspnet/NamedArguments.cs:38 aspnet GET /WeatherForecast',
  'aspnet/NamedArguments.cs:51 aspnet GET /api/NamedArgs',
  'aspnet/NamedArguments.cs:54 aspnet GET /api/NamedArgs/{id}',
  'aspnet/NamedArguments.cs:57 aspnet GET /api/NamedArgs/get-template',
  'aspnet/NamedArguments.cs:63 aspnet GET /api/NamedArgs',
  'aspnet/NamedArguments.cs:69 aspnet POST /api/NamedArgs',
  'aspnet/NamedArguments.cs:72 aspnet POST /api/NamedArgs/post-named',
  'aspnet/NamedArguments.cs:75 aspnet POST /api/NamedArgs/post-template',
  'aspnet/NamedArguments.cs:80 aspnet PUT /api/NamedArgs',
  'aspnet/NamedArguments.cs:83 aspnet PUT /api/NamedArgs/{id}',
  'aspnet/NamedArguments.cs:87 aspnet PUT /api/NamedArgs/put-template',
  'aspnet/NamedArguments.cs:93 aspnet PATCH /api/NamedArgs',
  'aspnet/NamedArguments.cs:96 aspnet PATCH /api/NamedArgs/{id}/flag',
  'aspnet/NamedArguments.cs:100 aspnet PATCH /api/NamedArgs/patch-template',
  'aspnet/NamedArguments.cs:105 aspnet DELETE /api/NamedArgs',
  'aspnet/NamedArguments.cs:108 aspnet DELETE /api/NamedArgs/{id}/hard',
  'aspnet/NamedArguments.cs:111 aspnet DELETE /api/NamedArgs/delete-template',
  // ---- Spring: every annotation in all four forms, under the class's
  // `@RequestMapping("/api/orders")`. The class-level annotation itself is
  // NOT a row: it is a prefix, and 3.6.1's `ANY /api/orders [partial]` was a
  // route Spring never serves. `/reordered` is the load-bearing one —
  // reachable only by binding the named argument, never by reading the first
  // one. Every @RequestMapping row is ANY, `/request-value` included: its
  // `method = RequestMethod.GET` is an attribute this pack does not read, and
  // ANY is the truth rather than a guess.
  'spring/OrderController.java:54 spring GET /api/orders/get-positional',
  'spring/OrderController.java:57 spring GET /api/orders/get-value',
  'spring/OrderController.java:60 spring GET /api/orders/get-path',
  'spring/OrderController.java:63 spring GET /api/orders',
  'spring/OrderController.java:67 spring POST /api/orders/post-positional',
  'spring/OrderController.java:70 spring POST /api/orders/post-value',
  'spring/OrderController.java:73 spring POST /api/orders/post-path',
  // Line 77 is `@Deprecated`, not the `@PostMapping` below it.
  'spring/OrderController.java:77 spring POST /api/orders',
  'spring/OrderController.java:82 spring PUT /api/orders/put-positional',
  'spring/OrderController.java:87 spring PUT /api/orders/reordered',
  'spring/OrderController.java:90 spring PUT /api/orders/put-path',
  'spring/OrderController.java:93 spring PUT /api/orders',
  'spring/OrderController.java:97 spring PATCH /api/orders/{id}/status',
  'spring/OrderController.java:100 spring PATCH /api/orders/patch-value',
  'spring/OrderController.java:103 spring PATCH /api/orders/patch-path',
  'spring/OrderController.java:106 spring PATCH /api/orders',
  'spring/OrderController.java:110 spring DELETE /api/orders/delete-positional',
  // Two paths in one mapping: not one literal, so nothing is joined to it.
  'spring/OrderController.java:115 spring DELETE {"/a", "/b"} [partial]',
  'spring/OrderController.java:118 spring DELETE /api/orders/delete-path',
  'spring/OrderController.java:122 spring DELETE /api/orders',
  'spring/OrderController.java:126 spring ANY /api/orders/request-positional',
  'spring/OrderController.java:131 spring ANY /api/orders/request-value',
  'spring/OrderController.java:134 spring ANY /api/orders/request-path',
  'spring/OrderController.java:137 spring ANY /api/orders',
  // ---- Spring class-level prefixes (spring/PrefixForms.java): one class
  // per shape the join decides. Resolved: the `value =` and `path =` prefix
  // forms (a bare mapping served AT the prefix, relative halves given their
  // slash), a handler with no prefix and no supertype, an outer class's own
  // route, and a nested @RestController with a prefix of its own.
  'spring/PrefixForms.java:22 spring GET /v1/items/list',
  'spring/PrefixForms.java:25 spring POST /v1/items',
  'spring/PrefixForms.java:34 spring GET /v2/items/detail',
  'spring/PrefixForms.java:58 spring GET /health',
  'spring/PrefixForms.java:107 spring GET /outer/o',
  'spring/PrefixForms.java:120 spring GET /nested/n',
  // Partial, each for its own reason: a constant prefix (`Paths.ORDERS`); a
  // superclass, and an interface, that may carry the prefix; an abstract
  // handler; an API interface's abstract methods, one per argument form; a
  // nested type that is no handler — a class, an interface, a record.
  // `OnlyPrefixController` has a prefix and no mapping, so no row at all.
  'spring/PrefixForms.java:42 spring GET /c [partial]',
  'spring/PrefixForms.java:65 spring GET /inherited [partial]',
  'spring/PrefixForms.java:73 spring DELETE /impl [partial]',
  'spring/PrefixForms.java:83 spring GET /a [partial]',
  'spring/PrefixForms.java:92 spring ANY /abs-positional [partial]',
  'spring/PrefixForms.java:95 spring ANY /abs-value [partial]',
  'spring/PrefixForms.java:98 spring ANY /abs-path [partial]',
  'spring/PrefixForms.java:112 spring GET /helper [partial]',
  'spring/PrefixForms.java:126 spring GET /inner-iface [partial]',
  'spring/PrefixForms.java:131 spring GET /in-record [partial]',
  // The @Controller twin of `InheritingController` — the inherits rule's
  // `@Controller` branch read DEAD in the ablation run until it existed.
  'spring/PrefixForms.java:141 spring GET /page [partial]',
  // ---- ASP.NET class routes and tokens (aspnet/PrefixTokens.cs). Resolved:
  // `[controller]/[action]` with the `Async` suffix dropped, a bare attribute
  // served AT the template, an action whose body holds a local function
  // (still `Compute`), two rooted paths — one still replacing its token — a
  // rooted path on an abstract base, and nested controllers' own routes.
  'aspnet/PrefixTokens.cs:22 aspnet GET /api/Reports/Summary',
  'aspnet/PrefixTokens.cs:26 aspnet GET /api/Reports/Detail/{id}',
  'aspnet/PrefixTokens.cs:35 aspnet GET /rooted/Reports',
  'aspnet/PrefixTokens.cs:39 aspnet GET /legacy/reports',
  'aspnet/PrefixTokens.cs:43 aspnet GET /api/Reports/Compute/calc',
  'aspnet/PrefixTokens.cs:87 aspnet GET /rooted-ping',
  'aspnet/PrefixTokens.cs:113 aspnet GET /api/outer/o',
  'aspnet/PrefixTokens.cs:127 aspnet GET /api/inner/i',
  // Partial: `[ActionName]` (a bare attribute, so its own path is empty),
  // two class routes, a constant one, `[area]`, an abstract base's relative
  // route, a controller with no [Route] of its own, `[ControllerName]`, and
  // a nested class that is no controller.
  'aspnet/PrefixTokens.cs:30 aspnet POST <inherited> [partial]',
  'aspnet/PrefixTokens.cs:56 aspnet GET m [partial]',
  'aspnet/PrefixTokens.cs:64 aspnet GET c [partial]',
  'aspnet/PrefixTokens.cs:73 aspnet GET a [partial]',
  'aspnet/PrefixTokens.cs:84 aspnet GET ping [partial]',
  'aspnet/PrefixTokens.cs:95 aspnet GET x [partial]',
  'aspnet/PrefixTokens.cs:104 aspnet GET r [partial]',
  'aspnet/PrefixTokens.cs:119 aspnet GET n [partial]',
].sort();

/**
 * Text that must never appear in any extracted path. `application/json` is
 * the one this fixture was built around: it is inside the first argument of
 * `@PutMapping(produces = "application/json", value = "/reordered")`, and a
 * rule that reads the first argument of the span rather than the range
 * Semgrep focused reports the route under that text instead of under its
 * path (measured: `spring PUT produces = "application/json" [partial]`).
 */
const ANNOTATION_DECOYS = [
  'application/json',
  'AuthGuard',
  'IgnoreApi',
  'RemoveOrder',
  // A named attribute argument is never a path (aspnet/NamedArguments.cs).
  'Name =',
  'Order =',
  'GetWeatherForecast',
  'GetById',
  'nameof',
  'pong',
  // The class-prefix fixtures: a commented-out prefix in each file; a type
  // whose @RequestMapping is no route (`/only` has no mapping, `/feign` is
  // an interface's); an outer prefix joined to a nested type that is no
  // handler; a renamed action or controller read as written; a local
  // function's name read as the action's.
  'commented',
  '/only',
  '/feign',
  '/outer/helper',
  '/outer/inner-iface',
  '/api/outer/n',
  'Original',
  'renamed',
  'Custom',
  'Inner',
];

describe('E2E — annotation route rules against the auditor fixture', () => {
  it.skipIf(!SEMGREP_AVAILABLE)(
    'reports every endpoint the three frameworks declare in their own documented style',
    async () => {
      // Outside any `test/` path — see the module comment.
      const work = makeTempDir('guardian-annotations-');
      cpSync(ANNOTATION_FIXTURE, work, { recursive: true });

      const ctx = makeContext();
      const tool = TOOLS.find((t) => t.name === 'map_attack_surface');
      if (!tool) throw new Error('map_attack_surface is not registered');

      const result = okResult<SurfaceResult>(
        await tool.handler({ project_path: work, force: true }, ctx),
      );
      expect(result.tools_run.map((t) => `${t.name}:${t.status}`)).toContain('semgrep:ok');
      const snapshotId = result.snapshot_id;
      expect(snapshotId).not.toBeNull();
      if (snapshotId === null) return;
      const snapshot = ctx.storage.surface.getById(snapshotId)?.snapshot;
      if (!snapshot) throw new Error('snapshot was not persisted');

      const actual = snapshot.routes
        .filter((r) => r.provenance === 'code')
        .map(describeAnnotationRoute)
        .sort();
      expect(actual).toEqual(EXPECTED_ANNOTATION_ROUTES);

      // An over-match fails the equality above; this says what it would mean.
      // A duplicated endpoint is the specific risk of adding a second
      // alternative to a rule that already matched the first — [HttpGet] +
      // [Route("submit")] is matched by both the path rule and (without its
      // pattern-not) the bare rule.
      expect(new Set(actual).size, 'two rules reported the same declaration').toBe(actual.length);

      for (const decoy of ANNOTATION_DECOYS) {
        expect(
          snapshot.routes.filter((r) => r.path_resolved.includes(decoy)),
          `fabricated route containing ${decoy}`,
        ).toEqual([]);
      }

      // The three languages must all read `ok`. `no_matches` would be the
      // shipped behaviour for csharp here — the whole controller matched
      // nothing — and `unreadable` would mean the bare rules' declaration-
      // spanning spans reached the span scanner, which they must not.
      for (const language of ['typescript', 'csharp', 'java']) {
        const entry = snapshot.coverage.find((c) => c.language === language);
        expect(entry?.status, `${language} coverage status`).toBe('ok');
        expect(entry?.unreadable_matches, `${language} unreadable_matches`).toBe(0);
      }
    },
    6 * 60_000,
  );
});

/* ---- the framework fixture ----------------------------------------------
 *
 * A THIRD tree, `test/fixtures/surface/frameworks/`, with the same finding
 * behind it as the annotations tree above: it was written by an auditor who
 * did not write the rules, so every file is the syntax the framework's own
 * documentation uses rather than the syntax some rule was built around. It is
 * their corpus, kept intact — the `L01`/`P10`/`G07`/`F01` markers in the
 * fixture files are theirs, and each one names a form the pack was asked
 * about. The only addition is `js/mount3/`, which exists because the
 * three-argument mount fix has no observable effect anywhere else in the tree.
 *
 * `fp/` is the adversarial half: ordinary non-route code shaped like routes.
 * It is scanned in the SAME run as everything else, deliberately, so that a
 * widening anywhere in the pack which starts fabricating decoy routes fails
 * the one equality below, rather than needing a separate test somebody
 * forgets to re-run after a rule change.
 *
 * What this tree pins that the other two do not:
 *   - fluent chains — `app.get(a, h).post(b, h)`, Hono's canonical style, and
 *     Laravel's `Route::middleware(...)->get(...)` — where Semgrep reports two
 *     matches whose spans share a left edge;
 *   - `app.use(prefix, middleware, router)`, end to end through
 *     `resolveNodeMounts`;
 *   - the frameworks that were entirely invisible: chi, `mux.Handle`,
 *     qualified actix/Rocket attributes, Laravel's fluent/resource/match forms;
 *   - that ordinary `Map`, Web Storage and HTTP-client calls are NOT routes.
 */

/**
 * Every route the framework fixture declares.
 *
 * Read against the fixture sources, not pasted from a run. The rows worth
 * knowing the reason for:
 *
 * `[partial]` on the koa/hono/fastify rows is `resolvers/node.ts`, not a rule:
 * any JS/TS route in a file that is neither a mounting file nor mounted
 * anywhere is flagged partial, which is correct — nothing in the tree says
 * where those apps are served. `js/express5.js` IS a mounting file, so its own
 * routes count as attached to the app and stay resolved.
 *
 * `mount3/orders.js:9 … /api/v2/list` is the three-argument mount assertion.
 * It resolves only if `guardian-mount-express` matched
 * `app.use('/api/v2', requireAuth, ordersRouter)` AND `synthesizeMount` read
 * the LAST argument as `$ROUTER`. Before the fix it read `/list [partial]`.
 *
 * `go/routes.go:35 chi GET /x` is a KNOWN under-resolution, pinned so it
 * cannot change silently: it is the inner route of
 * `r.Route("/chi/sub", func(r chi.Router) { r.Get("/x", …) })` and its served
 * path is `/chi/sub/x`. Mount resolution is Node-only, so there is nowhere for
 * a Go prefix to be applied; gin's `r.Group("/api/v1")` row above it
 * (`/items`) has the same shape and has read this way for as long as that rule
 * has existed.
 *
 * `py/flask_app.py:17` and `:21` are `fastapi`, not `flask`, and that is a
 * decided mislabel rather than an oversight: Flask 2.x's verb shortcut is the
 * same syntax as FastAPI's, and separating them needs to know what `app` was
 * constructed from. See the note above `guardian-route-flask` in
 * `configs/semgrep/routes.yml`. The endpoint is right; only the label is not.
 *
 * `php/routes.php:21`/`:22` (`photos`, `books`) are ANY at the RESOURCE BASE
 * path: `Route::resource` expands to seven endpoints and only the base follows
 * from the line itself.
 *
 * The four `fp/` rows are the decoys that survive, and each is undecidable
 * rather than untried. `Route::get('not/a/leading/slash', 'x')` on a class
 * that merely happens to be called `Route` is indistinguishable from Laravel's
 * facade; Ruby's `get 'config/value'` is indistinguishable from a Sinatra
 * route because that is exactly what a Sinatra route looks like. Requiring a
 * `do … end` block or a second argument was tried and measured: it left
 * `post 'queue/name', payload` matching anyway and made every real Sinatra
 * route match TWICE, once bare and once with its block. They are pinned so
 * that "still four" is asserted rather than assumed — a fifth fails here.
 *
 * ZERO rows from `fp/decoys.js` and `fp/decoys.go`, which is the point this
 * fixture arrived with. Before the change `cache.get('/etc/passwd')`,
 * `cache.delete('/tmp/session')`, `storage.get('/prefs')`,
 * `api.get('/external/thing', {…})`, `http.post('/webhook/out', body)` and
 * `reg.GET("/cache/key", nil)` were all reported as routes — the five JS ones
 * at `confidence: high` with `path_partial: false`.
 *
 * Five more decoys (`F07`, `F08` in `decoys.js`; `F31`–`F33` in `decoys.go`)
 * arrived later and for a different reason: the ablation harness reported the
 * guards that stop them as DEAD, and every one turned out load-bearing when
 * probed by hand. They read DEAD because **nothing in the corpus reached
 * them**, not because they do nothing —
 *
 *   - all three chi guards, because the only Go decoy was `reg.GET(…)` in
 *     SCREAMING case, which the *gin* rule absorbs before the TitleCase rule
 *     is consulted at all;
 *   - `guardian-route-express`'s one-argument `pattern-not`, because the three
 *     decoys the pack's own header credits to it (`cache.get`, `cache.delete`,
 *     `storage.get`) are on the `$APP` denylist too, so the denylist decides
 *     first and the arity guard never gets to;
 *   - `guardian-mount-express`'s `$PREFIX` regex, because the one `app.use`
 *     decoy carried a literal `/static` prefix.
 *
 * Each new one is therefore the shape the guard is *for* and nothing else's
 * job: a one-argument read on a receiver the denylist does not cover, a
 * TitleCase `Get` in each of its three excluded forms, and an `app.use` whose
 * first argument is a call. All five must stay silent on the shipped pack and
 * become findings the moment their guard is removed — that second half is the
 * harness's, and it is what the fixtures exist to give it.
 */
const EXPECTED_FRAMEWORK_ROUTES = [
  // ---- C#: attribute + minimal API, the attribute routes under the class's
  // `[Route("api/[controller]")]`; here too as the regression guard for the
  // `using static` import fix in the same file.
  'cs/OrdersController.cs:14 aspnet GET /api/Orders/all',
  'cs/OrdersController.cs:18 aspnet GET /api/Orders',
  'cs/OrdersController.cs:23 aspnet POST /api/Orders/submit',
  'cs/OrdersController.cs:27 aspnet GET /api/Orders/quick',
  'cs/OrdersController.cs:31 aspnet PUT /api/Orders/{id:int}',
  'cs/OrdersController.cs:35 aspnet DELETE /api/Orders/{id}',
  'cs/OrdersController.cs:39 aspnet PATCH /api/Orders/{id}/status',
  'cs/Program.cs:7 aspnet-minimal GET /minimal/health',
  'cs/Program.cs:10 aspnet-minimal POST /minimal/orders',
  'cs/Program.cs:14 aspnet-minimal GET /stats',
  // ---- the decoys that survive; see the note above.
  'fp/decoys.php:3 laravel GET not/a/leading/slash',
  'fp/decoys.rb:2 rails GET config/value',
  'fp/decoys.rb:3 rails DELETE /tmp/cache-entry',
  'fp/decoys.rb:4 rails POST queue/name',
  // ---- Go. `:20` is `mux.Handle` with an `http.StripPrefix` value, invisible
  // before this change; `:33`/`:34` are chi, a whole router that contributed
  // nothing because its verbs are TitleCase.
  'go/routes.go:16 net-http ANY /go/health',
  'go/routes.go:18 net-http ANY GET /go/items/{id} [partial]',
  'go/routes.go:20 net-http ANY /go/static/',
  'go/routes.go:22 net-http ANY /go/legacy',
  'go/routes.go:26 gin GET /gin/ping',
  'go/routes.go:29 gin POST /items',
  'go/routes.go:33 chi GET /chi/items',
  'go/routes.go:34 chi POST /chi/items',
  'go/routes.go:35 chi GET /x',
  'go/routes.go:39 gin GET /echo/items',
  // ---- Spring, under the class's `@RequestMapping("/api/orders")`, which is
  // no row of its own; the annotations tree pins it in depth.
  'java/OrderController.java:13 spring GET /api/orders/list',
  'java/OrderController.java:17 spring GET /api/orders/detail',
  'java/OrderController.java:21 spring GET /api/orders',
  'java/OrderController.java:25 spring POST /api/orders/create',
  'java/OrderController.java:29 spring DELETE {"/a", "/b"} [partial]',
  'java/OrderController.java:33 spring ANY /api/orders/legacy',
  'java/OrderController.java:37 spring PUT /api/orders/{id}',
  'java/OrderController.java:40 spring PATCH /api/orders/{id}/status',
  // ---- Express/Fastify/Koa/Hono. Line 21 carries BOTH chain routes, and
  // koa-hono.js:10 carries both halves of the multi-line Hono chain.
  'js/express5.js:10 express GET /health',
  'js/express5.js:14 express GET /api/${V}/ping [partial]',
  'js/express5.js:21 express GET /chain-a',
  'js/express5.js:21 express POST /chain-b',
  'js/express5.js:33 express ANY /any',
  'js/fastify.js:5 express GET /f/health [partial]',
  'js/fastify.js:15 express POST /f/orders [partial]',
  'js/koa-hono.js:6 express GET /koa/items [partial]',
  'js/koa-hono.js:10 express GET /hono/a [partial]',
  'js/koa-hono.js:10 express POST /hono/b [partial]',
  'mount3/orders.js:9 express GET /api/v2/list',
  // ---- Laravel. `:13` is the fluent (authenticated) route, `:21`/`:22` the
  // resource bases, `:28` the two-verb `Route::match` whose path is its SECOND
  // argument.
  'php/routes.php:10 laravel GET /orders',
  'php/routes.php:13 laravel GET /orders/secure',
  'php/routes.php:17 laravel GET /dashboard',
  'php/routes.php:21 laravel ANY photos',
  'php/routes.php:22 laravel ANY books',
  'php/routes.php:25 laravel POST /orders',
  'php/routes.php:28 laravel ANY /either',
  'php/wp.php:6 wp-rest ANY /wp-json/guardian/v1/things',
  'php/wp.php:16 wp-rest ANY /items/(?P<id>\\d+) [partial]',
  // ---- Python. There is deliberately NO row for `py/urls.py:11`
  // (`path("api/", include(…))`) — a mount point, not an endpoint.
  'py/fastapi_app.py:8 fastapi GET /fa/health',
  'py/fastapi_app.py:13 fastapi POST /fa/items',
  'py/fastapi_app.py:18 fastapi GET /fa/items/{item_id}',
  'py/flask_app.py:7 flask ANY /health',
  'py/flask_app.py:12 flask ANY /items',
  'py/flask_app.py:17 fastapi GET /items/<int:item_id>',
  'py/flask_app.py:21 fastapi POST /items',
  'py/flask_app.py:26 flask ANY /bp-items',
  'py/flask_app.py:35 flask ANY /cbv',
  'py/urls.py:7 django ANY orders/',
  'py/urls.py:9 django ANY r"^legacy/(?P<slug>[\\w-]+)/$" [partial]',
  'py/urls.py:13 django ANY admin/',
  'py/urls_qualified.py:5 django ANY qualified/',
  'py/urls_qualified.py:6 django ANY r"^qual/$" [partial]',
  // ---- Ruby. `resources :orders` is NOT here; see FRAMEWORK_SCOPE_DECISIONS.
  'rb/routes.rb:8 rails GET /rails/orders',
  'rb/routes.rb:10 rails GET rails/orders/:id',
  'rb/routes.rb:16 rails GET /ping',
  'rb/sinatra.rb:4 rails GET /sin/health',
  'rb/sinatra.rb:8 rails POST /sin/items',
  // ---- Rust. `actix.rs:16` is `#[actix_web::get]` and `axum_rocket.rs:21` is
  // `#[rocket::get]` — the qualified spellings, neither matched before.
  'rs/actix.rs:8 actix GET /rust/health',
  'rs/actix.rs:12 actix POST /rust/items',
  'rs/actix.rs:16 actix GET /rust/qualified',
  'rs/actix.rs:30 actix PUT /rust/items/{id}',
  'rs/actix.rs:33 actix PATCH /rust/items/{id}/status',
  'rs/actix.rs:36 actix DELETE /rust/items/{id}',
  'rs/axum_rocket.rs:21 actix GET /rocket/health',
  // ---- NestJS. Unchanged; the annotations tree pins it in depth.
  'ts/nest-alt.ts:6 nestjs GET arrow [partial]',
  'ts/nest-alt.ts:10 nestjs GET oneline [partial]',
  'ts/users.controller.ts:10 nestjs GET <inherited> [partial]',
  'ts/users.controller.ts:16 nestjs POST <inherited> [partial]',
  'ts/users.controller.ts:23 nestjs GET :id [partial]',
  'ts/users.controller.ts:30 nestjs PUT :id [partial]',
  'ts/users.controller.ts:36 nestjs PATCH :id/status [partial]',
  'ts/users.controller.ts:42 nestjs DELETE <inherited> [partial]',
  "ts/users.controller.ts:48 nestjs GET ['alias-a', 'alias-b'] [partial]",
].sort();

/**
 * Environment variables the same run must find, as a whole set.
 *
 * `STRIPE_KEY` (`const { STRIPE_KEY, SENTRY_DSN } = process.env`), `TWO_ARG`
 * (`GetEnvironmentVariable(name, target)`) and `LARAVEL_ENV` (Laravel's own
 * `env()` helper) are the three forms this change added; each was invisible,
 * and the first two are how a modern config module and a scoped .NET read are
 * ordinarily written.
 *
 * `SENTRY_DSN` is deliberately ABSENT: a destructuring statement yields ONE
 * Semgrep match, bound to the first name — the same limitation the ESM
 * named-import rule carries and documents. Pinning its absence is what stops
 * that quietly becoming a surprise. `$_SERVER['HTTP_HOST']` is absent too: a
 * request header is not configuration.
 */
const EXPECTED_FRAMEWORK_ENV = [
  'APP_ENV',
  'APP_KEY',
  'BARE_VAR',
  'DATABASE_URL',
  'HARD_VAR',
  'LARAVEL_ENV',
  'NO_DEFAULT_VAR',
  'ONE_ARG',
  'PORT',
  'REDIS_URL',
  'SOFT_VAR',
  'STRIPE_KEY',
  'TWO_ARG',
  'WITH_DEFAULT',
].sort();

/**
 * Path text that must never appear, whatever else changes.
 *
 * Every entry is either a decoy the pack DID report before this change or a
 * form whose absence is a decision. This is not redundant with the set
 * equality above: the equality says "these 87 rows and no others", while this
 * says WHY a particular string would be a defect, so a failure names the
 * fabrication instead of showing an 87-row diff.
 */
const FRAMEWORK_DECOYS = [
  '/etc/passwd', // Map.get with a path-shaped key
  '/tmp/session', // Map.delete
  '/external/thing', // an axios-style client called with an options object
  '/webhook/out', // an HTTP client bound to the name `http`
  '/prefs', // a one-argument Web Storage read
  '/cache/key', // a Go struct that merely happens to have GET and Get methods
  // The four below are the guard-specific decoys (F07, F31-F33) described
  // above EXPECTED_FRAMEWORK_ROUTES. `app.use(cors(), apiRouter)` (F08) has no
  // entry here on purpose: what it would fabricate is a MOUNT at prefix
  // `cors()`, and a mount is not a row in `snapshot.routes` — it is consumed
  // to resolve one. Nothing in `decoys.js` declares a route for it to be
  // applied to, so an assertion on the string would pass whether the guard
  // works or not, which is worse than no assertion. The harness is what
  // measures that one; see `mcp/test/ablate/packs.ts`.
  '/cache/one-arg', // a one-argument TitleCase `Get`
  'cacheKey', // a TitleCase `Get` on a computed key — the identifier as written
  '/site/title', // a one-argument read on a receiver the $APP denylist misses
  'https://api.example.com/v1/items', // F34: net/http's client, a TitleCase verb with three arguments
];

/**
 * Forms present in the corpus that this pack reports NOTHING for, on purpose.
 * Asserted as absences so each stays a decision rather than drifting into an
 * unnoticed gap — and so that adding a rule for one of them is a deliberate
 * edit here, not a silent set-equality failure someone re-baselines.
 *
 *   `resources :orders` (rb/routes.rb) — Rails' most idiomatic form, seven
 *     endpoints from one line. Not matched: unlike `Route::resource`, whose
 *     first argument is the base path and therefore genuinely served, the Rails
 *     form names a MODEL and the URLs come from Rails' pluralisation and
 *     nesting rules. Reporting `/orders` would be inference, not extraction,
 *     and reporting `orders` (the symbol as written) would be a phantom path.
 *     The consequence is real and worth stating plainly: a conventional Rails
 *     app is substantially under-reported by this pack.
 *   `axum` (rs/axum_rocket.rs) — registers through `Router::new().route(...)`,
 *     a method chain, not an attribute; it needs a rule of a different shape
 *     rather than another alternative on the actix ones.
 *   `fastify.route({ method, url })` and `fastify.register(plugin, { prefix })`
 *     — the object-literal forms, where neither path nor prefix is a positional
 *     argument.
 *   `router.route('/widgets').get(h).post(h)` — Express's other chaining idiom;
 *     the path is on `.route()` and the verbs are on calls that carry none.
 *   JAX-RS / Quarkus (java/JaxRsResource.java) — an entire framework family.
 *
 * Two more gaps exist in the corpus and are NOT in the list below, because the
 * string each would assert the absence of is legitimately served by a
 * different framework in the same tree: `fastify.route({ url: '/f/orders' })`
 * (the same path as the `fastify.post` on the line above it) and Flask's
 * `app.add_url_rule('/legacy', …)` (the same string as Spring's `/legacy`).
 * They are recorded here rather than asserted, since an assertion on either
 * would fail for the wrong reason.
 */
const FRAMEWORK_SCOPE_DECISIONS = [
  'orders', // Rails `resources :orders` — the model name, not a path
  'users', // Rails `resources :users, only: [...]`
  '/axum/health', // axum's Router::new().route(...)
  '/axum/items',
  '/widgets', // Express router.route('/widgets').get(...).post(...)
  '/jaxrs/items', // JAX-RS @Path
  // Django `path("api/", include("app.api.urls"))` — a mount point, not an
  // endpoint. Exact equality, not a substring: `api/` occurs inside plenty of
  // paths that ARE endpoints (`/api/orders`, `/api/v2/list`) and matching those
  // would fail this for the opposite of the reason it exists.
  'api/',
];

describe('E2E — framework rules and decoys against the auditor corpus', () => {
  it.skipIf(!SEMGREP_AVAILABLE)(
    'matches every framework form the corpus declares, and none of its decoys',
    async () => {
      // Outside any `test/` path — see the module comment.
      const work = makeTempDir('guardian-frameworks-');
      cpSync(FRAMEWORK_FIXTURE, work, { recursive: true });

      const ctx = makeContext();
      const tool = TOOLS.find((t) => t.name === 'map_attack_surface');
      if (!tool) throw new Error('map_attack_surface is not registered');

      const result = okResult<SurfaceResult>(
        await tool.handler({ project_path: work, force: true }, ctx),
      );
      expect(result.tools_run.map((t) => `${t.name}:${t.status}`)).toContain('semgrep:ok');
      const snapshotId = result.snapshot_id;
      expect(snapshotId).not.toBeNull();
      if (snapshotId === null) return;
      const snapshot = ctx.storage.surface.getById(snapshotId)?.snapshot;
      if (!snapshot) throw new Error('snapshot was not persisted');

      const actual = snapshot.routes
        .filter((r) => r.provenance === 'code')
        .map(describeAnnotationRoute)
        .sort();
      expect(actual).toEqual(EXPECTED_FRAMEWORK_ROUTES);

      // A fluent chain is the one shape where two DIFFERENT routes share a
      // file AND a line, so the duplicate check has to be on the whole row —
      // `/chain-a` reported twice is what this catches.
      expect(new Set(actual).size, 'two rules reported the same declaration').toBe(actual.length);

      for (const decoy of FRAMEWORK_DECOYS) {
        expect(
          snapshot.routes
            .filter((r) => r.path_resolved.includes(decoy))
            .map(describeAnnotationRoute),
          `fabricated route containing ${decoy}`,
        ).toEqual([]);
      }

      for (const gap of FRAMEWORK_SCOPE_DECISIONS) {
        expect(
          snapshot.routes.filter((r) => r.path_resolved === gap).map(describeAnnotationRoute),
          `${gap} is a documented scope decision; adding a rule for it means editing this list`,
        ).toEqual([]);
      }

      // Not one route out of either decoy file. Asserted at FILE level as well
      // as by path, because the failure mode is a rule widening that fabricates
      // something none of the path strings above happens to name.
      const fromDecoyFiles = snapshot.routes
        .filter((r) => /decoys\.(js|go|py)$/.test(r.file.replace(/\\/g, '/')))
        .map(describeAnnotationRoute);
      expect(fromDecoyFiles, 'routes fabricated out of non-route JS/Go/Python code').toEqual([]);

      expect(snapshot.env_vars.map((e) => e.name).sort()).toEqual(EXPECTED_FRAMEWORK_ENV);

      // Every language readable. `unreadable_matches > 0` is what the three
      // uncovered PHP `use` forms produced before the recovery fix, and it
      // means "routes here could not be read" — it must be zero everywhere.
      for (const entry of snapshot.coverage) {
        expect(entry.status, `${entry.language} coverage status`).toBe('ok');
        expect(entry.unreadable_matches, `${entry.language} unreadable_matches`).toBe(0);
      }

      // The recovery step must not report a partial failure. Before the PHP
      // group / alias / `use function` branches existed this read `failed`,
      // with five matches "MISSING from the surface".
      expect(result.tools_run.map((t) => `${t.name}:${t.status}`)).toContain(
        'semgrep-metavar-recovery:ok',
      );
    },
    6 * 60_000,
  );
});
