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

import { execa } from 'execa';
import { cpSync, existsSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

import type { PluginContext } from '../../src/context.js';
import { detectOs } from '../../src/platform/osDetect.js';
import { languageFromPath } from '../../src/surface/extract.js';
import { invokeSemgrep } from '../../src/surface/scanSemgrep.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { Storage } from '../../src/storage/index.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { ensureReportDir, readJsonSafe } from '../../src/tools/scanHelpers.js';
import { TOOLS } from '../../src/tools/index.js';
import '../../src/tools/mapAttackSurface.js';
import type { AttackSurfaceSnapshot, RouteRecord, SpecDiffEntry } from '../../src/types.js';

const here = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(here, '..', '..', '..');
const FIXTURE = resolve(here, '..', 'fixtures', 'surface', 'apps');
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
  return `${route.framework} ${route.method} ${route.path_resolved}${route.path_partial ? ' [partial]' : ''}`;
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
  'django ANY django/api/',
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
  // ---- Spring. @RequestMapping declares no verb, so both the class-level
  // base path and the method-level one are reported as ANY.
  'spring ANY /legacy',
  'spring ANY /spring/orders',
  'spring DELETE /{id}',
  'spring GET /list',
  'spring PATCH /{id}/status',
  'spring POST /create',
  'spring PUT /{id}',
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
 * The whole expected surface — one set, on any Semgrep version.
 *
 * That it no longer forks on the version is the point of the focus change, so
 * the tests below assert the version-independence explicitly rather than
 * letting a single-version run imply it.
 */
const EXPECTED_ROUTES = [...BASE_ROUTES, ...FOCUSED_ROUTES].sort();

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
  'ANY /django/api',
  'ANY /django/orders',
  'ANY /django/orders/{}',
  'ANY /flask/health',
  'ANY /flask/items/{}',
  'ANY /go/health',
  'ANY /go/orders',
  'ANY /legacy',
  'ANY /spring/orders',
  'ANY /wp-json/guardian/v1/items',
  'DELETE /api/users/{}',
  'DELETE /aspnet/orders/{}',
  'DELETE /fastapi/items/{}',
  'DELETE /gin/items/{}',
  'DELETE /laravel/orders/{}',
  'DELETE /minimal/orders/{}',
  'DELETE /rails/orders/{}',
  'DELETE /rust/items/{}',
  'DELETE /{}',
  'GET /admin/reports',
  'GET /api/users/list',
  'GET /aspnet/orders',
  'GET /aspnet/orders/audit',
  'GET /aspnet/orders/{}',
  'GET /fastapi/items',
  'GET /laravel/orders',
  'GET /list',
  'GET /minimal/health',
  'GET /rails/orders',
  'GET /rails/orders/{}',
  'GET /rust/documented',
  'GET /rust/gated',
  'GET /rust/health',
  'GET /stats',
  'PATCH /aspnet/orders/{}/status',
  'PATCH /laravel/orders/{}/status',
  'PATCH /rust/items/{}/status',
  'PATCH /{}/status',
  'POST /api/users/create',
  'POST /aspnet/orders',
  'POST /create',
  'POST /fastapi/items',
  'POST /gin/items',
  'POST /laravel/orders',
  'POST /minimal/orders',
  'POST /rails/orders',
  'POST /rust/items',
  'PUT /aspnet/orders/{}',
  'PUT /laravel/orders/{}',
  'PUT /rust/items/{}',
  'PUT /{}',
].sort();

const EXPECTED_DEAD = ['GET /deprecated/v0/orders'];

async function isInstalled(bin: string): Promise<boolean> {
  try {
    const r = await execa(detectOs() === 'win32' ? 'where' : 'which', [bin], {
      reject: false,
      timeout: 2_000,
    });
    return r.exitCode === 0;
  } catch {
    return false;
  }
}

/**
 * Resolved once, at collection time, so `it.skipIf` can report a skip as a
 * skip rather than each test deciding for itself and returning early.
 */
const FIXTURE_PRESENT = existsSync(FIXTURE);
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
    const work = mkdtempSync(join(tmpdir(), 'guardian-rulepack-'));
    cpSync(FIXTURE, work, { recursive: true });

    const ctx = makeContext();
    const tool = TOOLS.find((t) => t.name === 'map_attack_surface');
    expect(tool).toBeDefined();
    if (!tool) return;

    const result = (await tool.handler({ project_path: work, force: true }, ctx)) as SurfaceResult;

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
      // map_attack_surface: imports are not part of the persisted snapshot
      // shape (that is a later task's job), so only the rule pack's own
      // matching behaviour is under test here.
      const work = mkdtempSync(join(tmpdir(), 'guardian-rulepack-import-'));
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

  it.skipIf(!SEMGREP_AVAILABLE)('reports env vars, ports and per-language coverage from the same run', async () => {
    const work = mkdtempSync(join(tmpdir(), 'guardian-rulepack-'));
    cpSync(FIXTURE, work, { recursive: true });

    const ctx = makeContext();
    const tool = TOOLS.find((t) => t.name === 'map_attack_surface');
    if (!tool) throw new Error('map_attack_surface is not registered');

    const result = (await tool.handler({ project_path: work, force: true }, ctx)) as SurfaceResult;
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
  }, 6 * 60_000);

  it.skipIf(!SEMGREP_AVAILABLE)('recovers the captures Semgrep redacts, or says so in tools_run', async () => {
    const work = mkdtempSync(join(tmpdir(), 'guardian-rulepack-'));
    cpSync(FIXTURE, work, { recursive: true });

    const ctx = makeContext();
    const tool = TOOLS.find((t) => t.name === 'map_attack_surface');
    if (!tool) throw new Error('map_attack_surface is not registered');

    const result = (await tool.handler({ project_path: work, force: true }, ctx)) as SurfaceResult;

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
    const work = mkdtempSync(join(tmpdir(), 'guardian-rulepack-'));
    cpSync(FIXTURE, work, { recursive: true });

    const ctx = makeContext();
    const tool = TOOLS.find((t) => t.name === 'map_attack_surface');
    if (!tool) throw new Error('map_attack_surface is not registered');

    const result = (await tool.handler({ project_path: work, force: true }, ctx)) as SurfaceResult;
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
