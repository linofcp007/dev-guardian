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
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { Storage } from '../../src/storage/index.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { TOOLS } from '../../src/tools/index.js';
import '../../src/tools/mapAttackSurface.js';
import type { AttackSurfaceSnapshot, RouteRecord } from '../../src/types.js';

const here = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(here, '..', '..', '..');
const FIXTURE = resolve(here, '..', 'fixtures', 'surface', 'apps');
const SCRIPTS_DIR = resolve(ROOT, 'scripts');

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

/* The full surface of test/fixtures/surface/apps/, verified capture-by-capture
   against Semgrep 1.86.0 (which still emits `extra.metavars`) and reproduced
   through the byte-offset recovery on 1.164.0 (which redacts them). */
const EXPECTED_ROUTES = [
  // ---- ASP.NET attribute routing. The verb lives in the attribute name, so
  // each rule declares metadata.method; `[HttpGet]` with no argument has no
  // path to capture and is deliberately absent.
  //
  // `/aspnet/orders/{id}` GET carries a PRECEDING `[Produces("…")]` attribute:
  // its rule matches the decorated declaration, so the span starts at the
  // wrong attribute and the recovery has to find `HttpGet(` by name. Read
  // literally, the first argument list yields `application/json` — a resolved
  // route that exists nowhere.
  'aspnet DELETE /aspnet/orders/{id}',
  'aspnet GET /aspnet/orders',
  // `/aspnet/orders/audit` additionally carries an apostrophe in a comment
  // between its attributes and `[HttpGet("…FABRICATED…")]` inside a string in
  // its body. A recovery that lexes strings to find the anchor reports the
  // fabricated path here instead.
  'aspnet GET /aspnet/orders/audit',
  'aspnet GET /aspnet/orders/{id}',
  'aspnet PATCH /aspnet/orders/{id}/status',
  'aspnet POST /aspnet/orders',
  'aspnet PUT /aspnet/orders/{id}',
  // ---- ASP.NET minimal API. `/stats` is registered on a MapGroup("/admin")
  // builder; route groups are not resolved, so it is reported at the path the
  // registration itself names.
  'aspnet-minimal DELETE /minimal/orders/{id}',
  'aspnet-minimal GET /minimal/health',
  'aspnet-minimal GET /stats',
  'aspnet-minimal POST /minimal/orders',
  // ---- actix / Rocket. One rule binding the attribute name to $METHOD.
  // `/rust/gated` carries a PRECEDING `#[allow(dead_code)]`; read literally,
  // the span's first argument list yields `dead_code` as a resolved path.
  'actix DELETE /rust/items/{id}',
  // `/rust/documented` sits behind a doc comment with two apostrophes and a
  // `&'static` lifetime — the shape that made a string-lexing anchor search
  // skip the attribute and lose the route.
  'actix GET /rust/documented',
  'actix GET /rust/gated',
  'actix GET /rust/health',
  'actix PATCH /rust/items/{id}/status',
  'actix POST /rust/items',
  'actix PUT /rust/items/{id}',
  // ---- Django. The computed path survives as a route and is flagged, never
  // resolved; the regex route is flagged too, because a regex is not a URL.
  // Nothing from py-django/helpers.py, whose local `path()` helper is bait.
  'django ANY django/api/',
  'django ANY django/orders/',
  'django ANY django/orders/<int:order_id>/',
  'django ANY r"^django/legacy/(?P<slug>[\\w-]+)/$ [partial]',
  'django ANY settings.ADMIN_URL [partial]',
  // ---- Express. The four mounted routes carry their mount prefix; the two
  // declared in the mounting file itself do not.
  'express DELETE /api/users/:id',
  'express GET /admin/reports',
  'express GET /api/users/list',
  'express GET /health',
  'express POST /api/users/create',
  'express POST /login',
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
  // ---- NestJS. Every route is partial: the `@Controller('users')` prefix is
  // not resolvable from the method decorator, and resolveNodeMounts flags any
  // JS/TS route whose file it cannot tie to exactly one mount point.
  //
  // `purge/:id` carries a PRECEDING `@HttpCode(204)`; read literally, the
  // span's first argument list yields `204` as a resolved path.
  'nestjs DELETE :id [partial]',
  'nestjs DELETE purge/:id [partial]',
  // `audit/:id` carries the apostrophe-in-a-comment plus decorator-shaped text
  // in the body.
  'nestjs GET audit/:id [partial]',
  'nestjs GET :id [partial]',
  'nestjs PATCH :id/status [partial]',
  'nestjs POST /create [partial]',
  'nestjs PUT :id [partial]',
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
const SEMGREP_AVAILABLE = existsSync(FIXTURE) && (await isInstalled('semgrep'));
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
  it.runIf(REQUIRE_SEMGREP)('GUARDIAN_REQUIRE_SEMGREP=1 — Semgrep must be on PATH', () => {
    expect(
      SEMGREP_AVAILABLE,
      'GUARDIAN_REQUIRE_SEMGREP=1 but semgrep is not on PATH, so the only test that ' +
        'exercises the real rule pack would have been skipped. On Windows it is usually ' +
        'in %APPDATA%\\Roaming\\Python\\Python3xx\\Scripts.',
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

    expect(snapshot.routes.map(describeRoute).sort()).toEqual(EXPECTED_ROUTES);
    expect(result.routes_total).toBe(EXPECTED_ROUTES.length);
  }, 6 * 60_000);

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

    // Every language the fixture contains has rules AND matches. `no_matches`
    // or `no_rules` appearing here means a rule family stopped firing.
    const covered = snapshot.coverage.filter((c) => c.routes_found > 0);
    expect(covered.map((c) => c.language).sort()).toEqual([
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
    expect(covered.every((c) => c.status === 'ok')).toBe(true);
  }, 6 * 60_000);

  it.skipIf(!SEMGREP_AVAILABLE)('recovers the captures Semgrep redacts, or says so in tools_run', async () => {
    const work = mkdtempSync(join(tmpdir(), 'guardian-rulepack-'));
    cpSync(FIXTURE, work, { recursive: true });

    const ctx = makeContext();
    const tool = TOOLS.find((t) => t.name === 'map_attack_surface');
    if (!tool) throw new Error('map_attack_surface is not registered');

    const result = (await tool.handler({ project_path: work, force: true }, ctx)) as SurfaceResult;

    // Either Semgrep emitted metavariables (older / logged-in) and there is no
    // recovery entry at all, or it redacted them and every match was rebuilt.
    // What must never happen is a recovery step reporting losses: those
    // matches are routes missing from the inventory.
    const recovery = result.tools_run.find((t) => t.name === 'semgrep-metavar-recovery');
    if (recovery !== undefined) {
      expect(recovery.status).toBe('ok');
      expect(recovery.reason ?? '').toMatch(/recovered \d+ redacted match/);
    }
    expect(result.routes_total).toBe(EXPECTED_ROUTES.length);
  }, 6 * 60_000);
});
