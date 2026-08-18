/**
 * End-to-end test for `scan_dast`: the only test in this feature that runs
 * the fully assembled tool — target gate, planner, prober, all eight own-
 * engine checks, the rate-limit burst — against a REAL server over REAL
 * loopback sockets. Every other test in `mcp/test/unit/dast/` and
 * `mcp/test/integration/scanDast.test.ts` either exercises one pure module
 * in isolation or mocks the network at some boundary; this one proves the
 * assembled tool finds what it claims to find, and that the write envelope
 * — the thing that makes this tool safe to point at someone's live app —
 * actually held.
 *
 * ---- Why an exact SET of check names, not a count ----------------------
 *
 * `expect(findings.length).toBe(N)` passes when one check silently breaks
 * and another double-fires by the same amount — precisely the failure this
 * suite exists to catch (see the finding documented at the bottom of this
 * file). Comparing the sorted set of `subcategory` values instead makes a
 * missing check and a spurious extra one both fail loudly, and independently
 * of how many times each one fires.
 *
 * ---- Two runs, not one ---------------------------------------------------
 *
 * `probe_rate_limit` crosses the write envelope for exactly one route, so it
 * is opt-in and off by default. Folding it into the same run as the default-
 * envelope assertion would force a choice between two bad options: leave it
 * off and never test it, or turn it on and make the "exact set" assertion
 * depend on which opt-in flags happened to be set. Two runs against the same
 * fixture keep both assertions exact.
 *
 * ---- The write-envelope assertion --------------------------------------
 *
 * The tool's own JSON response is not proof of what actually happened on the
 * wire — it is the tool's account of itself. The fixture keeps an
 * independent log of every request it physically received (method + path,
 * recorded before any routing decision), and the assertion below reads that
 * log, not the tool's summary. The seeded inventory includes one DELETE
 * route specifically so this is not vacuous — see the comment on
 * `WRITE_ROUTE_PATH` below.
 */

import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import type { PluginContext } from '../../src/context.js';
import { RATE_LIMIT_BURST } from '../../src/dast/rateLimit.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { Storage } from '../../src/storage/index.js';
import { makeTempDir, cleanupTempDirs } from '../helpers/tempDir.js';

afterAll(cleanupTempDirs);
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { TOOLS } from '../../src/tools/index.js';
import '../../src/tools/scanDast.js';
import type { AttackSurfaceSnapshot, RouteRecord } from '../../src/types.js';
import { route as baseRoute } from '../unit/dast/helpers.js';
import { start } from '../fixtures/dast-app/server.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(here, '..', '..', '..');
const SCRIPTS_DIR = resolve(ROOT, 'scripts');

/* ------------------------------------------------------------------ */
/* Result shapes (trimmed to what this file asserts on)                */
/* ------------------------------------------------------------------ */

interface DastFindingShape {
  fingerprint: string;
  subcategory?: string;
  severity: string;
  message?: string;
}

interface DastOk {
  ok: true;
  findings: DastFindingShape[];
  summary: {
    checks: Record<string, string>;
    rate_limit: Record<string, unknown> | null;
  };
}

interface DastErr {
  ok: false;
  error: { code: string; message: string };
}

/** Mirrors `server.d.mts`; kept local so this file's typing does not depend
 *  on cross-extension declaration resolution succeeding (see that file's
 *  own comment — nothing in the build actually checks `test/**`). */
interface DastFixture {
  origin: string;
  close: () => Promise<void>;
  requests: { method: string; path: string }[];
}

/* ------------------------------------------------------------------ */
/* The seeded route inventory                                          */
/* ------------------------------------------------------------------ */

/**
 * `mcp/test/unit/dast/helpers.ts#route` is the shared builder Tasks 4, 5, 6
 * and 9 all use — reused here rather than a fourth divergent copy. This
 * thin wrapper only adds the (path, overrides) call shape this file wants.
 */
function routeAt(path: string, over: Partial<RouteRecord> = {}): RouteRecord {
  return baseRoute({ path_raw: path, path_resolved: path, ...over });
}

/**
 * The write-envelope assertion's one load-bearing route. `allow_write_methods`
 * is never set to `true` anywhere in this file, so `plan.ts#expandMethods`
 * gates this route out before a single request is built for it — see the
 * self-review note in the task report for the full trace. If the envelope
 * were ever opened (`allow_write_methods: true`), `expandMethods('DELETE',
 * true)` returns `['DELETE']` rather than `[]`, and this route WOULD be
 * probed: it is not a route the planner ignores for any other reason.
 */
const WRITE_ROUTE_PATH = '/admin/secrets';
const WRITE_ROUTE_METHOD = 'DELETE';

const ROUTES: RouteRecord[] = [
  routeAt('/public', { file: 'src/routes/public.ts', line: 5 }),
  // Paired with the OpenAPI-derived `auth_hint: 'required'` this tool needs
  // to confirm an anonymous-exposure bug — see design doc §6.
  routeAt('/admin/secrets', { file: 'src/routes/admin.ts', line: 12, auth_hint: 'required' }),
  routeAt(WRITE_ROUTE_PATH, {
    method: WRITE_ROUTE_METHOD,
    file: 'src/routes/admin.ts',
    line: 18,
  }),
  routeAt('/reflect-cors', { file: 'src/routes/cors.ts', line: 7 }),
  routeAt('/go', { file: 'src/routes/redirect.ts', line: 4 }),
  routeAt('/boom', { file: 'src/routes/boom.ts', line: 9 }),
  routeAt('/users', { method: 'OPTIONS', file: 'src/routes/users.ts', line: 3 }),
  routeAt('/login', { method: 'POST', file: 'src/routes/auth.ts', line: 21 }),
];

/* ------------------------------------------------------------------ */
/* Harness                                                             */
/* ------------------------------------------------------------------ */

function makeCtx(): PluginContext {
  const db = new Database(':memory:');
  runMigrations(db);
  return {
    storage: new Storage(db),
    shell: null,
    scriptsDir: SCRIPTS_DIR,
    progressNotifier: { notify: async () => {} } as unknown as PluginContext['progressNotifier'],
  };
}

function tool() {
  const found = TOOLS.find((t) => t.name === 'scan_dast');
  if (!found) throw new Error('scan_dast is not registered');
  return found;
}

function expectOk(r: DastOk | DastErr): DastOk {
  if (!r.ok) throw new Error(`expected ok, got ${r.error.code}: ${r.error.message}`);
  return r;
}

describe('E2E — scan_dast against a deliberately vulnerable fixture', () => {
  let fixture: DastFixture;
  let ctx: PluginContext;
  let projectPath: string;
  let runA: DastOk;
  let runB: DastOk;

  async function run(input: Record<string, unknown>): Promise<DastOk | DastErr> {
    const result = await tool().handler({ project_path: projectPath, ...input }, ctx);
    return result as unknown as DastOk | DastErr;
  }

  beforeAll(async () => {
    fixture = (await start()) as DastFixture;

    ctx = makeCtx();
    projectPath = makeTempDir('guardian-dast-e2e-');
    const snapshot: AttackSurfaceSnapshot = {
      routes: ROUTES,
      env_vars: [],
      ports: [],
      webhooks: [],
      coverage: [],
      tools_run: [],
      missing_tools: [],
      spec_files: [],
      // No spec diff seeded: `reachability` needs one to have any candidate
      // at all (design doc §6 / `checkStatus.ts`), and its deliberate
      // absence from run A's expected set is part of this file's contract.
      spec_diff: null,
      imports: [],
    };
    ctx.storage.surface.insert({ project_path: projectPath, tree_hash: 'seeded', snapshot });

    // Run A — every default. `probe_rate_limit` is off, `allow_write_methods`
    // is off, no credentials: the read-only envelope exactly as a caller who
    // supplies only `base_url` would get it.
    runA = expectOk(await run({ base_url: fixture.origin }));

    // Run B — opts into the one check the default envelope cannot reach
    // (`probe_rate_limit` crosses the write envelope for exactly one named
    // route). Naming `rate_limit_path` explicitly rather than relying on
    // inference keeps this run's target un-ambiguous.
    runB = expectOk(
      await run({
        base_url: fixture.origin,
        probe_rate_limit: true,
        rate_limit_path: '/login',
      }),
    );
  }, 30_000);

  afterAll(async () => {
    await fixture.close();
  });

  it('run A (read-only defaults) finds exactly the checks the fixture plants — nothing more, nothing less', () => {
    // The wrong implementation this guards against is not "finds too few
    // findings" or "finds too many" as a count — it's "finds the wrong SET
    // of checks", which a count cannot distinguish from a correct run whose
    // total happens to match by coincidence (one check silently breaking
    // while an unrelated one double-fires). `rate_limit` must be absent
    // because `probe_rate_limit` was never set; `reachability` must be
    // absent because the seeded snapshot carries no spec diff. Both
    // absences are as much a part of the contract as the six presences.
    const checks = new Set(runA.findings.map((f) => f.subcategory));
    expect([...checks].sort()).toEqual([
      'anonymous_exposure',
      'cors',
      'info_disclosure',
      'method_surface',
      'open_redirect',
      'security_headers',
    ]);
  });

  it('run A returns no two findings sharing a fingerprint', () => {
    // The fingerprint IS the finding's identity: `diff_scans`,
    // `set_baseline`, `regression_alert` and `suppress_finding` all key on
    // it, and SQLite's primary key is `(fingerprint, scan_id)`. Two entries
    // sharing one means the returned `findings` array and
    // `findings_count_by_severity` describe more problems than exist, while
    // the persisted table — where `INSERT OR IGNORE` silently absorbs the
    // second row — describes the right number. A reader of the live response
    // and a reader of the database then disagree.
    //
    // This is the assertion the Task 9 report predicted would be red: before
    // the `variant` filter landed in `checkInfoDisclosure`, `plan.ts`'s
    // unconditional `cors` GET at every kept path made `GET /boom` produce
    // two byte-identical `info_disclosure` fingerprints on every run.
    const fingerprints = runA.findings.map((f) => f.fingerprint);
    expect(new Set(fingerprints).size).toBe(fingerprints.length);
  });

  it('run A never produces a differential_authz or rate_limit finding without their preconditions', () => {
    // Restated as its own assertion (rather than relying solely on set
    // exclusion above) because these two are the ones a plausible-wrong
    // implementation would produce anyway: differential_authz by treating
    // "no credentials" as "credentials are absent, so equal" instead of
    // skipping outright, and rate_limit by defaulting the check on.
    expect(runA.findings.some((f) => f.subcategory === 'differential_authz')).toBe(false);
    expect(runA.findings.some((f) => f.subcategory === 'rate_limit')).toBe(false);
    expect(runA.summary.checks['differential_authz']).toBe('needs_credentials');
    expect(runA.summary.checks['rate_limit']).toBe('skipped_envelope');
  });

  it('run B (probe_rate_limit against /login) finds the missing limiter and reports the check ok', () => {
    // `ok` here is deliberate and easy to misread: it says the check RAN and
    // reached a verdict, nothing more. It is emphatically not a statement
    // about the target being clean — conflating the two is exactly what
    // `checkStatus.ts`'s doc comment warns against — and it is not a
    // statement about the sample being complete either: `cut_by_ceiling`
    // can be true alongside status `ok`, and `summary.rate_limit.sent` vs
    // `burst_planned` is where the sample size actually lives.
    const finding = runB.findings.find((f) => f.subcategory === 'rate_limit');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('medium');
    // Design §11: must never be reworded into "rate limiting is missing" —
    // a limiter above the burst threshold looks identical at this sample
    // size, and the message has to say so.
    expect(finding?.message ?? '').toMatch(/not proof/i);
    expect(runB.summary.checks['rate_limit']).toBe('ok');
  });

  it('the write envelope held: no DELETE/PUT/PATCH ever reached the fixture, and POST arrived only from the rate-limit burst', () => {
    // Read from the FIXTURE's own log, not the tool's self-reported summary
    // — the whole point of this assertion is to not merely trust the tool's
    // account of itself. `WRITE_ROUTE_PATH`/`WRITE_ROUTE_METHOD` above is
    // what makes this non-vacuous: a DELETE route genuinely sits in the
    // inventory the planner walked, in both run A and run B, and neither
    // run ever set `allow_write_methods`.
    const writes = fixture.requests.filter(
      (r) => r.method === 'DELETE' || r.method === 'PUT' || r.method === 'PATCH',
    );
    expect(writes).toEqual([]);

    // The rate-limit burst is the ONLY source of POST traffic across BOTH
    // runs: run A never touches POST /login at all (a POST-only route is
    // dropped by the read-only envelope before it is ever built into a
    // request — proved directly by the assertion below, since if run A had
    // sent even one, the total would exceed RATE_LIMIT_BURST), and the
    // fixture never returns 429/503, so run B's burst runs to completion
    // rather than stopping early.
    const posts = fixture.requests.filter((r) => r.method === 'POST');
    expect(posts).toHaveLength(RATE_LIMIT_BURST);
    expect(posts.every((r) => r.path === '/login')).toBe(true);
  });
});

/**
 * ---- A defect this test surfaced, since FIXED --------------------------
 *
 * RESOLVED in the final review wave: `checkInfoDisclosure` now opens with
 * `if (r.request.variant !== 'anonymous') continue;`, matching its four
 * route-scoped siblings, and `it('run A returns no two findings sharing a
 * fingerprint')` above is the assertion that keeps it fixed — it could only
 * be added after the filter landed, because it was genuinely red before.
 * The original report is kept below as the record of how it was found.
 *
 * `analyze.ts#checkInfoDisclosure`'s stack-trace branch has no `variant`
 * filter and no dedup, unlike every sibling route-scoped check (compare
 * `checkAnonymousExposure`, `checkReachability`, `checkOpenRedirect`, all of
 * which filter to `variant === 'anonymous'`) and unlike its own sibling
 * branch two lines below it (the version-banner check, deduped by
 * `(header, value)`). `plan.ts` always sends a `cors`-variant GET to every
 * kept path in addition to whatever the route's own anonymous request was —
 * for `GET /boom` specifically, that means TWO completed results at
 * identical (method: 'GET', path: '/boom'), both matching the same
 * stack-trace signature, both routed through the SAME `route_index`. Because
 * `dastFingerprint` is (correctly, deliberately) built from (check, method,
 * path, file) alone, both calls to `buildFinding` produce the byte-identical
 * fingerprint — confirmed directly against this repo's own
 * `planProbes`/`analyzeOrigin` (not simulated): the same run of `/boom`
 * always yields two `info_disclosure` findings, not one.
 *
 * SQLite's `INSERT OR IGNORE` against the `(fingerprint, scan_id)` primary
 * key silently absorbs the second row, so the STORED finding count is
 * correct — which is exactly why this file's own assertions (a `Set` of
 * `subcategory` values, never a count) do not fail here. But the tool's
 * in-memory `findings` array and `findings_count_by_severity` in THIS response
 * are not deduped before being returned, so a caller reading the live
 * response — not the database — sees a duplicate entry and an inflated
 * `low` count for any route whose leak is reachable by GET. `plan.ts`
 * guarantees exactly that reachability for essentially every kept route.
 *
 * This is not a hole this test's assertions needed to route around: the
 * chosen Set-based assertion is unaffected by it either way. It is reported
 * here, plainly, as a finding for Tasks 1–8 rather than silently
 * accommodated — see the task report for the recommended fix (filter to
 * `variant === 'anonymous'`, matching every sibling check, or dedupe by
 * fingerprint the way the banner branch already dedupes by (header, value)).
 */
