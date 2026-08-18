/**
 * Integration tests for `scan_dast` — the orchestrator, its persistence and
 * its refusal paths.
 *
 * The refusal paths are the highest-value tests in this feature. A refused
 * target, a missing surface snapshot and a target nothing is listening on are
 * three DIFFERENT facts and must read as three different results — never as
 * "0 findings". Each is asserted on its exact error code, on what it names in
 * its message, and on the fact that nothing was written to the scans table
 * (an empty scan row would be exactly the "clean run" reading those refusals
 * exist to prevent).
 *
 * The two pre-network refusals additionally assert `fetch` was never called.
 * That is the assertion that separates the correct implementation from the
 * plausible-wrong one which probes first and classifies afterwards: both
 * return the same error code, only one of them sends a packet to a host it
 * was not authorised to touch.
 */

import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

// Only `scannerAvailable` is faked — `ensureReportDir` and `readJsonSafe` must
// stay real, because the evidence-file and nuclei-output assertions below are
// about what actually lands on disk.
vi.mock('../../src/tools/scanHelpers.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/tools/scanHelpers.js')>();
  return { ...actual, scannerAvailable: vi.fn() };
});
vi.mock('../../src/dast/nuclei.js', () => ({ invokeNuclei: vi.fn() }));

import { existsSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import {
  createServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from 'node:http';
import { join } from 'node:path';
import type { PluginContext } from '../../src/context.js';
import { invokeNuclei } from '../../src/dast/nuclei.js';
import { RATE_LIMIT_BURST } from '../../src/dast/rateLimit.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { Storage } from '../../src/storage/index.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { TOOLS } from '../../src/tools/index.js';
import { scannerAvailable } from '../../src/tools/scanHelpers.js';
import type { AttackSurfaceSnapshot, RouteRecord, SpecDiff } from '../../src/types.js';
import '../../src/tools/scanDast.js';
import { makeTempDir, cleanupTempDirs } from '../helpers/tempDir.js';

afterAll(cleanupTempDirs);

/* ------------------------------------------------------------------ */
/* Fixture target                                                      */
/* ------------------------------------------------------------------ */

interface Received {
  method: string;
  url: string;
  auth: string | undefined;
}

let server: Server;
let origin = '';
/** A port nothing is listening on: bound, read back, then released. */
let deadOrigin = '';
let received: Received[] = [];
/** Requests to POST /login answered 200 before the first 429. Infinity = never. */
let loginLimitAfter = Number.POSITIVE_INFINITY;
let loginHits = 0;
/** Flipped between two runs to prove a fingerprint does not follow the status. */
let usersStatus = 200;
/** Responses to `/stall` that were never answered; destroyed on teardown. */
let stalled: ServerResponse[] = [];
/** Makes each POST /login slow, so a ceiling can fire mid-burst. */
let loginDelayMs = 0;
let pendingTimers: NodeJS.Timeout[] = [];

function headerOf(req: IncomingMessage, name: string): string | undefined {
  const value = req.headers[name];
  return Array.isArray(value) ? value[0] : value;
}

beforeAll(async () => {
  server = createServer((req, res) => {
    const url = req.url ?? '/';
    received.push({
      method: req.method ?? '',
      url,
      auth: headerOf(req, 'authorization'),
    });
    req.resume();

    // Never answers. Held open so the wall-clock ceiling — not the
    // per-request timeout — is what ends the probe.
    if (url.startsWith('/stall')) {
      stalled.push(res);
      return;
    }

    // Deliberately no security headers anywhere — `security_headers` is an
    // origin-level check and needs a target that never sets them.
    if (url === '/users' || url === '/admin') {
      // Byte-identical with and without a credential, which is what
      // `differential_authz` is looking for.
      res.writeHead(url === '/users' ? usersStatus : 200, {
        'content-type': 'application/json',
      });
      res.end('{"ok":true}');
      return;
    }
    if (url === '/login' && req.method === 'POST') {
      loginHits += 1;
      const hit = loginHits;
      const respond = (): void => {
        if (res.destroyed) return;
        if (hit > loginLimitAfter) {
          res.writeHead(429, { 'retry-after': '60' });
          res.end('slow down');
          return;
        }
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end('{"token":null}');
      };
      if (loginDelayMs > 0) {
        pendingTimers.push(setTimeout(respond, loginDelayMs));
      } else {
        respond();
      }
      return;
    }
    res.writeHead(404, { 'content-type': 'text/plain' });
    res.end('nope');
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const addr = server.address();
  if (addr === null || typeof addr === 'string') throw new Error('fixture has no address');
  origin = `http://127.0.0.1:${addr.port}`;

  const spare = createServer();
  await new Promise<void>((resolve) => spare.listen(0, '127.0.0.1', resolve));
  const spareAddr = spare.address();
  if (spareAddr === null || typeof spareAddr === 'string') throw new Error('no spare address');
  deadOrigin = `http://127.0.0.1:${spareAddr.port}`;
  await new Promise<void>((resolve) => spare.close(() => resolve()));
});

afterAll(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

/* ------------------------------------------------------------------ */
/* Harness                                                             */
/* ------------------------------------------------------------------ */

let projectPath = '';
let ctx: PluginContext;
let db: Database;

function makeCtx(): PluginContext {
  db = new Database(':memory:');
  runMigrations(db);
  return {
    storage: new Storage(db),
    shell: null,
    scriptsDir: join(process.cwd(), '..', 'scripts'),
    progressNotifier: { notify: async () => {} } as unknown as PluginContext['progressNotifier'],
  };
}

function tool() {
  const found = TOOLS.find((t) => t.name === 'scan_dast');
  if (!found) throw new Error('scan_dast is not registered');
  return found;
}

function route(path: string, over: Partial<RouteRecord> = {}): RouteRecord {
  return {
    method: 'GET',
    provenance: 'code',
    path_raw: path,
    path_resolved: path,
    path_partial: false,
    file: 'src/routes.ts',
    line: 10,
    framework: 'express',
    language: 'typescript',
    auth_hint: 'unknown',
    params: [],
    confidence: 'high',
    ...over,
  };
}

function seedSnapshot(routes: RouteRecord[], specDiff: SpecDiff | null = null): void {
  const snapshot: AttackSurfaceSnapshot = {
    routes,
    env_vars: [],
    ports: [],
    webhooks: [],
    coverage: [],
    tools_run: [],
    missing_tools: [],
    spec_files: [],
    spec_diff: specDiff,
    imports: [],
  };
  ctx.storage.surface.insert({ project_path: projectPath, tree_hash: 'seeded', snapshot });
}

interface DastOk {
  ok: true;
  scan_id: string;
  scan_type: string;
  coverage: string;
  warnings: string[];
  tools_run: { name: string; status: string; reason?: string }[];
  missing_tools: string[];
  evidence_dir: string;
  findings_count_by_severity: Record<string, number>;
  findings: {
    fingerprint: string;
    tool: string;
    subcategory?: string;
    severity: string;
    title: string;
    message?: string;
    file_path?: string;
  }[];
  target: Record<string, unknown>;
  summary: {
    routes_in_snapshot: number;
    routes_planned: number;
    requests_planned: number;
    requests_completed: number;
    requests_failed: number;
    probe_outcomes: { completed: number; timeout: number; cancelled: number; network_error: number };
    truncated: boolean;
    timed_out: boolean;
    wall_clock_ms: number;
    probes_cut: number;
    skipped: { method: string; path: string; reason: string }[];
    checks: Record<string, string>;
    rate_limit: Record<string, unknown> | null;
  };
}

interface DastErr {
  ok: false;
  error: { code: string; message: string };
}

async function run(input: Record<string, unknown>): Promise<DastOk | DastErr> {
  const result = await tool().handler({ project_path: projectPath, ...input }, ctx);
  return result as unknown as DastOk | DastErr;
}

function expectOk(r: DastOk | DastErr): DastOk {
  if (!r.ok) throw new Error(`expected ok, got ${r.error.code}: ${r.error.message}`);
  return r;
}

function expectErr(r: DastOk | DastErr): DastErr {
  if (r.ok) throw new Error('expected a refusal, got ok');
  return r;
}

/** Every row of a table, raw, so nothing a repo mapper drops can hide a secret. */
function rawRows(table: string): unknown[] {
  return ctx.storage.rawHandle().prepare(`SELECT * FROM ${table}`).all();
}

function evidenceFiles(dir: string): string[] {
  return readdirSync(dir).filter((f) => f.endsWith('.json'));
}

/** The status the run recorded for `path`, read back out of its evidence. */
function statusInEvidence(r: DastOk, path: string): number | null | undefined {
  for (const file of evidenceFiles(r.evidence_dir)) {
    const record = JSON.parse(readFileSync(join(r.evidence_dir, file), 'utf8')) as {
      exchanges: {
        request: { url: string };
        response: { status: number | null } | null;
      }[];
    };
    for (const exchange of record.exchanges) {
      if (exchange.request.url === `${origin}${path}`) return exchange.response?.status;
    }
  }
  return undefined;
}

beforeEach(() => {
  ctx = makeCtx();
  projectPath = makeTempDir('guardian-dast-');
  received = [];
  loginHits = 0;
  loginLimitAfter = Number.POSITIVE_INFINITY;
  loginDelayMs = 0;
  usersStatus = 200;
  vi.mocked(scannerAvailable).mockReset();
  vi.mocked(scannerAvailable).mockResolvedValue(null);
  vi.mocked(invokeNuclei).mockReset();
});

afterEach(() => {
  // Held-open responses would keep `server.close()` waiting forever, and a
  // delayed reply firing into the next test would corrupt its `received` log.
  for (const res of stalled) res.destroy();
  stalled = [];
  for (const timer of pendingTimers) clearTimeout(timer);
  pendingTimers = [];
  vi.restoreAllMocks();
});

/* ------------------------------------------------------------------ */
/* Refusals                                                            */
/* ------------------------------------------------------------------ */

describe('scan_dast refusals', () => {
  it('refuses a non-loopback target without attestation, before any request', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch');

    const r = expectErr(await run({ base_url: 'https://api.example.com' }));

    expect(r.error.code).toBe('target_not_authorized');
    expect(r.error.message).toMatch(/authorized_target/);
    // The whole point of the gate: not one packet. A tool that classified
    // after probing would still return this code.
    expect(fetchSpy).not.toHaveBeenCalled();
    // And the refusal outranks the missing snapshot — no snapshot was seeded,
    // so an implementation that checked storage first would answer
    // `no_surface_snapshot` here.
    expect(rawRows('scans')).toHaveLength(0);
  });

  it('rejects an unparseable base_url as unsupported, not as unauthorized', async () => {
    const r = expectErr(await run({ base_url: 'ftp://localhost/x' }));
    expect(r.error.code).toBe('unsupported_target');
    expect(r.error.message).toMatch(/http/);
  });

  it('refuses when no surface snapshot exists, naming the tool to run first', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch');

    const r = expectErr(await run({ base_url: deadOrigin }));

    expect(r.error.code).toBe('no_surface_snapshot');
    expect(r.error.message).toMatch(/map_attack_surface/);
    // `deadOrigin` has nothing listening: an implementation that liveness-
    // probed before reading storage would answer `target_not_found` instead,
    // and would have called fetch to find that out.
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(rawRows('scans')).toHaveLength(0);
  });

  it('reports a dead target distinctly from a clean scan', async () => {
    seedSnapshot([route('/users')]);

    const r = expectErr(await run({ base_url: deadOrigin }));

    expect(r.error.code).toBe('target_not_found');
    expect(r.error.message).toContain(deadOrigin);
    // Not "a scan that found nothing": no scan row exists at all.
    expect(rawRows('scans')).toHaveLength(0);
    expect(rawRows('findings')).toHaveLength(0);
  });

  it('refuses when the only snapshot belongs to a DIFFERENT project, never probing it', async () => {
    // `surface.getLatest()` returns the newest row in the WHOLE database,
    // regardless of project. Seed a snapshot for a foreign project only —
    // this project (`projectPath`) has none of its own — then call scan_dast
    // for THIS project. The plausible-wrong implementation reads getLatest(),
    // finds the foreign snapshot, and proceeds to probe ITS routes instead of
    // refusing, which contradicts the refusal message eleven lines above
    // ("No attack-surface snapshot exists for this project") and would emit
    // findings whose file_path points at another project's tree entirely.
    const otherProject = makeTempDir('guardian-dast-other-');
    const foreignSnapshot: AttackSurfaceSnapshot = {
      routes: [route('/other-projects-route')],
      env_vars: [],
      ports: [],
      webhooks: [],
      coverage: [],
      tools_run: [],
      missing_tools: [],
      spec_files: [],
      spec_diff: null,
      imports: [],
    };
    ctx.storage.surface.insert({
      project_path: otherProject,
      tree_hash: 'other-tree',
      snapshot: foreignSnapshot,
    });

    const fetchSpy = vi.spyOn(globalThis, 'fetch');
    const r = expectErr(await run({ base_url: deadOrigin }));

    expect(r.error.code).toBe('no_surface_snapshot');
    expect(r.error.message).toMatch(/map_attack_surface/);
    // The decisive assertion: an implementation that scanned the foreign
    // snapshot would have gone on to liveness-probe `deadOrigin` and answered
    // `target_not_found` instead — a different code AND a network call that
    // must never happen against an unvetted, foreign route inventory.
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(rawRows('scans')).toHaveLength(0);
    expect(rawRows('findings')).toHaveLength(0);
  });
});

/* ------------------------------------------------------------------ */
/* Envelope reporting                                                  */
/* ------------------------------------------------------------------ */

describe('scan_dast envelope reporting', () => {
  it('reports every skipped route with its reason, and the per-check status', async () => {
    seedSnapshot([
      route('/users'),
      route('/orders', { method: 'POST' }),
      route('/mounted/thing', { path_partial: true }),
    ]);

    const r = expectOk(await run({ base_url: origin }));

    expect(r.summary.skipped).toEqual([
      { method: 'POST', path: '/orders', reason: 'method_envelope' },
      { method: 'GET', path: '/mounted/thing', reason: 'partial_path' },
    ]);
    // A check that never ran must be visible as such — never as a check that
    // ran and found nothing. Asserted as an exact map: the plausible-wrong
    // implementation defaults every check to 'ok'.
    expect(r.summary.checks).toEqual({
      reachability: 'no_candidate',
      anonymous_exposure: 'no_candidate',
      differential_authz: 'needs_credentials',
      cors: 'ok',
      security_headers: 'ok',
      info_disclosure: 'ok',
      method_surface: 'ok',
      open_redirect: 'ok',
      rate_limit: 'skipped_envelope',
      nuclei: 'skipped_envelope',
    });
    // The skips are real, not merely reported: neither dropped route was sent.
    expect(received.some((x) => x.method === 'POST')).toBe(false);
    expect(received.some((x) => x.url.includes('/mounted'))).toBe(false);
    expect(r.coverage).toBe('full');
  });

  it('reports the request ceiling when it cuts the plan', async () => {
    seedSnapshot([route('/users'), route('/admin'), route('/other')]);

    const r = expectOk(await run({ base_url: origin, max_requests: 2 }));

    expect(r.summary.truncated).toBe(true);
    expect(r.summary.requests_planned).toBe(2);
    expect(r.summary.skipped.filter((s) => s.reason === 'cap').length).toBeGreaterThan(0);
    expect(r.warnings.some((w) => /max_requests|ceiling/i.test(w))).toBe(true);
  });

  it('reports the wall-clock ceiling when it cuts, and cut probes read cancelled', async () => {
    // Eight stalling routes, a 400ms ceiling, and a per-request timeout an
    // order of magnitude LARGER than the ceiling. That gap is what makes the
    // assertion decisive: nothing here can time out before the ceiling fires,
    // so any 'timeout' outcome would mean the cut came from somewhere else.
    seedSnapshot(Array.from({ length: 8 }, (_, i) => route(`/stall/${i}`)));

    const started = Date.now();
    const r = expectOk(
      await run({ base_url: origin, wall_clock_ms: 400, timeout_ms: 20_000 }),
    );
    const elapsed = Date.now() - started;

    // It returned at all, rather than hanging for 8 x 20s.
    expect(elapsed).toBeLessThan(10_000);

    expect(r.summary.timed_out).toBe(true);
    expect(r.summary.wall_clock_ms).toBe(400);
    expect(r.summary.probes_cut).toBeGreaterThan(0);
    expect(r.summary.requests_completed).toBe(0);

    // THE assertion. A probe the ceiling cut must read 'cancelled' — we
    // stopped asking — never 'timeout', which claims the target failed to
    // answer. Task 3 separated these two outcomes for exactly this moment.
    expect(r.summary.probe_outcomes.cancelled).toBe(r.summary.requests_planned);
    expect(r.summary.probe_outcomes.timeout).toBe(0);
    expect(r.summary.probe_outcomes.network_error).toBe(0);

    // A ceiling that cuts silently is worse than no ceiling.
    expect(r.warnings.some((w) => /wall-clock ceiling \(400ms\)/.test(w))).toBe(true);
    // Nothing completed, so a "0 findings" result here is meaningless — the
    // shared coverage signal has to say so, and 'none' is what it means.
    expect(r.coverage).toBe('none');
    expect(r.tools_run.find((t) => t.name === 'guardian-dast')?.status).toBe('failed');
    const cut = r.tools_run.find((t) => t.name === 'guardian-dast:wall-clock');
    expect(cut?.status).toBe('failed');
    expect(cut?.reason).toMatch(/400ms wall-clock ceiling/);
  });

  it('reports partial coverage when the ceiling cuts a run that measured something', async () => {
    // One fast route the scan gets through, then stalls. The distinction from
    // the test above is the whole point of splitting the wall-clock gap into
    // its own tools_run entry: 'none' means nothing was measured, 'partial'
    // means some of the inventory was.
    seedSnapshot([route('/users'), ...Array.from({ length: 8 }, (_, i) => route(`/stall/${i}`))]);

    const r = expectOk(
      await run({ base_url: origin, wall_clock_ms: 400, timeout_ms: 20_000 }),
    );

    expect(r.summary.timed_out).toBe(true);
    expect(r.summary.requests_completed).toBeGreaterThan(0);
    expect(r.summary.probe_outcomes.timeout).toBe(0);
    expect(r.coverage).toBe('partial');
  });

  it('degrades coverage when the target answered almost nothing, without any ceiling firing', async () => {
    // The gap this closes: `engineFailed` was true only when ZERO probes
    // completed, so a target answering one probe and timing out on the rest
    // reported tools_run: ok, coverage: 'full' and no warning — while
    // probe_outcomes.timeout said otherwise two fields away. `coverage` is the
    // field the consumer contract points at, so that is a "0 findings reads as
    // all clear" path.
    //
    // Note the inverted knobs versus the wall-clock tests above: a per-request
    // timeout an order of magnitude SMALLER than the ceiling, so the probes
    // genuinely time out against the target and nothing is cancelled. The
    // `timed_out: false` assertion is what proves this is a different route to
    // 'partial' than the ceiling's, rather than the ceiling firing early.
    seedSnapshot([route('/users'), ...Array.from({ length: 8 }, (_, i) => route(`/stall/${i}`))]);

    const r = expectOk(
      await run({ base_url: origin, timeout_ms: 250, wall_clock_ms: 30_000 }),
    );

    expect(r.summary.timed_out).toBe(false);
    expect(r.summary.probe_outcomes.cancelled).toBe(0);
    expect(r.summary.requests_completed).toBeGreaterThan(0);
    expect(r.summary.probe_outcomes.timeout).toBeGreaterThan(0);

    // A run that measured something but lost most of the plan is 'partial',
    // never 'full'.
    expect(r.coverage).toBe('partial');
    const gap = r.tools_run.find((t) => t.name === 'guardian-dast:unanswered');
    expect(gap?.status).toBe('failed');
    expect(gap?.reason).toMatch(/never answered/);
    // The engine itself still ran — the two facts stay separate, exactly as
    // the wall-clock entry keeps "we stopped asking" separate from "the target
    // did not answer".
    expect(r.tools_run.find((t) => t.name === 'guardian-dast')?.status).toBe('ok');
    expect(r.warnings.some((w) => /partial coverage/i.test(w))).toBe(true);
  });

  it('does not degrade coverage for a stray unanswered probe', async () => {
    // The other side of the threshold, and the reason it is not zero: a scan
    // that degrades on any single flaky timeout trains readers to ignore the
    // signal. Fourteen distinct routes answer (a 404 is an ANSWER — the probe
    // completed), one stalls: 2 unanswered out of 30 planned requests.
    // Distinct paths matter — `plan.ts` dedupes on (method, path), so
    // repeating one path would collapse the denominator and push the ratio
    // back over the line.
    seedSnapshot([
      ...Array.from({ length: 14 }, (_, i) => route(`/ok/${i}`)),
      route('/stall/solo'),
    ]);

    const r = expectOk(
      await run({ base_url: origin, timeout_ms: 250, wall_clock_ms: 30_000 }),
    );

    expect(r.summary.probe_outcomes.timeout).toBeGreaterThan(0);
    expect(r.tools_run.some((t) => t.name === 'guardian-dast:unanswered')).toBe(false);
    expect(r.coverage).toBe('full');
  });

  it('does not start nuclei once the wall-clock ceiling has fired', async () => {
    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/nuclei');
    seedSnapshot(Array.from({ length: 8 }, (_, i) => route(`/stall/${i}`)));

    const r = expectOk(
      await run({ base_url: origin, wall_clock_ms: 400, timeout_ms: 20_000, use_nuclei: true }),
    );

    // Starting a five-minute external scan after the ceiling expired would
    // make the ceiling meaningless.
    expect(vi.mocked(invokeNuclei)).not.toHaveBeenCalled();
    const entry = r.tools_run.find((t) => t.name === 'nuclei');
    expect(entry?.status).toBe('skipped');
    expect(entry?.reason).toMatch(/wall-clock ceiling/);
    // Not blamed on the install or on the target.
    expect(entry?.reason).not.toMatch(/not installed/);
  });

  it('keeps a zero-route snapshot distinguishable from a clean scan', async () => {
    seedSnapshot([]);

    const r = expectOk(await run({ base_url: origin }));

    expect(r.summary.routes_in_snapshot).toBe(0);
    expect(r.summary.requests_planned).toBe(0);
    expect(r.findings).toHaveLength(0);
    // The distinguishing signal: the checks did not run, so they must not
    // read 'ok'. A clean scan of a real inventory reports 'ok' here.
    expect(r.summary.checks.cors).toBe('no_candidate');
    expect(r.summary.checks.security_headers).toBe('no_candidate');
    expect(r.summary.checks.info_disclosure).toBe('no_candidate');
    expect(r.warnings.some((w) => /no routes/i.test(w))).toBe(true);
  });
});

/* ------------------------------------------------------------------ */
/* Credentials                                                         */
/* ------------------------------------------------------------------ */

describe('scan_dast credentials', () => {
  const SECRET = 'Bearer s3cr3t-do-not-leak-9f2a';

  it('never persists the credential, in any field of the result or the db', async () => {
    seedSnapshot([route('/users')]);

    const r = expectOk(await run({ base_url: origin, auth_header: SECRET }));

    // Without this the whole test is vacuous: prove the credential really was
    // put on the wire, so its absence at rest is redaction and not omission.
    expect(received.some((x) => x.auth === SECRET)).toBe(true);
    expect(r.findings.some((f) => f.subcategory === 'differential_authz')).toBe(true);

    const leak = 's3cr3t-do-not-leak-9f2a';
    expect(JSON.stringify(r)).not.toContain(leak);
    expect(JSON.stringify(rawRows('findings'))).not.toContain(leak);
    expect(JSON.stringify(rawRows('scans'))).not.toContain(leak);

    const files = evidenceFiles(r.evidence_dir);
    expect(files.length).toBeGreaterThan(0);
    const evidence = files.map((f) => readFileSync(join(r.evidence_dir, f), 'utf8')).join('\n');
    expect(evidence).not.toContain(leak);
    // The credential-bearing request IS in the evidence — redacted. An
    // implementation that simply never wrote request headers would pass every
    // `not.toContain` above while proving nothing.
    expect(evidence).toContain('«redacted»');
  });

  it('reads auth_header_env from the environment and still redacts it', async () => {
    process.env['GUARDIAN_TEST_DAST_TOKEN'] = 'Bearer env-token-8b31';
    try {
      seedSnapshot([route('/users')]);

      const r = expectOk(
        await run({ base_url: origin, auth_header_env: 'GUARDIAN_TEST_DAST_TOKEN' }),
      );

      expect(received.some((x) => x.auth === 'Bearer env-token-8b31')).toBe(true);
      expect(r.summary.checks.differential_authz).toBe('ok');
      expect(JSON.stringify(r)).not.toContain('env-token-8b31');
      const evidence = evidenceFiles(r.evidence_dir)
        .map((f) => readFileSync(join(r.evidence_dir, f), 'utf8'))
        .join('\n');
      expect(evidence).not.toContain('env-token-8b31');
    } finally {
      delete process.env['GUARDIAN_TEST_DAST_TOKEN'];
    }
  });

  it('redacts the credential from tools_run before it reaches SQLite', async () => {
    // `tools_run` holds one string this codebase does not author: nuclei's
    // first stderr line, stored verbatim. A target that echoes the
    // Authorization header into an error is all it takes for a credential to
    // reach the scans row. Requirement 2 is absolute precisely so this does
    // not depend on nuclei's wording.
    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/nuclei');
    vi.mocked(invokeNuclei).mockResolvedValue({
      ok: false,
      reason: `connection failed while sending Authorization: ${SECRET}`,
    });
    seedSnapshot([route('/users')]);

    const r = expectOk(await run({ base_url: origin, auth_header: SECRET, use_nuclei: true }));

    const leak = 's3cr3t-do-not-leak-9f2a';
    // The scans row is the only copy that was outside the choke point.
    expect(JSON.stringify(rawRows('scans'))).not.toContain(leak);
    expect(JSON.stringify(r)).not.toContain(leak);
    // Anti-vacuity: the string really did pass through tools_run, redacted.
    // Without this an implementation that dropped the reason entirely would
    // pass the two assertions above while proving nothing.
    expect(r.tools_run.find((t) => t.name === 'nuclei')?.reason).toContain('«redacted»');
  });

  it('warns loudly when auth_header_env names an unset variable', async () => {
    delete process.env['GUARDIAN_TEST_DAST_MISSING'];
    seedSnapshot([route('/users')]);

    const r = expectOk(
      await run({ base_url: origin, auth_header_env: 'GUARDIAN_TEST_DAST_MISSING' }),
    );

    // The caller asked for authenticated probing and did not get it. Silence
    // here is an anonymous run masquerading as an authenticated one.
    expect(r.warnings.some((w) => w.includes('GUARDIAN_TEST_DAST_MISSING'))).toBe(true);
    expect(r.summary.checks.differential_authz).toBe('needs_credentials');
    expect(received.every((x) => x.auth === undefined)).toBe(true);
  });
});

/* ------------------------------------------------------------------ */
/* Persistence + evidence                                              */
/* ------------------------------------------------------------------ */

describe('scan_dast persistence', () => {
  it('persists findings with scan_type dast and stable fingerprints across runs', async () => {
    seedSnapshot([route('/users'), route('/admin', { auth_hint: 'required' })]);

    const first = expectOk(await run({ base_url: origin }));
    // The app answers /users differently on the second run — an app restart,
    // a fixed 500, a flaky dependency. Without this the fingerprint assertion
    // below would also hold for an implementation that hashed the status in,
    // because both runs would have seen the same status.
    usersStatus = 503;
    const second = expectOk(await run({ base_url: origin }));

    expect(statusInEvidence(first, '/users')).toBe(200);
    expect(statusInEvidence(second, '/users')).toBe(503);

    expect(first.scan_id).not.toBe(second.scan_id);
    expect(first.findings.length).toBeGreaterThan(0);
    const fpA = first.findings.map((f) => f.fingerprint).sort();
    const fpB = second.findings.map((f) => f.fingerprint).sort();
    // Identical target, identical inventory: the same facts must carry the
    // same identity, or diff_scans / set_baseline / suppress_finding all
    // break. A fingerprint hashing the status or the scan id fails here.
    expect(fpB).toEqual(fpA);

    const scans = rawRows('scans') as { id: string; scan_type: string; status: string }[];
    expect(scans).toHaveLength(2);
    expect(scans.every((s) => s.scan_type === 'dast')).toBe(true);
    expect(scans.every((s) => s.status === 'completed')).toBe(true);

    const stored = ctx.storage.findings.listByScan(first.scan_id);
    expect(stored.map((f) => f.fingerprint).sort()).toEqual(fpA);
    expect(stored.every((f) => f.category === 'security')).toBe(true);
    expect(stored.some((f) => f.subcategory === 'anonymous_exposure')).toBe(true);
  });

  it('writes one redacted evidence file per finding under .guardian/reports/dast-*', async () => {
    seedSnapshot([route('/users', { auth_hint: 'required' })]);

    const r = expectOk(await run({ base_url: origin }));

    expect(r.evidence_dir).toContain(join('.guardian', 'reports'));
    expect(r.evidence_dir).toContain(`dast-${r.scan_id.slice(0, 8)}`);
    expect(existsSync(r.evidence_dir)).toBe(true);

    const files = evidenceFiles(r.evidence_dir);
    expect(files.sort()).toEqual(r.findings.map((f) => `${f.fingerprint}.json`).sort());

    const anon = r.findings.find((f) => f.subcategory === 'anonymous_exposure');
    if (anon === undefined) throw new Error('expected an anonymous_exposure finding');
    const record = JSON.parse(
      readFileSync(join(r.evidence_dir, `${anon.fingerprint}.json`), 'utf8'),
    ) as {
      fingerprint: string;
      check: string;
      exchanges: {
        request: { method: string; url: string };
        response: { status: number | null; body_excerpt: string } | null;
      }[];
    };
    expect(record.fingerprint).toBe(anon.fingerprint);
    expect(record.check).toBe('anonymous_exposure');

    // Every stored row's evidence pointer resolves. A pointer that looks real
    // and opens nothing is worse than no pointer at all.
    const rows = rawRows('findings') as { raw: string }[];
    expect(rows).toHaveLength(r.findings.length);
    for (const row of rows) {
      const raw = JSON.parse(row.raw) as { evidence_file: string | null; check: string };
      expect(raw.check).not.toBe('');
      if (raw.evidence_file === null) throw new Error('evidence_file was not recorded');
      expect(existsSync(raw.evidence_file)).toBe(true);
    }
    expect(record.exchanges[0]?.request.url).toBe(`${origin}/users`);
    expect(record.exchanges[0]?.response?.status).toBe(200);
    expect(record.exchanges[0]?.response?.body_excerpt).toBe('{"ok":true}');
  });
});

/* ------------------------------------------------------------------ */
/* Rate limit                                                          */
/* ------------------------------------------------------------------ */

describe('scan_dast rate-limit probe', () => {
  // A request one of this block's own bursts sent, but whose CLIENT gave up
  // on (the wall-clock ceiling in 'reports a ceiling that fires DURING the
  // burst', or a per-request timeout in any of the others), can still be
  // sitting between the OS socket and this fixture's 'request' handler when
  // the test that sent it returns: `received.push` runs at ARRIVAL time
  // (dast/probe.ts's fetch() call has already handed the bytes to the
  // kernel well before it settles waiting for a reply), independent of
  // whatever outcome the client eventually records. `runRateLimitBurst`
  // itself is fully sequential and awaits every request before the next,
  // so nothing is left pending from THIS process's point of view by the
  // time a test's own `await run(...)` resolves — but under sustained
  // parallel-suite load, an event-loop chain that never yields to a real
  // timer/I/O tick between this test's teardown and the next test's
  // `beforeEach` can starve the poll phase that would otherwise deliver an
  // already-arrived-at-the-kernel request to this handler, so the
  // `received.push` for it lands AFTER `beforeEach` has reset `received`
  // for the next test — not before.
  //
  // Reproduced live, repeatedly (not merely traced): 'never bursts an
  // arbitrary endpoint when nothing looks like an auth route' — the test
  // directly after 'reports a ceiling that fires DURING the burst' below —
  // saw `received` contain a POST it structurally cannot have sent itself
  // (its own scan reports `checks.rate_limit: 'no_candidate'`, which only
  // happens when `runRateLimitBurst` returns before `buildBurst` is ever
  // called — see rateLimit.ts:104-105). Polling `received.length` for two
  // consecutive stable reads, rather than a fixed sleep, because the actual
  // delay is a function of how starved this process's event loop is under
  // whatever else is running concurrently, not a constant; capped so a
  // genuinely stuck straggler cannot hang the suite.
  afterEach(async () => {
    let previous = -1;
    for (let attempt = 0; attempt < 40; attempt += 1) {
      const current = received.length;
      if (current === previous) return;
      previous = current;
      await new Promise<void>((resolve) => setTimeout(resolve, 25));
    }
  });

  function loginRoutes(): RouteRecord[] {
    return [route('/users'), route('/login', { method: 'POST', file: 'src/auth.ts', line: 42 })];
  }

  function loginPosts(): Received[] {
    return received.filter((x) => x.method === 'POST' && x.url === '/login');
  }

  it('stops the burst at the first 429', async () => {
    loginLimitAfter = 3;
    seedSnapshot(loginRoutes());

    const r = expectOk(await run({ base_url: origin, probe_rate_limit: true }));

    // The deterministic floor is 4: loginLimitAfter (3) successes, then the
    // 429 that stops the burst — the server's own hit counter is exact, so
    // fewer than 4 requests can never reach it. Derived from loginLimitAfter
    // itself, not a bare literal, so the two can never silently drift apart.
    //
    // NOT pinned to exactly 4, though: runRateLimitBurst (dast/passes.ts)
    // only recognises a 429 when its OWN probe call reports outcome
    // 'completed' — see rateLimitVerdict's completed-only counting. Under
    // parallel suite load a probe can occasionally be cut by its own
    // per-request timeout (dast/probe.ts) or, once one has, by
    // opts.aborted() at passes.ts:113 — cut, not failed: the target already
    // answered, this tool simply did not wait long enough to see it — and
    // when that happens to land on the request that would have been the
    // 429, the burst loop has no way to know a limiter just fired and sends
    // one more. A few extra requests under load is not the failure this
    // test exists to catch; sending anywhere close to the full burst is.
    // RATE_LIMIT_BURST / 2 keeps that the sharply distinguishing line —
    // "comfortably early" vs. "essentially all of it" — the same shape as
    // appRunner.test.ts's own expectWellUnderDeadline: derive the tolerance
    // from a value the test already configures, not a number that assumes
    // perfect scheduling. A rate limiter that is genuinely missing or
    // broken still fails this — see reports the absence of a limiter below,
    // which drives the identical target with loginLimitAfter left at
    // Infinity and requires the full RATE_LIMIT_BURST requests to be sent.
    const posts = loginPosts().length;
    expect(posts).toBeGreaterThanOrEqual(loginLimitAfter + 1);
    expect(posts).toBeLessThan(RATE_LIMIT_BURST / 2);

    // sent/at_request are omitted from this match on purpose: like `posts`
    // above, they are only guaranteed to equal loginLimitAfter + 1 when
    // every probe up to the 429 was observed without a timing miss —
    // observed: true already proves the limiter itself was genuinely
    // detected (a broken/missing limiter can never produce it), and
    // `posts`'s own upper bound already proves the burst stopped well short
    // of sending the whole thing, so pinning these two derived counts to
    // the exact same literal would only reintroduce the same flake without
    // checking anything `posts` does not already cover.
    expect(r.summary.rate_limit).toMatchObject({
      path: '/login',
      inferred: true,
      burst_planned: RATE_LIMIT_BURST,
      observed: true,
      // The limiter stopped this burst, not the wall clock. Reported on both
      // branches so a reader never has to infer it from a missing field.
      cut_by_ceiling: false,
    });
    // A limiter that works is not a finding.
    expect(r.findings.some((f) => f.subcategory === 'rate_limit')).toBe(false);
    expect(r.summary.checks.rate_limit).toBe('ok');
  });

  it('reports the absence of a limiter without claiming rate limiting is missing', async () => {
    seedSnapshot(loginRoutes());

    const r = expectOk(
      await run({ base_url: origin, probe_rate_limit: true, rate_limit_path: '/login' }),
    );

    expect(loginPosts()).toHaveLength(RATE_LIMIT_BURST);
    const finding = r.findings.find((f) => f.subcategory === 'rate_limit');
    if (finding === undefined) throw new Error('expected a rate_limit finding');
    expect(finding.severity).toBe('medium');
    // Design §11: this must never be reworded into "rate limiting is
    // missing" — a limiter above the burst threshold looks identical.
    expect(finding.message).toMatch(/not proof/i);
    expect(finding.message).toMatch(/indistinguishable/i);
    expect(finding.file_path).toBe('src/auth.ts');
    expect(r.summary.rate_limit).toMatchObject({
      path: '/login',
      inferred: false,
      observed: false,
      sent: RATE_LIMIT_BURST,
    });
    // The burst is written as ONE aggregate record, not thirty files that
    // collapse onto a single shared ProbeRequest.id.
    const record = JSON.parse(
      readFileSync(join(r.evidence_dir, `${finding.fingerprint}.json`), 'utf8'),
    ) as { burst?: { planned: number; sent: number; statuses: (number | null)[] } };
    expect(record.burst?.planned).toBe(RATE_LIMIT_BURST);
    expect(record.burst?.statuses).toHaveLength(RATE_LIMIT_BURST);
  });

  it('reports a ceiling that fires DURING the burst, not just before it', async () => {
    // The main plan is two fast requests and finishes well inside the
    // ceiling; the burst then runs into it. A `timed_out` flag read once,
    // right after executeProbes, reports `false` here — the run looks
    // complete while the rate-limit verdict rests on a sample this tool's own
    // ceiling truncated.
    loginDelayMs = 100;
    seedSnapshot(loginRoutes());

    const r = expectOk(
      await run({
        base_url: origin,
        probe_rate_limit: true,
        rate_limit_path: '/login',
        wall_clock_ms: 500,
      }),
    );

    // The burst really was cut: some requests landed, but not the full 30.
    const posts = loginPosts().length;
    expect(posts).toBeGreaterThan(0);
    expect(posts).toBeLessThan(RATE_LIMIT_BURST);

    expect(r.summary.timed_out).toBe(true);
    expect(r.warnings.some((w) => /wall-clock ceiling \(500ms\)/.test(w))).toBe(true);
    const cutEntry = r.tools_run.find((t) => t.name === 'guardian-dast:wall-clock');
    expect(cutEntry?.status).toBe('failed');
    // The main plan completed, so some of the inventory WAS measured.
    expect(r.coverage).toBe('partial');

    // And the finding must not read as a completed 30-request measurement.
    expect(r.summary.rate_limit).toMatchObject({ observed: false, cut_by_ceiling: true });
    const finding = r.findings.find((f) => f.subcategory === 'rate_limit');
    if (finding === undefined) throw new Error('expected a rate_limit finding');
    expect(finding.message).toMatch(/cut short by the scan's wall-clock ceiling/);
  });

  it('never bursts an arbitrary endpoint when nothing looks like an auth route', async () => {
    seedSnapshot([route('/users')]);

    const r = expectOk(await run({ base_url: origin, probe_rate_limit: true }));

    expect(r.summary.checks.rate_limit).toBe('no_candidate');
    expect(r.summary.rate_limit).toBeNull();
    expect(received.some((x) => x.method === 'POST')).toBe(false);
  });
});

/* ------------------------------------------------------------------ */
/* nuclei                                                              */
/* ------------------------------------------------------------------ */

describe('scan_dast nuclei pass', () => {
  it('reports a requested-but-absent nuclei as a skipped tool, never as silence', async () => {
    vi.mocked(scannerAvailable).mockResolvedValue(null);
    seedSnapshot([route('/users')]);

    const r = expectOk(await run({ base_url: origin, use_nuclei: true }));

    const entry = r.tools_run.find((t) => t.name === 'nuclei');
    if (entry === undefined) throw new Error('nuclei is missing from tools_run entirely');
    expect(entry.status).toBe('skipped');
    expect(entry.reason).toMatch(/not installed/i);
    expect(r.missing_tools).toContain('nuclei');
    // The gap must reach `coverage`, or a caller reads the finding count as
    // complete when a whole engine did not run.
    expect(r.coverage).toBe('partial');
    // Not `skipped_envelope`: the envelope did not exclude nuclei, a missing
    // binary did, and the status must not blame the wrong thing.
    expect(r.summary.checks.nuclei).toBe('scanner_missing');
    expect(vi.mocked(invokeNuclei)).not.toHaveBeenCalled();
  });

  it('normalises nuclei output into findings when the binary is present', async () => {
    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/nuclei');
    vi.mocked(invokeNuclei).mockImplementation(async (opts) => {
      writeFileSync(
        opts.outputPath,
        `${JSON.stringify({
          'template-id': 'tech-detect',
          info: { name: 'Technology detection', severity: 'info' },
          'matched-at': `${origin}/users`,
        })}\n`,
        'utf8',
      );
      return { ok: true };
    });
    seedSnapshot([route('/users')]);

    const r = expectOk(await run({ base_url: origin, use_nuclei: true }));

    const nucleiFindings = r.findings.filter((f) => f.tool === 'nuclei');
    expect(nucleiFindings).toHaveLength(1);
    expect(nucleiFindings[0]?.file_path).toBe('src/routes.ts');
    expect(r.summary.checks.nuclei).toBe('ok');
    expect(r.coverage).toBe('full');
    expect(vi.mocked(invokeNuclei).mock.calls[0]?.[0]?.targetUrl).toBe(origin);
    expect(vi.mocked(invokeNuclei).mock.calls[0]?.[0]?.allowIntrusive).toBe(false);
  });

  it('reports a failed nuclei run as failed, not as zero nuclei findings', async () => {
    vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/nuclei');
    vi.mocked(invokeNuclei).mockResolvedValue({ ok: false, reason: 'template load error' });
    seedSnapshot([route('/users')]);

    const r = expectOk(await run({ base_url: origin, use_nuclei: true }));

    const entry = r.tools_run.find((t) => t.name === 'nuclei');
    expect(entry?.status).toBe('failed');
    expect(entry?.reason).toContain('template load error');
    expect(r.summary.checks.nuclei).toBe('target_error');
    expect(r.coverage).toBe('partial');
  });
});
