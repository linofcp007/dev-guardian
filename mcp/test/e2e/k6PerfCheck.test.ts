/**
 * perf_check against the REAL k6 (`tools/perfCheck.ts`), over `fixtures/k6/project` — laid out as
 * grafana/quickpizza's k6/foundations scripts are — and a node HTTP server on 127.0.0.1:
 *
 *   - E1 the summary k6's `--summary-export` really writes: the requests, the latencies (no p99 by default), each
 *     threshold the script configures and the ones that failed;
 *   - E2 the series: two runs share it, a `K6_*` setting starts another;
 *   - E3 an edit of an imported module starts another series, and restoring it brings the first one back;
 *   - E4 the local modules the walk keys against what k6 itself packs (`k6 archive`): a differential of two
 *     readers of one script;
 *   - E5 the stated limit: `__ENV.CI` changes the load and keeps the key (k6 hands a script the system
 *     environment, and `CI` is a name perf_check hands k6);
 *   - E6 no usage report: through a logging proxy that refuses everything, a control run of a bare `k6 run` asks
 *     for something (or this proves nothing), perf_check's run asks for nothing.
 *
 * Hermetic: every `K6_*`, `CI` and `NO_PROXY` of the shell is unset, the proxy variables point at the refusing
 * proxy (the target is loopback, which Go never proxies), and HOME / USERPROFILE / APPDATA at a temporary folder,
 * so k6's config file and installation id are never the maintainer's.
 *
 * Gated on k6 being installed; `GUARDIAN_REQUIRE_K6=1` (`npm run test:docker -- --toolchain`) turns the skip into a
 * failure.
 */

import { spawn, spawnSync } from 'node:child_process';
import { cpSync, readFileSync, writeFileSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import type { PluginContext } from '../../src/context.js';
import { k6LocalInputs } from '../../src/metrics/k6Inputs.js';
import { resolveProjectPath } from '../../src/platform/projectPath.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';
import { k6ModuleReader } from '../../src/tools/perfCheck.js';
import { resetScannerCache } from '../../src/tools/scanHelpers.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';
import { isInstalled } from '../helpers/toolchain.js';

vi.setConfig({ testTimeout: 180_000 });

const FIXTURE = resolve(dirname(fileURLToPath(import.meta.url)), '../fixtures/k6/project');
const INSTALLED = await isInstalled('k6');
if (!INSTALLED && process.env['GUARDIAN_REQUIRE_K6'] === '1') {
  throw new Error('GUARDIAN_REQUIRE_K6=1 but k6 is not installed');
}

/** Every request the target served. */
let served = 0;
let target: Server;
let targetUrl = '';
/** Every host a client asked the proxy for (CONNECT host:port, or an absolute-URI request): any is the report. */
const asked: string[] = [];
let proxy: Server;
let proxyUrl = '';
let home = '';

beforeAll(async () => {
  await import('../../src/tools/perfCheck.js');
  resetScannerCache();
  target = createServer((req, res) => {
    served += 1;
    req.resume();
    res.writeHead(200, { 'content-type': 'application/json' }).end('{}');
  });
  await new Promise<void>((done) => target.listen(0, '127.0.0.1', done));
  targetUrl = `http://127.0.0.1:${String((target.address() as AddressInfo).port)}`;
  proxy = createServer((req, res) => {
    asked.push(req.url ?? '');
    res.writeHead(403).end();
  });
  proxy.on('connect', (req, socket) => {
    socket.on('error', () => {});
    asked.push(req.url ?? '');
    socket.end('HTTP/1.1 403 Forbidden\r\n\r\n');
  });
  proxy.on('clientError', (_e, socket) => socket.destroy());
  await new Promise<void>((done) => proxy.listen(0, '127.0.0.1', done));
  proxyUrl = `http://127.0.0.1:${String((proxy.address() as AddressInfo).port)}`;
  home = makeTempDir('k6-e2e-home-');
});
afterAll(async () => {
  await new Promise<void>((done) => target.close(() => done()));
  await new Promise<void>((done) => proxy.close(() => done()));
  cleanupTempDirs();
});

beforeEach(() => {
  for (const name of Object.keys(process.env)) {
    const upper = name.toUpperCase();
    if (upper.startsWith('K6_') || upper === 'CI' || upper === 'NO_PROXY' || upper.endsWith('_PROXY')) vi.stubEnv(name, undefined);
  }
  for (const name of ['HTTPS_PROXY', 'HTTP_PROXY', 'https_proxy', 'http_proxy']) vi.stubEnv(name, proxyUrl);
  for (const name of ['HOME', 'USERPROFILE', 'APPDATA']) vi.stubEnv(name, home);
  asked.length = 0;
});
afterEach(() => {
  vi.unstubAllEnvs();
});

interface Run {
  ok: boolean;
  passed?: boolean;
  summary?: Record<string, unknown>;
  history?: { series: string; recorded: boolean };
  error?: { message: string };
}

function plugin(): PluginContext {
  const db = new Database(':memory:');
  runMigrations(db);
  return { storage: new Storage(db), shell: null, scriptsDir: makeTempDir('k6-e2e-scripts-'), progressNotifier: { send: () => {} } };
}

/** The fixture project in a temporary folder, its target this file's server. */
function project(): string {
  const dir = resolveProjectPath(makeTempDir('k6-e2e-')).path;
  cpSync(FIXTURE, dir, { recursive: true });
  writeFileSync(join(dir, 'lib', 'target.js'), `export const BASE_URL = '${targetUrl}';\n`, 'utf8');
  return dir;
}

async function perfCheck(p: PluginContext, dir: string, script = 'load.js'): Promise<Run> {
  const tool = TOOLS.find((t) => t.name === 'perf_check');
  if (!tool) throw new Error('perf_check not registered');
  const r = (await tool.handler({ project_path: dir, k6_script_path: script }, p)) as Run;
  if (!r.ok) throw new Error(`perf_check failed: ${JSON.stringify(r.error)}`);
  return r;
}

const seriesKeys = (p: PluginContext, dir: string): unknown[] =>
  p.storage.scans.listCompletedOfTypes(dir, ['perf'], { limit: 100 }).map((r) => r.meta?.['series']).reverse();

describe('perf_check: k6 (real k6, a local server, gated)', () => {
  it.skipIf(!INSTALLED)('E1: the summary — requests, latencies, no p99 by default, the thresholds configured and failed', async () => {
    const dir = project();
    const before = served;
    const r = await perfCheck(plugin(), dir);
    // 2 iterations of 2 requests (lib/load-options.js SmokeOptions, lib/frontend/basic.js).
    expect(served - before).toBe(4);
    expect(r.passed).toBe(true);
    expect(r.summary?.['requests_total']).toBe(4);
    expect(r.summary?.['error_rate']).toBe(0);
    expect(Number.isFinite(r.summary?.['latency_avg_ms'])).toBe(true);
    expect(Number.isFinite(r.summary?.['latency_p95_ms'])).toBe(true);
    expect(r.summary?.['latency_p99_ms']).toBeNull();
    expect(r.summary?.['thresholds_configured']).toEqual(['http_req_duration: p(95)<5000']);
    expect(r.summary?.['thresholds_failed']).toEqual([]);
    expect(r.history?.series).toMatch(/^k6 · load\.js \([0-9a-f]{12}\) · 5 local modules #[0-9a-f]{6}$/);
  });

  it.skipIf(!INSTALLED)('E2: two runs share a series; a K6_* setting starts another', async () => {
    const dir = project();
    const p = plugin();
    const one = await perfCheck(p, dir);
    const two = await perfCheck(p, dir);
    expect(two.history?.series).toBe(one.history?.series);
    vi.stubEnv('K6_VUS', '2');
    const three = await perfCheck(p, dir);
    expect(three.history?.series).toMatch(/ · K6_\* #[0-9a-f]{6}$/);
    const keys = seriesKeys(p, dir);
    expect(keys[0]).toBe(keys[1]);
    expect(keys[2]).not.toBe(keys[0]);
  });

  it.skipIf(!INSTALLED)('E3: a comment edited in an imported module starts another series; restored, the first one again', async () => {
    const dir = project();
    const p = plugin();
    const file = join(dir, 'lib', 'load-options.js');
    const original = readFileSync(file, 'utf8');
    await perfCheck(p, dir);
    writeFileSync(file, `// edited\n${original}`, 'utf8');
    await perfCheck(p, dir);
    writeFileSync(file, original, 'utf8');
    await perfCheck(p, dir);
    const [first, edited, restored] = seriesKeys(p, dir);
    expect(edited).not.toBe(first);
    expect(restored).toBe(first);
  });

  it.skipIf(!INSTALLED)("E4: the modules keyed are what k6 itself packs (k6 archive), the opened data file and the commented import apart", () => {
    const dir = project();
    const out = join(makeTempDir('k6-e2e-archive-'), 'a.tar');
    const env = { ...process.env, K6_NO_USAGE_REPORT: 'true' };
    const archived = spawnSync('k6', ['archive', '-O', out, 'load.js'], { cwd: dir, env, encoding: 'utf8' });
    expect(archived.status, archived.stderr).toBe(0);
    const listing = spawnSync('tar', ['-tf', out], { encoding: 'utf8' });
    expect(listing.status, listing.stderr).toBe(0);
    // A local file is packed as `file/<its absolute path, the leading / dropped>`: the project-relative part of each.
    const root = dir.replace(/\\/g, '/').replace(/^\/+/, '');
    const entries = listing.stdout
      .split(/\r?\n/)
      .map((e) => e.replace(/^\.\//, ''))
      .filter((e) => e.startsWith('file/'))
      .map((e) => e.slice('file/'.length))
      .filter((e) => e.startsWith(`${root}/`))
      .map((e) => e.slice(root.length + 1).replace(/\/+$/, ''))
      .filter((e) => e !== '');
    // k6's tar lists a folder as its own entry, with or without a trailing slash (2.4.0: without): a folder is an entry
    // another entry lies below — never a file of the script's.
    const packed = entries.filter((e) => !entries.some((other) => other.startsWith(`${e}/`)));
    const walk = k6LocalInputs('load.js', k6ModuleReader(dir));
    const keyed = walk.files.filter(([, digest]) => digest !== 'missing').map(([path]) => path);
    expect(packed.length).toBeGreaterThan(0);
    // Everything k6 packs is the entry, a module the walk keyed, or the data file the script opens (not keyed).
    expect(packed.filter((e) => e !== 'load.js' && !keyed.includes(e) && e !== 'data/tokens.json')).toEqual([]);
    // Everything the walk keyed k6 packs, but the commented-out import (the stated over-key).
    expect(keyed.filter((path) => !packed.includes(path))).toEqual(['lib/spike-stages.js']);
  });

  it.skipIf(!INSTALLED)('E5 (a stated limit): __ENV.CI changes the load and keeps the key — CI is handed to k6, and no input of the key', async () => {
    const dir = project();
    writeFileSync(
      join(dir, 'ci.js'),
      [
        "import http from 'k6/http';",
        "import { BASE_URL } from './lib/target.js';",
        'export const options = { vus: 1, iterations: __ENV.CI ? 3 : 2 };',
        'export default function () { http.get(`${BASE_URL}/ci`); }',
        '',
      ].join('\n'),
      'utf8',
    );
    const p = plugin();
    const unset = await perfCheck(p, dir, 'ci.js');
    vi.stubEnv('CI', '1');
    const set = await perfCheck(p, dir, 'ci.js');
    expect(unset.summary?.['requests_total']).toBe(2);
    expect(set.summary?.['requests_total']).toBe(3);
    const keys = seriesKeys(p, dir);
    expect(keys[1]).toBe(keys[0]);
  });

  it.skipIf(!INSTALLED)('E6: no usage report — a bare k6 run asks the proxy (the control), perf_check asks for nothing', async () => {
    const dir = project();
    writeFileSync(join(dir, 'tiny.js'), "import http from 'k6/http';\nimport { BASE_URL } from './lib/target.js';\nexport const options = { vus: 1, iterations: 1 };\nexport default function () { http.get(BASE_URL); }\n", 'utf8');
    const env = { ...process.env };
    // Asynchronous: the proxy lives in this process, and a synchronous spawn would block it from answering.
    const code = await new Promise<number | null>((done) => {
      const child = spawn('k6', ['run', '--quiet', 'tiny.js'], { cwd: dir, env, stdio: 'ignore' });
      child.on('close', (c) => done(c));
      child.on('error', () => done(null));
    });
    expect(code).toBe(0);
    const control = asked.length;
    expect(control, 'the control run of a bare `k6 run` asked the proxy for nothing: this test proves nothing until it does').toBeGreaterThan(0);
    asked.length = 0;
    await perfCheck(plugin(), dir, 'tiny.js');
    expect(asked).toEqual([]);
  });
});
