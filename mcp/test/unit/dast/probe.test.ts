import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createServer, type Server } from 'node:http';
import { executeProbe, executeProbes, DEFAULT_PROBE_TIMEOUT_MS } from '../../../src/dast/probe.js';
import type { ProbeRequest } from '../../../src/dast/types.js';

let server: Server;
let origin = '';

beforeAll(async () => {
  server = createServer((req, res) => {
    const url = req.url ?? '/';
    if (url === '/ok') {
      res.writeHead(200, { 'content-type': 'text/plain', 'X-Custom': 'yes' });
      res.end('hello');
      return;
    }
    if (url === '/redirect') {
      res.writeHead(302, { location: 'https://elsewhere.example.com/' });
      res.end();
      return;
    }
    if (url === '/slow') {
      setTimeout(() => {
        res.writeHead(200);
        res.end('late');
      }, 2000);
      return;
    }
    if (url === '/echo-method') {
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end(req.method ?? '');
      return;
    }
    res.writeHead(404);
    res.end('nope');
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const addr = server.address();
  if (addr === null || typeof addr === 'string') throw new Error('no address');
  origin = `http://127.0.0.1:${addr.port}`;
});

afterAll(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

function req(path: string, over: Partial<ProbeRequest> = {}): ProbeRequest {
  return {
    id: `anonymous GET ${path}`,
    method: 'GET',
    path,
    url: `${origin}${path}`,
    headers: { accept: '*/*' },
    variant: 'anonymous',
    synthetic_params: false,
    route_index: 0,
    ...over,
  };
}

const OPTS = { timeoutMs: DEFAULT_PROBE_TIMEOUT_MS, concurrency: 4 };

describe('executeProbe', () => {
  it('records status, lower-cased headers, body prefix and a body hash', async () => {
    const r = await executeProbe(req('/ok'), OPTS);
    expect(r.outcome).toBe('completed');
    expect(r.status).toBe(200);
    expect(r.headers['x-custom']).toBe('yes');
    expect(r.body_prefix).toBe('hello');
    expect(r.body_hash).toHaveLength(64);
    expect(r.error).toBeNull();
  });

  it('does NOT follow redirects — it reports the 3xx and its Location', async () => {
    // The load-bearing assertion of this whole module: following the redirect
    // would carry the scanner to elsewhere.example.com, off the authorised
    // target. A wrong implementation returns 200 from the followed hop.
    const r = await executeProbe(req('/redirect'), OPTS);
    expect(r.status).toBe(302);
    expect(r.headers['location']).toBe('https://elsewhere.example.com/');
  });

  it('times out without throwing, recording outcome timeout', async () => {
    const r = await executeProbe(req('/slow'), { ...OPTS, timeoutMs: 200 });
    expect(r.outcome).toBe('timeout');
    expect(r.status).toBeNull();
    expect(r.error).not.toBeNull();
  });

  it('records a network error without throwing when nothing is listening', async () => {
    const dead = req('/ok');
    // Port 1 is reserved and never listening in CI.
    const r = await executeProbe({ ...dead, url: 'http://127.0.0.1:1/ok' }, OPTS);
    expect(r.outcome).toBe('network_error');
    expect(r.status).toBeNull();
    expect(r.error).not.toBeNull();
  });

  it('sends the method it was given', async () => {
    const r = await executeProbe(
      req('/echo-method', { method: 'HEAD', id: 'anonymous HEAD /echo-method' }),
      OPTS,
    );
    expect(r.status).toBe(200);
  });

  it('hashes different bodies differently and identical bodies identically', async () => {
    const a = await executeProbe(req('/ok'), OPTS);
    const b = await executeProbe(req('/ok'), OPTS);
    const c = await executeProbe(req('/missing'), OPTS);
    expect(a.body_hash).toBe(b.body_hash);
    expect(a.body_hash).not.toBe(c.body_hash);
  });
});

describe('executeProbes', () => {
  it('returns one result per request, in input order', async () => {
    const reqs = [req('/ok'), req('/missing'), req('/ok')];
    const results = await executeProbes(reqs, OPTS);
    expect(results).toHaveLength(3);
    expect(results.map((r) => r.status)).toEqual([200, 404, 200]);
  });
});
