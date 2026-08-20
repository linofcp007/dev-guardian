import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createServer, type Server } from 'node:http';
import { executeProbe, executeProbes, DEFAULT_PROBE_TIMEOUT_MS } from '../../../src/dast/probe.js';
import type { ProbeRequest } from '../../../src/dast/types.js';

let server: Server;
let origin = '';

/**
 * How many requests the server has actually been asked to handle on
 * `/slow`, counted the moment the handler is entered.
 *
 * This is the observable the cancellation test below asserts on. It exists
 * because "did the worker keep issuing live requests after the caller
 * cancelled" is a fact about the TARGET — how many requests reached it —
 * and the target can simply be asked. The test used to infer it from the
 * clock instead (`Date.now() - start < 1000`, reasoning that a worker still
 * spinning would have to sit through `/slow`'s 2000ms delay), which is a
 * proxy for the real property and one a loaded machine can falsify without
 * anything being wrong.
 */
let slowHits = 0;

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
      slowHits += 1;
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
    // No `signal` in OPTS: this pins the internal-timer path specifically,
    // so it is the assertion that would break if the cancelled/timeout
    // precedence in the catch block were ever reversed.
    const r = await executeProbe(req('/slow'), { ...OPTS, timeoutMs: 200 });
    expect(r.outcome).toBe('timeout');
    expect(r.status).toBeNull();
    expect(r.error).not.toBeNull();
  });

  it('records outcome cancelled — not timeout — when the caller aborts an in-flight probe', async () => {
    // A host stopping a scan and a target failing to answer are different
    // facts. The timer and an outer AbortSignal both abort the same internal
    // controller, so `controller.signal.aborted` alone cannot tell them
    // apart — a wrong implementation reports 'timeout' here. `timeoutMs`
    // comes from OPTS (DEFAULT_PROBE_TIMEOUT_MS, 5000ms), far longer than
    // this test runs, so only the outer abort can explain a non-'completed'
    // outcome.
    const outer = new AbortController();
    const pending = executeProbe(req('/slow'), { ...OPTS, signal: outer.signal });
    // Let the request actually reach the server's /slow handler before
    // cancelling from the outside — a real in-flight cancellation, not a
    // same-tick race.
    await new Promise((resolve) => setTimeout(resolve, 50));
    outer.abort();
    const r = await pending;
    expect(r.outcome).toBe('cancelled');
    expect(r.status).toBeNull();
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

  it('a worker does not keep issuing live requests after the caller cancels mid-run', async () => {
    // concurrency: 1 means every request is dequeued by the SAME worker
    // loop, one at a time, so #2 and #3 are claimed strictly after the abort
    // below has already fired on the shared signal. Adding an 'abort'
    // listener to an AbortSignal that is already aborted never fires it (the
    // event already happened) — so without an explicit up-front `aborted`
    // check, executeProbe would wire up no cancellation for #2/#3 and let
    // each run to completion (or its own 5s internal timeout) against the
    // live target instead of stopping immediately, i.e. the worker keeps
    // spinning through the queue after the scan was supposedly cancelled.
    const outer = new AbortController();
    const reqs = [req('/slow'), req('/slow'), req('/slow')];
    // Snapshotted rather than reset to zero: `/slow` is shared with the two
    // `executeProbe` tests above, and vitest runs the tests in a file
    // sequentially, so the baseline is whatever they already left behind.
    const hitsBefore = slowHits;
    const pending = executeProbes(reqs, { ...OPTS, concurrency: 1, signal: outer.signal });
    // Let request #1 actually start before cancelling out from under it.
    await new Promise((resolve) => setTimeout(resolve, 50));
    outer.abort();
    const results = await pending;
    // THE assertion: the target was contacted exactly once — for request #1,
    // which was already in flight when the abort fired. A worker that kept
    // spinning through the queue would have issued #2 and #3 as real HTTP
    // requests, and this counter would read three. Not inferred from how
    // long anything took: `await pending` cannot resolve until the worker
    // loop has finished, so by the time this line runs, a spinning worker
    // has necessarily already been counted.
    expect(slowHits - hitsBefore).toBe(1);
    expect(results.map((r) => r.outcome)).toEqual(['cancelled', 'cancelled', 'cancelled']);
    expect(results.every((r) => r.status === null)).toBe(true);
  });
});
