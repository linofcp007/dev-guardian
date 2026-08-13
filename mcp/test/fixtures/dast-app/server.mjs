/**
 * A dependency-free `node:http` fixture app for the `scan_dast` e2e test
 * (see `mcp/test/e2e/dastFixture.test.ts`). No Express, no new dev
 * dependency — the same discipline the tool it exercises applies to itself.
 *
 * Deliberately vulnerable, trip-once-per-check by construction:
 *
 *   - `GET  /public`         200, plain — a normal, uninteresting route.
 *   - `GET  /admin/secrets`  200 with no credentials. The seeded snapshot
 *                            marks this route `auth_hint: 'required'`, so the
 *                            live 200 is a confirmed anonymous-exposure bug.
 *   - `GET  /reflect-cors`   200, reflecting whatever `Origin` header it was
 *                            sent back as `Access-Control-Allow-Origin`, with
 *                            `Access-Control-Allow-Credentials: true`.
 *   - `GET  /go`             302 to an off-origin URL.
 *   - `GET  /boom`           500 with a Node-shaped stack trace in the body.
 *   - `OPTIONS /users`       204 advertising `Allow: GET, HEAD, OPTIONS,
 *                            DELETE` — DELETE is not in the static inventory.
 *   - `POST /login`          always 200, never 429 — no rate limiter.
 *   - No route, anywhere, ever sets a security header (CSP / X-Content-Type-
 *     Options / X-Frame-Options).
 *
 * Every other path/method (including any DELETE, PUT or PATCH — the seeded
 * inventory's write route is never supposed to reach here at all) falls
 * through to a plain 404, but is still logged first: see `requests` below.
 *
 * `requests` is the one capability the task brief for this fixture calls out
 * as necessary but not itself part of the vulnerable-behaviour list: a live
 * log of every request this server actually received (method + path),
 * recorded before any routing decision, so the e2e test can prove the write
 * envelope held from the server's own point of view rather than from what
 * the tool merely claims it sent.
 */

import { createServer } from 'node:http';

const STACK_TRACE_BODY =
  'Error: boom\n' +
  '    at Object.<anonymous> (/app/routes/boom.js:9:11)\n' +
  '    at Module._compile (node:internal/modules/cjs/loader:1105:14)\n';

/**
 * @returns {Promise<{
 *   origin: string,
 *   close: () => Promise<void>,
 *   requests: { method: string, path: string }[],
 * }>}
 */
export async function start() {
  /** @type {{ method: string, path: string }[]} */
  const requests = [];

  const server = createServer((req, res) => {
    const method = req.method ?? '';
    // Probes built by `mcp/src/dast/plan.ts` never carry a query string, so
    // `req.url` IS the path here — no query-string handling needed.
    const path = req.url ?? '/';
    requests.push({ method, path });
    // Drain the request body unconditionally, before any routing decision.
    // The rate-limit burst (and any stray write attempt, if the envelope
    // ever broke) carries one; an unread body left in a keep-alive socket
    // corrupts the next request read off the same connection.
    req.resume();

    if (path === '/public' && method === 'GET') {
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end('public');
      return;
    }

    if (path === '/admin/secrets' && method === 'GET') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('{"secret":"top-secret"}');
      return;
    }

    if (path === '/reflect-cors') {
      const origin = req.headers['origin'];
      /** @type {Record<string, string>} */
      const headers = { 'content-type': 'text/plain' };
      // Only reflect when an Origin header actually arrived — the anonymous
      // probe carries none, only the dedicated CORS probe does.
      if (typeof origin === 'string' && origin !== '') {
        headers['access-control-allow-origin'] = origin;
        headers['access-control-allow-credentials'] = 'true';
      }
      res.writeHead(200, headers);
      res.end('reflected');
      return;
    }

    if (path === '/go') {
      res.writeHead(302, { location: 'https://elsewhere.example.com/' });
      res.end();
      return;
    }

    if (path === '/boom') {
      res.writeHead(500, { 'content-type': 'text/plain' });
      res.end(STACK_TRACE_BODY);
      return;
    }

    if (path === '/users' && method === 'OPTIONS') {
      res.writeHead(204, { allow: 'GET, HEAD, OPTIONS, DELETE' });
      res.end();
      return;
    }

    if (path === '/login' && method === 'POST') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('{"ok":false}');
      return;
    }

    res.writeHead(404, { 'content-type': 'text/plain' });
    res.end('not found');
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const addr = server.address();
  if (addr === null || typeof addr === 'string') {
    throw new Error('dast-app fixture failed to bind a loopback port');
  }
  const origin = `http://127.0.0.1:${addr.port}`;

  const close = () =>
    new Promise((resolve, reject) => {
      server.close((err) => (err ? reject(err) : resolve()));
      // `server.close()` alone only stops accepting NEW connections; it waits
      // for every existing one — including an idle HTTP/1.1 keep-alive socket
      // fetch's undici client may still be holding open — before its callback
      // fires. Closing idle connections immediately is what keeps a slow or
      // CI-throttled run from leaving this fixture listening past the test
      // that started it. Any request still genuinely in flight is unaffected.
      server.closeIdleConnections();
    });

  return { origin, close, requests };
}
