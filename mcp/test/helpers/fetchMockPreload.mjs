/**
 * `node --import` preload that replaces the global `fetch` in a SUBPROCESS
 * (the hook e2e tests spawn `hooks/guardian-hook.mjs` as a real process, so
 * `vi.stubGlobal` cannot reach it).
 *
 *   GUARDIAN_TEST_FETCH_ROUTES  JSON `{ "<url>": { "status": 200, "body": …,
 *                               "hang": true, "accept": "<substring>" } }`.
 *                               A value may also be an ARRAY of such routes,
 *                               tried in order; the first whose `accept`
 *                               (if any) occurs in the request's Accept
 *                               header answers. The OSV batch URL may use
 *                               `"osv": { "<name>@<version>": ["MAL-…"] }`.
 *   GUARDIAN_TEST_FETCH_LOG     file every requested URL is appended to.
 *   GUARDIAN_TEST_FETCH_PROXY   `http://127.0.0.1:<port>` — instead of the
 *                               routes, send every request through the REAL
 *                               fetch to that local server, as
 *                               `<proxy>/<host><path>`. For tests that need
 *                               real sockets in the child (process-exit
 *                               behaviour after a fetch), still never the
 *                               real network.
 *
 * Any URL without a route REJECTS — no test using this can reach a real
 * network, and an unexpected request shows up as a failed lookup.
 */

import { appendFileSync } from 'node:fs';

const routes = JSON.parse(process.env.GUARDIAN_TEST_FETCH_ROUTES ?? '{}');
const log = process.env.GUARDIAN_TEST_FETCH_LOG;
const proxy = process.env.GUARDIAN_TEST_FETCH_PROXY;
const realFetch = globalThis.fetch;

function headerOf(init, name) {
  const h = init?.headers;
  if (h === undefined) return '';
  return new Headers(h).get(name) ?? '';
}

globalThis.fetch = async (input, init) => {
  const url = String(input instanceof Request ? input.url : input);
  if (log) appendFileSync(log, `${url}\n`);
  if (proxy) {
    const u = new URL(url);
    return realFetch(`${proxy}/${u.host}${u.pathname}${u.search}`, init);
  }
  const candidates = routes[url];
  if (candidates === undefined) throw new Error(`unexpected network call in test: ${url}`);
  const list = Array.isArray(candidates) ? candidates : [candidates];
  const accept = headerOf(init, 'accept');
  const route = list.find((r) => r.accept === undefined || accept.includes(r.accept));
  if (route === undefined) throw new Error(`no route for ${url} with accept ${accept}`);
  if (route.hang) {
    return new Promise((_resolve, reject) => {
      const signal = init?.signal;
      if (signal?.aborted) reject(new DOMException('aborted', 'AbortError'));
      signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')));
    });
  }
  let body = route.body;
  if (route.osv !== undefined) {
    const queries = JSON.parse(String(init?.body ?? '{}')).queries ?? [];
    body = {
      results: queries.map((q) => {
        const ids = route.osv[`${q.package?.name}@${q.version ?? ''}`] ?? [];
        return ids.length > 0 ? { vulns: ids.map((id) => ({ id })) } : {};
      }),
    };
  }
  return new Response(body === undefined ? '' : JSON.stringify(body), { status: route.status ?? 200 });
};
