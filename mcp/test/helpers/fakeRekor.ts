/**
 * A fake Rekor on 127.0.0.1 answering `POST /api/v1/log/entries/retrieve`
 * — cosign's online transparency-log search, run for a legacy signature
 * that carries no inclusion proof — with one fixed answer. Pointed at with
 * `COSIGN_REKOR_URL` (cosign binds every flag to a `COSIGN_` variable), so
 * the command line dev-guardian builds stays exactly what it is in
 * production.
 *
 * Part E review, round 3 (I1): cosign frames EVERY Rekor client error as
 * `searching log query: …`, a 400 included — and Rekor answers 400 when a
 * signature does not verify against its key. Only a 5xx, a 429 or a network
 * failure there means the question was not answered.
 */

import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';

export interface FakeRekor {
  /** `http://localhost:<port>`, for COSIGN_REKOR_URL. */
  url: string;
  /** Every request served, as `METHOD path -> status`. */
  requests: string[];
  close(): Promise<void>;
}

export async function startFakeRekor(answer: { status: number; body: unknown }): Promise<FakeRekor> {
  const requests: string[] = [];
  const server = createServer((req, res) => {
    // Drain the body before answering; cosign sends the search query.
    req.resume();
    req.on('end', () => {
      const status = req.method === 'POST' && req.url === '/api/v1/log/entries/retrieve' ? answer.status : 404;
      res.writeHead(status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(status === answer.status ? answer.body : { code: 404, message: 'not found' }));
      requests.push(`${req.method ?? '?'} ${req.url ?? ''} -> ${status}`);
    });
  });
  await new Promise<void>((resolveListen) => server.listen(0, '127.0.0.1', resolveListen));
  const port = (server.address() as AddressInfo).port;
  return {
    url: `http://localhost:${port}`,
    requests,
    close: () =>
      new Promise<void>((resolveClose) => {
        server.closeAllConnections();
        server.close(() => resolveClose());
      }),
  };
}
