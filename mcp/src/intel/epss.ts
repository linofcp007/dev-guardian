/**
 * FIRST EPSS (Exploit Prediction Scoring System) client —
 * `https://api.first.org/data/v1/epss?cve=…`, comma-joined, ≤100 CVE ids per
 * request (FIRST's own documented batch limit). Verified live 2026-09-25:
 * `curl 'https://api.first.org/data/v1/epss?cve=CVE-2021-44228'` returns
 * `{"status":"OK",...,"data":[{"cve":"CVE-2021-44228","epss":"0.999990000",
 * "percentile":"1.000000000","date":"2026-09-25"}]}` — `epss`/`percentile`
 * are STRINGS on the wire, parsed to numbers here.
 *
 * Network is optional, never required: every failure path (no `fetch`,
 * non-2xx, timeout/abort, malformed JSON, a request that throws) degrades to
 * `{ ok: false, reason }`. Callers (`intel/enrich.ts`) must treat that as
 * "unknown", never as "no CVE in this batch is scored".
 *
 * A CVE the response's `data` array does not mention (new/reserved, not yet
 * scored by EPSS) is simply absent from `scores` on an `ok: true` result —
 * that is a real, successfully-obtained negative, different from the whole
 * request having failed.
 */

const EPSS_URL = 'https://api.first.org/data/v1/epss';
const DEFAULT_TIMEOUT_MS = 6000;
const CHUNK = 100;

export interface EpssEntry {
  score: number;
  percentile: number;
}

export type EpssQueryResult =
  | { ok: true; scores: Map<string, EpssEntry> }
  | { ok: false; reason: string };

export interface EpssQueryOptions {
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
  signal?: AbortSignal;
}

export async function queryEpss(
  cveIds: readonly string[],
  opts: EpssQueryOptions = {},
): Promise<EpssQueryResult> {
  const ids = [...new Set(cveIds)];
  if (ids.length === 0) return { ok: true, scores: new Map() };

  const fetchImpl = opts.fetchImpl ?? (typeof fetch === 'function' ? fetch : undefined);
  if (fetchImpl === undefined) return { ok: false, reason: 'no fetch implementation available' };

  const scores = new Map<string, EpssEntry>();
  for (let i = 0; i < ids.length; i += CHUNK) {
    const chunk = ids.slice(i, i + CHUNK);
    const url = `${EPSS_URL}?cve=${chunk.map(encodeURIComponent).join(',')}`;
    const result = await fetchOneBatch(url, fetchImpl, opts);
    if (!result.ok) return result;
    for (const [cveId, entry] of result.scores) scores.set(cveId, entry);
  }
  return { ok: true, scores };
}

async function fetchOneBatch(
  url: string,
  fetchImpl: typeof fetch,
  opts: EpssQueryOptions,
): Promise<EpssQueryResult> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), opts.timeoutMs ?? DEFAULT_TIMEOUT_MS);
  if (opts.signal) {
    if (opts.signal.aborted) controller.abort();
    else opts.signal.addEventListener('abort', () => controller.abort(), { once: true });
  }
  try {
    const res = await fetchImpl(url, { signal: controller.signal });
    if (!res.ok) return { ok: false, reason: `FIRST EPSS returned http ${res.status}` };
    const json = (await res.json()) as { data?: unknown };
    return { ok: true, scores: parseEntries(json.data) };
  } catch (e) {
    return { ok: false, reason: describeFetchError(e) };
  } finally {
    clearTimeout(timeout);
  }
}

function parseEntries(data: unknown): Map<string, EpssEntry> {
  const scores = new Map<string, EpssEntry>();
  if (!Array.isArray(data)) return scores;
  for (const raw of data) {
    if (raw === null || typeof raw !== 'object') continue;
    const rec = raw as Record<string, unknown>;
    const cve = typeof rec['cve'] === 'string' ? rec['cve'] : undefined;
    const score = toNumber(rec['epss']);
    const percentile = toNumber(rec['percentile']);
    if (cve === undefined || score === undefined || percentile === undefined) continue;
    scores.set(cve, { score, percentile });
  }
  return scores;
}

function toNumber(v: unknown): number | undefined {
  if (typeof v === 'number' && Number.isFinite(v)) return v;
  if (typeof v === 'string' && v.trim() !== '') {
    const n = Number(v);
    if (Number.isFinite(n)) return n;
  }
  return undefined;
}

function describeFetchError(e: unknown): string {
  if (e instanceof Error) {
    if (e.name === 'AbortError') return 'FIRST EPSS request timed out';
    return e.message;
  }
  return 'FIRST EPSS request failed';
}
