/**
 * OSV.dev client — live dependency vulnerability lookups with offline fallback.
 *
 * OSV (https://osv.dev) aggregates vulnerability data across ecosystems
 * (npm, PyPI, Go, crates.io, RubyGems, Maven, …). We use the batch query
 * endpoint to ask "is this package@version known-vulnerable?" for the
 * dependencies declared in a skill/agent we're about to install.
 *
 * Network is optional, never required: every failure path (no `fetch`,
 * timeout, non-200, malformed JSON, DNS failure) degrades to
 * `{ online: false, vulns: [] }`. Callers must treat an offline result as
 * "unknown", not "clean".
 *
 * Uses the global `fetch` (Node ≥ 18). No third-party HTTP dependency.
 */

import { mebibytes, readJsonCapped } from '../platform/httpBody.js';
import type { Severity } from '../types.js';

export interface OsvPackageQuery {
  ecosystem: string;
  name: string;
  version?: string;
}

interface OsvVulnGroup {
  ecosystem: string;
  name: string;
  version?: string;
  vuln_ids: string[];
  severity: Severity;
}

export interface OsvResult {
  /** False when any query has no complete answer: callers read it as "not verified", never as clean. */
  online: boolean;
  queried: number;
  /**
   * Named packages past the cap of the call ({@link MAX_QUERIES} unless
   * `maxQueries` says otherwise), not looked up: unknown, never clean. A
   * caller that reports coverage names them as a gap.
   */
  unqueried: number;
  /** The hits of every batch that answered, also when another batch failed. */
  vulnerable_packages: OsvVulnGroup[];
  error?: string;
}

/**
 * What `queryOsv` returns: an {@link OsvResult} that also says which queries
 * have no complete answer. A separate type, so a result a caller builds by
 * hand (the offline stand-ins) does not have to carry the list.
 */
export interface OsvAnswer extends OsvResult {
  /**
   * Queries sent with no complete answer: a failed batch, a `results` missing
   * or not one per query, a result with `next_page_token`. Unknown, never clean.
   */
  unanswered: OsvPackageQuery[];
}

interface OsvQueryOptions {
  signal?: AbortSignal;
  timeoutMs?: number;
  /** Injectable for tests; defaults to the global `fetch`. */
  fetchImpl?: typeof fetch;
  /** Queries per request. Default {@link CHUNK}. */
  chunk?: number;
  /** Requests in flight at once. Default {@link IN_FLIGHT}. */
  inFlight?: number;
  /** Queries per call; the rest are `unqueried`. Default {@link MAX_QUERIES}. */
  maxQueries?: number;
}

const OSV_BATCH_URL = 'https://api.osv.dev/v1/querybatch';
const DEFAULT_TIMEOUT_MS = 6000;
/**
 * Packages looked up per call; the rest are `unqueried`. It was 200, and the
 * rest were dropped unsaid: a skill that declared 200 harmless dependencies
 * and then the vulnerable one read `osv.dev: ok`, clean (review of 3.6.0).
 */
const MAX_QUERIES = 1000;
/** Queries per request (OSV's querybatch takes up to 1000; a smaller batch keeps each answer small). */
const CHUNK = 100;
/** Requests in flight at once: 1000 packages are ten batches, not ten timeouts end to end. */
const IN_FLIGHT = 4;
/** An answer larger than this is not read: a batch of 100 answers in a few KB. */
const MAX_RESPONSE_BYTES = 16 * 1024 * 1024;

/** What one batch came to: its hits, and the queries it left without a complete answer. */
interface BatchOutcome {
  groups: OsvVulnGroup[];
  unanswered: OsvPackageQuery[];
  error?: string;
}

/** Reads the answer of one batch. A batch cannot be matched to its queries unless it has one result each. */
function readBatch(chunk: OsvPackageQuery[], json: unknown): BatchOutcome {
  const results = (json as { results?: unknown } | null)?.results;
  if (!Array.isArray(results) || results.length !== chunk.length) {
    const got = Array.isArray(results) ? `${results.length} results` : 'no results';
    return { groups: [], unanswered: chunk, error: `osv answered ${got} for ${chunk.length} queries` };
  }
  const groups: OsvVulnGroup[] = [];
  const unanswered: OsvPackageQuery[] = [];
  chunk.forEach((pkg, idx) => {
    const res: unknown = results[idx];
    if (typeof res !== 'object' || res === null) {
      unanswered.push(pkg);
      return;
    }
    // A cut result holds only its first page: what came is kept, the query is still unanswered.
    if ((res as { next_page_token?: unknown }).next_page_token !== undefined) unanswered.push(pkg);
    const vulns = (res as { vulns?: Array<{ id?: string }> }).vulns;
    if (Array.isArray(vulns) && vulns.length > 0) {
      const ids = vulns.map((v) => v.id).filter((x): x is string => typeof x === 'string');
      const group: OsvVulnGroup = { ecosystem: pkg.ecosystem, name: pkg.name, vuln_ids: ids, severity: 'high' };
      if (pkg.version) group.version = pkg.version;
      groups.push(group);
    }
  });
  const error = unanswered.length > 0 ? `osv left ${unanswered.length} of ${chunk.length} results incomplete` : undefined;
  return { groups, unanswered, ...(error !== undefined ? { error } : {}) };
}

export async function queryOsv(
  packages: OsvPackageQuery[],
  opts: OsvQueryOptions = {},
): Promise<OsvAnswer> {
  const named = packages.filter((p) => p.name);
  const queryable = named.slice(0, opts.maxQueries ?? MAX_QUERIES);
  const unqueried = named.length - queryable.length;
  if (queryable.length === 0) {
    return { online: true, queried: 0, unqueried, vulnerable_packages: [], unanswered: [] };
  }
  const fetchImpl = opts.fetchImpl ?? (typeof fetch === 'function' ? fetch : undefined);
  if (fetchImpl === undefined) {
    return { online: false, queried: 0, unqueried, vulnerable_packages: [], unanswered: [], error: 'no_fetch' };
  }

  const size = Math.max(1, opts.chunk ?? CHUNK);
  const chunks: OsvPackageQuery[][] = [];
  for (let i = 0; i < queryable.length; i += size) chunks.push(queryable.slice(i, i + size));
  // One outcome per batch: a batch that fails costs its own queries, not the others' answers.
  const outcomes: BatchOutcome[] = [];
  let next = 0;
  const work = async (): Promise<void> => {
    for (let c = next++; c < chunks.length; c = next++) {
      const chunk = chunks[c] ?? [];
      const body = {
        queries: chunk.map((p) => ({
          package: { name: p.name, ecosystem: p.ecosystem },
          ...(p.version ? { version: p.version } : {}),
        })),
      };
      try {
        outcomes[c] = readBatch(chunk, await postJson(OSV_BATCH_URL, body, opts, fetchImpl));
      } catch (e) {
        outcomes[c] = { groups: [], unanswered: chunk, error: e instanceof Error ? e.message : 'osv_request_failed' };
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(Math.max(1, opts.inFlight ?? IN_FLIGHT), chunks.length) }, work));

  const unanswered = outcomes.flatMap((o) => o.unanswered);
  const error = outcomes.find((o) => o.error !== undefined)?.error;
  return {
    online: unanswered.length === 0,
    queried: queryable.length,
    unqueried,
    vulnerable_packages: outcomes.flatMap((o) => o.groups),
    unanswered,
    ...(error !== undefined ? { error } : {}),
  };
}

async function postJson(
  url: string,
  body: unknown,
  opts: OsvQueryOptions,
  fetchImpl: typeof fetch,
): Promise<unknown> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), opts.timeoutMs ?? DEFAULT_TIMEOUT_MS);
  if (opts.signal) {
    if (opts.signal.aborted) controller.abort();
    else opts.signal.addEventListener('abort', () => controller.abort(), { once: true });
  }
  try {
    const res = await fetchImpl(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
    if (!res.ok) throw new Error(`osv http ${res.status}`);
    const read = await readJsonCapped(res, MAX_RESPONSE_BYTES);
    if (read === null) throw new Error(`osv answer over ${mebibytes(MAX_RESPONSE_BYTES)}`);
    return read.json;
  } finally {
    clearTimeout(timeout);
  }
}
