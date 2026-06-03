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

import type { Severity } from '../types.js';

export interface OsvPackageQuery {
  ecosystem: string;
  name: string;
  version?: string;
}

export interface OsvVulnGroup {
  ecosystem: string;
  name: string;
  version?: string;
  vuln_ids: string[];
  severity: Severity;
}

export interface OsvResult {
  online: boolean;
  queried: number;
  vulnerable_packages: OsvVulnGroup[];
  error?: string;
}

const OSV_BATCH_URL = 'https://api.osv.dev/v1/querybatch';
const DEFAULT_TIMEOUT_MS = 6000;
const MAX_QUERIES = 200;
const CHUNK = 100;

export async function queryOsv(
  packages: OsvPackageQuery[],
  opts: { signal?: AbortSignal; timeoutMs?: number } = {},
): Promise<OsvResult> {
  const queryable = packages.filter((p) => p.name).slice(0, MAX_QUERIES);
  if (queryable.length === 0) {
    return { online: true, queried: 0, vulnerable_packages: [] };
  }
  if (typeof fetch !== 'function') {
    return { online: false, queried: 0, vulnerable_packages: [], error: 'no_fetch' };
  }

  const vulnerable: OsvVulnGroup[] = [];
  try {
    for (let i = 0; i < queryable.length; i += CHUNK) {
      const chunk = queryable.slice(i, i + CHUNK);
      const body = {
        queries: chunk.map((p) => ({
          package: { name: p.name, ecosystem: p.ecosystem },
          ...(p.version ? { version: p.version } : {}),
        })),
      };
      const json = await postJson(OSV_BATCH_URL, body, opts);
      const results = Array.isArray((json as { results?: unknown }).results)
        ? ((json as { results: unknown[] }).results)
        : [];
      results.forEach((res, idx) => {
        const pkg = chunk[idx];
        if (!pkg) return;
        const vulns = (res as { vulns?: Array<{ id?: string }> })?.vulns;
        if (Array.isArray(vulns) && vulns.length > 0) {
          const ids = vulns.map((v) => v.id).filter((x): x is string => typeof x === 'string');
          const group: OsvVulnGroup = {
            ecosystem: pkg.ecosystem,
            name: pkg.name,
            vuln_ids: ids,
            severity: 'high',
          };
          if (pkg.version) group.version = pkg.version;
          vulnerable.push(group);
        }
      });
    }
  } catch (e) {
    return {
      online: false,
      queried: queryable.length,
      vulnerable_packages: [],
      error: e instanceof Error ? e.message : 'osv_request_failed',
    };
  }

  return { online: true, queried: queryable.length, vulnerable_packages: vulnerable };
}

async function postJson(
  url: string,
  body: unknown,
  opts: { signal?: AbortSignal; timeoutMs?: number },
): Promise<unknown> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), opts.timeoutMs ?? DEFAULT_TIMEOUT_MS);
  if (opts.signal) {
    if (opts.signal.aborted) controller.abort();
    else opts.signal.addEventListener('abort', () => controller.abort(), { once: true });
  }
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
    if (!res.ok) throw new Error(`osv http ${res.status}`);
    return await res.json();
  } finally {
    clearTimeout(timeout);
  }
}
