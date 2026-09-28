/**
 * What every `guardian://` resource shares: whose data it answers for, how a
 * list is paged, and how big one finding may be.
 *
 * **Scope.** A resource has no arguments beyond its URI, so it answers for
 * the project the server runs in — its working directory, in the canonical
 * spelling every scan persists (`platform/projectPath.ts#canonicalPath`).
 * Resources used to answer for "the newest scan in the database", which was
 * whichever project had scanned last; tools take `project_path` for any
 * other project.
 *
 * **Paging.** The findings resources documented `?page=` / `?page_size=`
 * and implemented them, yet `guardian://findings/open?page=2` answered
 * "Resource not found": the SDK matches a read against static URIs exactly,
 * and nothing covered a query string. They are now registered as URI
 * templates — `guardian://findings/open{?page,page_size}` — through
 * {@link QueryTolerantUriTemplate}, because the SDK's own RFC 6570 matcher
 * accepts a `{?a,b}` expression only when EVERY parameter is present, in the
 * declared order: `?page=2` alone, or `?page_size=10&page=2`, would still
 * have been "not found".
 */

import { UriTemplate, type Variables } from '@modelcontextprotocol/sdk/shared/uriTemplate.js';
import { canonicalPath } from '../platform/projectPath.js';
import type { Finding } from '../types.js';

/** Default and maximum page size for every paged resource. */
export const DEFAULT_PAGE_SIZE = 50;
export const MAX_PAGE_SIZE = 100;
/** A finding's `message` is cut to this many characters in a resource. */
export const MESSAGE_MAX_CHARS = 500;

/** The project a resource answers for: the server's working directory. */
export function serverProjectPath(): string {
  return canonicalPath(process.cwd());
}

/**
 * A URI template whose trailing `{?a,b,…}` expression matches any subset of
 * its parameters, in any order — and the bare URI with none. Unknown
 * parameters are ignored rather than turned into "Resource not found". The
 * part before the query expression is matched by the SDK's own template.
 */
export class QueryTolerantUriTemplate extends UriTemplate {
  private readonly base: UriTemplate;
  private readonly queryNames: readonly string[];

  constructor(template: string) {
    super(template);
    const m = /\{\?([^}]*)\}$/.exec(template);
    const baseTemplate = m ? template.slice(0, m.index) : template;
    this.base = new UriTemplate(baseTemplate);
    this.queryNames = m?.[1] ? m[1].split(',').map((n) => n.trim()).filter((n) => n.length > 0) : [];
  }

  override match(uri: string): Variables | null {
    const q = uri.indexOf('?');
    const path = q === -1 ? uri : uri.slice(0, q);
    const vars = this.base.match(path);
    if (vars === null) return null;
    if (q === -1) return vars;
    const params = new URLSearchParams(uri.slice(q + 1));
    const out: Variables = { ...vars };
    for (const name of this.queryNames) {
      const value = params.get(name);
      if (value !== null) out[name] = value;
    }
    return out;
  }
}

export interface Page<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
}

/**
 * Pages `all` by the URI's `?page=N&page_size=M` (defaults 1 and
 * {@link DEFAULT_PAGE_SIZE}; the size is capped at {@link MAX_PAGE_SIZE}).
 * The total is returned too, so a caller can loop without guessing.
 */
export function paginate<T>(uri: URL, all: readonly T[]): Page<T> {
  const total = all.length;
  const pageRaw = Number(uri.searchParams.get('page') ?? '1');
  const sizeRaw = Number(uri.searchParams.get('page_size') ?? String(DEFAULT_PAGE_SIZE));
  const page = Number.isFinite(pageRaw) && pageRaw > 0 ? Math.floor(pageRaw) : 1;
  const page_size =
    Number.isFinite(sizeRaw) && sizeRaw > 0 ? Math.min(Math.floor(sizeRaw), MAX_PAGE_SIZE) : DEFAULT_PAGE_SIZE;
  const start = (page - 1) * page_size;
  return { items: all.slice(start, start + page_size), total, page, page_size };
}

/** `f` with its `message` cut to {@link MESSAGE_MAX_CHARS} characters. */
export function boundFinding<T extends Finding>(f: T): T {
  if (f.message === undefined || f.message.length <= MESSAGE_MAX_CHARS) return f;
  return { ...f, message: `${f.message.slice(0, MESSAGE_MAX_CHARS - 1)}…` };
}
