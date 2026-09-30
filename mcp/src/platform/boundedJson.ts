/**
 * `JSON.parse` of a repository's file, bounded by the file's structure as
 * well as its size — the dependency-free half of `platform/boundedParse.ts`
 * (see there for the measurements), so `platform/projectFs.ts` can use it
 * without importing a package.
 */

export type BoundedParse =
  | { ok: true; value: unknown }
  | { ok: false; reason: 'too-complex' | 'too-large' | 'too-deep' | 'too-expanded' | 'invalid'; detail?: string };

/**
 * JSON values a parsed file may hold, counted as its `{`, `[` and `,`: a
 * large real `package-lock.json` (tens of MB) has several hundred thousand.
 * Counting only containers would miss `[1,1,1,…]` — one array, 33 million
 * numbers in 64 MiB. 60 MiB of `[{},{},…]` under the 64 MiB lock-file cap
 * took `JSON.parse` to 1.35 GB and a 20 s block (review of 3.0, W2E).
 */
export const JSON_MAX_NODES = 2_000_000;

/** Whether `text` holds more than `max` of the characters in `codes`, counted until the answer is known. */
export function exceedsCount(text: string, codes: ReadonlySet<number>, max: number): boolean {
  let n = 0;
  for (let i = 0; i < text.length; i++) {
    if (codes.has(text.charCodeAt(i))) {
      n += 1;
      if (n > max) return true;
    }
  }
  return false;
}

/** A JSON value opens a container or follows a `,` (counted inside strings too: an over-count, never an under-count). */
const JSON_NODE_CHARS: ReadonlySet<number> = new Set([0x7b, 0x5b, 0x2c]);

/** `JSON.parse` of `text` (a leading byte-order mark tolerated), when it holds at most `maxNodes` values ({@link JSON_MAX_NODES}). */
export function parseJsonBounded(text: string, maxNodes: number = JSON_MAX_NODES): BoundedParse {
  if (exceedsCount(text, JSON_NODE_CHARS, maxNodes)) return { ok: false, reason: 'too-complex' };
  try {
    return { ok: true, value: JSON.parse(text.charCodeAt(0) === 0xfeff ? text.slice(1) : text) as unknown };
  } catch (e) {
    return { ok: false, reason: 'invalid', detail: e instanceof Error ? e.message : String(e) };
  }
}

/** A sentence for a `too-complex` refusal. */
export function describeTooComplex(max: number, what: 'YAML nodes' | 'JSON values'): string {
  return `it holds more than ${max} ${what}, more than dev-guardian parses (a parse that large can exhaust the server's memory), and was not read`;
}
