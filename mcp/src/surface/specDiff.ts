/**
 * Compare routes extracted from source against routes declared in a spec.
 *
 * Pure. The two rules that matter are both about refusing to guess:
 *
 *   1. With no spec parsed there is no diff. `null`, not a diff in which every
 *      code route is undocumented.
 *   2. A route whose full path is unknown goes to `unmatchable`, and so does
 *      any spec route it might have been. See `spec_only` below.
 */

import type { HttpMethod, RouteRecord, SpecDiff, SpecDiffEntry } from '../types.js';

const PARAM_SYNTAX: readonly RegExp[] = [
  // WordPress first: `(?P<id>\d+)` contains `<id>`, which the Flask rule would
  // otherwise eat and leave `(?P{}\d+)` behind.
  /\(\?P<[^>]+>[^)]*\)/g,
  /\{[^}]*\}/g,        // OpenAPI, Spring: {id}
  /<[^>]*>/g,          // Flask: <int:id>
  /:[A-Za-z_]\w*\??/g, // Express, Rails: :id and :id?
];

export function normalisePath(path: string): string {
  let out = path;
  for (const re of PARAM_SYNTAX) out = out.replace(re, '{}');
  out = out.replace(/\/+$/, '');
  if (!out.startsWith('/')) out = `/${out}`;
  return out;
}

/**
 * `'ANY'` is a routing sentinel (a catch-all handler, or an operation key
 * OpenAPI/Swagger has no `HttpMethod` for — see `operationMethod` in
 * specImport.ts), not a wire method. It matches every concrete method the
 * other side declares at the same path.
 */
function methodsMatch(codeMethod: HttpMethod, specMethod: HttpMethod): boolean {
  return codeMethod === specMethod || codeMethod === 'ANY' || specMethod === 'ANY';
}

/** The concrete method is more informative than the `'ANY'` sentinel in a
 *  report meant for a human, so prefer it when the two disagree. */
function displayMethod(codeMethod: HttpMethod, specMethod: HttpMethod): HttpMethod {
  return codeMethod === 'ANY' ? specMethod : codeMethod;
}

/** Resolvable routes grouped by their normalised `path_resolved`. */
function indexByPath(routes: readonly RouteRecord[]): Map<string, RouteRecord[]> {
  const index = new Map<string, RouteRecord[]>();
  for (const route of routes) {
    const path = normalisePath(route.path_resolved);
    const bucket = index.get(path);
    if (bucket === undefined) index.set(path, [route]);
    else bucket.push(route);
  }
  return index;
}

/** `null` when no spec parsed — never a diff in which everything is undocumented. */
export function diffSpecRoutes(
  codeRoutes: readonly RouteRecord[],
  specRoutes: readonly RouteRecord[],
  specsParsed: number,
): SpecDiff | null {
  // Defensive: the caller splits by provenance, but a mislabelled route must
  // not diff a set against itself.
  const code = codeRoutes.filter((r) => r.provenance === 'code');
  const spec = specRoutes.filter((r) => r.provenance === 'spec');

  // No spec was found — that is not the same fact as "the spec documents
  // nothing" (specsParsed > 0 with specRoutes empty falls through below).
  // `<= 0`, not `=== 0`: a caller computing `parsed − failed` could hand us
  // a negative, and that must gate the same way zero does, not fall through
  // to a full diff where every code route reads as undocumented.
  if (specsParsed <= 0) return null;

  const codeResolvable = code.filter((r) => !r.path_partial);
  const codePartial = code.filter((r) => r.path_partial);
  const specResolvable = spec.filter((r) => !r.path_partial);
  const specPartial = spec.filter((r) => r.path_partial);

  const specByPath = indexByPath(specResolvable);

  // Every (code, spec) pair sharing a normalised path and a compatible
  // method is a match. A single code route can legitimately pair with more
  // than one spec route (an `ANY` handler covers every method a spec
  // documents at that path) — each such pair gets its own entry so no spec
  // route that genuinely has a code counterpart is later mistaken for dead
  // documentation just because some OTHER spec route at the same path was
  // picked first.
  const matched: SpecDiffEntry[] = [];
  const matchedCode = new Set<RouteRecord>();
  const matchedSpec = new Set<RouteRecord>();

  for (const c of codeResolvable) {
    const path = normalisePath(c.path_resolved);
    const candidates = specByPath.get(path) ?? [];
    for (const s of candidates) {
      if (!methodsMatch(c.method, s.method)) continue;
      matched.push({ method: displayMethod(c.method, s.method), path, code_route: c, spec_route: s });
      matchedCode.add(c);
      matchedSpec.add(s);
    }
  }

  const unmatchable: SpecDiffEntry[] = [];
  for (const c of codePartial) {
    unmatchable.push({
      method: c.method,
      path: normalisePath(c.path_raw),
      code_route: c,
      reason: 'code route has an unresolved prefix',
    });
  }
  for (const s of specPartial) {
    unmatchable.push({
      method: s.method,
      path: normalisePath(s.path_raw),
      spec_route: s,
      reason: 'spec server url is templated',
    });
  }

  // A resolvable code route nobody's spec matched LOOKS like a shadow
  // endpoint — unless a partial spec route's raw path is a suffix of it. A
  // partial spec route (its own prefix unresolved — typically a templated
  // `servers[].url`) is missing exactly a prefix, never a suffix, so suffix
  // is the test that asks "could this unresolved spec route BE this code
  // path": if so, the code route joins unmatchable instead — it is not a
  // shadow endpoint, it is the very route this diff could not resolve. This
  // costs some true shadow-endpoint findings; that is the correct direction
  // — see the mirror-image comment on spec_only below for why a false
  // positive here is worse than a withheld true one. `code_only_withheld`
  // counts how many, so the cost is visible rather than a silent gap.
  const code_only: SpecDiffEntry[] = [];
  let code_only_withheld = 0;
  for (const c of codeResolvable) {
    if (matchedCode.has(c)) continue;
    const path = normalisePath(c.path_resolved);
    const shadowing = specPartial.find((p) => path.endsWith(normalisePath(p.path_raw)));
    if (shadowing === undefined) {
      code_only.push({ method: c.method, path, code_route: c });
    } else {
      unmatchable.push({
        method: c.method,
        path,
        code_route: c,
        reason: `may be the same route as the partial spec route at ${shadowing.file}:${shadowing.line}`,
      });
      code_only_withheld += 1;
    }
  }

  // Mirror of the guard above: a resolvable spec route nobody's code matched
  // LOOKS like dead documentation — unless a partial code route's raw path is
  // a suffix of it. If so, the spec route joins unmatchable instead — it is
  // not dead, it is the very route this diff could not resolve. This costs
  // some true dead-documentation findings; that is the correct direction,
  // because a false "this no longer exists" is what gets working docs
  // deleted. `spec_only_withheld` counts how many, so the cost is visible
  // rather than a silent gap.
  const spec_only: SpecDiffEntry[] = [];
  let spec_only_withheld = 0;
  for (const s of specResolvable) {
    if (matchedSpec.has(s)) continue;
    const path = normalisePath(s.path_resolved);
    const shadowing = codePartial.find((p) => path.endsWith(normalisePath(p.path_raw)));
    if (shadowing === undefined) {
      spec_only.push({ method: s.method, path, spec_route: s });
    } else {
      unmatchable.push({
        method: s.method,
        path,
        spec_route: s,
        reason: `may be the same route as the partial code route at ${shadowing.file}:${shadowing.line}`,
      });
      spec_only_withheld += 1;
    }
  }

  return { matched, code_only, spec_only, unmatchable, code_only_withheld, spec_only_withheld };
}
