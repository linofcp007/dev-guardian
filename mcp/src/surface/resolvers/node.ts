/**
 * Resolve Express/Fastify/NestJS router mounting into real path prefixes.
 *
 * Semgrep sees `router.get('/list')` and `app.use('/api', usersRouter)` as
 * two unrelated matches in two files. Connecting them needs the import that
 * bound the variable:
 *
 *   app.ts:  import usersRouter from './routes/users'
 *   app.ts:  app.use('/api', usersRouter)
 *   routes/users.ts:  router.get('/list')      →  /api/list
 *
 * When a link in that chain is missing — a computed prefix, a re-exported
 * router, a module mounted at two different prefixes — we do NOT guess. The
 * route keeps its raw path and is flagged `path_partial`, so downstream
 * consumers know the path is incomplete rather than believing a wrong one.
 */

import type { MountRecord, RouteRecord } from '../../types.js';

export interface ImportRecord {
  /** The bound local symbol, e.g. `usersRouter`. */
  symbol: string;
  /** Project-relative file the symbol resolves to, e.g. `src/routes/users.ts`. */
  module_file: string;
  /** File containing the import statement. */
  file: string;
}

const NODE_LANGUAGES = new Set(['javascript', 'typescript']);

export function resolveNodeMounts(
  routes: RouteRecord[],
  mounts: MountRecord[],
  imports: ImportRecord[],
): RouteRecord[] {
  const prefixesByFile = buildPrefixIndex(mounts, imports);
  const mountingFiles = new Set(mounts.map((m) => m.file));

  return routes.map((route) => {
    if (!NODE_LANGUAGES.has(route.language)) return route;
    // A route declared in the same file that does the mounting is attached to
    // the app directly, not to a mounted sub-router.
    if (mountingFiles.has(route.file)) return route;

    const prefixes = prefixesByFile.get(route.file);
    if (prefixes === undefined || prefixes.size !== 1) {
      return { ...route, path_partial: true };
    }
    const prefix = [...prefixes][0];
    if (prefix === undefined) return { ...route, path_partial: true };

    return { ...route, path_resolved: joinPath(prefix, route.path_raw), path_partial: false };
  });
}

/** module file → the set of distinct prefixes it is mounted at. */
function buildPrefixIndex(
  mounts: MountRecord[],
  imports: ImportRecord[],
): Map<string, Set<string>> {
  const index = new Map<string, Set<string>>();
  for (const mount of mounts) {
    const binding = imports.find(
      (i) => i.file === mount.file && i.symbol === mount.router_var,
    );
    if (binding === undefined) continue;
    const existing = index.get(binding.module_file);
    if (existing === undefined) {
      index.set(binding.module_file, new Set([mount.prefix]));
    } else {
      existing.add(mount.prefix);
    }
  }
  return index;
}

export function joinPath(prefix: string, path: string): string {
  const left = prefix.replace(/\/+$/, '');
  const right = path.startsWith('/') ? path : `/${path}`;
  const joined = `${left}${right}`;
  return joined.startsWith('/') ? joined : `/${joined}`;
}
