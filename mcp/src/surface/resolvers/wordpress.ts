/**
 * Resolve WordPress REST routes to their served path.
 *
 * `register_rest_route('myplugin/v1', '/items', ...)` is reachable at
 * `/wp-json/myplugin/v1/items`. Semgrep captures the namespace and the route
 * as two separate metavariables and cannot concatenate them, so the
 * extractor stores the namespace on `RouteRecord.namespace` and the route on
 * `path_raw`. This module is the only place that knows how they combine.
 *
 * Without a namespace we cannot know where the route is served, so it is
 * flagged `path_partial` rather than guessed at. The same applies when either
 * half is a code expression instead of a literal — `self::NAMESPACE` and
 * `$this->namespace` are the dominant idioms in real plugins, and
 * `/wp-json/self::NAMESPACE/items` is a URL that exists nowhere. The
 * extractor already decided that (extract.ts `isLiteralPath`); this module
 * only has to not undo it.
 */

import type { RouteRecord } from '../../types.js';
import { joinPath } from './node.js';

const WP_REST_PREFIX = '/wp-json';
const WP_FRAMEWORK = 'wp-rest';

export function resolveWordpressRoutes(routes: RouteRecord[]): RouteRecord[] {
  return routes.map((route) => {
    if (route.framework !== WP_FRAMEWORK) return route;
    // Already unusable upstream: a namespace can only ever add a prefix, never
    // rescue a route value we could not read.
    if (route.path_partial) return route;

    const namespace = (route.namespace ?? '').trim().replace(/^\/+|\/+$/g, '');
    if (namespace.length === 0) return { ...route, path_partial: true };

    return {
      ...route,
      path_resolved: joinPath(`${WP_REST_PREFIX}/${namespace}`, route.path_raw),
      path_partial: false,
    };
  });
}
