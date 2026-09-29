/**
 * The verdict envelope, shared by all three evidence providers.
 *
 * Defined once, so `runtime` and `dependency` slot in without changing the
 * persisted shape. The one addition since: `dependency` needed a verdict the
 * other two never give — `imported`, "the project's code imports this
 * package, and no route was shown to reach the file that does". It is not
 * `reachable` (nothing connects it to a route) and it must not be
 * `unreachable` (the graph proves no absence of a path to a package), so it
 * is its own value — the only schema change, a new string in a TEXT column.
 */
export const VERDICTS = ['unreachable', 'reachable', 'imported', 'confirmed', 'unknown'];
export const PROVIDERS = ['static', 'runtime', 'dependency'];
/** The providers this version implements, in the order they run and report. */
export const IMPLEMENTED_PROVIDERS = ['static', 'dependency'];
//# sourceMappingURL=types.js.map