/**
 * The verdict envelope, shared by all three evidence providers.
 *
 * Defined once, now, so `runtime` and `dependency` slot in without changing
 * the persisted shape. If either later needs a change here, that is a finding
 * against the design, not against that provider.
 */
export const VERDICTS = ['unreachable', 'reachable', 'confirmed', 'unknown'];
export const PROVIDERS = ['static', 'runtime', 'dependency'];
//# sourceMappingURL=types.js.map