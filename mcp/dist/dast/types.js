/**
 * Shared shapes for the DAST engine.
 *
 * Kept in their own module (rather than in the top-level `types.ts`) because
 * none of them are persisted: they are the in-flight vocabulary of one scan.
 * The only DAST shape that reaches storage is `Finding`, which already exists.
 */
export const DAST_CHECKS = [
    'reachability',
    'anonymous_exposure',
    'differential_authz',
    'cors',
    'security_headers',
    'info_disclosure',
    'method_surface',
    'open_redirect',
    'rate_limit',
];
//# sourceMappingURL=types.js.map