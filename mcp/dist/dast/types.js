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
    // Not one of the own engine's nine checks above — nuclei is a separate
    // scanning engine (design doc §7) whose hits are normalised in
    // `normalizeNuclei.ts`. It still needs a `DastCheck` value of its own:
    // `DastFinding.check` is this closed union, and reusing an existing own-
    // engine value (e.g. tagging a nuclei hit `info_disclosure`) would make
    // `subcategory` lie about which engine produced the finding — precisely
    // what §7 says the result must never do — and risks two unrelated findings
    // colliding onto one fingerprint if they ever share a (method, path).
    'nuclei',
];
//# sourceMappingURL=types.js.map