/**
 * Deterministic hashing for MCP server config entries.
 *
 * Used to detect "this entry changed since the previous audit" — see
 * `storage/agentAuditRepo.ts`. Key order in the source JSON file must never
 * itself look like a change, so objects are stringified with their keys
 * sorted (recursively); array order IS preserved, since `args: ["-y", "pkg"]`
 * and `args: ["pkg", "-y"]` are genuinely different invocations.
 *
 * Pure functions. No I/O.
 */
import { createHash } from 'node:crypto';
/** JSON.stringify with object keys sorted recursively. Arrays keep their order. */
export function stableStringify(value) {
    return JSON.stringify(sortKeys(value));
}
function sortKeys(value) {
    if (Array.isArray(value))
        return value.map(sortKeys);
    if (value !== null && typeof value === 'object') {
        const out = {};
        for (const key of Object.keys(value).sort()) {
            out[key] = sortKeys(value[key]);
        }
        return out;
    }
    return value;
}
/** sha256(stableStringify(value)), hex-encoded. */
export function hashConfigValue(value) {
    return createHash('sha256').update(stableStringify(value)).digest('hex');
}
//# sourceMappingURL=hash.js.map