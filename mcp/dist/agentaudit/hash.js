/**
 * Deterministic hashing for MCP server config entries.
 *
 * Used to detect "this entry changed since the previous audit" — see
 * `storage/agentAuditRepo.ts`. Key order in the source JSON file must never
 * itself look like a change, so objects are stringified with their keys
 * sorted (recursively); array order IS preserved, since `args: ["-y", "pkg"]`
 * and `args: ["pkg", "-y"]` are genuinely different invocations.
 *
 * ITERATIVE (fix round 5 of the 3.0 additions, I-1): the recursive form —
 * sort the keys, then `JSON.stringify` — overflowed the stack on a value some
 * thousands of levels deep (6000 nested arrays, 12 KB, which an MCP server
 * controls), and took the whole audit down with it; `JSON.stringify` alone
 * overflows at ~5000. This produces the SAME string for any JSON data — the
 * test compares it with the recursive form byte for byte — because
 * `agent_config_hashes` (shipped in 2.0) stores hashes of it.
 *
 * Pure functions. No I/O.
 */
import { createHash } from 'node:crypto';
/** Text to emit as is, pushed on the work stack beside the values still to serialise. */
class Literal {
    text;
    constructor(text) {
        this.text = text;
    }
}
/** What `JSON.stringify` leaves out of an object, and writes as `null` in an array. */
function omitted(v) {
    return v === undefined || typeof v === 'function' || typeof v === 'symbol';
}
/**
 * `JSON.stringify` with object keys sorted (code-unit order, as `.sort()`),
 * arrays in their order, at any depth. Values are JSON data: plain objects,
 * arrays, strings, numbers, booleans, null.
 */
export function stableStringify(value) {
    const parts = [];
    const stack = [value];
    while (stack.length > 0) {
        const item = stack.pop();
        if (item instanceof Literal) {
            parts.push(item.text);
            continue;
        }
        if (Array.isArray(item)) {
            parts.push('[');
            stack.push(new Literal(']'));
            for (let i = item.length - 1; i >= 0; i -= 1) {
                const element = item[i];
                stack.push(omitted(element) ? new Literal('null') : element);
                if (i > 0)
                    stack.push(new Literal(','));
            }
            continue;
        }
        if (item !== null && typeof item === 'object') {
            const record = item;
            const keys = Object.keys(record)
                .sort()
                .filter((k) => !omitted(record[k]));
            parts.push('{');
            stack.push(new Literal('}'));
            for (let i = keys.length - 1; i >= 0; i -= 1) {
                const key = keys[i] ?? '';
                stack.push(record[key]);
                stack.push(new Literal(`${JSON.stringify(key)}:`));
                if (i > 0)
                    stack.push(new Literal(','));
            }
            continue;
        }
        // A scalar. NaN and ±Infinity are `null`, as JSON.stringify writes them.
        parts.push(omitted(item) ? 'null' : (JSON.stringify(item) ?? 'null'));
    }
    return parts.join('');
}
/** sha256(stableStringify(value)), hex-encoded. */
export function hashConfigValue(value) {
    return createHash('sha256').update(stableStringify(value)).digest('hex');
}
//# sourceMappingURL=hash.js.map