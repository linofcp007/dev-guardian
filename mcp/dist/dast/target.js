/**
 * Target classification and the authorization gate.
 *
 * Purely lexical over the URL string — DNS is never resolved. Resolving would
 * open the door to DNS rebinding (classify as loopback, connect to something
 * else on the retry) and would make this module impure. The only error this
 * can make is asking for attestation it did not strictly need; it can never
 * wave through a host it should have stopped.
 *
 * `private` and `public` are gated identically — only loopback is
 * auto-allowed. The distinction exists solely to word the refusal accurately;
 * it must never widen what is allowed.
 */
const LOOPBACK_HOSTS = new Set(['localhost', '::1', '[::1]']);
export function classifyTarget(baseUrl, authorized) {
    let parsed;
    try {
        parsed = new URL(baseUrl);
    }
    catch {
        return {
            allowed: false,
            target_class: 'public',
            origin: '',
            host: '',
            reason: `\`${baseUrl}\` is not a valid URL.`,
        };
    }
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        return {
            allowed: false,
            target_class: 'public',
            origin: '',
            host: parsed.hostname,
            reason: `Only http and https targets are supported (got \`${parsed.protocol}\`).`,
        };
    }
    const host = parsed.hostname;
    const targetClass = classifyHost(host);
    const origin = parsed.origin;
    if (targetClass === 'loopback') {
        return { allowed: true, target_class: targetClass, origin, host, reason: null };
    }
    if (authorized) {
        return { allowed: true, target_class: targetClass, origin, host, reason: null };
    }
    const where = targetClass === 'private'
        ? 'is on your private network'
        : 'is on the public internet';
    return {
        allowed: false,
        target_class: targetClass,
        origin,
        host,
        reason: `\`${host}\` ${where}, not loopback. Re-run with \`authorized_target: true\` ` +
            `to confirm you are authorised to send scan traffic to it. ` +
            `A hostname that resolves to localhost still needs this: the classification ` +
            `is lexical on purpose, so it can never be tricked into treating someone ` +
            `else's server as your own.`,
    };
}
function classifyHost(host) {
    const lower = host.toLowerCase();
    if (LOOPBACK_HOSTS.has(lower))
        return 'loopback';
    const v4 = parseIpv4(lower);
    if (v4 !== null) {
        const [a, b] = v4;
        if (a === 127)
            return 'loopback';
        if (a === 10)
            return 'private';
        if (a === 172 && b >= 16 && b <= 31)
            return 'private';
        if (a === 192 && b === 168)
            return 'private';
        if (a === 169 && b === 254)
            return 'private';
        return 'public';
    }
    // `URL.hostname` keeps IPv6 in brackets; strip before matching the ULA
    // prefix fc00::/7 (fc00–fdff).
    const v6 = lower.startsWith('[') && lower.endsWith(']') ? lower.slice(1, -1) : lower;
    if (v6 === '::1')
        return 'loopback';
    if (/^f[cd][0-9a-f]{2}:/.test(v6))
        return 'private';
    if (/^fe80:/.test(v6))
        return 'private';
    return 'public';
}
/** Returns the four octets, or null when `host` is not a dotted-quad literal. */
function parseIpv4(host) {
    const parts = host.split('.');
    if (parts.length !== 4)
        return null;
    const nums = [];
    for (const part of parts) {
        if (!/^\d{1,3}$/.test(part))
            return null;
        const n = Number(part);
        if (n > 255)
            return null;
        nums.push(n);
    }
    const [a, b, c, d] = nums;
    if (a === undefined || b === undefined || c === undefined || d === undefined)
        return null;
    return [a, b, c, d];
}
//# sourceMappingURL=target.js.map