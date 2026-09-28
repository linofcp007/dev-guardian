/**
 * Which declared entries a requested server name starts (fix round 3, I1),
 * and the keys an audited server is stored under (M6).
 *
 * A name is either qualified — `<source label>::<name>`, exactly as the
 * response's `server_key` prints it — or bare. A qualified name starts that
 * one entry. A bare name matching several entries starts them once when
 * they all launch the same way (the same server declared in two files), and
 * is REFUSED when they launch differently: which one the user meant is not
 * this tool's guess to make, and starting all of them ran code nobody named.
 * The refusal lists the qualified names to choose from.
 *
 * Pure functions. No I/O.
 */
import { hashConfigValue } from '../agentaudit/hash.js';
/** `<source>::<name>`: what a caller passes to pick one entry, and what the response prints. */
export function qualifiedName(e) {
    return `${e.sourceLabel}::${e.name}`;
}
/**
 * The key pins are stored under: JSON of `[source, name]`, which no two
 * entries share — unlike `<source>::<name>`, where `p)::x` + `y` and `p` +
 * `x)::y` read the same.
 */
export function serverPinKey(e) {
    return JSON.stringify([e.sourceLabel, e.name]);
}
/** The server name inside a {@link serverPinKey}; the whole key when it is not one. */
export function serverNameOfPinKey(key) {
    try {
        const parsed = JSON.parse(key);
        if (Array.isArray(parsed) && parsed.length === 2 && typeof parsed[1] === 'string')
            return parsed[1];
    }
    catch {
        /* not a JSON key */
    }
    return key;
}
/** What launching an entry means: two entries with the same value start the same server. */
function launchIdentity(e) {
    return hashConfigValue({
        command: e.command ?? null,
        args: e.args ?? null,
        env: e.env ?? null,
        cwd: e.cwd ?? null,
        url: e.url ?? null,
        transport: e.remoteTransport ?? null,
        headers: e.raw['headers'] ?? null,
    });
}
export function planTargets(requested, entries) {
    const plan = [];
    const started = new Map();
    for (const name of requested) {
        const qualified = entries.filter((e) => qualifiedName(e) === name);
        let candidates = qualified.length > 0 ? qualified : entries.filter((e) => e.name === name);
        if (candidates.length === 0) {
            plan.push({ requested: name, kind: 'missing' });
            continue;
        }
        const launches = new Set(candidates.map(launchIdentity));
        if (launches.size > 1) {
            plan.push({
                requested: name,
                kind: 'refuse',
                reason: `${candidates.length} entries named '${name}' launch different servers: ` +
                    `${candidates.map(qualifiedName).join(', ')}. Name one of them as <source>::<name>.`,
            });
            continue;
        }
        candidates = [...candidates];
        const [first, ...rest] = candidates;
        if (first === undefined)
            continue;
        const already = started.get(first);
        if (already !== undefined) {
            plan.push({ requested: name, kind: 'duplicate', of: already });
            continue;
        }
        started.set(first, name);
        plan.push({ requested: name, kind: 'start', entry: first, alsoDeclaredIn: rest.map(qualifiedName) });
    }
    return plan;
}
//# sourceMappingURL=select.js.map