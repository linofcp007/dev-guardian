/**
 * Normalizes the MCP server entries out of one config source.
 *
 * Different hosts spell the same idea differently (`mcpServers` vs
 * `servers`), so `ConfigSource.mcpServersField` says which top-level key
 * this file's shape uses — `configSources.ts` owns that mapping. This module
 * just reads whichever key it is told to and normalizes each entry.
 *
 * Pure function. No I/O.
 */
export function extractMcpServers(source) {
    if (!source.exists || source.mcpServersField === null || source.json === undefined)
        return [];
    const container = getObject(source.json, source.mcpServersField);
    if (container === undefined)
        return [];
    const out = [];
    for (const [name, value] of Object.entries(container)) {
        if (value === null || typeof value !== 'object' || Array.isArray(value))
            continue;
        const raw = value;
        const entry = { sourceLabel: source.label, name, raw };
        const command = raw['command'];
        if (typeof command === 'string')
            entry.command = command;
        const args = raw['args'];
        if (Array.isArray(args) && args.every((a) => typeof a === 'string'))
            entry.args = args;
        const cwd = raw['cwd'];
        if (typeof cwd === 'string')
            entry.cwd = cwd;
        const url = raw['url'];
        if (typeof url === 'string')
            entry.url = url;
        const type = raw['type'];
        if (typeof type === 'string')
            entry.type = type;
        const env = raw['env'];
        if (env !== null && typeof env === 'object' && !Array.isArray(env)) {
            entry.env = env;
        }
        out.push(entry);
    }
    return out;
}
function getObject(json, key) {
    if (json === null || typeof json !== 'object' || Array.isArray(json))
        return undefined;
    const value = json[key];
    if (value === null || typeof value !== 'object' || Array.isArray(value))
        return undefined;
    return value;
}
//# sourceMappingURL=mcpServers.js.map