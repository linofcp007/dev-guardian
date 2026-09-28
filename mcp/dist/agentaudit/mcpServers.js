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
function remoteAddress(raw, sourceLabel) {
    const str = (k) => (typeof raw[k] === 'string' ? raw[k] : undefined);
    const type = str('type')?.toLowerCase();
    const gemini = /(^|\/)\.gemini\/settings\.json$/.test(sourceLabel);
    const httpUrl = str('httpUrl');
    const url = str('url');
    const serverUrl = str('serverUrl');
    const address = httpUrl ?? url ?? serverUrl;
    if (address === undefined)
        return undefined;
    let transport;
    if (type === 'sse')
        transport = 'sse';
    else if (type !== undefined && type !== 'stdio')
        transport = 'http';
    else if (httpUrl !== undefined)
        transport = 'http';
    else if (gemini && url !== undefined)
        transport = 'sse';
    else
        transport = /\/sse\/?(?:[?#]|$)/i.test(address) ? 'sse' : 'http';
    return { url: address, transport };
}
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
        const remote = remoteAddress(raw, source.label);
        if (remote !== undefined) {
            entry.url = remote.url;
            entry.remoteTransport = remote.transport;
        }
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