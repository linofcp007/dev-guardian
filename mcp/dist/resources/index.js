/**
 * Resource registry.
 *
 * Every resource serves JSON. Resources with parameterized URIs (e.g.
 * `guardian://scans/{scan_id}`) are registered via the SDK's
 * `ResourceTemplate`; static URIs use the simple string form.
 */
import { ResourceTemplate, } from '@modelcontextprotocol/sdk/server/mcp.js';
export const RESOURCES = [];
export function registerResourceModule(resource) {
    if (RESOURCES.some((r) => r.name === resource.name)) {
        throw new Error(`Resource '${resource.name}' is already registered`);
    }
    RESOURCES.push(resource);
}
export function attachAllResources(server, ctx) {
    for (const resource of RESOURCES) {
        const mimeType = resource.mimeType ?? 'application/json';
        if (resource.isTemplate) {
            const template = new ResourceTemplate(resource.uri, { list: undefined });
            server.registerResource(resource.name, template, { description: resource.description, mimeType }, async (uri, params) => {
                const normalizedParams = normalizeParams(params);
                const { json } = await resource.handler(uri, normalizedParams, ctx);
                return {
                    contents: [
                        { uri: uri.href, mimeType, text: JSON.stringify(json, null, 2) },
                    ],
                };
            });
        }
        else {
            server.registerResource(resource.name, resource.uri, { description: resource.description, mimeType }, async (uri) => {
                const { json } = await resource.handler(uri, {}, ctx);
                return {
                    contents: [
                        { uri: uri.href, mimeType, text: JSON.stringify(json, null, 2) },
                    ],
                };
            });
        }
    }
}
function normalizeParams(params) {
    // Surface a stable shape — templates that capture a single segment yield a
    // string, multi-capture yields an array. We pass both through verbatim
    // (handlers know which one they expect).
    return params;
}
//# sourceMappingURL=index.js.map