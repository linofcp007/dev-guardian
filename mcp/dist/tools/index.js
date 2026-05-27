/**
 * Tool registry.
 *
 * Each phase that adds tools appends entries to the `TOOLS` array. The
 * server iterates the array on startup and calls `registerTool` for each
 * entry. No other file in the codebase needs to know about the SDK shape.
 */
/**
 * Mutable global registry. Modules append themselves at import time via
 * `registerToolModule`, which lets us keep additions localized to each
 * tool's file rather than threading a list through the bootstrap.
 */
export const TOOLS = [];
export function registerToolModule(tool) {
    if (TOOLS.some((t) => t.name === tool.name)) {
        throw new Error(`Tool '${tool.name}' is already registered`);
    }
    TOOLS.push(tool);
}
/** Wire every registered tool into an active McpServer. */
export function attachAllTools(server, ctx) {
    for (const tool of TOOLS) {
        server.registerTool(tool.name, {
            ...(tool.title ? { title: tool.title } : {}),
            description: tool.description,
            inputSchema: tool.inputSchema,
        }, async (input, extra) => {
            const callMeta = {};
            const typedExtra = extra;
            const tokenRaw = typedExtra?._meta?.progressToken;
            if (typeof tokenRaw === 'string' || typeof tokenRaw === 'number') {
                callMeta.progressToken = tokenRaw;
            }
            if (typedExtra?.signal instanceof AbortSignal) {
                callMeta.signal = typedExtra.signal;
            }
            const result = await tool.handler(input, ctx, callMeta);
            return toCallToolResult(result);
        });
    }
}
function toCallToolResult(result) {
    if (result.ok) {
        const { ok: _ok, ...rest } = result;
        const payload = { ok: true, ...rest };
        return {
            content: [{ type: 'text', text: JSON.stringify(payload, null, 2) }],
            structuredContent: payload,
        };
    }
    const errorPayload = { ok: false, error: result.error };
    return {
        isError: true,
        content: [
            {
                type: 'text',
                text: `Error (${result.error.code}): ${result.error.message}`,
            },
        ],
        structuredContent: errorPayload,
    };
}
//# sourceMappingURL=index.js.map