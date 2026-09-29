/**
 * Tool registry.
 *
 * Each phase that adds tools appends entries to the `TOOLS` array. The
 * server iterates the array on startup and calls `registerTool` for each
 * entry. No other file in the codebase needs to know about the SDK shape.
 */
import { z } from 'zod';
import { boundResponsePayload } from './responseBounds.js';
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
/**
 * Wire every registered tool into an active McpServer.
 *
 * Each input schema is registered STRICT. Handed a raw shape, the SDK wraps
 * it in a stripping `z.object`: a key the tool does not take was removed
 * without a word, while `tools/list` advertised `additionalProperties:
 * false`. A misnamed parameter therefore became the default instead of an
 * error — `scan_skill { project_path }` (it takes `target`) audited the
 * server's working directory and answered SAFE. Strict, the SDK answers
 * -32602 naming the key, before the handler runs. (A tool with no
 * parameters used to get no validation at all: the SDK skips an empty
 * shape.)
 */
export function attachAllTools(server, ctx) {
    for (const tool of TOOLS) {
        server.registerTool(tool.name, {
            ...(tool.title ? { title: tool.title } : {}),
            description: tool.description,
            inputSchema: strictInputSchema(tool),
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
            return toCallToolResult(result, tool.contentOnlyKeys ?? []);
        });
    }
}
/** The schema a tool is registered with: its shape, rejecting any other key. */
export function strictInputSchema(tool) {
    return z.object(tool.inputSchema).strict();
}
/**
 * A handler's result as the MCP host receives it. Per-file gap lists are cut
 * here and only here (`tools/responseBounds.ts`): the row and every internal
 * caller keep them whole. Exported for the response-size tests.
 */
export function toCallToolResult(result, contentOnlyKeys) {
    if (result.ok) {
        const { ok: _ok, ...rest } = result;
        const payload = boundResponsePayload({ ok: true, ...rest });
        const structured = { ...payload };
        for (const key of contentOnlyKeys)
            delete structured[key];
        // A tool with a bulky content-only payload is serialised compactly too:
        // re-indenting an inlined document adds whitespace to every line of it.
        const indent = contentOnlyKeys.length > 0 ? undefined : 2;
        return {
            content: [{ type: 'text', text: JSON.stringify(payload, null, indent) }],
            structuredContent: structured,
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