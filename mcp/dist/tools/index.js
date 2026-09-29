/**
 * Tool registry.
 *
 * Each phase that adds tools appends entries to the `TOOLS` array. The
 * server iterates the array on startup and calls `registerTool` for each
 * entry. No other file in the codebase needs to know about the SDK shape.
 */
import { z } from 'zod';
import { untrustedValue } from '../platform/untrustedText.js';
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
 * -32602 naming the key, before the handler runs.
 *
 * A call with no `arguments` at all (the MCP spec makes the field optional)
 * validates as `{}`. Measured on 430c797, before the schemas were strict, it
 * was already rejected — -32602 "Required" from every tool, `check_toolchain`
 * (no parameters at all) included — and an unknown key was stripped.
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
/**
 * The schema a tool is registered with: its shape, rejecting any other key,
 * and reading an absent `arguments` as `{}`.
 *
 * The default is applied on THIS instance's `safeParseAsync`, the one call
 * the SDK validates tool input with, rather than with `z.preprocess` or
 * `.default({})`: the SDK lists a tool's JSON schema only when the schema it
 * was given is an object (`.shape`), and either wrapper would turn every
 * tool's advertised schema into an empty one.
 */
export function strictInputSchema(tool) {
    const schema = z.object(tool.inputSchema).strict();
    const parse = schema.safeParseAsync.bind(schema);
    schema.safeParseAsync = (data, params) => parse(data ?? {}, params);
    return schema;
}
/**
 * A handler's result as the MCP host receives it. Per-file gap lists are cut
 * here and only here (`tools/responseBounds.ts`): the row and every internal
 * caller keep them whole. Exported for the response-size tests.
 *
 * Every string of the result — keys included, the error message and the
 * content-only keys too — is passed through `untrustedValue`
 * (`platform/untrustedText.ts`) here and only here: a rule message, a
 * snippet, a file name or a title from the scanned repository reaches the
 * model with its control, bidi and zero-width characters written as visible
 * `\u{XXXX}`. The handler's own object — and so the stored row — keeps its
 * bytes.
 */
export function toCallToolResult(result, contentOnlyKeys) {
    if (result.ok) {
        const { ok: _ok, ...rest } = result;
        const payload = untrustedValue(boundResponsePayload({ ok: true, ...rest }));
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
    const error = untrustedValue(result.error);
    const errorPayload = { ok: false, error };
    return {
        isError: true,
        content: [
            {
                type: 'text',
                text: `Error (${error.code}): ${error.message}`,
            },
        ],
        structuredContent: errorPayload,
    };
}
//# sourceMappingURL=index.js.map