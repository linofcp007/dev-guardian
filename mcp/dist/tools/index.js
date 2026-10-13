/**
 * Tool registry.
 *
 * Each phase that adds tools appends entries to the `TOOLS` array. The
 * server iterates the array on startup and calls `registerTool` for each
 * entry. No other file in the codebase needs to know about the SDK shape.
 */
import { toJsonSchemaCompat } from '@modelcontextprotocol/sdk/server/zod-json-schema-compat.js';
import { ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';
import { untrustedValue } from '../platform/untrustedText.js';
import { boundResponsePayload } from './responseBounds.js';
import { TOOL_ANNOTATIONS } from './annotations.js';
import { isDatabaseBusyError, SESSION_BUSY_TIMEOUT_MS } from '../storage/db.js';
/**
 * What a call answers when another process held the database's lock past the
 * wait (`storage/db.ts#SESSION_BUSY_TIMEOUT_MS`) — a coded, actionable error
 * instead of the bare "database is locked" a host used to show (review 8,
 * finding 11).
 */
export const DATABASE_BUSY_MESSAGE = "dev-guardian's database is locked by another process — another dev-guardian server, hook or CLI writing to " +
    `it (several can share one project) — and it was not released within ${SESSION_BUSY_TIMEOUT_MS / 1000} s. ` +
    'Retry the call in a few seconds. If it keeps happening, close the other sessions working on this project, ' +
    'or end a dev-guardian process that is stuck.';
/**
 * Mutable global registry. Modules append themselves at import time via
 * `registerToolModule`, which lets us keep additions localized to each
 * tool's file rather than threading a list through the bootstrap.
 *
 * It holds every name `tools/call` answers, hidden aliases included;
 * `listedTools()` is what `tools/list` shows.
 */
export const TOOLS = [];
/** The tools `tools/list` shows: every registered tool but the hidden aliases. */
export function listedTools(tools = TOOLS) {
    return tools.filter((t) => t.listed !== false);
}
/**
 * The `tools/list` answer: the listed tools, each with the JSON schema the
 * SDK would derive from its strict input schema (`toJsonSchemaCompat`, the
 * SDK's own converter and options) — less what no client needs:
 *
 *   - `$schema` (`http://json-schema.org/draft-07/schema#`, 54 characters a
 *     tool). The MCP specification makes it optional; without it a schema is
 *     read as JSON Schema 2020-12, and these schemas use no keyword whose
 *     meaning differs between the two (no tuple `items`, `definitions`,
 *     `dependencies` or `$ref` — `toolFolds.test.ts` holds that);
 *   - `execution: {taskSupport: "forbidden"}`, which the SDK adds to every
 *     tool: an absent `execution` means exactly that.
 *
 * Computed once per server: the registry does not change after startup.
 */
export function toolListing(tools = TOOLS) {
    return listedTools(tools).map((t) => {
        const inputSchema = toJsonSchemaCompat(strictInputSchema(t), {
            strictUnions: true,
            pipeStrategy: 'input',
        });
        delete inputSchema['$schema'];
        return {
            name: t.name,
            ...(t.title ? { title: t.title } : {}),
            description: t.description,
            inputSchema,
            ...(t.annotations !== undefined ? { annotations: t.annotations } : {}),
        };
    });
}
export function registerToolModule(tool) {
    if (TOOLS.some((t) => t.name === tool.name)) {
        throw new Error(`Tool '${tool.name}' is already registered`);
    }
    if (tool.annotations === undefined) {
        const hints = TOOL_ANNOTATIONS[tool.name];
        if (hints !== undefined)
            tool.annotations = { ...hints };
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
 *
 * Every registered tool answers `tools/call`, hidden aliases included; the
 * `tools/list` handler the SDK installed is then replaced with one that
 * serves `toolListing()` — the listed tools, without `$schema` and
 * `execution` (`Server.setRequestHandler` replaces a handler by design).
 */
export function attachAllTools(server, ctx) {
    for (const tool of TOOLS) {
        server.registerTool(tool.name, {
            ...(tool.title ? { title: tool.title } : {}),
            description: tool.description,
            inputSchema: strictInputSchema(tool),
            ...(tool.annotations !== undefined ? { annotations: tool.annotations } : {}),
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
            if (server.server.getClientCapabilities()?.sampling !== undefined) {
                callMeta.sampling = (params, options) => server.server.createMessage(params, options);
            }
            let result;
            try {
                result = await tool.handler(input, ctx, callMeta);
            }
            catch (e) {
                if (!isDatabaseBusyError(e))
                    throw e;
                result = { ok: false, error: { code: 'database_busy', message: DATABASE_BUSY_MESSAGE } };
            }
            const shapedBy = tool.route?.(input) ?? tool;
            return toCallToolResult(result, shapedBy.contentOnlyKeys ?? []);
        });
    }
    const listing = toolListing(TOOLS);
    server.server.setRequestHandler(ListToolsRequestSchema, () => ({ tools: listing }));
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
        // A bulky payload goes once, in the text block every host shows, as
        // compact JSON: re-indenting an inlined document adds whitespace to every
        // line of it (see `ToolModule.contentOnlyKeys`).
        if (contentOnlyKeys.length > 0)
            return { content: [{ type: 'text', text: JSON.stringify(payload) }] };
        return {
            content: [{ type: 'text', text: JSON.stringify(payload, null, 2) }],
            structuredContent: { ...payload },
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