/**
 * Tool registry.
 *
 * Each phase that adds tools appends entries to the `TOOLS` array. The
 * server iterates the array on startup and calls `registerTool` for each
 * entry. No other file in the codebase needs to know about the SDK shape.
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z, type ZodRawShape } from 'zod';
import type { PluginContext } from '../context.js';
import type { ToolResult } from '../types.js';
import { boundResponsePayload } from './responseBounds.js';

/**
 * The shape registered with the SDK. `inputSchema` is a raw zod shape (an
 * object literal of zod fields), NOT a `ZodObject`; `attachAllTools` wraps it
 * in a strict `z.object` (`strictInputSchema`), from which the SDK derives
 * both the JSON schema for the client and the validation.
 */
/**
 * Per-call metadata the registry extracts from the MCP request and forwards
 * to the tool handler. Currently surfaces only `progressToken` because
 * that's all the scan-tool factory needs; expand as new tools demand it.
 */
export interface ToolCallMeta {
  progressToken?: string | number;
  /**
   * AbortSignal from the MCP host (notifications/cancelled). When the host
   * cancels, this signal aborts and the scan-tool factory uses it to
   * SIGTERM the child process tree.
   */
  signal?: AbortSignal;
  /**
   * Set only by an orchestrator (`security_scan_full`) running this tool as
   * one of its children: the scan-tool factory records it in the child's
   * `meta.parent_scan_id`. Never set by the MCP host.
   */
  parentScanId?: string;
  /**
   * Set only with `parentScanId`: the tree hash the orchestrator computed for
   * the same project moments before, so its children do not re-hash the
   * whole tree once each. Omitted when a child may have changed the tree
   * (a Semgrep autofix) since.
   */
  treeHash?: string;
  /**
   * Set only by `create_fix_pr`, which runs tools on a disposable worktree
   * of a project: the project that worktree is a checkout of. Its rule
   * configuration (own Semgrep config, registered custom rules) and its
   * stored history (the CVEs `deps_update_plan` plans against) are what the
   * call uses — the worktree's own path has neither. Omitted: the scanned
   * path is its own origin. Never set by the MCP host.
   */
  originProjectPath?: string;
}

export interface ToolModule {
  name: string;
  description: string;
  /** Optional human title shown by some hosts. */
  title?: string;
  inputSchema: ZodRawShape;
  /**
   * Handler returns a typed `ToolResult`. The registry wrapper turns it
   * into the MCP CallToolResult shape (content blocks + structuredContent
   * + isError).
   */
  handler: (
    input: Record<string, unknown>,
    ctx: PluginContext,
    callMeta?: ToolCallMeta,
  ) => Promise<ToolResult<Record<string, unknown>>>;
  /**
   * Result keys sent ONCE, in the text content the model reads, and left
   * out of `structuredContent`. Every result otherwise travels twice (the
   * JSON text block and the structured copy), which for a bulky payload —
   * an inlined SBOM — doubles the response for nothing. Declaring any also
   * makes the text block compact JSON.
   */
  contentOnlyKeys?: readonly string[];
}

/**
 * Mutable global registry. Modules append themselves at import time via
 * `registerToolModule`, which lets us keep additions localized to each
 * tool's file rather than threading a list through the bootstrap.
 */
export const TOOLS: ToolModule[] = [];

export function registerToolModule(tool: ToolModule): void {
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
export function attachAllTools(server: McpServer, ctx: PluginContext): void {
  for (const tool of TOOLS) {
    server.registerTool(
      tool.name,
      {
        ...(tool.title ? { title: tool.title } : {}),
        description: tool.description,
        inputSchema: strictInputSchema(tool),
      },
      async (input, extra) => {
        const callMeta: ToolCallMeta = {};
        const typedExtra = extra as
          | { _meta?: { progressToken?: unknown }; signal?: AbortSignal }
          | undefined;
        const tokenRaw = typedExtra?._meta?.progressToken;
        if (typeof tokenRaw === 'string' || typeof tokenRaw === 'number') {
          callMeta.progressToken = tokenRaw;
        }
        if (typedExtra?.signal instanceof AbortSignal) {
          callMeta.signal = typedExtra.signal;
        }
        const result = await tool.handler(input as Record<string, unknown>, ctx, callMeta);
        return toCallToolResult(result, tool.contentOnlyKeys ?? []);
      },
    );
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
export function strictInputSchema(tool: Pick<ToolModule, 'inputSchema'>): z.ZodObject<ZodRawShape, 'strict'> {
  const schema = z.object(tool.inputSchema).strict();
  const parse = schema.safeParseAsync.bind(schema);
  schema.safeParseAsync = (data, params) => parse(data ?? {}, params);
  return schema;
}

/**
 * A handler's result as the MCP host receives it. Per-file gap lists are cut
 * here and only here (`tools/responseBounds.ts`): the row and every internal
 * caller keep them whole. Exported for the response-size tests.
 */
export function toCallToolResult<T extends Record<string, unknown>>(
  result: ToolResult<T>,
  contentOnlyKeys: readonly string[],
): {
  content: Array<{ type: 'text'; text: string }>;
  structuredContent: Record<string, unknown>;
  isError?: boolean;
} {
  if (result.ok) {
    const { ok: _ok, ...rest } = result;
    const payload = boundResponsePayload({ ok: true, ...rest } as Record<string, unknown>);
    const structured: Record<string, unknown> = { ...payload };
    for (const key of contentOnlyKeys) delete structured[key];
    // A tool with a bulky content-only payload is serialised compactly too:
    // re-indenting an inlined document adds whitespace to every line of it.
    const indent = contentOnlyKeys.length > 0 ? undefined : 2;
    return {
      content: [{ type: 'text', text: JSON.stringify(payload, null, indent) }],
      structuredContent: structured,
    };
  }
  const errorPayload = { ok: false, error: result.error } as Record<string, unknown>;
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
