/**
 * Tool registry.
 *
 * Each phase that adds tools appends entries to the `TOOLS` array. The
 * server iterates the array on startup and calls `registerTool` for each
 * entry. No other file in the codebase needs to know about the SDK shape.
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { ZodRawShape } from 'zod';
import type { PluginContext } from '../context.js';
import type { ToolResult } from '../types.js';

/**
 * The shape registered with the SDK. `inputSchema` is a raw zod shape (an
 * object literal of zod fields), NOT a `ZodObject` — the SDK derives both
 * the JSON schema for the client and the validated TS type from it.
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

/** Wire every registered tool into an active McpServer. */
export function attachAllTools(server: McpServer, ctx: PluginContext): void {
  for (const tool of TOOLS) {
    server.registerTool(
      tool.name,
      {
        ...(tool.title ? { title: tool.title } : {}),
        description: tool.description,
        inputSchema: tool.inputSchema,
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
        return toCallToolResult(result);
      },
    );
  }
}

function toCallToolResult<T extends Record<string, unknown>>(
  result: ToolResult<T>,
): {
  content: Array<{ type: 'text'; text: string }>;
  structuredContent: Record<string, unknown>;
  isError?: boolean;
} {
  if (result.ok) {
    const { ok: _ok, ...rest } = result;
    const payload = { ok: true, ...rest } as Record<string, unknown>;
    return {
      content: [{ type: 'text', text: JSON.stringify(payload, null, 2) }],
      structuredContent: payload,
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
