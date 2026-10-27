/**
 * Tool registry.
 *
 * Each phase that adds tools appends entries to the `TOOLS` array. The
 * server iterates the array on startup and calls `registerTool` for each
 * entry. No other file in the codebase needs to know about the SDK shape.
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { toJsonSchemaCompat } from '@modelcontextprotocol/sdk/server/zod-json-schema-compat.js';
import { ListToolsRequestSchema, type ToolAnnotations } from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';
import type { PluginContext } from '../context.js';
import type { SamplingFn } from '../llmscan/types.js';
import type { ToolResult } from '../types.js';
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
export const DATABASE_BUSY_MESSAGE =
  "dev-guardian's database is locked by another process — another dev-guardian server, hook or CLI writing to " +
  `it (several can share one project) — and it was not released within ${SESSION_BUSY_TIMEOUT_MS / 1000} s. ` +
  'Retry the call in a few seconds. If it keeps happening, close the other sessions working on this project, ' +
  'or end a dev-guardian process that is stuck.';

/**
 * A tool's parameters: an object literal of zod fields, NOT a `ZodObject`.
 * zod 4's own `ZodRawShape` holds `zod/v4/core` types, which have none of the
 * methods (`isOptional`, `description`) the folds and the tests read.
 */
export type ToolShape = Readonly<Record<string, z.ZodType>>;

/**
 * The shape registered with the SDK. `inputSchema` is a raw zod shape
 * (`ToolShape`); `attachAllTools` wraps it in a strict `z.object`
 * (`strictInputSchema`), from which the SDK derives both the JSON schema for
 * the client and the validation.
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
   * MCP sampling (`sampling/createMessage` to the client). Present only when
   * the client declared the `sampling` capability at initialize.
   */
  sampling?: SamplingFn;
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
  /**
   * The behaviour hints `tools/list` carries (read-only, destructive,
   * idempotent, open-world). Filled in at registration from the table in
   * `./annotations.ts` when the module does not declare its own.
   */
  annotations?: ToolAnnotations;
  inputSchema: ToolShape;
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
   * Bulky result keys — an inlined SBOM, an LLM-scan brief. Every result
   * otherwise travels twice (the JSON text block and the structured copy),
   * which for such a payload doubles the response for nothing. A tool that
   * declares any answers with the text block ALONE, compact JSON, and no
   * `structuredContent`: hosts disagree on which of the two the model reads
   * (Claude Code reads `structuredContent` when there is one — measured: a
   * brief kept out of it never reached the model), and with one
   * representation every host shows the whole result.
   */
  contentOnlyKeys?: readonly string[];
  /**
   * `false` for a hidden alias: the name still answers `tools/call`, with its
   * own parameters, but `tools/list` leaves it out — a fold (`./fold.ts`)
   * lists one tool for its family. Default: listed.
   */
  listed?: boolean;
  /**
   * A fold only: the member module a call with this input runs. The result
   * is shaped by that member (its `contentOnlyKeys`), not by the fold.
   */
  route?: (input: Record<string, unknown>) => ToolModule | undefined;
}

/**
 * A tool's input as its schema parses it — every key typed, defaults applied
 * (dg-maint finding 12: 51 hand-written `input as {…}` casts, nothing tying
 * one to its schema).
 */
export type ToolInput<S extends ToolShape> = z.output<z.ZodObject<S>>;

/** A {@link ToolModule} whose handler takes its own schema's {@link ToolInput}. */
interface ToolSpec<S extends ToolShape> extends Omit<ToolModule, 'inputSchema' | 'handler'> {
  inputSchema: S;
  handler: (input: ToolInput<S>, ctx: PluginContext, callMeta?: ToolCallMeta) => Promise<ToolResult<Record<string, unknown>>>;
}

/**
 * A tool module with its handler typed from its schema. The one place the
 * registry's untyped input meets that type: every caller hands a handler the
 * parse of exactly this schema — the SDK (`attachAllTools`, strict) or a fold
 * (`./fold.ts`, the member's strict schema). Nothing parses it again: an
 * in-process caller (`audit_executive`, a test) passes what the schema
 * would have produced.
 */
export function defineTool<S extends ToolShape>(spec: ToolSpec<S>): ToolModule {
  const { handler, ...rest } = spec;
  return { ...rest, handler: (input, ctx, callMeta) => handler(input as ToolInput<S>, ctx, callMeta) };
}

/**
 * Mutable global registry. Modules append themselves at import time via
 * `registerToolModule`, which lets us keep additions localized to each
 * tool's file rather than threading a list through the bootstrap.
 *
 * It holds every name `tools/call` answers, hidden aliases included;
 * `listedTools()` is what `tools/list` shows.
 */
export const TOOLS: ToolModule[] = [];

/** The tools `tools/list` shows: every registered tool but the hidden aliases. */
export function listedTools(tools: readonly ToolModule[] = TOOLS): ToolModule[] {
  return tools.filter((t) => t.listed !== false);
}

/** One entry of `tools/list`, as this server sends it. */
export interface ListedTool {
  name: string;
  title?: string;
  description: string;
  inputSchema: Record<string, unknown>;
  annotations?: ToolAnnotations;
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
 *     tool: an absent `execution` means exactly that;
 *   - the `pattern` zod 4 writes beside its own string formats
 *     ({@link FORMATS_WITH_OWN_PATTERN}).
 *
 * Computed once per server: the registry does not change after startup.
 */
export function toolListing(tools: readonly ToolModule[] = TOOLS): ListedTool[] {
  return listedTools(tools).map((t) => {
    const inputSchema = toJsonSchemaCompat(strictInputSchema(t), {
      strictUnions: true,
      pipeStrategy: 'input',
    });
    delete inputSchema['$schema'];
    dropFormatPatterns(inputSchema);
    return {
      name: t.name,
      ...(t.title ? { title: t.title } : {}),
      description: t.description,
      inputSchema,
      ...(t.annotations !== undefined ? { annotations: t.annotations } : {}),
    };
  });
}

/**
 * The JSON Schema formats zod 4 lists with its own regular expression beside
 * them (`z.guid()`: `uuid`, `z.iso.datetime()`: `date-time`). The expression
 * restates the format — zod 3's converter wrote the format alone — and the
 * scan ids' and `expires_at`'s cost 1 500 characters of the tools/list budget.
 * A tool's own `.regex()` on such a field would be listed as an `allOf` of
 * the two patterns, never as a lone `pattern`, so it is never the one dropped.
 */
const FORMATS_WITH_OWN_PATTERN = new Set(['uuid', 'date-time']);

/** Removes, in place, every lone `pattern` beside a {@link FORMATS_WITH_OWN_PATTERN} format. */
function dropFormatPatterns(node: unknown): void {
  if (node === null || typeof node !== 'object') return;
  if (Array.isArray(node)) {
    for (const item of node) dropFormatPatterns(item);
    return;
  }
  const schema = node as Record<string, unknown>;
  const format = schema['format'];
  if (typeof format === 'string' && FORMATS_WITH_OWN_PATTERN.has(format) && typeof schema['pattern'] === 'string') {
    delete schema['pattern'];
  }
  for (const value of Object.values(schema)) dropFormatPatterns(value);
}

export function registerToolModule(tool: ToolModule): void {
  if (TOOLS.some((t) => t.name === tool.name)) {
    throw new Error(`Tool '${tool.name}' is already registered`);
  }
  if (tool.annotations === undefined) {
    const hints = TOOL_ANNOTATIONS[tool.name];
    if (hints !== undefined) tool.annotations = { ...hints };
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
export function attachAllTools(server: McpServer, ctx: PluginContext): void {
  for (const tool of TOOLS) {
    server.registerTool(
      tool.name,
      {
        ...(tool.title ? { title: tool.title } : {}),
        description: tool.description,
        inputSchema: strictInputSchema(tool),
        ...(tool.annotations !== undefined ? { annotations: tool.annotations } : {}),
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
        if (server.server.getClientCapabilities()?.sampling !== undefined) {
          callMeta.sampling = (params, options) => server.server.createMessage(params, options);
        }
        let result: ToolResult<Record<string, unknown>>;
        try {
          result = await tool.handler(input as Record<string, unknown>, ctx, callMeta);
        } catch (e) {
          if (!isDatabaseBusyError(e)) throw e;
          result = { ok: false, error: { code: 'database_busy', message: DATABASE_BUSY_MESSAGE } };
        }
        const shapedBy = tool.route?.(input as Record<string, unknown>) ?? tool;
        return toCallToolResult(result, shapedBy.contentOnlyKeys ?? []);
      },
    );
  }
  const listing = toolListing(TOOLS);
  server.server.setRequestHandler(ListToolsRequestSchema, () => ({ tools: listing }));
}

/** What {@link strictInputSchema} returns: the tool's strict object behind a preprocess step. */
export type StrictInputSchema = z.ZodPreprocess<z.ZodObject<ToolShape, z.core.$strict>>;

/**
 * The schema a tool is registered with: its shape, rejecting any other key,
 * reading an absent `arguments` as `{}`, and refusing a list longer than
 * {@link MAX_INPUT_ARRAY} before the object is parsed at all.
 *
 * Both are a `z.preprocess` step in front of the strict object: an issue it
 * adds stops the pipe, so zod never walks the oversized list. Under zod 3 they
 * overrode the object's own `safeParseAsync`; zod 4's SDK path calls the
 * top-level `safeParseAsync(schema, data)`, which never reads that method.
 * The SDK takes a pipe as a tool's schema, and `toolListing` lists the
 * object's (`io: "input"` reads a preprocess as the schema it feeds).
 */
export function strictInputSchema(tool: Pick<ToolModule, 'inputSchema'>): StrictInputSchema {
  return z.preprocess((data, ctx) => {
    const oversized = oversizedArrayIn(data);
    if (oversized !== null) {
      const message = `at most ${MAX_INPUT_ARRAY} items per list (${oversized.length} given)`;
      ctx.addIssue({ code: 'custom', path: oversized.path, message, input: data });
      return data;
    }
    return data ?? {};
  }, z.strictObject(tool.inputSchema));
}

/**
 * The longest list a tool call may carry — ten times the largest any schema
 * accepts (1 000). Checked before zod sees the input. zod 3 parsed EVERY
 * element of an array even past its `.max()`, keeping one issue per failing
 * element with no cap (GHSA-mrhx-c7xc-m3w5); zod 4.6.6 checks a `.max()`
 * first and answers one issue without walking the elements. The cap stays:
 * it covers a list with no `.max()` and a list nested in another, and a call
 * of ten million items is refused without zod walking any of it.
 */
export const MAX_INPUT_ARRAY = 10_000;
/** How deep {@link oversizedArrayIn} looks; tool inputs nest two or three levels. */
const MAX_INPUT_DEPTH = 32;

/** The first array in `data` longer than {@link MAX_INPUT_ARRAY}, with its path; null when none. */
function oversizedArrayIn(data: unknown): { path: Array<string | number>; length: number } | null {
  const stack: Array<{ value: unknown; path: Array<string | number> }> = [{ value: data, path: [] }];
  while (stack.length > 0) {
    const next = stack.pop();
    if (next === undefined) break;
    const { value, path } = next;
    if (value === null || typeof value !== 'object' || path.length > MAX_INPUT_DEPTH) continue;
    if (Array.isArray(value)) {
      if (value.length > MAX_INPUT_ARRAY) return { path, length: value.length };
      value.forEach((v: unknown, i) => stack.push({ value: v, path: [...path, i] }));
    } else {
      for (const [k, v] of Object.entries(value)) stack.push({ value: v, path: [...path, k] });
    }
  }
  return null;
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
export function toCallToolResult<T extends Record<string, unknown>>(
  result: ToolResult<T>,
  contentOnlyKeys: readonly string[],
): {
  content: Array<{ type: 'text'; text: string }>;
  structuredContent?: Record<string, unknown>;
  isError?: boolean;
} {
  if (result.ok) {
    const { ok: _ok, ...rest } = result;
    const payload = untrustedValue(boundResponsePayload({ ok: true, ...rest } as Record<string, unknown>));
    // A bulky payload goes once, in the text block every host shows, as
    // compact JSON: re-indenting an inlined document adds whitespace to every
    // line of it (see `ToolModule.contentOnlyKeys`).
    if (contentOnlyKeys.length > 0) return { content: [{ type: 'text', text: JSON.stringify(payload) }] };
    return {
      content: [{ type: 'text', text: JSON.stringify(payload, null, 2) }],
      structuredContent: { ...payload },
    };
  }
  const error = untrustedValue(result.error);
  const errorPayload = { ok: false, error } as Record<string, unknown>;
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
