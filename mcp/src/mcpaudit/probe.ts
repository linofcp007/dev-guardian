/**
 * Starting ONE declared MCP server and asking it what it serves.
 *
 * `initialize`, then `tools/list`, `prompts/list`, `resources/list` and
 * `resources/templates/list` — each only where the server advertised the
 * capability, each followed through its `nextCursor` pages. Nothing else is
 * ever sent: no `tools/call`, no `prompts/get`, no `resources/read`. The
 * client declares no capabilities (no sampling, roots or elicitation), so a
 * server's own requests back are refused by the SDK rather than served. The
 * client names itself honestly (`dev-guardian-audit`): a server can tell it
 * is being audited, and a clean result covers only what it chose to show
 * this client — SECURITY.md and the tool description say so.
 *
 * Before anything is built:
 *
 *   - a cancelled call starts nothing;
 *   - an entry that reaches another machine (`launch.ts#remoteReasonOf`: a
 *     URL, a UNC command, a URL or UNC path on the command line) is
 *     `skipped` unless the caller passed `allowRemote`;
 *   - a stdio command is resolved without synchronous file-system or network
 *     access (`launch.ts#resolveCommand`).
 *
 * A stdio server runs through `stdioTransport.ts` (minimal environment,
 * inbound budget, the deadline checked on every chunk, process-tree kill).
 * Every exit path closes the session, which for stdio kills the tree.
 *
 * ## Budgets, and what is reported when one is reached
 *
 * At most {@link MAX_ITEMS} items per list and {@link MAX_PAGES} pages; a
 * repeated cursor ends a list. Reaching any of those, or a transport budget
 * or failure AFTER some listing was received, is `partial` — what was
 * received is analysed, and the reason names what stopped it. The same
 * failure before any listing arrived is `failed`. A list method answering
 * an error is `partial` too, and the other lists are still read; only
 * MethodNotFound (-32601) is silent, since a server need not implement
 * every list. None of these is a pass.
 *
 * The listing is read with a permissive schema, not the SDK's: definitions
 * that do not validate are what this audit is for, and a strict parse would
 * throw the whole listing away (`analyze.ts#normalizeListing` reads it).
 */

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import type { RequestOptions } from '@modelcontextprotocol/sdk/shared/protocol.js';
import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js';
import { ErrorCode, McpError } from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';
import type { McpServerEntry } from '../agentaudit/mcpServers.js';
import { remoteReasonOf, resolveCommand } from './launch.js';
import { DEFAULT_INBOUND_LIMITS, ProbeStdioTransport, probeEnvironment, type StdioLaunch } from './stdioTransport.js';

export type ProbeTransportKind = 'stdio' | 'http' | 'sse';

export interface RawListing {
  tools: unknown[];
  prompts: unknown[];
  resources: unknown[];
  resourceTemplates: unknown[];
}

export interface ProbeListed {
  /** `partial`: a budget or a failure stopped the listing after some of it arrived. */
  status: 'ok' | 'partial';
  /** Why the listing is partial. */
  reason?: string;
  transport: ProbeTransportKind;
  serverInfo?: { name: string; version: string };
  instructions?: string;
  advertised: { tools: boolean; prompts: boolean; resources: boolean };
  listing: RawListing;
  warnings: string[];
}

export interface ProbeNotOk {
  status: 'failed' | 'skipped';
  transport?: ProbeTransportKind;
  reason: string;
  warnings: string[];
}

export type ProbeOutcome = ProbeListed | ProbeNotOk;

export function isListed(o: ProbeOutcome): o is ProbeListed {
  return o.status === 'ok' || o.status === 'partial';
}

/** A function, not an inline check: TypeScript would narrow `aborted` across an await. */
function isAborted(signal: AbortSignal | undefined): boolean {
  return signal?.aborted === true;
}

export interface ProbeOptions {
  /** The project: every stdio server's working directory. */
  projectPath: string;
  timeoutMs: number;
  allowRemote: boolean;
  signal?: AbortSignal;
  /** Identifies the client in `initialize`. */
  clientVersion: string;
}

/** The label under which a plugin's `plugin.json` is read (`agentaudit/configSources.ts`). */
const PLUGIN_JSON_LABEL = '.claude-plugin/plugin.json';
const PLACEHOLDER = /\$\{[^}]*\}/g;
/** Per list. A server past these is not listing an interface; the rest is not read. */
export const MAX_PAGES = 100;
export const MAX_ITEMS = 1000;

type ListKey = 'tools' | 'prompts' | 'resources' | 'resourceTemplates';
const LIST_METHOD: Record<ListKey, string> = {
  tools: 'tools/list',
  prompts: 'prompts/list',
  resources: 'resources/list',
  resourceTemplates: 'resources/templates/list',
};

export async function probeServer(entry: McpServerEntry, opts: ProbeOptions): Promise<ProbeOutcome> {
  const warnings: string[] = [];
  const deadlineAt = Date.now() + opts.timeoutMs;
  const deadline = AbortSignal.timeout(opts.timeoutMs);
  const signal = opts.signal === undefined ? deadline : AbortSignal.any([deadline, opts.signal]);

  if (isAborted(opts.signal)) return { status: 'skipped', reason: 'cancelled before it was started', warnings };
  const remote = remoteReasonOf(entry);
  if (remote !== null && !opts.allowRemote) {
    return {
      status: 'skipped',
      reason: `${remote}: audit_mcp_tools contacts a remote MCP server only with allow_remote: true`,
      warnings,
    };
  }

  const expand = placeholderExpander(entry, opts.projectPath, warnings);
  let transport: Transport;
  let kind: ProbeTransportKind;
  let stdio: ProbeStdioTransport | null = null;
  if (entry.command !== undefined) {
    kind = 'stdio';
    const env = stringEnv(entry.env, expand, warnings);
    const resolved = await resolveCommand(expand(entry.command), probeEnvironment(env, null), opts.projectPath, deadlineAt);
    if (!resolved.ok) return { status: 'failed', transport: kind, reason: resolved.reason, warnings };
    if (isAborted(opts.signal)) return { status: 'skipped', reason: 'cancelled before it was started', warnings };
    const launch: StdioLaunch = {
      command: resolved.command,
      args: (entry.args ?? []).map(expand),
      env,
      cwd: opts.projectPath,
    };
    stdio = new ProbeStdioTransport(launch, { ...DEFAULT_INBOUND_LIMITS, deadline: deadlineAt });
    transport = stdio;
  } else if (entry.url !== undefined) {
    kind = entry.remoteTransport ?? 'http';
    let url: URL;
    try {
      url = new URL(expand(entry.url));
    } catch {
      return { status: 'failed', transport: kind, reason: "the entry's url is not a valid URL", warnings };
    }
    const requestInit: RequestInit = { headers: stringHeaders(entry.raw['headers'], expand) };
    transport =
      kind === 'sse'
        ? new SSEClientTransport(url, { requestInit })
        : new StreamableHTTPClientTransport(url, { requestInit });
  } else {
    return { status: 'failed', reason: 'the entry has neither a command nor a url', warnings };
  }

  const requestOptions = (): RequestOptions => {
    const left = Math.max(1, deadlineAt - Date.now());
    return { signal, timeout: left, maxTotalTimeout: left };
  };

  const client = new Client({ name: 'dev-guardian-audit', version: opts.clientVersion }, { capabilities: {} });
  // A protocol-level complaint (a stdout banner that is not JSON-RPC) is not
  // fatal; the request that needed an answer fails on its own if one is.
  client.onerror = () => {};
  const listing: RawListing = { tools: [], prompts: [], resources: [], resourceTemplates: [] };
  const stops: string[] = [];
  let received = false;
  let advertised = { tools: false, prompts: false, resources: false };
  let phase = 'start';

  /** The session itself is gone — every later request would fail too. */
  const sessionDead = (e: unknown): boolean =>
    signal.aborted ||
    (stdio?.closeReason ?? null) !== null ||
    (stdio?.exit ?? null) !== null ||
    (e instanceof McpError && (e.code === ErrorCode.ConnectionClosed || e.code === ErrorCode.RequestTimeout));

  /**
   * One list method, every page. Fix round 4 (the product's rule): only
   * MethodNotFound (-32601) is silent — a server need not implement every
   * list. Any other error answered by a live session makes the server
   * PARTIAL, with the reason, and the other lists are still read; the first
   * cut kept a -32603 on templates as a warning, and the server read ok.
   */
  const list = async (key: ListKey): Promise<void> => {
    phase = LIST_METHOD[key];
    const method = LIST_METHOD[key];
    try {
      const result = await listAll(
        key,
        (cursor) => {
          const params = cursor === undefined ? {} : { cursor };
          return client.request({ method, params }, PAGE, requestOptions()).then((page) => {
            received = true;
            return page;
          });
        },
        listing[key],
      );
      if (result !== null) stops.push(result);
    } catch (e) {
      if (sessionDead(e)) throw e;
      if (e instanceof McpError && e.code === ErrorCode.MethodNotFound) {
        warnings.push(`${method} is not implemented by the server (MethodNotFound)`);
        return;
      }
      received = true; // the session answered: what was listed so far is real
      stops.push(`${method} failed: ${messageOf(e).slice(0, 200)}`);
    }
  };

  try {
    phase = 'initialize';
    await client.connect(transport, requestOptions());
    const caps = client.getServerCapabilities() ?? {};
    advertised = {
      tools: caps.tools !== undefined,
      prompts: caps.prompts !== undefined,
      resources: caps.resources !== undefined,
    };
    if (advertised.tools) await list('tools');
    else warnings.push('the server does not advertise tools; tools/list was not called');
    if (advertised.prompts) await list('prompts');
    if (advertised.resources) {
      await list('resources');
      // Templates carry descriptions the model reads too; many servers that
      // serve resources do not implement the method (MethodNotFound, silent).
      await list('resourceTemplates');
    }
    const info = client.getServerVersion();
    const instructions = client.getInstructions();
    return {
      status: stops.length === 0 ? 'ok' : 'partial',
      ...(stops.length === 0 ? {} : { reason: stops.join('; ') }),
      transport: kind,
      ...(info === undefined ? {} : { serverInfo: { name: info.name, version: info.version } }),
      ...(instructions === undefined ? {} : { instructions }),
      advertised,
      listing,
      warnings,
    };
  } catch (e) {
    // The reason is read before the tree is killed: the kill itself would
    // otherwise read as "exited".
    const reason = failureReason(e, phase, opts, stdio, deadline);
    await stdio?.close();
    if (!received) return { status: 'failed', transport: kind, reason, warnings };
    const info = client.getServerVersion();
    const instructions = client.getInstructions();
    return {
      status: 'partial',
      reason: [...stops, `the listing stopped: ${reason}`].join('; '),
      transport: kind,
      ...(info === undefined ? {} : { serverInfo: { name: info.name, version: info.version } }),
      ...(instructions === undefined ? {} : { instructions }),
      advertised,
      listing,
      warnings,
    };
  } finally {
    await client.close().catch(() => {});
    await transport.close().catch(() => {});
  }
}

/**
 * Every item of a paged list, into `into`, following `nextCursor` — until
 * the list ends (null) or a budget stops it (the reason).
 */
async function listAll(
  key: ListKey,
  page: (cursor: string | undefined) => Promise<z.infer<typeof PAGE>>,
  into: unknown[],
): Promise<string | null> {
  const seen = new Set<string>();
  let cursor: string | undefined;
  const what = LIST_METHOD[key];
  for (let i = 0; i < MAX_PAGES; i += 1) {
    const result = await page(cursor);
    const items = result[key];
    if (!Array.isArray(items)) throw new Error(`${what} answered without a '${key}' array`);
    for (const item of items as unknown[]) {
      if (into.length >= MAX_ITEMS) {
        return `${what} returned more than ${MAX_ITEMS} items; only the first ${MAX_ITEMS} were read`;
      }
      into.push(item);
    }
    const next = result['nextCursor'];
    if (typeof next !== 'string' || next === '') return null;
    if (into.length >= MAX_ITEMS) {
      return `${what} has more than ${MAX_ITEMS} items; only the first ${MAX_ITEMS} were read`;
    }
    if (seen.has(next)) {
      return `${what} repeated cursor ${JSON.stringify(next.slice(0, 40))}; the listing stopped there`;
    }
    seen.add(next);
    cursor = next;
  }
  return `${what} did not end within ${MAX_PAGES} pages; the rest was not read`;
}

/** Any object: the list keys and `nextCursor` are checked by hand. */
const PAGE = z.object({}).passthrough();

function messageOf(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

/** What happened, in the order that explains it best — never the exit of a process this code killed. */
function failureReason(
  e: unknown,
  phase: string,
  opts: ProbeOptions,
  stdio: ProbeStdioTransport | null,
  deadline: AbortSignal,
): string {
  const exit = stdio?.exit ?? null;
  const stderr = stdio?.stderrTail.trim() ?? '';
  const withStderr = (s: string): string => (stderr === '' ? s : `${s}; stderr: ${stderr.slice(-600)}`);
  if (exit?.spawnError !== undefined) return withStderr(`could not start the server: ${exit.spawnError}`);
  const closed = stdio?.closeReason ?? null;
  if (closed !== null) return `the server ${closed} (during ${phase})`;
  if (opts.signal?.aborted === true) return `cancelled during ${phase}`;
  if (deadline.aborted || (e instanceof McpError && e.code === ErrorCode.RequestTimeout)) {
    return withStderr(`did not answer within ${opts.timeoutMs} ms (during ${phase})`);
  }
  if (exit !== null) {
    const how = exit.signal !== null ? `was killed by ${exit.signal}` : `exited with code ${exit.exitCode ?? '?'}`;
    return withStderr(`the server ${how} during ${phase}`);
  }
  return withStderr(`${phase} failed: ${messageOf(e).slice(0, 400)}`);
}

/**
 * `${CLAUDE_PLUGIN_ROOT}` in a plugin's own `plugin.json` is the plugin's
 * root — the project here — exactly as Claude Code expands it. Every other
 * `${VAR}` is passed through LITERALLY: expanding it would copy this
 * server's own environment (tokens included) into the third-party process,
 * which is what the minimal environment exists to prevent. Each one left
 * unexpanded is named in `warnings`, since a server that needs it may fail.
 */
function placeholderExpander(entry: McpServerEntry, projectPath: string, warnings: string[]): (s: string) => string {
  const seen = new Set<string>();
  return (value: string): string => {
    const expanded =
      entry.sourceLabel === PLUGIN_JSON_LABEL ? value.replace(/\$\{CLAUDE_PLUGIN_ROOT\}/g, projectPath) : value;
    for (const m of expanded.matchAll(PLACEHOLDER)) {
      if (seen.has(m[0])) continue;
      seen.add(m[0]);
      warnings.push(`${m[0]} was passed literally: placeholders are not expanded from dev-guardian's environment`);
    }
    return expanded;
  };
}

function stringEnv(
  env: Record<string, unknown> | undefined,
  expand: (s: string) => string,
  warnings: string[],
): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(env ?? {})) {
    if (typeof v === 'string') out[k] = expand(v);
    else warnings.push(`env ${k} is not a string and was not passed`);
  }
  return out;
}

function stringHeaders(headers: unknown, expand: (s: string) => string): Record<string, string> {
  const out: Record<string, string> = {};
  if (headers === null || typeof headers !== 'object' || Array.isArray(headers)) return out;
  for (const [k, v] of Object.entries(headers as Record<string, unknown>)) {
    if (typeof v === 'string') out[k] = expand(v);
  }
  return out;
}
