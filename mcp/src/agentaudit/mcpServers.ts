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

import type { ConfigSource } from './configSources.js';

export interface McpServerEntry {
  /** The `ConfigSource.label` this entry came from (e.g. ".mcp.json"). */
  sourceLabel: string;
  name: string;
  command?: string;
  args?: string[];
  cwd?: string;
  /** The remote address, whichever key the host spells it with: `url`, Windsurf's `serverUrl`, Gemini's `httpUrl`. */
  url?: string;
  /**
   * Set whenever `url` is: the transport this host means by that entry —
   * `type` when given; Gemini's `httpUrl` is Streamable HTTP and its `url`
   * SSE; otherwise a path ending in `/sse` is SSE and anything else
   * Streamable HTTP (what Cursor and Windsurf try first).
   */
  remoteTransport?: 'http' | 'sse';
  type?: string;
  env?: Record<string, unknown>;
  /** The entry's own raw object, for hashing and for fields this type does not model. */
  raw: Record<string, unknown>;
}

function remoteAddress(
  raw: Record<string, unknown>,
  sourceLabel: string,
): { url: string; transport: 'http' | 'sse' } | undefined {
  const str = (k: string): string | undefined => (typeof raw[k] === 'string' ? (raw[k] as string) : undefined);
  const type = str('type')?.toLowerCase();
  const gemini = /(^|\/)\.gemini\/settings\.json$/.test(sourceLabel);
  const httpUrl = str('httpUrl');
  const url = str('url');
  const serverUrl = str('serverUrl');
  const address = httpUrl ?? url ?? serverUrl;
  if (address === undefined) return undefined;
  let transport: 'http' | 'sse';
  if (type === 'sse') transport = 'sse';
  else if (type !== undefined && type !== 'stdio') transport = 'http';
  else if (httpUrl !== undefined) transport = 'http';
  else if (gemini && url !== undefined) transport = 'sse';
  else transport = /\/sse\/?(?:[?#]|$)/i.test(address) ? 'sse' : 'http';
  return { url: address, transport };
}

export function extractMcpServers(source: ConfigSource): McpServerEntry[] {
  if (!source.exists || source.mcpServersField === null || source.json === undefined) return [];
  const container = getObject(source.json, source.mcpServersField);
  if (container === undefined) return [];

  const out: McpServerEntry[] = [];
  for (const [name, value] of Object.entries(container)) {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) continue;
    const raw = value as Record<string, unknown>;
    const entry: McpServerEntry = { sourceLabel: source.label, name, raw };
    const command = raw['command'];
    if (typeof command === 'string') entry.command = command;
    const args = raw['args'];
    if (Array.isArray(args) && args.every((a) => typeof a === 'string')) entry.args = args as string[];
    const cwd = raw['cwd'];
    if (typeof cwd === 'string') entry.cwd = cwd;
    const remote = remoteAddress(raw, source.label);
    if (remote !== undefined) {
      entry.url = remote.url;
      entry.remoteTransport = remote.transport;
    }
    const type = raw['type'];
    if (typeof type === 'string') entry.type = type;
    const env = raw['env'];
    if (env !== null && typeof env === 'object' && !Array.isArray(env)) {
      entry.env = env as Record<string, unknown>;
    }
    out.push(entry);
  }
  return out;
}

function getObject(json: unknown, key: string): Record<string, unknown> | undefined {
  if (json === null || typeof json !== 'object' || Array.isArray(json)) return undefined;
  const value = (json as Record<string, unknown>)[key];
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return undefined;
  return value as Record<string, unknown>;
}
