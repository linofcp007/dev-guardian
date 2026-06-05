/**
 * Pure helpers for registering the dev-guardian MCP server into a host's
 * config file. No direct I/O lives here except path computation — the tool
 * handler reads/writes files and calls these to decide *what* to write.
 *
 * The server is always launched the same way the Claude Code plugin launches
 * it: `node <plugin>/mcp/dist/server.js`. For non-Claude hosts there is no
 * `${pluginDir}` placeholder, so we emit an ABSOLUTE path.
 */

import { join, resolve } from 'node:path';
import type { DetectedOs } from '../platform/osDetect.js';
import type { HostName, McpScope } from './hostSpecs.js';

/** The fixed id used for the server entry across every host. */
export const SERVER_ID = 'dev-guardian';

export interface ServerEntry {
  /** Present only for hosts that require it (VS Code / Copilot). */
  type?: 'stdio';
  command: string;
  args: string[];
  env: Record<string, string>;
}

/** Absolute path to the built MCP entrypoint, derived from scriptsDir. */
export function resolveServerJsPath(scriptsDir: string): string {
  // scriptsDir = <plugin>/scripts. The built server sits at <plugin>/mcp/dist/server.js.
  return resolve(scriptsDir, '..', 'mcp', 'dist', 'server.js');
}

/** Build the server-launch entry. `withType` adds `type:"stdio"` for Copilot. */
export function buildServerEntry(serverJsPath: string, withType: boolean): ServerEntry {
  const base: ServerEntry = { command: 'node', args: [serverJsPath], env: {} };
  return withType ? { type: 'stdio', ...base } : base;
}

export interface DesktopPathEnv {
  os: DetectedOs;
  home: string;
  /** %APPDATA% on Windows; ignored elsewhere. */
  appData?: string;
}

/** OS-specific location of Claude Desktop's config, or null when unsupported. */
export function claudeDesktopConfigPath(env: DesktopPathEnv): string | null {
  switch (env.os) {
    case 'win32': {
      const appData = env.appData ?? join(env.home, 'AppData', 'Roaming');
      return join(appData, 'Claude', 'claude_desktop_config.json');
    }
    case 'darwin':
      return join(env.home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json');
    case 'linux':
      return join(env.home, '.config', 'Claude', 'claude_desktop_config.json');
    default:
      return null;
  }
}

export interface ResolveEnv extends DesktopPathEnv {
  projectPath: string;
}

/**
 * Resolve the config file path for a host at a given (already-effective)
 * scope. Returns null for `manual` hosts (cline) or unsupported OSes.
 */
export function resolveMcpConfigPath(
  host: HostName,
  scope: McpScope,
  env: ResolveEnv,
): string | null {
  const { projectPath, home } = env;
  switch (host) {
    case 'cursor':
      return scope === 'global'
        ? join(home, '.cursor', 'mcp.json')
        : join(projectPath, '.cursor', 'mcp.json');
    case 'gemini':
      return scope === 'global'
        ? join(home, '.gemini', 'settings.json')
        : join(projectPath, '.gemini', 'settings.json');
    case 'codex':
      return scope === 'global'
        ? join(home, '.codex', 'config.toml')
        : join(projectPath, '.codex', 'config.toml');
    case 'copilot':
      // Workspace-scoped only.
      return join(projectPath, '.vscode', 'mcp.json');
    case 'windsurf':
      return join(home, '.codeium', 'windsurf', 'mcp_config.json');
    case 'claude-desktop':
      return claudeDesktopConfigPath(env);
    case 'cline':
      return null; // manual
    default:
      return null;
  }
}

export type MergeStatus = 'written' | 'merged' | 'already_present' | 'needs_update';

export interface MergeResult {
  status: MergeStatus;
  /** Content to write — present only for `written` / `merged`. */
  content?: string;
}

function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (typeof a !== typeof b) return false;
  if (a === null || b === null) return a === b;
  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) return false;
    return a.every((v, i) => deepEqual(v, b[i]));
  }
  if (typeof a === 'object') {
    const ao = a as Record<string, unknown>;
    const bo = b as Record<string, unknown>;
    const ak = Object.keys(ao);
    const bk = Object.keys(bo);
    if (ak.length !== bk.length) return false;
    return ak.every((k) => deepEqual(ao[k], bo[k]));
  }
  return false;
}

/**
 * Merge our server entry into a JSON host config, preserving everything else.
 * `existing` is the current file contents, or null when the file is absent.
 * Throws on malformed JSON so the caller can report `failed` without clobbering.
 */
export function mergeJsonConfig(
  existing: string | null,
  serverKey: string,
  entry: ServerEntry,
  force: boolean,
): MergeResult {
  let cfg: Record<string, unknown>;
  if (existing == null || existing.trim() === '') {
    cfg = {};
  } else {
    const parsed = JSON.parse(existing) as unknown;
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      throw new Error('config root is not a JSON object');
    }
    cfg = parsed as Record<string, unknown>;
  }

  const containerRaw = cfg[serverKey];
  const container =
    containerRaw && typeof containerRaw === 'object' && !Array.isArray(containerRaw)
      ? (containerRaw as Record<string, unknown>)
      : undefined;
  const current = container?.[SERVER_ID];

  if (current && deepEqual(current, entry)) return { status: 'already_present' };
  if (current && !force) return { status: 'needs_update' };

  const nextContainer = { ...(container ?? {}), [SERVER_ID]: entry };
  cfg[serverKey] = nextContainer;
  const content = `${JSON.stringify(cfg, null, 2)}\n`;
  return { status: existing == null || existing.trim() === '' ? 'written' : 'merged', content };
}

/** TOML literal string (single quotes) — no backslash escaping, ideal for
 *  Windows paths. Falls back to a basic (double-quoted) string only when the
 *  value itself contains a single quote. */
function tomlString(value: string): string {
  if (!value.includes("'")) return `'${value}'`;
  const escaped = value.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
  return `"${escaped}"`;
}

const TOML_HEADING = /^\[mcp_servers\.dev-guardian\]/m;

function buildTomlBlock(entry: ServerEntry): string {
  const args = entry.args.map((a) => tomlString(a)).join(', ');
  return (
    `[mcp_servers.${SERVER_ID}]\n` +
    `command = ${tomlString(entry.command)}\n` +
    `args = [${args}]\n` +
    `env = {}\n` +
    `enabled = true\n`
  );
}

/** Replace the existing `[mcp_servers.dev-guardian]` table (heading → next
 *  top-level `[` heading or EOF) with a freshly built one. */
function replaceTomlBlock(existing: string, entry: ServerEntry): string {
  const match = TOML_HEADING.exec(existing);
  if (!match) return `${existing.replace(/\n?$/, '\n')}\n${buildTomlBlock(entry)}`;
  const start = match.index;
  const after = existing.slice(start + match[0].length);
  const nextHeading = /\n\[/.exec(after);
  const end = nextHeading ? start + match[0].length + nextHeading.index + 1 : existing.length;
  const before = existing.slice(0, start);
  const tail = existing.slice(end);
  const block = buildTomlBlock(entry);
  return `${before}${block}${tail.startsWith('\n') ? tail : tail ? `\n${tail}` : ''}`;
}

/** Merge our server table into a Codex TOML config. */
export function mergeTomlConfig(
  existing: string | null,
  entry: ServerEntry,
  force: boolean,
): MergeResult {
  if (existing && TOML_HEADING.test(existing)) {
    if (!force) return { status: 'already_present' };
    return { status: 'merged', content: replaceTomlBlock(existing, entry) };
  }
  const block = buildTomlBlock(entry);
  if (!existing || existing.trim() === '') {
    return { status: 'written', content: block };
  }
  const sep = existing.endsWith('\n') ? '\n' : '\n\n';
  return { status: 'merged', content: `${existing}${sep}${block}` };
}

/** Human-readable snippet for `manual` hosts (cline). */
export function buildManualSnippet(serverJsPath: string): string {
  const entry = buildServerEntry(serverJsPath, false);
  const block = { mcpServers: { [SERVER_ID]: entry } };
  return JSON.stringify(block, null, 2);
}
