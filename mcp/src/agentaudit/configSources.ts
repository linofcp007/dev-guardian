/**
 * Where `audit_agent_config` reads config from, and reading it.
 *
 * Project-scoped files are read relative to the resolved project path.
 * User-scoped files (`~/.claude.json`, `~/.claude/settings.json`) are read
 * only when the caller opts in (`include_user_config: true`) — see
 * `tools/auditAgentConfig.ts`. `homedir()` resolves via `USERPROFILE` on
 * Windows / `HOME` on POSIX, so a test that wants an isolated home directory
 * points that env var at a temp dir before calling in.
 *
 * Every file is parsed as JSONC (`./jsonc.ts`), not strict JSON: real
 * `.vscode/mcp.json` and Cursor/VS Code settings carry `//`/`/* *\/`
 * comments and trailing commas as ordinary, hand-edited config, and a
 * strict `JSON.parse` reported the whole file unreadable the moment either
 * appeared. Strict JSON is valid JSONC, so this changes nothing for a file
 * that never had a comment in it.
 */

import { existsSync, readFileSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { parseJsonc } from './jsonc.js';

export type ConfigSourceKind = 'project' | 'user';

/** Which top-level key (if any) holds MCP server entries in this file's shape. */
export type McpServersField = 'mcpServers' | 'servers' | null;

export interface ConfigSourceDescriptor {
  /** Stable label used in `entry_key`, `file_path` and messages. */
  label: string;
  kind: ConfigSourceKind;
  mcpServersField: McpServersField;
  /** Resolve the absolute path to read, given the project root. */
  resolve: (projectPath: string) => string;
}

export interface ConfigSource {
  label: string;
  kind: ConfigSourceKind;
  absolutePath: string;
  mcpServersField: McpServersField;
  exists: boolean;
  raw?: string;
  json?: unknown;
  /** Set when the file exists but is not valid JSON. */
  parseError?: string;
}

const PROJECT_DESCRIPTORS: ConfigSourceDescriptor[] = [
  { label: '.mcp.json', kind: 'project', mcpServersField: 'mcpServers', resolve: (p) => join(p, '.mcp.json') },
  {
    label: '.claude/settings.json',
    kind: 'project',
    mcpServersField: null,
    resolve: (p) => join(p, '.claude', 'settings.json'),
  },
  {
    label: '.claude/settings.local.json',
    kind: 'project',
    mcpServersField: null,
    resolve: (p) => join(p, '.claude', 'settings.local.json'),
  },
  {
    label: '.cursor/mcp.json',
    kind: 'project',
    mcpServersField: 'mcpServers',
    resolve: (p) => join(p, '.cursor', 'mcp.json'),
  },
  {
    label: '.vscode/mcp.json',
    kind: 'project',
    mcpServersField: 'servers',
    resolve: (p) => join(p, '.vscode', 'mcp.json'),
  },
  {
    label: '.gemini/settings.json',
    kind: 'project',
    mcpServersField: 'mcpServers',
    resolve: (p) => join(p, '.gemini', 'settings.json'),
  },
];

const USER_DESCRIPTORS: ConfigSourceDescriptor[] = [
  { label: '~/.claude.json', kind: 'user', mcpServersField: 'mcpServers', resolve: () => join(homedir(), '.claude.json') },
  {
    label: '~/.claude/settings.json',
    kind: 'user',
    mcpServersField: null,
    resolve: () => join(homedir(), '.claude', 'settings.json'),
  },
];

/**
 * Every config source descriptor for this run — project-scoped always,
 * user-scoped only when `includeUserConfig` is true.
 */
export function configSourceDescriptors(includeUserConfig: boolean): ConfigSourceDescriptor[] {
  return includeUserConfig ? [...PROJECT_DESCRIPTORS, ...USER_DESCRIPTORS] : [...PROJECT_DESCRIPTORS];
}

/**
 * Config files here are small, hand-edited JSON(C) — a legitimate one is at
 * most a few KB. Same shape as `specDiscover.ts`'s `MAX_SPEC_BYTES` /
 * `mapAttackSurface.ts`'s size cap: checked via `statSync` BEFORE reading,
 * so an oversized or adversarial file is reported as a gap rather than read
 * (and JSON.parse'd) in full.
 */
export const MAX_CONFIG_BYTES = 256 * 1024;

/** Reads and parses every applicable config source. Missing files are `exists: false`, never thrown. */
export function readConfigSources(projectPath: string, includeUserConfig: boolean): ConfigSource[] {
  return configSourceDescriptors(includeUserConfig).map((descriptor) => readOne(descriptor, projectPath));
}

function readOne(descriptor: ConfigSourceDescriptor, projectPath: string): ConfigSource {
  const absolutePath = descriptor.resolve(projectPath);
  const base = {
    label: descriptor.label,
    kind: descriptor.kind,
    absolutePath,
    mcpServersField: descriptor.mcpServersField,
  };
  if (!existsSync(absolutePath)) return { ...base, exists: false };

  let size: number;
  try {
    size = statSync(absolutePath).size;
  } catch (e) {
    return { ...base, exists: false, parseError: `could not read: ${(e as Error).message}` };
  }
  if (size > MAX_CONFIG_BYTES) {
    return {
      ...base,
      exists: true,
      parseError: `file exceeds the ${MAX_CONFIG_BYTES}-byte size cap and was not read`,
    };
  }

  let raw: string;
  try {
    raw = readFileSync(absolutePath, 'utf8');
  } catch (e) {
    return { ...base, exists: false, parseError: `could not read: ${(e as Error).message}` };
  }
  try {
    const json = parseJsonc(raw);
    return { ...base, exists: true, raw, json };
  } catch (e) {
    return { ...base, exists: true, raw, parseError: `invalid JSON: ${(e as Error).message}` };
  }
}
