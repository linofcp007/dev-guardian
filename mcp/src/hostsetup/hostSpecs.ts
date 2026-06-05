/**
 * Declarative per-host setup specs for the `mcp-config` CLI / host setup.
 *
 * Each AI host needs up to two things to work with dev-guardian:
 *   1. an MCP-server registration in the host's own config file, and
 *   2. a "rules" / context file telling the host's AI when to call the tools.
 *
 * This table captures both, per host, so the tool handler stays declarative.
 * Path resolution (which is OS- and scope-dependent) lives in `mcpConfig.ts`.
 */

export type HostName =
  | 'cursor'
  | 'windsurf'
  | 'copilot'
  | 'cline'
  | 'codex'
  | 'gemini'
  | 'claude-desktop';

export const ALL_HOSTS: HostName[] = [
  'cursor',
  'windsurf',
  'copilot',
  'cline',
  'codex',
  'gemini',
  'claude-desktop',
];

export type McpScope = 'project' | 'global';

/**
 * How the host's MCP config is shaped on disk:
 *   - json-mcpServers: `{ "mcpServers": { "<id>": { command, args, env } } }`
 *   - json-servers:    `{ "servers":    { "<id>": { type:"stdio", command, args, env } } }` (VS Code / Copilot)
 *   - toml:            `[mcp_servers.<id>]` table (Codex CLI)
 *   - manual:          we can't reliably locate the config file → emit a snippet
 */
export type McpFormat = 'json-mcpServers' | 'json-servers' | 'toml' | 'manual';

export interface RulesSpec {
  /** File name under `host-rules/`. */
  template_file: string;
  /** Destination path within the user's project. */
  target_path: string;
}

export interface McpSpec {
  format: McpFormat;
  /** Container key for the server entry. Informational for toml/manual. */
  serverKey: 'mcpServers' | 'servers' | 'mcp_servers';
  /** Scopes this host supports. First entry is the fallback when an
   *  unsupported scope is requested. */
  scopes: McpScope[];
  /** When set, the host is global-only — requested scope is ignored. */
  forceScope?: McpScope;
  /** Shown for `manual` hosts to explain where the snippet goes. */
  manualNote?: string;
}

export interface HostSpec {
  /** Human-readable label. */
  description: string;
  /** Rules/context file, or null when the host has no rules mechanism. */
  rules: RulesSpec | null;
  mcp: McpSpec;
}

export const HOST_SPECS: Record<HostName, HostSpec> = {
  cursor: {
    description: 'Cursor — .cursor/mcp.json + .cursor/rules/dev-guardian.mdc',
    rules: { template_file: 'cursor.mdc', target_path: '.cursor/rules/dev-guardian.mdc' },
    mcp: { format: 'json-mcpServers', serverKey: 'mcpServers', scopes: ['project', 'global'] },
  },
  windsurf: {
    description: 'Windsurf — ~/.codeium/windsurf/mcp_config.json + .windsurfrules',
    rules: { template_file: 'windsurfrules', target_path: '.windsurfrules' },
    // Windsurf reads a single global MCP config; there is no project-scoped form.
    mcp: { format: 'json-mcpServers', serverKey: 'mcpServers', scopes: ['global'], forceScope: 'global' },
  },
  copilot: {
    description: 'GitHub Copilot (VS Code) — .vscode/mcp.json + .github/copilot-instructions.md',
    rules: { template_file: 'copilot-instructions.md', target_path: '.github/copilot-instructions.md' },
    // Copilot's workspace config uses the `servers` key and a `type` field.
    mcp: { format: 'json-servers', serverKey: 'servers', scopes: ['project'] },
  },
  cline: {
    description: 'Cline (VS Code) — MCP settings (manual) + .clinerules',
    rules: { template_file: 'clinerules', target_path: '.clinerules' },
    // cline_mcp_settings.json lives in VS Code globalStorage; not reliable to locate.
    mcp: {
      format: 'manual',
      serverKey: 'mcpServers',
      scopes: ['global'],
      manualNote:
        'Open Cline → MCP Servers → Configure (or edit cline_mcp_settings.json in VS Code globalStorage) and paste the snippet below.',
    },
  },
  codex: {
    description: 'OpenAI Codex CLI — ~/.codex/config.toml + AGENTS.md',
    rules: { template_file: 'AGENTS.md', target_path: 'AGENTS.md' },
    mcp: { format: 'toml', serverKey: 'mcp_servers', scopes: ['project', 'global'] },
  },
  gemini: {
    description: 'Gemini CLI — ~/.gemini/settings.json + GEMINI.md',
    rules: { template_file: 'GEMINI.md', target_path: 'GEMINI.md' },
    mcp: { format: 'json-mcpServers', serverKey: 'mcpServers', scopes: ['project', 'global'] },
  },
  'claude-desktop': {
    description: 'Claude Desktop — claude_desktop_config.json (OS-specific, global)',
    // Claude Desktop has no rules-file mechanism; it uses Projects / custom instructions.
    rules: null,
    mcp: { format: 'json-mcpServers', serverKey: 'mcpServers', scopes: ['global'], forceScope: 'global' },
  },
};

/** Resolve the effective scope for a host given the user's request. */
export function effectiveScope(spec: HostSpec, requested: McpScope): McpScope {
  if (spec.mcp.forceScope) return spec.mcp.forceScope;
  if (!spec.mcp.scopes.includes(requested)) return spec.mcp.scopes[0] as McpScope;
  return requested;
}
