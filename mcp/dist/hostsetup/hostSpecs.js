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
export const ALL_HOSTS = [
    'cursor',
    'windsurf',
    'copilot',
    'cline',
    'codex',
    'gemini',
    'claude-desktop',
];
export const HOST_SPECS = {
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
            manualNote: 'Open Cline → MCP Servers → Configure (or edit cline_mcp_settings.json in VS Code globalStorage) and paste the snippet below.',
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
export function effectiveScope(spec, requested) {
    if (spec.mcp.forceScope)
        return spec.mcp.forceScope;
    if (!spec.mcp.scopes.includes(requested))
        return spec.mcp.scopes[0];
    return requested;
}
//# sourceMappingURL=hostSpecs.js.map