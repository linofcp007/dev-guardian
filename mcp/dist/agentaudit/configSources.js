/**
 * Where `audit_agent_config` reads config from, and reading it.
 *
 * Project-scoped files are read relative to the resolved project path.
 * User-scoped files (`~/.claude.json`, `~/.claude/settings.json`) are read
 * only when the caller opts in (`include_user_config: true`) — see
 * `tools/auditAgentConfig.ts`. `homedir()` resolves via `USERPROFILE` on
 * Windows / `HOME` on POSIX, so a test that wants an isolated home directory
 * points that env var at a temp dir before calling in.
 */
import { existsSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
const PROJECT_DESCRIPTORS = [
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
const USER_DESCRIPTORS = [
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
export function configSourceDescriptors(includeUserConfig) {
    return includeUserConfig ? [...PROJECT_DESCRIPTORS, ...USER_DESCRIPTORS] : [...PROJECT_DESCRIPTORS];
}
/** Reads and JSON-parses every applicable config source. Missing files are `exists: false`, never thrown. */
export function readConfigSources(projectPath, includeUserConfig) {
    return configSourceDescriptors(includeUserConfig).map((descriptor) => readOne(descriptor, projectPath));
}
function readOne(descriptor, projectPath) {
    const absolutePath = descriptor.resolve(projectPath);
    const base = {
        label: descriptor.label,
        kind: descriptor.kind,
        absolutePath,
        mcpServersField: descriptor.mcpServersField,
    };
    if (!existsSync(absolutePath))
        return { ...base, exists: false };
    let raw;
    try {
        raw = readFileSync(absolutePath, 'utf8');
    }
    catch (e) {
        return { ...base, exists: false, parseError: `could not read: ${e.message}` };
    }
    try {
        const json = JSON.parse(raw);
        return { ...base, exists: true, raw, json };
    }
    catch (e) {
        return { ...base, exists: true, raw, parseError: `invalid JSON: ${e.message}` };
    }
}
//# sourceMappingURL=configSources.js.map