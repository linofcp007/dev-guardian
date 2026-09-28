/**
 * Where `audit_agent_config` reads config from, and reading it.
 *
 * Project-scoped files are read relative to the resolved project path.
 * User-scoped files (`~/.claude.json`, `~/.claude/settings.json`, Claude
 * Desktop's `claude_desktop_config.json`, `~/.cursor/mcp.json`, Windsurf's
 * `~/.codeium/windsurf/mcp_config.json`, `~/.gemini/settings.json`) are read
 * only when the caller opts in (`include_user_config: true`) — see
 * `tools/auditAgentConfig.ts` and `tools/auditMcpTools.ts`. `homedir()`
 * resolves via `USERPROFILE` on Windows / `HOME` on POSIX (Claude Desktop's
 * Windows path via `APPDATA`), so a test that wants an isolated home
 * directory points those env vars at a temp dir before calling in.
 *
 * Every file is parsed as JSONC (`./jsonc.ts`), not strict JSON: real
 * `.vscode/mcp.json` and Cursor/VS Code settings carry `//`/`/* *\/`
 * comments and trailing commas as ordinary, hand-edited config, and a
 * strict `JSON.parse` reported the whole file unreadable the moment either
 * appeared. Strict JSON is valid JSONC, so this changes nothing for a file
 * that never had a comment in it.
 *
 * ## Reading a file someone else controls
 *
 * Every file goes through the hooks' hardened reader
 * (`hooks/configFile.ts#readSmallText`), never `existsSync` + `readFileSync`:
 * that pair hung on a FIFO at `.mcp.json` (for ever), on a link to
 * `/dev/zero` (reading without end), and on a Windows link to
 * `\\<unreachable host>\share` (measured: past a 45 s kill, four cases of
 * four), which hung `audit_agent_config` and `audit_mcp_tools` with it. The
 * reader first walks the path's components below the source's root (the
 * project; the home directory for a user-level file) with `lstat` +
 * `readlink` only and refuses a link to a network or device path unopened,
 * then opens non-blocking and judges the DESCRIPTOR: only a regular file of
 * at most {@link MAX_CONFIG_BYTES} is read. A file that is there and was not
 * read is `exists: true` with its `refusal` and a `parseError` saying why —
 * never "missing", which would read as "no servers declared there".
 */
import { homedir } from 'node:os';
import { dirname, isAbsolute, join, relative } from 'node:path';
import { readSmallText } from '../hooks/configFile.js';
import { claudeDesktopConfigPath, resolveMcpConfigPath } from '../hostsetup/mcpConfig.js';
import { detectOs } from '../platform/osDetect.js';
import { parseJsonc } from './jsonc.js';
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
    // A Claude Code plugin declares its own servers here, launched with
    // `${CLAUDE_PLUGIN_ROOT}` expanded to the plugin's root (this directory).
    {
        label: '.claude-plugin/plugin.json',
        kind: 'project',
        mcpServersField: 'mcpServers',
        resolve: (p) => join(p, '.claude-plugin', 'plugin.json'),
    },
];
/**
 * The user-level config of the other hosts, at the same paths
 * `hostsetup/mcpConfig.ts` writes them (`dev-guardian mcp-config <host>
 * --write`) — one table of where each host keeps its config, not two.
 * Resolved at call time, so `HOME` / `USERPROFILE` / `APPDATA` set by a test
 * are honoured.
 */
function hostPathEnv() {
    return { os: detectOs(), home: homedir(), appData: process.env['APPDATA'], projectPath: '' };
}
/** A user-level host config path, or '' where the host has none on this OS ('' never exists). */
function hostConfigPath(host) {
    return resolveMcpConfigPath(host, 'global', hostPathEnv()) ?? '';
}
const USER_DESCRIPTORS = [
    { label: '~/.claude.json', kind: 'user', mcpServersField: 'mcpServers', resolve: () => join(homedir(), '.claude.json') },
    {
        label: '~/.claude/settings.json',
        kind: 'user',
        mcpServersField: null,
        resolve: () => join(homedir(), '.claude', 'settings.json'),
    },
    {
        label: 'claude_desktop_config.json',
        kind: 'user',
        mcpServersField: 'mcpServers',
        resolve: () => claudeDesktopConfigPath(hostPathEnv()) ?? '',
    },
    { label: '~/.cursor/mcp.json', kind: 'user', mcpServersField: 'mcpServers', resolve: () => hostConfigPath('cursor') },
    {
        label: '~/.codeium/windsurf/mcp_config.json',
        kind: 'user',
        mcpServersField: 'mcpServers',
        resolve: () => hostConfigPath('windsurf'),
    },
    { label: '~/.gemini/settings.json', kind: 'user', mcpServersField: 'mcpServers', resolve: () => hostConfigPath('gemini') },
];
/**
 * Every config source descriptor for this run — project-scoped always,
 * user-scoped only when `includeUserConfig` is true.
 */
export function configSourceDescriptors(includeUserConfig) {
    return includeUserConfig ? [...PROJECT_DESCRIPTORS, ...USER_DESCRIPTORS] : [...PROJECT_DESCRIPTORS];
}
/**
 * Config files here are small, hand-edited JSON(C) — a legitimate one is at
 * most a few KB. The reader judges the size on the opened descriptor and
 * reads at most this plus one byte, so an oversized or adversarial file is
 * reported as a gap rather than read (and parsed) in full.
 */
export const MAX_CONFIG_BYTES = 256 * 1024;
/** Reads and parses every applicable config source. Missing files are `exists: false`, never thrown. */
export function readConfigSources(projectPath, includeUserConfig) {
    return configSourceDescriptors(includeUserConfig).map((descriptor) => readOne(descriptor, projectPath));
}
const REFUSAL_MESSAGE = {
    'not-a-regular-file': 'not a regular file (a FIFO, a device, a directory or a pipe) and was not read',
    'too-large': `file exceeds the ${MAX_CONFIG_BYTES}-byte size cap and was not read`,
    unreadable: 'could not be read (permissions, a link loop, or an I/O error)',
    'remote-link': 'reached through a link to a network or device path, and was not opened',
};
function isWithin(root, path) {
    const rel = relative(root, path);
    return rel !== '' && !rel.startsWith('..') && !isAbsolute(rel);
}
/**
 * The directory below which the reader walks `path`'s links before opening
 * it: the project for a project file, the home directory for a user file —
 * or, for a user file outside the home directory (Claude Desktop under an
 * `APPDATA` set elsewhere), the directory two levels up, so the host's own
 * directory and the file are still walked. The root itself and its
 * ancestors are not walked: that is the user's own layout (see
 * `hooks/configFile.ts`).
 */
function walkRoot(kind, projectPath, path) {
    if (kind === 'project')
        return projectPath;
    const home = homedir();
    return isWithin(home, path) ? home : dirname(dirname(path));
}
function readOne(descriptor, projectPath) {
    const absolutePath = descriptor.resolve(projectPath);
    const base = {
        label: descriptor.label,
        kind: descriptor.kind,
        absolutePath,
        mcpServersField: descriptor.mcpServersField,
    };
    // '' is a host with no config location on this OS.
    if (absolutePath === '')
        return { ...base, exists: false };
    const read = readSmallText(absolutePath, MAX_CONFIG_BYTES, walkRoot(descriptor.kind, projectPath, absolutePath));
    if (read.status === 'absent')
        return { ...base, exists: false };
    if (read.status === 'refused') {
        return { ...base, exists: true, refusal: read.reason, parseError: REFUSAL_MESSAGE[read.reason] };
    }
    const raw = read.text;
    try {
        const json = parseJsonc(raw);
        return { ...base, exists: true, raw, json };
    }
    catch (e) {
        return { ...base, exists: true, raw, parseError: `invalid JSON: ${e.message}` };
    }
}
//# sourceMappingURL=configSources.js.map