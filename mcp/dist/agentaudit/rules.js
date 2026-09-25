/**
 * Rule checks for `audit_agent_config`.
 *
 * Each function takes normalized input (an `McpServerEntry[]` or one
 * `ConfigSource`) and returns `Finding[]` — pure, no I/O, no persistence.
 * `analyze.ts` runs every check across every config source it read and
 * concatenates the results.
 */
import { redact, scanForSecrets } from '../hooks/secretScan.js';
import { makeFinding } from '../runners/scannerParsers/index.js';
const TOOL = 'agent-audit';
/** Bash command prefixes dangerous enough that a `:*` (or bare-`*`) wildcard on them is a real risk. */
const DANGEROUS_BASH_PREFIXES = new Set([
    'rm', 'del', 'erase', 'rd', 'rmdir', 'remove-item',
    'curl', 'wget', 'iwr', 'irm', 'invoke-webrequest', 'invoke-restmethod',
    'sudo', 'su', 'chmod', 'chown', 'dd', 'mkfs', 'format',
    'eval', 'iex', 'invoke-expression',
    'ssh', 'scp', 'kill', 'killall', 'taskkill', 'shutdown', 'reboot',
]);
const NETWORK_EGRESS_RE = /\b(?:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod)\b/i;
// Redirection (`>`/`>>`, optionally preceded by a file-descriptor number) or
// a write-cmdlet, followed by a path that is absolute (leading `/`, `~`, or
// a Windows drive letter) or that walks up out of the current directory
// (`../`, `..\`). A relative path *within* the project (`./x`, `x/y.txt`)
// never matches. Heuristic — see checkHookRisks' doc comment.
const WRITE_OUTSIDE_RE = /(?:\d*>{1,2}|Out-File\s+-(?:Path\s+)?|Set-Content\s+-(?:Path\s+)?|Add-Content\s+-(?:Path\s+)?)\s*['"]?(?:~|\/(?!\/)|[A-Za-z]:[\\/]|\.\.[\\/])/i;
/** `${NAME}` template syntax — the shape `.mcp.json` never expands. */
const TEMPLATE_VAR_RE = /\$\{[A-Za-z_][A-Za-z0-9_]*\}/;
function finding(input) {
    return makeFinding({
        tool: TOOL,
        rule_id: input.rule_id,
        severity: input.severity,
        category: input.category,
        title: input.title,
        message: input.message,
        file_path: input.file_path,
        fix_available: false,
        ...(input.snippet !== undefined ? { snippet: input.snippet } : {}),
    });
}
function launcherName(command) {
    if (!command)
        return undefined;
    const base = command.replace(/\\/g, '/').split('/').pop() ?? command;
    return base.replace(/\.(cmd|exe|ps1|bat)$/i, '').toLowerCase();
}
/** First `args[]` element that is not a flag (does not start with `-`). */
function firstNonFlag(args, fromIndex = 0) {
    for (let i = fromIndex; i < args.length; i++) {
        const a = args[i];
        if (a !== undefined && !a.startsWith('-'))
            return a;
    }
    return undefined;
}
function launchSpecFor(entry) {
    const name = launcherName(entry.command);
    const args = entry.args ?? [];
    if (name === 'npx') {
        const pkg = firstNonFlag(args);
        return pkg ? { launcher: 'npx', packageSpec: pkg } : undefined;
    }
    if (name === 'uvx') {
        const pkg = firstNonFlag(args);
        return pkg ? { launcher: 'uvx', packageSpec: pkg } : undefined;
    }
    if (name === 'pipx') {
        // `pipx run <pkg>` — the package follows the `run` subcommand.
        const runIdx = args.findIndex((a) => a === 'run');
        if (runIdx === -1)
            return undefined;
        const pkg = firstNonFlag(args, runIdx + 1);
        return pkg ? { launcher: 'pipx', packageSpec: pkg } : undefined;
    }
    return undefined;
}
/** True when `spec` names an exact, non-floating version. */
function isPinned(launcher, spec) {
    if (launcher === 'npx') {
        // Strip a leading `@scope/` (npm scope), then look for a `@version` on
        // what remains — that is npm's own version-pin syntax.
        const unscoped = spec.replace(/^@[^/@]+\//, '');
        const at = unscoped.lastIndexOf('@');
        if (at <= 0)
            return false; // no version separator (or a bare `@scope/name`)
        const version = unscoped.slice(at + 1);
        return version.length > 0 && version.toLowerCase() !== 'latest';
    }
    // uv's `uvx` and pipx's `pipx run` both pin with PEP 440 `==`.
    const eq = spec.indexOf('==');
    return eq > 0 && spec.slice(eq + 2).length > 0;
}
export function checkUnpinnedLaunchers(entries) {
    const out = [];
    for (const entry of entries) {
        const spec = launchSpecFor(entry);
        if (!spec || isPinned(spec.launcher, spec.packageSpec))
            continue;
        out.push(finding({
            rule_id: 'agent-audit-unpinned-launcher',
            severity: 'medium',
            category: 'security',
            title: `MCP server '${entry.name}' launches an unpinned package`,
            message: `'${entry.name}' runs via ${spec.launcher} ${spec.packageSpec}, with no exact version pinned. ` +
                `A compromised or backdoored release published under this name runs automatically the next ` +
                `time this server starts. Pin an exact version.`,
            file_path: entry.sourceLabel,
            snippet: `${entry.command} ${(entry.args ?? []).join(' ')}`.trim(),
        }));
    }
    return out;
}
// ── 2. Remote servers over plain HTTP ──────────────────────────────────────
function isLoopbackHost(hostname) {
    const h = hostname.toLowerCase();
    return h === 'localhost' || h === '127.0.0.1' || h === '::1' || h === '0.0.0.0' || h.endsWith('.localhost');
}
export function checkPlainHttpRemotes(entries) {
    const out = [];
    for (const entry of entries) {
        if (!entry.url)
            continue;
        let parsed;
        try {
            parsed = new URL(entry.url);
        }
        catch {
            continue;
        }
        if (parsed.protocol !== 'http:' || isLoopbackHost(parsed.hostname))
            continue;
        out.push(finding({
            rule_id: 'agent-audit-http-remote',
            severity: 'high',
            category: 'security',
            title: `MCP server '${entry.name}' connects over plain HTTP`,
            message: `'${entry.name}' points at ${entry.url} — an unencrypted transport. Tool calls, responses, ` +
                `and any bearer token/header this server is configured with travel in the clear and can be ` +
                `read or altered in transit. Use https:// instead.`,
            file_path: entry.sourceLabel,
            snippet: entry.url,
        }));
    }
    return out;
}
// ── 3. Inline secrets in `env` ─────────────────────────────────────────────
export function checkInlineSecrets(entries) {
    const out = [];
    for (const entry of entries) {
        if (!entry.env)
            continue;
        for (const [key, value] of Object.entries(entry.env)) {
            if (typeof value !== 'string')
                continue;
            const hits = scanForSecrets(`${key}=${value}`);
            for (const hit of hits) {
                out.push(finding({
                    rule_id: 'agent-audit-inline-secret',
                    severity: hit.confidence === 'high' ? 'critical' : 'medium',
                    category: 'security',
                    title: `Possible ${hit.title} inline in MCP server '${entry.name}''s env block`,
                    message: `env.${key} on '${entry.name}' (${entry.sourceLabel}) looks like a ${hit.title.toLowerCase()} ` +
                        `written directly into the config file rather than referenced from a secret store or ` +
                        `\${VAR} placeholder. ${redact(value)}`,
                    file_path: entry.sourceLabel,
                    snippet: hit.preview,
                }));
            }
        }
    }
    return out;
}
// ── shared JSON helpers for the settings-shaped checks below ──────────────
function asObject(value) {
    return value !== null && typeof value === 'object' && !Array.isArray(value)
        ? value
        : undefined;
}
function asArray(value) {
    return Array.isArray(value) ? value : undefined;
}
// ── 4. Wildcard Bash permission allowlists ─────────────────────────────────
/** Parses `Bash(<specifier>)`. Returns the specifier, or undefined for another tool / malformed entry. */
function bashSpecifier(rule) {
    const m = /^Bash\((.*)\)$/.exec(rule);
    return m?.[1];
}
function isDangerousWildcard(specifier) {
    if (specifier === '*')
        return true;
    const m = /^(\S+)(?:\s.*)?:\*$/.exec(specifier);
    const leading = m?.[1];
    if (leading === undefined)
        return false;
    return DANGEROUS_BASH_PREFIXES.has(leading.toLowerCase());
}
export function checkWildcardPermissions(source) {
    const root = asObject(source.json);
    const permissions = asObject(root?.['permissions']);
    const allow = asArray(permissions?.['allow']);
    if (!allow)
        return [];
    const out = [];
    for (const rule of allow) {
        if (typeof rule !== 'string')
            continue;
        const specifier = bashSpecifier(rule);
        if (specifier === undefined || !isDangerousWildcard(specifier))
            continue;
        out.push(finding({
            rule_id: 'agent-audit-wildcard-permission',
            severity: specifier === '*' ? 'critical' : 'high',
            category: 'security',
            title: `Wildcard Bash permission: ${rule}`,
            message: `permissions.allow contains "${rule}", which auto-approves ${specifier === '*' ? 'every Bash command' : `any Bash command starting with '${specifier.split(':')[0]}'`} with no confirmation prompt. Narrow it to the specific commands actually needed.`,
            file_path: source.label,
            snippet: rule,
        }));
    }
    return out;
}
// ── 5. defaultMode: "bypassPermissions" ────────────────────────────────────
export function checkBypassPermissions(source) {
    const root = asObject(source.json);
    if (!root)
        return [];
    const permissions = asObject(root['permissions']);
    const mode = permissions?.['defaultMode'] ?? root['defaultMode'];
    if (mode !== 'bypassPermissions')
        return [];
    return [
        finding({
            rule_id: 'agent-audit-bypass-permissions',
            severity: 'critical',
            category: 'security',
            title: 'Permission prompts are fully disabled (defaultMode: "bypassPermissions")',
            message: `${source.label} sets defaultMode to "bypassPermissions" — every tool call (including Bash, ` +
                `file writes, and any MCP server this workspace trusts) runs with no confirmation at all.`,
            file_path: source.label,
        }),
    ];
}
// ── 6. enableAllProjectMcpServers ──────────────────────────────────────────
export function checkEnableAllProjectMcpServers(source) {
    const root = asObject(source.json);
    if (!root || root['enableAllProjectMcpServers'] !== true)
        return [];
    return [
        finding({
            rule_id: 'agent-audit-enable-all-mcp-servers',
            severity: 'medium',
            category: 'security',
            title: 'Every project-declared MCP server is auto-trusted (enableAllProjectMcpServers: true)',
            message: `${source.label} sets enableAllProjectMcpServers to true — any MCP server later added to this ` +
                `project's .mcp.json starts and is trusted automatically, with no per-server confirmation.`,
            file_path: source.label,
        }),
    ];
}
// ── 7. Hooks with network egress or writes outside the project ────────────
/**
 * "Writes outside the project" is a heuristic, not a shell parser: it looks
 * for a redirection operator or a write-cmdlet followed by something that
 * LOOKS like an absolute or upward-traversing path. It cannot see a write
 * hidden behind a variable (`> "$OUT"`) or a command substitution — those
 * are false negatives, not false positives, and are the same trade-off
 * `bashGuard.ts` documents for its own coarser rules.
 */
export function checkHookRisks(source) {
    const root = asObject(source.json);
    const hooksRoot = asObject(root?.['hooks']);
    if (!hooksRoot)
        return [];
    const out = [];
    for (const eventGroups of Object.values(hooksRoot)) {
        const groups = asArray(eventGroups);
        if (!groups)
            continue;
        for (const group of groups) {
            const groupObj = asObject(group);
            const hooks = asArray(groupObj?.['hooks']);
            if (!hooks)
                continue;
            for (const hook of hooks) {
                const hookObj = asObject(hook);
                const command = hookObj?.['command'];
                if (typeof command !== 'string')
                    continue;
                if (NETWORK_EGRESS_RE.test(command)) {
                    out.push(finding({
                        rule_id: 'agent-audit-hook-network-egress',
                        severity: 'high',
                        category: 'security',
                        title: 'A hook shells out to the network',
                        message: `${source.label} runs a hook whose command reaches out over the network ` +
                            `(curl/wget/iwr/irm): "${command}". A hook runs on every matching tool call with no ` +
                            `visible confirmation — this is where session data would leave silently.`,
                        file_path: source.label,
                        snippet: command,
                    }));
                }
                if (WRITE_OUTSIDE_RE.test(command)) {
                    out.push(finding({
                        rule_id: 'agent-audit-hook-write-outside-project',
                        severity: 'high',
                        category: 'security',
                        title: 'A hook writes outside the project directory',
                        message: `${source.label} runs a hook whose command writes to a path outside the project ` +
                            `("${command}"). Confirm this is intended — a hook is not sandboxed to the project root.`,
                        file_path: source.label,
                        snippet: command,
                    }));
                }
            }
        }
    }
    return out;
}
// ── 8. ${VAR} in a project .mcp.json (unexpanded by Claude Code) ──────────
export function checkUnexpandedVars(source) {
    // Scoped to .mcp.json specifically: this is the one file Claude Code
    // launches a project-scoped server from without expanding `${VAR}` in it
    // (only `${CLAUDE_PLUGIN_ROOT}`, inside plugin.json, is expanded). Cursor
    // and VS Code's own mcp.json support `${workspaceFolder}`; Gemini CLI has
    // a dedicated `cwd` field — see mcpJsonConfigs.test.ts.
    if (source.label !== '.mcp.json')
        return [];
    const root = asObject(source.json);
    const servers = asObject(root?.['mcpServers']);
    if (!servers)
        return [];
    const out = [];
    for (const [name, value] of Object.entries(servers)) {
        const entry = asObject(value);
        if (!entry)
            continue;
        const fields = [
            ['command', entry['command']],
            ['cwd', entry['cwd']],
        ];
        const args = asArray(entry['args']);
        if (args)
            args.forEach((a, i) => fields.push([`args[${i}]`, a]));
        for (const [field, value_] of fields) {
            if (typeof value_ !== 'string' || !TEMPLATE_VAR_RE.test(value_))
                continue;
            out.push(finding({
                rule_id: 'agent-audit-unexpanded-var',
                severity: 'medium',
                category: 'quality',
                title: `MCP server '${name}' will not start: unexpanded \${VAR} in .mcp.json`,
                message: `.mcp.json's "${name}".${field} is "${value_}". Claude Code does NOT expand \${VAR} ` +
                    `placeholders for a project-scoped .mcp.json server entry — only \${CLAUDE_PLUGIN_ROOT} ` +
                    `inside a plugin's own plugin.json is expanded there. The literal placeholder string ` +
                    `becomes part of the spawned command and the server fails to start ` +
                    `(MODULE_NOT_FOUND or similar). Use a path relative to the project root (Claude Code sets ` +
                    `cwd to it) or an absolute path instead.`,
                file_path: source.label,
                snippet: value_,
            }));
            break; // one finding per server entry is enough context
        }
    }
    return out;
}
//# sourceMappingURL=rules.js.map