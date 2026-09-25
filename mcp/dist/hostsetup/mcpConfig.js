/**
 * Pure helpers for registering the dev-guardian MCP server into a host's
 * config file. No direct I/O lives here except path computation — the tool
 * handler reads/writes files and calls these to decide *what* to write.
 *
 * The server is always launched the same way the Claude Code plugin launches
 * it: `node <plugin>/mcp/dist/server.js`. For non-Claude hosts there is no
 * `${CLAUDE_PLUGIN_ROOT}` placeholder, so we emit an ABSOLUTE path.
 */
import { join, resolve } from 'node:path';
/** The fixed id used for the server entry across every host. */
export const SERVER_ID = 'dev-guardian';
/** Absolute path to the built MCP entrypoint, derived from scriptsDir. */
export function resolveServerJsPath(scriptsDir) {
    // scriptsDir = <plugin>/scripts. The built server sits at <plugin>/mcp/dist/server.js.
    return resolve(scriptsDir, '..', 'mcp', 'dist', 'server.js');
}
/** Build the server-launch entry. `withType` adds `type:"stdio"` for Copilot. */
export function buildServerEntry(serverJsPath, withType) {
    const base = { command: 'node', args: [serverJsPath], env: {} };
    return withType ? { type: 'stdio', ...base } : base;
}
/** OS-specific location of Claude Desktop's config, or null when unsupported. */
export function claudeDesktopConfigPath(env) {
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
/**
 * Resolve the config file path for a host at a given (already-effective)
 * scope. Returns null for `manual` hosts (cline) or unsupported OSes.
 */
export function resolveMcpConfigPath(host, scope, env) {
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
function deepEqual(a, b) {
    if (a === b)
        return true;
    if (typeof a !== typeof b)
        return false;
    if (a === null || b === null)
        return a === b;
    if (Array.isArray(a) || Array.isArray(b)) {
        if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length)
            return false;
        return a.every((v, i) => deepEqual(v, b[i]));
    }
    if (typeof a === 'object') {
        const ao = a;
        const bo = b;
        const ak = Object.keys(ao);
        const bk = Object.keys(bo);
        if (ak.length !== bk.length)
            return false;
        return ak.every((k) => deepEqual(ao[k], bo[k]));
    }
    return false;
}
/**
 * Merge our server entry into a JSON host config, preserving everything else.
 * `existing` is the current file contents, or null when the file is absent.
 * Throws on malformed JSON so the caller can report `failed` without clobbering.
 */
export function mergeJsonConfig(existing, serverKey, entry, force) {
    let cfg;
    if (existing == null || existing.trim() === '') {
        cfg = {};
    }
    else {
        const parsed = JSON.parse(existing);
        if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
            throw new Error('config root is not a JSON object');
        }
        cfg = parsed;
    }
    const containerRaw = cfg[serverKey];
    const container = containerRaw && typeof containerRaw === 'object' && !Array.isArray(containerRaw)
        ? containerRaw
        : undefined;
    const current = container?.[SERVER_ID];
    if (current && deepEqual(current, entry))
        return { status: 'already_present' };
    if (current && !force)
        return { status: 'needs_update' };
    const nextContainer = { ...(container ?? {}), [SERVER_ID]: entry };
    cfg[serverKey] = nextContainer;
    const content = `${JSON.stringify(cfg, null, 2)}\n`;
    return { status: existing == null || existing.trim() === '' ? 'written' : 'merged', content };
}
/** TOML literal string (single quotes) — no backslash escaping, ideal for
 *  Windows paths. Falls back to a basic (double-quoted) string only when the
 *  value itself contains a single quote. */
function tomlString(value) {
    if (!value.includes("'"))
        return `'${value}'`;
    const escaped = value.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
    return `"${escaped}"`;
}
const TOML_HEADING = /^\[mcp_servers\.dev-guardian\]/m;
const OUR_TABLE_PATH = `mcp_servers.${SERVER_ID}`;
/** Any top-level TOML table heading (`[a.b.c]`) at the start of a line —
 *  used to find where OUR table (and any of its own sub-tables) ends and
 *  the next, unrelated table begins. Not `g`-scoped as a shared constant:
 *  `RegExp.exec` with the `g` flag is STATEFUL (advances `lastIndex` across
 *  calls), so each caller below constructs its own instance rather than risk
 *  a skipped or repeated match from a shared one used across two scans. */
function headingRegex() {
    return /^\[([^\]]+)\]/gm;
}
/** True for `mcp_servers.dev-guardian` itself AND any of its own sub-tables
 *  (`mcp_servers.dev-guardian.env`, …) — everything a fresh write of our
 *  block would own or replace. */
function isOwnTablePath(path) {
    return path === OUR_TABLE_PATH || path.startsWith(`${OUR_TABLE_PATH}.`);
}
/**
 * Locates the full span of OUR table — the `[mcp_servers.dev-guardian]`
 * heading through the end of the LAST of its own sub-tables, stopping at the
 * first heading that is not ours (or EOF). Returns `null` when our heading
 * is not present at all.
 *
 * This is what makes `[mcp_servers.dev-guardian.env]` (a sub-table, distinct
 * from our own generated `env = {}` SCALAR key) part of the span to remove:
 * the previous implementation only looked for "the next line starting with
 * `[`, ANY heading" to mark the end, so a hand-edited sub-table sitting
 * right after our heading was already (correctly) excluded from the
 * replaced region — but that meant it was never REMOVED either, so a
 * force-update left it sitting next to a freshly written `env = {}`: two
 * conflicting definitions of the same key, invalid TOML. Scanning every
 * heading and absorbing every one that is OURS (not just the first) fixes
 * that without needing a real TOML parser.
 */
function findOwnTomlSpan(existing) {
    const re = headingRegex();
    let match;
    let start = -1;
    let end = existing.length;
    while ((match = re.exec(existing)) !== null) {
        const path = match[1];
        if (path === undefined)
            continue;
        if (isOwnTablePath(path)) {
            if (start === -1)
                start = match.index;
            continue; // absorbed into our span; keep scanning for the true end
        }
        if (start !== -1) {
            end = match.index;
            break;
        }
    }
    return start === -1 ? null : { start, end };
}
function buildTomlBlock(entry) {
    const args = entry.args.map((a) => tomlString(a)).join(', ');
    return (`[mcp_servers.${SERVER_ID}]\n` +
        `command = ${tomlString(entry.command)}\n` +
        `args = [${args}]\n` +
        `env = {}\n` +
        `enabled = true\n`);
}
/** Textual comparison of an extracted existing span against a freshly built
 *  block, ignoring only blank lines and per-line surrounding whitespace —
 *  enough to tell "byte-for-byte the same table" from "genuinely differs"
 *  (including a sub-table the fresh block would never contain) without a
 *  real TOML parser. `buildTomlBlock`'s output is fully deterministic (one
 *  canonical key order), so this is exact for anything OUR OWN code wrote;
 *  it reads as "differs" for anything a human hand-edited, which is exactly
 *  the needs_update case. */
function normaliseTomlLines(text) {
    return text
        .split('\n')
        .map((line) => line.trim())
        .filter((line) => line.length > 0)
        .join('\n');
}
/** Replace the existing `[mcp_servers.dev-guardian]` table — heading through
 *  the end of its own last sub-table — with a freshly built one. */
function replaceTomlBlock(existing, entry) {
    const span = findOwnTomlSpan(existing);
    if (!span)
        return `${existing.replace(/\n?$/, '\n')}\n${buildTomlBlock(entry)}`;
    const before = existing.slice(0, span.start);
    const tail = existing.slice(span.end);
    const block = buildTomlBlock(entry);
    return `${before}${block}${tail.startsWith('\n') ? tail : tail ? `\n${tail}` : ''}`;
}
/** Merge our server table into a Codex TOML config. */
export function mergeTomlConfig(existing, entry, force) {
    if (existing && TOML_HEADING.test(existing)) {
        const span = findOwnTomlSpan(existing);
        const fresh = buildTomlBlock(entry);
        const currentText = span ? existing.slice(span.start, span.end) : '';
        if (normaliseTomlLines(currentText) === normaliseTomlLines(fresh)) {
            return { status: 'already_present' };
        }
        if (!force)
            return { status: 'needs_update' };
        return { status: 'merged', content: replaceTomlBlock(existing, entry) };
    }
    const block = buildTomlBlock(entry);
    if (!existing || existing.trim() === '') {
        return { status: 'written', content: block };
    }
    const sep = existing.endsWith('\n') ? '\n' : '\n\n';
    return { status: 'merged', content: `${existing}${sep}${block}` };
}
/**
 * Delimiters for the dev-guardian-managed block inside a shared rules file
 * (AGENTS.md, GEMINI.md, the copilot instructions file, …). Item 6b
 * (2026-09-25 full review): `--force` used to `copyFileSync` the WHOLE
 * rendered template over the target file, destroying any unrelated content
 * a user had already put there — reproduced directly, a project's own
 * "Never touch prod" instruction in AGENTS.md was gone after one run. Every
 * write below is confined to the text between these two markers; nothing
 * outside them is ever read for content or replaced.
 */
export const RULES_BLOCK_BEGIN = '<!-- dev-guardian:begin -->';
export const RULES_BLOCK_END = '<!-- dev-guardian:end -->';
function wrapRulesBlock(rendered) {
    return `${RULES_BLOCK_BEGIN}\n${rendered.replace(/\s+$/, '')}\n${RULES_BLOCK_END}\n`;
}
/**
 * Merge dev-guardian's own rendered rules content into a (possibly
 * user-owned, possibly absent) target file, confined to a delimited block —
 * never a whole-file replace. Mirrors `mergeJsonConfig`/`mergeTomlConfig`'s
 * own status vocabulary (`written` / `merged` / `already_present` /
 * `needs_update`) for the same reason those two share it: one predictable
 * contract for "did this write happen, and was anything already there."
 *
 *   - No existing file (or empty): write just the wrapped block. `written`.
 *   - Existing file, no markers found: APPEND the block — every byte of the
 *     existing file survives untouched, regardless of `force`. This is the
 *     non-destructive case `force` no longer needs to gate, because nothing
 *     is ever removed by it.
 *   - Existing file, markers found, content already matches: no write.
 *     `already_present` (idempotent, same as the JSON/TOML mergers).
 *   - Existing file, markers found, content differs (template changed, or
 *     `--update-mcp`/`--force` is what will refresh it): `needs_update` when
 *     `force` is off (nothing written — the caller reports it and waits for
 *     the user to opt in), `merged` when `force` is on — ONLY the text
 *     between the markers changes; everything before and after is copied
 *     through byte-for-byte.
 */
export function mergeRulesBlock(existing, rendered, force) {
    const block = wrapRulesBlock(rendered);
    if (existing == null || existing.trim() === '') {
        return { status: 'written', content: block };
    }
    const beginIdx = existing.indexOf(RULES_BLOCK_BEGIN);
    const endMarkerIdx = existing.indexOf(RULES_BLOCK_END);
    if (beginIdx === -1 || endMarkerIdx === -1 || endMarkerIdx < beginIdx) {
        // No (valid) existing block: append, preserving all existing content —
        // safe regardless of `force`, since nothing is ever removed.
        const sep = existing.endsWith('\n') ? '\n' : '\n\n';
        return { status: 'merged', content: `${existing}${sep}${block}` };
    }
    const endIdx = endMarkerIdx + RULES_BLOCK_END.length;
    const currentBlock = existing.slice(beginIdx, endIdx);
    if (currentBlock === block.replace(/\n$/, '')) {
        return { status: 'already_present' };
    }
    if (!force)
        return { status: 'needs_update' };
    const before = existing.slice(0, beginIdx);
    const after = existing.slice(endIdx);
    const afterJoined = after.startsWith('\n') ? after : after ? `\n${after}` : '';
    return { status: 'merged', content: `${before}${block}${afterJoined}` };
}
/** Human-readable snippet for `manual` hosts (cline). */
export function buildManualSnippet(serverJsPath) {
    const entry = buildServerEntry(serverJsPath, false);
    const block = { mcpServers: { [SERVER_ID]: entry } };
    return JSON.stringify(block, null, 2);
}
//# sourceMappingURL=mcpConfig.js.map