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
const OUR_TABLE_PATH = `mcp_servers.${SERVER_ID}`;
/** Any top-level TOML table heading (`[a.b.c]`) at the start of a line —
 *  used to find every heading that is OURS anywhere in the file. Not
 *  `g`-scoped as a shared constant: `RegExp.exec` with the `g` flag is
 *  STATEFUL (advances `lastIndex` across calls), so each caller below
 *  constructs its own instance rather than risk a skipped or repeated match
 *  from a shared one used across two scans. */
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
 * Locates EVERY span that is ours anywhere in the file — one entry per own
 * heading found, each running from that heading to the START of the NEXT
 * heading of any kind (or EOF). Returns `[]` when nothing of ours is
 * present.
 *
 * Fix round 1, item 3: the previous version (`findOwnTomlSpan`, singular)
 * stopped scanning the moment it saw the FIRST heading that was not ours,
 * so it found only a single, CONTIGUOUS span starting at the first own
 * heading. Two real shapes broke that:
 *   - a NON-CONTIGUOUS span — `[mcp_servers.dev-guardian]` … `[other]` …
 *     `[mcp_servers.dev-guardian.env]` — where a sub-table of ours reappears
 *     AFTER an unrelated table sits between it and the main heading. The old
 *     code stopped at `[other]` and never even looked past it, so the later
 *     `.env` sub-table was neither detected nor removed. Verified with
 *     `python -c "import tomllib..."`: "Cannot declare
 *     ('mcp_servers','dev-guardian','env') twice".
 *   - an ORPHAN sub-table with NO main heading at all —
 *     `[mcp_servers.dev-guardian.env]` alone. The old code's presence check
 *     (`TOML_HEADING.test`, matching only the exact main heading) missed it
 *     entirely, so `mergeTomlConfig` took the "no existing entry" branch and
 *     APPENDED a fresh block on top — two conflicting definitions of the
 *     same implicitly-created table. Verified: "Cannot overwrite a value".
 *
 * Scanning the WHOLE file for every own heading (never stopping at the
 * first foreign one) and collecting one span per own heading fixes both:
 * every own heading is found regardless of what sits between it and any
 * other, and "does an entry already exist" (for `mergeTomlConfig`'s own
 * needs_update/already_present decision) is now "is this list non-empty",
 * not "does the exact main heading exist".
 */
function findAllOwnTomlSpans(existing) {
    const re = headingRegex();
    const headings = [];
    let match;
    while ((match = re.exec(existing)) !== null) {
        const path = match[1];
        if (path === undefined)
            continue;
        headings.push({ index: match.index, path });
    }
    const spans = [];
    for (let i = 0; i < headings.length; i++) {
        const heading = headings[i];
        if (heading === undefined || !isOwnTablePath(heading.path))
            continue;
        const next = headings[i + 1];
        spans.push({ start: heading.index, end: next ? next.index : existing.length, path: heading.path });
    }
    return spans;
}
/** Removes every given span from `existing`, back-to-front by `start` so
 *  earlier offsets stay valid while later ones are spliced out — the
 *  reverse of the order `findAllOwnTomlSpans` returns them in (which is
 *  file order, front-to-back). */
function removeTomlSpans(existing, spans) {
    let result = existing;
    const byDescendingStart = [...spans].sort((a, b) => b.start - a.start);
    for (const span of byDescendingStart) {
        result = result.slice(0, span.start) + result.slice(span.end);
    }
    return result;
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
/**
 * Merge our server table into a Codex TOML config.
 *
 * Fix round 1, item 3: rebuilt around `findAllOwnTomlSpans` (every own
 * heading anywhere in the file, not just a single contiguous run starting
 * at the first one) so that both a non-contiguous span and an orphan
 * sub-table with no main heading are detected AND fully removed — see that
 * function's own doc comment for the two concrete failure modes this
 * replaces. On force, every own span is stripped out first and the fresh
 * block is appended once at the end — simpler and just as correct as trying
 * to reconstruct the ORIGINAL position, which non-contiguous spans make
 * ambiguous anyway (there is no longer one "spot" to put it back).
 */
export function mergeTomlConfig(existing, entry, force) {
    const fresh = buildTomlBlock(entry);
    if (!existing || existing.trim() === '') {
        return { status: 'written', content: fresh };
    }
    const spans = findAllOwnTomlSpans(existing);
    if (spans.length === 0) {
        const sep = existing.endsWith('\n') ? '\n' : '\n\n';
        return { status: 'merged', content: `${existing}${sep}${fresh}` };
    }
    // "Already exactly what we'd write" only has a meaningful reading when
    // there is exactly ONE own span and it IS the main heading — any extra
    // span (a stray sub-table, a duplicate) is itself evidence of staleness,
    // never a match.
    const onlySpan = spans.length === 1 ? spans[0] : undefined;
    if (onlySpan !== undefined && onlySpan.path === OUR_TABLE_PATH) {
        const currentText = existing.slice(onlySpan.start, onlySpan.end);
        if (normaliseTomlLines(currentText) === normaliseTomlLines(fresh)) {
            return { status: 'already_present' };
        }
    }
    if (!force)
        return { status: 'needs_update' };
    const remaining = removeTomlSpans(existing, spans).replace(/\s+$/, '');
    const content = remaining.length === 0 ? fresh : `${remaining}\n\n${fresh}`;
    return { status: 'merged', content };
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
 * Recognises an UNMARKED dev-guardian rules file from BEFORE this task —
 * every host-specific body prior to item 7's unification opened with some
 * variant of "…the **dev-guardian MCP server**…registered" (`AGENTS.md`:
 * "This repository has the **dev-guardian MCP server** registered.";
 * `copilot-instructions.md`: "This project uses the **dev-guardian MCP
 * server**"; `clinerules`: "This project has the dev-guardian MCP server
 * registered."; today's canonical body: "This project has the
 * **dev-guardian MCP server** registered."), so a single substring survives
 * across every version, old or new, with or without the bold markers.
 *
 * Fix round 1, item 2: without this, a project that ran an OLDER
 * `mcp-config --write` (back when it still `copyFileSync`d the whole file)
 * has an `AGENTS.md`/etc. that is ENTIRELY unmarked dev-guardian text — the
 * "no markers found" branch below used to treat that exactly like foreign
 * content and blindly APPEND a second, freshly-wrapped copy underneath it:
 * a ~220-line duplicate sitting beside stale text, forever, on every future
 * `--write`. Detecting it here routes it through the SAME
 * needs_update/force-gated path a stale MARKED block already goes through,
 * so it is reported rather than silently doubled, and only replaced when
 * the caller explicitly opts in.
 */
const LEGACY_UNMARKED_SIGNATURE = /dev-guardian MCP server/;
/**
 * Merge dev-guardian's own rendered rules content into a (possibly
 * user-owned, possibly absent) target file, confined to a delimited block —
 * never a whole-file replace. Mirrors `mergeJsonConfig`/`mergeTomlConfig`'s
 * own status vocabulary (`written` / `merged` / `already_present` /
 * `needs_update`) for the same reason those two share it: one predictable
 * contract for "did this write happen, and was anything already there."
 *
 * Only for SHARED files — a host's own general-purpose instructions file
 * (`AGENTS.md`, `GEMINI.md`, the copilot instructions file, `clinerules`)
 * that dev-guardian is a GUEST in, alongside whatever else the user or
 * another tool already put there. Cursor's `.mdc` and Windsurf's rules file
 * are NOT shared — nothing else writes to `.cursor/rules/dev-guardian.mdc`
 * or `.windsurf/rules/dev-guardian.md`, and both require YAML frontmatter as
 * the file's literal first bytes to be recognised at all, which a
 * `<!-- dev-guardian:begin -->` marker placed before it would break (fix
 * round 1, item 1 — CRITICAL: this exact mistake disabled the rule on every
 * new Cursor/Windsurf install). Those two go through `mergeOwnedRulesFile`
 * instead, which writes the file whole.
 *
 *   - No existing file (or empty): write just the wrapped block. `written`.
 *   - Existing file, no markers found, no legacy signature: APPEND the
 *     block — every byte of the existing (genuinely foreign) content
 *     survives untouched, regardless of `force`. This is the
 *     non-destructive case `force` no longer needs to gate, because nothing
 *     is ever removed by it.
 *   - Existing file, no markers found, BUT the legacy signature IS present
 *     (an older, whole-file dev-guardian install): `needs_update` when
 *     `force` is off (refuse to touch it, rather than risk duplicating);
 *     `merged` when `force` is on — the WHOLE file is replaced with the
 *     freshly wrapped block, the same scope the pre-fix `copyFileSync` had,
 *     now gated behind an explicit, informed opt-in instead of silent by
 *     default.
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
        if (LEGACY_UNMARKED_SIGNATURE.test(existing)) {
            if (!force)
                return { status: 'needs_update' };
            return { status: 'merged', content: block };
        }
        // Genuinely foreign content: append, preserving everything — safe
        // regardless of `force`, since nothing is ever removed.
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
/**
 * Merge dev-guardian's rendered content into a file dev-guardian OWNS
 * exclusively — Cursor's `.cursor/rules/dev-guardian.mdc` and Windsurf's
 * `.windsurf/rules/dev-guardian.md` (fix round 1, items 1 and 2). Unlike
 * `mergeRulesBlock`, there is no delimited-block/legacy-signature dance:
 * nothing else is ever expected to write to these paths, so the whole file
 * IS dev-guardian's content, always, and can simply be written or
 * overwritten outright — including its required leading YAML frontmatter,
 * which a `<!-- dev-guardian:begin -->` marker placed before it would break.
 * `force` plays no part here (unlike the JSON/TOML/shared-rules mergers):
 * there is nothing else in the file whose loss `force` needs to gate.
 */
export function mergeOwnedRulesFile(existing, rendered) {
    if (existing === rendered)
        return { status: 'already_present' };
    return { status: existing === null ? 'written' : 'merged', content: rendered };
}
/** Human-readable snippet for `manual` hosts (cline). */
export function buildManualSnippet(serverJsPath) {
    const entry = buildServerEntry(serverJsPath, false);
    const block = { mcpServers: { [SERVER_ID]: entry } };
    return JSON.stringify(block, null, 2);
}
//# sourceMappingURL=mcpConfig.js.map