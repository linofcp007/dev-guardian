/**
 * Host-setup orchestration — shared core behind the `dev-guardian mcp-config`
 * CLI. Context-free (no PluginContext): callers pass plain paths so this works
 * from a terminal without an MCP connection.
 *
 *   - previewMcpConfig(): the "print this, paste it" block for a host (bootstrap).
 *   - setupHost():        write/merge the MCP config + drop the rules file.
 *
 * The actual JSON/TOML merge and path resolution live in `mcpConfig.ts`; the
 * per-host shape table lives in `hostSpecs.ts`. This module only wires I/O.
 */
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync, } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ALL_HOSTS, effectiveScope, HOST_SPECS, } from './hostSpecs.js';
import { buildManualSnippet, buildServerEntry, mergeJsonConfig, mergeOwnedRulesFile, mergeRulesBlock, mergeTomlConfig, resolveMcpConfigPath, RULES_BLOCK_BEGIN, RULES_BLOCK_END, } from './mcpConfig.js';
import { substituteCliPath } from './rulesTemplate.js';
/**
 * Directory of KNOWN, byte-exact legacy rules-template snapshots — every
 * shared-host body (`AGENTS.md`, `GEMINI.md`, copilot instructions,
 * `clinerules`) this project has ever shipped, from before item 7's
 * canonical-body unification. Sits next to this module's own compiled
 * location (`mcp/dist/hostsetup/legacyRulesTemplates/`, copied there by
 * `scripts/copy-assets.mjs` — same convention as `storage/migrations/*.sql`)
 * so it resolves correctly whether this file is running from `dist/`
 * (production) or `src/` (dev, via tsx) without either needing to know
 * which.
 */
const LEGACY_TEMPLATES_DIR = resolve(dirname(fileURLToPath(import.meta.url)), 'legacyRulesTemplates');
/**
 * Loads every known legacy template body, cached after the first call —
 * `installRulesOne` runs once per host in `setupHost`'s own `.map()`, and
 * re-reading a handful of small files from disk that many times has no
 * value. Returns `[]` (never throws) when the directory is missing — a
 * build that skipped `copy-assets.mjs` degrades to `mergeRulesBlock`'s own
 * safe defaults (no known templates to match against — a file that mentions
 * dev-guardian falls through to `manual_merge_required` rather than
 * anything being silently rewritten), not a crash.
 */
let cachedLegacyTemplates = null;
function loadKnownLegacyTemplates() {
    if (cachedLegacyTemplates)
        return cachedLegacyTemplates;
    try {
        const files = readdirSync(LEGACY_TEMPLATES_DIR);
        cachedLegacyTemplates = files.map((f) => readFileSync(join(LEGACY_TEMPLATES_DIR, f), 'utf8'));
    }
    catch {
        cachedLegacyTemplates = [];
    }
    return cachedLegacyTemplates;
}
/**
 * Hosts whose rules file dev-guardian owns EXCLUSIVELY — nothing else is
 * ever expected to write to `.cursor/rules/dev-guardian.mdc` or
 * `.windsurf/rules/dev-guardian.md`, unlike `AGENTS.md`/`GEMINI.md`/the
 * copilot instructions file/`clinerules`, which are general-purpose files
 * dev-guardian is a GUEST in. Fix round 1, item 1 (CRITICAL): both of these
 * also require YAML frontmatter as the file's literal first bytes to be
 * recognised by their host at all — wrapping them in a
 * `<!-- dev-guardian:begin -->` marker (item 6b's delimited-block scheme,
 * correct for the shared files) put that marker BEFORE the frontmatter,
 * silently disabling the rule (`alwaysApply`/`trigger`) on every install.
 * These two route through `mergeOwnedRulesFile` instead, which writes the
 * whole file — frontmatter first, always.
 */
const OWNED_WHOLE_FILE_HOSTS = new Set(['cursor', 'windsurf']);
/** `<plugin>/host-rules` lives next to `<plugin>/scripts`. */
export function resolveHostRulesDir(scriptsDir) {
    return resolve(scriptsDir, '..', 'host-rules');
}
/**
 * True when `host` is a global-only host (Windsurf, Claude Desktop —
 * `spec.mcp.forceScope === 'global'`) being swept in via `hosts: ['all']`
 * at a NON-global requested scope. Item 6d (2026-09-25 full review):
 * `mcp-config all --write` at the default (project) scope used to silently
 * write the GLOBAL Windsurf and Claude Desktop configs anyway — surprising,
 * cross-project side effects nobody asked for — because both hosts force
 * their own scope regardless of what was requested. Naming a SINGLE
 * global-only host explicitly (`mcp-config windsurf --write`) is unaffected:
 * the user asked for that host by name, so there is nothing surprising about
 * it landing in its only possible location.
 */
function isForceGlobalSkippedUnderAll(spec, requestedAll, requestedScope) {
    return requestedAll && spec.mcp.forceScope === 'global' && requestedScope !== 'global';
}
/** Write/merge MCP config + rules for one or more hosts. */
export function setupHost(opts) {
    const requestedAll = opts.hosts.includes('all');
    const hosts = requestedAll ? [...ALL_HOSTS] : opts.hosts;
    return hosts.map((host) => {
        const spec = HOST_SPECS[host];
        const scope = effectiveScope(spec, opts.scope);
        const rules = opts.installRules
            ? installRulesOne(host, spec, opts.hostsDir, opts.projectPath, opts.apply, opts.force, opts.cliPath)
            : { status: 'skipped', reason: 'install_rules=false' };
        const skipGlobal = isForceGlobalSkippedUnderAll(spec, requestedAll, opts.scope);
        const mcp = !opts.registerMcp
            ? { status: 'skipped', reason: 'register_mcp=false' }
            : skipGlobal
                ? {
                    status: 'skipped',
                    scope,
                    reason: "global-only host skipped under 'all' at project scope, to avoid an unexpected write " +
                        "to your global config — pass --global (or --scope global) to include it",
                }
                : registerMcpOne(host, spec, scope, opts.serverJsPath, opts.env, opts.apply, opts.force);
        return { host, scope, ...rules, mcp };
    });
}
/** The "paste this" config block for a host — no files touched. Bootstrap path. */
export function previewMcpConfig(host, scope, serverJsPath, env) {
    const spec = HOST_SPECS[host];
    const m = spec.mcp;
    const eff = effectiveScope(spec, scope);
    const base = {
        host,
        scope: eff,
        format: m.format,
        key: m.serverKey,
        ...(spec.rules ? { rules_target: spec.rules.target_path } : {}),
    };
    if (m.format === 'manual') {
        return { ...base, block: buildManualSnippet(serverJsPath), manual: true };
    }
    const configPath = resolveMcpConfigPath(host, eff, env);
    const entry = buildServerEntry(serverJsPath, m.format === 'json-servers');
    const merged = m.format === 'toml'
        ? mergeTomlConfig(null, entry, false)
        : mergeJsonConfig(null, m.serverKey, entry, false);
    return {
        ...base,
        ...(configPath ? { config_path: configPath } : {}),
        block: merged.content ?? '',
        manual: false,
    };
}
/**
 * Renders the template at `src` (substituting `{{DEV_GUARDIAN_CLI}}` with
 * `cliPath` — item 6a) and installs it at `dst`.
 *
 * Two different merge strategies, chosen by `host` (fix round 1, item 1):
 *   - `OWNED_WHOLE_FILE_HOSTS` (Cursor, Windsurf): `mergeOwnedRulesFile`
 *     writes the file whole, frontmatter first, always — see that
 *     function's own doc comment in `mcpConfig.ts`.
 *   - Every other host: `mergeRulesBlock` manages a delimited block inside
 *     a shared file (item 6b), never a whole-file overwrite — see ITS doc
 *     comment for the full written/merged/already_present/needs_update
 *     contract, including the legacy-unmarked-copy detection added in fix
 *     round 1, item 2.
 */
function installRulesOne(host, spec, hostsDir, projectPath, apply, force, cliPath) {
    const rules = spec.rules;
    if (!rules) {
        return {
            status: 'unsupported',
            reason: 'host has no rules-file mechanism (uses Projects / custom instructions instead)',
        };
    }
    const src = join(hostsDir, rules.template_file);
    const dst = join(projectPath, rules.target_path);
    const base = {
        template_file: rules.template_file,
        source_path: src,
        target_path: dst,
        status: 'would_write',
    };
    if (!existsSync(src))
        return { ...base, status: 'template_missing', reason: `${src} missing` };
    let templateText;
    let existingText = null;
    try {
        templateText = readFileSync(src, 'utf8');
        if (existsSync(dst))
            existingText = readFileSync(dst, 'utf8');
    }
    catch (e) {
        return { ...base, status: 'failed', reason: e.message };
    }
    const rendered = substituteCliPath(templateText, cliPath);
    const merged = OWNED_WHOLE_FILE_HOSTS.has(host)
        ? mergeOwnedRulesFile(existingText, rendered)
        : mergeRulesBlock(existingText, rendered, force, loadKnownLegacyTemplates());
    if (merged.status === 'already_present')
        return { ...base, status: 'already_present' };
    if (merged.status === 'needs_update') {
        return {
            ...base,
            status: 'needs_update',
            reason: 'the installed rules block differs from the current template; pass --update-mcp to refresh it',
        };
    }
    if (merged.status === 'manual_merge_required') {
        return {
            ...base,
            status: 'manual_merge_required',
            reason: `this file mentions dev-guardian but its content does not match a known dev-guardian template ` +
                `exactly (whole, or as a leading/trailing region), so it will NOT be merged automatically — doing ` +
                `so could destroy content that only coincidentally sits near the mention. Add the managed block ` +
                `yourself at ${dst}, between ${RULES_BLOCK_BEGIN} and ${RULES_BLOCK_END}.`,
        };
    }
    // Narrowed (Global Constraint 1: no `as` casts standing in for a runtime
    // check), not `merged.content as string` — `written`/`merged` are the only
    // two statuses left at this point, and both mergers' own contracts
    // guarantee `content` is set for them; this makes that guarantee an
    // explicit, checked one rather than an assumed one.
    const { content } = merged;
    if (content === undefined) {
        return { ...base, status: 'failed', reason: 'internal error: merge produced no content to write' };
    }
    if (!apply) {
        return {
            ...base,
            status: merged.status === 'written' ? 'would_write' : 'would_merge',
            bytes: Buffer.byteLength(content, 'utf8'),
        };
    }
    try {
        mkdirSync(dirname(dst), { recursive: true });
        writeFileSync(dst, content, 'utf8');
        return { ...base, status: merged.status, bytes: statSync(dst).size };
    }
    catch (e) {
        return { ...base, status: 'failed', reason: e.message };
    }
}
function registerMcpOne(host, spec, scope, serverJsPath, env, apply, force) {
    const m = spec.mcp;
    if (m.format === 'manual') {
        return {
            status: 'manual',
            key: m.serverKey,
            snippet: buildManualSnippet(serverJsPath),
            reason: m.manualNote,
        };
    }
    const configPath = resolveMcpConfigPath(host, scope, env);
    if (!configPath) {
        return { status: 'unsupported', scope, reason: `could not resolve config path (os=${env.os})` };
    }
    let existing = null;
    try {
        if (existsSync(configPath))
            existing = readFileSync(configPath, 'utf8');
    }
    catch (e) {
        return { status: 'failed', config_path: configPath, key: m.serverKey, scope, reason: e.message };
    }
    const entry = buildServerEntry(serverJsPath, m.format === 'json-servers');
    let merged;
    try {
        merged =
            m.format === 'toml'
                ? mergeTomlConfig(existing, entry, force)
                : mergeJsonConfig(existing, m.serverKey, entry, force);
    }
    catch (e) {
        return {
            status: 'failed',
            config_path: configPath,
            key: m.serverKey,
            scope,
            reason: `existing config could not be parsed safely (left untouched): ${e.message}`,
        };
    }
    if (merged.status === 'already_present') {
        return { status: 'already_present', config_path: configPath, key: m.serverKey, scope };
    }
    if (merged.status === 'needs_update') {
        return {
            status: 'needs_update',
            config_path: configPath,
            key: m.serverKey,
            scope,
            reason: 'an entry named "dev-guardian" exists but differs; pass --update-mcp to update it',
        };
    }
    if (!apply) {
        return {
            status: merged.status === 'written' ? 'would_write' : 'would_merge',
            config_path: configPath,
            key: m.serverKey,
            scope,
        };
    }
    // Narrowed (Global Constraint 1), not `merged.content as string` — see the
    // identical narrowing in `installRulesOne` above for why: `written`/
    // `merged` are the only statuses reachable here, and both `mergeJsonConfig`/
    // `mergeTomlConfig` guarantee `content` is set for them.
    const { content } = merged;
    if (content === undefined) {
        return {
            status: 'failed',
            config_path: configPath,
            key: m.serverKey,
            scope,
            reason: 'internal error: merge produced no content to write',
        };
    }
    try {
        mkdirSync(dirname(configPath), { recursive: true });
        writeFileSync(configPath, content, 'utf8');
        return { status: merged.status, config_path: configPath, key: m.serverKey, scope };
    }
    catch (e) {
        return { status: 'failed', config_path: configPath, key: m.serverKey, scope, reason: e.message };
    }
}
//# sourceMappingURL=setup.js.map