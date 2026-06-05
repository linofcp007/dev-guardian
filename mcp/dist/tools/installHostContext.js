/**
 * `install_host_context` — set up a non-Claude AI host to use dev-guardian.
 *
 * Two things make a host dev-guardian-aware:
 *   1. an MCP-server registration in the host's config file (so the tools are
 *      reachable), and
 *   2. a "rules" / context file (so the host's AI knows *when* to call them).
 *
 * This tool does both, idempotently, for Cursor, Windsurf, GitHub Copilot,
 * Cline, Codex CLI, Gemini CLI and Claude Desktop. The MCP registration merges
 * into any existing host config without clobbering other servers; the rules
 * file is copied from `<plugin>/host-rules/`. Use host="all" to do every host.
 *
 * Claude Code / Cowork need none of this — the plugin registers the server
 * automatically via `.claude-plugin/plugin.json`.
 */
import { copyFileSync, existsSync, mkdirSync, readFileSync, statSync, writeFileSync, } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { z } from 'zod';
import { ALL_HOSTS, effectiveScope, HOST_SPECS, } from '../hostsetup/hostSpecs.js';
import { buildManualSnippet, buildServerEntry, mergeJsonConfig, mergeTomlConfig, resolveMcpConfigPath, resolveServerJsPath, } from '../hostsetup/mcpConfig.js';
import { detectOs } from '../platform/osDetect.js';
import { resolveProjectPath } from '../platform/projectPath.js';
import { ProjectPath } from '../schemas.js';
import { registerToolModule } from './index.js';
const inputSchema = {
    project_path: ProjectPath,
    host: z
        .enum(['cursor', 'windsurf', 'copilot', 'cline', 'codex', 'gemini', 'claude-desktop', 'all'])
        .describe('Which host to set up. Use "all" to set up every supported host.'),
    scope: z
        .enum(['project', 'global'])
        .optional()
        .describe('Where to register the MCP server: "project" (config inside the repo, default) or "global" ' +
        '(user-level config). Only affects MCP registration; rules files are always project-scoped. ' +
        'Windsurf and Claude Desktop are global-only and ignore this.'),
    register_mcp: z
        .boolean()
        .optional()
        .describe('Write/merge the MCP server registration into the host config. Default: true.'),
    install_rules: z
        .boolean()
        .optional()
        .describe('Copy the host rules/context file into the project. Default: true.'),
    force: z
        .boolean()
        .optional()
        .describe('Overwrite an existing rules file / update a differing MCP entry. Default: false.'),
    apply: z
        .boolean()
        .optional()
        .describe('When false, return only the planned actions without writing. Default: true.'),
};
const tool = {
    name: 'install_host_context',
    title: 'Set up a non-Claude AI host (MCP server + rules)',
    description: 'Make a non-Claude AI host dev-guardian-aware: register the MCP server in its config (merging, ' +
        'not clobbering) AND drop the host rules file. Supports Cursor, Windsurf, GitHub Copilot, Cline, ' +
        'Codex CLI, Gemini CLI and Claude Desktop. Idempotent. Use host="all" for every host, ' +
        'scope="global" for a user-level MCP registration. apply=false previews the plan.',
    inputSchema,
    handler: async (input, ctx) => handler(input, ctx),
};
registerToolModule(tool);
async function handler(input, ctx) {
    const inp = input;
    let projectPath;
    try {
        projectPath = resolveProjectPath(inp.project_path).path;
    }
    catch (e) {
        return failDomain('not_a_git_repo', e.message);
    }
    const apply = inp.apply ?? true;
    const force = inp.force === true;
    const registerMcp = inp.register_mcp ?? true;
    const installRules = inp.install_rules ?? true;
    const requestedScope = inp.scope ?? 'project';
    const requestedHosts = inp.host === 'all' ? [...ALL_HOSTS] : [inp.host];
    const hostsDir = resolveHostRulesDir(ctx.scriptsDir);
    const needsRules = installRules && requestedHosts.some((h) => HOST_SPECS[h].rules);
    if (needsRules && !existsSync(hostsDir)) {
        return failDomain('scanner_failed', `host-rules templates not found at ${hostsDir}. Re-install the plugin or build it.`);
    }
    const serverJsPath = resolveServerJsPath(ctx.scriptsDir);
    const env = {
        os: detectOs(),
        home: homedir(),
        appData: process.env.APPDATA,
        projectPath,
    };
    const results = requestedHosts.map((host) => {
        const spec = HOST_SPECS[host];
        const scope = effectiveScope(spec, requestedScope);
        const rules = installRules
            ? installRulesOne(spec, hostsDir, projectPath, apply, force)
            : { status: 'skipped', reason: 'install_rules=false' };
        const mcp = registerMcp
            ? registerMcpOne(host, spec, scope, serverJsPath, env, apply, force)
            : { status: 'skipped', reason: 'register_mcp=false' };
        return { host, scope, ...rules, mcp };
    });
    return {
        ok: true,
        applied: apply,
        project_path: projectPath,
        server_js: serverJsPath,
        results,
        next_steps: 'Restart the target AI host so it re-reads its MCP config and rules file. Then ask "what ' +
            'dev-guardian tools do you have?" — it should list the MCP tools. For hosts marked "manual" ' +
            '(Cline), paste the returned snippet into the host\'s MCP settings.',
    };
}
function installRulesOne(spec, hostsDir, projectPath, apply, force) {
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
    if (existsSync(dst) && !force) {
        return { ...base, status: 'already_exists', reason: 'force=false; not overwriting' };
    }
    if (!apply) {
        try {
            return { ...base, status: 'would_write', bytes: statSync(src).size };
        }
        catch {
            return { ...base, status: 'would_write' };
        }
    }
    try {
        mkdirSync(dirname(dst), { recursive: true });
        copyFileSync(src, dst);
        return { ...base, status: 'written', bytes: statSync(dst).size };
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
    const withType = m.format === 'json-servers';
    const entry = buildServerEntry(serverJsPath, withType);
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
            reason: 'an entry named "dev-guardian" exists but differs; pass force=true to update it',
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
    try {
        mkdirSync(dirname(configPath), { recursive: true });
        writeFileSync(configPath, merged.content, 'utf8');
        return { status: merged.status, config_path: configPath, key: m.serverKey, scope };
    }
    catch (e) {
        return { status: 'failed', config_path: configPath, key: m.serverKey, scope, reason: e.message };
    }
}
function resolveHostRulesDir(scriptsDir) {
    // scriptsDir = <plugin>/scripts/. host-rules sits next to scripts/.
    return resolve(scriptsDir, '..', 'host-rules');
}
function failDomain(code, message) {
    return { ok: false, error: { code, message } };
}
//# sourceMappingURL=installHostContext.js.map