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
import { copyFileSync, existsSync, mkdirSync, readFileSync, statSync, writeFileSync, } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { ALL_HOSTS, effectiveScope, HOST_SPECS, } from './hostSpecs.js';
import { buildManualSnippet, buildServerEntry, mergeJsonConfig, mergeTomlConfig, resolveMcpConfigPath, } from './mcpConfig.js';
/** `<plugin>/host-rules` lives next to `<plugin>/scripts`. */
export function resolveHostRulesDir(scriptsDir) {
    return resolve(scriptsDir, '..', 'host-rules');
}
/** Write/merge MCP config + rules for one or more hosts. */
export function setupHost(opts) {
    const hosts = opts.hosts.includes('all')
        ? [...ALL_HOSTS]
        : opts.hosts;
    return hosts.map((host) => {
        const spec = HOST_SPECS[host];
        const scope = effectiveScope(spec, opts.scope);
        const rules = opts.installRules
            ? installRulesOne(spec, opts.hostsDir, opts.projectPath, opts.apply, opts.force)
            : { status: 'skipped', reason: 'install_rules=false' };
        const mcp = opts.registerMcp
            ? registerMcpOne(host, spec, scope, opts.serverJsPath, opts.env, opts.apply, opts.force)
            : { status: 'skipped', reason: 'register_mcp=false' };
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
            reason: 'an entry named "dev-guardian" exists but differs; pass --force to update it',
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
//# sourceMappingURL=setup.js.map