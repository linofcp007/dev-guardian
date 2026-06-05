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

import {
  copyFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import {
  ALL_HOSTS,
  effectiveScope,
  HOST_SPECS,
  type HostName,
  type HostSpec,
  type McpScope,
} from './hostSpecs.js';
import {
  buildManualSnippet,
  buildServerEntry,
  mergeJsonConfig,
  mergeTomlConfig,
  resolveMcpConfigPath,
  type ResolveEnv,
} from './mcpConfig.js';

export type RulesStatus =
  | 'written'
  | 'already_exists'
  | 'would_write'
  | 'template_missing'
  | 'failed'
  | 'skipped'
  | 'unsupported';

export interface RulesResult {
  template_file?: string;
  source_path?: string;
  target_path?: string;
  status: RulesStatus;
  bytes?: number;
  reason?: string;
}

export type McpStatus =
  | 'written'
  | 'merged'
  | 'already_present'
  | 'needs_update'
  | 'would_write'
  | 'would_merge'
  | 'manual'
  | 'unsupported'
  | 'failed'
  | 'skipped';

export interface McpResult {
  status: McpStatus;
  config_path?: string;
  key?: string;
  scope?: McpScope;
  snippet?: string;
  reason?: string;
}

export interface HostResult extends RulesResult {
  host: HostName;
  scope: McpScope;
  mcp: McpResult;
}

/** `<plugin>/host-rules` lives next to `<plugin>/scripts`. */
export function resolveHostRulesDir(scriptsDir: string): string {
  return resolve(scriptsDir, '..', 'host-rules');
}

export interface SetupOptions {
  hosts: Array<HostName | 'all'>;
  projectPath: string;
  hostsDir: string;
  serverJsPath: string;
  env: ResolveEnv;
  scope: McpScope;
  registerMcp: boolean;
  installRules: boolean;
  apply: boolean;
  force: boolean;
}

/** Write/merge MCP config + rules for one or more hosts. */
export function setupHost(opts: SetupOptions): HostResult[] {
  const hosts: HostName[] = opts.hosts.includes('all')
    ? [...ALL_HOSTS]
    : (opts.hosts as HostName[]);

  return hosts.map((host) => {
    const spec = HOST_SPECS[host];
    const scope = effectiveScope(spec, opts.scope);
    const rules: RulesResult = opts.installRules
      ? installRulesOne(spec, opts.hostsDir, opts.projectPath, opts.apply, opts.force)
      : { status: 'skipped', reason: 'install_rules=false' };
    const mcp: McpResult = opts.registerMcp
      ? registerMcpOne(host, spec, scope, opts.serverJsPath, opts.env, opts.apply, opts.force)
      : { status: 'skipped', reason: 'register_mcp=false' };
    return { host, scope, ...rules, mcp };
  });
}

export interface PreviewResult {
  host: HostName;
  scope: McpScope;
  format: HostSpec['mcp']['format'];
  config_path?: string;
  key: string;
  /** The exact block to paste (JSON / TOML), or the manual snippet. */
  block: string;
  /** Destination of the rules file in the project, when the host has one. */
  rules_target?: string;
  manual: boolean;
}

/** The "paste this" config block for a host — no files touched. Bootstrap path. */
export function previewMcpConfig(
  host: HostName,
  scope: McpScope,
  serverJsPath: string,
  env: ResolveEnv,
): PreviewResult {
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
  const merged =
    m.format === 'toml'
      ? mergeTomlConfig(null, entry, false)
      : mergeJsonConfig(null, m.serverKey, entry, false);
  return {
    ...base,
    ...(configPath ? { config_path: configPath } : {}),
    block: merged.content ?? '',
    manual: false,
  };
}

function installRulesOne(
  spec: HostSpec,
  hostsDir: string,
  projectPath: string,
  apply: boolean,
  force: boolean,
): RulesResult {
  const rules = spec.rules;
  if (!rules) {
    return {
      status: 'unsupported',
      reason: 'host has no rules-file mechanism (uses Projects / custom instructions instead)',
    };
  }
  const src = join(hostsDir, rules.template_file);
  const dst = join(projectPath, rules.target_path);
  const base: RulesResult = {
    template_file: rules.template_file,
    source_path: src,
    target_path: dst,
    status: 'would_write',
  };

  if (!existsSync(src)) return { ...base, status: 'template_missing', reason: `${src} missing` };
  if (existsSync(dst) && !force) {
    return { ...base, status: 'already_exists', reason: 'force=false; not overwriting' };
  }
  if (!apply) {
    try {
      return { ...base, status: 'would_write', bytes: statSync(src).size };
    } catch {
      return { ...base, status: 'would_write' };
    }
  }
  try {
    mkdirSync(dirname(dst), { recursive: true });
    copyFileSync(src, dst);
    return { ...base, status: 'written', bytes: statSync(dst).size };
  } catch (e) {
    return { ...base, status: 'failed', reason: (e as Error).message };
  }
}

function registerMcpOne(
  host: HostName,
  spec: HostSpec,
  scope: McpScope,
  serverJsPath: string,
  env: ResolveEnv,
  apply: boolean,
  force: boolean,
): McpResult {
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

  let existing: string | null = null;
  try {
    if (existsSync(configPath)) existing = readFileSync(configPath, 'utf8');
  } catch (e) {
    return { status: 'failed', config_path: configPath, key: m.serverKey, scope, reason: (e as Error).message };
  }

  const entry = buildServerEntry(serverJsPath, m.format === 'json-servers');

  let merged;
  try {
    merged =
      m.format === 'toml'
        ? mergeTomlConfig(existing, entry, force)
        : mergeJsonConfig(existing, m.serverKey, entry, force);
  } catch (e) {
    return {
      status: 'failed',
      config_path: configPath,
      key: m.serverKey,
      scope,
      reason: `existing config could not be parsed safely (left untouched): ${(e as Error).message}`,
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
    writeFileSync(configPath, merged.content as string, 'utf8');
    return { status: merged.status, config_path: configPath, key: m.serverKey, scope };
  } catch (e) {
    return { status: 'failed', config_path: configPath, key: m.serverKey, scope, reason: (e as Error).message };
  }
}
