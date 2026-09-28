/**
 * Orchestrates the agent-workspace audit: runs every rule check across every
 * config source that was read, and compares each MCP server entry's hash
 * against the previous audit's.
 *
 * Pure function over its inputs (`ConfigSource[]` + the previous hash map) —
 * no I/O. `tools/auditAgentConfig.ts` does the reading and persistence.
 */

import { makeFinding } from '../runners/scannerParsers/index.js';
import type { Finding } from '../types.js';
import type { AgentConfigHashEntry } from '../storage/agentAuditRepo.js';
import type { ConfigSource } from './configSources.js';
import { hashConfigValue } from './hash.js';
import { extractMcpServers, type McpServerEntry } from './mcpServers.js';
import {
  checkBypassPermissions,
  checkEnableAllProjectMcpServers,
  checkHookRisks,
  checkInlineSecrets,
  checkPlainHttpRemotes,
  checkUnexpandedVars,
  checkUnpinnedLaunchers,
  checkWildcardPermissions,
} from './rules.js';

export interface AgentAuditResult {
  findings: Finding[];
  warnings: string[];
  mcpServersFound: number;
  /** Every current entry's hash, ready to upsert into `agent_config_hashes`. */
  entryHashes: AgentConfigHashEntry[];
  entriesChanged: number;
  sourcesRead: string[];
  sourcesMissing: string[];
}

function entryKey(entry: McpServerEntry): string {
  return `${entry.sourceLabel}::${entry.name}`;
}

/**
 * `~/.claude.json` nests per-project MCP servers under `projects[path].mcpServers`
 * alongside its own top-level (global) `mcpServers`. Each project's servers
 * are exposed as their own synthetic source — labelled distinctly — so a
 * stale or malicious server declared for some OTHER project in the user's
 * global config is not silently skipped just because its path does not
 * match the project being audited.
 */
function expandNestedProjectSources(source: ConfigSource): ConfigSource[] {
  if (source.label !== '~/.claude.json' || !source.exists || source.json === undefined) return [];
  const root = source.json;
  if (root === null || typeof root !== 'object' || Array.isArray(root)) return [];
  const projects = (root as Record<string, unknown>)['projects'];
  if (projects === null || typeof projects !== 'object' || Array.isArray(projects)) return [];

  const out: ConfigSource[] = [];
  for (const [projectKey, value] of Object.entries(projects as Record<string, unknown>)) {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) continue;
    const mcpServers = (value as Record<string, unknown>)['mcpServers'];
    if (mcpServers === null || typeof mcpServers !== 'object' || Array.isArray(mcpServers)) continue;
    out.push({
      label: `~/.claude.json (project: ${projectKey})`,
      kind: 'user',
      absolutePath: source.absolutePath,
      mcpServersField: 'mcpServers',
      exists: true,
      json: { mcpServers },
    });
  }
  return out;
}

export function analyzeAgentConfig(
  sources: ConfigSource[],
  previousHashes: ReadonlyMap<string, string>,
): AgentAuditResult {
  const warnings: string[] = [];
  const sourcesRead: string[] = [];
  const sourcesMissing: string[] = [];

  const allSources: ConfigSource[] = [];
  for (const source of sources) {
    if (source.parseError !== undefined) {
      warnings.push(`${source.label}: ${source.parseError}`);
      continue;
    }
    if (!source.exists) {
      sourcesMissing.push(source.label);
      continue;
    }
    sourcesRead.push(source.label);
    allSources.push(source);
    allSources.push(...expandNestedProjectSources(source));
  }

  const findings: Finding[] = [];
  const entries: McpServerEntry[] = [];
  for (const source of allSources) {
    entries.push(...extractMcpServers(source));
    findings.push(...checkWildcardPermissions(source));
    findings.push(...checkBypassPermissions(source));
    findings.push(...checkEnableAllProjectMcpServers(source));
    findings.push(...checkHookRisks(source));
    findings.push(...checkUnexpandedVars(source));
  }
  findings.push(...checkUnpinnedLaunchers(entries));
  findings.push(...checkPlainHttpRemotes(entries));
  findings.push(...checkInlineSecrets(entries));

  const entryHashes: AgentConfigHashEntry[] = [];
  let entriesChanged = 0;
  for (const entry of entries) {
    const key = entryKey(entry);
    const hash = hashConfigValue(entry.raw);
    entryHashes.push({ entry_key: key, hash });

    const previous = previousHashes.get(key);
    if (previous !== undefined && previous !== hash) {
      entriesChanged += 1;
      findings.push(
        makeFinding({
          tool: 'agent-audit',
          rule_id: 'agent-audit-entry-changed',
          severity: 'low',
          category: 'security',
          title: `MCP server '${entry.name}' changed since the previous audit`,
          message:
            `'${entry.name}' in ${entry.sourceLabel} does not match what the previous audit_agent_config ` +
            `run recorded for it. Confirm the change was intentional.`,
          file_path: entry.sourceLabel,
          fix_available: false,
        }),
      );
    }
  }

  return {
    findings,
    warnings,
    mcpServersFound: entries.length,
    entryHashes,
    entriesChanged,
    sourcesRead,
    sourcesMissing,
  };
}
