/**
 * `audit_mcp_tools` — audit what the MCP servers configured for a project
 * ACTUALLY serve: start each server the caller names, list its tools,
 * prompts and resources, and check those definitions (`mcpaudit/analyze.ts`)
 * and whether they changed since the last audit (`mcpaudit/pins.ts`).
 *
 * `audit_agent_config` reads the same config files statically and never sees
 * a tool definition; `scan_skill` reads a manifest on disk. Neither sees what
 * the host loads into the model's context, which is where tool poisoning
 * lives, and neither can notice a definition that changes after it was
 * approved.
 *
 * This tool EXECUTES THIRD-PARTY CODE, so its envelope is fixed here, not
 * left to the caller:
 *
 *   - only the entry names listed in `servers` are started — there is no
 *     wildcard and no default, and a name no config declares is `skipped`;
 *   - a stdio server gets the SDK's minimal default environment plus the
 *     entry's own `env` (`mcpaudit/stdioTransport.ts`), never this server's
 *     full environment; its working directory is the project;
 *   - only `initialize` and the list methods (`tools/list`, `prompts/list`,
 *     `resources/list`) are sent — never `tools/call` (`mcpaudit/probe.ts`);
 *   - a remote (http/sse) server is contacted only with `allow_remote`;
 *   - the process tree is killed afterwards, every time.
 *
 * A server that did not run — not declared, remote without `allow_remote`,
 * failed to start, did not answer in `timeout_ms` — is `skipped`/`failed`
 * in `tools_run` with its reason, lands in `missing_tools`, and lowers
 * `coverage`: never a clean pass.
 */

import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import type { PluginContext } from '../context.js';
import { collectMcpEntries, type CollectedMcpEntries } from '../agentaudit/analyze.js';
import { readConfigSources } from '../agentaudit/configSources.js';
import type { McpServerEntry } from '../agentaudit/mcpServers.js';
import {
  analyzeServerListing,
  MCP_AUDIT_TOOL_NAME,
  normalizeListing,
  type OtherServer,
  type ServerListing,
} from '../mcpaudit/analyze.js';
import { comparePins, parsePinKey } from '../mcpaudit/pins.js';
import { probeServer, type ProbeOutcome } from '../mcpaudit/probe.js';
import { escapeInvisible } from '../mcpaudit/rules.js';
import { InvalidProjectPathError, resolveProjectPath } from '../platform/projectPath.js';
import { resolveVersion } from '../platform/version.js';
import type { McpPin } from '../storage/mcpToolPinsRepo.js';
import type { Finding, FindingsCountBySeverity, ToolResult, ToolRun } from '../types.js';
import { computeCoverage } from './scanCoverage.js';
import { registerToolModule, type ToolCallMeta, type ToolModule } from './index.js';

const DEFAULT_TIMEOUT_MS = 20_000;

const inputSchema = {
  project_path: z
    .string()
    .min(1)
    .optional()
    .describe('Absolute or relative path to the project whose MCP configs declare the servers. Defaults to the current working directory.'),
  servers: z
    .array(z.string().min(1).regex(/^[^*?]+$/, 'exact server names only: no wildcards'))
    .min(1)
    .max(50)
    .describe(
      'REQUIRED. The exact MCP server entry names to start and audit, as they appear in the config ' +
        '(e.g. ["github", "filesystem"]). No wildcard and no default: only these are executed.',
    ),
  include_user_config: z
    .boolean()
    .optional()
    .default(false)
    .describe(
      'Also look the names up in the user-level configs (Claude Code, Claude Desktop, Cursor, Windsurf, ' +
        'Gemini). Off by default.',
    ),
  allow_remote: z
    .boolean()
    .optional()
    .default(false)
    .describe('Contact remote (http/sse) servers among the named ones. Off by default: they are skipped.'),
  timeout_ms: z
    .number()
    .int()
    .min(1000)
    .max(300_000)
    .optional()
    .default(DEFAULT_TIMEOUT_MS)
    .describe('Per-server budget for starting, initialize and every list call. A server that does not answer in time fails.'),
};

const tool: ToolModule = {
  name: 'audit_mcp_tools',
  title: 'Audit the tool definitions MCP servers actually serve (poisoning, shadowing, rug pulls)',
  // Worded so this description does not trip the checks it lists: measured,
  // a literal tag block or file name here was a finding on dev-guardian itself.
  description:
    'Start the MCP servers named in `servers`, list the tools, prompts and resources each one serves, and ' +
    'check those definitions: tool poisoning (instructions aimed at the model, IMPORTANT-tag blocks), hidden ' +
    'Unicode (tag characters, zero-width, bidi), instructions to read secrets or agent config (SSH keys, ' +
    'dotenv files, MCP host configs), to hide actions from the user, to send data to a URL or smuggle it in a parameter, ' +
    'cross-server shadowing, large base64 blobs, abnormally long descriptions. Pins each tool (sha256 of ' +
    'name, title, description, input/output schema, annotations), prompt and resource template: a tool ' +
    'changed since the previous audit is a high "rug pull" finding (reported once, then re-pinned), a ' +
    'prompt or resource changed is medium; a new or removed tool or prompt is low/info. ' +
    'THIS EXECUTES THIRD-PARTY CODE: it runs the named servers\' commands as the host would, ONLY for the ' +
    'server names the caller lists explicitly (no wildcard, no default), with a minimal environment (plus ' +
    'the entry\'s own env), cwd = the project; it never calls tools/call; it contacts remote servers only ' +
    'with allow_remote; and it kills the process tree after. Run it only for servers the user asked to ' +
    'audit. Names are looked up in the configs audit_agent_config reads. A name not declared, a remote ' +
    'server without allow_remote, or a server that fails or does not answer within timeout_ms is ' +
    'skipped/failed with a reason and lowers coverage — never a clean pass.',
  inputSchema,
  handler: (input, ctx, callMeta) => handler(input, ctx, callMeta),
};

registerToolModule(tool);

interface ServerReport {
  name: string;
  server_key?: string;
  source?: string;
  transport?: string;
  status: 'ok' | 'failed' | 'skipped';
  reason?: string;
  server_info?: { name: string; version: string };
  tools_count: number;
  prompts_count: number;
  resources_count: number;
  resource_templates_count?: number;
  malformed_definitions?: number;
  /** Pin keys (`mcpaudit/pins.ts#pinKey`): a tool's name, or `<kind>:<id>`. */
  pins?: { first_audit: boolean; changed: string[]; added: string[]; removed: string[]; rehashed?: string[] };
  warnings?: string[];
}

async function handler(
  input: Record<string, unknown>,
  ctx: PluginContext,
  callMeta?: ToolCallMeta,
): Promise<ToolResult<Record<string, unknown>>> {
  const inp = input as {
    project_path?: string;
    servers?: unknown;
    include_user_config?: boolean;
    allow_remote?: boolean;
    timeout_ms?: number;
  };

  // The schema already requires this; checked again because nothing may be
  // started on an input that bypassed it.
  const names = Array.isArray(inp.servers)
    ? [...new Set(inp.servers.filter((s): s is string => typeof s === 'string' && s !== ''))]
    : [];
  if (names.length === 0 || names.some((n) => /[*?]/.test(n))) {
    return {
      ok: false,
      error: {
        code: 'unsupported_target',
        message: 'servers must list the exact MCP server names to audit; no wildcard and no default.',
      },
    };
  }

  let projectPath: string;
  try {
    projectPath = resolveProjectPath(inp.project_path).path;
  } catch (e) {
    if (e instanceof InvalidProjectPathError) {
      return { ok: false, error: { code: 'target_not_found', message: e.message } };
    }
    throw e;
  }

  const includeUserConfig = inp.include_user_config === true;
  const allowRemote = inp.allow_remote === true;
  const timeoutMs = typeof inp.timeout_ms === 'number' ? inp.timeout_ms : DEFAULT_TIMEOUT_MS;
  const collected = collectMcpEntries(readConfigSources(projectPath, includeUserConfig));

  const scanId = randomUUID();
  ctx.storage.scans.insert({ scan_id: scanId, scan_type: 'mcp_tool_audit', project_path: projectPath, tree_hash: '' });
  const run: AuditRun = { scanId, projectPath, names, includeUserConfig, allowRemote, timeoutMs, collected };
  try {
    return await runAudit(ctx, run, callMeta);
  } catch (e) {
    // Every probe closes its own process tree; what is left is the row.
    ctx.storage.scans.finalize({
      scan_id: scanId,
      status: 'failed',
      tools_run: [],
      missing_tools: [],
      error: e instanceof Error ? e.message : String(e),
    });
    throw e;
  }
}

interface AuditRun {
  scanId: string;
  projectPath: string;
  names: string[];
  includeUserConfig: boolean;
  allowRemote: boolean;
  timeoutMs: number;
  collected: CollectedMcpEntries;
}

async function runAudit(
  ctx: PluginContext,
  run: AuditRun,
  callMeta?: ToolCallMeta,
): Promise<ToolResult<Record<string, unknown>>> {
  const { scanId, projectPath, names, includeUserConfig, allowRemote, timeoutMs, collected } = run;
  const toolsRun: ToolRun[] = [];
  const missingTools: string[] = [];
  const reports: ServerReport[] = [];
  const probed: Array<{ entry: McpServerEntry; report: ServerReport; listing: ServerListing }> = [];
  const clientVersion = resolveVersion();

  // A config that exists and was not read may declare any of the names: the
  // audit did not see it, so it is a failed pass, never "no servers there".
  for (const u of collected.sourcesUnreadable) {
    const runName = `${MCP_AUDIT_TOOL_NAME}:${u.source}`;
    toolsRun.push({ name: runName, status: 'failed', reason: `config not read: ${u.reason}` });
    missingTools.push(runName);
  }
  const unreadableNote =
    collected.sourcesUnreadable.length === 0
      ? ''
      : `; these config sources exist and could not be read: ${collected.sourcesUnreadable
          .map((u) => `${u.source} (${u.reason})`)
          .join(', ')}`;

  for (const name of names) {
    const entries = collected.entries.filter((e) => e.name === name);
    if (entries.length === 0) {
      const runName = `${MCP_AUDIT_TOOL_NAME}:${name}`;
      const reason =
        `not declared in any config source read (${collected.sourcesRead.join(', ') || 'none found'})` +
        unreadableNote +
        (includeUserConfig ? '' : '; user-level configs were not read (include_user_config)');
      toolsRun.push({ name: runName, status: 'skipped', reason });
      missingTools.push(runName);
      reports.push({ name, status: 'skipped', reason, tools_count: 0, prompts_count: 0, resources_count: 0 });
      continue;
    }
    for (const entry of entries) {
      const serverKey = `${entry.sourceLabel}::${entry.name}`;
      const runName = `${MCP_AUDIT_TOOL_NAME}:${serverKey}`;
      const outcome: ProbeOutcome = await probeServer(entry, {
        projectPath,
        timeoutMs,
        allowRemote,
        clientVersion,
        ...(callMeta?.signal === undefined ? {} : { signal: callMeta.signal }),
      });
      const base = {
        name,
        server_key: serverKey,
        source: entry.sourceLabel,
        ...(outcome.transport === undefined ? {} : { transport: outcome.transport }),
        ...(outcome.warnings.length > 0 ? { warnings: outcome.warnings.map(escapeInvisible) } : {}),
      };
      if (outcome.status !== 'ok') {
        const reason = escapeInvisible(outcome.reason);
        toolsRun.push({ name: runName, status: outcome.status, reason });
        missingTools.push(runName);
        reports.push({ ...base, status: outcome.status, reason, tools_count: 0, prompts_count: 0, resources_count: 0 });
        continue;
      }
      const normalized = normalizeListing(outcome.listing);
      const listing: ServerListing = {
        serverKey,
        serverName: entry.name,
        sourceLabel: entry.sourceLabel,
        ...(outcome.instructions === undefined ? {} : { instructions: outcome.instructions }),
        tools: normalized.tools,
        prompts: normalized.prompts,
        resources: normalized.resources,
        resourceTemplates: normalized.resourceTemplates,
      };
      const report: ServerReport = {
        ...base,
        status: 'ok',
        ...(outcome.serverInfo === undefined
          ? {}
          : {
              server_info: {
                name: escapeInvisible(outcome.serverInfo.name),
                version: escapeInvisible(outcome.serverInfo.version),
              },
            }),
        tools_count: normalized.tools.length,
        prompts_count: normalized.prompts.length,
        resources_count: normalized.resources.length,
        resource_templates_count: normalized.resourceTemplates.length,
        ...(normalized.malformed > 0 ? { malformed_definitions: normalized.malformed } : {}),
      };
      toolsRun.push({ name: runName, status: 'ok' });
      reports.push(report);
      probed.push({ entry, report, listing });
    }
  }

  // Cross-server shadowing: every other server listed now, plus what earlier
  // audits pinned for servers not listed this time.
  const others: OtherServer[] = probed.map((p) => ({
    serverKey: p.listing.serverKey,
    serverName: p.listing.serverName,
    toolNames: p.listing.tools.map((t) => t.name),
  }));
  const probedKeys = new Set(others.map((o) => o.serverKey));
  const pinned = new Map<string, string[]>();
  for (const row of ctx.storage.mcpToolPins.listPinKeys(projectPath)) {
    if (probedKeys.has(row.server_key)) continue;
    const item = parsePinKey(row.key);
    if (item.kind !== 'tool') continue;
    const list = pinned.get(row.server_key) ?? [];
    list.push(item.id);
    pinned.set(row.server_key, list);
  }
  for (const [serverKey, toolNames] of pinned) {
    others.push({ serverKey, serverName: serverKey.slice(serverKey.lastIndexOf('::') + 2), toolNames });
  }

  const findings: Finding[] = [];
  const newPins: Array<{ serverKey: string; pins: McpPin[] }> = [];
  for (const { report, listing } of probed) {
    findings.push(...analyzeServerListing(listing, others));
    const comparison = comparePins(
      listing,
      ctx.storage.mcpToolPins.getServerPins(projectPath, listing.serverKey),
      ctx.storage.mcpToolPins.hasServer(projectPath, listing.serverKey),
    );
    findings.push(...comparison.findings);
    report.pins = {
      first_audit: comparison.firstAudit,
      changed: comparison.changed,
      added: comparison.added,
      removed: comparison.removed,
      ...(comparison.rehashed.length > 0 ? { rehashed: comparison.rehashed } : {}),
    };
    if (comparison.warnings.length > 0) report.warnings = [...(report.warnings ?? []), ...comparison.warnings];
    newPins.push({ serverKey: listing.serverKey, pins: comparison.pins });
  }

  if (findings.length > 0) {
    ctx.storage.findings.bulkInsert(findings.map((f) => ({ ...f, scan_id: scanId })));
  }
  for (const { serverKey, pins } of newPins) ctx.storage.mcpToolPins.replaceServerPins(projectPath, serverKey, pins);

  const warnings = [...collected.warnings];
  const coverage = computeCoverage(toolsRun, missingTools);
  ctx.storage.scans.finalize({
    scan_id: scanId,
    status: 'completed',
    tools_run: toolsRun,
    missing_tools: missingTools,
    meta: {
      servers_requested: names,
      include_user_config: includeUserConfig,
      allow_remote: allowRemote,
      timeout_ms: timeoutMs,
      servers: reports,
      sources_read: collected.sourcesRead,
      sources_unreadable: collected.sourcesUnreadable,
    },
  });

  return {
    ok: true,
    scan_id: scanId,
    project_path: projectPath,
    coverage,
    findings_count: findings.length,
    findings_by_severity: countBySeverity(findings),
    findings,
    servers: reports,
    tools_run: toolsRun,
    missing_tools: missingTools,
    sources_read: collected.sourcesRead,
    sources_unreadable: collected.sourcesUnreadable,
    warnings,
  };
}

function countBySeverity(findings: Finding[]): FindingsCountBySeverity {
  const out: FindingsCountBySeverity = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
  for (const f of findings) out[f.severity] += 1;
  return out;
}
