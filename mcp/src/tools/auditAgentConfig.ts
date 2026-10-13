/**
 * `audit_agent_config` — audit the AI-agent workspace configuration itself:
 * the MCP server declarations and Claude Code settings that decide what an
 * agent session is ALLOWED to do, rather than the project's own source code.
 *
 * Distinct from `scan_skill` (which vets a third-party skill/MCP artifact
 * BEFORE install): this tool audits the config already wired up in THIS
 * project (and, opt-in, the user's own `~/.claude.json` / `~/.claude/
 * settings.json`) — the same class of defect `scan_skill` cannot see because
 * nothing was ever "installed" from an external artifact; it was hand-edited
 * into a settings file.
 *
 * Read-only, offline, and it never touches the files it reads: every check
 * in `agentaudit/rules.ts` is a pure function over the parsed JSON.
 */

import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import type { PluginContext } from '../context.js';
import { analyzeAgentConfig } from '../agentaudit/analyze.js';
import { readConfigSources } from '../agentaudit/configSources.js';
import { InvalidProjectPathError, projectPathErrorCode, resolveProjectPath } from '../platform/projectPath.js';
import { filterFindings } from '../severity/filter.js';
import { SeverityMin } from '../schemas.js';
import type { Finding, ToolResult, ToolRun } from '../types.js';
import { computeCoverage } from './scanCoverage.js';
import { registerToolModule, type ToolModule } from './index.js';
import { countBySeverity } from '../severity/counts.js';

const inputSchema = {
  project_path: z
    .string()
    .min(1)
    .optional()
    .describe("The project to audit. Default: the server's working directory."),
  include_user_config: z
    .boolean()
    .optional()
    .default(false)
    // Third person on purpose: an imperative "read ~/.claude.json" in a tool
    // description is an instruction to the model as far as the model can
    // tell, and audit_mcp_tools flagged exactly that here (fix round 3, M7).
    .describe(
      'Also read the user-level configs every project shares. Default false.',
    ),
  severity_min: SeverityMin,
};

const tool: ToolModule = {
  name: 'audit_agent_config',
  title: 'Audit the agent workspace configuration',
  description:
    "Audit this project's agent configuration (.mcp.json, .claude/, .cursor/, .vscode/, .gemini/, " +
    'plugin.json; user-level ones with include_user_config): unpinned npx/uvx servers, plain-http remote ' +
    'servers, inline secrets (redacted), wildcard Bash permissions, bypassPermissions, hooks that reach ' +
    'the network, ${VAR} placeholders Claude Code does not expand, entries changed since the last audit. ' +
    'Reads only; audit_mcp_tools inspects what servers serve.',
  inputSchema,
  handler: (input, ctx) => handler(input, ctx),
};

registerToolModule(tool);

// No `await` inside — every check is synchronous — but the registry's
// `ToolModule.handler` contract always returns a Promise, so this is async.
async function handler(
  input: Record<string, unknown>,
  ctx: PluginContext,
): Promise<ToolResult<Record<string, unknown>>> {
  const inp = input as {
    project_path?: string;
    include_user_config?: boolean;
    severity_min?: Finding['severity'];
  };

  let projectPath: string;
  try {
    projectPath = resolveProjectPath(inp.project_path).path;
  } catch (e) {
    if (e instanceof InvalidProjectPathError) {
      return { ok: false, error: { code: projectPathErrorCode(e), message: e.message } };
    }
    throw e;
  }

  const includeUserConfig = inp.include_user_config === true;
  const sources = readConfigSources(projectPath, includeUserConfig);
  const previousHashes = ctx.storage.agentAudit.getHashes(projectPath);
  const result = analyzeAgentConfig(sources, previousHashes);

  const findings = filterFindings(result.findings, inp.severity_min);

  const scanId = randomUUID();
  ctx.storage.scans.insert({
    scan_id: scanId,
    scan_type: 'agent_audit',
    project_path: projectPath,
    // Not a source-tree scan (nothing here is a git checkout of code), so
    // there is no tree to hash — same convention `wp_cron_audit` uses.
    tree_hash: '',
  });
  if (result.findings.length > 0) {
    ctx.storage.findings.bulkInsert(result.findings.map((f) => ({ ...f, scan_id: scanId })));
  }
  ctx.storage.agentAudit.upsertHashes(projectPath, result.entryHashes);

  // A config that exists and was not read (refused by the reader, too large,
  // not valid JSON) was not audited: one failed pass per such file, in
  // missing_tools, so the scan's coverage is partial rather than clean.
  const toolsRun: ToolRun[] = [{ name: 'agent-audit', status: 'ok' }];
  const missingTools: string[] = [];
  for (const u of result.sourcesUnreadable) {
    const unreadName = `agent-audit:${u.source}`;
    toolsRun.push({ name: unreadName, status: 'failed', reason: u.reason });
    missingTools.push(unreadName);
  }
  ctx.storage.scans.finalize({
    scan_id: scanId,
    status: 'completed',
    tools_run: toolsRun,
    missing_tools: missingTools,
    meta: {
      include_user_config: includeUserConfig,
      mcp_servers_found: result.mcpServersFound,
      entries_changed: result.entriesChanged,
      sources_read: result.sourcesRead,
      sources_missing: result.sourcesMissing,
      sources_unreadable: result.sourcesUnreadable,
    },
  });

  return {
    ok: true,
    scan_id: scanId,
    project_path: projectPath,
    include_user_config: includeUserConfig,
    findings_count: findings.length,
    findings_by_severity: countBySeverity(findings),
    findings,
    mcp_servers_found: result.mcpServersFound,
    entries_changed_since_previous_audit: result.entriesChanged,
    sources_read: result.sourcesRead,
    sources_missing: result.sourcesMissing,
    sources_unreadable: result.sourcesUnreadable,
    coverage: computeCoverage(toolsRun, missingTools),
    warnings: result.warnings,
  };
}

