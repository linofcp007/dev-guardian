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
import { analyzeAgentConfig } from '../agentaudit/analyze.js';
import { readConfigSources } from '../agentaudit/configSources.js';
import { InvalidProjectPathError, resolveProjectPath } from '../platform/projectPath.js';
import { filterFindings } from '../severity/filter.js';
import { SeverityMin } from '../schemas.js';
import { computeCoverage } from './scanCoverage.js';
import { registerToolModule } from './index.js';
const inputSchema = {
    project_path: z
        .string()
        .min(1)
        .optional()
        .describe('Absolute or relative path to the project to audit. Defaults to the current working directory.'),
    include_user_config: z
        .boolean()
        .optional()
        .default(false)
        // Third person on purpose: an imperative "read ~/.claude.json" in a tool
        // description is an instruction to the model as far as the model can
        // tell, and audit_mcp_tools flagged exactly that here (fix round 3, M7).
        .describe('When true, the audit also reads the USER-level config, shared across every project on this ' +
        'machine: ~/.claude.json (or $CLAUDE_CONFIG_DIR/.claude.json), ~/.claude/settings.json, Claude ' +
        'Desktop\'s claude_desktop_config.json, ~/.cursor/mcp.json, Windsurf\'s ' +
        '~/.codeium/windsurf/mcp_config.json and ~/.gemini/settings.json. Off by default: it is outside ' +
        'this project and auditing it here would mix one project\'s report with settings that affect ' +
        'every other project too.'),
    severity_min: SeverityMin,
};
const tool = {
    name: 'audit_agent_config',
    title: 'Audit the AI-agent workspace configuration (MCP servers, permissions, hooks)',
    description: 'Audit the AI-agent workspace configuration in this project (and, opt-in, the user-level config) ' +
        'for risk signals that would let an agent session run unpinned code, leak secrets, or bypass ' +
        'permission prompts. Reads .mcp.json, .claude/settings.json, .claude/settings.local.json, ' +
        '.cursor/mcp.json, .vscode/mcp.json, .gemini/settings.json, .claude-plugin/plugin.json, and with ' +
        'include_user_config also ~/.claude.json, ~/.claude/settings.json and the Claude Desktop, Cursor, ' +
        'Windsurf and Gemini user configs. Flags: MCP servers launched via npx/uvx/pipx with no ' +
        'version pinned; remote MCP servers over plain http://; secrets written inline in an env block ' +
        '(redacted in the response); wildcard Bash permission allowlists (Bash(*), Bash(rm:*), ' +
        'Bash(curl:*)); defaultMode: bypassPermissions; enableAllProjectMcpServers; hooks that shell out ' +
        'to the network (curl/wget/iwr/irm) or write outside the project; and ${VAR} placeholders in a ' +
        'project .mcp.json, which Claude Code does not expand there (a real defect this repo shipped). ' +
        'Hashes each MCP server entry and flags ones changed since the previous audit. No network access; ' +
        'nothing here is executed. For the tool definitions a server actually serves (poisoning, rug pulls), ' +
        'use audit_mcp_tools, which starts the servers you name.',
    inputSchema,
    handler: (input, ctx) => handler(input, ctx),
};
registerToolModule(tool);
// No `await` inside — every check is synchronous — but the registry's
// `ToolModule.handler` contract always returns a Promise, so this is async.
async function handler(input, ctx) {
    const inp = input;
    let projectPath;
    try {
        projectPath = resolveProjectPath(inp.project_path).path;
    }
    catch (e) {
        if (e instanceof InvalidProjectPathError) {
            return { ok: false, error: { code: 'target_not_found', message: e.message } };
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
    const toolsRun = [{ name: 'agent-audit', status: 'ok' }];
    const missingTools = [];
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
function countBySeverity(findings) {
    const out = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
    for (const f of findings)
        out[f.severity] += 1;
    return out;
}
//# sourceMappingURL=auditAgentConfig.js.map