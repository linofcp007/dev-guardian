/**
 * Pinning what a server serves, so a definition that changes under the same
 * name — a "rug pull": approved once, rewritten later — is reported.
 *
 * Each tool is pinned as sha256 of the canonical JSON of
 * `{name, description, inputSchema, annotations}` (keys sorted, absent fields
 * as null — `agentaudit/hash.ts`'s `stableStringify`), and compared with the
 * pins the previous audit of the same server stored
 * (`storage/mcpToolPinsRepo.ts`). The first audit of a server only records.
 *
 * Pure functions. No I/O.
 */
import { hashConfigValue } from '../agentaudit/hash.js';
import { makeFinding } from '../runners/scannerParsers/index.js';
import { MCP_TOOL_AUDIT } from './analyze.js';
import { escapeInvisible } from './rules.js';
export function toolDefinitionHash(tool) {
    return hashConfigValue({
        name: tool.name,
        description: tool.description ?? null,
        inputSchema: tool.inputSchema ?? null,
        annotations: tool.annotations ?? null,
    });
}
/**
 * Compare `listing`'s tools with `previous` (tool name → hash).
 * `auditedBefore` says whether the server was audited at all before — with
 * an empty `previous` it separates "had no tools" (every tool is new) from
 * "never audited" (nothing to compare).
 */
export function comparePins(listing, previous, auditedBefore) {
    const current = new Map();
    for (const tool of listing.tools)
        current.set(tool.name, toolDefinitionHash(tool));
    const pins = [...current].map(([tool_name, hash]) => ({ tool_name, hash }));
    const firstAudit = !auditedBefore && previous.size === 0;
    if (firstAudit)
        return { findings: [], firstAudit, changed: [], added: [], removed: [], pins };
    const changed = [];
    const added = [];
    for (const [name, hash] of current) {
        const before = previous.get(name);
        if (before === undefined)
            added.push(name);
        else if (before !== hash)
            changed.push(name);
    }
    const removed = [...previous.keys()].filter((name) => !current.has(name)).sort();
    const server = escapeInvisible(listing.serverName);
    const finding = (ruleId, severity, name, title, message) => makeFinding({
        tool: MCP_TOOL_AUDIT,
        rule_id: ruleId,
        severity,
        category: 'security',
        subcategory: 'mcp_rug_pull',
        title: escapeInvisible(title),
        message: escapeInvisible(message),
        file_path: listing.sourceLabel,
        snippet: escapeInvisible(`${server} > tool '${name}'`),
        fix_available: false,
    });
    const findings = [
        ...changed.map((name) => finding('mcp-tool-definition-changed', 'high', name, `Rug pull: MCP server '${server}' changed tool '${name}' since the previous audit`, `Tool '${name}' of server '${server}' (${listing.sourceLabel}) is served with a different definition ` +
            '(description, input schema or annotations) than the previous audit_mcp_tools run recorded, under ' +
            'the same name. A tool approved once and rewritten later is how a server turns malicious after ' +
            'review. Read the new definition before using the server again; this audit now pins it.')),
        ...added.map((name) => finding('mcp-tool-added', 'low', name, `MCP server '${server}' added tool '${name}' since the previous audit`, `Server '${server}' (${listing.sourceLabel}) now serves a tool '${name}' the previous audit did not see.`)),
        ...removed.map((name) => finding('mcp-tool-removed', 'info', name, `MCP server '${server}' no longer serves tool '${name}'`, `Server '${server}' (${listing.sourceLabel}) served a tool '${name}' at the previous audit and does not now.`)),
    ];
    return { findings, firstAudit, changed, added, removed, pins };
}
//# sourceMappingURL=pins.js.map