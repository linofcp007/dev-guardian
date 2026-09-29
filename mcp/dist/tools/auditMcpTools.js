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
 *   - only the entries the names in `servers` select are started
 *     (`mcpaudit/select.ts`): no wildcard, no default; a bare name whose
 *     entries launch different servers is refused with the qualified
 *     `<source>::<name>` list; Claude Code's global config contributes only
 *     THIS project's entries (the server runs with this project as cwd);
 *   - a stdio server gets the SDK's minimal default environment plus the
 *     entry's own `env` (`mcpaudit/stdioTransport.ts`), never this server's
 *     full environment; its working directory is the project;
 *   - only `initialize` and the list methods are sent — never `tools/call`
 *     (`mcpaudit/probe.ts`);
 *   - an entry that reaches another machine is contacted only with
 *     `allow_remote` (`mcpaudit/launch.ts`);
 *   - the process tree is killed afterwards, every time;
 *   - cancelling stops launching, and the whole audit has a budget
 *     (`GUARDIAN_MCP_AUDIT_BUDGET_MS`, 10 minutes by default): the servers
 *     left when it runs out are skipped with that reason.
 *
 * A server that did not run — not declared, ambiguous, remote without
 * `allow_remote`, failed to start, did not answer in `timeout_ms`, cancelled,
 * out of budget — is `skipped`/`failed` in `tools_run` with its reason, lands
 * in `missing_tools`, and lowers `coverage`; a listing a budget cut short is
 * `partial` (ok in `tools_run`, with the reason, and in `missing_tools`).
 * Never a clean pass.
 */
import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import { collectMcpEntries } from '../agentaudit/analyze.js';
import { readConfigSources } from '../agentaudit/configSources.js';
import { analyzeServerListingAsync, MCP_AUDIT_TOOL_NAME, normalizeListing, shadowingFromMentions, } from '../mcpaudit/analyze.js';
import { capFindings, capList, capText, MAX_LIST_ENTRIES, MAX_LIST_ENTRY_BYTES, MAX_REPORT_STRING_BYTES, } from '../mcpaudit/output.js';
import { comparePins, parsePinKey } from '../mcpaudit/pins.js';
import { isListed, probeServer } from '../mcpaudit/probe.js';
import { escapeInvisible } from '../mcpaudit/rules.js';
import { planTargets, qualifiedName, serverNameOfPinKey, serverPinKey } from '../mcpaudit/select.js';
import { InvalidProjectPathError, resolveProjectPath } from '../platform/projectPath.js';
import { resolveVersion } from '../platform/version.js';
import { computeCoverage } from './scanCoverage.js';
import { registerToolModule } from './index.js';
const DEFAULT_TIMEOUT_MS = 20_000;
/** The whole audit's budget, unless `GUARDIAN_MCP_AUDIT_BUDGET_MS` sets another. */
const DEFAULT_AUDIT_BUDGET_MS = 10 * 60 * 1000;
function auditBudgetMs() {
    const raw = Number(process.env['GUARDIAN_MCP_AUDIT_BUDGET_MS']);
    return Number.isFinite(raw) && raw > 0 ? raw : DEFAULT_AUDIT_BUDGET_MS;
}
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
        .describe('REQUIRED. The MCP servers to start and audit: an entry name as it appears in the config ' +
        '(e.g. ["github"]), or `<source>::<name>` (e.g. ".mcp.json::github") to pick one entry when ' +
        'several share a name. No wildcard and no default: only these are executed.'),
    include_user_config: z
        .boolean()
        .optional()
        .default(false)
        .describe('Also look the names up in the user-level configs (Claude Code, Claude Desktop, Cursor, Windsurf, ' +
        'Gemini). Off by default.'),
    allow_remote: z
        .boolean()
        .optional()
        .default(false)
        .describe('Contact servers that reach another machine: a url entry (even at localhost), a command on a network ' +
        'path, a URL in the command line or an env value (mcp-remote and other proxies, a database URL), ' +
        'ssh, sshpass, plink, kubectl or oc anywhere in the command line, docker/podman/nerdctl told to use ' +
        'another engine. A URL whose host is exactly localhost, 127.x.x.x or [::1] is local, unless it ' +
        'carries a backslash, more than one @, or a query on a non-HTTP scheme; a local tunnel (ssh -L, a proxy) is ' +
        'not seen. Off by default: they are skipped.'),
    timeout_ms: z
        .number()
        .int()
        .min(1000)
        .max(300_000)
        .optional()
        .default(DEFAULT_TIMEOUT_MS)
        .describe('Per-server budget for starting, initialize and every list call. A server that does not answer in time fails.'),
};
const tool = {
    name: 'audit_mcp_tools',
    title: 'Audit the tool definitions MCP servers actually serve (poisoning, shadowing, rug pulls)',
    // Worded so this description does not trip the checks it lists: measured,
    // a literal tag block or file name here was a finding on dev-guardian itself.
    description: 'Start the MCP servers named in `servers` (a name, or `<source>::<name>` when several entries share ' +
        'it), list the tools, prompts, resources and templates each serves, and check them: instructions aimed ' +
        'at the model, hidden Unicode and look-alike letters, instructions to read secrets or agent config, to ' +
        'hide actions from the user, to send data out (a URL, an address, an image, a parameter), cross-server ' +
        'shadowing, base64 blobs, oversized descriptions. Pins every definition and the server instructions: ' +
        'a tool or the instructions changed since the previous audit is a high "rug pull", reported once. ' +
        'THIS EXECUTES THIRD-PARTY CODE: it runs the named servers\' commands as the host would, ONLY for ' +
        'the names the caller lists (no wildcard, no default), with a minimal environment plus the entry\'s ' +
        'own env, cwd = the project; it never calls tools/call; it contacts remote servers (a url; a ' +
        'network-path command; a non-loopback URL in the command line or env; ssh or kubectl; a remote ' +
        'docker/podman engine) only with allow_remote; it kills the process tree ' +
        'after. Run it only for servers the user asked to audit. A server can recognise this audit: a clean ' +
        'result covers only what it chose to show this client. A name not declared or ambiguous, a remote ' +
        'server without allow_remote, a server that fails or does not answer within timeout_ms, or a listing ' +
        'a budget cut short is skipped/failed/partial with a reason and lowers coverage, never a clean pass.',
    inputSchema,
    handler: (input, ctx, callMeta) => handler(input, ctx, callMeta),
};
registerToolModule(tool);
async function handler(input, ctx, callMeta) {
    const inp = input;
    // The schema already requires this; checked again because nothing may be
    // started on an input that bypassed it.
    const names = Array.isArray(inp.servers)
        ? [...new Set(inp.servers.filter((s) => typeof s === 'string' && s !== ''))]
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
    const allowRemote = inp.allow_remote === true;
    const timeoutMs = typeof inp.timeout_ms === 'number' ? inp.timeout_ms : DEFAULT_TIMEOUT_MS;
    // Only THIS project's entries of Claude Code's global config: a server is
    // started with this project as its working directory.
    const collected = collectMcpEntries(readConfigSources(projectPath, includeUserConfig), { onlyProject: projectPath });
    const scanId = randomUUID();
    ctx.storage.scans.insert({ scan_id: scanId, scan_type: 'mcp_tool_audit', project_path: projectPath, tree_hash: '' });
    const run = { scanId, projectPath, names, includeUserConfig, allowRemote, timeoutMs, collected };
    try {
        return await runAudit(ctx, run, callMeta);
    }
    catch (e) {
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
/** Every string a report carries, made visible: server text never rides out raw (fix round 4). */
function visibleList(values) {
    return values.map(escapeInvisible);
}
/**
 * A report list as it is returned: visible, and bounded — at most
 * {@link MAX_LIST_ENTRIES} entries, each cut (fix round 5, I-3). A server of
 * 1000 tools with 64 KiB names was a pin list of megabytes.
 */
function reportList(values, entryBytes = MAX_LIST_ENTRY_BYTES) {
    return capList(visibleList(values), MAX_LIST_ENTRIES, entryBytes);
}
/** One reason or name of a report: visible, and cut. */
function reportText(value, maxBytes = MAX_REPORT_STRING_BYTES) {
    return capText(escapeInvisible(value), maxBytes);
}
async function runAudit(ctx, run, callMeta) {
    const { scanId, projectPath, names, includeUserConfig, allowRemote, timeoutMs, collected } = run;
    const toolsRun = [];
    const missingTools = [];
    const reports = [];
    const audited = [];
    const findings = [];
    const clientVersion = resolveVersion();
    const budgetMs = auditBudgetMs();
    const auditDeadline = Date.now() + budgetMs;
    const signal = callMeta?.signal;
    /** Cancel and the overall budget stop the analysis too, between items. */
    const shouldStop = () => {
        if (signal?.aborted === true)
            return 'cancelled';
        if (Date.now() > auditDeadline)
            return `the audit's overall budget of ${budgetMs} ms ran out`;
        return null;
    };
    // A config that exists and was not read may declare any of the names: the
    // audit did not see it, so it is a failed pass, never "no servers there".
    for (const u of collected.sourcesUnreadable) {
        const runName = `${MCP_AUDIT_TOOL_NAME}:${escapeInvisible(u.source)}`;
        toolsRun.push({ name: runName, status: 'failed', reason: escapeInvisible(`config not read: ${u.reason}`) });
        missingTools.push(runName);
    }
    const unreadableNote = collected.sourcesUnreadable.length === 0
        ? ''
        : `; these config sources exist and could not be read: ${collected.sourcesUnreadable
            .map((u) => `${u.source} (${u.reason})`)
            .join(', ')}`;
    const notRun = (name, status, reason, extra = {}) => {
        const runName = `${MCP_AUDIT_TOOL_NAME}:${extra.server_key ?? escapeInvisible(name)}`;
        const shown = reportText(reason);
        toolsRun.push({ name: runName, status, reason: shown });
        missingTools.push(runName);
        reports.push({
            name: reportText(name, MAX_LIST_ENTRY_BYTES),
            ...extra,
            status,
            reason: shown,
            tools_count: 0,
            prompts_count: 0,
            resources_count: 0,
        });
    };
    for (const target of planTargets(names, collected.entries)) {
        const name = target.requested;
        if (target.kind === 'missing') {
            notRun(name, 'skipped', `not declared in any config source read (${collected.sourcesRead.join(', ') || 'none found'})` +
                unreadableNote +
                (includeUserConfig ? '' : '; user-level configs were not read (include_user_config)'));
            continue;
        }
        if (target.kind === 'refuse') {
            notRun(name, 'skipped', target.reason);
            continue;
        }
        if (target.kind === 'duplicate') {
            reports.push({
                name: reportText(name, MAX_LIST_ENTRY_BYTES),
                status: 'skipped',
                reason: reportText(`the same server as '${target.of}', audited once`),
                tools_count: 0,
                prompts_count: 0,
                resources_count: 0,
            });
            continue;
        }
        const entry = target.entry;
        const qualified = escapeInvisible(qualifiedName(entry));
        const base = {
            server_key: qualified,
            source: escapeInvisible(entry.sourceLabel),
            ...(target.alsoDeclaredIn.length > 0 ? { also_declared_in: reportList(target.alsoDeclaredIn) } : {}),
        };
        if (signal?.aborted === true) {
            notRun(name, 'skipped', 'cancelled before it was started', base);
            continue;
        }
        const left = auditDeadline - Date.now();
        if (left <= 0) {
            notRun(name, 'skipped', `the audit's overall budget of ${budgetMs} ms was used up before this server`, base);
            continue;
        }
        const outcome = await probeServer(entry, {
            projectPath,
            timeoutMs: Math.min(timeoutMs, left),
            allowRemote,
            clientVersion,
            ...(signal === undefined ? {} : { signal }),
        });
        const withTransport = {
            ...base,
            ...(outcome.transport === undefined ? {} : { transport: outcome.transport }),
            ...(outcome.warnings.length > 0 ? { warnings: reportList(outcome.warnings, MAX_REPORT_STRING_BYTES) } : {}),
        };
        if (!isListed(outcome)) {
            notRun(name, outcome.status, outcome.reason, withTransport);
            continue;
        }
        // From here the listing lives only until the end of this iteration:
        // pinned, analysed, then dropped before the next server is started.
        const normalized = normalizeListing(outcome.listing);
        const listing = {
            serverKey: serverPinKey(entry),
            serverName: entry.name,
            sourceLabel: entry.sourceLabel,
            ...(outcome.instructions === undefined ? {} : { instructions: outcome.instructions }),
            tools: normalized.tools,
            prompts: normalized.prompts,
            resources: normalized.resources,
            resourceTemplates: normalized.resourceTemplates,
        };
        const partialReasons = outcome.status === 'partial' ? [outcome.reason ?? 'the listing was cut short'] : [];
        const complete = partialReasons.length === 0;
        // One server's failure never costs another its results (fix round 5,
        // I-1): whatever this server's listing makes the comparison or the
        // analysis throw, the server is partial with the reason, its pins are
        // left as they were, and the audit carries on.
        const serverFindings = [];
        let comparison = null;
        let analysis = null;
        try {
            // Pins hash the FULL content — linear, iterative and cheap — so a
            // change past any analysis bound is still caught.
            comparison = comparePins(listing, ctx.storage.mcpToolPins.getServerPins(projectPath, listing.serverKey), ctx.storage.mcpToolPins.hasServer(projectPath, listing.serverKey), { complete });
            serverFindings.push(...comparison.findings);
            analysis = await analyzeServerListingAsync(listing, [], { shouldStop });
            serverFindings.push(...analysis.findings);
            // Listed in full, analysed in part: partial, with what was not read.
            if (analysis.cuts.length > 0)
                partialReasons.push(`analysis cut: ${analysis.cuts.slice(0, 3).join('; ')}`);
        }
        catch (e) {
            const message = e instanceof Error ? e.message : String(e);
            partialReasons.push(`this server's listing could not be fully processed (${message.slice(0, 200)}); its pins were left as they were`);
        }
        const reason = partialReasons.length === 0 ? undefined : reportText(partialReasons.join('; '));
        const warnings = reportList([...(withTransport.warnings ?? []), ...(comparison?.warnings ?? [])], MAX_REPORT_STRING_BYTES);
        const report = {
            name: reportText(name, MAX_LIST_ENTRY_BYTES),
            ...withTransport,
            ...(warnings.length > 0 ? { warnings } : {}),
            status: reason === undefined ? 'ok' : 'partial',
            ...(reason === undefined ? {} : { reason }),
            ...(outcome.serverInfo === undefined
                ? {}
                : {
                    server_info: {
                        name: reportText(outcome.serverInfo.name, MAX_LIST_ENTRY_BYTES),
                        version: reportText(outcome.serverInfo.version, MAX_LIST_ENTRY_BYTES),
                    },
                }),
            tools_count: normalized.tools.length,
            prompts_count: normalized.prompts.length,
            resources_count: normalized.resources.length,
            resource_templates_count: normalized.resourceTemplates.length,
            ...(normalized.malformed > 0 ? { malformed_definitions: normalized.malformed } : {}),
            ...(comparison === null
                ? {}
                : {
                    pins: {
                        first_audit: comparison.firstAudit,
                        changed: reportList(comparison.changed),
                        added: reportList(comparison.added),
                        removed: reportList(comparison.removed),
                    },
                }),
        };
        const runName = `${MCP_AUDIT_TOOL_NAME}:${qualified}`;
        if (reason === undefined) {
            toolsRun.push({ name: runName, status: 'ok' });
        }
        else {
            // Ran, and saw part of it: ok AND missing, the partial shape.
            toolsRun.push({ name: runName, status: 'ok', reason: `partial: ${reason}` });
            missingTools.push(runName);
        }
        reports.push(report);
        audited.push({
            report,
            target: {
                serverKey: listing.serverKey,
                serverName: listing.serverName,
                sourceLabel: listing.sourceLabel,
                ownToolNames: new Set(listing.tools.map((t) => t.name)),
            },
            mentions: analysis?.mentions ?? { bare: new Map(), quoted: new Map(), full: false, reported: new Set() },
            toolNames: listing.tools.map((t) => t.name),
            // Pins are written only for a server fully compared AND analysed.
            pins: comparison !== null && analysis !== null ? comparison.pins : null,
            complete,
            findings: serverFindings,
        });
    }
    // Cross-server shadowing, once every server of this audit is known: each
    // server's mentioned names against every other server listed now, and what
    // earlier audits pinned for servers not listed this time.
    const others = audited.map((a) => ({
        serverKey: a.target.serverKey,
        serverName: a.target.serverName,
        toolNames: a.toolNames,
    }));
    const auditedKeys = new Set(others.map((o) => o.serverKey));
    const pinned = new Map();
    for (const row of ctx.storage.mcpToolPins.listPinKeys(projectPath)) {
        if (auditedKeys.has(row.server_key))
            continue;
        const item = parsePinKey(row.key);
        if (item.kind !== 'tool')
            continue;
        const list = pinned.get(row.server_key) ?? [];
        list.push(item.id);
        pinned.set(row.server_key, list);
    }
    for (const [serverKey, toolNames] of pinned) {
        others.push({ serverKey, serverName: serverNameOfPinKey(serverKey), toolNames });
    }
    for (const a of audited)
        a.findings.push(...shadowingFromMentions(a.target, a.mentions, others));
    // Bounded before it is stored or returned (fix round 5, I-3): 50 per
    // server and 500 in all, each cap summarised in one finding.
    findings.push(...capFindings(audited.map((a) => ({
        label: `MCP server '${a.report.server_key ?? a.report.name}'`,
        sourceLabel: a.target.sourceLabel,
        findings: a.findings,
    }))));
    if (findings.length > 0) {
        ctx.storage.findings.bulkInsert(findings.map((f) => ({ ...f, scan_id: scanId })));
    }
    for (const a of audited) {
        if (a.pins === null)
            continue;
        if (a.complete)
            ctx.storage.mcpToolPins.replaceServerPins(projectPath, a.target.serverKey, a.pins);
        else
            ctx.storage.mcpToolPins.upsertServerPins(projectPath, a.target.serverKey, a.pins);
    }
    const warnings = reportList(collected.warnings, MAX_REPORT_STRING_BYTES);
    const sourcesRead = visibleList(collected.sourcesRead);
    const sourcesUnreadable = collected.sourcesUnreadable.map((u) => ({
        source: escapeInvisible(u.source),
        reason: escapeInvisible(u.reason),
    }));
    const coverage = computeCoverage(toolsRun, missingTools);
    ctx.storage.scans.finalize({
        scan_id: scanId,
        status: 'completed',
        tools_run: toolsRun,
        missing_tools: missingTools,
        meta: {
            servers_requested: visibleList(names),
            include_user_config: includeUserConfig,
            allow_remote: allowRemote,
            timeout_ms: timeoutMs,
            servers: reports,
            sources_read: sourcesRead,
            sources_unreadable: sourcesUnreadable,
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
        sources_read: sourcesRead,
        sources_unreadable: sourcesUnreadable,
        warnings,
    };
}
function countBySeverity(findings) {
    const out = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
    for (const f of findings)
        out[f.severity] += 1;
    return out;
}
//# sourceMappingURL=auditMcpTools.js.map