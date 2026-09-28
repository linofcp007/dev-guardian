/**
 * Orchestrates the agent-workspace audit: runs every rule check across every
 * config source that was read, and compares each MCP server entry's hash
 * against the previous audit's.
 *
 * Pure function over its inputs (`ConfigSource[]` + the previous hash map) —
 * no I/O. `tools/auditAgentConfig.ts` does the reading and persistence.
 */
import { makeFinding } from '../runners/scannerParsers/index.js';
import { hashConfigValue } from './hash.js';
import { extractMcpServers } from './mcpServers.js';
import { checkBypassPermissions, checkEnableAllProjectMcpServers, checkHookRisks, checkInlineSecrets, checkPlainHttpRemotes, checkUnexpandedVars, checkUnpinnedLaunchers, checkWildcardPermissions, } from './rules.js';
function entryKey(entry) {
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
function expandNestedProjectSources(source) {
    if (source.label !== '~/.claude.json' || !source.exists || source.json === undefined)
        return [];
    const root = source.json;
    if (root === null || typeof root !== 'object' || Array.isArray(root))
        return [];
    const projects = root['projects'];
    if (projects === null || typeof projects !== 'object' || Array.isArray(projects))
        return [];
    const out = [];
    for (const [projectKey, value] of Object.entries(projects)) {
        if (value === null || typeof value !== 'object' || Array.isArray(value))
            continue;
        const mcpServers = value['mcpServers'];
        if (mcpServers === null || typeof mcpServers !== 'object' || Array.isArray(mcpServers))
            continue;
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
/**
 * Every MCP server entry the read sources declare — shared by
 * `audit_agent_config` (static checks) and `audit_mcp_tools` (which starts
 * only the entries the caller names). A source that exists and could not be
 * read or parsed is a named warning and an entry of `sourcesUnreadable`, and so is an `mcpServers` given as a path to another file (a
 * plugin's `plugin.json` may do that): nothing here follows it, and saying
 * nothing would read as "no servers there".
 */
export function collectMcpEntries(sources) {
    const warnings = [];
    const sourcesRead = [];
    const sourcesMissing = [];
    const sourcesUnreadable = [];
    const allSources = [];
    for (const source of sources) {
        if (source.parseError !== undefined) {
            warnings.push(`${source.label}: ${source.parseError}`);
            sourcesUnreadable.push({ source: source.label, reason: source.parseError });
            continue;
        }
        if (!source.exists) {
            sourcesMissing.push(source.label);
            continue;
        }
        sourcesRead.push(source.label);
        allSources.push(source);
        allSources.push(...expandNestedProjectSources(source));
        const pathForm = mcpServersPath(source);
        if (pathForm !== null) {
            warnings.push(`${source.label}: ${source.mcpServersField ?? 'mcpServers'} is a path ("${pathForm}"), not an inline ` +
                'object; the servers declared in that file were not read from here');
        }
    }
    const entries = [];
    for (const source of allSources)
        entries.push(...extractMcpServers(source));
    return { sources: allSources, entries, warnings, sourcesRead, sourcesMissing, sourcesUnreadable };
}
/** The `mcpServers` value when it is a string (a path to another file), else null. */
function mcpServersPath(source) {
    if (source.mcpServersField === null)
        return null;
    const root = source.json;
    if (root === null || typeof root !== 'object' || Array.isArray(root))
        return null;
    const value = root[source.mcpServersField];
    return typeof value === 'string' ? value : null;
}
export function analyzeAgentConfig(sources, previousHashes) {
    const collected = collectMcpEntries(sources);
    const { warnings, sourcesRead, sourcesMissing, sourcesUnreadable, entries } = collected;
    const findings = [];
    for (const source of collected.sources) {
        findings.push(...checkWildcardPermissions(source));
        findings.push(...checkBypassPermissions(source));
        findings.push(...checkEnableAllProjectMcpServers(source));
        findings.push(...checkHookRisks(source));
        findings.push(...checkUnexpandedVars(source));
    }
    findings.push(...checkUnpinnedLaunchers(entries));
    findings.push(...checkPlainHttpRemotes(entries));
    findings.push(...checkInlineSecrets(entries));
    const entryHashes = [];
    let entriesChanged = 0;
    for (const entry of entries) {
        const key = entryKey(entry);
        const hash = hashConfigValue(entry.raw);
        entryHashes.push({ entry_key: key, hash });
        const previous = previousHashes.get(key);
        if (previous !== undefined && previous !== hash) {
            entriesChanged += 1;
            findings.push(makeFinding({
                tool: 'agent-audit',
                rule_id: 'agent-audit-entry-changed',
                severity: 'low',
                category: 'security',
                title: `MCP server '${entry.name}' changed since the previous audit`,
                message: `'${entry.name}' in ${entry.sourceLabel} does not match what the previous audit_agent_config ` +
                    `run recorded for it. Confirm the change was intentional.`,
                file_path: entry.sourceLabel,
                fix_available: false,
            }));
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
        sourcesUnreadable,
    };
}
//# sourceMappingURL=analyze.js.map