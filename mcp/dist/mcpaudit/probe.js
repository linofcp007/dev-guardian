/**
 * Starting ONE declared MCP server and asking it what it serves.
 *
 * `initialize`, then `tools/list`, `prompts/list`, `resources/list` and
 * `resources/templates/list` — each only where the server advertised the
 * capability, each followed through its `nextCursor` pages. Nothing else is
 * ever sent: no `tools/call`, no `prompts/get`, no `resources/read`. The
 * client declares no capabilities (no sampling, roots or elicitation), so a
 * server's own requests back are refused by the SDK rather than served. The
 * client names itself honestly (`dev-guardian-audit`): a server can tell it
 * is being audited, and a clean result covers only what it chose to show
 * this client — SECURITY.md and the tool description say so.
 *
 * Before anything is built:
 *
 *   - a cancelled call starts nothing;
 *   - an entry that reaches another machine (`launch.ts#remoteReasonOf`: a
 *     URL, a UNC command, a URL or UNC path on the command line) is
 *     `skipped` unless the caller passed `allowRemote`;
 *   - a stdio command is resolved without synchronous file-system or network
 *     access (`launch.ts#resolveCommand`).
 *
 * A stdio server runs through `stdioTransport.ts` (minimal environment,
 * inbound budget, the deadline checked on every chunk, process-tree kill).
 * Every exit path closes the session, which for stdio kills the tree.
 *
 * ## Budgets, and what is reported when one is reached
 *
 * At most {@link MAX_ITEMS} items per list and {@link MAX_PAGES} pages; a
 * repeated cursor ends a list. Reaching any of those, or a transport budget
 * or failure AFTER some listing was received, is `partial` — what was
 * received is analysed, and the reason names what stopped it. The same
 * failure before any listing arrived is `failed`. Neither is a pass.
 *
 * The listing is read with a permissive schema, not the SDK's: definitions
 * that do not validate are what this audit is for, and a strict parse would
 * throw the whole listing away (`analyze.ts#normalizeListing` reads it).
 */
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { ErrorCode, McpError } from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';
import { remoteReasonOf, resolveCommand } from './launch.js';
import { DEFAULT_INBOUND_LIMITS, ProbeStdioTransport, probeEnvironment } from './stdioTransport.js';
export function isListed(o) {
    return o.status === 'ok' || o.status === 'partial';
}
/** A function, not an inline check: TypeScript would narrow `aborted` across an await. */
function isAborted(signal) {
    return signal?.aborted === true;
}
/** The label under which a plugin's `plugin.json` is read (`agentaudit/configSources.ts`). */
const PLUGIN_JSON_LABEL = '.claude-plugin/plugin.json';
const PLACEHOLDER = /\$\{[^}]*\}/g;
/** Per list. A server past these is not listing an interface; the rest is not read. */
export const MAX_PAGES = 100;
export const MAX_ITEMS = 1000;
const LIST_METHOD = {
    tools: 'tools/list',
    prompts: 'prompts/list',
    resources: 'resources/list',
    resourceTemplates: 'resources/templates/list',
};
export async function probeServer(entry, opts) {
    const warnings = [];
    const deadlineAt = Date.now() + opts.timeoutMs;
    const deadline = AbortSignal.timeout(opts.timeoutMs);
    const signal = opts.signal === undefined ? deadline : AbortSignal.any([deadline, opts.signal]);
    if (isAborted(opts.signal))
        return { status: 'skipped', reason: 'cancelled before it was started', warnings };
    const remote = remoteReasonOf(entry);
    if (remote !== null && !opts.allowRemote) {
        return {
            status: 'skipped',
            reason: `${remote}: audit_mcp_tools contacts a remote MCP server only with allow_remote: true`,
            warnings,
        };
    }
    const expand = placeholderExpander(entry, opts.projectPath, warnings);
    let transport;
    let kind;
    let stdio = null;
    if (entry.command !== undefined) {
        kind = 'stdio';
        const env = stringEnv(entry.env, expand, warnings);
        const resolved = await resolveCommand(expand(entry.command), probeEnvironment(env, null), opts.projectPath, deadlineAt);
        if (!resolved.ok)
            return { status: 'failed', transport: kind, reason: resolved.reason, warnings };
        if (isAborted(opts.signal))
            return { status: 'skipped', reason: 'cancelled before it was started', warnings };
        const launch = {
            command: resolved.command,
            args: (entry.args ?? []).map(expand),
            env,
            cwd: opts.projectPath,
        };
        stdio = new ProbeStdioTransport(launch, { ...DEFAULT_INBOUND_LIMITS, deadline: deadlineAt });
        transport = stdio;
    }
    else if (entry.url !== undefined) {
        kind = entry.remoteTransport ?? 'http';
        let url;
        try {
            url = new URL(expand(entry.url));
        }
        catch {
            return { status: 'failed', transport: kind, reason: "the entry's url is not a valid URL", warnings };
        }
        const requestInit = { headers: stringHeaders(entry.raw['headers'], expand) };
        transport =
            kind === 'sse'
                ? new SSEClientTransport(url, { requestInit })
                : new StreamableHTTPClientTransport(url, { requestInit });
    }
    else {
        return { status: 'failed', reason: 'the entry has neither a command nor a url', warnings };
    }
    const requestOptions = () => {
        const left = Math.max(1, deadlineAt - Date.now());
        return { signal, timeout: left, maxTotalTimeout: left };
    };
    const client = new Client({ name: 'dev-guardian-audit', version: opts.clientVersion }, { capabilities: {} });
    // A protocol-level complaint (a stdout banner that is not JSON-RPC) is not
    // fatal; the request that needed an answer fails on its own if one is.
    client.onerror = () => { };
    const listing = { tools: [], prompts: [], resources: [], resourceTemplates: [] };
    const stops = [];
    let received = false;
    let advertised = { tools: false, prompts: false, resources: false };
    let phase = 'start';
    const list = async (key) => {
        phase = LIST_METHOD[key];
        const method = LIST_METHOD[key];
        const result = await listAll(key, (cursor) => {
            const params = cursor === undefined ? {} : { cursor };
            return client.request({ method, params }, PAGE, requestOptions()).then((page) => {
                received = true;
                return page;
            });
        }, listing[key]);
        if (result !== null)
            stops.push(result);
    };
    try {
        phase = 'initialize';
        await client.connect(transport, requestOptions());
        const caps = client.getServerCapabilities() ?? {};
        advertised = {
            tools: caps.tools !== undefined,
            prompts: caps.prompts !== undefined,
            resources: caps.resources !== undefined,
        };
        if (advertised.tools)
            await list('tools');
        else
            warnings.push('the server does not advertise tools; tools/list was not called');
        if (advertised.prompts)
            await list('prompts');
        if (advertised.resources) {
            await list('resources');
            // Templates carry descriptions the model reads too. Many servers that
            // serve resources do not implement this method: that is no failure.
            try {
                await list('resourceTemplates');
            }
            catch (e) {
                if (signal.aborted || (stdio?.closeReason ?? null) !== null || (stdio?.exit ?? null) !== null)
                    throw e;
                if (!(e instanceof McpError && e.code === ErrorCode.MethodNotFound)) {
                    warnings.push(`resources/templates/list failed, templates were not read: ${messageOf(e).slice(0, 200)}`);
                }
            }
        }
        const info = client.getServerVersion();
        const instructions = client.getInstructions();
        return {
            status: stops.length === 0 ? 'ok' : 'partial',
            ...(stops.length === 0 ? {} : { reason: stops.join('; ') }),
            transport: kind,
            ...(info === undefined ? {} : { serverInfo: { name: info.name, version: info.version } }),
            ...(instructions === undefined ? {} : { instructions }),
            advertised,
            listing,
            warnings,
        };
    }
    catch (e) {
        // The reason is read before the tree is killed: the kill itself would
        // otherwise read as "exited".
        const reason = failureReason(e, phase, opts, stdio, deadline);
        await stdio?.close();
        if (!received)
            return { status: 'failed', transport: kind, reason, warnings };
        const info = client.getServerVersion();
        const instructions = client.getInstructions();
        return {
            status: 'partial',
            reason: [...stops, `the listing stopped: ${reason}`].join('; '),
            transport: kind,
            ...(info === undefined ? {} : { serverInfo: { name: info.name, version: info.version } }),
            ...(instructions === undefined ? {} : { instructions }),
            advertised,
            listing,
            warnings,
        };
    }
    finally {
        await client.close().catch(() => { });
        await transport.close().catch(() => { });
    }
}
/**
 * Every item of a paged list, into `into`, following `nextCursor` — until
 * the list ends (null) or a budget stops it (the reason).
 */
async function listAll(key, page, into) {
    const seen = new Set();
    let cursor;
    const what = LIST_METHOD[key];
    for (let i = 0; i < MAX_PAGES; i += 1) {
        const result = await page(cursor);
        const items = result[key];
        if (!Array.isArray(items))
            throw new Error(`${what} answered without a '${key}' array`);
        for (const item of items) {
            if (into.length >= MAX_ITEMS) {
                return `${what} returned more than ${MAX_ITEMS} items; only the first ${MAX_ITEMS} were read`;
            }
            into.push(item);
        }
        const next = result['nextCursor'];
        if (typeof next !== 'string' || next === '')
            return null;
        if (into.length >= MAX_ITEMS) {
            return `${what} has more than ${MAX_ITEMS} items; only the first ${MAX_ITEMS} were read`;
        }
        if (seen.has(next)) {
            return `${what} repeated cursor ${JSON.stringify(next.slice(0, 40))}; the listing stopped there`;
        }
        seen.add(next);
        cursor = next;
    }
    return `${what} did not end within ${MAX_PAGES} pages; the rest was not read`;
}
/** Any object: the list keys and `nextCursor` are checked by hand. */
const PAGE = z.object({}).passthrough();
function messageOf(e) {
    return e instanceof Error ? e.message : String(e);
}
/** What happened, in the order that explains it best — never the exit of a process this code killed. */
function failureReason(e, phase, opts, stdio, deadline) {
    const exit = stdio?.exit ?? null;
    const stderr = stdio?.stderrTail.trim() ?? '';
    const withStderr = (s) => (stderr === '' ? s : `${s}; stderr: ${stderr.slice(-600)}`);
    if (exit?.spawnError !== undefined)
        return withStderr(`could not start the server: ${exit.spawnError}`);
    const closed = stdio?.closeReason ?? null;
    if (closed !== null)
        return `the server ${closed} (during ${phase})`;
    if (opts.signal?.aborted === true)
        return `cancelled during ${phase}`;
    if (deadline.aborted || (e instanceof McpError && e.code === ErrorCode.RequestTimeout)) {
        return withStderr(`did not answer within ${opts.timeoutMs} ms (during ${phase})`);
    }
    if (exit !== null) {
        const how = exit.signal !== null ? `was killed by ${exit.signal}` : `exited with code ${exit.exitCode ?? '?'}`;
        return withStderr(`the server ${how} during ${phase}`);
    }
    return withStderr(`${phase} failed: ${messageOf(e).slice(0, 400)}`);
}
/**
 * `${CLAUDE_PLUGIN_ROOT}` in a plugin's own `plugin.json` is the plugin's
 * root — the project here — exactly as Claude Code expands it. Every other
 * `${VAR}` is passed through LITERALLY: expanding it would copy this
 * server's own environment (tokens included) into the third-party process,
 * which is what the minimal environment exists to prevent. Each one left
 * unexpanded is named in `warnings`, since a server that needs it may fail.
 */
function placeholderExpander(entry, projectPath, warnings) {
    const seen = new Set();
    return (value) => {
        const expanded = entry.sourceLabel === PLUGIN_JSON_LABEL ? value.replace(/\$\{CLAUDE_PLUGIN_ROOT\}/g, projectPath) : value;
        for (const m of expanded.matchAll(PLACEHOLDER)) {
            if (seen.has(m[0]))
                continue;
            seen.add(m[0]);
            warnings.push(`${m[0]} was passed literally: placeholders are not expanded from dev-guardian's environment`);
        }
        return expanded;
    };
}
function stringEnv(env, expand, warnings) {
    const out = {};
    for (const [k, v] of Object.entries(env ?? {})) {
        if (typeof v === 'string')
            out[k] = expand(v);
        else
            warnings.push(`env ${k} is not a string and was not passed`);
    }
    return out;
}
function stringHeaders(headers, expand) {
    const out = {};
    if (headers === null || typeof headers !== 'object' || Array.isArray(headers))
        return out;
    for (const [k, v] of Object.entries(headers)) {
        if (typeof v === 'string')
            out[k] = expand(v);
    }
    return out;
}
//# sourceMappingURL=probe.js.map