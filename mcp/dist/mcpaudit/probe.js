/**
 * Starting ONE declared MCP server and asking it what it serves.
 *
 * `initialize`, then `tools/list`, `prompts/list`, `resources/list` and
 * `resources/templates/list` —
 * each only where the server advertised the capability, each followed
 * through every `nextCursor` page. Nothing else is ever sent: no
 * `tools/call`, no `prompts/get`, no `resources/read`. The client declares no
 * capabilities (no sampling, roots or elicitation), so a server's own
 * requests back are refused by the SDK rather than served.
 *
 * A stdio server runs through `stdioTransport.ts` (minimal environment,
 * process-tree kill). A remote one (`url`, type `http`/`sse`) is contacted
 * only when the caller passed `allowRemote`; otherwise it is `skipped`.
 * Every exit path closes the session, which for stdio kills the tree.
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
import { ProbeStdioTransport } from './stdioTransport.js';
/** The label under which a plugin's `plugin.json` is read (`agentaudit/configSources.ts`). */
const PLUGIN_JSON_LABEL = '.claude-plugin/plugin.json';
const PLACEHOLDER = /\$\{[^}]*\}/g;
/** A server that pages past this is not listing tools. */
const MAX_PAGES = 100;
const MAX_ITEMS = 10_000;
/** `type` values that mean "remote, Streamable HTTP" across hosts. */
const HTTP_TYPES = new Set(['http', 'streamable-http', 'streamablehttp', 'streamable_http']);
export async function probeServer(entry, opts) {
    const warnings = [];
    const expand = placeholderExpander(entry, opts.projectPath, warnings);
    const type = entry.type?.toLowerCase();
    let transport;
    let kind;
    let stdio = null;
    if (entry.command !== undefined && type !== 'sse' && (type === undefined || !HTTP_TYPES.has(type))) {
        kind = 'stdio';
        const launch = {
            command: expand(entry.command),
            args: (entry.args ?? []).map(expand),
            env: stringEnv(entry.env, expand, warnings),
            cwd: opts.projectPath,
        };
        stdio = new ProbeStdioTransport(launch);
        transport = stdio;
    }
    else if (entry.url !== undefined) {
        kind = type === 'sse' ? 'sse' : 'http';
        let url;
        try {
            url = new URL(expand(entry.url));
        }
        catch {
            return { status: 'failed', transport: kind, reason: 'the entry\'s url is not a valid URL', warnings };
        }
        if (!opts.allowRemote) {
            return {
                status: 'skipped',
                transport: kind,
                reason: `remote server at ${url.origin}: audit_mcp_tools contacts a remote MCP server only with ` +
                    'allow_remote: true',
                warnings,
            };
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
    const deadline = AbortSignal.timeout(opts.timeoutMs);
    const signal = opts.signal === undefined ? deadline : AbortSignal.any([deadline, opts.signal]);
    const requestOptions = () => {
        return { signal, timeout: opts.timeoutMs, maxTotalTimeout: opts.timeoutMs };
    };
    const client = new Client({ name: 'dev-guardian-audit', version: opts.clientVersion }, { capabilities: {} });
    // A protocol-level complaint (a stdout banner that is not JSON-RPC) is not
    // fatal; the request that needed an answer fails on its own if one is.
    client.onerror = () => { };
    let phase = 'start';
    try {
        phase = 'initialize';
        await client.connect(transport, requestOptions());
        const caps = client.getServerCapabilities() ?? {};
        const advertised = {
            tools: caps.tools !== undefined,
            prompts: caps.prompts !== undefined,
            resources: caps.resources !== undefined,
        };
        const listing = { tools: [], prompts: [], resources: [], resourceTemplates: [] };
        if (advertised.tools) {
            phase = 'tools/list';
            listing.tools = await listAll('tools', (cursor) => client.request({ method: 'tools/list', params: cursor === undefined ? {} : { cursor } }, PAGE, requestOptions()));
        }
        if (advertised.prompts) {
            phase = 'prompts/list';
            listing.prompts = await listAll('prompts', (cursor) => client.request({ method: 'prompts/list', params: cursor === undefined ? {} : { cursor } }, PAGE, requestOptions()));
        }
        if (advertised.resources) {
            phase = 'resources/list';
            listing.resources = await listAll('resources', (cursor) => client.request({ method: 'resources/list', params: cursor === undefined ? {} : { cursor } }, PAGE, requestOptions()));
            // Templates carry descriptions the model reads too. Many servers that
            // serve resources do not implement this method: that is no failure.
            phase = 'resources/templates/list';
            try {
                listing.resourceTemplates = await listAll('resourceTemplates', (cursor) => client.request({ method: 'resources/templates/list', params: cursor === undefined ? {} : { cursor } }, PAGE, requestOptions()));
            }
            catch (e) {
                if (signal.aborted || (stdio?.exit ?? null) !== null)
                    throw e;
                if (!(e instanceof McpError && e.code === ErrorCode.MethodNotFound)) {
                    warnings.push(`resources/templates/list failed, templates were not read: ${String(e.message).slice(0, 200)}`);
                }
            }
        }
        if (!advertised.tools)
            warnings.push('the server does not advertise tools; tools/list was not called');
        const info = client.getServerVersion();
        const instructions = client.getInstructions();
        return {
            status: 'ok',
            transport: kind,
            ...(info === undefined ? {} : { serverInfo: { name: info.name, version: info.version } }),
            ...(instructions === undefined ? {} : { instructions }),
            advertised,
            listing,
            warnings,
        };
    }
    catch (e) {
        // Let the process finish dying so its exit and stderr are known.
        await stdio?.close();
        return { status: 'failed', transport: kind, reason: failureReason(e, phase, opts, stdio, deadline), warnings };
    }
    finally {
        await client.close().catch(() => { });
        await transport.close().catch(() => { });
    }
}
/** Every item of a paged list, following `nextCursor` until it stops. */
async function listAll(key, page) {
    const out = [];
    const seen = new Set();
    let cursor;
    for (let i = 0; i < MAX_PAGES; i += 1) {
        const result = await page(cursor);
        const items = result[key];
        if (!Array.isArray(items))
            throw new Error(`${key}/list answered without a '${key}' array`);
        out.push(...items);
        if (out.length > MAX_ITEMS)
            throw new Error(`${key}/list returned more than ${MAX_ITEMS} items`);
        const next = result.nextCursor;
        if (typeof next !== 'string' || next === '')
            return out;
        if (seen.has(next))
            throw new Error(`${key}/list repeated cursor ${JSON.stringify(next.slice(0, 40))}`);
        seen.add(next);
        cursor = next;
    }
    throw new Error(`${key}/list did not finish within ${MAX_PAGES} pages`);
}
/** Any object: the three list keys and `nextCursor` are checked by hand. */
const PAGE = z.object({}).passthrough();
function failureReason(e, phase, opts, stdio, deadline) {
    const exit = stdio?.exit ?? null;
    const stderr = stdio?.stderrTail.trim() ?? '';
    const withStderr = (s) => (stderr === '' ? s : `${s}; stderr: ${stderr.slice(-600)}`);
    if (exit?.spawnError !== undefined)
        return withStderr(`could not start the server: ${exit.spawnError}`);
    if (deadline.aborted)
        return withStderr(`did not answer within ${opts.timeoutMs} ms (during ${phase})`);
    if (opts.signal?.aborted === true)
        return `cancelled during ${phase}`;
    if (exit !== null) {
        const how = exit.signal !== null ? `was killed by ${exit.signal}` : `exited with code ${exit.exitCode ?? '?'}`;
        return withStderr(`the server ${how} during ${phase}`);
    }
    const message = e instanceof Error ? e.message : String(e);
    return withStderr(`${phase} failed: ${message.slice(0, 400)}`);
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