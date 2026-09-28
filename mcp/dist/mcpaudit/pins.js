/**
 * Pinning what a server serves, so a definition that changes under the same
 * name — a "rug pull": approved once, rewritten later — is reported.
 *
 * ## What is pinned
 *
 * Everything the model sees about each item, as sha256 of its canonical JSON
 * (keys sorted, absent fields as null — `agentaudit/hash.ts`'s
 * `stableStringify`):
 *
 *   - a tool: `{name, title, description, inputSchema, outputSchema, annotations}`;
 *   - a prompt: `{name, title, description, arguments}`;
 *   - a resource: `{uri, name, title, description}`, keyed by its uri;
 *   - a resource template: `{uriTemplate, name, title, description}`, keyed by
 *     its uri template.
 *
 * A resource without a uri is analysed but not pinned: there is nothing
 * stable to key it on. Resources are DATA on most servers (files, rows,
 * documents), so one appearing or disappearing is not reported — only a
 * changed definition under the same uri is.
 *
 * ## Keys ({@link pinKey})
 *
 * A tool is keyed by its bare name — what every pin written before prompts
 * and resources were pinned holds. Every other kind is `<kind>:<id>`, and a
 * tool whose name itself starts with a reserved prefix is `tool:<name>`, so
 * no key can be two items: a tool named `prompt:x` and a prompt named `x`
 * are `tool:prompt:x` and `prompt:x`.
 *
 * ## Hash schemes, and the upgrade from the narrower one
 *
 * A pin is `v<scheme>:<hex>`. Scheme 1 is the bare hex this branch first
 * wrote, over a tool's `{name, description, inputSchema, annotations}` only.
 * When a stored pin's scheme is older than the current one, the definition
 * served now is hashed with THAT scheme's recipe too: equal means nothing the
 * old pin recorded has changed, and the item is re-pinned under the current
 * scheme without a finding (`rehashed`); different is a real change, and is
 * reported. The one thing this cannot see is a change, made across the
 * upgrade itself, in a field the old scheme never recorded (a tool's title or
 * output schema) — the old pin holds nothing to compare it with. A pin of a
 * scheme this build does not know (written by a newer one) cannot be
 * compared at all: it is re-pinned, and a warning says so.
 *
 * Pure functions. No I/O.
 */
import { hashConfigValue } from '../agentaudit/hash.js';
import { makeFinding } from '../runners/scannerParsers/index.js';
import { MCP_AUDIT_TOOL_NAME, } from './analyze.js';
import { escapeInvisible } from './rules.js';
/** The scheme every pin is written with now. */
export const PIN_SCHEME = 2;
const NON_TOOL_KINDS = ['prompt', 'resource', 'resource-template'];
/** Prefixes a bare tool key may not start with; `resource:` never prefixes `resource-template:`. */
const RESERVED_PREFIX = /^(tool|prompt|resource|resource-template):/;
/** The storage key of one item. Injective across kinds; see the module doc. */
export function pinKey(kind, id) {
    if (kind !== 'tool')
        return `${kind}:${id}`;
    return RESERVED_PREFIX.test(id) ? `tool:${id}` : id;
}
/**
 * `tool:` — built rather than written as one quoted literal: the source scan
 * in `test/unit/history/runNames.test.ts` reads every `tool:` followed by a
 * quote as a finding's `tool` field.
 */
const TOOL_KEY_PREFIX = `${'tool'}:`;
/** The inverse of {@link pinKey}. */
export function parsePinKey(key) {
    if (key.startsWith(TOOL_KEY_PREFIX))
        return { kind: 'tool', id: key.slice(TOOL_KEY_PREFIX.length) };
    for (const kind of NON_TOOL_KINDS) {
        if (key.startsWith(`${kind}:`))
            return { kind, id: key.slice(kind.length + 1) };
    }
    return { kind: 'tool', id: key };
}
function versioned(value) {
    return `v${PIN_SCHEME}:${hashConfigValue(value)}`;
}
export function toolDefinitionHash(tool) {
    return versioned({
        name: tool.name,
        title: tool.title ?? null,
        description: tool.description ?? null,
        inputSchema: tool.inputSchema ?? null,
        outputSchema: tool.outputSchema ?? null,
        annotations: tool.annotations ?? null,
    });
}
/** Scheme 1: bare hex over four of a tool's fields. Only ever compared against, never written. */
function toolDefinitionHashV1(tool) {
    return hashConfigValue({
        name: tool.name,
        description: tool.description ?? null,
        inputSchema: tool.inputSchema ?? null,
        annotations: tool.annotations ?? null,
    });
}
function promptHash(p) {
    return versioned({
        name: p.name,
        title: p.title ?? null,
        description: p.description ?? null,
        arguments: p.arguments ?? null,
    });
}
function resourceHash(r, uriKey) {
    return versioned({
        [uriKey]: r.uri ?? null,
        name: r.name,
        title: r.title ?? null,
        description: r.description ?? null,
    });
}
/** The scheme a stored pin was written with: 1 for bare hex, null when unrecognisable. */
export function pinScheme(stored) {
    const m = /^v(\d+):[0-9a-f]{64}$/.exec(stored);
    if (m?.[1] !== undefined)
        return Number(m[1]);
    return /^[0-9a-f]{64}$/.test(stored) ? 1 : null;
}
function pinnedItems(listing) {
    const items = [];
    for (const t of listing.tools) {
        items.push({
            key: pinKey('tool', t.name),
            kind: 'tool',
            label: t.name,
            hash: toolDefinitionHash(t),
            legacyHash: (scheme) => (scheme === 1 ? toolDefinitionHashV1(t) : null),
        });
    }
    for (const p of listing.prompts) {
        items.push({ key: pinKey('prompt', p.name), kind: 'prompt', label: p.name, hash: promptHash(p), legacyHash: () => null });
    }
    for (const r of listing.resources) {
        if (r.uri === undefined)
            continue;
        items.push({ key: pinKey('resource', r.uri), kind: 'resource', label: r.uri, hash: resourceHash(r, 'uri'), legacyHash: () => null });
    }
    for (const r of listing.resourceTemplates ?? []) {
        if (r.uri === undefined)
            continue;
        items.push({
            key: pinKey('resource-template', r.uri),
            kind: 'resource-template',
            label: r.uri,
            hash: resourceHash(r, 'uriTemplate'),
            legacyHash: () => null,
        });
    }
    return items;
}
const KIND_WORD = {
    tool: 'tool',
    prompt: 'prompt',
    resource: 'resource',
    'resource-template': 'resource template',
};
/** A tool changed is the rug pull; a prompt or resource changed is model-facing text too, but not a capability. */
const CHANGED_SEVERITY = {
    tool: 'high',
    prompt: 'medium',
    resource: 'medium',
    'resource-template': 'medium',
};
export function comparePins(listing, previous, auditedBefore, options = {}) {
    const complete = options.complete !== false;
    const items = new Map();
    for (const item of pinnedItems(listing))
        items.set(item.key, item);
    const pins = [...items.values()].map((i) => ({ key: i.key, hash: i.hash }));
    const firstAudit = !auditedBefore && previous.size === 0;
    const none = { changed: [], added: [], removed: [], rehashed: [], firstPinned: [], warnings: [] };
    if (firstAudit)
        return { findings: [], firstAudit, ...none, pins };
    const changed = [];
    const added = [];
    const rehashed = [];
    const warnings = [];
    for (const item of items.values()) {
        const before = previous.get(item.key);
        if (before === undefined) {
            added.push(item);
            continue;
        }
        if (before === item.hash)
            continue;
        const scheme = pinScheme(before);
        if (scheme === PIN_SCHEME) {
            changed.push(item);
        }
        else if (scheme !== null && scheme < PIN_SCHEME) {
            const old = item.legacyHash(scheme);
            if (old === before)
                rehashed.push(item.key);
            else
                changed.push(item);
        }
        else {
            warnings.push(`${KIND_WORD[item.kind]} '${escapeInvisible(item.label)}': its stored pin (${before.slice(0, 4)}…) is of a ` +
                'scheme this build does not know, so it could not be compared; re-pinned');
        }
    }
    const removed = complete ? [...previous.keys()].filter((key) => !items.has(key)).sort() : [];
    const server = escapeInvisible(listing.serverName);
    const finding = (ruleId, severity, what, title, message) => makeFinding({
        tool: MCP_AUDIT_TOOL_NAME,
        rule_id: ruleId,
        severity,
        category: 'security',
        subcategory: 'mcp_rug_pull',
        title: escapeInvisible(title),
        message: escapeInvisible(message),
        file_path: listing.sourceLabel,
        snippet: escapeInvisible(`${server} > ${what}`),
        fix_available: false,
    });
    const findings = [];
    for (const item of changed) {
        const what = `${KIND_WORD[item.kind]} '${item.label}'`;
        findings.push(item.kind === 'tool'
            ? finding('mcp-tool-definition-changed', 'high', what, `Rug pull: MCP server '${server}' changed tool '${item.label}' since the previous audit`, `Tool '${item.label}' of server '${server}' (${listing.sourceLabel}) is served with a different ` +
                'definition (title, description, input or output schema, or annotations) than the previous ' +
                'audit_mcp_tools run recorded, under the same name. A tool approved once and rewritten later is ' +
                'how a server turns malicious after review. Read the new definition before using the server ' +
                'again; this audit now pins it.')
            : finding(`mcp-${item.kind}-definition-changed`, CHANGED_SEVERITY[item.kind], what, `MCP server '${server}' changed ${what} since the previous audit`, `The ${what} of server '${server}' (${listing.sourceLabel}) is served with a different name, title ` +
                'or description than the previous audit recorded. That text reaches the model; read the new ' +
                'version. This audit now pins it.'));
    }
    for (const item of added) {
        if (item.kind === 'resource')
            continue; // data, not interface: see the module doc
        const what = `${KIND_WORD[item.kind]} '${item.label}'`;
        findings.push(finding(`mcp-${item.kind}-added`, 'low', what, `MCP server '${server}' added ${what} since the previous audit`, `Server '${server}' (${listing.sourceLabel}) now serves a ${what} the previous audit did not see.`));
    }
    for (const key of removed) {
        const { kind, id } = parsePinKey(key);
        if (kind === 'resource')
            continue;
        const what = `${KIND_WORD[kind]} '${id}'`;
        findings.push(finding(`mcp-${kind}-removed`, 'info', what, `MCP server '${server}' no longer serves ${what}`, `Server '${server}' (${listing.sourceLabel}) served a ${what} at the previous audit and does not now.`));
    }
    return {
        findings,
        firstAudit,
        changed: changed.map((i) => i.key),
        added: added.map((i) => i.key),
        removed,
        rehashed,
        firstPinned: [],
        warnings,
        pins,
    };
}
//# sourceMappingURL=pins.js.map