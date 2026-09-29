/**
 * Pinning what a server serves, so a definition that changes under the same
 * name — a "rug pull": approved once, rewritten later — is reported.
 *
 * ## What is pinned
 *
 * Everything the model sees about each item, as sha256 of its canonical JSON
 * (keys sorted, absent fields as null — `agentaudit/hash.ts`'s
 * `stableStringify`), over the FULL content — hashing is linear and cheap,
 * so a change past any analysis bound is still caught:
 *
 *   - a tool: `{name, title, description, inputSchema, outputSchema, annotations}`;
 *   - a prompt: `{name, title, description, arguments}`;
 *   - a resource: `{uri, name, title, description}`, keyed by its uri;
 *   - a resource template: `{uriTemplate, name, title, description}`, keyed
 *     by its uri template;
 *   - the server's `instructions`, which the host puts into the system
 *     prompt.
 *
 * A resource without a uri is analysed but not pinned: there is nothing
 * stable to key it on. Resources are DATA on most servers (files, rows,
 * documents), so one appearing or disappearing is not reported — only a
 * changed definition under the same uri is.
 *
 * What a change is reported as: a tool, or the instructions, high (the rug
 * pull); a prompt, resource or template, medium. An item added is low and
 * one removed info (instructions that appear are high: new text in the
 * system prompt).
 *
 * ## One name, several definitions (fix round 4)
 *
 * A listing may serve two tools under one name, and clients resolve that
 * ambiguously. The first cut kept the LAST definition of a name, so a server
 * could serve `[fetch rewritten, fetch original]` and read unchanged (0
 * findings, coverage full; the same across pages). A key's pin now covers
 * EVERY definition under it (their hashes, sorted), and a duplicate tool
 * name is itself a high finding, `mcp-tool-duplicate-name`. Names are
 * compared as a reader sees them — NFKC, case-folded, trimmed (fix round
 * 5): `Fetch`, `ｆｅｔｃｈ` and `fetch ` beside `fetch` are duplicates too,
 * though each keeps its own exact-name pin.
 *
 * ## Tombstones
 *
 * An item that stops being served is not forgotten: its pin stays as a
 * TOMBSTONE (`-` before the hash). Deleting it let an audit that happened to
 * see no tools wipe every pin, so a poisoned tool that came back afterwards
 * was merely "added" (low). An item that returns unchanged is "added" again,
 * one that returns with another definition is a change — high for a tool. A
 * tombstone still absent reports nothing. Resources are forgotten instead.
 *
 * ## Keys ({@link pinKey})
 *
 * A tool is keyed by its bare name. Every other kind is `<kind>:<id>`, and a
 * tool whose name itself starts with a reserved prefix is `tool:<name>`, so
 * no key can be two items.
 *
 * ## Scheme
 *
 * A pin is `v<scheme>:<hex>` (this is scheme 1). A stored pin of another
 * scheme — written by another build — cannot be compared: it is re-pinned,
 * and a warning says so. When the recipe changes, a new scheme number and
 * the comparison from the old one come with it.
 *
 * Pure functions. No I/O.
 */
import { hashConfigValue } from '../agentaudit/hash.js';
import { makeFinding } from '../runners/scannerParsers/index.js';
import { MCP_AUDIT_TOOL_NAME, } from './analyze.js';
import { escapeInvisible } from './rules.js';
/** The scheme every pin is written with. */
export const PIN_SCHEME = 1;
const NON_TOOL_KINDS = ['prompt', 'resource', 'resource-template', 'instructions'];
/** Prefixes a bare tool key may not start with; `resource:` never prefixes `resource-template:`. */
const RESERVED_PREFIX = /^(tool|prompt|resource|resource-template|instructions):/;
/** Marks a pin whose item is no longer served. */
const TOMBSTONE = '-';
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
function promptHash(p) {
    return versioned({ name: p.name, title: p.title ?? null, description: p.description ?? null, arguments: p.arguments ?? null });
}
function resourceHash(r, uriKey) {
    return versioned({ [uriKey]: r.uri ?? null, name: r.name, title: r.title ?? null, description: r.description ?? null });
}
/** The scheme a stored pin (live or tombstone) was written with, or null when unrecognisable. */
export function pinScheme(stored) {
    const value = stored.startsWith(TOMBSTONE) ? stored.slice(TOMBSTONE.length) : stored;
    const m = /^v(\d+):[0-9a-f]{64}$/.exec(value);
    return m?.[1] === undefined ? null : Number(m[1]);
}
/** Every item, one per key; several definitions under one key are pinned together. */
function pinnedItems(listing) {
    const byKey = new Map();
    const add = (kind, id, label, hash) => {
        const key = pinKey(kind, id);
        const slot = byKey.get(key);
        if (slot === undefined)
            byKey.set(key, { kind, label, hashes: [hash] });
        else
            slot.hashes.push(hash);
    };
    for (const t of listing.tools)
        add('tool', t.name, t.name, toolDefinitionHash(t));
    for (const p of listing.prompts)
        add('prompt', p.name, p.name, promptHash(p));
    for (const r of listing.resources)
        if (r.uri !== undefined)
            add('resource', r.uri, r.uri, resourceHash(r, 'uri'));
    for (const r of listing.resourceTemplates ?? []) {
        if (r.uri !== undefined)
            add('resource-template', r.uri, r.uri, resourceHash(r, 'uriTemplate'));
    }
    if (listing.instructions !== undefined) {
        add('instructions', '', 'instructions', versioned({ instructions: listing.instructions }));
    }
    return [...byKey].map(([key, { kind, label, hashes }]) => ({
        key,
        kind,
        label,
        // One definition: its own hash. Several: every one of them, order-free.
        hash: hashes.length === 1 ? (hashes[0] ?? '') : versioned({ definitions: [...hashes].sort() }),
    }));
}
/**
 * A tool name as a reader sees it (fix round 5, minor 5): NFKC, case-folded
 * (upper then lower, so `ß` and `SS` meet as full folding has them), and
 * trimmed — `Fetch`, `ｆｅｔｃｈ` and `fetch ` all read `fetch`.
 */
export function readableName(name) {
    return name.normalize('NFKC').toUpperCase().toLowerCase().normalize('NFKC').trim();
}
/** The tool names served more than once as a reader sees them: each group in listing order. */
function duplicateToolNames(tools) {
    const groups = new Map();
    for (const t of tools) {
        const key = readableName(t.name);
        const group = groups.get(key);
        if (group === undefined)
            groups.set(key, [t.name]);
        else
            group.push(t.name);
    }
    return [...groups.values()].filter((g) => g.length > 1);
}
const KIND_WORD = {
    tool: 'tool',
    prompt: 'prompt',
    resource: 'resource',
    'resource-template': 'resource template',
    instructions: 'instructions',
};
const CHANGED_SEVERITY = {
    tool: 'high',
    prompt: 'medium',
    resource: 'medium',
    'resource-template': 'medium',
    instructions: 'high',
};
/**
 * Compare what `listing` serves with `previous` (pin key → stored value).
 * `auditedBefore` says whether the server was audited at all before — with
 * an empty `previous` it separates "had nothing" (everything is new) from
 * "never audited" (nothing to compare).
 */
export function comparePins(listing, previous, auditedBefore, options = {}) {
    const complete = options.complete !== false;
    const items = new Map();
    for (const item of pinnedItems(listing))
        items.set(item.key, item);
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
    // A duplicate tool name is a finding on every audit, the first included.
    const findings = [];
    for (const names of duplicateToolNames(listing.tools)) {
        const first = names[0] ?? '';
        const distinct = [...new Set(names)];
        const shown = distinct.slice(0, 5).map((n) => `'${n.length > 80 ? `${n.slice(0, 80)}…` : n}'`);
        const alike = distinct.length > 1;
        findings.push(finding('mcp-tool-duplicate-name', 'high', `tool '${first}'`, alike
            ? `MCP server '${server}' serves ${names.length} tools whose names read the same: ${shown.join(', ')}`
            : `MCP server '${server}' serves ${names.length} tools named ${shown.join(', ')}`, `Server '${server}' (${listing.sourceLabel}) lists ${names.length} definitions under ` +
            (alike
                ? `names that read the same once case, width and surrounding space are set aside: ${shown.join(', ')}` +
                    (distinct.length > shown.length ? `, and ${distinct.length - shown.length} more` : '')
                : `the tool name ${shown.join(', ')}`) +
            '. Clients resolve a duplicate name ambiguously, and a model reads look-alike names as one tool, so ' +
            'the definition that was reviewed need not be the one that is called — and the model reads all of them.'));
    }
    const pins = [...items.values()].map((i) => ({ key: i.key, hash: i.hash }));
    const firstAudit = !auditedBefore && previous.size === 0;
    if (firstAudit)
        return { findings, firstAudit, changed: [], added: [], removed: [], warnings: [], pins };
    const changed = [];
    const added = [];
    const warnings = [];
    for (const item of items.values()) {
        const stored = previous.get(item.key);
        if (stored === undefined) {
            added.push(item);
            continue;
        }
        const tombstone = stored.startsWith(TOMBSTONE);
        const value = tombstone ? stored.slice(TOMBSTONE.length) : stored;
        if (value === item.hash) {
            if (tombstone)
                added.push(item); // back, unchanged: served again
            continue;
        }
        if (pinScheme(value) === PIN_SCHEME) {
            changed.push(item);
            continue;
        }
        warnings.push(`${KIND_WORD[item.kind]} '${escapeInvisible(item.label)}': its stored pin (${escapeInvisible(value.slice(0, 4))}…) ` +
            'is of a scheme this build does not know, so it could not be compared; re-pinned');
    }
    const removed = [];
    const tombstones = [];
    if (complete) {
        for (const [key, stored] of previous) {
            if (items.has(key))
                continue;
            if (parsePinKey(key).kind === 'resource')
                continue; // data: forgotten, not tombstoned
            if (stored.startsWith(TOMBSTONE)) {
                tombstones.push({ key, hash: stored }); // still gone: nothing new to say
            }
            else {
                removed.push(key);
                tombstones.push({ key, hash: `${TOMBSTONE}${stored}` });
            }
        }
        removed.sort();
    }
    for (const item of changed) {
        const what = `${KIND_WORD[item.kind]} '${item.label}'`;
        if (item.kind === 'tool') {
            findings.push(finding('mcp-tool-definition-changed', 'high', what, `Rug pull: MCP server '${server}' changed tool '${item.label}' since the previous audit`, `Tool '${item.label}' of server '${server}' (${listing.sourceLabel}) is served with a different ` +
                'definition (title, description, input or output schema, or annotations, or another definition ' +
                'served beside it under the same name) than the previous audit_mcp_tools run recorded — or came ' +
                'back changed after being removed. A tool approved once and rewritten later is how a server ' +
                'turns malicious after review. Read the new definition before using the server again; this audit ' +
                'now pins it.'));
        }
        else if (item.kind === 'instructions') {
            findings.push(finding('mcp-server-instructions-changed', 'high', 'instructions', `MCP server '${server}' changed its instructions since the previous audit`, `The instructions server '${server}' (${listing.sourceLabel}) sends at initialize differ from what ` +
                'the previous audit recorded. The host puts them into the system prompt. Read them before using ' +
                'the server again; this audit now pins them.'));
        }
        else {
            findings.push(finding(`mcp-${item.kind}-definition-changed`, CHANGED_SEVERITY[item.kind], what, `MCP server '${server}' changed ${what} since the previous audit`, `The ${what} of server '${server}' (${listing.sourceLabel}) is served with a different name, title ` +
                'or description than the previous audit recorded. That text reaches the model; read the new ' +
                'version. This audit now pins it.'));
        }
    }
    for (const item of added) {
        if (item.kind === 'resource')
            continue; // data, not interface: see the module doc
        if (item.kind === 'instructions') {
            findings.push(finding('mcp-server-instructions-changed', 'high', 'instructions', `MCP server '${server}' now sends instructions it did not send at the previous audit`, `Server '${server}' (${listing.sourceLabel}) sends instructions at initialize that the previous audit ` +
                'did not see. The host puts them into the system prompt; read them.'));
            continue;
        }
        const what = `${KIND_WORD[item.kind]} '${item.label}'`;
        findings.push(finding(`mcp-${item.kind}-added`, 'low', what, `MCP server '${server}' added ${what} since the previous audit`, `Server '${server}' (${listing.sourceLabel}) now serves a ${what} the previous audit did not see.`));
    }
    for (const key of removed) {
        const { kind, id } = parsePinKey(key);
        if (kind === 'instructions') {
            findings.push(finding('mcp-server-instructions-removed', 'info', 'instructions', `MCP server '${server}' no longer sends instructions`, `Server '${server}' (${listing.sourceLabel}) sent instructions at the previous audit and does not now.`));
            continue;
        }
        const what = `${KIND_WORD[kind]} '${id}'`;
        findings.push(finding(`mcp-${kind}-removed`, 'info', what, `MCP server '${server}' no longer serves ${what}`, `Server '${server}' (${listing.sourceLabel}) served a ${what} at the previous audit and does not now.`));
    }
    return {
        findings,
        firstAudit,
        changed: changed.map((i) => i.key),
        added: added.map((i) => i.key),
        removed,
        warnings,
        pins: [...pins, ...tombstones],
    };
}
//# sourceMappingURL=pins.js.map