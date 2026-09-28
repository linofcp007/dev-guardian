/**
 * What `audit_mcp_tools` checks in the definitions an MCP server served:
 * every tool, prompt and resource it listed, and its `instructions`.
 *
 * The input is what the server answered to `tools/list`, `prompts/list` and
 * `resources/list` — never what a manifest on disk claims — so this sees the
 * text the host actually loads into the model's context. `rules.ts` holds the
 * checks; this module walks every string a definition carries, applies them,
 * and turns hits into findings: one per (rule, server, item), naming every
 * field of that item that matched.
 *
 * Pure function over its inputs. No I/O.
 */
import { makeFinding } from '../runners/scannerParsers/index.js';
import { escapeInvisible, findEncodedBlob, mixedScriptWord, OVERSIZED_DESCRIPTION_CHARS, readAs, scanInvisible, TEXT_RULES, } from './rules.js';
/**
 * The `tool` every finding of `audit_mcp_tools` carries, and the base of its
 * per-server `tools_run` names (`mcp-tool-audit:<source>::<server>`).
 */
export const MCP_AUDIT_TOOL_NAME = 'mcp-tool-audit';
/**
 * The raw `tools` / `prompts` / `resources` arrays a server answered with,
 * reduced to what is checked. The SDK's own schemas are not used to read
 * them: a server whose definitions do not validate is exactly the kind this
 * audit exists for, and rejecting its whole listing would report nothing.
 */
export function normalizeListing(raw) {
    let malformed = 0;
    const pick = (items, build) => {
        const out = [];
        for (const item of items ?? []) {
            if (item === null || typeof item !== 'object' || Array.isArray(item)) {
                malformed += 1;
                continue;
            }
            const o = item;
            const name = o['name'];
            if (typeof name !== 'string') {
                malformed += 1;
                continue;
            }
            out.push(build(o, name));
        }
        return out;
    };
    const str = (v) => (typeof v === 'string' ? v : undefined);
    const tools = pick(raw.tools, (o, name) => {
        const t = { name };
        const title = str(o['title']);
        if (title !== undefined)
            t.title = title;
        const description = str(o['description']);
        if (description !== undefined)
            t.description = description;
        if (o['inputSchema'] !== undefined)
            t.inputSchema = o['inputSchema'];
        if (o['outputSchema'] !== undefined)
            t.outputSchema = o['outputSchema'];
        if (o['annotations'] !== undefined)
            t.annotations = o['annotations'];
        return t;
    });
    const prompts = pick(raw.prompts, (o, name) => {
        const p = { name };
        const title = str(o['title']);
        if (title !== undefined)
            p.title = title;
        const description = str(o['description']);
        if (description !== undefined)
            p.description = description;
        if (o['arguments'] !== undefined)
            p.arguments = o['arguments'];
        return p;
    });
    const resources = pick(raw.resources, (o, name) => {
        const r = { name };
        const title = str(o['title']);
        if (title !== undefined)
            r.title = title;
        const description = str(o['description']);
        if (description !== undefined)
            r.description = description;
        const uri = str(o['uri']);
        if (uri !== undefined)
            r.uri = uri;
        return r;
    });
    const resourceTemplates = pick(raw.resourceTemplates, (o, name) => {
        const r = { name };
        const title = str(o['title']);
        if (title !== undefined)
            r.title = title;
        const description = str(o['description']);
        if (description !== undefined)
            r.description = description;
        const uri = str(o['uriTemplate']);
        if (uri !== undefined)
            r.uri = uri;
        return r;
    });
    return { tools, prompts, resources, resourceTemplates, malformed };
}
/**
 * Bounds of one walk, so a hostile schema cannot make the analysis itself
 * the denial of service. Fix round 3, M2: the first cut stopped at depth 24
 * SILENTLY and read object keys only inside `properties`; now every string
 * and every key is read, and a walk that hits a bound says so — the listing
 * is then only partly analysed, which the tool reports as partial.
 */
const MAX_DEPTH = 128;
const MAX_NODES_PER_WALK = 50_000;
/**
 * Every string in `value` and every object key (a key can carry text the
 * model reads as well as a value can), iteratively. A bound reached is
 * pushed to `cuts`.
 */
function walkStrings(value, root, item, out, cuts) {
    const stack = [{ v: value, path: root, depth: 0 }];
    let nodes = 0;
    let tooDeep = false;
    while (stack.length > 0) {
        const top = stack.pop();
        if (top === undefined)
            break;
        nodes += 1;
        if (nodes > MAX_NODES_PER_WALK) {
            cuts.push(`${item} ${root}: more than ${MAX_NODES_PER_WALK} nodes; the rest was not analysed`);
            return;
        }
        const { v, path, depth } = top;
        if (typeof v === 'string') {
            out.push({ item, path, text: v });
            continue;
        }
        if (v === null || typeof v !== 'object')
            continue;
        if (depth >= MAX_DEPTH) {
            tooDeep = true;
            continue;
        }
        if (Array.isArray(v)) {
            for (let i = v.length - 1; i >= 0; i -= 1)
                stack.push({ v: v[i], path: `${path}[${i}]`, depth: depth + 1 });
            continue;
        }
        const entries = Object.entries(v);
        for (let i = entries.length - 1; i >= 0; i -= 1) {
            const entry = entries[i];
            if (entry === undefined)
                continue;
            const [key, child] = entry;
            const childPath = `${path}.${key}`;
            out.push({ item, path: `${childPath} (key)`, text: key });
            stack.push({ v: child, path: childPath, depth: depth + 1 });
        }
    }
    if (tooDeep)
        cuts.push(`${item} ${root}: nesting deeper than ${MAX_DEPTH} levels was not analysed`);
}
/** A name as it may appear in a finding: visible, and short. */
function shortName(name) {
    const visible = escapeInvisible(name);
    return visible.length > 80 ? `${visible.slice(0, 80)}…` : visible;
}
function fieldsOf(listing, cuts) {
    const out = [];
    if (listing.instructions !== undefined) {
        out.push({ item: 'server instructions', path: 'instructions', text: listing.instructions });
    }
    for (const t of listing.tools) {
        const item = `tool '${shortName(t.name)}'`;
        out.push({ item, path: 'name', text: t.name });
        if (t.title !== undefined)
            out.push({ item, path: 'title', text: t.title });
        if (t.description !== undefined)
            out.push({ item, path: 'description', text: t.description });
        walkStrings(t.inputSchema, 'inputSchema', item, out, cuts);
        walkStrings(t.outputSchema, 'outputSchema', item, out, cuts);
        walkStrings(t.annotations, 'annotations', item, out, cuts);
    }
    for (const p of listing.prompts) {
        const item = `prompt '${shortName(p.name)}'`;
        out.push({ item, path: 'name', text: p.name });
        if (p.title !== undefined)
            out.push({ item, path: 'title', text: p.title });
        if (p.description !== undefined)
            out.push({ item, path: 'description', text: p.description });
        walkStrings(p.arguments, 'arguments', item, out, cuts);
    }
    const resources = [
        ...listing.resources.map((r) => ({ r, kind: 'resource' })),
        ...(listing.resourceTemplates ?? []).map((r) => ({ r, kind: 'resource template' })),
    ];
    for (const { r, kind } of resources) {
        const item = `${kind} '${shortName(r.name)}'`;
        out.push({ item, path: 'name', text: r.name });
        if (r.title !== undefined)
            out.push({ item, path: 'title', text: r.title });
        if (r.description !== undefined)
            out.push({ item, path: 'description', text: r.description });
        if (r.uri !== undefined)
            out.push({ item, path: 'uri', text: r.uri });
    }
    return out;
}
const EXCERPT_BEFORE = 60;
const EXCERPT_AFTER = 120;
/** A short, single-line, visible excerpt around `index`. */
function excerpt(text, index) {
    const start = Math.max(0, index - EXCERPT_BEFORE);
    const end = Math.min(text.length, index + EXCERPT_AFTER);
    const body = escapeInvisible(text.slice(start, end)).replace(/\s+/g, ' ').trim();
    return `${start > 0 ? '…' : ''}${body}${end < text.length ? '…' : ''}`;
}
/**
 * Every text rule, on the text as written AND as it reads (`readAs`: NFKC,
 * look-alike letters folded to Latin) — `Іgnоrе рrеvіоus іnstruсtіоns` in
 * Cyrillic look-alikes, or in full-width letters, matches no ASCII pattern
 * as written (fix round 3, I4).
 */
function textRuleHits(field) {
    const hits = [];
    const folded = readAs(field.text);
    const texts = folded === field.text ? [field.text] : [field.text, folded];
    for (const rule of TEXT_RULES) {
        if (rule.id === 'mcp-tool-cross-server-shadowing')
            continue; // needs the other servers; see below
        let hit = null;
        for (const [i, text] of texts.entries()) {
            for (const pattern of rule.patterns) {
                pattern.lastIndex = 0;
                const m = pattern.exec(text);
                if (m === null)
                    continue;
                hit = {
                    ...ruleMeta(rule.id),
                    field,
                    index: Math.min(m.index, field.text.length),
                    ...(i === 1 ? { detail: 'written with look-alike or compatibility characters' } : {}),
                };
                break;
            }
            if (hit !== null)
                break;
        }
        if (hit !== null)
            hits.push(hit);
    }
    return hits;
}
function homoglyphHit(field) {
    const mixed = mixedScriptWord(field.text);
    if (mixed === null)
        return null;
    return {
        ...ruleMeta('mcp-tool-homoglyph'),
        field,
        index: mixed.index,
        detail: `${JSON.stringify(escapeInvisible(mixed.word))} reads as ${JSON.stringify(readAs(mixed.word))}`,
    };
}
function ruleMeta(id) {
    const rule = TEXT_RULES.find((r) => r.id === id);
    if (rule !== undefined) {
        return { rule: id, severity: rule.severity, subcategory: rule.subcategory, label: rule.label, explain: rule.explain };
    }
    if (id === 'mcp-tool-hidden-unicode') {
        return {
            rule: id,
            severity: 'high',
            subcategory: 'mcp_tool_poisoning',
            label: 'hidden Unicode',
            explain: 'The text carries characters that render as nothing or reorder what is shown — invisible to anyone ' +
                'reviewing the tool list, read in full by the model.',
        };
    }
    if (id === 'mcp-tool-homoglyph') {
        return {
            rule: id,
            severity: 'medium',
            subcategory: 'mcp_tool_poisoning',
            label: 'look-alike letters from another script',
            explain: 'A word mixes Latin letters with Cyrillic or Greek look-alikes — it reads as one thing to a reviewer ' +
                'and is another string to every text check. Ordinary text in another alphabet does not trip this.',
        };
    }
    if (id === 'mcp-tool-encoded-blob') {
        return {
            rule: id,
            severity: 'medium',
            subcategory: 'mcp_tool_poisoning',
            label: 'a large encoded blob',
            explain: 'The text carries a long base64 run. A description has no use for one; an instruction encoded this ' +
                'way passes every plain-text check, and the model can decode it.',
        };
    }
    return {
        rule: id,
        severity: 'low',
        subcategory: 'mcp_tool_poisoning',
        label: 'an abnormally long description',
        explain: `The description is over ${OVERSIZED_DESCRIPTION_CHARS} characters. Length is no attack by itself, ` +
            'but it is where a payload hides below the part a reviewer reads.',
    };
}
function hiddenUnicodeHit(field) {
    const scan = scanInvisible(field.text);
    if (scan === null)
        return null;
    const tags = scan.decodedTags.trim();
    const selectors = scan.decodedSelectors.trim();
    const detail = `${scan.count} invisible code point(s): ${scan.kinds.join(', ')}` +
        (tags === '' ? '' : `; the tag characters spell ${JSON.stringify(tags.slice(0, 200))}`) +
        (selectors === '' ? '' : `; the variation selectors spell ${JSON.stringify(escapeInvisible(selectors).slice(0, 200))}`);
    return { ...ruleMeta('mcp-tool-hidden-unicode'), field, index: Math.max(0, scan.index), detail };
}
function blobHit(field) {
    const blob = findEncodedBlob(field.text);
    if (blob === null)
        return null;
    const detail = `a ${blob.length}-character base64 run` +
        (blob.decodedText === null
            ? ' (it does not decode to readable text)'
            : ` that decodes to readable text: ${JSON.stringify(escapeInvisible(blob.decodedText).slice(0, 200))}`);
    const meta = ruleMeta('mcp-tool-encoded-blob');
    // Readable text hidden in an encoding is a stronger signal than bytes.
    return { ...meta, severity: blob.decodedText === null ? 'medium' : 'high', field, index: 0, detail };
}
function oversizedHit(field) {
    if (field.path !== 'description' && field.path !== 'instructions')
        return null;
    if (field.text.length <= OVERSIZED_DESCRIPTION_CHARS)
        return null;
    return {
        ...ruleMeta('mcp-tool-description-oversized'),
        field,
        index: OVERSIZED_DESCRIPTION_CHARS,
        detail: `${field.text.length} characters`,
    };
}
/**
 * A tool name is matched bare only when it cannot be an ordinary word —
 * `send_email`, `readFile`, `git.push` — and otherwise only in quotes or
 * backticks: `list` or `search` in prose is English, not a reference.
 */
function distinctive(name) {
    return name.length >= 4 && /[_.-]|[a-z][A-Z]/.test(name);
}
function buildShadowIndex(listing, others) {
    const own = new Set(listing.tools.map((t) => t.name));
    const bare = new Map();
    const quoted = new Map();
    for (const other of others) {
        if (other.serverKey === listing.serverKey)
            continue;
        for (const toolName of other.toolNames) {
            if (own.has(toolName))
                continue;
            if (!quoted.has(toolName))
                quoted.set(toolName, other.serverName);
            if (distinctive(toolName) && !bare.has(toolName))
                bare.set(toolName, other.serverName);
        }
    }
    return { bare, quoted };
}
/** The first other-server tool name `text` mentions, with where. */
function mentionedToolName(text, index) {
    if (index.bare.size > 0) {
        for (const m of text.matchAll(/[A-Za-z0-9_][A-Za-z0-9_.-]*/g)) {
            const token = m[0].replace(/[.-]+$/, '');
            const candidates = [token, ...token.split('.')];
            for (const c of candidates) {
                const server = index.bare.get(c);
                if (server !== undefined)
                    return { name: c, server, at: m.index };
            }
        }
    }
    if (index.quoted.size > 0) {
        for (const m of text.matchAll(/[`'"]([^`'"\n]{1,128})[`'"]/g)) {
            const quotedName = m[1];
            if (quotedName === undefined)
                continue;
            const server = index.quoted.get(quotedName);
            if (server !== undefined)
                return { name: quotedName, server, at: m.index };
        }
    }
    return null;
}
function shadowingHits(field, listing, index) {
    const meta = ruleMeta('mcp-tool-cross-server-shadowing');
    const mention = mentionedToolName(field.text, index);
    if (mention !== null) {
        return [
            { ...meta, field, index: mention.at, detail: `it names '${mention.name}', a tool of server '${mention.server}'` },
        ];
    }
    // `mcp__<server>__<tool>`: how Claude Code names another server's tool.
    for (const m of field.text.matchAll(/\bmcp__([\w-]+?)__[\w-]+/g)) {
        if (m[1] !== undefined && m[1] !== listing.serverName) {
            return [{ ...meta, field, index: m.index, detail: `it names ${JSON.stringify(m[0])}, a tool of server '${m[1]}'` }];
        }
    }
    const rule = TEXT_RULES.find((r) => r.id === 'mcp-tool-cross-server-shadowing');
    for (const pattern of rule?.patterns ?? []) {
        pattern.lastIndex = 0;
        const m = pattern.exec(field.text);
        if (m !== null)
            return [{ ...meta, field, index: m.index }];
    }
    return [];
}
function itemKey(hit) {
    return `${hit.rule}\u0000${hit.field.item}`;
}
export function analyzeServerListing(listing, others) {
    return analyzeServerListingDetailed(listing, others).findings;
}
export function analyzeServerListingDetailed(listing, others) {
    const groups = new Map();
    const add = (hit) => {
        if (hit === null)
            return;
        const key = itemKey(hit);
        const group = groups.get(key);
        if (group === undefined)
            groups.set(key, [hit]);
        else
            group.push(hit);
    };
    const cuts = [];
    const shadowIndex = buildShadowIndex(listing, others);
    for (const field of fieldsOf(listing, cuts)) {
        for (const hit of textRuleHits(field))
            add(hit);
        add(hiddenUnicodeHit(field));
        add(homoglyphHit(field));
        add(blobHit(field));
        add(oversizedHit(field));
        for (const hit of shadowingHits(field, listing, shadowIndex))
            add(hit);
    }
    const findings = [];
    for (const hits of groups.values()) {
        const first = hits[0];
        if (first === undefined)
            continue;
        const severity = hits.reduce((s, h) => (rank(h.severity) > rank(s) ? h.severity : s), first.severity);
        const paths = [...new Set(hits.map((h) => h.field.path))];
        const details = [...new Set(hits.flatMap((h) => (h.detail === undefined ? [] : [h.detail])))];
        const shownPaths = paths.slice(0, 6).join(', ') + (paths.length > 6 ? `, and ${paths.length - 6} more` : '');
        const server = shortName(listing.serverName);
        // Every string below may carry text the server chose; `escapeInvisible`
        // keeps an invisible payload from riding out in the audit's own output.
        findings.push(makeFinding({
            tool: MCP_AUDIT_TOOL_NAME,
            rule_id: first.rule,
            severity,
            category: 'security',
            subcategory: first.subcategory,
            title: escapeInvisible(`MCP server '${server}', ${first.field.item}: ${first.label}`),
            message: escapeInvisible(`${first.explain} Seen in ${first.field.item} of server '${server}' ` +
                `(${listing.sourceLabel}), field(s): ${shownPaths}.` +
                (details.length > 0 ? ` Evidence: ${details.slice(0, 3).join('; ')}.` : '')),
            file_path: listing.sourceLabel,
            snippet: escapeInvisible(`${server} > ${first.field.item} > ${first.field.path}: ${excerpt(first.field.text, first.index)}`),
            fix_available: false,
        }));
    }
    return { findings, cuts: cuts.map(escapeInvisible) };
}
const RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
function rank(s) {
    return RANK[s];
}
//# sourceMappingURL=analyze.js.map