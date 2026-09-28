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
 *   - a resource template: `{uriTemplate, name, title, description}`, keyed
 *     by its uri template;
 *   - the server's `instructions`, which the host puts into the system
 *     prompt (fix round 3, I6).
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
 * ## Tombstones (fix round 3, I7)
 *
 * An item that stops being served is not forgotten: its pin stays as a
 * TOMBSTONE (`-` before the hash). The first cut deleted it, so an audit
 * that happened to see no tools wiped every pin, and a poisoned tool that
 * came back afterwards was merely "added" (low). Now an item that returns
 * unchanged is "added" again, and one that returns with another definition
 * is a change — high for a tool. A tombstone still absent reports nothing.
 * Resources are data and are forgotten instead.
 *
 * ## Keys ({@link pinKey})
 *
 * A tool is keyed by its bare name — what every pin written before other
 * kinds were pinned holds. Every other kind is `<kind>:<id>`, and a tool
 * whose name itself starts with a reserved prefix is `tool:<name>`, so no
 * key can be two items.
 *
 * ## Hash schemes, the upgrade, and kinds an older audit did not pin
 *
 * A pin is `v<scheme>:<hex>`; bare hex is scheme 1, which covered four of a
 * tool's fields and nothing else. Scheme 2 added title and output schema and
 * the other kinds; scheme 3 (this one) adds the instructions and tombstones
 * — the tool, prompt and resource recipes are the same in 2 and 3.
 *
 *   - A stored pin of an older scheme is compared by hashing what is served
 *     now with THAT scheme's recipe: equal means nothing the old pin
 *     recorded changed, and the item is re-pinned without a finding
 *     (`rehashed`); different is a change, reported. A change across the
 *     upgrade itself in a field the old scheme never recorded cannot be
 *     seen — the old pin holds nothing to compare it with.
 *   - The previous audit's scheme is the newest among its stored pins. An
 *     item of a kind that scheme did not pin is recorded silently the first
 *     time (`firstPinned`, fix round 3, M3) — not reported as added.
 *   - A pin of a scheme this build does not know is re-pinned, and a
 *     warning says it could not be compared.
 *
 * Pure functions. No I/O.
 */

import { hashConfigValue } from '../agentaudit/hash.js';
import { makeFinding } from '../runners/scannerParsers/index.js';
import type { McpPin } from '../storage/mcpToolPinsRepo.js';
import type { Finding, Severity } from '../types.js';
import {
  MCP_AUDIT_TOOL_NAME,
  type PromptDefinition,
  type ResourceDefinition,
  type ServerListing,
  type ToolDefinition,
} from './analyze.js';
import { escapeInvisible } from './rules.js';

/** The scheme every pin is written with now. */
export const PIN_SCHEME = 3;

export type PinItemKind = 'tool' | 'prompt' | 'resource' | 'resource-template' | 'instructions';

/** The scheme that first pinned each kind. */
const KIND_SINCE: Record<PinItemKind, number> = {
  tool: 1,
  prompt: 2,
  resource: 2,
  'resource-template': 2,
  instructions: 3,
};

const NON_TOOL_KINDS: readonly PinItemKind[] = ['prompt', 'resource', 'resource-template', 'instructions'];
/** Prefixes a bare tool key may not start with; `resource:` never prefixes `resource-template:`. */
const RESERVED_PREFIX = /^(tool|prompt|resource|resource-template|instructions):/;
/** Marks a pin whose item is no longer served. */
const TOMBSTONE = '-';

/** The storage key of one item. Injective across kinds; see the module doc. */
export function pinKey(kind: PinItemKind, id: string): string {
  if (kind !== 'tool') return `${kind}:${id}`;
  return RESERVED_PREFIX.test(id) ? `tool:${id}` : id;
}

/**
 * `tool:` — built rather than written as one quoted literal: the source scan
 * in `test/unit/history/runNames.test.ts` reads every `tool:` followed by a
 * quote as a finding's `tool` field.
 */
const TOOL_KEY_PREFIX = `${'tool'}:`;

/** The inverse of {@link pinKey}. */
export function parsePinKey(key: string): { kind: PinItemKind; id: string } {
  if (key.startsWith(TOOL_KEY_PREFIX)) return { kind: 'tool', id: key.slice(TOOL_KEY_PREFIX.length) };
  for (const kind of NON_TOOL_KINDS) {
    if (key.startsWith(`${kind}:`)) return { kind, id: key.slice(kind.length + 1) };
  }
  return { kind: 'tool', id: key };
}

function versioned(value: unknown, scheme: number): string {
  return `v${scheme}:${hashConfigValue(value)}`;
}

/** A tool's pin under `scheme` (bare hex for scheme 1). */
function toolHash(tool: ToolDefinition, scheme: number): string {
  if (scheme === 1) {
    return hashConfigValue({
      name: tool.name,
      description: tool.description ?? null,
      inputSchema: tool.inputSchema ?? null,
      annotations: tool.annotations ?? null,
    });
  }
  return versioned(
    {
      name: tool.name,
      title: tool.title ?? null,
      description: tool.description ?? null,
      inputSchema: tool.inputSchema ?? null,
      outputSchema: tool.outputSchema ?? null,
      annotations: tool.annotations ?? null,
    },
    scheme,
  );
}

export function toolDefinitionHash(tool: ToolDefinition): string {
  return toolHash(tool, PIN_SCHEME);
}

function promptHash(p: PromptDefinition, scheme: number): string {
  return versioned(
    { name: p.name, title: p.title ?? null, description: p.description ?? null, arguments: p.arguments ?? null },
    scheme,
  );
}

function resourceHash(r: ResourceDefinition, uriKey: 'uri' | 'uriTemplate', scheme: number): string {
  return versioned(
    { [uriKey]: r.uri ?? null, name: r.name, title: r.title ?? null, description: r.description ?? null },
    scheme,
  );
}

/** The scheme a stored pin (live or tombstone) was written with: 1 for bare hex, null when unrecognisable. */
export function pinScheme(stored: string): number | null {
  const value = stored.startsWith(TOMBSTONE) ? stored.slice(TOMBSTONE.length) : stored;
  const m = /^v(\d+):[0-9a-f]{64}$/.exec(value);
  if (m?.[1] !== undefined) return Number(m[1]);
  return /^[0-9a-f]{64}$/.test(value) ? 1 : null;
}

interface PinnedItem {
  key: string;
  kind: PinItemKind;
  /** The name shown in findings. */
  label: string;
  /** This item hashed with `scheme` — null where that scheme did not pin this kind. */
  hashAt: (scheme: number) => string | null;
}

function pinnedItems(listing: ServerListing): PinnedItem[] {
  const since = (kind: PinItemKind, f: (scheme: number) => string) => (scheme: number) =>
    scheme >= KIND_SINCE[kind] ? f(scheme) : null;
  const items: PinnedItem[] = [];
  for (const t of listing.tools) {
    items.push({ key: pinKey('tool', t.name), kind: 'tool', label: t.name, hashAt: since('tool', (s) => toolHash(t, s)) });
  }
  for (const p of listing.prompts) {
    items.push({ key: pinKey('prompt', p.name), kind: 'prompt', label: p.name, hashAt: since('prompt', (s) => promptHash(p, s)) });
  }
  for (const r of listing.resources) {
    if (r.uri === undefined) continue;
    items.push({
      key: pinKey('resource', r.uri),
      kind: 'resource',
      label: r.uri,
      hashAt: since('resource', (s) => resourceHash(r, 'uri', s)),
    });
  }
  for (const r of listing.resourceTemplates ?? []) {
    if (r.uri === undefined) continue;
    items.push({
      key: pinKey('resource-template', r.uri),
      kind: 'resource-template',
      label: r.uri,
      hashAt: since('resource-template', (s) => resourceHash(r, 'uriTemplate', s)),
    });
  }
  const instructions = listing.instructions;
  if (instructions !== undefined) {
    items.push({
      key: pinKey('instructions', ''),
      kind: 'instructions',
      label: 'instructions',
      hashAt: since('instructions', (s) => versioned({ instructions }, s)),
    });
  }
  return items;
}

export interface CompareOptions {
  /**
   * False when the listing was cut short (a budget): nothing is reported
   * removed, no tombstone is written, and the pins returned are only what
   * was seen, to be ADDED to the stored ones.
   */
  complete?: boolean;
}

export interface PinComparison {
  findings: Finding[];
  /** No previous audit of this server: nothing was compared. */
  firstAudit: boolean;
  /** Pin keys ({@link pinKey}) — a tool's is its name. */
  changed: string[];
  added: string[];
  removed: string[];
  /** Stored under an older scheme, unchanged by that scheme's recipe, re-pinned without a finding. */
  rehashed: string[];
  /** Items of a kind the previous audit did not pin yet: recorded, not reported as added. */
  firstPinned: string[];
  warnings: string[];
  /** What to store for this server now: live pins, and tombstones (`-` + hash). */
  pins: McpPin[];
}

const KIND_WORD: Record<PinItemKind, string> = {
  tool: 'tool',
  prompt: 'prompt',
  resource: 'resource',
  'resource-template': 'resource template',
  instructions: 'instructions',
};

const CHANGED_SEVERITY: Record<PinItemKind, Severity> = {
  tool: 'high',
  prompt: 'medium',
  resource: 'medium',
  'resource-template': 'medium',
  instructions: 'high',
};

type Verdict = 'same' | 'rehashed' | 'changed' | 'unknown-scheme';

/** `stored` (a live value, no tombstone mark) against what `item` is now. */
function judge(item: PinnedItem, stored: string): Verdict {
  const current = item.hashAt(PIN_SCHEME);
  if (stored === current) return 'same';
  const scheme = pinScheme(stored);
  if (scheme === PIN_SCHEME) return 'changed';
  if (scheme !== null && scheme < PIN_SCHEME) {
    const old = item.hashAt(scheme);
    // null: that scheme did not pin this kind, yet a pin exists — compare as changed.
    return old === stored ? 'rehashed' : 'changed';
  }
  return 'unknown-scheme';
}

/**
 * Compare what `listing` serves with `previous` (pin key → stored value).
 * `auditedBefore` says whether the server was audited at all before — with
 * an empty `previous` it separates "had nothing" (everything is new) from
 * "never audited" (nothing to compare).
 */
export function comparePins(
  listing: ServerListing,
  previous: ReadonlyMap<string, string>,
  auditedBefore: boolean,
  options: CompareOptions = {},
): PinComparison {
  const complete = options.complete !== false;
  const items = new Map<string, PinnedItem>();
  for (const item of pinnedItems(listing)) items.set(item.key, item);
  const live = (item: PinnedItem): McpPin => ({ key: item.key, hash: item.hashAt(PIN_SCHEME) ?? '' });

  const firstAudit = !auditedBefore && previous.size === 0;
  if (firstAudit) {
    return {
      findings: [],
      firstAudit,
      changed: [],
      added: [],
      removed: [],
      rehashed: [],
      firstPinned: [],
      warnings: [],
      pins: [...items.values()].map(live),
    };
  }

  // The previous audit's scheme: which kinds it pinned.
  const storedSchemes = [...previous.values()].map(pinScheme).filter((s): s is number => s !== null);
  const previousScheme = storedSchemes.length > 0 ? Math.max(...storedSchemes) : PIN_SCHEME;

  const changed: PinnedItem[] = [];
  const added: PinnedItem[] = [];
  const rehashed: string[] = [];
  const firstPinned: string[] = [];
  const warnings: string[] = [];
  for (const item of items.values()) {
    const stored = previous.get(item.key);
    if (stored === undefined) {
      if (KIND_SINCE[item.kind] > previousScheme) firstPinned.push(item.key);
      else added.push(item);
      continue;
    }
    const tombstone = stored.startsWith(TOMBSTONE);
    const verdict = judge(item, tombstone ? stored.slice(TOMBSTONE.length) : stored);
    if (verdict === 'changed') changed.push(item);
    else if (tombstone) added.push(item); // back, unchanged: served again
    else if (verdict === 'rehashed') rehashed.push(item.key);
    else if (verdict === 'unknown-scheme') {
      warnings.push(
        `${KIND_WORD[item.kind]} '${escapeInvisible(item.label)}': its stored pin (${stored.slice(0, 4)}…) is of a ` +
          'scheme this build does not know, so it could not be compared; re-pinned',
      );
    }
  }

  const removed: string[] = [];
  const tombstones: McpPin[] = [];
  if (complete) {
    for (const [key, stored] of previous) {
      if (items.has(key)) continue;
      if (parsePinKey(key).kind === 'resource') continue; // data: forgotten, not tombstoned
      if (stored.startsWith(TOMBSTONE)) {
        tombstones.push({ key, hash: stored }); // still gone: nothing new to say
      } else {
        removed.push(key);
        tombstones.push({ key, hash: `${TOMBSTONE}${stored}` });
      }
    }
    removed.sort();
  }

  const server = escapeInvisible(listing.serverName);
  const finding = (ruleId: string, severity: Severity, what: string, title: string, message: string): Finding =>
    makeFinding({
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

  const findings: Finding[] = [];
  for (const item of changed) {
    const what = `${KIND_WORD[item.kind]} '${item.label}'`;
    if (item.kind === 'tool') {
      findings.push(
        finding(
          'mcp-tool-definition-changed',
          'high',
          what,
          `Rug pull: MCP server '${server}' changed tool '${item.label}' since the previous audit`,
          `Tool '${item.label}' of server '${server}' (${listing.sourceLabel}) is served with a different ` +
            'definition (title, description, input or output schema, or annotations) than the previous ' +
            'audit_mcp_tools run recorded, under the same name — or came back changed after being removed. ' +
            'A tool approved once and rewritten later is how a server turns malicious after review. Read ' +
            'the new definition before using the server again; this audit now pins it.',
        ),
      );
    } else if (item.kind === 'instructions') {
      findings.push(
        finding(
          'mcp-server-instructions-changed',
          'high',
          'instructions',
          `MCP server '${server}' changed its instructions since the previous audit`,
          `The instructions server '${server}' (${listing.sourceLabel}) sends at initialize differ from what ` +
            'the previous audit recorded. The host puts them into the system prompt. Read them before using ' +
            'the server again; this audit now pins them.',
        ),
      );
    } else {
      findings.push(
        finding(
          `mcp-${item.kind}-definition-changed`,
          CHANGED_SEVERITY[item.kind],
          what,
          `MCP server '${server}' changed ${what} since the previous audit`,
          `The ${what} of server '${server}' (${listing.sourceLabel}) is served with a different name, title ` +
            'or description than the previous audit recorded. That text reaches the model; read the new ' +
            'version. This audit now pins it.',
        ),
      );
    }
  }
  for (const item of added) {
    if (item.kind === 'resource') continue; // data, not interface: see the module doc
    if (item.kind === 'instructions') {
      findings.push(
        finding(
          'mcp-server-instructions-changed',
          'high',
          'instructions',
          `MCP server '${server}' now sends instructions it did not send at the previous audit`,
          `Server '${server}' (${listing.sourceLabel}) sends instructions at initialize that the previous audit ` +
            'did not see. The host puts them into the system prompt; read them.',
        ),
      );
      continue;
    }
    const what = `${KIND_WORD[item.kind]} '${item.label}'`;
    findings.push(
      finding(
        `mcp-${item.kind}-added`,
        'low',
        what,
        `MCP server '${server}' added ${what} since the previous audit`,
        `Server '${server}' (${listing.sourceLabel}) now serves a ${what} the previous audit did not see.`,
      ),
    );
  }
  for (const key of removed) {
    const { kind, id } = parsePinKey(key);
    if (kind === 'instructions') {
      findings.push(
        finding(
          'mcp-server-instructions-removed',
          'info',
          'instructions',
          `MCP server '${server}' no longer sends instructions`,
          `Server '${server}' (${listing.sourceLabel}) sent instructions at the previous audit and does not now.`,
        ),
      );
      continue;
    }
    const what = `${KIND_WORD[kind]} '${id}'`;
    findings.push(
      finding(
        `mcp-${kind}-removed`,
        'info',
        what,
        `MCP server '${server}' no longer serves ${what}`,
        `Server '${server}' (${listing.sourceLabel}) served a ${what} at the previous audit and does not now.`,
      ),
    );
  }

  return {
    findings,
    firstAudit,
    changed: changed.map((i) => i.key),
    added: added.map((i) => i.key),
    removed,
    rehashed,
    firstPinned,
    warnings,
    pins: [...[...items.values()].map(live), ...tombstones],
  };
}
