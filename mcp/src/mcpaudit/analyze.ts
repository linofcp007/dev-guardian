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
import type { Finding, Severity } from '../types.js';
import { capFindingText, capPath, capSegment, MAX_PATH_CHARS } from './output.js';
import {
  escapeInvisible,
  findEncodedBlob,
  mcpRuleTaxonomy,
  mixedScriptWord,
  OVERSIZED_DESCRIPTION_CHARS,
  PASS_TO_DESTINATION,
  PASS_TO_WORD,
  readAs,
  SENSITIVE_PATH_ANYWHERE,
  scanInvisible,
  TEXT_RULES,
  type McpRuleId,
} from './rules.js';

/**
 * The `tool` every finding of `audit_mcp_tools` carries, and the base of its
 * per-server `tools_run` names (`mcp-tool-audit:<source>::<server>`).
 */
export const MCP_AUDIT_TOOL_NAME = 'mcp-tool-audit';

export interface ToolDefinition {
  name: string;
  title?: string;
  description?: string;
  inputSchema?: unknown;
  outputSchema?: unknown;
  annotations?: unknown;
}

export interface PromptDefinition {
  name: string;
  title?: string;
  description?: string;
  arguments?: unknown;
}

export interface ResourceDefinition {
  name: string;
  title?: string;
  description?: string;
  uri?: string;
}

export interface ServerListing {
  /** `<config source label>::<server name>` — the pin key. */
  serverKey: string;
  serverName: string;
  /** The config file the entry came from: every finding's `file_path`. */
  sourceLabel: string;
  instructions?: string;
  tools: ToolDefinition[];
  prompts: PromptDefinition[];
  resources: ResourceDefinition[];
  /** `resources/templates/list`; `uri` holds the template. */
  resourceTemplates?: ResourceDefinition[];
}

/** Another server's tools, for the cross-server shadowing check. */
export interface OtherServer {
  serverKey: string;
  serverName: string;
  toolNames: readonly string[];
}

export interface NormalizedListing {
  tools: ToolDefinition[];
  prompts: PromptDefinition[];
  resources: ResourceDefinition[];
  resourceTemplates: ResourceDefinition[];
  /** Entries dropped because they were not an object with a string `name`. */
  malformed: number;
}

/**
 * The raw `tools` / `prompts` / `resources` arrays a server answered with,
 * reduced to what is checked. The SDK's own schemas are not used to read
 * them: a server whose definitions do not validate is exactly the kind this
 * audit exists for, and rejecting its whole listing would report nothing.
 */
export function normalizeListing(raw: {
  tools?: unknown[];
  prompts?: unknown[];
  resources?: unknown[];
  resourceTemplates?: unknown[];
}): NormalizedListing {
  let malformed = 0;
  const pick = <T>(items: unknown[] | undefined, build: (o: Record<string, unknown>, name: string) => T): T[] => {
    const out: T[] = [];
    for (const item of items ?? []) {
      if (item === null || typeof item !== 'object' || Array.isArray(item)) {
        malformed += 1;
        continue;
      }
      const o = item as Record<string, unknown>;
      const name = o['name'];
      if (typeof name !== 'string') {
        malformed += 1;
        continue;
      }
      out.push(build(o, name));
    }
    return out;
  };
  const str = (v: unknown): string | undefined => (typeof v === 'string' ? v : undefined);

  const tools = pick<ToolDefinition>(raw.tools, (o, name) => {
    const t: ToolDefinition = { name };
    const title = str(o['title']);
    if (title !== undefined) t.title = title;
    const description = str(o['description']);
    if (description !== undefined) t.description = description;
    if (o['inputSchema'] !== undefined) t.inputSchema = o['inputSchema'];
    if (o['outputSchema'] !== undefined) t.outputSchema = o['outputSchema'];
    if (o['annotations'] !== undefined) t.annotations = o['annotations'];
    return t;
  });
  const prompts = pick<PromptDefinition>(raw.prompts, (o, name) => {
    const p: PromptDefinition = { name };
    const title = str(o['title']);
    if (title !== undefined) p.title = title;
    const description = str(o['description']);
    if (description !== undefined) p.description = description;
    if (o['arguments'] !== undefined) p.arguments = o['arguments'];
    return p;
  });
  const resources = pick<ResourceDefinition>(raw.resources, (o, name) => {
    const r: ResourceDefinition = { name };
    const title = str(o['title']);
    if (title !== undefined) r.title = title;
    const description = str(o['description']);
    if (description !== undefined) r.description = description;
    const uri = str(o['uri']);
    if (uri !== undefined) r.uri = uri;
    return r;
  });
  const resourceTemplates = pick<ResourceDefinition>(raw.resourceTemplates, (o, name) => {
    const r: ResourceDefinition = { name };
    const title = str(o['title']);
    if (title !== undefined) r.title = title;
    const description = str(o['description']);
    if (description !== undefined) r.description = description;
    const uri = str(o['uriTemplate']);
    if (uri !== undefined) r.uri = uri;
    return r;
  });
  return { tools, prompts, resources, resourceTemplates, malformed };
}


/** One string the model will read, and where it sits. */
interface TextField {
  /** `tool 'x'`, `prompt 'p'`, `resource 'r'`, `server instructions`. */
  item: string;
  /** `description`, `inputSchema.properties.path.description`, … */
  path: string;
  text: string;
}

const MiB = 1024 * 1024;

/**
 * What one server's analysis may read (fix round 4, C1 residual). The review
 * measured the analysis itself as the denial of service: it ran on the main
 * thread over every string of every listing, unbounded — one server of 4
 * pages x a 7 MiB description stalled the event loop 19 s and reported ok;
 * three such servers took 1.7 GB. Real listings are two orders of magnitude
 * smaller: the largest measured (dev-guardian's own, 58 tools) carries 90 000
 * characters of text, its longest string 1463 (2781 in server-sequential-
 * thinking). Past any bound the rest is not analysed and the server is
 * partial, with the reason; a string over its bound is itself a finding.
 */
export interface AnalysisBounds {
  /** All text of one server, in characters. */
  maxTextChars: number;
  /** One string: past this it is analysed only up to it. */
  maxStringChars: number;
  /** Strings (values and object keys) of one server. */
  maxStrings: number;
  /** Distinct names kept for the cross-server shadowing check. */
  maxMentions: number;
}

export const ANALYSIS_BOUNDS: AnalysisBounds = {
  maxTextChars: 2 * MiB,
  maxStringChars: 64 * 1024,
  maxStrings: 50_000,
  maxMentions: 20_000,
};

/**
 * Inside one item, a yield to the event loop after this much text analysed
 * or this much time, whichever comes first (fix round 5, minor 4). By string
 * count (every 1000) one item of 31 strings of 64 KiB, ~62 ms each, stalled
 * 1.6 s; now the longest stall is one string's analysis.
 */
const YIELD_EVERY_CHARS = 256 * 1024;
const YIELD_EVERY_MS = 16;

/**
 * Depth bound of one walk (fix round 3, M2): every string and every key is
 * read, and a walk that hits the bound says so.
 */
const MAX_DEPTH = 128;

/** What marks the path of an object key, as opposed to its value. */
const KEY_SUFFIX = ' (key)';

/** Called once per walk that met nesting past {@link MAX_DEPTH}. */
type OnTooDeep = (item: string, root: string) => void;

/** Every string in `value` and every object key, iteratively, each with its (bounded) path. */
function* walkStrings(value: unknown, root: string, item: string, onTooDeep: OnTooDeep): Generator<TextField> {
  const stack: Array<{ v: unknown; path: string; depth: number }> = [{ v: value, path: root, depth: 0 }];
  let tooDeep = false;
  while (stack.length > 0) {
    const top = stack.pop();
    if (top === undefined) break;
    const { v, path, depth } = top;
    if (typeof v === 'string') {
      yield { item, path, text: v };
      continue;
    }
    if (v === null || typeof v !== 'object') continue;
    if (depth >= MAX_DEPTH) {
      tooDeep = true;
      continue;
    }
    // A path names where a hit is; it never carries the key text itself past
    // a few dozen characters (fix round 5, I-3: a 20 KB key was a 20 KB path,
    // six of them to a message).
    if (Array.isArray(v)) {
      for (let i = v.length - 1; i >= 0; i -= 1) stack.push({ v: v[i], path: capPath(`${path}[${i}]`), depth: depth + 1 });
      continue;
    }
    const entries = Object.entries(v as Record<string, unknown>);
    for (let i = entries.length - 1; i >= 0; i -= 1) {
      const entry = entries[i];
      if (entry === undefined) continue;
      const [key, child] = entry;
      const childPath = `${path}.${capSegment(key)}`;
      yield { item, path: `${capPath(childPath, MAX_PATH_CHARS - KEY_SUFFIX.length)}${KEY_SUFFIX}`, text: key };
      stack.push({ v: child, path: capPath(childPath), depth: depth + 1 });
    }
  }
  if (tooDeep) onTooDeep(item, root);
}

/** A name as it may appear in a finding: visible, and short. */
function shortName(name: string): string {
  const visible = escapeInvisible(name);
  return visible.length > 80 ? `${visible.slice(0, 80)}…` : visible;
}

interface ItemFields {
  item: string;
  fields: Iterable<TextField>;
  /** The item's own parameter names, lower-cased: a bare word naming one is a parameter (M7). */
  params: ReadonlySet<string>;
}

const NO_PARAMS: ReadonlySet<string> = new Set();
/** Parameter names kept per item: more than any real tool has. */
const MAX_PARAMS = 1000;

/** The top-level property names of a tool's input schema. */
function schemaParams(schema: unknown): ReadonlySet<string> {
  if (schema === null || typeof schema !== 'object') return NO_PARAMS;
  const props = (schema as Record<string, unknown>)['properties'];
  if (props === null || typeof props !== 'object' || Array.isArray(props)) return NO_PARAMS;
  const out = new Set<string>();
  for (const key in props) {
    if (out.size >= MAX_PARAMS) break;
    if (Object.hasOwn(props, key)) out.add(key.toLowerCase());
  }
  return out;
}

/** A prompt's argument names. */
function promptParams(args: unknown): ReadonlySet<string> {
  if (!Array.isArray(args)) return NO_PARAMS;
  const out = new Set<string>();
  for (const a of args.slice(0, MAX_PARAMS)) {
    const name: unknown = a !== null && typeof a === 'object' ? (a as Record<string, unknown>)['name'] : undefined;
    if (typeof name === 'string') out.add(name.toLowerCase());
  }
  return out;
}

function* itemsOf(listing: ServerListing, onTooDeep: OnTooDeep): Generator<ItemFields> {
  if (listing.instructions !== undefined) {
    yield {
      item: 'server instructions',
      fields: [{ item: 'server instructions', path: 'instructions', text: listing.instructions }],
      params: NO_PARAMS,
    };
  }
  for (const t of listing.tools) {
    const item = `tool '${shortName(t.name)}'`;
    yield {
      item,
      params: schemaParams(t.inputSchema),
      fields: (function* () {
        yield { item, path: 'name', text: t.name };
        if (t.title !== undefined) yield { item, path: 'title', text: t.title };
        if (t.description !== undefined) yield { item, path: 'description', text: t.description };
        yield* walkStrings(t.inputSchema, 'inputSchema', item, onTooDeep);
        yield* walkStrings(t.outputSchema, 'outputSchema', item, onTooDeep);
        yield* walkStrings(t.annotations, 'annotations', item, onTooDeep);
      })(),
    };
  }
  for (const p of listing.prompts) {
    const item = `prompt '${shortName(p.name)}'`;
    yield {
      item,
      params: promptParams(p.arguments),
      fields: (function* () {
        yield { item, path: 'name', text: p.name };
        if (p.title !== undefined) yield { item, path: 'title', text: p.title };
        if (p.description !== undefined) yield { item, path: 'description', text: p.description };
        yield* walkStrings(p.arguments, 'arguments', item, onTooDeep);
      })(),
    };
  }
  const resources = [
    ...listing.resources.map((r) => ({ r, kind: 'resource' })),
    ...(listing.resourceTemplates ?? []).map((r) => ({ r, kind: 'resource template' })),
  ];
  for (const { r, kind } of resources) {
    const item = `${kind} '${shortName(r.name)}'`;
    const fields: TextField[] = [{ item, path: 'name', text: r.name }];
    if (r.title !== undefined) fields.push({ item, path: 'title', text: r.title });
    if (r.description !== undefined) fields.push({ item, path: 'description', text: r.description });
    if (r.uri !== undefined) fields.push({ item, path: 'uri', text: r.uri });
    yield { item, fields, params: NO_PARAMS };
  }
}

/** A hit of one rule on one field. */
interface Hit {
  rule: McpRuleId;
  severity: Severity;
  subcategory: string;
  label: string;
  explain: string;
  field: TextField;
  /** Where in `field.text` the match starts, for the excerpt. */
  index: number;
  /** Extra evidence for the message (decoded tags, the tool named, …). */
  detail?: string;
}

const EXCERPT_BEFORE = 60;
const EXCERPT_AFTER = 120;

/** A short, single-line, visible excerpt around `index`. */
function excerpt(text: string, index: number): string {
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
function textRuleHits(field: TextField, params: ReadonlySet<string>): Hit[] {
  const hits: Hit[] = [];
  const folded = readAs(field.text);
  const texts = folded === field.text ? [field.text] : [field.text, folded];
  for (const rule of TEXT_RULES) {
    if (rule.id === 'mcp-tool-cross-server-shadowing') continue; // needs the other servers; see below
    let hit: Hit | null = null;
    for (const [i, text] of texts.entries()) {
      for (const pattern of rule.patterns) {
        pattern.lastIndex = 0;
        const m = pattern.exec(text);
        if (m === null) continue;
        hit = {
          ...ruleMeta(rule.id),
          field,
          index: Math.min(m.index, field.text.length),
          ...(i === 1 ? { detail: 'written with look-alike or compatibility characters' } : {}),
        };
        break;
      }
      if (hit !== null) break;
    }
    if (hit !== null) hits.push(hit);
  }
  return escalateSensitive(field, texts, hits, params);
}

const RULE_PATTERNS = (id: McpRuleId): readonly RegExp[] => TEXT_RULES.find((r) => r.id === id)?.patterns ?? [];
/** Passing it to a parameter, another tool or a URL, or hiding it: what makes a sensitive file high. */
const PASS_ON_OR_HIDE: readonly RegExp[] = [
  ...PASS_TO_DESTINATION,
  ...RULE_PATTERNS('mcp-tool-parameter-smuggling'),
  ...RULE_PATTERNS('mcp-tool-conceal-from-user'),
];

function matches(pattern: RegExp, text: string): boolean {
  pattern.lastIndex = 0;
  return pattern.test(text);
}

/**
 * The sentences of `text` and where each starts: a sentence ends at `.`,
 * `!` or `?` before whitespace or the end — a dot inside a path does not end
 * one — and at a line end.
 */
function sentencesOf(text: string): Array<{ text: string; start: number }> {
  const out: Array<{ text: string; start: number }> = [];
  let start = 0;
  for (let i = 0; i < text.length; i += 1) {
    const c = text[i];
    const next = text[i + 1];
    const ends = c === '\n' || ((c === '.' || c === '!' || c === '?') && (next === undefined || /\s/.test(next)));
    if (!ends) continue;
    out.push({ text: text.slice(start, i + 1), start });
    start = i + 1;
  }
  if (start < text.length) out.push({ text: text.slice(start), start });
  return out;
}

const HIGH_SENSITIVE = {
  severity: 'high' as const,
  label: 'an instruction to pass credential or agent-config files on',
  explain:
    'The text points the model at an SSH key, cloud or package-registry credentials, a .env file or an MCP ' +
    'host config AND, in the same sentence, tells it to pass that to a parameter, another tool or a URL, or ' +
    'to hide it from the user — the shape of tool-poisoning exfiltration. No tool needs that.',
};

/**
 * Fix rounds 4 and 5, M7: a sensitive path in a SENTENCE that also directs
 * passing it to a parameter, another tool or a URL, or hiding it, is high —
 * with or without a read verb. A bare word counts as a parameter only when
 * it names one of this item's own (`include it as sidenote` with a
 * `sidenote` parameter). Passing it into output — `include it in the
 * response/summary/report` — is medium: output goes to the user. Telling the
 * model only to read it stays medium: an SSH or registry helper may need
 * exactly that. Measured on the round-4 rule: matching the path and the
 * directive anywhere in the field made "Read ~/.ssh/config to find the host.
 * Then pass it as the `host` parameter." high.
 */
function escalateSensitive(field: TextField, texts: readonly string[], hits: Hit[], params: ReadonlySet<string>): Hit[] {
  let high: number | null = null;
  let weak: { at: number; word: string } | null = null;
  for (const text of texts) {
    if (!SENSITIVE_PATH_ANYWHERE.test(text)) continue;
    for (const s of sentencesOf(text)) {
      const path = SENSITIVE_PATH_ANYWHERE.exec(s.text);
      if (path === null) continue;
      const at = Math.min(s.start + path.index, field.text.length);
      if (PASS_ON_OR_HIDE.some((p) => matches(p, s.text))) {
        high = at;
        break;
      }
      const word = PASS_TO_WORD.exec(s.text)?.[1];
      if (word === undefined) continue;
      if (params.has(word.toLowerCase())) {
        high = at;
        break;
      }
      weak ??= { at, word: word.slice(0, 64) };
    }
    if (high !== null) break;
  }
  const existing = hits.findIndex((h) => h.rule === 'mcp-tool-sensitive-file-access');
  const withDetail = (h: Hit, detail: string): Hit => ({ ...h, detail: h.detail === undefined ? detail : `${h.detail}; ${detail}` });
  if (high !== null) {
    const detail = 'directs passing the file to a parameter, another tool or a URL, or hiding it, in the same sentence';
    const h = hits[existing];
    if (h !== undefined) {
      hits[existing] = withDetail({ ...h, ...HIGH_SENSITIVE }, detail);
      return hits;
    }
    return [...hits, { ...ruleMeta('mcp-tool-sensitive-file-access'), ...HIGH_SENSITIVE, field, index: high, detail }];
  }
  if (weak !== null) {
    const detail = `directs including the file in '${weak.word}' — output, not a parameter, a tool or a URL`;
    const h = hits[existing];
    if (h !== undefined) {
      hits[existing] = withDetail(h, detail);
      return hits;
    }
    return [...hits, { ...ruleMeta('mcp-tool-sensitive-file-access'), field, index: weak.at, detail }];
  }
  return hits;
}

function homoglyphHit(field: TextField): Hit | null {
  const mixed = mixedScriptWord(field.text);
  if (mixed === null) return null;
  return {
    ...ruleMeta('mcp-tool-homoglyph'),
    field,
    index: mixed.index,
    detail: `${JSON.stringify(escapeInvisible(mixed.word))} reads as ${JSON.stringify(readAs(mixed.word))}`,
  };
}

function ruleMeta(id: McpRuleId): Omit<Hit, 'field' | 'index' | 'detail'> {
  const rule = TEXT_RULES.find((r) => r.id === id);
  if (rule !== undefined) {
    return { rule: id, severity: rule.severity, subcategory: rule.subcategory, label: rule.label, explain: rule.explain };
  }
  switch (id) {
    case 'mcp-tool-hidden-unicode':
      return {
        rule: id,
        severity: 'high',
        subcategory: 'mcp_tool_poisoning',
        label: 'hidden Unicode',
        explain:
          'The text carries characters that render as nothing or reorder what is shown — invisible to anyone ' +
          'reviewing the tool list, read in full by the model.',
      };
    case 'mcp-tool-homoglyph':
      return {
        rule: id,
        severity: 'medium',
        subcategory: 'mcp_tool_poisoning',
        label: 'look-alike letters from another script',
        explain:
          'A word mixes Latin letters with Cyrillic or Greek look-alikes — it reads as one thing to a reviewer ' +
          'and is another string to every text check. Ordinary text in another alphabet does not trip this.',
      };
    case 'mcp-tool-encoded-blob':
      return {
        rule: id,
        severity: 'medium',
        subcategory: 'mcp_tool_poisoning',
        label: 'a large encoded blob',
        explain:
          'The text carries a long base64 run. A description has no use for one; an instruction encoded this ' +
          'way passes every plain-text check, and the model can decode it.',
      };
    case 'mcp-tool-schema-too-deep':
      return {
        rule: id,
        severity: 'medium',
        subcategory: 'mcp_tool_poisoning',
        label: 'a value nested too deep to analyse',
        explain:
          `A value is nested more than ${MAX_DEPTH} levels deep. No real schema needs that — a few levels is ` +
          'normal — and what lies deeper was not analysed; it is still covered by the pin.',
      };
    case 'mcp-tool-string-over-bound':
      return {
        rule: id,
        severity: 'medium',
        subcategory: 'mcp_tool_poisoning',
        label: 'a string too long to analyse',
        explain:
          `A single string is over ${ANALYSIS_BOUNDS.maxStringChars / 1024} KiB — no real tool definition needs ` +
          'one, and everything past that length was not analysed. The model reads all of it.',
      };
    case 'mcp-tool-cross-server-shadowing':
      return {
        rule: id,
        severity: 'high',
        subcategory: 'mcp_tool_poisoning',
        label: 'instructions about how other tools must behave',
        explain:
          'The text names a tool of another server. Every tool of every server shares one context, so a ' +
          "description can rewrite another server's behaviour (\"shadowing\") without ever being called itself.",
      };
    default:
      return {
        rule: id,
        severity: 'low',
        subcategory: 'mcp_tool_poisoning',
        label: 'an abnormally long description',
        explain:
          `The description is over ${OVERSIZED_DESCRIPTION_CHARS} characters. Length is no attack by itself, ` +
          'but it is where a payload hides below the part a reviewer reads.',
      };
  }
}

function hiddenUnicodeHit(field: TextField): Hit | null {
  const scan = scanInvisible(field.text);
  if (scan === null) return null;
  const tags = scan.decodedTags.trim();
  const selectors = scan.decodedSelectors.trim();
  const detail =
    `${scan.count} invisible code point(s): ${scan.kinds.join(', ')}` +
    (tags === '' ? '' : `; the tag characters spell ${JSON.stringify(tags.slice(0, 200))}`) +
    (selectors === '' ? '' : `; the variation selectors spell ${JSON.stringify(escapeInvisible(selectors).slice(0, 200))}`);
  return { ...ruleMeta('mcp-tool-hidden-unicode'), field, index: Math.max(0, scan.index), detail };
}

function blobHit(field: TextField): Hit | null {
  const blob = findEncodedBlob(field.text);
  if (blob === null) return null;
  const detail =
    `a ${blob.length}-character base64 run` +
    (blob.decodedText === null
      ? ' (it does not decode to readable text)'
      : ` that decodes to readable text: ${JSON.stringify(escapeInvisible(blob.decodedText).slice(0, 200))}`);
  const meta = ruleMeta('mcp-tool-encoded-blob');
  // Readable text hidden in an encoding is a stronger signal than bytes.
  return { ...meta, severity: blob.decodedText === null ? 'medium' : 'high', field, index: 0, detail };
}

/** On the FULL length: a description cut for analysis is still as long as it is. */
function oversizedHit(field: TextField, fullLength: number): Hit | null {
  if (field.path !== 'description' && field.path !== 'instructions') return null;
  if (fullLength <= OVERSIZED_DESCRIPTION_CHARS) return null;
  return {
    ...ruleMeta('mcp-tool-description-oversized'),
    field,
    index: Math.min(OVERSIZED_DESCRIPTION_CHARS, field.text.length),
    detail: `${fullLength} characters`,
  };
}

/** The generic "how other tools must behave" phrasings and `mcp__<server>__<tool>`; names come later. */
function genericShadowingHit(field: TextField, listing: ServerListing): Hit | null {
  const meta = ruleMeta('mcp-tool-cross-server-shadowing');
  // `mcp__<server>__<tool>`: how Claude Code names another server's tool.
  for (const m of field.text.matchAll(/\bmcp__([\w-]+?)__[\w-]+/g)) {
    if (m[1] !== undefined && m[1] !== listing.serverName) {
      return { ...meta, field, index: m.index, detail: `it names ${JSON.stringify(m[0])}, a tool of server '${m[1]}'` };
    }
  }
  const rule = TEXT_RULES.find((r) => r.id === 'mcp-tool-cross-server-shadowing');
  for (const pattern of rule?.patterns ?? []) {
    pattern.lastIndex = 0;
    const m = pattern.exec(field.text);
    if (m !== null) return { ...meta, field, index: m.index };
  }
  return null;
}

/**
 * A tool name is matched bare only when it cannot be an ordinary word —
 * `send_email`, `readFile`, `git.push` — and otherwise only in quotes or
 * backticks: `list` or `search` in prose is English, not a reference.
 */
function distinctive(name: string): boolean {
  return name.length >= 4 && /[_.-]|[a-z][A-Z]/.test(name);
}

/** Where a candidate name was first seen. */
export interface MentionRef {
  item: string;
  path: string;
}

/**
 * The names one server's text mentions, kept after its listing is dropped
 * so the cross-server check can run once every server is known (fix round
 * 4): distinctive bare tokens, and every short quoted string. Bounded by
 * `maxMentions`; `full` says the bound was hit.
 */
export interface MentionIndex {
  bare: Map<string, MentionRef>;
  quoted: Map<string, MentionRef>;
  full: boolean;
  /** Items that already have a shadowing finding (a generic phrasing): not reported twice. */
  reported: Set<string>;
}

function indexMentions(field: TextField, index: MentionIndex, max: number): void {
  const put = (map: Map<string, MentionRef>, name: string): void => {
    if (map.has(name)) return;
    if (index.bare.size + index.quoted.size >= max) {
      index.full = true;
      return;
    }
    map.set(name, { item: field.item, path: field.path });
  };
  for (const m of field.text.matchAll(/[A-Za-z0-9_][A-Za-z0-9_.-]*/g)) {
    const token = m[0].replace(/[.-]+$/, '');
    for (const candidate of [token, ...token.split('.')]) if (distinctive(candidate)) put(index.bare, candidate);
  }
  for (const m of field.text.matchAll(/[`'"]([^`'"\n]{1,128})[`'"]/g)) {
    if (m[1] !== undefined) put(index.quoted, m[1]);
  }
}

/** A server as the cross-server check sees it. */
export interface ShadowTarget {
  serverKey: string;
  serverName: string;
  sourceLabel: string;
  ownToolNames: ReadonlySet<string>;
}

interface NameMention {
  ref: MentionRef;
  name: string;
  server: string;
}

/**
 * Tools of OTHER servers that `mentions` names (fix round 3, I3: one lookup
 * per name, never a regex per name), the first per item of `target`.
 */
function mentionedNames(target: ShadowTarget, mentions: MentionIndex, others: readonly OtherServer[]): NameMention[] {
  const byItem = new Map<string, NameMention>();
  for (const other of others) {
    if (other.serverKey === target.serverKey) continue;
    for (const name of other.toolNames) {
      if (target.ownToolNames.has(name)) continue;
      const ref = (distinctive(name) ? mentions.bare.get(name) : undefined) ?? mentions.quoted.get(name);
      if (ref === undefined || byItem.has(ref.item)) continue;
      byItem.set(ref.item, { ref, name, server: other.serverName });
    }
  }
  return [...byItem.values()];
}

/**
 * The cross-server check for a server whose listing is gone: one finding
 * per item that names another server's tool — except an item already
 * reported for shadowing by its own phrasing.
 */
export function shadowingFromMentions(
  target: ShadowTarget,
  mentions: MentionIndex,
  others: readonly OtherServer[],
): Finding[] {
  const meta = ruleMeta('mcp-tool-cross-server-shadowing');
  const server = shortName(target.serverName);
  const hits = mentionedNames(target, mentions, others).filter((m) => !mentions.reported.has(m.ref.item));
  return hits.map(({ ref, name, server: otherServer }) =>
    makeFinding({
      tool: MCP_AUDIT_TOOL_NAME,
      rule_id: meta.rule,
      severity: meta.severity,
      category: 'security',
      subcategory: meta.subcategory,
      title: escapeInvisible(`MCP server '${server}', ${ref.item}: ${meta.label}`),
      message: escapeInvisible(
        `${meta.explain} Seen in ${ref.item} of server '${server}' (${target.sourceLabel}), field ${ref.path}. ` +
          `Evidence: it names '${name}', a tool of server '${otherServer}'.`,
      ),
      file_path: target.sourceLabel,
      snippet: escapeInvisible(`${server} > ${ref.item} > ${ref.path}: names '${name}'`),
      fix_available: false,
      ...taxonomyOf(meta.rule),
    }),
  );
}

/** `makeFinding`'s taxonomy for a rule (`rules.ts#mcpRuleTaxonomy`), or nothing: unmapped. */
function taxonomyOf(rule: string): { taxonomy?: { cwe: string[] } } {
  const taxonomy = mcpRuleTaxonomy(rule);
  return taxonomy === undefined ? {} : { taxonomy };
}

function itemKey(hit: Hit): string {
  return `${hit.rule}\u0000${hit.field.item}`;
}

export interface ListingAnalysis {
  findings: Finding[];
  /**
   * What a bound (or a stop) kept from being analysed: non-empty means the
   * listing was only partly analysed — never a clean result.
   */
  cuts: string[];
  /** The names this server's text mentions, for the cross-server check once every server is known. */
  mentions: MentionIndex;
}

interface AnalysisRun {
  listing: ServerListing;
  bounds: AnalysisBounds;
  groups: Map<string, Hit[]>;
  cuts: string[];
  mentions: MentionIndex;
  strings: number;
  chars: number;
}

function startRun(listing: ServerListing, bounds: AnalysisBounds): AnalysisRun {
  return {
    listing,
    bounds,
    groups: new Map(),
    cuts: [],
    mentions: { bare: new Map(), quoted: new Map(), full: false, reported: new Set() },
    strings: 0,
    chars: 0,
  };
}

function addHit(run: AnalysisRun, hit: Hit | null): void {
  if (hit === null) return;
  const key = itemKey(hit);
  const group = run.groups.get(key);
  if (group === undefined) run.groups.set(key, [hit]);
  else group.push(hit);
}

function formatChars(n: number): string {
  if (n % MiB === 0) return `${n / MiB} MiB`;
  if (n % 1024 === 0) return `${n / 1024} KiB`;
  return `${n} characters`;
}

/**
 * The analysis, one item at a time: yields after every item and, inside
 * one, after every {@link YIELD_EVERY_CHARS} characters analysed or
 * {@link YIELD_EVERY_MS} ms, so a driver can give the event loop a turn —
 * and stop — between them.
 */
function* analysisSteps(run: AnalysisRun): Generator<void> {
  const { listing, bounds } = run;
  let overlong = false;
  let charsSinceYield = 0;
  let lastYield = Date.now();
  const yieldDue = (): boolean => charsSinceYield >= YIELD_EVERY_CHARS || Date.now() - lastYield >= YIELD_EVERY_MS;
  const resumed = (): void => {
    charsSinceYield = 0;
    lastYield = Date.now();
  };
  // Nesting past the bound is a finding and a cut (fix round 5, I-1): a real
  // schema is a few levels deep; thousands is a value built to break things.
  const onTooDeep: OnTooDeep = (item, root) => {
    run.cuts.push(`${item} ${root}: nesting deeper than ${MAX_DEPTH} levels was not analysed`);
    addHit(run, {
      ...ruleMeta('mcp-tool-schema-too-deep'),
      field: { item, path: root, text: '' },
      index: 0,
      detail: `more than ${MAX_DEPTH} levels`,
    });
  };
  for (const { fields, params } of itemsOf(listing, onTooDeep)) {
    for (const field of fields) {
      if (run.strings >= bounds.maxStrings) {
        run.cuts.push(`more than ${bounds.maxStrings} strings; the rest was not analysed`);
        return;
      }
      if (run.chars >= bounds.maxTextChars) {
        run.cuts.push(`more than ${formatChars(bounds.maxTextChars)} of text; the rest was not analysed`);
        return;
      }
      run.strings += 1;
      const fullLength = field.text.length;
      let text = field.text;
      if (fullLength > bounds.maxStringChars) {
        addHit(run, {
          ...ruleMeta('mcp-tool-string-over-bound'),
          field: { ...field, text: field.text.slice(0, EXCERPT_AFTER * 2) },
          index: 0,
          detail: `${fullLength} characters`,
        });
        if (!overlong) {
          overlong = true;
          run.cuts.push(`strings over ${formatChars(bounds.maxStringChars)} were analysed only up to that length`);
        }
        text = text.slice(0, bounds.maxStringChars);
      }
      text = text.slice(0, bounds.maxTextChars - run.chars);
      run.chars += text.length;
      const analysed: TextField = text === field.text ? field : { ...field, text };
      for (const hit of textRuleHits(analysed, params)) addHit(run, hit);
      addHit(run, hiddenUnicodeHit(analysed));
      addHit(run, homoglyphHit(analysed));
      addHit(run, blobHit(analysed));
      addHit(run, oversizedHit(analysed, fullLength));
      const shadow = genericShadowingHit(analysed, listing);
      if (shadow !== null) run.mentions.reported.add(field.item);
      addHit(run, shadow);
      indexMentions(analysed, run.mentions, bounds.maxMentions);
      charsSinceYield += text.length;
      if (yieldDue()) {
        yield;
        resumed();
      }
    }
    yield;
    resumed();
  }
}

function finishRun(run: AnalysisRun, others: readonly OtherServer[]): ListingAnalysis {
  const { listing } = run;
  if (run.mentions.full) {
    run.cuts.push(`more than ${run.bounds.maxMentions} names mentioned; the cross-server check saw only those`);
  }
  // With the other servers known now, a name mention joins the item's other
  // shadowing evidence in one finding; the tool, which drops each listing
  // before the next server is known, calls shadowingFromMentions later.
  if (others.length > 0) {
    const target: ShadowTarget = {
      serverKey: listing.serverKey,
      serverName: listing.serverName,
      sourceLabel: listing.sourceLabel,
      ownToolNames: new Set(listing.tools.map((t) => t.name)),
    };
    const meta = ruleMeta('mcp-tool-cross-server-shadowing');
    for (const m of mentionedNames(target, run.mentions, others)) {
      addHit(run, {
        ...meta,
        field: { item: m.ref.item, path: m.ref.path, text: `names '${m.name}'` },
        index: 0,
        detail: `it names '${m.name}', a tool of server '${m.server}'`,
      });
    }
  }
  const findings: Finding[] = [];
  for (const hits of run.groups.values()) {
    const first = hits[0];
    if (first === undefined) continue;
    const severity = hits.reduce<Severity>((s, h) => (rank(h.severity) > rank(s) ? h.severity : s), first.severity);
    const paths = [...new Set(hits.map((h) => h.field.path))];
    const details = [...new Set(hits.flatMap((h) => (h.detail === undefined ? [] : [h.detail])))];
    const shownPaths = paths.slice(0, 6).join(', ') + (paths.length > 6 ? `, and ${paths.length - 6} more` : '');
    const server = shortName(listing.serverName);
    // Every string below may carry text the server chose; `escapeInvisible`
    // keeps an invisible payload from riding out in the audit's own output.
    findings.push(
      capFindingText(makeFinding({
        tool: MCP_AUDIT_TOOL_NAME,
        rule_id: first.rule,
        severity,
        category: 'security',
        subcategory: first.subcategory,
        title: escapeInvisible(`MCP server '${server}', ${first.field.item}: ${first.label}`),
        message: escapeInvisible(
          `${first.explain} Seen in ${first.field.item} of server '${server}' ` +
            `(${listing.sourceLabel}), field(s): ${shownPaths}.` +
            (details.length > 0 ? ` Evidence: ${details.slice(0, 3).join('; ')}.` : ''),
        ),
        file_path: listing.sourceLabel,
        snippet: escapeInvisible(
          `${server} > ${first.field.item} > ${first.field.path}: ${excerpt(first.field.text, first.index)}`,
        ),
        fix_available: false,
        ...taxonomyOf(first.rule),
      })),
    );
  }
  return { findings, cuts: run.cuts.map(escapeInvisible), mentions: run.mentions };
}

export function analyzeServerListing(listing: ServerListing, others: readonly OtherServer[]): Finding[] {
  return analyzeServerListingDetailed(listing, others).findings;
}

/** The whole analysis at once — for tests and small listings. The tool uses {@link analyzeServerListingAsync}. */
export function analyzeServerListingDetailed(
  listing: ServerListing,
  others: readonly OtherServer[],
  bounds: AnalysisBounds = ANALYSIS_BOUNDS,
): ListingAnalysis {
  const run = startRun(listing, bounds);
  for (const step of analysisSteps(run)) void step;
  return finishRun(run, others);
}

export interface AsyncAnalysisOptions {
  bounds?: AnalysisBounds;
  /** Asked between steps: a reason stops the analysis there (a cut, so the server is partial). */
  shouldStop?: () => string | null;
}

/**
 * The analysis as the tool runs it: a turn of the event loop between items
 * (and, inside one, every ~256 KiB of text or ~16 ms), so no listing stalls
 * the server, and a stop — cancel, the audit budget — honoured between them.
 */
export async function analyzeServerListingAsync(
  listing: ServerListing,
  others: readonly OtherServer[],
  options: AsyncAnalysisOptions = {},
): Promise<ListingAnalysis> {
  const run = startRun(listing, options.bounds ?? ANALYSIS_BOUNDS);
  const steps = analysisSteps(run);
  for (;;) {
    const stop = options.shouldStop?.() ?? null;
    if (stop !== null) {
      run.cuts.push(`analysis stopped: ${stop}`);
      break;
    }
    if (steps.next().done === true) break;
    await new Promise<void>((resolve) => setImmediate(resolve));
  }
  return finishRun(run, others);
}

const RANK: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

function rank(s: Severity): number {
  return RANK[s];
}
