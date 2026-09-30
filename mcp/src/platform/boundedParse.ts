/**
 * Parsing a repository's YAML and JSON without letting the file choose how
 * much memory and time the parse takes.
 *
 * A byte cap bounds what is READ, not what a parser builds from it. Measured
 * with `yaml` 2.x on Node 24 (review of 3.0, W2E): the plugin's own 83 KB
 * rule pack parses in ~70 ms and a few MB, but 1 MiB of `- {}` lines took
 * 6 s and 243 MB of heap, 1 MiB of `k: v` lines 5 s and 493 MB, and 8 MiB
 * 1.9–3.7 GB. `JSON.parse` is far cheaper per byte but not free: 60 MiB of
 * `[{},{},…]` under the 64 MiB lock-file cap was 1.35 GB and a 20 s block.
 *
 * YAML is judged in three gates, all before a value is built (round 3 of that
 * review, after the first gate was found to count only `\n { [ ,` — so
 * `- - - … x`, a million levels of nesting on ONE line, passed it and ran a
 * 768 MB server out of memory through `scan_sast`, the rule-id reader and
 * `scan_containers`):
 *
 *   1. BYTES — a configuration (Semgrep rules, a compose file, a workspace
 *      declaration, budgets) is parsed up to 1 MiB, twelve times the largest
 *      rule pack this repository ships (rgpd.yml, 85 KB); an API spec up to
 *      its 5 MiB read cap.
 *   2. INDICATORS — every character that can open, separate or decorate a
 *      YAML node is counted: a line break, `- ? : , [ ] { }`, the anchor,
 *      alias and tag marks `& * !`, the block-scalar and quote marks
 *      `| > ' "`, and `% @ \` #`. A node the parser builds needs at least one
 *      of them, so this over-counts and never under-counts. The real packs:
 *      rgpd.yml 12 836, the others under 9 000.
 *   3. DEPTH — the text is parsed to yaml's concrete syntax tree, whose
 *      parser keeps its own stack (no recursion), and the tree is walked
 *      without recursion; more than 64 nested collections is refused before
 *      the recursive composition ever runs. The real packs nest 7–18 deep.
 *
 * The composition then runs with duplicate-key checking off: `yaml` compares
 * each new key with every earlier one in its map, so one map of 50 000 keys
 * took more than 60 s (10 000: 2.6 s); without the check it is linear (50 000:
 * 2.2 s), and a later duplicate simply wins — Docker Compose and Semgrep
 * refuse such files themselves. More than one document is refused before any
 * is composed. Then the VALUE is bounded before it is built
 * ({@link expandedSize}): at most 1 000 aliases, a value of at most 500 000
 * nodes once they are followed (1 000 000 for a spec), and no alias inside
 * what it names. `yaml`'s own `maxAliasCount` is off, because its counting
 * walks the document again for every alias: a chain of anchored collections
 * holding aliases took 49 s to be refused by it.
 *
 * Measured in `node:22` under `--memory 768m` with a fuzz of 33 generated
 * shapes — nesting on one line and over lines, width, anchors, aliases, merge
 * keys, tags, directives, documents, comments, block scalars, escapes and
 * one error per line — each sized to the largest the gates admit, plus 400
 * seeded random documents (`test/unit/platform/yamlBounds.test.ts`,
 * `test/helpers/yamlFuzz.ts`): at the configuration bounds every admitted
 * parse took at most 0.54 s and 62 MB of heap, at the spec bounds 1.2 s and
 * 112 MB, and the random corpus 0.91 s and 101 MB. A text refused by any gate
 * is `too-large`, `too-complex`, `too-deep` or `too-expanded`, and the caller
 * treats it like any file it could not read: named, never "clean". The JSON
 * half is `platform/boundedJson.ts`, free of any package import.
 */

import { Composer, isAlias, isCollection, isPair, Parser, type CST, type Document } from 'yaml';
import { exceedsCount, type BoundedParse } from './boundedJson.js';

export { describeTooComplex, JSON_MAX_NODES, parseJsonBounded, type BoundedParse } from './boundedJson.js';

/** What a YAML text may be before it is parsed. */
export interface YamlLimits {
  /** UTF-16 code units (a byte or more each). */
  maxBytes: number;
  /** Indicator characters (see the module doc) — an over-count of the nodes. */
  maxNodes: number;
  /** Nested collections, measured on the syntax tree. */
  maxDepth: number;
  /** Nodes the value holds once every alias is followed (see {@link expandedSize}). */
  maxExpanded: number;
  /**
   * Aliases the document may hold: `yaml` resolves each one by scanning every
   * anchor and alias before it, so resolving them all is quadratic in their
   * number (measured in the fuzz: 16 665 aliases, 3.4 s).
   */
  maxAliases: number;
}

/** A configuration or rule file: Semgrep rules, a compose file, a workspace declaration, budgets. */
export const YAML_CONFIG_LIMITS: YamlLimits = { maxBytes: 1024 * 1024, maxNodes: 50_000, maxDepth: 64, maxExpanded: 500_000, maxAliases: 1_000 };
/** An API specification (map_attack_surface imports one per call; its read cap is 5 MiB). */
export const YAML_SPEC_LIMITS: YamlLimits = { maxBytes: 5 * 1024 * 1024, maxNodes: 100_000, maxDepth: 64, maxExpanded: 1_000_000, maxAliases: 1_000 };

/** Kept for callers that name the bound: the configuration's indicator bound. */
export const YAML_CONFIG_MAX_NODES = YAML_CONFIG_LIMITS.maxNodes;
export const YAML_SPEC_MAX_NODES = YAML_SPEC_LIMITS.maxNodes;

/** Every character that can open, separate or decorate a YAML node (see the module doc). */
const YAML_INDICATORS: ReadonlySet<number> = new Set([...'\n-?:,[]{}&*!|>\'"%@`#'].map((c) => c.charCodeAt(0)));

/** Why a YAML text is refused before parsing, or null. */
export type YamlRefusal = 'too-large' | 'too-complex' | 'too-deep' | 'too-expanded';

/** Gates 1 and 2 (bytes, indicators) — no parser involved. */
function preGate(text: string, limits: YamlLimits): YamlRefusal | null {
  if (text.length > limits.maxBytes) return 'too-large';
  if (exceedsCount(text, YAML_INDICATORS, limits.maxNodes)) return 'too-complex';
  return null;
}

/** Whether `text` is refused by the first two gates — asked without parsing. */
export function yamlTooComplex(text: string, limits: YamlLimits = YAML_CONFIG_LIMITS): boolean {
  return preGate(text, limits) !== null;
}

type CstToken = { type?: string; value?: unknown; items?: Array<{ key?: unknown; value?: unknown }> };

/** The deepest nesting of collections in yaml's syntax tree — walked with an explicit stack; stops past `limit`. */
function cstDepth(tokens: readonly unknown[], limit: number): number {
  const stack: Array<[unknown, number]> = tokens.map((t) => [t, 0]);
  let max = 0;
  while (stack.length > 0) {
    const top = stack.pop();
    if (top === undefined) break;
    const [t, depth] = top;
    if (typeof t !== 'object' || t === null) continue;
    const tok = t as CstToken;
    if (tok.type === 'block-map' || tok.type === 'block-seq' || tok.type === 'flow-collection') {
      const d = depth + 1;
      if (d > max) max = d;
      if (max > limit) return max;
      for (const item of tok.items ?? []) {
        if (item.key !== undefined && item.key !== null) stack.push([item.key, d]);
        if (item.value !== undefined && item.value !== null) stack.push([item.value, d]);
      }
    } else if (tok.type === 'document' && tok.value !== undefined) {
      stack.push([tok.value, depth]);
    }
  }
  return max;
}

/** The three gates; the syntax tree when all pass, for the composition to reuse. */
function gate(
  text: string,
  limits: YamlLimits,
): { tokens: CST.Token[] } | { refused: { ok: false; reason: YamlRefusal | 'invalid'; detail?: string } } {
  const refused = preGate(text, limits);
  if (refused !== null) return { refused: { ok: false, reason: refused } };
  try {
    const tokens: CST.Token[] = Array.from(new Parser().parse(text));
    // More than one document is refused before any is composed: composing each first cost 0.6–2.5 s
    // on 278 small invalid documents (the fuzz's slowest input).
    if (tokens.filter((t) => t.type === 'document').length > 1) {
      return { refused: { ok: false, reason: 'invalid', detail: 'the file holds more than one YAML document' } };
    }
    if (cstDepth(tokens, limits.maxDepth) > limits.maxDepth) return { refused: { ok: false, reason: 'too-deep' } };
    return { tokens };
  } catch (e) {
    return { refused: { ok: false, reason: 'invalid', detail: e instanceof Error ? e.message : String(e) } };
  }
}

/** Which gate refuses `text` (`invalid`: the syntax tree could not be built), or null — nothing composed. */
export function yamlGate(text: string, limits: YamlLimits = YAML_CONFIG_LIMITS): YamlRefusal | 'invalid' | null {
  const gated = gate(text, limits);
  return 'refused' in gated ? gated.refused.reason : null;
}

/** A node's children in document order: a pair's key and value, a collection's items. */
function childrenOf(n: object): unknown[] {
  if (isPair(n)) return [n.key, n.value];
  if (isCollection(n)) return n.items as unknown[];
  return [];
}

/**
 * How many nodes the document's VALUE holds once every alias is followed —
 * a "billion laughs" is a small document whose value is astronomically large
 * — counting past `max` no further; `cycle` for an alias inside the node it
 * names, which `toJS` turns into a circular object that any walk of the value
 * would follow for ever. Two passes with explicit stacks, each node once:
 *
 *   1. document order: each alias's target is the last node anchored with its
 *      name before it — `yaml`'s own rule (`Alias.resolve`);
 *   2. post-order, memoized: a node is 1 plus its children; an alias costs its
 *      target's total, so a DAG of shared anchors is counted as expanded.
 *
 * It replaces `yaml`'s `maxAliasCount`, whose own counting resolves every
 * alias in an anchored node by walking the whole document again: the fuzz's
 * chain of anchored collections holding aliases took 49 s to be refused.
 */
function expandedSize(doc: Document.Parsed, max: number, maxAliases: number): number | 'cycle' | 'aliases' {
  const targets = new Map<object, object>();
  const anchors = new Map<string, object>();
  let aliases = 0;
  const pending: unknown[] = [doc.contents];
  while (pending.length > 0) {
    const n = pending.pop();
    if (typeof n !== 'object' || n === null) continue;
    if (isAlias(n)) {
      aliases += 1;
      if (aliases > maxAliases) return 'aliases';
      const t = anchors.get(n.source);
      if (t !== undefined) targets.set(n, t);
      continue;
    }
    const anchor = (n as { anchor?: unknown }).anchor;
    if (typeof anchor === 'string') anchors.set(anchor, n);
    const kids = childrenOf(n);
    for (let i = kids.length - 1; i >= 0; i--) pending.push(kids[i]);
  }

  const sizes = new Map<object, number>();
  const onPath = new Set<object>();
  type Frame = { node: object; kids: unknown[]; next: number; sum: number };
  const stack: Frame[] = [];
  /** A child's size when already known, `cycle`, or undefined after pushing its frame. */
  const enter = (child: unknown): number | 'cycle' | undefined => {
    if (typeof child !== 'object' || child === null) return 1;
    let node: object = child;
    if (isAlias(node)) {
      const t = targets.get(node);
      if (t === undefined) return 1; // unresolved: toJS refuses it
      node = t;
    }
    if (onPath.has(node)) return 'cycle';
    const known = sizes.get(node);
    if (known !== undefined) return known;
    onPath.add(node);
    stack.push({ node, kids: childrenOf(node), next: 0, sum: 1 });
    return undefined;
  };
  const first = enter(doc.contents);
  if (first !== undefined) return first;
  while (stack.length > 0) {
    const frame = stack[stack.length - 1];
    if (frame === undefined) break;
    if (frame.next < frame.kids.length) {
      const got = enter(frame.kids[frame.next]);
      frame.next += 1;
      if (got === 'cycle') return 'cycle';
      if (got !== undefined) {
        frame.sum += got;
        if (frame.sum > max) return max + 1; // the value holds more than max: no need to count the rest
      }
      continue;
    }
    stack.pop();
    onPath.delete(frame.node);
    sizes.set(frame.node, frame.sum);
    const parent = stack[stack.length - 1];
    if (parent === undefined) return frame.sum;
    parent.sum += frame.sum;
    if (parent.sum > max) return max + 1;
  }
  return 0;
}

export type BoundedYamlDocument =
  | { ok: true; doc: Document.Parsed }
  | { ok: false; reason: YamlRefusal | 'invalid'; detail?: string };

/**
 * `text` as one YAML document, when it passes every gate. For a caller that
 * needs the document itself (source ranges); {@link parseYamlBounded} for the
 * value. More than one document, or a syntax error, is `invalid`.
 */
export function parseYamlDocumentBounded(text: string, limits: YamlLimits = YAML_CONFIG_LIMITS): BoundedYamlDocument {
  const gated = gate(text, limits);
  if ('refused' in gated) return gated.refused;
  let docs: Document.Parsed[];
  try {
    docs = Array.from(new Composer({ uniqueKeys: false }).compose(gated.tokens, true, text.length));
  } catch (e) {
    return { ok: false, reason: 'invalid', detail: e instanceof Error ? e.message : String(e) };
  }
  if (docs.length > 1) return { ok: false, reason: 'invalid', detail: 'the file holds more than one YAML document' };
  const doc = docs[0];
  if (doc === undefined) return { ok: false, reason: 'invalid', detail: 'no YAML document' };
  const error = doc.errors[0];
  if (error !== undefined) return { ok: false, reason: 'invalid', detail: error.message };
  const expanded = expandedSize(doc, limits.maxExpanded, limits.maxAliases);
  if (expanded === 'cycle') return { ok: false, reason: 'invalid', detail: 'an alias refers to the node that holds it' };
  if (expanded === 'aliases' || expanded > limits.maxExpanded) return { ok: false, reason: 'too-expanded' };
  return { ok: true, doc };
}

/**
 * The value of a document {@link parseYamlDocumentBounded} admitted. Its
 * aliases were counted and found acyclic there, so `yaml`'s own
 * `maxAliasCount` — quadratic in the document, and the fuzz's slowest input —
 * is off; an alias to a missing anchor still throws.
 */
export function yamlDocumentValue(doc: Document.Parsed): unknown {
  return doc.toJS({ maxAliasCount: -1 }) as unknown;
}

/** `yaml`'s value of `text`, when it passes every gate (see the module doc). */
export function parseYamlBounded(text: string, limits: YamlLimits = YAML_CONFIG_LIMITS): BoundedParse {
  const parsed = parseYamlDocumentBounded(text, limits);
  if (!parsed.ok) return parsed.detail === undefined ? { ok: false, reason: parsed.reason } : { ok: false, reason: parsed.reason, detail: parsed.detail };
  try {
    return { ok: true, value: yamlDocumentValue(parsed.doc) };
  } catch (e) {
    return { ok: false, reason: 'invalid', detail: e instanceof Error ? e.message : String(e) };
  }
}

/** A sentence for any refusal of {@link parseYamlBounded} / {@link parseYamlDocumentBounded}. */
export function describeYamlRefusal(
  parsed: { reason: YamlRefusal | 'invalid'; detail?: string },
  limits: YamlLimits = YAML_CONFIG_LIMITS,
): string {
  switch (parsed.reason) {
    case 'too-large':
      return `it is larger than the ${Math.round(limits.maxBytes / 1024)} KiB dev-guardian parses as YAML, and was not read`;
    case 'too-complex':
      return `it holds more than ${limits.maxNodes} YAML indicators (a bound on its nodes), more than dev-guardian parses — a parse that large can exhaust the server's memory — and was not read`;
    case 'too-deep':
      return `it nests collections more than ${limits.maxDepth} deep, more than dev-guardian parses, and was not read`;
    case 'too-expanded':
      return `it holds more than ${limits.maxAliases} aliases, or its aliases expand it to more than ${limits.maxExpanded} nodes — more than dev-guardian parses — and it was not read`;
    default:
      return `not valid YAML${parsed.detail !== undefined ? ` (${parsed.detail.split('\n')[0] ?? ''})` : ''}`;
  }
}
