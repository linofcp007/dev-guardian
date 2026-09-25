/**
 * Readers for the plugin's prose surface — `commands/*.md` and
 * `skills/<name>/SKILL.md` — shared by the tests that hold that surface to the
 * MCP tools it drives.
 *
 * Two things live here and nowhere else:
 *
 *   - frontmatter parsing with the `yaml` package, the same way a strict YAML
 *     loader reads it. Two skills shipped with an unquoted `: ` inside
 *     `description:`, which a strict loader rejects outright; a regex-based
 *     reader would never have noticed.
 *   - a small parser for the tool-call spellings the docs use —
 *     `tool_name { key: value, nested: { key: value } }` and
 *     `tool_name(key=value, key?)` — so every parameter a command or skill
 *     tells the model to pass can be checked against the registered zod
 *     schema, nested keys (`scope.diff.base`) and enum values included.
 */

import { readdirSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse as parseYaml } from 'yaml';
import type { ZodTypeAny } from 'zod';

export const REPO_ROOT = resolve(fileURLToPath(new URL('../../../..', import.meta.url)));
export const COMMANDS_DIR = resolve(REPO_ROOT, 'commands');
export const SKILLS_DIR = resolve(REPO_ROOT, 'skills');

export interface PluginDoc {
  /** Repo-relative, POSIX. */
  rel: string;
  kind: 'command' | 'skill';
  /** Command file stem or skill directory name — what `/name` invokes. */
  name: string;
  text: string;
  /** The raw frontmatter block, without the `---` fences. */
  frontmatterRaw: string;
  body: string;
}

const FRONTMATTER = /^---\r?\n([\s\S]*?)\r?\n---\r?\n([\s\S]*)$/;

function load(rel: string, kind: PluginDoc['kind'], name: string): PluginDoc {
  const text = readFileSync(resolve(REPO_ROOT, rel), 'utf8');
  const m = FRONTMATTER.exec(text);
  return { rel, kind, name, text, frontmatterRaw: m?.[1] ?? '', body: m?.[2] ?? text };
}

export function commandDocs(): PluginDoc[] {
  return readdirSync(COMMANDS_DIR)
    .filter((f) => f.endsWith('.md'))
    .sort()
    .map((f) => load(`commands/${f}`, 'command', f.slice(0, -'.md'.length)));
}

export function skillDocs(): PluginDoc[] {
  return readdirSync(SKILLS_DIR, { withFileTypes: true })
    .filter((d) => d.isDirectory())
    .map((d) => d.name)
    .sort()
    .map((name) => load(`skills/${name}/SKILL.md`, 'skill', name));
}

export function allDocs(): PluginDoc[] {
  return [...commandDocs(), ...skillDocs()];
}

/** The frontmatter as a strict YAML loader sees it; throws on invalid YAML. */
export function frontmatter(doc: PluginDoc): Record<string, unknown> {
  const parsed: unknown = parseYaml(doc.frontmatterRaw);
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error(`${doc.rel}: frontmatter is not a mapping`);
  }
  return parsed as Record<string, unknown>;
}

// ---------------------------------------------------------------- zod shapes

interface ZodDefLike {
  typeName?: string;
  innerType?: ZodTypeAny;
  schema?: ZodTypeAny;
  type?: ZodTypeAny;
  values?: unknown;
  shape?: () => Record<string, ZodTypeAny>;
}

function def(t: ZodTypeAny): ZodDefLike {
  return t._def as ZodDefLike;
}

/** Strip optional / default / nullable / effects wrappers. */
export function unwrap(t: ZodTypeAny): ZodTypeAny {
  let cur = t;
  for (;;) {
    const d = def(cur);
    const next = d.innerType ?? (d.typeName === 'ZodEffects' ? d.schema : undefined);
    if (next === undefined) return cur;
    cur = next;
  }
}

export function objectShape(t: ZodTypeAny): Record<string, ZodTypeAny> | null {
  const d = def(unwrap(t));
  return d.typeName === 'ZodObject' && d.shape ? d.shape() : null;
}

/** The allowed literals of an enum field, or of an array-of-enum field. */
export function enumValues(t: ZodTypeAny): readonly string[] | null {
  const inner = unwrap(t);
  const d = def(inner);
  if (d.typeName === 'ZodEnum' && Array.isArray(d.values)) return d.values.map(String);
  if (d.typeName === 'ZodArray' && d.type) return enumValues(d.type);
  return null;
}

// ---------------------------------------------------------- tool-call parser

export interface ToolCallRef {
  tool: string;
  /** Each key path the call names, e.g. `['scope', 'diff', 'base']`. */
  keys: { path: string[]; literals: string[] }[];
  /** The source text of the call, for error messages. */
  snippet: string;
}

const CALL_HEAD = /\b([a-z][a-z0-9]*(?:_[a-z0-9]+)+)[ \t]*([({])/g;

/** Index just past the bracket that closes the one at `open`, or -1. */
function matchBracket(src: string, open: number): number {
  const pairs: Record<string, string> = { '(': ')', '{': '}', '[': ']' };
  const stack: string[] = [];
  let quote: string | null = null;
  for (let i = open; i < src.length; i++) {
    const c = src[i] ?? '';
    if (quote !== null) {
      if (c === '\\') i++;
      else if (c === quote) quote = null;
      continue;
    }
    if (c === '"' || c === "'") {
      quote = c;
      continue;
    }
    const close = pairs[c];
    if (close !== undefined) stack.push(close);
    else if (c === stack[stack.length - 1]) {
      stack.pop();
      if (stack.length === 0) return i + 1;
    } else if (c === '\n' && src[i + 1] === '\n') {
      return -1; // a call never spans a blank line — this was prose
    }
  }
  return -1;
}

/** Split `src` on top-level commas (outside quotes and brackets). */
function splitTop(src: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let quote: string | null = null;
  let start = 0;
  for (let i = 0; i < src.length; i++) {
    const c = src[i] ?? '';
    if (quote !== null) {
      if (c === '\\') i++;
      else if (c === quote) quote = null;
      continue;
    }
    if (c === '"' || c === "'") quote = c;
    else if (c === '(' || c === '{' || c === '[') depth++;
    else if (c === ')' || c === '}' || c === ']') depth--;
    else if (c === ',' && depth === 0) {
      out.push(src.slice(start, i));
      start = i + 1;
    }
  }
  out.push(src.slice(start));
  return out.map((s) => s.trim()).filter((s) => s !== '' && s !== '...' && s !== '…');
}

/** Quoted string literals directly in a value (`"a"` or `["a", "b"]`). */
function literalsOf(value: string): string[] {
  const v = value.trim();
  const inner = v.startsWith('[') && v.endsWith(']') ? v.slice(1, -1) : v;
  return splitTop(inner)
    .map((s) => /^"([^"]*)"$|^'([^']*)'$/.exec(s))
    .flatMap((m) => (m === null ? [] : [m[1] ?? m[2] ?? '']));
}

/** Key paths of a `{ key: value, ... }` block (body without the braces). */
function objectKeys(body: string, prefix: string[], out: ToolCallRef['keys']): void {
  for (const entry of splitTop(body)) {
    const m = /^["']?([A-Za-z_][A-Za-z0-9_]*)["']?\s*:\s*([\s\S]*)$/.exec(entry);
    if (m === null) throw new Error(`not a key: value entry: ${entry}`);
    const key = m[1] ?? '';
    const value = (m[2] ?? '').trim();
    const path = [...prefix, key];
    out.push({ path, literals: literalsOf(value) });
    if (value.startsWith('{') && value.endsWith('}')) objectKeys(value.slice(1, -1), path, out);
  }
}

/** Key paths of a `(key=value, key?, key)` argument list. */
function argKeys(body: string, out: ToolCallRef['keys']): void {
  for (const entry of splitTop(body)) {
    const m = /^([A-Za-z_][A-Za-z0-9_]*)\s*(?:\?|=\s*([\s\S]*))?$/.exec(entry);
    if (m === null) throw new Error(`not a key=value argument: ${entry}`);
    const value = (m[2] ?? '').trim();
    out.push({ path: [m[1] ?? ''], literals: literalsOf(value) });
    if (value.startsWith('{') && value.endsWith('}')) objectKeys(value.slice(1, -1), [m[1] ?? ''], out);
  }
}

/**
 * Every `name { … }` / `name(…)` call in `text` whose name satisfies
 * `isCandidate` — the caller decides which snake_case names count as tools,
 * so a Python `select_related(...)` in a code sample is not mistaken for one.
 */
export function toolCalls(text: string, isCandidate: (name: string) => boolean): ToolCallRef[] {
  const calls: ToolCallRef[] = [];
  for (const m of text.matchAll(CALL_HEAD)) {
    const tool = m[1] ?? '';
    if (!isCandidate(tool)) continue;
    const open = (m.index ?? 0) + m[0].length - 1;
    const end = matchBracket(text, open);
    const snippet = end === -1 ? text.slice(m.index ?? 0, open + 40) : text.slice(m.index ?? 0, end);
    if (end === -1) throw new Error(`unbalanced tool call: ${snippet}`);
    const body = text.slice(open + 1, end - 1);
    const keys: ToolCallRef['keys'] = [];
    try {
      if (m[2] === '{') objectKeys(body, [], keys);
      else argKeys(body, keys);
    } catch (e) {
      throw new Error(`${(e as Error).message}\n  in: ${snippet}`);
    }
    calls.push({ tool, keys, snippet });
  }
  return calls;
}

/** Single-backtick spans (not fenced blocks) in `text`. */
export function inlineCode(text: string): string[] {
  const withoutFences = text.replace(/```[\s\S]*?```/g, '');
  return [...withoutFences.matchAll(/`([^`\n]+)`/g)].map((m) => m[1] ?? '');
}
