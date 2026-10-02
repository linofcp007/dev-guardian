/**
 * Briefs — the self-contained text a task is handed out with (US-1.AC-2).
 *
 * A verify brief carries the finding (tool, rule, message, `file:line`), the
 * code around it (the function holding the line, at most 200 lines) between
 * two copies of a random boundary marker, the response schema, and the
 * instruction that everything between the markers is data. Secrets the
 * existing detectors find are replaced by `‹rule line n›` markers (the whole
 * line goes: the detector reports where a secret is, not its extent) before
 * anything reaches the brief (US-1.AC-13). A brief never exceeds
 * {@link MAX_BRIEF_TOKENS} estimated tokens.
 *
 * Templates: `configs/llm-scan/prompts/<version>/{verify,hunt-entrypoint,hunt-crosscut}.md`.
 * Project files are read through the injected contained reader; the templates
 * are plugin files, found like `configs/semgrep/*.yml` (`resolveConfigsDir`)
 * and read once. One substitution pass fills a template, so a `{…}` inside
 * quoted code is never expanded again.
 */

import { randomBytes } from 'node:crypto';
import { join } from 'node:path';
import { readSmallText } from '../hooks/configFile.js';
import { scanForSecrets } from '../hooks/secretScan.js';
import { resolveConfigsDir } from '../platform/configsDir.js';
import type { Finding, RouteRecord } from '../types.js';
import { HUNT_CLASSES } from './classes.js';
import { entryPointId } from './plan.js';
import { MAX_EVIDENCE_WORDS, MAX_HUNT_FINDINGS, MAX_REASONING_WORDS, MAX_TITLE_CHARS, type ProjectReader } from './submission.js';
import type { LlmScanTask } from './types.js';

/** US-1.AC-2, US-3.AC-3 */
export const MAX_BRIEF_TOKENS = 25_000;
/** US-1.AC-12: the verify brief's P95 over the verification set. */
export const VERIFY_BRIEF_P95_TOKENS = 8_000;
/** The excerpt is the function holding the line, at most this many lines. */
export const MAX_EXCERPT_LINES = 200;
/** The prompt version a brief is rendered with unless the plan names another. */
export const CURRENT_PROMPT_VERSION = 'v1';

/**
 * Size caps per part, so a brief stays far under {@link MAX_BRIEF_TOKENS}
 * whatever a scanner or a file holds, and a verify brief keeps its P95 under
 * {@link VERIFY_BRIEF_P95_TOKENS} (a template is about 1.5k tokens).
 */
const MAX_EXCERPT_CHARS = 20_000;
const MAX_LINE_CHARS = 400;
const MAX_FLAGGED_LINE_CHARS = 2_000;
const MAX_MESSAGE_CHARS = 4_000;
const MAX_SNIPPET_CHARS = 2_000;
const MAX_LIST_CHARS = 12_000;
const MAX_LIST_ITEMS = 200;
const MAX_FINDING_MESSAGE_CHARS = 300;
/** How far above the flagged line the enclosing function's start is looked for. */
const MAX_LOOKBACK_LINES = 400;
const BOUNDARY_TRIES = 20;

export interface BriefContext {
  /** Canonical project root. */
  root: string;
  /** The contained reader (`readProjectText` in production). */
  reader: ProjectReader;
  /** The marker that delimits quoted code: random per brief in production, seeded in tests. */
  boundary: () => string;
  /** The scanner finding a verify task checks. */
  finding?: Finding;
  /** The routes a hunt task covers. */
  entry_points?: RouteRecord[];
  /** What scanners already reported in the task's files (hunt). */
  scanner_findings?: Finding[];
  /** Default: the current prompt version. */
  prompt_version?: string;
  /** The ceiling a brief is held to, in estimated tokens. Default {@link MAX_BRIEF_TOKENS}; lower only in tests. */
  max_tokens?: number;
}

export interface RenderedBrief {
  text: string;
  /** `text.length` */
  chars: number;
  /** chars / 4 — the design's estimate. */
  estimated_tokens: number;
}

/** A fresh unguessable boundary marker: the production {@link BriefContext.boundary}. */
export function randomBoundary(): string {
  return `BOUNDARY-${randomBytes(12).toString('hex')}`;
}

export function estimateTokens(text: string): number {
  return Math.ceil(text.length / 4);
}

// ---- templates -------------------------------------------------------------

const TEMPLATE_NAMES = { verify: 'verify', hunt: 'hunt-entrypoint', crosscut: 'hunt-crosscut' } as const;
const templateCache = new Map<string, string>();

/** A template, read once. A missing or unreadable one is a fixed-text error. */
function loadTemplate(version: string, name: string): string {
  const key = `${version}/${name}`;
  const cached = templateCache.get(key);
  if (cached !== undefined) return cached;
  if (!/^v[0-9]+$/.test(version)) throw new Error('llm-scan prompt version is not of the form vN');
  const read = readSmallText(join(resolveConfigsDir(), 'llm-scan', 'prompts', version, `${name}.md`), 256 * 1024);
  if (read.status !== 'ok') throw new Error(`llm-scan prompt template ${key}.md is not available (${read.status}); the plugin install is incomplete`);
  // The provenance comment on the first line (NFR-4) documents the file; it is not part of the prompt.
  const text = read.text.replace(/^<!--[^\n]*-->\r?\n+/, '');
  templateCache.set(key, text);
  return text;
}

// ---- response schemas ------------------------------------------------------

const VERIFY_SCHEMA = JSON.stringify(
  {
    type: 'object',
    additionalProperties: false,
    required: ['verdict', 'attacker_input', 'operation', 'decisive_line', 'reasoning'],
    properties: {
      verdict: { enum: ['real', 'not_real', 'undetermined'] },
      attacker_input: { type: 'string', description: 'file:line, or "none"' },
      operation: { type: 'string', description: 'file:line' },
      decisive_line: { type: 'string', description: 'file:line — reason' },
      reasoning: { type: 'string', description: `at most ${String(MAX_REASONING_WORDS)} words` },
    },
  },
  null,
  2,
);

const HUNT_SCHEMA = JSON.stringify(
  {
    type: 'object',
    additionalProperties: false,
    required: ['entry_points_reviewed', 'findings'],
    properties: {
      entry_points_reviewed: { type: 'array', items: { type: 'string' } },
      findings: {
        type: 'array',
        maxItems: MAX_HUNT_FINDINGS,
        items: {
          type: 'object',
          additionalProperties: false,
          required: ['file', 'line', 'class', 'title', 'attacker', 'evidence'],
          properties: {
            file: { type: 'string', description: 'project-relative path' },
            line: { type: 'integer', minimum: 1 },
            class: { enum: [...HUNT_CLASSES] },
            title: { type: 'string', maxLength: MAX_TITLE_CHARS },
            attacker: { type: 'string', maxLength: MAX_TITLE_CHARS },
            evidence: { type: 'string', description: `at most ${String(MAX_EVIDENCE_WORDS)} words, with at least one file:line` },
          },
        },
      },
    },
  },
  null,
  2,
);

// ---- secrets ---------------------------------------------------------------

/**
 * `text` with every line that holds a detected secret replaced by
 * `‹rule line n›` (n counted from `firstLine`). The detector reports where a
 * secret is, never its extent, so the whole line goes; a private key's body
 * goes with its header, up to the END line.
 */
function scrubSecrets(text: string, firstLine = 1): string {
  const hits = scanForSecrets(text);
  if (hits.length === 0) return text;
  const lines = text.split(/\r?\n/);
  const rulesByLine = new Map<number, string[]>();
  const keyBody = new Set<number>();
  for (const h of hits) {
    const at = h.line - 1;
    rulesByLine.set(at, [...(rulesByLine.get(at) ?? []), h.ruleId]);
    if (h.ruleId !== 'private-key-block') continue;
    for (let i = at + 1; i < lines.length; i += 1) {
      keyBody.add(i);
      if ((lines[i] ?? '').includes('-----END')) break;
    }
  }
  return lines
    .map((line, i) => {
      const rules = rulesByLine.get(i);
      if (rules === undefined) return keyBody.has(i) ? '‹private key body removed›' : line;
      const indent = /^\s*/.exec(line)?.[0] ?? '';
      return `${indent}‹${rules.join(', ')} line ${String(firstLine + i)}›`;
    })
    .join('\n');
}

const clip = (s: string, max: number): string => (s.length <= max ? s : `${s.slice(0, max)} …[cut, ${String(s.length - max)} more characters]`);

// ---- the excerpt -----------------------------------------------------------

const CONTROL_WORDS = /^(?:if|else|elif|for|foreach|while|do|switch|case|catch|try|finally|with|return|await|throw|synchronized|using|lock|until|unless)\b/;
const indentOf = (line: string): number => (/^[ \t]*/.exec(line)?.[0] ?? '').replace(/\t/g, '    ').length;

/**
 * A heuristic over text only (no parser, so any language): a declaration line
 * of a function or method — a keyword form, an arrow function, or a
 * call-shaped header that opens a block and is not a control statement.
 */
function startsFunction(line: string): boolean {
  const t = line.trim();
  if (t === '' || CONTROL_WORDS.test(t)) return false;
  if (/^(?:(?:export|public|private|protected|static|async|final|override|abstract|default|pub|unsafe|extern|const)\s+)*(?:function\*?|def|func|fn|fun|sub)\b/.test(t)) return true;
  if (/=>\s*\{?\s*$/.test(t)) return true;
  return /\w\s*\([^;]*\)\s*(?:->\s*[^{]+|:\s*[\w<>[\]|., ]+|throws\s+[\w., ]+)?\s*\{?\s*:?\s*$/.test(t) && /[{:]\s*$/.test(t);
}

/** 1-based inclusive range of the lines to quote around `flagged`. */
function excerptRange(lines: readonly string[], flagged: number): [number, number] {
  const total = lines.length;
  const at = Math.min(Math.max(flagged, 1), total);
  const window = (): [number, number] => {
    const s = Math.max(1, Math.min(at - 99, total - MAX_EXCERPT_LINES + 1));
    return [s, Math.min(total, s + MAX_EXCERPT_LINES - 1)];
  };
  const flaggedIndent = indentOf(lines[at - 1] ?? '');
  let start = 0;
  for (let n = at; n >= 1 && at - n <= MAX_LOOKBACK_LINES; n -= 1) {
    const line = lines[n - 1] ?? '';
    if (line.trim() === '' || !startsFunction(line)) continue;
    if (indentOf(line) < flaggedIndent || n === at) {
      start = n;
      break;
    }
  }
  if (start === 0) return window();
  const startIndent = indentOf(lines[start - 1] ?? '');
  let end = total;
  for (let n = start + 1; n <= total; n += 1) {
    const line = lines[n - 1] ?? '';
    if (line.trim() === '' || indentOf(line) > startIndent) continue;
    end = /^\s*(?:[})\]]|end\b)/.test(line) ? n : n - 1;
    break;
  }
  while (end > at && (lines[end - 1] ?? '').trim() === '') end -= 1;
  if (end < at) return window();
  if (end - start + 1 <= MAX_EXCERPT_LINES) return [start, end];
  const s = Math.max(start, Math.min(at - 99, end - MAX_EXCERPT_LINES + 1));
  return [s, s + MAX_EXCERPT_LINES - 1];
}

/** The numbered, secret-free, size-capped quote of the code around `flagged`; `>` marks the flagged line. */
function renderExcerpt(text: string, flagged: number | undefined, maxChars: number = MAX_EXCERPT_CHARS): string {
  const lines = text.split(/\r?\n/);
  // A line past the end of the file (a stale scan) marks the last line, and the excerpt says so.
  const beyond = flagged !== undefined && flagged > lines.length;
  const at = Math.min(Math.max(flagged ?? 1, 1), lines.length);
  const note = beyond ? `(the flagged line ${String(flagged)} is beyond the end of the file; the last line, ${String(at)}, is marked)\n` : '';
  const [from, to] = excerptRange(lines, at);
  const scrubbed = scrubSecrets(lines.slice(from - 1, to).join('\n'), from).split('\n');
  const width = String(to).length;
  const rows = scrubbed.map((line, i) => {
    const n = from + i;
    const cap = n === at ? MAX_FLAGGED_LINE_CHARS : MAX_LINE_CHARS;
    return `${n === at ? '>' : ' '}${String(n).padStart(width)} | ${clip(line, cap)}`;
  });
  // Over the character cap: drop lines from the end farther from the flagged one.
  let lo = 0;
  let hi = rows.length;
  let size = rows.reduce((a, r) => a + r.length + 1, 0);
  const flaggedIdx = at - from;
  while (size > maxChars && hi - lo > 1) {
    if (flaggedIdx - lo >= hi - 1 - flaggedIdx) size -= (rows[lo++] ?? '').length + 1;
    else size -= (rows[--hi] ?? '').length + 1;
  }
  return note + rows.slice(lo, hi).join('\n');
}

// ---- parts -----------------------------------------------------------------

function renderFinding(f: Finding, file: string | undefined): string {
  const line = file !== undefined && f.line_start !== undefined ? `:${String(f.line_start)}` : '';
  const rows = [
    `tool: ${scrubSecrets(f.tool)}`,
    `rule: ${scrubSecrets(f.rule_id ?? '(none)')}`,
    `severity: ${f.severity}`,
    `location: ${file === undefined ? '(no file)' : scrubSecrets(file)}${line}`,
    `title: ${clip(scrubSecrets(f.title), 300)}`,
    `message: ${clip(scrubSecrets(f.message ?? ''), MAX_MESSAGE_CHARS)}`,
  ];
  if (f.snippet !== undefined && f.snippet !== '') rows.push(`snippet: ${clip(scrubSecrets(f.snippet), MAX_SNIPPET_CHARS)}`);
  return rows.join('\n');
}

function renderList(items: readonly string[], more: string): string {
  if (items.length === 0) return '(none)';
  const out: string[] = [];
  let size = 0;
  for (const item of items.slice(0, MAX_LIST_ITEMS)) {
    if (size + item.length > MAX_LIST_CHARS) break;
    out.push(item);
    size += item.length + 1;
  }
  if (out.length < items.length) out.push(`(${String(items.length - out.length)} more ${more} not listed)`);
  return out.join('\n');
}

function renderScannerFindings(findings: readonly Finding[] | undefined): string {
  return renderList(
    (findings ?? []).map((f) => {
      const where = f.file_path !== undefined ? ` at ${scrubSecrets(f.file_path)}${f.line_start !== undefined ? `:${String(f.line_start)}` : ''}` : '';
      const msg = scrubSecrets(f.message ?? f.title).replace(/\s+/g, ' ');
      return `- ${scrubSecrets(f.tool)} ${scrubSecrets(f.rule_id ?? '(none)')}${where}: ${clip(msg, MAX_FINDING_MESSAGE_CHARS)}`;
    }),
    'findings',
  );
}

/**
 * The entry points a hunt starts from: the routes' stable ids; else the ids the
 * task names; else (the crosscut task) its files; else `(none)` — never a
 * literal placeholder.
 */
function renderEntryPoints(task: LlmScanTask, ctx: BriefContext): string {
  const ids =
    ctx.entry_points !== undefined && ctx.entry_points.length > 0
      ? ctx.entry_points.map((r) => entryPointId(r, ctx.root))
      : (task.target.entry_points ?? []);
  // A route literal or a path can hold a token: the ids go through the same scrub as the code.
  return renderList((ids.length > 0 ? ids : task.target.files).map((id) => scrubSecrets(id)), 'entry points');
}

interface VerifyData {
  finding: string;
  excerpt: string;
  /** The excerpt again within a smaller character budget (the flagged line always stays). */
  excerptWithin?: (maxChars: number) => string;
}

function renderVerifyData(task: LlmScanTask, ctx: BriefContext): VerifyData {
  const f = ctx.finding;
  if (f === undefined) throw new Error('a verify brief needs the scanner finding');
  const file = task.target.files[0] ?? f.file_path;
  if (file === undefined || file === '') return { finding: renderFinding(f, undefined), excerpt: '(the finding names no file)' };
  const read = ctx.reader(ctx.root, file);
  if (read.status !== 'ok') return { finding: renderFinding(f, file), excerpt: `(the file could not be read: ${read.status})` };
  const text = read.text;
  return {
    finding: renderFinding(f, file),
    excerpt: renderExcerpt(text, f.line_start),
    excerptWithin: (maxChars) => renderExcerpt(text, f.line_start, maxChars),
  };
}

// ---- rendering -------------------------------------------------------------

export function renderBrief(task: LlmScanTask, ctx: BriefContext): RenderedBrief {
  const template = loadTemplate(ctx.prompt_version ?? CURRENT_PROMPT_VERSION, TEMPLATE_NAMES[task.kind]);
  let excerptWithin: ((maxChars: number) => string) | undefined;
  let values: Record<string, string>;
  if (task.kind === 'verify') {
    const { excerptWithin: within, ...data } = renderVerifyData(task, ctx);
    excerptWithin = within;
    values = { ...data, schema: VERIFY_SCHEMA };
  } else {
    values = { entry_points: renderEntryPoints(task, ctx), scanner_findings: renderScannerFindings(ctx.scanner_findings), schema: HUNT_SCHEMA };
  }
  // The marker must not occur in anything it fences, or the data could close its own block.
  let boundary = ctx.boundary();
  for (let tries = 1; Object.values(values).some((v) => v.includes(boundary)); tries += 1) {
    if (tries >= BOUNDARY_TRIES) throw new Error('could not draw a boundary marker absent from the quoted data');
    boundary = ctx.boundary();
  }
  values['boundary'] = boundary;
  // One pass: a `{name}` inside a value is data and is not expanded again.
  const fill = (): string => template.replace(/\{(boundary|finding|excerpt|schema|entry_points|scanner_findings)\}/g, (whole, name: string) => values[name] ?? whole);
  const limit = ctx.max_tokens ?? MAX_BRIEF_TOKENS;
  let text = fill();
  // Hard ceiling: shrink the variable parts — the lists first, then the excerpt
  // around the flagged line — and refuse rather than return an over-cap brief.
  if (estimateTokens(text) > limit) {
    for (const key of ['entry_points', 'scanner_findings']) if (values[key] !== undefined) values[key] = '(omitted: the brief size limit)';
    text = fill();
  }
  for (let cap = MAX_EXCERPT_CHARS >> 1; excerptWithin !== undefined && estimateTokens(text) > limit && cap >= 1; cap >>= 1) {
    values['excerpt'] = excerptWithin(cap);
    text = fill();
  }
  if (estimateTokens(text) > limit) throw new Error('the brief exceeds the size limit even with its variable parts cut to the minimum');
  return { text, chars: text.length, estimated_tokens: estimateTokens(text) };
}
