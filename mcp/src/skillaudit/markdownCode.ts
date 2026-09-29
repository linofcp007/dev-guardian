/**
 * The code inside an instruction file.
 *
 * A third-party skill is read by the model as instructions, so a fenced
 * ```bash``` block or an inline `curl … | bash` in its SKILL.md is what the
 * model runs — the same as the line in `scripts/setup.sh` that the code rules
 * already score. This module splits a text file (Markdown and the other
 * `DOC_EXT` formats) into the two views the pattern pass needs:
 *
 *   - `code`: every line of a code block and every inline code span, each
 *     with the line number it sits on in the file — the `code`-target rules
 *     run over these. A code block is a fenced block (any info string, or
 *     none), an indented block (four spaces or a tab, after a blank line),
 *     or an HTML `<pre>` / `<code>` element; inline code is a backtick span
 *     or a one-line `<code>` element;
 *   - `prose`: every line of the file as it reads — an inline span's text
 *     kept with its backticks dropped, HTML code tags dropped, character
 *     references decoded — which the `prose`-target rules run over.
 *
 * Round 3 of the 3.0 review found each of these as a one-token bypass: the
 * prose view used to BLANK inline spans, so "send the contents of
 * `~/.ssh/id_rsa` to https://…" was invisible to the exfiltration prose rule;
 * indented code, `<pre>` and `<code>` were read as prose, where no code rule
 * looks and no line is joined.
 *
 * Deliberately more permissive than a Markdown renderer: a fence is accepted
 * at any indentation and behind `>` quote markers, because an attacker picks
 * the spelling a renderer would ignore and the model still reads. An
 * unclosed fence, `<pre>` or `<code>` runs to the end of the file.
 *
 * Inside a code block, a line ending in `\` or in a single `|` continues on
 * the next: the continued lines are ALSO reported as one logical line, at the
 * line it starts on — an install one-liner is routinely wrapped that way, and
 * the pipe to the shell is then on a line of its own.
 *
 * Pure functions. No I/O.
 */

export type CodeKind = 'fenced' | 'indented' | 'pre' | 'inline';

export interface CodeUnit {
  /** 1-based line the unit starts on in the file. */
  line: number;
  text: string;
  kind: CodeKind;
  /** 0-based index of the code block the unit belongs to; null for inline code. */
  block: number | null;
}

export interface MarkdownViews {
  code: CodeUnit[];
  /** Same length and line numbering as the file; each line as it reads. */
  prose: string[];
}

export const FENCE_OPEN = /^[ \t>]*(`{3,}|~{3,})(.*)$/;
const INDENTED = /^(?: {4,}|\t)(?=\S)/;
const HTML_CODE_TAG = /<\/?(?:pre|code|kbd|samp|tt)\b[^>]*>/gi;
const HTML_CODE_INLINE = /<(pre|code|kbd|samp|tt)\b[^>]*>([\s\S]*?)<\/\1\s*>/gi;
/** `<pre>` opens a block anywhere outside a backtick span; a multi-line `<code>` only at the start of its line. */
const PRE_OPEN = /<pre\b[^>]*>/i;
const CODE_BLOCK_OPEN = /^[ \t>]{0,3}<code\b[^>]*>/i;
const BACKSLASH_CONTINUATION = /\\[ \t]*$/;
const PIPE_CONTINUATION = /(?<!\|)\|[ \t]*$/;

/** Does this code line continue on the next one? */
export function continues(text: string): boolean {
  return BACKSLASH_CONTINUATION.test(text) || PIPE_CONTINUATION.test(text);
}

/** `a \` + `b` → `a b`; `a |` + `b` → `a | b`. */
export function joinContinued(first: string, next: string): string {
  return `${first.replace(BACKSLASH_CONTINUATION, '')} ${next.trim()}`;
}

const NAMED_ENTITIES: Record<string, string> = {
  lt: '<',
  gt: '>',
  amp: '&',
  quot: '"',
  apos: "'",
  nbsp: ' ',
  verbar: '|',
  vert: '|',
  VerticalLine: '|',
  dollar: '$',
  lpar: '(',
  rpar: ')',
  sol: '/',
};

/** HTML character references, the way a renderer — and a model — reads them (`&#124;` is `|`). */
export function decodeEntities(text: string): string {
  return text.replace(/&(#x[0-9a-f]+|#\d+|[A-Za-z]+);/gi, (whole, ref: string) => {
    if (ref.startsWith('#x') || ref.startsWith('#X')) return safeCodePoint(Number.parseInt(ref.slice(2), 16), whole);
    if (ref.startsWith('#')) return safeCodePoint(Number.parseInt(ref.slice(1), 10), whole);
    return NAMED_ENTITIES[ref] ?? whole;
  });
}

function safeCodePoint(code: number, fallback: string): string {
  return Number.isInteger(code) && code > 0 && code <= 0x10ffff ? String.fromCodePoint(code) : fallback;
}

/** Collects a block's lines, and each run of continued lines as one more unit. */
class BlockLines {
  private pending: CodeUnit | null = null;
  constructor(private readonly out: CodeUnit[]) {}

  add(unit: CodeUnit): void {
    this.out.push(unit);
    const more = continues(unit.text);
    if (this.pending) {
      const joined: CodeUnit = { ...this.pending, text: joinContinued(this.pending.text, unit.text) };
      if (more) {
        this.pending = joined;
      } else {
        this.out.push(joined);
        this.pending = null;
      }
    } else if (more) {
      this.pending = unit;
    }
  }

  end(): void {
    if (this.pending) this.out.push(this.pending);
    this.pending = null;
  }
}

type BlockState =
  | { kind: 'fenced'; char: string; length: number }
  // `<code>` ends at a blank line too, as a CommonMark HTML block does: a
  // stray `<code>` in prose must not turn the rest of the file into code.
  | { kind: 'pre'; close: RegExp; endsAtBlank: boolean }
  | { kind: 'indented' };

export interface SplitOptions {
  /**
   * Read four-space / tab indentation after a blank line as a code block.
   * True for Markdown and plain text; false for other text files (HTML,
   * JSON, YAML), where indentation is layout, not a code block.
   */
  indentedCode?: boolean;
}

export function splitMarkdown(content: string, opts: SplitOptions = {}): MarkdownViews {
  const indentedCode = opts.indentedCode !== false;
  const lines = content.split(/\r?\n/);
  const code: CodeUnit[] = [];
  const prose: string[] = [];
  const block = new BlockLines(code);
  let state: BlockState | null = null;
  let blocks = 0;
  let previousBlank = true;

  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i] ?? '';
    const lineNo = i + 1;
    const current = blocks - 1;

    if (state?.kind === 'fenced') {
      if (isClosingFence(line, state)) {
        block.end();
        state = null;
        prose.push('');
      } else {
        block.add({ line: lineNo, text: line, kind: 'fenced', block: current });
        prose.push(line);
      }
      previousBlank = line.trim() === '';
      continue;
    }

    if (state?.kind === 'pre' && state.endsAtBlank && line.trim() === '') {
      block.end();
      state = null;
    }

    if (state?.kind === 'pre') {
      const close = state.close.exec(line);
      const inside = decodeEntities((close ? line.slice(0, close.index) : line).replace(HTML_CODE_TAG, ''));
      if (inside.trim() !== '') block.add({ line: lineNo, text: inside, kind: 'pre', block: current });
      prose.push(inside);
      if (close) {
        block.end();
        state = null;
      }
      previousBlank = line.trim() === '';
      continue;
    }

    if (state?.kind === 'indented') {
      if (INDENTED.test(line)) {
        block.add({ line: lineNo, text: line.replace(/^(?: {4}|\t)/, ''), kind: 'indented', block: current });
        prose.push(line.trim());
        previousBlank = false;
        continue;
      }
      if (line.trim() === '') {
        // A blank line may sit inside an indented block; the next line decides.
        prose.push('');
        previousBlank = true;
        continue;
      }
      block.end();
      state = null;
    }

    const open = FENCE_OPEN.exec(line);
    const run = open?.[1];
    // A backtick fence's info string may not contain a backtick — that is an
    // inline span (```x``` on one line), handled below.
    if (open && run && !(run.startsWith('`') && (open[2] ?? '').includes('`'))) {
      state = { kind: 'fenced', char: run.charAt(0), length: run.length };
      blocks += 1;
      prose.push('');
      previousBlank = false;
      continue;
    }

    // HTML is looked for outside backtick spans: `pair <code>` is text.
    const spans = inlineSpans(line);
    const outside = blankSpans(line, spans);
    const opener = htmlBlockOpener(outside);
    if (opener) {
      state = { kind: 'pre', close: opener.close, endsAtBlank: opener.endsAtBlank };
      blocks += 1;
      const after = decodeEntities(line.slice(opener.end).replace(HTML_CODE_TAG, ''));
      if (after.trim() !== '') block.add({ line: lineNo, text: after, kind: 'pre', block: blocks - 1 });
      prose.push(decodeEntities(line.replace(HTML_CODE_TAG, '')));
      previousBlank = false;
      continue;
    }

    if (indentedCode && previousBlank && INDENTED.test(line)) {
      state = { kind: 'indented' };
      blocks += 1;
      block.add({ line: lineNo, text: line.replace(/^(?: {4}|\t)/, ''), kind: 'indented', block: blocks - 1 });
      prose.push(line.trim());
      previousBlank = false;
      continue;
    }

    for (const s of spans) code.push({ line: lineNo, text: s.text, kind: 'inline', block: null });
    for (const m of outside.matchAll(HTML_CODE_INLINE)) {
      const text = decodeEntities((m[2] ?? '').replace(HTML_CODE_TAG, ''));
      if (text.trim() !== '') code.push({ line: lineNo, text, kind: 'inline', block: null });
    }
    prose.push(decodeEntities(keepSpanText(line, spans).replace(HTML_CODE_TAG, '')));
    previousBlank = line.trim() === '';
  }
  block.end();
  return { code, prose };
}

/** An HTML element that opens a code block on this line and does not close on it. */
function htmlBlockOpener(outside: string): { close: RegExp; endsAtBlank: boolean; end: number } | null {
  const pre = PRE_OPEN.exec(outside);
  if (pre && !/<\/pre\s*>/i.test(outside.slice(pre.index))) {
    return { close: /<\/pre\s*>/i, endsAtBlank: false, end: pre.index + pre[0].length };
  }
  const codeOpen = CODE_BLOCK_OPEN.exec(outside);
  if (codeOpen && !/<\/code\s*>/i.test(outside)) {
    return { close: /<\/code\s*>/i, endsAtBlank: true, end: codeOpen.index + codeOpen[0].length };
  }
  return null;
}

/** The line with each backtick span replaced by spaces, so positions still line up. */
function blankSpans(line: string, spans: Span[]): string {
  let out = line;
  for (const s of spans) out = out.slice(0, s.start) + ' '.repeat(s.end - s.start) + out.slice(s.end);
  return out;
}

function isClosingFence(line: string, fence: { char: string; length: number }): boolean {
  const m = /^[ \t>]*(`{3,}|~{3,})[ \t]*$/.exec(line);
  const run = m?.[1];
  return run !== undefined && run.charAt(0) === fence.char && run.length >= fence.length;
}

export interface Span {
  /** Where the opening backticks start. */
  start: number;
  /** Just past the closing backticks. */
  end: number;
  text: string;
}

/**
 * CommonMark code spans on one line: a run of N backticks opens, the next run
 * of exactly N closes, and an unmatched run is literal text. One leading and
 * one trailing space are stripped when both are present.
 */
export function inlineSpans(line: string): Span[] {
  const out: Span[] = [];
  let i = 0;
  while (i < line.length) {
    if (line[i] !== '`') {
      i += 1;
      continue;
    }
    let n = 0;
    while (line[i + n] === '`') n += 1;
    const openEnd = i + n;
    let j = openEnd;
    let close = -1;
    while (j < line.length) {
      if (line[j] !== '`') {
        j += 1;
        continue;
      }
      let m = 0;
      while (line[j + m] === '`') m += 1;
      if (m === n) {
        close = j;
        break;
      }
      j += m;
    }
    if (close === -1) {
      i = openEnd;
      continue;
    }
    let text = line.slice(openEnd, close);
    if (text.length >= 2 && text.startsWith(' ') && text.endsWith(' ') && text.trim() !== '') {
      text = text.slice(1, -1);
    }
    out.push({ start: i, end: close + n, text });
    i = close + n;
  }
  return out;
}

/** The line as it reads: each span replaced by its text, without the backticks. */
function keepSpanText(line: string, spans: Span[]): string {
  if (spans.length === 0) return line;
  let out = '';
  let at = 0;
  for (const s of spans) {
    out += line.slice(at, s.start) + s.text;
    at = s.end;
  }
  return out + line.slice(at);
}
