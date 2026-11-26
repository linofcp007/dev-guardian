/**
 * The suppression examples dev-guardian's prose shows, judged by the reader
 * of the pass that reports a bare one (`src/testintegrity/suppressions.ts`,
 * `guardian-suppressions`); `suppressionExamples.test.ts` holds the prose to
 * it.
 *
 * An agent copies the example it reads, so every `nosec` / `nosemgrep` form
 * the prose offers names its rule and gives the reason
 * (docs/maintainers/prose.md, Bodies). Which code spans are offered is read
 * per sentence, by syntax: a sentence that asks for the form "with a reason",
 * or that shows one complete form, offers forms to write — every `nosec` /
 * `nosemgrep` span in it must be complete; a sentence that only names the
 * bare forms (what the pass reports, what a scanner reads) offers none. So a
 * form to avoid is named in a sentence of its own.
 *
 * Where the prose is: a text file's blocks (a blank line, a list item or a
 * table row starts one; a fenced block is not read — it may show what the
 * pass reports), split into sentences at `.`, `!` or `?` and a blank; a
 * source file's string expressions — the pieces a `+` joins read as one, a
 * template's text with `${…}` for each hole — never its comments.
 *
 * Complete, by the reader: the span goes on an added line of a Python,
 * JavaScript and Go file (after the language's comment marker, unless it
 * starts with one), each `<placeholder>` filled with {@link FILL}; in one of
 * those languages the whole span reads as reasoned, and the span or a prefix
 * of it cut at a blank reads as naming a rule — its rule, the reason cut off —
 * with nothing reported either time.
 */

import ts from 'typescript';
import { detectSuppressions, type SuppressionCounts } from '../../../src/testintegrity/suppressions.js';
import type { Prose } from './pluginDocs.js';

/** The directives whose examples are held here. */
const DIRECTIVE = /nos(?:ec|em)/i;

/** A sentence that asks for the reason offers the forms it shows. */
const ASKS_A_REASON = /\bwith a reason\b/i;

/** What fills a `<placeholder>`: a rule name to Semgrep (any word) and to Bandit (a snake_case test name), and a reason to all (three letters). */
const FILL = 'filled_in';

/** A line of code of each language, and its comment marker. */
const PROBES = { py: ['x = 1  ', '#'], js: ['x = 1;  ', '//'], go: ['x := 1 ', '//'] } as const;
type ProbeLang = keyof typeof PROBES;

function countsOf(lang: ProbeLang, span: string): SuppressionCounts {
  const [code, marker] = PROBES[lang];
  const line = span.startsWith(marker) ? `${code}${span}` : `${code}${marker} ${span}`;
  return detectSuppressions([{ path: `src/example.${lang}`, added: [{ line: 1, text: line }], removed: [], after: `${line}\n` }]).counts;
}

export interface Verdict {
  complete: boolean;
  /** Why it is not, or ''. */
  why: string;
}

const judged = new Map<string, Verdict>();

/** How the pass's reader takes one span (see the module comment). */
export function judge(span: string): Verdict {
  const known = judged.get(span);
  if (known !== undefined) return known;
  const filled = span.replace(/<[^<>]+>/g, FILL);
  const words = filled.split(' ');
  let read = false;
  let named = false;
  let reasoned = false;
  let verdict: Verdict | undefined;
  for (const lang of Object.keys(PROBES) as ProbeLang[]) {
    const whole = countsOf(lang, filled);
    if (whole.added === 0) continue;
    read = true;
    const hasReason = whole.reported === 0 && whole.named === 0 && whole.reasoned > 0;
    let hasRule = false;
    for (let i = 1; i <= words.length && !hasRule; i += 1) {
      const cut = countsOf(lang, words.slice(0, i).join(' '));
      hasRule = cut.reported === 0 && cut.reasoned === 0 && cut.named > 0;
    }
    if (hasRule && hasReason) {
      verdict = { complete: true, why: '' };
      break;
    }
    named ||= hasRule;
    reasoned ||= hasReason;
  }
  verdict ??= {
    complete: false,
    why: !read
      ? 'is read by no scanner dev-guardian runs'
      : !named && !reasoned
        ? 'names no rule and gives no reason'
        : !named
          ? 'names no rule'
          : 'gives no reason',
  };
  judged.set(span, verdict);
  return verdict;
}

/** The blocks of a text: a blank line, a list item or a table row starts one; a fenced block is left out. */
function blocks(text: string): string[] {
  const out: string[] = [];
  let cur: string[] = [];
  let fenced = false;
  const flush = (): void => {
    if (cur.length > 0) out.push(cur.join('\n'));
    cur = [];
  };
  for (const line of text.split(/\r?\n/)) {
    if (/^\s*(?:```|~~~)/.test(line)) {
      flush();
      fenced = !fenced;
      continue;
    }
    if (fenced) continue;
    if (line.trim() === '' || /^\s*(?:[-*+] |\d+\. |#|\||>)/.test(line)) flush();
    if (line.trim() !== '') cur.push(line);
  }
  flush();
  return out;
}

const HOLE = '${…}';

/** A source file's string expressions (see the module comment). */
function stringExpressions(rel: string, text: string): string[] {
  const kind = rel.endsWith('.ts') ? ts.ScriptKind.TS : ts.ScriptKind.JS;
  const sf = ts.createSourceFile(rel, text, ts.ScriptTarget.Latest, false, kind);
  const out: string[] = [];
  // The text of a string expression and the sub-expressions it leaves as holes; null for anything else.
  const fold = (n: ts.Node): { text: string; holes: ts.Node[] } | null => {
    if (ts.isStringLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n)) return { text: n.text, holes: [] };
    if (ts.isTemplateExpression(n)) {
      return { text: n.head.text + n.templateSpans.map((s) => HOLE + s.literal.text).join(''), holes: n.templateSpans.map((s) => s.expression) };
    }
    if (ts.isParenthesizedExpression(n)) return fold(n.expression);
    if (ts.isBinaryExpression(n) && n.operatorToken.kind === ts.SyntaxKind.PlusToken) {
      const l = fold(n.left);
      const r = fold(n.right);
      if (l === null && r === null) return null;
      return { text: (l?.text ?? HOLE) + (r?.text ?? HOLE), holes: [...(l?.holes ?? [n.left]), ...(r?.holes ?? [n.right])] };
    }
    return null;
  };
  const visit = (n: ts.Node): void => {
    const f = fold(n);
    if (f === null) {
      ts.forEachChild(n, visit);
      return;
    }
    out.push(f.text);
    for (const h of f.holes) visit(h);
  };
  visit(sf);
  return out;
}

/** A file's prose, block by block: a text file's blocks, or the blocks of a source file's string expressions. */
export function proseUnits(rel: string, text: string): string[] {
  return /\.(?:ts|mjs|js)$/.test(rel) ? stringExpressions(rel, text).flatMap(blocks) : blocks(text);
}

export interface Sentence {
  /** The sentence, white space as one space. */
  text: string;
  /** The same, its code spans emptied: what it says around them. */
  around: string;
  spans: string[];
}

const SPAN = /`([^`]+)`/g;
const MASKED = /\u0000(\d+)\u0001/g;

/** A block's sentences: split at `.`, `!` or `?` and a blank, never inside a code span (whose blanks are kept, a line end as one). */
export function sentences(block: string): Sentence[] {
  const spans: string[] = [];
  const masked = block
    .replace(SPAN, (_m, s: string) => `\u0000${spans.push(s.replace(/\r?\n\s*/g, ' ')) - 1}\u0001`)
    .replace(/\s+/g, ' ')
    .trim();
  return masked.split(/(?<=[.!?])\s+/).map((piece) => {
    const own: string[] = [];
    const around = piece.replace(MASKED, (_m, i: string) => {
      own.push(spans[Number(i)] ?? '');
      return '``';
    });
    return { text: piece.replace(MASKED, (_m, i: string) => `\`${spans[Number(i)] ?? ''}\``), around, spans: own };
  });
}

export interface Example {
  rel: string;
  span: string;
  verdict: Verdict;
  sentence: string;
}

/** Every `nosec` / `nosemgrep` span a sentence offers as a form to write (see the module comment). */
export function examplesIn(files: readonly Prose[]): Example[] {
  const out: Example[] = [];
  for (const f of files) {
    if (!DIRECTIVE.test(f.text)) continue;
    for (const block of proseUnits(f.rel, f.text)) {
      for (const s of sentences(block)) {
        const found = s.spans.filter((x) => DIRECTIVE.test(x)).map((span) => ({ span, verdict: judge(span) }));
        if (found.length === 0) continue;
        if (!ASKS_A_REASON.test(s.around) && !found.some((x) => x.verdict.complete)) continue;
        for (const x of found) out.push({ rel: f.rel, ...x, sentence: s.text });
      }
    }
  }
  return out;
}

/** The offered forms that are not complete, as lines a failure prints. */
export function exampleProblems(files: readonly Prose[]): string[] {
  return examplesIn(files)
    .filter((x) => !x.verdict.complete)
    .map((x) => `${x.rel}: \`${x.span}\` ${x.verdict.why} — in "${x.sentence.slice(0, 200)}"`);
}
