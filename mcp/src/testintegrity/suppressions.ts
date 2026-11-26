/**
 * Suppressions a change adds — the diff's second in-process pass, beside
 * `detect.ts` and under a name of its own ({@link SUPPRESSIONS_TOOL}), so a
 * reader of the verdict never takes one for a weakened test. A directive that
 * silences a linter, a type checker or one of the scanners dev-guardian runs
 * is read on the DIFF: one that was already there is the project's decision;
 * one this change adds, with no reason next to it, is a question for its
 * author — an agent copies the suppressions it finds, and one without a
 * reason teaches the next change to silence the same rule.
 *
 *   | rule                      | severity | an added directive, with no reason                 |
 *   | ------------------------- | -------- | -------------------------------------------------- |
 *   | scanner-suppression-added | medium   | a scanner's naming no rule: it hides every finding |
 *   |                           |          | of that scanner there, dev-guardian's gate's too   |
 *   | suppression-added         | medium   | a linter's for the whole file naming no rule       |
 *   |                           | low      | a linter's for the whole file naming its rules, or |
 *   |                           |          | for a line naming none                             |
 *
 * Every other added directive — one naming the rules it silences (which the
 * linters themselves ask for), or giving a reason — is counted on the pass's
 * reason line, never reported. Nothing is high: nothing here blocks at the
 * default `--fail-on high`.
 *
 * The directives are a closed table ({@link ROWS}), each read the way its
 * tool reads it: Semgrep honours a blank-led `nosem` anywhere on the line,
 * a string included, and not `//nosemgrep` with no blank; Bandit and gosec
 * read comments only, gosec one that STARTS with `#nosec`; gitleaks reads
 * `gitleaks:allow` anywhere on the line; ESLint reads its file-wide form in a
 * block comment only. A reason is three letters in a row: after the
 * directive and its arguments in the same comment (the tool's own field —
 * `-- why`, `reason = "why"`, `Justification = "why"` — or free text), or in
 * a whole-line comment directly above that is not itself a directive. The
 * reason is never judged, and a doubt never is: a line inside a multi-line
 * string, template, raw string or heredoc an earlier line opened is not read
 * (but by Semgrep's and gitleaks' rows, whose tools read it too), a line
 * above that is one counts as a reason, and a directive naming nothing in a
 * block comment that runs on past its line (its arguments may be on the
 * next) is counted as naming its rules.
 *
 * A removed directive carries one added one with the same text (a moved
 * block, an edited line that kept its directive, a file moved without
 * `git mv`): that one is not new. Files under `NOT_TESTS` (fixtures,
 * `testdata`, snapshots) are not read; `@ts-expect-error` in a test file
 * asserts a compile error, and is not one.
 *
 * Pure: the change's files in, findings and counts out (`gitChanges.ts`
 * reads them). `PICKAXE_ERE` is the rows' tokens for `git diff -G`, which
 * lists the files whose added or removed lines hold one: every row's match
 * holds one of its tokens, and a token is a literal, a bracket class or an
 * optional `!` — read the same by git's POSIX ERE and V8.
 */

import { makeFinding } from '../runners/scannerParsers/index.js';
import type { Finding, Severity } from '../types.js';
import { isTestFile, NOT_TESTS, type DiffLine } from './detect.js';

/** The `tool` of every finding here, and the pass's `tools_run` name. */
export const SUPPRESSIONS_TOOL = 'guardian-suppressions';

/** The languages whose directives are read (`html`: a Vue or Svelte file, whose template has HTML comments). */
type SuppressionLang = 'js' | 'html' | 'py' | 'go' | 'rs' | 'jvm' | 'cs' | 'php' | 'rb' | 'sh' | 'c' | 'tf' | 'yaml' | 'docker';

/** A file's suppression language by its name, or null (not read). */
export function suppressionLanguageOf(path: string): SuppressionLang | null {
  const name = path.slice(path.lastIndexOf('/') + 1);
  if (/^(?:Dockerfile|Containerfile)(?:\..+)?$/i.test(name) || /\.dockerfile$/i.test(name)) return 'docker';
  const ext = /\.([A-Za-z0-9+]+)$/.exec(name)?.[1]?.toLowerCase();
  switch (ext) {
    case 'js':
    case 'jsx':
    case 'mjs':
    case 'cjs':
    case 'ts':
    case 'tsx':
    case 'mts':
    case 'cts':
      return 'js';
    case 'vue':
    case 'svelte':
      return 'html';
    case 'py':
    case 'pyi':
      return 'py';
    case 'go':
      return 'go';
    case 'rs':
      return 'rs';
    case 'java':
    case 'kt':
    case 'kts':
    case 'groovy':
    case 'scala':
      return 'jvm';
    case 'cs':
      return 'cs';
    case 'php':
      return 'php';
    case 'rb':
      return 'rb';
    case 'sh':
    case 'bash':
    case 'zsh':
      return 'sh';
    case 'c':
    case 'cc':
    case 'cpp':
    case 'cxx':
    case 'c++':
    case 'h':
    case 'hh':
    case 'hpp':
    case 'hxx':
      return 'c';
    case 'tf':
    case 'hcl':
      return 'tf';
    case 'yml':
    case 'yaml':
      return 'yaml';
    default:
      return null;
  }
}

// ---------------------------------------------------------------------------
// The lexer: what of each line is code, a comment or a string, with the state
// the lines above leave (a block comment, a string that runs on, a heredoc).
// ---------------------------------------------------------------------------

interface Lexer {
  /** Line comment markers. */
  line: readonly string[];
  /** Block comments: opener, closer. */
  block: ReadonlyArray<readonly [string, string]>;
  /** Quote characters. */
  quotes: string;
  /** Of those, the ones whose strings may run on past their line (a template, a Go raw string, a shell string). */
  spans: string;
  /** Of those, the ones with no backslash escape inside (Go's raw string, a shell or YAML single quote). */
  noEscape: string;
  /** Triple-quoted strings (Python's, Java's text blocks, C#'s raw strings): they run on. */
  triple: readonly string[];
  /** Where `#` starts a comment, when it is a marker: anywhere, only at the line's start or after a blank, only first on the line, or never as `#[` (PHP's attribute). */
  hash?: 'anywhere' | 'afterBlank' | 'lineStart' | 'notBracket';
  heredoc?: 'sh' | 'rb' | 'php' | 'tf';
  /** Rust: `r#"…"#` raw strings, `'x'` a character where a lone `'` is a lifetime. */
  rust?: true;
  /** C++'s `R"delim(…)delim"`. */
  cppRaw?: true;
  /** C#'s `@"…"` verbatim strings, which run on (`""` is a quote inside). */
  verbatim?: true;
  /** Ruby's `=begin` … `=end`. */
  rubyDoc?: true;
}

const C_BLOCK = [['/*', '*/']] as const;
const BACKTICK = String.fromCharCode(96);

const LEXERS: Readonly<Record<SuppressionLang, Lexer>> = {
  js: { line: ['//'], block: C_BLOCK, quotes: `'"${BACKTICK}`, spans: BACKTICK, noEscape: '', triple: [] },
  html: { line: ['//'], block: [['/*', '*/'], ['<!--', '-->']], quotes: `'"${BACKTICK}`, spans: BACKTICK, noEscape: '', triple: [] },
  py: { line: ['#'], block: [], quotes: `'"`, spans: '', noEscape: '', triple: ['"""', "'''"], hash: 'anywhere' },
  go: { line: ['//'], block: C_BLOCK, quotes: `'"${BACKTICK}`, spans: BACKTICK, noEscape: BACKTICK, triple: [] },
  rs: { line: ['//'], block: C_BLOCK, quotes: '"', spans: '"', noEscape: '', triple: [], rust: true },
  jvm: { line: ['//'], block: C_BLOCK, quotes: `'"`, spans: '', noEscape: '', triple: ['"""'] },
  cs: { line: ['//'], block: C_BLOCK, quotes: `'"`, spans: '', noEscape: '', triple: ['"""'], verbatim: true },
  php: { line: ['//', '#'], block: C_BLOCK, quotes: `'"`, spans: `'"`, noEscape: '', triple: [], hash: 'notBracket', heredoc: 'php' },
  rb: { line: ['#'], block: [], quotes: `'"`, spans: `'"`, noEscape: '', triple: [], hash: 'anywhere', heredoc: 'rb', rubyDoc: true },
  sh: { line: ['#'], block: [], quotes: `'"`, spans: `'"`, noEscape: "'", triple: [], hash: 'afterBlank', heredoc: 'sh' },
  c: { line: ['//'], block: C_BLOCK, quotes: `'"`, spans: '', noEscape: '', triple: [], cppRaw: true },
  tf: { line: ['#', '//'], block: C_BLOCK, quotes: '"', spans: '', noEscape: '', triple: [], hash: 'anywhere', heredoc: 'tf' },
  yaml: { line: ['#'], block: [], quotes: `'"`, spans: '', noEscape: "'", triple: [], hash: 'afterBlank' },
  docker: { line: ['#'], block: [], quotes: '', spans: '', noEscape: '', triple: [], hash: 'lineStart', heredoc: 'sh' },
};

type State =
  | { k: 'code' }
  | { k: 'block'; close: string }
  /** A string open past its line: `close` ends it (`"`, a backtick, `"""`). */
  | { k: 'quote'; close: string; esc: boolean }
  /** A raw string, no escapes: Rust's `"#…`, C++'s `)delim"`. */
  | { k: 'raw'; close: string }
  | { k: 'verbatim' }
  | { k: 'heredoc'; id: string; end: 'exact' | 'tabs' | 'indented' | 'php' }
  | { k: 'rubyDoc' };

const CODE: State = { k: 'code' };

/** Where a comment sits on its line. */
interface CommentPart {
  /** Where its text starts (just after the marker) and ends (before a closer on the line, else the line's end). */
  start: number;
  end: number;
  marker: string;
  /** The line continues a block comment an earlier line opened. */
  cont: boolean;
  /** A block comment that runs on past this line. */
  unclosed: boolean;
}

/** One line as the lexer read it. */
interface LineRead {
  /** The line starts inside a string, a template or a heredoc an earlier line opened: nothing on it is code or a comment. */
  literal: boolean;
  comments: CommentPart[];
  /** The line, every comment and string blanked, at the same positions. */
  code: string;
  /** Code or a string on it — not only blanks and comments. */
  substance: boolean;
}

function literalLine(line: string): LineRead {
  return { literal: true, comments: [], code: ' '.repeat(line.length), substance: true };
}

const HEREDOC: Readonly<Record<NonNullable<Lexer['heredoc']>, RegExp>> = {
  // `<<EOF`, `<<-EOF`, `<<'EOF'` — never `<<<` (a here-string).
  sh: /<<(-?)[ \t]*(['"]?)([A-Za-z_][\w-]*)\2/y,
  rb: /<<([~-]?)(['"]?)([A-Za-z_]\w*)\2/y,
  php: /<<<[ \t]*(['"]?)([A-Za-z_]\w*)\1/y,
  tf: /<<(-?)([A-Za-z_]\w*)/y,
};

/** A heredoc opening at `i`: its length and the state its body is read in. */
function heredocAt(line: string, i: number, kind: NonNullable<Lexer['heredoc']>): { length: number; state: State } | null {
  if (kind === 'sh' && line.startsWith('<<<', i)) return null;
  const re = HEREDOC[kind];
  re.lastIndex = i;
  const m = re.exec(line);
  if (m === null) return null;
  if (kind === 'php') return { length: m[0].length, state: { k: 'heredoc', id: m[2] ?? '', end: 'php' } };
  if (kind === 'rb') return { length: m[0].length, state: { k: 'heredoc', id: m[3] ?? '', end: m[1] === '' ? 'exact' : 'indented' } };
  if (kind === 'tf') return { length: m[0].length, state: { k: 'heredoc', id: m[2] ?? '', end: 'indented' } };
  return { length: m[0].length, state: { k: 'heredoc', id: m[3] ?? '', end: m[1] === '-' ? 'tabs' : 'exact' } };
}

function heredocEnds(line: string, st: { id: string; end: 'exact' | 'tabs' | 'indented' | 'php' }): boolean {
  switch (st.end) {
    case 'exact':
      return line === st.id;
    case 'tabs':
      return line.replace(/^\t+/, '') === st.id;
    case 'indented':
      return line.trim() === st.id;
    case 'php': {
      const t = line.trimStart();
      return t.startsWith(st.id) && !/^\w/.test(t.slice(st.id.length));
    }
  }
}

const RUST_RAW = /b?r(#*)"/y;
const RUST_CHAR = /'(?:\\(?:x[0-9a-fA-F]{2}|u\{[0-9a-fA-F]{1,6}\}|.)|[^\\'\n])'/y;
const CPP_RAW = /(?:u8|[uUL])?R"([^()\\\s]{0,16})\(/y;
const WORD_BEFORE = /\w/;

/** A string opening at `i`: how far its opener reaches and the state inside (a Rust character literal is skipped whole). */
function stringAt(line: string, i: number, lex: Lexer): { skip: number; state: State } | null {
  for (const t of lex.triple) if (line.startsWith(t, i)) return { skip: t.length, state: { k: 'quote', close: t, esc: true } };
  const free = i === 0 || !WORD_BEFORE.test(line.charAt(i - 1));
  if (lex.verbatim === true) {
    const v = line.startsWith('@"', i) ? 2 : line.startsWith('$@"', i) || line.startsWith('@$"', i) ? 3 : 0;
    if (v > 0) return { skip: v, state: { k: 'verbatim' } };
  }
  if (lex.rust === true && free) {
    RUST_RAW.lastIndex = i;
    const m = RUST_RAW.exec(line);
    if (m !== null) return { skip: m[0].length, state: { k: 'raw', close: `"${m[1] ?? ''}` } };
  }
  if (lex.cppRaw === true && free) {
    CPP_RAW.lastIndex = i;
    const m = CPP_RAW.exec(line);
    if (m !== null) return { skip: m[0].length, state: { k: 'raw', close: `)${m[1] ?? ''}"` } };
  }
  const ch = line.charAt(i);
  if (lex.rust === true && ch === "'") {
    RUST_CHAR.lastIndex = i;
    const m = RUST_CHAR.exec(line);
    // A character literal is skipped whole; a lone `'` is a lifetime, plain code.
    return m !== null ? { skip: m[0].length, state: CODE } : null;
  }
  if (lex.quotes.includes(ch)) return { skip: 1, state: { k: 'quote', close: ch, esc: !lex.noEscape.includes(ch) } };
  return null;
}

/** Where the string `st` ends on the line from `i`: the index just past its closer, or -1. */
function stringEnd(line: string, i: number, st: State): number {
  if (st.k === 'raw') {
    const at = line.indexOf(st.close, i);
    return at < 0 ? -1 : at + st.close.length;
  }
  if (st.k === 'verbatim') {
    for (let j = i; j < line.length; j += 1) {
      if (line.charAt(j) !== '"') continue;
      if (line.charAt(j + 1) === '"') {
        j += 1;
        continue;
      }
      return j + 1;
    }
    return -1;
  }
  if (st.k !== 'quote') return i;
  for (let j = i; j < line.length; j += 1) {
    if (st.esc && line.charAt(j) === '\\') {
      j += 1;
      continue;
    }
    if (line.startsWith(st.close, j)) return j + st.close.length;
  }
  return -1;
}

/** The line comment marker at `i`, if one starts there. */
function lineMarkerAt(line: string, i: number, lex: Lexer): string | null {
  for (const m of lex.line) {
    if (!line.startsWith(m, i)) continue;
    if (m !== '#') return m;
    switch (lex.hash) {
      case 'afterBlank':
        if (i === 0 || /\s/.test(line.charAt(i - 1))) return m;
        break;
      case 'lineStart':
        // (`trim` stops at the first non-blank from either end: linear however many `#` the line holds — timed.)
        if (line.slice(0, i).trim() === '') return m;
        break;
      case 'notBracket':
        if (line.charAt(i + 1) !== '[') return m;
        break;
      default:
        return m;
    }
  }
  return null;
}

/** Whether a string state runs on to the next line (a template, a raw or triple-quoted string, a multi-line string). */
function runsOn(st: State, lex: Lexer): boolean {
  if (st.k === 'raw' || st.k === 'verbatim' || st.k === 'block') return true;
  if (st.k !== 'quote') return false;
  return st.close.length > 1 || lex.spans.includes(st.close);
}

/** The characters that can start a marker, a string or a heredoc in `lex`'s language: code between them is copied whole. */
function specialOf(lex: Lexer): RegExp {
  const chars = new Set<string>([...lex.quotes]);
  for (const m of lex.line) chars.add(m.charAt(0));
  for (const [open] of lex.block) chars.add(open.charAt(0));
  for (const t of lex.triple) chars.add(t.charAt(0));
  if (lex.heredoc !== undefined) chars.add('<');
  if (lex.verbatim === true) for (const c of '@$') chars.add(c);
  if (lex.rust === true) for (const c of "br'") chars.add(c);
  if (lex.cppRaw === true) for (const c of 'uULR') chars.add(c);
  return new RegExp(`[${[...chars].map((c) => c.replace(/[^A-Za-z0-9]/, '\\$&')).join('')}]`, 'g');
}

const SPECIAL = new Map<Lexer, RegExp>(Object.values(LEXERS).map((lex) => [lex, specialOf(lex)]));
const NOT_BLANK = /\S/;

function readLine(line: string, lex: Lexer, start: State): { read: LineRead; next: State } {
  if (start.k === 'heredoc') return { read: literalLine(line), next: heredocEnds(line, start) ? CODE : start };
  if (start.k === 'rubyDoc') return { read: literalLine(line), next: /^=end(?!\w)/.test(line) ? CODE : start };
  if (lex.rubyDoc === true && start.k === 'code' && /^=begin(?!\w)/.test(line)) return { read: literalLine(line), next: { k: 'rubyDoc' } };
  const n = line.length;
  let code = '';
  const blank = (count: number): void => {
    code += ' '.repeat(count);
  };
  const special = SPECIAL.get(lex) ?? /[^]/g;
  const comments: CommentPart[] = [];
  const literal = start.k !== 'code' && start.k !== 'block';
  let substance = literal;
  let st: State = start;
  let doc: State | null = null;
  let i = 0;
  if (st.k === 'block') {
    const close = line.indexOf(st.close);
    comments.push({ start: 0, end: close < 0 ? n : close, marker: st.close, cont: true, unclosed: close < 0 });
    if (close < 0) return { read: { literal: false, comments, code: ' '.repeat(n), substance: false }, next: st };
    blank(close + st.close.length);
    i = close + st.close.length;
    st = CODE;
  }
  while (i < n) {
    if (st.k !== 'code') {
      const end = stringEnd(line, i, st);
      if (end < 0) {
        blank(n - i);
        i = n;
        break;
      }
      blank(end - i);
      i = end;
      st = CODE;
      continue;
    }
    // Plain code up to the next character that can start something: copied whole.
    special.lastIndex = i;
    const next = special.exec(line);
    const stop = next === null ? n : next.index;
    if (stop > i) {
      const run = line.slice(i, stop);
      code += run;
      if (!substance && NOT_BLANK.test(run)) substance = true;
      i = stop;
      continue;
    }
    const lc = lineMarkerAt(line, i, lex);
    if (lc !== null) {
      comments.push({ start: i + lc.length, end: n, marker: lc, cont: false, unclosed: false });
      blank(n - i);
      i = n;
      break;
    }
    const bc = lex.block.find(([open]) => line.startsWith(open, i));
    if (bc !== undefined) {
      const [open, close] = bc;
      const from = i + open.length;
      const at = line.indexOf(close, from);
      comments.push({ start: from, end: at < 0 ? n : at, marker: open, cont: false, unclosed: at < 0 });
      if (at < 0) {
        blank(n - i);
        st = { k: 'block', close };
        i = n;
        break;
      }
      blank(at + close.length - i);
      i = at + close.length;
      continue;
    }
    if (lex.heredoc !== undefined && doc === null) {
      const h = heredocAt(line, i, lex.heredoc);
      if (h !== null) {
        code += line.slice(i, i + h.length);
        doc = h.state;
        substance = true;
        i += h.length;
        continue;
      }
    }
    const s = stringAt(line, i, lex);
    if (s !== null) {
      blank(s.skip);
      substance = true;
      i += s.skip;
      st = s.state;
      continue;
    }
    // A special character that starts nothing here (a `/` that is no comment, a lifetime's `'`): code.
    code += line.charAt(i);
    substance = true;
    i += 1;
  }
  // A one-line string still open at the end closes with it (nothing after its quote was read); one that runs on carries.
  let next: State = runsOn(st, lex) ? st : CODE;
  if (doc !== null && next.k === 'code') next = doc;
  return { read: { literal, comments, code, substance }, next };
}

/** Every line of `text` as the lexer of `lang` reads it, in order. */
export function readLines(text: string, lang: SuppressionLang): LineRead[] {
  const lex = LEXERS[lang];
  const out: LineRead[] = [];
  let state: State = CODE;
  for (const raw of text.split('\n')) {
    const r = readLine(raw.endsWith('\r') ? raw.slice(0, -1) : raw, lex, state);
    out.push(r.read);
    state = r.next;
  }
  return out;
}

// ---------------------------------------------------------------------------
// The directives: a closed table, each row read the way its tool reads it.
// ---------------------------------------------------------------------------

/**
 * Where a row is read: `line` anywhere on the raw line, strings and literal
 * lines included (Semgrep, gitleaks); `start` at the start of a comment's
 * text; `segment` there or after any later `#` in the comment (Python's
 * `# type: ignore  # noqa`); `inside` anywhere in a comment; `code` in the
 * line's code, strings and comments blanked (an attribute, an annotation, a
 * pragma).
 */
type At = 'line' | 'start' | 'segment' | 'inside' | 'code';

/**
 * `leading`: the whole file before the file's first code, else the line; `leading-only`: nothing after code
 * (TypeScript reads `@ts-nocheck` only there). `leading-bare`: an own-line form whose region runs on (Pylint,
 * RuboCop, ShellCheck), the whole file when it names no rule before the file's first code, else the line;
 * `package-bare`: golangci-lint's, the whole file when it names no rule in the comment group the file's
 * `package` clause carries ({@link packageDocOf}), else the line. Anywhere else the region is not certain by
 * syntax, and a named form stays counted as every rule-naming line form is.
 */
type Scope = 'line' | 'file' | 'leading' | 'leading-only' | 'leading-bare' | 'package-bare';

interface Row {
  id: string;
  /** The tool that reads it, for the finding's text. */
  reader: string;
  cls: 'lint' | 'scanner';
  langs: readonly SuppressionLang[];
  at: At;
  /**
   * The directive and its arguments, never anchored (`start` / `segment`
   * rows are tried where the comment's text begins). Named groups: `names`
   * (the rules it names — no word, or only `all` for an `allNames` row, is
   * every rule), `file` / `line` (the scope it takes over `scope`).
   */
  re: RegExp;
  scope: Scope;
  /** Its grammar always names what it silences (`#[allow(…)]`, `trivy:ignore:<id>`). */
  named?: true;
  /** `all` as its names is every rule (Pylint, golangci-lint, RuboCop, ShellCheck). */
  allNames?: true;
  /** Only in these comment markers (ESLint's file-wide form: a block comment). */
  markers?: readonly string[];
  /** A leading `*` or `/` before it in the comment is fine (TypeScript reads `/// @ts-ignore`, `/** @ts-ignore *\/`). */
  gutter?: true;
  /** Read on a line inside a block comment (a PHP docblock's tags). */
  inBlock?: true;
  /** The tool's own reason field, read from the directive to the next one on the line (`reason = "…"`). */
  field?: RegExp;
  /** More of the match: `skip` it (not this directive after all), or say it names what it silences. */
  check?: (g: Readonly<Record<string, string | undefined>>, rest: string) => { skip?: boolean; names?: boolean };
  /** The directive in the finding's text. */
  label: string | ((g: Readonly<Record<string, string | undefined>>) => string);
  /** The tool's own form with a reason, for the message. */
  form: string;
  /** A scanner row: what it hides. */
  hides?: string;
  /** The `git diff -G` tokens: every match of `re` holds one. */
  tokens: readonly string[];
}

const TAB = String.fromCharCode(9);
/** A token's blank: a space or a tab, any number — one bracket class git's ERE and V8 read alike. */
const SP = `[ ${TAB}]*`;

const ALL_LANGS: readonly SuppressionLang[] = ['js', 'html', 'py', 'go', 'rs', 'jvm', 'cs', 'php', 'rb', 'sh', 'c', 'tf', 'yaml', 'docker'];
const JS: readonly SuppressionLang[] = ['js', 'html'];
const IAC: readonly SuppressionLang[] = ['tf', 'yaml', 'docker'];

/** A rule list after a blank: `rule`, `@scope/rule`, `plugin/rule`, comma-separated (a `--` alone names no rule: no word). */
const RULE_LIST = String.raw`[ \t]+[@\w./-]+(?:[ \t]*,[ \t]*[@\w./-]+)*`;
/** flake8 / Ruff codes: `E501`, `W291,E402`. */
const CODES = String.raw`[a-z]+\d+(?:[\s,]+[a-z]+\d+)*`;

const ROWS: readonly Row[] = [
  // ---- the scanners dev-guardian runs: hidden from its own scans and gate
  {
    id: 'nosemgrep',
    reader: 'Semgrep',
    cls: 'scanner',
    langs: ALL_LANGS,
    at: 'line',
    // Semgrep's own reading: a blank, then nosem or nosemgrep in any case; `:` or `=` and ids name the rules (read
    // here up to a `--`, so the reason after the documented `nosemgrep: <id> -- <reason>` stays one).
    re: / nosem(?:grep)?(?<names>[:=]\s?[^,\s-][^,\s]*(?:[,\s]+[^,\s-][^,\s]*)*)?/i,
    scope: 'line',
    label: 'nosemgrep',
    form: '`nosemgrep: <rule-id> -- <reason>`',
    hides: "Semgrep's findings on this line (alone on its line, on the next one)",
    tokens: [' [Nn][Oo][Ss][Ee][Mm]'],
  },
  {
    id: 'bandit-nosec',
    reader: 'Bandit',
    cls: 'scanner',
    langs: ['py'],
    at: 'segment',
    // Bandit's own reading (a real comment, `#` then blanks then nosec): its test ids or names up to the next `#`.
    re: /nosec:?[ \t]*(?<names>(?:[Bb]\d+|[a-z\d]+(?:_[a-z\d]+)+)(?:[ \t,]+(?:[Bb]\d+|[a-z\d]+(?:_[a-z\d]+)+))*)?/,
    scope: 'line',
    label: '# nosec',
    form: '`# nosec B602  # <reason>`',
    hides: "Bandit's findings on this line",
    tokens: ['nosec'],
  },
  {
    id: 'gosec-nosec',
    reader: 'gosec',
    cls: 'scanner',
    langs: ['go'],
    at: 'start',
    // gosec's own reading: a comment whose text starts with #nosec; its G-ids name the rules, `--` starts the justification.
    re: /#nosec(?<names>(?:[ \t,]*G\d{3})+)?/,
    scope: 'line',
    label: '#nosec',
    form: '`#nosec G304 -- <reason>`',
    hides: "gosec's findings on this line",
    tokens: ['nosec'],
  },
  {
    id: 'gitleaks-allow',
    reader: 'gitleaks',
    cls: 'scanner',
    langs: ALL_LANGS,
    at: 'line',
    re: /gitleaks:allow/, // gitleaks reads its own directive anywhere on the line: this is its name, with no secret
    scope: 'line',
    label: 'gitleaks:allow',
    form: '`gitleaks:allow` and the reason after it',
    hides: "gitleaks' findings on this line",
    tokens: ['gitleaks:allow'],
  },
  {
    id: 'trivy-ignore',
    reader: 'Trivy',
    cls: 'scanner',
    langs: IAC,
    at: 'start',
    re: /(?:trivy|tfsec):ignore:(?<names>[\w*.-]+)/,
    scope: 'line',
    // `*` names no check: Trivy then reports none here.
    check: (g) => ({ names: g['names'] !== '*' }),
    label: 'trivy:ignore',
    form: '`trivy:ignore:<id>` and a comment saying why',
    hides: "Trivy's findings of every check here",
    tokens: ['trivy:ignore:', 'tfsec:ignore:'],
  },
  {
    id: 'zizmor-ignore',
    reader: 'zizmor',
    cls: 'scanner',
    langs: ['yaml'],
    at: 'start',
    re: /zizmor:[ \t]*ignore\[(?<names>[^\]\n]*)\]/,
    scope: 'line',
    named: true,
    label: 'zizmor: ignore',
    form: '`# zizmor: ignore[<rule>]` and a comment saying why',
    hides: "zizmor's finding of that rule here",
    tokens: ['zizmor:'],
  },
  {
    id: 'hadolint-ignore',
    reader: 'hadolint',
    cls: 'scanner',
    langs: ['docker'],
    at: 'start',
    re: /hadolint[ \t]+(?:global[ \t]+)?ignore=(?<names>[\w,]+)/,
    scope: 'line',
    named: true,
    label: 'hadolint ignore',
    form: '`# hadolint ignore=<rule>` and a comment saying why',
    hides: "hadolint's finding of that rule here",
    tokens: ['hadolint'],
  },
  {
    id: 'cppcheck-suppress',
    reader: 'cppcheck',
    cls: 'scanner',
    langs: ['c'],
    at: 'start',
    re: /cppcheck-suppress(?:-file|-begin|-macro)?(?:[ \t]+|\[)(?<names>[\w,-]+)/,
    scope: 'line',
    named: true,
    label: 'cppcheck-suppress',
    form: '`// cppcheck-suppress <id>` and a comment saying why',
    hides: "cppcheck's finding of that id here",
    tokens: ['cppcheck-suppress'],
  },
  {
    id: 'spotbugs',
    reader: 'SpotBugs',
    cls: 'scanner',
    langs: ['jvm'],
    at: 'code',
    re: /(?<![\w$.])@(?:edu\.umd\.cs\.findbugs\.annotations\.)?SuppressF[Bb]Warnings\b(?:[ \t]*\((?<names>[^)\n]*)(?<close>\))?)?/,
    scope: 'line',
    field: /\bjustification[ \t]*=[ \t]*"[^"\n]*\p{L}{3}/u,
    // An argument (a pattern, a justification) or one running on to the next line: not the bare form.
    check: (g) => ({ names: g['names'] !== undefined && (g['names'].trim() !== '' || g['close'] === undefined) }),
    label: '@SuppressFBWarnings',
    form: '`@SuppressFBWarnings(value = "<pattern>", justification = "<reason>")`',
    hides: "SpotBugs' (and FindSecBugs') findings on the element it annotates",
    tokens: ['Suppress'],
  },
  {
    id: 'cs-pragma-warning',
    reader: 'the C# compiler',
    cls: 'scanner',
    langs: ['cs'],
    at: 'code',
    re: /^[ \t]*#[ \t]*pragma[ \t]+warning[ \t]+disable\b(?<names>[^/\n]*)/,
    scope: 'line',
    label: '#pragma warning disable',
    form: '`#pragma warning disable <id> // <reason>`',
    hides: "every compiler and analyzer warning up to the next `#pragma warning restore` (the .NET security analyzers' and security-code-scan's included)",
    tokens: ['pragma'],
  },

  // ---- linters and type checkers
  {
    id: 'eslint-disable',
    reader: 'ESLint',
    cls: 'lint',
    langs: JS,
    at: 'start',
    // The file-wide form: ESLint reads it in a block comment only (`// eslint-disable` disables nothing).
    re: new RegExp(String.raw`(?<tool>eslint|oxlint)-disable(?![\w-])(?<names>${RULE_LIST})?`),
    scope: 'file',
    markers: ['/*', '<!--'],
    label: (g) => `/* ${g['tool'] ?? 'eslint'}-disable */`,
    form: '`/* eslint-disable <rule> -- <reason> */`',
    tokens: ['eslint-disable', 'oxlint-disable'],
  },
  {
    id: 'eslint-disable-line',
    reader: 'ESLint',
    cls: 'lint',
    langs: JS,
    at: 'start',
    re: new RegExp(String.raw`(?<tool>eslint|oxlint)-disable-(?<line>next-line|line)(?![\w-])(?<names>${RULE_LIST})?`),
    scope: 'line',
    label: (g) => `${g['tool'] ?? 'eslint'}-disable-${g['line'] ?? 'line'}`,
    form: '`// eslint-disable-next-line <rule> -- <reason>`',
    tokens: ['eslint-disable', 'oxlint-disable'],
  },
  {
    id: 'ts-ignore',
    reader: 'TypeScript',
    cls: 'lint',
    langs: JS,
    at: 'start',
    gutter: true,
    re: /@ts-(?<kind>ignore|expect-error)(?![\w-])/,
    scope: 'line',
    label: (g) => `@ts-${g['kind'] ?? 'ignore'}`,
    form: '`// @ts-expect-error: <reason>`',
    tokens: ['@ts-ignore', '@ts-expect-error'],
  },
  {
    id: 'ts-nocheck',
    reader: 'TypeScript',
    cls: 'lint',
    langs: JS,
    at: 'start',
    gutter: true,
    re: /@ts-nocheck(?![\w-])/,
    scope: 'leading-only',
    label: '@ts-nocheck',
    form: '`// @ts-nocheck: <reason>`',
    tokens: ['@ts-nocheck'],
  },
  {
    id: 'noqa',
    reader: 'flake8 / Ruff',
    cls: 'lint',
    langs: ['py'],
    at: 'segment',
    re: new RegExp(String.raw`noqa(?![\w-])(?::[ \t]?(?<names>${CODES}))?`, 'i'),
    scope: 'line',
    label: '# noqa',
    form: '`# noqa: <code>  # <reason>`',
    tokens: ['[Nn][Oo][Qq][Aa]'],
  },
  {
    id: 'noqa-file',
    reader: 'flake8 / Ruff',
    cls: 'lint',
    langs: ['py'],
    at: 'segment',
    re: new RegExp(String.raw`(?:ruff|flake8)[ \t]*:[ \t]*noqa(?![\w-])(?::[ \t]?(?<names>${CODES}))?`, 'i'),
    scope: 'file',
    label: '# ruff: noqa',
    form: '`# ruff: noqa: <code>` and a comment saying why',
    tokens: ['[Nn][Oo][Qq][Aa]'],
  },
  {
    id: 'type-ignore',
    reader: 'mypy',
    cls: 'lint',
    langs: ['py'],
    at: 'segment',
    // Before any code, mypy reads it as the whole module's.
    re: /type:[ \t]*ignore(?![\w-])(?<names>\[[^\]\n]*\])?/,
    scope: 'leading',
    label: '# type: ignore',
    form: '`# type: ignore[<code>]  # <reason>`',
    tokens: [`type:${SP}ignore`],
  },
  {
    id: 'pyright-ignore',
    reader: 'Pyright',
    cls: 'lint',
    langs: ['py'],
    at: 'segment',
    re: /pyright:[ \t]*ignore(?![\w-])(?<names>\[[^\]\n]*\])?/,
    scope: 'line',
    label: '# pyright: ignore',
    form: '`# pyright: ignore[<rule>]  # <reason>`',
    tokens: ['pyright'],
  },
  {
    id: 'mypy-ignore-errors',
    reader: 'mypy',
    cls: 'lint',
    langs: ['py'],
    at: 'segment',
    re: /mypy:[ \t]*ignore-errors(?![\w-])/,
    scope: 'file',
    label: '# mypy: ignore-errors',
    form: 'a comment above it saying why',
    tokens: ['mypy'],
  },
  {
    id: 'pylint',
    reader: 'Pylint',
    cls: 'lint',
    langs: ['py'],
    at: 'segment',
    re: /pylint:[ \t]*(?:(?<file>skip-file)|disable(?<line>-next)?[ \t]*=[ \t]*(?<names>[\w-]+(?:[ \t]*,[ \t]*[\w-]+)*))/,
    scope: 'leading-bare',
    allNames: true,
    label: (g) => (g['file'] !== undefined ? '# pylint: skip-file' : '# pylint: disable'),
    form: '`# pylint: disable=<check>  # <reason>`',
    tokens: ['pylint'],
  },
  {
    id: 'nolint',
    reader: 'golangci-lint',
    cls: 'lint',
    langs: ['go'],
    at: 'start',
    re: /nolint(?![\w-])(?::(?<names>[\w-]+(?:,[\w-]+)*))?/,
    scope: 'package-bare',
    allNames: true,
    label: '//nolint',
    form: '`//nolint:<linter> // <reason>`',
    tokens: ['nolint'],
  },
  {
    id: 'staticcheck',
    reader: 'staticcheck',
    cls: 'lint',
    langs: ['go'],
    at: 'start',
    re: /lint:(?<file>file-)?ignore[ \t]+(?<names>[\w,*-]+)/,
    scope: 'line',
    named: true,
    label: (g) => (g['file'] !== undefined ? '//lint:file-ignore' : '//lint:ignore'),
    form: '`//lint:ignore <check> <reason>`',
    tokens: ['lint:ignore', 'lint:file-ignore'],
  },
  {
    id: 'rust-allow',
    reader: 'rustc / Clippy',
    cls: 'lint',
    langs: ['rs'],
    at: 'code',
    re: /#(?<file>!)?\[[ \t]*(?:allow|expect)[ \t]*\(/,
    scope: 'line',
    named: true,
    field: /\breason[ \t]*=[ \t]*"[^"\n]*\p{L}{3}/u,
    label: (g) => (g['file'] !== undefined ? '#![allow(…)]' : '#[allow(…)]'),
    form: '`#[allow(<lint>, reason = "<reason>")]`',
    tokens: [`#!?\\[${SP}allow`, `#!?\\[${SP}expect`],
  },
  {
    id: 'rust-cfg-attr',
    reader: 'rustc / Clippy',
    cls: 'lint',
    langs: ['rs'],
    at: 'code',
    re: /#(?<file>!)?\[[ \t]*cfg_attr[ \t]*\(/,
    scope: 'line',
    named: true,
    field: /\breason[ \t]*=[ \t]*"[^"\n]*\p{L}{3}/u,
    check: (_g, rest) => ({ skip: !/\b(?:allow|expect)[ \t]*\(/.test(rest) }),
    label: '#[cfg_attr(…, allow(…))]',
    form: '`#[cfg_attr(<cfg>, allow(<lint>, reason = "<reason>"))]`',
    tokens: ['cfg_attr'],
  },
  {
    id: 'jvm-suppress',
    reader: 'javac / Kotlin',
    cls: 'lint',
    langs: ['jvm'],
    at: 'code',
    re: /(?<![\w$.])@(?<file>file:)?(?:SuppressWarnings|Suppress)[ \t]*\(/,
    scope: 'line',
    named: true,
    label: (g) => (g['file'] !== undefined ? '@file:Suppress' : '@SuppressWarnings'),
    form: 'a comment above it saying why',
    tokens: ['Suppress'],
  },
  {
    id: 'nosonar',
    reader: 'SonarQube',
    cls: 'lint',
    langs: ['jvm'],
    at: 'inside',
    re: /\bNOSONAR\b/,
    scope: 'line',
    label: 'NOSONAR',
    form: '`// NOSONAR <reason>`',
    tokens: ['NOSONAR'],
  },
  {
    id: 'cs-suppress-message',
    reader: 'the .NET analyzers',
    cls: 'lint',
    langs: ['cs'],
    at: 'code',
    re: /\[[ \t]*(?:(?<file>assembly|module)[ \t]*:[ \t]*)?(?:System\.Diagnostics\.CodeAnalysis\.)?SuppressMessage(?:Attribute)?[ \t]*\(/,
    scope: 'line',
    named: true,
    field: /\bJustification[ \t]*=[ \t]*"[^"\n]*\p{L}{3}/u,
    label: (g) => (g['file'] !== undefined ? `[${g['file']}: SuppressMessage]` : '[SuppressMessage]'),
    form: '`Justification = "<reason>"`',
    tokens: ['Suppress'],
  },
  {
    id: 'phpstan-ignore',
    reader: 'PHPStan',
    cls: 'lint',
    langs: ['php'],
    at: 'inside',
    inBlock: true,
    re: /@phpstan-ignore(?<line>-next-line|-line)?(?![\w-])(?<names>[ \t]+[\w.]+(?:[ \t]*,[ \t]*[\w.]+)*)?/,
    scope: 'line',
    label: (g) => `@phpstan-ignore${g['line'] ?? ''}`,
    form: '`@phpstan-ignore <identifier> (<reason>)`',
    tokens: ['@phpstan-ignore'],
  },
  {
    id: 'psalm-suppress',
    reader: 'Psalm',
    cls: 'lint',
    langs: ['php'],
    at: 'inside',
    inBlock: true,
    re: /@psalm-suppress[ \t]+(?<names>[\w\\]+)/,
    scope: 'line',
    named: true,
    label: '@psalm-suppress',
    form: 'a comment saying why',
    tokens: ['@psalm-suppress'],
  },
  {
    id: 'phpcs',
    reader: 'PHP_CodeSniffer',
    cls: 'lint',
    langs: ['php'],
    at: 'start',
    re: /phpcs:(?:(?<file>ignoreFile)|(?<line>ignore)|disable)(?![\w-])(?<names>[ \t]+[\w.]+(?:[ \t]*,[ \t]*[\w.]+)*)?/,
    scope: 'file',
    label: (g) => (g['file'] !== undefined ? 'phpcs:ignoreFile' : g['line'] !== undefined ? 'phpcs:ignore' : 'phpcs:disable'),
    form: '`// phpcs:ignore <sniff> -- <reason>`',
    tokens: ['phpcs:'],
  },
  {
    id: 'rubocop',
    reader: 'RuboCop',
    cls: 'lint',
    langs: ['rb'],
    at: 'start',
    re: /rubocop[ \t]*:[ \t]*(?:disable|todo)[ \t]+(?<names>[\w/]+(?:[ \t]*,[ \t]*[\w/]+)*)/,
    scope: 'leading-bare',
    allNames: true,
    label: '# rubocop:disable',
    form: '`# rubocop:disable <Cop> -- <reason>`',
    tokens: ['rubocop'],
  },
  {
    id: 'shellcheck',
    reader: 'ShellCheck',
    cls: 'lint',
    langs: ['sh'],
    at: 'start',
    re: /shellcheck[ \t]+disable=(?<names>[\w,-]+)/,
    scope: 'leading-bare',
    allNames: true,
    label: '# shellcheck disable',
    form: '`# shellcheck disable=<code>  # <reason>`',
    tokens: ['shellcheck'],
  },
  {
    id: 'nolint-c',
    reader: 'clang-tidy',
    cls: 'lint',
    langs: ['c'],
    at: 'inside',
    re: /\bNOLINT(?:NEXTLINE|BEGIN)?\b(?<names>\([^)\n]*\))?/,
    scope: 'line',
    label: 'NOLINT',
    form: '`// NOLINT(<check>): <reason>`',
    tokens: ['NOLINT'],
  },
  {
    id: 'c-pragma-diagnostic',
    reader: 'GCC / Clang',
    cls: 'lint',
    langs: ['c'],
    at: 'code',
    re: /^[ \t]*#[ \t]*pragma[ \t]+(?:GCC|clang)[ \t]+diagnostic[ \t]+ignored\b/,
    scope: 'line',
    named: true,
    label: '#pragma diagnostic ignored',
    form: 'a comment saying why',
    tokens: ['pragma'],
  },
  {
    id: 'checkov',
    reader: 'Checkov',
    cls: 'lint',
    langs: IAC,
    at: 'start',
    re: /checkov:skip=(?<names>[\w,]+)/,
    scope: 'line',
    named: true,
    label: 'checkov:skip',
    form: '`checkov:skip=<id>:<reason>`',
    tokens: ['checkov'],
  },
];

/** Each row's id, class, languages and tokens — what the tests hold the table to. */
export const SUPPRESSION_ROWS: ReadonlyArray<{ id: string; cls: 'lint' | 'scanner'; langs: readonly SuppressionLang[]; tokens: readonly string[] }> =
  ROWS.map((r) => ({ id: r.id, cls: r.cls, langs: r.langs, tokens: r.tokens }));

/** The rows' tokens for `git diff -G` (POSIX ERE): a file whose added or removed lines hold none holds no directive. */
export const PICKAXE_ERE: string = [...new Set(ROWS.flatMap((r) => r.tokens))].join('|');
const PICKAXE_JS = new RegExp(PICKAXE_ERE);

/** Whether `text` holds a token of {@link PICKAXE_ERE} — what `-G` asks of a file no diff lists (an untracked one). */
export function mayHoldSuppression(text: string): boolean {
  return PICKAXE_JS.test(text);
}

interface Compiled {
  row: Row;
  /** Tried where it is read (`y`): start, segment. */
  sticky: RegExp;
  /** Searched (`g`): line, inside, code. */
  search: RegExp;
  /** Its tokens: a comment holding none is not tried (every match holds one). */
  token: RegExp;
}

const COMPILED: ReadonlyMap<SuppressionLang, readonly Compiled[]> = new Map(
  ALL_LANGS.map((lang) => [
    lang,
    ROWS.filter((row) => row.langs.includes(lang)).map((row) => {
      const flags = row.re.flags.replace(/[gy]/g, '');
      return {
        row,
        sticky: new RegExp(row.re.source, `${flags}y`),
        search: new RegExp(row.re.source, `${flags}g`),
        token: new RegExp(row.tokens.join('|')),
      };
    }),
  ]),
);

/** One directive on a line. */
interface Hit {
  row: Row;
  start: number;
  end: number;
  groups: Readonly<Record<string, string | undefined>>;
  /** The comment it is in; null for a `line` or `code` row. */
  part: CommentPart | null;
}

function groupsOf(m: RegExpExecArray): Readonly<Record<string, string | undefined>> {
  return m.groups ?? {};
}

/** Where a comment's text begins, blanks (and a gutter of `*` / `/`, where the row allows one) skipped. */
function textStart(text: string, from: number, gutter: boolean, cont: boolean): number {
  let i = from;
  const skip = (ch: string): boolean => ch === ' ' || ch === TAB || ((gutter || cont) && (ch === '*' || (gutter && ch === '/')));
  while (i < text.length && skip(text.charAt(i))) i += 1;
  return i;
}

/** `c` tried at `at` of `text`, its positions moved by `offset` (where `text` starts on the line). */
function tryAt(c: Compiled, text: string, at: number, offset: number, part: CommentPart | null): Hit | null {
  c.sticky.lastIndex = at;
  const m = c.sticky.exec(text);
  if (m === null) return null;
  return { row: c.row, start: offset + m.index, end: offset + m.index + m[0].length, groups: groupsOf(m), part };
}

/** `c`'s first match in `text`, its positions moved by `offset`. */
function searchIn(c: Compiled, text: string, offset: number, part: CommentPart | null): Hit | null {
  c.search.lastIndex = 0;
  const m = c.search.exec(text);
  if (m === null) return null;
  return { row: c.row, start: offset + m.index, end: offset + m.index + m[0].length, groups: groupsOf(m), part };
}

/** A comment row in one comment's own text — never past it: each regex reads one comment, however many the line has. */
function inComment(c: Compiled, part: CommentPart, text: string): Hit | null {
  const row = c.row;
  if (row.at === 'start') return tryAt(c, text, textStart(text, 0, row.gutter === true, part.cont), part.start, part);
  if (row.at === 'inside') return searchIn(c, text, part.start, part);
  // `segment`: Python's comment, its text and each `#` after it starts another (`# type: ignore  # noqa: E501`) —
  // every directive there starts with a letter, so a `#` before anything else starts none.
  const first = tryAt(c, text, textStart(text, 0, false, false), part.start, part);
  if (first !== null) return first;
  const next = /#[ \t]*(?=[A-Za-z])/g;
  for (let m = next.exec(text); m !== null; m = next.exec(text)) {
    const h = tryAt(c, text, m.index + m[0].length, part.start, part);
    if (h !== null) return h;
  }
  return null;
}

/** Every directive on one line, in order: one per row at most. */
function hitsOn(line: string, read: LineRead, lang: SuppressionLang): Hit[] {
  const hits: Hit[] = [];
  const rows = COMPILED.get(lang) ?? [];
  for (const c of rows) {
    if (c.row.at === 'line') {
      const h = searchIn(c, line, 0, null);
      if (h !== null) hits.push(h);
    } else if (c.row.at === 'code' && !read.literal) {
      c.search.lastIndex = 0;
      // Found in the code, strings and comments blanked; its arguments read on the raw line.
      const m = c.search.exec(read.code);
      const h = m === null ? null : tryAt(c, line, m.index, 0, null);
      if (h !== null) hits.push(h);
    }
  }
  if (read.literal) return hits.sort((a, b) => a.start - b.start);
  const found = new Set<Compiled>();
  for (const part of read.comments) {
    const text = line.slice(part.start, part.end);
    for (const c of rows) {
      const row = c.row;
      if (row.at === 'line' || row.at === 'code' || found.has(c)) continue;
      if (part.cont && row.inBlock !== true) continue;
      if (row.markers !== undefined && (part.cont || !row.markers.includes(part.marker))) continue;
      if (!c.token.test(text)) continue;
      const h = inComment(c, part, text);
      if (h === null) continue;
      hits.push(h);
      found.add(c);
    }
  }
  return hits.sort((a, b) => a.start - b.start);
}

/** Three letters in a row: a reason, never judged. */
const LETTERS = /\p{L}{3}/u;

/** Whether the line itself gives `h` a reason (see the module comment). */
function sameLineReason(line: string, read: LineRead, hits: readonly Hit[], h: Hit): boolean {
  let next = line.length;
  let prev = h.part?.start ?? 0;
  for (const o of hits) {
    if (o === h) continue;
    if (o.start >= h.end && o.start < next) next = o.start;
    if (o.end <= h.start && o.end > prev) prev = o.end;
  }
  if (h.row.at === 'code') {
    if (h.row.field !== undefined && h.row.field.test(line.slice(h.start, next))) return true;
    return read.comments.some((p) => p.start >= h.end && LETTERS.test(line.slice(p.start, Math.min(p.end, next))));
  }
  if (h.part === null) return LETTERS.test(line.slice(h.end, next));
  if (LETTERS.test(line.slice(h.end, Math.min(h.part.end, next)))) return true;
  return h.row.at === 'inside' && LETTERS.test(line.slice(Math.max(prev, h.part.start), h.start));
}

/** Whether the line above gives a reason: a whole-line comment with words that is not itself a directive — or a doubt. */
function aboveReason(lines: readonly LineRead[], raw: readonly string[], idx: number, lang: SuppressionLang): boolean {
  const r = lines[idx - 1];
  const text = raw[idx - 1];
  if (r === undefined || text === undefined) return false;
  if (r.literal) return true;
  if (r.substance || r.comments.length === 0) return false;
  if (hitsOn(text, r, lang).length > 0) return false;
  return r.comments.some((p) => LETTERS.test(text.slice(p.start, p.end)));
}

/**
 * What a directive silences: whether it names its rules, whether it covers
 * the whole file, and whether that is a doubt (its arguments may be on the
 * next line: counted, never judged); or skip it.
 */
function readHit(
  h: Hit,
  line: string,
  where: { leading: boolean; packageDoc: boolean },
  testFile: boolean,
): { names: boolean; file: boolean; doubt: boolean } | null {
  const row = h.row;
  const { leading } = where;
  const extra = row.check?.(h.groups, line.slice(h.end)) ?? {};
  if (extra.skip === true) return null;
  if (row.id === 'ts-ignore' && h.groups['kind'] === 'expect-error' && testFile) return null;
  if (row.scope === 'leading-only' && !leading) return null;
  let names: boolean;
  if (row.named === true) names = true;
  else if (extra.names !== undefined) names = extra.names;
  else {
    // A rule named: a word in the list (`NOLINT(*)`, `# type: ignore[]` name none) — never `all` where that means every rule.
    const listed = (h.groups['names'] ?? '').trim();
    names = /\w/.test(listed) && !(row.allNames === true && /^all$/i.test(listed));
  }
  const file =
    h.groups['line'] !== undefined
      ? false
      : h.groups['file'] !== undefined ||
        row.scope === 'file' ||
        row.scope === 'leading-only' ||
        (row.scope === 'leading' && leading) ||
        (row.scope === 'leading-bare' && leading && !names) ||
        (row.scope === 'package-bare' && where.packageDoc && !names);
  // A block comment running on past the line: its arguments may be on the next one.
  return { names, file, doubt: !names && h.part !== null && h.part.unclosed };
}

/** The text a removed directive carries an added one by: its row and its words, from the directive to its comment's end. */
function keyOf(h: Hit, line: string): string {
  const end = h.part !== null ? h.part.end : line.length;
  return `${h.row.id}:${line.slice(h.start, end).trim().replace(/\s+/g, ' ')}`;
}

/** A changed file as the pass reads it. */
export interface SuppressionFile {
  /** Project-relative, `/`-separated: the new path (the old one for a deletion). */
  path: string;
  added: DiffLine[];
  removed: DiffLine[];
  /** The file after the change; null when it was not read (its added lines are not judged). */
  after: string | null;
}

/** What the pass counted (see the module comment). */
export interface SuppressionCounts {
  /** Files read: with a token in an added or removed line. */
  files: number;
  /** New directives: reported + named + reasoned. */
  added: number;
  reported: number;
  /** Naming the rules they silence, with no reason. */
  named: number;
  reasoned: number;
  /** Carried by a removed directive of the same text: not new. */
  carried: number;
  /** Files with added lines whose text was not read (the bound, or unreadable): not judged. */
  unread: number;
}

type Outcome = 'medium' | 'low' | 'named' | 'reasoned';

function outcomeOf(cls: Row['cls'], names: boolean, file: boolean, reasoned: boolean): Outcome {
  if (reasoned) return 'reasoned';
  if (cls === 'scanner') return names ? 'named' : 'medium';
  if (file) return names ? 'low' : 'medium';
  return names ? 'named' : 'low';
}

function finding(h: Hit, path: string, line: number, severity: Severity, names: boolean, file: boolean): Finding {
  const row = h.row;
  const label = `\`${typeof row.label === 'string' ? row.label : row.label(h.groups)}\``;
  if (row.cls === 'scanner') {
    return makeFinding({
      tool: SUPPRESSIONS_TOOL,
      rule_id: 'scanner-suppression-added',
      severity,
      category: 'quality',
      subcategory: 'suppression',
      title: `${path}:${line} adds a ${row.reader} suppression with no reason and no rule named (${label})`,
      message:
        `This change hides ${row.hides ?? `${row.reader}'s findings here`} from every scan, dev-guardian's gate included, and ` +
        `does not say why. If it is a false positive, say so in the scanner's own form (${row.form}); if not, fix the code.`,
      file_path: path,
      line_start: line,
      line_end: line,
    });
  }
  const scope = file ? (names ? ', for the whole file' : ', for the whole file and every rule') : ', for every rule on its line';
  return makeFinding({
    tool: SUPPRESSIONS_TOOL,
    rule_id: 'suppression-added',
    severity,
    category: 'quality',
    subcategory: 'suppression',
    title: `${path}:${line} silences ${row.reader} with no reason (${label}${scope})`,
    message:
      `This change silences ${row.reader} here (${label}${scope}) and does not say why. A suppression is sometimes right — a ` +
      `false positive, a deliberate exception — so say which next to it (${row.form}), or fix what the rule found: an agent ` +
      'copies the suppressions it finds, and one without a reason teaches the next change to silence the same rule.',
    file_path: path,
    line_start: line,
    line_end: line,
  });
}

function splitLines(text: string): string[] {
  return text.split('\n').map((l) => (l.endsWith('\r') ? l.slice(0, -1) : l));
}

/** The index of the first line with code on it — a shebang first line aside; the lines before it are the file's leading ones. */
function firstSubstance(lines: readonly LineRead[], raw: readonly string[]): number {
  for (let i = 0; i < lines.length; i += 1) {
    if (i === 0 && (raw[0] ?? '').startsWith('#!')) continue;
    if (lines[i]?.substance === true) return i;
  }
  return lines.length;
}

/**
 * The lines of the comment group a Go file's `package` clause carries — the
 * group golangci-lint widens a `//nolint` in to the whole file: the lines
 * directly above the first code (no blank line between), when that code is
 * `package` at column 1 and the group's first comment opens at column 1 too
 * (its column must be the clause's). `[from, to)`, or null. A blank line
 * inside a block comment there ends the group early: it reads as smaller,
 * never larger.
 */
function packageDocOf(lines: readonly LineRead[], raw: readonly string[], firstCode: number): { from: number; to: number } | null {
  if (!/^package\b/.test(raw[firstCode] ?? '')) return null;
  let from = firstCode;
  while (from > 0 && NOT_BLANK.test(raw[from - 1] ?? '')) from -= 1;
  const first = lines[from]?.comments[0];
  if (first === undefined || first.start !== first.marker.length) return null;
  return { from, to: firstCode };
}

/** Every finding and count of one change's files (see the module comment). */
export function detectSuppressions(files: readonly SuppressionFile[]): { findings: Finding[]; counts: SuppressionCounts } {
  const counts: SuppressionCounts = { files: 0, added: 0, reported: 0, named: 0, reasoned: 0, carried: 0, unread: 0 };
  const findings: Finding[] = [];
  const read = files.filter((f) => !NOT_TESTS.test(f.path));
  // Every removed directive of the change, by its text: each carries one added directive.
  const carried = new Map<string, number>();
  for (const f of read) {
    const lang = suppressionLanguageOf(f.path);
    if (lang === null) continue;
    for (const r of f.removed) {
      const text = r.text.endsWith('\r') ? r.text.slice(0, -1) : r.text;
      const lexed = readLine(text, LEXERS[lang], CODE).read;
      for (const h of hitsOn(text, lexed, lang)) carried.set(keyOf(h, text), (carried.get(keyOf(h, text)) ?? 0) + 1);
    }
  }
  for (const f of read) {
    const lang = suppressionLanguageOf(f.path);
    if (lang === null) continue;
    counts.files += 1;
    if (f.added.length === 0) continue;
    if (f.after === null) {
      counts.unread += 1;
      continue;
    }
    const raw = splitLines(f.after);
    const lines = readLines(f.after, lang);
    const leadingUntil = firstSubstance(lines, raw);
    const doc = packageDocOf(lines, raw, leadingUntil);
    const testFile = isTestFile(f.path);
    for (const a of f.added) {
      const idx = a.line - 1;
      const text = raw[idx];
      const lexed = lines[idx];
      const addedText = a.text.endsWith('\r') ? a.text.slice(0, -1) : a.text;
      // The diff and the text disagree on this line: a doubt, not read.
      if (text === undefined || lexed === undefined || text !== addedText) continue;
      const hits = hitsOn(text, lexed, lang);
      for (const h of hits) {
        const what = readHit(h, text, { leading: idx < leadingUntil, packageDoc: doc !== null && idx >= doc.from && idx < doc.to }, testFile);
        if (what === null) continue;
        const key = keyOf(h, text);
        const left = carried.get(key) ?? 0;
        if (left > 0) {
          carried.set(key, left - 1);
          counts.carried += 1;
          continue;
        }
        const reasoned = sameLineReason(text, lexed, hits, h) || aboveReason(lines, raw, idx, lang);
        const outcome = what.doubt && !reasoned ? 'named' : outcomeOf(h.row.cls, what.names, what.file, reasoned);
        counts.added += 1;
        if (outcome === 'named') counts.named += 1;
        else if (outcome === 'reasoned') counts.reasoned += 1;
        else {
          counts.reported += 1;
          findings.push(finding(h, f.path, a.line, outcome, what.names, what.file));
        }
      }
    }
  }
  return { findings, counts };
}
