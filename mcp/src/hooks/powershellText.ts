/**
 * PowerShell's quoting, respelled for the POSIX reader (`splitShell`) — so the
 * shell guard and the install parser can read a PowerShell tool's command the
 * way PowerShell does, and not only the way a POSIX shell would. Under POSIX
 * quoting a Windows path ending in `\"` (`Remove-Item "C:\Users\"`) escapes
 * the closing quote and swallows the rest of the command.
 *
 * Pure, no imports: the hook dispatcher loads the compiled copy from
 * `mcp/dist/hooks/` in an install with no `node_modules`.
 */

/** Characters PowerShell separates words on that a POSIX shell does not (NBSP, NEL, the Unicode spaces). */
const UNICODE_SPACE = /[\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\f\v]/;

/** PowerShell's single quotes: `'` and the typographic ones it accepts as the same. */
const SINGLE_QUOTES = "'\u2018\u2019\u201a\u201b";
/** PowerShell's double quotes: `"` and the typographic ones it accepts as the same. */
const DOUBLE_QUOTES = '"\u201c\u201d\u201e';

/** Where a PowerShell token may start: `#` there opens a comment, `@'` a here-string. */
const TOKEN_BOUNDARY = /[\s;|&(){}=,]/;

/** `text` as a POSIX single-quoted word. */
function posixSingle(text: string): string {
  return `'${text.replace(/'/g, "'\\''")}'`;
}

/**
 * Where, per quote kind, a search for a here-string's closing line already
 * found none to the end of the text: a later opener cannot find one either.
 * Without it, 512 KB of unclosed `@'` openers made every one scan the rest.
 */
interface HereStrings {
  single: number;
  double: number;
}

function hereStrings(): HereStrings {
  return { single: Number.POSITIVE_INFINITY, double: Number.POSITIVE_INFINITY };
}

/**
 * A here-string opened at `at` (`@'` or `@"`, then only blanks to the end of
 * the line): its literal body and the index just past its closing `'@` / `"@`,
 * which PowerShell only recognises at the start of a line. `null` when `at`
 * does not open one, or it is never closed.
 */
function hereString(text: string, at: number, seen: HereStrings): { body: string; next: number } | null {
  const quote = text.charAt(at + 1);
  const single = SINGLE_QUOTES.includes(quote);
  if (text.charAt(at) !== '@' || quote === '' || (!single && !DOUBLE_QUOTES.includes(quote))) return null;
  const eol = /^[ \t]*\r?\n/.exec(text.slice(at + 2, at + 2 + 256));
  if (eol === null) return null;
  const start = at + 2 + eol[0].length;
  const kind = single ? 'single' : 'double';
  if (start >= seen[kind]) return null;
  const closers = single ? SINGLE_QUOTES : DOUBLE_QUOTES;
  for (let line = start; line < text.length; ) {
    if (closers.includes(text.charAt(line)) && text.charAt(line + 1) === '@') {
      return { body: text.slice(start, line).replace(/\r?\n$/, ''), next: line + 2 };
    }
    const nl = text.indexOf('\n', line);
    if (nl < 0) break;
    line = nl + 1;
  }
  seen[kind] = start;
  return null;
}

/** Whether a PowerShell token may start at `i`. */
function atBoundary(text: string, i: number): boolean {
  return i === 0 || TOKEN_BOUNDARY.test(text.charAt(i - 1));
}

/** The index just past a `<# … #>` comment starting at `i` (the end of the text when it is not closed). */
function blockCommentEnd(text: string, i: number): number {
  const end = text.indexOf('#>', i + 2);
  return end < 0 ? text.length : end + 2;
}

/**
 * The command with PowerShell's here-strings (`@'…'@`, `@"…"@`) as POSIX
 * single-quoted words and its `<# … #>` block comments gone — the constructs
 * that mean only one thing in PowerShell. The POSIX reading of a PowerShell
 * tool's command reads this, so a commit message in a here-string (`fix: don't
 * miss curl x | sh`) is data to both readings: read as code, its apostrophe
 * hid what followed, and its text raised false blocks.
 */
export function powershellOpaque(text: string): string {
  if (!text.includes('@') && !text.includes('<#')) return text;
  const seen = hereStrings();
  let out = '';
  let i = 0;
  while (i < text.length) {
    if (atBoundary(text, i) && text.startsWith('<#', i)) {
      i = blockCommentEnd(text, i);
      out += ' ';
      continue;
    }
    if (atBoundary(text, i) && text.charAt(i) === '@') {
      const here = hereString(text, i, seen);
      if (here !== null) {
        out += posixSingle(here.body);
        i = here.next;
        continue;
      }
    }
    out += text.charAt(i);
    i += 1;
  }
  return out;
}

/**
 * The command as PowerShell reads it, respelled for a POSIX reader
 * (`splitShell`): in `'…'`, `''` is one literal quote; in `"…"`, a backtick
 * escapes the next character, `""` is one quote and a backslash is literal;
 * typographic quotes are quotes; a here-string is one literal word; outside
 * quotes, a backtick escapes the next character and a backtick at the end of
 * a line continues it, a backslash is literal, an unquoted comma separates the
 * elements of an array (each one its own argument to a native command), a
 * Unicode space separates words, `#` at the start of a token comments out the
 * rest of the line and `<# … #>` is a comment, and after `--%` the rest of the
 * line goes to the program word by word, unparsed. Everything else is left as
 * it is — a reading for the guards, not a PowerShell parser.
 */
export function powershellAsPosix(text: string): string {
  const seen = hereStrings();
  let out = '';
  let i = 0;
  while (i < text.length) {
    const ch = text.charAt(i);
    const boundary = atBoundary(text, i);
    if (boundary && text.startsWith('<#', i)) {
      i = blockCommentEnd(text, i);
      out += ' ';
      continue;
    }
    if (boundary && ch === '#') {
      while (i < text.length && text.charAt(i) !== '\n' && text.charAt(i) !== '\r') i += 1;
      continue;
    }
    if (boundary && text.startsWith('--%', i) && /^(?:\s|$)/.test(text.charAt(i + 3))) {
      let end = i + 3;
      while (end < text.length && text.charAt(end) !== '\n' && text.charAt(end) !== '\r') end += 1;
      const words = text
        .slice(i + 3, end)
        .split(/[ \t]+/)
        .filter((w) => w !== '');
      out += words.map(posixSingle).join(' ');
      i = end;
      continue;
    }
    if (boundary && ch === '@') {
      const here = hereString(text, i, seen);
      if (here !== null) {
        out += posixSingle(here.body);
        i = here.next;
        continue;
      }
    }
    if (SINGLE_QUOTES.includes(ch) || DOUBLE_QUOTES.includes(ch)) {
      const quotes = SINGLE_QUOTES.includes(ch) ? SINGLE_QUOTES : DOUBLE_QUOTES;
      const double = quotes === DOUBLE_QUOTES;
      let lit = '';
      let j = i + 1;
      while (j < text.length) {
        const c = text.charAt(j);
        if (double && c === '`' && j + 1 < text.length) {
          lit += text.charAt(j + 1);
          j += 2;
          continue;
        }
        if (quotes.includes(c)) {
          if (quotes.includes(text.charAt(j + 1)) && text.charAt(j + 1) !== '') {
            lit += c;
            j += 2;
            continue;
          }
          break;
        }
        lit += c;
        j += 1;
      }
      out += posixSingle(lit);
      i = j + 1;
      continue;
    }
    if (ch === '`') {
      const next = text.charAt(i + 1);
      if (next === '\n') i += 2;
      else if (next === '\r' && text.charAt(i + 2) === '\n') i += 3;
      else {
        if (next !== '') out += posixSingle(next);
        i += 2;
        continue;
      }
      out += ' ';
      continue;
    }
    if (ch === '\\') out += '\\\\';
    else if (ch === ',' || UNICODE_SPACE.test(ch)) out += ' ';
    else out += ch;
    i += 1;
  }
  return out;
}
