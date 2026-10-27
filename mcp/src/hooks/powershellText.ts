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

/**
 * Where a PowerShell token may start in argument mode: `#` there opens a
 * comment and `<#` a block comment. Not after `=`: `a=#b` is one argument
 * (fix round 5 — `Write-Host "C:\x\" a=#b; Remove-Item …` hid the delete).
 */
const TOKEN_BOUNDARY = /[\s;|&(){},]/;
/** Where a here-string may open: also after `=`, as in `$msg=@'`. */
const HERE_STRING_BOUNDARY = /[\s;|&(){},=]/;

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

/** One of PowerShell's single quotes — never the empty string past the end of the text. */
function isSingleQuote(c: string): boolean {
  return c !== '' && SINGLE_QUOTES.includes(c);
}

/** One of PowerShell's double quotes — never the empty string past the end of the text. */
function isDoubleQuote(c: string): boolean {
  return c !== '' && DOUBLE_QUOTES.includes(c);
}

/**
 * The index just past the `)` that closes a `$(` inside an expandable string,
 * its body starting at `from` — found the way PowerShell's tokenizer finds it,
 * measured with its own parser: by counting parentheses alone, a backtick
 * escaping the next character. A quote, a comment or a here-string in the body
 * neither ends it nor hides a `)` from the count — `"$('"')"` is one string,
 * and `"$(Write-Output ")")"` closes at the first `)`. `-1` when it is never
 * closed: a parse error, which runs nothing.
 */
function subexpressionEnd(text: string, from: number): number {
  let depth = 1;
  for (let i = from; i < text.length; i += 1) {
    const c = text.charAt(i);
    if (c === '`') i += 1;
    else if (c === '(') depth += 1;
    else if (c === ')') {
      depth -= 1;
      if (depth === 0) return i + 1;
    }
  }
  return -1;
}

/** The index just past the `}` that ends a braced variable (`${…}`) whose name starts at `from`: any text, a backtick escaping. */
function bracedVariableEnd(text: string, from: number): number {
  for (let i = from; i < text.length; i += 1) {
    const c = text.charAt(i);
    if (c === '`') i += 1;
    else if (c === '}') return i + 1;
  }
  return text.length;
}

/**
 * The index just past what begins at `i` inside an expandable string and is
 * read as one piece there — a `$( … )` subexpression ({@link subexpressionEnd})
 * or a braced variable (`"${"}"` is one string), to the end of `text` when
 * never closed; `-1` for anything else.
 */
function expandablePieceEnd(text: string, i: number): number {
  if (text.charAt(i) !== '$') return -1;
  const next = text.charAt(i + 1);
  if (next === '{') return bracedVariableEnd(text, i + 2);
  if (next !== '(') return -1;
  const end = subexpressionEnd(text, i + 2);
  return end < 0 ? text.length : end;
}

/**
 * A here-string opened at `at` (`@'` or `@"`, then only blanks to the end of
 * the line): its literal body and the index just past its closing `'@` / `"@`,
 * which PowerShell only recognises at the start of a line — and, in an
 * expandable one, never inside a `$( … )`, whose parentheses PowerShell counts
 * first (`@"⏎$(⏎"@⏎)⏎"@` is one here-string). `null` when `at` does not open
 * one, or it is never closed.
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
  for (let i = start; i < text.length; ) {
    if ((i === start || text.charAt(i - 1) === '\n') && closers.includes(text.charAt(i)) && text.charAt(i + 1) === '@') {
      return { body: text.slice(start, i).replace(/\r?\n$/, ''), next: i + 2 };
    }
    if (single) {
      const nl = text.indexOf('\n', i);
      if (nl < 0) break;
      i = nl + 1;
    } else if (text.charAt(i) === '`') i += 2;
    else if (text.startsWith('$(', i)) {
      const end = subexpressionEnd(text, i + 2);
      if (end < 0) break;
      i = end;
    } else i += 1;
  }
  seen[kind] = start;
  return null;
}

/** Whether a PowerShell token may start at `i`. */
function atBoundary(text: string, i: number, boundary: RegExp = TOKEN_BOUNDARY): boolean {
  return i === 0 || boundary.test(text.charAt(i - 1));
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
    if (atBoundary(text, i, HERE_STRING_BOUNDARY) && text.charAt(i) === '@') {
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
 * Appends the body of each `$( … )` in the expandable string whose text starts
 * at `from` to `out`, and returns the index just past the string: past its
 * closing quote for a `"…"` one (`closes`, where `""` is one quote), the end
 * of `text` for a here-string's body. A backtick escapes, and a braced
 * variable is a name, not code.
 */
function expandableSubexpressions(text: string, from: number, closes: boolean, out: string[]): number {
  let j = from;
  while (j < text.length) {
    const c = text.charAt(j);
    if (c === '`') {
      j += 2;
      continue;
    }
    if (closes && isDoubleQuote(c)) {
      if (!isDoubleQuote(text.charAt(j + 1))) return j + 1;
      j += 2;
      continue;
    }
    if (c === '$' && text.charAt(j + 1) === '(') {
      // The body ends before its `)`, or with the text when it is never closed.
      const end = subexpressionEnd(text, j + 2);
      out.push(text.slice(j + 2, end < 0 ? text.length : end - 1));
      if (end < 0) return text.length;
      j = end;
      continue;
    }
    const piece = expandablePieceEnd(text, j);
    j = piece < 0 ? j + 1 : piece;
  }
  return text.length;
}

/**
 * The bodies of the `$( … )` subexpressions PowerShell runs from INSIDE an
 * expandable string — `"…"` (typographic quotes too) or an `@"…"@` here-string
 * — before it makes the string: `Write-Host "x $(Remove-Item …)"` runs
 * `Remove-Item …`. Not in a single-quoted string, a literal here-string or a
 * comment, not after a backtick (`` `$( `` is text), and not after `--%`,
 * which hands the rest of the line on unexpanded. A string inside a body is
 * reached by reading that body in turn. Each string's extent is PowerShell's
 * ({@link subexpressionEnd}).
 */
export function powershellSubexpressions(text: string): string[] {
  if (!text.includes('$(')) return [];
  const seen = hereStrings();
  const out: string[] = [];
  let i = 0;
  while (i < text.length) {
    const ch = text.charAt(i);
    const boundary = atBoundary(text, i);
    if (ch === '`') {
      i += 2;
      continue;
    }
    if (boundary && text.startsWith('<#', i)) {
      i = blockCommentEnd(text, i);
      continue;
    }
    if (boundary && (ch === '#' || (text.startsWith('--%', i) && /^(?:\s|$)/.test(text.charAt(i + 3))))) {
      // A comment lasts to the end of the line; `--%`'s text to it or a `|`.
      const stops = ch === '#' ? '\n\r' : '\n\r|';
      while (i < text.length && !stops.includes(text.charAt(i))) i += 1;
      continue;
    }
    if (ch === '@' && atBoundary(text, i, HERE_STRING_BOUNDARY)) {
      const here = hereString(text, i, seen);
      if (here !== null) {
        if (isDoubleQuote(text.charAt(i + 1))) expandableSubexpressions(here.body, 0, false, out);
        i = here.next;
        continue;
      }
    }
    if (isSingleQuote(ch)) {
      i = singleQuotedEnd(text, i);
      continue;
    }
    if (ch === '$' && text.charAt(i + 1) === '{') {
      i = bracedVariableEnd(text, i + 2);
      continue;
    }
    i = isDoubleQuote(ch) ? expandableSubexpressions(text, i + 1, true, out) : i + 1;
  }
  return out;
}

/** A braced variable's whole spelling (`${env:USERPROFILE}`, `${C:\x.txt}`) whose characters the POSIX reader reads as written. */
const PLAIN_BRACED_VARIABLE = /^\$\{[\w:.?\\/-]*\}$/;

/** The index just past the `'…'` string opened at `at`, `''` inside it being one quote. */
function singleQuotedEnd(text: string, at: number): number {
  for (let j = at + 1; j < text.length; j += 1) {
    if (!isSingleQuote(text.charAt(j))) continue;
    if (!isSingleQuote(text.charAt(j + 1))) return j + 1;
    j += 1;
  }
  return text.length;
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
 * rest of the line and `<# … #>` is a comment, after `--%` the rest of the
 * line (to a `|`) goes to the program word by word, unparsed, and a script
 * block's braces separate statements. Everything else is left as it is — a
 * reading for the guards, not a PowerShell parser.
 */
export function powershellAsPosix(text: string): string {
  const seen = hereStrings();
  /** Per open `{`: whether it is a `${…}` / `@{…}` literal rather than a script block. */
  const braces: boolean[] = [];
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
      // It lasts to the end of the line or the next `|` (fix round 5).
      while (end < text.length && !'\n\r|'.includes(text.charAt(end))) end += 1;
      const words = text
        .slice(i + 3, end)
        .split(/[ \t]+/)
        .filter((w) => w !== '');
      out += words.map(posixSingle).join(' ');
      i = end;
      continue;
    }
    if (ch === '@' && atBoundary(text, i, HERE_STRING_BOUNDARY)) {
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
        // A subexpression or a braced variable is one piece of the string: a
        // quote inside it does not end the string (`"$('"')"; Remove-Item …`
        // hid the delete). Its own commands are read on their own
        // (`powershellSubexpressions`).
        const piece = double ? expandablePieceEnd(text, j) : -1;
        if (piece >= 0) {
          lit += text.slice(j, piece);
          j = piece;
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
    // A braced variable's name is any text to its `}` — PowerShell's parser
    // reads `${"}` and `${#}` as variables — so one holding a quote, a `#`, a
    // parenthesis or a space is one literal word: read as code, `${"};
    // Remove-Item C:\ …` hid the delete, and `${env:ProgramFiles(x86)}` was
    // split at its `(`. A plain name is left as it was.
    if (ch === '$' && text.charAt(i + 1) === '{') {
      const end = bracedVariableEnd(text, i + 2);
      const spelled = text.slice(i, end);
      if (!PLAIN_BRACED_VARIABLE.test(spelled)) {
        out += posixSingle(spelled);
        i = end;
        continue;
      }
    }
    if (ch === '`') {
      const next = text.charAt(i + 1);
      if (next === '\n') i += 2;
      else if (next === '\r' && text.charAt(i + 2) === '\n') i += 3;
      else {
        // PowerShell ignores a backtick before an ordinary word character, so
        // `` i`ex `` is `iex`: the character continues the bareword unquoted,
        // or the iex / download rules miss it (review of 3.6.0, finding 6). A
        // non-word character (`` `$ ``, `` `" ``) is a literal, kept as one.
        if (next !== '') out += /[A-Za-z0-9_]/.test(next) ? next : posixSingle(next);
        i += 2;
        continue;
      }
      out += ' ';
      continue;
    }
    // A script block is code: `ForEach-Object { Remove-Item … }` runs it
    // (fix round 5). Its braces become statement boundaries; the braces of
    // `${var}` and of a hashtable `@{…}` stay what they are.
    if (ch === '{') {
      const literal = /[$@]/.test(text.charAt(i - 1));
      braces.push(literal);
      out += literal ? '{' : ' ; ';
      i += 1;
      continue;
    }
    if (ch === '}') {
      out += braces.pop() === true ? '}' : ' ; ';
      i += 1;
      continue;
    }
    if (ch === '\\') out += '\\\\';
    else if (ch === ',' || UNICODE_SPACE.test(ch)) out += ' ';
    else out += ch;
    i += 1;
  }
  return out;
}
