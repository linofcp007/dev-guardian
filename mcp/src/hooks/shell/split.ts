/**
 * The shell tokenizer the guardrail hooks read a command with: statements,
 * pipeline members and words, quote-, escape- and heredoc-aware. Moved out of
 * `bashGuard.ts` (which explains why it segments at all) so that the install
 * vetting's parser can read a command without loading the whole guard.
 *
 * Pure functions. No I/O. No dependencies.
 */

// ─────────────────────────────────────────────────────────── shell scanning

/**
 * Stands in for a quoted span in the text a pattern is matched against.
 *
 * A single space, so a quoted argument contributes *word separation and
 * nothing else*: `echo 'git push --force'` masks to `echo`, while
 * `git push --force "$REMOTE"` and `chmod -R 777 "$dir"` still match — the
 * hazard is in the unquoted words there and the quoted one is a mere operand.
 * An opaque non-space sentinel was the other candidate and gains nothing:
 * quoted spans never carry a separator, so a space cannot let a match cross
 * a boundary that segmentation already removed, and it breaks `\s` — which
 * would stop `> "$HOME"/.bash_history` reading as a history wipe.
 */
export const MASK = ' ';

export interface ShellWord {
  /** The word after quote removal — what the shell would actually pass. */
  value: string;
  /** True when any character of the word came from inside quotes. */
  quoted: boolean;
  /**
   * Offsets in `value` of each `<` or `>` that was UNQUOTED code — a
   * redirection operator, not data (`echo "a > b"` has none). Absent when
   * there is none.
   */
  redirectAt?: number[];
}

export interface ShellStatement {
  /** Raw statement text with every quoted span replaced by {@link MASK}. */
  masked: string;
  /** Pipeline members, one word list per simple command. */
  commands: ShellWord[][];
  /**
   * The body text of every heredoc opened on this statement's line, in
   * order. Data on the receiving command's stdin, not shell code in
   * general — `git commit -F - <<'EOF'` never executes it — EXCEPT when the
   * receiving command is itself a bare shell reading a script from stdin
   * (`bash <<EOF … EOF`), which is exactly what this exists for
   * `collect()` to recognise. Undefined when this statement opened none.
   */
  heredocBodies?: string[];
  /** The separator that ended this statement; absent for the last one. */
  end?: StatementEnd;
}

/** What ends a statement: a list operator, a line end, or a subshell / substitution boundary. */
export type StatementEnd = '&&' | '||' | ';' | '&' | '\n' | '(' | ')' | '`';

export interface ShellSplit {
  /** The whole command, masked, with separators intact and heredocs removed. */
  maskedCommand: string;
  /**
   * `maskedCommand` with, after the mask of each double-quoted span, the
   * variables that span interpolates ({@link interpolatedVariables}): `$b =
   * "$a"` reads `$b =  $a `. A copy through a string is still a copy — the
   * one thing {@link powershellDownloadExecution} reads this for; every other
   * rule reads `maskedCommand`, where a quoted span is data. A quoted variable
   * NAME where a name goes (`-OutVariable 'r'`, {@link quotedName}) is
   * written back the same way, so it names that variable and no other.
   */
  interpolatedCommand: string;
  statements: ShellStatement[];
}

interface PendingHeredoc {
  word: string;
  /**
   * The statement that OPENED this heredoc — captured by reference at the
   * moment `<<` is parsed, while that statement is still being built (see
   * `currentStatement` in `splitShell`). Never the statement that happens to
   * be last on the source line: `bash <<EOF; echo done` has two statements
   * on one line, and the heredoc belongs to the first, not `echo done`.
   */
  statement: ShellStatement;
}

/** Reads a quoted span starting at `start`, returning its content and the index after it. */
function scanQuote(source: string, start: number): { inner: string; next: number } {
  const quote = source.charAt(start);
  let inner = '';
  let i = start + 1;
  while (i < source.length) {
    const ch = source.charAt(i);
    if (quote === '"' && ch === '\\') {
      const next = source.charAt(i + 1);
      if (next === '"' || next === '\\' || next === '$' || next === '`') {
        inner += next;
        i += 2;
        continue;
      }
      if (next === '\n') {
        i += 2;
        continue;
      }
      inner += ch;
      i += 1;
      continue;
    }
    if (ch === quote) return { inner, next: i + 1 };
    inner += ch;
    i += 1;
  }
  // Unterminated quote: treat the rest of the input as quoted.
  return { inner, next: source.length };
}

/**
 * A variable a double-quoted string interpolates (`$a`, `${a}`, `$script:a`),
 * a subexpression opening, or a parenthesis — the tokens
 * {@link interpolatedVariables} reads. `${…}` is capped, so a run of unclosed
 * `${` cannot make each one rescan the rest.
 */
const INTERPOLATION = /\$\{[^}\n]{0,128}\}|\$[\w:]+|\$\(|[()]/g;

/**
 * The variables a double-quoted string's text interpolates, as written: `$a`
 * and `${a}` in the string itself — its whole value, whatever follows
 * (`"$a.txt"` is `$a` and then `.txt`) — and, inside a `$( … )` subexpression,
 * one that is not read for a member or an index: `"$($items.Count)"` holds a
 * count, not `$items`.
 */
function interpolatedVariables(inner: string): string[] {
  if (!inner.includes('$')) return [];
  const out: string[] = [];
  let depth = 0;
  for (const m of inner.matchAll(INTERPOLATION)) {
    const t = m[0];
    if (t === '$(') depth += 1;
    else if (t === '(') depth += depth > 0 ? 1 : 0;
    else if (t === ')') depth -= depth > 0 ? 1 : 0;
    else {
      const next = inner.charAt(m.index + t.length);
      if (depth === 0 || (next !== '.' && next !== '[')) out.push(t);
    }
  }
  return out;
}

/**
 * The end of the masked text where a variable's NAME comes next: after
 * `-OutVariable` / `-ov`, `Tee-Object`'s `-Variable`, `-Name`, or right after
 * `Set-` / `New-` / `Get-Variable`. A quoted name there is written back too
 * (review 3.0 wave 2, round 2), so `-OutVariable 'r'` fills `$r` and not, as a
 * masked name did, every variable.
 */
const NAME_POSITION =
  /(?:(?:^|[\s;|&(])-(?:ov|outv[a-z]*|v[a-z]*|n[a-z]*)[ \t]*:?[ \t]*|(?:^|[\s;|&(])(?:set-variable|new-variable|get-variable|sv|nv|gv)[ \t]+)$/i;
/** A variable's name, with its scope — never one of the words the flow tokens read as a command. */
const QUOTED_NAME = /^(?:(?:global|script|local|private|using|variable):)?[A-Za-z_]\w{0,63}$/i;
const TOKEN_WORD =
  /^(?:iex|invoke-expression|irm|iwr|invoke-restmethod|invoke-webrequest|curl|wget|set-variable|new-variable|get-variable|sv|nv|gv|tee|tee-object)$/i;

/** A quoted span's text, when it is a variable's name in a place a name goes ({@link NAME_POSITION}). */
function quotedName(maskedBefore: string, inner: string): string | undefined {
  if (!QUOTED_NAME.test(inner) || TOKEN_WORD.test(inner)) return undefined;
  return NAME_POSITION.test(maskedBefore.slice(-48)) ? inner : undefined;
}

/** `masked` with each interpolation's variables written back after the mask that ends at its offset. */
function withInterpolations(masked: string, interpolations: ReadonlyArray<{ at: number; vars: string }>): string {
  if (interpolations.length === 0) return masked;
  let out = '';
  let from = 0;
  for (const { at, vars } of interpolations) {
    out += `${masked.slice(from, at)}${vars} `;
    from = at;
  }
  return out + masked.slice(from);
}

const HEREDOC_WORD = /^[A-Za-z_][A-Za-z0-9_]*$/;

/**
 * Reads a `<<`/`<<-` heredoc operator at `start`. Returns null when the
 * delimiter is not a plain identifier — `$((1 << 2))` must not be mistaken for
 * a heredoc, because doing so would swallow the rest of the command.
 */
function readHeredocOperator(
  source: string,
  start: number,
): { word: string; next: number } | null {
  let i = start + 2;
  if (source.charAt(i) === '-') i += 1; // `<<-` strips leading tabs from the body
  while (source.charAt(i) === ' ' || source.charAt(i) === '\t') i += 1;

  const quote = source.charAt(i);
  let word = '';
  if (quote === "'" || quote === '"') {
    const scanned = scanQuote(source, i);
    word = scanned.inner;
    i = scanned.next;
  } else {
    while (i < source.length && /[A-Za-z0-9_]/.test(source.charAt(i))) {
      word += source.charAt(i);
      i += 1;
    }
  }
  if (!HEREDOC_WORD.test(word)) return null;
  return { word, next: i };
}

/**
 * Attaches a captured heredoc body to the statement that opened it
 * ({@link PendingHeredoc.statement}), appending rather than overwriting —
 * `bash <<A; bash <<B` opens two heredocs on the SAME statement's command
 * list in principle (two simple commands, but if a single command opened
 * two, e.g. via redirection tricks, both bodies belong to it).
 */
function attachHeredocBody(heredoc: PendingHeredoc, body: string): void {
  const target = heredoc.statement;
  if (target.heredocBodies === undefined) target.heredocBodies = [];
  target.heredocBodies.push(body);
}

/**
 * Skips the bodies of every heredoc opened on the line just ended, CAPTURING
 * each body's text along the way and attaching it to the STATEMENT THAT
 * OPENED IT (`heredoc.statement`, set when `<<` was parsed) — never to
 * whichever statement happens to be last on the source line. That
 * distinction matters the moment a line carries more than one statement:
 * `bash <<EOF; echo done` opens its heredoc on `bash`, and `echo done` is a
 * second, unrelated statement that follows it on the same line; attaching by
 * position (`statements[statements.length - 1]`) attached to `echo done`
 * instead, so `bash`'s own heredoc — the one shape this file exists to
 * assess as a command — silently lost its body. `bash <<A; cat <<B` was the
 * other failure mode of that same bug: two heredocs opened on one line, both
 * bodies landing on the second statement (`cat`) and none on the first.
 *
 * The body is data on the command's stdin, never shell code in general; a
 * commit message written through `git commit -F - <<'EOF'` is the shape that
 * made skipping necessary in the first place. It is captured, not just
 * skipped, because that stops being true for exactly one shape — `bash
 * <<EOF … EOF` hands the body to bash as the script it runs — and
 * `collect()` is what tells the two apart, by whether the statement's own
 * command is a shell reading stdin (`scriptReader` in bashGuard.ts); this
 * function has no way to know that itself, since it only ever sees raw
 * source text, not resolved commands.
 *
 * The delimiter is matched on the trimmed line, which covers `<<` and `<<-`
 * alike and errs toward ending the heredoc *early*. That is the safe side:
 * ending early resumes treating text as shell, so the worst case is a false
 * positive, never a hazard swallowed as data.
 */
function skipHeredocBodies(source: string, from: number, pending: PendingHeredoc[]): number {
  let pos = from;
  while (pending.length > 0) {
    const heredoc = pending.shift();
    if (heredoc === undefined) break;
    const lines: string[] = [];
    for (;;) {
      if (pos >= source.length) {
        attachHeredocBody(heredoc, lines.join('\n'));
        return source.length;
      }
      const newline = source.indexOf('\n', pos);
      const line = newline === -1 ? source.slice(pos) : source.slice(pos, newline);
      pos = newline === -1 ? source.length : newline + 1;
      if (line.trim() === heredoc.word) break;
      lines.push(line);
      if (newline === -1) {
        attachHeredocBody(heredoc, lines.join('\n'));
        return source.length;
      }
    }
    attachHeredocBody(heredoc, lines.join('\n'));
  }
  return pos;
}

/**
 * Shell reserved words that can stand where a command name belongs and are not
 * themselves a command: the words that open or close a loop, a conditional or
 * a brace group, plus `!` (pipeline negation). `splitShell` drops one of these
 * — unquoted, at a command position — so the command that follows it is the
 * one the rules see. Never `for`/`case`/`select`: the words after those are a
 * variable name and a word list, not a command.
 */
const COMPOUND_RESERVED = new Set(['if', 'then', 'elif', 'else', 'fi', 'while', 'until', 'do', 'done', 'esac', '{', '}', '!']);

/**
 * Segments a command into statements and their pipeline members. Quote-,
 * escape- and heredoc-aware; not a shell parser (see the module comment).
 * The body of a compound command is split like any other statement: the
 * separators around it (`;`, newline, `&&`, `|`) already end a statement, and
 * the reserved word that opens it is dropped (`COMPOUND_RESERVED`).
 */
export function splitShell(command: string): ShellSplit {
  const statements: ShellStatement[] = [];
  let maskedCommand = '';
  /** Where in `maskedCommand` a double-quoted span's mask ends, and the variables it interpolates. */
  const interpolations: Array<{ at: number; vars: string }> = [];

  let masked = '';
  let commands: ShellWord[][] = [];
  let words: ShellWord[] = [];
  let buf = '';
  let bufQuoted = false;
  let bufRedirects: number[] = [];
  let hasWord = false;
  /** Every word of the current command after its first is an unquoted `-` flag. */
  let dashTail = true;
  /** Last code character emitted, to tell a background `&` from `2>&1`. */
  let lastCode = '';
  const heredocs: PendingHeredoc[] = [];
  /**
   * What each open `(` is: `word` for a substitution that is part of a word
   * (`$(`, `$((`, `<(`, `>(`, `=(`, `@(`), `group` for a subshell. After a
   * `)` that closed a word — or after a closing backtick — a `#` continues the
   * word and is no comment: `echo $(date)#x; rm -rf /` runs `rm` (fix round 5).
   */
  const parens: Array<'word' | 'group' | 'case'> = [];
  let closedWord = false;
  let inBacktick = false;
  /**
   * The `ShellStatement` object for whatever statement is currently being
   * built — created up front, then mutated (not replaced) by `endStatement`
   * once its `masked`/`commands` are known, and pushed by that SAME
   * reference. A heredoc opened mid-statement (`<<` is parsed by
   * `heredocs.push`, below) records a reference to this object — the object
   * identity is what lets its body attach to the right statement later, once
   * `skipHeredocBodies` reads it, even though the two events (opening a
   * heredoc, and reading its body) happen many characters apart and possibly
   * after other statements/heredocs on the same source line.
   */
  let currentStatement: ShellStatement = { masked: '', commands: [] };

  const endWord = (): void => {
    // A reserved word where a command name belongs opens or closes a compound
    // command (`do rm -rf /`, `then …`, `{ …`); the command is the word AFTER
    // it. Kept, it read as a command called `do`, and every loop, `if` and
    // brace-group body went unassessed (final review I13).
    const reserved = hasWord && !bufQuoted && words.length === 0 && COMPOUND_RESERVED.has(buf);
    // `case … esac` patterns end in a bare `)`: inside `$(…)` they must not
    // close the substitution (fix round 6).
    if (hasWord && !bufQuoted && words.length === 0) {
      if (buf === 'case') parens.push('case');
      else if (buf === 'esac' && parens[parens.length - 1] === 'case') parens.pop();
    }
    // A `{` also opens a body after a function header (`function f { … }`) and
    // after the `time` runner (`time { … }`, `time -p { … }`). The header is not
    // a command, so it goes with the brace; `time` stays, a runner the command
    // after the brace is resolved through (re-review follow-up to I13).
    const opensBody = hasWord && !bufQuoted && buf === '{';
    const first = words[0];
    const unquotedHead = first !== undefined && !first.quoted ? first.value : '';
    if (opensBody && unquotedHead === 'function' && words.length === 2) {
      words = [];
      dashTail = true;
      buf = '';
      bufQuoted = false;
      bufRedirects = [];
      hasWord = false;
      return;
    }
    // `dashTail`: every word after the first is an unquoted `-` flag — kept
    // as the words arrive (re-checking them at every `{` was quadratic).
    const afterTime = opensBody && unquotedHead === 'time' && dashTail;
    if (hasWord && !reserved && !afterTime) {
      if (words.length >= 1 && (bufQuoted || !buf.startsWith('-'))) dashTail = false;
      words.push(
        bufRedirects.length > 0
          ? { value: buf, quoted: bufQuoted, redirectAt: bufRedirects }
          : { value: buf, quoted: bufQuoted },
      );
    }
    buf = '';
    bufQuoted = false;
    bufRedirects = [];
    hasWord = false;
  };
  const endCommand = (): void => {
    endWord();
    if (words.length > 0) commands.push(words);
    words = [];
    dashTail = true;
  };
  const endStatement = (end?: StatementEnd): void => {
    endCommand();
    const text = masked.trim();
    if (text.length > 0 || commands.length > 0) {
      currentStatement.masked = text;
      currentStatement.commands = commands;
      if (end !== undefined) currentStatement.end = end;
      statements.push(currentStatement);
    }
    masked = '';
    commands = [];
    lastCode = '';
    currentStatement = { masked: '', commands: [] };
  };
  const emitCode = (ch: string): void => {
    if (ch === '>' || ch === '<') bufRedirects.push(buf.length);
    buf += ch;
    hasWord = true;
    masked += ch;
    maskedCommand += ch;
    lastCode = ch;
  };

  let i = 0;
  while (i < command.length) {
    const ch = command.charAt(i);

    if (ch === '\\') {
      const next = command.charAt(i + 1);
      if (next === '') {
        emitCode('\\');
        i += 1;
        continue;
      }
      if (next === '\n') {
        i += 2; // line continuation
        continue;
      }
      // Escaped literal — the character loses any special meaning, which is
      // what keeps `find … -exec rm {} \;` a single statement.
      buf += next;
      hasWord = true;
      masked += next;
      maskedCommand += next;
      lastCode = '';
      i += 2;
      continue;
    }

    // A `#` that starts a word comments out the rest of the line, in a POSIX
    // shell and in PowerShell alike. Read as code, the apostrophe in `# clean
    // the user's build dir` opened a quote that ran to the end of the command
    // and hid every line after it — `rm -rf /` included (fix round 4, C1).
    // Heredoc bodies never reach here (`skipHeredocBodies`).
    if (ch === '#' && !hasWord && !(closedWord && /[)`]/.test(command.charAt(i - 1)))) {
      while (i < command.length && command.charAt(i) !== '\n' && command.charAt(i) !== '\r') i += 1;
      continue;
    }

    if (ch === "'" || ch === '"') {
      const scanned = scanQuote(command, i);
      buf += scanned.inner;
      bufQuoted = true;
      hasWord = true;
      const name = quotedName(maskedCommand, scanned.inner);
      masked += MASK;
      maskedCommand += MASK;
      const vars = ch === '"' ? interpolatedVariables(scanned.inner) : [];
      if (name !== undefined) vars.push(name);
      if (vars.length > 0) interpolations.push({ at: maskedCommand.length, vars: vars.join(' ') });
      lastCode = MASK;
      i = scanned.next;
      continue;
    }

    if (ch === '\n') {
      endStatement('\n');
      maskedCommand += '\n';
      // skipHeredocBodies attaches each body directly, via the statement
      // reference each PendingHeredoc recorded when its `<<` was parsed —
      // not to whichever statement is last here. `endStatement()` above may
      // have just pushed several statements onto a single line before this
      // point (every `;` on the line already ran it), so "last" would be
      // wrong whenever more than one statement shares this line.
      i = heredocs.length > 0 ? skipHeredocBodies(command, i + 1, heredocs) : i + 1;
      continue;
    }

    if (ch === ';') {
      endStatement(';');
      maskedCommand += ';';
      i += 1;
      continue;
    }

    // A bare CR — not the first half of CRLF — ends a line in PowerShell, so
    // a `cd` and the write after it are two statements (fix round 1, M5). A
    // POSIX shell reads it as part of a word; ending the statement there only
    // ever assesses more. Pending heredocs keep waiting for the real newline.
    if (ch === '\r' && command.charAt(i + 1) !== '\n') {
      endStatement('\n');
      maskedCommand += '\n';
      i += 1;
      continue;
    }

    // Subshells, groups and command substitution: whatever is inside runs as
    // its own command, so the boundary is a statement boundary.
    if (ch === '(' || ch === ')' || ch === '`') {
      if (ch === '(') parens.push(/[$<>=@(]/.test(command.charAt(i - 1)) ? 'word' : 'group');
      // A `case` pattern's `)` has no `(` of its own (fix round 6); an `esac`
      // right before this `)` has closed its `case` already.
      else if (ch === ')') {
        if (buf === 'esac' && !bufQuoted && words.length === 0 && parens[parens.length - 1] === 'case') parens.pop();
        closedWord = parens[parens.length - 1] === 'case' ? false : parens.pop() === 'word';
      }
      else {
        closedWord = inBacktick;
        inBacktick = !inBacktick;
      }
      endStatement(ch === '(' ? '(' : ch === ')' ? ')' : '`');
      maskedCommand += ch;
      i += 1;
      continue;
    }

    if (ch === '&') {
      const next = command.charAt(i + 1);
      if (next === '&') {
        endStatement('&&');
        maskedCommand += '&&';
        i += 2;
        continue;
      }
      // `2>&1`, `&>log`, `|&` — a redirection, not a separator.
      if (next === '>' || lastCode === '>' || lastCode === '<' || lastCode === '|') {
        emitCode('&');
        i += 1;
        continue;
      }
      endStatement('&');
      maskedCommand += '&';
      i += 1;
      continue;
    }

    if (ch === '|') {
      // `>|` is a redirection (write, overriding noclobber), not a pipe.
      if (lastCode === '>') {
        emitCode('|');
        i += 1;
        continue;
      }
      const next = command.charAt(i + 1);
      if (next === '|') {
        endStatement('||');
        maskedCommand += '||';
        i += 2;
        continue;
      }
      // A pipe stays *inside* the statement: `curl … | sh` is one hazard.
      endCommand();
      masked += '|';
      maskedCommand += '|';
      lastCode = '|';
      i += 1;
      continue;
    }

    // Not the tail of a `<<<` here-string, whose `<<x` is no heredoc (fix round 5).
    if (ch === '<' && command.charAt(i + 1) === '<' && command.charAt(i + 2) !== '<' && command.charAt(i - 1) !== '<') {
      const heredoc = readHeredocOperator(command, i);
      if (heredoc !== null) {
        heredocs.push({ word: heredoc.word, statement: currentStatement });
        endWord();
        masked += ' ';
        maskedCommand += ' ';
        lastCode = '';
        i = heredoc.next;
        continue;
      }
    }

    if (ch === ' ' || ch === '\t' || ch === '\r') {
      endWord();
      masked += ' ';
      maskedCommand += ch;
      i += 1;
      continue;
    }

    emitCode(ch);
    i += 1;
  }
  endStatement();

  return { maskedCommand, interpolatedCommand: withInterpolations(maskedCommand, interpolations), statements };
}

