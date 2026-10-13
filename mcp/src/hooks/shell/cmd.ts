/**
 * cmd.exe's command line as the shell guard reads it: `cmd /c LINE` (or `/k`)
 * split into its commands — on `&`, `&&`, `||` and `|` outside double quotes —
 * each command into its words and the files its `>` / `>>` write, the commands
 * of nested `cmd /c` lines flattened, and the whole line respelled for the
 * POSIX reader so the full assessment judges it as a shell line. Moved out of
 * `bashGuard.ts`, which judges what those commands do (`cmdEffects` there
 * models their file effects).
 *
 * Pure functions. No I/O.
 */

import { pushAll } from './arrays.js';
import { cmdSwitch } from './command.js';
import type { ShellWord } from './split.js';

/** A cmd.exe command: its words, and the files its `>` / `>>` redirections write. */
interface CmdCommand {
  words: string[];
  redirects: string[];
}

/**
 * Splits a cmd.exe command line into its commands — on `&`, `&&`, `||` and `|`
 * outside double quotes — and each command into words, on whitespace outside
 * double quotes. Quotes are removed, backslashes are literal, and `^` escapes
 * the next character (`^&` is a literal `&`), as in cmd. A `>` or `>>` (after an
 * optional descriptor digit) makes the next word a file the command writes;
 * `>&1` duplicates a descriptor and names none; `<` reads a file.
 */
function splitCmdLine(line: string): CmdCommand[] {
  const commands: CmdCommand[] = [];
  let words: string[] = [];
  let redirects: string[] = [];
  let cur = '';
  let inQuote = false;
  let has = false;
  let role: 'arg' | 'write' | 'read' = 'arg';
  const endWord = (): void => {
    if (has) {
      if (role === 'write') redirects.push(cur);
      else if (role === 'arg') words.push(cur);
      role = 'arg';
    }
    cur = '';
    has = false;
  };
  const endCommand = (): void => {
    endWord();
    role = 'arg';
    if (words.length > 0 || redirects.length > 0) commands.push({ words, redirects });
    words = [];
    redirects = [];
  };
  for (let i = 0; i < line.length; i += 1) {
    const ch = line.charAt(i);
    if (ch === '"') {
      inQuote = !inQuote;
      has = true;
    } else if (!inQuote && ch === '^' && i + 1 < line.length) {
      i += 1;
      cur += line.charAt(i);
      has = true;
    } else if (!inQuote && (ch === '&' || ch === '|')) {
      endCommand();
      if (line.charAt(i + 1) === ch) i += 1;
    } else if (!inQuote && (ch === '>' || ch === '<')) {
      if (has && /^\d$/.test(cur)) {
        cur = '';
        has = false;
      } else endWord();
      if (ch === '>' && line.charAt(i + 1) === '>') i += 1;
      if (line.charAt(i + 1) === '&') {
        i += 1;
        while (/\d/.test(line.charAt(i + 1))) i += 1;
        continue;
      }
      role = ch === '>' ? 'write' : 'read';
    } else if (!inQuote && /\s/.test(ch)) {
      if (has) endWord();
    } else {
      cur += ch;
      has = true;
    }
  }
  endCommand();
  return commands;
}

/** A cmd.exe command's own name and arguments, past a leading `@` and any `call`. */
export function cmdCommandWords(words: readonly string[]): string[] {
  const out = [...words];
  const first = out[0];
  if (first !== undefined && first.startsWith('@')) {
    if (first.length > 1) out[0] = first.slice(1);
    else out.shift();
  }
  while (out.length > 0 && (out[0] ?? '').toLowerCase() === 'call') out.shift();
  return out;
}

/** `cmd /c cmd /c …` nesting judged; deeper is not (a chain thousands deep once overflowed the stack). */
export const MAX_CMD_NESTING = 8;

/** A word as a POSIX shell word that reads back as exactly itself. */
export function posixWord(word: string): string {
  return /^[A-Za-z0-9_./:@%+=,-]+$/.test(word) ? word : `'${word.replace(/'/g, "'\\''")}'`;
}

/**
 * The line `cmd /c LINE` (or `/k`) runs, as text for the full assessment
 * (`collect`). A first word that is itself a whole line (`cmd /c "rd /s /q
 * C:\ & echo"`) is kept as written, its backslashes doubled — cmd reads them
 * literally, a POSIX reader as escapes — and its `^x` escapes outside double
 * quotes become POSIX `\x`, so `echo a ^& b` stays one command; every later
 * shell word is quoted so it reads back as itself (`cmd /c rd /s /q C:\` keeps
 * its `C:\`). cmd's own `&`, `&&`, `||` and `|` read the same way to the
 * POSIX reader.
 */
export function cmdLineText(rawArgs: readonly string[]): string | undefined {
  const args = rawArgs.map(cmdSwitch);
  const at = args.findIndex((a) => /^\/[ck]$/i.test(a));
  if (at < 0) return undefined;
  const [first, ...more] = args.slice(at + 1);
  if (first === undefined) return undefined;
  const head = /[\s&|^<>]/.test(first.trim()) ? cmdTextAsPosix(first) : posixWord(first);
  return [head, ...more.map(posixWord)].join(' ');
}

/** A cmd line respelled for the POSIX reader: `\` literal, `^x` outside double quotes an escaped `x`. */
function cmdTextAsPosix(line: string): string {
  let out = '';
  let inQuote = false;
  for (let i = 0; i < line.length; i += 1) {
    const ch = line.charAt(i);
    if (ch === '"') inQuote = !inQuote;
    if (ch === '\\') out += '\\\\';
    else if (ch === '^' && !inQuote && i + 1 < line.length) {
      i += 1;
      out += `\\${line.charAt(i)}`;
    } else out += ch;
  }
  return out;
}

/** The commands `cmd /c LINE` (or `/k`) runs — see {@link cmdEffects} for how the line is read. */
export function cmdLine(rawArgs: readonly string[]): CmdCommand[] {
  const args = rawArgs.map(cmdSwitch);
  const at = args.findIndex((a) => /^\/[ck]$/i.test(a));
  if (at < 0) return [];
  const first = args[at + 1];
  if (first === undefined) return [];
  const head = first.trim();
  const commands = /[\s&|^<>]/.test(head) ? splitCmdLine(head) : [{ words: [head], redirects: [] }];
  // The shell words after the first one continue the line's LAST command.
  const last = commands[commands.length - 1];
  if (last !== undefined) pushAll(last.words, args.slice(at + 2));
  return commands;
}

/**
 * Every command a `cmd /c` line runs, nested `cmd /c` lines flattened, as
 * shell words — for the checks that read a command rather than its file
 * effects: the plugin command and program text (fix round 1, M1).
 */
export function cmdInnerCommands(args: readonly string[], depth = 0): ShellWord[][] {
  if (depth > MAX_CMD_NESTING) return [];
  const out: ShellWord[][] = [];
  for (const command of cmdLine(args)) {
    const words = cmdCommandWords(command.words);
    const name = (words[0] ?? '').toLowerCase().replace(/\.exe$/, '');
    if (name === 'cmd') pushAll(out, cmdInnerCommands(words.slice(1), depth + 1));
    else out.push(words.map((value) => ({ value, quoted: false })));
  }
  return out;
}
