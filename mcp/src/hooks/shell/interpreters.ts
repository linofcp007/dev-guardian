/**
 * Program text on the command line: which word of a command is an
 * interpreter (`node`, `python`, `perl`, `ruby`, `php`, `deno`, `bun`, `pwsh`,
 * … — behind `npx`, `bunx`, `pnpm dlx`, `uv run`, cmd's `start`), the program
 * it is handed (`-e` / `-c` text, a here-doc or `echo … |` on its stdin,
 * PowerShell's `-Command` / `-EncodedCommand`) and the string literals of that
 * program. Moved out of `bashGuard.ts`, which judges what the literals name
 * (`judgeCode`) and whether a download is run as a program.
 *
 * Pure functions. No I/O.
 */

import { windowsName } from '../guardedPath.js';
import { commandName } from './command.js';
import { perlLike, withoutRedirectWords } from './effects.js';
import type { ShellWord } from './split.js';

const PYTHON = /^(?:python[0-9.]*|py|pypy[0-9.]*)$/;
const INTERPRETERS = new Set(['node', 'nodejs', 'bun', 'deno', 'tsx', 'ts-node', 'perl', 'ruby', 'php', 'pwsh', 'powershell']);
/** `X run … python -c …`: tools that run an interpreter in a managed environment. */
export const RUN_WRAPPERS = new Set(['uv', 'poetry', 'pipenv', 'pdm', 'rye', 'hatch', 'conda', 'mamba', 'micromamba', 'pixi']);

export function isInterpreter(name: string): boolean {
  return PYTHON.test(name) || INTERPRETERS.has(name);
}

/** Commands that launch the program named after their own flags: `npx node …`, cmd's `start /b node …`. */
const LAUNCHERS = new Set(['npx', 'bunx', 'pnpx', 'start']);
/** Package managers whose subcommand launches a program: `pnpm dlx`, `npm exec`, `yarn dlx`, `bun x`, … */
const LAUNCHER_SUBCOMMANDS: Readonly<Record<string, ReadonlySet<string>>> = {
  npm: new Set(['exec', 'x']),
  pnpm: new Set(['dlx', 'exec']),
  yarn: new Set(['dlx', 'exec']),
  bun: new Set(['x']),
};
/** Launcher options whose next word is their value, not the program (`npx -p pkg`). */
export const LAUNCHER_VALUED = new Set(['-p', '--package', '-c', '--call', '/d']);

/** The index of the first word at or after `from` that is not a `-` flag (`words.length` if none). */
export function firstNonFlag(words: readonly ShellWord[], from: number): number {
  let k = from;
  while (k < words.length && (words[k]?.value ?? '').startsWith('-')) k += 1;
  return k;
}

/** An interpreter's name as written — `node@20` (through `npx`) is `node`. */
export function interpreterName(word: string): string {
  return commandName(word).replace(/@[\w.^~<>=-]*$/, '');
}

/**
 * Index of the interpreter a command runs: at `start`, behind `uv run`-style
 * wrappers, or behind a launcher (`npx --yes node@20`, `start "" /b node`);
 * -1 for none.
 */
export function interpreterIndex(words: readonly ShellWord[], start: number): number {
  let i = start;
  // No hop cap: every hop moves `i` forward, so this is linear — and a cap of
  // four made five `npx -y` in front of `node -e …` a silent ok (fix round 4).
  while (i < words.length) {
    const name = interpreterName(words[i]?.value ?? '');
    // `bun x` launches before `bun` interprets; global flags may come first
    // (`pnpm --silent dlx`, `npm --yes exec`).
    const sub = LAUNCHER_SUBCOMMANDS[name] === undefined ? -1 : firstNonFlag(words, i + 1);
    const launches = sub >= 0 && LAUNCHER_SUBCOMMANDS[name]?.has(words[sub]?.value ?? '') === true;
    if (isInterpreter(name) && !launches) return i;
    if (RUN_WRAPPERS.has(name) && words[i + 1]?.value === 'run') {
      for (let k = i + 2; k < Math.min(words.length, i + 10); k += 1) {
        if (isInterpreter(interpreterName(words[k]?.value ?? ''))) return k;
      }
      return -1;
    }
    if (launches) i = sub + 1;
    else if (LAUNCHERS.has(name)) i += 1;
    else return -1;
    // Past the launcher's own options (and `start`'s empty "" title).
    while (i < words.length) {
      const w = words[i]?.value ?? '';
      if (w !== '' && !/^(?:-|\/[A-Za-z])/.test(w)) break;
      i += LAUNCHER_VALUED.has(w.toLowerCase()) ? 2 : 1;
    }
  }
  return -1;
}

/** Node / Bun options that take a value (none of them program text). */
const NODE_VALUED = new Set([
  '-r', '--require', '--import', '--loader', '--experimental-loader', '-C', '--conditions', '--input-type',
  '--env-file', '--title', '--cwd', '--config', '--preload',
]);

/** `node -e CODE`, `--eval`, `-p`, `--print`, `-pe`, `--eval=CODE`; nothing once a script file is named. */
function nodeCode(args: readonly string[]): string[] {
  for (let i = 0; i < args.length; i += 1) {
    const a = args[i] ?? '';
    const eq = /^--(?:eval|print)=([\s\S]*)$/.exec(a);
    if (eq !== null) return [eq[1] ?? ''];
    if (/^-(?:e|p|pe|ep)$/.test(a) || a === '--eval' || a === '--print') return [args[i + 1] ?? ''];
    if (NODE_VALUED.has(a)) {
      i += 1;
      continue;
    }
    if (!a.startsWith('-')) return [];
  }
  return [];
}

/** `python -c CODE` (also clustered: `-Bc CODE`, `-cCODE`); nothing for `-m`, a script file or `-` (stdin). */
function pythonCode(args: readonly string[]): string[] {
  for (let i = 0; i < args.length; i += 1) {
    const a = args[i] ?? '';
    if (a === '-' || !a.startsWith('-')) return [];
    if (a.startsWith('--')) continue;
    for (let k = 1; k < a.length; k += 1) {
      const c = a.charAt(k);
      if (c === 'c') {
        const rest = a.slice(k + 1);
        return [rest !== '' ? rest : (args[i + 1] ?? '')];
      }
      if (c === 'm') return [];
      if (c === 'W' || c === 'X') {
        if (k === a.length - 1) i += 1;
        break;
      }
    }
  }
  return [];
}

/** `php -r CODE` (and `-B`/`-R`/`-E` per-line code); nothing once a script file is named. */
function phpCode(args: readonly string[]): string[] {
  const code: string[] = [];
  for (let i = 0; i < args.length; i += 1) {
    const a = args[i] ?? '';
    if (/^-[rBRE]$/.test(a)) {
      code.push(args[i + 1] ?? '');
      i += 1;
    } else if (/^-r./.test(a)) code.push(a.slice(2));
    else if (a === '-f' || a === '-F' || !a.startsWith('-')) return code;
    else if (/^-[dcz]$/.test(a)) i += 1;
  }
  return code;
}

/** PowerShell's `-EncodedCommand` payload: base64 of UTF-16LE text. */
function decodeUtf16Base64(text: string): string {
  if (!/^[A-Za-z0-9+/=]+$/.test(text)) return '';
  return Buffer.from(text, 'base64').toString('utf16le');
}

/** `pwsh`/`powershell` parameters that take a value (none of them program text). */
const PS_HOST_VALUED = new Set([
  'ex', 'ep', 'executionpolicy', 'w', 'windowstyle', 'wd', 'workingdirectory', 'configurationname', 'o', 'of',
  'outputformat', 'if', 'inputformat', 'v', 'version', 'psconsolefile', 'settings', 'settingsfile',
  'custompipename', 'configurationfile',
]);

/**
 * The program text `pwsh` / `powershell` runs: everything after `-Command`
 * (`-c`, or a 3+ letter prefix of it), as PowerShell itself joins it, or the
 * decoded `-EncodedCommand` (`-e`, `-ec`, `-enc`, …). Windows PowerShell 5 also
 * runs a first positional argument as a command; pwsh 7 runs it as a file.
 */
export function powershellCommand(args: readonly string[], name: string): string[] {
  for (let i = 0; i < args.length; i += 1) {
    const a = args[i] ?? '';
    const m = /^[-/]([A-Za-z]+)$/.exec(a);
    if (m === null) return name === 'powershell' ? [args.slice(i).join(' ')] : [];
    const p = (m[1] ?? '').toLowerCase();
    if (p === 'c' || (p.length >= 3 && 'command'.startsWith(p))) {
      const rest = args.slice(i + 1);
      return rest.length === 0 || rest[0] === '-' ? [] : [rest.join(' ')];
    }
    if (p === 'e' || (p.length >= 2 && 'encodedcommand'.startsWith(p))) return [decodeUtf16Base64(args[i + 1] ?? '')];
    if (p === 'f' || p === 'file') return [];
    if (PS_HOST_VALUED.has(p)) i += 1;
  }
  return [];
}

/**
 * Program text a command hands an interpreter on its own command line —
 * `node -e`, `python -c`, `perl -e`, `ruby -e`, `php -r`, `deno eval`,
 * `pwsh -Command` / `-EncodedCommand`, also behind `uv run` and the like. A
 * script FILE is never read: its code is on disk, and cannot be judged here.
 */
export function inlineCode(words: readonly ShellWord[], start: number): string[] {
  const at = interpreterIndex(words, start);
  if (at < 0) return [];
  const name = interpreterName(words[at]?.value ?? '');
  const args = words.slice(at + 1).map((w) => w.value);
  if (PYTHON.test(name)) return pythonCode(args);
  switch (name) {
    case 'node':
    case 'nodejs':
    case 'bun':
    case 'tsx':
    case 'ts-node':
      return nodeCode(args);
    case 'deno':
      return args[0] === 'eval' ? args.slice(1).filter((a) => !a.startsWith('-')).slice(0, 1) : [];
    case 'perl':
      return perlLike(args, 'eE', 'IMm').code;
    case 'ruby':
      return perlLike(args, 'e', 'IrCEFx').code;
    case 'php':
      return phpCode(args);
    case 'pwsh':
    case 'powershell':
      return powershellCommand(args, name);
    default:
      return [];
  }
}

/**
 * True when `words` runs an interpreter that reads its program from stdin —
 * no `-c`/`-e` text, no module, no script file, whatever options come first
 * ({@link interpreterProgram}). What `python - <<EOF … EOF` and `echo '…' |
 * node` hand it is its program.
 */
export function isBareInterpreterStdin(words: readonly ShellWord[]): boolean {
  const program = interpreterProgram(withoutRedirectWords(words), 0);
  return program.kind === 'dash' || (program.kind === 'none' && program.readsStdin);
}

/**
 * Where an interpreter's program comes from (review round 3, item 2):
 *
 *   - `inline` — on its command line (`python -c`, `node -e`, `perl -e`,
 *     `php -r`, `deno eval`), or a module (`python -m json.tool`): stdin, or
 *     any operand, is data;
 *   - `file` — its first operand, `words[index]`;
 *   - `dash` — an explicit `-`: stdin;
 *   - `none` — no program at all, which `readsStdin` interpreters (python,
 *     node, perl, ruby, php) then read from stdin; and the operand a process
 *     substitution right after them would fill;
 *   - `unknown` — not an interpreter this knows the options of.
 *
 * Read with each interpreter's own table of options that take a value, so
 * `python3 -W ignore -`, `node --max-old-space-size 4096 i.js` and `perl -I lib
 * f.pl` find the program behind them — `-W ignore` read `ignore` as the script.
 */
type InterpreterProgram =
  | { kind: 'inline' }
  | { kind: 'file'; index: number }
  | { kind: 'dash' }
  | { kind: 'none'; readsStdin: boolean }
  | { kind: 'unknown' };

/** Node's own options that take the next word as their value (besides `--opt=value`). */
export const NODE_OPTION_VALUED = new Set([
  ...NODE_VALUED,
  '--max-old-space-size', '--max-semi-space-size', '--stack-size', '--max-http-header-size', '--inspect-port',
  '--debug-port', '--openssl-config', '--icu-data-dir', '--redirect-warnings', '--report-dir', '--report-directory',
  '--report-filename', '--report-signal', '--diagnostic-dir', '--heapsnapshot-signal', '--heapsnapshot-near-heap-limit',
  '--dns-result-order', '--unhandled-rejections', '--disable-warning', '--watch-path', '--test-reporter',
  '--test-reporter-destination', '--test-name-pattern', '--test-concurrency', '--experimental-policy',
  '--policy-integrity', '--secure-heap', '--secure-heap-min', '--cpu-prof-dir', '--cpu-prof-name', '--cpu-prof-interval',
  '--heap-prof-dir', '--heap-prof-name', '--heap-prof-interval', '--trace-event-categories',
  '--trace-event-file-pattern', '--use-largepages', '--tls-cipher-list', '--tls-keylog', '--localstorage-file',
  '--env-file-if-exists', '--experimental-sea-config',
]);

/** deno run's and bun run's options that take the next word as their value. */
const DENO_RUN_VALUED = new Set(['-c', '--config', '--import-map', '--lock', '--cert', '--location', '--seed', '--env-file', '--ext']);
const BUN_RUN_VALUED = new Set([
  '--cwd', '-c', '--config', '--env-file', '-r', '--preload', '--tsconfig-override', '-d', '--define', '-l', '--loader',
  '--main-fields', '--conditions', '--filter', '-F', '--elide-lines', '--shell',
]);

/** The operand at `i`: `-` is stdin, anything else the program file. */
function operandAt(words: readonly ShellWord[], i: number, readsStdin: boolean): InterpreterProgram {
  const w = words[i];
  if (w === undefined) return { kind: 'none', readsStdin };
  return w.value === '-' ? { kind: 'dash' } : { kind: 'file', index: i };
}

/**
 * A POSIX-style option cluster (`-uW ignore`, `-Wignore`, `-e 'code'`): `inline`
 * letters define the program, `valued` letters take the rest of the cluster or
 * the next word. Returns how many words the option used, or `inline`.
 */
function clusterWords(word: string, inline: string, valued: string): number | 'inline' {
  for (let k = 1; k < word.length; k += 1) {
    const c = word.charAt(k);
    if (inline.includes(c)) return 'inline';
    if (valued.includes(c)) return k === word.length - 1 ? 2 : 1;
  }
  return 1;
}

export function interpreterProgram(words: readonly ShellWord[], at: number): InterpreterProgram {
  const name = interpreterName(words[at]?.value ?? '');
  const python = PYTHON.test(name);
  const nodeLike = ['node', 'nodejs', 'tsx', 'ts-node'].includes(name);
  if (!python && !nodeLike && !['perl', 'ruby', 'php', 'deno', 'bun'].includes(name)) return { kind: 'unknown' };
  let i = at + 1;
  if (name === 'deno' || name === 'bun') {
    const sub = words[i]?.value ?? '';
    if (sub === 'eval' || (name === 'bun' && /^(?:-e|-p|--eval|--print)$/.test(sub))) return { kind: 'inline' };
    if (sub === 'run') i += 1;
    else if (name === 'deno' || sub !== '-') return { kind: 'unknown' };
  }
  const readsStdin = !['deno', 'bun', 'tsx', 'ts-node'].includes(name);
  for (; i < words.length; i += 1) {
    const v = words[i]?.value ?? '';
    if (v === '--') return operandAt(words, i + 1, readsStdin);
    if (v === '-' || !v.startsWith('-')) return operandAt(words, i, readsStdin);
    if (python) {
      if (v.startsWith('--')) {
        if (v === '--check-hash-based-pycs') i += 1;
        continue;
      }
      const used = clusterWords(v, 'cm', 'WXQ');
      if (used === 'inline') return { kind: 'inline' };
      i += used - 1;
    } else if (nodeLike) {
      if (/^-(?:e|p|pe|ep)$/.test(v) || /^--(?:eval|print)(?:=|$)/.test(v)) return { kind: 'inline' };
      if (!v.includes('=') && NODE_OPTION_VALUED.has(v)) i += 1;
    } else if (name === 'deno' || name === 'bun') {
      if (!v.includes('=') && (name === 'deno' ? DENO_RUN_VALUED : BUN_RUN_VALUED).has(v)) i += 1;
    } else if (name === 'php') {
      if (/^-[rBRE]/.test(v)) return { kind: 'inline' };
      if (v === '-f' || v === '-F') return operandAt(words, i + 1, readsStdin);
      if (/^-[dcz]$/.test(v)) i += 1;
    } else {
      // perl and ruby: `-e` program text; the letters that take a value, as `perlLike` reads them.
      if (v.startsWith('--')) continue;
      const used = clusterWords(v, name === 'perl' ? 'eE' : 'e', name === 'perl' ? 'IMm' : 'IrCEFx');
      if (used === 'inline') return { kind: 'inline' };
      i += used - 1;
    }
  }
  return { kind: 'none', readsStdin };
}

/** How a program's string literals are written: Python, JavaScript, or the rest (Perl, Ruby, PHP, PowerShell). */
export type CodeLang = 'python' | 'js' | 'other';

export function codeLang(interpreter: string): CodeLang {
  if (PYTHON.test(interpreter)) return 'python';
  return ['node', 'nodejs', 'bun', 'deno', 'tsx', 'ts-node'].includes(interpreter) ? 'js' : 'other';
}

/**
 * The string literals of a piece of program text: `'…'` and `"…"`, plus
 * `` `…` `` in JavaScript and `'''…'''` / `"""…"""` in Python. A backslash
 * escapes the next character only when that is a backslash or the closing
 * quote, so a Windows path or a raw string keeps its backslashes. A comment
 * outside a literal — `#` (Python and the rest), `// ` (JavaScript and the
 * rest) — is skipped, so an apostrophe in it does not pair with the next
 * quote. Not a parser for any one language: it finds the literals a path would
 * be written in.
 */
export function codeLiterals(code: string, lang: CodeLang): string[] {
  const quotes = lang === 'js' ? ['"', "'", '`'] : ['"', "'"];
  const out: string[] = [];
  let i = 0;
  while (i < code.length) {
    const ch = code.charAt(i);
    const atWordStart = i === 0 || /\s/.test(code.charAt(i - 1));
    const comment =
      atWordStart && ((ch === '#' && lang !== 'js') || (lang !== 'python' && code.startsWith('// ', i)));
    if (comment) {
      const nl = code.indexOf('\n', i);
      i = nl < 0 ? code.length : nl + 1;
      continue;
    }
    if (!quotes.includes(ch)) {
      i += 1;
      continue;
    }
    const close = lang === 'python' && code.startsWith(ch.repeat(3), i) ? ch.repeat(3) : ch;
    let lit = '';
    let j = i + close.length;
    while (j < code.length) {
      const c = code.charAt(j);
      const next = code.charAt(j + 1);
      if (c === '\\' && (next === '\\' || next === ch)) {
        lit += next;
        j += 2;
        continue;
      }
      if (code.startsWith(close, j)) break;
      lit += c;
      j += 1;
    }
    out.push(lit);
    i = j + close.length;
  }
  return out;
}

/** Literals as paths: trimmed, every run of backslashes read as `/`. */
export function literalPaths(literals: readonly string[]): string[] {
  return asWindowsOpens(literals.map((l) => tail(l.trim()).replace(/\\+/g, '/')));
}

/**
 * The end of a path, which is all any pattern here is anchored to — so a
 * megabyte-long word full of `.guardian/hooks` cannot make `hooks[^/]*\.json$`
 * rescan it from every occurrence.
 */
export function tail(path: string): string {
  return path.length > 1024 ? path.slice(-1024) : path;
}

/**
 * Each path, and — when it differs — the name Windows opens for it: without
 * an NTFS stream suffix or trailing dots and spaces (review M1:
 * `hooks.config.json::$DATA` writes the file itself). Both are judged, so the
 * second can only add a match; elsewhere a colon is part of a name, and
 * refusing that odd name there costs nothing.
 */
export function asWindowsOpens(paths: readonly string[]): string[] {
  const out = [...paths];
  for (const p of paths) {
    const named = windowsName(p);
    if (named !== p) out.push(named);
  }
  return out;
}
