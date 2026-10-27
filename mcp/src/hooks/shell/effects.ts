/**
 * What a command does to the filesystem, as far as the shell guard models it
 * (`effectsOf`): the files it writes — redirections, `tee`, `sed -i`,
 * `perl -pi`, `sort -o`, `rsync`, `cp`, PowerShell `Set-Content`, cmd `copy`,
 * … — the paths it removes or moves away, the directories it copies a whole
 * tree onto, the links, FIFOs and device nodes it creates, and the trees it
 * empties without a delete command. Every path is resolved against the `cd`s
 * before it (`paths.ts`), and each command of a `cmd /c` line is modelled too
 * (`cmd.ts`). Moved out of `bashGuard.ts`, which judges these effects
 * (`judgeEffects`).
 *
 * Pure functions. No I/O.
 */

import { pushAll } from './arrays.js';
import { cmdCommandWords, cmdLine, MAX_CMD_NESTING } from './cmd.js';
import { cmdSwitch, parseRedirect, psParam } from './command.js';
import { cwdAfter, dirOf, resolveFrom, wildcardMatch } from './paths.js';
import type { ShellWord } from './split.js';

/**
 * What one simple command does to the filesystem, as far as this guard models
 * it. Every path is already resolved against the directory the command runs
 * in ({@link resolveFrom}).
 */
export interface Effects {
  /** Files written: created, overwritten, appended to or emptied. */
  writes: string[];
  /** Paths deleted or moved away. */
  removes: string[];
  /** Directories a whole tree is moved or copied onto — replaced, when they did not exist. */
  dirs: string[];
  /** FIFOs and device nodes created. */
  special: string[];
  /** Links created. */
  links: string[];
  /**
   * The files a HARD link is made to — a second name for the same file, through
   * which a write reaches it (review round 3, item 5).
   */
  hardLinkSources: string[];
  /**
   * Directories whose whole content a command deletes without a delete command
   * (review 8, item 9): `rsync --delete` and `robocopy /MIR` into them, a
   * recursive `[IO.Directory]::Delete`.
   */
  trees: string[];
  /**
   * The symbolic links and junctions created, each `[link, target]` — a second
   * name for the target, through which a later write of the line reaches it
   * unnamed (review 12, finding 1): `mklink /J z .claude` makes
   * `z/settings.local.json` Claude Code's settings. The target is resolved the
   * way the link reads it: from the link's directory, or — a junction's — from
   * the command's.
   */
  aliases: Array<readonly [string, string]>;
}

export function noEffects(): Effects {
  return { writes: [], removes: [], dirs: [], special: [], links: [], hardLinkSources: [], trees: [], aliases: [] };
}

function mergeEffects(into: Effects, from: Effects): void {
  pushAll(into.writes, from.writes);
  pushAll(into.removes, from.removes);
  pushAll(into.dirs, from.dirs);
  pushAll(into.special, from.special);
  pushAll(into.links, from.links);
  pushAll(into.hardLinkSources, from.hardLinkSources);
  pushAll(into.trees, from.trees);
  pushAll(into.aliases, from.aliases);
}

/** `a/b/c` → `c`, for either separator. */
export function lastSegment(path: string): string {
  return path.split(/[\\/]/).filter((s) => s.length > 0).pop() ?? path;
}

/** The words that are not options, `--` ending the options; `valued` options consume the next word. */
function operands(args: readonly string[], valued: ReadonlySet<string>): string[] {
  const out: string[] = [];
  let optionsDone = false;
  for (let i = 0; i < args.length; i++) {
    const a = args[i] ?? '';
    if (!optionsDone && a === '--') {
      optionsDone = true;
      continue;
    }
    if (!optionsDone && a.startsWith('-') && a.length > 1) {
      if (valued.has(a)) i++;
      continue;
    }
    out.push(a);
  }
  return out;
}

/** `ln`'s operands past its options, and its `-t DIR` (`--target-directory`): `hasDir` even when DIR is missing. */
function lnOperands(args: readonly string[]): { names: string[]; dir: string | undefined; hasDir: boolean } {
  let dir: string | undefined;
  let hasDir = false;
  const rest: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i] ?? '';
    const long = /^--target-directory=(.*)$/.exec(a);
    if (long !== null) {
      hasDir = true;
      if (long[1] !== '') dir = long[1];
    } else if (a === '--target-directory' || /^-[a-zA-Z]*t$/.test(a)) {
      hasDir = true;
      dir = args[++i];
    } else if (/^-t./.test(a)) {
      hasDir = true;
      dir = a.slice(2);
    } else if (a === '-S' || a === '--suffix') i++;
    else rest.push(a);
  }
  return { names: operands(rest, new Set()), dir, hasDir };
}

/** `ln [opts] TARGET… LINK`, `ln [opts] TARGET`, `ln -t DIR TARGET…`: the paths it creates. */
function lnDestinations(args: readonly string[]): string[] {
  const { names: targets, dir } = lnOperands(args);
  if (dir !== undefined) return targets.map((t) => `${dir}/${lastSegment(t)}`);
  if (targets.length >= 2) return [targets[targets.length - 1] ?? ''];
  return targets.length === 1 ? [lastSegment(targets[0] ?? '')] : [];
}

/** `-s` / `--symbolic`: `ln` makes symbolic links. */
function lnSymbolic(args: readonly string[]): boolean {
  return args.some((a) => a === '--symbolic' || /^-[a-zA-Z]*s[a-zA-Z]*$/.test(a));
}

/** The files `ln` hard-links to — every source operand, unless `-s` / `--symbolic` makes the links symbolic. */
function lnHardSources(args: readonly string[]): string[] {
  if (lnSymbolic(args)) return [];
  const { names, hasDir } = lnOperands(args);
  return hasDir || names.length < 2 ? names : names.slice(0, -1);
}

/**
 * `ln -s`'s links, each with what it points at ({@link Effects.aliases}), the
 * target as written. With two names the second is the link, or — when it is a
 * directory — the directory the link is made in: both are listed.
 */
function lnAliases(args: readonly string[]): Array<readonly [string, string]> {
  if (!lnSymbolic(args)) return [];
  const { names, dir } = lnOperands(args);
  if (dir !== undefined) return names.map((t) => [`${dir}/${lastSegment(t)}`, t] as const);
  if (names.length === 1) return [[lastSegment(names[0] ?? ''), names[0] ?? ''] as const];
  const link = names[names.length - 1] ?? '';
  const sources = names.slice(0, -1);
  return sources.flatMap((t) =>
    sources.length === 1 ? [[link, t] as const, [`${link}/${lastSegment(t)}`, t] as const] : [[`${link}/${lastSegment(t)}`, t] as const],
  );
}

/** A link's target as the link reads it: a relative one from the link's own directory. */
function fromLink(link: string, target: string): string {
  return resolveFrom(dirOf(link.replace(/\\/g, '/')), target);
}

/**
 * `New-Item`'s parameters that take a value, by the name the code below uses,
 * with every name and alias it may be spelled by. PowerShell binds any prefix
 * that names one parameter (review 3.0, wave 2: `ni -it HardLink` is
 * `-ItemType`), and a common parameter never makes one ambiguous — measured
 * on pwsh 7.6 and Windows PowerShell 5.1, `-i` is `-ItemType` and `-v` is
 * `-Value`, whatever `-InformationAction` and `-Verbose` begin with (round 2).
 * `-t` begins both `-Type` and `-Target`, and PowerShell refuses it.
 */
const NEW_ITEM_VALUED: ReadonlyArray<readonly [string, readonly string[]]> = [
  ['type', ['itemtype', 'type']],
  ['path', ['path', 'literalpath', 'pspath', 'lp']],
  ['name', ['name']],
  ['target', ['value', 'target']],
  ['credential', ['credential']],
];

function newItemParam(spelled: string): string | undefined {
  const exact = NEW_ITEM_VALUED.find(([, names]) => names.includes(spelled));
  if (exact !== undefined) return exact[0];
  const matches = NEW_ITEM_VALUED.filter(([, names]) => names.some((n) => n.startsWith(spelled)));
  return matches.length === 1 ? matches[0]?.[0] : undefined;
}

/**
 * The item type a FileSystem `-ItemType` value names. The provider matches
 * the value as a prefix, wildcards allowed, in this order — so `h` and
 * `Hard` are `HardLink`, `s*` is `SymbolicLink` — and `''` is a file.
 */
function itemTypeOf(value: string): string {
  if (value === '') return 'file';
  const pattern = `${value.toLowerCase()}*`;
  if (wildcardMatch(pattern, 'directory') || wildcardMatch(pattern, 'container')) return 'directory';
  return ['file', 'symboliclink', 'junction', 'hardlink'].find((t) => wildcardMatch(pattern, t)) ?? 'unknown';
}

/** `New-Item`'s item type ({@link itemTypeOf}) and paths (`-Path`, `-LiteralPath`, `-Name`, or the first positional). */
function newItemArgs(args: readonly string[]): { itemType: string; paths: string[]; target?: string } {
  let spelledType = '';
  let target: string | undefined;
  const paths: string[] = [];
  const positional: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i] ?? '';
    const param = /^-([A-Za-z]+)(?::(.*))?$/.exec(a);
    if (param === null) {
      positional.push(a);
      continue;
    }
    const name = newItemParam((param[1] ?? '').toLowerCase());
    const inline = param[2];
    const value = inline !== undefined ? inline : name !== undefined ? (args[++i] ?? '') : undefined;
    if (value === undefined) continue;
    if (name === 'type') spelledType = value;
    else if (name === 'path' || name === 'name') paths.push(value);
    else if (name === 'target') target = value;
  }
  if (paths.length === 0 && positional.length > 0) paths.push(positional[0] ?? '');
  const itemType = itemTypeOf(spelledType);
  return target === undefined ? { itemType, paths } : { itemType, paths, target };
}

/** `mklink [/D|/H|/J] LINK TARGET`: the link is the first operand. */
function mklinkDestinations(args: readonly string[]): string[] {
  const link = args.find((a) => !a.startsWith('/'));
  return link === undefined ? [] : [link];
}

/**
 * `cmd /c LINE` (or `/k`): what every command of the line does. The line is
 * what follows the `/c`/`/k` switch. When its first word is itself a whole
 * command line — `cmd /c "mklink a b"` hands cmd ONE quoted word — it is split
 * the way cmd splits it (`splitCmdLine`), and EVERY command is assessed past a
 * leading `@` or `call`: a `mklink`, a `copy` / `move` / `del` / `ren`, a
 * nested `cmd /c`, a `>` redirection, and a `cd /d` that later relative paths
 * are resolved from. Any other word is kept whole, so a quoted path with a
 * space in it (`"C:\Users\me\CLAUDE SKILLS\…"`) is judged as the one path it
 * is — splitting every word on whitespace, as this once did, cut such a path in
 * two and never recognised it (final review I11); checking only the first
 * command of a split line let a mklink after `&&` through (re-review); a
 * redirection inside the quoted line was not seen at all (Part Y).
 */
function cmdEffects(args: readonly string[], cwd: string, depth = 0): Effects {
  const e = noEffects();
  if (depth > MAX_CMD_NESTING) return e;
  const commands = cmdLine(args);
  let dir = cwd;
  for (const command of commands) {
    const [raw, ...rest] = cmdCommandWords(command.words);
    const name = (raw ?? '').toLowerCase().replace(/\.exe$/, '');
    pushAll(e.writes, command.redirects.map((r) => resolveFrom(dir, r)));
    mergeEffects(e, effectsOf(name, rest, dir, depth + 1));
    dir = cwdAfter(name, rest, dir) ?? dir;
  }
  return e;
}

/**
 * The files a simple command's redirections write: `> f`, `>> f`, `>| f`,
 * `N> f`, `&> f`, `>f`. Only an UNQUOTED operator counts
 * ({@link ShellWord.redirectAt}); `>&2` / `>&-` duplicate or close a
 * descriptor and name no file, and `<…` only reads.
 */
export function redirectTargets(words: readonly ShellWord[]): string[] {
  const out: string[] = [];
  for (let i = 0; i < words.length; i += 1) {
    const word = words[i];
    const r = word === undefined ? null : parseRedirect(word);
    if (r === null || !r.op.startsWith('>')) continue;
    const next = words[i + 1]?.value;
    if (r.op.endsWith('&')) {
      const fd = r.inline !== '' ? r.inline : (next ?? '');
      if (/^\d*-?$/.test(fd)) continue;
    }
    const target = r.inline !== '' ? r.inline : next;
    if (target !== undefined) out.push(target);
  }
  return out;
}

/**
 * The argument values with every redirection (operator and operand) removed,
 * so `tee /tmp/x < .guardian/hooks.config.json` reads as `tee /tmp/x`: a file
 * a command reads through `<` is never one it writes.
 */
export function withoutRedirections(words: readonly ShellWord[]): string[] {
  const out: string[] = [];
  for (let i = 0; i < words.length; i += 1) {
    const word = words[i];
    if (word === undefined) continue;
    const r = parseRedirect(word);
    if (r === null) {
      out.push(word.value);
      continue;
    }
    if (!/^(?:\d*|&)$/.test(r.prefix)) out.push(r.prefix);
    if (r.inline === '') i += 1;
  }
  return out;
}

/** `DIR/<last segment of src>`, for a copy or move into a directory. */
function intoDir(dir: string, src: string): string {
  return `${dir.replace(/[\\/]+$/, '')}/${lastSegment(src)}`;
}

/** Values of `name`'s option, spelled `-o F`, `-oF`, `--output F` or `--output=F`. */
function optionValues(args: readonly string[], short: string, long: string): string[] {
  const out: string[] = [];
  for (let i = 0; i < args.length; i += 1) {
    const a = args[i] ?? '';
    if (a === short || a === long) {
      const v = args[i + 1];
      if (v !== undefined) out.push(v);
    } else if (a.startsWith(`${long}=`)) out.push(a.slice(long.length + 1));
    else if (a.startsWith(short) && a.length > short.length && !a.startsWith('--')) out.push(a.slice(short.length));
  }
  return out;
}

/** The sources and destination of a copy or a move. */
interface Transfer {
  sources: string[];
  dest?: string;
  /** `dest` came from `-t` / `--target-directory`: an existing directory the sources go INTO. */
  into: boolean;
  /** `-r`, `-R`, `-a`, `--recursive`, `--archive`, PowerShell `-Recurse`, xcopy/robocopy `/E` `/S` `/MIR`. */
  recursive: boolean;
}

/** `cp`/`mv`/`install` options that take a value, none of them the destination. */
const COPY_VALUED = new Set(['-S', '--suffix', '-m', '--mode', '-o', '--owner', '-g', '--group']);
/** PowerShell `Copy-Item`/`Move-Item` parameters, by full lower-case name: those naming paths… */
const PS_PATH_PARAMS = ['path', 'literalpath', 'destination'];
/** …the others that take a value, and the switches. */
const PS_VALUE_PARAMS = ['filter', 'include', 'exclude', 'credential', 'fromsession', 'tosession'];
const PS_SWITCHES = ['recurse', 'force', 'container', 'passthru', 'whatif', 'confirm'];

/** A full PowerShell parameter name `spelled` names: itself, or a prefix of 3+ letters (`-Dest`, `-Rec`). */
function psName(spelled: string): string | undefined {
  const lower = spelled.toLowerCase();
  const all = [...PS_PATH_PARAMS, ...PS_VALUE_PARAMS, ...PS_SWITCHES];
  if (all.includes(lower)) return lower;
  return lower.length >= 3 ? all.find((n) => n.startsWith(lower)) : undefined;
}

/**
 * The sources and destination of a copy or a move: POSIX `cp`/`mv`/`install`
 * (the last operand, or `-t DIR`), PowerShell `Copy-Item`/`Move-Item`
 * (`-Path`, `-Destination`, or the first two positionals), and cmd `copy` /
 * `move`, whose `/Y`-style switches are not paths (`slashSwitches`).
 */
export function parseTransfer(args: readonly string[], slashSwitches: boolean): Transfer {
  const named: string[] = [];
  const positional: string[] = [];
  let dest: string | undefined;
  let into = false;
  let recursive = false;
  let optionsDone = false;
  for (let i = 0; i < args.length; i += 1) {
    const a = args[i] ?? '';
    if (slashSwitches && /^\/[A-Za-z]/.test(a)) continue;
    if (optionsDone || a === '-' || !a.startsWith('-')) {
      positional.push(a);
      continue;
    }
    if (a === '--') {
      optionsDone = true;
      continue;
    }
    const target = /^--target-directory(?:=(.*))?$/.exec(a);
    if (target !== null) {
      dest = target[1] ?? args[++i];
      into = true;
      continue;
    }
    if (a === '--recursive' || a === '--archive') {
      recursive = true;
      continue;
    }
    const ps = /^-([A-Za-z]+)(?::(.*))?$/.exec(a);
    const param = ps === null ? undefined : psName(ps[1] ?? '');
    if (ps !== null && param !== undefined) {
      const value = PS_PATH_PARAMS.includes(param) || PS_VALUE_PARAMS.includes(param) ? (ps[2] ?? args[++i]) : undefined;
      if (param === 'recurse') recursive = true;
      else if (param === 'destination') dest = value;
      else if ((param === 'path' || param === 'literalpath') && value !== undefined) named.push(value);
      continue;
    }
    if (COPY_VALUED.has(a)) {
      i += 1;
      continue;
    }
    if (/^-[a-zA-Z]*t$/.test(a)) {
      dest = args[++i];
      into = true;
    } else if (/^-t./.test(a)) {
      dest = a.slice(2);
      into = true;
    }
    if (!a.startsWith('--') && /[rRa]/.test(a.slice(1))) recursive = true;
  }
  const sources = [...named, ...positional];
  if (dest === undefined && sources.length >= 2) dest = sources.pop();
  return dest === undefined ? { sources, into, recursive } : { sources, dest, into, recursive };
}

/** `rsync` options that take a value — never the destination. */
const RSYNC_VALUED = new Set([
  '-e', '--rsh', '-f', '--filter', '--exclude', '--include', '--exclude-from', '--include-from', '--files-from',
  '-T', '--temp-dir', '-B', '--block-size', '--chmod', '--chown', '--log-file', '--password-file', '--partial-dir',
  '--backup-dir', '--suffix', '--compare-dest', '--copy-dest', '--link-dest', '--rsync-path', '-M',
  '--remote-option', '--port', '--timeout', '--contimeout', '--bwlimit', '--max-size', '--min-size', '--out-format',
  '--info', '--debug', '--iconv', '--usermap', '--groupmap', '--address', '--sockopts', '--max-delete',
]);

/**
 * `perl`/`ruby` switches: the `-e` program texts, whether `-i` edits the file
 * operands in place, and those operands. A short cluster is read letter by
 * letter (`-pi`, `-lne`, `-0777`): a code letter takes the rest of the cluster
 * or the next word, `i` takes the rest as its backup extension (`-i.bak`, and
 * `-pie` is `-p -i` with extension `e`), a value letter (`-I dir`, `-M mod`)
 * takes the rest or the next word. Without a program text, the first operand
 * is the script file.
 */
export function perlLike(
  args: readonly string[],
  codeLetters: string,
  valueLetters: string,
): { code: string[]; inPlace: boolean; files: string[] } {
  const code: string[] = [];
  const operandsSeen: string[] = [];
  let inPlace = false;
  let optionsDone = false;
  for (let i = 0; i < args.length; i += 1) {
    const a = args[i] ?? '';
    if (!optionsDone && a === '--') {
      optionsDone = true;
      continue;
    }
    if (optionsDone || !a.startsWith('-') || a.length === 1 || a.startsWith('--')) {
      if (optionsDone || !a.startsWith('--')) operandsSeen.push(a);
      continue;
    }
    for (let k = 1; k < a.length; k += 1) {
      const c = a.charAt(k);
      if (codeLetters.includes(c)) {
        const rest = a.slice(k + 1);
        code.push(rest !== '' ? rest : (args[++i] ?? ''));
        break;
      }
      if (c === 'i') {
        inPlace = true;
        break;
      }
      if (valueLetters.includes(c)) {
        if (k === a.length - 1) i += 1;
        break;
      }
      if (c === '0') while (/[0-9a-fA-Fx]/.test(a.charAt(k + 1))) k += 1;
      if (c === 'l') while (/[0-9]/.test(a.charAt(k + 1))) k += 1;
    }
  }
  const files = code.length > 0 ? operandsSeen : operandsSeen.slice(1);
  return { code, inPlace, files };
}

const SED_IN_PLACE = /^(?:-[a-zA-Z]*i.*|--in-place(?:=.*)?)$/;

/** vi / vim / ex options whose value is the next word (a short cluster ending in one of these letters, too). */
const EDITOR_VALUED_LETTERS = 'cSuUiTwWtq';

/** The files `vi`, `vim`, `nvim` or `ex` opens — every operand but an option's value and a `+cmd`. */
function editorFiles(args: readonly string[]): string[] {
  const out: string[] = [];
  let optionsDone = false;
  for (let i = 0; i < args.length; i += 1) {
    const a = args[i] ?? '';
    if (!optionsDone && a === '--') {
      optionsDone = true;
      continue;
    }
    if (!optionsDone && a === '--cmd') {
      i += 1;
      continue;
    }
    if (!optionsDone && /^-[A-Za-z]+$/.test(a)) {
      if (EDITOR_VALUED_LETTERS.includes(a.charAt(a.length - 1))) i += 1;
      continue;
    }
    if (!optionsDone && (a.startsWith('-') || a.startsWith('+'))) continue;
    out.push(a);
  }
  return out;
}

/**
 * The files a command itself writes — `tee`, `sed -i`, `dd of=`, `curl -o`,
 * `wget -O`, `sort -o`, `truncate`, `sponge`, `shred`, `perl -i` / `ruby -i`,
 * and PowerShell `Set-Content`/`Add-Content`/`Clear-Content`/`Out-File`/
 * `Tee-Object`. Never a file it only reads. Copies, moves, renames and
 * `New-Item` are in {@link effectsOf}.
 */
export function commandWriteDestinations(name: string, args: readonly string[]): string[] {
  switch (name) {
    case 'tee':
    case 'sponge':
      return operands(args, new Set());
    case 'sed':
      return args.some((a) => SED_IN_PLACE.test(a))
        ? operands(args, new Set(['-e', '-f', '--expression', '--file', '-l', '--line-length']))
        : [];
    case 'dd':
      return args.filter((a) => a.startsWith('of=')).map((a) => a.slice(3));
    case 'curl':
      return optionValues(args, '-o', '--output');
    case 'wget':
      return optionValues(args, '-O', '--output-document');
    case 'sort':
      return optionValues(args, '-o', '--output');
    case 'truncate':
      return operands(args, new Set(['-s', '--size', '-r', '--reference']));
    case 'shred':
      return operands(args, new Set(['-n', '--iterations', '-s', '--size', '--random-source']));
    case 'perl': {
      const p = perlLike(args, 'eE', 'IMm');
      return p.inPlace ? p.files : [];
    }
    case 'ruby': {
      const p = perlLike(args, 'e', 'IrCEFx');
      return p.inPlace ? p.files : [];
    }
    // In-place editors, scripted (review 8, item 15): `ed f`, `ex -sc '…|x' f`,
    // `vim -es -c '…' -c wq f` write the files they open.
    case 'ed':
    case 'red':
      return operands(args, new Set(['-p', '--prompt']));
    case 'ex':
    case 'vi':
    case 'vim':
    case 'nvim':
    case 'gvim':
      return editorFiles(args);
    // `sc` is Windows PowerShell 5.1's alias of Set-Content (review 8, item 15).
    case 'sc':
    case 'set-content':
    case 'add-content':
    case 'ac':
    case 'clear-content':
    case 'clc':
    case 'out-file':
    case 'tee-object':
      // Any argument: the path is positional or a -Path/-LiteralPath/-FilePath
      // value, and nothing else these take looks like a hook config path.
      return args.map((a) => a.replace(/^-[A-Za-z]+:/, ''));
    default:
      return [];
  }
}

/** git's own options before its subcommand that take the next word as their value. */
const GIT_VALUED = new Set(['-c', '--git-dir', '--work-tree', '--namespace', '--exec-path', '--config-env', '--super-prefix', '--attr-source']);

/**
 * The working-tree paths `git rm` deletes and `git mv` moves away — its
 * pathspecs past its options and `--`, read from the directory git's `-C`
 * moves to — as written: a pathspec is git's, not the shell's (its `*`
 * crosses `/`), so the guard judges them itself. None for `git rm --cached`,
 * which only untracks, for `-n` / `--dry-run`, which only lists, and for an
 * exclusion (`:!x`, `:^x`, `:(exclude)x`); any other magic (`:/x`,
 * `:(top,glob)x`) is dropped and the rest read from where the command runs.
 * Not in {@link effectsOf}: only Claude Code's settings are judged on them.
 */
export function gitRemoves(args: readonly string[]): string[] {
  let dir = '';
  let i = 0;
  for (; i < args.length; i += 1) {
    const a = args[i] ?? '';
    if (a === '-C') dir = resolveFrom(dir, args[++i] ?? '.');
    else if (GIT_VALUED.has(a)) i += 1;
    else if (!a.startsWith('-')) break;
  }
  const sub = args[i];
  if (sub !== 'rm' && sub !== 'mv') return [];
  const paths: string[] = [];
  let optionsDone = false;
  for (let k = i + 1; k < args.length; k += 1) {
    const a = args[k] ?? '';
    if (!optionsDone && a === '--') optionsDone = true;
    else if (!optionsDone && a.startsWith('--')) {
      // git takes a long option by any prefix that names it alone: `--cach`, `--dry`.
      const name = a.slice(2).split('=')[0] ?? '';
      if (name !== '' && ((sub === 'rm' && 'cached'.startsWith(name)) || 'dry-run'.startsWith(name))) return [];
      if (name === 'pathspec-from-file' && !a.includes('=')) k += 1;
    } else if (!optionsDone && /^-[A-Za-z]+$/.test(a)) {
      if (a.includes('n')) return [];
    } else if (!/^:(?:\/*[!^]|\([^)]*\bexclude\b)/.test(a)) paths.push(a.replace(/^:(?:\([^)]*\)|\/+)/, ''));
  }
  // `git mv SOURCE… DEST`: the sources go; with one operand it does nothing.
  const gone = sub === 'mv' ? paths.slice(0, -1) : paths;
  return gone.filter((p) => p !== '').map((p) => resolveFrom(dir, p));
}

/** Commands that delete what they are given. */
const REMOVERS = new Set(['rm', 'unlink', 'ri', 'remove-item', 'del', 'erase', 'rd', 'rmdir']);

/** cmd.exe commands with `/x` switches, which Git Bash spells `//x` ({@link cmdSwitch}). */
const CMD_SWITCHED = new Set(['copy', 'move', 'xcopy', 'robocopy', 'mklink', 'del', 'erase', 'rd', 'rmdir', 'ren', 'rename']);

/**
 * What `name args` does to the filesystem, from `cwd` — every path resolved
 * ({@link resolveFrom}). A copy writes its destination (and each source's name
 * inside it) and, recursive, may replace that directory wholesale; a move also
 * removes its sources; a rename removes its source and writes its new name; a
 * delete removes; `ln`, `mklink` and `New-Item -ItemType SymbolicLink` create
 * links, `mkfifo` and `mknod` special files; `cmd /c` is assessed command by
 * command ({@link cmdEffects}). A symbolic link's or a junction's target is
 * never a write: it is recorded with its link in `aliases`, which the guard
 * judges as a second name for it (review 12, finding 1).
 */
export function effectsOf(name: string, rawArgs: readonly string[], cwd: string, depth = 0): Effects {
  if (name === 'cmd') return cmdEffects(rawArgs, cwd, depth);
  // cmd's own commands, run from Git Bash, take their switches as `//Y` (review 8, item 2).
  const args = CMD_SWITCHED.has(name) ? rawArgs.map(cmdSwitch) : rawArgs;
  const at = (p: string): string => resolveFrom(cwd, p);
  const e = noEffects();
  switch (name) {
    case 'mkfifo':
      pushAll(e.special, operands(args, new Set(['-m', '--mode'])).map(at));
      return e;
    case 'mknod':
      pushAll(e.special, operands(args, new Set(['-m', '--mode'])).slice(0, 1).map(at));
      return e;
    case 'ln':
      pushAll(e.links, lnDestinations(args).map(at));
      pushAll(e.hardLinkSources, lnHardSources(args).map(at));
      for (const [link, target] of lnAliases(args)) e.aliases.push([at(link), at(fromLink(link, target))]);
      return e;
    case 'link':
      pushAll(e.hardLinkSources, operands(args, new Set()).slice(0, 1).map(at));
      return e;
    case 'fsutil':
      // `fsutil hardlink create <new> <existing>`
      if (/^hardlink$/i.test(args[0] ?? '') && /^create$/i.test(args[1] ?? '')) {
        if (args[2] !== undefined) e.links.push(at(args[2]));
        if (args[3] !== undefined) e.hardLinkSources.push(at(args[3]));
      }
      return e;
    case 'mklink': {
      pushAll(e.links, mklinkDestinations(args).map(at));
      // `mklink /H <link> <target>`: a hard link to the target.
      const names = args.filter((a) => !a.startsWith('/'));
      const [link, target] = names;
      if (args.some((a) => /^\/h$/i.test(a))) {
        if (target !== undefined) e.hardLinkSources.push(at(target));
      } else if (link !== undefined && target !== undefined) {
        // A junction's target is resolved from the command's directory; a symbolic link's from its own.
        e.aliases.push([at(link), at(args.some((a) => /^\/j$/i.test(a)) ? target : fromLink(link, target))]);
      }
      return e;
    }
    case 'new-item':
    case 'ni': {
      const item = newItemArgs(args);
      if (['symboliclink', 'hardlink', 'junction'].includes(item.itemType)) pushAll(e.links, item.paths.map(at));
      if (item.itemType === 'hardlink' && item.target !== undefined) e.hardLinkSources.push(at(item.target));
      else if (item.itemType === 'file') pushAll(e.writes, item.paths.map(at));
      const target = item.target;
      if (target !== undefined && (item.itemType === 'symboliclink' || item.itemType === 'junction')) {
        for (const p of item.paths) e.aliases.push([at(p), at(item.itemType === 'junction' ? target : fromLink(p, target))]);
      }
      return e;
    }
    case 'cp':
    case 'install':
    case 'copy-item':
    case 'cpi':
    case 'copy':
    case 'mv':
    case 'move-item':
    case 'mi':
    case 'move': {
      const t = parseTransfer(args, name === 'copy' || name === 'move');
      const moves = name === 'mv' || name === 'move-item' || name === 'mi' || name === 'move';
      if (moves) pushAll(e.removes, t.sources.map(at));
      // `cp -l` / `--link` hard-links instead of copying.
      if (name === 'cp' && args.some((a) => a === '--link' || /^-[a-zA-Z]*l[a-zA-Z]*$/.test(a))) pushAll(e.hardLinkSources, t.sources.map(at));
      if (t.dest === undefined) return e;
      const dest = t.dest;
      if (!t.into) e.writes.push(at(dest));
      pushAll(e.writes, t.sources.map((s) => at(intoDir(dest, s))));
      if (!t.into && (moves || t.recursive)) e.dirs.push(at(dest));
      return e;
    }
    case 'xcopy':
    case 'robocopy': {
      const [, dest, ...files] = args.filter((a) => !/^\/[A-Za-z]/.test(a));
      if (dest !== undefined) {
        e.dirs.push(at(dest));
        e.writes.push(at(dest));
        pushAll(e.writes, files.map((f) => at(intoDir(dest, f))));
        // `/MIR` and `/PURGE` delete what the source lacks: from an empty source, everything.
        if (name === 'robocopy' && args.some((a) => /^\/(?:mir|purge)$/i.test(a))) e.trees.push(at(dest));
      }
      return e;
    }
    case 'rsync': {
      const paths = operands(args, RSYNC_VALUED);
      const dest = paths.pop();
      if (dest === undefined || paths.length === 0) return e;
      e.writes.push(at(dest));
      pushAll(e.writes, paths.map((s) => at(intoDir(dest, s))));
      if (args.some((a) => a === '--recursive' || a === '--archive' || /^-[a-zA-Z]*[ra]/.test(a))) e.dirs.push(at(dest));
      if (args.some((a) => /^--del(?:ete(?:-[a-z]+)?)?$/.test(a))) e.trees.push(at(dest));
      return e;
    }
    case 'ren':
    case 'rename':
    case 'rename-item':
    case 'rni': {
      const positional = args.filter((a) => !a.startsWith('-') && !/^\/[A-Za-z]$/.test(a));
      const src = psParam(args, ['path', 'literalpath']) ?? positional.shift();
      const newName = psParam(args, ['newname']) ?? positional.shift();
      if (src === undefined) return e;
      e.removes.push(at(src));
      if (newName !== undefined) {
        const dest = /[\\/]/.test(newName) ? newName : `${dirOf(src.replace(/\\/g, '/')) || '.'}/${newName}`;
        e.writes.push(at(dest));
        e.dirs.push(at(dest));
      }
      return e;
    }
    default:
      break;
  }
  if (REMOVERS.has(name)) pushAll(e.removes, operands(args, new Set()).filter((a) => !/^\/[A-Za-z]$/.test(a)).map(at));
  const written = commandWriteDestinations(name, args).map(at);
  pushAll(e.writes, written);
  if (name === 'shred' && args.some((a) => a === '--remove' || a.startsWith('--remove=') || /^-[a-zA-Z]*u/.test(a))) {
    pushAll(e.removes, written);
  }
  return e;
}

/** `words` without their redirections (`<<< text`, `> f`, `2>&1`) — the operator word and a detached target both go. */
export function withoutRedirectWords(words: readonly ShellWord[]): ShellWord[] {
  const out: ShellWord[] = [];
  for (let i = 0; i < words.length; i += 1) {
    const word = words[i];
    if (word === undefined) continue;
    const r = parseRedirect(word);
    if (r === null) out.push(word);
    else if (r.inline === '') i += 1;
  }
  return out;
}
