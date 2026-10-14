/**
 * Where each command of a command line runs, as the `cd`s before it moved it —
 * the one tracker the shell guard reads a relative delete target with (review
 * of 3.4.0, finding 9: `cd / && rm -rf *` only warned) and the install vetting
 * reads a launcher's working directory with (finding 5: `false && cd web; npx
 * x` ran `x` where the line began, and the hook looked for it in `web`). The
 * install parser's own `directoryAfter` went away for it.
 *
 * Two answers per command, for the two directions a guard can err in:
 *
 *   - `may` — the directory if every `cd` before it ran and succeeded: what a
 *     deny must assume (`false && cd /; rm -rf *` may delete the root);
 *   - `sure` — the directory only when every `cd` before it surely ran: each at
 *     the head of an unconditional list or joined to it by `&&` (never after
 *     `||` or another command's `&&`), outside a pipeline, a background list, a
 *     compound command or a function body, and — under `CDPATH` — never a bare
 *     name it may look up elsewhere. Whether each one SUCCEEDED (`cd
 *     missing; npx x`) is the reader's to check: a step whose directory is not
 *     there did not move the shell. What the install vetting must assume
 *     before it skips anything.
 *
 * Each is the targets of the moves in order, as written (dequoted) — each
 * relative to the one before, `~` the home directory, the caller resolving
 * them against where the line began — or `null` when a move cannot be followed
 * (a target in a variable, `popd` past the stack, a subshell's end this split
 * did not see begin). A subshell's moves end with it (`(cd web && npm ci) &&
 * npx x`); `cd -`, `$OLDPWD` and `pushd` / `popd` go back where they say.
 *
 * Pure functions. No I/O. One pass over the statements.
 */

import { commandName, resolveCommand } from './command.js';
import { CD_COMMANDS, CD_RETURNS, cdOperand } from './paths.js';
import type { ShellStatement, ShellWord } from './split.js';

/** The moves to a command's working directory, from where the line began; `null`: not known. */
export type Steps = readonly string[] | null;

/** Where one command runs ({@link workdirs}). */
export interface Workdir {
  may: Steps;
  sure: Steps;
}

/** A directory change, as {@link cdMove} reads it. */
type Move = { kind: 'cd'; target: string | undefined; push: boolean } | { kind: 'pop' } | { kind: 'unknown' };

/** A `cd` target this cannot read literally: an expansion, a glob, a cmd.exe `%VAR%`, another account's `~name`. */
const UNREAD_TARGET = /[$`%*?[\]{}]|^~[^\\/]/;

/** The move one simple command makes, if it is a directory change. */
function cdMove(words: readonly ShellWord[]): Move | undefined {
  const at = resolveCommand(words).index;
  const name = commandName(words[at]?.value ?? '');
  if (name === 'cd..') return { kind: 'cd', target: '..', push: false };
  if (CD_RETURNS.has(name)) return { kind: 'pop' };
  if (!CD_COMMANDS.has(name)) return undefined;
  const target = cdOperand(words.slice(at + 1).map((w) => w.value));
  if (target === null) return { kind: 'unknown' };
  return { kind: 'cd', target, push: name === 'pushd' || name === 'push-location' };
}

/** Whether a word sets `CDPATH` (`CDPATH=…`, the value of `export`). */
function setsCdpath(words: readonly ShellWord[]): boolean {
  return words.some((w) => /^CDPATH=/.test(w.value));
}

/** The reserved words that open a compound command or a body, and those that close one. */
const OPENERS = new Set(['if', 'while', 'until', 'for', 'select', 'case', '{', 'function']);
const CLOSERS = new Set(['fi', 'done', 'esac', '}']);
const INSIDE = new Set(['then', 'else', 'elif', 'do', '!', 'time', '-p']);

/**
 * How a statement moves the compound-command depth: the reserved words at its
 * start (`if`, `then`, `{`, `}`, `done`, …), in its masked text — the split
 * drops them from the words. A function's header (`f()`) leaves its `{` there.
 */
function depthDelta(masked: string): number {
  let delta = 0;
  for (const word of masked.trim().split(/\s+/)) {
    if (OPENERS.has(word)) delta += 1;
    else if (CLOSERS.has(word)) delta -= 1;
    else if (!INSIDE.has(word)) break;
  }
  return delta;
}

/** One saved place: what `cd -` returns to and what `popd` pops, per answer. */
interface Place {
  may: Steps;
  sure: Steps;
  prevMay: Steps;
  prevSure: Steps;
  stack: ReadonlyArray<{ may: Steps; sure: Steps }>;
}

/**
 * The most moves followed, and the deepest `pushd` stack: no real line needs
 * more, and each move copies its list — a line of thousands of `cd`s would
 * cost their square.
 */
const MAX_STEPS = 64;

/** `steps` and a move to `target` — an absolute target alone, whatever came before; `null` when not known. */
function moved(steps: Steps, target: string | undefined): Steps {
  const t = target ?? '~';
  if (/^(?:[\\/]|~(?:[\\/]|$)|[A-Za-z]:[\\/])/.test(t)) return [t];
  return steps === null || steps.length >= MAX_STEPS ? null : [...steps, t];
}

/**
 * Where each command of `statements` runs: `[statement][command]`, the
 * directory before that command (see the module doc). `cdpath`: `CDPATH` is
 * set in the environment the line starts in.
 */
export function workdirs(statements: readonly ShellStatement[], opts: { cdpath?: boolean } = {}): Workdir[][] {
  // Where each and-or list ends: the first end that is not `&&` / `||`.
  const listEnd: Array<string | undefined> = new Array<string | undefined>(statements.length);
  for (let k = statements.length - 1; k >= 0; k -= 1) {
    const end = statements[k]?.end;
    listEnd[k] = end === '&&' || end === '||' ? listEnd[k + 1] : end;
  }
  // `cd -` before any move goes back to where the shell was before the line: not known.
  let here: Place = { may: [], sure: [], prevMay: null, prevSure: null, stack: [] };
  /** Where the current list began — a background list leaves the shell there. */
  let listStart: Place = here;
  /** Every statement of the current list so far is a lone `cd` joined by `&&`: a `cd` now surely runs. */
  let trusted = true;
  /** An `||` came earlier in the current list: what follows it may run because a `cd` failed. */
  let orElse = false;
  let cdpath = opts.cdpath === true;
  let depth = 0;
  const outer: Place[] = [];
  let inBacktick = false;
  const out: Workdir[][] = [];
  for (let k = 0; k < statements.length; k += 1) {
    const statement = statements[k];
    if (statement === undefined) {
      out.push([]);
      continue;
    }
    const before = statements[k - 1]?.end;
    if (before === '&&' || before === '||') {
      if (before === '||') {
        trusted = false;
        orElse = true;
      }
    } else {
      // A new list. After a subshell's or a substitution's end its connector
      // is not known (`(…) && cd x` keeps no `&&`): nothing in it is trusted.
      listStart = here;
      trusted = before !== ')' && !(before === '`' && !inBacktick);
      orElse = false;
    }
    const delta = depthDelta(statement.masked);
    if (delta > 0) depth += delta;
    const lone = statement.commands.length === 1;
    // A substitution that begins where the statement ends continues its last
    // word: `cd \`pwd\``, `cd $(…)` name a directory this cannot read.
    const continued = statement.end === '(' || (statement.end === '`' && !inBacktick);
    const row: Workdir[] = [];
    statement.commands.forEach((words, c) => {
      row.push({ may: here.may, sure: orElse ? null : here.sure });
      const at = resolveCommand(words).index;
      const prefixCdpath = setsCdpath(words.slice(0, at));
      // `CDPATH=x` alone sets it for the rest of the line; so does `export CDPATH=x`.
      if ((at >= words.length && prefixCdpath) || (commandName(words[at]?.value ?? '') === 'export' && setsCdpath(words.slice(at + 1)))) cdpath = true;
      const found = cdMove(words);
      const move: Move | undefined = found !== undefined && continued && c === statement.commands.length - 1 ? { kind: 'unknown' } : found;
      if (move === undefined) {
        trusted = false;
        return;
      }
      const surely = trusted && lone && depth === 0 && listEnd[k] !== '&';
      if (move.kind === 'unknown') {
        here = { ...here, may: null, sure: null, prevMay: here.may, prevSure: here.sure };
      } else if (move.kind === 'pop') {
        const top = here.stack[here.stack.length - 1];
        here = {
          may: top?.may ?? null,
          sure: surely ? (top?.sure ?? null) : null,
          prevMay: here.may,
          prevSure: here.sure,
          stack: here.stack.slice(0, -1),
        };
      } else {
        const back = move.target === '-' || (move.target !== undefined && /^\$\{?OLDPWD\}?$/.test(move.target));
        const unread = !back && move.target !== undefined && UNREAD_TARGET.test(move.target);
        // Under CDPATH a bare name may be found elsewhere: `./x`, `../x` and absolute paths are not looked up.
        const lookedUp = (cdpath || prefixCdpath) && move.target !== undefined && !/^(?:\.\.?(?:[\\/]|$)|[\\/~]|[A-Za-z]:)/.test(move.target);
        const nextMay = back ? here.prevMay : unread ? null : moved(here.may, move.target);
        // A bare `cd` goes home — what a deny assumes; where `$HOME` points is not what the vetting skips on.
        const nextSure = !surely || unread || lookedUp || move.target === undefined ? null : back ? here.prevSure : moved(here.sure, move.target);
        here = {
          may: nextMay,
          sure: nextSure,
          prevMay: here.may,
          prevSure: here.sure,
          stack: !move.push ? here.stack : here.stack.length >= MAX_STEPS ? [] : [...here.stack, { may: here.may, sure: here.sure }],
        };
      }
      // A move in a pipeline is a subshell's in bash (PowerShell's runs in the
      // same runspace): what follows does not surely run there.
      if (!lone) here = { ...here, sure: null };
    });
    out.push(row);
    if (delta < 0) depth = Math.max(0, depth + delta);
    // The end of a background list: the shell stays where the list began.
    const end = statement.end;
    if (end === '&') here = { ...listStart, may: here.may, prevMay: here.prevMay };
    if (end === '(') outer.push(here);
    else if (end === '`') {
      if (!inBacktick) outer.push(here);
      else here = outer.pop() ?? { ...here, may: null, sure: null };
      inBacktick = !inBacktick;
    } else if (end === ')') {
      // A `(` at the start of the line leaves no statement: where it began is not known.
      here = outer.pop() ?? { ...here, may: null, sure: null };
    }
  }
  return out;
}
