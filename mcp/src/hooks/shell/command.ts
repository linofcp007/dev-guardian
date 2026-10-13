/**
 * Which word of a simple command names the program it runs — past `VAR=x`
 * assignments, redirections and runners (`sudo`, `env`, `timeout 30`,
 * cmd's `start`, …) read with their own options — and the small readers that
 * needs: a word's last path segment, its first redirection, a cmd.exe switch
 * in Git Bash's `//x` spelling. Moved out of `bashGuard.ts`, shared with the
 * install vetting's parser.
 *
 * Pure functions. No I/O.
 */

import type { ShellWord } from './split.js';

export function basename(value: string): string {
  const parts = value.split(/[\\/]/);
  const last = parts[parts.length - 1];
  return last === undefined || last.length === 0 ? value : last;
}

/** Commands whose job is to run another command, so the real one follows. */
const RUNNERS = new Set([
  'sudo',
  'doas',
  'env',
  'command',
  'exec',
  'builtin',
  'nohup',
  'nice',
  'time',
  'timeout',
  'setsid',
  'stdbuf',
  'xargs',
  'watch',
  // cmd's `start [/b] ["title"] PROGRAM` (fix round 2).
  'start',
]);

/**
 * Each runner's own options that consume a value — short letters (also at the
 * end of a cluster: `-Eu root`) and long names (`--user root`, `--user=root`).
 * Per runner, never one table for all: a shared set made `-n`, `-i`, `-s` and
 * `-k` take a value, which they do for `nice`, `xargs` or `timeout` but not
 * for `sudo` or `env` — so `sudo -n rm -rf /` read `rm` as the value of `-n`
 * and only warned as sudo, and `env -i rm -rf /` was ok (review I1). Options
 * whose value is optional and attached (`xargs -i[R]`, `-e[EOF]`) take none.
 */
const RUNNER_VALUED: Readonly<Record<string, { short: string; long: ReadonlySet<string> }>> = {
  sudo: {
    short: 'CDgpRrTtUu',
    long: new Set(['user', 'group', 'host', 'prompt', 'close-from', 'chdir', 'chroot', 'role', 'type', 'other-user', 'command-timeout']),
  },
  doas: { short: 'uC', long: new Set() },
  env: { short: 'uCSa', long: new Set(['unset', 'chdir', 'split-string', 'argv0']) },
  exec: { short: 'a', long: new Set() },
  nice: { short: 'n', long: new Set(['adjustment']) },
  time: { short: 'fo', long: new Set(['format', 'output']) },
  timeout: { short: 'sk', long: new Set(['signal', 'kill-after']) },
  stdbuf: { short: 'ioe', long: new Set(['input', 'output', 'error']) },
  xargs: {
    // `J` is BSD's `-J replstr`.
    short: 'adEIJLnPs',
    long: new Set(['arg-file', 'delimiter', 'max-args', 'max-procs', 'max-chars', 'process-slot-var']),
  },
  watch: { short: 'nq', long: new Set(['interval', 'equexit']) },
};

/** How many words a runner's option takes: 1 for a switch or an attached value, 2 when the value is the next word. */
export function runnerOptionWords(runner: string, option: string): number {
  const valued = RUNNER_VALUED[runner];
  if (valued === undefined) return 1;
  if (option.startsWith('--')) {
    return !option.includes('=') && valued.long.has(option.slice(2)) ? 2 : 1;
  }
  // A short cluster: the first letter that takes a value takes the rest of the
  // cluster, or — when it is the last letter — the next word.
  for (let k = 1; k < option.length; k += 1) {
    if (valued.short.includes(option.charAt(k))) return k === option.length - 1 ? 2 : 1;
  }
  return 1;
}

export const ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/;

/**
 * Walks past `VAR=x` assignments and runner prefixes (`sudo`, `env`, `xargs`,
 * `timeout 30`, …) to the index of the word that actually names the command,
 * reporting on the way whether privilege was elevated. `through`, when given,
 * limits the runners walked past to those named (the rest end the walk).
 */
export function resolveCommand(words: readonly ShellWord[], through?: ReadonlySet<string>): { index: number; elevated: boolean } {
  let i = 0;
  let elevated = false;
  // No hop cap: every pass consumes at least one word, so this is linear —
  // and a cap of 32 made `nice` x40 + `rm -rf /` a silent ok (fix round 4).
  while (i < words.length) {
    const word = words[i];
    if (word === undefined) break;
    if (ASSIGNMENT.test(word.value)) {
      i += 1;
      continue;
    }
    // A redirection may come before the command name: `2>/dev/null rm -rf /`
    // runs `rm` (fix round 4). Its target, when it is the next word, goes too.
    const redirect = parseRedirect(word);
    if (redirect !== null && /^(?:\d*|&|\{[A-Za-z_]\w*\})$/.test(redirect.prefix)) {
      i += redirect.inline === '' ? 2 : 1;
      continue;
    }
    const name = basename(word.value);
    if (!RUNNERS.has(name) || (through !== undefined && !through.has(name))) break;
    if (name === 'sudo' || name === 'doas') elevated = true;
    i += 1;
    if (name === 'start') {
      // Its `/x` switches (`/d DIR` takes a value) and one quoted title.
      let titled = false;
      while (i < words.length) {
        const arg = words[i];
        if (arg === undefined) break;
        if (!titled && arg.quoted) {
          titled = true;
          i += 1;
        } else if (/^\/[A-Za-z]+$/.test(cmdSwitch(arg.value))) i += /^\/d$/i.test(cmdSwitch(arg.value)) ? 2 : 1;
        else break;
      }
      continue;
    }
    while (i < words.length) {
      const arg = words[i];
      if (arg === undefined) break;
      if (ASSIGNMENT.test(arg.value)) {
        i += 1;
        continue;
      }
      if (arg.value === '--') {
        i += 1;
        break;
      }
      if (arg.value.startsWith('-') && arg.value.length > 1) {
        i += runnerOptionWords(name, arg.value);
        continue;
      }
      // `env -` is `env -i`.
      if (name === 'env' && arg.value === '-') {
        i += 1;
        continue;
      }
      if ((name === 'timeout' || name === 'watch') && /^\d+(?:\.\d+)?[smhd]?$/.test(arg.value)) {
        i += 1;
        continue;
      }
      break;
    }
  }
  return { index: i, elevated };
}

/**
 * The index of the word that names the command, past `VAR=x` and runner
 * prefixes read with their own options (`sudo -n`, `env -i`, `timeout 30`,
 * …) — for the install parser, which must find the same command the shell
 * guard does.
 */
export function commandWordIndex(words: readonly ShellWord[]): number {
  return resolveCommand(words).index;
}

/**
 * A cmd.exe switch as cmd receives it from Git Bash (review 8, item 2): MSYS
 * turns an argument that starts with `//` into one that starts with `/`, which
 * is why `cmd //c …` is the form that runs there — `cmd /c` is path-converted
 * to `cmd C:/` and opens an interactive cmd. Read the same way from either
 * tool: it can only add a reading.
 */
export function cmdSwitch(word: string): string {
  return /^\/\/[A-Za-z?]/.test(word) ? word.slice(1) : word;
}

export interface Redirect {
  /** What precedes the operator in the same word: `''`, an fd number, `&`, or an ordinary word (`x>f`). */
  prefix: string;
  /** `>`, `>>`, `>|`, `>&`, `<`, `<>`, `<<<`, `<&`, … */
  op: string;
  /** The operand written in the same word (`>f`), or `''` when it is the next word. */
  inline: string;
}

/** The first unquoted redirection in `word`, if it has one. */
export function parseRedirect(word: ShellWord): Redirect | null {
  const at = word.redirectAt?.[0];
  if (at === undefined) return null;
  const tail = word.value.slice(at);
  const op = /^[<>]+[|&]?/.exec(tail)?.[0] ?? tail.charAt(0);
  return { prefix: word.value.slice(0, at), op, inline: tail.slice(op.length) };
}

