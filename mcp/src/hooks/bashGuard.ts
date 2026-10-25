/**
 * Fast, dependency-free risk assessment for shell commands, used by the
 * guardian PreToolUse(Bash) hook and by `dev-guardian check --bash`.
 *
 * Three levels:
 *   - 'block' → catastrophic and effectively never a legitimate assistant
 *               action (wiping the filesystem root, piping a remote script
 *               straight into a shell, overwriting a raw disk, fork bombs).
 *               The hook denies these by default; the patterns are tight
 *               enough that false positives are extremely unlikely.
 *   - 'warn'  → genuinely risky but sometimes intended (force-push, hard
 *               reset, broad recursive delete, sudo, chmod 777). Surfaced as
 *               a non-blocking note so the model double-checks intent.
 *   - 'ok'    → nothing notable.
 *
 * ## Why this file segments the command before matching anything
 *
 * Every rule used to be a regex run against the whole command string, and
 * three families of false positive fall straight out of that. All three were
 * observed on real commands from this repo's own sessions:
 *
 *  1. **Matching across a command separator.** `[^\n]*` crosses `&&`, so
 *     `git push origin main && git worktree remove .worktrees/java --force`
 *     read as a force-push. Eight of the twelve regex rules carry such a span.
 *  2. **Matching inside a quoted argument.** `echo 'git push --force 2>&1'`
 *     pushes nothing; the text is data. Every rule had this defect, because
 *     every rule matched text rather than command structure.
 *  3. **Matching inside a heredoc body.** `git commit -F - <<'EOF' … EOF` puts
 *     a commit message on stdin. One such message contained a lone `~` on a
 *     line, and because the `rm` tokeniser split on `;|&` but *not* on
 *     newlines, `rm -rf ./.playwright-mcp` two lines earlier collected it as a
 *     target: a real commit was **blocked** as `rm -rf ~`.
 *
 * The obvious repair — dropping `&` from the character classes — is wrong: a
 * genuine force-push is very often `git push --force 2>&1 | tee log`, and
 * `2>&1` contains `&`. Narrowing on the character trades a false positive for
 * a false negative, which is the worse direction for a guardrail.
 *
 * So `splitShell()` does a small, quote-aware, escape-aware, heredoc-aware
 * scan and yields **statements** (split on `&&`, `||`, `;`, newline, a
 * background `&`, `(`, `)` and backticks) each holding its **pipeline
 * members** as word lists. A reserved word at a command position (`do`,
 * `then`, `else`, `{`, `!`, …) is dropped, so the body of a loop, an `if` or a
 * brace group is judged like a top-level statement. Rules then run against
 * structure:
 *
 *   - a statement keeps its pipeline intact, because `curl … | sh` is one
 *     hazard spanning a pipe — splitting on `|` would have silently disarmed
 *     `remote-pipe-to-shell` and `powershell-iex-download`, the two block
 *     rules that require the pipe to match at all;
 *   - quoted spans collapse to a single space in the text a regex sees, so
 *     quoted text cannot match, while staying a real word for the tokenised
 *     rules (`rm -rf '/'` is still a delete of `/`);
 *   - `rm` and `sudo` are decided on *words at a command position*, never on
 *     text, so `apt-get install -y git sudo pipx` no longer reads as elevation;
 *   - `fork-bomb` is the one rule scoped to the whole command, since its
 *     signature is made of the very separators everything else splits on.
 *
 * Because quoting stops being matchable, `sh -c '…'`, `bash -c '…'` (including
 * behind `docker exec … bash -c`), `su … -c '…'`, `eval …` and PowerShell's
 * `-Command …` / `-EncodedCommand …` are re-entered and assessed as commands
 * in their own right, to depth 3. That is strictly more coverage than the old
 * text matching had, not less: `bash -c 'rm -rf /'` was never blocked before,
 * and is now.
 *
 * ## The guard's own configuration
 *
 * The hook configuration files and Claude Code's settings are protected by
 * what a command DOES to them, modelled per command (`effectsOf`): the files
 * it writes (redirections, `tee`, `sed -i`, `perl -pi`, `sort -o`, `rsync`,
 * `cp`, PowerShell `Set-Content`, cmd `copy`, `[IO.File]::WriteAllText`, …),
 * the paths it removes or moves away, the directories it copies a whole tree
 * onto, and the links, FIFOs and device nodes it creates. Relative paths are
 * resolved against the `cd`s earlier in the same command (`resolveFrom`), and
 * each command of a quoted `cmd /c "…"` line is modelled too. Program text on
 * a command line (`node -e`, `python -c`, a heredoc fed to `python -`) cannot
 * be modelled that way, so it is refused when one of its string literals
 * names a hook configuration path at all (`judgeCode`).
 *
 * What this is NOT: a shell parser, nor an interpreter. Command substitution
 * inside double quotes (`echo "$(rm -rf /)"`) stays invisible, exactly as it
 * was before this file grew a scanner, and so does anything decided at run
 * time — a path in a variable, a script run from a file. Fail-open is the
 * design; a missed warning is the failure mode we accept, and no block rule
 * was narrowed to get here.
 *
 * ## ReDoS
 *
 * `assessBashCommand` caps every LINE of its input at 16 KB before doing
 * anything else (`capLines`) — measured, a 100 KB single-line unquoted
 * command took 2-3.6s against several of the `[^\n]*`-shaped BASH_RULES
 * patterns above, each restarting its search at every position in a haystack
 * with nothing for it to find. Capping first bounds that to a small, fixed
 * constant regardless of how large the real input is, the same fix applied
 * in `secretScan.ts`.
 *
 * Pure functions. No I/O. No dependencies.
 */

import { homedir } from 'node:os';
import { userDataDir } from './dataRegistry.js';
import { powershellAsPosix, powershellOpaque } from './powershellText.js';
import { pushAll } from './shell/arrays.js';
import { cmdInnerCommands, cmdLineText, posixWord } from './shell/cmd.js';
import { ASSIGNMENT, basename, cmdSwitch, cmdSwitches, commandName, psParam, resolveCommand, runnerOptionWords } from './shell/command.js';
import { commandWriteDestinations, type Effects, effectsOf, lastSegment, noEffects, parseTransfer, redirectTargets, withoutRedirections, withoutRedirectWords } from './shell/effects.js';
import { asWindowsOpens, codeLang, type CodeLang, codeLiterals, firstNonFlag, inlineCode, interpreterIndex, interpreterName, interpreterProgram, isBareInterpreterStdin, isInterpreter, LAUNCHER_VALUED, literalPaths, NODE_OPTION_VALUED, powershellCommand, powershellReadsStdin, RUN_WRAPPERS, tail } from './shell/interpreters.js';
import { CD_COMMANDS, CD_RETURNS, cwdAfter, dirOf, isAbsolutePath, MAX_CWD, normalizedPath, resolveFrom, wildcardMatch } from './shell/paths.js';
import { MASK, splitShell, type ShellStatement, type ShellWord } from './shell/split.js';
import { type Steps, workdirs } from './shell/workdir.js';

// How a command is READ lives in `shell/` — the tokenizer (`split.ts`), the
// command-word resolution (`command.ts`), cmd.exe's line reader (`cmd.ts`),
// paths as the command moves between directories (`paths.ts`), what it does
// to the filesystem (`effects.ts`), the program text it hands an interpreter
// (`interpreters.ts`) — and this module judges it. What it exported from them before stays exported
// from here.
export { commandWordIndex } from './shell/command.js';
export { splitShell, type ShellSplit, type ShellStatement, type ShellWord, type StatementEnd } from './shell/split.js';

export type BashRiskLevel = 'ok' | 'warn' | 'block';

/**
 * Where a rule's pattern is evaluated.
 *   - 'statement' (default) — against one shell statement, pipeline included,
 *     with quoted spans masked. This is what stops a match crossing `&&`.
 *   - 'command' — against the whole masked command line. Only for signatures
 *     built out of separators, which segmentation would tear apart.
 */
export type BashRuleScope = 'statement' | 'command';

export interface BashRule {
  id: string;
  level: Exclude<BashRiskLevel, 'ok'>;
  reason: string;
  pattern: RegExp;
  scope?: BashRuleScope;
  /**
   * A linear-time equivalent of `pattern`, used instead of it wherever it is
   * given: the pattern's `[^\n]*` restarts at every occurrence of its
   * keyword, which made a 16 KB statement cost up to ~190 ms and 127 of them
   * run past the hook's 15 s timeout (fix round 2). The pattern stays as the
   * specification, and a differential test holds the two equal.
   */
  test?: (text: string) => boolean;
}

export interface BashAssessment {
  level: BashRiskLevel;
  /** Human-readable reasons, most severe first. */
  reasons: string[];
  /** Matched rule ids, for telemetry / allowlisting. */
  rules: string[];
  /**
   * The whole deny message, when the one rule that blocks words its own —
   * `db-adopt-yes`, whose reason already says what to do instead — for the
   * hook to send in place of its standard wording. Absent otherwise, and
   * whenever another rule blocks too.
   */
  denyMessage?: string;
  /**
   * Set when the command is the user's decision to take rather than a hazard —
   * `dev-guardian baseline update` (review 8, C2) — and nothing blocks it: the
   * hook asks the user, with this as the reason, instead of letting it run.
   * The level stays `warn`, which is what `check --bash` and a hook whose
   * block is switched off report.
   */
  ask?: string;
  /**
   * The scripts the command hands a shell, each as that shell reads it — a
   * `bash -c` / `eval` / `pwsh -c` / `-EncodedCommand` script, a `cmd /c` line,
   * a script fed to a shell (`echo '…' | sh`, `cat <<EOF | bash`), a process
   * substitution — to the guard's nesting depth, at most
   * {@link MAX_NOTED_SCRIPTS}. The hook vets the installs in them as it does
   * the command's own (review of 3.3.0: `bash -c 'npm i x'` was never vetted).
   * Absent when there is none.
   */
  scripts?: ReadonlyArray<{ text: string; shell: 'bash' | 'powershell' }>;
}

/**
 * The pattern-matched rules.
 *
 * NB: three further rules are *tokenised* rather than pattern-matched, because
 * their verdict depends on a word's position in the command rather than on
 * text: `rm-rf-root` / `rm-rf-broad` (the delete *target* decides block vs
 * warn — a regex cannot tell `rm -rf /` from `rm -rf node_modules`) and `sudo`
 * (only elevation at a command position counts; `apt-get install sudo` is
 * installing a package).
 */
export const BASH_RULES: BashRule[] = [
  // ── Catastrophic: block by default ───────────────────────────────────────
  {
    id: 'no-preserve-root',
    level: 'block',
    reason: 'Uses --no-preserve-root, defeating the root-deletion safeguard',
    pattern: /--no-preserve-root/i,
  },
  {
    id: 'remote-pipe-to-shell',
    level: 'block',
    reason: 'Pipes a downloaded script directly into a shell (curl|wget … | sh/bash)',
    // `sudo -E bash`, `sudo -H -E bash` etc. — flags between `sudo` and the
    // shell name — used to fall through this pattern, which only allowed
    // `sudo` directly followed by the shell.
    // A flag never contains `|`: `-\S+` spanned pipes and made `| sudo -x|sudo
    // -x|…` quadratic (fix round 3).
    pattern: /\b(?:curl|wget)\b[^\n]*?\|\s*(?:sudo\s+(?:-[^\s|]+\s+)*)?(?:ba|z|da)?sh\b/i,
    test: after(/\b(?:curl|wget)\b/i, /\|\s*(?:sudo\s+(?:-[^\s|]+\s+)*)?(?:ba|z|da)?sh\b/i),
  },
  {
    id: 'powershell-iex-download',
    level: 'block',
    reason: 'Downloads and executes remote code via Invoke-Expression',
    // `irm`/`iwr` are PowerShell's own built-in aliases for
    // Invoke-RestMethod/Invoke-WebRequest — as common in the wild as the
    // full names, and the piped-download shape is identical either way.
    pattern: /(?:iwr|irm|invoke-webrequest|invoke-restmethod|wget|curl)[^\n]*\|\s*(?:iex|invoke-expression)/i,
    test: after(/(?:iwr|irm|invoke-webrequest|invoke-restmethod|wget|curl)/i, /\|\s*(?:iex|invoke-expression)/i),
  },
  {
    id: 'powershell-iex-nested',
    level: 'block',
    reason: 'Downloads and executes remote code via Invoke-Expression',
    // `iex (irm …)` / `Invoke-Expression (Invoke-RestMethod …)` is the same
    // hazard as the piped form above, spelled with the download as a nested
    // call instead of a pipe. `(` is a statement boundary everywhere else in
    // this file (subshells, command substitution), so this must be
    // scope:'command' to see across it — narrow enough (iex/Invoke-Expression
    // immediately opening a paren around a download cmdlet) that it does not
    // reopen the cross-separator false positives scope:'command' otherwise
    // reintroduces the download and the pipe are never split across `&&`/`;`
    // for the same reason the fork-bomb signature needs scope:'command'.
    pattern: /\b(?:iex|invoke-expression)\s*\(\s*(?:irm|iwr|invoke-restmethod|invoke-webrequest)\b/i,
    scope: 'command',
  },
  {
    id: 'powershell-disk-format',
    level: 'block',
    reason: 'Formats or clears an entire disk/volume',
    pattern: /\b(?:Format-Volume|Clear-Disk)\b/i,
  },
  {
    id: 'process-substitution-remote-fetch',
    level: 'block',
    reason: 'Executes a downloaded script via process substitution (bash <(curl …))',
    // `bash <(curl …)` hands bash a fake file whose content is curl's stdout
    // — the same hazard as `curl … | sh`, spelled with process substitution
    // instead of a pipe. `<(` is not a statement separator anywhere else in
    // this file, so scope:'command' (which sees the un-split text) is enough
    // here and no tokenizer change is needed — unlike `sh -c "$(curl …)"`,
    // where the whole thing sits inside quotes and is handled separately, by
    // `isBareRemoteFetch` on the extracted `-c` script text. `source <(curl
    // …)` and `. <(wget …)` run the download in the current shell — the same
    // hazard (review I1); `.` counts only where a command starts.
    pattern: /(?:\b(?:sh|bash|zsh|dash|ksh|ash|mksh|source)\b|(?:^|[;&|(){}])[ \t]*\.(?=\s))[^\n]*<\(\s*(?:curl|wget)\b/im,
    scope: 'command',
    test: processSubstitutionFetch,
  },
  {
    id: 'disk-overwrite',
    level: 'block',
    reason: 'Writes raw bytes to a block device (dd/mkfs/wipefs/shred on /dev/…)',
    // The `\b` used to sit in front of the whole group, and a leading `\b`
    // before `>` demands a word character immediately to its left — so the
    // redirect alternative matched `cat x>/dev/sda` and never the
    // `cat x > /dev/sda` anybody actually writes. Each alternative anchors
    // itself now.
    //
    // `dd … of=` is deliberately narrower than the rest: it only blocks a
    // handful of real block-device name families (`sd`/`hd`/`vd`/`xvd`/
    // `nvme`/`mmcblk`/`disk`/`md`/`dm-`, plus the Windows `\\.\PhysicalDriveN`
    // spelling) — `dd … of=/dev/null`, `of=/dev/stdout`, `of=/dev/zero` and
    // an ordinary regular-file target are all common, harmless uses of dd
    // that this used to block outright by matching any `/dev/` path.
    // `mkfs`/`wipefs`/`shred` keep matching any `/dev/…` target: unlike dd,
    // there is no ordinary reason to run any of them against something that
    // is not a device, so narrowing them has no false positive to fix.
    // `mkfs`'s target used to have to sit immediately after the command
    // (`mkfs\s+\/dev\/`), so `mkfs -t ext4 /dev/sdb` — flags between the
    // command and its target — never matched; `[^\n]*` between them (already
    // safe here: this rule runs per masked *statement*, so it cannot cross a
    // `&&`/`;`/newline) fixes that the same way the rest of this alternation
    // already tolerates flags before its target.
    pattern:
      /(?:\bdd\b[^\n]*\bof=(?:\/dev\/(?:sd|hd|vd|xvd|nvme|mmcblk|disk|md|dm-)[\w-]*|\\\\\.\\PhysicalDrive\d*)|\bmkfs(?:\.\w+)?\b[^\n]*\/dev\/|\bwipefs\b[^\n]*\/dev\/|\bshred\b[^\n]*\/dev\/|>\s*\/dev\/(?:sd|hd|vd|xvd|nvme|mmcblk|disk|md|dm-))/i,
    test: anyOf(
      after(/\bdd\b/i, /\bof=(?:\/dev\/(?:sd|hd|vd|xvd|nvme|mmcblk|disk|md|dm-)[\w-]*|\\\\\.\\PhysicalDrive\d*)/i),
      after(/\bmkfs(?:\.\w+)?\b/i, /\/dev\//i),
      after(/\bwipefs\b/i, /\/dev\//i),
      after(/\bshred\b/i, /\/dev\//i),
      (t) => />\s*\/dev\/(?:sd|hd|vd|xvd|nvme|mmcblk|disk|md|dm-)/i.test(t),
    ),
  },
  {
    id: 'fork-bomb',
    level: 'block',
    reason: 'Shell fork bomb',
    // Scoped to the whole command: `(`, `)`, `|`, `&` and `;` are the very
    // characters splitShell() separates on, so this signature only exists
    // before segmentation. Quoted spans are still masked, so
    // `echo ':(){ :|:& };:'` stays inert. Any function name, not only `:`
    // (review 8, item 9: `f(){ f|f& };f` was ok); the backreference is the
    // specification, `forkBomb` the linear reading of it.
    pattern: /(?<![\w:.-])([\w:.-]{1,64})\s*\(\s*\)\s*\{\s*\1\s*\|\s*\1\s*&\s*\}\s*;\s*\1(?![\w:.-])/,
    scope: 'command',
    test: forkBomb,
  },
  {
    id: 'chmod-777-root',
    level: 'block',
    reason: 'Recursively makes the filesystem root world-writable',
    // `chmod 777 -R /` is the same hazard as `chmod -R 777 /` with the flag
    // and the mode swapped — both orders are real, so both are matched.
    pattern: /\bchmod\b[^\n]*(?:-[a-z]*R[a-z]*\s+0?777\s+\/(?:\s|$)|0?777\s+-[a-z]*R[a-z]*\s+\/(?:\s|$))/i,
    // `-[a-z]*R[a-z]*` backtracked quadratically over a run of R's; a lookahead
    // for the R and one greedy run cannot.
    test: after(
      /\bchmod\b/i,
      /(?:-(?=[a-z]*R)[a-z]*\s+0?777\s+\/(?:\s|$)|0?777\s+-(?=[a-z]*R)[a-z]*\s+\/(?:\s|$))/i,
    ),
  },

  // ── Risky: warn only ─────────────────────────────────────────────────────
  {
    id: 'git-force-push',
    level: 'warn',
    reason: 'Force-push can overwrite remote history',
    // `+main`/`+master` is git's own shorthand for a forced update of that
    // ref (a `+` prefix on a push refspec), and `--mirror` force-overwrites
    // every ref on the remote — same hazard as `--force`, different spelling.
    pattern: /\bgit\s+push\b[^\n]*?(?:--force\b|--force-with-lease\b|\s-f\b|\s\+\S|--mirror\b)/i,
    test: after(/\bgit\s+push\b/i, /(?:--force\b|--force-with-lease\b|\s-f\b|\s\+\S|--mirror\b)/i),
  },
  {
    id: 'git-hard-reset',
    level: 'warn',
    reason: 'git reset --hard discards uncommitted work',
    pattern: /\bgit\s+reset\b[^\n]*--hard\b/i,
    test: after(/\bgit\s+reset\b/i, /--hard\b/i),
  },
  {
    id: 'git-clean-force',
    level: 'warn',
    reason: 'git clean -fd permanently removes untracked files',
    pattern: /\bgit\s+clean\b[^\n]*-[a-z]*f/i,
    test: after(/\bgit\s+clean\b/i, /-[a-z]*f/i),
  },
  {
    id: 'chmod-777',
    level: 'warn',
    reason: 'chmod 777 grants world-write — overly permissive',
    pattern: /\bchmod\b[^\n]*\b0?777\b/i,
    test: after(/\bchmod\b/i, /\b0?777\b/i),
  },
  {
    id: 'history-wipe',
    level: 'warn',
    reason: 'Clears shell history',
    pattern: /\bhistory\s+-c\b|>\s*~?\/?\.(?:bash|zsh)_history\b/i,
  },
];

/**
 * `KEYWORD[^\n]*TAIL` in linear time: the pattern restarts its `[^\n]*` at
 * every occurrence of the keyword and rescans to the end each time. It matches
 * exactly when TAIL occurs at or after the end of the FIRST keyword match (a
 * later keyword never ends earlier), so one keyword search and one TAIL search
 * from there — in the whole text, so `\b` and lookarounds see the same
 * neighbours — decide it. TAIL itself must not backtrack over long runs.
 */
function after(keyword: RegExp, tail: RegExp): (text: string) => boolean {
  const kw = new RegExp(keyword.source, keyword.flags.replace(/[gy]/g, ''));
  const tl = new RegExp(tail.source, `${tail.flags.replace(/[gy]/g, '')}g`);
  return (text: string): boolean => {
    const m = kw.exec(text);
    if (m === null) return false;
    tl.lastIndex = m.index + m[0].length;
    return tl.test(text);
  };
}

function anyOf(...tests: Array<(text: string) => boolean>): (text: string) => boolean {
  return (text: string): boolean => tests.some((t) => t(text));
}

/**
 * `process-substitution-remote-fetch`'s pattern, in linear time: on some
 * line, a shell name ENDS at or before the start of a `<( curl|wget`. The
 * pattern itself restarts its `[^\n]*` at every shell name on the line.
 */
function processSubstitutionFetch(text: string): boolean {
  for (const line of text.split('\n')) {
    const shell = /\b(?:sh|bash|zsh|dash|ksh|ash|mksh|source)\b|(?:^|[;&|(){}])[ \t]*\.(?=\s)/i.exec(line);
    if (shell === null) continue;
    const shellEnd = shell.index + shell[0].length;
    for (const fetch of line.matchAll(/<\(\s*(?:curl|wget)\b/gi)) {
      if (fetch.index >= shellEnd) return true;
    }
  }
  return false;
}

/** A character of a fork bomb's function name. */
const FORK_NAME_CHAR = /[\w:.-]/;

/**
 * `fork-bomb`'s pattern in linear time: at each `( ) {`, the name right before
 * it (1-64 characters, whole), then the body `NAME | NAME & } ; NAME` read
 * once from there. The pattern's backreference retried every name length at
 * every position of a long word.
 */
function forkBomb(text: string): boolean {
  for (const m of text.matchAll(/\(\s*\)\s*\{\s*/g)) {
    let end = m.index;
    for (let k = 0; end > 0 && k < 64 && /\s/.test(text.charAt(end - 1)); k += 1) end -= 1;
    let start = end;
    while (start > 0 && end - start < 64 && FORK_NAME_CHAR.test(text.charAt(start - 1))) start -= 1;
    if (start === end || (start > 0 && FORK_NAME_CHAR.test(text.charAt(start - 1)))) continue;
    const name = text.slice(start, end).replace(/[.*+?^${}()|[\]\\-]/g, '\\$&');
    const body = new RegExp(`${name}\\s*\\|\\s*${name}\\s*&\\s*\\}\\s*;\\s*${name}(?![\\w:.-])`, 'y');
    body.lastIndex = m.index + m[0].length;
    if (body.test(text)) return true;
  }
  return false;
}

const SUDO_RULE = {
  id: 'sudo',
  level: 'warn',
  reason: 'Runs with elevated privileges (sudo)',
} as const;

const LEVEL_RANK: Record<BashRiskLevel, number> = { ok: 0, warn: 1, block: 2 };

interface MatchedRule {
  id: string;
  level: Exclude<BashRiskLevel, 'ok'>;
  reason: string;
}

// ────────────────────────────────────────────────────── tokenised rules

function stripQuotes(token: string): string {
  // Loops, not `/['"`]+$/`: that regex restarts at every quote of a long run.
  const q = (c: string): boolean => c === "'" || c === '"' || c === '`';
  let a = 0;
  let b = token.length;
  while (a < b && q(token.charAt(a))) a += 1;
  while (b > a && q(token.charAt(b - 1))) b -= 1;
  return token.slice(a, b);
}

/** What a catastrophic target is: the filesystem root, a drive root or a system directory — or a home directory. */
type TargetKind = 'root' | 'home';

/** The top-level directories of a POSIX system and of macOS, whose loss takes the system with it. */
const SYSTEM_DIRS = ['etc', 'usr', 'bin', 'sbin', 'var', 'lib', 'lib64', 'boot', 'sys', 'proc', 'root', 'home', 'opt', 'dev', 'Users', 'System'];

/**
 * Windows' own folders under a drive root, in every spelling a command reaches
 * them by (review 8, item 3): after `C:\`, `C:/`, `C:` (the POSIX reader drops
 * an unquoted `\`), Git Bash's `/c/` and WSL's `/mnt/c/`, in any case, and
 * `Program Files` by its 8.3 name (`PROGRA~1`).
 */
const WINDOWS_DIR =
  /^(?:[A-Za-z]:[\\/]?|\/(?:mnt\/)?[A-Za-z]\/)(?:Windows(?:[\\/]?(?:System32|SysWOW64))?|Users|Program Files(?: \(x86\))?|ProgramData|PROGRA~\d)(?:[\\/]\*?)?$/i;

/** The same folders, one path segment each, for a glob to be matched against. */
const WINDOWS_DIR_NAMES = ['windows', 'users', 'program files', 'program files (x86)', 'programdata'];

/**
 * Filesystem locations whose recursive deletion is effectively never
 * intended, and which kind each is. Covers POSIX roots and home, macOS's
 * `/Users`/`/System`, Git Bash / WSL drive-root spellings (`/c`, `/c/*`,
 * `/mnt/c`, `/mnt/c/*`), native Windows drive roots (`C:/`, `C:\`, `C:/*`) and
 * Windows' own folders under any of them — the same set applies whether the
 * command deleting them is `rm`, PowerShell's `Remove-Item`, `rd`/`del` or
 * `find`, so this is shared by every delete-assessing function below. A glob
 * that can name one of them counts as naming it (`/[a-z]*`, `/?*`, `/c/U*`).
 * So does any other spelling of the same path ({@link plainTarget}): `/usr/..`,
 * `C:\Windows\.`, `\\?\C:\Windows`, `\\host\c$\`, `FileSystem::C:\`,
 * `$WINDIR`, `~/..` (review of 3.3.0).
 */
/**
 * A leading `${VAR:?…}` / `${VAR:-…}` / `${VAR:=…}` / `${VAR?…}` / `${VAR=…}`
 * reduced to `${VAR}` (review of 3.6.0, finding 8): these yield the variable's
 * value, so `"${HOME:?}"` and `${HOME:-x}` name the home directory — a common
 * idiom that only warned. `:+`/`+` (the alternate, not the value) and `#`/`%`/
 * `/` (which change the value) are left as written, so they do not match.
 */
function normalizeParamModifier(t: string): string {
  const m = /^\$\{((?:env:)?[A-Za-z_]\w*)(?::?[-=?])[^{}]*\}/.exec(t);
  return m === null ? t : `\${${m[1] ?? ''}}${t.slice(m[0].length)}`;
}

function catastrophicKind(raw: string, tildeUsers = true): TargetKind | null {
  const stripped = normalizeParamModifier(stripQuotes(raw));
  return spelledKind(stripped, tildeUsers) ?? plainKind(raw, tildeUsers);
}

/** {@link catastrophicKind} of a target as written — the spellings it names outright. */
function spelledKind(t: string, tildeUsers: boolean): TargetKind | null {
  if (t === '/' || /^\/\*+$/.test(t)) return 'root'; // root, or everything under root
  // PowerShell's `\` and `\*` are the current drive's root; in bash the `\`
  // is an escape, so `rm -rf \*` arrives here as `*` and is not this.
  if (/^\\\*?$/.test(t)) return 'root';
  // Home, and everything under it — with either separator, since PowerShell
  // and Git Bash take both (review I2: `Remove-Item ~\* -Recurse -Force` and
  // `$HOME\*` only warned). PowerShell's `$HOME` is `$home` too.
  if (/^~(?:[\\/]\*?)?$/.test(t)) return 'home';
  // Another account's home: `~alice` is `/home/alice` (review 8, item 3). Not
  // from the PowerShell tool, which has no `~name` — and whose POSIX reading
  // turns `~\project\build` into `~projectbuild`.
  if (tildeUsers && /^~[A-Za-z_][\w.-]*(?:[\\/]\*?)?$/.test(t)) return 'home';
  if (/^\$\{?HOME\}?(?:[\\/]\*?)?$/i.test(t)) return 'home'; // $HOME, $HOME/, $HOME\*, ${HOME}, …
  // Git Bash sees the Windows environment: `$USERPROFILE`, `$HOMEDRIVE$HOMEPATH`.
  if (
    /^(?:\$\{?USERPROFILE\}?|\$\{?HOMEDRIVE\}?\$\{?HOMEPATH\}?|\$\{?env:HOMEDRIVE\}?\$\{?env:HOMEPATH\}?)(?:[\\/]\*?)?$/i.test(t)
  ) {
    return 'home';
  }
  // Git Bash / WSL drive-root spellings: /c, /c/, /c/*, /mnt/c, /mnt/c/*.
  if (/^\/[a-z](?:\/\*?)?$/i.test(t)) return 'root';
  if (/^\/mnt\/[a-z](?:\/\*?)?$/i.test(t)) return 'root';
  // Native Windows drive roots: C:/, C:\, C:/*, C:\*.
  if (/^[A-Za-z]:[\\/]\*?$/.test(t)) return 'root';
  // The same through cmd's and PowerShell's environment spellings — the home
  // directory, the system drive and the system directories — and those
  // directories named outright (fix round 2: `rmdir /s /q %USERPROFILE%`).
  if (/^(?:%(?:USERPROFILE|HOMEDRIVE%%HOMEPATH|HOMEPATH)%|\$\{?env:(?:USERPROFILE|HOMEPATH)\}?)(?:[\\/]\*?)?$/i.test(t)) {
    return 'home';
  }
  if (
    /^(?:%(?:HOMEDRIVE|SystemDrive|SystemRoot|windir|ProgramFiles|ProgramFiles\(x86\)|ProgramData|ALLUSERSPROFILE|PUBLIC)%|\$\{?env:(?:HOMEDRIVE|SystemDrive|SystemRoot|windir|ProgramFiles|ProgramData|ALLUSERSPROFILE|PUBLIC)\}?)(?:[\\/]\*?)?$/i.test(t)
  ) {
    return 'root';
  }
  if (WINDOWS_DIR.test(t)) return 'root';
  // Top-level system directories (exact, optionally trailing / or /*),
  // including macOS's capitalised ones.
  if (/^\/(?:etc|usr|bin|sbin|var|lib|lib64|boot|sys|proc|root|home|opt|dev|Users|System)(?:\/\*?)?$/.test(t)) {
    return 'root';
  }
  return globNamesCatastrophic(t) ? 'root' : null;
}

/** The longest target {@link plainTarget} reads: no catastrophic path is long, however it is spelled. */
const MAX_PLAIN_TARGET = 4096;

/**
 * Windows' own directories by the variable that names them, as bash (`$WINDIR`,
 * `${SYSTEMROOT}` — Git Bash sees the Windows environment), cmd (`%windir%`) and
 * PowerShell (`$env:windir`, `${env:ProgramFiles(x86)}`) spell it — each as the
 * path it names on a default installation, which is what is compared.
 */
const ROOT_VARIABLES: Readonly<Record<string, string>> = {
  windir: 'C:/Windows',
  systemroot: 'C:/Windows',
  programfiles: 'C:/Program Files',
  'programfiles(x86)': 'C:/Program Files (x86)',
  programw6432: 'C:/Program Files',
  programdata: 'C:/ProgramData',
  allusersprofile: 'C:/ProgramData',
  systemdrive: 'C:/',
  homedrive: 'C:/',
};

/** The variables that name the home directory, in the same spellings; `$HOMEDRIVE$HOMEPATH` is matched whole. */
const HOME_VARIABLES = new Set(['home', 'userprofile']);

/** A variable at the start of a target: `$X`, `${X}`, `$env:X`, `${env:X}`, `%X%` — its name, lower-cased, and the rest. */
function leadingVariable(t: string): { name: string; rest: string } | undefined {
  const m = /^(?:\$\{(?:env:)?([A-Za-z_][\w()]*)\}|\$(?:env:)?([A-Za-z_]\w*(?:\(x86\))?)|%([A-Za-z_][\w()]*)%)/i.exec(t);
  if (m === null) return undefined;
  const name = (m[1] ?? m[2] ?? m[3] ?? '').toLowerCase();
  return { name, rest: t.slice((m[0] ?? '').length) };
}

/**
 * A delete target with its spelling taken away (review of 3.3.0: each of these
 * only warned): quotes; PowerShell's provider prefix (`FileSystem::`,
 * `Microsoft.PowerShell.Core\FileSystem::`); a device prefix (`\\?\`, `\\.\`,
 * `\\?\UNC\`); an administrative share (`\\host\c$\…` is that host's `C:\…`,
 * whichever host — deleting another machine's system folder is no less
 * catastrophic); `\` read as `/`, doubled separators and `.` segments dropped,
 * `..` folded (never above the root); and on a Windows path a segment's
 * trailing dots and spaces, which Windows drops when it opens it. A leading
 * home variable (`~`, `$HOME`, `$USERPROFILE`, `%USERPROFILE%`,
 * `$env:USERPROFILE`, `$HOMEDRIVE$HOMEPATH`) is kept as `~` with how far the
 * rest climbs above it (`up`); one of Windows' own (`$WINDIR`, `%ProgramFiles%`,
 * …) is replaced by the path it names — unless `variables` is off. `undefined`
 * for a relative path (`C:` and `C:dir` are relative to drive C's current
 * directory), which names nothing this can judge.
 */
function plainTarget(raw: string, variables = true): { path: string; home: boolean; up: number } | undefined {
  let t = stripQuotes(raw.trim());
  if (t.length === 0 || t.length > MAX_PLAIN_TARGET) return undefined;
  t = t.replace(/^(?:Microsoft\.PowerShell\.Core\\)?FileSystem::/i, '');
  const unc = /^[\\/]{2}[?.][\\/]UNC[\\/]/i.exec(t);
  if (unc !== null) t = `//${t.slice(unc[0].length)}`;
  else t = t.replace(/^[\\/]{2}[?.][\\/](?=[A-Za-z]:)/, '');
  const share = /^[\\/]{2}[^\\/]+[\\/]([A-Za-z])\$(?=[\\/]|$)/.exec(t);
  if (share !== null) t = `${share[1] ?? ''}:/${t.slice(share[0].length)}`;
  let home = false;
  const homePair = /^(?:\$\{?(?:env:)?HOMEDRIVE\}?\$\{?(?:env:)?HOMEPATH\}?|%HOMEDRIVE%%HOMEPATH%)/i.exec(t);
  if (/^~(?=[\\/]|$)/.test(t)) home = true;
  else if (variables && homePair !== null) {
    home = true;
    t = `~${t.slice(homePair[0].length)}`;
  } else if (variables) {
    const v = leadingVariable(t);
    if (v !== undefined && HOME_VARIABLES.has(v.name)) {
      home = true;
      t = `~${v.rest}`;
    } else if (v !== undefined && ROOT_VARIABLES[v.name] !== undefined) t = `${ROOT_VARIABLES[v.name] ?? ''}${v.rest}`;
  }
  const drive = /^[A-Za-z]:/.exec(t)?.[0] ?? '';
  const body = t.slice(drive.length);
  if (!home && !/^[\\/]/.test(body)) return undefined;
  const windows = drive !== '' || /^[\\/](?:mnt[\\/])?[A-Za-z](?:[\\/]|$)/.test(body);
  const segments: string[] = [];
  let up = 0;
  for (const raw0 of (home ? body.slice(1) : body).split(/[\\/]+/)) {
    const seg = windows && raw0 !== '.' && raw0 !== '..' ? raw0.replace(/[. ]+$/, '') : raw0;
    if (seg === '' || seg === '.') continue;
    if (seg === '..') {
      if (segments.length > 0) segments.pop();
      else if (home) up += 1;
      continue;
    }
    segments.push(seg);
  }
  if (home) return { path: ['~', ...segments].join('/'), home, up };
  return { path: `${drive}/${segments.join('/')}`, home, up: 0 };
}

/**
 * {@link catastrophicKind} of a target's plain path ({@link plainTarget}): what
 * the spellings it names outright are judged as. A climb above the home
 * directory reaches the directory every home is in (`/home`, `C:\Users`), or
 * the root — a system directory either way; `~/../alice` is another account's
 * home.
 */
function plainKind(raw: string, tildeUsers: boolean): TargetKind | null {
  const plain = plainTarget(raw);
  if (plain === undefined) return null;
  if (plain.home) {
    const below = plain.path === '~' ? 0 : plain.path.split('/').length - 1;
    if (plain.up === 0) return below === 0 ? 'home' : null;
    return below < plain.up ? 'root' : below === plain.up ? 'home' : null;
  }
  return plain.path === stripQuotes(raw) ? null : spelledKind(plain.path, tildeUsers);
}

function isCatastrophicTarget(raw: string, tildeUsers = true): boolean {
  return catastrophicKind(raw, tildeUsers) !== null;
}

/** Whether glob segment `seg` can match one of `names`, case-insensitively. */
function segmentMatches(seg: string, names: readonly string[]): boolean {
  const pattern = seg.toLowerCase();
  return names.some((n) => wildcardMatch(pattern, n.toLowerCase()));
}

const DRIVE_LETTERS = Array.from({ length: 26 }, (_, k) => String.fromCharCode(97 + k));

/**
 * A glob that can name the filesystem root's own directories, a drive root or
 * a Windows folder under one (review 8, item 3): `/[a-z]*` and `/?*` name
 * `/bin` and `/etc`, `/c/U*` names `/c/Users`, `/mnt/?` a drive. A glob below
 * one of them (`/tmp/*`, `/usr/local/*`) names none. Only short paths are
 * read: no catastrophic target is long.
 */
function globNamesCatastrophic(t: string): boolean {
  if (t.length > 256 || !GLOB.test(t)) return false;
  const path = t.replace(/\\/g, '/').replace(/\/+(?:\*)?$/, '');
  const drive = /^([^/]*):(?:\/|$)/.exec(path);
  let segs: string[];
  if (drive !== null) {
    if (!segmentMatches(drive[1] ?? '', DRIVE_LETTERS)) return false;
    segs = path.slice((drive[0] ?? '').length).split('/').filter((s) => s !== '');
    return segs.length === 0 || (segs.length === 1 && segmentMatches(segs[0] ?? '', WINDOWS_DIR_NAMES));
  }
  if (!path.startsWith('/')) return false;
  segs = path.slice(1).split('/').filter((s) => s !== '');
  const [a = '', b = '', c = ''] = segs;
  if (segs.length === 1) return segmentMatches(a, SYSTEM_DIRS) || segmentMatches(a, DRIVE_LETTERS);
  const letter = (s: string): boolean => segmentMatches(s, DRIVE_LETTERS);
  if (segs.length === 2) return (letter(a) && segmentMatches(b, WINDOWS_DIR_NAMES)) || (segmentMatches(a, ['mnt']) && letter(b));
  return segs.length === 3 && segmentMatches(a, ['mnt']) && letter(b) && segmentMatches(c, WINDOWS_DIR_NAMES);
}

/** The home directory as {@link targetKey} spells it, and whether paths compare case-insensitively (Windows). */
interface HomeDir {
  key: string;
  fold: boolean;
}

/**
 * A delete target as a comparable path: quotes and a trailing `/`, `\`, `/*`
 * or `\*` gone, `\` read as `/`, and — where paths fold case (Windows) — Git
 * Bash's `/c/…` and WSL's `/mnt/c/…` read as `c:/…`, lower-cased. An absolute
 * path is read plain first ({@link plainTarget}, its variables as written):
 * `C:\Users\alice\.` and `\\?\C:\Users\alice` are `C:\Users\alice` (review of
 * 3.3.0).
 */
function targetKey(raw: string, fold: boolean): string {
  const plain = plainTarget(raw, false);
  const t = stripQuotes((plain !== undefined && !plain.home ? plain.path : raw).trim())
    .replace(/\\/g, '/')
    .replace(/\/{2,}/g, '/')
    .replace(/\/+\*?$/, '');
  return fold ? t.replace(/^(?:\/mnt)?\/([a-z])(?=\/|$)/i, '$1:').toLowerCase() : t;
}

/** `home` for {@link isHomeTarget}; none for an empty home or one that is a root. */
function homeDirFor(home: string | undefined, platform: string): HomeDir | undefined {
  if (home === undefined) return undefined;
  const fold = platform === 'win32';
  const key = targetKey(home, fold);
  return key === '' || /^[a-z]:$/i.test(key) ? undefined : { key, fold };
}

/**
 * The home directory named outright — `C:\Users\alice`, `/c/Users/alice/`,
 * `/home/alice/*` — compared with `os.homedir()`, case-insensitively on
 * Windows (review I2), where its 8.3 name counts too (`C:\Users\ADMINI~1`, what
 * `%TEMP%` is often spelled with — review of 3.4.0, finding 9). A path below it
 * is not the home directory.
 */
function isHomeTarget(raw: string, home: HomeDir | undefined): boolean {
  if (home === undefined) return false;
  const key = targetKey(raw, home.fold);
  if (key === home.key) return true;
  if (!home.fold) return false;
  const cut = key.lastIndexOf('/');
  const homeCut = home.key.lastIndexOf('/');
  if (cut < 0 || key.slice(0, cut) !== home.key.slice(0, homeCut)) return false;
  const short = /^([^~/]{1,6})~\d+$/.exec(key.slice(cut + 1));
  return short !== null && home.key.slice(homeCut + 1).replace(/[\s.]/g, '').startsWith(short[1] ?? '');
}

/**
 * What a delete's target is read against beyond its own spelling (review of
 * 3.4.0, finding 9: `rm -rf ..` from a child of the home directory, `cd / &&
 * rm -rf *`, `"$TEMP/../../.."` and `Get-ChildItem C:\ | Remove-Item -Recurse`
 * only warned — a relative target was never resolved).
 */
interface DeleteContext {
  /** The directory the command runs in, absolute and with `/` separators, when it is known. */
  dir?: string | undefined;
  /** The values of the variables a target may start with, by lower-cased name: `temp`, `tmp`, `tmpdir`, `localappdata`, `appdata`. */
  vars?: Readonly<Record<string, string>> | undefined;
  /** A bare drive (`C:`) is that drive's root — Git Bash's reading, not cmd's or PowerShell's (the drive's current directory). */
  bareDriveRoot?: boolean | undefined;
  /** What the pipe hands a PowerShell delete with no path of its own. */
  piped?: string | undefined;
  /** The listing that hands it over walked the whole tree (`gci ~ -Recurse`): the delete needs no `-Recurse` of its own. */
  pipedRecursive?: boolean | undefined;
}

/** `$PWD`, `${PWD}`, `$env:PWD`, `$(pwd)`, `` `pwd` `` at the start of a target. */
const PWD_PREFIX = /^(?:\$\(\s*pwd\s*\)|`\s*pwd\s*`|\$\{?PWD\}?|\$env:PWD)(?=[\\/]|$)/i;

/**
 * A delete target read against {@link DeleteContext}: a relative one joined
 * to the directory the command runs in, one led by `$PWD` (and its spellings)
 * or by `$TEMP`, `$TMP`, `$TMPDIR`, `$LOCALAPPDATA`, `$APPDATA` (in bash's,
 * cmd's and PowerShell's spellings) with that value in its place — left to
 * {@link catastrophicKind} and {@link isHomeTarget} to fold its `..`s. `undefined`
 * when there is nothing to read it against.
 */
function resolvedTarget(raw: string, ctx: DeleteContext): string | undefined {
  const t = normalizeParamModifier(stripQuotes(raw.trim()));
  if (t === '' || t.length > MAX_PLAIN_TARGET || t.includes('::')) return undefined;
  const pwd = PWD_PREFIX.exec(t);
  if (pwd !== null) return ctx.dir === undefined ? undefined : `${ctx.dir}${t.slice(pwd[0].length)}`;
  const v = leadingVariable(t);
  if (v !== undefined) {
    const value = ctx.vars?.[v.name];
    return value === undefined || value === '' ? undefined : `${value.replace(/\\/g, '/')}${v.rest.replace(/\\/g, '/')}`;
  }
  if (/^(?:[\\/~$%]|[A-Za-z]:)/.test(t) || ctx.dir === undefined) return undefined;
  return `${ctx.dir}/${t}`;
}

/** The targets a delete is judged on: each as written, and as {@link resolvedTarget} reads it. */
function judgedTargets(targets: readonly string[], ctx: DeleteContext): string[] {
  return targets.flatMap((t) => {
    const resolved = resolvedTarget(t, ctx);
    return resolved === undefined ? [t] : [t, resolved];
  });
}

/** Git Bash's bare drive: `C:`, `C:.`, `C:..` — the drive's root there. */
function isBareDrive(raw: string): boolean {
  return /^[A-Za-z]:\.{0,2}$/.test(stripQuotes(raw.trim()));
}

/** Remove-Item's path parameters and their abbreviations: `-Path`, `-LiteralPath`, `-LP`, `-PSPath`. */
const PS_PATH_PARAM = /^(?:pa(?:t|th)?|l(?:i(?:t(?:e(?:r(?:a(?:l(?:p(?:a(?:t(?:h)?)?)?)?)?)?)?)?)?)?|lp|pspath)$/;

/** `rm`/PowerShell's `Remove-Item` (and its `ri` alias) — dash-style flags. */
const DASH_DELETE_HEADS = new Set(['rm', 'ri', 'remove-item']);
/** cmd.exe-style delete commands, also reachable from PowerShell — slash flags. */
const SLASH_DELETE_HEADS = new Set(['rd', 'rmdir', 'del', 'erase']);

/** GNU `rm`'s long options, which getopt_long also takes by any prefix that names one of them alone. */
const RM_LONG_OPTIONS = ['force', 'interactive', 'one-file-system', 'no-preserve-root', 'preserve-root', 'recursive', 'dir', 'verbose', 'help', 'version'];

/**
 * The GNU `rm` long option a `--` word names (review of 3.6.0, finding 1):
 * itself, or the one option it is an unambiguous prefix of — `--rec` and
 * `--r` are `--recursive`, `--no-p` is `--no-preserve-root` — read without
 * its `=value` and case. `undefined` for none, or an ambiguous prefix
 * (`--v`: `--verbose` or `--version`).
 */
function rmLongOption(token: string): string | undefined {
  const name = (token.slice(2).split('=')[0] ?? '').toLowerCase();
  if (name === '') return undefined;
  if (RM_LONG_OPTIONS.includes(name)) return name;
  const named = RM_LONG_OPTIONS.filter((o) => o.startsWith(name));
  return named.length === 1 ? named[0] : undefined;
}

/**
 * A cluster of `rm`'s short options — GNU's `-d -f -i -I -r -R -v` and BSD's
 * `-P -W -x` — of any length: `-rfvd` is four flags, recursive among them.
 * A PowerShell parameter name (`-Force`, `-Recurse`) has a letter no `rm`
 * takes, so it is never read as one.
 */
const RM_SHORT_CLUSTER = /^[dfiIPrRvWx]+$/;

/**
 * Tokenised assessment of one simple command. The *target* — not just the
 * flags — decides severity: `rm -rf /` is catastrophic, `rm -rf node_modules`
 * is merely risky. Covers both `rm`/`Remove-Item`/`ri` (dash flags: GNU-style
 * clusters like `-rf`/`-fo`, `--recursive`/`--force`, and PowerShell's
 * whole-word `-Recurse`/`-Force`) and `rd`/`rmdir`/`del`/`erase` (cmd.exe-
 * style slash flags: `/s` recurse, `/q` quiet-force — and, being Remove-Item
 * aliases in PowerShell, its dash flags too).
 */
function assessRecursiveDelete(words: ShellWord[], start: number, home?: HomeDir, tildeUsers = true, ctx: DeleteContext = {}): MatchedRule | null {
  const head = words[start];
  if (head === undefined) return null;
  const name = basename(head.value).toLowerCase();
  const dashStyle = DASH_DELETE_HEADS.has(name);
  const slashStyle = !dashStyle && SLASH_DELETE_HEADS.has(name);
  if (!dashStyle && !slashStyle) return null;

  let recursive = false;
  let noPreserve = false;
  const targets: string[] = [];

  const rest = words.slice(start + 1);
  for (let k = 0; k < rest.length; k += 1) {
    // PowerShell takes an en or em dash for a parameter's `-` (fix round 4).
    const token = (rest[k]?.value ?? '').replace(/^[\u2013\u2014\u2015]/, '-');
    // `/q` (quiet) asks nothing \u2014 but neither does a tool with no terminal, so
    // `/s` alone decides. Git Bash's `//s` reaches cmd as `/s` (review 8, item 2),
    // and `/s/q` is `/s` and `/q` (review of 3.6.0, finding 3).
    if (slashStyle && token.startsWith('/')) {
      if (cmdSwitches(token)?.includes('s') === true) recursive = true;
      continue;
    }
    // Dash flags: `rm`'s and `Remove-Item`'s — and, since `rd`, `rmdir`, `del`
    // and `erase` are Remove-Item aliases in PowerShell, theirs too:
    // `rmdir C:\Users -Recurse -Force` was ok (fix round 4).
    // GNU getopt takes a long option by any prefix that names it alone, so
    // `--rec` recurses as `--recursive` does (review of 3.6.0, finding 1).
    if (token.startsWith('--')) {
      const option = rmLongOption(token);
      if (option === 'no-preserve-root') noPreserve = true;
      else if (option === 'recursive') recursive = true;
      continue;
    }
    if (token.startsWith('-') && token.length > 1) {
      // A PowerShell parameter may be given its value after a colon, split at
      // the FIRST colon only (`-Path:C:\Users` is `C:\Users` — fix round 6).
      const colon = token.indexOf(':');
      const flags = colon < 0 ? token.slice(1) : token.slice(1, colon);
      let value = colon < 0 ? undefined : token.slice(colon + 1);
      const lower = flags.toLowerCase();
      // PowerShell binds a parameter by any prefix that names it alone: of
      // Remove-Item's, only `-Recurse` begins with `r` (`-Recu`, `-Recur` —
      // review of 3.6.0, finding 2), and `-fo` is the shortest `-Force`
      // (`-f` is `-Filter` too).
      const recurseParam = lower !== '' && 'recurse'.startsWith(lower);
      const isSwitch = recurseParam || (lower.length >= 2 && 'force'.startsWith(lower));
      // A switch's value may also be the next word (`-Recurse: $false`); any
      // other parameter's next word stays where it is — `-Path: C:\Users`
      // names the target (fix round 6).
      if (value === '' && isSwitch) {
        value = rest[k + 1]?.value ?? '';
        k += 1;
      }
      if (value !== undefined && value !== '' && PS_PATH_PARAM.test(lower)) targets.push(value);
      // `-Recurse:$true` is on, `-Recurse:$false` off.
      const on = value === undefined || !/^\$?(?:false|0)$/i.test(value);
      // PowerShell's whole-word parameter names first — `-Recurse` and its
      // abbreviations. Checked before the cluster readings below because
      // those (does the flag text contain the letter r?) are right for a
      // *cluster* of single-letter flags like `-rf`, where every character
      // really is its own flag, and wrong for a whole parameter name.
      // `-Force` / `-fo` decide nothing any more (review 8, item 1); they are
      // read only so that their value is not taken for a target. A cluster of
      // `rm`'s own letters recurses at any length (`-rfvd` was ok: only three
      // letters were read — finding 1); a short word with an `r` still does,
      // as before.
      if (recurseParam) recursive ||= on;
      else if (!isSwitch && value === undefined && /r/i.test(flags) && (RM_SHORT_CLUSTER.test(flags) || flags.length <= 3)) recursive = true;
    } else targets.push(token);
  }

  // Recursion decides, not force (review 8, item 1): the Bash and PowerShell
  // tools have no terminal to ask on, so `rm -r ~` and `Remove-Item ~ -Recurse`
  // delete as much as their forced forms — measured: both removed a whole tree.
  // A delete handed every item of a recursive listing (`gci ~ -Recurse -File |
  // ri -Force`) deletes the tree item by item, with no `-Recurse` of its own
  // (review of 3.6.0, finding 10).
  const fromPipe = targets.length === 0 && ctx.piped !== undefined;
  if (!(recursive || noPreserve || (fromPipe && ctx.pipedRecursive === true))) return null;

  // A PowerShell delete with no path of its own deletes what the pipe hands it.
  if (fromPipe && ctx.piped !== undefined) targets.push(ctx.piped);
  if (
    noPreserve ||
    (ctx.bareDriveRoot === true && targets.some(isBareDrive)) ||
    judgedTargets(targets, ctx).some((t) => isCatastrophicTarget(t, tildeUsers) || isHomeTarget(t, home))
  ) {
    return { ...RULE_RM_ROOT };
  }
  return { ...RULE_RM_BROAD };
}

/** PowerShell's listing cmdlets and their aliases: what they write down a pipe is items a `Remove-Item` after them deletes. */
const LISTERS = new Set(['get-childitem', 'gci', 'ls', 'dir', 'get-item', 'gi']);

/** `Get-ChildItem`'s parameters that narrow what it lists, and those that take a value. */
const LIST_NARROWING = /^-(?:fi(?:l(?:t(?:er?)?)?)?|inc(?:l(?:u(?:de?)?)?)?|ex(?:c(?:l(?:u(?:de?)?)?)?)?|at(?:t(?:r(?:i(?:b(?:u(?:t(?:es?)?)?)?)?)?)?)?|name)$/i;
const LIST_VALUED = /^-(?:de(?:p(?:th?)?)?|fi(?:l(?:t(?:er?)?)?)?|inc(?:l(?:u(?:de?)?)?)?|ex(?:c(?:l(?:u(?:de?)?)?)?)?|at(?:t(?:r(?:i(?:b(?:u(?:t(?:es?)?)?)?)?)?)?)?)$/i;

/**
 * What a PowerShell listing hands a delete down the pipe (review of 3.4.0,
 * finding 9: `Get-ChildItem C:\ | Remove-Item -Recurse` only warned): the
 * children of the path `Get-ChildItem` / `gci` / `ls` / `dir` lists (`-Path`,
 * `-LiteralPath` or its first operand; `.` without one), the item `Get-Item`
 * names. Nothing when a filter narrows the listing (`-Filter`, `-Include`,
 * `-Exclude`, `-Attributes`, `-Name`): what it lists is then not all of it.
 */
function pipedItems(words: readonly ShellWord[]): string | undefined {
  const at = resolveCommand(words).index;
  const name = commandName(words[at]?.value ?? '');
  if (!LISTERS.has(name)) return undefined;
  const args = withoutRedirections(words.slice(at + 1));
  if (args.some((a) => LIST_NARROWING.test(a.split(':')[0] ?? a))) return undefined;
  let path = psParam(args, ['path', 'literalpath', 'lp', 'pspath']);
  for (let i = 0; path === undefined && i < args.length; i += 1) {
    const a = args[i] ?? '';
    if (a.startsWith('-')) i += LIST_VALUED.test(a) ? 1 : 0;
    else path = a;
  }
  if (name === 'get-item' || name === 'gi') return path ?? '.';
  return `${(path ?? '.').replace(/[\\/]+$/, '')}/*`;
}

/**
 * Whether a `Get-ChildItem` (`gci`, `ls`, `dir`) walks the whole tree: `-Recurse`
 * by any prefix PowerShell binds to it alone (`-rec` on — `-r` and `-re` are
 * `-ReadOnly` too), not `:$false`, or a `-Depth`. What it lists is then every
 * item below its path, and a delete it pipes them to deletes them all.
 */
function listsRecursively(words: readonly ShellWord[]): boolean {
  const at = resolveCommand(words).index;
  const name = commandName(words[at]?.value ?? '');
  if (!LISTERS.has(name) || name === 'get-item' || name === 'gi') return false;
  return withoutRedirections(words.slice(at + 1)).some((a) => {
    const m = /^-([A-Za-z]+)(?::(.*))?$/.exec(a);
    if (m === null) return false;
    const p = (m[1] ?? '').toLowerCase();
    const off = m[2] !== undefined && /^\$?(?:false|0)$/i.test(m[2]);
    return !off && ((p.length >= 3 && 'recurse'.startsWith(p)) || (p.length >= 2 && 'depth'.startsWith(p)));
  });
}

const RULE_RM_ROOT: MatchedRule = {
  id: 'rm-rf-root',
  level: 'block',
  reason: 'Recursive delete of the filesystem root, a drive root, a system directory or a home directory',
};

const RULE_RM_BROAD: MatchedRule = {
  id: 'rm-rf-broad',
  level: 'warn',
  reason: 'Recursive delete — confirm the target path is intended',
};

/** `find`'s tests that narrow what it finds — with one, `find ~ … -delete` is a cleanup, not a wipe. */
const FIND_FILTERS = new Set([
  '-name', '-iname', '-path', '-ipath', '-wholename', '-iwholename', '-regex', '-iregex', '-lname', '-ilname',
  '-newer', '-anewer', '-cnewer', '-newerxy', '-mtime', '-mmin', '-atime', '-amin', '-ctime', '-cmin', '-used',
  '-size', '-empty', '-perm', '-user', '-group', '-uid', '-gid', '-nouser', '-nogroup', '-inum', '-samefile',
  '-links', '-readable', '-writable', '-executable', '-context',
]);

/** What `find -exec` / `-execdir` / `-ok` runs to delete what it found. */
const FIND_DELETERS = new Set(['rm', 'unlink', 'rmdir', 'shred', 'remove-item', 'ri', 'del', 'erase', 'rd']);

const RULE_FIND_ROOT: MatchedRule = {
  id: 'find-delete-root',
  level: 'block',
  reason: 'find … -delete (or -exec rm) on the filesystem root, a drive root, a system directory or a home directory deletes everything under it',
};
const RULE_FIND_HOME: MatchedRule = {
  id: 'find-delete-home',
  level: 'warn',
  reason: 'find … -delete targets the home directory — confirm this is intended',
};
const RULE_FIND_BROAD: MatchedRule = {
  id: 'find-delete-broad',
  level: 'warn',
  reason: 'find . -delete with no test to narrow it deletes everything under the working directory — confirm this is intended',
};

/**
 * `find … -delete` — like `rm`/`Remove-Item`, the *target* decides severity
 * (review 8, item 7): the filesystem root, a drive root or a system directory
 * blocks; the home directory blocks when no test narrows what is found
 * (`find ~ -delete`) and warns when one does (`find ~ -name '*.pyc' -delete`);
 * the working directory with nothing to narrow it warns, as `rm -rf .` does;
 * anything else (`find ./tmp -delete`) stays 'ok'. A delete is `-delete` or an
 * `-exec` / `-execdir` / `-ok` of `rm` and the like — whose own targets are
 * judged as any delete's (`-exec rm -rf / \;`). The start paths come after
 * `find`'s own options (`-H`, `-L`, `-P`, `-O3`, `-D tree`) and end at the
 * first test; a value after a test (`-path /`) is not a start path. With none,
 * GNU find starts at `.`.
 */
function assessFind(words: ShellWord[], start: number, home?: HomeDir, tildeUsers = true, ctx: DeleteContext = {}): MatchedRule | null {
  const head = words[start];
  if (head === undefined || basename(head.value) !== 'find') return null;

  const rest = words.slice(start + 1);
  const execs = findExecCommands(words, start);
  const viaExec = execs.some((cmd) => FIND_DELETERS.has(commandName(cmd[resolveCommand(cmd).index]?.value ?? '')));
  // A delete inside an `-exec` is judged on its own targets too.
  const inner = execs.map((cmd) => assessRecursiveDelete(cmd, resolveCommand(cmd).index, home, tildeUsers, { ...ctx, piped: undefined })).find((r) => r?.level === 'block');
  if (inner !== undefined && inner !== null) return inner;
  if (!viaExec && !rest.some((w) => w.value === '-delete')) return null;

  let k = 0;
  while (k < rest.length) {
    const v = rest[k]?.value ?? '';
    if (/^-(?:[HLP]|O\d*)$/.test(v)) k += 1;
    else if (v === '-D') k += 2;
    else break;
  }
  const targets: string[] = [];
  for (; k < rest.length; k += 1) {
    const v = rest[k]?.value ?? '';
    if (v.startsWith('-') || v === '(' || v === '!' || v === ')' || v === ',') break; // the first test ends the paths
    targets.push(stripQuotes(v));
  }
  if (targets.length === 0) targets.push('.');
  const filtered = rest.some((w) => FIND_FILTERS.has(w.value));
  // A relative start path is where the command runs (review of 3.4.0, finding 9: `cd / && find . -delete`).
  const judged = judgedTargets(targets, ctx);

  if (judged.some((t) => catastrophicKind(t, tildeUsers) === 'root')) return { ...RULE_FIND_ROOT };
  if (judged.some((t) => catastrophicKind(t, tildeUsers) === 'home' || isHomeTarget(t, home))) {
    return filtered ? { ...RULE_FIND_HOME } : { ...RULE_FIND_ROOT };
  }
  if (!filtered && targets.some((t) => /^\.[\\/]?$/.test(t))) return { ...RULE_FIND_BROAD };
  return null;
}

/**
 * `find … | xargs rm` (review of 3.6.0, finding 10): xargs hands the deleter
 * every path find lists, exactly as `find … -exec rm` does, so the pipeline is
 * judged as that — by find's start paths and its tests ({@link assessFind}).
 * The deleter needs no recursive flag of its own: find already walked the
 * tree (`find ~ -type f | xargs rm -f` was ok while `-exec rm` blocked).
 * Member `c` is xargs running a deleter; the nearest `find` before it lists.
 */
function findPipedIntoDeleter(commands: readonly ShellWord[][], c: number, home: HomeDir | undefined, tildeUsers: boolean, ctx: DeleteContext): MatchedRule | null {
  const words = commands[c];
  if (words === undefined || c === 0) return null;
  const at = resolveCommand(words).index;
  if (!words.slice(0, at).some((w) => commandName(w.value) === 'xargs')) return null;
  if (!FIND_DELETERS.has(commandName(words[at]?.value ?? ''))) return null;
  for (let p = c - 1; p >= 0; p -= 1) {
    const prev = commands[p] ?? [];
    const f = resolveCommand(prev).index;
    if (commandName(prev[f]?.value ?? '') === 'find') {
      return assessFind([...prev, { value: '-delete', quoted: false }], f, home, tildeUsers, { ...ctx, piped: undefined, pipedRecursive: undefined });
    }
  }
  return null;
}

/**
 * The guardrail hooks' own configuration files: a project's
 * `.guardian/hooks.config.json` / `.guardian/hooks-allowlist.json` and the
 * user-level `~/.config/dev-guardian/hooks.json` — matched by their last path
 * segments with the separators optional, because the POSIX-style tokenizer
 * reads an UNQUOTED `\` as an escape and drops it
 * (`C:\proj\.guardian\hooks.config.json` arrives as
 * `C:proj.guardianhooks.config.json`). A quoted `\` is normalised to `/`.
 */
const HOOK_CONFIG_PATH = /(?:\.guardian\/?hooks[^/]*\.json|\.config\/?dev-guardian\/?hooks\.json)$/i;

function isHookConfigPath(arg: string): boolean {
  return HOOK_CONFIG_PATH.test(arg.replace(/\\/g, '/'));
}

/**
 * The directories that hold those files: a project's `.guardian` and the
 * user-level `~/.config/dev-guardian`. A LINK created at one of them redirects
 * every config file below it at once — to `\\host\share`, whose open can hold
 * the hook past its timeout, or to a directory the model wrote. Matched on the
 * path's end, separators optional for the same reason as `HOOK_CONFIG_PATH`.
 */
const HOOK_CONFIG_DIR = /(?:\.guardian|\.config\/?dev-guardian)\/?$/i;

function isHookConfigDir(arg: string): boolean {
  return HOOK_CONFIG_DIR.test(arg.replace(/\\/g, '/'));
}

/**
 * The user-level configuration directory alone. Removing IT is refused;
 * removing a project's whole `.guardian` is not — that directory also holds the
 * scan database, deleting it is how a project resets dev-guardian's state, and
 * the project configuration it takes along could only have made the guard
 * stricter.
 */
const USER_CONFIG_DIR = /\.config\/?dev-guardian\/?$/i;

/** Claude Code's own settings, project or user level; separators optional as in `HOOK_CONFIG_PATH`. */
const CLAUDE_SETTINGS_PATH = /\.claude\/?settings(?:\.local)?\.json$/i;

/**
 * Claude Code's managed settings — `ClaudeCode/managed-settings.json` under Program Files, ProgramData or
 * `/Library/Application Support`, `/etc/claude-code/managed-settings.json` — which win over every other
 * settings file (review 12, finding 7). Always this machine's: never "elsewhere".
 */
const MANAGED_SETTINGS_PATH = /(?:ClaudeCode|claude-code)\/?managed-settings\.json$/i;

/** The same files through Claude Code's `CLAUDE_CONFIG_DIR`, spelled as a variable (bash, cmd, PowerShell). */
const CONFIG_DIR_VARIABLE_SETTINGS = /(?:\$\{?(?:env:)?CLAUDE_CONFIG_DIR\}?|%CLAUDE_CONFIG_DIR%)\/?settings(?:\.local)?\.json$/i;

/**
 * Whether a path names Claude Code's settings (review round 2, ruling 3): under
 * `.claude`, through the `CLAUDE_CONFIG_DIR` variable, or — when that is set
 * (`scope.configDirName`, its last segment) — directly under a directory of that
 * name, separators optional as in `HOOK_CONFIG_PATH` (`~/.claude-conta2/settings.json`).
 */
function isSettingsPath(path: string, configDirName: string | undefined): boolean {
  if (CLAUDE_SETTINGS_PATH.test(path) || CONFIG_DIR_VARIABLE_SETTINGS.test(path) || MANAGED_SETTINGS_PATH.test(path)) return true;
  if (configDirName === undefined) return false;
  const lower = path.toLowerCase();
  for (const file of ['settings.json', 'settings.local.json']) {
    if (lower.endsWith(`${configDirName}/${file}`) || lower.endsWith(`${configDirName}${file}`)) return true;
  }
  return false;
}

/**
 * dev-guardian's data directory as a command spells its default locations and
 * its variable (review 3.0 wave 2, round 2): `%LOCALAPPDATA%` / `$env:LOCALAPPDATA`
 * / `…/AppData/Local`, `$XDG_DATA_HOME`, `~/.local/share` — each followed by
 * `dev-guardian` — and `$GUARDIAN_DATA_DIR` / `%GUARDIAN_DATA_DIR%`. Matched
 * at the end of a normalised path.
 */
const DATA_DIR_SPELLED =
  /(?:(?:\$\{?(?:env:)?(?:localappdata|xdg_data_home)\}?|%(?:localappdata|xdg_data_home)%|appdata\/local|\.local\/share)\/dev-guardian|\$\{?(?:env:)?guardian_data_dir\}?|%guardian_data_dir%)$/;

/** Whether `path` names dev-guardian's data directory: its actual path (`dataDir`, normalised) or a spelling of it. */
function isDataDirPath(path: string, dataDir: string | undefined): boolean {
  const p = normalizedPath(path);
  return (dataDir !== undefined && p === dataDir) || DATA_DIR_SPELLED.test(p);
}

/**
 * Whether `path` is dev-guardian's registry of trusted databases,
 * `<data dir>/registry`, or a path below it — the data directory as it
 * actually is (`dataDir`, normalised) or as {@link DATA_DIR_SPELLED} spells it.
 * A `registry` of any other directory (a project's, npm's) is not it.
 */
function isRegistryPath(path: string, dataDir: string | undefined): boolean {
  const p = normalizedPath(path);
  for (let at = p.indexOf('/registry'); at >= 0; at = p.indexOf('/registry', at + 1)) {
    const next = p.charAt(at + '/registry'.length);
    if (next !== '' && next !== '/') continue;
    const parent = p.slice(0, at);
    if ((dataDir !== undefined && parent === dataDir) || DATA_DIR_SPELLED.test(parent)) return true;
  }
  return false;
}

/** The last segment of `CLAUDE_CONFIG_DIR`, lower-cased, as {@link isSettingsPath} matches it; none when unset. */
function configDirNameOf(dir: string | undefined): string | undefined {
  const last = (dir ?? '').trim().replace(/[\\/]+$/, '').split(/[\\/]/).pop() ?? '';
  return last === '' ? undefined : last.toLowerCase();
}

/**
 * A key of Claude Code's settings that switches dev-guardian's hooks off:
 * `disableAllHooks`, the dispatcher's own environment switches, and
 * `enabledPlugins` when the same text names dev-guardian. The Write/Edit guard
 * (`settingsGuard.ts`) judges an edit of the settings by the value it sets; the
 * content a shell command writes cannot be read reliably, so here the key alone
 * decides, anywhere in the command's text — `NODE_OPTIONS` and
 * `GUARDIAN_PKG_VET_DEADLINE_MS` among them (review of 3.4.0, finding 4).
 */
function namesLooseningKey(text: string): boolean {
  return (
    /\bdisableAllHooks\b|\bGUARDIAN_HOOKS(?:_BASH_BLOCK)?\b|\bGUARDIAN_PKG_VET(?:_DEADLINE_MS)?\b|\bNODE_OPTIONS\b/i.test(text) ||
    (/enabledPlugins/i.test(text) && /dev-guardian/i.test(text))
  );
}

/**
 * Whether the whole command names a loosening key — computed once per
 * assessment (fix round 3), and only for a command that writes the settings.
 * Also through an escape (`disableAllHook\x73`, `s`, `\163`) and inside
 * a base64 literal the command decodes (`echo eyJ… | base64 -d >
 * .claude/settings.local.json`) — review 8, item 15.
 */
function loosens(scope: Scope): boolean {
  if (scope.notes.loosens === undefined) {
    const raw = scope.raw;
    scope.notes.loosens =
      namesLooseningKey(raw) ||
      (raw.includes('\\') && namesLooseningKey(unescapeText(raw))) ||
      base64Literals(raw).some((text) => namesLooseningKey(text) || namesLooseningKey(unescapeText(text)));
  }
  return scope.notes.loosens;
}

/** `\xHH`, `\u{H…}`, `\uHHHH` and octal `\NNN` escapes — printf's, `$'…'`'s, JSON's, JavaScript's — read as what they spell. */
function unescapeText(text: string): string {
  return text.replace(/\\(?:x([0-9A-Fa-f]{2})|u\{([0-9A-Fa-f]{1,6})\}|u([0-9A-Fa-f]{4})|([0-7]{1,3}))/g, (all, x?: string, u1?: string, u2?: string, o?: string) => {
    const code = x !== undefined ? parseInt(x, 16) : u1 !== undefined ? parseInt(u1, 16) : u2 !== undefined ? parseInt(u2, 16) : parseInt(o ?? '', 8);
    return Number.isFinite(code) && code <= 0x10ffff ? String.fromCodePoint(code) : all;
  });
}

/** The most base64 literals of one command decoded to look for a settings key. */
const MAX_BASE64_LITERALS = 64;

/** The text of each base64 literal in `text` (16+ characters) that decodes to UTF-8 text. */
function base64Literals(text: string): string[] {
  const out: string[] = [];
  let tried = 0;
  for (const m of text.matchAll(/[A-Za-z0-9+/]{16,}={0,2}/g)) {
    if ((tried += 1) > MAX_BASE64_LITERALS) break;
    const decoded = decodeBase64(m[0]);
    if (decoded !== undefined && !decoded.includes('�')) out.push(decoded);
  }
  return out;
}

// ── globs and braces (where a command moves between directories: `shell/paths.ts`)

const GLOB = /[*?[]/;

/** The user-level configuration file's path, segment by segment from its end. */
const USER_CONFIG_TAIL: readonly string[] = ['.config', 'dev-guardian', 'hooks.json'];
/** Every configuration file's path, segment by segment from its end, for a glob to be matched against. */
const CONFIG_TAILS: ReadonlyArray<readonly string[]> = [
  ['.guardian', 'hooks.config.json'],
  ['.guardian', 'hooks-allowlist.json'],
  USER_CONFIG_TAIL,
];

/**
 * True when a glob in `path` can name a configuration file (of `tails`): in
 * its last segment (`.guardian/hooks*`), or in a directory above it (review
 * 8, item 6: `> ~/.config/dev-guardia?/hooks.json` overwrote the file — bash
 * expands a redirection's target too).
 */
function globNamesConfig(path: string, tails: ReadonlyArray<readonly string[]> = CONFIG_TAILS): boolean {
  const t = tail(path);
  if (!GLOB.test(t)) return false;
  const segs = t.split('/').filter((s) => s !== '');
  return tails.some(
    (names) =>
      names.length <= segs.length &&
      names.every((name, k) => wildcardMatch((segs[segs.length - names.length + k] ?? '').toLowerCase(), name)),
  );
}

/** The most words one word's brace expansion may become; past it the word is read as written. */
const MAX_BRACE_WORDS = 64;
/** The longest word whose braces are expanded. */
const MAX_BRACE_WORD = 1024;

/**
 * Where `word`'s first expandable brace is (bash's brace expansion): a `{`
 * not after `$`, its matching `}`, and between them a top-level `,` or a
 * sequence (`1..3`, `a..e`). `{}`, `{x}` and `${…}` are not expansions.
 */
function braceAt(word: string): { pre: string; alts: string[]; post: string } | undefined | 'too-many' {
  for (let i = word.indexOf('{'); i >= 0; i = word.indexOf('{', i + 1)) {
    if (word.charAt(i - 1) === '$') continue;
    let depth = 0;
    const commas: number[] = [];
    let close = -1;
    for (let j = i + 1; j < word.length; j += 1) {
      const c = word.charAt(j);
      if (c === '{') depth += 1;
      else if (c === '}') {
        if (depth === 0) {
          close = j;
          break;
        }
        depth -= 1;
      } else if (c === ',' && depth === 0) commas.push(j);
    }
    if (close < 0) return undefined;
    const pre = word.slice(0, i);
    const post = word.slice(close + 1);
    if (commas.length > 0) {
      const alts: string[] = [];
      let from = i + 1;
      for (const c of [...commas, close]) {
        alts.push(word.slice(from, c));
        from = c + 1;
      }
      return { pre, alts, post };
    }
    const seq = /^(-?\d{1,6}|[A-Za-z])\.\.(-?\d{1,6}|[A-Za-z])$/.exec(word.slice(i + 1, close));
    if (seq !== null) {
      const [a = '', b = ''] = [seq[1], seq[2]];
      const numeric = /\d/.test(a) && /\d/.test(b);
      if (!numeric && (/\d/.test(a) || /\d/.test(b))) continue;
      const lo = numeric ? Number(a) : a.charCodeAt(0);
      const hi = numeric ? Number(b) : b.charCodeAt(0);
      if (Math.abs(hi - lo) + 1 > MAX_BRACE_WORDS) return 'too-many';
      const step = lo <= hi ? 1 : -1;
      const alts: string[] = [];
      for (let v = lo; ; v += step) {
        alts.push(numeric ? String(v) : String.fromCharCode(v));
        if (v === hi) break;
      }
      return { pre, alts, post };
    }
  }
  return undefined;
}

/**
 * Bash's brace expansion of one word (review 8, item 6): `{rm,-rf,/}` is
 * `rm -rf /`, `{rm,} -rf /` is `rm -rf /`, `/{bin,etc}` is `/bin /etc`,
 * `x{1..3}` is `x1 x2 x3`, nested braces included. An empty result is dropped,
 * as bash drops it. `undefined` when nothing expands, or when the word would
 * become more than {@link MAX_BRACE_WORDS} words — then it is read as written.
 */
function expandBraces(word: string): string[] | undefined {
  if (word.length > MAX_BRACE_WORD || !word.includes('{') || !word.includes('}')) return undefined;
  const out: string[] = [];
  const stack = [word];
  let expanded = false;
  for (let steps = 0; stack.length > 0; steps += 1) {
    if (steps > 8 * MAX_BRACE_WORDS) return undefined;
    const w = stack.pop() ?? '';
    const at = braceAt(w);
    if (at === 'too-many') return undefined;
    if (at === undefined) {
      if (w !== '') out.push(w);
      if (out.length > MAX_BRACE_WORDS) return undefined;
      continue;
    }
    expanded = true;
    for (let k = at.alts.length - 1; k >= 0; k -= 1) stack.push(`${at.pre}${at.alts[k] ?? ''}${at.post}`);
    if (stack.length > 8 * MAX_BRACE_WORDS) return undefined;
  }
  return expanded ? out : undefined;
}

/** A command's words with every unquoted brace expanded ({@link expandBraces}); the same array when none is. */
function expandWords(words: ShellWord[]): ShellWord[] {
  if (!words.some((w) => !w.quoted && w.value.includes('{'))) return words;
  let out: ShellWord[] | undefined;
  for (const [k, w] of words.entries()) {
    const expanded = w.quoted || w.redirectAt !== undefined ? undefined : expandBraces(w.value);
    if (expanded === undefined) {
      out?.push(w);
      continue;
    }
    out ??= words.slice(0, k);
    for (const value of expanded) out.push({ value, quoted: false });
  }
  return out ?? words;
}

/**
 * True when program text names a hook configuration path: a string literal
 * that ENDS in one (`'.guardian/hooks.config.json'`, `r'C:\…\.config\
 * dev-guardian\hooks.json'`, `">…/hooks.json"`) or in the user-level directory,
 * or one assembled from parts (`join(home, '.config', 'dev-guardian',
 * 'hooks.json')`). A sentence that merely mentions a path does not end in it.
 */
function literalsNameHookConfig(literals: readonly string[], scope: Scope): Placement {
  const paths = literalPaths(literals);
  // A literal spelled in full is placed like a shell write's target; one
  // assembled from parts is not known, so this session's (review 8, item 14).
  const named = locate(paths, (p) => HOOK_CONFIG_PATH.test(p) || USER_CONFIG_DIR.test(p), scope);
  if (named === 'inside') return named;
  const has = (re: RegExp): boolean => paths.some((p) => re.test(p));
  if (has(/(?:^|\/)dev-guardian\/?$/i) && has(/(?:^|\/)hooks\.json$/i)) return 'inside';
  if (has(/(?:^|\/)\.guardian\/?$/i) && has(/(?:^|\/)hooks[.-][^/]*\.json$/i)) return 'inside';
  return named;
}

/** The same for Claude Code's settings files. */
function literalsNameClaudeSettings(literals: readonly string[], scope: Scope): Placement {
  const configDirName = scope.configDirName;
  const paths = literalPaths(literals);
  const named = locate(paths, (p) => isSettingsPath(p, configDirName), scope);
  if (named === 'inside') return named;
  const has = (re: RegExp): boolean => paths.some((p) => re.test(p));
  const inDir =
    has(/(?:^|\/)\.claude\/?$/i) ||
    (configDirName !== undefined && paths.some((p) => p.toLowerCase().replace(/\/+$/, '').endsWith(configDirName)));
  return inDir && has(/^settings(?:\.local)?\.json$/i) ? 'inside' : named;
}

// ── .NET file calls in PowerShell

/**
 * Whether an index of `text` lies outside every quoted span (POSIX quoting),
 * for indices asked in increasing order: the scan resumes where the last one
 * stopped, so a text with many calls is still read once.
 */
function quoteTracker(text: string): (index: number) => boolean {
  let quote = '';
  let i = 0;
  return (index: number): boolean => {
    for (; i < index; i += 1) {
      const ch = text.charAt(i);
      if (quote === '') {
        if (ch === '\\') i += 1;
        else if (ch === "'" || ch === '"') quote = ch;
      } else if (quote === '"' && ch === '\\') i += 1;
      else if (ch === quote) quote = '';
    }
    return quote === '';
  };
}

/**
 * How far past its `(` a call's arguments are read — a path, not a file's
 * content. This is what keeps `dotNetEffects` linear, so every call is judged
 * (a cap of 256 calls let 256 harmless ones hide the write after them — fix
 * round 4); arguments that run past it are noted, never a silent ok.
 */
const MAX_CALL_ARGS = 512;

/**
 * The first two argument texts of a call whose `(` ends just before `from`:
 * split on depth-0 commas, up to the matching `)` — the most any call judged
 * here needs — and never more than {@link MAX_CALL_ARGS} characters on
 * (`cut` when the text went on past that without closing the call).
 */
function callArgs(text: string, from: number): { args: string[]; cut: boolean } {
  const args: string[] = [];
  let depth = 0;
  let cur = '';
  let quote = '';
  const end = Math.min(text.length, from + MAX_CALL_ARGS);
  let closed = false;
  for (let i = from; i < end; i += 1) {
    const ch = text.charAt(i);
    if (quote !== '') {
      cur += ch;
      if (ch === quote) quote = '';
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      cur += ch;
      continue;
    }
    if (ch === ')' && depth === 0) {
      closed = true;
      break;
    }
    if (ch === '(') depth += 1;
    if (ch === ')') depth -= 1;
    if (ch === ',' && depth === 0) {
      args.push(cur.trim());
      cur = '';
      if (args.length === 2) return { args, cut: false };
      continue;
    }
    cur += ch;
  }
  args.push(cur.trim());
  return { args, cut: !closed && end < text.length };
}

/** A call argument as a path: a quoted string's content, or the last string literal inside an expression. */
function argPath(arg: string): string {
  const q = /^(['"])([\s\S]*)\1$/.exec(arg);
  if (q !== null) return (q[2] ?? '').replace(q[1] === "'" ? /''/g : /`"/g, q[1] ?? '');
  const literals = codeLiterals(arg, 'other');
  return literals[literals.length - 1] ?? arg;
}

const DOTNET_CALL = /\[\s*(?:System\s*\.\s*)?IO\s*\.\s*(File|Directory)\s*\]\s*::\s*([A-Za-z]+)\s*\(/gi;

/**
 * What PowerShell's `[IO.File]::…` / `[IO.Directory]::…` calls in `text` do —
 * `WriteAllText`, `AppendAllText`, `Create`, `Open…` write their first
 * argument, `Copy` its second, `Move` / `Replace` move the first onto the
 * second, `Delete` removes, `CreateSymbolicLink` links. A call inside a quoted
 * span is data, not code; the arguments are resolved from `cwd`.
 */
function dotNetEffects(text: string, cwd: string, notes?: Notes): Effects {
  const e = noEffects();
  const newObject = /new-object/i.test(text);
  if (!text.includes('::') && !newObject) return e;
  const unquotedAt = quoteTracker(text);
  for (const m of text.matchAll(DOTNET_CALL)) {
    if (!unquotedAt(m.index)) continue;
    const kind = (m[1] ?? '').toLowerCase();
    const method = (m[2] ?? '').toLowerCase();
    const call = callArgs(text, m.index + m[0].length);
    if (call.cut && notes !== undefined) notes.calls = true;
    const paths = call.args.map((a) => resolveFrom(cwd, argPath(a)));
    const [first, second] = paths;
    if (first === undefined) continue;
    if (method === 'delete') {
      e.removes.push(first);
      // `[IO.Directory]::Delete('C:\', $true)`: the whole tree (review 8, item 9).
      if (kind === 'directory' && /^\$?true$/i.test(call.args[1] ?? '')) e.trees.push(first);
    } else if (method === 'createsymboliclink') {
      e.links.push(first);
      if (second !== undefined) e.aliases.push([first, second]);
    }
    else if (method === 'move' || method === 'replace') {
      e.removes.push(first);
      if (second !== undefined) (kind === 'directory' ? e.dirs : e.writes).push(second);
    } else if (kind === 'file' && method === 'copy') {
      if (second !== undefined) e.writes.push(second);
    } else if (kind === 'file' && /^(?:write|append|create|open)/.test(method) && !/^open(?:read|text)$/.test(method)) {
      e.writes.push(first);
    }
  }
  // A stream opened for writing (review 8, item 15): `[IO.StreamWriter]::new(p)`,
  // `New-Object IO.StreamWriter(p)` / `-ArgumentList p`, and a `FileStream` not
  // opened only to read.
  if (!/streamwriter|filestream/i.test(text)) return e;
  const unquotedWriterAt = quoteTracker(text);
  for (const m of text.matchAll(DOTNET_WRITER)) {
    if (!unquotedWriterAt(m.index)) continue;
    const kind = (m[1] ?? m[2] ?? '').toLowerCase();
    const after = m.index + m[0].length;
    const open = /^\s*@?\(/.exec(text.slice(after, after + 64));
    let args: string[];
    if (open !== null) {
      const call = callArgs(text, after + open[0].length);
      if (call.cut && notes !== undefined) notes.calls = true;
      args = call.args;
    } else {
      const word = /^\s*('(?:[^']|'')*'|"(?:[^"`]|`.)*"|[^\s;|,)]+)/.exec(text.slice(after, after + MAX_CALL_ARGS));
      args = word === null ? [] : [word[1] ?? ''];
    }
    const first = args[0];
    if (first === undefined || first === '') continue;
    // Every argument of the call, not only the first two `callArgs` reads.
    const all = text.slice(after, after + MAX_CALL_ARGS).split(')')[0] ?? '';
    if (kind === 'filestream' && /\bRead\b/i.test(all) && !/Write|Create|Append|Truncate/i.test(all)) continue;
    e.writes.push(resolveFrom(cwd, argPath(first)));
  }
  return e;
}

/** `[IO.StreamWriter]::new(`, `New-Object [-TypeName] System.IO.StreamWriter [-ArgumentList]` and the same for `FileStream`. */
const DOTNET_WRITER =
  /\[\s*(?:System\s*\.\s*)?IO\s*\.\s*(StreamWriter|FileStream)\s*\]\s*::\s*new\b|\bNew-Object\s+(?:-TypeName\s+)?(?:System\s*\.\s*)?IO\s*\.\s*(StreamWriter|FileStream)\b(?:\s+-ArgumentList\b|\s+-Args?\b)?/gi;

// ── the rules

const RULE_HARD_LINK: MatchedRule = {
  id: 'guard-config-hard-link',
  level: 'block',
  reason:
    "Makes a hard link to the guardrail hooks' own configuration or to Claude Code's settings — a second name through which it can be rewritten",
};

/** The directory that holds Claude Code's project or user settings; separators optional as in `HOOK_CONFIG_PATH`. */
const CLAUDE_DIR = /\.claude\/?$/i;

/** The directory that holds Claude Code's managed settings ({@link MANAGED_SETTINGS_PATH}). */
const MANAGED_SETTINGS_DIR = /(?:^|\/)(?:etc\/?claude-code|ClaudeCode)\/?$/i;

const RULE_LINK: MatchedRule = {
  id: 'guard-config-link',
  level: 'block',
  reason:
    "Makes a symbolic link or a junction to the guardrail hooks' own configuration, to Claude Code's settings or to " +
    'the directory that holds them — a second name through which a later command rewrites them without naming them',
};

/**
 * dev-guardian's registry of trusted databases written from the shell (review
 * 3.0 wave 2, round 2): what `db adopt --yes` writes, and so the user's
 * decision whichever command writes it.
 */
const RULE_REGISTRY: MatchedRule = {
  id: 'guardian-registry-write',
  level: 'block',
  reason:
    "Writes dev-guardian's registry of trusted databases (<data dir>/registry) — which database to trust is the " +
    "user's decision: they run the dev-guardian CLI's `db adopt` themselves, in a terminal",
};

/** Program text naming the registry: a literal path in it, or its parts (`'dev-guardian', 'registry'`). */
function literalsNameRegistry(literals: readonly string[], dataDir: string | undefined): boolean {
  const paths = literalPaths(literals);
  if (paths.some((p) => isRegistryPath(p, dataDir))) return true;
  const has = (re: RegExp): boolean => paths.some((p) => re.test(p));
  return has(/(?:^|\/)dev-guardian\/?$/i) && has(/^registry\/?$/i);
}

const RULE_SPECIAL: MatchedRule = {
  id: 'guard-config-special-file',
  level: 'block',
  reason: "Replaces the guardrail hooks' own configuration with a FIFO, a device node or a link",
};
const RULE_WRITE: MatchedRule = {
  id: 'guard-config-shell-write',
  level: 'block',
  reason: "Writes the guardrail hooks' own configuration from the shell",
};
const RULE_REMOVE: MatchedRule = {
  id: 'guard-config-remove',
  level: 'block',
  reason: "Removes or moves away the guardrail hooks' own configuration",
};
const RULE_DIR: MatchedRule = {
  id: 'guard-config-dir-replace',
  level: 'block',
  reason: "Moves or copies a directory onto the guardrail hooks' configuration directory",
};
const RULE_INLINE: MatchedRule = {
  id: 'guard-config-inline-code',
  level: 'block',
  reason: "Runs program code that names the guardrail hooks' own configuration",
};
const RULE_SETTINGS: MatchedRule = {
  id: 'claude-settings-loosen',
  level: 'block',
  reason: "Writes Claude Code's settings with a key that switches the guardrail hooks off",
};

/**
 * Where a guarded path a command names lies: `inside` — where the hooks of
 * this session read it (the project, the working directory, the home
 * directory, `CLAUDE_CONFIG_DIR`), or anywhere a variable, a relative path or
 * a mangled spelling leaves unknown; `outside` — provably elsewhere (another
 * project, a test fixture's fake HOME); `null` — not a guarded path at all.
 */
type Placement = 'inside' | 'outside' | null;

/** The more serious of several placements. */
function worst(placements: readonly Placement[]): Placement {
  if (placements.includes('inside')) return 'inside';
  return placements.includes('outside') ? 'outside' : null;
}

/** The places a guarded path counts as this session's, as {@link targetKey} spells them. */
interface Places {
  fold: boolean;
  home?: string | undefined;
  cwd?: string | undefined;
  project?: string | undefined;
  configDir?: string | undefined;
}

/** `key` is `dir` or below it. */
function keyAtOrBelow(dir: string | undefined, key: string): boolean {
  return dir !== undefined && dir !== '' && (key === dir || key.startsWith(`${dir}/`));
}

/**
 * Where the guarded paths of `paths` (those `pred` accepts) lie ({@link
 * Placement}). Without {@link Scope.places} — the CLI's `check`, the tests'
 * default — every one is `inside`, as it always was. A path is `outside` only
 * when it is spelled in full (`/tmp/x/…`, `C:/x/…`, `~other/…`, or `~/…` and
 * `$HOME/…` below home) and lies under none of the places: a project's
 * `.guardian/hooks*.json` counts under the project or the working directory,
 * the user-level `hooks.json` only as the home directory's own, Claude Code's
 * settings under any of them.
 */
function locate(paths: readonly string[], pred: (p: string) => boolean, scope: Scope): Placement {
  let found: Placement = null;
  for (const p of paths) {
    if (!pred(p)) continue;
    if (placeOf(p, scope) === 'inside') return 'inside';
    found = 'outside';
  }
  return found;
}

function placeOf(raw: string, scope: Scope): Placement {
  const places = scope.places;
  if (places === undefined) return 'inside';
  let t = stripQuotes(raw).replace(/\\/g, '/');
  const homeSpelled = /^(?:~|\$\{?HOME\}?|\$\{?USERPROFILE\}?|\$\{?env:USERPROFILE\}?|%USERPROFILE%)(?=\/|$)/i.exec(t);
  if (homeSpelled !== null) {
    if (places.home === undefined) return 'inside';
    t = `${places.home}${t.slice(homeSpelled[0].length)}`;
  } else if (/^~[A-Za-z_]/.test(t)) {
    // `~other/…` is another account's: never this session's hooks.
    return 'outside';
  } else if (!/^(?:\/|[A-Za-z]:\/)/.test(t)) {
    // Relative (the working directory), a variable, or a spelling the POSIX
    // reader mangled (`C:proj.guardian…`): unknown, so this session's.
    return 'inside';
  }
  // A glob may name the place itself: unknown, so this session's.
  if (GLOB.test(t)) return 'inside';
  const key = targetKey(t, places.fold);
  if (/(?:^|\/)\.config\/dev-guardian(?:\/|$)/i.test(key)) {
    if (places.home === undefined) return 'inside';
    return keyAtOrBelow(`${places.home}/.config/dev-guardian`, key) ? 'inside' : 'outside';
  }
  if (MANAGED_SETTINGS_PATH.test(key)) return 'inside';
  if (isSettingsPath(key, scope.configDirName) || CLAUDE_DIR.test(key)) {
    return [places.project, places.cwd, places.home, places.configDir].some((d) => keyAtOrBelow(d, key)) ? 'inside' : 'outside';
  }
  return [places.project, places.cwd].some((d) => keyAtOrBelow(d, key)) ? 'inside' : 'outside';
}

/** The guarded path one elsewhere: a warning, since it is not this session's (review 8, item 14). */
const RULE_ELSEWHERE: MatchedRule = {
  id: 'guard-config-elsewhere',
  level: 'warn',
  reason:
    "Writes a file named like the guardrail hooks' configuration or Claude Code's settings outside this project, " +
    'the working directory and the home directory — not the one this session reads; confirm the target',
};

/** A block device: what `tee` or `cp` must not be pointed at (review 8, item 9). */
const BLOCK_DEVICE = /^\/dev\/(?:sd|hd|vd|xvd|nvme|mmcblk|disk|md|dm-)|PhysicalDrive\d/i;

const RULE_DISK_WRITE: MatchedRule = {
  id: 'disk-overwrite',
  level: 'block',
  reason: 'Writes raw bytes to a block device (dd/mkfs/wipefs/shred on /dev/…)',
};

/** The most links one command's lines may make that later paths are read through ({@link throughLinks}). */
const MAX_ALIASES = 64;
/** The most paths one command may have looked up on disk ({@link AssessOptions.realPath}). */
const MAX_LOOKUPS = 64;

/**
 * A path the command names, absolute and `/`-separated — `~` read as the home
 * directory, on Windows an MSYS `/c/…` as `C:/…`, a relative one from the
 * directory the statements start in — or `undefined` when that cannot be told
 * (a variable, `~user`, a drive-relative `C:x`, an unknown start).
 */
function absoluteOf(raw: string, scope: Scope): string | undefined {
  const t = stripQuotes(raw).replace(/\\/g, '/');
  if (/^~(?=\/|$)/.test(t)) return scope.homePath === undefined ? undefined : `${scope.homePath.replace(/\/+$/, '')}${t.slice(1)}`;
  if (/^[~$%]/.test(t)) return undefined;
  if (scope.windows === true) {
    const msys = /^\/(?:cygdrive\/)?([A-Za-z])(?=\/|$)/.exec(t);
    if (msys !== null) return `${(msys[1] ?? '').toUpperCase()}:${t.slice(msys[0].length) || '/'}`;
    if (/^[A-Za-z]:(?!\/)/.test(t)) return undefined;
  }
  if (/^(?:\/|[A-Za-z]:\/)/.test(t)) return t;
  return scope.dir === undefined ? undefined : resolveFrom(scope.dir, t);
}

/** How a link and a path under it are compared: absolute when it can be told, no trailing `/`, lower-cased on Windows. */
function aliasKey(raw: string, scope: Scope): string {
  const k = (absoluteOf(raw, scope) ?? stripQuotes(raw).replace(/\\/g, '/')).replace(/\/+$/, '');
  return scope.windows === true ? k.toLowerCase() : k;
}

/**
 * How much of a path {@link realPathOf} looks up: all of it (a directory a
 * tree lands on, a link's target); all of it when its name could be a
 * guarded file, else its directory (a write — `cp` of a hundred files into
 * one directory looks that directory up once); only its directory (a remove,
 * a new link or FIFO, a hard link: a link AT the path is what they act on).
 */
type Lookup = 'path' | 'name' | 'parent';

/**
 * Where an absolute path really leads through the links already on disk
 * ({@link AssessOptions.realPath}), `/`-separated — `undefined` when as
 * written, unknown, or past {@link MAX_LOOKUPS} or the budget (each noted).
 */
function realPathOf(raw: string, scope: Scope, lookup: Lookup): string | undefined {
  const realPath = scope.realPath;
  if (realPath === undefined) return undefined;
  const whole = absoluteOf(raw, scope)?.replace(/(?<=.)\/+$/, '');
  if (whole === undefined || GLOB.test(whole) || /^\/dev\//.test(whole)) return undefined;
  const cut = whole.lastIndexOf('/');
  // A name that may be a guarded file: `….json` (a stream or trailing dots after it too), or an 8.3 short name.
  if (lookup === 'path' || (lookup === 'name' && /\.json|~\d/i.test(whole.slice(cut + 1)))) return lookedUp(whole, realPath, scope);
  if (cut <= 0 || /^[A-Za-z]:$/.test(whole.slice(0, cut))) return undefined;
  const dir = lookedUp(whole.slice(0, cut), realPath, scope);
  return dir === undefined ? undefined : `${dir.replace(/\/+$/, '')}${whole.slice(cut)}`;
}

/** {@link realPathOf}'s one lookup of `abs`, asked once per path ({@link Notes.realPaths}). */
function lookedUp(abs: string, realPath: (path: string) => string | undefined, scope: Scope): string | undefined {
  const notes = scope.notes;
  if (notes.realPaths.has(abs)) return notes.realPaths.get(abs);
  if (notes.realPaths.size >= MAX_LOOKUPS) {
    notes.links = true;
    return undefined;
  }
  if (notes.now() > notes.deadline) {
    notes.budget = true;
    return undefined;
  }
  let real: string | undefined;
  try {
    real = realPath(abs)?.replace(/\\/g, '/');
  } catch {
    real = undefined;
  }
  const differs = real !== undefined && (scope.windows === true ? real.toLowerCase() !== abs.toLowerCase() : real !== abs);
  const found = differs ? real : undefined;
  notes.realPaths.set(abs, found);
  return found;
}

/**
 * `effects` with every path also as it really leads (review 12, finding 1):
 * through a link this command made before it — `mklink /J z .claude &&
 * echo … > z/settings.local.json` writes `.claude/settings.local.json`; the
 * links are kept, up to {@link MAX_ALIASES}, in {@link Notes.aliases} — and
 * through one already on disk ({@link realPathOf}). Paths are only added, so
 * each is still judged as written. `targets`: what the links made here point
 * at, read the same way.
 */
function throughLinks(effects: Effects, scope: Scope): { effects: Effects; targets: string[] } {
  const notes = scope.notes;
  /**
   * `paths`, and where each leads ({@link Lookup}). A link AT the path is
   * followed unless `lookup` is `parent` — a write goes through it, while a
   * remove, a new link, a FIFO or a hard link acts on the link itself.
   */
  const expand = (paths: readonly string[], lookup: Lookup): string[] => {
    const out = [...paths];
    for (const p of paths) {
      if (notes.aliases.length > 0) {
        const key = aliasKey(p, scope);
        for (const [link, target] of notes.aliases) {
          if ((lookup !== 'parent' && key === link) || key.startsWith(`${link}/`)) out.push(`${target}${key.slice(link.length)}`);
        }
      }
      const real = realPathOf(p, scope, lookup);
      if (real !== undefined) out.push(real);
    }
    return out;
  };
  // The links and their targets through the links made BEFORE them; every
  // other path also through these — a `cmd /c` line's `mklink` and its write.
  const targets = expand(
    effects.aliases.map(([, target]) => target),
    'path',
  );
  const links = expand(effects.links, 'parent');
  for (const [link, target] of effects.aliases) {
    if (notes.aliases.length >= MAX_ALIASES) {
      notes.links = true;
      break;
    }
    notes.aliases.push([aliasKey(link, scope), aliasKey(target, scope)]);
  }
  return {
    effects: {
      writes: expand(effects.writes, 'name'),
      removes: expand(effects.removes, 'parent'),
      dirs: expand(effects.dirs, 'path'),
      special: expand(effects.special, 'parent'),
      links,
      hardLinkSources: expand(effects.hardLinkSources, 'parent'),
      trees: expand(effects.trees, 'path'),
      aliases: effects.aliases,
    },
    targets,
  };
}

/**
 * The rules a command's filesystem effects break. The guard's own
 * configuration: a FIFO, device node or link created at a config file (a link
 * also at a config directory — final review I12 and fix round 2, N1); a write
 * onto a config file (M5); its removal, or the user-level directory's; a
 * directory moved or copied onto a config directory. Claude Code's settings: a
 * write of `.claude/settings*.json` whose command names a loosening key
 * anywhere (`raw`). Each path is judged as written and as it really leads
 * ({@link throughLinks}); a symbolic link or a junction made to any of those
 * files or directories is a second name for it (review 12, finding 1).
 */
function judgeEffects(effects: Effects, scope: Scope): MatchedRule[] {
  const { effects: named, targets: linkTargets } = throughLinks(effects, scope);
  const e: Effects = {
    writes: asWindowsOpens(named.writes.map(tail)),
    removes: asWindowsOpens(named.removes.map(tail)),
    dirs: asWindowsOpens(named.dirs.map(tail)),
    special: asWindowsOpens(named.special.map(tail)),
    links: asWindowsOpens(named.links.map(tail)),
    hardLinkSources: asWindowsOpens(named.hardLinkSources.map(tail)),
    trees: named.trees.map(tail),
    aliases: [],
  };
  const targets = asWindowsOpens(linkTargets.map(tail));
  const out: MatchedRule[] = [];
  // Each guarded path is this session's only where the hooks read it; one
  // elsewhere — another project's, a test fixture's HOME — warns (review 8, item 14).
  const judged = (rule: MatchedRule, where: Placement): void => {
    if (where === 'inside') out.push({ ...rule });
    else if (where === 'outside') out.push({ ...RULE_ELSEWHERE });
  };
  const configAt = (p: string): boolean => isHookConfigPath(p) || globNamesConfig(p);
  judged(RULE_SPECIAL, worst([locate(e.special, isHookConfigPath, scope), locate(e.links, (p) => isHookConfigPath(p) || isHookConfigDir(p), scope)]));
  judged(RULE_WRITE, locate(e.writes, configAt, scope));
  const removesConfig = (p: string): boolean =>
    isHookConfigPath(p) || USER_CONFIG_DIR.test(p) || globNamesConfig(p, [USER_CONFIG_TAIL]);
  judged(RULE_REMOVE, locate(e.removes, removesConfig, scope));
  judged(RULE_DIR, locate(e.dirs, isHookConfigDir, scope));
  // A hard link to a configuration file, to Claude Code's settings (the Write
  // guard judges a write through one as that file; a shell write through one
  // names neither), or — `cp -al` — to every file of a directory that holds
  // them (review 3.0, wave 2).
  const linksGuarded = (p: string): boolean =>
    isHookConfigPath(p) || isHookConfigDir(p) || isSettingsPath(p, scope.configDirName) || CLAUDE_DIR.test(p);
  judged(RULE_HARD_LINK, locate(e.hardLinkSources, linksGuarded, scope));
  judged(RULE_LINK, locate(targets, (p) => linksGuarded(p) || MANAGED_SETTINGS_DIR.test(p), scope));
  // A whole tree deleted by a copy or a .NET call (review 8, item 9), and a
  // block device written by `tee` or `cp` (`cat /dev/zero | tee /dev/sda`).
  if (e.trees.some((p) => isCatastrophicTarget(p, scope.tildeUsers) || isHomeTarget(p, scope.home))) out.push({ ...RULE_RM_ROOT });
  if (e.writes.some((p) => BLOCK_DEVICE.test(p))) out.push({ ...RULE_DISK_WRITE });
  // dev-guardian's registry of trusted databases (round 2): an entry written,
  // linked or copied into it, a hard link to one, or the registry or the whole
  // data directory replaced. Removing one only un-trusts a database.
  const inRegistry = (p: string): boolean => isRegistryPath(p, scope.dataDir);
  const registryOrData = (p: string): boolean => inRegistry(p) || isDataDirPath(p, scope.dataDir);
  if (
    e.writes.some(inRegistry) ||
    e.special.some(inRegistry) ||
    e.hardLinkSources.some(inRegistry) ||
    e.links.some(registryOrData) ||
    e.dirs.some(registryOrData) ||
    targets.some(registryOrData)
  ) {
    out.push({ ...RULE_REGISTRY });
  }
  const settings = locate(e.writes, (p) => isSettingsPath(p, scope.configDirName), scope);
  if (settings !== null && loosens(scope)) judged(RULE_SETTINGS, settings);
  return out;
}

const RULE_PLUGIN_OFF: MatchedRule = {
  id: 'claude-plugin-disable',
  level: 'block',
  reason: "Switches the guardrail hooks off through Claude Code's plugin command",
};

/**
 * `claude plugin disable|uninstall dev-guardian…` (also `plugins`, `remove`,
 * `marketplace remove`, and behind `npx @anthropic-ai/claude-code`): it writes
 * the `enabledPlugins` entry the Write/Edit settings guard refuses, or removes
 * the plugin and every hook with it.
 */
function turnsPluginOff(words: readonly ShellWord[], start: number): boolean {
  let i = start;
  const head = words[i]?.value ?? '';
  if (commandName(head) === 'npx' && /(?:^|\/)claude-code(?:@|$)/.test(words[i + 1]?.value ?? '')) i += 1;
  else if (commandName(head) !== 'claude') return false;
  const rest = words.slice(i + 1).map((w) => w.value);
  if (rest[0] !== 'plugin' && rest[0] !== 'plugins') return false;
  const verbs = rest[1] === 'marketplace' ? rest.slice(2, 3) : rest.slice(1, 2);
  if (!verbs.some((v) => /^(?:disable|uninstall|remove|rm)$/.test(v))) return false;
  return rest.some((a) => /dev-guardian/i.test(a));
}

/**
 * `dev-guardian db adopt --yes` makes a project's database trusted. That is a
 * person's decision, taken after reading the summary `db adopt` prints without
 * `--yes`: a hostile repository can ship a database that hides its findings,
 * and its text can talk an assistant into adopting it (review 3.0, wave 2).
 * The reason is the whole deny message ({@link BashAssessment.denyMessage}).
 */
const RULE_DB_ADOPT: MatchedRule = {
  id: 'db-adopt-yes',
  level: 'block',
  reason: 'db adopt --yes marks a database as trusted; run it yourself in a terminal after reading `db adopt` without --yes',
};

/**
 * The CLI, as a command or a script: `dev-guardian`, `dev-guardian.mjs`,
 * `dev-guardian.cmd`, `dev-guardian@3.0.1` — and `guardian.cjs`, the launcher
 * dev-spec-driven writes into `.specs/`, which hands every argument on to it.
 */
const CLI_NAME = /^(?:dev-guardian(?:@[\w.^~<>=-]*)?(?:\.(?:mjs|cjs|js|cmd|ps1|exe))?|guardian\.cjs)$/i;
/** What runs the CLI named as its program: node and the other runtimes, and the package runners. */
const CLI_HOSTS = new Set(['node', 'nodejs', 'bun', 'deno', 'tsx', 'ts-node', 'npx', 'pnpx', 'bunx', 'npm', 'pnpm', 'yarn']);
/** A package runner's or a runtime's subcommand before the program: `pnpm dlx`, `npm exec`, `bun x`, `deno run`. */
const CLI_HOST_SUBCOMMANDS = new Set(['dlx', 'exec', 'x', 'run']);

/**
 * The arguments the dev-guardian CLI is given by this command, or none when it
 * does not run the CLI: its name at the command position (a path to it, `.mjs`
 * and a package version included), or as the program of `node` (past node's
 * own options), `npx` / `pnpm dlx` / `bunx` / `npm exec` and the like.
 */
function cliArgs(words: readonly ShellWord[], at: number): string[] | undefined {
  const head = words[at];
  if (head === undefined) return undefined;
  if (CLI_NAME.test(basename(head.value))) return words.slice(at + 1).map((w) => w.value);
  if (!CLI_HOSTS.has(interpreterName(head.value))) return undefined;
  let subcommand = false;
  for (let i = at + 1; i < words.length; i += 1) {
    const v = words[i]?.value ?? '';
    if (v.startsWith('-')) {
      i += !v.includes('=') && (NODE_OPTION_VALUED.has(v) || LAUNCHER_VALUED.has(v)) ? 1 : 0;
      continue;
    }
    if (!subcommand && CLI_HOST_SUBCOMMANDS.has(v)) {
      subcommand = true;
      continue;
    }
    return CLI_NAME.test(basename(v)) ? words.slice(i + 1).map((w) => w.value) : undefined;
  }
  return undefined;
}

/**
 * `dev-guardian db adopt … --yes` (or `--yes=…`), its options in any order,
 * when the command at `at` runs the CLI directly ({@link cliArgs}) — a
 * speed bump, not a wall: the indirect launches are in docs/hooks.md's known
 * limits, and the registry the command writes is guarded by path.
 */
function adoptsDatabase(words: readonly ShellWord[], at: number): boolean {
  const args = cliArgs(words, at);
  if (args === undefined) return false;
  const db = args.findIndex((a) => !a.startsWith('-'));
  if (args[db] !== 'db' || !args.slice(db + 1).includes('adopt')) return false;
  return args.some((a) => a === '--yes' || a.startsWith('--yes='));
}

/**
 * The same, launched one step removed (review 3.0 wave 2, round 2): by
 * PowerShell's `Start-Process` / `saps` / `start` (its program and
 * `-ArgumentList`), or by `find … -exec` / `-execdir` / `-ok`. (`env -S` is
 * read as a nested script instead: it can hand on any command.)
 */
function adoptsDatabaseThroughLauncher(words: readonly ShellWord[], at: number): boolean {
  return throughLauncher(words, at, adoptsDatabase);
}

/** `runs` of the command `Start-Process` starts, or of one `find -exec` runs. */
function throughLauncher(words: readonly ShellWord[], at: number, runs: (words: readonly ShellWord[], at: number) => boolean): boolean {
  const started = startProcessArgv(words, at);
  if (started !== undefined && runs(started, 0)) return true;
  return findExecCommands(words, at).some((cmd) => runs(cmd, resolveCommand(cmd).index));
}

/**
 * `dev-guardian baseline update` run by the assistant (review 8, C2): it
 * accepts EVERY current finding into `.guardian/baseline.json` — a feature's
 * own new finding included — and the gate then reports none of them. That is
 * the user's decision, so the hook asks ({@link BashAssessment.ask}) instead
 * of denying: `dev-guardian baseline update`, `node …/dev-guardian.mjs
 * baseline update`, `node .specs/guardian.cjs baseline update`, behind `npx`
 * or a runner, in a nested script or launched by `Start-Process` / `find -exec`.
 */
function updatesBaseline(words: readonly ShellWord[], at: number): boolean {
  const args = cliArgs(words, at);
  if (args === undefined) return false;
  const plain = args.filter((a) => !a.startsWith('-'));
  return plain[0] === 'baseline' && plain[1] === 'update';
}

const RULE_BASELINE_UPDATE: MatchedRule = {
  id: 'baseline-update',
  level: 'warn',
  reason:
    'dev-guardian baseline update accepts EVERY current finding into .guardian/baseline.json, new ones included, and the ' +
    'gate stops reporting them — the user decides. To accept one reviewed finding, suppress it inline with a reason ' +
    '(`nosemgrep: <rule> -- <reason>`, `# nosec`), or rebuild the baseline on the base commit',
};

const START_PROCESS = new Set(['start-process', 'saps', 'start']);

/** As plain words. */
function plainWords(values: readonly string[]): ShellWord[] {
  return values.map((value) => ({ value, quoted: false }));
}

/**
 * The command line `Start-Process` starts: its `-FilePath` (or first
 * positional) and every word of its `-ArgumentList` (or second positional) —
 * a list's items and a single string's words alike. None when the command at
 * or before `at` is not Start-Process.
 */
function startProcessArgv(words: readonly ShellWord[], at: number): ShellWord[] | undefined {
  const sp = words.findIndex((w, i) => i <= at && START_PROCESS.has(commandName(w.value)));
  if (sp < 0) return undefined;
  let file: string | undefined;
  const list: string[] = [];
  const positional: string[] = [];
  let inList = false;
  for (let i = sp + 1; i < words.length; i += 1) {
    const v = words[i]?.value ?? '';
    const param = /^-([A-Za-z]+)(?::([\s\S]*))?$/.exec(v);
    if (param !== null) {
      inList = false;
      const name = `-${param[1] ?? ''}`;
      const inline = param[2];
      if (PS_FILE_PATH.test(name)) file = inline ?? words[(i += 1)]?.value;
      else if (PS_ARGUMENT_LIST.test(name)) {
        inList = true;
        if (inline !== undefined) list.push(inline);
      } else if (inline === undefined && /^-(?:verb|wo\w*|windowstyle|w|redirect\w*|credential|cred|environment)$/i.test(name)) i += 1;
      continue;
    }
    if (inList) list.push(v);
    else positional.push(v);
  }
  file ??= positional.shift();
  if (list.length === 0 && positional[0] !== undefined) list.push(positional[0]);
  if (file === undefined) return undefined;
  return plainWords([file, ...list.flatMap((a) => a.split(/\s+/).filter((s) => s !== ''))]);
}

/** The commands `find` runs for what it finds: each `-exec` / `-execdir` / `-ok` / `-okdir` to its `;` or `{} +`. */
function findExecCommands(words: readonly ShellWord[], at: number): ShellWord[][] {
  if (commandName(words[at]?.value ?? '') !== 'find') return [];
  const out: ShellWord[][] = [];
  let cmd: ShellWord[] | undefined;
  for (let i = at + 1; i < words.length; i += 1) {
    const w = words[i];
    if (w === undefined) continue;
    if (cmd === undefined) {
      if (/^-(?:exec|execdir|ok|okdir)$/.test(w.value)) cmd = [];
      continue;
    }
    if (w.value === ';' || (w.value === '+' && words[i - 1]?.value === '{}')) {
      out.push(cmd);
      cmd = undefined;
    } else cmd.push(w);
  }
  if (cmd !== undefined && cmd.length > 0) out.push(cmd);
  return out;
}

/**
 * The command line `env -S STRING [args…]` (`--split-string`, `-S` in a
 * cluster) runs: the string split into words, then the rest — read as a
 * nested script, since it can hand on any command (`env -S 'rm -rf /'`).
 * `end` is where the command after the runners starts.
 */
function envSplitScript(words: readonly ShellWord[], end: number): string | undefined {
  for (let i = 0; i < Math.min(end, words.length); i += 1) {
    if (commandName(words[i]?.value ?? '') !== 'env') continue;
    for (let j = i + 1; j < words.length; j += 1) {
      const a = words[j]?.value ?? '';
      let value: string | undefined;
      let next = j + 1;
      const long = /^--split-string(?:=([\s\S]*))?$/.exec(a);
      // `-S` in a short cluster, unless a letter before it takes the value (`-uS` is `-u S`).
      const valued = /^-[^-]/.test(a) ? /[uCSa]/.exec(a.slice(1)) : null;
      if (long !== null) {
        if (long[1] !== undefined) value = long[1];
        else {
          value = words[j + 1]?.value;
          next = j + 2;
        }
      } else if (valued !== null && valued[0] === 'S') {
        const rest = a.slice(valued.index + 2);
        if (rest !== '') value = rest;
        else {
          value = words[j + 1]?.value;
          next = j + 2;
        }
      } else if (/^-[^-]/.test(a) || a.startsWith('--')) {
        j += runnerOptionWords('env', a) - 1;
        continue;
      } else if (ASSIGNMENT.test(a) || a === '-') {
        continue;
      } else return undefined;
      if (value === undefined) return undefined;
      return [value, ...words.slice(next).map((w) => w.value)].join(' ');
    }
    return undefined;
  }
  return undefined;
}

/** Program text that names a hook config path; or Claude Code's settings, with a loosening key in the command. */
function judgeCode(code: string, lang: CodeLang, scope: Scope): MatchedRule[] {
  const literals = codeLiterals(code, lang);
  const out: MatchedRule[] = [];
  const placed = (rule: MatchedRule, where: Placement): void => {
    if (where === 'inside') out.push({ ...rule });
    else if (where === 'outside') out.push({ ...RULE_ELSEWHERE });
  };
  placed(RULE_INLINE, literalsNameHookConfig(literals, scope));
  const settings = literalsNameClaudeSettings(literals, scope);
  if (settings !== null && loosens(scope)) placed(RULE_SETTINGS, settings);
  if (literalsNameRegistry(literals, scope.dataDir)) out.push({ ...RULE_REGISTRY });
  return out;
}

/** Where a command's statements run, and the whole command as given (see {@link collect}). */
interface Scope {
  /** The whole command as given — quotes and heredoc bodies included. */
  raw: string;
  /** Where the `cd`s so far moved to; `''` = where the command started. */
  cwd: string;
  /** Shared by every nested scope: what a cap or the budget dropped, and the clock. */
  notes: Notes;
  /** The home directory, to recognise it named outright as a delete target. */
  home?: HomeDir | undefined;
  /** The last segment of Claude Code's `CLAUDE_CONFIG_DIR`, lower-cased, when it is set. */
  configDirName?: string | undefined;
  /** dev-guardian's per-user data directory, normalised ({@link normalizedPath}), whose `registry/` is guarded. */
  dataDir?: string | undefined;
  /** These statements are a `cmd /c` line: cmd.exe runs a bare name from the working directory. */
  cmdLine?: boolean;
  /** `~name` is another account's home: a POSIX shell's reading, never the PowerShell tool's. */
  tildeUsers?: boolean;
  /** These statements are PowerShell's — the PowerShell tool's, or a script handed to `pwsh -c` / `iex`. */
  powershell?: boolean;
  /** Where a guarded path is this session's ({@link placeOf}); none: everywhere. */
  places?: Places | undefined;
  /** Where the command was before its last `cd` — what `cd -` returns to ({@link moveCwd}). */
  prevCwd?: string;
  /** `pushd`'s stack, replaced on every change. */
  dirStack?: readonly string[];
  /** `CDPATH`, when the command set it. */
  cdpath?: readonly string[];
  /**
   * The directory these statements start in — absolute, `/`-separated — when
   * it is known: the hook's working directory, then where a nested script is
   * handed over. What a relative delete target is read against.
   */
  dir?: string | undefined;
  /** The home directory's path, `/`-separated, for a `cd ~`. */
  homePath?: string | undefined;
  /** The variables a delete target may start with ({@link DeleteContext}). */
  vars?: Readonly<Record<string, string>> | undefined;
  /** Git Bash reads a bare drive (`C:`) as its root ({@link DeleteContext}). */
  bareDriveRoot?: boolean;
  /** The command runs on Windows: paths compare case-insensitively, an MSYS `/c/…` is `C:/…`. */
  windows?: boolean;
  /** {@link AssessOptions.realPath}. */
  realPath?: ((path: string) => string | undefined) | undefined;
}

/**
 * One simple command against the guard's own configuration and Claude Code's
 * settings: what it writes, removes, replaces or links ({@link effectsOf},
 * redirections included), and any program text it hands an interpreter on its
 * command line ({@link inlineCode}) — which is refused when it names a hook
 * configuration path at all, reading or writing: reading one needs no program.
 */
function assessGuardConfig(words: ShellWord[], start: number, scope: Scope): MatchedRule[] {
  const head = words[start];
  if (head === undefined) return [];
  const e = effectsOf(commandName(head.value), withoutRedirections(words.slice(start + 1)), scope.cwd);
  pushAll(e.writes, redirectTargets(words).map((t) => resolveFrom(scope.cwd, t)));
  const out = judgeEffects(e, scope);
  // Each command of a `cmd /c` line, as if it stood alone (M1).
  const commands = commandName(head.value) === 'cmd' ? cmdInnerCommands(words.slice(start + 1).map((w) => w.value)) : [];
  for (const [cmdWords, at] of [[words, start] as const, ...commands.map((c) => [c, 0] as const)]) {
    if (turnsPluginOff(cmdWords, at)) out.push({ ...RULE_PLUGIN_OFF });
    const lang = codeLang(interpreterName(cmdWords[interpreterIndex(cmdWords, at)]?.value ?? ''));
    for (const code of inlineCode(cmdWords, at)) pushAll(out, judgeCode(code, lang, scope));
  }
  return out;
}

/**
 * True when `script` (already dequoted) IS a remote download, rather than
 * merely containing one — the entire text is a bare `curl`/`wget` invocation,
 * or one wrapped in `$( … )`/backticks. This is what `bash <(curl …)` hands
 * to bash as its script argument, and what `sh -c "$(curl …)"` hands to `-c`:
 * both execute the downloaded bytes without ever spelling `| sh`, so neither
 * is caught by `remote-pipe-to-shell`, and neither should be confused with
 * the ordinary, harmless `x=$(curl …)` (captures output into a variable;
 * never executed) — which is exactly why this checks the *whole* trimmed
 * script rather than searching for `curl`/`wget` anywhere inside it.
 */
function isBareRemoteFetch(script: string): boolean {
  const s = script.trim();
  const unwrapped =
    s.startsWith('$(') && s.endsWith(')')
      ? s.slice(2, -1).trim()
      : s.startsWith('`') && s.endsWith('`')
        ? s.slice(1, -1).trim()
        : s;
  return /^(?:curl|wget)\b/i.test(unwrapped);
}

const SHELLS = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh', 'ash', 'mksh', 'su', 'pwsh', 'powershell']);

/** A script a command hands to a shell; `powershell` when PowerShell reads it. */
interface NestedScript {
  text: string;
  powershell: boolean;
  /** Handed to `Invoke-Expression` (`iex`), which runs it as PowerShell. */
  iex?: boolean;
  /** What it runs is not on the command line: `iex $s`, `Invoke-Expression -Command $code`. */
  unread?: true;
}

function shellScript(text: string): NestedScript {
  return { text, powershell: false };
}
const DASH_C = /^-[A-Za-z]*c$/;

/** flock's options that take the next word as their value (`-w SECS`, `-E CODE`). */
const FLOCK_VALUED = /^-[wE]$|^--(?:timeout|conflict-exit-code)$/;

/**
 * The script a nested-script carrier runs (review of 3.6.0, finding 7), or
 * `null` when `name` is not one. The carriers run their payload through a
 * shell, so each is assessed as a shell script — a catastrophic delete wrapped
 * in one used to be invisible:
 *
 *   - `trap 'SCRIPT' SIGSPEC` — the first operand, run on the signal (a lone
 *     operand with no sigspec is `trap SCRIPT` querying/printing, not running);
 *   - `flock FILE -c 'SCRIPT'`, or `flock [opts] FILE CMD …` run directly;
 *   - `script [-q] -c 'SCRIPT' FILE` (also `-qc`, `--command`);
 *   - `runuser … -c 'SCRIPT'`, or `runuser … -- CMD …` run as the user.
 */
function carrierScript(name: string, words: readonly ShellWord[], start: number): string | undefined | null {
  const rest = words.slice(start + 1);
  /** A `-c`/`--command`/`--command=` script at `rest[i]`, or `undefined` when there is none. */
  const dashC = (w: ShellWord | undefined, nextWord: ShellWord | undefined): string | undefined => {
    if (w === undefined) return undefined;
    if (w.value.startsWith('--command=')) return w.value.slice('--command='.length);
    return !w.quoted && (DASH_C.test(w.value) || w.value === '--command') ? (nextWord?.value ?? '') : undefined;
  };
  const argv = (from: number): string | undefined => rest.slice(from).map((x) => x.value).join(' ') || undefined;
  if (name === 'trap') {
    let i = 0;
    while (i < rest.length && (rest[i]?.value ?? '').startsWith('-') && rest[i]?.value !== '--') i += 1;
    if (rest[i]?.value === '--') i += 1;
    const arg = rest[i]?.value;
    // A command to run needs a signal after it; `-`/`` reset it.
    return arg !== undefined && arg !== '-' && arg !== '' && rest.length > i + 1 ? arg : undefined;
  }
  if (name === 'script') {
    for (let i = 0; i < rest.length; i += 1) {
      const c = dashC(rest[i], rest[i + 1]);
      if (c !== undefined) return c;
    }
    return undefined;
  }
  if (name === 'runuser') {
    for (let i = 0; i < rest.length; i += 1) {
      const c = dashC(rest[i], rest[i + 1]);
      if (c !== undefined) return c;
      if (rest[i]?.value === '--') return argv(i + 1);
    }
    return undefined;
  }
  if (name === 'flock') {
    // flock's own options precede the lock FILE; `-c` may follow it (`flock
    // FILE -c '…'`), else the command runs directly (`flock FILE CMD …`).
    let i = 0;
    while (i < rest.length && (rest[i]?.value ?? '').startsWith('-')) {
      const c = dashC(rest[i], rest[i + 1]);
      if (c !== undefined) return c;
      i += FLOCK_VALUED.test(rest[i]?.value ?? '') ? 2 : 1;
    }
    const c = dashC(rest[i + 1], rest[i + 2]);
    return c !== undefined ? c : argv(i + 1);
  }
  return null;
}

/**
 * Scripts this command hands to a shell — `sh -c '…'`, `bash -lc '…'`,
 * `docker exec box bash -c '…'`, `su -s /bin/sh www-data -c '…'`, `eval …`,
 * and PowerShell's `-Command …` / `-EncodedCommand …` (`pwsh`, `powershell`).
 * Masking quoted spans would otherwise make those bodies unmatchable, which
 * *is* the right call for `echo 'git push --force'` and the wrong one here.
 * `powershell` marks PowerShell program text, which is also read with
 * PowerShell's quoting (fix round 4: `pwsh -Command 'Remove-Item "C:\Users\"
 * -Recurse -Force'` read POSIX-only was ok).
 */
function nestedScripts(words: ShellWord[], start: number): NestedScript[] {
  const head = words[start];
  const name = head === undefined ? '' : basename(head.value).toLowerCase();
  // Carriers that run a script they are handed (review of 3.6.0, finding 7):
  // `trap 'SCRIPT' SIGSPEC`, `flock FILE -c 'SCRIPT'` / `flock FILE CMD …`,
  // `script [-q] -c 'SCRIPT' FILE`, `runuser … -c 'SCRIPT'` / `runuser … --
  // CMD …`. Each runs its payload through a shell, so it is assessed as one.
  const carried = carrierScript(name, words, start);
  if (carried !== null) return carried === undefined ? [] : [shellScript(carried)];
  // `npx -c "…"` / `npm exec -c "…"` runs its argument in a shell (fix round 2).
  const launcher = head === undefined ? '' : commandName(head.value);
  if (launcher === 'npx' || launcher === 'pnpx' || (launcher === 'npm' && words[firstNonFlag(words, start + 1)]?.value === 'exec')) {
    for (let i = start + 1; i < words.length; i += 1) {
      const v = words[i]?.value ?? '';
      if (v === '-c' || v === '--call') return words[i + 1] === undefined ? [] : [shellScript(words[i + 1]?.value ?? '')];
      if (v.startsWith('--call=')) return [shellScript(v.slice('--call='.length))];
      if (v === '--') break;
    }
  }
  if (head !== undefined && basename(head.value) === 'eval') {
    const script = words
      .slice(start + 1)
      .map((w) => w.value)
      .join(' ')
      .trim();
    return script.length > 0 ? [shellScript(script)] : [];
  }
  // PowerShell's `eval`: `iex "& { $(irm …) }"` runs its argument — quoted or
  // not — as PowerShell (review I1).
  if (launcher === 'wsl') {
    const script = wslScript(words, start);
    return script === undefined || script.trim() === '' ? [] : [shellScript(script)];
  }
  if (launcher === 'iex' || launcher === 'invoke-expression') {
    const args = words.slice(start + 1).filter((w, k) => !(k === 0 && !w.quoted && /^-c(?:o(?:m(?:m(?:a(?:n(?:d)?)?)?)?)?)?$/i.test(w.value)));
    const script = args
      .map((w) => w.value)
      .join(' ')
      .trim();
    // Only variables — `iex $s`, `iex $env:X` — run what the command line does not hold (review of 3.4.0, finding 6).
    if (args.length > 0 && args.every((w) => !w.quoted && /^\$(?:\{[^}]*\}|[\w:?]+)$/.test(w.value))) {
      return [{ text: script, powershell: true, iex: true, unread: true }];
    }
    return script.length > 0 ? [{ text: script, powershell: true, iex: true }] : [];
  }
  let sawShell = false;
  for (let i = start; i < words.length; i += 1) {
    const word = words[i];
    if (word === undefined) continue;
    const name = commandName(word.value);
    if (!word.quoted && (name === 'pwsh' || name === 'powershell')) {
      return powershellCommand(
        words.slice(i + 1).map((w) => w.value),
        name,
      )
        .filter((s) => s.trim().length > 0)
        .map((text) => ({ text, powershell: true }));
    }
    // A running flag, not a re-slice of the words before every `-…c` word:
    // that was quadratic (`-c -c -c …`, `find -exec`, `git -c`, `python
    // -c`: 64 KB took 15 s — fix round 3, I-2).
    if (!word.quoted && DASH_C.test(word.value) && sawShell) {
      const script = scriptAfterDashC(words, i + 1);
      return script === undefined ? [] : [shellScript(script)];
    }
    if (SHELLS.has(basename(word.value))) sawShell = true;
  }
  return [];
}

/**
 * The script a shell's `-c` runs: its first operand — the shell's other
 * options may come between (`bash -c -e 'cmd'`, `-o pipefail`), and `--`
 * ends them (review 8, item 8: `bash -c -- 'rm -rf /'` took `--` for the
 * script and was ok).
 */
function scriptAfterDashC(words: readonly ShellWord[], from: number): string | undefined {
  for (let j = from; j < words.length; j += 1) {
    const w = words[j];
    if (w === undefined) return undefined;
    if (!w.quoted && w.value === '--') return words[j + 1]?.value;
    if (!w.quoted && /^[-+][oO]$/.test(w.value)) {
      j += 1;
      continue;
    }
    if (!w.quoted && /^[-+][A-Za-z]+$/.test(w.value)) continue;
    return w.value;
  }
  return undefined;
}

/** What reads its stdin as a script, and in which language: a POSIX shell, PowerShell, or cmd.exe. */
type ReaderKind = 'shell' | 'powershell' | 'cmd';

/** A POSIX shell's options that take the next word as their value. */
const SHELL_VALUED = /^(?:[-+][oO]|--rcfile|--init-file)$/;

/**
 * Whether a command reads what it is fed as a script, and as which language
 * — a shell given no script of its own, past the runners in front of it
 * (`sudo`, `env`, `timeout 5`, `nice`, … and `busybox`): `bash`, `sh -`,
 * `bash -s -- x` (`-s`: the words after are the script's arguments), `bash
 * /dev/stdin`, `su root`; `source /dev/stdin`; PowerShell's `iex` /
 * `Invoke-Expression` with no argument and its host with `-Command -` or no
 * command at all; cmd.exe with no `/c` or `/k`. A shell with a `-c` script
 * (`nestedScripts`'s) or a script file reads its stdin as data. Before review
 * of 3.4.0, finding 6, only a shell's name followed by nothing but flags
 * counted: `| bash -s -- x`, `| env bash`, `| timeout 5 bash`, `| bash
 * /dev/stdin`, `| busybox sh`, `| iex` and `| cmd` were silent.
 */
function scriptReader(words: readonly ShellWord[]): ReaderKind | undefined {
  const plain = withoutRedirectWords(words);
  let at = resolveCommand(plain, PIPE_RUNNERS).index;
  if (commandName(plain[at]?.value ?? '') === 'busybox') at += 1;
  const name = commandName(plain[at]?.value ?? '');
  const args = plain.slice(at + 1);
  if (name === 'iex' || name === 'invoke-expression') return args.length === 0 ? 'powershell' : undefined;
  if (name === 'pwsh' || name === 'powershell') return powershellReadsStdin(args.map((w) => w.value)) ? 'powershell' : undefined;
  if (name === 'cmd') {
    // `cmd /k` (or `/c`) with no command after it runs what it reads, as a bare `cmd` does (review 12, finding 8).
    const run = args.findIndex((a) => /^\/[ck]$/i.test(cmdSwitch(a.value)));
    if (run >= 0 && run < args.length - 1) return undefined;
    return args.every((a) => /^\/[A-Za-z]+$/.test(cmdSwitch(a.value))) ? 'cmd' : undefined;
  }
  if (name === 'source' || name === '.') return STDIN_PATHS.has(args[0]?.value ?? '') ? 'shell' : undefined;
  // `xargs -I{} bash -c {}`, `xargs sh -c`: each line it reads IS a shell's
  // script (review 12, finding 8) — not `xargs -I{} sh -c 'gcc -c {}'`, where
  // the line is a word of a script the command line holds.
  if (name === 'xargs') {
    const rest = plain.slice(at);
    const p = resolveCommand(rest).index;
    const program = commandName(rest[p]?.value ?? '');
    if (!SCRIPT_SHELLS.has(program) && program !== 'su') return undefined;
    const c = rest.findIndex((w, k) => k > p && !w.quoted && DASH_C.test(w.value));
    if (c < 0) return undefined;
    const script = rest[c + 1]?.value;
    const replace = xargsReplacement(rest.slice(1, p).map((w) => w.value));
    return script === undefined || (replace !== undefined && script.trim() === replace) ? 'shell' : undefined;
  }
  // `script -q -c bash` runs a shell that reads the pipe; without `-c`, `script` runs the user's shell.
  if (name === 'script') {
    const c = args.findIndex((a) => /^(?:-[A-Za-z]*c|--command)$/.test(a.value) || a.value.startsWith('--command='));
    if (c < 0) return 'shell';
    const program = args[c]?.value.startsWith('--command=') ? args[c]?.value.slice('--command='.length) : args[c + 1]?.value;
    const inner = program === undefined ? undefined : splitShell(program).statements;
    const only = inner?.length === 1 && inner[0]?.commands.length === 1 ? inner[0]?.commands[0] : undefined;
    return only === undefined ? undefined : scriptReader(only);
  }
  if (!STDIN_SHELLS.has(name)) return undefined;
  if (name === 'su') return args.some((a) => /^(?:-[A-Za-z]*c|--command|--session-command)(?:=|$)/.test(a.value)) ? undefined : 'shell';
  for (let i = 0; i < args.length; i += 1) {
    const w = args[i];
    if (w === undefined) break;
    const v = w.value;
    if (w.quoted) return STDIN_PATHS.has(v) ? 'shell' : undefined;
    if (v === '-') return 'shell';
    if (v === '--') return args[i + 1] === undefined || STDIN_PATHS.has(args[i + 1]?.value ?? '') ? 'shell' : undefined;
    if (SHELL_VALUED.test(v)) {
      i += 1;
      continue;
    }
    if (/^-[A-Za-z]*c[A-Za-z]*$/.test(v)) return undefined;
    if (/^-[A-Za-z]*s[A-Za-z]*$/.test(v)) return 'shell';
    if (/^[-+]/.test(v)) continue;
    return STDIN_PATHS.has(v) ? 'shell' : undefined;
  }
  return 'shell';
}

/** Whether a command reads its stdin as a script ({@link scriptReader}). */
function readsScript(words: readonly ShellWord[]): boolean {
  return scriptReader(words) !== undefined;
}

/** A script fed to a reader: its text, or `opaque` (a decoder's output), or `unread` (any other output). */
interface FedScript {
  text: string;
  reader: readonly ShellWord[];
  opaque?: true;
  unread?: true;
  /** The language it is run as, when the reader's words do not say ({@link scriptReader}). */
  kind?: ReaderKind;
}

/** Whether a pipeline member downloads: what it feeds a reader is `remote-pipe-to-shell`'s, not unread text. */
function downloads(words: readonly ShellWord[]): boolean {
  return DOWNLOADERS.has(commandName(words[resolveCommand(words).index]?.value ?? ''));
}

/**
 * Text a statement hands a program to run, other than on its command line —
 * finding 4: text is data only until something feeds it to a program as its
 * *script*, and the existing heredoc-is-data behaviour (`git commit -F -
 * <<'EOF'`) must not change for any command that is not itself such a reader
 * (`reads`: a shell reading its stdin — {@link scriptReader} — or a bare
 * interpreter). Two shapes:
 *
 *   - `bash <<EOF … EOF` — the heredoc IS the script. `splitShell` captures
 *     the body on the statement (`heredocBodies`) precisely so this can
 *     recognise it; every other command's heredoc stays inert, as before.
 *   - `echo '…' | bash` / `printf '…' | sh` — a reader in the pipeline reads
 *     the output of the members before it as its script. `printf`'s own
 *     format-vs-arguments split is not modelled; the last argument is used,
 *     which is exactly right for the common single- or two-argument form
 *     (`printf '%s' 'rm -rf ~'`) and merely imprecise, not wrong, for anything
 *     fancier. What `cat` passes on counts too — `cat <<'EOF' | bash`, `cat
 *     <<< '…' | sh` — and, read as PowerShell (`powershell`), a string that
 *     begins the pipeline (`'…' | bash`). Output that cannot be read here
 *     (`cat f | bash`, `gc x.ps1 | iex`) is `unread`: never a silent ok
 *     (review of 3.4.0, finding 6).
 */
function fedScripts(statement: ShellStatement, reads: (words: readonly ShellWord[]) => boolean, powershell = false): FedScript[] {
  const scripts: FedScript[] = [];
  const first = statement.commands[0];
  if (statement.heredocBodies && first !== undefined && reads(first)) {
    pushAll(scripts, statement.heredocBodies.map((text) => ({ text, reader: first })));
  }
  let downloaded = false;
  for (let c = 1; c < statement.commands.length; c += 1) {
    downloaded ||= downloads(statement.commands[c - 1] ?? []);
    const reader = statement.commands[c];
    if (reader === undefined || !reads(reader)) continue;
    const fed = textOutputOf(statement.commands, { heredocs: statement.heredocBodies, powershell }, c);
    if (fed === 'opaque') scripts.push({ text: '', reader, opaque: true });
    else if (fed === undefined) {
      if (!downloaded) scripts.push({ text: '', reader, unread: true });
    } else if (fed.trim().length > 0) scripts.push({ text: fed.trim(), reader });
  }
  return scripts;
}

const RULE_UNREAD_SCRIPT: MatchedRule = {
  id: 'unread-script',
  level: 'warn',
  reason:
    'Runs text it could not read as a script (… | bash, gc x | iex, iex (…), [scriptblock]::Create($x), … | cmd) — what it runs was not assessed',
};

/** A statement's closing word for the group a pipe after it reads from: `)`, or a reserved word that ends a compound command. */
const GROUP_CLOSERS = /^(\}|done|fi|esac)\s*\|/;

/**
 * Scripts a reader takes from a group in front of its pipe (review of 3.4.0,
 * finding 6): `(echo '…') | bash`, `{ echo '…'; } | bash` — the group's
 * statements' output, as {@link textOutputOf} reads it; and any other
 * compound (`done | bash`, `fi | bash`) or output it cannot read, `unread`.
 * `(` at the start of the line leaves no statement, so a `)` group is the
 * statements back to the last one that ended with `(`, or the line's start.
 */
function groupFedScripts(statements: readonly ShellStatement[], powershell: boolean): FedScript[] {
  const out: FedScript[] = [];
  // Where the group a pipe may read from begins — after the last statement
  // that ended with `(`, at the last that began with `{` — never before the
  // last group already read: one pass, each statement read once.
  let afterOpen = 0;
  let brace = 0;
  let read = 0;
  for (let k = 0; k < statements.length; k += 1) {
    const statement = statements[k];
    if (statement === undefined) continue;
    const reader = statement.commands[0];
    const closer = GROUP_CLOSERS.exec(statement.masked)?.[1];
    const paren = /^\|/.test(statement.masked) && k > 0 && statements[k - 1]?.end === ')';
    if (reader !== undefined && (closer !== undefined || paren) && readsScript(reader)) {
      if (closer !== undefined && closer !== '}') out.push({ text: '', reader, unread: true });
      else {
        const texts: string[] = [];
        let unread = false;
        for (let j = Math.max(paren ? afterOpen : brace, read); j < k; j += 1) {
          const text = textOutputOf(statements[j]?.commands ?? [], { heredocs: statements[j]?.heredocBodies, powershell });
          if (typeof text === 'string') texts.push(text);
          else unread = true;
        }
        if (unread) out.push({ text: '', reader, unread: true });
        else if (texts.join('').trim() !== '') out.push({ text: texts.join('\n').trim(), reader });
      }
      read = k + 1;
    }
    if (/^\{/.test(statement.masked)) brace = k;
    if (statement.end === '(') afterOpen = k + 1;
  }
  return out;
}

/**
 * Scripts an output process substitution reads (review of 3.4.0, finding 6):
 * `… | tee >(bash)`, `echo '…' > >(bash)` — the `>(` ends statement `k` with
 * its `>`, and a reader that is the substitution's first command reads what
 * `tee` passes on or what the command writes there.
 */
function outputSubstitutionScripts(statements: readonly ShellStatement[], powershell: boolean): FedScript[] {
  const out: FedScript[] = [];
  for (let k = 0; k < statements.length - 1; k += 1) {
    const statement = statements[k];
    if (statement === undefined || statement.end !== '(' || !statement.masked.endsWith('>')) continue;
    const reader = statements[k + 1]?.commands[0];
    if (reader === undefined || !readsScript(reader)) continue;
    const members = statement.commands.map((words, c) => {
      if (c < statement.commands.length - 1) return words;
      let end = words.length;
      while (end > 0 && words[end - 1]?.value === '>') end -= 1;
      return words.slice(0, end);
    });
    const text = textOutputOf(members, { heredocs: statement.heredocBodies, powershell });
    if (text === 'opaque') out.push({ text: '', reader, opaque: true });
    else if (text === undefined) out.push({ text: '', reader, unread: true });
    else if (text.trim() !== '') out.push({ text: text.trim(), reader });
  }
  return out;
}

/**
 * The program `iex (…)` / `Invoke-Expression $(…)` runs (review of 3.4.0,
 * finding 6): the `(` ends statement `k` right after `iex` (or its
 * `-Command`, or the `$` of `$(`), and the statements up to the one the `)`
 * ends write it — a string there is the program; anything else (`gc x.ps1
 * -Raw`) is `unread`.
 */
function iexSubexpressionScripts(statements: readonly ShellStatement[]): FedScript[] {
  const out: FedScript[] = [];
  for (let k = 0; k < statements.length - 1; k += 1) {
    const statement = statements[k];
    const words = statement?.commands[statement.commands.length - 1];
    if (statement === undefined || words === undefined || statement.end !== '(') continue;
    const at = resolveCommand(words).index;
    const name = commandName(words[at]?.value ?? '');
    if (name !== 'iex' && name !== 'invoke-expression') continue;
    if (!words.slice(at + 1).every((w) => w.value === '$' || /^-c(?:o(?:m(?:m(?:a(?:n(?:d)?)?)?)?)?)?$/i.test(w.value))) continue;
    // One statement in the parentheses is read; more (`iex (a; b)`), or
    // another `(` inside, is not — and is unread, never silent.
    const body = statements[k + 1];
    const text = body?.end === ')' ? textOutputOf(body.commands, { heredocs: body.heredocBodies, powershell: true }) : undefined;
    if (typeof text === 'string') {
      if (text.trim() !== '') out.push({ text: text.trim(), reader: words, kind: 'powershell' });
    } else out.push({ text: '', reader: words, unread: true });
  }
  return out;
}

/** A script block made from text: `[scriptblock]::Create(`, and the engine's `InvokeScript(` / `NewScriptBlock(`. */
const SCRIPT_BLOCK_CALL =
  /\[\s*(?:System\s*\.\s*Management\s*\.\s*Automation\s*\.\s*)?scriptblock\s*\]\s*::\s*Create\s*\(|\$ExecutionContext\s*\.\s*(?:SessionState\s*\.\s*)?InvokeCommand\s*\.\s*(?:InvokeScript|NewScriptBlock)\s*\(|\.\s*AddScript\s*\(/gi;

/** The most script-block calls of one command read, and how far into each one's argument. */
const MAX_SCRIPT_BLOCK_CALLS = 32;
const MAX_SCRIPT_BLOCK_ARG = 16 * 1024;

/**
 * The program a PowerShell script block is made from (review of 3.4.0,
 * finding 6: `& ([scriptblock]::Create('Remove-Item -Recurse -Force C:\'))`
 * was silent): its argument when it is one string literal (`'…'` with `''`,
 * or `"…"`), else `unread`. A download there is
 * `powershell-iex-download`'s.
 */
function scriptBlockScripts(text: string): Array<string | 'unread'> {
  const out: Array<string | 'unread'> = [];
  let calls = 0;
  for (const m of text.matchAll(SCRIPT_BLOCK_CALL)) {
    if ((calls += 1) > MAX_SCRIPT_BLOCK_CALLS) {
      out.push('unread');
      break;
    }
    const from = m.index + m[0].length;
    const window = text.slice(from, from + MAX_SCRIPT_BLOCK_ARG);
    const literal = /^\s*(?:'((?:[^']|'')*)'|"((?:[^"`]|`.)*)")\s*\)/.exec(window);
    if (literal === null) out.push('unread');
    else out.push(literal[1] !== undefined ? literal[1].replace(/''/g, "'") : (literal[2] ?? '').replace(/`(.)/g, '$1'));
  }
  return out;
}

/** The most encoded text decoded to judge what it decodes to. */
const MAX_DECODED = 64 * 1024;

const RULE_DECODED_SCRIPT: MatchedRule = {
  id: 'decoded-script',
  level: 'warn',
  reason:
    'Runs decoded text as a script (base64 -d, xxd -r, gunzip, openssl … fed to a shell or an interpreter) — what it runs could not be assessed',
};

/** A command that turns encoded text back into something else: base64 (which is decoded here), or a decoder whose output is not read. */
function decoderOf(words: readonly ShellWord[]): 'base64' | 'other' | undefined {
  const at = resolveCommand(words).index;
  const name = commandName(words[at]?.value ?? '');
  const args = withoutRedirections(words.slice(at + 1));
  if (name === 'base64' || name === 'base32' || name === 'basenc') {
    if (!args.some((a) => /^(?:--decode|-[A-Za-z]*[dD][A-Za-z]*)$/.test(a))) return undefined;
    return name === 'base64' ? 'base64' : 'other';
  }
  if (name === 'openssl') {
    if (!args.includes('-d')) return undefined;
    return args.some((a) => a === 'base64' || a === '-base64' || a === '-a') && !args.some((a) => /^-(?:aes|des|chacha|bf|camellia|in$)/.test(a))
      ? 'base64'
      : 'other';
  }
  if (name === 'xxd') return args.some((a) => /^-[A-Za-z]*r/.test(a)) ? 'other' : undefined;
  if (name === 'gzip' || name === 'bzip2' || name === 'xz' || name === 'zstd' || name === 'lz4') {
    return args.some((a) => a === '--decompress' || /^-[A-Za-z]*d/.test(a)) ? 'other' : undefined;
  }
  return ['gunzip', 'zcat', 'bunzip2', 'bzcat', 'unxz', 'xzcat', 'unzstd', 'zstdcat', 'uudecode', 'rev'].includes(name) ? 'other' : undefined;
}

/** `text` as base64, decoded to UTF-8 — or `undefined` when it is not base64 at all. */
function decodeBase64(text: string): string | undefined {
  const compact = text.replace(/\s+/g, '');
  if (compact.length === 0 || compact.length > MAX_DECODED || !/^[A-Za-z0-9+/=_-]+$/.test(compact)) return undefined;
  return Buffer.from(compact.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
}

/** A here-string's text in `words` (`<<< 'text'`, `<<<text`), when it has one. */
function hereStringText(words: readonly ShellWord[]): string | undefined {
  for (let i = 0; i < words.length; i += 1) {
    const w = words[i];
    if (w === undefined || !w.value.startsWith('<<<') || w.redirectAt?.[0] !== 0) continue;
    const inline = w.value.slice(3);
    return inline.length > 0 ? inline : words[i + 1]?.value;
  }
  return undefined;
}

/**
 * What a pipeline writes to its stdout, as far as the command line says (review
 * 8, item 8): `echo`'s words, `printf`'s last argument, and base64 decoded
 * from either (or from a `<<<` here-string) — `echo cm0gLXJmIC8K | base64 -d`
 * writes `rm -rf /`. `opaque` when a decoder writes text that cannot be read
 * here (`base64 -d payload.b64`, `xxd -r`, `gunzip`); `undefined` for anything
 * else (`cat f`), which is no different from running a file.
 *
 * What a member only passes on is read through it (review of 3.3.0: these were
 * silent): `cat` with no file to read — its here-string (`cat <<< '…'`), the
 * statement's heredoc (`cat <<'EOF' | bash`; a heredoc's operator leaves no
 * word, so the statement's bodies are taken as `cat`'s), or the member before
 * it — and `tee`, which copies its input to stdout. Read as PowerShell
 * (`feed.powershell`), a pipeline that begins with a string writes it:
 * `'rm -rf /' | bash`.
 *
 * Of the members before `end` (all of them by default) — a reader in the
 * middle of a pipeline reads the members before it (review of 3.4.0, finding
 * 6) — walked back from the last, never sliced or recursed into, so that a
 * pipeline of any length costs one pass.
 */
function textOutputOf(
  members: readonly ShellWord[][],
  feed: { heredocs?: readonly string[] | undefined; powershell?: boolean } = {},
  end = members.length,
): string | 'opaque' | undefined {
  // The base64 decoders met on the way back, the last member's first.
  let decodes = 0;
  const decoded = (text: string): string | 'opaque' => {
    let t = text;
    for (let k = 0; k < decodes; k += 1) {
      const d = decodeBase64(t);
      if (d === undefined) return 'opaque';
      t = d;
    }
    return t;
  };
  for (let i = end - 1; i >= 0; i -= 1) {
    const last = members[i];
    if (last === undefined) return undefined;
    const lone = last.length === 1 ? last[0] : undefined;
    if (feed.powershell === true && i === 0 && lone !== undefined && lone.quoted) return decoded(lone.value);
    const at = resolveCommand(last).index;
    const name = commandName(last[at]?.value ?? '');
    const args = withoutRedirections(last.slice(at + 1));
    if (name === 'echo') return decoded(args.filter((a, k) => !(k === 0 && /^-[neE]+$/.test(a))).join(' '));
    if (name === 'printf') return decoded(args[args.length - 1] ?? '');
    if (!((name === 'cat' && args.every((a) => a === '-')) || name === 'tee')) {
      const decoder = decoderOf(last);
      if (decoder === undefined) return decodes > 0 ? 'opaque' : undefined;
      if (decoder === 'other') return 'opaque';
      decodes += 1;
    }
    // What this member reads: its here-string, the statement's heredoc, or the member before it.
    const here = hereStringText(last);
    if (here !== undefined) return decoded(here);
    if (feed.heredocs !== undefined && feed.heredocs.length > 0) return decoded(feed.heredocs.join('\n'));
  }
  return decodes > 0 ? 'opaque' : undefined;
}

/**
 * What a `$( … )` or `` `…` `` substitution that IS the whole of `script` writes
 * ({@link textOutputOf}) — `bash -c "$(echo … | base64 -d)"` runs it. Only a
 * substitution of one statement is read.
 */
function substitutionOutput(script: string): string | 'opaque' | undefined {
  const s = script.trim();
  const inner = s.startsWith('$(') && s.endsWith(')') ? s.slice(2, -1) : s.startsWith('`') && s.endsWith('`') ? s.slice(1, -1) : undefined;
  if (inner === undefined || inner.length > MAX_DECODED) return undefined;
  const statements = splitShell(inner).statements;
  const only = statements.length === 1 ? statements[0] : undefined;
  return only === undefined ? undefined : textOutputOf(only.commands.map(expandWords));
}

/**
 * Scripts a shell (or `source` / `.`) reads from a process substitution
 * (review 8, item 8): `bash <(echo 'rm -rf /')`, `source <(echo … | base64
 * -d)`. The `<(` ends statement `k` with the reader's `<`; the statements up to
 * the one the `)` ends are what it runs. A download there is
 * `process-substitution-remote-fetch`'s.
 */
function processSubstitutionScripts(statements: readonly ShellStatement[]): Array<string | 'opaque'> {
  const out: Array<string | 'opaque'> = [];
  for (let k = 0; k < statements.length - 1; k += 1) {
    const statement = statements[k];
    if (statement === undefined || statement.end !== '(' || !statement.masked.endsWith('<')) continue;
    const words = statement.commands[statement.commands.length - 1];
    const lastWord = words?.[words.length - 1];
    if (words === undefined || lastWord === undefined || lastWord.value !== '<' || lastWord.redirectAt?.[0] !== 0) continue;
    const head = words.slice(0, -1);
    const at = resolveCommand(head).index;
    const name = commandName(head[at]?.value ?? '');
    const shell = STDIN_SHELLS.has(name) && scriptOperand(head, at, name) === undefined && !head.some((w) => !w.quoted && DASH_C.test(w.value));
    if (!shell && name !== 'source' && name !== '.') continue;
    const texts: string[] = [];
    let opaque = false;
    for (let j = k + 1; j < statements.length; j += 1) {
      const body = statements[j];
      if (body === undefined) break;
      const text = textOutputOf(body.commands.map(expandWords), { heredocs: body.heredocBodies });
      if (text === 'opaque') opaque = true;
      else if (text !== undefined) texts.push(text);
      if (body.end === ')') break;
    }
    if (opaque) out.push('opaque');
    if (texts.length > 0) out.push(texts.join('\n'));
  }
  return out;
}

/**
 * The body of a `$( … )` command substitution starting just after its `$(` at
 * `from`, and the index after its `)`. Parens are balanced, and a `)` inside a
 * quoted span or escaped does not close it (`$(echo ")")`).
 */
function scanSubstitutionBody(command: string, from: number): { body: string; next: number } {
  let depth = 1;
  let quote = '';
  for (let i = from; i < command.length; i += 1) {
    const ch = command.charAt(i);
    if (quote !== '') {
      if (quote === '"' && ch === '\\') i += 1;
      else if (ch === quote) quote = '';
      continue;
    }
    if (ch === '\\') i += 1;
    else if (ch === "'" || ch === '"') quote = ch;
    else if (ch === '(') depth += 1;
    else if (ch === ')') {
      depth -= 1;
      if (depth === 0) return { body: command.slice(from, i), next: i + 1 };
    }
  }
  return { body: command.slice(from), next: command.length };
}

/**
 * Collects the command substitutions inside the double-quoted string that
 * begins just after the `"` at `from` — `$( … )` and `` `…` `` — appending
 * each body to `out`, and returns the index after the closing `"`. A `\$`,
 * `` \` `` or `\\` is a literal, and `$((` is arithmetic (no command runs).
 */
function scanDoubleQuotedSubstitutions(command: string, from: number, out: string[]): number {
  let i = from;
  while (i < command.length) {
    const ch = command.charAt(i);
    if (ch === '\\') {
      i += 2;
      continue;
    }
    if (ch === '"') return i + 1;
    if (ch === '`') {
      let end = i + 1;
      while (end < command.length && !(command.charAt(end) === '`' && command.charAt(end - 1) !== '\\')) end += 1;
      out.push(command.slice(i + 1, end));
      i = end + 1;
      continue;
    }
    if (ch === '$' && command.charAt(i + 1) === '(' && command.charAt(i + 2) !== '(') {
      const sub = scanSubstitutionBody(command, i + 2);
      out.push(sub.body);
      i = sub.next;
      continue;
    }
    i += 1;
  }
  return command.length;
}

/**
 * The command substitutions a command runs from INSIDE a double-quoted string
 * (review of 3.6.0, finding 4): `echo "$(rm -rf /)"`, `: "$(…)"`, `` x="`…`"
 * ``. `splitShell` masks a double-quoted span to one space, so a `$( … )` or
 * backtick in it was never a statement and the body — which the shell runs
 * regardless of the quotes — went unassessed, defeating every block rule. An
 * UNQUOTED substitution is already a statement of its own (`(` / backtick is a
 * boundary), and a single-quoted one never runs, so only the double-quoted
 * ones are collected here; nested ones are reached by recursing on each body.
 */
function quotedSubstitutions(command: string): string[] {
  const out: string[] = [];
  let i = 0;
  while (i < command.length) {
    const ch = command.charAt(i);
    if (ch === '\\') i += 2;
    else if (ch === "'") {
      const end = command.indexOf("'", i + 1);
      i = end < 0 ? command.length : end + 1;
    } else if (ch === '"') i = scanDoubleQuotedSubstitutions(command, i + 1, out);
    else i += 1;
  }
  return out;
}

// ─────────────────────────────────────────────── download, then run it

/** Commands that fetch a URL: `curl`, `wget` and PowerShell's web cmdlets and their aliases. */
const DOWNLOADERS = new Set(['curl', 'wget', 'iwr', 'irm', 'invoke-webrequest', 'invoke-restmethod']);

/**
 * The runners a pipeline member is looked through to find what reads the
 * pipe — never `xargs`, `watch` or cmd's `start`, which do not hand the
 * command their stdin as a script.
 */
const PIPE_RUNNERS = new Set(['sudo', 'doas', 'env', 'command', 'exec', 'builtin', 'nohup', 'nice', 'time', 'timeout', 'setsid', 'stdbuf']);

/** Shells that run what arrives on their stdin. */
const STDIN_SHELLS = new Set([...SHELLS, 'fish', 'csh', 'tcsh']);

/** The paths through which `source` / `.` read their stdin. */
const STDIN_PATHS = new Set(['/dev/stdin', '/dev/fd/0', '/proc/self/fd/0']);

const RULE_PIPE_TO_SHELL: MatchedRule = {
  id: 'remote-pipe-to-shell',
  level: 'block',
  reason: 'Pipes a downloaded script directly into a shell (curl|wget … | sh/bash)',
};

const RULE_FETCH_EXEC: MatchedRule = {
  id: 'remote-pipe-to-shell',
  level: 'block',
  reason: 'Executes the output of a remote download (curl/wget via $(…) or `…`)',
};

const RULE_IEX_DOWNLOAD: MatchedRule = {
  id: 'powershell-iex-download',
  level: 'block',
  reason: 'Downloads and executes remote code via Invoke-Expression',
};

const RULE_DOWNLOAD_RUN: MatchedRule = {
  id: 'download-then-run',
  level: 'block',
  reason: 'Downloads a file and runs it in the same command (DownloadFile / -OutFile, then &, ., Start-Process, …)',
};

/** The same, for a POSIX download — named for what it is (review round 3, item 7). */
const RULE_POSIX_DOWNLOAD_RUN: MatchedRule = {
  id: 'download-then-run',
  level: 'block',
  reason:
    'Downloads a file (curl -o / -O, wget, > file) and runs it in the same command (sh f, ./f, source f, python3 f, …) ' +
    'with no checksum or signature check of that file in between',
};

/**
 * Whether a command reads its stdin as a script: a shell, `source` / `.` of
 * `/dev/stdin`, or an interpreter given no program of its own — `python3 -`,
 * bare `node`, `perl`, `ruby`, `php` (review round 2, ruling 2). An
 * interpreter handed its program (`python3 -c '…'`, `python3 script.py`,
 * `python3 -m json.tool`, `perl -ne '…'`) reads stdin as data.
 */
function readsStdinAsScript(words: readonly ShellWord[], at: number): boolean {
  const name = commandName(words[at]?.value ?? '');
  if (STDIN_SHELLS.has(name)) return true;
  if ((name === 'source' || name === '.') && STDIN_PATHS.has(words[at + 1]?.value ?? '')) return true;
  if (name === 'xargs') return xargsRunsStdin(words, at);
  const plain = withoutRedirectWords(words.slice(at));
  if (RUN_WRAPPERS.has(name) && words[at + 1]?.value === 'run') return runWrapperReadsStdin(plain, 2, name === 'uv');
  // `uvx python -`, `uv tool run python -` (review 3.0 wave 2, round 2).
  if (name === 'uvx') return runWrapperReadsStdin(plain, 1, false);
  if (name === 'uv' && words[at + 1]?.value === 'tool' && words[at + 2]?.value === 'run') return runWrapperReadsStdin(plain, 3, false);
  return isInterpreter(name) && isBareInterpreterStdin(plain);
}

/** `uv run`, `uvx`, `pixi run`, `poetry run`, `conda run` … options that take the next word as their value. */
const RUN_WRAPPER_VALUED = new Set([
  '--with', '--with-editable', '--with-requirements', '-p', '--python', '--project', '--directory', '--env-file',
  '--extra', '--group', '--only-group', '--no-group', '--package', '--index', '--default-index', '-i', '--index-url',
  '--extra-index-url', '-f', '--find-links', '--config-file', '--cache-dir', '-C', '--config-setting', '-n', '--name',
  '--prefix', '--cwd', '-e', '--environment', '--from', '--manifest-path',
]);

/**
 * `uv run python -`, `poetry run python`, `uv run -` (review 3.0, wave 2), and
 * `pixi run python -`, `uvx python -` (round 2): a wrapper whose program — the
 * first word at `from` past the wrapper's own options — is an interpreter
 * reading its program from stdin, or, where `dashIsProgram` (`uv run`), `-`
 * itself: `uv run -` runs a Python script read from stdin. `uv run python
 * script.py` and `uv run parse.py -` read stdin as data.
 */
function runWrapperReadsStdin(words: readonly ShellWord[], from: number, dashIsProgram: boolean): boolean {
  for (let i = from; i < words.length; i += 1) {
    const v = words[i]?.value ?? '';
    if (v === '-') return dashIsProgram;
    if (v === '--') continue;
    if (v.startsWith('-')) {
      i += !v.includes('=') && RUN_WRAPPER_VALUED.has(v) ? 1 : 0;
      continue;
    }
    return isInterpreter(interpreterName(v)) && isBareInterpreterStdin(words.slice(i));
  }
  return false;
}

/**
 * `xargs [options] sh -c` with no script after `-c` (review round 3, item 2):
 * xargs appends what it reads on stdin, so that text becomes the `-c` script —
 * `curl … | xargs -0 sh -c` runs the download. Also an interpreter's `-c` /
 * `-e` left without its program text. And (review 3.0, wave 2) a `-c` script
 * or program text holding xargs's replacement string (`-I{}`, `-i`,
 * `--replace`, BSD's `-J`): `xargs -I{} sh -c '{}'` writes each line it reads
 * into the program — `sh -c 'echo "$0"'`, where the line is an argument, does
 * not.
 */
function xargsRunsStdin(words: readonly ShellWord[], at: number): boolean {
  return xargsProgram(words, at) !== undefined;
}

/**
 * How xargs makes its input a program, for {@link xargsRunsStdin}: `appended`
 * as the `-c` script or program text itself, `replaced` into it through the
 * replacement string — which has a safe form the deny can name (review 3.0
 * wave 2, round 2: the line as an argument, `sh -c '… "$1"' _ {}`).
 */
function xargsProgram(words: readonly ShellWord[], at: number): 'appended' | 'replaced' | undefined {
  const rest = withoutRedirectWords(words.slice(at));
  const i = resolveCommand(rest).index;
  const name = commandName(rest[i]?.value ?? '');
  const last = rest[rest.length - 1]?.value ?? '';
  if (i >= rest.length - 1) return undefined;
  const replace = xargsReplacement(rest.slice(1, i).map((w) => w.value));
  if (SCRIPT_SHELLS.has(name) || name === 'su') {
    if (DASH_C.test(last)) return 'appended';
    const c = rest.findIndex((w, k) => k > i && !w.quoted && DASH_C.test(w.value));
    const script = c < 0 ? undefined : rest[c + 1]?.value;
    if (script === undefined) return undefined;
    if (replace !== undefined && script.includes(replace)) return 'replaced';
    return runsItsArguments(script) ? 'appended' : undefined;
  }
  if (!isInterpreter(name)) return undefined;
  if (/^(?:-[A-Za-z]*[ceE]|-r|--eval|--print|-p)$/.test(last)) return 'appended';
  return replace !== undefined && inlineCode(rest, i).some((code) => code.includes(replace)) ? 'replaced' : undefined;
}

/** A positional parameter: `$0`–`$9`, `$@`, `$*`, `${1}`. */
const POSITIONAL = /\$(?:[0-9@*]|\{[0-9@*]\})/;

/**
 * A `-c` script that runs its own arguments (review 3.0 wave 2, round 2): one
 * of its commands is `eval` of a positional parameter (`eval "$0"`, `eval
 * $1`), or is named by one (`"$0"`, `$@`). xargs hands each line it reads to
 * such a script as an argument, and the script runs it — `sh -c 'echo "$0"'`
 * only prints it.
 */
function runsItsArguments(script: string): boolean {
  if (!POSITIONAL.test(script)) return false;
  return splitShell(script).statements.some((st) =>
    st.commands.some((words) => {
      const at = resolveCommand(words).index;
      const head = words[at]?.value ?? '';
      if (POSITIONAL.test(head) && head.replace(POSITIONAL, '') === '') return true;
      return basename(head) === 'eval' && words.slice(at + 1).some((w) => POSITIONAL.test(w.value));
    }),
  );
}

/**
 * The string xargs replaces with each line it reads, from its own options:
 * `-I R` / `-IR`, `-i` / `-iR` and `--replace[=R]` (`{}` when none is given),
 * BSD's `-J R`; none without one of them.
 */
function xargsReplacement(options: readonly string[]): string | undefined {
  let replace: string | undefined;
  for (let k = 0; k < options.length; k += 1) {
    const o = options[k] ?? '';
    if (o === '--replace') replace = '{}';
    else if (o.startsWith('--replace=')) replace = o.slice('--replace='.length) || '{}';
    else if (/^-[^-]/.test(o)) {
      for (let c = 1; c < o.length; c += 1) {
        const letter = o.charAt(c);
        const attached = o.slice(c + 1);
        if (letter === 'I' || letter === 'J') {
          replace = attached !== '' ? attached : options[(k += 1)];
          break;
        }
        if (letter === 'i') {
          replace = attached !== '' ? attached : '{}';
          break;
        }
        if ('adELnPs'.includes(letter)) {
          if (attached === '') k += 1;
          break;
        }
      }
    }
  }
  return replace === '' ? undefined : replace;
}

/**
 * An interpreter whose program is a process substitution that downloads:
 * `python3 <(curl …)`, `node --max-old-space-size 4096 <(wget …)`. The `<(`
 * ends statement `k` (`(` is a statement boundary), so its command's last word
 * is the `<` and statement `k + 1` is what the substitution runs; the
 * substitution is the program exactly when, without it, the interpreter has
 * no program at all ({@link interpreterProgram}) — `python3 process.py <(curl
 * …)` hands the download to a script as data.
 */
function interpreterRunsFetch(statements: readonly ShellStatement[], k: number): boolean {
  const statement = statements[k];
  if (statement === undefined || !statement.masked.endsWith('<')) return false;
  const words = statement.commands[statement.commands.length - 1];
  const lastWord = words?.[words.length - 1];
  if (words === undefined || lastWord === undefined || lastWord.value !== '<' || lastWord.redirectAt?.[0] !== 0) return false;
  const next = statements[k + 1]?.commands[0];
  if (next === undefined || !['curl', 'wget'].includes(commandName(next[resolveCommand(next).index]?.value ?? ''))) return false;
  const head = words.slice(0, -1);
  const at = resolveCommand(head).index;
  return interpreterProgram(head, at).kind === 'none';
}

const RULE_PROCESS_FETCH: MatchedRule = {
  id: 'process-substitution-remote-fetch',
  level: 'block',
  reason: 'Executes a downloaded script via process substitution (bash <(curl …))',
};

/**
 * `curl … | bash`, judged on the pipeline's structure rather than its text
 * (review I1): a member that downloads, and after it a member whose command —
 * resolved through `VAR=x`, `env`, `command`, `exec`, `sudo` and its options,
 * quotes and an absolute path — is a shell. The text rule only knew a bare
 * shell name right after the `|` (and `sudo`), so `| /bin/bash`, `| env
 * PNPM_VERSION=10 sh -`, `| "bash"` and `| command bash` all ran unassessed.
 * xargs writing the download into its program through the replacement string
 * gets a reason of its own, which names the safe form.
 */
function pipesDownloadIntoShell(statement: ShellStatement): MatchedRule | null {
  let downloaded = false;
  for (const words of statement.commands) {
    const at = resolveCommand(words, PIPE_RUNNERS).index;
    if (downloaded && readsStdinAsScript(words, at)) {
      const xargs = commandName(words[at]?.value ?? '') === 'xargs' ? xargsProgram(words, at) : undefined;
      return xargs === 'replaced' ? RULE_XARGS_REPLACED : RULE_PIPE_TO_SHELL;
    }
    if (DOWNLOADERS.has(commandName(words[at]?.value ?? ''))) downloaded = true;
  }
  return null;
}

/**
 * A download piped into a subshell that runs a shell (review of 3.6.0, finding
 * 5): `curl … | (sh)`, `wget … | (bash -s)` — the `(` ends the piping
 * statement, so the shell inside it is not a member of that pipeline and
 * `pipesDownloadIntoShell` never saw it. Statement `k` pipes (its masked text
 * ends with `|`) into a group it opens (`end === '('`), and a downloader runs
 * somewhere in it; a command in the subshell, up to its matching `)`, reads
 * its stdin as a script.
 */
function pipesDownloadIntoSubshell(statements: readonly ShellStatement[]): MatchedRule | null {
  for (let k = 0; k < statements.length - 1; k += 1) {
    const statement = statements[k];
    if (statement === undefined || statement.end !== '(' || !statement.masked.endsWith('|')) continue;
    if (!statement.commands.some((words) => DOWNLOADERS.has(commandName(words[resolveCommand(words, PIPE_RUNNERS).index]?.value ?? '')))) continue;
    let depth = 1;
    for (let j = k + 1; j < statements.length && depth > 0; j += 1) {
      const body = statements[j];
      if (body === undefined) break;
      const first = body.commands[0];
      if (first !== undefined && readsStdinAsScript(first, resolveCommand(first, PIPE_RUNNERS).index)) return RULE_PIPE_TO_SHELL;
      if (body.end === '(') depth += 1;
      else if (body.end === ')') depth -= 1;
    }
  }
  return null;
}

/**
 * The command substitution `eval` runs across the `(` or backtick that split
 * it from `eval` (review of 3.6.0, finding 5): `eval $(curl …)`, `` eval
 * `curl …` `` — the quoted `eval "$(curl …)"` already blocks (the quote keeps
 * it one word), these did not. Statement `k`'s last command is `eval` ending
 * with `$(` (its last word the `$`, `end === '('`) or with a backtick; the
 * body is the statements up to the matching close. `eval` runs that body's
 * OUTPUT, so a download there is the downloaded script it runs
 * ({@link isBareRemoteFetch}'s hazard), and anything else is read as the text
 * it writes ({@link substitutionOutput}).
 */
function evalSubstitutionBodies(statements: readonly ShellStatement[]): ShellStatement[][] {
  const out: ShellStatement[][] = [];
  for (let k = 0; k < statements.length - 1; k += 1) {
    const statement = statements[k];
    if (statement === undefined) continue;
    const words = statement.commands[statement.commands.length - 1];
    if (words === undefined || basename(words[resolveCommand(words).index]?.value ?? '') !== 'eval') continue;
    const backtick = statement.end === '`';
    const dollarParen = statement.end === '(' && words[words.length - 1]?.value === '$';
    if (!backtick && !dollarParen) continue;
    const body: ShellStatement[] = [];
    let depth = 1;
    for (let j = k + 1; j < statements.length; j += 1) {
      const b = statements[j];
      if (b === undefined) break;
      body.push(b);
      if (backtick) {
        if (b.end === '`') break;
      } else if (b.end === '(') depth += 1;
      else if (b.end === ')') {
        depth -= 1;
        if (depth === 0) break;
      }
    }
    if (body.length > 0) out.push(body);
  }
  return out;
}

/** A download written into xargs's program through its replacement string — and how to hand it over as data. */
const RULE_XARGS_REPLACED: MatchedRule = {
  id: 'xargs-download-program',
  level: 'block',
  reason:
    "Writes downloaded text into a program through xargs's replacement string (xargs -I{} sh -c '… {} …'), " +
    `where it runs as code; hand each line over as an argument instead: xargs -I{} sh -c '… "$1"' _ {} ` +
    '(sys.argv / process.argv for an interpreter)',
};

/** `bash <<< "$(curl …)"`, `source /dev/stdin <<< "$(wget …)"`: a download handed to a shell as a here-string. */
function hereStringFetchIntoShell(words: readonly ShellWord[], at: number): boolean {
  if (!readsStdinAsScript(words, at) && !['source', '.'].includes(commandName(words[at]?.value ?? ''))) return false;
  for (let i = at + 1; i < words.length; i += 1) {
    const w = words[i];
    if (w === undefined || !w.value.startsWith('<<<') || w.redirectAt?.[0] !== 0) continue;
    const inline = w.value.slice(3);
    if (isBareRemoteFetch(inline.length > 0 ? inline : (words[i + 1]?.value ?? ''))) return true;
  }
  return false;
}

/** A download in PowerShell program text: a web cmdlet, or a `WebClient` / `HttpClient` fetch. */
const PS_DOWNLOAD =
  /(?<![\w$-])(?:irm|iwr|invoke-restmethod|invoke-webrequest|curl|wget|start-bitstransfer)(?![\w-])|\.\s*(?:downloadstring|downloaddata|downloadfile|openread|getstringasync|getbytearrayasync|getstreamasync)\s*\(/i;

/**
 * The tokens {@link powershellDownloadExecution} reads, one named group each:
 *
 *   - `run` — what runs its argument as PowerShell: `iex` / `Invoke-Expression`
 *     (a command only as a word of its own — never a file's name or extension,
 *     `x.iex`: review round 2), and the script-block builders and runners
 *     `[scriptblock]::Create(…)`, `$ExecutionContext.InvokeCommand.InvokeScript(…)`
 *     / `.NewScriptBlock(…)` and `-ScriptBlock (…)` (review round 3: Microsoft's
 *     dotnet-install one-liner is `&([scriptblock]::Create((iwr …)))`);
 *   - `dl` — a download;
 *   - `ref`, and `assign` after it — a variable read, or assigned, so that
 *     `$s = irm …; iex $s` is seen — as `$s`, `${s}` or `$script:s`, one
 *     variable ({@link psVariable}). One group for both, so a run of unclosed
 *     `${` is scanned for its capped name once per `$`, not twice;
 *   - the other ways a command puts a value in a variable, or reads one back
 *     (review 3.0, wave 2): `setvar` — `Set-Variable` / `New-Variable` (`sv`,
 *     `nv`), whose name {@link variableNamed} reads; `outvar` — the common
 *     `-OutVariable` (`-ov`) of any cmdlet, with its name; `tee` and `teevar`
 *     — `Tee-Object` (`tee`) and its `-Variable`; `getvar` — `Get-Variable`
 *     (`gv`), a read of the variable it names;
 *   - parentheses, pipes and statement separators.
 */
const PS_EXEC_TOKENS =
  /(?<run>(?<![\w$.\\/-])(?:iex|invoke-expression)(?![\w.-])|\[\s*(?:(?:system\s*\.\s*)?management\s*\.\s*automation\s*\.\s*)?scriptblock\s*\]\s*::\s*create\b|\.\s*(?:invokescript|newscriptblock)\b|(?<![\w-])-scriptblock\b)|(?<dl>(?<![\w$-])(?:irm|iwr|invoke-restmethod|invoke-webrequest|curl|wget)(?![\w-])|\.\s*(?:downloadstring|downloaddata|openread|getstringasync|getbytearrayasync|getstreamasync)\b)|(?<ref>\$(?:\{[^}\n]{0,128}\}|[\w:]+))(?<assign>\s*\+?=(?!=))?|(?<setvar>(?<![\w$.\\/-])(?:set-variable|new-variable|sv|nv)(?![\w.-]))|(?<getvar>(?<![\w$.\\/-])(?:get-variable|gv)(?![\w.-]))|(?<tee>(?<![\w$.\\/-])(?:tee-object|tee)(?![\w.-]))|(?<outvar>(?<![\w-])-(?:ov|outv(?:a(?:r(?:i(?:a(?:b(?:le?)?)?)?)?)?)?)(?![\w-])(?:(?:[ \t]*:[ \t]*|[ \t]+)\+?(?<outname>[A-Za-z_][\w:]*))?)|(?<teevar>(?<![\w-])-v(?:a(?:r(?:i(?:a(?:b(?:le?)?)?)?)?)?)?(?![\w-])(?:(?:[ \t]*:[ \t]*|[ \t]+)(?<teename>[A-Za-z_][\w:]*))?)|&&|\|\||[()|;\n]/gi;

/**
 * A variable as one name: `$` and the name, lower-cased, without braces or a
 * scope — `${Script:S}`, `$script:s` and `$s` are all `$s` (`$env:x` stays
 * itself: an environment variable is another variable).
 */
function psVariable(spelled: string): string {
  let v = spelled.toLowerCase();
  if (v.startsWith('$')) v = v.slice(1);
  if (v.startsWith('{') && v.endsWith('}')) v = v.slice(1, -1);
  return `$${v.replace(/^(?:global|script|local|private|using|variable):/, '')}`;
}

/** `Set-`, `New-` and `Get-Variable` parameters that take a value, other than `-Name`. */
const VARIABLE_VALUED = ['value', 'scope', 'option', 'description', 'include', 'exclude', 'visibility'];

/** How far {@link variableNamed} reads for a name, and how many names one assessment reads. */
const VARIABLE_NAME_WINDOW = 256;
const MAX_VARIABLE_NAMES = 256;

/**
 * The variable a `Set-Variable` / `New-Variable` / `Get-Variable` whose name
 * ends at `from` names, as {@link psVariable} spells it: `-Name x`, `-Name:x`,
 * `-n x`, or else its first positional argument (a named `-Name` binds first,
 * wherever it stands). `*` — any variable — when the name cannot be read: a
 * quoted one (masked in this text), one computed by an expression, or none
 * within the next {@link VARIABLE_NAME_WINDOW} characters.
 */
function variableNamed(text: string, from: number): string {
  const end = Math.min(text.length, from + VARIABLE_NAME_WINDOW);
  let named: string | undefined;
  let positional: string | undefined;
  let wantName = false;
  let skipValue = false;
  let i = from;
  while (i < end) {
    const c = text.charAt(i);
    if (c === ' ' || c === '\t') {
      i += 1;
      continue;
    }
    if (c === ';' || c === '|' || c === '\n' || c === '&' || c === ')') break;
    // One word: to a blank or a separator — a parenthesised value whole.
    let j = i + 1;
    if (c === '(') {
      for (let depth = 1; j < end && depth > 0; j += 1) {
        const d = text.charAt(j);
        if (d === '(') depth += 1;
        else if (d === ')') depth -= 1;
      }
    } else {
      while (j < end && !' \t;|&()\n'.includes(text.charAt(j))) j += 1;
    }
    const word = text.slice(i, j);
    i = j;
    if (wantName) {
      wantName = false;
      named = /^[$\w{}:]+$/.test(word) ? psVariable(word) : '*';
      continue;
    }
    if (skipValue) {
      skipValue = false;
      continue;
    }
    const param = /^-([A-Za-z]+)(?::(.*))?$/.exec(word);
    if (param !== null) {
      const p = (param[1] ?? '').toLowerCase();
      const inline = param[2];
      if ('name'.startsWith(p)) {
        if (inline === undefined) wantName = true;
        else named = /^[$\w{}:]+$/.test(inline) ? psVariable(inline) : '*';
      } else if (inline === undefined && p.length >= 2 && VARIABLE_VALUED.some((v) => v.startsWith(p))) skipValue = true;
      continue;
    }
    positional ??= /^[\w{}:]+$/.test(word) ? psVariable(word) : '*';
  }
  return named ?? positional ?? '*';
}

/**
 * `Invoke-Expression` over a download, on the masked command text (review I1):
 * `iex ((New-Object Net.WebClient).DownloadString(…))` (Chocolatey's official
 * installer), `iex $wc.DownloadString(…)`, and a download piped into `iex`
 * from inside a group — `(irm …) | iex` — where the `(` that ends a statement
 * everywhere else had separated the download from the pipe. One pass over the
 * tokens, so linear: a stack says which open parentheses hold `iex`'s
 * argument, and a download seen in the current `;`/newline segment is armed by
 * the next `|` for an `iex` after it.
 *
 * `text` is the command's {@link ShellSplit.interpolatedCommand}: a quoted
 * span is masked, except for the variables a double-quoted one interpolates —
 * `$b = "$a"` copies `$a`, and `iex "$s"` runs `$s`.
 */
function powershellDownloadExecution(text: string): boolean {
  if (!/iex|invoke-expression|scriptblock|invokescript/i.test(text)) return false;
  const opens: boolean[] = [];
  let inIex = 0;
  let pendingIex = false;
  let downloaded = false;
  let piped = false;
  /** The variables being assigned in this `;`/newline segment, and the variables that hold a download. */
  let assigning: string[] = [];
  const tainted = new Set<string>();
  /** In a `Tee-Object` command, whose `-Variable` receives what it is piped. */
  let inTee = false;
  /** The `)` just read closed iex's parenthesised argument: a `.DownloadString(…)` chained onto it is still iex's. */
  let afterIexParen = false;
  let names = 0;
  /** `*`, a variable whose name could not be read, holds whatever any name may. */
  const holdsDownload = (v: string): boolean => tainted.has(v) || tainted.has('*') || (v === '*' && tainted.size > 0);
  /** A download (or a variable holding one): run when it is `iex`'s argument, else armed for a pipe. */
  const download = (): boolean => {
    if (inIex > 0 || pendingIex) return true;
    downloaded = true;
    for (const v of assigning) tainted.add(v);
    return false;
  };
  /** A variable this command fills — from what it is piped, or from a download later in the segment. */
  const fills = (v: string): void => {
    assigning.push(v);
    if (downloaded) tainted.add(v);
  };
  /** The name a `Set-` / `New-` / `Get-Variable` gives, read at most {@link MAX_VARIABLE_NAMES} times. */
  const nameAfter = (at: number): string => (++names > MAX_VARIABLE_NAMES ? '*' : variableNamed(text, at));
  for (const m of text.matchAll(PS_EXEC_TOKENS)) {
    const t = m[0].toLowerCase();
    const g = m.groups ?? {};
    // Cleared every token; set again only by a `)` that closed iex's argument.
    const afterParen = afterIexParen;
    afterIexParen = false;
    if (g['run'] !== undefined) {
      if (piped) return true;
      pendingIex = true;
    } else if (g['dl'] !== undefined) {
      if (download()) return true;
      // `iex (New-Object Net.WebClient).DownloadString(url)`: the `.Download…`
      // method is chained onto the `)` that closed iex's argument, so its
      // result is still what iex runs (review of 3.6.0, finding 6). The
      // method-call form of `dl` begins with a `.`.
      if (afterParen && t.startsWith('.')) return true;
    } else if (g['ref'] !== undefined) {
      const v = psVariable(g['ref']);
      if (g['assign'] !== undefined) assigning = [v];
      else if (holdsDownload(v) && download()) return true;
    } else if (g['setvar'] !== undefined) {
      fills(nameAfter(m.index + m[0].length));
    } else if (g['getvar'] !== undefined) {
      if (holdsDownload(nameAfter(m.index + m[0].length)) && download()) return true;
    } else if (g['tee'] !== undefined) {
      inTee = true;
    } else if (g['outvar'] !== undefined) {
      fills(g['outname'] === undefined ? '*' : psVariable(g['outname']));
    } else if (g['teevar'] !== undefined) {
      if (inTee) fills(g['teename'] === undefined ? '*' : psVariable(g['teename']));
    } else if (t === '(') {
      opens.push(pendingIex);
      if (pendingIex) inIex += 1;
      pendingIex = false;
    } else if (t === ')') {
      if (opens.pop() === true) {
        inIex -= 1;
        afterIexParen = true;
      }
      pendingIex = false;
    } else if (t === '|') {
      if (downloaded) piped = true;
      pendingIex = false;
      inTee = false;
    } else {
      // `;`, a newline, `&&`, `||`.
      downloaded = false;
      piped = false;
      pendingIex = false;
      assigning = [];
      inTee = false;
    }
  }
  return false;
}

/** A path as compared between a download's destination and a command that runs it. */
function runKey(path: string): string {
  return stripQuotes(path.trim())
    .replace(/\\/g, '/')
    .replace(/^(?:\.\/)+/, '')
    .replace(/\/{2,}/g, '/')
    .toLowerCase();
}

/** `.DownloadFile(url, path)` and its async forms. */
const DOWNLOAD_FILE_CALL = /\.\s*DownloadFile(?:Async|TaskAsync)?\s*\(/gi;

/** PowerShell's web cmdlets (and 5.1's `curl` / `wget` aliases) that can save to a file. */
const SAVING_CMDLETS = new Set(['iwr', 'irm', 'invoke-webrequest', 'invoke-restmethod', 'start-bitstransfer', 'curl', 'wget']);

/** `-OutFile` (from `-OutF`) and BITS's `-Destination` (from `-Dest`), with an attached `:value` or not. */
const SAVE_PARAM = /^-(?:outf(?:i(?:le?)?)?|dest(?:i(?:n(?:a(?:t(?:i(?:on?)?)?)?)?)?)?)(?::(.*))?$/i;

/** curl's short options that take a value: in a cluster, the first of them takes the rest of it, or the next word. */
const CURL_SHORT_VALUED = 'AbcCdDeEFHKmoPQrtTuUwxXyYz';
/** wget's short options that take a value (`-o` is its LOG file, not the download). */
const WGET_SHORT_VALUED = 'OoPtTwUeiaBQlDIXRA';

/** A URL argument. */
const URL_ARG = /^[a-z][a-z0-9+.-]*:\/\//i;

/** The name curl `-O` / wget give a download: the URL path's last segment (wget: `index.html` when there is none). */
function remoteName(url: string, fallback: string | undefined): string | undefined {
  const path = url.replace(/^[a-z][a-z0-9+.-]*:\/\/[^/]*/i, '').replace(/[?#].*$/, '');
  const last = path.split('/').pop() ?? '';
  return last !== '' ? last : fallback;
}

/**
 * The files a POSIX `curl` or `wget` saves (review round 2, ruling 1):
 * `curl -o f` / `--output f` / `-fsSLo f`, `curl -O URL` (named after the
 * URL), `wget -O f` / `--output-document=f`, `wget URL` (named after the URL,
 * under `-P dir`), and either with its stdout redirected (`curl URL > f`).
 * `-O -` is stdout, not a file.
 */
function posixSaves(name: string, words: readonly ShellWord[], at: number): string[] {
  if (name !== 'curl' && name !== 'wget') return [];
  const wget = name === 'wget';
  const valued = wget ? WGET_SHORT_VALUED : CURL_SHORT_VALUED;
  const saved: string[] = [...redirectTargets(words.slice(at + 1))];
  const urls: string[] = [];
  let named = false;
  let remote = false;
  let dir = '';
  const save = (f: string | undefined): void => {
    if (f === undefined || f === '' || f === '-') {
      if (f === '-') named = true;
      return;
    }
    named = true;
    saved.push(f);
  };
  const args = words.slice(at + 1).map((w) => w.value);
  for (let i = 0; i < args.length; i += 1) {
    const a = args[i] ?? '';
    const long = /^--([a-z-]+)(?:=(.*))?$/i.exec(a);
    if (long !== null) {
      const flag = (long[1] ?? '').toLowerCase();
      const value = (): string | undefined => (long[2] !== undefined ? long[2] : args[(i += 1)]);
      if (!wget && flag === 'output') save(value());
      else if (wget && flag === 'output-document') save(value());
      else if (!wget && (flag === 'remote-name' || flag === 'remote-name-all')) remote = true;
      else if ((!wget && flag === 'output-dir') || (wget && flag === 'directory-prefix')) dir = value() ?? '';
      continue;
    }
    if (a.startsWith('-') && a.length > 1) {
      for (let k = 1; k < a.length; k += 1) {
        const c = a.charAt(k);
        if (!wget && c === 'O') remote = true;
        if (!valued.includes(c)) continue;
        const v = k < a.length - 1 ? a.slice(k + 1) : args[(i += 1)];
        if ((wget && c === 'O') || (!wget && c === 'o')) save(v);
        else if (wget && c === 'P') dir = v ?? '';
        break;
      }
      continue;
    }
    if (URL_ARG.test(a)) urls.push(a);
  }
  if ((wget && !named) || (!wget && remote && !named)) {
    for (const url of urls) {
      const file = remoteName(url, wget ? 'index.html' : undefined);
      if (file !== undefined) saved.push(dir === '' ? file : `${dir.replace(/[\\/]+$/, '')}/${file}`);
    }
  } else if (dir !== '') {
    return saved.map((f) => (isAbsolutePath(f) ? f : `${dir.replace(/[\\/]+$/, '')}/${f}`));
  }
  return saved;
}

/**
 * The files a command saves from what it is piped: `tee` / `Tee-Object`,
 * `sponge`, `dd of=`, `Set-Content`, `Add-Content`, `Out-File` — and its
 * stdout redirected (`gunzip > tool`, `cat > i.sh`). Behind a download that
 * writes to its stdout, these are the download saved under another name.
 */
function pipedSaves(name: string, words: readonly ShellWord[], at: number): string[] {
  const out = redirectTargets(words.slice(at + 1));
  pushAll(out, commandWriteDestinations(name, withoutRedirections(words.slice(at + 1))).filter((f) => !f.startsWith('-')));
  return out;
}

/** The files a PowerShell web cmdlet saves: `-OutFile path`, BITS's `-Destination path`. */
function powershellSaves(name: string, words: readonly ShellWord[], at: number): string[] {
  if (!SAVING_CMDLETS.has(name)) return [];
  const out: string[] = [];
  for (let i = at + 1; i < words.length; i += 1) {
    const m = SAVE_PARAM.exec(words[i]?.value ?? '');
    if (m === null) continue;
    const dest = m[1] !== undefined && m[1] !== '' ? m[1] : words[i + 1]?.value;
    if (dest !== undefined && dest.trim() !== '') out.push(dest);
  }
  return out;
}

/** The destinations of `.DownloadFile(url, path)` calls outside a quoted span. */
function downloadFileCalls(text: string): string[] {
  if (!/downloadfile/i.test(text)) return [];
  const out: string[] = [];
  const unquotedAt = quoteTracker(text);
  for (const m of text.matchAll(DOWNLOAD_FILE_CALL)) {
    if (!unquotedAt(m.index)) continue;
    // In the POSIX reading of a PowerShell command an unquoted comma is a
    // space, so the arguments may arrive as one: its last literal is the path.
    const { args } = callArgs(text, m.index + m[0].length);
    const second = args[1];
    const literals = codeLiterals(args[0] ?? '', 'other');
    const dest = second !== undefined ? argPath(second) : literals.length >= 2 ? literals[literals.length - 1] : undefined;
    if (dest !== undefined && dest.trim() !== '') out.push(dest);
  }
  return out;
}

/** Shells, which run their first operand as a script unless given one with `-c`. */
const SCRIPT_SHELLS = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh', 'ash', 'mksh', 'fish', 'csh', 'tcsh']);

/** Commands that open whatever they are given — a program runs, a document only opens. */
const OPENERS = new Set(['start', 'start-process', 'saps', 'invoke-item', 'ii']);

/** Commands that run a file named anywhere in their arguments. */
const RUNS_ARGUMENT = new Set(['msiexec', 'cscript', 'wscript', 'rundll32', 'iex', 'invoke-expression']);

/** Commands that print a file, so `gc x | iex` and `cat x | sh` run it. */
const READERS = new Set(['get-content', 'gc', 'cat', 'type']);

/**
 * File types an opener RUNS rather than displays (review round 2: `Start-Process
 * readme.txt` opens Notepad, and a downloaded document opened that way is no
 * download-then-run). A name with no extension counts: it may be a program.
 */
const RUNNABLE_EXTENSIONS = new Set([
  'exe', 'com', 'bat', 'cmd', 'msi', 'msp', 'msix', 'msixbundle', 'appx', 'appxbundle', 'ps1', 'psm1', 'vbs', 'vbe', 'js',
  'jse', 'wsf', 'wsh', 'hta', 'scr', 'cpl', 'jar', 'reg', 'lnk', 'application', 'appref-ms', 'sh', 'bash', 'command', 'py',
  'pyw', 'pl', 'rb', 'php', 'app', 'pkg',
]);

function isRunnableName(path: string): boolean {
  const last = stripQuotes(path).split(/[\\/]/).pop() ?? '';
  const ext = /\.([A-Za-z0-9-]+)$/.exec(last)?.[1];
  return ext === undefined || RUNNABLE_EXTENSIONS.has(ext.toLowerCase());
}

/** Start-Process's `-ArgumentList` (`-Args`, and its abbreviations) and `-FilePath` (`-Path`, `-PSPath`, `-LP`). */
const PS_ARGUMENT_LIST = /^-(?:args|a(?:r(?:g(?:u(?:m(?:e(?:n(?:t(?:l(?:i(?:st?)?)?)?)?)?)?)?)?)?)?)$/i;
const PS_FILE_PATH = /^-(?:f(?:i(?:l(?:e(?:p(?:a(?:th?)?)?)?)?)?)?|path|pspath|lp)$/i;

/**
 * The first operand of a shell or an interpreter — the script it runs — or
 * none when it runs program text instead (`sh -c`, `python -c`, `node -e`,
 * `python -m`).
 */
function scriptOperand(words: readonly ShellWord[], at: number, name: string): string | undefined {
  const rest = words.slice(at + 1);
  if (SCRIPT_SHELLS.has(name)) {
    if (rest.some((w) => !w.quoted && DASH_C.test(w.value))) return undefined;
    return withoutRedirections(rest).find((v) => !v.startsWith('-'));
  }
  // An interpreter's own options, read with its table of valued ones (round 3, item 2).
  const plain = withoutRedirectWords(words.slice(at));
  const program = interpreterProgram(plain, 0);
  if (program.kind === 'file') return plain[program.index]?.value;
  if (program.kind !== 'unknown') return undefined;
  if (inlineCode(words, at).length > 0 || rest.some((w) => /^-[A-Za-z]*m$/.test(w.value))) return undefined;
  return withoutRedirections(rest).find((v) => !v.startsWith('-'));
}

/** Whether a pipeline member reads its stdin as a program: a shell, `source /dev/stdin`, or a bare interpreter. */
function runsStdin(words: readonly ShellWord[], at: number): boolean {
  return readsStdinAsScript(words, at);
}

/**
 * The files one simple command runs through its arguments — the command's own
 * name is judged by the caller (a path runs that file, a bare name what PATH
 * finds): `. file` / `source file`, a shell's or interpreter's script (`sh f`,
 * `python3 f.py`), `powershell -File file`, `cmd /c file`, a program an opener
 * starts (`Start-Process setup.exe`, `ii i.ps1`, `Start-Process msiexec
 * -ArgumentList '/i x.msi'` — never a document), `msiexec /i file`, and a
 * file printed into something that runs its stdin (`gc f | iex`, `cat f | sh`).
 */
function commandRuns(statement: ShellStatement, c: number, heads: readonly number[], pipedIntoRunner: boolean): string[] {
  const words = statement.commands[c];
  const at = heads[c] ?? 0;
  const head = words?.[at];
  if (words === undefined || head === undefined) return [];
  const name = commandName(head.value);
  const out: string[] = [];
  const rest = withoutRedirections(words.slice(at + 1));
  const operands = rest.filter((v) => v !== '' && !v.startsWith('-') && !/^\/[A-Za-z]+$/.test(v));
  if (name === '.' || name === 'source') {
    if (rest[0] !== undefined) out.push(rest[0]);
  } else if (name === 'powershell' || name === 'pwsh') {
    const file = rest.findIndex((v) => /^-f(?:i(?:le?)?)?$/i.test(v));
    if (file >= 0) out.push(rest[file + 1] ?? '');
    else out.push(...operands);
  } else if (name === 'cmd') {
    const run = rest.findIndex((v) => /^\/[ck]$/i.test(cmdSwitch(v)));
    if (run >= 0) out.push(rest[run + 1] ?? '');
  } else if (SCRIPT_SHELLS.has(name) || isInterpreter(name)) {
    const script = scriptOperand(words, at, name);
    if (script !== undefined) out.push(script);
  } else if (OPENERS.has(name)) {
    const files: string[] = [];
    for (let i = 0; i < rest.length; i += 1) {
      const v = rest[i] ?? '';
      if (PS_ARGUMENT_LIST.test(v)) files.push(...(rest[(i += 1)] ?? '').split(/[\s,]+/));
      else if (PS_FILE_PATH.test(v)) files.push(rest[(i += 1)] ?? '');
      else if (v.startsWith('-')) i += /^-(?:verb|wo\w*|windowstyle|w|redirect\w*|credential|cred)$/i.test(v) ? 1 : 0;
      else files.push(v);
    }
    out.push(...files.filter((f) => f !== '' && !/^\/[A-Za-z]+$/.test(f) && isRunnableName(f)));
  } else if (RUNS_ARGUMENT.has(name)) {
    out.push(...operands);
  } else if (READERS.has(name) && pipedIntoRunner) {
    out.push(...operands);
  }
  return out.filter((f) => f !== '');
}

/** Per pipeline member: whether a LATER member runs its stdin (`iex`, a shell, a bare interpreter) — one pass from the end. */
function pipedIntoRunners(statement: ShellStatement, heads: readonly number[]): boolean[] {
  const out: boolean[] = new Array<boolean>(statement.commands.length).fill(false);
  let later = false;
  for (let c = statement.commands.length - 1; c >= 0; c -= 1) {
    out[c] = later;
    const words = statement.commands[c] ?? [];
    const i = heads[c] ?? 0;
    const n = commandName(words[i]?.value ?? '');
    if (n === 'iex' || n === 'invoke-expression' || runsStdin(words, i)) later = true;
  }
  return out;
}

/** Whether a command line may download anything at all — the cheap test before the walk. */
const MAY_DOWNLOAD = /curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod|start-bitstransfer|downloadfile/i;

/** Checksum and signature tools, as `(name, words) => whether this invocation checks`. */
function isIntegrityCheck(words: readonly ShellWord[], at: number): boolean {
  const name = commandName(words[at]?.value ?? '');
  const args = words.slice(at + 1).map((w) => w.value);
  if (/^(?:sha(?:1|224|256|384|512)sum|b2sum|shasum)$/.test(name)) {
    return args.some((a) => a === '--check' || /^-[A-Za-z]*c[A-Za-z]*$/.test(a));
  }
  if (name === 'gpg' || name === 'gpg2') return args.includes('--verify');
  if (name === 'gpgv') return true;
  if (name === 'minisign' || name === 'signify') return args.some((a) => /^-[A-Za-z]*V/.test(a));
  if (name === 'cosign') return args.includes('verify-blob');
  if (name === 'openssl') return args.some((a) => a === '-verify' || a === '-prverify');
  return false;
}

/** Where a directory change leaves relative paths: `cd`, `pushd`, `Set-Location` (a `popd` goes back to the start). */
function cwdFor(name: string, args: readonly string[], cwd: string): string {
  if (CD_RETURNS.has(name)) return '';
  if (!CD_COMMANDS.has(name)) return cwd;
  const dir = psParam(args, ['path', 'literalpath']) ?? args.find((a) => !(a.startsWith('-') || /^\/d$/i.test(a)));
  if (dir === undefined) return '~';
  const next = resolveFrom(cwd, dir);
  return next.length > MAX_CWD ? '' : next;
}

/** Which kind of command saved the file that was run — it decides how the deny names the shape. */
type DownloadKind = 'posix' | 'powershell';

/** Commands that move or copy a file, so a download keeps its mark under the new name (review round 3, item 3). */
const TRANSFERS = new Set(['mv', 'cp', 'install', 'copy-item', 'cpi', 'copy', 'move-item', 'mi', 'move']);

/** Directories a bare command name is found in on PATH: a marked file placed there runs by its name alone. */
const PATH_DIRS = /^(?:\/usr\/local\/s?bin|\/usr\/s?bin|\/s?bin|\/opt\/homebrew\/bin|\/opt\/local\/bin|(?:~|\$\{?home\}?)\/(?:\.local\/)?bin)$/i;

/**
 * What an `mv` / `cp` / `install` / `Copy-Item` / `Move-Item` puts where: each
 * source, and the paths it may now be at — the destination itself, and a file
 * of the source's name inside it when the destination may be a directory.
 */
function transfersOf(name: string, words: readonly ShellWord[], at: number): Array<{ from: string; to: string[] }> {
  if (!TRANSFERS.has(name)) return [];
  const args = withoutRedirections(words.slice(at + 1));
  if (name === 'install' && args.some((a) => a === '-d' || a === '--directory')) return [];
  const t = parseTransfer(args, name === 'copy' || name === 'move');
  const dest = t.dest;
  if (dest === undefined) return [];
  return t.sources.map((from) => {
    const inside = `${dest.replace(/[\\/]+$/, '')}/${lastSegment(from)}`;
    return { from, to: t.into ? [inside] : [dest, inside] };
  });
}

/** gpg's options that take the next word as their value — never a signature or a data file. */
const GPG_VALUED = new Set([
  '--keyring', '--primary-keyring', '--secret-keyring', '--homedir', '--trustdb-name', '--options', '--status-fd',
  '--logger-fd', '--attribute-fd', '--passphrase-fd', '--command-fd', '--status-file', '--logger-file',
  '--default-key', '-u', '--local-user', '-r', '--recipient', '-o', '--output', '--trusted-key', '--trust-model',
  '--verify-options', '--assert-signer', '--weak-digest', '--auto-key-locate', '--keyserver', '--keyserver-options',
  '--compress-algo', '--cipher-algo', '--digest-algo', '--display-charset', '--charset',
]);

/** What `gpg --verify` / `gpgv` is handed: its signature, then the data files it verifies against it. */
function gpgOperands(args: readonly string[], gpgv: boolean): string[] {
  const out: string[] = [];
  let verifying = gpgv;
  let optionsDone = false;
  for (let i = 0; i < args.length; i += 1) {
    const a = args[i] ?? '';
    if (!optionsDone && a === '--verify') verifying = true;
    else if (!optionsDone && a === '--') optionsDone = true;
    else if (!optionsDone && a.startsWith('-') && a !== '-') i += !a.includes('=') && GPG_VALUED.has(a) ? 1 : 0;
    else if (verifying) out.push(a);
  }
  return out;
}

/** The data file a detached signature or a checksum file is named after: `i.sh.asc` → `i.sh`. */
const SIDECAR = /^(.+)\.(?:sha(?:1|224|256|384|512)(?:sum)?|asc|sig|minisig)$/;

/**
 * An integrity check at the end of a statement's pipeline, and what it names
 * (review round 3, item 3): `names`, every word of every member (`echo "<sha>
 * f" | sha256sum -c` names `f`), split on blanks; `lists`, the checksum lists a
 * `sha256sum -c` is handed as operands; `implied`, the data files a sidecar
 * implies — each checksum file's (`sha256sum -c i.sh.sha256` checks `i.sh`), and
 * a signature's only when gpg is handed it alone (`gpg --verify i.sh.asc`
 * verifies `i.sh`). Handed a data file, gpg verifies THAT file: `gpg --verify
 * i.sh.asc other` says nothing of `i.sh` (review 3.0, wave 2). cosign,
 * minisign, signify and openssl always name the file they check. Paths as
 * {@link runKey}s.
 */
function integrityCheckOf(
  statement: ShellStatement,
  heads: readonly number[],
  cwd: string,
): { names: string[]; lists: string[]; implied: string[] } | undefined {
  const last = statement.commands.length - 1;
  const words = statement.commands[last];
  const at = heads[last] ?? 0;
  if (words === undefined || !isIntegrityCheck(words, at)) return undefined;
  const key = (token: string): string => runKey(resolveFrom(cwd, token));
  const names: string[] = [];
  statement.commands.forEach((member, c) => {
    for (const w of member.slice((heads[c] ?? 0) + 1)) {
      for (const token of w.value.split(/\s+/)) if (token !== '' && !token.startsWith('-')) names.push(key(token));
    }
  });
  const tool = commandName(words[at]?.value ?? '');
  const args = withoutRedirections(words.slice(at + 1));
  const sumTool = /^(?:sha(?:1|224|256|384|512)sum|b2sum|shasum)$/.test(tool);
  const lists = sumTool ? args.filter((v) => !v.startsWith('-') && !/^\d+$/.test(v)).map(key) : [];
  const implying = sumTool ? names.slice() : [];
  if (tool === 'gpg' || tool === 'gpg2' || tool === 'gpgv') {
    const operands = gpgOperands(args, tool === 'gpgv');
    const signature = operands[0];
    if (operands.length === 1 && signature !== undefined) implying.push(key(signature));
  }
  const implied = implying.flatMap((name) => SIDECAR.exec(name)?.[1] ?? []);
  return { names, lists, implied };
}

/**
 * What an archive extraction reads and where it writes: `tar` / `bsdtar`
 * extracting (`x` in its first-word cluster or a `-…x…` one, `--extract`,
 * `--get`) from `-f FILE` / `--file` — stdin when none or `-` — into `-C DIR` /
 * `--directory` (the working directory when none); `unzip FILE -d DIR`. The
 * valued letters of a cluster take the following words in order, as tar's own
 * old style does (`tar xzfC t.tgz /usr/local/bin`). None for anything else.
 */
function archiveExtraction(name: string, words: readonly ShellWord[], at: number): { dir?: string; archive?: string } | undefined {
  const args = withoutRedirections(words.slice(at + 1));
  const out: { dir?: string; archive?: string } = {};
  if (name === 'unzip') {
    for (let i = 0; i < args.length; i += 1) {
      const a = args[i] ?? '';
      if (a === '-d') out.dir = args[(i += 1)];
      else if (a.startsWith('-d') && a.length > 2) out.dir = a.slice(2);
      else if (!a.startsWith('-') && out.archive === undefined) out.archive = a;
    }
    return out.archive === undefined ? undefined : out;
  }
  if (name !== 'tar' && name !== 'bsdtar' && name !== 'gtar') return undefined;
  let extract = false;
  const pending: string[] = [];
  const take = (letter: string, value: string | undefined): void => {
    if (letter === 'f') out.archive = value;
    else out.dir = value;
  };
  for (let i = 0; i < args.length; i += 1) {
    const a = args[i] ?? '';
    if (a === '--extract' || a === '--get') {
      extract = true;
      continue;
    }
    const long = /^--(directory|file)(?:=(.*))?$/.exec(a);
    if (long !== null) {
      take(long[1] === 'file' ? 'f' : 'C', long[2] ?? args[(i += 1)]);
      continue;
    }
    if (a.startsWith('--')) continue;
    const option = a.startsWith('-') && a !== '-';
    if (!option && i > 0) {
      const letter = pending.shift();
      if (letter !== undefined) take(letter, a);
      continue;
    }
    const cluster = option ? a.slice(1) : a;
    for (let c = 0; c < cluster.length; c += 1) {
      const letter = cluster.charAt(c);
      if (letter === 'x') extract = true;
      if (letter !== 'f' && letter !== 'C') continue;
      const rest = cluster.slice(c + 1);
      if (option && rest !== '') {
        take(letter, rest);
        break;
      }
      pending.push(letter);
      if (option) break;
    }
  }
  return extract ? out : undefined;
}

/**
 * Commands that do not run an extracted archive's files: shell builtins and the
 * file tools an install runs around one (`chmod +x`, `ls -l`, `which`, a
 * checksum). After an archive of unknown names is extracted into a PATH
 * directory, any other bare command may be one of its files.
 */
const NOT_FROM_ARCHIVE = new Set([
  'echo', 'printf', 'cd', 'pwd', 'export', 'unset', 'set', 'true', 'false', 'test', '[', '[[', 'command', 'type', 'hash',
  'which', 'whereis', 'ls', 'chmod', 'chown', 'chgrp', 'rm', 'rmdir', 'mv', 'cp', 'ln', 'mkdir', 'touch', 'cat', 'head',
  'tail', 'grep', 'sed', 'awk', 'sort', 'wc', 'file', 'stat', 'du', 'df', 'tar', 'bsdtar', 'gzip', 'gunzip', 'xz', 'unzip',
  'curl', 'wget', 'install', 'sleep', 'date', 'uname', 'id', 'whoami', 'exit', 'sha256sum', 'sha512sum', 'shasum', 'gpg',
  'readlink', 'realpath', 'basename', 'dirname', 'tee', 'find', 'source', '.', 'popd', 'pushd',
]);

/**
 * A file downloaded and run by the same command line (review I1, PowerShell's
 * `DownloadFile` / `-OutFile` then run; round 2, ruling 1, POSIX `curl -o f
 * && sh f` and the like). Paths are compared after the `cd`s before them, and
 * a download keeps its mark through `mv` / `cp` / `install` (round 3, item 3).
 * The command's own name runs the file when it is a path (`./tool`); a bare
 * name only under cmd.exe (`bareRunsCwd`), or when the marked file was placed
 * in a PATH directory in the same command (round 3, item 4). A run is not
 * counted when a check OF THAT FILE — naming it, its `.sha256` / `.asc` /
 * `.sig` / `.minisig`, or a checksum list downloaded in the command — lies
 * between its latest download and the run, and every statement from the check
 * to the run is joined by `&&` — or, after a plain `set -e` with no compound
 * command or subshell since, by `;` or a new line: the run is then conditional
 * on the check. A check right after `||` never counts (`a || check && run`
 * skips it when `a` succeeds). A run
 * in a later, separate command is not seen at all: that is download, inspect,
 * run. Returns what saved the file that ran, which names the shape in the deny.
 */
function downloadsThenRuns(text: string, statements: readonly ShellStatement[], bareRunsCwd: boolean): DownloadKind | null {
  if (!MAY_DOWNLOAD.test(text)) return null;
  /** Per file, its latest download so far (`.DownloadFile` calls come before every statement), carried by mv / cp / install. */
  const downloads = new Map<string, { at: number; kind: DownloadKind }>();
  for (const dest of downloadFileCalls(text)) downloads.set(runKey(resolveFrom('', dest)), { at: -1, kind: 'powershell' });
  /** Bare command names that PATH now resolves to a marked file: placed by mv / cp / install into a PATH directory. */
  const pathBins = new Map<string, string>();
  /**
   * Per file, the latest integrity check of it joined to the current statement
   * by `&&` all the way; `listAt`, the latest check against a checksum list
   * downloaded in the chain, which may cover every download. Both are carried
   * forward and cleared at any other separator, so each run is judged in
   * constant time.
   */
  const verified = new Map<string, number>();
  let listAt = -2;
  /**
   * `set -e` in force ({@link errexitSetting}): a check's failure ends the
   * script, so a `;` or a new line after it is as conditional as `&&` — while
   * `errexitHolds`, false for good after a compound command, a subshell or a
   * command substitution ({@link COMPOUND_WORDS}).
   */
  let errexit = false;
  let errexitHolds = true;
  let cwd = '';
  /**
   * PATH directories a download was extracted into (round 2), each with its
   * first extraction: what the archive held is unknown, so a later bare name
   * may be any of it. One entry per directory, so a lookup is constant time.
   */
  const extracted = new Map<string, { at: number; kind: DownloadKind }>();
  for (let k = 0; k < statements.length; k += 1) {
    const statement = statements[k];
    if (statement === undefined) continue;
    const heads = statement.commands.map((words) => resolveCommand(words).index);
    const ran: string[] = [];
    const saved: Array<{ key: string; kind: DownloadKind }> = [];
    // Nothing downloaded yet: nothing a run could match, so runs are not read.
    const reading = downloads.size > 0 || extracted.size > 0;
    const piped = reading ? pipedIntoRunners(statement, heads) : [];
    /** A download earlier in this pipeline writes to its stdout: what a later member saves is the download. */
    let streaming: DownloadKind | undefined;
    /** A bare name run after an extraction into a PATH directory, and what downloaded the archive. */
    let fromArchive: DownloadKind | undefined;
    /** Whether `archive` (a file, or stdin for `-` / none) is a download no check has cleared: what downloaded it. */
    const downloadedArchive = (archive: string | undefined): DownloadKind | undefined => {
      if (archive === undefined || archive === '-') return streaming;
      const key = runKey(resolveFrom(cwd, archive));
      const d = downloads.get(key);
      return d !== undefined && !((verified.get(key) ?? -3) > d.at) && !(listAt > d.at) ? d.kind : undefined;
    };
    statement.commands.forEach((words, c) => {
      const at = heads[c] ?? 0;
      const head = words[at]?.value ?? '';
      const name = commandName(head);
      const posix = posixSaves(name, words, at);
      const ps = powershellSaves(name, words, at);
      for (const dest of posix) saved.push({ key: runKey(resolveFrom(cwd, dest)), kind: 'posix' });
      for (const dest of ps) saved.push({ key: runKey(resolveFrom(cwd, dest)), kind: 'powershell' });
      // `curl … | sudo tee /usr/local/bin/tool`, `| gunzip > tool`, `irm … |
      // Out-File i.ps1` (review 3.0 wave 2, round 2).
      if (streaming !== undefined) {
        const kind = streaming;
        for (const dest of pipedSaves(name, words, at)) saved.push({ key: runKey(resolveFrom(cwd, dest)), kind });
      }
      // `curl … | tar xz -C /usr/local/bin`, `tar xzf t.tgz -C ~/.local/bin`
      // after `curl -o t.tgz`, `unzip t.zip -d /usr/local/bin` (round 2).
      const extraction = archiveExtraction(name, words, at);
      if (extraction !== undefined) {
        const dir = runKey(resolveFrom(cwd, extraction.dir ?? '.')).replace(/\/+$/, '');
        const kind = downloadedArchive(extraction.archive);
        if (kind !== undefined && PATH_DIRS.test(dir) && !extracted.has(dir)) extracted.set(dir, { at: k, kind });
      }
      if (DOWNLOADERS.has(name) && posix.length === 0 && ps.length === 0) {
        streaming = name === 'curl' || name === 'wget' ? 'posix' : 'powershell';
      }
      if (reading) {
        for (const file of commandRuns(statement, c, heads, piped[c] === true)) ran.push(runKey(resolveFrom(cwd, file)));
        // The command itself: a path runs that file. A bare name is looked up
        // on PATH by a POSIX shell and by PowerShell — only cmd.exe searches
        // the working directory first (review round 3, item 4).
        if (/[\\/]/.test(head)) ran.push(runKey(resolveFrom(cwd, head)));
        else if (head !== '') {
          const onPath = pathBins.get(head.toLowerCase());
          if (onPath !== undefined) ran.push(onPath);
          if (!NOT_FROM_ARCHIVE.has(head.toLowerCase())) {
            for (const e of extracted.values()) if (e.at < k) fromArchive ??= e.kind;
          }
          if (bareRunsCwd) {
            for (const ext of /\.[A-Za-z0-9]+$/.test(head) ? [''] : ['', '.exe', '.cmd', '.bat', '.com']) {
              ran.push(runKey(resolveFrom(cwd, `${head}${ext}`)));
            }
          }
        }
        // A marked file moved or copied keeps its mark (review round 3, item 3).
        for (const { from, to } of transfersOf(name, words, at)) {
          const src = runKey(resolveFrom(cwd, from));
          const mark = downloads.get(src);
          if (mark === undefined) continue;
          for (const dest of to) {
            const key = runKey(resolveFrom(cwd, dest));
            downloads.set(key, mark);
            const check = verified.get(src);
            if (check !== undefined) verified.set(key, check);
            const bin = lastSegment(key);
            if (PATH_DIRS.test(dirOf(key)) && bin !== '') pathBins.set(bin, key);
          }
        }
      }
      cwd = cwdFor(name, withoutRedirections(words.slice(at + 1)), cwd);
    });
    // `iex (Get-Content file -Raw)`: the `(` ended the statement holding `iex`.
    const only = statement.commands.length === 1 ? statement.commands[0] : undefined;
    const lone = only !== undefined && only.length === 1 ? commandName(only[0]?.value ?? '') : '';
    const next = statements[k + 1]?.commands[0];
    if (reading && (lone === 'iex' || lone === 'invoke-expression') && next !== undefined && READERS.has(commandName(next[0]?.value ?? ''))) {
      for (const w of next.slice(1)) if (!w.value.startsWith('-')) ran.push(runKey(resolveFrom(cwd, w.value)));
    }
    for (const file of ran) {
      const d = downloads.get(file);
      // Run after its download, and not behind a check of it made after that download.
      if (d !== undefined && d.at < k && !((verified.get(file) ?? -3) > d.at) && !(listAt > d.at)) return d.kind;
      // A file of an archive extracted into a PATH directory, run by its path.
      const e = extracted.get(dirOf(file));
      if (e !== undefined && e.at < k) return e.kind;
    }
    if (fromArchive !== undefined) return fromArchive;
    for (const { key, kind } of saved) {
      downloads.set(key, { at: k, kind });
      verified.delete(key);
      // Saved straight into a PATH directory, it runs by its bare name as a
      // moved one does (review 3.0, wave 2: `curl -o /usr/local/bin/tool …`).
      const bin = lastSegment(key);
      if (PATH_DIRS.test(dirOf(key)) && bin !== '') pathBins.set(bin, key);
    }
    // A compound command, a subshell or a command substitution: a check inside
    // one may be skipped, or its failure not end the script — `set -e` carries
    // nothing from here on.
    // Read on the statement's own text: `splitShell` drops the reserved word
    // that opens a body (`if`, `then`, `!`, `{`), so its commands do not hold it.
    const lead = /^\s*(\S+)/.exec(statement.masked)?.[1] ?? '';
    if (COMPOUND_WORDS.has(lead) || statement.end === '(' || statement.end === ')' || statement.end === '`') errexitHolds = false;
    const setting = statement.end !== '&' ? errexitSetting(statement) : undefined;
    if (setting !== undefined) errexit = setting;
    // A pipeline's status is its last member's: only a check there decides —
    // and only for the files it names (review round 3, item 3). Never one
    // after `||`: in `a || check && run` the check is skipped whenever `a`
    // succeeds, and the run goes ahead.
    const check = statements[k - 1]?.end === '||' ? undefined : integrityCheckOf(statement, heads, cwd);
    if (check !== undefined) {
      for (const name of check.names) if (downloads.has(name)) verified.set(name, k);
      for (const name of check.implied) verified.set(name, k);
      if (check.lists.some((list) => downloads.has(list))) listAt = k;
    }
    const carried = statement.end === '&&' || (errexit && errexitHolds && (statement.end === ';' || statement.end === '\n'));
    if (!carried) {
      verified.clear();
      listAt = -2;
    }
  }
  return null;
}

/**
 * Words that lead a compound command or a negation — `if`, `then`, `while`,
 * `do`, `{`, `!`, … A statement they lead may never run, or run only on a
 * condition, and errexit does not apply to a condition or to `!`.
 */
const COMPOUND_WORDS = new Set([
  'if', 'then', 'else', 'elif', 'fi', 'for', 'while', 'until', 'do', 'done', 'case', 'esac', 'select', 'function', '{', '}',
  '!', '[[', ']]', 'coproc',
]);

/**
 * What a `set` statement does to errexit: `true` for `set -e` (any flag
 * cluster holding `e`: `-eu`, `-euo pipefail`, `-xe`) and `set -o errexit`,
 * `false` for `+e` / `+o errexit`, `undefined` when it does neither or the
 * statement is no plain `set` (a pipeline member runs in a subshell). The
 * options end at the first word that is not one — `set -- -e` sets a
 * positional parameter.
 */
function errexitSetting(statement: ShellStatement): boolean | undefined {
  if (statement.commands.length !== 1) return undefined;
  const words = statement.commands[0] ?? [];
  if (words[0]?.value !== 'set') return undefined;
  let out: boolean | undefined;
  for (let i = 1; i < words.length; i += 1) {
    const m = /^([-+])([A-Za-z]+)$/.exec(words[i]?.value ?? '');
    if (m === null) break;
    const on = m[1] === '-';
    const letters = m[2] ?? '';
    if (letters.includes('e')) out = on;
    if (letters.endsWith('o')) {
      if (words[i + 1]?.value === 'errexit') out = on;
      i += 1;
    }
  }
  return out;
}

/** A POSIX shell's `CDPATH=a:b`: the directories a relative `cd` also searches. */
function cdpathValue(word: string): string[] | undefined {
  const m = /^CDPATH=(.*)$/.exec(word);
  return m === null ? undefined : (m[1] ?? '').split(':').filter((d) => d !== '');
}

/**
 * Where the command is after `words` ({@link cwdAfter}), with what a `cd`
 * can return to (review 8, item 15): `cd -` and `cd "$OLDPWD"` go back to the
 * directory before the last move, `pushd` / `popd` keep a stack, and a
 * relative `cd` also searches `CDPATH` — set before the command
 * (`CDPATH=~/.config cd dev-guardian`) or earlier in the command (`export
 * CDPATH=…`, `CDPATH=…;`). Each used to read as "where the command started",
 * so `cd ~/.config/dev-guardian; cd /tmp; cd -; echo > hooks.json` was ok. A
 * `CDPATH` entry that names a guarded directory is taken: the conservative
 * reading. Stacks are replaced, never mutated: a nested scope shares them.
 */
function moveCwd(scope: Scope, words: readonly ShellWord[], at: number): void {
  // `CDPATH=x` alone, or `export CDPATH=x`: for the rest of the command.
  const head = words[at];
  const exported = head !== undefined && commandName(head.value) === 'export';
  for (const w of exported ? words.slice(at + 1) : head === undefined ? words : []) {
    const dirs = cdpathValue(w.value);
    if (dirs !== undefined) scope.cdpath = dirs;
  }
  if (head === undefined) return;
  const name = commandName(head.value);
  const args = withoutRedirections(words.slice(at + 1));
  const prefix = words.slice(0, at).map((w) => cdpathValue(w.value)).find((d) => d !== undefined);
  const cdpath = prefix ?? scope.cdpath ?? [];
  const here = scope.cwd;
  if (name === 'popd' || name === 'pop-location') {
    const stack = scope.dirStack ?? [];
    scope.prevCwd = here;
    scope.cwd = stack[stack.length - 1] ?? '';
    scope.dirStack = stack.slice(0, -1);
    return;
  }
  if (!CD_COMMANDS.has(name)) return;
  const target = psParam(args, ['path', 'literalpath']) ?? args.find((a) => a === '-' || !(a.startsWith('-') || /^\/d$/i.test(a)));
  const pushes = name === 'pushd' || name === 'push-location';
  let next: string | undefined;
  if (target === '-' || (target !== undefined && /^\$\{?OLDPWD\}?$/.test(target))) next = scope.prevCwd ?? '';
  else if (pushes && target === undefined) {
    // `pushd` alone swaps the top two.
    const stack = scope.dirStack ?? [];
    next = stack[stack.length - 1] ?? '';
    scope.dirStack = [...stack.slice(0, -1), here];
    scope.prevCwd = here;
    scope.cwd = next;
    return;
  } else {
    next = cwdAfter(name, args, here, scope.dataDir) ?? here;
    if (target !== undefined && !isAbsolutePath(target) && !/^\.\.?(?:[\\/]|$)/.test(target)) {
      for (const dir of cdpath) {
        const via = cwdAfter('cd', [resolveFrom(dir, target)], '', scope.dataDir);
        if (via !== undefined && via !== '') {
          next = via;
          break;
        }
      }
    }
  }
  if (pushes) scope.dirStack = [...(scope.dirStack ?? []), here];
  scope.prevCwd = here;
  scope.cwd = next;
}

// ─────────────────────────────── other catastrophic and destructive commands

/** The filesystem root or a drive root — not a directory below one. */
const ROOT_ITSELF = /^(?:\/\*?|\\\*?|[A-Za-z]:[\\/]?\*?|\/(?:mnt\/)?[A-Za-z]\/?\*?)$/i;

/**
 * `chmod -R` / `chown -R` / `chgrp -R` of the filesystem root, a drive root or
 * a system directory (review 8, item 9): `chmod -R a+rwx /` matched no rule
 * (only a numeric 777 did), and `chown -R x /` none at all — a recursive owner
 * change clears every setuid bit, `sudo`'s included. The root itself blocks;
 * a system directory (`/usr`, `/etc`, `C:\Windows`) warns.
 */
function recursivePermsOnRoot(words: readonly ShellWord[], at: number, tildeUsers = true): MatchedRule | null {
  const name = commandName(words[at]?.value ?? '');
  if (name !== 'chmod' && name !== 'chown' && name !== 'chgrp') return null;
  const args = withoutRedirections(words.slice(at + 1));
  if (!args.some((a) => a === '--recursive' || /^-[A-Za-z]*R[A-Za-z]*$/.test(a))) return null;
  const operandWords = args.filter((a) => !a.startsWith('-') || /^-[rwxXst]+$/.test(a));
  const targets = args.some((a) => a.startsWith('--reference')) ? operandWords : operandWords.slice(1);
  const roots = targets.filter((t) => catastrophicKind(t, tildeUsers) === 'root');
  if (roots.length === 0) return null;
  return roots.some((t) => ROOT_ITSELF.test(stripQuotes(t)))
    ? { id: 'recursive-perms-root', level: 'block', reason: 'Recursively changes the permissions or the owner of the filesystem root' }
    : { id: 'recursive-perms-system', level: 'warn', reason: 'Recursively changes the permissions or the owner of a system directory — confirm this is intended' };
}

/**
 * Commands that destroy something no delete rule sees (review 8, item 9) —
 * warnings, since each is sometimes the job: Windows' restore points
 * (`vssadmin delete shadows`, `wmic shadowcopy delete`), a machine-wide
 * registry key (`reg delete HKLM\…`), the infrastructure Terraform manages
 * (`terraform destroy`, `apply -destroy`), an S3 bucket's objects (`aws s3 rm
 * --recursive`, `aws s3 rb --force`) and a GitHub repository (`gh repo delete`).
 */
function destructiveCommand(words: readonly ShellWord[], at: number): MatchedRule | null {
  const name = commandName(words[at]?.value ?? '');
  const args = withoutRedirections(words.slice(at + 1));
  const plain = args.filter((a) => !a.startsWith('-') && !/^\/[A-Za-z]/.test(a)).map((a) => a.toLowerCase());
  if ((name === 'vssadmin' && plain[0] === 'delete' && plain[1] === 'shadows') || (name === 'wmic' && plain[0] === 'shadowcopy' && plain.includes('delete'))) {
    return { id: 'shadow-copy-delete', level: 'warn', reason: "Deletes Windows' volume shadow copies (restore points)" };
  }
  // `HKLM\SYSTEM` reaches the POSIX reader as `HKLMSYSTEM`.
  if (name === 'reg' && plain[0] === 'delete' && /^(?:hklm|hkey_local_machine)/i.test(plain[1] ?? '')) {
    return { id: 'registry-delete', level: 'warn', reason: 'Deletes a machine-wide registry key (HKLM)' };
  }
  if ((name === 'terraform' || name === 'tofu' || name === 'terragrunt') && (plain[0] === 'destroy' || (plain[0] === 'apply' && args.includes('-destroy')))) {
    return { id: 'terraform-destroy', level: 'warn', reason: 'Destroys the infrastructure Terraform manages' };
  }
  if (name === 'aws' && plain[0] === 's3' && ((plain[1] === 'rm' && args.includes('--recursive')) || (plain[1] === 'rb' && args.includes('--force')))) {
    return { id: 's3-recursive-delete', level: 'warn', reason: "Deletes an S3 bucket's objects recursively" };
  }
  if (name === 'gh' && plain[0] === 'repo' && plain[1] === 'delete') {
    return { id: 'gh-repo-delete', level: 'warn', reason: 'Deletes a GitHub repository' };
  }
  return null;
}

/**
 * The command line PowerShell's `Start-Process` / `saps` starts, as a script
 * ({@link startProcessArgv}): its program and `-ArgumentList` (review 8, item
 * 9 — `Start-Process cmd -ArgumentList '/c rd /s /q C:\'` was ok).
 */
function startedCommandLine(words: readonly ShellWord[], at: number): string | undefined {
  const name = commandName(words[at]?.value ?? '');
  if (name !== 'start-process' && name !== 'saps') return undefined;
  const argv = startProcessArgv(words, at);
  return argv === undefined ? undefined : argv.map((w) => posixWord(w.value)).join(' ');
}

/** `wsl`'s own options that take a value. */
const WSL_VALUED = new Set(['-d', '--distribution', '-u', '--user', '--cd', '--shell-type', '--distribution-id']);

/**
 * The command `wsl [options] [--] command…` runs in Linux (review 8, item 9:
 * `wsl rm -rf /mnt/c` was ok): the words after its options — after `-e` /
 * `--exec` run without a shell, otherwise through the default shell. A
 * management option (`--install`, `--list`, `--shutdown`, …) runs none.
 */
function wslScript(words: readonly ShellWord[], start: number): string | undefined {
  for (let i = start + 1; i < words.length; i += 1) {
    const v = words[i]?.value ?? '';
    if (v === '--') return words.slice(i + 1).map((w) => w.value).join(' ');
    if (v === '-e' || v === '--exec') return words.slice(i + 1).map((w) => posixWord(w.value)).join(' ');
    if (WSL_VALUED.has(v)) {
      i += 1;
      continue;
    }
    if (v === '--system' || v === '-s') continue;
    if (v.startsWith('-')) return undefined;
    return words.slice(i).map((w) => w.value).join(' ');
  }
  return undefined;
}

// ──────────────────────────────────────────────────────────── assessment

const MAX_NESTING = 3;

/** The longest directory followed: no real one is longer, and a line of long `cd`s must not cost its square. */
const MAX_DIR = 4096;

/** A `/`-separated path with its `.` and `..` segments folded — never above its root or drive. */
function foldDots(path: string): string {
  const drive = /^[A-Za-z]:/.exec(path)?.[0] ?? '';
  const parts: string[] = [];
  for (const seg of path.slice(drive.length).split('/')) {
    if (seg === '' || seg === '.') continue;
    if (seg === '..') parts.pop();
    else parts.push(seg);
  }
  return `${drive}/${parts.join('/')}`;
}

/**
 * The directory a command runs in ({@link workdirs}' `may`: what a deny must
 * assume) — the moves applied to where the statements start: `~`, `$HOME`,
 * `$USERPROFILE` (and `$env:` / `%…%`) the home directory, `$PWD` where the
 * command is, `$TEMP`, `$TMP`, `$TMPDIR`, `$LOCALAPPDATA`, `$APPDATA` what they
 * name, and Git Bash's bare `C:` the drive's root (review 12, finding 16:
 * `cd "$HOME"`, `cd $env:TEMP\..\..\..`, `cd C:` were not followed). `undefined`
 * when any of it is not known.
 */
function dirAfter(
  start: string | undefined,
  steps: Steps,
  ctx: { homePath?: string | undefined; vars?: Readonly<Record<string, string>> | undefined; bareDriveRoot?: boolean },
): string | undefined {
  if (steps === null) return undefined;
  let cur = start;
  for (const step of steps) {
    let target = step.replace(/\\/g, '/');
    if (target === '~' || target.startsWith('~/')) {
      if (ctx.homePath === undefined) return undefined;
      target = `${ctx.homePath}${target.slice(1)}`;
    } else if (/^[$%]/.test(target)) {
      const v = leadingVariable(target);
      const value =
        v === undefined ? undefined : HOME_VARIABLES.has(v.name) ? ctx.homePath : v.name === 'pwd' ? cur : ctx.vars?.[v.name];
      if (v === undefined || value === undefined) return undefined;
      target = `${value.replace(/\\/g, '/')}${v.rest.replace(/\\/g, '/')}`;
    } else if (/^[A-Za-z]:\.?$/.test(target)) {
      // `cd C:` — the drive's root in Git Bash; in cmd and PowerShell, the drive's own current directory.
      if (ctx.bareDriveRoot !== true) return undefined;
      target = `${target.charAt(0)}:/`;
    }
    if (/^(?:\/|[A-Za-z]:\/)/.test(target)) cur = foldDots(target);
    else if (cur === undefined) return undefined;
    else cur = foldDots(`${cur}/${target}`);
    if (cur.length > MAX_DIR) return undefined;
  }
  return cur;
}

/** The variables a delete target may start with, from the environment ({@link DeleteContext.vars}). */
function targetVariables(env: Readonly<Record<string, string | undefined>>): Record<string, string> {
  const get = (...names: string[]): string | undefined => {
    for (const name of names) {
      const key = Object.keys(env).find((k) => k.toUpperCase() === name);
      const value = key === undefined ? undefined : env[key]?.trim();
      if (value !== undefined && value !== '') return value;
    }
    return undefined;
  };
  const out: Record<string, string> = {};
  for (const [name, from] of [
    ['temp', ['TEMP', 'TMP']],
    ['tmp', ['TMP', 'TEMP']],
    ['tmpdir', ['TMPDIR']],
    ['localappdata', ['LOCALAPPDATA']],
    ['appdata', ['APPDATA']],
  ] as const) {
    const value = get(...from);
    if (value !== undefined) out[name] = value;
  }
  return out;
}

/**
 * Every rule `command` breaks, into `out`. `scope` carries the whole command
 * as given (a loosening key for Claude Code's settings is looked for there)
 * and the directory the statements have `cd`'d into so far, which each
 * statement updates in order; a nested script starts from the directory its
 * parent was in and cannot move the parent.
 */
function collect(command: string, depth: number, out: MatchedRule[], scope: Scope): void {
  const cmd = command.trim();
  if (cmd.length === 0) return;
  // Before any whole-text work: a nested script is split and scanned whole,
  // and nested PowerShell text is read twice at every level (fix round 5).
  if (scope.notes.now() > scope.notes.deadline) {
    scope.notes.budget = true;
    return;
  }

  const { maskedCommand, interpolatedCommand, statements } = splitShell(cmd);

  // The whole-command rules are local signatures, or have a linear `test`
  // (see `BashRule.test`), so they read the whole command uncapped: a long
  // line of ordinary statements is not "partially assessed".
  const commandText = collapseBlanks(maskedCommand);
  for (const rule of BASH_RULES) {
    if (rule.scope === 'command' && (rule.test ?? ((t: string) => rule.pattern.test(t)))(commandText)) {
      out.push({ id: rule.id, level: rule.level, reason: rule.reason });
    }
  }
  // `[IO.File]::WriteAllText(…)`: the `(` that opens its arguments is a
  // statement boundary to `splitShell`, so it is judged on the command text.
  pushAll(out, judgeEffects(dotNetEffects(cmd, scope.cwd, scope.notes), scope));
  // PowerShell running a download (review I1): through `iex` across the `(`
  // that splits statements, and a file downloaded then run. A variable copied
  // through a double-quoted string is still the download (review 3.0, wave 2).
  const flowText = interpolatedCommand === maskedCommand ? commandText : collapseBlanks(interpolatedCommand);
  if (powershellDownloadExecution(flowText)) out.push(RULE_IEX_DOWNLOAD);
  const ranDownload = downloadsThenRuns(cmd, statements, scope.cmdLine === true);
  if (ranDownload !== null) out.push(ranDownload === 'posix' ? RULE_POSIX_DOWNLOAD_RUN : RULE_DOWNLOAD_RUN);
  // `python3 <(curl …)`: an interpreter's script is a download (round 2, ruling 2).
  if (/<\(\s*(?:curl|wget)/i.test(commandText) && statements.some((_s, k) => interpreterRunsFetch(statements, k))) {
    out.push(RULE_PROCESS_FETCH);
  }
  // `bash <(echo 'rm -rf /')`: what the substitution writes is the script (review 8, item 8).
  if (commandText.includes('<(')) collectGenerated(processSubstitutionScripts(statements), depth, out, scope);
  // `curl … | (sh)`: a subshell runs the download the pipe hands it — the `(`
  // separated the shell from the pipeline (review of 3.6.0, finding 5).
  const subshell = pipesDownloadIntoSubshell(statements);
  if (subshell !== null) out.push(subshell);
  // `eval $(curl …)` / `` eval `curl …` ``: the substitution eval runs, split
  // off by the `(` / backtick — the quoted form already blocks (finding 5).
  for (const body of evalSubstitutionBodies(statements)) {
    if (body.some((b) => b.commands.some((words) => DOWNLOADERS.has(commandName(words[resolveCommand(words, PIPE_RUNNERS).index]?.value ?? ''))))) {
      out.push({ ...RULE_FETCH_EXEC });
    } else {
      collectGenerated(body.map((b) => textOutputOf(b.commands.map(expandWords), { heredocs: b.heredocBodies })), depth, out, scope);
    }
  }
  // A `$( … )` or backtick inside a double-quoted string runs regardless of
  // the quotes (review of 3.6.0, finding 4): `echo "$(rm -rf /)"`, `: "$(…)"`.
  // splitShell masked it away; it is re-entered here as a nested script,
  // within the same nesting cap and budget. An unquoted one is already a
  // statement of its own, so it is not collected twice.
  if (cmd.includes('$(') || cmd.includes('`')) {
    for (const body of quotedSubstitutions(cmd)) {
      if (body.trim() === '') continue;
      if (depth >= MAX_NESTING) {
        scope.notes.depth = true;
        continue;
      }
      noteScript(scope, body, scope.powershell === true);
      collect(body, depth + 1, out, { ...scope, cmdLine: false });
    }
  }
  // Where each command runs, as the `cd`s before it moved it (review of
  // 3.4.0, finding 9): a relative delete target is read against it.
  const dirs = workdirs(statements);
  const startDir = scope.dir;
  // Worked out once per list of moves: the tracker hands every command up to
  // the next move the same list, so a line of thousands of commands after
  // dozens of `cd`s does not fold the same path thousands of times.
  let memoSteps: Steps | undefined;
  let memoDir: string | undefined;
  const dirOf = (steps: Steps): string | undefined => {
    if (steps !== memoSteps) {
      memoSteps = steps;
      memoDir = dirAfter(startDir, steps, { homePath: scope.homePath, vars: scope.vars, bareDriveRoot: scope.bareDriveRoot === true && scope.powershell !== true && scope.cmdLine !== true });
    }
    return memoDir;
  };
  // What a reader is fed from outside one statement's pipeline (review of
  // 3.4.0, finding 6): `tee >(bash)`, `(echo …) | bash`, `{ …; } | bash`,
  // `iex (gc x.ps1 -Raw)`, and a script block made from text.
  const powershellScope = scope.powershell === true;
  collectFed(
    [
      ...(commandText.includes('>(') ? outputSubstitutionScripts(statements, powershellScope) : []),
      ...groupFedScripts(statements, powershellScope),
      ...iexSubexpressionScripts(statements),
      ...(powershellScope && /scriptblock|InvokeCommand|AddScript/i.test(cmd)
        ? scriptBlockScripts(cmd).map((text): FedScript => (text === 'unread' ? { text: '', reader: [], unread: true } : { text, reader: [], kind: 'powershell' }))
        : []),
    ],
    depth,
    out,
    scope,
  );

  for (const [s, written] of statements.entries()) {
    // The total time budget: a hook that outlives Claude Code's 15 s timeout
    // lets the command run unassessed, so what is left is reported instead.
    if (scope.notes.now() > scope.notes.deadline) {
      scope.notes.budget = true;
      return;
    }
    // Brace expansion first, as bash does it (review 8, item 6): `{rm,-rf,/}`
    // runs `rm -rf /`. The statement's words are read expanded from here on.
    const commands = written.commands.map(expandWords);
    const expanded = commands.some((c, k) => c !== written.commands[k]);
    const statement: ShellStatement = expanded ? { ...written, commands } : written;
    // The ReDoS cap applies to each STATEMENT — never to a line before it is
    // split, which let padding hide every statement after it (fix round 1).
    const masked = capText(collapseBlanks(statement.masked), scope.notes);
    // An expanded statement is read as its words, too, a quoted word masked.
    const expandedText = expanded
      ? capText(collapseBlanks(commands.map((ws) => ws.map((w) => (w.quoted ? MASK : w.value)).join(' ')).join(' | ')), scope.notes)
      : undefined;
    for (const rule of BASH_RULES) {
      if (rule.scope === 'command') continue;
      const test = rule.test ?? ((t: string): boolean => rule.pattern.test(t));
      if (test(masked) || (expandedText !== undefined && test(expandedText))) {
        out.push({ id: rule.id, level: rule.level, reason: rule.reason });
      }
    }
    const piped = pipesDownloadIntoShell(statement);
    if (piped !== null) out.push(piped);
    for (const [c, words] of statement.commands.entries()) {
      // The budget is checked per command too: one statement can hold a
      // pipeline of thousands of commands (fix round 3, I-2).
      if (scope.notes.now() > scope.notes.deadline) {
        scope.notes.budget = true;
        return;
      }
      const resolved = resolveCommand(words);
      if (resolved.elevated) out.push({ ...SUDO_RULE });
      const here = dirOf(dirs[s]?.[c]?.may ?? null);
      const deleting: DeleteContext = {
        dir: here,
        vars: scope.vars,
        bareDriveRoot: scope.bareDriveRoot === true && scope.powershell !== true && scope.cmdLine !== true,
        piped: scope.powershell === true && c > 0 ? pipedItems(statement.commands[c - 1] ?? []) : undefined,
        pipedRecursive: scope.powershell === true && c > 0 ? listsRecursively(statement.commands[c - 1] ?? []) : undefined,
      };
      const del = assessRecursiveDelete(words, resolved.index, scope.home, scope.tildeUsers, deleting);
      if (del !== null) out.push(del);
      const find = assessFind(words, resolved.index, scope.home, scope.tildeUsers, deleting);
      if (find !== null) out.push(find);
      // `find ~ -type f | xargs rm -f`: judged as `find … -exec rm` (finding 10).
      const findXargs = findPipedIntoDeleter(statement.commands, c, scope.home, scope.tildeUsers !== false, deleting);
      if (findXargs !== null) out.push(findXargs);
      if (hereStringFetchIntoShell(words, resolved.index)) out.push(RULE_FETCH_EXEC);
      // `bash <<< 'rm -rf /'`, `sh <<< "$(echo … | base64 -d)"`: the here-string is the script (review 8, item 8).
      const hereText = hereStringText(words);
      const hereReader = hereText === undefined ? undefined : scriptReader(words);
      if (hereText !== undefined && hereReader !== undefined) {
        const generated = substitutionOutput(hereText) ?? hereText;
        collectFed([generated === 'opaque' ? { text: '', reader: words, opaque: true } : { text: generated, reader: words, kind: hereReader }], depth, out, { ...scope, dir: here });
      }
      // `python3 -c "$(curl …)"`, `node -e "$(curl …)"`: the program IS a
      // download, as `sh -c "$(curl …)"` is (round 2, ruling 2).
      if (inlineCode(words, resolved.index).some(isBareRemoteFetch)) out.push(RULE_FETCH_EXEC);
      pushAll(out, assessGuardConfig(words, resolved.index, scope));
      if (adoptsDatabase(words, resolved.index) || adoptsDatabaseThroughLauncher(words, resolved.index)) out.push({ ...RULE_DB_ADOPT });
      if (updatesBaseline(words, resolved.index) || throughLauncher(words, resolved.index, updatesBaseline)) {
        out.push({ ...RULE_BASELINE_UPDATE });
      }
      const perms = recursivePermsOnRoot(words, resolved.index, scope.tildeUsers);
      if (perms !== null) out.push(perms);
      const destructive = destructiveCommand(words, resolved.index);
      if (destructive !== null) out.push(destructive);
      const scripts = nestedScripts(words, resolved.index);
      const split = envSplitScript(words, resolved.index);
      if (split !== undefined) scripts.push(shellScript(split));
      // `Start-Process cmd -ArgumentList '/c rd /s /q C:\'`: the command it starts (review 8, item 9).
      const started = startedCommandLine(words, resolved.index);
      if (started !== undefined) scripts.push(shellScript(started));
      const cmdHead = words[resolved.index];
      const line =
        cmdHead !== undefined && commandName(cmdHead.value) === 'cmd'
          ? cmdLineText(withoutRedirections(words.slice(resolved.index + 1)))
          : undefined;
      // Past the nesting depth, what is nested is not judged — and that is a
      // warning, never a silent ok (fix round 3, I-4).
      if (depth >= MAX_NESTING && (scripts.length > 0 || line !== undefined)) scope.notes.depth = true;
      if (depth < MAX_NESTING) {
        for (const { text: script, powershell, iex, unread } of scripts) {
          if (unread === true) {
            out.push({ ...RULE_UNREAD_SCRIPT });
            continue;
          }
          // `sh -c "$(curl …)"` / `bash -c "$(wget -qO- …)"` — the whole -c
          // script IS a download, executed without ever spelling `| sh`.
          // Recursing alone would not catch this: the extracted script is
          // just "curl …" with no pipe to a shell inside it, so nothing in
          // BASH_RULES fires on it at the next depth. Checked directly, in
          // addition to (not instead of) recursing.
          if (isBareRemoteFetch(script)) out.push(RULE_FETCH_EXEC);
          // `bash -c "$(echo … | base64 -d)"`: what the substitution writes is
          // the script (review 8, item 8).
          if (!powershell) collectGenerated([substitutionOutput(script)], depth, out, scope);
          // `iex "& { $(irm …) }"`: whatever `iex` is handed is code, so a
          // download anywhere in it — quoted or not — is run (review I1).
          if (iex === true && PS_DOWNLOAD.test(script)) out.push(RULE_IEX_DOWNLOAD);
          noteScript(scope, script, powershell);
          collect(script, depth + 1, out, { ...scope, cmdLine: false, powershell, dir: here });
          const asPowerShell = powershell ? powershellAsPosix(script) : script;
          if (asPowerShell !== script) collect(asPowerShell, depth + 1, out, { ...scope, cmdLine: false, powershell, dir: here });
        }
        // Every command of a `cmd /c` line gets the full assessment, like a
        // top-level statement: deletes, pattern rules, nested shells (fix
        // round 2 — `cmd /c rd /s /q C:\` was ok, as it was at 166117a).
        if (line !== undefined) {
          noteScript(scope, line, false);
          collect(line, depth + 1, out, { ...scope, cmdLine: true, powershell: false, dir: here });
        }
      }
      moveCwd(scope, words, resolved.index);
    }
    // Finding 4: text a shell actually reads as its script — `bash <<EOF …
    // EOF`, `echo '…' | bash`, `printf '…' | sh` — is assessed as a command
    // in its own right, the same way a `-c` script already is above. Scoped
    // to the STATEMENT rather than any one command in its pipeline, since
    // both shapes this covers depend on more than one command (a reader —
    // `scriptReader` — plus either a heredoc on the same statement or the
    // members before it). A program an interpreter reads the same way
    // (`python - <<EOF`) is judged as program text, like `python -c`.
    const fed = fedScripts(statement, readsScript, scope.powershell === true);
    if (fed.length > 0) collectFed(fed, depth, out, { ...scope, dir: dirOf(dirs[s]?.[0]?.may ?? null) });
    for (const { text, reader, opaque, unread } of fedScripts(statement, isBareInterpreterStdin, scope.powershell === true)) {
      if (unread === true) continue;
      if (opaque === true) out.push({ ...RULE_DECODED_SCRIPT });
      else pushAll(out, judgeCode(text, codeLang(commandName(reader[0]?.value ?? '')), scope));
    }
  }
}

/**
 * Scripts fed to a reader ({@link FedScript}), each assessed as the language
 * its reader runs — a POSIX shell's, PowerShell's (read both ways, as a `pwsh
 * -c` script is), or a cmd.exe line's — and a warning for a decoder's output
 * (`decoded-script`) or any other output (`unread-script`) that cannot be
 * read here: never a silent ok.
 */
function collectFed(fed: readonly FedScript[], depth: number, out: MatchedRule[], scope: Scope): void {
  if (fed.length === 0) return;
  if (fed.some((f) => f.opaque === true)) out.push({ ...RULE_DECODED_SCRIPT });
  if (fed.some((f) => f.unread === true)) out.push({ ...RULE_UNREAD_SCRIPT });
  const readable = fed.filter((f) => f.opaque !== true && f.unread !== true);
  if (readable.length === 0) return;
  if (depth >= MAX_NESTING) {
    scope.notes.depth = true;
    return;
  }
  for (const f of readable) {
    const kind = f.kind ?? scriptReader(f.reader) ?? 'shell';
    const powershell = kind === 'powershell';
    noteScript(scope, f.text, powershell);
    collect(f.text, depth + 1, out, { ...scope, cmdLine: kind === 'cmd', powershell });
    const asPosix = powershell ? powershellAsPosix(f.text) : f.text;
    if (asPosix !== f.text) collect(asPosix, depth + 1, out, { ...scope, cmdLine: false, powershell });
  }
}

/**
 * A script whose text is only known as what another command writes — a
 * process substitution a shell reads, or a `$(…)` handed to `bash -c` /
 * `eval` (review 8, item 8): assessed like any nested script, and a decoder
 * whose output cannot be read is a warning, never a silent ok.
 */
function collectGenerated(texts: ReadonlyArray<string | 'opaque' | undefined>, depth: number, out: MatchedRule[], scope: Scope): void {
  for (const text of texts) {
    if (text === undefined) continue;
    if (text === 'opaque') out.push({ ...RULE_DECODED_SCRIPT });
    else if (depth >= MAX_NESTING) scope.notes.depth = true;
    else {
      noteScript(scope, text, false);
      collect(text, depth + 1, out, { ...scope, cmdLine: false, powershell: false });
    }
  }
}

/** The statement text the pattern rules read is capped here — see the module doc's ReDoS note. */
const MAX_STATEMENT_LENGTH = 16 * 1024;
/** The whole command is read to here: the corpus's longest real command is 58 KB. */
const MAX_COMMAND_LENGTH = 512 * 1024;
/**
 * The assessment's time budget. The hook has 15 s in all; measured, a 512 KB
 * command of the worst shapes (`<(<(…`, `$($(…`) takes up to about 2 s per
 * reading on a loaded machine (the PowerShell tool reads twice), so this
 * only backs the caps up on a machine far slower or busier than expected.
 */
const DEFAULT_BUDGET_MS = 2500;

export interface AssessOptions {
  /** Milliseconds the assessment may take before the rest is reported as not assessed. */
  budgetMs?: number;
  /** The clock (tests). */
  now?: () => number;
  /**
   * The shell that will run the command. For `powershell` the command is ALSO
   * read the way PowerShell quotes (`powershellAsPosix`: backslash literal,
   * backtick escapes, `''` / `""`), and the more severe verdict of the two
   * readings wins (fix round 3, I-3, controller ruling).
   */
  shell?: 'bash' | 'powershell';
  /** The home directory a delete must not name outright (default `os.homedir()`; tests). */
  homeDir?: string;
  /** Decides whether paths compare case-insensitively (default `process.platform`; tests). */
  platform?: NodeJS.Platform;
  /** Claude Code's `CLAUDE_CONFIG_DIR`, whose `settings*.json` are its settings (default: the environment's; `''` for none). */
  claudeConfigDir?: string;
  /**
   * dev-guardian's per-user data directory, whose `registry/` a command may not
   * write (default: `userDataDir()` from the environment; tests). Its default
   * spellings (`~/.local/share/dev-guardian`, `%LOCALAPPDATA%\dev-guardian`,
   * `$GUARDIAN_DATA_DIR`) are recognised whatever this is.
   */
  dataDir?: string;
  /**
   * The directory the command runs in, and the project the session belongs to
   * (the hook's payload `cwd` and its project root). With either, a guarded
   * path spelled in full that lies outside them both and the home directory —
   * another project's `.guardian/hooks.config.json`, a fake HOME's
   * `~/.config/dev-guardian/hooks.json` — warns instead of being denied
   * (review 8, item 14). Without them, every one is denied.
   */
  cwd?: string;
  projectDir?: string;
  /**
   * The environment the command runs with: `TEMP`, `TMP`, `TMPDIR`,
   * `LOCALAPPDATA`, `APPDATA` are what a delete target led by them names
   * (default: this process's; tests).
   */
  env?: Readonly<Record<string, string | undefined>>;
  /**
   * Where an absolute path really leads through the links already on disk —
   * a symbolic link, a junction, an 8.3 name on the way — or `undefined` when
   * as written or unknown. A redirect into `z/` with `z` a junction to
   * `.claude` writes Claude Code's settings (review 12, finding 1). The
   * dispatcher passes one that never asks the network; without it (the CLI's
   * `check`, the tests) paths are judged as written, and through the links
   * the command itself makes.
   */
  realPath?: (path: string) => string | undefined;
}

/** `os.homedir()`, or none when it cannot be determined (it throws without a passwd entry). */
function safeHomedir(): string | undefined {
  try {
    return homedir();
  } catch {
    return undefined;
  }
}

/** The warning for what a cap or the budget dropped — never a silent `ok` — naming which one. */
function partialRule(notes: Notes): MatchedRule | null {
  const causes = [
    ...(notes.statement ? ['over 16 KB'] : []),
    ...(notes.command ? ['over 512 KB'] : []),
    ...(notes.budget ? ['assessment time budget exhausted'] : []),
    ...(notes.depth ? [`nested more than ${MAX_NESTING} levels deep`] : []),
    ...(notes.calls ? [`an [IO.File] call's arguments over ${MAX_CALL_ARGS} characters`] : []),
    ...(notes.failed ? ['the assessment failed'] : []),
    ...(notes.links ? [`more than ${MAX_ALIASES} links made, or ${MAX_LOOKUPS} paths looked up through links`] : []),
  ];
  return causes.length === 0
    ? null
    : { id: 'partially-assessed', level: 'warn', reason: `part of this command was not assessed (${causes.join('; ')})` };
}

/** Runs of spaces and tabs as one space: no rule pattern tells them apart, and padding stops counting. */
function collapseBlanks(text: string): string {
  return text.replace(/[ \t]{2,}/g, ' ');
}

/** What a cap or the budget dropped, shared by every nested scope; and the budget's clock. */
interface Notes {
  statement: boolean;
  command: boolean;
  budget: boolean;
  /** A nested script, cmd line or fed script past {@link MAX_NESTING}, not judged. */
  depth: boolean;
  /** {@link namesLooseningKey} of the whole command, once computed. */
  loosens: boolean | undefined;
  /** The assessment threw part-way; what it found before that still counts. */
  failed: boolean;
  /** An `[IO.File]::` call's arguments ran past {@link MAX_CALL_ARGS}. */
  calls: boolean;
  deadline: number;
  now: () => number;
  /** The scripts handed to a shell so far ({@link BashAssessment.scripts}), by `shell\0text`. */
  scripts: Map<string, { text: string; shell: 'bash' | 'powershell' }>;
  /** The links the command made so far, `[link, target]` as {@link aliasKey} spells them ({@link throughLinks}). */
  aliases: Array<readonly [string, string]>;
  /** The paths looked up on disk so far, with where each really leads ({@link realPathOf}). */
  realPaths: Map<string, string | undefined>;
  /** More links, or lookups, than {@link MAX_ALIASES} / {@link MAX_LOOKUPS}. */
  links: boolean;
}

/** The most nested scripts {@link BashAssessment.scripts} lists. */
const MAX_NOTED_SCRIPTS = 64;

/** Records a script the command hands a shell, for the install vetting ({@link BashAssessment.scripts}). */
function noteScript(scope: Scope, text: string, powershell: boolean): void {
  const scripts = scope.notes.scripts;
  const shell = powershell ? 'powershell' : 'bash';
  const t = text.trim();
  if (t === '' || scripts.size >= MAX_NOTED_SCRIPTS) return;
  const key = `${shell}\0${t}`;
  if (!scripts.has(key)) scripts.set(key, { text: t, shell });
}

/** `text` cut at the cap, noting that something was dropped. */
function capText(text: string, notes: Notes): string {
  if (text.length <= MAX_STATEMENT_LENGTH) return text;
  notes.statement = true;
  return text.slice(0, MAX_STATEMENT_LENGTH);
}

/**
 * Assess a shell command. The overall level is the most severe rule matched;
 * a command a cap cut short is at least a warning (`partially-assessed`).
 */
export function assessBashCommand(command: string, opts: AssessOptions = {}): BashAssessment {
  const whole = (command ?? '').trim();
  if (!whole) return { level: 'ok', reasons: [], rules: [] };
  const now = opts.now ?? ((): number => performance.now());
  const deadline = now() + (opts.budgetMs ?? DEFAULT_BUDGET_MS);
  // The 512 KB cap is on what was written, never on a respelling of it: a
  // respelled `'` is four characters (fix round 4).
  const cut = whole.length > MAX_COMMAND_LENGTH;
  const text = cut ? whole.slice(0, MAX_COMMAND_LENGTH) : whole;
  const homeRaw = opts.homeDir ?? safeHomedir();
  const platform = opts.platform ?? process.platform;
  const home = homeDirFor(homeRaw, platform);
  const dataDir = normalizedPath(opts.dataDir ?? safeUserDataDir());
  const configDir = opts.claudeConfigDir ?? process.env['CLAUDE_CONFIG_DIR'];
  const fold = platform === 'win32';
  const placeKey = (p: string | undefined): string | undefined => (p === undefined || p.trim() === '' ? undefined : targetKey(p, fold));
  const where: Where = {
    home,
    configDirName: configDirNameOf(configDir),
    dataDir: dataDir === '' ? undefined : dataDir,
    tildeUsers: opts.shell !== 'powershell',
    powershell: opts.shell === 'powershell',
    places:
      opts.cwd === undefined && opts.projectDir === undefined
        ? undefined
        : { fold, home: placeKey(homeRaw), cwd: placeKey(opts.cwd), project: placeKey(opts.projectDir), configDir: placeKey(configDir) },
    dir: opts.cwd === undefined || opts.cwd.trim() === '' ? undefined : foldDots(opts.cwd.replace(/\\/g, '/')),
    homePath: homeRaw === undefined ? undefined : homeRaw.replace(/\\/g, '/'),
    vars: targetVariables(opts.env ?? process.env),
    bareDriveRoot: platform === 'win32' && opts.shell !== 'powershell',
    windows: platform === 'win32',
    realPath: opts.realPath,
  };
  if (opts.shell !== 'powershell') return assessReadings([text], cut, now, deadline, where);
  // Under POSIX quoting, PowerShell's ordinary `"C:\Users\"` escapes its
  // closing quote and swallows the rest of the command, with no warning.
  // PowerShell's own reading goes first, so the one budget is never spent on
  // the POSIX reading before the reading that matches what will run; a block
  // needs no second reading. The POSIX reading sees here-strings and block
  // comments for what they are: nothing else can be meant by them.
  return assessReadings([powershellAsPosix(text), powershellOpaque(text)], cut, now, deadline, where);
}

/** What the assessment knows of the machine: the home directory, and Claude Code's `CLAUDE_CONFIG_DIR`. */
interface Where {
  home: HomeDir | undefined;
  configDirName: string | undefined;
  /** dev-guardian's data directory, normalised. */
  dataDir: string | undefined;
  /** `~name` names a home directory — false for the PowerShell tool. */
  tildeUsers: boolean;
  /** The command is PowerShell's (the PowerShell tool): a string that begins a pipeline is its output. */
  powershell: boolean;
  /** Where the guarded paths are this session's, when the caller said where it runs. */
  places: Places | undefined;
  /** The working directory, `/`-separated, when the caller said it. */
  dir: string | undefined;
  homePath: string | undefined;
  vars: Readonly<Record<string, string>>;
  bareDriveRoot: boolean;
  windows: boolean;
  realPath: ((path: string) => string | undefined) | undefined;
}

/** {@link userDataDir}, or `''` when it cannot be worked out. */
function safeUserDataDir(): string {
  try {
    return userDataDir();
  } catch {
    return '';
  }
}

/**
 * The readings of one command, assessed into one verdict: every rule any
 * reading matched, and one partial note for all of them — so on a tie no
 * reading's reasons are dropped. A reading after one that blocked is skipped.
 */
function assessReadings(
  readings: readonly string[],
  cut: boolean,
  now: () => number,
  deadline: number,
  where: Where,
): BashAssessment {
  const notes: Notes = {
    statement: false,
    command: cut,
    budget: false,
    depth: false,
    loosens: undefined,
    failed: false,
    calls: false,
    deadline,
    now,
    scripts: new Map(),
    aliases: [],
    realPaths: new Map(),
    links: false,
  };

  const matched: MatchedRule[] = [];
  for (const [n, cmd] of readings.entries()) {
    if (n > 0 && (cmd === readings[n - 1] || matched.some((m) => m.level === 'block'))) continue;
    notes.loosens = undefined;
    // An exception here used to escape to the hook, which then answered with
    // no decision at all — and the command ran unassessed (fix round 3, I-1:
    // 125 000 operands overflowed the stack). Whatever throws now, the answer
    // is at least a warning, and a block found before it still blocks.
    try {
      collect(cmd, 0, matched, { raw: cmd, cwd: '', notes, ...where });
    } catch {
      notes.failed = true;
    }
  }
  const partial = partialRule(notes);
  if (partial !== null) matched.push(partial);
  const scripts = notes.scripts.size > 0 ? { scripts: [...notes.scripts.values()] } : {};

  if (matched.length === 0) return { level: 'ok', reasons: [], rules: [], ...scripts };

  // De-dupe by id, then most severe first.
  const byId = new Map<string, MatchedRule>();
  for (const m of matched) if (!byId.has(m.id)) byId.set(m.id, m);
  // A catastrophic delete makes the broad-delete note redundant noise.
  if (byId.has('rm-rf-root')) byId.delete('rm-rf-broad');
  const effective = [...byId.values()].sort((a, b) => LEVEL_RANK[b.level] - LEVEL_RANK[a.level]);
  const blocks = effective.filter((r) => r.level === 'block');
  const only = blocks.length === 1 ? blocks[0] : undefined;
  const own = only?.id === RULE_DB_ADOPT.id ? only.reason : undefined;
  const ask = blocks.length === 0 ? byId.get(RULE_BASELINE_UPDATE.id)?.reason : undefined;

  return {
    level: effective[0]?.level ?? 'ok',
    reasons: effective.map((r) => r.reason),
    rules: effective.map((r) => r.id),
    ...(own === undefined ? {} : { denyMessage: own }),
    ...(ask === undefined ? {} : { ask }),
    ...scripts,
  };
}
