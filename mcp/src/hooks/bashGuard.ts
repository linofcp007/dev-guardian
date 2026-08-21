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
 * members** as word lists. Rules then run against structure:
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
 * behind `docker exec … bash -c`), `su … -c '…'` and `eval …` are re-entered
 * and assessed as commands in their own right, to depth 3. That is strictly
 * more coverage than the old text matching had, not less: `bash -c 'rm -rf /'`
 * was never blocked before, and is now.
 *
 * What this is NOT: a shell parser. Command substitution inside double quotes
 * (`echo "$(rm -rf /)"`) stays invisible, exactly as it was before this file
 * grew a scanner. Fail-open is the design; a missed warning is the failure
 * mode we accept, and no block rule was narrowed to get here.
 *
 * Pure functions. No I/O. No dependencies.
 */

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
}

export interface BashAssessment {
  level: BashRiskLevel;
  /** Human-readable reasons, most severe first. */
  reasons: string[];
  /** Matched rule ids, for telemetry / allowlisting. */
  rules: string[];
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
    pattern: /\b(?:curl|wget)\b[^\n]*?\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b/i,
  },
  {
    id: 'powershell-iex-download',
    level: 'block',
    reason: 'Downloads and executes remote code via Invoke-Expression',
    pattern: /(?:iwr|invoke-webrequest|invoke-restmethod|wget|curl)[^\n]*\|\s*(?:iex|invoke-expression)/i,
  },
  {
    id: 'disk-overwrite',
    level: 'block',
    reason: 'Writes raw bytes to a block device (dd/mkfs/shred on /dev/…)',
    // The `\b` used to sit in front of the whole group, and a leading `\b`
    // before `>` demands a word character immediately to its left — so the
    // redirect alternative matched `cat x>/dev/sda` and never the
    // `cat x > /dev/sda` anybody actually writes. Each alternative anchors
    // itself now.
    pattern: /(?:\bdd\b[^\n]*\bof=\/dev\/|\bmkfs(?:\.\w+)?\s+\/dev\/|\bshred\b[^\n]*\/dev\/|>\s*\/dev\/(?:sd|nvme|hd|disk))/i,
  },
  {
    id: 'fork-bomb',
    level: 'block',
    reason: 'Shell fork bomb',
    // Scoped to the whole command: `(`, `)`, `|`, `&` and `;` are the very
    // characters splitShell() separates on, so this signature only exists
    // before segmentation. Quoted spans are still masked, so
    // `echo ':(){ :|:& };:'` stays inert.
    pattern: /:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/,
    scope: 'command',
  },
  {
    id: 'chmod-777-root',
    level: 'block',
    reason: 'Recursively makes the filesystem root world-writable',
    pattern: /\bchmod\b[^\n]*-[a-z]*R[a-z]*\s+0?777\s+\/(?:\s|$)/i,
  },

  // ── Risky: warn only ─────────────────────────────────────────────────────
  {
    id: 'git-force-push',
    level: 'warn',
    reason: 'Force-push can overwrite remote history',
    pattern: /\bgit\s+push\b[^\n]*?(?:--force\b|--force-with-lease\b|\s-f\b)/i,
  },
  {
    id: 'git-hard-reset',
    level: 'warn',
    reason: 'git reset --hard discards uncommitted work',
    pattern: /\bgit\s+reset\b[^\n]*--hard\b/i,
  },
  {
    id: 'git-clean-force',
    level: 'warn',
    reason: 'git clean -fd permanently removes untracked files',
    pattern: /\bgit\s+clean\b[^\n]*-[a-z]*f/i,
  },
  {
    id: 'chmod-777',
    level: 'warn',
    reason: 'chmod 777 grants world-write — overly permissive',
    pattern: /\bchmod\b[^\n]*\b0?777\b/i,
  },
  {
    id: 'history-wipe',
    level: 'warn',
    reason: 'Clears shell history',
    pattern: /\bhistory\s+-c\b|>\s*~?\/?\.(?:bash|zsh)_history\b/i,
  },
];

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
const MASK = ' ';

export interface ShellWord {
  /** The word after quote removal — what the shell would actually pass. */
  value: string;
  /** True when any character of the word came from inside quotes. */
  quoted: boolean;
}

export interface ShellStatement {
  /** Raw statement text with every quoted span replaced by {@link MASK}. */
  masked: string;
  /** Pipeline members, one word list per simple command. */
  commands: ShellWord[][];
}

export interface ShellSplit {
  /** The whole command, masked, with separators intact and heredocs removed. */
  maskedCommand: string;
  statements: ShellStatement[];
}

interface PendingHeredoc {
  word: string;
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
 * Skips the bodies of every heredoc opened on the line just ended. The body is
 * data on the command's stdin, never shell code; a commit message written
 * through `git commit -F - <<'EOF'` is the shape that made this necessary.
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
    for (;;) {
      if (pos >= source.length) return source.length;
      const newline = source.indexOf('\n', pos);
      const line = newline === -1 ? source.slice(pos) : source.slice(pos, newline);
      pos = newline === -1 ? source.length : newline + 1;
      if (line.trim() === heredoc.word) break;
      if (newline === -1) return source.length;
    }
  }
  return pos;
}

/**
 * Segments a command into statements and their pipeline members. Quote-,
 * escape- and heredoc-aware; not a shell parser (see the module comment).
 */
export function splitShell(command: string): ShellSplit {
  const statements: ShellStatement[] = [];
  let maskedCommand = '';

  let masked = '';
  let commands: ShellWord[][] = [];
  let words: ShellWord[] = [];
  let buf = '';
  let bufQuoted = false;
  let hasWord = false;
  /** Last code character emitted, to tell a background `&` from `2>&1`. */
  let lastCode = '';
  const heredocs: PendingHeredoc[] = [];

  const endWord = (): void => {
    if (hasWord) words.push({ value: buf, quoted: bufQuoted });
    buf = '';
    bufQuoted = false;
    hasWord = false;
  };
  const endCommand = (): void => {
    endWord();
    if (words.length > 0) commands.push(words);
    words = [];
  };
  const endStatement = (): void => {
    endCommand();
    const text = masked.trim();
    if (text.length > 0 || commands.length > 0) statements.push({ masked: text, commands });
    masked = '';
    commands = [];
    lastCode = '';
  };
  const emitCode = (ch: string): void => {
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

    if (ch === "'" || ch === '"') {
      const scanned = scanQuote(command, i);
      buf += scanned.inner;
      bufQuoted = true;
      hasWord = true;
      masked += MASK;
      maskedCommand += MASK;
      lastCode = MASK;
      i = scanned.next;
      continue;
    }

    if (ch === '\n') {
      endStatement();
      maskedCommand += '\n';
      i = heredocs.length > 0 ? skipHeredocBodies(command, i + 1, heredocs) : i + 1;
      continue;
    }

    if (ch === ';') {
      endStatement();
      maskedCommand += ';';
      i += 1;
      continue;
    }

    // Subshells, groups and command substitution: whatever is inside runs as
    // its own command, so the boundary is a statement boundary.
    if (ch === '(' || ch === ')' || ch === '`') {
      endStatement();
      maskedCommand += ch;
      i += 1;
      continue;
    }

    if (ch === '&') {
      const next = command.charAt(i + 1);
      if (next === '&') {
        endStatement();
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
      endStatement();
      maskedCommand += '&';
      i += 1;
      continue;
    }

    if (ch === '|') {
      const next = command.charAt(i + 1);
      if (next === '|') {
        endStatement();
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

    if (ch === '<' && command.charAt(i + 1) === '<' && command.charAt(i + 2) !== '<') {
      const heredoc = readHeredocOperator(command, i);
      if (heredoc !== null) {
        heredocs.push({ word: heredoc.word });
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

  return { maskedCommand, statements };
}

// ────────────────────────────────────────────────────── tokenised rules

function basename(value: string): string {
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
]);

/** Runner flags that consume the next word, so it is not the command. */
const FLAG_TAKES_VALUE = new Set(['-u', '-g', '-n', '-C', '-k', '-s', '-I', '-i', '--user', '--group']);

const ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/;

/**
 * Walks past `VAR=x` assignments and runner prefixes (`sudo`, `env`, `xargs`,
 * `timeout 30`, …) to the index of the word that actually names the command,
 * reporting on the way whether privilege was elevated.
 */
function resolveCommand(words: ShellWord[]): { index: number; elevated: boolean } {
  let i = 0;
  let elevated = false;
  let guard = 0;
  while (i < words.length && guard < 32) {
    guard += 1;
    const word = words[i];
    if (word === undefined) break;
    if (ASSIGNMENT.test(word.value)) {
      i += 1;
      continue;
    }
    const name = basename(word.value);
    if (!RUNNERS.has(name)) break;
    if (name === 'sudo' || name === 'doas') elevated = true;
    i += 1;
    while (i < words.length) {
      const arg = words[i];
      if (arg === undefined) break;
      if (ASSIGNMENT.test(arg.value)) {
        i += 1;
        continue;
      }
      if (arg.value.startsWith('-') && arg.value.length > 1) {
        i += FLAG_TAKES_VALUE.has(arg.value) ? 2 : 1;
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

function stripQuotes(token: string): string {
  return token.replace(/^['"`]+|['"`]+$/g, '');
}

/** Filesystem locations whose recursive deletion is effectively never intended. */
function isCatastrophicTarget(raw: string): boolean {
  const t = stripQuotes(raw);
  if (t === '/' || /^\/\*+$/.test(t)) return true; // root, or everything under root
  if (t === '~' || t === '~/') return true; // home root
  if (/^\$\{?HOME\}?\/?$/.test(t)) return true; // $HOME / ${HOME}
  // Top-level system directories (exact, optionally trailing / or /*).
  if (/^\/(?:etc|usr|bin|sbin|var|lib|lib64|boot|sys|proc|root|home|opt|dev)(?:\/\*?)?$/.test(t)) {
    return true;
  }
  return false;
}

/**
 * Tokenised assessment of one simple command. The *target* — not just the
 * flags — decides severity: `rm -rf /` is catastrophic, `rm -rf node_modules`
 * is merely risky.
 */
function assessRm(words: ShellWord[], start: number): MatchedRule | null {
  const head = words[start];
  if (head === undefined || basename(head.value) !== 'rm') return null;

  let recursive = false;
  let force = false;
  let noPreserve = false;
  const targets: string[] = [];

  for (const word of words.slice(start + 1)) {
    const token = word.value;
    if (token === '--no-preserve-root') noPreserve = true;
    else if (token === '--recursive') recursive = true;
    else if (token === '--force') force = true;
    else if (token.startsWith('--')) continue;
    else if (token.startsWith('-')) {
      const flags = token.slice(1);
      if (/r/i.test(flags)) recursive = true;
      if (/f/.test(flags)) force = true;
    } else targets.push(token);
  }

  if (!((recursive && force) || noPreserve)) return null;

  if (noPreserve || targets.some(isCatastrophicTarget)) {
    return {
      id: 'rm-rf-root',
      level: 'block',
      reason: 'Recursive force-delete targeting the filesystem root or home directory',
    };
  }
  return {
    id: 'rm-rf-broad',
    level: 'warn',
    reason: 'Recursive force-delete — confirm the target path is intended',
  };
}

const SHELLS = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh', 'ash', 'mksh', 'su']);
const DASH_C = /^-[A-Za-z]*c$/;

/**
 * Scripts this command hands to a shell — `sh -c '…'`, `bash -lc '…'`,
 * `docker exec box bash -c '…'`, `su -s /bin/sh www-data -c '…'`, `eval …`.
 * Masking quoted spans would otherwise make those bodies unmatchable, which
 * *is* the right call for `echo 'git push --force'` and the wrong one here.
 */
function nestedScripts(words: ShellWord[], start: number): string[] {
  const head = words[start];
  if (head !== undefined && basename(head.value) === 'eval') {
    const script = words
      .slice(start + 1)
      .map((w) => w.value)
      .join(' ')
      .trim();
    return script.length > 0 ? [script] : [];
  }
  for (let i = start; i < words.length; i += 1) {
    const word = words[i];
    if (word === undefined || word.quoted || !DASH_C.test(word.value)) continue;
    const namesShell = words.slice(start, i).some((w) => SHELLS.has(basename(w.value)));
    if (!namesShell) continue;
    const script = words[i + 1];
    return script === undefined ? [] : [script.value];
  }
  return [];
}

// ──────────────────────────────────────────────────────────── assessment

const MAX_NESTING = 3;

function collect(command: string, depth: number, out: MatchedRule[]): void {
  const cmd = command.trim();
  if (cmd.length === 0) return;

  const { maskedCommand, statements } = splitShell(cmd);

  for (const rule of BASH_RULES) {
    if (rule.scope === 'command' && rule.pattern.test(maskedCommand)) {
      out.push({ id: rule.id, level: rule.level, reason: rule.reason });
    }
  }

  for (const statement of statements) {
    for (const rule of BASH_RULES) {
      if (rule.scope !== 'command' && rule.pattern.test(statement.masked)) {
        out.push({ id: rule.id, level: rule.level, reason: rule.reason });
      }
    }
    for (const words of statement.commands) {
      const resolved = resolveCommand(words);
      if (resolved.elevated) out.push({ ...SUDO_RULE });
      const rm = assessRm(words, resolved.index);
      if (rm !== null) out.push(rm);
      if (depth < MAX_NESTING) {
        for (const script of nestedScripts(words, resolved.index)) collect(script, depth + 1, out);
      }
    }
  }
}

/**
 * Assess a shell command. The overall level is the most severe rule matched.
 */
export function assessBashCommand(command: string): BashAssessment {
  const cmd = (command ?? '').trim();
  if (!cmd) return { level: 'ok', reasons: [], rules: [] };

  const matched: MatchedRule[] = [];
  collect(cmd, 0, matched);

  if (matched.length === 0) return { level: 'ok', reasons: [], rules: [] };

  // De-dupe by id, then most severe first.
  const byId = new Map<string, MatchedRule>();
  for (const m of matched) if (!byId.has(m.id)) byId.set(m.id, m);
  // A catastrophic delete makes the broad-delete note redundant noise.
  if (byId.has('rm-rf-root')) byId.delete('rm-rf-broad');
  const effective = [...byId.values()].sort((a, b) => LEVEL_RANK[b.level] - LEVEL_RANK[a.level]);

  return {
    level: effective[0]?.level ?? 'ok',
    reasons: effective.map((r) => r.reason),
    rules: effective.map((r) => r.id),
  };
}
