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
export const BASH_RULES = [
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
        pattern: /\b(?:curl|wget)\b[^\n]*?\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:ba|z|da)?sh\b/i,
    },
    {
        id: 'powershell-iex-download',
        level: 'block',
        reason: 'Downloads and executes remote code via Invoke-Expression',
        // `irm`/`iwr` are PowerShell's own built-in aliases for
        // Invoke-RestMethod/Invoke-WebRequest — as common in the wild as the
        // full names, and the piped-download shape is identical either way.
        pattern: /(?:iwr|irm|invoke-webrequest|invoke-restmethod|wget|curl)[^\n]*\|\s*(?:iex|invoke-expression)/i,
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
        // `isBareRemoteFetch` on the extracted `-c` script text.
        pattern: /\b(?:sh|bash|zsh|dash|ksh|ash|mksh)\b[^\n]*<\(\s*(?:curl|wget)\b/i,
        scope: 'command',
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
        pattern: /(?:\bdd\b[^\n]*\bof=(?:\/dev\/(?:sd|hd|vd|xvd|nvme|mmcblk|disk|md|dm-)[\w-]*|\\\\\.\\PhysicalDrive\d*)|\bmkfs(?:\.\w+)?\b[^\n]*\/dev\/|\bwipefs\b[^\n]*\/dev\/|\bshred\b[^\n]*\/dev\/|>\s*\/dev\/(?:sd|hd|vd|xvd|nvme|mmcblk|disk|md|dm-))/i,
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
        // `chmod 777 -R /` is the same hazard as `chmod -R 777 /` with the flag
        // and the mode swapped — both orders are real, so both are matched.
        pattern: /\bchmod\b[^\n]*(?:-[a-z]*R[a-z]*\s+0?777\s+\/(?:\s|$)|0?777\s+-[a-z]*R[a-z]*\s+\/(?:\s|$))/i,
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
};
const LEVEL_RANK = { ok: 0, warn: 1, block: 2 };
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
/** Reads a quoted span starting at `start`, returning its content and the index after it. */
function scanQuote(source, start) {
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
        if (ch === quote)
            return { inner, next: i + 1 };
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
function readHeredocOperator(source, start) {
    let i = start + 2;
    if (source.charAt(i) === '-')
        i += 1; // `<<-` strips leading tabs from the body
    while (source.charAt(i) === ' ' || source.charAt(i) === '\t')
        i += 1;
    const quote = source.charAt(i);
    let word = '';
    if (quote === "'" || quote === '"') {
        const scanned = scanQuote(source, i);
        word = scanned.inner;
        i = scanned.next;
    }
    else {
        while (i < source.length && /[A-Za-z0-9_]/.test(source.charAt(i))) {
            word += source.charAt(i);
            i += 1;
        }
    }
    if (!HEREDOC_WORD.test(word))
        return null;
    return { word, next: i };
}
/**
 * Attaches a captured heredoc body to the statement that opened it
 * ({@link PendingHeredoc.statement}), appending rather than overwriting —
 * `bash <<A; bash <<B` opens two heredocs on the SAME statement's command
 * list in principle (two simple commands, but if a single command opened
 * two, e.g. via redirection tricks, both bodies belong to it).
 */
function attachHeredocBody(heredoc, body) {
    const target = heredoc.statement;
    if (target.heredocBodies === undefined)
        target.heredocBodies = [];
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
 * command is a bare shell reading stdin ({@link isBareShellStdin}); this
 * function has no way to know that itself, since it only ever sees raw
 * source text, not resolved commands.
 *
 * The delimiter is matched on the trimmed line, which covers `<<` and `<<-`
 * alike and errs toward ending the heredoc *early*. That is the safe side:
 * ending early resumes treating text as shell, so the worst case is a false
 * positive, never a hazard swallowed as data.
 */
function skipHeredocBodies(source, from, pending) {
    let pos = from;
    while (pending.length > 0) {
        const heredoc = pending.shift();
        if (heredoc === undefined)
            break;
        const lines = [];
        for (;;) {
            if (pos >= source.length) {
                attachHeredocBody(heredoc, lines.join('\n'));
                return source.length;
            }
            const newline = source.indexOf('\n', pos);
            const line = newline === -1 ? source.slice(pos) : source.slice(pos, newline);
            pos = newline === -1 ? source.length : newline + 1;
            if (line.trim() === heredoc.word)
                break;
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
export function splitShell(command) {
    const statements = [];
    let maskedCommand = '';
    let masked = '';
    let commands = [];
    let words = [];
    let buf = '';
    let bufQuoted = false;
    let bufRedirects = [];
    let hasWord = false;
    /** Last code character emitted, to tell a background `&` from `2>&1`. */
    let lastCode = '';
    const heredocs = [];
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
    let currentStatement = { masked: '', commands: [] };
    const endWord = () => {
        // A reserved word where a command name belongs opens or closes a compound
        // command (`do rm -rf /`, `then …`, `{ …`); the command is the word AFTER
        // it. Kept, it read as a command called `do`, and every loop, `if` and
        // brace-group body went unassessed (final review I13).
        const reserved = hasWord && !bufQuoted && words.length === 0 && COMPOUND_RESERVED.has(buf);
        if (hasWord && !reserved) {
            words.push(bufRedirects.length > 0
                ? { value: buf, quoted: bufQuoted, redirectAt: bufRedirects }
                : { value: buf, quoted: bufQuoted });
        }
        buf = '';
        bufQuoted = false;
        bufRedirects = [];
        hasWord = false;
    };
    const endCommand = () => {
        endWord();
        if (words.length > 0)
            commands.push(words);
        words = [];
    };
    const endStatement = () => {
        endCommand();
        const text = masked.trim();
        if (text.length > 0 || commands.length > 0) {
            currentStatement.masked = text;
            currentStatement.commands = commands;
            statements.push(currentStatement);
        }
        masked = '';
        commands = [];
        lastCode = '';
        currentStatement = { masked: '', commands: [] };
    };
    const emitCode = (ch) => {
        if (ch === '>' || ch === '<')
            bufRedirects.push(buf.length);
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
            // `>|` is a redirection (write, overriding noclobber), not a pipe.
            if (lastCode === '>') {
                emitCode('|');
                i += 1;
                continue;
            }
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
    return { maskedCommand, statements };
}
// ────────────────────────────────────────────────────── tokenised rules
function basename(value) {
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
function resolveCommand(words) {
    let i = 0;
    let elevated = false;
    let guard = 0;
    while (i < words.length && guard < 32) {
        guard += 1;
        const word = words[i];
        if (word === undefined)
            break;
        if (ASSIGNMENT.test(word.value)) {
            i += 1;
            continue;
        }
        const name = basename(word.value);
        if (!RUNNERS.has(name))
            break;
        if (name === 'sudo' || name === 'doas')
            elevated = true;
        i += 1;
        while (i < words.length) {
            const arg = words[i];
            if (arg === undefined)
                break;
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
function stripQuotes(token) {
    return token.replace(/^['"`]+|['"`]+$/g, '');
}
/**
 * Filesystem locations whose recursive deletion is effectively never
 * intended. Covers POSIX roots and home, macOS's `/Users`/`/System`, Git
 * Bash / WSL drive-root spellings (`/c`, `/c/*`, `/mnt/c`, `/mnt/c/*`) and
 * native Windows drive roots (`C:/`, `C:\`, `C:/*`) — the same set applies
 * whether the command deleting them is `rm`, PowerShell's `Remove-Item`, or
 * `rd`/`del`, so this is shared by every delete-assessing function below.
 */
function isCatastrophicTarget(raw) {
    const t = stripQuotes(raw);
    if (t === '/' || /^\/\*+$/.test(t))
        return true; // root, or everything under root
    if (t === '~' || t === '~/' || t === '~/*')
        return true; // home root, incl. everything under it
    if (/^\$\{?HOME\}?(?:\/\*?)?$/.test(t))
        return true; // $HOME, $HOME/, $HOME/*, ${HOME}, …
    // Git Bash / WSL drive-root spellings: /c, /c/, /c/*, /mnt/c, /mnt/c/*.
    if (/^\/[a-z](?:\/\*?)?$/i.test(t))
        return true;
    if (/^\/mnt\/[a-z](?:\/\*?)?$/i.test(t))
        return true;
    // Native Windows drive roots: C:/, C:\, C:/*, C:\*.
    if (/^[A-Za-z]:[\\/]\*?$/.test(t))
        return true;
    // Top-level system directories (exact, optionally trailing / or /*),
    // including macOS's capitalised ones.
    if (/^\/(?:etc|usr|bin|sbin|var|lib|lib64|boot|sys|proc|root|home|opt|dev|Users|System)(?:\/\*?)?$/.test(t)) {
        return true;
    }
    return false;
}
/** `rm`/PowerShell's `Remove-Item` (and its `ri` alias) — dash-style flags. */
const DASH_DELETE_HEADS = new Set(['rm', 'ri', 'remove-item']);
/** cmd.exe-style delete commands, also reachable from PowerShell — slash flags. */
const SLASH_DELETE_HEADS = new Set(['rd', 'rmdir', 'del', 'erase']);
/**
 * Tokenised assessment of one simple command. The *target* — not just the
 * flags — decides severity: `rm -rf /` is catastrophic, `rm -rf node_modules`
 * is merely risky. Covers both `rm`/`Remove-Item`/`ri` (dash flags: GNU-style
 * clusters like `-rf`/`-fo`, `--recursive`/`--force`, and PowerShell's
 * whole-word `-Recurse`/`-Force`) and `rd`/`rmdir`/`del`/`erase` (cmd.exe-
 * style slash flags: `/s` recurse, `/q` quiet-force).
 */
function assessRecursiveDelete(words, start) {
    const head = words[start];
    if (head === undefined)
        return null;
    const name = basename(head.value).toLowerCase();
    const dashStyle = DASH_DELETE_HEADS.has(name);
    const slashStyle = !dashStyle && SLASH_DELETE_HEADS.has(name);
    if (!dashStyle && !slashStyle)
        return null;
    let recursive = false;
    let force = false;
    let noPreserve = false;
    const targets = [];
    for (const word of words.slice(start + 1)) {
        const token = word.value;
        if (dashStyle) {
            if (token === '--no-preserve-root')
                noPreserve = true;
            else if (token === '--recursive')
                recursive = true;
            else if (token === '--force')
                force = true;
            else if (token.startsWith('--'))
                continue;
            else if (token.startsWith('-')) {
                const flags = token.slice(1);
                const lower = flags.toLowerCase();
                // PowerShell's whole-word parameter names first — `-Recurse`,
                // `-Force`, and their common abbreviations. Checked before the
                // GNU-cluster heuristic below because that heuristic (does the flag
                // text contain the letter r/f anywhere?) is right for a *cluster* of
                // single-letter flags like `-rf`/`-fo`, where every character really
                // is its own flag, and wrong for a whole parameter name — `-Filter`
                // or `-Confirm` both contain an 'f', and would otherwise read as
                // `-Force` by accident.
                if (lower === 'recurse' || lower === 'rec')
                    recursive = true;
                else if (lower === 'force' || lower === 'fo')
                    force = true;
                else if (flags.length <= 3) {
                    if (/r/i.test(flags))
                        recursive = true;
                    if (/f/i.test(flags))
                        force = true;
                }
            }
            else
                targets.push(token);
        }
        else {
            const lower = token.toLowerCase();
            if (lower === '/s')
                recursive = true;
            else if (lower === '/q')
                force = true;
            else if (token.startsWith('/'))
                continue;
            else
                targets.push(token);
        }
    }
    if (!((recursive && force) || noPreserve))
        return null;
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
/**
 * `find … -delete` — like `rm`/`Remove-Item`, the *target* decides severity:
 * the filesystem root is catastrophic, the home directory is merely risky
 * (an ordinary `find some/path -delete` is neither and stays 'ok'). Only the
 * leading, non-flag operands are read as paths — `find / -name foo -delete`
 * still targets `/`, but a flag value that happens to equal `/` or `~` after
 * a primary (e.g. `-path /`) is not mistaken for `find`'s own start path.
 */
function assessFind(words, start) {
    const head = words[start];
    if (head === undefined || basename(head.value) !== 'find')
        return null;
    const rest = words.slice(start + 1);
    if (!rest.some((w) => w.value === '-delete'))
        return null;
    const targets = [];
    for (const word of rest) {
        if (word.value.startsWith('-'))
            break; // first primary/flag ends the path list
        targets.push(stripQuotes(word.value));
    }
    if (targets.length === 0)
        return null;
    if (targets.some((t) => t === '/' || /^\/\*+$/.test(t))) {
        return {
            id: 'find-delete-root',
            level: 'block',
            reason: 'find … -delete on the filesystem root deletes everything under it',
        };
    }
    if (targets.some((t) => t === '~' || t === '~/' || /^\$\{?HOME\}?\/?$/.test(t))) {
        return {
            id: 'find-delete-home',
            level: 'warn',
            reason: 'find … -delete targets the home directory — confirm this is intended',
        };
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
function isHookConfigPath(arg) {
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
function isHookConfigDir(arg) {
    return HOOK_CONFIG_DIR.test(arg.replace(/\\/g, '/'));
}
/** Commands that create a link (never a FIFO or a device node). */
const LINK_CREATORS = new Set(['ln', 'mklink', 'cmd', 'new-item', 'ni']);
/** `a/b/c` → `c`, for either separator. */
function lastSegment(path) {
    return path.split(/[\\/]/).filter((s) => s.length > 0).pop() ?? path;
}
/** The words that are not options, `--` ending the options; `valued` options consume the next word. */
function operands(args, valued) {
    const out = [];
    let optionsDone = false;
    for (let i = 0; i < args.length; i++) {
        const a = args[i] ?? '';
        if (!optionsDone && a === '--') {
            optionsDone = true;
            continue;
        }
        if (!optionsDone && a.startsWith('-') && a.length > 1) {
            if (valued.has(a))
                i++;
            continue;
        }
        out.push(a);
    }
    return out;
}
/** `ln [opts] TARGET… LINK`, `ln [opts] TARGET`, `ln -t DIR TARGET…`: the paths it creates. */
function lnDestinations(args) {
    let dir;
    const rest = [];
    for (let i = 0; i < args.length; i++) {
        const a = args[i] ?? '';
        const long = /^--target-directory=(.+)$/.exec(a);
        if (long !== null)
            dir = long[1];
        else if (a === '--target-directory' || /^-[a-zA-Z]*t$/.test(a))
            dir = args[++i];
        else if (/^-t./.test(a))
            dir = a.slice(2);
        else if (a === '-S' || a === '--suffix')
            i++;
        else
            rest.push(a);
    }
    const targets = operands(rest, new Set());
    if (dir !== undefined)
        return targets.map((t) => `${dir}/${lastSegment(t)}`);
    if (targets.length >= 2)
        return [targets[targets.length - 1] ?? ''];
    return targets.length === 1 ? [lastSegment(targets[0] ?? '')] : [];
}
/** `New-Item`'s link path (`-Path`, `-LiteralPath`, `-Name`, or the first positional) — only for a link item type. */
function newItemLinkDestinations(args) {
    let itemType = '';
    const paths = [];
    const positional = [];
    for (let i = 0; i < args.length; i++) {
        const a = args[i] ?? '';
        const param = /^-([A-Za-z]+)(?::(.*))?$/.exec(a);
        if (param === null) {
            positional.push(a);
            continue;
        }
        const name = (param[1] ?? '').toLowerCase();
        const inline = param[2];
        const takesValue = ['path', 'literalpath', 'name', 'itemtype', 'type', 'target', 'value', 'credential'].includes(name);
        const value = inline !== undefined ? inline : takesValue ? (args[++i] ?? '') : undefined;
        if (value === undefined)
            continue;
        if (name === 'itemtype' || name === 'type')
            itemType = value;
        else if (name === 'path' || name === 'literalpath' || name === 'name')
            paths.push(value);
    }
    if (!/^(?:symboliclink|hardlink|junction)$/i.test(itemType))
        return [];
    if (paths.length === 0 && positional.length > 0)
        paths.push(positional[0] ?? '');
    return paths;
}
/** `mklink [/D|/H|/J] LINK TARGET`: the link is the first operand. */
function mklinkDestinations(args) {
    const link = args.find((a) => !a.startsWith('/'));
    return link === undefined ? [] : [link];
}
/**
 * Splits a cmd.exe command line the way cmd does for `mklink`: on whitespace
 * outside double quotes, with the quotes removed and backslashes literal.
 */
function splitCmdLine(line) {
    const out = [];
    let cur = '';
    let inQuote = false;
    let has = false;
    for (const ch of line) {
        if (ch === '"') {
            inQuote = !inQuote;
            has = true;
        }
        else if (!inQuote && /\s/.test(ch)) {
            if (has)
                out.push(cur);
            cur = '';
            has = false;
        }
        else {
            cur += ch;
            has = true;
        }
    }
    if (has)
        out.push(cur);
    return out;
}
/**
 * `cmd /c mklink LINK TARGET` (or `/k`): the link `mklink` creates. The command
 * cmd runs is the word after the `/c`/`/k` switch. When that word is itself a
 * whole command line — `cmd /c "mklink a b"` hands cmd ONE quoted word — it is
 * split the way cmd splits it; any other word is kept whole, so a quoted link
 * path with a space in it (`"C:\Users\me\CLAUDE SKILLS\…"`) is judged as the
 * one path it is. Splitting every word on whitespace, as this used to, cut
 * such a path in two and never recognised it (final review I11).
 */
function cmdMklinkDestinations(args) {
    const at = args.findIndex((a) => /^\/[ck]$/i.test(a));
    if (at < 0)
        return [];
    const first = args[at + 1];
    if (first === undefined)
        return [];
    const head = first.trim();
    const line = /\s/.test(head) ? splitCmdLine(head) : [head];
    const rest = [...line.slice(1), ...args.slice(at + 2)];
    const command = (line[0] ?? '').toLowerCase().replace(/\.exe$/, '');
    return command === 'mklink' ? mklinkDestinations(rest) : [];
}
/**
 * The paths a FIFO-, device- or link-creating command writes: `mkfifo NAME…`,
 * `mknod NAME TYPE …`, `ln`'s link names, `mklink`'s link (directly or through
 * `cmd /c`), and `New-Item -ItemType SymbolicLink|HardLink|Junction`'s path.
 * Never a link's SOURCE: `ln -s ~/.config/dev-guardian/hooks.json backup.json`
 * reads the config, it does not replace it.
 */
function specialFileDestinations(name, args) {
    switch (name) {
        case 'mkfifo':
            return operands(args, new Set(['-m', '--mode']));
        case 'mknod':
            return operands(args, new Set(['-m', '--mode'])).slice(0, 1);
        case 'ln':
            return lnDestinations(args);
        case 'mklink':
            return mklinkDestinations(args);
        case 'new-item':
        case 'ni':
            return newItemLinkDestinations(args);
        case 'cmd':
            return cmdMklinkDestinations(args);
        default:
            return [];
    }
}
/**
 * A FIFO, a device node or a link created AT one of the hook configuration
 * files, or a link created at the directory holding them (`.guardian`,
 * `~/.config/dev-guardian` — final review I12). A FIFO or a link to
 * `/dev/zero` there used to hang the hook until its 15 s timeout, after which
 * the tool call ran unguarded (Task 23 fix round 2, N1). The hook's reader
 * now refuses such a file (it judges the descriptor it opened, and refuses a
 * link to a network path before opening), so this is defence in depth:
 * refusing to create one there, as the Write/Edit guard refuses an
 * assistant's edit of the same files.
 */
function assessGuardConfigSpecialFile(words, start) {
    const head = words[start];
    if (head === undefined)
        return null;
    const name = basename(head.value).toLowerCase().replace(/\.exe$/, '');
    const args = words.slice(start + 1).map((w) => w.value);
    const makesLink = LINK_CREATORS.has(name);
    const hits = specialFileDestinations(name, args).some((p) => isHookConfigPath(p) || (makesLink && isHookConfigDir(p)));
    if (!hits)
        return null;
    return {
        id: 'guard-config-special-file',
        level: 'block',
        reason: "Replaces the guardrail hooks' own configuration with a FIFO, a device node or a link",
    };
}
/** The first unquoted redirection in `word`, if it has one. */
function parseRedirect(word) {
    const at = word.redirectAt?.[0];
    if (at === undefined)
        return null;
    const tail = word.value.slice(at);
    const op = /^[<>]+[|&]?/.exec(tail)?.[0] ?? tail.charAt(0);
    return { prefix: word.value.slice(0, at), op, inline: tail.slice(op.length) };
}
/**
 * The files a simple command's redirections write: `> f`, `>> f`, `>| f`,
 * `N> f`, `&> f`, `>f`. Only an UNQUOTED operator counts
 * ({@link ShellWord.redirectAt}); `>&2` / `>&-` duplicate or close a
 * descriptor and name no file, and `<…` only reads.
 */
function redirectTargets(words) {
    const out = [];
    for (let i = 0; i < words.length; i += 1) {
        const word = words[i];
        const r = word === undefined ? null : parseRedirect(word);
        if (r === null || !r.op.startsWith('>'))
            continue;
        const next = words[i + 1]?.value;
        if (r.op.endsWith('&')) {
            const fd = r.inline !== '' ? r.inline : (next ?? '');
            if (/^\d*-?$/.test(fd))
                continue;
        }
        const target = r.inline !== '' ? r.inline : next;
        if (target !== undefined)
            out.push(target);
    }
    return out;
}
/**
 * The argument values with every redirection (operator and operand) removed,
 * so `tee /tmp/x < .guardian/hooks.config.json` reads as `tee /tmp/x`: a file
 * a command reads through `<` is never one it writes.
 */
function withoutRedirections(words) {
    const out = [];
    for (let i = 0; i < words.length; i += 1) {
        const word = words[i];
        if (word === undefined)
            continue;
        const r = parseRedirect(word);
        if (r === null) {
            out.push(word.value);
            continue;
        }
        if (!/^(?:\d*|&)$/.test(r.prefix))
            out.push(r.prefix);
        if (r.inline === '')
            i += 1;
    }
    return out;
}
/** `DIR/<last segment of src>`, for a copy or move into a directory. */
function intoDir(dir, src) {
    return `${dir.replace(/[\\/]+$/, '')}/${lastSegment(src)}`;
}
/**
 * `cp`/`mv`/`install`: the destination, and — since it may be a directory —
 * every source's name inside it. `-t DIR` / `--target-directory=DIR` names the
 * directory outright.
 */
function copyDestinations(args, valued) {
    let dir;
    const rest = [];
    for (let i = 0; i < args.length; i += 1) {
        const a = args[i] ?? '';
        const long = /^--target-directory=(.+)$/.exec(a);
        if (long !== null)
            dir = long[1];
        else if (a === '--target-directory' || /^-[a-zA-Z]*t$/.test(a))
            dir = args[++i];
        else if (/^-t./.test(a))
            dir = a.slice(2);
        else
            rest.push(a);
    }
    const paths = operands(rest, valued);
    if (dir !== undefined)
        return paths.map((p) => intoDir(dir, p));
    if (paths.length < 2)
        return [];
    const dest = paths[paths.length - 1] ?? '';
    return [dest, ...paths.slice(0, -1).map((p) => intoDir(dest, p))];
}
/** A PowerShell `-Name value` / `-Name:value` parameter's value, by any of `names`. */
function psParam(args, names) {
    for (let i = 0; i < args.length; i += 1) {
        const m = /^-([A-Za-z]+)(?::(.*))?$/.exec(args[i] ?? '');
        if (m === null || !names.includes((m[1] ?? '').toLowerCase()))
            continue;
        return m[2] !== undefined ? m[2] : args[i + 1];
    }
    return undefined;
}
/** Values of `name`'s option, spelled `-o F`, `-oF`, `--output F` or `--output=F`. */
function optionValues(args, short, long) {
    const out = [];
    for (let i = 0; i < args.length; i += 1) {
        const a = args[i] ?? '';
        if (a === short || a === long) {
            const v = args[i + 1];
            if (v !== undefined)
                out.push(v);
        }
        else if (a.startsWith(`${long}=`))
            out.push(a.slice(long.length + 1));
        else if (a.startsWith(short) && a.length > short.length && !a.startsWith('--'))
            out.push(a.slice(short.length));
    }
    return out;
}
const SED_IN_PLACE = /^(?:-[a-zA-Z]*i.*|--in-place(?:=.*)?)$/;
/**
 * The files a command itself writes — `tee`, `sed -i`, `cp`/`mv`/`install`
 * onto, `dd of=`, `curl -o`, `wget -O`, PowerShell `Set-Content`/`Add-Content`/
 * `Out-File`/`Tee-Object`/`Copy-Item`/`Move-Item`, cmd `copy`/`move`. Never a
 * file it only reads.
 */
function commandWriteDestinations(name, args) {
    switch (name) {
        case 'tee':
            return operands(args, new Set());
        case 'sed':
            return args.some((a) => SED_IN_PLACE.test(a))
                ? operands(args, new Set(['-e', '-f', '--expression', '--file', '-l', '--line-length']))
                : [];
        case 'cp':
        case 'mv':
        case 'install': {
            // PowerShell's `cp`/`mv` aliases take -Destination; POSIX's take operands.
            const dest = psParam(args, ['destination']);
            if (dest !== undefined)
                return [dest];
            return copyDestinations(args, new Set(['-S', '--suffix', '-m', '--mode', '-o', '--owner', '-g', '--group']));
        }
        case 'copy-item':
        case 'cpi':
        case 'move-item':
        case 'mi':
        case 'copy':
        case 'move': {
            const dest = psParam(args, ['destination']);
            if (dest !== undefined)
                return [dest];
            // cmd's `/Y`-style switches are not paths.
            return copyDestinations(args.filter((a) => !/^\/-?[A-Za-z]$/.test(a)), new Set());
        }
        case 'dd':
            return args.filter((a) => a.startsWith('of=')).map((a) => a.slice(3));
        case 'curl':
            return optionValues(args, '-o', '--output');
        case 'wget':
            return optionValues(args, '-O', '--output-document');
        case 'set-content':
        case 'add-content':
        case 'ac':
        case 'out-file':
        case 'tee-object':
            // Any argument: the path is positional or a -Path/-LiteralPath/-FilePath
            // value, and nothing else these take looks like a hook config path.
            return args.map((a) => a.replace(/^-[A-Za-z]+:/, ''));
        default:
            return [];
    }
}
/**
 * A shell write onto one of the hook configuration files — a redirection,
 * `tee`, `sed -i`, `cp`/`mv` onto it, and their PowerShell spellings (final
 * review M5). The Write/Edit guard refuses an assistant's edit of the same
 * files; this is the same refusal for the shell. A project file cannot loosen
 * the protective hooks anyway, but the user-level one can switch every hook
 * off. Not a shell parser: a write made inside a program (`python -c`,
 * `node -e`, `[IO.File]::WriteAllText`) or inside a quoted `cmd /c "… > f"` is
 * not seen.
 */
function assessGuardConfigShellWrite(words, start) {
    const head = words[start];
    const name = head === undefined ? '' : basename(head.value).toLowerCase().replace(/\.exe$/, '');
    const args = withoutRedirections(words.slice(start + 1));
    const targets = [...redirectTargets(words), ...commandWriteDestinations(name, args)];
    if (!targets.some(isHookConfigPath))
        return null;
    return {
        id: 'guard-config-shell-write',
        level: 'block',
        reason: "Writes the guardrail hooks' own configuration from the shell",
    };
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
function isBareRemoteFetch(script) {
    const s = script.trim();
    const unwrapped = s.startsWith('$(') && s.endsWith(')')
        ? s.slice(2, -1).trim()
        : s.startsWith('`') && s.endsWith('`')
            ? s.slice(1, -1).trim()
            : s;
    return /^(?:curl|wget)\b/i.test(unwrapped);
}
const SHELLS = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh', 'ash', 'mksh', 'su', 'pwsh', 'powershell']);
const DASH_C = /^-[A-Za-z]*c$/;
/**
 * Scripts this command hands to a shell — `sh -c '…'`, `bash -lc '…'`,
 * `docker exec box bash -c '…'`, `su -s /bin/sh www-data -c '…'`, `eval …`.
 * Masking quoted spans would otherwise make those bodies unmatchable, which
 * *is* the right call for `echo 'git push --force'` and the wrong one here.
 */
function nestedScripts(words, start) {
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
        if (word === undefined || word.quoted || !DASH_C.test(word.value))
            continue;
        const namesShell = words.slice(start, i).some((w) => SHELLS.has(basename(w.value)));
        if (!namesShell)
            continue;
        const script = words[i + 1];
        return script === undefined ? [] : [script.value];
    }
    return [];
}
/**
 * True when `words` is a bare shell invocation reading its script from
 * stdin — the shell name and, at most, flags after it; no `-c` script (that
 * is `nestedScripts`'s job) and no script-file argument. This is what
 * `bash <<EOF … EOF` and `… | bash` both hand a shell: the fed text IS the
 * script, executed exactly as if it were typed at an interactive prompt.
 */
function isBareShellStdin(words) {
    const head = words[0];
    if (head === undefined || !SHELLS.has(basename(head.value)))
        return false;
    return words.slice(1).every((w) => w.value.startsWith('-'));
}
/**
 * Text a statement hands to a shell to execute, other than through `-c` —
 * finding 4: text is data only until something feeds it to a shell as its
 * *script*, and the existing heredoc-is-data behaviour (`git commit -F -
 * <<'EOF'`) must not change for any command that is not itself a shell.
 * Two shapes:
 *
 *   - `bash <<EOF … EOF` — the heredoc IS the script. `splitShell` captures
 *     the body on the statement (`heredocBodies`) precisely so this can
 *     recognise it; every other command's heredoc stays inert, as before.
 *   - `echo '…' | bash` / `printf '…' | sh` — the shell is the LAST member
 *     of the pipeline and reads the PREVIOUS member's output as its script.
 *     `printf`'s own format-vs-arguments split is not modelled; the last
 *     argument is used, which is exactly right for the common single- or
 *     two-argument form (`printf '%s' 'rm -rf ~'`) and merely imprecise,
 *     not wrong, for anything fancier.
 */
function fedShellScripts(statement) {
    const scripts = [];
    if (statement.commands.length === 1 && statement.heredocBodies) {
        const only = statement.commands[0];
        if (only !== undefined && isBareShellStdin(only))
            scripts.push(...statement.heredocBodies);
    }
    if (statement.commands.length >= 2) {
        const last = statement.commands[statement.commands.length - 1];
        const prev = statement.commands[statement.commands.length - 2];
        if (last !== undefined && prev !== undefined && isBareShellStdin(last)) {
            const prevHead = prev[0];
            const prevName = prevHead === undefined ? '' : basename(prevHead.value);
            const args = prev.slice(1);
            let fed = '';
            if (prevName === 'echo')
                fed = args.map((w) => w.value).join(' ').trim();
            else if (prevName === 'printf')
                fed = (args[args.length - 1]?.value ?? '').trim();
            if (fed.length > 0)
                scripts.push(fed);
        }
    }
    return scripts;
}
// ──────────────────────────────────────────────────────────── assessment
const MAX_NESTING = 3;
function collect(command, depth, out) {
    const cmd = command.trim();
    if (cmd.length === 0)
        return;
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
            if (resolved.elevated)
                out.push({ ...SUDO_RULE });
            const del = assessRecursiveDelete(words, resolved.index);
            if (del !== null)
                out.push(del);
            const find = assessFind(words, resolved.index);
            if (find !== null)
                out.push(find);
            const special = assessGuardConfigSpecialFile(words, resolved.index);
            if (special !== null)
                out.push(special);
            const shellWrite = assessGuardConfigShellWrite(words, resolved.index);
            if (shellWrite !== null)
                out.push(shellWrite);
            if (depth < MAX_NESTING) {
                for (const script of nestedScripts(words, resolved.index)) {
                    // `sh -c "$(curl …)"` / `bash -c "$(wget -qO- …)"` — the whole -c
                    // script IS a download, executed without ever spelling `| sh`.
                    // Recursing alone would not catch this: the extracted script is
                    // just "curl …" with no pipe to a shell inside it, so nothing in
                    // BASH_RULES fires on it at the next depth. Checked directly, in
                    // addition to (not instead of) recursing.
                    if (isBareRemoteFetch(script)) {
                        out.push({
                            id: 'remote-pipe-to-shell',
                            level: 'block',
                            reason: 'Executes the output of a remote download (curl/wget via $(…) or `…`)',
                        });
                    }
                    collect(script, depth + 1, out);
                }
            }
        }
        // Finding 4: text a shell actually reads as its script — `bash <<EOF …
        // EOF`, `echo '…' | bash`, `printf '…' | sh` — is assessed as a command
        // in its own right, the same way a `-c` script already is above. Scoped
        // to the STATEMENT rather than any one command in its pipeline, since
        // both shapes this covers depend on more than one command
        // (`isBareShellStdin` on the shell, plus either a heredoc on the same
        // statement or the *preceding* pipeline member).
        if (depth < MAX_NESTING) {
            for (const script of fedShellScripts(statement))
                collect(script, depth + 1, out);
        }
    }
}
/** Each scanned line is capped here — see the module doc's ReDoS note. */
const MAX_LINE_LENGTH = 16 * 1024;
function capLines(text) {
    if (text.length <= MAX_LINE_LENGTH)
        return text; // common case: no line can exceed the whole string
    return text
        .split('\n')
        .map((line) => (line.length > MAX_LINE_LENGTH ? line.slice(0, MAX_LINE_LENGTH) : line))
        .join('\n');
}
/**
 * Assess a shell command. The overall level is the most severe rule matched.
 */
export function assessBashCommand(command) {
    const cmd = capLines((command ?? '').trim());
    if (!cmd)
        return { level: 'ok', reasons: [], rules: [] };
    const matched = [];
    collect(cmd, 0, matched);
    if (matched.length === 0)
        return { level: 'ok', reasons: [], rules: [] };
    // De-dupe by id, then most severe first.
    const byId = new Map();
    for (const m of matched)
        if (!byId.has(m.id))
            byId.set(m.id, m);
    // A catastrophic delete makes the broad-delete note redundant noise.
    if (byId.has('rm-rf-root'))
        byId.delete('rm-rf-broad');
    const effective = [...byId.values()].sort((a, b) => LEVEL_RANK[b.level] - LEVEL_RANK[a.level]);
    return {
        level: effective[0]?.level ?? 'ok',
        reasons: effective.map((r) => r.reason),
        rules: effective.map((r) => r.id),
    };
}
//# sourceMappingURL=bashGuard.js.map