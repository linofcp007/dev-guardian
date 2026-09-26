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
        // A `{` also opens a body after a function header (`function f { … }`) and
        // after the `time` runner (`time { … }`, `time -p { … }`). The header is not
        // a command, so it goes with the brace; `time` stays, a runner the command
        // after the brace is resolved through (re-review follow-up to I13).
        const opensBody = hasWord && !bufQuoted && buf === '{';
        const first = words[0];
        const unquotedHead = first !== undefined && !first.quoted ? first.value : '';
        if (opensBody && unquotedHead === 'function' && words.length === 2) {
            words = [];
            buf = '';
            bufQuoted = false;
            bufRedirects = [];
            hasWord = false;
            return;
        }
        const afterTime = opensBody && unquotedHead === 'time' && words.slice(1).every((w) => !w.quoted && w.value.startsWith('-'));
        if (hasWord && !reserved && !afterTime) {
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
 * A key of Claude Code's settings that switches dev-guardian's hooks off:
 * `disableAllHooks`, the dispatcher's own environment switches, and
 * `enabledPlugins` when the same text names dev-guardian. The Write/Edit guard
 * (`settingsGuard.ts`) judges an edit of the settings by the value it sets; the
 * content a shell command writes cannot be read reliably, so here the key alone
 * decides, anywhere in the command's text.
 */
function namesLooseningKey(text) {
    return (/disableAllHooks|GUARDIAN_HOOKS|GUARDIAN_PKG_VET/i.test(text) ||
        (/enabledPlugins/i.test(text) && /dev-guardian/i.test(text)));
}
/** A command word's name: its last path segment, lower-cased, without `.exe`. */
function commandName(word) {
    return basename(word).toLowerCase().replace(/\.exe$/, '');
}
// ── paths, as the command moves between directories
/** A path that does not depend on the current directory: `/…`, `~…`, `$VAR…`, `%VAR%…`, `\\…`, `C:…`. */
function isAbsolutePath(path) {
    return /^(?:[\\/~$%]|[A-Za-z]:)/.test(path);
}
/**
 * `target` as the command sees it after the `cd`s before it (`cwd`; `''` while
 * there was none): joined onto `cwd` unless absolute, every `\` read as `/`,
 * and `.` and `..` segments folded. So `cd ~/.config/dev-guardian && echo … >
 * hooks.json` names the file it writes, and so does `echo … >
 * .guardian/x/../hooks.config.json`.
 */
function resolveFrom(cwd, target) {
    const joined = cwd === '' || isAbsolutePath(target) ? target : `${cwd.replace(/[\\/]+$/, '')}/${target}`;
    const parts = joined.replace(/\\/g, '/').split('/');
    const out = [];
    parts.forEach((part, i) => {
        if (part === '.' || (part === '' && i > 0 && i < parts.length - 1))
            return;
        const prev = out[out.length - 1];
        if (part === '..' && prev !== undefined && prev !== '..' && prev !== '') {
            out.pop();
            return;
        }
        out.push(part);
    });
    return out.join('/');
}
/** `a/b/c` → `a/b`; `''` when there is no directory part. */
function dirOf(path) {
    const cut = path.lastIndexOf('/');
    return cut < 0 ? '' : path.slice(0, cut);
}
const CD_COMMANDS = new Set(['cd', 'chdir', 'pushd', 'set-location', 'sl', 'push-location']);
const CD_RETURNS = new Set(['popd', 'pop-location']);
/**
 * The directory a `cd`, `pushd` or `Set-Location` moves to from `cwd`, or
 * `undefined` when `name` is none of them. A bare `cd` goes home; `cd -`,
 * `popd` and `Pop-Location` go back somewhere this does not track, which reads
 * as where the command started (`''`).
 */
function cwdAfter(name, args, cwd) {
    if (CD_RETURNS.has(name))
        return '';
    if (!CD_COMMANDS.has(name))
        return undefined;
    const dir = psParam(args, ['path', 'literalpath']) ?? args.find((a) => a === '-' || !(a.startsWith('-') || /^\/d$/i.test(a)));
    if (dir === undefined)
        return '~';
    if (dir === '-')
        return '';
    return resolveFrom(cwd, dir);
}
const GLOB = /[*?[]/;
/** The configuration files a directory holds, by the directory's kind. */
function configNamesIn(dir) {
    if (USER_CONFIG_DIR.test(dir))
        return ['hooks.json'];
    if (/\.guardian\/?$/i.test(dir))
        return ['hooks.config.json', 'hooks-allowlist.json'];
    return [];
}
/** True when a glob in `path`'s last segment can match a configuration file of the config directory it sits in. */
function globNamesConfig(path) {
    const last = path.slice(path.lastIndexOf('/') + 1);
    if (!GLOB.test(last))
        return false;
    const names = configNamesIn(dirOf(path));
    if (names.length === 0)
        return false;
    try {
        const re = new RegExp(`^${last.replace(/[.+^${}()|\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.')}$`, 'i');
        return names.some((n) => re.test(n));
    }
    catch {
        return false;
    }
}
function noEffects() {
    return { writes: [], removes: [], dirs: [], special: [], links: [] };
}
function mergeEffects(into, from) {
    into.writes.push(...from.writes);
    into.removes.push(...from.removes);
    into.dirs.push(...from.dirs);
    into.special.push(...from.special);
    into.links.push(...from.links);
}
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
/** `New-Item`'s item type and paths (`-Path`, `-LiteralPath`, `-Name`, or the first positional). */
function newItemArgs(args) {
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
    if (paths.length === 0 && positional.length > 0)
        paths.push(positional[0] ?? '');
    return { itemType, paths };
}
/** `mklink [/D|/H|/J] LINK TARGET`: the link is the first operand. */
function mklinkDestinations(args) {
    const link = args.find((a) => !a.startsWith('/'));
    return link === undefined ? [] : [link];
}
/**
 * Splits a cmd.exe command line into its commands — on `&`, `&&`, `||` and `|`
 * outside double quotes — and each command into words, on whitespace outside
 * double quotes. Quotes are removed, backslashes are literal, and `^` escapes
 * the next character (`^&` is a literal `&`), as in cmd. A `>` or `>>` (after an
 * optional descriptor digit) makes the next word a file the command writes;
 * `>&1` duplicates a descriptor and names none; `<` reads a file.
 */
function splitCmdLine(line) {
    const commands = [];
    let words = [];
    let redirects = [];
    let cur = '';
    let inQuote = false;
    let has = false;
    let role = 'arg';
    const endWord = () => {
        if (has) {
            if (role === 'write')
                redirects.push(cur);
            else if (role === 'arg')
                words.push(cur);
            role = 'arg';
        }
        cur = '';
        has = false;
    };
    const endCommand = () => {
        endWord();
        role = 'arg';
        if (words.length > 0 || redirects.length > 0)
            commands.push({ words, redirects });
        words = [];
        redirects = [];
    };
    for (let i = 0; i < line.length; i += 1) {
        const ch = line.charAt(i);
        if (ch === '"') {
            inQuote = !inQuote;
            has = true;
        }
        else if (!inQuote && ch === '^' && i + 1 < line.length) {
            i += 1;
            cur += line.charAt(i);
            has = true;
        }
        else if (!inQuote && (ch === '&' || ch === '|')) {
            endCommand();
            if (line.charAt(i + 1) === ch)
                i += 1;
        }
        else if (!inQuote && (ch === '>' || ch === '<')) {
            if (has && /^\d$/.test(cur)) {
                cur = '';
                has = false;
            }
            else
                endWord();
            if (ch === '>' && line.charAt(i + 1) === '>')
                i += 1;
            if (line.charAt(i + 1) === '&') {
                i += 1;
                while (/\d/.test(line.charAt(i + 1)))
                    i += 1;
                continue;
            }
            role = ch === '>' ? 'write' : 'read';
        }
        else if (!inQuote && /\s/.test(ch)) {
            if (has)
                endWord();
        }
        else {
            cur += ch;
            has = true;
        }
    }
    endCommand();
    return commands;
}
/** A cmd.exe command's own name and arguments, past a leading `@` and any `call`. */
function cmdCommandWords(words) {
    const out = [...words];
    const first = out[0];
    if (first !== undefined && first.startsWith('@')) {
        if (first.length > 1)
            out[0] = first.slice(1);
        else
            out.shift();
    }
    while (out.length > 0 && (out[0] ?? '').toLowerCase() === 'call')
        out.shift();
    return out;
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
function cmdEffects(args, cwd) {
    const e = noEffects();
    const at = args.findIndex((a) => /^\/[ck]$/i.test(a));
    if (at < 0)
        return e;
    const first = args[at + 1];
    if (first === undefined)
        return e;
    const head = first.trim();
    const commands = /[\s&|^<>]/.test(head) ? splitCmdLine(head) : [{ words: [head], redirects: [] }];
    // The shell words after the first one continue the line's LAST command.
    const last = commands[commands.length - 1];
    if (last !== undefined)
        last.words.push(...args.slice(at + 2));
    let dir = cwd;
    for (const command of commands) {
        const [raw, ...rest] = cmdCommandWords(command.words);
        const name = (raw ?? '').toLowerCase().replace(/\.exe$/, '');
        e.writes.push(...command.redirects.map((r) => resolveFrom(dir, r)));
        mergeEffects(e, effectsOf(name, rest, dir));
        dir = cwdAfter(name, rest, dir) ?? dir;
    }
    return e;
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
/** `cp`/`mv`/`install` options that take a value, none of them the destination. */
const COPY_VALUED = new Set(['-S', '--suffix', '-m', '--mode', '-o', '--owner', '-g', '--group']);
/** PowerShell `Copy-Item`/`Move-Item` parameters, by full lower-case name: those naming paths… */
const PS_PATH_PARAMS = ['path', 'literalpath', 'destination'];
/** …the others that take a value, and the switches. */
const PS_VALUE_PARAMS = ['filter', 'include', 'exclude', 'credential', 'fromsession', 'tosession'];
const PS_SWITCHES = ['recurse', 'force', 'container', 'passthru', 'whatif', 'confirm'];
/** A full PowerShell parameter name `spelled` names: itself, or a prefix of 3+ letters (`-Dest`, `-Rec`). */
function psName(spelled) {
    const lower = spelled.toLowerCase();
    const all = [...PS_PATH_PARAMS, ...PS_VALUE_PARAMS, ...PS_SWITCHES];
    if (all.includes(lower))
        return lower;
    return lower.length >= 3 ? all.find((n) => n.startsWith(lower)) : undefined;
}
/**
 * The sources and destination of a copy or a move: POSIX `cp`/`mv`/`install`
 * (the last operand, or `-t DIR`), PowerShell `Copy-Item`/`Move-Item`
 * (`-Path`, `-Destination`, or the first two positionals), and cmd `copy` /
 * `move`, whose `/Y`-style switches are not paths (`slashSwitches`).
 */
function parseTransfer(args, slashSwitches) {
    const named = [];
    const positional = [];
    let dest;
    let into = false;
    let recursive = false;
    let optionsDone = false;
    for (let i = 0; i < args.length; i += 1) {
        const a = args[i] ?? '';
        if (slashSwitches && /^\/[A-Za-z]/.test(a))
            continue;
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
            if (param === 'recurse')
                recursive = true;
            else if (param === 'destination')
                dest = value;
            else if ((param === 'path' || param === 'literalpath') && value !== undefined)
                named.push(value);
            continue;
        }
        if (COPY_VALUED.has(a)) {
            i += 1;
            continue;
        }
        if (/^-[a-zA-Z]*t$/.test(a)) {
            dest = args[++i];
            into = true;
        }
        else if (/^-t./.test(a)) {
            dest = a.slice(2);
            into = true;
        }
        if (!a.startsWith('--') && /[rRa]/.test(a.slice(1)))
            recursive = true;
    }
    const sources = [...named, ...positional];
    if (dest === undefined && sources.length >= 2)
        dest = sources.pop();
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
function perlLike(args, codeLetters, valueLetters) {
    const code = [];
    const operandsSeen = [];
    let inPlace = false;
    let optionsDone = false;
    for (let i = 0; i < args.length; i += 1) {
        const a = args[i] ?? '';
        if (!optionsDone && a === '--') {
            optionsDone = true;
            continue;
        }
        if (optionsDone || !a.startsWith('-') || a.length === 1 || a.startsWith('--')) {
            if (optionsDone || !a.startsWith('--'))
                operandsSeen.push(a);
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
                if (k === a.length - 1)
                    i += 1;
                break;
            }
            if (c === '0')
                while (/[0-9a-fA-Fx]/.test(a.charAt(k + 1)))
                    k += 1;
            if (c === 'l')
                while (/[0-9]/.test(a.charAt(k + 1)))
                    k += 1;
        }
    }
    const files = code.length > 0 ? operandsSeen : operandsSeen.slice(1);
    return { code, inPlace, files };
}
const SED_IN_PLACE = /^(?:-[a-zA-Z]*i.*|--in-place(?:=.*)?)$/;
/**
 * The files a command itself writes — `tee`, `sed -i`, `dd of=`, `curl -o`,
 * `wget -O`, `sort -o`, `truncate`, `sponge`, `shred`, `perl -i` / `ruby -i`,
 * and PowerShell `Set-Content`/`Add-Content`/`Clear-Content`/`Out-File`/
 * `Tee-Object`. Never a file it only reads. Copies, moves, renames and
 * `New-Item` are in {@link effectsOf}.
 */
function commandWriteDestinations(name, args) {
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
/** Commands that delete what they are given. */
const REMOVERS = new Set(['rm', 'unlink', 'ri', 'remove-item', 'del', 'erase', 'rd', 'rmdir']);
/**
 * What `name args` does to the filesystem, from `cwd` — every path resolved
 * ({@link resolveFrom}). A copy writes its destination (and each source's name
 * inside it) and, recursive, may replace that directory wholesale; a move also
 * removes its sources; a rename removes its source and writes its new name; a
 * delete removes; `ln`, `mklink` and `New-Item -ItemType SymbolicLink` create
 * links, `mkfifo` and `mknod` special files; `cmd /c` is assessed command by
 * command ({@link cmdEffects}). Never a link's SOURCE: `ln -s
 * ~/.config/dev-guardian/hooks.json backup.json` reads the config.
 */
function effectsOf(name, args, cwd) {
    if (name === 'cmd')
        return cmdEffects(args, cwd);
    const at = (p) => resolveFrom(cwd, p);
    const e = noEffects();
    switch (name) {
        case 'mkfifo':
            e.special.push(...operands(args, new Set(['-m', '--mode'])).map(at));
            return e;
        case 'mknod':
            e.special.push(...operands(args, new Set(['-m', '--mode'])).slice(0, 1).map(at));
            return e;
        case 'ln':
            e.links.push(...lnDestinations(args).map(at));
            return e;
        case 'mklink':
            e.links.push(...mklinkDestinations(args).map(at));
            return e;
        case 'new-item':
        case 'ni': {
            const item = newItemArgs(args);
            if (/^(?:symboliclink|hardlink|junction)$/i.test(item.itemType))
                e.links.push(...item.paths.map(at));
            else if (item.itemType === '' || /^file$/i.test(item.itemType))
                e.writes.push(...item.paths.map(at));
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
            if (moves)
                e.removes.push(...t.sources.map(at));
            if (t.dest === undefined)
                return e;
            const dest = t.dest;
            e.writes.push(...(t.into ? [] : [at(dest)]), ...t.sources.map((s) => at(intoDir(dest, s))));
            if (!t.into && (moves || t.recursive))
                e.dirs.push(at(dest));
            return e;
        }
        case 'xcopy':
        case 'robocopy': {
            const [, dest, ...files] = args.filter((a) => !/^\/[A-Za-z]/.test(a));
            if (dest !== undefined) {
                e.dirs.push(at(dest));
                e.writes.push(at(dest), ...files.map((f) => at(intoDir(dest, f))));
            }
            return e;
        }
        case 'rsync': {
            const paths = operands(args, RSYNC_VALUED);
            const dest = paths.pop();
            if (dest === undefined || paths.length === 0)
                return e;
            e.writes.push(at(dest), ...paths.map((s) => at(intoDir(dest, s))));
            if (args.some((a) => a === '--recursive' || a === '--archive' || /^-[a-zA-Z]*[ra]/.test(a)))
                e.dirs.push(at(dest));
            return e;
        }
        case 'ren':
        case 'rename':
        case 'rename-item':
        case 'rni': {
            const positional = args.filter((a) => !a.startsWith('-') && !/^\/[A-Za-z]$/.test(a));
            const src = psParam(args, ['path', 'literalpath']) ?? positional.shift();
            const newName = psParam(args, ['newname']) ?? positional.shift();
            if (src === undefined)
                return e;
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
    if (REMOVERS.has(name))
        e.removes.push(...operands(args, new Set()).filter((a) => !/^\/[A-Za-z]$/.test(a)).map(at));
    const written = commandWriteDestinations(name, args).map(at);
    e.writes.push(...written);
    if (name === 'shred' && args.some((a) => a === '--remove' || a.startsWith('--remove=') || /^-[a-zA-Z]*u/.test(a))) {
        e.removes.push(...written);
    }
    return e;
}
// ── program text on the command line
const PYTHON = /^(?:python[0-9.]*|py|pypy[0-9.]*)$/;
const INTERPRETERS = new Set(['node', 'nodejs', 'bun', 'deno', 'perl', 'ruby', 'php', 'pwsh', 'powershell']);
/** `X run … python -c …`: tools that run an interpreter in a managed environment. */
const RUN_WRAPPERS = new Set(['uv', 'poetry', 'pipenv', 'pdm', 'rye', 'hatch', 'conda', 'mamba', 'micromamba']);
function isInterpreter(name) {
    return PYTHON.test(name) || INTERPRETERS.has(name);
}
/** Index of the interpreter a command runs, at `start` or behind `uv run`-style wrappers; -1 for none. */
function interpreterIndex(words, start) {
    const name = commandName(words[start]?.value ?? '');
    if (isInterpreter(name))
        return start;
    if (RUN_WRAPPERS.has(name) && words[start + 1]?.value === 'run') {
        for (let i = start + 2; i < Math.min(words.length, start + 10); i += 1) {
            if (isInterpreter(commandName(words[i]?.value ?? '')))
                return i;
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
function nodeCode(args) {
    for (let i = 0; i < args.length; i += 1) {
        const a = args[i] ?? '';
        const eq = /^--(?:eval|print)=([\s\S]*)$/.exec(a);
        if (eq !== null)
            return [eq[1] ?? ''];
        if (/^-(?:e|p|pe|ep)$/.test(a) || a === '--eval' || a === '--print')
            return [args[i + 1] ?? ''];
        if (NODE_VALUED.has(a)) {
            i += 1;
            continue;
        }
        if (!a.startsWith('-'))
            return [];
    }
    return [];
}
/** `python -c CODE` (also clustered: `-Bc CODE`, `-cCODE`); nothing for `-m`, a script file or `-` (stdin). */
function pythonCode(args) {
    for (let i = 0; i < args.length; i += 1) {
        const a = args[i] ?? '';
        if (a === '-' || !a.startsWith('-'))
            return [];
        if (a.startsWith('--'))
            continue;
        for (let k = 1; k < a.length; k += 1) {
            const c = a.charAt(k);
            if (c === 'c') {
                const rest = a.slice(k + 1);
                return [rest !== '' ? rest : (args[i + 1] ?? '')];
            }
            if (c === 'm')
                return [];
            if (c === 'W' || c === 'X') {
                if (k === a.length - 1)
                    i += 1;
                break;
            }
        }
    }
    return [];
}
/** `php -r CODE` (and `-B`/`-R`/`-E` per-line code); nothing once a script file is named. */
function phpCode(args) {
    const code = [];
    for (let i = 0; i < args.length; i += 1) {
        const a = args[i] ?? '';
        if (/^-[rBRE]$/.test(a)) {
            code.push(args[i + 1] ?? '');
            i += 1;
        }
        else if (/^-r./.test(a))
            code.push(a.slice(2));
        else if (a === '-f' || a === '-F' || !a.startsWith('-'))
            return code;
        else if (/^-[dcz]$/.test(a))
            i += 1;
    }
    return code;
}
/** PowerShell's `-EncodedCommand` payload: base64 of UTF-16LE text. */
function decodeUtf16Base64(text) {
    if (!/^[A-Za-z0-9+/=]+$/.test(text))
        return '';
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
function powershellCommand(args, name) {
    for (let i = 0; i < args.length; i += 1) {
        const a = args[i] ?? '';
        const m = /^[-/]([A-Za-z]+)$/.exec(a);
        if (m === null)
            return name === 'powershell' ? [args.slice(i).join(' ')] : [];
        const p = (m[1] ?? '').toLowerCase();
        if (p === 'c' || (p.length >= 3 && 'command'.startsWith(p))) {
            const rest = args.slice(i + 1);
            return rest.length === 0 || rest[0] === '-' ? [] : [rest.join(' ')];
        }
        if (p === 'e' || (p.length >= 2 && 'encodedcommand'.startsWith(p)))
            return [decodeUtf16Base64(args[i + 1] ?? '')];
        if (p === 'f' || p === 'file')
            return [];
        if (PS_HOST_VALUED.has(p))
            i += 1;
    }
    return [];
}
/**
 * Program text a command hands an interpreter on its own command line —
 * `node -e`, `python -c`, `perl -e`, `ruby -e`, `php -r`, `deno eval`,
 * `pwsh -Command` / `-EncodedCommand`, also behind `uv run` and the like. A
 * script FILE is never read: its code is on disk, and cannot be judged here.
 */
function inlineCode(words, start) {
    const at = interpreterIndex(words, start);
    if (at < 0)
        return [];
    const name = commandName(words[at]?.value ?? '');
    const args = words.slice(at + 1).map((w) => w.value);
    if (PYTHON.test(name))
        return pythonCode(args);
    switch (name) {
        case 'node':
        case 'nodejs':
        case 'bun':
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
 * the interpreter and, at most, flags (or `-`); no `-c`/`-e` text, no module,
 * no script file. What `python - <<EOF … EOF` and `echo '…' | node` hand it is
 * its program.
 */
function isBareInterpreterStdin(words) {
    const name = commandName(words[0]?.value ?? '');
    if (!isInterpreter(name) || name === 'pwsh' || name === 'powershell' || name === 'deno')
        return false;
    if (!words.slice(1).every((w) => w.value.startsWith('-')))
        return false;
    return inlineCode(words, 0).length === 0 && !words.some((w) => /^-[A-Za-z]*m$/.test(w.value));
}
function codeLang(interpreter) {
    if (PYTHON.test(interpreter))
        return 'python';
    return ['node', 'nodejs', 'bun', 'deno'].includes(interpreter) ? 'js' : 'other';
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
function codeLiterals(code, lang) {
    const quotes = lang === 'js' ? ['"', "'", '`'] : ['"', "'"];
    const out = [];
    let i = 0;
    while (i < code.length) {
        const ch = code.charAt(i);
        const atWordStart = i === 0 || /\s/.test(code.charAt(i - 1));
        const comment = atWordStart && ((ch === '#' && lang !== 'js') || (lang !== 'python' && code.startsWith('// ', i)));
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
            if (code.startsWith(close, j))
                break;
            lit += c;
            j += 1;
        }
        out.push(lit);
        i = j + close.length;
    }
    return out;
}
/** Literals as paths: trimmed, every run of backslashes read as `/`. */
function literalPaths(literals) {
    return literals.map((l) => l.trim().replace(/\\+/g, '/'));
}
/**
 * True when program text names a hook configuration path: a string literal
 * that ENDS in one (`'.guardian/hooks.config.json'`, `r'C:\…\.config\
 * dev-guardian\hooks.json'`, `">…/hooks.json"`) or in the user-level directory,
 * or one assembled from parts (`join(home, '.config', 'dev-guardian',
 * 'hooks.json')`). A sentence that merely mentions a path does not end in it.
 */
function literalsNameHookConfig(literals) {
    const paths = literalPaths(literals);
    if (paths.some((p) => HOOK_CONFIG_PATH.test(p) || USER_CONFIG_DIR.test(p)))
        return true;
    const has = (re) => paths.some((p) => re.test(p));
    if (has(/(?:^|\/)dev-guardian\/?$/i) && has(/(?:^|\/)hooks\.json$/i))
        return true;
    return has(/(?:^|\/)\.guardian\/?$/i) && has(/(?:^|\/)hooks[.-][^/]*\.json$/i);
}
/** The same for Claude Code's settings files. */
function literalsNameClaudeSettings(literals) {
    const paths = literalPaths(literals);
    if (paths.some((p) => CLAUDE_SETTINGS_PATH.test(p)))
        return true;
    const has = (re) => paths.some((p) => re.test(p));
    return has(/(?:^|\/)\.claude\/?$/i) && has(/^settings(?:\.local)?\.json$/i);
}
// ── .NET file calls in PowerShell
/** Whether `index` in `text` lies outside every quoted span (POSIX quoting). */
function unquotedAt(text, index) {
    let quote = '';
    for (let i = 0; i < index; i += 1) {
        const ch = text.charAt(i);
        if (quote === '') {
            if (ch === '\\')
                i += 1;
            else if (ch === "'" || ch === '"')
                quote = ch;
        }
        else if (quote === '"' && ch === '\\')
            i += 1;
        else if (ch === quote)
            quote = '';
    }
    return quote === '';
}
/** The argument texts of a call whose `(` ends just before `from`: split on depth-0 commas, up to the matching `)`. */
function callArgs(text, from) {
    const args = [];
    let depth = 0;
    let cur = '';
    let quote = '';
    for (let i = from; i < text.length; i += 1) {
        const ch = text.charAt(i);
        if (quote !== '') {
            cur += ch;
            if (ch === quote)
                quote = '';
            continue;
        }
        if (ch === "'" || ch === '"') {
            quote = ch;
            cur += ch;
            continue;
        }
        if (ch === ')' && depth === 0)
            break;
        if (ch === '(')
            depth += 1;
        if (ch === ')')
            depth -= 1;
        if (ch === ',' && depth === 0) {
            args.push(cur.trim());
            cur = '';
            continue;
        }
        cur += ch;
    }
    args.push(cur.trim());
    return args;
}
/** A call argument as a path: a quoted string's content, or the last string literal inside an expression. */
function argPath(arg) {
    const q = /^(['"])([\s\S]*)\1$/.exec(arg);
    if (q !== null)
        return (q[2] ?? '').replace(q[1] === "'" ? /''/g : /`"/g, q[1] ?? '');
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
function dotNetEffects(text, cwd) {
    const e = noEffects();
    if (!text.includes('::'))
        return e;
    for (const m of text.matchAll(DOTNET_CALL)) {
        if (!unquotedAt(text, m.index))
            continue;
        const kind = (m[1] ?? '').toLowerCase();
        const method = (m[2] ?? '').toLowerCase();
        const paths = callArgs(text, m.index + m[0].length).map((a) => resolveFrom(cwd, argPath(a)));
        const [first, second] = paths;
        if (first === undefined)
            continue;
        if (method === 'delete')
            e.removes.push(first);
        else if (method === 'createsymboliclink')
            e.links.push(first);
        else if (method === 'move' || method === 'replace') {
            e.removes.push(first);
            if (second !== undefined)
                (kind === 'directory' ? e.dirs : e.writes).push(second);
        }
        else if (kind === 'file' && method === 'copy') {
            if (second !== undefined)
                e.writes.push(second);
        }
        else if (kind === 'file' && /^(?:write|append|create|open)/.test(method) && !/^open(?:read|text)$/.test(method)) {
            e.writes.push(first);
        }
    }
    return e;
}
// ── the rules
const RULE_SPECIAL = {
    id: 'guard-config-special-file',
    level: 'block',
    reason: "Replaces the guardrail hooks' own configuration with a FIFO, a device node or a link",
};
const RULE_WRITE = {
    id: 'guard-config-shell-write',
    level: 'block',
    reason: "Writes the guardrail hooks' own configuration from the shell",
};
const RULE_REMOVE = {
    id: 'guard-config-remove',
    level: 'block',
    reason: "Removes or moves away the guardrail hooks' own configuration",
};
const RULE_DIR = {
    id: 'guard-config-dir-replace',
    level: 'block',
    reason: "Moves or copies a directory onto the guardrail hooks' configuration directory",
};
const RULE_INLINE = {
    id: 'guard-config-inline-code',
    level: 'block',
    reason: "Runs program code that names the guardrail hooks' own configuration",
};
const RULE_SETTINGS = {
    id: 'claude-settings-loosen',
    level: 'block',
    reason: "Writes Claude Code's settings with a key that switches the guardrail hooks off",
};
/**
 * The rules a command's filesystem effects break. The guard's own
 * configuration: a FIFO, device node or link created at a config file (a link
 * also at a config directory — final review I12 and fix round 2, N1); a write
 * onto a config file (M5); its removal, or the user-level directory's; a
 * directory moved or copied onto a config directory. Claude Code's settings: a
 * write of `.claude/settings*.json` whose command names a loosening key
 * anywhere (`raw`).
 */
function judgeEffects(e, raw) {
    const out = [];
    if (e.special.some(isHookConfigPath) || e.links.some((p) => isHookConfigPath(p) || isHookConfigDir(p))) {
        out.push({ ...RULE_SPECIAL });
    }
    if (e.writes.some((p) => isHookConfigPath(p) || globNamesConfig(p)))
        out.push({ ...RULE_WRITE });
    const removesConfig = (p) => isHookConfigPath(p) || USER_CONFIG_DIR.test(p) || (USER_CONFIG_DIR.test(dirOf(p)) && globNamesConfig(p));
    if (e.removes.some(removesConfig))
        out.push({ ...RULE_REMOVE });
    if (e.dirs.some(isHookConfigDir))
        out.push({ ...RULE_DIR });
    if (e.writes.some((p) => CLAUDE_SETTINGS_PATH.test(p)) && namesLooseningKey(raw))
        out.push({ ...RULE_SETTINGS });
    return out;
}
const RULE_PLUGIN_OFF = {
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
function turnsPluginOff(words, start) {
    let i = start;
    const head = words[i]?.value ?? '';
    if (commandName(head) === 'npx' && /(?:^|\/)claude-code(?:@|$)/.test(words[i + 1]?.value ?? ''))
        i += 1;
    else if (commandName(head) !== 'claude')
        return false;
    const rest = words.slice(i + 1).map((w) => w.value);
    if (rest[0] !== 'plugin' && rest[0] !== 'plugins')
        return false;
    const verbs = rest[1] === 'marketplace' ? rest.slice(2, 3) : rest.slice(1, 2);
    if (!verbs.some((v) => /^(?:disable|uninstall|remove|rm)$/.test(v)))
        return false;
    return rest.some((a) => /dev-guardian/i.test(a));
}
/** Program text that names a hook config path; or Claude Code's settings, with a loosening key in the command. */
function judgeCode(code, lang, raw) {
    const literals = codeLiterals(code, lang);
    const out = [];
    if (literalsNameHookConfig(literals))
        out.push({ ...RULE_INLINE });
    if (literalsNameClaudeSettings(literals) && namesLooseningKey(raw))
        out.push({ ...RULE_SETTINGS });
    return out;
}
/**
 * One simple command against the guard's own configuration and Claude Code's
 * settings: what it writes, removes, replaces or links ({@link effectsOf},
 * redirections included), and any program text it hands an interpreter on its
 * command line ({@link inlineCode}) — which is refused when it names a hook
 * configuration path at all, reading or writing: reading one needs no program.
 */
function assessGuardConfig(words, start, scope) {
    const head = words[start];
    if (head === undefined)
        return [];
    const e = effectsOf(commandName(head.value), withoutRedirections(words.slice(start + 1)), scope.cwd);
    e.writes.push(...redirectTargets(words).map((t) => resolveFrom(scope.cwd, t)));
    const out = judgeEffects(e, scope.raw);
    if (turnsPluginOff(words, start))
        out.push({ ...RULE_PLUGIN_OFF });
    const lang = codeLang(commandName(words[interpreterIndex(words, start)]?.value ?? ''));
    for (const code of inlineCode(words, start))
        out.push(...judgeCode(code, lang, scope.raw));
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
 * `docker exec box bash -c '…'`, `su -s /bin/sh www-data -c '…'`, `eval …`,
 * and PowerShell's `-Command …` / `-EncodedCommand …` (`pwsh`, `powershell`).
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
        if (word === undefined)
            continue;
        const name = commandName(word.value);
        if (!word.quoted && (name === 'pwsh' || name === 'powershell')) {
            return powershellCommand(words.slice(i + 1).map((w) => w.value), name).filter((s) => s.trim().length > 0);
        }
        if (word.quoted || !DASH_C.test(word.value))
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
 * Text a statement hands a program to run, other than on its command line —
 * finding 4: text is data only until something feeds it to a program as its
 * *script*, and the existing heredoc-is-data behaviour (`git commit -F -
 * <<'EOF'`) must not change for any command that is not itself such a reader
 * (`reads`: a bare shell, or a bare interpreter). Two shapes:
 *
 *   - `bash <<EOF … EOF` — the heredoc IS the script. `splitShell` captures
 *     the body on the statement (`heredocBodies`) precisely so this can
 *     recognise it; every other command's heredoc stays inert, as before.
 *   - `echo '…' | bash` / `printf '…' | sh` — the reader is the LAST member
 *     of the pipeline and reads the PREVIOUS member's output as its script.
 *     `printf`'s own format-vs-arguments split is not modelled; the last
 *     argument is used, which is exactly right for the common single- or
 *     two-argument form (`printf '%s' 'rm -rf ~'`) and merely imprecise,
 *     not wrong, for anything fancier.
 */
function fedScripts(statement, reads) {
    const scripts = [];
    if (statement.commands.length === 1 && statement.heredocBodies) {
        const only = statement.commands[0];
        if (only !== undefined && reads(only))
            scripts.push(...statement.heredocBodies.map((text) => ({ text, reader: only })));
    }
    if (statement.commands.length >= 2) {
        const last = statement.commands[statement.commands.length - 1];
        const prev = statement.commands[statement.commands.length - 2];
        if (last !== undefined && prev !== undefined && reads(last)) {
            const prevHead = prev[0];
            const prevName = prevHead === undefined ? '' : basename(prevHead.value);
            const args = prev.slice(1);
            let fed = '';
            if (prevName === 'echo')
                fed = args.map((w) => w.value).join(' ').trim();
            else if (prevName === 'printf')
                fed = (args[args.length - 1]?.value ?? '').trim();
            if (fed.length > 0)
                scripts.push({ text: fed, reader: last });
        }
    }
    return scripts;
}
// ──────────────────────────────────────────────────────────── assessment
const MAX_NESTING = 3;
/**
 * Every rule `command` breaks, into `out`. `scope` carries the whole command
 * as given (a loosening key for Claude Code's settings is looked for there)
 * and the directory the statements have `cd`'d into so far, which each
 * statement updates in order; a nested script starts from the directory its
 * parent was in and cannot move the parent.
 */
function collect(command, depth, out, scope) {
    const cmd = command.trim();
    if (cmd.length === 0)
        return;
    const { maskedCommand, statements } = splitShell(cmd);
    for (const rule of BASH_RULES) {
        if (rule.scope === 'command' && rule.pattern.test(maskedCommand)) {
            out.push({ id: rule.id, level: rule.level, reason: rule.reason });
        }
    }
    // `[IO.File]::WriteAllText(…)`: the `(` that opens its arguments is a
    // statement boundary to `splitShell`, so it is judged on the command text.
    out.push(...judgeEffects(dotNetEffects(cmd, scope.cwd), scope.raw));
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
            out.push(...assessGuardConfig(words, resolved.index, scope));
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
                    collect(script, depth + 1, out, { ...scope });
                }
            }
            const head = words[resolved.index];
            if (head !== undefined) {
                const args = withoutRedirections(words.slice(resolved.index + 1));
                scope.cwd = cwdAfter(commandName(head.value), args, scope.cwd) ?? scope.cwd;
            }
        }
        // Finding 4: text a shell actually reads as its script — `bash <<EOF …
        // EOF`, `echo '…' | bash`, `printf '…' | sh` — is assessed as a command
        // in its own right, the same way a `-c` script already is above. Scoped
        // to the STATEMENT rather than any one command in its pipeline, since
        // both shapes this covers depend on more than one command
        // (`isBareShellStdin` on the shell, plus either a heredoc on the same
        // statement or the *preceding* pipeline member). A program an
        // interpreter reads the same way (`python - <<EOF`) is judged as program
        // text, like `python -c`.
        if (depth < MAX_NESTING) {
            for (const { text } of fedScripts(statement, isBareShellStdin))
                collect(text, depth + 1, out, { ...scope });
        }
        for (const { text, reader } of fedScripts(statement, isBareInterpreterStdin)) {
            out.push(...judgeCode(text, codeLang(commandName(reader[0]?.value ?? '')), scope.raw));
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
    collect(cmd, 0, matched, { raw: cmd, cwd: '' });
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