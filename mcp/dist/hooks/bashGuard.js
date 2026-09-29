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
import { windowsName } from './guardedPath.js';
import { powershellAsPosix, powershellOpaque } from './powershellText.js';
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
        pattern: /(?:\bdd\b[^\n]*\bof=(?:\/dev\/(?:sd|hd|vd|xvd|nvme|mmcblk|disk|md|dm-)[\w-]*|\\\\\.\\PhysicalDrive\d*)|\bmkfs(?:\.\w+)?\b[^\n]*\/dev\/|\bwipefs\b[^\n]*\/dev\/|\bshred\b[^\n]*\/dev\/|>\s*\/dev\/(?:sd|hd|vd|xvd|nvme|mmcblk|disk|md|dm-))/i,
        test: anyOf(after(/\bdd\b/i, /\bof=(?:\/dev\/(?:sd|hd|vd|xvd|nvme|mmcblk|disk|md|dm-)[\w-]*|\\\\\.\\PhysicalDrive\d*)/i), after(/\bmkfs(?:\.\w+)?\b/i, /\/dev\//i), after(/\bwipefs\b/i, /\/dev\//i), after(/\bshred\b/i, /\/dev\//i), (t) => />\s*\/dev\/(?:sd|hd|vd|xvd|nvme|mmcblk|disk|md|dm-)/i.test(t)),
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
        // `-[a-z]*R[a-z]*` backtracked quadratically over a run of R's; a lookahead
        // for the R and one greedy run cannot.
        test: after(/\bchmod\b/i, /(?:-(?=[a-z]*R)[a-z]*\s+0?777\s+\/(?:\s|$)|0?777\s+-(?=[a-z]*R)[a-z]*\s+\/(?:\s|$))/i),
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
function after(keyword, tail) {
    const kw = new RegExp(keyword.source, keyword.flags.replace(/[gy]/g, ''));
    const tl = new RegExp(tail.source, `${tail.flags.replace(/[gy]/g, '')}g`);
    return (text) => {
        const m = kw.exec(text);
        if (m === null)
            return false;
        tl.lastIndex = m.index + m[0].length;
        return tl.test(text);
    };
}
function anyOf(...tests) {
    return (text) => tests.some((t) => t(text));
}
/**
 * `process-substitution-remote-fetch`'s pattern, in linear time: on some
 * line, a shell name ENDS at or before the start of a `<( curl|wget`. The
 * pattern itself restarts its `[^\n]*` at every shell name on the line.
 */
function processSubstitutionFetch(text) {
    for (const line of text.split('\n')) {
        const shell = /\b(?:sh|bash|zsh|dash|ksh|ash|mksh|source)\b|(?:^|[;&|(){}])[ \t]*\.(?=\s)/i.exec(line);
        if (shell === null)
            continue;
        const shellEnd = shell.index + shell[0].length;
        for (const fetch of line.matchAll(/<\(\s*(?:curl|wget)\b/gi)) {
            if (fetch.index >= shellEnd)
                return true;
        }
    }
    return false;
}
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
function interpolatedVariables(inner) {
    if (!inner.includes('$'))
        return [];
    const out = [];
    let depth = 0;
    for (const m of inner.matchAll(INTERPOLATION)) {
        const t = m[0];
        if (t === '$(')
            depth += 1;
        else if (t === '(')
            depth += depth > 0 ? 1 : 0;
        else if (t === ')')
            depth -= depth > 0 ? 1 : 0;
        else {
            const next = inner.charAt(m.index + t.length);
            if (depth === 0 || (next !== '.' && next !== '['))
                out.push(t);
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
const NAME_POSITION = /(?:(?:^|[\s;|&(])-(?:ov|outv[a-z]*|v[a-z]*|n[a-z]*)[ \t]*:?[ \t]*|(?:^|[\s;|&(])(?:set-variable|new-variable|get-variable|sv|nv|gv)[ \t]+)$/i;
/** A variable's name, with its scope — never one of the words the flow tokens read as a command. */
const QUOTED_NAME = /^(?:(?:global|script|local|private|using|variable):)?[A-Za-z_]\w{0,63}$/i;
const TOKEN_WORD = /^(?:iex|invoke-expression|irm|iwr|invoke-restmethod|invoke-webrequest|curl|wget|set-variable|new-variable|get-variable|sv|nv|gv|tee|tee-object)$/i;
/** A quoted span's text, when it is a variable's name in a place a name goes ({@link NAME_POSITION}). */
function quotedName(maskedBefore, inner) {
    if (!QUOTED_NAME.test(inner) || TOKEN_WORD.test(inner))
        return undefined;
    return NAME_POSITION.test(maskedBefore.slice(-48)) ? inner : undefined;
}
/** `masked` with each interpolation's variables written back after the mask that ends at its offset. */
function withInterpolations(masked, interpolations) {
    if (interpolations.length === 0)
        return masked;
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
    /** Where in `maskedCommand` a double-quoted span's mask ends, and the variables it interpolates. */
    const interpolations = [];
    let masked = '';
    let commands = [];
    let words = [];
    let buf = '';
    let bufQuoted = false;
    let bufRedirects = [];
    let hasWord = false;
    /** Every word of the current command after its first is an unquoted `-` flag. */
    let dashTail = true;
    /** Last code character emitted, to tell a background `&` from `2>&1`. */
    let lastCode = '';
    const heredocs = [];
    /**
     * What each open `(` is: `word` for a substitution that is part of a word
     * (`$(`, `$((`, `<(`, `>(`, `=(`, `@(`), `group` for a subshell. After a
     * `)` that closed a word — or after a closing backtick — a `#` continues the
     * word and is no comment: `echo $(date)#x; rm -rf /` runs `rm` (fix round 5).
     */
    const parens = [];
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
    let currentStatement = { masked: '', commands: [] };
    const endWord = () => {
        // A reserved word where a command name belongs opens or closes a compound
        // command (`do rm -rf /`, `then …`, `{ …`); the command is the word AFTER
        // it. Kept, it read as a command called `do`, and every loop, `if` and
        // brace-group body went unassessed (final review I13).
        const reserved = hasWord && !bufQuoted && words.length === 0 && COMPOUND_RESERVED.has(buf);
        // `case … esac` patterns end in a bare `)`: inside `$(…)` they must not
        // close the substitution (fix round 6).
        if (hasWord && !bufQuoted && words.length === 0) {
            if (buf === 'case')
                parens.push('case');
            else if (buf === 'esac' && parens[parens.length - 1] === 'case')
                parens.pop();
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
            if (words.length >= 1 && (bufQuoted || !buf.startsWith('-')))
                dashTail = false;
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
        dashTail = true;
    };
    const endStatement = (end) => {
        endCommand();
        const text = masked.trim();
        if (text.length > 0 || commands.length > 0) {
            currentStatement.masked = text;
            currentStatement.commands = commands;
            if (end !== undefined)
                currentStatement.end = end;
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
        // A `#` that starts a word comments out the rest of the line, in a POSIX
        // shell and in PowerShell alike. Read as code, the apostrophe in `# clean
        // the user's build dir` opened a quote that ran to the end of the command
        // and hid every line after it — `rm -rf /` included (fix round 4, C1).
        // Heredoc bodies never reach here (`skipHeredocBodies`).
        if (ch === '#' && !hasWord && !(closedWord && /[)`]/.test(command.charAt(i - 1)))) {
            while (i < command.length && command.charAt(i) !== '\n' && command.charAt(i) !== '\r')
                i += 1;
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
            if (name !== undefined)
                vars.push(name);
            if (vars.length > 0)
                interpolations.push({ at: maskedCommand.length, vars: vars.join(' ') });
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
            if (ch === '(')
                parens.push(/[$<>=@(]/.test(command.charAt(i - 1)) ? 'word' : 'group');
            // A `case` pattern's `)` has no `(` of its own (fix round 6); an `esac`
            // right before this `)` has closed its `case` already.
            else if (ch === ')') {
                if (buf === 'esac' && !bufQuoted && words.length === 0 && parens[parens.length - 1] === 'case')
                    parens.pop();
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
const RUNNER_VALUED = {
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
function runnerOptionWords(runner, option) {
    const valued = RUNNER_VALUED[runner];
    if (valued === undefined)
        return 1;
    if (option.startsWith('--')) {
        return !option.includes('=') && valued.long.has(option.slice(2)) ? 2 : 1;
    }
    // A short cluster: the first letter that takes a value takes the rest of the
    // cluster, or — when it is the last letter — the next word.
    for (let k = 1; k < option.length; k += 1) {
        if (valued.short.includes(option.charAt(k)))
            return k === option.length - 1 ? 2 : 1;
    }
    return 1;
}
const ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/;
/**
 * Walks past `VAR=x` assignments and runner prefixes (`sudo`, `env`, `xargs`,
 * `timeout 30`, …) to the index of the word that actually names the command,
 * reporting on the way whether privilege was elevated. `through`, when given,
 * limits the runners walked past to those named (the rest end the walk).
 */
function resolveCommand(words, through) {
    let i = 0;
    let elevated = false;
    // No hop cap: every pass consumes at least one word, so this is linear —
    // and a cap of 32 made `nice` x40 + `rm -rf /` a silent ok (fix round 4).
    while (i < words.length) {
        const word = words[i];
        if (word === undefined)
            break;
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
        if (!RUNNERS.has(name) || (through !== undefined && !through.has(name)))
            break;
        if (name === 'sudo' || name === 'doas')
            elevated = true;
        i += 1;
        if (name === 'start') {
            // Its `/x` switches (`/d DIR` takes a value) and one quoted title.
            let titled = false;
            while (i < words.length) {
                const arg = words[i];
                if (arg === undefined)
                    break;
                if (!titled && arg.quoted) {
                    titled = true;
                    i += 1;
                }
                else if (/^\/[A-Za-z]+$/.test(arg.value))
                    i += /^\/d$/i.test(arg.value) ? 2 : 1;
                else
                    break;
            }
            continue;
        }
        while (i < words.length) {
            const arg = words[i];
            if (arg === undefined)
                break;
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
export function commandWordIndex(words) {
    return resolveCommand(words).index;
}
function stripQuotes(token) {
    // Loops, not `/['"`]+$/`: that regex restarts at every quote of a long run.
    const q = (c) => c === "'" || c === '"' || c === '`';
    let a = 0;
    let b = token.length;
    while (a < b && q(token.charAt(a)))
        a += 1;
    while (b > a && q(token.charAt(b - 1)))
        b -= 1;
    return token.slice(a, b);
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
    // PowerShell's `\` and `\*` are the current drive's root; in bash the `\`
    // is an escape, so `rm -rf \*` arrives here as `*` and is not this.
    if (/^\\\*?$/.test(t))
        return true;
    // Home, and everything under it — with either separator, since PowerShell
    // and Git Bash take both (review I2: `Remove-Item ~\* -Recurse -Force` and
    // `$HOME\*` only warned). PowerShell's `$HOME` is `$home` too.
    if (/^~(?:[\\/]\*?)?$/.test(t))
        return true;
    if (/^\$\{?HOME\}?(?:[\\/]\*?)?$/i.test(t))
        return true; // $HOME, $HOME/, $HOME\*, ${HOME}, …
    // Git Bash sees the Windows environment: `$USERPROFILE`, `$HOMEDRIVE$HOMEPATH`.
    if (/^(?:\$\{?USERPROFILE\}?|\$\{?HOMEDRIVE\}?\$\{?HOMEPATH\}?|\$\{?env:HOMEDRIVE\}?\$\{?env:HOMEPATH\}?)(?:[\\/]\*?)?$/i.test(t)) {
        return true;
    }
    // Git Bash / WSL drive-root spellings: /c, /c/, /c/*, /mnt/c, /mnt/c/*.
    if (/^\/[a-z](?:\/\*?)?$/i.test(t))
        return true;
    if (/^\/mnt\/[a-z](?:\/\*?)?$/i.test(t))
        return true;
    // Native Windows drive roots: C:/, C:\, C:/*, C:\*.
    if (/^[A-Za-z]:[\\/]\*?$/.test(t))
        return true;
    // The same through cmd's and PowerShell's environment spellings — the home
    // directory, the system drive and the system directories — and those
    // directories named outright (fix round 2: `rmdir /s /q %USERPROFILE%`).
    // The POSIX tokenizer drops an unquoted `\`, so `C:\Windows` may arrive
    // as `C:Windows`.
    if (/^(?:%(?:USERPROFILE|HOMEDRIVE%%HOMEPATH|HOMEDRIVE|HOMEPATH|SystemDrive|SystemRoot|windir|ProgramFiles|ProgramFiles\(x86\)|ProgramData|ALLUSERSPROFILE|PUBLIC)%|\$\{?env:(?:USERPROFILE|HOMEDRIVE|HOMEPATH|SystemDrive|SystemRoot|windir|ProgramFiles|ProgramData|ALLUSERSPROFILE|PUBLIC)\}?)(?:[\\/]\*?)?$/i.test(t)) {
        return true;
    }
    if (/^[A-Za-z]:[\\/]?(?:Windows|Users|Program Files(?: \(x86\))?|ProgramData)(?:[\\/]\*?)?$/i.test(t))
        return true;
    // Top-level system directories (exact, optionally trailing / or /*),
    // including macOS's capitalised ones.
    if (/^\/(?:etc|usr|bin|sbin|var|lib|lib64|boot|sys|proc|root|home|opt|dev|Users|System)(?:\/\*?)?$/.test(t)) {
        return true;
    }
    return false;
}
/**
 * A delete target as a comparable path: quotes and a trailing `/`, `\`, `/*`
 * or `\*` gone, `\` read as `/`, and — where paths fold case (Windows) — Git
 * Bash's `/c/…` and WSL's `/mnt/c/…` read as `c:/…`, lower-cased.
 */
function targetKey(raw, fold) {
    const t = stripQuotes(raw.trim())
        .replace(/\\/g, '/')
        .replace(/\/{2,}/g, '/')
        .replace(/\/+\*?$/, '');
    return fold ? t.replace(/^(?:\/mnt)?\/([a-z])(?=\/|$)/i, '$1:').toLowerCase() : t;
}
/** `home` for {@link isHomeTarget}; none for an empty home or one that is a root. */
function homeDirFor(home, platform) {
    if (home === undefined)
        return undefined;
    const fold = platform === 'win32';
    const key = targetKey(home, fold);
    return key === '' || /^[a-z]:$/i.test(key) ? undefined : { key, fold };
}
/**
 * The home directory named outright — `C:\Users\alice`, `/c/Users/alice/`,
 * `/home/alice/*` — compared with `os.homedir()`, case-insensitively on
 * Windows (review I2). A path below it is not the home directory.
 */
function isHomeTarget(raw, home) {
    return home !== undefined && targetKey(raw, home.fold) === home.key;
}
/** Remove-Item's path parameters and their abbreviations: `-Path`, `-LiteralPath`, `-LP`, `-PSPath`. */
const PS_PATH_PARAM = /^(?:pa(?:t|th)?|l(?:i(?:t(?:e(?:r(?:a(?:l(?:p(?:a(?:t(?:h)?)?)?)?)?)?)?)?)?)?|lp|pspath)$/;
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
 * style slash flags: `/s` recurse, `/q` quiet-force — and, being Remove-Item
 * aliases in PowerShell, its dash flags too).
 */
function assessRecursiveDelete(words, start, home) {
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
    const rest = words.slice(start + 1);
    for (let k = 0; k < rest.length; k += 1) {
        // PowerShell takes an en or em dash for a parameter's `-` (fix round 4).
        const token = (rest[k]?.value ?? '').replace(/^[\u2013\u2014\u2015]/, '-');
        if (slashStyle && token.startsWith('/')) {
            const lower = token.toLowerCase();
            if (lower === '/s')
                recursive = true;
            else if (lower === '/q')
                force = true;
            continue;
        }
        // Dash flags: `rm`'s and `Remove-Item`'s — and, since `rd`, `rmdir`, `del`
        // and `erase` are Remove-Item aliases in PowerShell, theirs too:
        // `rmdir C:\Users -Recurse -Force` was ok (fix round 4).
        if (token === '--no-preserve-root')
            noPreserve = true;
        else if (token === '--recursive')
            recursive = true;
        else if (token === '--force')
            force = true;
        else if (token.startsWith('--'))
            continue;
        else if (token.startsWith('-') && token.length > 1) {
            // A PowerShell parameter may be given its value after a colon, split at
            // the FIRST colon only (`-Path:C:\Users` is `C:\Users` — fix round 6).
            const colon = token.indexOf(':');
            const flags = colon < 0 ? token.slice(1) : token.slice(1, colon);
            let value = colon < 0 ? undefined : token.slice(colon + 1);
            const lower = flags.toLowerCase();
            const isSwitch = lower === 'recurse' || lower === 'rec' || lower === 'force' || lower === 'fo';
            // A switch's value may also be the next word (`-Recurse: $false`); any
            // other parameter's next word stays where it is — `-Path: C:\Users`
            // names the target (fix round 6).
            if (value === '' && isSwitch) {
                value = rest[k + 1]?.value ?? '';
                k += 1;
            }
            if (value !== undefined && value !== '' && PS_PATH_PARAM.test(lower))
                targets.push(value);
            // `-Recurse:$true` is on, `-Recurse:$false` off.
            const on = value === undefined || !/^\$?(?:false|0)$/i.test(value);
            // PowerShell's whole-word parameter names first — `-Recurse`,
            // `-Force`, and their common abbreviations. Checked before the
            // GNU-cluster heuristic below because that heuristic (does the flag
            // text contain the letter r/f anywhere?) is right for a *cluster* of
            // single-letter flags like `-rf`/`-fo`, where every character really
            // is its own flag, and wrong for a whole parameter name — `-Filter`
            // or `-Confirm` both contain an 'f', and would otherwise read as
            // `-Force` by accident.
            if (lower === 'recurse' || lower === 'rec')
                recursive ||= on;
            else if (lower === 'force' || lower === 'fo')
                force ||= on;
            else if (value === undefined && flags.length <= 3) {
                if (/r/i.test(flags))
                    recursive = true;
                if (/f/i.test(flags))
                    force = true;
            }
        }
        else
            targets.push(token);
    }
    if (!((recursive && force) || noPreserve))
        return null;
    if (noPreserve || targets.some((t) => isCatastrophicTarget(t) || isHomeTarget(t, home))) {
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
/** The same files through Claude Code's `CLAUDE_CONFIG_DIR`, spelled as a variable (bash, cmd, PowerShell). */
const CONFIG_DIR_VARIABLE_SETTINGS = /(?:\$\{?(?:env:)?CLAUDE_CONFIG_DIR\}?|%CLAUDE_CONFIG_DIR%)\/?settings(?:\.local)?\.json$/i;
/**
 * Whether a path names Claude Code's settings (review round 2, ruling 3): under
 * `.claude`, through the `CLAUDE_CONFIG_DIR` variable, or — when that is set
 * (`scope.configDirName`, its last segment) — directly under a directory of that
 * name, separators optional as in `HOOK_CONFIG_PATH` (`~/.claude-conta2/settings.json`).
 */
function isSettingsPath(path, configDirName) {
    if (CLAUDE_SETTINGS_PATH.test(path) || CONFIG_DIR_VARIABLE_SETTINGS.test(path))
        return true;
    if (configDirName === undefined)
        return false;
    const lower = path.toLowerCase();
    for (const file of ['settings.json', 'settings.local.json']) {
        if (lower.endsWith(`${configDirName}/${file}`) || lower.endsWith(`${configDirName}${file}`))
            return true;
    }
    return false;
}
/** The last segment of `CLAUDE_CONFIG_DIR`, lower-cased, as {@link isSettingsPath} matches it; none when unset. */
function configDirNameOf(dir) {
    const last = (dir ?? '').trim().replace(/[\\/]+$/, '').split(/[\\/]/).pop() ?? '';
    return last === '' ? undefined : last.toLowerCase();
}
/**
 * A key of Claude Code's settings that switches dev-guardian's hooks off:
 * `disableAllHooks`, the dispatcher's own environment switches, and
 * `enabledPlugins` when the same text names dev-guardian. The Write/Edit guard
 * (`settingsGuard.ts`) judges an edit of the settings by the value it sets; the
 * content a shell command writes cannot be read reliably, so here the key alone
 * decides, anywhere in the command's text.
 */
function namesLooseningKey(text) {
    return (/\bdisableAllHooks\b|\bGUARDIAN_HOOKS(?:_BASH_BLOCK)?\b|\bGUARDIAN_PKG_VET\b/i.test(text) ||
        (/enabledPlugins/i.test(text) && /dev-guardian/i.test(text)));
}
/** Whether the whole command names a loosening key — computed once per assessment (fix round 3). */
function loosens(scope) {
    if (scope.notes.loosens === undefined)
        scope.notes.loosens = namesLooseningKey(scope.raw);
    return scope.notes.loosens;
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
/** The longest current directory tracked. */
const MAX_CWD = 320;
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
    const next = resolveFrom(cwd, dir);
    // Only a directory a later relative path could need is tracked: one that
    // names a configuration directory or a parent of one. Any other
    // relative target still names its own config path in full. And never one
    // longer than a real directory: a chain of `cd`s built to be slow.
    return next.length > MAX_CWD || !/\.guardian|dev-guardian|\.config|\.claude/i.test(next) ? '' : next;
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
    return names.some((n) => wildcardMatch(last.toLowerCase(), n));
}
/**
 * `*` / `?` matching without backtracking (a `[…]` class matches any one
 * character): the classic two-pointer walk, O(pattern × name). A pattern
 * turned into a RegExp of `.*` runs backtracks exponentially on a name it
 * does not match.
 */
function wildcardMatch(pattern, name) {
    const pat = pattern.replace(/\[[^\]]*\]/g, '?');
    let pi = 0;
    let ni = 0;
    let star = -1;
    let mark = 0;
    while (ni < name.length) {
        const c = pat.charAt(pi);
        if (pi < pat.length && (c === '?' || c === name.charAt(ni))) {
            pi += 1;
            ni += 1;
        }
        else if (pi < pat.length && c === '*') {
            star = pi;
            mark = ni;
            pi += 1;
        }
        else if (star >= 0) {
            pi = star + 1;
            mark += 1;
            ni = mark;
        }
        else
            return false;
    }
    while (pat.charAt(pi) === '*')
        pi += 1;
    return pi === pat.length;
}
function noEffects() {
    return { writes: [], removes: [], dirs: [], special: [], links: [], hardLinkSources: [] };
}
/**
 * `into.push(...from)` without the spread: a spread passes every element as an
 * argument, and past ~125 000 of them (`rm a a a … /`, 245 KB) the engine
 * throws RangeError — which the hook turned into no decision at all (fix
 * round 3, I-1). Every append of a user-sized array in this file goes here.
 */
function pushAll(into, from) {
    for (const x of from)
        into.push(x);
}
function mergeEffects(into, from) {
    pushAll(into.writes, from.writes);
    pushAll(into.removes, from.removes);
    pushAll(into.dirs, from.dirs);
    pushAll(into.special, from.special);
    pushAll(into.links, from.links);
    pushAll(into.hardLinkSources, from.hardLinkSources);
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
/** The files `ln` hard-links to — every source operand, unless `-s` / `--symbolic` makes the links symbolic. */
function lnHardSources(args) {
    if (args.some((a) => a === '--symbolic' || /^-[a-zA-Z]*s[a-zA-Z]*$/.test(a)))
        return [];
    let dir = false;
    const rest = [];
    for (let i = 0; i < args.length; i++) {
        const a = args[i] ?? '';
        if (/^--target-directory=/.test(a))
            dir = true;
        else if (a === '--target-directory' || /^-[a-zA-Z]*t$/.test(a)) {
            dir = true;
            i += 1;
        }
        else if (/^-t./.test(a))
            dir = true;
        else if (a === '-S' || a === '--suffix')
            i += 1;
        else
            rest.push(a);
    }
    const names = operands(rest, new Set());
    return dir || names.length < 2 ? names : names.slice(0, -1);
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
const NEW_ITEM_VALUED = [
    ['type', ['itemtype', 'type']],
    ['path', ['path', 'literalpath', 'pspath', 'lp']],
    ['name', ['name']],
    ['target', ['value', 'target']],
    ['credential', ['credential']],
];
function newItemParam(spelled) {
    const exact = NEW_ITEM_VALUED.find(([, names]) => names.includes(spelled));
    if (exact !== undefined)
        return exact[0];
    const matches = NEW_ITEM_VALUED.filter(([, names]) => names.some((n) => n.startsWith(spelled)));
    return matches.length === 1 ? matches[0]?.[0] : undefined;
}
/**
 * The item type a FileSystem `-ItemType` value names. The provider matches
 * the value as a prefix, wildcards allowed, in this order — so `h` and
 * `Hard` are `HardLink`, `s*` is `SymbolicLink` — and `''` is a file.
 */
function itemTypeOf(value) {
    if (value === '')
        return 'file';
    const pattern = `${value.toLowerCase()}*`;
    if (wildcardMatch(pattern, 'directory') || wildcardMatch(pattern, 'container'))
        return 'directory';
    return ['file', 'symboliclink', 'junction', 'hardlink'].find((t) => wildcardMatch(pattern, t)) ?? 'unknown';
}
/** `New-Item`'s item type ({@link itemTypeOf}) and paths (`-Path`, `-LiteralPath`, `-Name`, or the first positional). */
function newItemArgs(args) {
    let spelledType = '';
    let target;
    const paths = [];
    const positional = [];
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
        if (value === undefined)
            continue;
        if (name === 'type')
            spelledType = value;
        else if (name === 'path' || name === 'name')
            paths.push(value);
        else if (name === 'target')
            target = value;
    }
    if (paths.length === 0 && positional.length > 0)
        paths.push(positional[0] ?? '');
    const itemType = itemTypeOf(spelledType);
    return target === undefined ? { itemType, paths } : { itemType, paths, target };
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
/** `cmd /c cmd /c …` nesting judged; deeper is not (a chain thousands deep once overflowed the stack). */
const MAX_CMD_NESTING = 8;
/** A word as a POSIX shell word that reads back as exactly itself. */
function posixWord(word) {
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
function cmdLineText(args) {
    const at = args.findIndex((a) => /^\/[ck]$/i.test(a));
    if (at < 0)
        return undefined;
    const [first, ...more] = args.slice(at + 1);
    if (first === undefined)
        return undefined;
    const head = /[\s&|^<>]/.test(first.trim()) ? cmdTextAsPosix(first) : posixWord(first);
    return [head, ...more.map(posixWord)].join(' ');
}
/** A cmd line respelled for the POSIX reader: `\` literal, `^x` outside double quotes an escaped `x`. */
function cmdTextAsPosix(line) {
    let out = '';
    let inQuote = false;
    for (let i = 0; i < line.length; i += 1) {
        const ch = line.charAt(i);
        if (ch === '"')
            inQuote = !inQuote;
        if (ch === '\\')
            out += '\\\\';
        else if (ch === '^' && !inQuote && i + 1 < line.length) {
            i += 1;
            out += `\\${line.charAt(i)}`;
        }
        else
            out += ch;
    }
    return out;
}
/** The commands `cmd /c LINE` (or `/k`) runs — see {@link cmdEffects} for how the line is read. */
function cmdLine(args) {
    const at = args.findIndex((a) => /^\/[ck]$/i.test(a));
    if (at < 0)
        return [];
    const first = args[at + 1];
    if (first === undefined)
        return [];
    const head = first.trim();
    const commands = /[\s&|^<>]/.test(head) ? splitCmdLine(head) : [{ words: [head], redirects: [] }];
    // The shell words after the first one continue the line's LAST command.
    const last = commands[commands.length - 1];
    if (last !== undefined)
        pushAll(last.words, args.slice(at + 2));
    return commands;
}
/**
 * Every command a `cmd /c` line runs, nested `cmd /c` lines flattened, as
 * shell words — for the checks that read a command rather than its file
 * effects: the plugin command and program text (fix round 1, M1).
 */
function cmdInnerCommands(args, depth = 0) {
    if (depth > MAX_CMD_NESTING)
        return [];
    const out = [];
    for (const command of cmdLine(args)) {
        const words = cmdCommandWords(command.words);
        const name = (words[0] ?? '').toLowerCase().replace(/\.exe$/, '');
        if (name === 'cmd')
            pushAll(out, cmdInnerCommands(words.slice(1), depth + 1));
        else
            out.push(words.map((value) => ({ value, quoted: false })));
    }
    return out;
}
function cmdEffects(args, cwd, depth = 0) {
    const e = noEffects();
    if (depth > MAX_CMD_NESTING)
        return e;
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
function effectsOf(name, args, cwd, depth = 0) {
    if (name === 'cmd')
        return cmdEffects(args, cwd, depth);
    const at = (p) => resolveFrom(cwd, p);
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
            return e;
        case 'link':
            pushAll(e.hardLinkSources, operands(args, new Set()).slice(0, 1).map(at));
            return e;
        case 'fsutil':
            // `fsutil hardlink create <new> <existing>`
            if (/^hardlink$/i.test(args[0] ?? '') && /^create$/i.test(args[1] ?? '')) {
                if (args[2] !== undefined)
                    e.links.push(at(args[2]));
                if (args[3] !== undefined)
                    e.hardLinkSources.push(at(args[3]));
            }
            return e;
        case 'mklink': {
            pushAll(e.links, mklinkDestinations(args).map(at));
            // `mklink /H <link> <target>`: a hard link to the target.
            const names = args.filter((a) => !a.startsWith('/'));
            if (args.some((a) => /^\/h$/i.test(a)) && names[1] !== undefined)
                e.hardLinkSources.push(at(names[1]));
            return e;
        }
        case 'new-item':
        case 'ni': {
            const item = newItemArgs(args);
            if (['symboliclink', 'hardlink', 'junction'].includes(item.itemType))
                pushAll(e.links, item.paths.map(at));
            if (item.itemType === 'hardlink' && item.target !== undefined)
                e.hardLinkSources.push(at(item.target));
            else if (item.itemType === 'file')
                pushAll(e.writes, item.paths.map(at));
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
                pushAll(e.removes, t.sources.map(at));
            // `cp -l` / `--link` hard-links instead of copying.
            if (name === 'cp' && args.some((a) => a === '--link' || /^-[a-zA-Z]*l[a-zA-Z]*$/.test(a)))
                pushAll(e.hardLinkSources, t.sources.map(at));
            if (t.dest === undefined)
                return e;
            const dest = t.dest;
            if (!t.into)
                e.writes.push(at(dest));
            pushAll(e.writes, t.sources.map((s) => at(intoDir(dest, s))));
            if (!t.into && (moves || t.recursive))
                e.dirs.push(at(dest));
            return e;
        }
        case 'xcopy':
        case 'robocopy': {
            const [, dest, ...files] = args.filter((a) => !/^\/[A-Za-z]/.test(a));
            if (dest !== undefined) {
                e.dirs.push(at(dest));
                e.writes.push(at(dest));
                pushAll(e.writes, files.map((f) => at(intoDir(dest, f))));
            }
            return e;
        }
        case 'rsync': {
            const paths = operands(args, RSYNC_VALUED);
            const dest = paths.pop();
            if (dest === undefined || paths.length === 0)
                return e;
            e.writes.push(at(dest));
            pushAll(e.writes, paths.map((s) => at(intoDir(dest, s))));
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
        pushAll(e.removes, operands(args, new Set()).filter((a) => !/^\/[A-Za-z]$/.test(a)).map(at));
    const written = commandWriteDestinations(name, args).map(at);
    pushAll(e.writes, written);
    if (name === 'shred' && args.some((a) => a === '--remove' || a.startsWith('--remove=') || /^-[a-zA-Z]*u/.test(a))) {
        pushAll(e.removes, written);
    }
    return e;
}
// ── program text on the command line
const PYTHON = /^(?:python[0-9.]*|py|pypy[0-9.]*)$/;
const INTERPRETERS = new Set(['node', 'nodejs', 'bun', 'deno', 'tsx', 'ts-node', 'perl', 'ruby', 'php', 'pwsh', 'powershell']);
/** `X run … python -c …`: tools that run an interpreter in a managed environment. */
const RUN_WRAPPERS = new Set(['uv', 'poetry', 'pipenv', 'pdm', 'rye', 'hatch', 'conda', 'mamba', 'micromamba', 'pixi']);
function isInterpreter(name) {
    return PYTHON.test(name) || INTERPRETERS.has(name);
}
/** Commands that launch the program named after their own flags: `npx node …`, cmd's `start /b node …`. */
const LAUNCHERS = new Set(['npx', 'bunx', 'pnpx', 'start']);
/** Package managers whose subcommand launches a program: `pnpm dlx`, `npm exec`, `yarn dlx`, `bun x`, … */
const LAUNCHER_SUBCOMMANDS = {
    npm: new Set(['exec', 'x']),
    pnpm: new Set(['dlx', 'exec']),
    yarn: new Set(['dlx', 'exec']),
    bun: new Set(['x']),
};
/** Launcher options whose next word is their value, not the program (`npx -p pkg`). */
const LAUNCHER_VALUED = new Set(['-p', '--package', '-c', '--call', '/d']);
/** The index of the first word at or after `from` that is not a `-` flag (`words.length` if none). */
function firstNonFlag(words, from) {
    let k = from;
    while (k < words.length && (words[k]?.value ?? '').startsWith('-'))
        k += 1;
    return k;
}
/** An interpreter's name as written — `node@20` (through `npx`) is `node`. */
function interpreterName(word) {
    return commandName(word).replace(/@[\w.^~<>=-]*$/, '');
}
/**
 * Index of the interpreter a command runs: at `start`, behind `uv run`-style
 * wrappers, or behind a launcher (`npx --yes node@20`, `start "" /b node`);
 * -1 for none.
 */
function interpreterIndex(words, start) {
    let i = start;
    // No hop cap: every hop moves `i` forward, so this is linear — and a cap of
    // four made five `npx -y` in front of `node -e …` a silent ok (fix round 4).
    while (i < words.length) {
        const name = interpreterName(words[i]?.value ?? '');
        // `bun x` launches before `bun` interprets; global flags may come first
        // (`pnpm --silent dlx`, `npm --yes exec`).
        const sub = LAUNCHER_SUBCOMMANDS[name] === undefined ? -1 : firstNonFlag(words, i + 1);
        const launches = sub >= 0 && LAUNCHER_SUBCOMMANDS[name]?.has(words[sub]?.value ?? '') === true;
        if (isInterpreter(name) && !launches)
            return i;
        if (RUN_WRAPPERS.has(name) && words[i + 1]?.value === 'run') {
            for (let k = i + 2; k < Math.min(words.length, i + 10); k += 1) {
                if (isInterpreter(interpreterName(words[k]?.value ?? '')))
                    return k;
            }
            return -1;
        }
        if (launches)
            i = sub + 1;
        else if (LAUNCHERS.has(name))
            i += 1;
        else
            return -1;
        // Past the launcher's own options (and `start`'s empty "" title).
        while (i < words.length) {
            const w = words[i]?.value ?? '';
            if (w !== '' && !/^(?:-|\/[A-Za-z])/.test(w))
                break;
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
    const name = interpreterName(words[at]?.value ?? '');
    const args = words.slice(at + 1).map((w) => w.value);
    if (PYTHON.test(name))
        return pythonCode(args);
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
function isBareInterpreterStdin(words) {
    const program = interpreterProgram(withoutRedirectWords(words), 0);
    return program.kind === 'dash' || (program.kind === 'none' && program.readsStdin);
}
/** Node's own options that take the next word as their value (besides `--opt=value`). */
const NODE_OPTION_VALUED = new Set([
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
function operandAt(words, i, readsStdin) {
    const w = words[i];
    if (w === undefined)
        return { kind: 'none', readsStdin };
    return w.value === '-' ? { kind: 'dash' } : { kind: 'file', index: i };
}
/**
 * A POSIX-style option cluster (`-uW ignore`, `-Wignore`, `-e 'code'`): `inline`
 * letters define the program, `valued` letters take the rest of the cluster or
 * the next word. Returns how many words the option used, or `inline`.
 */
function clusterWords(word, inline, valued) {
    for (let k = 1; k < word.length; k += 1) {
        const c = word.charAt(k);
        if (inline.includes(c))
            return 'inline';
        if (valued.includes(c))
            return k === word.length - 1 ? 2 : 1;
    }
    return 1;
}
function interpreterProgram(words, at) {
    const name = interpreterName(words[at]?.value ?? '');
    const python = PYTHON.test(name);
    const nodeLike = ['node', 'nodejs', 'tsx', 'ts-node'].includes(name);
    if (!python && !nodeLike && !['perl', 'ruby', 'php', 'deno', 'bun'].includes(name))
        return { kind: 'unknown' };
    let i = at + 1;
    if (name === 'deno' || name === 'bun') {
        const sub = words[i]?.value ?? '';
        if (sub === 'eval' || (name === 'bun' && /^(?:-e|-p|--eval|--print)$/.test(sub)))
            return { kind: 'inline' };
        if (sub === 'run')
            i += 1;
        else if (name === 'deno' || sub !== '-')
            return { kind: 'unknown' };
    }
    const readsStdin = !['deno', 'bun', 'tsx', 'ts-node'].includes(name);
    for (; i < words.length; i += 1) {
        const v = words[i]?.value ?? '';
        if (v === '--')
            return operandAt(words, i + 1, readsStdin);
        if (v === '-' || !v.startsWith('-'))
            return operandAt(words, i, readsStdin);
        if (python) {
            if (v.startsWith('--')) {
                if (v === '--check-hash-based-pycs')
                    i += 1;
                continue;
            }
            const used = clusterWords(v, 'cm', 'WXQ');
            if (used === 'inline')
                return { kind: 'inline' };
            i += used - 1;
        }
        else if (nodeLike) {
            if (/^-(?:e|p|pe|ep)$/.test(v) || /^--(?:eval|print)(?:=|$)/.test(v))
                return { kind: 'inline' };
            if (!v.includes('=') && NODE_OPTION_VALUED.has(v))
                i += 1;
        }
        else if (name === 'deno' || name === 'bun') {
            if (!v.includes('=') && (name === 'deno' ? DENO_RUN_VALUED : BUN_RUN_VALUED).has(v))
                i += 1;
        }
        else if (name === 'php') {
            if (/^-[rBRE]/.test(v))
                return { kind: 'inline' };
            if (v === '-f' || v === '-F')
                return operandAt(words, i + 1, readsStdin);
            if (/^-[dcz]$/.test(v))
                i += 1;
        }
        else {
            // perl and ruby: `-e` program text; the letters that take a value, as `perlLike` reads them.
            if (v.startsWith('--'))
                continue;
            const used = clusterWords(v, name === 'perl' ? 'eE' : 'e', name === 'perl' ? 'IMm' : 'IrCEFx');
            if (used === 'inline')
                return { kind: 'inline' };
            i += used - 1;
        }
    }
    return { kind: 'none', readsStdin };
}
function codeLang(interpreter) {
    if (PYTHON.test(interpreter))
        return 'python';
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
    return asWindowsOpens(literals.map((l) => tail(l.trim()).replace(/\\+/g, '/')));
}
/**
 * The end of a path, which is all any pattern here is anchored to — so a
 * megabyte-long word full of `.guardian/hooks` cannot make `hooks[^/]*\.json$`
 * rescan it from every occurrence.
 */
function tail(path) {
    return path.length > 1024 ? path.slice(-1024) : path;
}
/**
 * Each path, and — when it differs — the name Windows opens for it: without
 * an NTFS stream suffix or trailing dots and spaces (review M1:
 * `hooks.config.json::$DATA` writes the file itself). Both are judged, so the
 * second can only add a match; elsewhere a colon is part of a name, and
 * refusing that odd name there costs nothing.
 */
function asWindowsOpens(paths) {
    const out = [...paths];
    for (const p of paths) {
        const named = windowsName(p);
        if (named !== p)
            out.push(named);
    }
    return out;
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
function literalsNameClaudeSettings(literals, configDirName) {
    const paths = literalPaths(literals);
    if (paths.some((p) => isSettingsPath(p, configDirName)))
        return true;
    const has = (re) => paths.some((p) => re.test(p));
    const inDir = has(/(?:^|\/)\.claude\/?$/i) ||
        (configDirName !== undefined && paths.some((p) => p.toLowerCase().replace(/\/+$/, '').endsWith(configDirName)));
    return inDir && has(/^settings(?:\.local)?\.json$/i);
}
// ── .NET file calls in PowerShell
/**
 * Whether an index of `text` lies outside every quoted span (POSIX quoting),
 * for indices asked in increasing order: the scan resumes where the last one
 * stopped, so a text with many calls is still read once.
 */
function quoteTracker(text) {
    let quote = '';
    let i = 0;
    return (index) => {
        for (; i < index; i += 1) {
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
function callArgs(text, from) {
    const args = [];
    let depth = 0;
    let cur = '';
    let quote = '';
    const end = Math.min(text.length, from + MAX_CALL_ARGS);
    let closed = false;
    for (let i = from; i < end; i += 1) {
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
        if (ch === ')' && depth === 0) {
            closed = true;
            break;
        }
        if (ch === '(')
            depth += 1;
        if (ch === ')')
            depth -= 1;
        if (ch === ',' && depth === 0) {
            args.push(cur.trim());
            cur = '';
            if (args.length === 2)
                return { args, cut: false };
            continue;
        }
        cur += ch;
    }
    args.push(cur.trim());
    return { args, cut: !closed && end < text.length };
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
function dotNetEffects(text, cwd, notes) {
    const e = noEffects();
    if (!text.includes('::'))
        return e;
    const unquotedAt = quoteTracker(text);
    for (const m of text.matchAll(DOTNET_CALL)) {
        if (!unquotedAt(m.index))
            continue;
        const kind = (m[1] ?? '').toLowerCase();
        const method = (m[2] ?? '').toLowerCase();
        const call = callArgs(text, m.index + m[0].length);
        if (call.cut && notes !== undefined)
            notes.calls = true;
        const paths = call.args.map((a) => resolveFrom(cwd, argPath(a)));
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
const RULE_HARD_LINK = {
    id: 'guard-config-hard-link',
    level: 'block',
    reason: "Makes a hard link to the guardrail hooks' own configuration or to Claude Code's settings — a second name through which it can be rewritten",
};
/** The directory that holds Claude Code's project or user settings; separators optional as in `HOOK_CONFIG_PATH`. */
const CLAUDE_DIR = /\.claude\/?$/i;
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
function judgeEffects(effects, scope) {
    const e = {
        writes: asWindowsOpens(effects.writes.map(tail)),
        removes: asWindowsOpens(effects.removes.map(tail)),
        dirs: asWindowsOpens(effects.dirs.map(tail)),
        special: asWindowsOpens(effects.special.map(tail)),
        links: asWindowsOpens(effects.links.map(tail)),
        hardLinkSources: asWindowsOpens(effects.hardLinkSources.map(tail)),
    };
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
    // A hard link to a configuration file, to Claude Code's settings (the Write
    // guard judges a write through one as that file; a shell write through one
    // names neither), or — `cp -al` — to every file of a directory that holds
    // them (review 3.0, wave 2).
    const linksGuarded = (p) => isHookConfigPath(p) || isHookConfigDir(p) || isSettingsPath(p, scope.configDirName) || CLAUDE_DIR.test(p);
    if (e.hardLinkSources.some(linksGuarded))
        out.push({ ...RULE_HARD_LINK });
    if (e.writes.some((p) => isSettingsPath(p, scope.configDirName)) && loosens(scope))
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
/**
 * `dev-guardian db adopt --yes` makes a project's database trusted. That is a
 * person's decision, taken after reading the summary `db adopt` prints without
 * `--yes`: a hostile repository can ship a database that hides its findings,
 * and its text can talk an assistant into adopting it (review 3.0, wave 2).
 * The reason is the whole deny message ({@link BashAssessment.denyMessage}).
 */
const RULE_DB_ADOPT = {
    id: 'db-adopt-yes',
    level: 'block',
    reason: 'db adopt --yes marks a database as trusted; run it yourself in a terminal after reading `db adopt` without --yes',
};
/** The CLI, as a command or a script: `dev-guardian`, `dev-guardian.mjs`, `dev-guardian.cmd`, `dev-guardian@3.0.1`. */
const CLI_NAME = /^dev-guardian(?:@[\w.^~<>=-]*)?(?:\.(?:mjs|cjs|js|cmd|ps1|exe))?$/i;
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
function cliArgs(words, at) {
    const head = words[at];
    if (head === undefined)
        return undefined;
    if (CLI_NAME.test(basename(head.value)))
        return words.slice(at + 1).map((w) => w.value);
    if (!CLI_HOSTS.has(interpreterName(head.value)))
        return undefined;
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
/** `dev-guardian db adopt … --yes` (or `--yes=…`), its options in any order, however the CLI is launched. */
function adoptsDatabase(words, at) {
    const args = cliArgs(words, at);
    if (args === undefined)
        return false;
    const db = args.findIndex((a) => !a.startsWith('-'));
    if (args[db] !== 'db' || !args.slice(db + 1).includes('adopt'))
        return false;
    return args.some((a) => a === '--yes' || a.startsWith('--yes='));
}
/** Program text that names a hook config path; or Claude Code's settings, with a loosening key in the command. */
function judgeCode(code, lang, scope) {
    const literals = codeLiterals(code, lang);
    const out = [];
    if (literalsNameHookConfig(literals))
        out.push({ ...RULE_INLINE });
    if (literalsNameClaudeSettings(literals, scope.configDirName) && loosens(scope))
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
    pushAll(e.writes, redirectTargets(words).map((t) => resolveFrom(scope.cwd, t)));
    const out = judgeEffects(e, scope);
    // Each command of a `cmd /c` line, as if it stood alone (M1).
    const commands = commandName(head.value) === 'cmd' ? cmdInnerCommands(words.slice(start + 1).map((w) => w.value)) : [];
    for (const [cmdWords, at] of [[words, start], ...commands.map((c) => [c, 0])]) {
        if (turnsPluginOff(cmdWords, at))
            out.push({ ...RULE_PLUGIN_OFF });
        const lang = codeLang(interpreterName(cmdWords[interpreterIndex(cmdWords, at)]?.value ?? ''));
        for (const code of inlineCode(cmdWords, at))
            pushAll(out, judgeCode(code, lang, scope));
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
function shellScript(text) {
    return { text, powershell: false };
}
const DASH_C = /^-[A-Za-z]*c$/;
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
function nestedScripts(words, start) {
    const head = words[start];
    // `npx -c "…"` / `npm exec -c "…"` runs its argument in a shell (fix round 2).
    const launcher = head === undefined ? '' : commandName(head.value);
    if (launcher === 'npx' || launcher === 'pnpx' || (launcher === 'npm' && words[firstNonFlag(words, start + 1)]?.value === 'exec')) {
        for (let i = start + 1; i < words.length; i += 1) {
            const v = words[i]?.value ?? '';
            if (v === '-c' || v === '--call')
                return words[i + 1] === undefined ? [] : [shellScript(words[i + 1]?.value ?? '')];
            if (v.startsWith('--call='))
                return [shellScript(v.slice('--call='.length))];
            if (v === '--')
                break;
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
    if (launcher === 'iex' || launcher === 'invoke-expression') {
        const script = words
            .slice(start + 1)
            .map((w) => w.value)
            .join(' ')
            .trim();
        return script.length > 0 ? [{ text: script, powershell: true, iex: true }] : [];
    }
    let sawShell = false;
    for (let i = start; i < words.length; i += 1) {
        const word = words[i];
        if (word === undefined)
            continue;
        const name = commandName(word.value);
        if (!word.quoted && (name === 'pwsh' || name === 'powershell')) {
            return powershellCommand(words.slice(i + 1).map((w) => w.value), name)
                .filter((s) => s.trim().length > 0)
                .map((text) => ({ text, powershell: true }));
        }
        // A running flag, not a re-slice of the words before every `-…c` word:
        // that was quadratic (`-c -c -c …`, `find -exec`, `git -c`, `python
        // -c`: 64 KB took 15 s — fix round 3, I-2).
        if (!word.quoted && DASH_C.test(word.value) && sawShell) {
            const script = words[i + 1];
            return script === undefined ? [] : [shellScript(script.value)];
        }
        if (SHELLS.has(basename(word.value)))
            sawShell = true;
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
            pushAll(scripts, statement.heredocBodies.map((text) => ({ text, reader: only })));
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
const RULE_PIPE_TO_SHELL = {
    id: 'remote-pipe-to-shell',
    level: 'block',
    reason: 'Pipes a downloaded script directly into a shell (curl|wget … | sh/bash)',
};
const RULE_FETCH_EXEC = {
    id: 'remote-pipe-to-shell',
    level: 'block',
    reason: 'Executes the output of a remote download (curl/wget via $(…) or `…`)',
};
const RULE_IEX_DOWNLOAD = {
    id: 'powershell-iex-download',
    level: 'block',
    reason: 'Downloads and executes remote code via Invoke-Expression',
};
const RULE_DOWNLOAD_RUN = {
    id: 'download-then-run',
    level: 'block',
    reason: 'Downloads a file and runs it in the same command (DownloadFile / -OutFile, then &, ., Start-Process, …)',
};
/** The same, for a POSIX download — named for what it is (review round 3, item 7). */
const RULE_POSIX_DOWNLOAD_RUN = {
    id: 'download-then-run',
    level: 'block',
    reason: 'Downloads a file (curl -o / -O, wget, > file) and runs it in the same command (sh f, ./f, source f, python3 f, …) ' +
        'with no checksum or signature check of that file in between',
};
/**
 * Whether a command reads its stdin as a script: a shell, `source` / `.` of
 * `/dev/stdin`, or an interpreter given no program of its own — `python3 -`,
 * bare `node`, `perl`, `ruby`, `php` (review round 2, ruling 2). An
 * interpreter handed its program (`python3 -c '…'`, `python3 script.py`,
 * `python3 -m json.tool`, `perl -ne '…'`) reads stdin as data.
 */
function readsStdinAsScript(words, at) {
    const name = commandName(words[at]?.value ?? '');
    if (STDIN_SHELLS.has(name))
        return true;
    if ((name === 'source' || name === '.') && STDIN_PATHS.has(words[at + 1]?.value ?? ''))
        return true;
    if (name === 'xargs')
        return xargsRunsStdin(words, at);
    const plain = withoutRedirectWords(words.slice(at));
    if (RUN_WRAPPERS.has(name) && words[at + 1]?.value === 'run')
        return runWrapperReadsStdin(plain, 2, name === 'uv');
    // `uvx python -`, `uv tool run python -` (review 3.0 wave 2, round 2).
    if (name === 'uvx')
        return runWrapperReadsStdin(plain, 1, false);
    if (name === 'uv' && words[at + 1]?.value === 'tool' && words[at + 2]?.value === 'run')
        return runWrapperReadsStdin(plain, 3, false);
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
function runWrapperReadsStdin(words, from, dashIsProgram) {
    for (let i = from; i < words.length; i += 1) {
        const v = words[i]?.value ?? '';
        if (v === '-')
            return dashIsProgram;
        if (v === '--')
            continue;
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
function xargsRunsStdin(words, at) {
    return xargsProgram(words, at) !== undefined;
}
/**
 * How xargs makes its input a program, for {@link xargsRunsStdin}: `appended`
 * as the `-c` script or program text itself, `replaced` into it through the
 * replacement string — which has a safe form the deny can name (review 3.0
 * wave 2, round 2: the line as an argument, `sh -c '… "$1"' _ {}`).
 */
function xargsProgram(words, at) {
    const rest = withoutRedirectWords(words.slice(at));
    const i = resolveCommand(rest).index;
    const name = commandName(rest[i]?.value ?? '');
    const last = rest[rest.length - 1]?.value ?? '';
    if (i >= rest.length - 1)
        return undefined;
    const replace = xargsReplacement(rest.slice(1, i).map((w) => w.value));
    if (SCRIPT_SHELLS.has(name) || name === 'su') {
        if (DASH_C.test(last))
            return 'appended';
        const c = rest.findIndex((w, k) => k > i && !w.quoted && DASH_C.test(w.value));
        const script = c < 0 ? undefined : rest[c + 1]?.value;
        if (script === undefined)
            return undefined;
        if (replace !== undefined && script.includes(replace))
            return 'replaced';
        return runsItsArguments(script) ? 'appended' : undefined;
    }
    if (!isInterpreter(name))
        return undefined;
    if (/^(?:-[A-Za-z]*[ceE]|-r|--eval|--print|-p)$/.test(last))
        return 'appended';
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
function runsItsArguments(script) {
    if (!POSITIONAL.test(script))
        return false;
    return splitShell(script).statements.some((st) => st.commands.some((words) => {
        const at = resolveCommand(words).index;
        const head = words[at]?.value ?? '';
        if (POSITIONAL.test(head) && head.replace(POSITIONAL, '') === '')
            return true;
        return basename(head) === 'eval' && words.slice(at + 1).some((w) => POSITIONAL.test(w.value));
    }));
}
/**
 * The string xargs replaces with each line it reads, from its own options:
 * `-I R` / `-IR`, `-i` / `-iR` and `--replace[=R]` (`{}` when none is given),
 * BSD's `-J R`; none without one of them.
 */
function xargsReplacement(options) {
    let replace;
    for (let k = 0; k < options.length; k += 1) {
        const o = options[k] ?? '';
        if (o === '--replace')
            replace = '{}';
        else if (o.startsWith('--replace='))
            replace = o.slice('--replace='.length) || '{}';
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
                    if (attached === '')
                        k += 1;
                    break;
                }
            }
        }
    }
    return replace === '' ? undefined : replace;
}
/** `words` without their redirections (`<<< text`, `> f`, `2>&1`) — the operator word and a detached target both go. */
function withoutRedirectWords(words) {
    const out = [];
    for (let i = 0; i < words.length; i += 1) {
        const word = words[i];
        if (word === undefined)
            continue;
        const r = parseRedirect(word);
        if (r === null)
            out.push(word);
        else if (r.inline === '')
            i += 1;
    }
    return out;
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
function interpreterRunsFetch(statements, k) {
    const statement = statements[k];
    if (statement === undefined || !statement.masked.endsWith('<'))
        return false;
    const words = statement.commands[statement.commands.length - 1];
    const lastWord = words?.[words.length - 1];
    if (words === undefined || lastWord === undefined || lastWord.value !== '<' || lastWord.redirectAt?.[0] !== 0)
        return false;
    const next = statements[k + 1]?.commands[0];
    if (next === undefined || !['curl', 'wget'].includes(commandName(next[resolveCommand(next).index]?.value ?? '')))
        return false;
    const head = words.slice(0, -1);
    const at = resolveCommand(head).index;
    return interpreterProgram(head, at).kind === 'none';
}
const RULE_PROCESS_FETCH = {
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
function pipesDownloadIntoShell(statement) {
    let downloaded = false;
    for (const words of statement.commands) {
        const at = resolveCommand(words, PIPE_RUNNERS).index;
        if (downloaded && readsStdinAsScript(words, at)) {
            const xargs = commandName(words[at]?.value ?? '') === 'xargs' ? xargsProgram(words, at) : undefined;
            return xargs === 'replaced' ? RULE_XARGS_REPLACED : RULE_PIPE_TO_SHELL;
        }
        if (DOWNLOADERS.has(commandName(words[at]?.value ?? '')))
            downloaded = true;
    }
    return null;
}
/** A download written into xargs's program through its replacement string — and how to hand it over as data. */
const RULE_XARGS_REPLACED = {
    id: 'xargs-download-program',
    level: 'block',
    reason: "Writes downloaded text into a program through xargs's replacement string (xargs -I{} sh -c '… {} …'), " +
        `where it runs as code; hand each line over as an argument instead: xargs -I{} sh -c '… "$1"' _ {} ` +
        '(sys.argv / process.argv for an interpreter)',
};
/** `bash <<< "$(curl …)"`, `source /dev/stdin <<< "$(wget …)"`: a download handed to a shell as a here-string. */
function hereStringFetchIntoShell(words, at) {
    if (!readsStdinAsScript(words, at) && !['source', '.'].includes(commandName(words[at]?.value ?? '')))
        return false;
    for (let i = at + 1; i < words.length; i += 1) {
        const w = words[i];
        if (w === undefined || !w.value.startsWith('<<<') || w.redirectAt?.[0] !== 0)
            continue;
        const inline = w.value.slice(3);
        if (isBareRemoteFetch(inline.length > 0 ? inline : (words[i + 1]?.value ?? '')))
            return true;
    }
    return false;
}
/** A download in PowerShell program text: a web cmdlet, or a `WebClient` / `HttpClient` fetch. */
const PS_DOWNLOAD = /(?<![\w$-])(?:irm|iwr|invoke-restmethod|invoke-webrequest|curl|wget|start-bitstransfer)(?![\w-])|\.\s*(?:downloadstring|downloaddata|downloadfile|openread|getstringasync|getbytearrayasync|getstreamasync)\s*\(/i;
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
const PS_EXEC_TOKENS = /(?<run>(?<![\w$.\\/-])(?:iex|invoke-expression)(?![\w.-])|\[\s*(?:(?:system\s*\.\s*)?management\s*\.\s*automation\s*\.\s*)?scriptblock\s*\]\s*::\s*create\b|\.\s*(?:invokescript|newscriptblock)\b|(?<![\w-])-scriptblock\b)|(?<dl>(?<![\w$-])(?:irm|iwr|invoke-restmethod|invoke-webrequest|curl|wget)(?![\w-])|\.\s*(?:downloadstring|downloaddata|openread|getstringasync|getbytearrayasync|getstreamasync)\b)|(?<ref>\$(?:\{[^}\n]{0,128}\}|[\w:]+))(?<assign>\s*\+?=(?!=))?|(?<setvar>(?<![\w$.\\/-])(?:set-variable|new-variable|sv|nv)(?![\w.-]))|(?<getvar>(?<![\w$.\\/-])(?:get-variable|gv)(?![\w.-]))|(?<tee>(?<![\w$.\\/-])(?:tee-object|tee)(?![\w.-]))|(?<outvar>(?<![\w-])-(?:ov|outv(?:a(?:r(?:i(?:a(?:b(?:le?)?)?)?)?)?)?)(?![\w-])(?:(?:[ \t]*:[ \t]*|[ \t]+)\+?(?<outname>[A-Za-z_][\w:]*))?)|(?<teevar>(?<![\w-])-v(?:a(?:r(?:i(?:a(?:b(?:le?)?)?)?)?)?)?(?![\w-])(?:(?:[ \t]*:[ \t]*|[ \t]+)(?<teename>[A-Za-z_][\w:]*))?)|&&|\|\||[()|;\n]/gi;
/**
 * A variable as one name: `$` and the name, lower-cased, without braces or a
 * scope — `${Script:S}`, `$script:s` and `$s` are all `$s` (`$env:x` stays
 * itself: an environment variable is another variable).
 */
function psVariable(spelled) {
    let v = spelled.toLowerCase();
    if (v.startsWith('$'))
        v = v.slice(1);
    if (v.startsWith('{') && v.endsWith('}'))
        v = v.slice(1, -1);
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
function variableNamed(text, from) {
    const end = Math.min(text.length, from + VARIABLE_NAME_WINDOW);
    let named;
    let positional;
    let wantName = false;
    let skipValue = false;
    let i = from;
    while (i < end) {
        const c = text.charAt(i);
        if (c === ' ' || c === '\t') {
            i += 1;
            continue;
        }
        if (c === ';' || c === '|' || c === '\n' || c === '&' || c === ')')
            break;
        // One word: to a blank or a separator — a parenthesised value whole.
        let j = i + 1;
        if (c === '(') {
            for (let depth = 1; j < end && depth > 0; j += 1) {
                const d = text.charAt(j);
                if (d === '(')
                    depth += 1;
                else if (d === ')')
                    depth -= 1;
            }
        }
        else {
            while (j < end && !' \t;|&()\n'.includes(text.charAt(j)))
                j += 1;
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
                if (inline === undefined)
                    wantName = true;
                else
                    named = /^[$\w{}:]+$/.test(inline) ? psVariable(inline) : '*';
            }
            else if (inline === undefined && p.length >= 2 && VARIABLE_VALUED.some((v) => v.startsWith(p)))
                skipValue = true;
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
function powershellDownloadExecution(text) {
    if (!/iex|invoke-expression|scriptblock|invokescript/i.test(text))
        return false;
    const opens = [];
    let inIex = 0;
    let pendingIex = false;
    let downloaded = false;
    let piped = false;
    /** The variables being assigned in this `;`/newline segment, and the variables that hold a download. */
    let assigning = [];
    const tainted = new Set();
    /** In a `Tee-Object` command, whose `-Variable` receives what it is piped. */
    let inTee = false;
    let names = 0;
    /** `*`, a variable whose name could not be read, holds whatever any name may. */
    const holdsDownload = (v) => tainted.has(v) || tainted.has('*') || (v === '*' && tainted.size > 0);
    /** A download (or a variable holding one): run when it is `iex`'s argument, else armed for a pipe. */
    const download = () => {
        if (inIex > 0 || pendingIex)
            return true;
        downloaded = true;
        for (const v of assigning)
            tainted.add(v);
        return false;
    };
    /** A variable this command fills — from what it is piped, or from a download later in the segment. */
    const fills = (v) => {
        assigning.push(v);
        if (downloaded)
            tainted.add(v);
    };
    /** The name a `Set-` / `New-` / `Get-Variable` gives, read at most {@link MAX_VARIABLE_NAMES} times. */
    const nameAfter = (at) => (++names > MAX_VARIABLE_NAMES ? '*' : variableNamed(text, at));
    for (const m of text.matchAll(PS_EXEC_TOKENS)) {
        const t = m[0].toLowerCase();
        const g = m.groups ?? {};
        if (g['run'] !== undefined) {
            if (piped)
                return true;
            pendingIex = true;
        }
        else if (g['dl'] !== undefined) {
            if (download())
                return true;
        }
        else if (g['ref'] !== undefined) {
            const v = psVariable(g['ref']);
            if (g['assign'] !== undefined)
                assigning = [v];
            else if (holdsDownload(v) && download())
                return true;
        }
        else if (g['setvar'] !== undefined) {
            fills(nameAfter(m.index + m[0].length));
        }
        else if (g['getvar'] !== undefined) {
            if (holdsDownload(nameAfter(m.index + m[0].length)) && download())
                return true;
        }
        else if (g['tee'] !== undefined) {
            inTee = true;
        }
        else if (g['outvar'] !== undefined) {
            fills(g['outname'] === undefined ? '*' : psVariable(g['outname']));
        }
        else if (g['teevar'] !== undefined) {
            if (inTee)
                fills(g['teename'] === undefined ? '*' : psVariable(g['teename']));
        }
        else if (t === '(') {
            opens.push(pendingIex);
            if (pendingIex)
                inIex += 1;
            pendingIex = false;
        }
        else if (t === ')') {
            if (opens.pop() === true)
                inIex -= 1;
            pendingIex = false;
        }
        else if (t === '|') {
            if (downloaded)
                piped = true;
            pendingIex = false;
            inTee = false;
        }
        else {
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
function runKey(path) {
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
function remoteName(url, fallback) {
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
function posixSaves(name, words, at) {
    if (name !== 'curl' && name !== 'wget')
        return [];
    const wget = name === 'wget';
    const valued = wget ? WGET_SHORT_VALUED : CURL_SHORT_VALUED;
    const saved = [...redirectTargets(words.slice(at + 1))];
    const urls = [];
    let named = false;
    let remote = false;
    let dir = '';
    const save = (f) => {
        if (f === undefined || f === '' || f === '-') {
            if (f === '-')
                named = true;
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
            const value = () => (long[2] !== undefined ? long[2] : args[(i += 1)]);
            if (!wget && flag === 'output')
                save(value());
            else if (wget && flag === 'output-document')
                save(value());
            else if (!wget && (flag === 'remote-name' || flag === 'remote-name-all'))
                remote = true;
            else if ((!wget && flag === 'output-dir') || (wget && flag === 'directory-prefix'))
                dir = value() ?? '';
            continue;
        }
        if (a.startsWith('-') && a.length > 1) {
            for (let k = 1; k < a.length; k += 1) {
                const c = a.charAt(k);
                if (!wget && c === 'O')
                    remote = true;
                if (!valued.includes(c))
                    continue;
                const v = k < a.length - 1 ? a.slice(k + 1) : args[(i += 1)];
                if ((wget && c === 'O') || (!wget && c === 'o'))
                    save(v);
                else if (wget && c === 'P')
                    dir = v ?? '';
                break;
            }
            continue;
        }
        if (URL_ARG.test(a))
            urls.push(a);
    }
    if ((wget && !named) || (!wget && remote && !named)) {
        for (const url of urls) {
            const file = remoteName(url, wget ? 'index.html' : undefined);
            if (file !== undefined)
                saved.push(dir === '' ? file : `${dir.replace(/[\\/]+$/, '')}/${file}`);
        }
    }
    else if (dir !== '') {
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
function pipedSaves(name, words, at) {
    const out = redirectTargets(words.slice(at + 1));
    pushAll(out, commandWriteDestinations(name, withoutRedirections(words.slice(at + 1))).filter((f) => !f.startsWith('-')));
    return out;
}
/** The files a PowerShell web cmdlet saves: `-OutFile path`, BITS's `-Destination path`. */
function powershellSaves(name, words, at) {
    if (!SAVING_CMDLETS.has(name))
        return [];
    const out = [];
    for (let i = at + 1; i < words.length; i += 1) {
        const m = SAVE_PARAM.exec(words[i]?.value ?? '');
        if (m === null)
            continue;
        const dest = m[1] !== undefined && m[1] !== '' ? m[1] : words[i + 1]?.value;
        if (dest !== undefined && dest.trim() !== '')
            out.push(dest);
    }
    return out;
}
/** The destinations of `.DownloadFile(url, path)` calls outside a quoted span. */
function downloadFileCalls(text) {
    if (!/downloadfile/i.test(text))
        return [];
    const out = [];
    const unquotedAt = quoteTracker(text);
    for (const m of text.matchAll(DOWNLOAD_FILE_CALL)) {
        if (!unquotedAt(m.index))
            continue;
        // In the POSIX reading of a PowerShell command an unquoted comma is a
        // space, so the arguments may arrive as one: its last literal is the path.
        const { args } = callArgs(text, m.index + m[0].length);
        const second = args[1];
        const literals = codeLiterals(args[0] ?? '', 'other');
        const dest = second !== undefined ? argPath(second) : literals.length >= 2 ? literals[literals.length - 1] : undefined;
        if (dest !== undefined && dest.trim() !== '')
            out.push(dest);
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
function isRunnableName(path) {
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
function scriptOperand(words, at, name) {
    const rest = words.slice(at + 1);
    if (SCRIPT_SHELLS.has(name)) {
        if (rest.some((w) => !w.quoted && DASH_C.test(w.value)))
            return undefined;
        return withoutRedirections(rest).find((v) => !v.startsWith('-'));
    }
    // An interpreter's own options, read with its table of valued ones (round 3, item 2).
    const plain = withoutRedirectWords(words.slice(at));
    const program = interpreterProgram(plain, 0);
    if (program.kind === 'file')
        return plain[program.index]?.value;
    if (program.kind !== 'unknown')
        return undefined;
    if (inlineCode(words, at).length > 0 || rest.some((w) => /^-[A-Za-z]*m$/.test(w.value)))
        return undefined;
    return withoutRedirections(rest).find((v) => !v.startsWith('-'));
}
/** Whether a pipeline member reads its stdin as a program: a shell, `source /dev/stdin`, or a bare interpreter. */
function runsStdin(words, at) {
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
function commandRuns(statement, c, heads, pipedIntoRunner) {
    const words = statement.commands[c];
    const at = heads[c] ?? 0;
    const head = words?.[at];
    if (words === undefined || head === undefined)
        return [];
    const name = commandName(head.value);
    const out = [];
    const rest = withoutRedirections(words.slice(at + 1));
    const operands = rest.filter((v) => v !== '' && !v.startsWith('-') && !/^\/[A-Za-z]+$/.test(v));
    if (name === '.' || name === 'source') {
        if (rest[0] !== undefined)
            out.push(rest[0]);
    }
    else if (name === 'powershell' || name === 'pwsh') {
        const file = rest.findIndex((v) => /^-f(?:i(?:le?)?)?$/i.test(v));
        if (file >= 0)
            out.push(rest[file + 1] ?? '');
        else
            out.push(...operands);
    }
    else if (name === 'cmd') {
        const run = rest.findIndex((v) => /^\/[ck]$/i.test(v));
        if (run >= 0)
            out.push(rest[run + 1] ?? '');
    }
    else if (SCRIPT_SHELLS.has(name) || isInterpreter(name)) {
        const script = scriptOperand(words, at, name);
        if (script !== undefined)
            out.push(script);
    }
    else if (OPENERS.has(name)) {
        const files = [];
        for (let i = 0; i < rest.length; i += 1) {
            const v = rest[i] ?? '';
            if (PS_ARGUMENT_LIST.test(v))
                files.push(...(rest[(i += 1)] ?? '').split(/[\s,]+/));
            else if (PS_FILE_PATH.test(v))
                files.push(rest[(i += 1)] ?? '');
            else if (v.startsWith('-'))
                i += /^-(?:verb|wo\w*|windowstyle|w|redirect\w*|credential|cred)$/i.test(v) ? 1 : 0;
            else
                files.push(v);
        }
        out.push(...files.filter((f) => f !== '' && !/^\/[A-Za-z]+$/.test(f) && isRunnableName(f)));
    }
    else if (RUNS_ARGUMENT.has(name)) {
        out.push(...operands);
    }
    else if (READERS.has(name) && pipedIntoRunner) {
        out.push(...operands);
    }
    return out.filter((f) => f !== '');
}
/** Per pipeline member: whether a LATER member runs its stdin (`iex`, a shell, a bare interpreter) — one pass from the end. */
function pipedIntoRunners(statement, heads) {
    const out = new Array(statement.commands.length).fill(false);
    let later = false;
    for (let c = statement.commands.length - 1; c >= 0; c -= 1) {
        out[c] = later;
        const words = statement.commands[c] ?? [];
        const i = heads[c] ?? 0;
        const n = commandName(words[i]?.value ?? '');
        if (n === 'iex' || n === 'invoke-expression' || runsStdin(words, i))
            later = true;
    }
    return out;
}
/** Whether a command line may download anything at all — the cheap test before the walk. */
const MAY_DOWNLOAD = /curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod|start-bitstransfer|downloadfile/i;
/** Checksum and signature tools, as `(name, words) => whether this invocation checks`. */
function isIntegrityCheck(words, at) {
    const name = commandName(words[at]?.value ?? '');
    const args = words.slice(at + 1).map((w) => w.value);
    if (/^(?:sha(?:1|224|256|384|512)sum|b2sum|shasum)$/.test(name)) {
        return args.some((a) => a === '--check' || /^-[A-Za-z]*c[A-Za-z]*$/.test(a));
    }
    if (name === 'gpg' || name === 'gpg2')
        return args.includes('--verify');
    if (name === 'gpgv')
        return true;
    if (name === 'minisign' || name === 'signify')
        return args.some((a) => /^-[A-Za-z]*V/.test(a));
    if (name === 'cosign')
        return args.includes('verify-blob');
    if (name === 'openssl')
        return args.some((a) => a === '-verify' || a === '-prverify');
    return false;
}
/** Where a directory change leaves relative paths: `cd`, `pushd`, `Set-Location` (a `popd` goes back to the start). */
function cwdFor(name, args, cwd) {
    if (CD_RETURNS.has(name))
        return '';
    if (!CD_COMMANDS.has(name))
        return cwd;
    const dir = psParam(args, ['path', 'literalpath']) ?? args.find((a) => !(a.startsWith('-') || /^\/d$/i.test(a)));
    if (dir === undefined)
        return '~';
    const next = resolveFrom(cwd, dir);
    return next.length > MAX_CWD ? '' : next;
}
/** Commands that move or copy a file, so a download keeps its mark under the new name (review round 3, item 3). */
const TRANSFERS = new Set(['mv', 'cp', 'install', 'copy-item', 'cpi', 'copy', 'move-item', 'mi', 'move']);
/** Directories a bare command name is found in on PATH: a marked file placed there runs by its name alone. */
const PATH_DIRS = /^(?:\/usr\/local\/s?bin|\/usr\/s?bin|\/s?bin|\/opt\/homebrew\/bin|\/opt\/local\/bin|(?:~|\$\{?home\}?)\/(?:\.local\/)?bin)$/i;
/**
 * What an `mv` / `cp` / `install` / `Copy-Item` / `Move-Item` puts where: each
 * source, and the paths it may now be at — the destination itself, and a file
 * of the source's name inside it when the destination may be a directory.
 */
function transfersOf(name, words, at) {
    if (!TRANSFERS.has(name))
        return [];
    const args = withoutRedirections(words.slice(at + 1));
    if (name === 'install' && args.some((a) => a === '-d' || a === '--directory'))
        return [];
    const t = parseTransfer(args, name === 'copy' || name === 'move');
    const dest = t.dest;
    if (dest === undefined)
        return [];
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
function gpgOperands(args, gpgv) {
    const out = [];
    let verifying = gpgv;
    let optionsDone = false;
    for (let i = 0; i < args.length; i += 1) {
        const a = args[i] ?? '';
        if (!optionsDone && a === '--verify')
            verifying = true;
        else if (!optionsDone && a === '--')
            optionsDone = true;
        else if (!optionsDone && a.startsWith('-') && a !== '-')
            i += !a.includes('=') && GPG_VALUED.has(a) ? 1 : 0;
        else if (verifying)
            out.push(a);
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
function integrityCheckOf(statement, heads, cwd) {
    const last = statement.commands.length - 1;
    const words = statement.commands[last];
    const at = heads[last] ?? 0;
    if (words === undefined || !isIntegrityCheck(words, at))
        return undefined;
    const key = (token) => runKey(resolveFrom(cwd, token));
    const names = [];
    statement.commands.forEach((member, c) => {
        for (const w of member.slice((heads[c] ?? 0) + 1)) {
            for (const token of w.value.split(/\s+/))
                if (token !== '' && !token.startsWith('-'))
                    names.push(key(token));
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
        if (operands.length === 1 && signature !== undefined)
            implying.push(key(signature));
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
function archiveExtraction(name, words, at) {
    const args = withoutRedirections(words.slice(at + 1));
    const out = {};
    if (name === 'unzip') {
        for (let i = 0; i < args.length; i += 1) {
            const a = args[i] ?? '';
            if (a === '-d')
                out.dir = args[(i += 1)];
            else if (a.startsWith('-d') && a.length > 2)
                out.dir = a.slice(2);
            else if (!a.startsWith('-') && out.archive === undefined)
                out.archive = a;
        }
        return out.archive === undefined ? undefined : out;
    }
    if (name !== 'tar' && name !== 'bsdtar' && name !== 'gtar')
        return undefined;
    let extract = false;
    const pending = [];
    const take = (letter, value) => {
        if (letter === 'f')
            out.archive = value;
        else
            out.dir = value;
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
        if (a.startsWith('--'))
            continue;
        const option = a.startsWith('-') && a !== '-';
        if (!option && i > 0) {
            const letter = pending.shift();
            if (letter !== undefined)
                take(letter, a);
            continue;
        }
        const cluster = option ? a.slice(1) : a;
        for (let c = 0; c < cluster.length; c += 1) {
            const letter = cluster.charAt(c);
            if (letter === 'x')
                extract = true;
            if (letter !== 'f' && letter !== 'C')
                continue;
            const rest = cluster.slice(c + 1);
            if (option && rest !== '') {
                take(letter, rest);
                break;
            }
            pending.push(letter);
            if (option)
                break;
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
 * to the run is joined by `&&`: the run is then conditional on the check. A run
 * in a later, separate command is not seen at all: that is download, inspect,
 * run. Returns what saved the file that ran, which names the shape in the deny.
 */
function downloadsThenRuns(text, statements, bareRunsCwd) {
    if (!MAY_DOWNLOAD.test(text))
        return null;
    /** Per file, its latest download so far (`.DownloadFile` calls come before every statement), carried by mv / cp / install. */
    const downloads = new Map();
    for (const dest of downloadFileCalls(text))
        downloads.set(runKey(resolveFrom('', dest)), { at: -1, kind: 'powershell' });
    /** Bare command names that PATH now resolves to a marked file: placed by mv / cp / install into a PATH directory. */
    const pathBins = new Map();
    /**
     * Per file, the latest integrity check of it joined to the current statement
     * by `&&` all the way; `listAt`, the latest check against a checksum list
     * downloaded in the chain, which may cover every download. Both are carried
     * forward and cleared at any other separator, so each run is judged in
     * constant time.
     */
    const verified = new Map();
    let listAt = -2;
    let cwd = '';
    /**
     * PATH directories a download was extracted into (round 2), each with its
     * first extraction: what the archive held is unknown, so a later bare name
     * may be any of it. One entry per directory, so a lookup is constant time.
     */
    const extracted = new Map();
    for (let k = 0; k < statements.length; k += 1) {
        const statement = statements[k];
        if (statement === undefined)
            continue;
        const heads = statement.commands.map((words) => resolveCommand(words).index);
        const ran = [];
        const saved = [];
        // Nothing downloaded yet: nothing a run could match, so runs are not read.
        const reading = downloads.size > 0 || extracted.size > 0;
        const piped = reading ? pipedIntoRunners(statement, heads) : [];
        /** A download earlier in this pipeline writes to its stdout: what a later member saves is the download. */
        let streaming;
        /** A bare name run after an extraction into a PATH directory, and what downloaded the archive. */
        let fromArchive;
        /** Whether `archive` (a file, or stdin for `-` / none) is a download no check has cleared: what downloaded it. */
        const downloadedArchive = (archive) => {
            if (archive === undefined || archive === '-')
                return streaming;
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
            for (const dest of posix)
                saved.push({ key: runKey(resolveFrom(cwd, dest)), kind: 'posix' });
            for (const dest of ps)
                saved.push({ key: runKey(resolveFrom(cwd, dest)), kind: 'powershell' });
            // `curl … | sudo tee /usr/local/bin/tool`, `| gunzip > tool`, `irm … |
            // Out-File i.ps1` (review 3.0 wave 2, round 2).
            if (streaming !== undefined) {
                const kind = streaming;
                for (const dest of pipedSaves(name, words, at))
                    saved.push({ key: runKey(resolveFrom(cwd, dest)), kind });
            }
            // `curl … | tar xz -C /usr/local/bin`, `tar xzf t.tgz -C ~/.local/bin`
            // after `curl -o t.tgz`, `unzip t.zip -d /usr/local/bin` (round 2).
            const extraction = archiveExtraction(name, words, at);
            if (extraction !== undefined) {
                const dir = runKey(resolveFrom(cwd, extraction.dir ?? '.')).replace(/\/+$/, '');
                const kind = downloadedArchive(extraction.archive);
                if (kind !== undefined && PATH_DIRS.test(dir) && !extracted.has(dir))
                    extracted.set(dir, { at: k, kind });
            }
            if (DOWNLOADERS.has(name) && posix.length === 0 && ps.length === 0) {
                streaming = name === 'curl' || name === 'wget' ? 'posix' : 'powershell';
            }
            if (reading) {
                for (const file of commandRuns(statement, c, heads, piped[c] === true))
                    ran.push(runKey(resolveFrom(cwd, file)));
                // The command itself: a path runs that file. A bare name is looked up
                // on PATH by a POSIX shell and by PowerShell — only cmd.exe searches
                // the working directory first (review round 3, item 4).
                if (/[\\/]/.test(head))
                    ran.push(runKey(resolveFrom(cwd, head)));
                else if (head !== '') {
                    const onPath = pathBins.get(head.toLowerCase());
                    if (onPath !== undefined)
                        ran.push(onPath);
                    if (!NOT_FROM_ARCHIVE.has(head.toLowerCase())) {
                        for (const e of extracted.values())
                            if (e.at < k)
                                fromArchive ??= e.kind;
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
                    if (mark === undefined)
                        continue;
                    for (const dest of to) {
                        const key = runKey(resolveFrom(cwd, dest));
                        downloads.set(key, mark);
                        const check = verified.get(src);
                        if (check !== undefined)
                            verified.set(key, check);
                        const bin = lastSegment(key);
                        if (PATH_DIRS.test(dirOf(key)) && bin !== '')
                            pathBins.set(bin, key);
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
            for (const w of next.slice(1))
                if (!w.value.startsWith('-'))
                    ran.push(runKey(resolveFrom(cwd, w.value)));
        }
        for (const file of ran) {
            const d = downloads.get(file);
            // Run after its download, and not behind a check of it made after that download.
            if (d !== undefined && d.at < k && !((verified.get(file) ?? -3) > d.at) && !(listAt > d.at))
                return d.kind;
            // A file of an archive extracted into a PATH directory, run by its path.
            const e = extracted.get(dirOf(file));
            if (e !== undefined && e.at < k)
                return e.kind;
        }
        if (fromArchive !== undefined)
            return fromArchive;
        for (const { key, kind } of saved) {
            downloads.set(key, { at: k, kind });
            verified.delete(key);
            // Saved straight into a PATH directory, it runs by its bare name as a
            // moved one does (review 3.0, wave 2: `curl -o /usr/local/bin/tool …`).
            const bin = lastSegment(key);
            if (PATH_DIRS.test(dirOf(key)) && bin !== '')
                pathBins.set(bin, key);
        }
        // A pipeline's status is its last member's: only a check there decides —
        // and only for the files it names (review round 3, item 3).
        const check = integrityCheckOf(statement, heads, cwd);
        if (check !== undefined) {
            for (const name of check.names)
                if (downloads.has(name))
                    verified.set(name, k);
            for (const name of check.implied)
                verified.set(name, k);
            if (check.lists.some((list) => downloads.has(list)))
                listAt = k;
        }
        if (statement.end !== '&&') {
            verified.clear();
            listAt = -2;
        }
    }
    return null;
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
        if (rule.scope === 'command' && (rule.test ?? ((t) => rule.pattern.test(t)))(commandText)) {
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
    if (powershellDownloadExecution(flowText))
        out.push(RULE_IEX_DOWNLOAD);
    const ranDownload = downloadsThenRuns(cmd, statements, scope.cmdLine === true);
    if (ranDownload !== null)
        out.push(ranDownload === 'posix' ? RULE_POSIX_DOWNLOAD_RUN : RULE_DOWNLOAD_RUN);
    // `python3 <(curl …)`: an interpreter's script is a download (round 2, ruling 2).
    if (/<\(\s*(?:curl|wget)/i.test(commandText) && statements.some((_s, k) => interpreterRunsFetch(statements, k))) {
        out.push(RULE_PROCESS_FETCH);
    }
    for (const statement of statements) {
        // The total time budget: a hook that outlives Claude Code's 15 s timeout
        // lets the command run unassessed, so what is left is reported instead.
        if (scope.notes.now() > scope.notes.deadline) {
            scope.notes.budget = true;
            return;
        }
        // The ReDoS cap applies to each STATEMENT — never to a line before it is
        // split, which let padding hide every statement after it (fix round 1).
        const masked = capText(collapseBlanks(statement.masked), scope.notes);
        for (const rule of BASH_RULES) {
            if (rule.scope !== 'command' && (rule.test ?? ((t) => rule.pattern.test(t)))(masked)) {
                out.push({ id: rule.id, level: rule.level, reason: rule.reason });
            }
        }
        const piped = pipesDownloadIntoShell(statement);
        if (piped !== null)
            out.push(piped);
        for (const words of statement.commands) {
            // The budget is checked per command too: one statement can hold a
            // pipeline of thousands of commands (fix round 3, I-2).
            if (scope.notes.now() > scope.notes.deadline) {
                scope.notes.budget = true;
                return;
            }
            const resolved = resolveCommand(words);
            if (resolved.elevated)
                out.push({ ...SUDO_RULE });
            const del = assessRecursiveDelete(words, resolved.index, scope.home);
            if (del !== null)
                out.push(del);
            const find = assessFind(words, resolved.index);
            if (find !== null)
                out.push(find);
            if (hereStringFetchIntoShell(words, resolved.index))
                out.push(RULE_FETCH_EXEC);
            // `python3 -c "$(curl …)"`, `node -e "$(curl …)"`: the program IS a
            // download, as `sh -c "$(curl …)"` is (round 2, ruling 2).
            if (inlineCode(words, resolved.index).some(isBareRemoteFetch))
                out.push(RULE_FETCH_EXEC);
            pushAll(out, assessGuardConfig(words, resolved.index, scope));
            if (adoptsDatabase(words, resolved.index))
                out.push({ ...RULE_DB_ADOPT });
            const scripts = nestedScripts(words, resolved.index);
            const cmdHead = words[resolved.index];
            const line = cmdHead !== undefined && commandName(cmdHead.value) === 'cmd'
                ? cmdLineText(withoutRedirections(words.slice(resolved.index + 1)))
                : undefined;
            // Past the nesting depth, what is nested is not judged — and that is a
            // warning, never a silent ok (fix round 3, I-4).
            if (depth >= MAX_NESTING && (scripts.length > 0 || line !== undefined))
                scope.notes.depth = true;
            if (depth < MAX_NESTING) {
                for (const { text: script, powershell, iex } of scripts) {
                    // `sh -c "$(curl …)"` / `bash -c "$(wget -qO- …)"` — the whole -c
                    // script IS a download, executed without ever spelling `| sh`.
                    // Recursing alone would not catch this: the extracted script is
                    // just "curl …" with no pipe to a shell inside it, so nothing in
                    // BASH_RULES fires on it at the next depth. Checked directly, in
                    // addition to (not instead of) recursing.
                    if (isBareRemoteFetch(script))
                        out.push(RULE_FETCH_EXEC);
                    // `iex "& { $(irm …) }"`: whatever `iex` is handed is code, so a
                    // download anywhere in it — quoted or not — is run (review I1).
                    if (iex === true && PS_DOWNLOAD.test(script))
                        out.push(RULE_IEX_DOWNLOAD);
                    collect(script, depth + 1, out, { ...scope, cmdLine: false });
                    const asPowerShell = powershell ? powershellAsPosix(script) : script;
                    if (asPowerShell !== script)
                        collect(asPowerShell, depth + 1, out, { ...scope, cmdLine: false });
                }
                // Every command of a `cmd /c` line gets the full assessment, like a
                // top-level statement: deletes, pattern rules, nested shells (fix
                // round 2 — `cmd /c rd /s /q C:\` was ok, as it was at 166117a).
                if (line !== undefined)
                    collect(line, depth + 1, out, { ...scope, cmdLine: true });
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
        const fed = fedScripts(statement, isBareShellStdin);
        if (depth < MAX_NESTING) {
            for (const { text } of fed)
                collect(text, depth + 1, out, { ...scope, cmdLine: false });
        }
        else if (fed.length > 0)
            scope.notes.depth = true;
        for (const { text, reader } of fedScripts(statement, isBareInterpreterStdin)) {
            pushAll(out, judgeCode(text, codeLang(commandName(reader[0]?.value ?? '')), scope));
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
/** `os.homedir()`, or none when it cannot be determined (it throws without a passwd entry). */
function safeHomedir() {
    try {
        return homedir();
    }
    catch {
        return undefined;
    }
}
/** The warning for what a cap or the budget dropped — never a silent `ok` — naming which one. */
function partialRule(notes) {
    const causes = [
        ...(notes.statement ? ['over 16 KB'] : []),
        ...(notes.command ? ['over 512 KB'] : []),
        ...(notes.budget ? ['assessment time budget exhausted'] : []),
        ...(notes.depth ? [`nested more than ${MAX_NESTING} levels deep`] : []),
        ...(notes.calls ? [`an [IO.File] call's arguments over ${MAX_CALL_ARGS} characters`] : []),
        ...(notes.failed ? ['the assessment failed'] : []),
    ];
    return causes.length === 0
        ? null
        : { id: 'partially-assessed', level: 'warn', reason: `part of this command was not assessed (${causes.join('; ')})` };
}
/** Runs of spaces and tabs as one space: no rule pattern tells them apart, and padding stops counting. */
function collapseBlanks(text) {
    return text.replace(/[ \t]{2,}/g, ' ');
}
/** `text` cut at the cap, noting that something was dropped. */
function capText(text, notes) {
    if (text.length <= MAX_STATEMENT_LENGTH)
        return text;
    notes.statement = true;
    return text.slice(0, MAX_STATEMENT_LENGTH);
}
/**
 * Assess a shell command. The overall level is the most severe rule matched;
 * a command a cap cut short is at least a warning (`partially-assessed`).
 */
export function assessBashCommand(command, opts = {}) {
    const whole = (command ?? '').trim();
    if (!whole)
        return { level: 'ok', reasons: [], rules: [] };
    const now = opts.now ?? (() => performance.now());
    const deadline = now() + (opts.budgetMs ?? DEFAULT_BUDGET_MS);
    // The 512 KB cap is on what was written, never on a respelling of it: a
    // respelled `'` is four characters (fix round 4).
    const cut = whole.length > MAX_COMMAND_LENGTH;
    const text = cut ? whole.slice(0, MAX_COMMAND_LENGTH) : whole;
    const home = homeDirFor(opts.homeDir ?? safeHomedir(), opts.platform ?? process.platform);
    const where = { home, configDirName: configDirNameOf(opts.claudeConfigDir ?? process.env['CLAUDE_CONFIG_DIR']) };
    if (opts.shell !== 'powershell')
        return assessReadings([text], cut, now, deadline, where);
    // Under POSIX quoting, PowerShell's ordinary `"C:\Users\"` escapes its
    // closing quote and swallows the rest of the command, with no warning.
    // PowerShell's own reading goes first, so the one budget is never spent on
    // the POSIX reading before the reading that matches what will run; a block
    // needs no second reading. The POSIX reading sees here-strings and block
    // comments for what they are: nothing else can be meant by them.
    return assessReadings([powershellAsPosix(text), powershellOpaque(text)], cut, now, deadline, where);
}
/**
 * The readings of one command, assessed into one verdict: every rule any
 * reading matched, and one partial note for all of them — so on a tie no
 * reading's reasons are dropped. A reading after one that blocked is skipped.
 */
function assessReadings(readings, cut, now, deadline, where) {
    const notes = {
        statement: false,
        command: cut,
        budget: false,
        depth: false,
        loosens: undefined,
        failed: false,
        calls: false,
        deadline,
        now,
    };
    const matched = [];
    for (const [n, cmd] of readings.entries()) {
        if (n > 0 && (cmd === readings[n - 1] || matched.some((m) => m.level === 'block')))
            continue;
        notes.loosens = undefined;
        // An exception here used to escape to the hook, which then answered with
        // no decision at all — and the command ran unassessed (fix round 3, I-1:
        // 125 000 operands overflowed the stack). Whatever throws now, the answer
        // is at least a warning, and a block found before it still blocks.
        try {
            collect(cmd, 0, matched, { raw: cmd, cwd: '', notes, ...where });
        }
        catch {
            notes.failed = true;
        }
    }
    const partial = partialRule(notes);
    if (partial !== null)
        matched.push(partial);
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
    const blocks = effective.filter((r) => r.level === 'block');
    const only = blocks.length === 1 ? blocks[0] : undefined;
    const own = only?.id === RULE_DB_ADOPT.id ? only.reason : undefined;
    return {
        level: effective[0]?.level ?? 'ok',
        reasons: effective.map((r) => r.reason),
        rules: effective.map((r) => r.id),
        ...(own === undefined ? {} : { denyMessage: own }),
    };
}
//# sourceMappingURL=bashGuard.js.map