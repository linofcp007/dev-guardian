/**
 * Fast, dependency-free risk assessment for shell commands, used by the
 * guardian PreToolUse(Bash) hook.
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
 * Pure functions. No I/O.
 */
export const BASH_RULES = [
    // ── Catastrophic: block by default ───────────────────────────────────────
    // NB: `rm -rf` is handled separately in assessRmCommand() (tokenised) so the
    // *target* decides block vs warn — a regex can't tell `rm -rf /` from
    // `rm -rf node_modules`.
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
        pattern: /\b(?:dd\b[^\n]*\bof=\/dev\/|mkfs(?:\.\w+)?\s+\/dev\/|shred\b[^\n]*\/dev\/|>\s*\/dev\/(?:sd|nvme|hd|disk))/i,
    },
    {
        id: 'fork-bomb',
        level: 'block',
        reason: 'Shell fork bomb',
        pattern: /:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/,
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
        id: 'sudo',
        level: 'warn',
        reason: 'Runs with elevated privileges (sudo)',
        pattern: /(^|[\s;&|])sudo\s+/,
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
const LEVEL_RANK = { ok: 0, warn: 1, block: 2 };
function stripQuotes(token) {
    return token.replace(/^['"`]+|['"`]+$/g, '');
}
/** Filesystem locations whose recursive deletion is effectively never intended. */
function isCatastrophicTarget(raw) {
    const t = stripQuotes(raw);
    if (t === '/' || /^\/\*+$/.test(t))
        return true; // root, or everything under root
    if (t === '~' || t === '~/')
        return true; // home root
    if (/^\$\{?HOME\}?\/?$/.test(t))
        return true; // $HOME / ${HOME}
    // Top-level system directories (exact, optionally trailing / or /*).
    if (/^\/(?:etc|usr|bin|sbin|var|lib|lib64|boot|sys|proc|root|home|opt|dev)(?:\/\*?)?$/.test(t)) {
        return true;
    }
    return false;
}
/**
 * Tokenised assessment of `rm` invocations across a command's segments. The
 * *target* — not just the flags — decides severity: `rm -rf /` is catastrophic,
 * `rm -rf node_modules` is merely risky. Returns the worst single verdict, or
 * null when there is no recursive-force delete.
 */
function assessRmCommand(cmd) {
    const segments = cmd.split(/&&|\|\||[;|&]/);
    let broad = null;
    for (const seg of segments) {
        const tokens = seg.trim().split(/\s+/).filter(Boolean);
        let i = 0;
        while (i < tokens.length && (tokens[i] === 'sudo' || tokens[i] === 'command'))
            i++;
        if (tokens[i] !== 'rm')
            continue;
        let recursive = false;
        let force = false;
        let noPreserve = false;
        const targets = [];
        for (const token of tokens.slice(i + 1)) {
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
                if (/r/i.test(flags))
                    recursive = true;
                if (/f/.test(flags))
                    force = true;
            }
            else
                targets.push(token);
        }
        if (!((recursive && force) || noPreserve))
            continue;
        if (noPreserve || targets.some(isCatastrophicTarget)) {
            return {
                id: 'rm-rf-root',
                level: 'block',
                reason: 'Recursive force-delete targeting the filesystem root or home directory',
            };
        }
        broad = {
            id: 'rm-rf-broad',
            level: 'warn',
            reason: 'Recursive force-delete — confirm the target path is intended',
        };
    }
    return broad;
}
/**
 * Assess a shell command. The overall level is the most severe rule matched.
 */
export function assessBashCommand(command) {
    const cmd = (command ?? '').trim();
    if (!cmd)
        return { level: 'ok', reasons: [], rules: [] };
    const matched = [];
    for (const rule of BASH_RULES) {
        if (rule.pattern.test(cmd))
            matched.push({ id: rule.id, level: rule.level, reason: rule.reason });
    }
    const rm = assessRmCommand(cmd);
    if (rm)
        matched.push(rm);
    if (matched.length === 0)
        return { level: 'ok', reasons: [], rules: [] };
    // De-dupe by id, then most severe first.
    const byId = new Map();
    for (const m of matched)
        if (!byId.has(m.id))
            byId.set(m.id, m);
    const effective = [...byId.values()].sort((a, b) => LEVEL_RANK[b.level] - LEVEL_RANK[a.level]);
    return {
        level: effective[0]?.level ?? 'ok',
        reasons: effective.map((r) => r.reason),
        rules: effective.map((r) => r.id),
    };
}
//# sourceMappingURL=bashGuard.js.map