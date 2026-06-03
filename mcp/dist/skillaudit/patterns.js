/**
 * AI-agent threat pattern rule packs.
 *
 * Each rule maps to one `ThreatCategory` and is matched line-by-line against
 * a file's content. A rule declares a `target`:
 *   - 'text' → only run against instruction/doc artifacts (SKILL.md, README,
 *     *.md, *.txt, plain MCP manifest prose). These are where prompt-level
 *     attacks live.
 *   - 'code' → only run against executable/source artifacts (*.sh, *.py,
 *     *.js, *.ts, *.ps1, …). These are where real code execution lives.
 *   - 'any'  → both.
 *
 * Rules are intentionally conservative regexes: a hit is a *signal*, scored
 * by severity, never an automatic verdict. The scorer aggregates them.
 *
 * Hidden-Unicode (invisible instruction smuggling) is detected separately in
 * `analyze.ts` via code-point inspection rather than a literal regex, so this
 * file stays free of un-greppable invisible characters.
 *
 * Pure data + pure functions. No I/O.
 */
import { THREAT_CATEGORY_META } from './taxonomy.js';
export const SKILL_RULES = [
    // ───────────────────────────── prompt_injection ─────────────────────────
    {
        id: 'pi-override-instructions',
        category: 'prompt_injection',
        severity: 'high',
        title: 'Instruction-override phrasing',
        message: 'Text instructs the model to ignore/override prior or system instructions — classic prompt injection.',
        target: 'text',
        patterns: [
            /ignore\s+(all\s+)?(the\s+)?(previous|prior|above|earlier)\s+(instructions|prompts?|rules)/i,
            /disregard\s+(the\s+)?(above|previous|prior|all\s+earlier)/i,
            /forget\s+(everything|all)\s+(you\s+)?(were\s+told|know|above)/i,
            /\boverride\s+your\s+(instructions|guidelines|system\s+prompt)/i,
        ],
    },
    {
        id: 'pi-roleplay-escape',
        category: 'prompt_injection',
        severity: 'high',
        title: 'Role / guardrail escape phrasing',
        message: 'Text tries to redefine the assistant or bypass its safety guidelines (jailbreak pattern).',
        target: 'text',
        patterns: [
            /you\s+are\s+now\s+(an?\s+)?(unrestricted|developer\s+mode|dan|jailbroken)/i,
            /bypass\s+(your\s+)?(safety|guard\s?rails?|guidelines|content\s+policy)/i,
            /\bjailbreak\b/i,
            /pretend\s+(that\s+)?you\s+(have\s+no|are\s+not\s+bound\s+by)\s+(rules|restrictions)/i,
        ],
    },
    {
        id: 'pi-conceal-from-user',
        category: 'prompt_injection',
        severity: 'high',
        title: 'Instruction to hide actions from the user',
        message: 'Text instructs the model to act without informing or asking the user — covert behaviour.',
        target: 'text',
        patterns: [
            /do\s+not\s+(tell|inform|notify|mention\s+to)\s+the\s+user/i,
            /without\s+(asking|informing|telling|notifying)\s+the\s+user/i,
            /don'?t\s+let\s+the\s+user\s+(know|see)/i,
        ],
    },
    // ─────────────────────────── system_prompt_leakage ──────────────────────
    {
        id: 'spl-reveal-prompt',
        category: 'system_prompt_leakage',
        title: 'Attempt to extract the system prompt',
        message: 'Text asks the model to reveal/repeat its system prompt or hidden instructions.',
        target: 'text',
        patterns: [
            /(reveal|print|repeat|show|output|dump)\s+(me\s+)?(your|the)\s+(system\s+)?(prompt|instructions)/i,
            /repeat\s+(the\s+)?(text|everything)\s+(above|before\s+this)/i,
            /what\s+(are|were)\s+your\s+(initial|original|exact)\s+instructions/i,
        ],
    },
    // ───────────────────────────── memory_poisoning ─────────────────────────
    {
        id: 'mp-persist-instruction',
        category: 'memory_poisoning',
        severity: 'high',
        title: 'Durable memory / rules injection',
        message: 'Text tries to write attacker-controlled content into persistent memory, rules files or CLAUDE.md so it survives the session.',
        target: 'any',
        patterns: [
            /(add|append|write|save)\s+(this|the\s+following)\s+to\s+(your\s+)?(memory|rules|claude\.md|agents\.md)/i,
            /remember\s+(this\s+)?(forever|permanently|across\s+sessions|in\s+all\s+future)/i,
            /(\.claude\/(memory|CLAUDE\.md)|~\/\.claude\/)/i,
            /persist\s+this\s+(instruction|rule|behaviou?r)/i,
        ],
    },
    // ─────────────────────────────── rogue_agent ────────────────────────────
    {
        id: 'ra-conditional-trigger',
        category: 'rogue_agent',
        severity: 'high',
        title: 'Time-bomb / conditional hidden behaviour',
        message: 'Behaviour gated on a date, environment or "nobody watching" condition — hallmark of a logic bomb.',
        target: 'any',
        patterns: [
            /if\s+(the\s+)?(date|day|time)\s+(is|>=|>|after|past)/i,
            /(after|once\s+it\s+is)\s+(20\d{2}-\d{2}-\d{2}|20\d{2})/i,
            /when\s+(no\s+one|nobody)\s+(is\s+)?(watching|looking|around)/i,
            /only\s+(do\s+this\s+)?(if|when)\s+(running\s+in\s+)?(prod(uction)?|ci\b)/i,
        ],
    },
    // ─────────────────────────────── trigger_abuse ──────────────────────────
    {
        id: 'ta-overbroad-activation',
        category: 'trigger_abuse',
        title: 'Over-broad / coercive activation language',
        message: 'The skill demands activation on essentially every request — designed to intercept unrelated work.',
        target: 'text',
        patterns: [
            /always\s+(use|invoke|run|load)\s+this\s+skill/i,
            /for\s+(any|every|all)\s+(request|task|message|prompt|question)/i,
            /use\s+this\s+skill\s+for\s+everything/i,
            /regardless\s+of\s+(what\s+)?the\s+user\s+(asks|says|wants)/i,
        ],
    },
    // ────────────────────────────── data_exfiltration ───────────────────────
    {
        id: 'de-env-over-network',
        category: 'data_exfiltration',
        severity: 'critical',
        title: 'Environment / secrets sent over the network',
        message: 'Code reads environment variables or credentials and ships them to a network destination.',
        target: 'code',
        patterns: [
            /(fetch|axios|requests?\.(post|get|put)|http[s]?\.request|urllib|httpx)[^\n]{0,120}(process\.env|os\.environ|getenv|ENV\[)/i,
            /(process\.env|os\.environ|getenv)[^\n]{0,120}(fetch|axios|requests?\.|\.post\(|upload|send\()/i,
            /\b(curl|wget)\b[^\n]{0,200}(\$\{?[A-Z_]*(TOKEN|KEY|SECRET|PASSWORD|CREDENTIAL))/i,
        ],
    },
    {
        id: 'de-read-sensitive-files',
        category: 'data_exfiltration',
        severity: 'high',
        title: 'Reads sensitive local credential files',
        message: 'Code references SSH keys, cloud credentials, browser data or .env — sensitive material a skill rarely needs.',
        target: 'code',
        patterns: [
            /(id_rsa|\.ssh\/|\.aws\/credentials|\.npmrc|\.netrc|\.env\b|cookies\.sqlite|Login\s+Data)/i,
        ],
    },
    {
        id: 'de-dns-or-raw-egress',
        category: 'data_exfiltration',
        severity: 'high',
        title: 'Covert egress channel (DNS / raw socket / nc)',
        message: 'Use of DNS lookups, raw sockets or netcat as a data channel.',
        target: 'code',
        patterns: [
            /\b(nc|ncat|netcat)\b\s+[^\n]{0,60}\d{2,5}/i,
            /\b(dig|nslookup|host)\b[^\n]{0,80}\$\(/i,
            /socket\.socket\([^\n]{0,40}SOCK_(STREAM|DGRAM)/i,
        ],
    },
    // ──────────────────────────── privilege_escalation ──────────────────────
    {
        id: 'pe-elevation',
        category: 'privilege_escalation',
        severity: 'high',
        title: 'Privilege elevation / over-permissive perms',
        message: 'Elevates privileges, writes to system paths, or sets dangerously open permissions.',
        target: 'code',
        patterns: [
            /\bsudo\b\s+(-S\s+)?\S/i,
            /chmod\s+(-R\s+)?(777|a\+rwx|\+s)\b/i,
            /chown\s+(-R\s+)?root\b/i,
            /\b(setuid|setgid)\b/i,
            />\s*\/etc\/(sudoers|passwd|shadow|crontab)/i,
        ],
    },
    {
        id: 'pe-disable-protections',
        category: 'privilege_escalation',
        severity: 'high',
        title: 'Disables security protections',
        message: 'Turns off SELinux, firewall, Gatekeeper, SIP or antivirus.',
        target: 'code',
        patterns: [
            /setenforce\s+0|systemctl\s+stop\s+(firewalld|ufw)|ufw\s+disable/i,
            /spctl\s+--master-disable|csrutil\s+disable/i,
            /Set-MpPreference\s+-Disable(RealtimeMonitoring|IOAVProtection)/i,
        ],
    },
    // ────────────────────────────── supply_chain ────────────────────────────
    {
        id: 'sc-curl-pipe-shell',
        category: 'supply_chain',
        severity: 'high',
        title: 'Remote fetch piped to a shell',
        message: 'Downloads a remote script and executes it unverified (curl|bash and friends).',
        target: 'code',
        patterns: [
            /\b(curl|wget)\b[^\n|]{0,200}\|\s*(sudo\s+)?(bash|sh|zsh|python[23]?|node)\b/i,
            /\beval\s+"\$\(\s*(curl|wget)\b/i,
            /(iwr|invoke-webrequest|invoke-restmethod)[^\n|]{0,200}\|\s*(iex|invoke-expression)/i,
        ],
    },
    {
        id: 'sc-untrusted-install',
        category: 'supply_chain',
        severity: 'medium',
        title: 'Install from untrusted / unpinned source',
        message: 'Installs packages directly from a URL, git HEAD, or with lifecycle scripts enabled.',
        target: 'any',
        patterns: [
            /(pip|pip3)\s+install\s+[^\n]{0,200}(git\+http|https?:\/\/)/i,
            /npm\s+(install|i)\s+[^\n]{0,200}(git\+|https?:\/\/|github:)/i,
            /"(preinstall|postinstall|install)"\s*:/i,
        ],
    },
    // ───────────────────────────── excessive_agency ─────────────────────────
    {
        id: 'ea-destructive-unattended',
        category: 'excessive_agency',
        severity: 'high',
        title: 'Unattended destructive operation',
        message: 'Recursive delete of a home/root path, force-push, or DROP/TRUNCATE with no confirmation.',
        target: 'code',
        patterns: [
            /rm\s+-rf?\s+(--no-preserve-root\s+)?(\$HOME|~|\/|\/\*|\.\*)/i,
            /git\s+push\s+(-f|--force)\b/i,
            /(DROP|TRUNCATE)\s+(TABLE|DATABASE)\b/i,
        ],
    },
    {
        id: 'ea-autonomous-loop',
        category: 'excessive_agency',
        severity: 'medium',
        title: 'Self-directing / unbounded loop',
        message: 'Skill describes acting autonomously in an unbounded loop or self-modifying.',
        target: 'any',
        patterns: [
            /\bwhile\s+(true|1)\b/i,
            /self[-\s]?(modify|replicat|propagat)/i,
            /keep\s+(running|going)\s+until\s+(you|it)\s+(succeed|can)/i,
        ],
    },
    // ───────────────────────────── output_handling ──────────────────────────
    {
        id: 'oh-unsafe-render-or-eval',
        category: 'output_handling',
        severity: 'medium',
        title: 'Untrusted output rendered/executed unsafely',
        message: 'Model/remote output flows into innerHTML, document.write, or eval without sanitisation.',
        target: 'code',
        patterns: [
            /dangerouslySetInnerHTML/,
            /\.innerHTML\s*=/,
            /document\.write\s*\(/,
            /\beval\s*\(\s*(response|result|output|data|completion)\b/i,
        ],
    },
    // ───────────────────────────── dangerous_code ───────────────────────────
    {
        id: 'dc-dynamic-exec',
        category: 'dangerous_code',
        severity: 'high',
        title: 'Dynamic code execution',
        message: 'Direct use of eval/exec/Function or a shell from code.',
        target: 'code',
        patterns: [
            /\beval\s*\(/,
            /\bexec\s*\(/,
            /\bnew\s+Function\s*\(/,
            /os\.system\s*\(/,
            /child_process\.(exec|execSync)\s*\(/,
            /subprocess\.(run|call|Popen|check_output)\([^\n]{0,120}shell\s*=\s*True/i,
        ],
    },
    {
        id: 'dc-unsafe-deserialize',
        category: 'dangerous_code',
        severity: 'high',
        title: 'Unsafe deserialisation / dynamic load',
        message: 'pickle.loads / yaml.load / unsafe deserialisation or remote module import.',
        target: 'code',
        patterns: [
            /pickle\.loads?\s*\(/,
            /yaml\.load\s*\((?![^)]*Safe)/,
            /marshal\.loads?\s*\(/,
            /vm\.runIn(New|This)Context\s*\(/,
            /__import__\s*\(/,
        ],
    },
    {
        id: 'dc-encoded-payload-exec',
        category: 'dangerous_code',
        severity: 'critical',
        title: 'Decode-then-execute (obfuscated payload)',
        message: 'Base64/hex content is decoded and immediately executed — strong sign of a hidden payload.',
        target: 'code',
        patterns: [
            /(atob|Buffer\.from)\s*\([^\n]{0,160}(eval|Function|exec)/i,
            /base64\.b64decode\s*\([^\n]{0,160}(exec|eval|os\.system|subprocess)/i,
            /(eval|exec)\s*\([^\n]{0,40}(decode|b64decode|unhexlify|fromCharCode)/i,
        ],
    },
    // ─────────────────────────────── tool_misuse ────────────────────────────
    {
        id: 'tm-shell-from-text-tool',
        category: 'tool_misuse',
        severity: 'medium',
        title: 'Shell/network access from a non-execution helper',
        message: 'A skill that presents as read-only/formatting still reaches for shell or process-spawn primitives.',
        target: 'code',
        patterns: [/(spawn|spawnSync|popen|system)\s*\(/i],
    },
    // ──────────────────────────── mcp_tool_poisoning ────────────────────────
    {
        id: 'mtp-instructions-in-description',
        category: 'mcp_tool_poisoning',
        severity: 'high',
        title: 'Hidden instructions inside a tool/MCP description',
        message: 'An MCP tool name/description embeds directives that manipulate the model when the tool list is read.',
        target: 'any',
        patterns: [
            /"description"\s*:\s*"[^"]{0,400}(ignore\s+(previous|all)|do\s+not\s+(tell|mention|inform)|system\s+prompt|<important>|<secret>)/i,
            /<important>[\s\S]{0,400}<\/important>/i,
        ],
    },
];
/**
 * Run every rule whose target matches the file class against `content`,
 * returning one match per (rule, line) hit. `isCode` selects which rule
 * targets apply.
 */
export function scanContent(content, isCode) {
    const matches = [];
    const lines = content.split(/\r?\n/);
    for (const rule of SKILL_RULES) {
        if (rule.target === 'code' && !isCode)
            continue;
        if (rule.target === 'text' && isCode)
            continue;
        for (const pattern of rule.patterns) {
            for (let i = 0; i < lines.length; i += 1) {
                const line = lines[i] ?? '';
                pattern.lastIndex = 0;
                if (pattern.test(line)) {
                    matches.push({
                        rule,
                        line: i + 1,
                        snippet: line.trim().slice(0, 240),
                    });
                    break; // one hit per (rule, pattern) is enough signal
                }
            }
        }
    }
    return dedupeByRuleLine(matches);
}
/** Collapse multiple patterns of the same rule hitting the same line. */
function dedupeByRuleLine(matches) {
    const seen = new Set();
    const out = [];
    for (const m of matches) {
        const key = `${m.rule.id}:${m.line}`;
        if (seen.has(key))
            continue;
        seen.add(key);
        out.push(m);
    }
    return out;
}
export function severityOfRule(rule) {
    return rule.severity ?? THREAT_CATEGORY_META[rule.category].defaultSeverity;
}
//# sourceMappingURL=patterns.js.map