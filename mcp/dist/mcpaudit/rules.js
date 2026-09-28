/**
 * The text checks `audit_mcp_tools` runs over every string an MCP server
 * serves to the model: tool/prompt/resource names, titles and descriptions,
 * every string inside a tool's `inputSchema` / `outputSchema`, and the
 * server's `instructions`.
 *
 * Every check is a regex or a code-point scan over one string. A hit is a
 * signal to review, not a verdict — the same stance `skillaudit/patterns.ts`
 * takes — and each rule's message says what legitimate server would also
 * trip it, where one plausibly would.
 *
 * Pure data + pure functions. No I/O.
 */
import { MCP_DESCRIPTION_POISONING } from '../skillaudit/analyze.js';
import { SKILL_RULES } from '../skillaudit/patterns.js';
/**
 * The `scan_skill` prompt-level rules that apply to a description: text an
 * attacker writes to steer the model. Its code rules (`target: 'code'`) look
 * for executable shapes a description never has; `pi-conceal-from-user` has a
 * rule of its own below.
 */
const SKILL_TEXT_RULE_IDS = new Set([
    'pi-override-instructions',
    'pi-roleplay-escape',
    'spl-reveal-prompt',
    'mp-persist-instruction',
    'ta-overbroad-activation',
    'mtp-instructions-in-description',
]);
const SKILL_TEXT_PATTERNS = SKILL_RULES.filter((r) => SKILL_TEXT_RULE_IDS.has(r.id)).flatMap((r) => r.patterns);
const CONCEAL_SKILL_PATTERNS = SKILL_RULES.find((r) => r.id === 'pi-conceal-from-user')?.patterns ?? [];
/** A request verb within one clause of a secret-bearing noun. */
const READ_VERB = String.raw `\b(read|open|cat|load|include|pass|send|provide|attach|upload|extract|collect|copy|fetch|retrieve|dump|print|forward)\b`;
const SECRET_NOUN = String.raw `\b(credentials?|api[\s_-]?keys?|private\s+keys?|ssh\s+keys?|access\s+tokens?|auth(entication)?\s+tokens?|secrets?|passwords?)\b`;
/** What an exfiltration instruction ships out. */
const DATA_NOUN = String.raw `\b(data|contents?|conversation|chat|history|messages?|files?|results?|outputs?|keys?|tokens?|secrets?|credentials?|env(ironment)?|variables|everything|context|prompts?)\b`;
export const TEXT_RULES = [
    {
        id: 'mcp-tool-poisoning',
        severity: 'high',
        subcategory: 'mcp_tool_poisoning',
        label: 'instructions aimed at the model',
        explain: 'The text carries directives aimed at the model rather than a description of what the tool does — ' +
            'instruction overrides, <IMPORTANT>/<system> blocks, jailbreak or persistence phrasing. The host ' +
            'loads it into the model context with every tool list.',
        patterns: [MCP_DESCRIPTION_POISONING, ...SKILL_TEXT_PATTERNS],
    },
    {
        id: 'mcp-tool-sensitive-file-access',
        severity: 'high',
        subcategory: 'data_exfiltration',
        label: 'a reference to credential or agent-config files',
        explain: 'The text points the model at SSH keys, cloud or package-registry credentials, .env files or an MCP ' +
            'host config — files a tool description has no reason to ask for. A secrets-manager server may ' +
            'legitimately name them; any other server should not.',
        patterns: [
            /(~\/\.ssh\b|\.ssh\/|\bid_(rsa|dsa|ecdsa|ed25519)\b|\bauthorized_keys\b)/i,
            /(\bmcp\.json\b|\bmcp_config\.json\b|claude_desktop_config\.json|\.claude\.json\b)/i,
            /(\.aws\/credentials|\.netrc\b|\.npmrc\b|\.pypirc\b|\.git-credentials\b|\.docker\/config\.json|\.kube\/config\b|\/etc\/(passwd|shadow)\b)/i,
            /(^|[\s`'"(/])\.env(\.[\w-]+)?(?![\w-])/i,
            new RegExp(`${READ_VERB}[^.\\n]{0,60}${SECRET_NOUN}`, 'i'),
        ],
    },
    {
        id: 'mcp-tool-conceal-from-user',
        severity: 'high',
        subcategory: 'prompt_injection',
        label: 'an instruction to hide something from the user',
        explain: 'The text tells the model to keep an action from the user — the covert half of nearly every ' +
            'published tool-poisoning attack. No legitimate tool needs its use hidden.',
        patterns: [
            ...CONCEAL_SKILL_PATTERNS,
            /\b(do\s+not|don'?t|never)\s+(mention|reveal|show|disclose|display|tell|inform|notify|alert)\b[^.\n]{0,60}\b(user|human|anyone)\b/i,
            /\b(do\s+not|don'?t|never)\s+(mention|reveal|disclose)\s+(that|this|it)\b/i,
            /\b(silently|secretly|covertly|quietly)\s+(send|read|copy|upload|forward|call|run|execute|include|add|attach|post)\b/i,
            /\bwithout\s+(the\s+)?(user|user'?s|their)\s+(knowing|knowledge|consent|awareness|noticing)\b/i,
            /\bthe\s+user\s+(must|should|need)\s+not\s+(know|see|notice|be\s+(told|informed|aware))\b/i,
            /\b(keep|hide)\s+(this|it|these)\s+(secret\s+)?from\s+the\s+user\b/i,
        ],
    },
    {
        id: 'mcp-tool-exfiltration',
        severity: 'high',
        subcategory: 'data_exfiltration',
        label: 'an instruction to send data to an outside destination',
        explain: 'The text tells the model to ship data to a URL, a webhook or a fixed address. A notification or ' +
            'webhook server that names its own endpoint can trip this; a tool whose job is not sending should not.',
        patterns: [
            new RegExp(String.raw `\b(send|post|upload|forward|transmit|exfiltrate|submit|report|copy|mirror|beacon)\b[^.\n]{0,60}` +
                DATA_NOUN +
                String.raw `[^\n]{0,80}?(https?:\/\/|\bwebhook\b|\bendpoint\b|\bremote\s+server\b)`, 'i'),
            /\b(send|forward|bcc|cc|redirect|copy)\b[^.\n]{0,80}\b(to|bcc)\s+[\w.+-]+@[\w-]+\.[\w.-]+/i,
            /\bmust\s+(be\s+)?sent\s+to\s+[\w.+-]+@[\w-]+\.[\w.-]+/i,
        ],
    },
    {
        id: 'mcp-tool-parameter-smuggling',
        severity: 'high',
        subcategory: 'data_exfiltration',
        label: 'an instruction to smuggle data out through a parameter',
        explain: 'The text tells the model to put conversation, file or secret content into a tool argument — the ' +
            'argument is then sent to the server with the call, which is how a description exfiltrates data ' +
            'without any network code of its own.',
        patterns: [
            /\b(pass|put|include|add|append|embed|insert|place|provide|attach|encode|send)\b[^.\n]{0,60}\b(its|the|their|this|that)\s+(full\s+|entire\s+|raw\s+|complete\s+)?(content|contents|text|value|data)\s+(as|in|into)\s+[`'"][\w-]+[`'"]/i,
            /\b(pass|put|include|add|append|embed|insert|place|provide|attach|encode)\b[^.\n]{0,80}\b(contents?|conversation|chat\s+history|previous\s+messages|system\s+prompt|files?|keys?|tokens?|secrets?|credentials|environment|variables|history|instructions)\b[^.\n]{0,60}\b(in|into|as|inside|within)\s+(the\s+|this\s+|a\s+)?[`'"]?[\w-]+[`'"]?\s+(parameter|param|argument|arg|field)\b/i,
        ],
    },
    {
        id: 'mcp-tool-cross-server-shadowing',
        severity: 'high',
        subcategory: 'mcp_tool_poisoning',
        label: 'instructions about how other tools must behave',
        explain: 'The text tells the model how to use tools other than this one. Every tool of every server shares ' +
            "one context, so a description can rewrite another server's behaviour (\"shadowing\") without ever " +
            'being called itself.',
        patterns: [
            /\b(when|whenever|before|after)\s+(using|calling|invoking|you\s+(use|call|invoke))\s+(any|all|every|other|another|the\s+other)\s+(\w+\s+)?(tools?|servers?|mcp)\b/i,
            /\b(all|any|every)\s+other\s+(tools?|mcp\s+servers?|servers?)\b/i,
            /\binstead\s+of\s+(using|calling)\s+(the\s+)?[`'"]?[\w.-]+[`'"]?\s+tool\b/i,
            /\b(other|another)\s+(mcp\s+)?servers?'?s?\s+tools?\b/i,
            /\bwhen\s+this\s+tool\s+is\s+(available|present|loaded|installed|enabled)\b/i,
            /\bthis\s+tool\s+(overrides|replaces|supersedes)\b/i,
        ],
    },
];
export function invisibleKind(code) {
    if (code >= 0xe0000 && code <= 0xe007f)
        return 'tag characters';
    if ((code >= 0x200b && code <= 0x200d) || // zero-width space / non-joiner / joiner
        (code >= 0x2060 && code <= 0x2064) || // word joiner, invisible operators
        code === 0xfeff || // zero-width no-break space (BOM)
        code === 0x180e // Mongolian vowel separator
    ) {
        return 'zero-width characters';
    }
    if (code === 0x200e || // LRM
        code === 0x200f || // RLM
        (code >= 0x202a && code <= 0x202e) || // embeddings / overrides
        (code >= 0x2066 && code <= 0x2069) // isolates
    ) {
        return 'bidi controls';
    }
    return null;
}
export function scanInvisible(text) {
    const kinds = new Set();
    let count = 0;
    let decodedTags = '';
    for (const ch of text) {
        const code = ch.codePointAt(0);
        if (code === undefined)
            continue;
        const kind = invisibleKind(code);
        if (kind === null)
            continue;
        kinds.add(kind);
        count += 1;
        if (kind === 'tag characters' && code >= 0xe0020 && code <= 0xe007e) {
            decodedTags += String.fromCharCode(code - 0xe0000);
        }
    }
    return count === 0 ? null : { kinds: [...kinds], count, decodedTags };
}
/** Replace every invisible code point with a visible `\u{…}` escape, so output never re-carries it. */
export function escapeInvisible(text) {
    let out = '';
    for (const ch of text) {
        const code = ch.codePointAt(0);
        out += code !== undefined && invisibleKind(code) !== null ? `\\u{${code.toString(16).toUpperCase()}}` : ch;
    }
    return out;
}
/**
 * A base64 (or base64url) run long enough to hold a payload. Both cases and
 * a digit are required, so a lowercase hex digest — a common, harmless long
 * token in a description — is not one.
 */
const BASE64_RUN = /[A-Za-z0-9+/_-]{100,}={0,2}/g;
export const BLOB_MIN_LENGTH = 100;
export function findEncodedBlob(text) {
    BASE64_RUN.lastIndex = 0;
    for (const m of text.matchAll(BASE64_RUN)) {
        const run = m[0];
        if (!/[A-Z]/.test(run) || !/[a-z]/.test(run) || !/[0-9]/.test(run))
            continue;
        const decoded = Buffer.from(run.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
        let printable = 0;
        for (const ch of decoded) {
            const code = ch.codePointAt(0) ?? 0;
            if ((code >= 0x20 && code < 0x7f) || code === 0x0a || code === 0x0d || code === 0x09)
                printable += 1;
        }
        const readable = decoded.length > 0 && printable / decoded.length >= 0.9;
        return { length: run.length, decodedText: readable ? decoded : null };
    }
    return null;
}
/**
 * Past this a description is abnormal: Claude Code cuts a tool description
 * at 2048 characters, and this repo's own ceiling is 1500. Length alone is no
 * attack, which is why this is `low` — but a long description is where a
 * payload hides below the part anyone reads.
 */
export const OVERSIZED_DESCRIPTION_CHARS = 2048;
//# sourceMappingURL=rules.js.map