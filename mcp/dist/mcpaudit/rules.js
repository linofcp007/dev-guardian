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
import { isLegitimateInvisible, subdivisionFlagTags } from '../platform/invisibleChars.js';
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
/**
 * `mp-persist-instruction` also matches a bare `~/.claude/` or
 * `.claude/memory` PATH. In a skill that is a write target; in a tool
 * description it is a reference, and it is checked as one — by
 * `mcp-tool-sensitive-file-access` below. Measured: kept here, it reported
 * `audit_agent_config`'s own list of the files it reads as "poisoning".
 */
const isPathOnlyPattern = (p) => p.source.includes(String.raw `\.claude\/`);
const SKILL_TEXT_PATTERNS = SKILL_RULES.filter((r) => SKILL_TEXT_RULE_IDS.has(r.id))
    .flatMap((r) => r.patterns)
    .filter((p) => !isPathOnlyPattern(p));
const CONCEAL_SKILL_PATTERNS = SKILL_RULES.find((r) => r.id === 'pi-conceal-from-user')?.patterns ?? [];
/**
 * An instruction to fetch SOMEONE's secrets: a verb, then a possessive or
 * quantifier, then the secret within two words — "read the user's API keys",
 * "collect all stored credentials". A verb merely NEAR a secret word was
 * measured noisy on dev-guardian's own 58 tools: "copy the configs …, then
 * report a first-pass secrets status", and sudo's own "a terminal is required
 * to read the password".
 */
const READ_VERB = String.raw `(?:read|open|cat|load|include|pass|send|provide|attach|upload|extract|collect|copy|fetch|retrieve|dump|print|forward|grab|gather|get)\s+`;
/**
 * A directive to the MODEL, not a tool describing itself (fix round 3, M7):
 * a verb in its base form where a sentence, a clause or an instruction
 * starts — at the start of the text, after a sentence end, a colon, a comma
 * or an opening parenthesis, or after `you must/should/need to`, `please`,
 * `first`, `then`, `and`, `also`, `always`, `now`. `Reads .mcp.json` (the
 * tool's own action, third person) is not one; `Before answering, read
 * ~/.ssh/id_rsa` is. Measured: the looser rule flagged audit_agent_config and
 * vet_packages for naming the files THEY read.
 */
const DIRECTIVE = String.raw `(?:^|[.!?:;,(]\s*|\b(?:you\s+(?:must|should|need\s+to|have\s+to)|please|first|then|and|also|always|now)\s+)`;
/** Up to 80 characters of the same sentence: a dot inside a path does not end it. */
const SAME_SENTENCE = String.raw `(?:(?![.!?](?:\s|$))[^\n]){0,80}?`;
/**
 * What follows a `.ssh` path when it names a public key or `known_hosts`:
 * neither is a secret (fix round 5, M7), and a key-registration helper
 * legitimately reads one.
 */
const NOT_A_SECRET_AFTER = String.raw `(?![^\s\x60'"]*?(?:\.pub|known_hosts)\b)`;
/** A credential or agent-config file, named as a path (either slash). */
const SENSITIVE_PATH = [
    String.raw `~[\/\\]\.ssh\b${NOT_A_SECRET_AFTER}`,
    String.raw `\.ssh[\/\\]${NOT_A_SECRET_AFTER}`,
    String.raw `\bid_(?:rsa|dsa|ecdsa|ed25519)\b(?!\.pub\b)`,
    String.raw `\bauthorized_keys\b`,
    String.raw `\bmcp\.json\b`,
    String.raw `\bmcp_config\.json\b`,
    String.raw `claude_desktop_config\.json`,
    String.raw `\.claude\.json\b`,
    String.raw `~[\/\\]\.claude[\/\\]`,
    String.raw `\.claude[\/\\]memory\b`,
    String.raw `\.aws[\/\\]credentials`,
    String.raw `\.netrc\b`,
    String.raw `\.npmrc\b`,
    String.raw `\.pypirc\b`,
    String.raw `\.git-credentials\b`,
    String.raw `\.docker[\/\\]config\.json`,
    String.raw `\.kube[\/\\]config\b`,
    String.raw `\/etc\/(?:passwd|shadow)\b`,
    // `.env`, `C:\project\.env`, `./.env.local` — not `.environment`, and not
    // the templates `.env.example`, `.env.sample`, `.env.template` (fix round
    // 5, M7). A lookbehind, so `read .env` matches: the verb's own space is
    // not there to be consumed a second time.
    String.raw `(?<=^|[\s\x60'"(\/\\])\.env(?!\.(?:example|sample|template)\b)(?:\.[\w-]+)?(?![\w-])`,
].join('|');
/** A credential or agent-config path anywhere in a text. */
export const SENSITIVE_PATH_ANYWHERE = new RegExp(`(?:${SENSITIVE_PATH})`, 'i');
/** `pass it`, `include its contents`, `send the key` … then a preposition: the start of a pass-on. */
const PASS_ON = String.raw `\b(?:pass|include|send|attach|add|put|append|embed|forward|upload|post|provide|copy|paste|insert|encode)\s+` +
    String.raw `(?:it|them|this|that|those|its\s+(?:full\s+|entire\s+|raw\s+)?contents?|the\s+(?:full\s+|entire\s+|raw\s+)?(?:contents?|file|key|keys|token|value|values|text|output))\b` +
    String.raw `[^.\n]{0,60}?\b(?:as|in|into|to|via|inside|within)\s+(?:the\s+|a\s+|an\s+|this\s+)?`;
/**
 * A directive to pass something ON to a parameter, another tool or a URL
 * (fix rounds 4 and 5, M7): `pass its content as 'sidenote'`, `put the
 * contents in the notes parameter`, `pass it to the send_email tool`, `send
 * it to https://…`. With a sensitive path in the same sentence this is the
 * shape of tool-poisoning exfiltration, and the finding is high.
 */
export const PASS_TO_DESTINATION = [
    new RegExp(PASS_ON +
        String.raw `(?:[\x60'"][\w.-]+[\x60'"]|[\w-]+\s+(?:param(?:eter)?|arg(?:ument)?|field|tool)\b|param(?:eter)?s?\b|arg(?:ument)?s?\b|(?:other\s+|another\s+)?tool\b|[a-z][a-z0-9+.-]*:\/\/)`, 'i'),
];
/**
 * A pass-on to a bare word, captured: `include it in the response`, `add
 * them to the report`, `include it as sidenote`. Output goes to the user,
 * so this is medium — unless the word is a parameter of the tool itself, in
 * which case it is a {@link PASS_TO_DESTINATION} written without quotes.
 */
export const PASS_TO_WORD = new RegExp(PASS_ON + String.raw `([a-z_][\w-]*)`, 'i');
const OWNER = String.raw `(all\s+|any\s+|every\s+)?(of\s+)?(the\s+)?(user'?s?|your|their|local|stored|saved|cached)\s+(\w+\s+){0,2}`;
const SECRET_NOUN = String.raw `(credentials?|api[\s_-]?keys?|private\s+keys?|ssh\s+keys?|access\s+tokens?|auth(entication)?\s+tokens?|secrets?|passwords?)\b`;
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
        patterns: [
            MCP_DESCRIPTION_POISONING,
            ...SKILL_TEXT_PATTERNS,
            // A "developer mode" persona (fix round 3, I5).
            /\b(enable|enter|activate|switch\s+(?:on|to|into)|turn\s+on|go\s+into|you\s+are\s+(?:now\s+)?in)\s+(?:the\s+)?developer\s+mode\b/i,
            /\bdeveloper\s+mode\s+(?:is\s+)?(?:enabled|activated|on)\b/i,
        ],
    },
    {
        id: 'mcp-tool-sensitive-file-access',
        // Medium: an SSH, cloud or registry helper legitimately tells the model
        // to read such a file. `analyze.ts` raises it to high when the same text
        // also directs passing it elsewhere or hiding it (fix round 4, M7).
        severity: 'medium',
        subcategory: 'data_exfiltration',
        label: 'an instruction to read credential or agent-config files',
        explain: 'The text tells the model to read an SSH key or config, cloud or package-registry credentials, a .env ' +
            'file or an MCP host config. Confirm that is this tool\'s own purpose (an SSH or registry helper may ' +
            'need it); a tool that only names the files it reads itself does not trip this.',
        patterns: [
            new RegExp(`${DIRECTIVE}${READ_VERB}${SAME_SENTENCE}(?:${SENSITIVE_PATH})`, 'i'),
            new RegExp(`${DIRECTIVE}${READ_VERB}${OWNER}${SECRET_NOUN}`, 'i'),
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
            // "Always bcc audit@…", "cc: attacker@…" (fix round 3, I5).
            /\bb?cc\b\s*:?\s*[\w.+-]+@[\w-]+(?:\.[\w-]+)+/i,
            // A URL whose query the model is to fill with data: `?d=<conversation summary>`.
            new RegExp(String.raw `https?:\/\/[^\s"'<>)]+[?&][\w.-]+=\s*(?:<[^>\n]{0,80}?|\{\{?[^}\n]{0,80}?|\[[^\]\n]{0,80}?)` +
                String.raw `\b(conversation|chat|history|summary|messages?|context|prompts?|secrets?|tokens?|keys?|passwords?|credentials?|env|contents?|data|files?|previous)\b`, 'i'),
            // A markdown image with a query: rendering it sends the query to that host.
            /!\[[^\]\n]*\]\(\s*<?https?:\/\/[^)\s>]+\?[^)\s]+\)/i,
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
/**
 * Code points that render as nothing, or reorder what does: Unicode's own
 * `Default_Ignorable_Code_Point` and `Bidi_Control` classes, plus the
 * interlinear annotation controls U+FFF9–FFFB (format characters that are in
 * neither). Fix round 3, I4: the first cut listed ranges by hand and missed
 * variation selectors (U+FE00–FE0F, U+E0100–E01EF — a whole smuggling
 * alphabet), U+061C, U+00AD, U+034F, the Hangul fillers, U+180B–180F,
 * U+206A–206F, U+FFF9–FFFB and U+1D173–1D17A.
 */
const INVISIBLE = /[\p{Default_Ignorable_Code_Point}\p{Bidi_Control}\u{FFF9}-\u{FFFB}]/u;
export function invisibleKind(code) {
    const ch = String.fromCodePoint(code);
    if (!INVISIBLE.test(ch))
        return null;
    if (code >= 0xe0000 && code <= 0xe007f)
        return 'tag characters';
    if ((code >= 0xfe00 && code <= 0xfe0f) || (code >= 0xe0100 && code <= 0xe01ef))
        return 'variation selectors';
    if (/\p{Bidi_Control}/u.test(ch))
        return 'bidi controls';
    return 'zero-width and other invisible characters';
}
function readable(text) {
    if (text.length === 0)
        return false;
    let printable = 0;
    for (const ch of text) {
        const c = ch.codePointAt(0) ?? 0;
        if (c >= 0x20 && c !== 0x7f && c !== 0xfffd)
            printable += 1;
    }
    return printable / [...text].length >= 0.9;
}
export function scanInvisible(text) {
    const points = [...text].map((ch) => ch.codePointAt(0) ?? 0);
    const flagTags = subdivisionFlagTags(points);
    const kinds = new Set();
    let count = 0;
    let decodedTags = '';
    const selectorBytes = [];
    let index = -1;
    let offset = 0;
    for (let i = 0; i < points.length; i += 1) {
        const code = points[i] ?? 0;
        const kind = invisibleKind(code);
        if (kind !== null && !flagTags.has(i) && !isLegitimateInvisible(code, points[i - 1], points[i + 1])) {
            kinds.add(kind);
            count += 1;
            if (index < 0)
                index = offset;
            if (kind === 'tag characters' && code >= 0xe0020 && code <= 0xe007e)
                decodedTags += String.fromCharCode(code - 0xe0000);
            if (code >= 0xfe00 && code <= 0xfe0f)
                selectorBytes.push(code - 0xfe00);
            else if (code >= 0xe0100 && code <= 0xe01ef)
                selectorBytes.push(code - 0xe0100 + 16);
        }
        offset += code > 0xffff ? 2 : 1;
    }
    if (count === 0)
        return null;
    const selectors = selectorBytes.length >= 4 ? Buffer.from(selectorBytes).toString('utf8') : '';
    return { kinds: [...kinds], count, decodedTags, decodedSelectors: readable(selectors) ? selectors : '', index };
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
 * Letters of other scripts that read as Latin ones: Cyrillic and Greek
 * capitals and small letters with a Latin twin. `Іgnоrе` (three of them)
 * reads as "Ignore" and matches no ASCII pattern.
 */
const CONFUSABLES = {
    // Cyrillic
    а: 'a', А: 'A', В: 'B', е: 'e', Е: 'E', ё: 'e', Ё: 'E', К: 'K', к: 'k', М: 'M', Н: 'H', о: 'o', О: 'O',
    р: 'p', Р: 'P', с: 'c', С: 'C', Т: 'T', у: 'y', У: 'Y', х: 'x', Х: 'X', і: 'i', І: 'I', ї: 'i', Ї: 'I',
    ј: 'j', Ј: 'J', ѕ: 's', Ѕ: 'S', ԁ: 'd', ԛ: 'q', ԝ: 'w', Ԝ: 'W', һ: 'h', Һ: 'H', ү: 'y', Ү: 'Y', ɡ: 'g',
    // Greek
    Α: 'A', Β: 'B', Ε: 'E', Ζ: 'Z', Η: 'H', Ι: 'I', Κ: 'K', Μ: 'M', Ν: 'N', Ο: 'O', Ρ: 'P', Τ: 'T', Υ: 'Y',
    Χ: 'X', ο: 'o', ν: 'v', ρ: 'p', ι: 'i', κ: 'k', υ: 'u', χ: 'x', α: 'a',
};
/**
 * What the text reads as: NFKC (full-width `Ｉｇｎｏｒｅ` → `Ignore`, and the
 * other compatibility forms) with look-alike letters folded to Latin. The
 * text rules run on this too (fix round 3, I4).
 */
export function readAs(text) {
    let out = '';
    for (const ch of text.normalize('NFKC'))
        out += CONFUSABLES[ch] ?? ch;
    return out;
}
/**
 * The first word of four letters or more that mixes Latin letters with
 * Cyrillic or Greek look-alikes (`pаypal`, `Іgnоrе`), or null. A word wholly
 * in one script is ordinary text in that language; a unit like `μs` is too
 * short, and a Greek letter with no Latin twin (μ, λ) is not a look-alike.
 */
export function mixedScriptWord(text) {
    for (const m of text.matchAll(/[\p{L}\p{M}]{4,}/gu)) {
        const word = m[0];
        let latin = false;
        let lookAlike = false;
        let otherForeign = false;
        for (const ch of word) {
            if (/\p{Script=Latin}/u.test(ch))
                latin = true;
            else if (/[\p{Script=Cyrillic}\p{Script=Greek}]/u.test(ch)) {
                if (CONFUSABLES[ch] !== undefined)
                    lookAlike = true;
                else
                    otherForeign = true;
            }
        }
        if (latin && lookAlike && !otherForeign)
            return { word, index: m.index };
    }
    return null;
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