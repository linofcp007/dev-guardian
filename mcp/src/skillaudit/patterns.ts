/**
 * AI-agent threat pattern rule packs.
 *
 * Each rule maps to one `ThreatCategory` and is matched line-by-line against
 * a file's content. A rule declares a `target`:
 *   - 'text' → only run against instruction/doc artifacts (SKILL.md, README,
 *     *.md, *.txt, plain MCP manifest prose), over the whole file. These are
 *     where prompt-level attacks live.
 *   - 'code' → run against executable/source artifacts (*.sh, *.py, *.js,
 *     *.ts, *.ps1, …), AND against the code inside an instruction file: its
 *     fenced blocks and inline code spans (`markdownCode.ts`). For a
 *     third-party skill the instructions are what the model runs, so a
 *     ```bash``` block in SKILL.md is as executable as `scripts/setup.sh`.
 *   - 'prose' → only the prose of an instruction file, with its code blanked
 *     out: the same command written as a sentence ("run curl … | bash").
 *     Each prose rule is the variant of a code rule with the same id plus
 *     `-prose`, so a command is scored once, by the shape it is written in.
 *   - 'any'  → both kinds of file, whole content.
 *
 * The code in an instruction file is as often a MENTION as an instruction:
 * `rm -rf /` in the list of what a hook blocks, `pattern: \.env$` in a doc
 * about writing detection rules, `exec(` in a bug catalogue. Measured twice:
 *   - this repo's own docs, which document every attack here: 82 code-rule
 *     hits in inline spans and fenced blocks, every one a mention — a bare
 *     name (`eval()`, `.env`), a placeholder (`curl … | sh`) or a quoted
 *     example. None named a URL;
 *   - 75 legitimate third-party skills installed on the development machine
 *     (Anthropic's official plugins among them): at full severity, a skill
 *     that teaches how to write hook rules scored +100 from fenced YAML
 *     patterns and one about writing hooks +125, both DO_NOT_INSTALL. The one
 *     hit that was an instruction to run a remote script — Homebrew's
 *     `/bin/bash -c "$(curl -fsSL https://…)"` — named a URL.
 * So an inline span is scanned only when it is a whole command (it has an
 * argument, and no `…` / `...` placeholder), and a code hit in an instruction
 * file scores a level below its rule unless its span, or its fenced block,
 * names a remote destination (a URL or an IP address) — the one thing a
 * mention of an attack leaves out and an instruction to carry it out cannot.
 * A skill's own scripts are scored as before, at full severity.
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

import type { Severity } from '../types.js';
import { splitMarkdown } from './markdownCode.js';
import type { ThreatCategory } from './taxonomy.js';
import { THREAT_CATEGORY_META } from './taxonomy.js';

export type RuleTarget = 'text' | 'code' | 'prose' | 'any';

/**
 * A credential file, named as a path. `.env` only as a FILE: `process.env` is
 * a property, and matching it read every Node script that reads a setting as
 * "reads sensitive local credential files". A public key (`*.pub`) is not a
 * credential — sending one to a server is how you register it.
 */
const SENSITIVE_FILE =
  String.raw`(id_rsa(?!\.pub)|id_ed25519(?!\.pub)|id_ecdsa(?!\.pub)|\.ssh\/(?![\w.-]*\.pub\b)|\.aws\/credentials|\.netrc|\.npmrc|\.git-credentials|\.kube\/config|\.docker\/config\.json|cookies\.sqlite|Login\s+Data|(?<![\w$)\]])\.env\b)`;

/** A program or API call that sends bytes off the machine. */
const NETWORK_SENDER =
  String.raw`\b(curl|wget|nc|ncat|netcat|scp|sftp|Invoke-WebRequest|Invoke-RestMethod|iwr|irm|requests\.(post|put)|httpx\.(post|put)|fetch|axios)\b`;

/** The same act, in words. */
const SEND_VERB = String.raw`\b(send|sends|sent|upload|uploads|post|posts|transmit|forward|submit|paste|exfiltrate)\b`;

/** A concrete remote endpoint: what an instruction to exfiltrate has and a description of one does not. */
const REMOTE_DESTINATION = String.raw`(\b(https?|s?ftp):\/\/[^\s'"<>)]+|\b\d{1,3}(\.\d{1,3}){3}\b)`;

const REMOTE_DESTINATION_RE = new RegExp(REMOTE_DESTINATION, 'i');

/** What precedes a secret that AUTHENTICATES a request rather than being its payload. */
const AUTH_HEADER = String.raw`(authorization:\s*(bearer|basic|token)?\s*|--oauth2-bearer\s+|private-token:\s*|x-api-key:\s*|(-u|--user)\s+["']?[^\s:"']*:)`;

export interface SkillRule {
  id: string;
  category: ThreatCategory;
  /** Overrides the category default when present. */
  severity?: Severity;
  title: string;
  message: string;
  target: RuleTarget;
  patterns: RegExp[];
  fix?: string;
}

/**
 * Where in the file a match was found: `line` is a whole line of a code file
 * or a `text`/`any` rule over the whole of an instruction file; the other
 * three are the views `markdownCode.ts` splits an instruction file into.
 */
export type MatchSource = 'line' | 'fenced' | 'inline' | 'prose';

export interface RuleMatch {
  rule: SkillRule;
  line: number;
  snippet: string;
  source: MatchSource;
  /**
   * The rule's severity, or one level lower for code in an instruction file
   * that names no remote destination (see the header).
   */
  severity: Severity;
}

export const SKILL_RULES: SkillRule[] = [
  // ───────────────────────────── prompt_injection ─────────────────────────
  {
    id: 'pi-override-instructions',
    category: 'prompt_injection',
    severity: 'high',
    title: 'Instruction-override phrasing',
    message:
      'Text instructs the model to ignore/override prior or system instructions — classic prompt injection.',
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
    message:
      'Text tries to redefine the assistant or bypass its safety guidelines (jailbreak pattern).',
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
    message:
      'Text instructs the model to act without informing or asking the user — covert behaviour.',
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
    message:
      'Text tries to write attacker-controlled content into persistent memory, rules files or CLAUDE.md so it survives the session.',
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
    message:
      'Behaviour gated on a date, environment or "nobody watching" condition — hallmark of a logic bomb.',
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
    message:
      'The skill demands activation on essentially every request — designed to intercept unrelated work.',
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
    message:
      'Code reads environment variables or credentials and ships them to a network destination.',
    target: 'code',
    patterns: [
      /(fetch|axios|requests?\.(post|get|put)|http[s]?\.request|urllib|httpx)[^\n]{0,120}(process\.env|os\.environ|getenv|ENV\[)/i,
      /(process\.env|os\.environ|getenv)[^\n]{0,120}(fetch|axios|requests?\.|\.post\(|upload|send\()/i,
      // Not when the secret authenticates the request — that is the next
      // rule. Measured: an official plugin's `curl -H "Authorization: Bearer
      // $API_TOKEN" https://api.example.com/mcp/health`, a health check in a
      // reference doc, read critical and took its skill to DO_NOT_INSTALL.
      new RegExp(`\\b(curl|wget)\\b[^\\n]{0,200}(?<!${AUTH_HEADER}["']?)(\\$\\{?[A-Z_]*(TOKEN|KEY|SECRET|PASSWORD|CREDENTIAL))`, 'i'),
    ],
  },
  {
    id: 'de-secret-in-auth-header',
    category: 'data_exfiltration',
    severity: 'medium',
    title: 'Secret from the environment sent as request authentication',
    message:
      'A request authenticates with a token, key or password from the environment. That is how an API is called — ' +
      'and also how a stolen token reaches a server that is not its own. Confirm the endpoint is the service the ' +
      'secret belongs to.',
    target: 'code',
    patterns: [
      new RegExp(
        `\\b(curl|wget|Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\\b[^\\n]{0,200}${AUTH_HEADER}["']?\\$\\{?[A-Z_]*(TOKEN|KEY|SECRET|PASSWORD|CREDENTIAL)`,
        'i',
      ),
    ],
  },
  {
    id: 'de-read-sensitive-files',
    category: 'data_exfiltration',
    severity: 'high',
    title: 'Reads sensitive local credential files',
    message:
      'Code references SSH keys, cloud credentials, browser data or .env — sensitive material a skill rarely needs.',
    target: 'code',
    patterns: [new RegExp(SENSITIVE_FILE, 'i')],
  },
  {
    id: 'de-sensitive-file-over-network',
    category: 'data_exfiltration',
    severity: 'critical',
    title: 'Credential file sent over the network',
    message:
      'One command both names a credential file (SSH key, cloud credentials, .netrc/.npmrc, browser data, .env) ' +
      'and a network client — the shape of `cat ~/.ssh/id_rsa | curl --data-binary @- https://…`.',
    target: 'code',
    patterns: [new RegExp(`^(?=.*${SENSITIVE_FILE})(?=.*${NETWORK_SENDER})`, 'i')],
  },
  {
    id: 'de-sensitive-file-over-network-prose',
    category: 'data_exfiltration',
    severity: 'high',
    title: 'Instruction to send a credential file to a remote endpoint',
    message:
      'The prose of an instruction file names a credential file, a way to send it and a concrete destination ' +
      '(a URL or an IP address) in one sentence. A description of the attack names no endpoint; ' +
      'an instruction to carry it out has to.',
    target: 'prose',
    patterns: [
      new RegExp(`^(?=.*${SENSITIVE_FILE})(?=.*(${NETWORK_SENDER}|${SEND_VERB}))(?=.*${REMOTE_DESTINATION})`, 'i'),
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
      /\b(curl|wget)\b[^\n|]{0,200}\|\s*(sudo\s+(-\S+\s+)*)?(bash|sh|zsh|dash|ksh|python[23]?|node)\b/i,
      /\beval\s+"\$\(\s*(curl|wget)\b/i,
      /\b(iwr|irm|invoke-webrequest|invoke-restmethod)\b[^\n|]{0,200}\|\s*(iex|invoke-expression)/i,
      // `bash <(curl …)`, `sh -c "$(curl …)"` — the other two ways install
      // one-liners are written, and the hook's block list names both.
      /\b(bash|sh|zsh|dash|ksh|source)\s+(-\w+\s+)*<\(\s*(curl|wget)\b/i,
      /\b(bash|sh|zsh|dash|ksh)\s+-c\s+["']?\$\(\s*(curl|wget)\b/i,
      /\b(iex|invoke-expression)\b\s*\(?\s*\(?\s*(iwr|irm|invoke-webrequest|invoke-restmethod|new-object\s+(system\.)?net\.webclient)\b/i,
    ],
  },
  {
    id: 'sc-curl-pipe-shell-prose',
    category: 'supply_chain',
    severity: 'high',
    title: 'Instruction to pipe a remote script to a shell',
    message:
      'The prose of an instruction file tells the reader to download a script from a concrete URL and run it ' +
      'unverified. The documentation shape (`curl … | sh`, "curl|bash") names no URL and is not reported.',
    target: 'prose',
    patterns: [
      /\b(curl|wget)\b[^|]{0,200}?\b(https?|ftp):\/\/[^|]{0,300}\|\s*(sudo\s+(-\S+\s+)*)?(bash|sh|zsh|dash|ksh|python[23]?|node|perl|ruby)\b/i,
      /\b(bash|sh|zsh|dash|ksh|source)\s+(-\w+\s+)*<\(\s*(curl|wget)\b[^)]{0,300}\b(https?|ftp):\/\//i,
      /\b(bash|sh|zsh|dash|ksh)\s+-c\s+["']?\$\(\s*(curl|wget)\b[^)]{0,300}\b(https?|ftp):\/\//i,
      /\beval\s+["']?\$\(\s*(curl|wget)\b[^)]{0,300}\b(https?|ftp):\/\//i,
      /\b(iwr|irm|invoke-webrequest|invoke-restmethod)\b[^|]{0,200}?\bhttps?:\/\/[^|]{0,300}\|\s*(iex|invoke-expression)\b/i,
      /\b(iex|invoke-expression)\b\s*\(?\s*\(?\s*(iwr|irm|invoke-webrequest|invoke-restmethod|new-object\s+(system\.)?net\.webclient)\b.{0,300}\bhttps?:\/\//i,
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
    message:
      'A skill that presents as read-only/formatting still reaches for shell or process-spawn primitives.',
    target: 'code',
    // Not after `::`: `thread::spawn(` / `tokio::spawn(` start a thread or a
    // task, not a process.
    patterns: [/(?<!::)(spawn|spawnSync|popen|system)\s*\(/i],
  },

  // ──────────────────────────── mcp_tool_poisoning ────────────────────────
  {
    id: 'mtp-instructions-in-description',
    category: 'mcp_tool_poisoning',
    severity: 'high',
    title: 'Hidden instructions inside a tool/MCP description',
    message:
      'An MCP tool name/description embeds directives that manipulate the model when the tool list is read.',
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
export function scanContent(content: string, isCode: boolean): RuleMatch[] {
  const lines = content.split(/\r?\n/);
  const whole: Unit[] = lines.map((text, i) => ({ line: i + 1, text, source: 'line', namesRemote: true }));
  if (isCode) {
    return dedupeByRuleLine(matchUnits(rulesFor('code', 'any'), whole));
  }
  const views = splitMarkdown(content);
  const remoteBlocks = new Set<number>();
  for (const u of views.code) {
    if (u.block !== null && REMOTE_DESTINATION_RE.test(u.text)) remoteBlocks.add(u.block);
  }
  const prose: Unit[] = views.prose.map((text, i) => ({ line: i + 1, text, source: 'prose', namesRemote: true }));
  const code: Unit[] = views.code
    .filter((u) => u.kind === 'fenced' || isWholeCommand(u.text))
    .map((u) => ({
      line: u.line,
      text: u.text,
      source: u.kind,
      namesRemote: u.block === null ? REMOTE_DESTINATION_RE.test(u.text) : remoteBlocks.has(u.block),
    }));
  return dedupeByRuleLine([
    ...matchUnits(rulesFor('text', 'any'), whole),
    ...matchUnits(rulesFor('prose'), prose),
    ...matchUnits(rulesFor('code'), code),
  ]);
}

interface Unit {
  line: number;
  text: string;
  source: MatchSource;
  /** For code in an instruction file: its span, or its fenced block, names a URL or an IP address. */
  namesRemote: boolean;
}

function rulesFor(...targets: RuleTarget[]): SkillRule[] {
  return SKILL_RULES.filter((r) => targets.includes(r.target));
}

const SEVERITY_RANK: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

/**
 * One hit per (rule, pattern) is enough signal — but it is the most severe
 * one, not the first: a mention early in a file (scored a level lower) must
 * not hide the real command further down that names its endpoint.
 */
function matchUnits(rules: SkillRule[], units: Unit[]): RuleMatch[] {
  const matches: RuleMatch[] = [];
  for (const rule of rules) {
    const full = severityOfRule(rule);
    for (const pattern of rule.patterns) {
      let best: RuleMatch | null = null;
      for (const unit of units) {
        pattern.lastIndex = 0;
        if (!pattern.test(unit.text)) continue;
        const severity = severityFor(rule, unit);
        if (best === null || SEVERITY_RANK[severity] > SEVERITY_RANK[best.severity]) {
          best = { rule, line: unit.line, snippet: unit.text.trim().slice(0, 240), source: unit.source, severity };
        }
        if (severity === full) break; // nothing later can outrank it
      }
      if (best) matches.push(best);
    }
  }
  return matches;
}

/**
 * An inline span worth reading as code: it has an argument (`rm -rf /`, not
 * `eval()` or `.env`) — or names a remote destination, so that
 * `curl${IFS}https://…|bash`, written without a space to look like a bare
 * name, is still read — and no placeholder (`curl … | sh` cannot be run as
 * written). See the header for the measurement behind both.
 */
function isWholeCommand(span: string): boolean {
  const t = span.trim();
  return (/\s/.test(t) || REMOTE_DESTINATION_RE.test(t)) && !/…|\.\.\./.test(t);
}

const ONE_LEVEL_LOWER: Record<Severity, Severity> = {
  critical: 'high',
  high: 'medium',
  medium: 'low',
  low: 'info',
  info: 'info',
};

function severityFor(rule: SkillRule, unit: Unit): Severity {
  const base = severityOfRule(rule);
  return unit.namesRemote ? base : ONE_LEVEL_LOWER[base];
}

/** Collapse multiple patterns of the same rule hitting the same line. */
function dedupeByRuleLine(matches: RuleMatch[]): RuleMatch[] {
  const seen = new Set<string>();
  const out: RuleMatch[] = [];
  for (const m of matches) {
    const key = `${m.rule.id}:${m.line}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(m);
  }
  return out;
}

export function severityOfRule(rule: SkillRule): Severity {
  return rule.severity ?? THREAT_CATEGORY_META[rule.category].defaultSeverity;
}
