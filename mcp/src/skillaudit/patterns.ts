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
 *     fenced, indented and `<pre>` / `<code>` blocks and its inline code
 *     (`markdownCode.ts`). For a third-party skill the instructions are what
 *     the model runs, so a ```bash``` block in SKILL.md is as executable as
 *     `scripts/setup.sh`. In either kind of file, lines continued with `\`
 *     or a trailing `|` are also read as one.
 *   - 'prose' → every line of an instruction file as it reads, inline code
 *     included (its backticks dropped): the same command written as a
 *     sentence ("run curl … | bash", "send `~/.ssh/id_rsa` to https://…").
 *     Each prose rule is the variant of a code rule with the same id plus
 *     `-prose`; where both fire on one line, one finding is kept.
 *   - 'any'  → both kinds of file, whole content.
 *   `sc-download-then-run` is read over the whole file rather than a line:
 *   a file downloaded, then run further down.
 *
 * The code in an instruction file is as often a MENTION as an instruction:
 * `rm -rf /` in the list of what a hook blocks, `pattern: \.env$` in a doc
 * about writing detection rules, `exec(` in a bug catalogue. Rounds 1 and 2
 * scored code with no fetch target one level lower, measured against this
 * repo's docs and 75 third-party skills. Round 3 of the 3.0 review showed
 * that rewards obfuscation — `echo <b64> | base64 -d | xargs curl -fsSL |
 * bash` has no target ON PURPOSE — and ruled: a finding is scored a level
 * lower ONLY when a placeholder stands where its target would be (`…`, a
 * standalone `...`, `<url>`, `<script>`, `<path>` in an argument's position,
 * or the documentation hosts `example.com` / `.org` / `.net` themselves), and
 * never when the span or its block has a real target — a URL or an IP, or a
 * network client given a variable or substitution (`$URL`, `${X}`, `$1`,
 * `$(…)`, `%VAR%`, `$env:X`) or a scheme-less host — whatever `# ...` it
 * also carries. An absent target is full severity. The measured cost, on the
 * same 75 skills: seven verdicts rise, among them the hookify `writing-rules`
 * skill (fenced detection patterns, 40 → 100) — see CHANGELOG.md. An inline
 * span is read at all only when it is a whole command (an argument or a real
 * target) and not a placeholder. A skill's own scripts are scored at full
 * severity, as always.
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
import { continues, joinContinued, splitMarkdown } from './markdownCode.js';
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

/**
 * A variable or substitution — what a command names its target with when the
 * value is set somewhere else: `$URL`, `${X}`, `$1`, `$(…)`, a backtick
 * substitution, cmd's `%VAR%`, PowerShell's `$env:X`.
 */
const SHELL_VALUE = String.raw`(\$env:[A-Za-z_]\w*|\$\{?[A-Za-z_]\w*\}?|\$\d|\$\(|` + '`[^`\\n]+`' + String.raw`|%[A-Za-z_]\w*%)`;

/** A host named without a scheme: `get.example.com`, `statsd.local:8125/x`. */
const BARE_HOST = String.raw`(?<![\w@/.$%-])(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}(?::\d+)?(?:\/[^\s'"|;&)]*)?(?![\w.-])`;

/** Shell programs that fetch from, or send to, the target they are given. */
const SHELL_NET_CLIENT = String.raw`\b(curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod|nc|ncat|netcat|scp|sftp|ftp|DownloadString|DownloadFile)\b`;

/**
 * A network command with something to reach: a shell client followed, within
 * the same simple command, by a variable, a substitution or a scheme-less
 * host. With the URL / IP check this is what "has a fetch target" means — see
 * the header: the one-level downgrade is for code that has none.
 */
const NET_COMMAND_WITH_TARGET_RE = new RegExp(
  `${SHELL_NET_CLIENT}[^|;&\\n]*?(${SHELL_VALUE}|${BARE_HOST})`,
  'i',
);

function hasFetchTarget(text: string): boolean {
  return REMOTE_DESTINATION_RE.test(text) || NET_COMMAND_WITH_TARGET_RE.test(text);
}

/** Programs that run the program text they are handed. */
const INTERPRETER = String.raw`(bash|sh|zsh|dash|ksh|python[23]?(?:\.\d+)?|node|perl|ruby|php|pwsh|powershell(?:\.exe)?)`;

/** What a prose command fetches from: a URL, a host with no scheme, or a variable. */
const PROSE_TARGET = String.raw`(\b(https?|ftp):\/\/|${SHELL_VALUE}|${BARE_HOST})`;

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
export type MatchSource = 'line' | 'fenced' | 'indented' | 'pre' | 'inline' | 'prose';

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
      new RegExp(String.raw`\b(curl|wget)\b[^\n|]{0,200}\|\s*(sudo\s+(-\S+\s+)*)?${INTERPRETER}\b`, 'i'),
      /\beval\s+"\$\(\s*(curl|wget)\b/i,
      /\b(iwr|irm|invoke-webrequest|invoke-restmethod)\b[^\n|]{0,200}\|\s*(iex|invoke-expression)/i,
      // `bash <(curl …)`, `sh -c "$(curl …)"`, and the same with any
      // interpreter (`python3 -c "$(curl …)"`, `node -e`, `perl -e`, `php -r`,
      // `pwsh -Command`): an interpreter reading a program it just downloaded.
      new RegExp(String.raw`\b(${INTERPRETER}|source)\s+(-\w+\s+)*<\(\s*(curl|wget)\b`, 'i'),
      new RegExp(String.raw`\b${INTERPRETER}\s+(-\S+\s+)*-(c|e|r|Command|EncodedCommand)\s+["']?\$\(\s*(curl|wget)\b`, 'i'),
      /\b(iex|invoke-expression)\b\s*\(?\s*\(?\s*(iwr|irm|invoke-webrequest|invoke-restmethod|new-object\s+(system\.)?net\.webclient)\b/i,
    ],
  },
  {
    id: 'sc-curl-pipe-shell-prose',
    category: 'supply_chain',
    severity: 'high',
    title: 'Instruction to pipe a remote script to a shell',
    message:
      'The prose of an instruction file tells the reader to download a script from a concrete target — a URL, a ' +
      'host, or a variable set elsewhere — and run it unverified. The documentation shape (`curl … | sh`, ' +
      '"curl|bash") names no target and is not reported.',
    target: 'prose',
    patterns: [
      // A URL, a host with no scheme (`curl -fsSL get.example.io | sh`, the
      // get.docker.com shape), or a variable (`URL=https://…`, then
      // `curl -s $URL | bash`) as the target.
      new RegExp(
        String.raw`\b(curl|wget)\b[^|\n]{0,200}?${PROSE_TARGET}[^|\n]{0,300}\|\s*(sudo\s+(-\S+\s+)*)?${INTERPRETER}\b`,
        'i',
      ),
      new RegExp(String.raw`\b(${INTERPRETER}|source)\s+(-\w+\s+)*<\(\s*(curl|wget)\b[^)\n]{0,300}?${PROSE_TARGET}`, 'i'),
      new RegExp(
        String.raw`\b${INTERPRETER}\s+(-\S+\s+)*-(c|e|r|Command|EncodedCommand)\s+["']?\$\(\s*(curl|wget)\b[^)\n]{0,300}?${PROSE_TARGET}`,
        'i',
      ),
      new RegExp(String.raw`\beval\s+["']?\$\(\s*(curl|wget)\b[^)\n]{0,300}?${PROSE_TARGET}`, 'i'),
      new RegExp(
        String.raw`\b(iwr|irm|invoke-webrequest|invoke-restmethod)\b[^|\n]{0,200}?${PROSE_TARGET}[^|\n]{0,300}\|\s*(iex|invoke-expression)\b`,
        'i',
      ),
      /\b(iex|invoke-expression)\b\s*\(?\s*\(?\s*(iwr|irm|invoke-webrequest|invoke-restmethod|new-object\s+(system\.)?net\.webclient)\b.{0,300}\bhttps?:\/\//i,
    ],
  },
  {
    id: 'sc-download-then-run',
    category: 'supply_chain',
    severity: 'high',
    title: 'Remote file downloaded, then run',
    message:
      'A file is downloaded (curl -o / -O, wget, iwr -OutFile) and later run from a shell or an interpreter, ' +
      'on the same line or further down the same file — curl|bash in two steps.',
    target: 'code',
    // Read by `downloadThenRun` over the whole file, not line by line.
    patterns: [],
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
export interface ScanOptions {
  /**
   * The file is Markdown or plain text (`.md`, `.txt`, no extension): its
   * indented lines can be a code block. Default true; false for other text
   * files — HTML, JSON, YAML — where indentation is layout.
   */
  markdown?: boolean;
}

export function scanContent(content: string, isCode: boolean, opts: ScanOptions = {}): RuleMatch[] {
  const lines = content.split(/\r?\n/);
  if (isCode) {
    const units = codeFileUnits(lines);
    return finalize([...matchUnits(rulesFor('code', 'any'), units), ...downloadThenRun(units, false)]);
  }
  const whole: Unit[] = lines.map((text, i) => ({ line: i + 1, text, source: 'line', lowered: false }));
  const views = splitMarkdown(content, { indentedCode: opts.markdown !== false });
  const targetBlocks = new Set<number>();
  for (const u of views.code) {
    if (u.block !== null && hasRealTarget(u.text)) targetBlocks.add(u.block);
  }
  // Documentation hosts read as the placeholder they are, in prose too.
  const prose: Unit[] = views.prose.map((text, i) => ({
    line: i + 1,
    text: withoutDocHosts(text),
    display: text,
    source: 'prose',
    lowered: false,
  }));
  const code: Unit[] = views.code
    .filter((u) => u.kind !== 'inline' || isWholeCommand(u.text))
    .map((u) => ({
      line: u.line,
      text: u.text,
      source: u.kind,
      lowered: isPlaceholder(u.text) && !(u.block !== null && targetBlocks.has(u.block)),
    }));
  return finalize([
    ...matchUnits(rulesFor('text', 'any'), whole),
    ...matchUnits(rulesFor('prose'), prose),
    ...matchUnits(rulesFor('code'), code),
    ...downloadThenRun([...code, ...prose].sort((a, b) => a.line - b.line), true),
  ]);
}

interface Unit {
  line: number;
  /** What the rules match. */
  text: string;
  /** What the finding shows, when it differs from `text`. */
  display?: string;
  source: MatchSource;
  /** Scored one level below its rule: a placeholder stands where the target would be. */
  lowered: boolean;
}

/**
 * A code file's lines, plus each run of continued lines (`\` or a trailing
 * single `|`, as a shell reads them) as one more unit at its first line:
 * `curl -fsSL https://… |` + `bash` is one pipeline.
 */
function codeFileUnits(lines: string[]): Unit[] {
  const units: Unit[] = [];
  let pending: Unit | null = null;
  lines.forEach((text, i) => {
    const unit: Unit = { line: i + 1, text, source: 'line', lowered: false };
    units.push(unit);
    const more = continues(text);
    if (pending) {
      const joined: Unit = { ...pending, text: joinContinued(pending.text, text) };
      if (more) {
        pending = joined;
      } else {
        units.push(joined);
        pending = null;
      }
    } else if (more) {
      pending = unit;
    }
  });
  if (pending) units.push(pending);
  return units;
}

function rulesFor(...targets: RuleTarget[]): SkillRule[] {
  return SKILL_RULES.filter((r) => targets.includes(r.target));
}

const SEVERITY_RANK: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

/**
 * One hit per (rule, pattern) is enough signal — but it is the most severe
 * one, not the first: a mention early in a file (scored a level lower) must
 * not hide the real command further down.
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
        const severity = unit.lowered ? ONE_LEVEL_LOWER[full] : full;
        if (best === null || SEVERITY_RANK[severity] > SEVERITY_RANK[best.severity]) {
          best = { rule, line: unit.line, snippet: snippetOf(unit), source: unit.source, severity };
        }
        if (severity === full) break; // nothing later can outrank it
      }
      if (best) matches.push(best);
    }
  }
  return matches;
}

function snippetOf(unit: Unit): string {
  return (unit.display ?? unit.text).trim().slice(0, 240);
}

// ───────────────────────── placeholders and targets ─────────────────────────

/**
 * What documentation writes where the target would be: an ellipsis, `...` as
 * a token of its own (not a spread, `...args`), an angle-bracket name in an
 * argument's position (`<url>`, `"<URL>"`, `<script>`, `<path>` — not an HTML
 * tag followed by its content).
 */
const PLACEHOLDER_TOKEN_RE =
  /…|(?<![\w.])\.\.\.(?![\w.])|(?<=^|[\s=:'"(\[])<[A-Za-z][\w-]*>(?=$|[\s|;&)'"\/\]])/;

/**
 * The documentation hosts themselves — `example.com` / `.org` / `.net`, with
 * or without `www.` — not their subdomains: `evil.example.com` is a host a
 * reader could be sent to, and the review's own reproductions use it.
 */
const DOC_HOST_RE =
  /(?:\b(?:https?|s?ftp):\/\/)?(?<![\w.@-])(?:www\.)?example\.(?:com|org|net)(?![\w.-])(?:[:/][^\s'"<>|;&)]*)?/gi;

function withoutDocHosts(text: string): string {
  return text.replace(DOC_HOST_RE, '<url>');
}

/** A fetch target that is not a documentation host (`hasFetchTarget`). */
function hasRealTarget(text: string): boolean {
  return hasFetchTarget(withoutDocHosts(text));
}

/**
 * Round 3 (N4): code in an instruction file is scored a level lower ONLY when
 * a placeholder stands where its target would be. An absent target is not a
 * placeholder — `echo <b64> | base64 -d | xargs curl -fsSL | bash` names no
 * target on purpose — and (N2) code with a real target is never a
 * placeholder, whatever `…` or `# ...` it also carries.
 */
function isPlaceholder(text: string): boolean {
  if (hasRealTarget(text)) return false;
  DOC_HOST_RE.lastIndex = 0;
  const docHost = DOC_HOST_RE.test(text);
  DOC_HOST_RE.lastIndex = 0;
  return PLACEHOLDER_TOKEN_RE.test(text) || docHost;
}

/**
 * An inline span worth reading as code: it has an argument (`rm -rf /`, not
 * `eval()` or `.env`) or a real target (`curl${IFS}https://…|bash`, written
 * without a space to look like a bare name), and it is not a placeholder
 * (`curl … | sh` cannot be run as written; `curl https://… | bash # ...` can).
 */
function isWholeCommand(span: string): boolean {
  const t = span.trim();
  return (/\s/.test(t) || hasRealTarget(t)) && !isPlaceholder(t);
}

const ONE_LEVEL_LOWER: Record<Severity, Severity> = {
  critical: 'high',
  high: 'medium',
  medium: 'low',
  low: 'info',
  info: 'info',
};

// ─────────────────────────── download, then run ────────────────────────────

interface Download {
  unit: Unit;
  /** Where in `unit.text` the download command ends. */
  end: number;
  file: string;
}

const CURL_OUTPUT = /\bcurl\b[^|;&\n]*?(?:\s-[A-Za-z]*o\s*|\s--output(?:\s+|=))["']?([^\s"'|;&<>]+)/g;
const CURL_REDIRECT = /\bcurl\b[^|;&\n]*?\s>\s*["']?([^\s"'|;&<>]+)/g;
const CURL_REMOTE_NAME = /\bcurl\b[^|;&\n]*?\s(?:-[A-Za-z]*O[A-Za-z]*|--remote-name)(?=\s|$)[^|;&\n]*/g;
const WGET_OUTPUT = /\bwget\b[^|;&\n]*?(?:\s-[A-Za-z]*O\s*|\s--output-document(?:\s+|=))["']?([^\s"'|;&<>-][^\s"'|;&<>]*)/g;
const WGET_REMOTE_NAME = /\bwget\b(?![^|;&\n]*\s-[A-Za-z]*O)[^|;&\n]*/g;
const PS_OUTFILE = /\b(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^|;&\n]*?\s-OutFile\s+["']?([^\s"'|;&<>]+)/gi;
const URL_IN = /\b(?:https?|ftp):\/\/[^\s'"|;&<>)]+/i;

function downloadsIn(unit: Unit): Download[] {
  const out: Download[] = [];
  const add = (m: RegExpExecArray, file: string | undefined): void => {
    const base = basenameOf(file ?? '');
    if (base !== '') out.push({ unit, end: m.index + m[0].length, file: base });
  };
  for (const re of [CURL_OUTPUT, CURL_REDIRECT, WGET_OUTPUT, PS_OUTFILE]) {
    for (const m of unit.text.matchAll(re)) add(m as RegExpExecArray, m[1]);
  }
  for (const re of [CURL_REMOTE_NAME, WGET_REMOTE_NAME]) {
    for (const m of unit.text.matchAll(re)) {
      const url = URL_IN.exec(m[0]);
      if (url) add(m as RegExpExecArray, url[0].replace(/[?#].*$/, ''));
    }
  }
  return out;
}

function basenameOf(path: string): string {
  const base = path.split(/[/\\]/).pop() ?? '';
  return /[A-Za-z0-9]/.test(base) ? base : '';
}

const RUNNER = String.raw`(?:bash|sh|zsh|dash|ksh|source|\.|python[23]?(?:\.\d+)?|node|perl|ruby|php|pwsh|powershell(?:\.exe)?|&)`;

function runsFile(text: string, file: string): boolean {
  const f = file.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const end = String.raw`(?=$|[\s"'|;&)])`;
  const viaRunner = String.raw`(?:^|[\s;&|(])(?:sudo\s+(?:-\S+\s+)*)?${RUNNER}\s+(?:-\S+\s+)*["']?(?:[^\s"'|;&]*[\/\\])?${f}${end}`;
  const direct = String.raw`(?:^\s*|[;&|(]\s*|\bsudo\s+(?:-\S+\s+)*)["']?[^\s"'|;&]*[\/\\]${f}${end}`;
  return new RegExp(`${viaRunner}|${direct}`).test(text);
}

const DOWNLOAD_THEN_RUN = SKILL_RULES.find((r) => r.id === 'sc-download-then-run');

/**
 * A file downloaded and later run — on the same line or anywhere further down
 * the same file (round 3, N6: the hook's shell guard follows the same policy
 * for one command line). `units` must be in file order. One finding per file.
 */
function downloadThenRun(units: Unit[], instructionFile: boolean): RuleMatch[] {
  if (!DOWNLOAD_THEN_RUN) return [];
  const full = severityOfRule(DOWNLOAD_THEN_RUN);
  for (const dl of units.flatMap(downloadsIn)) {
    const rest = dl.unit.text.slice(dl.end);
    const run = runsFile(rest, dl.file)
      ? dl.unit
      : units.find((u) => u.line > dl.unit.line && runsFile(u.text, dl.file));
    if (!run) continue;
    const lowered = instructionFile && isPlaceholder(dl.unit.text);
    return [
      {
        rule: DOWNLOAD_THEN_RUN,
        line: run.line,
        snippet: `${snippetOf(run)} (downloaded at line ${dl.unit.line})`.slice(0, 240),
        source: run.source,
        severity: lowered ? ONE_LEVEL_LOWER[full] : full,
      },
    ];
  }
  return [];
}

// ────────────────────────────────── dedupe ──────────────────────────────────

/**
 * One finding per (rule, line). A prose rule and the code rule for the same
 * shape (`x-prose` and `x`) on the same line are one finding too — the
 * prose view now reads inline code as well, and a command is scored once:
 * the more severe of the two, the code rule on a tie.
 */
function finalize(matches: RuleMatch[]): RuleMatch[] {
  const best = new Map<string, RuleMatch>();
  for (const m of matches) {
    const key = `${m.rule.id.replace(/-prose$/, '')}:${m.line}`;
    const seen = best.get(key);
    if (
      seen === undefined ||
      SEVERITY_RANK[m.severity] > SEVERITY_RANK[seen.severity] ||
      (m.severity === seen.severity && seen.source === 'prose' && m.source !== 'prose')
    ) {
      best.set(key, m);
    }
  }
  return [...best.values()];
}

export function severityOfRule(rule: SkillRule): Severity {
  return rule.severity ?? THREAT_CATEGORY_META[rule.category].defaultSeverity;
}
