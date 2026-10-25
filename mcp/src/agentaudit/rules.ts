/**
 * Rule checks for `audit_agent_config`.
 *
 * Each function takes normalized input (an `McpServerEntry[]` or one
 * `ConfigSource`) and returns `Finding[]` — pure, no I/O, no persistence.
 * `analyze.ts` runs every check across every config source it read and
 * concatenates the results.
 */

import { redact, scanForSecrets } from '../hooks/secretScan.js';
import { maskSecrets } from '../redaction/maskSecrets.js';
import { makeFinding } from '../runners/scannerParsers/index.js';
import { scanContent } from '../skillaudit/patterns.js';
import { matchSignatures } from '../skillaudit/yaraSignatures.js';
import type { Finding } from '../types.js';
import type { ConfigSource } from './configSources.js';
import type { McpServerEntry } from './mcpServers.js';

const TOOL = 'agent-audit';

/**
 * A hook command that reaches the network: a client program, a raw socket,
 * an interpreter's HTTP or socket API, PowerShell's and Windows' own
 * downloaders, a DNS lookup. It was curl / wget / iwr / irm alone, and
 * `| nc host 9000`, `bash -i >& /dev/tcp/…` and `python -c "urllib…"`
 * audited clean (review of 3.6.0).
 */
const NETWORK_EGRESS_RE = new RegExp(
  [
    String.raw`\b(?:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod|nc|ncat|netcat|socat|telnet|ssh|scp|sftp|ftp|tftp)(?:\.exe)?\b(?!-)`,
    String.raw`\/dev\/(?:tcp|udp)\/`,
    String.raw`\b(?:urllib|http\.client|httplib|requests\.(?:get|post|put|patch|request)|httpx|aiohttp|socket\.(?:socket|create_connection)|net\.(?:connect|createConnection)|https?\.(?:get|request)\s*\(|fetch\s*\(|axios|XMLHttpRequest|Net::HTTP|LWP::|IO::Socket|HTTP::Tiny|fsockopen|curl_exec|open-uri)`,
    String.raw`\b(?:Net\.WebClient|System\.Net\.Http|Start-BitsTransfer|bitsadmin|certutil(?:\.exe)?\b[^|;&\n]*-urlcache|DownloadString|DownloadFile|UploadString|UploadFile|Resolve-DnsName|nslookup|dig)\b`,
  ].join('|'),
  'i',
);
// Redirection (`>`/`>>`, optionally preceded by a file-descriptor number) or
// a write-cmdlet, followed by a path that is absolute (leading `/`, `~`, or
// a Windows drive letter) or that walks up out of the current directory
// (`../`, `..\`). A relative path *within* the project (`./x`, `x/y.txt`)
// never matches. Heuristic — see checkHookRisks' doc comment.
const WRITE_OUTSIDE_RE =
  /(?:\d*>{1,2}|Out-File\s+-(?:Path\s+)?|Set-Content\s+-(?:Path\s+)?|Add-Content\s+-(?:Path\s+)?)\s*['"]?(?:~|\/(?!\/)|[A-Za-z]:[\\/]|\.\.[\\/])/i;

/** `${NAME}` template syntax — the shape `.mcp.json` never expands. */
const TEMPLATE_VAR_RE = /\$\{[A-Za-z_][A-Za-z0-9_]*\}/;

function finding(input: {
  rule_id: string;
  severity: Finding['severity'];
  category: Finding['category'];
  title: string;
  message: string;
  file_path: string;
  snippet?: string;
}): Finding {
  return makeFinding({
    tool: TOOL,
    rule_id: input.rule_id,
    severity: input.severity,
    category: input.category,
    title: input.title,
    message: input.message,
    file_path: input.file_path,
    fix_available: false,
    ...(input.snippet !== undefined ? { snippet: input.snippet } : {}),
  });
}

// ── 1. Unpinned package launchers (npx/uvx/pipx) ──────────────────────────

interface LaunchSpec {
  launcher: 'npx' | 'uvx' | 'pipx';
  packageSpec: string;
}

function launcherName(command: string | undefined): string | undefined {
  if (!command) return undefined;
  const base = command.replace(/\\/g, '/').split('/').pop() ?? command;
  return base.replace(/\.(cmd|exe|ps1|bat)$/i, '').toLowerCase();
}

/** First `args[]` element that is not a flag (does not start with `-`). */
function firstNonFlag(args: string[], fromIndex = 0): string | undefined {
  for (let i = fromIndex; i < args.length; i++) {
    const a = args[i];
    if (a !== undefined && !a.startsWith('-')) return a;
  }
  return undefined;
}

function launchSpecFor(entry: McpServerEntry): LaunchSpec | undefined {
  const name = launcherName(entry.command);
  const args = entry.args ?? [];
  if (name === 'npx') {
    const pkg = firstNonFlag(args);
    return pkg ? { launcher: 'npx', packageSpec: pkg } : undefined;
  }
  if (name === 'uvx') {
    const pkg = firstNonFlag(args);
    return pkg ? { launcher: 'uvx', packageSpec: pkg } : undefined;
  }
  if (name === 'pipx') {
    // `pipx run <pkg>` — the package follows the `run` subcommand.
    const runIdx = args.findIndex((a) => a === 'run');
    if (runIdx === -1) return undefined;
    const pkg = firstNonFlag(args, runIdx + 1);
    return pkg ? { launcher: 'pipx', packageSpec: pkg } : undefined;
  }
  return undefined;
}

/** An exact semver version — what npm resolves to one release, and nothing else does. */
const EXACT_SEMVER = /^v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
/** An exact PEP 440 release (`0.3.0`, `2025.1.17`, `1.0rc1`, `1!2.0.post1`): no operator, no `*`. */
const EXACT_PEP440 = /^(?:\d+!)?\d+(?:\.\d+)*(?:(?:a|b|rc)\d+)?(?:\.post\d+)?(?:\.dev\d+)?(?:\+[0-9A-Za-z.]+)?$/i;

/**
 * True when `spec` names an exact, non-floating version. Any `@<something>`
 * read as pinned before (review of 3.6.0): `pkg@^1.2.3`, `@~1.2.3`, `@1.x`,
 * `@>=1`, `@next`, `@*` all float — only an exact semver version is one
 * release. uv's own `uvx pkg@1.0` was read as unpinned: uvx takes `@` with
 * an exact version as `==`.
 */
function isPinned(launcher: LaunchSpec['launcher'], spec: string): boolean {
  if (launcher === 'npx') {
    // Strip a leading `@scope/` (npm scope), then look for a `@version` on
    // what remains — that is npm's own version-pin syntax.
    const unscoped = spec.replace(/^@[^/@]+\//, '');
    const at = unscoped.lastIndexOf('@');
    if (at <= 0) return false; // no version separator (or a bare `@scope/name`)
    return EXACT_SEMVER.test(unscoped.slice(at + 1));
  }
  // uv's `uvx` and pipx's `pipx run` both pin with PEP 440 `==` (or `===`);
  // uvx also with `@<exact version>` (`@latest` floats).
  const eq = /^[^=<>!~@\s]+===?(.+)$/.exec(spec);
  if (eq?.[1] !== undefined) return EXACT_PEP440.test(eq[1]);
  const at = launcher === 'uvx' ? /^[^=<>!~@\s]+@(.+)$/.exec(spec) : null;
  return at?.[1] !== undefined && EXACT_PEP440.test(at[1]);
}

export function checkUnpinnedLaunchers(entries: McpServerEntry[]): Finding[] {
  const out: Finding[] = [];
  for (const entry of entries) {
    const spec = launchSpecFor(entry);
    if (!spec || isPinned(spec.launcher, spec.packageSpec)) continue;
    out.push(
      finding({
        rule_id: 'agent-audit-unpinned-launcher',
        severity: 'medium',
        category: 'security',
        title: `MCP server '${entry.name}' launches an unpinned package`,
        message:
          `'${entry.name}' runs via ${spec.launcher} ${spec.packageSpec}, with no exact version pinned. ` +
          `A compromised or backdoored release published under this name runs automatically the next ` +
          `time this server starts. Pin an exact version.`,
        file_path: entry.sourceLabel,
        // An argument may be a credential (`--token ghp_…`): masked, as every quoted line here is.
        snippet: maskSecrets(`${entry.command} ${(entry.args ?? []).join(' ')}`.trim()),
      }),
    );
  }
  return out;
}

// ── 2. Remote servers over plain HTTP ──────────────────────────────────────

function isLoopbackHost(hostname: string): boolean {
  const h = hostname.toLowerCase();
  return h === 'localhost' || h === '127.0.0.1' || h === '::1' || h === '0.0.0.0' || h.endsWith('.localhost');
}

export function checkPlainHttpRemotes(entries: McpServerEntry[]): Finding[] {
  const out: Finding[] = [];
  for (const entry of entries) {
    if (!entry.url) continue;
    let parsed: URL;
    try {
      parsed = new URL(entry.url);
    } catch {
      continue;
    }
    if (parsed.protocol !== 'http:' || isLoopbackHost(parsed.hostname)) continue;
    // The address, not its credentials: a query (`?api_key=…`) or a userinfo
    // password was copied whole into the message and the snippet.
    const shown = maskSecrets(entry.url);
    out.push(
      finding({
        rule_id: 'agent-audit-http-remote',
        severity: 'high',
        category: 'security',
        title: `MCP server '${entry.name}' connects over plain HTTP`,
        message:
          `'${entry.name}' points at ${shown} — an unencrypted transport. Tool calls, responses, ` +
          `and any bearer token/header this server is configured with travel in the clear and can be ` +
          `read or altered in transit. Use https:// instead.`,
        file_path: entry.sourceLabel,
        snippet: shown,
      }),
    );
  }
  return out;
}

// ── 3. Inline secrets in `env`, `headers`, `args` and `url` ────────────────

/** One place of an entry a credential can be written: where (for the message), the text scanned, and the value. */
interface SecretPlace {
  where: string;
  text: string;
  value: string;
}

/**
 * Every place of an entry a credential can be written inline. Only `env` was
 * searched (review of 3.6.0): an `Authorization: Bearer …` header, a
 * `--token …` argument and a `?api_key=…` URL went unseen. An argument is
 * read with the flag before it, so `--api-key X` reads as `api-key=X`.
 */
function secretPlaces(entry: McpServerEntry): SecretPlace[] {
  const places: SecretPlace[] = [];
  for (const [key, value] of Object.entries(entry.env ?? {})) {
    if (typeof value === 'string') places.push({ where: `env.${key}`, text: `${key}=${value}`, value });
  }
  const headers = asObject(entry.raw['headers']);
  for (const [key, value] of Object.entries(headers ?? {})) {
    if (typeof value === 'string') places.push({ where: `headers.${key}`, text: `${key}: ${value}`, value });
  }
  const args = entry.args ?? [];
  args.forEach((arg, i) => {
    const flag = /^--?([\w.-]+)$/.exec(args[i - 1] ?? '')?.[1];
    places.push({ where: `args[${i}]`, text: flag === undefined ? arg : `${flag}=${arg}`, value: arg });
  });
  if (entry.url !== undefined) places.push({ where: 'url', text: entry.url, value: entry.url });
  return places;
}

export function checkInlineSecrets(entries: McpServerEntry[]): Finding[] {
  const out: Finding[] = [];
  for (const entry of entries) {
    for (const place of secretPlaces(entry)) {
      // One finding per place: the most certain of its hits (a token under a
      // credential name is both a provider token and an assignment).
      const hits = scanForSecrets(place.text);
      const best = hits.find((h) => h.confidence === 'high') ?? hits[0];
      for (const hit of best === undefined ? [] : [best]) {
        out.push(
          finding({
            rule_id: 'agent-audit-inline-secret',
            severity: hit.confidence === 'high' ? 'critical' : 'medium',
            category: 'security',
            title: `Possible ${hit.title} inline in MCP server '${entry.name}' (${place.where.split(/[.[]/)[0]})`,
            message:
              `${place.where} on '${entry.name}' (${entry.sourceLabel}) looks like a ${hit.title.toLowerCase()} ` +
              `written directly into the config file rather than referenced from a secret store or ` +
              `\${VAR} placeholder. ${place.where === 'url' ? maskSecrets(place.value) : redact(place.value)}`,
            file_path: entry.sourceLabel,
            snippet: hit.preview,
          }),
        );
      }
    }
  }
  return out;
}

// ── shared JSON helpers for the settings-shaped checks below ──────────────

function asObject(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function asArray(value: unknown): unknown[] | undefined {
  return Array.isArray(value) ? value : undefined;
}

// ── 4. Wildcard Bash permission allowlists ─────────────────────────────────

/**
 * Parses `Bash(<specifier>)`. Returns the specifier, or undefined for another
 * tool / malformed entry. A bare `Bash` — and `Bash()`, `Bash(:*)`, `Bash( *)`,
 * whose prefix is empty — grants the tool whole: `*`. Review of 3.6.0: a bare
 * `"allow": ["Bash"]`, every command with no prompt, was never flagged, and
 * the empty-prefix spellings were skipped as "no prefix".
 */
function bashSpecifier(rule: string): string | undefined {
  if (rule.trim() === 'Bash') return '*';
  const m = /^Bash\((.*)\)$/.exec(rule.trim());
  const specifier = m?.[1];
  if (specifier === undefined) return undefined;
  return specifier.replace(/:?\*$/, '').trim() === '' ? '*' : specifier;
}

/**
 * Coordinator review, round 1: the original version of this check only
 * recognised a wildcard written `<prefix>:*` (colon before the star). A
 * trailing `*` with no colon — `Bash(node -e ' *)`, an entry this repo's
 * own `.claude/settings.local.json` actually carries — was never even
 * examined, so an interpreter-escape prefix went unflagged purely because
 * of which separator its author happened to type. Both spellings grant the
 * same thing (Claude Code prefix-matches everything before the `*`), so
 * both are recognised here: strip one trailing `*`, then an optional `:`
 * separator, then trailing whitespace, and whatever is left is the prefix
 * being granted unconditionally. Returns undefined for `*` alone (handled
 * as its own, always-critical case) and for a specifier with no trailing
 * wildcard at all (an exact command grants nothing beyond itself).
 */
function trailingWildcardPrefix(specifier: string): string | undefined {
  if (specifier === '*' || !specifier.endsWith('*')) return undefined;
  const prefix = specifier.slice(0, -1).replace(/:$/, '').trimEnd();
  return prefix.length > 0 ? prefix : undefined;
}

/**
 * True when `prefix` (lower-cased) is exactly one of `words`, or begins with
 * one of them followed by a space — a word-boundary prefix match, so
 * `"npm run"` matches `"npm run test:*"`'s prefix but not an unrelated
 * `"npm running-something"`.
 */
function matchesPrefixList(prefix: string, words: readonly string[]): boolean {
  return words.some((w) => prefix === w || prefix.startsWith(`${w} `));
}

/**
 * A small, deliberately narrow allowlist of trailing-wildcard prefixes that
 * are safe DESPITE the wildcard: a fixed, project-controlled verb (an npm/
 * pnpm/yarn script name, a read-only git subcommand) rather than a path, a
 * shell, or an interpreter. Anything not on this list is flagged (at
 * `medium` by default, `high` when it also matches `HIGH_RISK_BASH_PREFIXES`
 * below) — kept intentionally small rather than grown to "everything that
 * looks fine", which is exactly the reasoning gap that let `Bash(node -e '
 * *)` read as equivalent to `Bash(npm run *)` before this review.
 */
const SAFE_WILDCARD_PREFIXES = [
  'npm run', 'npm test', 'pnpm run', 'pnpm test', 'yarn run', 'yarn test',
  'git status', 'git diff', 'git log',
];

/**
 * Prefixes that turn a trailing wildcard into effectively arbitrary code
 * execution or an outright destructive action, rated 'high' rather than the
 * 'medium' every other non-safe-listed prefix gets. Two families:
 *   - interpreters given an inline-code flag (`node -e`, `python -c`,
 *     `bash -c`, …) — the wildcard suffix IS the code that runs;
 *   - single commands whose blast radius does not need a flag to be
 *     catastrophic (rm, curl, wget, sudo, dd, …) — the original dangerous-
 *     prefix list from before this review, carried forward unchanged so a
 *     prefix that used to read 'high' still does.
 */
const HIGH_RISK_BASH_PREFIXES = [
  'node -e', 'python -c', 'python3 -c', 'bash -c', 'sh -c', 'zsh -c', 'ksh -c',
  'pwsh -c', 'powershell -c', 'eval', 'iex', 'invoke-expression',
  'rm', 'del', 'erase', 'rd', 'rmdir', 'remove-item',
  'curl', 'wget', 'iwr', 'irm', 'invoke-webrequest', 'invoke-restmethod',
  'sudo', 'su', 'chmod', 'chown', 'dd', 'mkfs', 'format',
  'ssh', 'scp', 'kill', 'killall', 'taskkill', 'shutdown', 'reboot',
];

export function checkWildcardPermissions(source: ConfigSource): Finding[] {
  const root = asObject(source.json);
  const permissions = asObject(root?.['permissions']);
  const allow = asArray(permissions?.['allow']);
  if (!allow) return [];

  const out: Finding[] = [];
  for (const entry of allow) {
    if (typeof entry !== 'string') continue;
    const specifier = bashSpecifier(entry);
    // Quoted masked: a rule can hold a credential (`Bash(curl -H "Authorization: Bearer …" *)`).
    const rule = maskSecrets(entry);
    if (specifier === undefined) continue;

    if (specifier === '*') {
      out.push(
        finding({
          rule_id: 'agent-audit-wildcard-permission',
          severity: 'critical',
          category: 'security',
          title: `Wildcard Bash permission: ${rule}`,
          message:
            `permissions.allow contains "${rule}", which auto-approves every Bash command with no ` +
            `confirmation prompt. Narrow it to the specific commands actually needed.`,
          file_path: source.label,
          snippet: rule,
        }),
      );
      continue;
    }

    const prefix = trailingWildcardPrefix(specifier);
    if (prefix === undefined) continue; // exact command, or no wildcard at all — grants nothing extra
    const lowerPrefix = prefix.toLowerCase();
    if (matchesPrefixList(lowerPrefix, SAFE_WILDCARD_PREFIXES)) continue;

    const severity: Finding['severity'] = matchesPrefixList(lowerPrefix, HIGH_RISK_BASH_PREFIXES)
      ? 'high'
      : 'medium';
    out.push(
      finding({
        rule_id: 'agent-audit-wildcard-permission',
        severity,
        category: 'security',
        title: `Wildcard Bash permission: ${rule}`,
        message:
          `permissions.allow contains "${rule}", which auto-approves any Bash command starting with ` +
          `'${maskSecrets(prefix)}' with no confirmation prompt. Narrow it to the specific commands actually needed.`,
        file_path: source.label,
        snippet: rule,
      }),
    );
  }
  return out;
}

// ── 5. defaultMode: "bypassPermissions" ────────────────────────────────────

export function checkBypassPermissions(source: ConfigSource): Finding[] {
  const root = asObject(source.json);
  if (!root) return [];
  const permissions = asObject(root['permissions']);
  const mode = permissions?.['defaultMode'] ?? root['defaultMode'];
  if (mode !== 'bypassPermissions') return [];
  return [
    finding({
      rule_id: 'agent-audit-bypass-permissions',
      severity: 'critical',
      category: 'security',
      title: 'Permission prompts are fully disabled (defaultMode: "bypassPermissions")',
      message:
        `${source.label} sets defaultMode to "bypassPermissions" — every tool call (including Bash, ` +
        `file writes, and any MCP server this workspace trusts) runs with no confirmation at all.`,
      file_path: source.label,
    }),
  ];
}

// ── 6. enableAllProjectMcpServers ──────────────────────────────────────────

export function checkEnableAllProjectMcpServers(source: ConfigSource): Finding[] {
  const root = asObject(source.json);
  if (!root || root['enableAllProjectMcpServers'] !== true) return [];
  return [
    finding({
      rule_id: 'agent-audit-enable-all-mcp-servers',
      severity: 'medium',
      category: 'security',
      title: 'Every project-declared MCP server is auto-trusted (enableAllProjectMcpServers: true)',
      message:
        `${source.label} sets enableAllProjectMcpServers to true — any MCP server later added to this ` +
        `project's .mcp.json starts and is trusted automatically, with no per-server confirmation.`,
      file_path: source.label,
    }),
  ];
}

// ── 7. Hooks with network egress or writes outside the project ────────────

/**
 * "Writes outside the project" is a heuristic, not a shell parser: it looks
 * for a redirection operator or a write-cmdlet followed by something that
 * LOOKS like an absolute or upward-traversing path. It cannot see a write
 * hidden behind a variable (`> "$OUT"`) or a command substitution — those
 * are false negatives, not false positives, and are the same trade-off
 * `bashGuard.ts` documents for its own coarser rules.
 *
 * A hook in exec form (`"command": "bash", "args": ["-c", "…"]`) is read
 * with its arguments: the command alone is only the program's name. The
 * line is also read with scan_skill's code rules and signatures — the same
 * download-and-run, credential exfiltration, reverse shell or destructive
 * command that skill audits score (review of 3.6.0: a hook piping the
 * transcript to `nc` read clean). Every command is quoted masked
 * (`redaction/maskSecrets.ts`): a hook's `Authorization: Bearer …` was
 * copied into the finding whole.
 */
export function checkHookRisks(source: ConfigSource): Finding[] {
  const root = asObject(source.json);
  const hooksRoot = asObject(root?.['hooks']);
  if (!hooksRoot) return [];

  const out: Finding[] = [];
  for (const eventGroups of Object.values(hooksRoot)) {
    const groups = asArray(eventGroups);
    if (!groups) continue;
    for (const group of groups) {
      const groupObj = asObject(group);
      const hooks = asArray(groupObj?.['hooks']);
      if (!hooks) continue;
      for (const hook of hooks) {
        const hookObj = asObject(hook);
        const program = hookObj?.['command'];
        if (typeof program !== 'string') continue;
        const args = (asArray(hookObj?.['args']) ?? []).filter((a): a is string => typeof a === 'string');
        const command = [program, ...args].join(' ');
        const shown = maskSecrets(command);
        const egress = NETWORK_EGRESS_RE.exec(command);
        if (egress !== null) {
          out.push(
            finding({
              rule_id: 'agent-audit-hook-network-egress',
              severity: 'high',
              category: 'security',
              title: 'A hook shells out to the network',
              message:
                `${source.label} runs a hook whose command reaches out over the network ` +
                `(${egress[0].trim()}): "${shown}". A hook runs on every matching tool call with no ` +
                `visible confirmation — this is where session data would leave silently.`,
              file_path: source.label,
              snippet: shown,
            }),
          );
        }
        if (WRITE_OUTSIDE_RE.test(command)) {
          out.push(
            finding({
              rule_id: 'agent-audit-hook-write-outside-project',
              severity: 'high',
              category: 'security',
              title: 'A hook writes outside the project directory',
              message:
                `${source.label} runs a hook whose command writes to a path outside the project ` +
                `("${shown}"). Confirm this is intended — a hook is not sandboxed to the project root.`,
              file_path: source.label,
              snippet: shown,
            }),
          );
        }
        out.push(...dangerousCommandFindings(source, command, shown));
      }
    }
  }
  return out;
}

/** scan_skill's code rules and signatures over one hook command: each a finding at that rule's severity. */
function dangerousCommandFindings(source: ConfigSource, command: string, shown: string): Finding[] {
  const hits = [
    ...scanContent(command, true).map((m) => ({ id: m.rule.id, title: m.rule.title, severity: m.severity })),
    ...matchSignatures(command).map((m) => ({ id: m.signature.id, title: m.signature.title, severity: m.signature.severity })),
  ];
  return hits.map((hit) =>
    finding({
      rule_id: 'agent-audit-hook-dangerous-command',
      severity: hit.severity,
      category: 'security',
      title: `A hook runs: ${hit.title}`,
      message:
        `${source.label} runs a hook whose command scan_skill's rule ${hit.id} flags (${hit.title.toLowerCase()}): ` +
        `"${shown}". The host runs it as written on every matching event.`,
      file_path: source.label,
      snippet: shown,
    }),
  );
}

// ── 8. ${VAR} in a project .mcp.json (unexpanded by Claude Code) ──────────

export function checkUnexpandedVars(source: ConfigSource): Finding[] {
  // Scoped to .mcp.json specifically: this is the one file Claude Code
  // launches a project-scoped server from without expanding `${VAR}` in it
  // (only `${CLAUDE_PLUGIN_ROOT}`, inside plugin.json, is expanded). Cursor
  // and VS Code's own mcp.json support `${workspaceFolder}`; Gemini CLI has
  // a dedicated `cwd` field — see mcpJsonConfigs.test.ts.
  if (source.label !== '.mcp.json') return [];
  const root = asObject(source.json);
  const servers = asObject(root?.['mcpServers']);
  if (!servers) return [];

  const out: Finding[] = [];
  for (const [name, value] of Object.entries(servers)) {
    const entry = asObject(value);
    if (!entry) continue;
    const fields: Array<[string, unknown]> = [
      ['command', entry['command']],
      ['cwd', entry['cwd']],
    ];
    const args = asArray(entry['args']);
    if (args) args.forEach((a, i) => fields.push([`args[${i}]`, a]));

    for (const [field, value_] of fields) {
      if (typeof value_ !== 'string' || !TEMPLATE_VAR_RE.test(value_)) continue;
      out.push(
        finding({
          rule_id: 'agent-audit-unexpanded-var',
          severity: 'medium',
          category: 'quality',
          title: `MCP server '${name}' will not start: unexpanded \${VAR} in .mcp.json`,
          message:
            `.mcp.json's "${name}".${field} is "${maskSecrets(value_)}". Claude Code does NOT expand \${VAR} ` +
            `placeholders for a project-scoped .mcp.json server entry — only \${CLAUDE_PLUGIN_ROOT} ` +
            `inside a plugin's own plugin.json is expanded there. The literal placeholder string ` +
            `becomes part of the spawned command and the server fails to start ` +
            `(MODULE_NOT_FOUND or similar). Use a path relative to the project root (Claude Code sets ` +
            `cwd to it) or an absolute path instead.`,
          file_path: source.label,
          snippet: maskSecrets(value_),
        }),
      );
      break; // one finding per server entry is enough context
    }
  }
  return out;
}
