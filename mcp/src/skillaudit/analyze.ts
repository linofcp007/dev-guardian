/**
 * Skill-audit orchestrator.
 *
 * Given an ingested target (a list of text files), runs every analysis pass
 * and produces canonical `Finding`s plus the rolled-up risk score and
 * per-category breakdown:
 *
 *   1. Pattern rules     (patterns.ts)      — prompt-level + code-level signals,
 *                                            the code rules also over the fenced
 *                                            and inline code of an instruction file
 *   2. YARA signatures   (yaraSignatures.ts)— known-bad artifacts
 *   3. Taint-light       (taint.ts)         — source→sink within a file
 *   4. Hidden Unicode    (here)             — invisible instruction smuggling
 *   5. MCP manifest      (here)             — least-privilege / tool poisoning
 *   6. Dependencies+OSV  (deps.ts, osv.ts)  — known CVEs in declared deps
 *
 * Every signal becomes a Finding with `category: 'security'` and
 * `subcategory: <ThreatCategory>` so it flows through the existing storage,
 * scoring, reporting and resource surfaces unchanged. The install
 * recommendation comes from `score.ts`.
 */

import { makeFinding } from '../runners/scannerParsers/index.js';
import { queryOsv, type OsvResult } from '../runners/osv.js';
import type { Finding, Severity } from '../types.js';
import { extractDependencies } from './deps.js';
import type { IngestedFile, SymlinkEntry } from './ingest.js';
import { scanContent, severityOfRule, type RuleMatch } from './patterns.js';
import { scoreFindings, type ScoreResult, type ScoreSignal } from './score.js';
import { detectTaint } from './taint.js';
import { THREAT_CATEGORIES, type ThreatCategory } from './taxonomy.js';
import { matchSignatures } from './yaraSignatures.js';

const TOOL = 'guardian-scanskill';

/** The same words every other `GUARDIAN_OFFLINE` caller reports. */
export const OSV_OFFLINE_REASON = 'network disabled (GUARDIAN_OFFLINE=1)';

export interface SkillAuditReport {
  findings: Finding[];
  score: ScoreResult;
  category_breakdown: Record<ThreatCategory, number>;
  osv: OsvResult | null;
  files_scanned: number;
  executable_files: number;
  hidden_unicode_files: number;
}

export interface AnalyzeOptions {
  checkDeps?: boolean;
  signal?: AbortSignal;
  /**
   * No network: the OSV lookup sends nothing and reports itself offline.
   * Default: `GUARDIAN_OFFLINE === '1'`, as every other network caller
   * (intel, pkgvet, secrets/verify) reads it.
   */
  offline?: boolean;
  /** Links `ingest.ts#collectDir` found and refused to follow — see
   *  `SymlinkEntry`'s own doc comment for why walking never reads through
   *  one. Each becomes its own finding below. */
  symlinks?: SymlinkEntry[];
}

export async function analyzeSkill(
  files: IngestedFile[],
  opts: AnalyzeOptions = {},
): Promise<SkillAuditReport> {
  const findings: Finding[] = [];
  const signals: ScoreSignal[] = [];
  let executableFiles = 0;
  let hiddenUnicodeFiles = 0;

  const push = (f: Finding, isExecutable: boolean, scored = true): void => {
    findings.push(f);
    signals.push({ severity: f.severity, isExecutable, scored });
  };
  // A citation (see `patterns.ts`) is reported every time, at low, but a
  // rule's citations score once per skill: a threat catalogue that quotes
  // the same attack class ten times is one fact about it, not ten. Measured
  // in round 2 of the wave: without this, dev-spec-driven's catalogue read
  // CAUTION on its eight quoted examples alone.
  const citedRules = new Set<string>();

  // 0. Symlinks/junctions the ingester refused to follow. Reported here
  // (never as a raw ingested "file") so the pattern/YARA/taint passes below
  // never see a link's target string as if it were reviewable source — see
  // `SymlinkEntry`: the target is a path, never content.
  for (const link of opts.symlinks ?? []) {
    const escaped = link.kind === 'escaped_directory';
    push(
      makeFinding({
        tool: TOOL,
        rule_id: escaped ? 'skill-directory-escapes-root' : 'skill-symlink',
        severity: 'medium',
        category: 'security',
        subcategory: 'privilege_escalation',
        title: escaped ? 'Directory escapes the skill package root' : 'Symlink in skill package',
        message: escaped
          ? `${link.relPath} resolves outside the ingested package root (${link.target}) and ` +
            'was not entered.'
          : `${link.relPath} is a symlink to ${link.target}. It was not followed and its target ` +
            'was never read — review whether it is intended to reach outside the package.',
        file_path: link.relPath,
      }),
      false,
    );
  }

  for (const file of files) {
    if (file.isExecutable) executableFiles += 1;

    // 1. Pattern rules.
    for (const m of scanContent(file.content, file.isCode, { markdown: isMarkdownLike(file.relPath) })) {
      const repeat = m.cited && citedRules.has(m.rule.id);
      if (m.cited) citedRules.add(m.rule.id);
      push(
        makeFinding({
          tool: TOOL,
          rule_id: m.rule.id,
          severity: m.severity,
          category: 'security',
          subcategory: m.rule.category,
          title: m.rule.title,
          message: m.rule.message + whereFound(m),
          file_path: file.relPath,
          line_start: m.line,
          line_end: m.line,
          snippet: m.snippet,
        }),
        file.isExecutable,
        !repeat,
      );
    }

    // 1b. The commands a plugin's configuration runs. A `.json` file is not
    // code, so its strings never met the code rules — but the host executes
    // a hook's `command` on every matching event, and an MCP server's
    // `command` + `args` when it starts (round 2 of the wave).
    for (const cmd of executedCommands(file)) {
      for (const m of scanContent(cmd.text, true)) {
        push(
          makeFinding({
            tool: TOOL,
            rule_id: m.rule.id,
            severity: m.severity,
            category: 'security',
            subcategory: m.rule.category,
            title: m.rule.title,
            message: `${m.rule.message} Found in a command ${cmd.what}, which the host runs as written.`,
            file_path: file.relPath,
            line_start: cmd.line,
            line_end: cmd.line,
            snippet: m.snippet,
          }),
          file.isExecutable,
        );
      }
    }

    // 2. YARA signatures.
    for (const m of matchSignatures(file.content)) {
      push(
        makeFinding({
          tool: TOOL,
          rule_id: m.signature.id,
          severity: m.signature.severity,
          category: 'security',
          subcategory: m.signature.category,
          title: m.signature.title,
          message: m.signature.description,
          file_path: file.relPath,
          line_start: m.line,
          line_end: m.line,
          snippet: m.snippet,
        }),
        file.isExecutable,
      );
    }

    // 3. Taint-light (code files only).
    if (file.isCode || file.isExecutable) {
      const flow = detectTaint(file.content);
      if (flow) {
        push(
          makeFinding({
            tool: TOOL,
            rule_id: 'taint-source-to-sink',
            severity: 'high',
            category: 'security',
            subcategory: 'taint',
            title: `Possible exfiltration flow: ${flow.source_id} → ${flow.sink_id}`,
            message:
              `Source (${flow.source_id}) at line ${flow.source_line} co-occurs with a network/exec sink ` +
              `(${flow.sink_id}) at line ${flow.sink_line} in the same file. Confirm the data flow.`,
            file_path: file.relPath,
            line_start: flow.source_line,
            line_end: flow.sink_line,
            snippet: flow.sink_snippet,
          }),
          file.isExecutable,
        );
      }
    }

    // 4. Hidden Unicode.
    const hidden = findHiddenUnicode(file.content);
    if (hidden) {
      hiddenUnicodeFiles += 1;
      push(
        makeFinding({
          tool: TOOL,
          rule_id: 'ra-hidden-unicode',
          severity: 'high',
          category: 'security',
          subcategory: 'rogue_agent',
          title: 'Hidden / invisible Unicode characters',
          message:
            `Invisible code point(s) found (e.g. U+${hidden.code.toString(16).toUpperCase()}). ` +
            'Zero-width / tag characters are a channel for instructions invisible to humans but read by the model.',
          file_path: file.relPath,
          line_start: hidden.line,
          line_end: hidden.line,
          snippet: `<invisible code point U+${hidden.code.toString(16).toUpperCase()}>`,
        }),
        file.isExecutable,
      );
    }

    // 5. MCP manifest checks.
    for (const f of analyzeMcpManifest(file)) push(f, file.isExecutable);
  }

  // 6. Dependencies → OSV.
  let osv: OsvResult | null = null;
  if (opts.checkDeps !== false) {
    const deps = extractDependencies(
      files.map((f) => ({ relPath: f.relPath, content: f.content })),
    );
    const offline = opts.offline ?? process.env['GUARDIAN_OFFLINE'] === '1';
    if (deps.length > 0 && offline) {
      // Unknown, never clean: scan_skill records `osv.dev: skipped` with this reason.
      osv = { online: false, queried: 0, vulnerable_packages: [], error: OSV_OFFLINE_REASON };
    } else if (deps.length > 0) {
      const osvOpts: { signal?: AbortSignal } = {};
      if (opts.signal) osvOpts.signal = opts.signal;
      osv = await queryOsv(deps, osvOpts);
      for (const grp of osv.vulnerable_packages) {
        push(
          makeFinding({
            tool: TOOL,
            rule_id: 'osv-vulnerable-dependency',
            severity: grp.severity,
            category: 'security',
            subcategory: 'supply_chain',
            title: `Vulnerable dependency: ${grp.name}${grp.version ? `@${grp.version}` : ''}`,
            message:
              `OSV reports ${grp.vuln_ids.length} known vulnerabilit${grp.vuln_ids.length === 1 ? 'y' : 'ies'} ` +
              `for ${grp.ecosystem} package ${grp.name}: ${grp.vuln_ids.slice(0, 8).join(', ')}.`,
            file_path: grp.name,
          }),
          false,
        );
      }
    }
  }

  const category_breakdown = emptyBreakdown();
  for (const f of findings) {
    const cat = f.subcategory as ThreatCategory | undefined;
    if (cat && cat in category_breakdown) category_breakdown[cat] += 1;
  }

  return {
    findings,
    score: scoreFindings(signals),
    category_breakdown,
    osv,
    files_scanned: files.length,
    executable_files: executableFiles,
    hidden_unicode_files: hiddenUnicodeFiles,
  };
}

/**
 * The command lines a plugin's configuration makes the host run: every
 * `command` string (with its `args`, when they are strings) in a
 * `hooks.json`, a `plugin.json`, an `.mcp.json` / `mcp.json`, or a
 * `.claude/settings*.json` — hooks and MCP servers alike. Each carries the
 * line its `command` sits on.
 */
function executedCommands(file: IngestedFile): Array<{ text: string; line: number; what: string }> {
  const name = file.relPath.split('/').pop()?.toLowerCase() ?? '';
  const inClaudeDir = /(^|\/)\.claude\/settings(\.local)?\.json$/i.test(file.relPath);
  if (!['hooks.json', 'plugin.json', '.mcp.json', 'mcp.json'].includes(name) && !inClaudeDir) return [];
  let json: unknown;
  try {
    json = JSON.parse(file.content);
  } catch {
    return [];
  }
  const out: Array<{ text: string; line: number; what: string }> = [];
  const walk = (node: unknown, depth: number): void => {
    if (depth > 12 || node === null || typeof node !== 'object') return;
    if (Array.isArray(node)) {
      for (const item of node) walk(item, depth + 1);
      return;
    }
    const obj = node as Record<string, unknown>;
    const command = obj['command'];
    if (typeof command === 'string' && command.trim() !== '') {
      const args = Array.isArray(obj['args']) ? obj['args'].filter((a): a is string => typeof a === 'string') : [];
      const at = file.content.indexOf(JSON.stringify(command));
      out.push({
        text: [command, ...args].join(' '),
        line: at === -1 ? 1 : file.content.slice(0, at).split(/\r?\n/).length,
        what: obj['type'] === 'command' || name === 'hooks.json' ? `a hook in ${name}` : `an MCP server in ${name}`,
      });
    }
    for (const value of Object.values(obj)) walk(value, depth + 1);
  };
  walk(json, 0);
  return out;
}

/** Markdown or plain text, where an indented block is code: `.md`, `.txt`, `.rst`, `.adoc`, or no extension. */
function isMarkdownLike(relPath: string): boolean {
  const name = relPath.split('/').pop() ?? '';
  return /\.(md|markdown|mdx|txt|rst|adoc)$/i.test(name) || !name.includes('.');
}

/** Says which part of an instruction file a code rule read, and why a hit scores below its rule. */
const CODE_SOURCE_TEXT: Partial<Record<RuleMatch['source'], string>> = {
  fenced: 'a fenced code block',
  indented: 'an indented code block',
  pre: 'an HTML <pre> / <code> block',
  inline: 'inline code',
};

function whereFound(m: RuleMatch): string {
  if (m.cited) {
    return (
      ' Cited, not said: the phrase is quoted — in quotation marks, a code span, or a code block — under text ' +
      'that labels it an attack to resist and does not tell the reader to use it: the shape of documentation ' +
      'that describes the attack. Reported at low, not dismissed: a model does not stop obeying an instruction ' +
      'because it is quoted, so read it if the file is not about AI safety.'
    );
  }
  const kind = CODE_SOURCE_TEXT[m.source];
  if (kind === undefined) return '';
  const where = ` Found in ${kind} of an instruction file, which the model may run as written.`;
  if (m.severity === severityOfRule(m.rule)) return where;
  return m.rule.fetchesOrSends === true
    ? `${where} Scored one level below the rule: a placeholder (…, <url>, example.com) stands where its ` +
        'target would be, and nothing in it or in its block is a real target — the shape of documentation.'
    : `${where} Scored one level below the rule: nothing in it or in its block is a fetch target, and such ` +
        'code is as often a mention of the command as an instruction to run it.';
}

function emptyBreakdown(): Record<ThreatCategory, number> {
  const out = {} as Record<ThreatCategory, number>;
  for (const c of THREAT_CATEGORIES) out[c] = 0;
  return out;
}

/** First invisible code point + its line, or null. */
function findHiddenUnicode(content: string): { code: number; line: number } | null {
  const lines = content.split(/\r?\n/);
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i] ?? '';
    for (const ch of line) {
      const code = ch.codePointAt(0);
      if (code !== undefined && isInvisible(code)) return { code, line: i + 1 };
    }
  }
  return null;
}

function isInvisible(code: number): boolean {
  return (
    (code >= 0x200b && code <= 0x200f) || // zero-width space/joiner/non-joiner + LRM/RLM
    (code >= 0x202a && code <= 0x202e) || // bidi overrides
    (code >= 0x2060 && code <= 0x2064) || // word joiner / invisible operators
    code === 0xfeff || // BOM / zero-width no-break space
    (code >= 0xe0000 && code <= 0xe007f) // Unicode tag block
  );
}

/**
 * Directives that manipulate the model when it reads a tool description.
 * Shared with `audit_mcp_tools` (`mcpaudit/analyze.ts`), which runs it over
 * the definitions a server actually serves rather than a manifest on disk.
 */
export const MCP_DESCRIPTION_POISONING =
  /(ignore\s+(previous|all)|do\s+not\s+(tell|mention|inform)|system\s+prompt|<important>|<secret>|<system>)/i;

/**
 * MCP-specific manifest checks: least-privilege (over-broad declared
 * capability) and tool poisoning (instructions hidden in tool descriptions).
 * Only runs on JSON manifests that actually look like MCP configs.
 */
function analyzeMcpManifest(file: IngestedFile): Finding[] {
  const name = file.relPath.split('/').pop()?.toLowerCase() ?? '';
  const looksMcp =
    /mcp.*\.json$/.test(name) ||
    name === 'plugin.json' ||
    /"mcpservers"\s*:/i.test(file.content) ||
    (/"command"\s*:/.test(file.content) && /"args"\s*:/.test(file.content) && name.endsWith('.json'));
  if (!looksMcp) return [];

  const out: Finding[] = [];
  let json: unknown;
  try {
    json = JSON.parse(file.content);
  } catch {
    json = null;
  }

  // Least privilege: wildcard scopes/permissions.
  if (
    /"(permissions|scopes|allowedTools|capabilities)"\s*:\s*(\[[^\]]*"(\*|all)"|"(\*|all)")/i.test(
      file.content,
    )
  ) {
    out.push(
      finding(
        file,
        'mcp-wildcard-scope',
        'medium',
        'mcp_least_privilege',
        'MCP manifest grants wildcard scope',
        'The manifest declares "*"/"all" permissions or capabilities — far broader than any single purpose needs.',
      ),
    );
  }

  // Tool poisoning: hidden directives inside tool descriptions.
  const desc = collectDescriptions(json);
  for (const d of desc) {
    if (MCP_DESCRIPTION_POISONING.test(d)) {
      out.push(
        finding(
          file,
          'mcp-tool-description-poisoning',
          'high',
          'mcp_tool_poisoning',
          'Hidden instructions in MCP tool description',
          'A tool description embeds directives that manipulate the model when the host loads the tool list.',
        ),
      );
      break;
    }
  }
  return out;
}

function collectDescriptions(json: unknown, acc: string[] = []): string[] {
  if (!json || typeof json !== 'object') return acc;
  if (Array.isArray(json)) {
    for (const item of json) collectDescriptions(item, acc);
    return acc;
  }
  for (const [key, value] of Object.entries(json as Record<string, unknown>)) {
    if ((key === 'description' || key === 'name' || key === 'instructions') && typeof value === 'string') {
      acc.push(value);
    } else if (value && typeof value === 'object') {
      collectDescriptions(value, acc);
    }
  }
  return acc;
}

function finding(
  file: IngestedFile,
  ruleId: string,
  severity: Severity,
  subcategory: ThreatCategory,
  title: string,
  message: string,
): Finding {
  return makeFinding({
    tool: TOOL,
    rule_id: ruleId,
    severity,
    category: 'security',
    subcategory,
    title,
    message,
    file_path: file.relPath,
    line_start: 1,
  });
}
