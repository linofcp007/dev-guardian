/**
 * What `audit_mcp_tools` returns is bounded (fix round 5, I-3). The text of
 * a finding comes from what a server chose to serve, and nothing else bounded
 * it: a 1.8 MB fixture produced two findings whose messages were 1.29 MB
 * each, and 50 servers 7725 findings in a 6.4 MB result — all of it read by
 * the model that called the tool.
 *
 * - every string is cut to a byte bound here: a message to 2 KiB, a title and
 *   a snippet to less; a report list to a count, and each entry of it;
 * - a server keeps its 50 most severe findings; the rest become ONE finding
 *   saying how many and of which rules;
 * - the audit keeps 500 in total, with one more such summary.
 *
 * What is dropped is dropped from the stored findings too: the scan records
 * what it reported, and the summary is the record of the rest.
 *
 * Pure. No I/O.
 */

import { makeFinding } from '../runners/scannerParsers/index.js';
import type { Finding, Severity } from '../types.js';

/** A key segment of a field path (`inputSchema.properties.<key>`). */
export const MAX_PATH_SEGMENT_CHARS = 64;
/** A whole field path. */
export const MAX_PATH_CHARS = 256;
/** A finding's message, in UTF-8 bytes. */
export const MAX_MESSAGE_BYTES = 2048;
export const MAX_TITLE_BYTES = 512;
export const MAX_SNIPPET_BYTES = 1024;
/** One reason, warning or list entry of a server's report. */
export const MAX_REPORT_STRING_BYTES = 2048;
export const MAX_LIST_ENTRY_BYTES = 256;
/** Entries of one report list (pins changed / added / removed, warnings). */
export const MAX_LIST_ENTRIES = 100;

export const MAX_FINDINGS_PER_SERVER = 50;
export const MAX_FINDINGS_TOTAL = 500;
export const CAPPED_RULE_ID = 'mcp-audit-findings-capped';

const ELLIPSIS = '…';
const ELLIPSIS_BYTES = 3;

function utf8Length(cp: number): number {
  if (cp < 0x80) return 1;
  if (cp < 0x800) return 2;
  if (cp < 0x10000) return 3;
  return 4;
}

/**
 * `text` cut to at most `maxBytes` of UTF-8, ending in `…` when it was cut.
 * Never splits a code point: a surrogate pair stays whole or goes.
 */
export function capText(text: string, maxBytes: number): string {
  // A code unit is at least one byte: past `maxBytes` units it is over for sure.
  if (text.length <= maxBytes / 3 || Buffer.byteLength(text, 'utf8') <= maxBytes) return text;
  const budget = maxBytes - ELLIPSIS_BYTES;
  let bytes = 0;
  let end = 0;
  for (const ch of text.slice(0, maxBytes)) {
    const cp = ch.codePointAt(0) ?? 0;
    const size = utf8Length(cp);
    if (bytes + size > budget) break;
    bytes += size;
    end += ch.length;
  }
  return `${text.slice(0, end)}${ELLIPSIS}`;
}

/** At most `maxEntries` entries, each cut to `entryBytes`, then `… and N more`. */
export function capList(values: readonly string[], maxEntries = MAX_LIST_ENTRIES, entryBytes = MAX_LIST_ENTRY_BYTES): string[] {
  const out = values.slice(0, maxEntries).map((v) => capText(v, entryBytes));
  if (values.length > maxEntries) out.push(`${ELLIPSIS} and ${values.length - maxEntries} more`);
  return out;
}

/** A key segment of a path, cut to {@link MAX_PATH_SEGMENT_CHARS}. */
export function capSegment(key: string): string {
  return key.length <= MAX_PATH_SEGMENT_CHARS ? key : `${key.slice(0, MAX_PATH_SEGMENT_CHARS - 1)}${ELLIPSIS}`;
}

/** A path, cut to {@link MAX_PATH_CHARS} (or `max`). */
export function capPath(path: string, max = MAX_PATH_CHARS): string {
  return path.length <= max ? path : `${path.slice(0, max - 1)}${ELLIPSIS}`;
}

/** Every text field of a finding within its byte bound. */
export function capFindingText(f: Finding): Finding {
  const title = capText(f.title, MAX_TITLE_BYTES);
  const message = f.message === undefined ? undefined : capText(f.message, MAX_MESSAGE_BYTES);
  const snippet = f.snippet === undefined ? undefined : capText(f.snippet, MAX_SNIPPET_BYTES);
  if (title === f.title && message === f.message && snippet === f.snippet) return f;
  return {
    ...f,
    title,
    ...(message === undefined ? {} : { message }),
    ...(snippet === undefined ? {} : { snippet }),
  };
}

const RANK: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

/** What a summary finding stands for: counted, so a summary dropped by the total cap is not lost. */
interface Tally {
  count: number;
  rules: Map<string, number>;
  worst: Severity;
}

function emptyTally(): Tally {
  return { count: 0, rules: new Map(), worst: 'info' };
}

function addToTally(t: Tally, rule: string, count: number, severity: Severity): void {
  t.count += count;
  t.rules.set(rule, (t.rules.get(rule) ?? 0) + count);
  if (RANK[severity] > RANK[t.worst]) t.worst = severity;
}

function mergeTally(into: Tally, from: Tally): void {
  for (const [rule, n] of from.rules) addToTally(into, rule, n, from.worst);
}

/** The `keep` most severe of `findings`, in their original order, and the rest. */
function mostSevere(findings: readonly Finding[], keep: number): { kept: Finding[]; dropped: Finding[] } {
  if (findings.length <= keep) return { kept: [...findings], dropped: [] };
  const order = findings.map((f, i) => ({ f, i }));
  order.sort((a, b) => RANK[b.f.severity] - RANK[a.f.severity] || a.i - b.i);
  const keepIdx = new Set(order.slice(0, keep).map((o) => o.i));
  return {
    kept: findings.filter((_, i) => keepIdx.has(i)),
    dropped: findings.filter((_, i) => !keepIdx.has(i)),
  };
}

function summary(tally: Tally, where: string, filePath: string): Finding {
  const rules = [...tally.rules.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .map(([rule, n]) => `${rule} ×${n}`);
  return capFindingText(
    makeFinding({
      tool: 'mcp-tool-audit',
      rule_id: CAPPED_RULE_ID,
      // As severe as the worst it stands for: a summary must not hide a high.
      severity: tally.worst,
      category: 'security',
      subcategory: 'mcp_tool_poisoning',
      title: `${where}: ${tally.count} more findings not listed`,
      message:
        `${tally.count} more findings ${where === 'audit_mcp_tools' ? 'of this audit' : `for ${where}`} were not ` +
        `listed or stored — the output keeps the ${MAX_FINDINGS_PER_SERVER} most severe per server and ` +
        `${MAX_FINDINGS_TOTAL} in all. By rule: ${rules.join(', ')}. The most severe of them is ${tally.worst}. ` +
        'Audit fewer servers at a time, or read the definitions themselves, to see each one.',
      file_path: filePath,
      snippet: `${where}: ${rules.join(', ')}`,
      fix_available: false,
    }),
  );
}

export interface ServerFindings {
  /** How the summary names the server: `MCP server 'x'`. */
  label: string;
  /** Its config file: the summary's `file_path`. */
  sourceLabel: string;
  findings: readonly Finding[];
}

/**
 * The findings the audit returns and stores: each within its byte bounds,
 * at most {@link MAX_FINDINGS_PER_SERVER} per server and
 * {@link MAX_FINDINGS_TOTAL} in all, each cap followed by one summary.
 */
export function capFindings(servers: readonly ServerFindings[]): Finding[] {
  const tallies = new Map<Finding, Tally>();
  const all: Finding[] = [];
  for (const s of servers) {
    const { kept, dropped } = mostSevere(s.findings, MAX_FINDINGS_PER_SERVER);
    all.push(...kept.map(capFindingText));
    if (dropped.length === 0) continue;
    const tally = emptyTally();
    for (const f of dropped) addToTally(tally, f.rule_id ?? f.tool, 1, f.severity);
    const s0 = summary(tally, s.label, s.sourceLabel);
    tallies.set(s0, tally);
    all.push(s0);
  }
  if (all.length <= MAX_FINDINGS_TOTAL) return all;
  const { kept, dropped } = mostSevere(all, MAX_FINDINGS_TOTAL);
  const tally = emptyTally();
  for (const f of dropped) {
    const inner = tallies.get(f);
    if (inner === undefined) addToTally(tally, f.rule_id ?? f.tool, 1, f.severity);
    else mergeTally(tally, inner);
  }
  return [...kept, summary(tally, 'audit_mcp_tools', servers[0]?.sourceLabel ?? '')];
}
