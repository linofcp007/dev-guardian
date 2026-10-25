/**
 * SpotBugs SARIF parser (`-sarif -output <file>`, SpotBugs 4.10 with
 * FindSecBugs) — the security findings of compiled Java and Kotlin
 * (`runners/spotbugsRun.ts` keeps only the SECURITY and MALICIOUS_CODE
 * categories).
 *
 * A result names its source relative to the `-sourcepath` root it was found
 * under: `uriBaseId` → `originalUriBaseIds[id].uri` (`file:/C:/p/src/main/
 * java/`), joined with `uri` (`com/example/App.java`). One whose source was
 * not found has no base: it is matched against the project's own files by
 * that suffix — else, as Kotlin need not mirror its package in its
 * directories, by the file name alone — and kept as written when none or
 * several match. Each rule
 * carries its CWE (`relationships`, toolComponent `CWE`), which the finding
 * takes. Every SpotBugs level is coarse (FindSecBugs' injections are
 * `warning`), so the CWE weighs in: an injection, an unsafe deserialisation,
 * XXE, a path traversal or a forged request is `high`; otherwise `error` is
 * `high`, `warning` `medium`, `note` `low`.
 */

import { fileURLToPath } from 'node:url';
import type { Finding, Severity } from '../../types.js';
import {
  asArray,
  getNumber,
  getProp,
  getString,
  makeFinding,
  parseInputAsJson,
  toRelativeIfPossible,
  type ParserContext,
  type ParserOutput,
  type ScannerParser,
} from './index.js';

const SPOTBUGS_TOOL_NAME = 'spotbugs';

/** CWEs whose finding is `high` whatever SpotBugs' level (see the module comment). */
const HIGH_CWES = new Set(['22', '78', '89', '90', '91', '94', '95', '502', '611', '643', '917', '918', '943']);

const LEVEL: Readonly<Record<string, Severity>> = { error: 'high', warning: 'medium', note: 'low' };

interface RuleInfo {
  cwe?: string;
  title?: string;
}

/** The parser, with the project's files (project-relative, `/`-separated) a source without a base is matched against. */
export function spotbugsParserFor(projectFiles: readonly string[]): ScannerParser {
  return {
    name: SPOTBUGS_TOOL_NAME,
    parse(input: unknown, ctx: ParserContext = {}): ParserOutput {
      const findings: Finding[] = [];
      for (const run of asArray(getProp(parseInputAsJson(input), 'runs'))) {
        const rules = ruleInfo(run);
        const bases = baseUris(run);
        for (const result of asArray(getProp(run, 'results'))) {
          const finding = mapResult(result, rules, bases, projectFiles, ctx);
          if (finding) findings.push(finding);
        }
      }
      return { findings, cves: [] };
    },
  };
}

/** Each rule's CWE and short description, by id. */
function ruleInfo(run: unknown): Map<string, RuleInfo> {
  const out = new Map<string, RuleInfo>();
  for (const rule of asArray(getProp(getProp(getProp(run, 'tool'), 'driver'), 'rules'))) {
    const id = getString(rule, 'id');
    if (id === undefined) continue;
    const info: RuleInfo = {};
    for (const rel of asArray(getProp(rule, 'relationships'))) {
      const target = getProp(rel, 'target');
      if (getString(getProp(target, 'toolComponent'), 'name') === 'CWE') {
        const cwe = getString(target, 'id');
        if (cwe !== undefined) info.cwe = cwe;
      }
    }
    const title = getString(getProp(rule, 'shortDescription'), 'text');
    if (title !== undefined) info.title = title.replace(/\.\s*$/, '');
    out.set(id, info);
  }
  return out;
}

/** `originalUriBaseIds`: id → the directory it stands for. */
function baseUris(run: unknown): Map<string, string> {
  const out = new Map<string, string>();
  const ids = getProp(run, 'originalUriBaseIds');
  if (ids === null || typeof ids !== 'object') return out;
  for (const [id, value] of Object.entries(ids as Record<string, unknown>)) {
    const uri = getString(value, 'uri');
    if (uri !== undefined) out.set(id, uri);
  }
  return out;
}

/** `file:/C:/p/src/main/java/` + `com/example/App.java` → `C:\p\src\main\java\com\example\App.java`. */
function resolvePath(uri: string, base: string | undefined): string {
  const joined = base !== undefined ? `${base.endsWith('/') ? base : `${base}/`}${uri}` : uri;
  if (!joined.startsWith('file:')) return joined;
  try {
    return fileURLToPath(joined.replace(/^file:\/(?!\/)/, 'file:///'));
  } catch {
    return joined;
  }
}

/** A source SpotBugs did not find under a root: the one project file that ends with its package path, else as written. */
function bySuffix(uri: string, files: readonly string[]): string {
  const matches = files.filter((f) => f === uri || f.endsWith(`/${uri}`));
  if (matches.length === 1) return matches[0] ?? uri;
  if (matches.length > 1) return uri;
  // Kotlin need not mirror its package in its directories (`src/main/kotlin/net/Foo.kt` in
  // `package org.ex.net`): the one project file of that name, when there is exactly one.
  const name = uri.slice(uri.lastIndexOf('/') + 1);
  const named = files.filter((f) => f === name || f.endsWith(`/${name}`));
  return named.length === 1 ? (named[0] ?? uri) : uri;
}

function mapResult(
  raw: unknown,
  rules: Map<string, RuleInfo>,
  bases: Map<string, string>,
  files: readonly string[],
  ctx: ParserContext,
): Finding | null {
  const ruleId = getString(raw, 'ruleId');
  const location = getProp(asArray(getProp(raw, 'locations'))[0], 'physicalLocation');
  const artifact = getProp(location, 'artifactLocation');
  const uri = getString(artifact, 'uri');
  if (!ruleId || !uri) return null;
  const baseId = getString(artifact, 'uriBaseId');
  const base = baseId !== undefined ? bases.get(baseId) : undefined;
  const file = base !== undefined ? toRelativeIfPossible(resolvePath(uri, base), ctx.project_path) : bySuffix(uri, files);
  const info = rules.get(ruleId) ?? {};
  const message = getString(getProp(raw, 'message'), 'text') ?? info.title ?? ruleId;
  const line = getNumber(getProp(location, 'region'), 'startLine');
  const severity: Severity =
    info.cwe !== undefined && HIGH_CWES.has(info.cwe) ? 'high' : (LEVEL[getString(raw, 'level') ?? ''] ?? 'medium');
  const input: Parameters<typeof makeFinding>[0] = {
    tool: SPOTBUGS_TOOL_NAME,
    rule_id: ruleId,
    severity,
    category: 'security',
    subcategory: ruleId,
    title: info.title ?? message,
    message: `${ruleId}: ${message}`,
    file_path: file,
    fix_available: false,
    taxonomy: { cwe: info.cwe !== undefined ? `CWE-${info.cwe}` : undefined },
  };
  if (line !== undefined) {
    input.line_start = line;
    input.line_end = line;
  }
  return makeFinding(input);
}
