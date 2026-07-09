/**
 * `npm audit --json` output parser.
 *
 * npm has shipped two audit JSON shapes:
 *   - v2 (npm 7+, the current default): a `vulnerabilities` map keyed by
 *     package name. Each entry's `via` array holds either advisory *objects*
 *     (the real vulnerability — title/url/source/severity) or *strings*
 *     (a transitive reference to another vulnerable package, not its own
 *     advisory). We emit one Finding per distinct advisory object.
 *   - v1 (npm 6): an `advisories` map keyed by advisory id, each carrying
 *     `module_name`, `severity`, `cves`, etc.
 *
 * We handle both so the parser does not silently emit nothing on an older
 * lockfile. CVEs are only emitted from v1 (where `cves[]` is explicit); v2
 * advisory objects carry GHSA urls rather than reliable CVE ids, and Trivy
 * already populates the CVE table across stacks — npm audit's value here is
 * the GitHub-advisory coverage that turns into counted Findings.
 */

import type { Finding } from '../../types.js';
import {
  asArray,
  getNumber,
  getProp,
  getString,
  makeFinding,
  normalizeSeverity,
  parseInputAsJson,
  type ParserContext,
  type ParserCveInput,
  type ParserOutput,
  type ScannerParser,
} from './index.js';

export const NPM_AUDIT_TOOL_NAME = 'npm-audit';

export const npmAuditParser: ScannerParser = {
  name: NPM_AUDIT_TOOL_NAME,
  parse(input: unknown, ctx: ParserContext = {}): ParserOutput {
    const root = parseInputAsJson(input);
    const findings: Finding[] = [];
    const cves: ParserCveInput[] = [];
    const seen = new Set<string>();

    // --- npm 7+ (audit report v2) -----------------------------------------
    const vulns = getProp(root, 'vulnerabilities');
    if (vulns && typeof vulns === 'object') {
      for (const entry of Object.values(vulns as Record<string, unknown>)) {
        const fixAvailable = fixIsAvailable(getProp(entry, 'fixAvailable'));
        for (const via of asArray(getProp(entry, 'via'))) {
          // String `via` = "vulnerable because of another package" — the real
          // advisory is emitted under that other package. Skip to avoid noise.
          if (typeof via !== 'object' || via === null) continue;
          const finding = mapV2Advisory(via, fixAvailable, seen, ctx);
          if (finding) findings.push(finding);
        }
      }
    }

    // --- npm 6 (advisories map) -------------------------------------------
    const advisories = getProp(root, 'advisories');
    if (advisories && typeof advisories === 'object') {
      for (const adv of Object.values(advisories as Record<string, unknown>)) {
        const out = mapV1Advisory(adv, seen);
        if (out?.finding) findings.push(out.finding);
        if (out?.cves) cves.push(...out.cves);
      }
    }

    return { findings, cves };
  },
};

function fixIsAvailable(raw: unknown): boolean {
  if (typeof raw === 'boolean') return raw;
  // v2 may report `{ name, version, isSemVerMajor }` — presence means a fix.
  return raw !== null && typeof raw === 'object';
}

function mapV2Advisory(
  via: unknown,
  fixAvailable: boolean,
  seen: Set<string>,
  _ctx: ParserContext,
): Finding | null {
  const source = getNumber(via, 'source') ?? getString(via, 'source');
  const url = getString(via, 'url');
  const pkg = getString(via, 'name') ?? getString(via, 'dependency');
  const title = getString(via, 'title');
  if (source === undefined && !url && !title) return null;

  const key = `v2:${source ?? url ?? `${pkg}:${title}`}`;
  if (seen.has(key)) return null;
  seen.add(key);

  const range = getString(via, 'range');
  const input: Parameters<typeof makeFinding>[0] = {
    tool: NPM_AUDIT_TOOL_NAME,
    rule_id: String(source ?? url ?? pkg ?? 'npm-advisory'),
    severity: normalizeSeverity(getString(via, 'severity')),
    category: 'security',
    subcategory: 'dependency',
    title: title ?? `Vulnerability in ${pkg ?? 'a dependency'}`,
    file_path: 'package.json',
    fix_available: fixAvailable,
    snippet: `${pkg ?? ''}@${range ?? ''}`,
  };
  const message = composeMessage(pkg, range, url);
  if (message) input.message = message;
  return makeFinding(input);
}

function mapV1Advisory(
  adv: unknown,
  seen: Set<string>,
): { finding: Finding; cves: ParserCveInput[] } | null {
  const id = getNumber(adv, 'id') ?? getString(adv, 'id');
  const pkg = getString(adv, 'module_name');
  const title = getString(adv, 'title');
  if (!pkg && !title) return null;

  const key = `v1:${id ?? title}`;
  if (seen.has(key)) return null;
  seen.add(key);

  const severity = normalizeSeverity(getString(adv, 'severity'));
  const range = getString(adv, 'vulnerable_versions');
  const url = getString(adv, 'url');
  const recommendation = getString(adv, 'recommendation');

  const input: Parameters<typeof makeFinding>[0] = {
    tool: NPM_AUDIT_TOOL_NAME,
    rule_id: String(id ?? title),
    severity,
    category: 'security',
    subcategory: 'dependency',
    title: title ?? `Vulnerability in ${pkg}`,
    file_path: 'package.json',
    fix_available: recommendation ? /upgrad|updat/i.test(recommendation) : false,
    snippet: `${pkg ?? ''}@${range ?? ''}`,
  };
  const message = composeMessage(pkg, range, url ?? recommendation);
  if (message) input.message = message;

  const cves: ParserCveInput[] = [];
  for (const cveId of asArray(getProp(adv, 'cves'))) {
    if (typeof cveId === 'string' && /^CVE-\d/i.test(cveId)) {
      const cve: ParserCveInput = {
        cve_id: cveId,
        package_name: pkg ?? 'unknown',
        severity,
      };
      cves.push(cve);
    }
  }

  return { finding: makeFinding(input), cves };
}

function composeMessage(
  pkg: string | undefined,
  range: string | undefined,
  tail: string | undefined,
): string | undefined {
  const parts: string[] = [];
  if (pkg) parts.push(`package: ${pkg}`);
  if (range) parts.push(`vulnerable: ${range}`);
  if (tail) parts.push(tail);
  return parts.length > 0 ? parts.join(' · ') : undefined;
}
