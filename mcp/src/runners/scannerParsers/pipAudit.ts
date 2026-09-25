/**
 * `pip-audit --format json` output parser.
 *
 * Schema (pip-audit's own `--format json`, stable since 2.x):
 *
 *   { "dependencies": [
 *       { "name": "django", "version": "2.0.1", "vulns": [
 *           { "id": "PYSEC-2019-1234", "fix_versions": ["2.2.9"],
 *             "aliases": ["CVE-2019-19844"], "description": "…" }
 *       ] }
 *   ] }
 *
 * `id` is a PyPA/OSV advisory id, not a CVE — the CVE (when one exists) is
 * in `aliases`. Severity is not part of pip-audit's JSON output at all (its
 * OSV-sourced data routinely has none), so every finding here defaults to
 * `medium` via `normalizeSeverity(undefined)`, same as every other parser in
 * this module when the scanner itself is silent about severity.
 */

import type { Finding } from '../../types.js';
import {
  asArray,
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

export const PIP_AUDIT_TOOL_NAME = 'pip-audit';

export const pipAuditParser: ScannerParser = {
  name: PIP_AUDIT_TOOL_NAME,
  parse(input: unknown, _ctx: ParserContext = {}): ParserOutput {
    const root = parseInputAsJson(input);
    const findings: Finding[] = [];
    const cves: ParserCveInput[] = [];

    for (const dep of asArray(getProp(root, 'dependencies'))) {
      const name = getString(dep, 'name');
      if (!name) continue;
      const version = getString(dep, 'version');

      for (const vuln of asArray(getProp(dep, 'vulns'))) {
        const id = getString(vuln, 'id');
        if (!id) continue;
        const fixVersions = stringArray(getProp(vuln, 'fix_versions'));
        const aliases = stringArray(getProp(vuln, 'aliases'));
        const cveId = aliases.find((a) => /^CVE-\d/i.test(a));
        const description = getString(vuln, 'description');
        const severity = normalizeSeverity(undefined);

        const findingInput: Parameters<typeof makeFinding>[0] = {
          tool: PIP_AUDIT_TOOL_NAME,
          rule_id: id,
          severity,
          category: 'security',
          subcategory: 'dependency',
          title: `${id} in ${name}${version ? ` ${version}` : ''}`,
          fix_available: fixVersions.length > 0,
          file_path: 'requirements.txt',
          snippet: `${name}@${version ?? ''}`,
        };
        if (description !== undefined) findingInput.message = description;
        findings.push(makeFinding(findingInput));

        if (cveId) {
          const cve: ParserCveInput = { cve_id: cveId, package_name: name, severity };
          if (version !== undefined) cve.installed_version = version;
          const fixed = fixVersions[0];
          if (fixed !== undefined) cve.fixed_version = fixed;
          cves.push(cve);
        }
      }
    }

    return { findings, cves };
  },
};

function stringArray(value: unknown): string[] {
  return asArray(value).filter((v): v is string => typeof v === 'string');
}
