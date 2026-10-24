/**
 * govulncheck (`-format json`) parser — the vulnerable symbols a module's own
 * code calls (`runners/govulncheckRun.ts` has the stream's shape).
 *
 * Input: `{ moduleDir, report }` — the module's directory (project-relative,
 * `.` for the root) and its report, because a frame's `position.filename` is
 * relative to the module's root. One finding per (vulnerability, call site):
 * the call site is the frame of the trace nearest the vulnerable symbol that
 * belongs to the analysed module (its last frame is the entry point, always
 * the module's own). `rule_id` is the Go vulnerability id (`GO-2022-1059`),
 * its CVE and GHSA ids in `vuln_aliases`; `snippet` is `module@version`, the
 * shape `deps_audit` reads a dependency finding's package from. Severity is
 * `medium` here — the database gives none — and `deps_audit` takes Trivy's for
 * the same CVE when there is one.
 */

import type { Finding } from '../../types.js';
import { govulncheckMessages } from '../govulncheckRun.js';
import {
  asArray,
  dependencyTaxonomy,
  getNumber,
  getProp,
  getString,
  makeFinding,
  toPosixPath,
  type ParserOutput,
  type ScannerParser,
} from './index.js';

const GOVULNCHECK_TOOL_NAME = 'govulncheck';

export const govulncheckParser: ScannerParser = {
  name: GOVULNCHECK_TOOL_NAME,
  parse(input: unknown): ParserOutput {
    const moduleDir = getString(input, 'moduleDir') ?? '.';
    const messages = govulncheckMessages(getString(input, 'report') ?? '') ?? [];
    const osv = new Map<string, unknown>();
    for (const m of messages) {
      const entry = getProp(m, 'osv');
      const id = getString(entry, 'id');
      if (id !== undefined) osv.set(id, entry);
    }
    const findings: Finding[] = [];
    const seen = new Set<string>();
    for (const m of messages) {
      const finding = getProp(m, 'finding');
      const id = getString(finding, 'osv');
      const trace = asArray(getProp(finding, 'trace'));
      const symbol = trace[0];
      if (id === undefined || getString(symbol, 'function') === undefined) continue;
      const own = getString(trace.at(-1), 'module');
      const site = trace.slice(1).find((frame) => getString(frame, 'module') === own);
      const file = getString(getProp(site, 'position'), 'filename');
      const line = getNumber(getProp(site, 'position'), 'line');
      if (file === undefined) continue;
      const path = moduleDir === '.' ? toPosixPath(file) : `${moduleDir}/${toPosixPath(file)}`;
      const key = `${id}|${path}|${String(line)}`;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push(mapFinding(id, osv.get(id), finding, symbol, site, path, line));
    }
    return { findings, cves: [] };
  },
};

function qualified(frame: unknown): string {
  const pkg = getString(frame, 'package') ?? '';
  const fn = getString(frame, 'function') ?? '';
  const receiver = getString(frame, 'receiver');
  const name = receiver !== undefined ? `${receiver}.${fn}` : fn;
  return pkg !== '' ? `${pkg}.${name}` : name;
}

function mapFinding(
  id: string,
  entry: unknown,
  finding: unknown,
  symbol: unknown,
  site: unknown,
  path: string,
  line: number | undefined,
): Finding {
  const module = getString(symbol, 'module') ?? 'a dependency';
  const version = getString(symbol, 'version') ?? '';
  const fixed = getString(finding, 'fixed_version');
  const url = getString(getProp(entry, 'database_specific'), 'url') ?? `https://pkg.go.dev/vuln/${id}`;
  const summary = getString(entry, 'summary') ?? `${id} in ${module}`;
  const input: Parameters<typeof makeFinding>[0] = {
    tool: GOVULNCHECK_TOOL_NAME,
    rule_id: id,
    severity: 'medium',
    category: 'security',
    subcategory: 'dependency',
    title: summary,
    message:
      `${module}${version !== '' ? `@${version}` : ''}: ${qualified(site)} calls ${qualified(symbol)}, which is vulnerable ` +
      `(${id}); ${fixed !== undefined ? `fixed in ${fixed}` : 'no fixed version yet'} — ${url}`,
    file_path: path,
    fix_available: fixed !== undefined,
    snippet: `${module}@${version}`,
    taxonomy: dependencyTaxonomy(),
    vuln_aliases: asArray(getProp(entry, 'aliases')),
  };
  if (line !== undefined) {
    input.line_start = line;
    input.line_end = line;
  }
  return makeFinding(input);
}
