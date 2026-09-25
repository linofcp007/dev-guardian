/**
 * `license_compatibility` — cross-check the project's declared license
 * against the licenses of its dependencies. Flags incompatibilities
 * (e.g. MIT project pulling AGPL-3.0 dep is a legal problem, not just a
 * style one).
 *
 * Read-only: consumes the latest compliance_check / deps scan from
 * storage. Does not spawn scanners.
 *
 * Compatibility rules are simplified — full license law is nuanced. The
 * tool reports facts; the model (or a human lawyer) decides.
 */

import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import type { PluginContext } from '../context.js';
import { resolveProjectPath } from '../platform/projectPath.js';
import { ProjectPath } from '../schemas.js';
import type { DomainError, ToolResult } from '../types.js';
import { registerToolModule, type ToolModule } from './index.js';

interface LicenseEntry {
  license: string;
  packages: string[];
  risk: string;
}

interface IncompatibilityRow {
  project_license: string;
  dep_license: string;
  packages: string[];
  reason: string;
}

const tool: ToolModule = {
  name: 'license_compatibility',
  title: 'License compatibility check',
  description:
    'Cross-check the project license (package.json incl. UNLICENSED, pyproject.toml, composer.json, ' +
    '.csproj PackageLicenseExpression, or LICENSE) against the licenses of installed deps captured ' +
    'by the most recent compliance_check. No declared license (or UNLICENSED) is treated as ' +
    'proprietary and still flags copyleft deps. Pure SQL read — does not spawn scanners.',
  inputSchema: { project_path: ProjectPath },
  handler: async (input, ctx) => handler(input, ctx),
};

registerToolModule(tool);

async function handler(
  input: Record<string, unknown>,
  ctx: PluginContext,
): Promise<ToolResult<Record<string, unknown>>> {
  const inp = input as { project_path?: string };
  let projectPath: string;
  try {
    projectPath = resolveProjectPath(inp.project_path).path;
  } catch (e) {
    return failDomain('not_a_git_repo', (e as Error).message);
  }

  const projectLicense = detectProjectLicense(projectPath);
  // No declared license (the normal case for proprietary client work) and
  // npm's own `UNLICENSED` (which means exactly that — "no permission
  // granted", not to be confused with the public-domain `Unlicense`) are
  // the SAME legal position: all rights reserved. Both used to return zero
  // issues unconditionally, because the loop below only ran when
  // `projectLicense` was a known permissive/copyleft label — the most
  // common real case (nothing declared) skipped every check. A closed
  // project with no declared terms is the LEAST tolerant position of any
  // license this tool models, not the most: any copyleft dependency risks
  // an obligation nothing here has agreed to.
  const isProprietary = projectLicense === null || projectLicense.trim().toUpperCase() === 'UNLICENSED';
  const compliance = findLatestCompliance(ctx);
  const meta = compliance?.meta as { licenses_summary?: LicenseEntry[] } | undefined;
  const depLicenses = meta?.licenses_summary ?? [];

  const incompatibilities: IncompatibilityRow[] = [];
  for (const entry of depLicenses) {
    const reason = isProprietary
      ? proprietaryReason(entry.license)
      : incompatibleReason(projectLicense as string, entry.license);
    if (reason) {
      incompatibilities.push({
        project_license: projectLicense ?? 'proprietary (no license declared)',
        dep_license: entry.license,
        packages: entry.packages,
        reason,
      });
    }
  }

  return {
    ok: true,
    project_license: projectLicense ?? null,
    treated_as_proprietary: isProprietary,
    last_compliance_scan_id: compliance?.scan_id ?? null,
    dependencies_audited: depLicenses.length,
    incompatibilities,
    summary: {
      total: incompatibilities.length,
      by_dep_license: groupByLicense(incompatibilities),
    },
    notes:
      'Compatibility rules are heuristic — definitive guidance requires legal review. ' +
      'A "reciprocal" license (GPL/AGPL/SSPL) included in a permissive project requires the ' +
      'whole project to be released under the same terms when distributed. No declared license ' +
      '(and npm\'s UNLICENSED) is treated as proprietary/all-rights-reserved — the least ' +
      'tolerant position, not an exemption from these checks.',
  };
}

function detectProjectLicense(projectPath: string): string | null {
  // Prefer machine-readable sources before LICENSE file headers.
  try {
    const pkgPath = join(projectPath, 'package.json');
    if (existsSync(pkgPath)) {
      const pkg = JSON.parse(readFileSync(pkgPath, 'utf8')) as { license?: unknown };
      if (typeof pkg.license === 'string') return pkg.license;
    }
  } catch {
    /* ignore */
  }
  try {
    const pyProject = join(projectPath, 'pyproject.toml');
    if (existsSync(pyProject)) {
      const raw = readFileSync(pyProject, 'utf8');
      const m = /license\s*=\s*["']([^"']+)["']/i.exec(raw) ??
        /license-expression\s*=\s*["']([^"']+)["']/i.exec(raw);
      if (m && m[1]) return m[1];
    }
  } catch {
    /* ignore */
  }
  try {
    const composer = join(projectPath, 'composer.json');
    if (existsSync(composer)) {
      const cjson = JSON.parse(readFileSync(composer, 'utf8')) as { license?: unknown };
      if (typeof cjson.license === 'string') return cjson.license;
      if (Array.isArray(cjson.license) && typeof cjson.license[0] === 'string')
        return cjson.license[0];
    }
  } catch {
    /* ignore */
  }
  try {
    // .NET: `<PackageLicenseExpression>` in the first .csproj found at the
    // project root — same shallow, root-only scope as every other manifest
    // check in this function (never a recursive walk).
    const csproj = findFirstCsproj(projectPath);
    if (csproj) {
      const xml = readFileSync(csproj, 'utf8');
      const m = /<PackageLicenseExpression>([^<]+)<\/PackageLicenseExpression>/i.exec(xml);
      if (m && m[1]) return m[1].trim();
    }
  } catch {
    /* ignore */
  }
  // Last resort: peek at LICENSE / LICENSE.md / LICENSE.txt header.
  for (const name of ['LICENSE', 'LICENSE.md', 'LICENSE.txt', 'COPYING']) {
    const p = join(projectPath, name);
    if (!existsSync(p)) continue;
    try {
      const head = readFileSync(p, 'utf8').slice(0, 500);
      if (/MIT License/i.test(head)) return 'MIT';
      if (/Apache License,?\s*Version\s*2/i.test(head)) return 'Apache-2.0';
      if (/BSD 3-Clause/i.test(head)) return 'BSD-3-Clause';
      if (/BSD 2-Clause/i.test(head)) return 'BSD-2-Clause';
      if (/GNU Affero General Public License/i.test(head)) return 'AGPL-3.0';
      if (/GNU General Public License/i.test(head) && /version 3/i.test(head)) return 'GPL-3.0';
      if (/GNU General Public License/i.test(head) && /version 2/i.test(head)) return 'GPL-2.0';
      if (/Mozilla Public License/i.test(head)) return 'MPL-2.0';
      if (/ISC License/i.test(head)) return 'ISC';
    } catch {
      /* ignore */
    }
  }
  return null;
}

interface ComplianceRow {
  scan_id: string;
  meta?: unknown;
}

function findLatestCompliance(ctx: PluginContext): ComplianceRow | null {
  const history = ctx.storage.scans.listHistory(50);
  const row = history.find((s) => s.scan_type === 'compliance' && s.status === 'completed');
  if (!row) return null;
  const full = ctx.storage.scans.getById(row.scan_id);
  return full ? { scan_id: row.scan_id, meta: full.meta } : null;
}

/**
 * Heuristic compatibility table. Returns the reason as a string when the
 * combination is risky/incompatible, or null when it's fine.
 *
 * The rule of thumb: more permissive project + more restrictive dep = risk.
 * The same dep is fine in a project of the same or stricter terms.
 */
const PERMISSIVE = new Set([
  'MIT',
  'ISC',
  'Apache-2.0',
  'BSD-2-Clause',
  'BSD-3-Clause',
  'CC0-1.0',
  'Unlicense',
  '0BSD',
]);
const AGPL = new Set(['AGPL-1.0', 'AGPL-3.0']);
const VIRAL = new Set(['AGPL-1.0', 'AGPL-3.0', 'GPL-2.0', 'GPL-3.0', 'SSPL-1.0', 'OSL-3.0']);
const WEAK_COPYLEFT = new Set(['LGPL-2.1', 'LGPL-3.0', 'MPL-2.0', 'EPL-2.0']);
const COMMERCIAL = new Set(['BUSL-1.1', 'Elastic-2.0', 'CommonsClause']);

function incompatibleReason(projectLicense: string, depLicense: string): string | null {
  const proj = normaliseLicense(projectLicense);
  const dep = normaliseLicense(depLicense);

  // AGPL is checked before the generic viral case: unlike GPL, its network-
  // use clause is triggered by making the software available over a
  // network (a SaaS deployment) even when nothing is ever distributed —
  // the generic "distributing the combined work" wording below would
  // understate the risk for exactly this dependency.
  if (PERMISSIVE.has(proj) && AGPL.has(dep)) {
    return (
      `Permissive project '${projectLicense}' includes AGPL dependency '${depLicense}'. Unlike GPL, ` +
      `AGPL's network-use clause is triggered by making the software available over a network ` +
      `(e.g. SaaS) even without ever distributing binaries — review before any network deployment.`
    );
  }
  if (PERMISSIVE.has(proj) && VIRAL.has(dep)) {
    return `Permissive project '${projectLicense}' includes viral copyleft dep '${depLicense}'. Distributing the combined work requires releasing the whole project under '${depLicense}'.`;
  }
  if (PERMISSIVE.has(proj) && WEAK_COPYLEFT.has(dep)) {
    return `Permissive project '${projectLicense}' includes weak-copyleft dep '${depLicense}'. Static linking / bundling may require sources of the dep to be available; safe when linked dynamically.`;
  }
  if (PERMISSIVE.has(proj) && COMMERCIAL.has(dep)) {
    return `Permissive project '${projectLicense}' includes a source-available-but-not-OSI license '${depLicense}'. Restricts deployment models — review the dep's specific terms.`;
  }
  // GPL-2.0-only vs Apache-2.0: normaliseLicense strips both the "-only" and
  // "-or-later" SPDX suffixes, so this also catches a dependency declared
  // exactly as GPL-2.0-only (as opposed to GPL-2.0-or-later, which can move
  // to GPL-3.0 and does not carry this specific incompatibility).
  if (proj === 'GPL-2.0' && dep === 'Apache-2.0') {
    return `GPL-2.0 project + Apache-2.0 dep: known incompatibility (patent termination clauses). Move to GPL-3.0 or replace the dep.`;
  }
  if (proj === 'AGPL-3.0' && COMMERCIAL.has(dep)) {
    return `AGPL-3.0 project + commercial-source-available dep '${depLicense}': mutually exclusive distribution terms.`;
  }
  return null;
}

/**
 * No project license declared (or npm's `UNLICENSED`) is treated as
 * proprietary/all-rights-reserved — the LEAST tolerant position, so a
 * copyleft dependency is flagged here even though no project license was
 * ever entered into `incompatibleReason`'s permissive/dep table above.
 */
function proprietaryReason(depLicense: string): string | null {
  const dep = normaliseLicense(depLicense);
  if (AGPL.has(dep)) {
    return (
      `No project license declared (treated as proprietary/all-rights-reserved). AGPL dependency ` +
      `'${depLicense}' triggers its network-use clause: even SaaS deployment without redistributing ` +
      `binaries requires releasing source to users interacting with it over a network — incompatible ` +
      `with a closed-source project.`
    );
  }
  if (VIRAL.has(dep)) {
    return (
      `No project license declared (treated as proprietary). Viral copyleft dependency '${depLicense}' ` +
      `requires the combined work to be released under '${depLicense}' when distributed — incompatible ` +
      `with closed-source distribution.`
    );
  }
  if (WEAK_COPYLEFT.has(dep)) {
    return (
      `No project license declared (treated as proprietary). Weak-copyleft dependency '${depLicense}' ` +
      `may require its own source to stay available if statically linked/bundled — review before ` +
      `distributing.`
    );
  }
  if (COMMERCIAL.has(dep)) {
    return (
      `No project license declared (treated as proprietary). Dependency '${depLicense}' is source-` +
      `available but not OSI-approved, restricting deployment models — review its specific terms.`
    );
  }
  return null;
}

function normaliseLicense(s: string): string {
  return s
    .trim()
    .replace(/^["']|["']$/g, '')
    .replace(/[-_]or[-_]later$/i, '')
    .replace(/[-_]only$/i, '')
    .replace(/\s+/g, '');
}

/** First `.csproj` at the project root, in directory listing order — same
 *  shallow, root-only scope as every other manifest check in this file. */
function findFirstCsproj(projectPath: string): string | null {
  try {
    const name = readdirSync(projectPath)
      .filter((n) => n.toLowerCase().endsWith('.csproj'))
      .sort()[0];
    return name ? join(projectPath, name) : null;
  } catch {
    return null;
  }
}

function groupByLicense(rows: IncompatibilityRow[]): Record<string, number> {
  const out: Record<string, number> = {};
  for (const r of rows) {
    out[r.dep_license] = (out[r.dep_license] ?? 0) + r.packages.length;
  }
  return out;
}

function failDomain(
  code: DomainError['code'],
  message: string,
): ToolResult<Record<string, unknown>> {
  return { ok: false, error: { code, message } };
}
