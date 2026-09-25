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

/**
 * A dependency license this tool could not classify as either compatible or
 * risky — an unrecognised SPDX id, or an OR/AND expression with an
 * unrecognised operand. Fix round 1, item 5: this used to fall through
 * `incompatibleReason`/`proprietaryReason` returning `null`, which reads
 * IDENTICALLY to "checked and fine" — an SPDX expression like
 * `MIT OR Apache-2.0` (whitespace-collapsed by the old `normaliseLicense`
 * into the unrecognisable `MITORApache-2.0`) or any license this table
 * simply does not know about silently reported zero issues. Reported
 * separately from `incompatibilities`, never silently merged into either
 * bucket: "unknown" and "known fine" are different findings.
 */
interface UndeterminedRow {
  project_license: string;
  dep_license: string;
  packages: string[];
  reason: string;
}

const tool: ToolModule = {
  name: 'license_compatibility',
  title: 'License compatibility check',
  description:
    'Cross-check the project license (package.json incl. UNLICENSED, pyproject.toml, composer.json ' +
    'incl. "proprietary"/"SEE LICENSE IN …", .csproj PackageLicenseExpression, or LICENSE) against ' +
    'the licenses of installed deps captured by the most recent compliance_check OF THIS PROJECT. ' +
    'No declared license (or a proprietary label) is treated as proprietary and still flags ' +
    'copyleft deps; an unrecognised or SPDX OR/AND dependency license is reported as ' +
    '`undetermined`, never silently compatible. Pure SQL read — does not spawn scanners.',
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
  // No declared license (the normal case for proprietary client work) and a
  // license label that IS a proprietary declaration (npm's `UNLICENSED`;
  // composer's own documented `"proprietary"` / `"Proprietary"` /
  // `"SEE LICENSE IN <file>"`) are the SAME legal position: all rights
  // reserved, terms unknown to this tool. All used to return zero issues
  // unconditionally, because the loop below only ran when `projectLicense`
  // was a known permissive/copyleft label — the most common real case
  // (nothing declared, or a proprietary label) skipped every check. A
  // closed project with no usable declared terms is the LEAST tolerant
  // position of any license this tool models, not the most: any copyleft
  // dependency risks an obligation nothing here has agreed to.
  const isProprietary = projectLicense === null || isProprietaryLabel(projectLicense);
  const compliance = findLatestCompliance(ctx, projectPath);
  const meta = compliance?.meta as { licenses_summary?: LicenseEntry[] } | undefined;
  const depLicenses = meta?.licenses_summary ?? [];

  const incompatibilities: IncompatibilityRow[] = [];
  const undetermined: UndeterminedRow[] = [];
  const reportedProjectLicense = projectLicense ?? 'proprietary (no license declared)';
  for (const entry of depLicenses) {
    const verdict = evaluateDependencyLicense(projectLicense, isProprietary, entry.license);
    if (verdict.kind === 'incompatible') {
      incompatibilities.push({
        project_license: reportedProjectLicense,
        dep_license: entry.license,
        packages: entry.packages,
        reason: verdict.reason,
      });
    } else if (verdict.kind === 'undetermined') {
      undetermined.push({
        project_license: reportedProjectLicense,
        dep_license: entry.license,
        packages: entry.packages,
        reason: verdict.reason,
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
    undetermined,
    summary: {
      total: incompatibilities.length,
      by_dep_license: groupByLicense(incompatibilities),
      undetermined_total: undetermined.length,
    },
    notes:
      'Compatibility rules are heuristic — definitive guidance requires legal review. ' +
      'A "reciprocal" license (GPL/AGPL/SSPL) included in a permissive project requires the ' +
      'whole project to be released under the same terms when distributed. No declared license ' +
      '(or a proprietary label) is treated as proprietary/all-rights-reserved — the least ' +
      'tolerant position, not an exemption from these checks. `undetermined` lists a dependency ' +
      'license this tool could not classify at all (unrecognised, or an SPDX OR/AND expression ' +
      'with an unrecognised operand) — never silently read as compatible.',
  };
}

/** npm's `UNLICENSED`, composer's documented `"proprietary"` /
 *  `"Proprietary"` / `"SEE LICENSE IN <file>"` — every label that itself
 *  DECLARES "no open terms granted", as opposed to a real SPDX license id
 *  this tool simply does not recognise (that case is `undetermined`, not
 *  proprietary — see `evaluateDependencyLicense`). */
function isProprietaryLabel(s: string): boolean {
  const t = s.trim();
  return /^UNLICENSED$/i.test(t) || /^proprietary$/i.test(t) || /^SEE LICENSE IN /i.test(t);
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

/** `listHistoryForProject`, never `listHistory` (fix round 1, item 5): the
 *  latter is unscoped across the WHOLE database, so a `compliance_check` of
 *  a DIFFERENT project on the same server could win here and attribute its
 *  dependency licenses to this one — the exact class of bug already fixed
 *  for `deps_update_plan`'s CVE source (`scansRepo.ts`'s own module
 *  comment). Filtered to `status === 'completed'` in JS, matching that same
 *  file's convention for its project-scoped siblings. */
function findLatestCompliance(ctx: PluginContext, projectPath: string): ComplianceRow | null {
  const history = ctx.storage.scans.listHistoryForProject(projectPath, 50);
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
 *
 * Every GPL-family id is listed in all three SPDX forms — bare (the
 * deprecated, ambiguous form), `-only` and `-or-later` — rather than
 * normalising away the suffix. `normaliseLicense` used to strip BOTH
 * suffixes, treating `GPL-2.0-or-later` identically to `GPL-2.0-only`; that
 * silently exempted `-or-later` from the checks below entirely (a stale
 * assumption a previous version of this file's own comment asserted
 * without a test — fix round 1, item 5). `-or-later` still carries the SAME
 * risk here: the recipient must actually exercise the "or later" option and
 * relicense before the specific incompatibility goes away, which this tool
 * cannot verify happened, so it is flagged too — with a different reason
 * than `-only`, which has no such escape at all.
 */
function withSuffixes(...bases: string[]): Set<string> {
  const out = new Set<string>();
  for (const b of bases) {
    out.add(b);
    out.add(`${b}-only`);
    out.add(`${b}-or-later`);
  }
  return out;
}

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
const AGPL = withSuffixes('AGPL-1.0', 'AGPL-3.0');
const VIRAL = withSuffixes('AGPL-1.0', 'AGPL-3.0', 'GPL-2.0', 'GPL-3.0', 'SSPL-1.0', 'OSL-3.0');
const WEAK_COPYLEFT = new Set(['LGPL-2.1', 'LGPL-3.0', 'MPL-2.0', 'EPL-2.0']);
const COMMERCIAL = new Set(['BUSL-1.1', 'Elastic-2.0', 'CommonsClause']);
/** Every license id this table has an opinion about — anything else is
 *  `undetermined`, never silently compatible (fix round 1, item 5). */
const KNOWN_LICENSES = new Set<string>([...PERMISSIVE, ...VIRAL, ...WEAK_COPYLEFT, ...COMMERCIAL]);

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
  // GPL-2.0 (any SPDX suffix form) vs Apache-2.0: the patent-termination
  // incompatibility. `-or-later` gets a DIFFERENT reason: the project could
  // avoid it by actually relicensing under GPL-3.0, which this tool cannot
  // confirm happened, so it is flagged with that escape named rather than
  // silently exempted.
  if ((proj === 'GPL-2.0' || proj === 'GPL-2.0-only' || proj === 'GPL-2.0-or-later') && dep === 'Apache-2.0') {
    const escape =
      proj === 'GPL-2.0-or-later'
        ? ' The project may avoid this by exercising its "or-later" option and relicensing under ' +
          'GPL-3.0, which has no such incompatibility with Apache-2.0 — until that relicensing is ' +
          'done explicitly, the two remain in tension.'
        : '';
    return `GPL-2.0 project + Apache-2.0 dep: known incompatibility (patent termination clauses).${escape} Move to GPL-3.0 or replace the dep.`;
  }
  if ((proj === 'AGPL-3.0' || proj === 'AGPL-3.0-only' || proj === 'AGPL-3.0-or-later') && COMMERCIAL.has(dep)) {
    return `AGPL-3.0 project + commercial-source-available dep '${depLicense}': mutually exclusive distribution terms.`;
  }
  return null;
}

/**
 * No project license declared (or a proprietary label) is treated as
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

type SingleVerdict = { kind: 'ok' } | { kind: 'risky'; reason: string } | { kind: 'unknown' };

/** Verdict for one, already-split license id — never an OR/AND expression.
 *  'unknown' when `dep` is not in ANY of the tables above at all: this is
 *  the case `incompatibleReason`/`proprietaryReason` used to collapse into
 *  "returns null" (indistinguishable from "checked, and it's fine"). */
function classifySingleLicense(
  projectLicense: string | null,
  isProprietary: boolean,
  depLicenseRaw: string,
): SingleVerdict {
  const dep = normaliseLicense(depLicenseRaw);
  if (!KNOWN_LICENSES.has(dep)) return { kind: 'unknown' };
  const reason = isProprietary
    ? proprietaryReason(depLicenseRaw)
    : incompatibleReason(projectLicense as string, depLicenseRaw);
  return reason ? { kind: 'risky', reason } : { kind: 'ok' };
}

type DependencyVerdict =
  | { kind: 'ok' }
  | { kind: 'incompatible'; reason: string }
  | { kind: 'undetermined'; reason: string };

/**
 * A dependency's license, which may be a single SPDX id or an `OR`/`AND`
 * expression (`"MIT OR Apache-2.0"`, `"GPL-2.0-only AND Apache-2.0"`) — fix
 * round 1, item 5. Only flat, TOP-LEVEL `OR`/`AND` is handled (no
 * parenthesised nesting); a more complex expression falls through to the
 * same `undetermined` outcome as a single unrecognised license, which is
 * the honest answer either way — this tool was never going to resolve
 * nested boolean license logic, and the alternative (silently reading it as
 * compatible) is exactly the defect being fixed.
 *
 *   - **OR** (the licensee may pick either): compatible if ANY operand is a
 *     recognised, compatible option. Incompatible only if EVERY operand is
 *     recognised AND risky. Undetermined if no operand is compatible and at
 *     least one is unrecognised — picking the unknown one might be fine,
 *     might not be; this tool cannot tell.
 *   - **AND** (a dual-licensed dependency; both sets of terms apply): risky
 *     if ANY operand is risky (every term binds, so one risky term makes
 *     the whole combination risky). Undetermined if none are risky but at
 *     least one is unrecognised.
 */
function evaluateDependencyLicense(
  projectLicense: string | null,
  isProprietary: boolean,
  depLicenseRaw: string,
): DependencyVerdict {
  const expr = parseLicenseExpression(depLicenseRaw);

  if (expr.kind === 'single') {
    const v = classifySingleLicense(projectLicense, isProprietary, expr.parts[0] ?? depLicenseRaw);
    if (v.kind === 'ok') return { kind: 'ok' };
    if (v.kind === 'risky') return { kind: 'incompatible', reason: v.reason };
    return {
      kind: 'undetermined',
      reason: `License '${depLicenseRaw}' is not one this tool recognises — compatibility could not be determined. Review manually.`,
    };
  }

  const verdicts = expr.parts.map((p) => classifySingleLicense(projectLicense, isProprietary, p));
  if (expr.kind === 'or') {
    if (verdicts.some((v) => v.kind === 'ok')) return { kind: 'ok' };
    if (verdicts.every((v) => v.kind === 'risky')) {
      const reasons = verdicts.flatMap((v) => (v.kind === 'risky' ? [v.reason] : []));
      return { kind: 'incompatible', reason: `Every option in SPDX OR expression '${depLicenseRaw}' is risky — ${reasons.join(' | ')}` };
    }
    return {
      kind: 'undetermined',
      reason: `SPDX OR expression '${depLicenseRaw}' includes an unrecognised option — compatibility could not be fully determined. Review manually.`,
    };
  }

  // AND: every term binds.
  const risky = verdicts.find((v) => v.kind === 'risky');
  if (risky && risky.kind === 'risky') {
    return { kind: 'incompatible', reason: `SPDX AND expression '${depLicenseRaw}': ${risky.reason}` };
  }
  if (verdicts.some((v) => v.kind === 'unknown')) {
    return {
      kind: 'undetermined',
      reason: `SPDX AND expression '${depLicenseRaw}' includes an unrecognised term — compatibility could not be fully determined. Review manually.`,
    };
  }
  return { kind: 'ok' };
}

type LicenseExpression =
  | { kind: 'single'; parts: [string] }
  | { kind: 'or'; parts: string[] }
  | { kind: 'and'; parts: string[] };

/** Splits on a top-level ` OR ` / ` AND ` (case-insensitive, whichever
 *  appears — SPDX expressions do not mix the two without parentheses to
 *  disambiguate precedence, which this parser does not attempt). */
function parseLicenseExpression(raw: string): LicenseExpression {
  const orParts = raw.split(/\s+OR\s+/i).map((s) => s.trim()).filter(Boolean);
  if (orParts.length > 1) return { kind: 'or', parts: orParts };
  const andParts = raw.split(/\s+AND\s+/i).map((s) => s.trim()).filter(Boolean);
  if (andParts.length > 1) return { kind: 'and', parts: andParts };
  return { kind: 'single', parts: [raw.trim()] };
}

function normaliseLicense(s: string): string {
  return s
    .trim()
    .replace(/^["']|["']$/g, '')
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
