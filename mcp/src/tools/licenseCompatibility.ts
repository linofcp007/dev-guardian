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
    'copyleft deps; an unrecognised or SPDX OR/AND expression on EITHER side (project or ' +
    'dependency) is reported as `undetermined`, never silently compatible. Pure SQL read — does ' +
    'not spawn scanners.',
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
 * Every GNU-family id is listed in all three SPDX forms — bare (the
 * deprecated form, which SPDX defines as `-only`), `-only` and `-or-later` —
 * rather than normalising the suffix away: `GPL-2.0-or-later` and
 * `GPL-2.0-only` are different licenses for compatibility purposes (see
 * `gnuVersions`).
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
const WEAK_COPYLEFT = new Set([...withSuffixes('LGPL-2.0', 'LGPL-2.1', 'LGPL-3.0'), 'MPL-2.0', 'EPL-2.0']);
const COMMERCIAL = new Set(['BUSL-1.1', 'Elastic-2.0', 'CommonsClause']);
/** Every license id this table has an opinion about — anything else is
 *  `undetermined`, never silently compatible (fix round 1, item 5). */
const KNOWN_LICENSES = new Set<string>([...PERMISSIVE, ...VIRAL, ...WEAK_COPYLEFT, ...COMMERCIAL]);

/** The versions each GNU license family was published in. */
const GNU_VERSIONS: Record<'GPL' | 'AGPL' | 'LGPL', string[]> = {
  GPL: ['1.0', '2.0', '3.0'],
  AGPL: ['1.0', '3.0'],
  LGPL: ['2.0', '2.1', '3.0'],
};

interface GnuTerms {
  family: 'GPL' | 'AGPL' | 'LGPL';
  /** Every version a work under this id may be distributed under: one for
   *  `-only` (and the bare form, which SPDX defines as `-only`), that one and
   *  every later one for `-or-later`. */
  versions: string[];
}

function gnuVersions(id: string): GnuTerms | null {
  const m = /^(AGPL|LGPL|GPL)-(\d\.\d)(-only|-or-later)?$/.exec(id);
  const family = m?.[1];
  const version = m?.[2];
  if ((family !== 'GPL' && family !== 'AGPL' && family !== 'LGPL') || version === undefined) return null;
  const all = GNU_VERSIONS[family];
  if (!all.includes(version)) return null;
  const versions = m?.[3] === '-or-later' ? all.filter((v) => Number(v) >= Number(version)) : [version];
  return { family, versions };
}

/** The GPL versions an LGPL-licensed work may be relicensed under — LGPL-2.x
 *  section 3 allows GPL-2.0 "or any later version"; LGPL-3.0 is GPL-3.0 plus
 *  extra permissions, so GPL-3.0 only. */
function lgplAsGpl(lgpl: GnuTerms): string[] {
  return lgpl.versions.some((v) => v !== '3.0') ? ['2.0', '3.0'] : ['3.0'];
}

/**
 * GNU-family pairs, decided by VERSION rather than by name: a combination is
 * fine when some one version of the license is allowed by both sides — the
 * combined work is distributed under that version. This is what makes
 * `GPL-2.0-only` + `GPL-2.0-only` fine (it was `undetermined`), `GPL-2.0-only`
 * + `GPL-3.0-only` incompatible (no common version), and
 * `GPL-2.0-or-later` + `GPL-3.0` fine (the project elects GPL-3.0). An LGPL
 * dependency in a GPL project is read as the GPL versions it may be
 * relicensed under. `null` for any pair outside those families.
 */
function gnuPairVerdict(proj: string, dep: string): SingleVerdict | null {
  const p = gnuVersions(proj);
  const d = gnuVersions(dep);
  if (!p || !d) return null;
  let depVersions: string[];
  if (p.family === d.family) depVersions = d.versions;
  else if (p.family === 'GPL' && d.family === 'LGPL') depVersions = lgplAsGpl(d);
  else return null;
  const common = p.versions.filter((v) => depVersions.includes(v));
  if (common.length > 0) return { kind: 'ok' };
  const fam = p.family;
  return {
    kind: 'risky',
    reason:
      `${proj} project + ${dep} dependency: no ${fam} version both allow — the project can only be ` +
      `distributed under ${fam}-${p.versions.join(`/${fam}-`)}, the dependency only under ` +
      `${fam}-${depVersions.join(`/${fam}-`)}.`,
  };
}

/** A version-accurate description of an AGPL dependency's network clause:
 *  AGPL-3.0's section 13 and AGPL-1.0's section 2(d) are different
 *  obligations, and AGPL-1.0 is built on GPL-2.0, not GPL-3.0. */
function agplNetworkClause(dep: string): string {
  if (dep.startsWith('AGPL-1.0')) {
    return (
      `AGPL-1.0 (Affero GPL v1: GPL-2.0 plus section 2(d)) requires that a program which lets network ` +
      `users download its source keeps that facility in place — review before any network deployment.`
    );
  }
  return (
    `Unlike GPL, AGPL-3.0's section 13 is triggered by making the software available over a network ` +
    `(e.g. SaaS) even without ever distributing binaries: users interacting with it must be offered the source.`
  );
}

/**
 * Heuristic compatibility table. Returns the reason as a string when the
 * combination is risky/incompatible, or null when it's fine or not covered
 * here (`classifySingleLicensePair` tells those two apart).
 *
 * The rule of thumb: more permissive project + more restrictive dep = risk.
 */
function incompatibleReason(projectLicense: string, depLicense: string): string | null {
  const proj = normaliseLicense(projectLicense);
  const dep = normaliseLicense(depLicense);

  // AGPL is checked before the generic viral case: its network clause
  // applies even when nothing is ever distributed, which the generic
  // "distributing the combined work" wording below would understate.
  if (PERMISSIVE.has(proj) && AGPL.has(dep)) {
    return `Permissive project '${projectLicense}' includes AGPL dependency '${depLicense}'. ${agplNetworkClause(dep)}`;
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
  // GPL-2.0-only vs Apache-2.0: the patent-termination incompatibility. Only
  // the -only form (and the bare id, which SPDX defines as -only): a
  // GPL-2.0-or-later project can be distributed under GPL-3.0, which is
  // compatible with Apache-2.0 — the same election that makes it compatible
  // with a GPL-3.0 dependency (`gnuPairVerdict`), so the two answers agree.
  if ((proj === 'GPL-2.0' || proj === 'GPL-2.0-only') && dep === 'Apache-2.0') {
    return `GPL-2.0-only project + Apache-2.0 dep: known incompatibility (patent termination clauses). Move to GPL-2.0-or-later / GPL-3.0 or replace the dep.`;
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
      `'${depLicense}' is copyleft — incompatible with a closed-source project. ${agplNetworkClause(dep)}`
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

/**
 * A small, EXPLICIT compatibility matrix for (project, dependency) pairs
 * `incompatibleReason` and `gnuPairVerdict` do not cover.
 *
 * Only the pairs below have a real answer; everything else a copyleft
 * project pulls in — SSPL-1.0, BUSL-1.1, MPL-2.0 into GPL, GPL into AGPL,
 * and so on — falls through to `classifySingleLicensePair`'s own `unknown`
 * (-> undetermined), which is the honest answer: this tool does not model
 * that combination, and "undetermined" is not the same finding as "checked,
 * and it's fine".
 */
function explicitPairVerdict(proj: string, dep: string): SingleVerdict | null {
  // A GPL-2.0-only project cannot take on any AGPL: AGPL-3.0 is built on
  // GPL-3.0 (a version GPL-2.0-only cannot move to), and AGPL-1.0 adds a
  // network requirement GPL-2.0 does not allow on top of its own terms.
  if ((proj === 'GPL-2.0' || proj === 'GPL-2.0-only') && AGPL.has(dep)) {
    return {
      kind: 'risky',
      reason: dep.startsWith('AGPL-1.0')
        ? `GPL-2.0-only project + AGPL dependency '${dep}': AGPL-1.0 is GPL-2.0 plus an extra network-use ` +
          `requirement (its section 2(d)), and GPL-2.0 forbids imposing further restrictions on the ` +
          `combined work — the two cannot be combined.`
        : `GPL-2.0-only project + AGPL dependency '${dep}': AGPL-3.0 is built on GPL-3.0, and a ` +
          `GPL-2.0-only project has no "or later" route to GPL-3.0-family terms.`,
    };
  }
  // The same license on both sides: the combined work is distributed under
  // exactly those terms. (GNU families are decided by version above; the
  // commercial source-available licenses are left undetermined — their
  // terms carry per-licensor parameters, so "same id" is not "same terms".)
  if (proj === dep && (VIRAL.has(dep) || WEAK_COPYLEFT.has(dep))) return { kind: 'ok' };
  return null;
}

/** Verdict for one, already-split project license id against one,
 *  already-split dependency license id — never an OR/AND expression on
 *  either side (that composition lives in `evaluateAgainstProject` /
 *  `evaluateDependencyLicense`). 'unknown' when `dep` is not in ANY of the
 *  tables above at all, or when no rule covers this exact pair AND the
 *  dependency is not itself permissive (which is fine against anything —
 *  the whole point of "permissive" is that it imposes no terms to conflict
 *  with). */
function classifySingleLicensePair(projectLicenseSingle: string, depLicenseRaw: string): SingleVerdict {
  const dep = normaliseLicense(depLicenseRaw);
  if (!KNOWN_LICENSES.has(dep)) return { kind: 'unknown' };
  const proj = normaliseLicense(projectLicenseSingle);
  const reason = incompatibleReason(projectLicenseSingle, depLicenseRaw);
  if (reason) return { kind: 'risky', reason };
  if (PERMISSIVE.has(proj) || PERMISSIVE.has(dep)) return { kind: 'ok' };
  const gnu = gnuPairVerdict(proj, dep);
  if (gnu) return gnu;
  const explicit = explicitPairVerdict(proj, dep);
  if (explicit) return explicit;
  return { kind: 'unknown' };
}

/**
 * Resolves ONE (already-split) dependency license id against the project's
 * FULL license — which may itself be an SPDX `OR`/`AND` expression (fix
 * round 2, item 5: the project side was never parsed at all before this;
 * `"MIT OR Apache-2.0"` went through `normaliseLicense` as one opaque
 * string, `MITORApache-2.0`, matching no rule for any dependency).
 *
 *   - **OR** (the project may be released under whichever alternative the
 *     distributor picks): compatible if the distributor COULD pick an
 *     alternative the dependency is fine under — i.e. compatible if ANY
 *     alternative is ok, same "the licensee gets to choose" semantics
 *     `evaluateDependencyLicense` already applies to a dependency-side OR.
 *     Incompatible only when EVERY alternative is risky (no escape route).
 *   - **AND** (a dual-licensed project; both sets of terms apply at once):
 *     risky if ANY alternative is risky.
 */
function evaluateAgainstProject(
  projectLicense: string | null,
  isProprietary: boolean,
  depLicenseSingle: string,
): SingleVerdict {
  if (isProprietary) {
    const dep = normaliseLicense(depLicenseSingle);
    if (!KNOWN_LICENSES.has(dep)) return { kind: 'unknown' };
    const reason = proprietaryReason(depLicenseSingle);
    return reason ? { kind: 'risky', reason } : { kind: 'ok' };
  }

  const projExpr = parseLicenseExpression(projectLicense as string);
  if (projExpr.kind === 'complex') return { kind: 'unknown' };
  if (projExpr.kind === 'single') {
    return classifySingleLicensePair(projExpr.parts[0], depLicenseSingle);
  }

  const verdicts = projExpr.parts.map((p) => classifySingleLicensePair(p, depLicenseSingle));
  if (projExpr.kind === 'or') {
    if (verdicts.some((v) => v.kind === 'ok')) return { kind: 'ok' };
    if (verdicts.every((v) => v.kind === 'risky')) {
      const reasons = verdicts.flatMap((v) => (v.kind === 'risky' ? [v.reason] : []));
      return {
        kind: 'risky',
        reason: `Every license option the project may be released under ('${projectLicense}') is incompatible with dependency '${depLicenseSingle}': ${reasons.join(' | ')}`,
      };
    }
    return { kind: 'unknown' };
  }

  // AND: every project term applies simultaneously.
  const risky = verdicts.find((v) => v.kind === 'risky');
  if (risky && risky.kind === 'risky') return risky;
  if (verdicts.some((v) => v.kind === 'unknown')) return { kind: 'unknown' };
  return { kind: 'ok' };
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

  if (expr.kind === 'complex') {
    return {
      kind: 'undetermined',
      reason:
        `Dependency license '${depLicenseRaw}' mixes AND/OR with parentheses in a way this tool does ` +
        `not attempt to resolve (real SPDX operator precedence, not just a flat OR-then-AND split) — ` +
        `review manually rather than risk misreading which term actually applies.`,
    };
  }

  if (expr.kind === 'single') {
    const v = evaluateAgainstProject(projectLicense, isProprietary, expr.parts[0] ?? depLicenseRaw);
    if (v.kind === 'ok') return { kind: 'ok' };
    if (v.kind === 'risky') return { kind: 'incompatible', reason: v.reason };
    return {
      kind: 'undetermined',
      reason:
        `Compatibility between project license '${projectLicense ?? 'proprietary (no license declared)'}' and ` +
        `dependency license '${depLicenseRaw}' could not be determined — this tool has no rule for that pair, ` +
        `or does not recognise one of the two licenses. Review manually.`,
    };
  }

  const verdicts = expr.parts.map((p) => evaluateAgainstProject(projectLicense, isProprietary, p));
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
  | { kind: 'and'; parts: string[] }
  | { kind: 'complex'; raw: string };

/**
 * Strips exactly ONE wrapping pair of parentheses when the ENTIRE string is
 * that one pair — `"(MIT OR Apache-2.0)"` -> `"MIT OR Apache-2.0"` —
 * verified by depth-counting, not just checking the first/last characters:
 * `"(MIT) OR (Apache-2.0)"` also starts with `(` and ends with `)`, but the
 * first `(` closes well before the string ends, so it is NOT one wrap and
 * is returned unchanged (and then caught by the `/[()]/` check below).
 */
function stripSingleOuterWrap(raw: string): string {
  const s = raw.trim();
  if (s.length < 2 || s[0] !== '(' || s[s.length - 1] !== ')') return s;
  let depth = 0;
  for (let i = 0; i < s.length; i += 1) {
    if (s[i] === '(') depth += 1;
    else if (s[i] === ')') {
      depth -= 1;
      if (depth === 0 && i !== s.length - 1) return s; // closed early — not one wrap
    }
  }
  return depth === 0 ? s.slice(1, -1).trim() : s; // unbalanced — leave as-is
}

/**
 * Splits on a top-level ` OR ` / ` AND ` (case-insensitive, whichever
 * appears) after stripping AT MOST one fully-wrapping outer parenthesis
 * pair. Fix round 3, item N4: this parser does not attempt real operator
 * precedence (SPDX gives `AND` higher precedence than `OR`, with
 * parentheses able to override it) — `"(MIT OR Apache-2.0) AND
 * GPL-3.0-only"` needs that precedence to read as `AND` at the top level,
 * but a naive split-on-OR-first reads it as `OR` with parts `"(MIT"` and
 * `"Apache-2.0) AND GPL-3.0-only"`, and the FIRST part alone (a recognised
 * permissive license once its stray paren is stripped) made the whole
 * expression read compatible — silently dropping the `AND GPL-3.0-only`
 * term entirely. Reproduced by the coordinator against a proprietary and an
 * MIT project alike.
 *
 * Rather than implement full precedence, any string that still contains a
 * `(` or `)` after the single-outer-wrap strip is reported `complex` and
 * resolves to `undetermined` wherever it is used (never guessed at) — the
 * coordinator's own offered alternative to a full parser. This covers every
 * case that actually matters here: a SINGLE license or a flat `OR`/`AND`
 * list, optionally wrapped in one redundant outer pair, parses exactly as
 * before; anything with a nested or non-wrapping paren — the case that
 * silently misparsed — is now refused rather than guessed at.
 */
function parseLicenseExpression(raw: string): LicenseExpression {
  const stripped = stripSingleOuterWrap(raw);
  if (/[()]/.test(stripped)) return { kind: 'complex', raw };
  const orParts = stripped.split(/\s+OR\s+/i).map((s) => s.trim()).filter(Boolean);
  if (orParts.length > 1) return { kind: 'or', parts: orParts };
  const andParts = stripped.split(/\s+AND\s+/i).map((s) => s.trim()).filter(Boolean);
  if (andParts.length > 1) return { kind: 'and', parts: andParts };
  return { kind: 'single', parts: [stripped] };
}

function normaliseLicense(s: string): string {
  return s
    .trim()
    .replace(/^["']|["']$/g, '')
    // Strip parens ANYWHERE, not just a matched leading/trailing pair (fix
    // round 2, item 5): `parseLicenseExpression` splits on ` OR `/` AND `
    // BEFORE this runs, so a wrapping `(MIT OR Apache-2.0)` becomes the two
    // parts `(MIT` and `Apache-2.0)` — each individually unrecognisable
    // unless the stray paren on each is removed here. This tool never
    // attempts parenthesised precedence (see `parseLicenseExpression`'s own
    // comment), so a paren is always noise once a single term is reached.
    .replace(/[()]/g, '')
    .replace(/\s+/g, '')
    // SPDX's deprecated `GPL-2.0+` spelling IS `GPL-2.0-or-later`.
    .replace(/^((?:A|L)?GPL-\d\.\d)\+$/, '$1-or-later');
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
