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
import { resolveProjectPath } from '../platform/projectPath.js';
import { ProjectPath } from '../schemas.js';
import { registerToolModule } from './index.js';
const tool = {
    name: 'license_compatibility',
    title: 'License compatibility check',
    description: 'Cross-check the project license (package.json incl. UNLICENSED, pyproject.toml, composer.json ' +
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
async function handler(input, ctx) {
    const inp = input;
    let projectPath;
    try {
        projectPath = resolveProjectPath(inp.project_path).path;
    }
    catch (e) {
        return failDomain('not_a_git_repo', e.message);
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
    const meta = compliance?.meta;
    const depLicenses = meta?.licenses_summary ?? [];
    const incompatibilities = [];
    const undetermined = [];
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
        }
        else if (verdict.kind === 'undetermined') {
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
        notes: 'Compatibility rules are heuristic — definitive guidance requires legal review. ' +
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
function isProprietaryLabel(s) {
    const t = s.trim();
    return /^UNLICENSED$/i.test(t) || /^proprietary$/i.test(t) || /^SEE LICENSE IN /i.test(t);
}
function detectProjectLicense(projectPath) {
    // Prefer machine-readable sources before LICENSE file headers.
    try {
        const pkgPath = join(projectPath, 'package.json');
        if (existsSync(pkgPath)) {
            const pkg = JSON.parse(readFileSync(pkgPath, 'utf8'));
            if (typeof pkg.license === 'string')
                return pkg.license;
        }
    }
    catch {
        /* ignore */
    }
    try {
        const pyProject = join(projectPath, 'pyproject.toml');
        if (existsSync(pyProject)) {
            const raw = readFileSync(pyProject, 'utf8');
            const m = /license\s*=\s*["']([^"']+)["']/i.exec(raw) ??
                /license-expression\s*=\s*["']([^"']+)["']/i.exec(raw);
            if (m && m[1])
                return m[1];
        }
    }
    catch {
        /* ignore */
    }
    try {
        const composer = join(projectPath, 'composer.json');
        if (existsSync(composer)) {
            const cjson = JSON.parse(readFileSync(composer, 'utf8'));
            if (typeof cjson.license === 'string')
                return cjson.license;
            if (Array.isArray(cjson.license) && typeof cjson.license[0] === 'string')
                return cjson.license[0];
        }
    }
    catch {
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
            if (m && m[1])
                return m[1].trim();
        }
    }
    catch {
        /* ignore */
    }
    // Last resort: peek at LICENSE / LICENSE.md / LICENSE.txt header.
    for (const name of ['LICENSE', 'LICENSE.md', 'LICENSE.txt', 'COPYING']) {
        const p = join(projectPath, name);
        if (!existsSync(p))
            continue;
        try {
            const head = readFileSync(p, 'utf8').slice(0, 500);
            if (/MIT License/i.test(head))
                return 'MIT';
            if (/Apache License,?\s*Version\s*2/i.test(head))
                return 'Apache-2.0';
            if (/BSD 3-Clause/i.test(head))
                return 'BSD-3-Clause';
            if (/BSD 2-Clause/i.test(head))
                return 'BSD-2-Clause';
            if (/GNU Affero General Public License/i.test(head))
                return 'AGPL-3.0';
            if (/GNU General Public License/i.test(head) && /version 3/i.test(head))
                return 'GPL-3.0';
            if (/GNU General Public License/i.test(head) && /version 2/i.test(head))
                return 'GPL-2.0';
            if (/Mozilla Public License/i.test(head))
                return 'MPL-2.0';
            if (/ISC License/i.test(head))
                return 'ISC';
        }
        catch {
            /* ignore */
        }
    }
    return null;
}
/** `listHistoryForProject`, never `listHistory` (fix round 1, item 5): the
 *  latter is unscoped across the WHOLE database, so a `compliance_check` of
 *  a DIFFERENT project on the same server could win here and attribute its
 *  dependency licenses to this one — the exact class of bug already fixed
 *  for `deps_update_plan`'s CVE source (`scansRepo.ts`'s own module
 *  comment). Filtered to `status === 'completed'` in JS, matching that same
 *  file's convention for its project-scoped siblings. */
function findLatestCompliance(ctx, projectPath) {
    const history = ctx.storage.scans.listHistoryForProject(projectPath, 50);
    const row = history.find((s) => s.scan_type === 'compliance' && s.status === 'completed');
    if (!row)
        return null;
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
function withSuffixes(...bases) {
    const out = new Set();
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
const KNOWN_LICENSES = new Set([...PERMISSIVE, ...VIRAL, ...WEAK_COPYLEFT, ...COMMERCIAL]);
/** GPL-3.0, all three SPDX suffix forms — used only by `explicitPairVerdict`'s
 *  GPL-2.0-vs-GPL-3.0 rules below. */
const GPL3_FAMILY = withSuffixes('GPL-3.0');
function incompatibleReason(projectLicense, depLicense) {
    const proj = normaliseLicense(projectLicense);
    const dep = normaliseLicense(depLicense);
    // AGPL is checked before the generic viral case: unlike GPL, its network-
    // use clause is triggered by making the software available over a
    // network (a SaaS deployment) even when nothing is ever distributed —
    // the generic "distributing the combined work" wording below would
    // understate the risk for exactly this dependency.
    if (PERMISSIVE.has(proj) && AGPL.has(dep)) {
        return (`Permissive project '${projectLicense}' includes AGPL dependency '${depLicense}'. Unlike GPL, ` +
            `AGPL's network-use clause is triggered by making the software available over a network ` +
            `(e.g. SaaS) even without ever distributing binaries — review before any network deployment.`);
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
        const escape = proj === 'GPL-2.0-or-later'
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
function proprietaryReason(depLicense) {
    const dep = normaliseLicense(depLicense);
    if (AGPL.has(dep)) {
        return (`No project license declared (treated as proprietary/all-rights-reserved). AGPL dependency ` +
            `'${depLicense}' triggers its network-use clause: even SaaS deployment without redistributing ` +
            `binaries requires releasing source to users interacting with it over a network — incompatible ` +
            `with a closed-source project.`);
    }
    if (VIRAL.has(dep)) {
        return (`No project license declared (treated as proprietary). Viral copyleft dependency '${depLicense}' ` +
            `requires the combined work to be released under '${depLicense}' when distributed — incompatible ` +
            `with closed-source distribution.`);
    }
    if (WEAK_COPYLEFT.has(dep)) {
        return (`No project license declared (treated as proprietary). Weak-copyleft dependency '${depLicense}' ` +
            `may require its own source to stay available if statically linked/bundled — review before ` +
            `distributing.`);
    }
    if (COMMERCIAL.has(dep)) {
        return (`No project license declared (treated as proprietary). Dependency '${depLicense}' is source-` +
            `available but not OSI-approved, restricting deployment models — review its specific terms.`);
    }
    return null;
}
/**
 * A small, EXPLICIT compatibility matrix for (project, dependency) pairs
 * `incompatibleReason` does not cover at all — fix round 3, item N5.
 *
 * The fix round 2 shape used a whole-FAMILY "is this project license one I
 * understand" flag (`isModeledProjectLicense`): any GPL-2.0 suffix form, or
 * any AGPL suffix form, read as "modelled", so "no rule fired" there meant
 * "fine" — but `incompatibleReason` only actually has a rule for GPL-2.0
 * project + Apache-2.0 dependency, and AGPL-3.0 project + a COMMERCIAL
 * dependency. Every OTHER dependency against a GPL-2.0/AGPL-3.0 project
 * silently read "ok" purely because the PROJECT side happened to be a
 * recognised family name — reproduced by the coordinator: a GPL-2.0-only
 * project against GPL-3.0-only / AGPL-3.0 / SSPL-1.0 / BUSL-1.1
 * dependencies, and an AGPL-3.0-only project against GPL-2.0-only /
 * SSPL-1.0, all read compatible.
 *
 * Only the pairs below have a real answer; everything else a GPL-2.0/
 * AGPL-3.0 project pulls in — SSPL-1.0, BUSL-1.1, MPL-2.0, and so on — falls
 * through to `classifySingleLicensePair`'s own `unknown` (-> undetermined),
 * which is the honest answer: this tool does not model that combination,
 * and "undetermined" is not the same finding as "checked, and it's fine".
 */
function explicitPairVerdict(proj, dep) {
    // GPL-2.0 with NO "or later" escape: incompatible with GPL-3.0 (a
    // different, non-interchangeable copyleft license) and with AGPL (whose
    // terms require GPL-3.0-compatible licensing, which GPL-2.0-only cannot
    // provide).
    if (proj === 'GPL-2.0' || proj === 'GPL-2.0-only') {
        if (GPL3_FAMILY.has(dep)) {
            return {
                kind: 'risky',
                reason: `GPL-2.0 project + GPL-3.0 dependency '${dep}': different, non-interchangeable copyleft ` +
                    `terms — a GPL-2.0-only project has no "or later" escape into GPL-3.0.`,
            };
        }
        if (AGPL.has(dep)) {
            return {
                kind: 'risky',
                reason: `GPL-2.0 project + AGPL dependency '${dep}': AGPL's terms require GPL-3.0-compatible ` +
                    `licensing, which a GPL-2.0-only project cannot provide.`,
            };
        }
    }
    // GPL-2.0-or-later MAY relicense to GPL-3.0 — the escape the bare/-only
    // forms lack — so a GPL-3.0 dependency is compatible as GPL-3.0.
    if (proj === 'GPL-2.0-or-later' && GPL3_FAMILY.has(dep)) {
        return { kind: 'ok' };
    }
    return null;
}
/** Verdict for one, already-split project license id against one,
 *  already-split dependency license id — never an OR/AND expression on
 *  either side (that composition lives in `evaluateAgainstProject` /
 *  `evaluateDependencyLicense`). 'unknown' when `dep` is not in ANY of the
 *  tables above at all, or when neither `incompatibleReason` nor
 *  `explicitPairVerdict` has a rule for this exact pair AND the dependency
 *  is not itself permissive (which is fine against anything — the whole
 *  point of "permissive" is that it imposes no terms to conflict with).
 *  These cases used to collapse into "returns null", indistinguishable from
 *  "checked, and it's fine". */
function classifySingleLicensePair(projectLicenseSingle, depLicenseRaw) {
    const dep = normaliseLicense(depLicenseRaw);
    if (!KNOWN_LICENSES.has(dep))
        return { kind: 'unknown' };
    const proj = normaliseLicense(projectLicenseSingle);
    const reason = incompatibleReason(projectLicenseSingle, depLicenseRaw);
    if (reason)
        return { kind: 'risky', reason };
    if (PERMISSIVE.has(proj) || PERMISSIVE.has(dep))
        return { kind: 'ok' };
    const explicit = explicitPairVerdict(proj, dep);
    if (explicit)
        return explicit;
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
function evaluateAgainstProject(projectLicense, isProprietary, depLicenseSingle) {
    if (isProprietary) {
        const dep = normaliseLicense(depLicenseSingle);
        if (!KNOWN_LICENSES.has(dep))
            return { kind: 'unknown' };
        const reason = proprietaryReason(depLicenseSingle);
        return reason ? { kind: 'risky', reason } : { kind: 'ok' };
    }
    const projExpr = parseLicenseExpression(projectLicense);
    if (projExpr.kind === 'complex')
        return { kind: 'unknown' };
    if (projExpr.kind === 'single') {
        return classifySingleLicensePair(projExpr.parts[0], depLicenseSingle);
    }
    const verdicts = projExpr.parts.map((p) => classifySingleLicensePair(p, depLicenseSingle));
    if (projExpr.kind === 'or') {
        if (verdicts.some((v) => v.kind === 'ok'))
            return { kind: 'ok' };
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
    if (risky && risky.kind === 'risky')
        return risky;
    if (verdicts.some((v) => v.kind === 'unknown'))
        return { kind: 'unknown' };
    return { kind: 'ok' };
}
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
function evaluateDependencyLicense(projectLicense, isProprietary, depLicenseRaw) {
    const expr = parseLicenseExpression(depLicenseRaw);
    if (expr.kind === 'complex') {
        return {
            kind: 'undetermined',
            reason: `Dependency license '${depLicenseRaw}' mixes AND/OR with parentheses in a way this tool does ` +
                `not attempt to resolve (real SPDX operator precedence, not just a flat OR-then-AND split) — ` +
                `review manually rather than risk misreading which term actually applies.`,
        };
    }
    if (expr.kind === 'single') {
        const v = evaluateAgainstProject(projectLicense, isProprietary, expr.parts[0] ?? depLicenseRaw);
        if (v.kind === 'ok')
            return { kind: 'ok' };
        if (v.kind === 'risky')
            return { kind: 'incompatible', reason: v.reason };
        return {
            kind: 'undetermined',
            reason: `Compatibility between project license '${projectLicense ?? 'proprietary (no license declared)'}' and ` +
                `dependency license '${depLicenseRaw}' could not be determined — either side (or both) is not one this ` +
                `tool recognises. Review manually.`,
        };
    }
    const verdicts = expr.parts.map((p) => evaluateAgainstProject(projectLicense, isProprietary, p));
    if (expr.kind === 'or') {
        if (verdicts.some((v) => v.kind === 'ok'))
            return { kind: 'ok' };
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
/**
 * Strips exactly ONE wrapping pair of parentheses when the ENTIRE string is
 * that one pair — `"(MIT OR Apache-2.0)"` -> `"MIT OR Apache-2.0"` —
 * verified by depth-counting, not just checking the first/last characters:
 * `"(MIT) OR (Apache-2.0)"` also starts with `(` and ends with `)`, but the
 * first `(` closes well before the string ends, so it is NOT one wrap and
 * is returned unchanged (and then caught by the `/[()]/` check below).
 */
function stripSingleOuterWrap(raw) {
    const s = raw.trim();
    if (s.length < 2 || s[0] !== '(' || s[s.length - 1] !== ')')
        return s;
    let depth = 0;
    for (let i = 0; i < s.length; i += 1) {
        if (s[i] === '(')
            depth += 1;
        else if (s[i] === ')') {
            depth -= 1;
            if (depth === 0 && i !== s.length - 1)
                return s; // closed early — not one wrap
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
function parseLicenseExpression(raw) {
    const stripped = stripSingleOuterWrap(raw);
    if (/[()]/.test(stripped))
        return { kind: 'complex', raw };
    const orParts = stripped.split(/\s+OR\s+/i).map((s) => s.trim()).filter(Boolean);
    if (orParts.length > 1)
        return { kind: 'or', parts: orParts };
    const andParts = stripped.split(/\s+AND\s+/i).map((s) => s.trim()).filter(Boolean);
    if (andParts.length > 1)
        return { kind: 'and', parts: andParts };
    return { kind: 'single', parts: [stripped] };
}
function normaliseLicense(s) {
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
        .replace(/\s+/g, '');
}
/** First `.csproj` at the project root, in directory listing order — same
 *  shallow, root-only scope as every other manifest check in this file. */
function findFirstCsproj(projectPath) {
    try {
        const name = readdirSync(projectPath)
            .filter((n) => n.toLowerCase().endsWith('.csproj'))
            .sort()[0];
        return name ? join(projectPath, name) : null;
    }
    catch {
        return null;
    }
}
function groupByLicense(rows) {
    const out = {};
    for (const r of rows) {
        out[r.dep_license] = (out[r.dep_license] ?? 0) + r.packages.length;
    }
    return out;
}
function failDomain(code, message) {
    return { ok: false, error: { code, message } };
}
//# sourceMappingURL=licenseCompatibility.js.map