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
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { resolveProjectPath } from '../platform/projectPath.js';
import { ProjectPath } from '../schemas.js';
import { registerToolModule } from './index.js';
const tool = {
    name: 'license_compatibility',
    title: 'License compatibility check',
    description: 'Cross-check the project license (from LICENSE / package.json / pyproject.toml) against the ' +
        'licenses of installed deps captured by the most recent compliance_check. Flags incompatibilities ' +
        '(e.g. permissive project + viral copyleft dep). Pure SQL read — does not spawn scanners.',
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
    const compliance = findLatestCompliance(ctx);
    const meta = compliance?.meta;
    const depLicenses = meta?.licenses_summary ?? [];
    const incompatibilities = [];
    if (projectLicense && depLicenses.length > 0) {
        for (const entry of depLicenses) {
            const reason = incompatibleReason(projectLicense, entry.license);
            if (reason) {
                incompatibilities.push({
                    project_license: projectLicense,
                    dep_license: entry.license,
                    packages: entry.packages,
                    reason,
                });
            }
        }
    }
    return {
        ok: true,
        project_license: projectLicense ?? null,
        last_compliance_scan_id: compliance?.scan_id ?? null,
        dependencies_audited: depLicenses.length,
        incompatibilities,
        summary: {
            total: incompatibilities.length,
            by_dep_license: groupByLicense(incompatibilities),
        },
        notes: 'Compatibility rules are heuristic — definitive guidance requires legal review. ' +
            'A "reciprocal" license (GPL/AGPL/SSPL) included in a permissive project requires the ' +
            'whole project to be released under the same terms when distributed.',
    };
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
function findLatestCompliance(ctx) {
    const history = ctx.storage.scans.listHistory(50);
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
 */
function incompatibleReason(projectLicense, depLicense) {
    const proj = normaliseLicense(projectLicense);
    const dep = normaliseLicense(depLicense);
    // Permissive projects + viral copyleft is the classic trap.
    const permissive = new Set([
        'MIT',
        'ISC',
        'Apache-2.0',
        'BSD-2-Clause',
        'BSD-3-Clause',
        'CC0-1.0',
        'Unlicense',
        '0BSD',
    ]);
    const viral = new Set([
        'AGPL-1.0',
        'AGPL-3.0',
        'GPL-2.0',
        'GPL-3.0',
        'SSPL-1.0',
        'OSL-3.0',
    ]);
    const weakCopyleft = new Set(['LGPL-2.1', 'LGPL-3.0', 'MPL-2.0', 'EPL-2.0']);
    const commercial = new Set(['BUSL-1.1', 'Elastic-2.0', 'CommonsClause']);
    if (permissive.has(proj) && viral.has(dep)) {
        return `Permissive project '${projectLicense}' includes viral copyleft dep '${depLicense}'. Distributing the combined work requires releasing the whole project under '${depLicense}'.`;
    }
    if (permissive.has(proj) && weakCopyleft.has(dep)) {
        return `Permissive project '${projectLicense}' includes weak-copyleft dep '${depLicense}'. Static linking / bundling may require sources of the dep to be available; safe when linked dynamically.`;
    }
    if (permissive.has(proj) && commercial.has(dep)) {
        return `Permissive project '${projectLicense}' includes a source-available-but-not-OSI license '${depLicense}'. Restricts deployment models — review the dep's specific terms.`;
    }
    if (proj === 'GPL-2.0' && dep === 'Apache-2.0') {
        return `GPL-2.0 project + Apache-2.0 dep: known incompatibility (patent termination clauses). Move to GPL-3.0 or replace the dep.`;
    }
    if (proj === 'AGPL-3.0' && commercial.has(dep)) {
        return `AGPL-3.0 project + commercial-source-available dep '${depLicense}': mutually exclusive distribution terms.`;
    }
    return null;
}
function normaliseLicense(s) {
    return s
        .trim()
        .replace(/^["']|["']$/g, '')
        .replace(/[-_]or[-_]later$/i, '')
        .replace(/\s+/g, '');
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