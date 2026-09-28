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
 *
 * `file_path` on every finding here defaults to `'requirements.txt'` ONLY
 * when no source file is known — pip-audit's own JSON says nothing about
 * which requirements file (or `pyproject.toml`) a dependency came from, so
 * `depsAudit.ts` runs one pip-audit invocation PER file (fix round 1, item
 * 9) and attributes each call's output to that file. `scanToolFactory.ts`
 * builds ONE `ParserContext` for a whole scan and reuses it for every
 * `parser_inputs` entry, so a per-call `ctx.source_file` cannot vary across
 * several pip-audit calls in the same scan; `depsAudit.ts` instead embeds a
 * `__source_file` key in the JSON blob it hands to this parser for each
 * call, which takes precedence when present. `ctx.source_file` is read as a
 * fallback for a caller that genuinely only has one invocation to attribute
 * (kept for API symmetry with the other parsers here, and for direct unit
 * tests that pass it without going through `depsAudit.ts` at all).
 *
 * ---- `fix_versions[0]` is not "the fix" (fix round 1, CRITICAL item 1) ----
 *
 * pip-audit lists ONE fix per still-maintained release branch: installed
 * `2.0.1`, `fix_versions: ["1.11.27", "2.2.9", "3.0.1"]` — `1.11.27` is an
 * OLDER branch's backport, not an upgrade path for a 2.0.1 install; picking
 * index 0 blindly proposed `django==1.11.27`, a downgrade labelled
 * `security`. `minCleanVersionAbove` (`../../deps/versionCompare.js`) picks
 * the smallest candidate that is genuinely ABOVE the installed version;
 * `cve.fixed_version` is left unset when no candidate qualifies (an active
 * CVE with no known safe upgrade is reported by `deps_update_plan` as
 * `unplanned`, never guessed at).
 */
import { minCleanVersionAbove } from '../../deps/versionCompare.js';
import { asArray, getProp, getString, makeFinding, normalizeSeverity, parseInputAsJson, } from './index.js';
export const PIP_AUDIT_TOOL_NAME = 'pip-audit';
export const pipAuditParser = {
    name: PIP_AUDIT_TOOL_NAME,
    parse(input, ctx = {}) {
        const root = parseInputAsJson(input);
        const findings = [];
        const cves = [];
        const filePath = getString(root, '__source_file') ?? ctx.source_file ?? 'requirements.txt';
        for (const dep of asArray(getProp(root, 'dependencies'))) {
            const name = getString(dep, 'name');
            if (!name)
                continue;
            const version = getString(dep, 'version');
            for (const vuln of asArray(getProp(dep, 'vulns'))) {
                const id = getString(vuln, 'id');
                if (!id)
                    continue;
                const fixVersions = stringArray(getProp(vuln, 'fix_versions'));
                const aliases = stringArray(getProp(vuln, 'aliases'));
                const cveId = aliases.find((a) => /^CVE-\d/i.test(a));
                const description = getString(vuln, 'description');
                const severity = normalizeSeverity(undefined);
                const safeFix = minCleanVersionAbove(version, fixVersions);
                const findingInput = {
                    tool: PIP_AUDIT_TOOL_NAME,
                    rule_id: id,
                    severity,
                    category: 'security',
                    subcategory: 'dependency',
                    title: `${id} in ${name}${version ? ` ${version}` : ''}`,
                    fix_available: fixVersions.length > 0,
                    file_path: filePath,
                    snippet: `${name}@${version ?? ''}`,
                    // OSV's own aliases — what ties PYSEC-… to its CVE and GHSA.
                    vuln_aliases: aliases,
                };
                if (description !== undefined)
                    findingInput.message = description;
                findings.push(makeFinding(findingInput));
                if (cveId) {
                    const cve = { cve_id: cveId, package_name: name, severity };
                    if (version !== undefined)
                        cve.installed_version = version;
                    // Only a version genuinely ABOVE what is installed is recorded as
                    // the fix — never fix_versions[0], which can be an older branch's
                    // backport (see this module's own doc comment). Left unset when no
                    // candidate qualifies: an unknown fix is not the same as "no fix",
                    // and `deps_update_plan` must not silently invent one.
                    if (safeFix !== undefined)
                        cve.fixed_version = safeFix;
                    cves.push(cve);
                }
            }
        }
        return { findings, cves };
    },
};
function stringArray(value) {
    return asArray(value).filter((v) => typeof v === 'string');
}
//# sourceMappingURL=pipAudit.js.map