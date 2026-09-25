/**
 * How create_fix_pr re-verifies a target: which tool and rule packs produced
 * it (`rescanOriginOf`), and whether the re-scan's own bookkeeping says the
 * scanner that must re-check it ran ok (`scannerNotVerified`). Pure — the
 * re-scan itself runs in `../tools/createFixPr.ts`.
 */
import { isDepsAuditScan } from '../types.js';
import { DEP_SCANNER_TOOLS, findingEcosystem } from './candidates.js';
/**
 * The re-scan for `f`, read off the scan it came from — or null when no tool
 * can re-run the rule packs that produced it (a WordPress scan's Semgrep
 * pass, a WPScan component), which makes it no candidate at all.
 *
 *   - `sast` → `scan_sast`, with the `local_only` that scan recorded;
 *   - `bugs` → `bug_hunt`, with its `include_language_packs`;
 *   - a script-era `security_full` row's Semgrep finding → `scan_sast` (its
 *     registry ruleset is a subset of scan_sast's; a rule it never loaded
 *     can only make the differential stricter, never looser);
 *   - a dependency finding → `deps_audit` for a deps_audit or script-era
 *     security_full row, `scan_deps` for a scan_deps row.
 *
 * A row written before the choice was recorded reads as the default (the
 * registry on, language packs off).
 */
export function rescanOriginOf(f, scan) {
    if (f.tool === 'semgrep') {
        if (scan.scan_type === 'sast' || scan.scan_type === 'security_full') {
            const localOnly = scan.scan_type === 'sast' && scan.meta?.['local_only'] === true;
            return { key: `scan_sast:${String(localOnly)}`, tool: 'scan_sast', input: { local_only: localOnly } };
        }
        if (scan.scan_type === 'bugs') {
            const languagePacks = scan.meta?.['include_language_packs'] === true;
            return {
                key: `bug_hunt:${String(languagePacks)}`,
                tool: 'bug_hunt',
                input: { include_language_packs: languagePacks },
            };
        }
        return null;
    }
    if (DEP_SCANNER_TOOLS.includes(f.tool) && f.tool !== 'wpscan') {
        if (isDepsAuditScan(scan) || scan.scan_type === 'security_full') {
            return { key: 'deps_audit', tool: 'deps_audit', input: {} };
        }
        if (scan.scan_type === 'deps')
            return { key: 'scan_deps', tool: 'scan_deps', input: {} };
    }
    return null;
}
/**
 * The name of the scanner that would have to re-check `target` and did not
 * run ok in `scan`, or null when it did. By the target's own `tool` — never a
 * guess from the group's source (task-7-review.md I5): `deps_audit` records
 * npm audit by its command (`npm`), and never attempts WPScan at all.
 */
export function scannerNotVerified(target, scan) {
    const ranOk = (name) => scan.tools_run.some((t) => t.name === name && t.status === 'ok') && !scan.missing_tools.includes(name);
    switch (target.tool) {
        case 'semgrep':
            return ranOk('semgrep') ? null : 'semgrep';
        case 'trivy': {
            if (!ranOk('trivy'))
                return 'trivy';
            const ecosystem = findingEcosystem(target);
            const gap = ecosystem === null ? null : `trivy:${ecosystem}`;
            return gap !== null && scan.missing_tools.includes(gap) ? gap : null;
        }
        case 'npm-audit':
            return ranOk('npm') ? null : 'npm-audit';
        case 'pip-audit':
            return ranOk('pip-audit') ? null : 'pip-audit';
        case 'dotnet-list-package':
            return ranOk('dotnet') ? null : 'dotnet-list-package';
        default:
            return target.tool;
    }
}
//# sourceMappingURL=rescan.js.map