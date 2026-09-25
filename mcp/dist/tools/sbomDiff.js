/**
 * `sbom_diff` — compare two SBOM scan rows, full component list, keyed by
 * (ecosystem, name).
 *
 * `generate_sbom` always writes the complete SBOM document to
 * `.guardian/reports/sbom-<scan>/` (`meta.file_path`) and additionally
 * persists a capped `top_packages` summary (25 entries, document order) for
 * cheap inline display. This tool now ALWAYS reads the full file when it is
 * still on disk — never the capped summary — because comparing only the
 * first 25 components in document order silently missed every change
 * outside that slice; `top_packages` is a last-resort fallback for a scan
 * row whose file has since been deleted, not the normal path. `use_full_file`
 * is still accepted for backward compatibility but is now a no-op: the
 * behaviour it used to opt into is the only behaviour there is.
 *
 * Keyed by (ecosystem, name), not name alone: two different ecosystems can
 * legitimately share a package name (an npm `lodash` and an unrelated
 * `lodash` elsewhere), and collapsing them under one name silently merged
 * two different packages' version histories into one diff entry. Ecosystem
 * is read from each component's purl (`pkg:TYPE/...`) — CycloneDX's own
 * `purl` field, SPDX's `externalRefs[].referenceType === 'purl'` — and
 * falls back to `'unknown'` when no purl is present (the `top_packages`
 * fallback path never carries one).
 *
 * Output buckets:
 *   - added:     present in `to`, not in `from`
 *   - removed:   present in `from`, not in `to`
 *   - changed:   same (ecosystem, name), different version
 *   - unchanged: same (ecosystem, name) and version (count only)
 *
 * The default pair is the two latest completed SBOM scans OF THIS PROJECT
 * (`project_path`, resolved the same way every other tool resolves it) —
 * previously unscoped across the whole database, so two unrelated projects'
 * SBOMs could be compared by accident whenever neither `from_scan_id` nor
 * `to_scan_id` was given. Explicit ids bypass the project scope entirely (a
 * caller who names both scans exactly is trusted to mean it).
 *
 * The response arrays are capped (`RESPONSE_CAP`); `summary` always carries
 * the TRUE, uncapped totals, and `truncated` says whether anything was left
 * out of the arrays — the same "cap the response, never the count" shape
 * `scanToolFactory.ts`'s own `top_findings` uses.
 */
import { existsSync, readFileSync } from 'node:fs';
import { z } from 'zod';
import { resolveProjectPath } from '../platform/projectPath.js';
import { ProjectPath } from '../schemas.js';
import { registerToolModule } from './index.js';
/** Response arrays are capped here; `summary` counts are never capped. */
const RESPONSE_CAP = 50;
const inputSchema = {
    project_path: ProjectPath,
    from_scan_id: z.string().uuid().optional(),
    to_scan_id: z.string().uuid().optional(),
    /** No longer changes behaviour — full-file comparison always happens now
     *  when the SBOM file is still on disk. Kept so an existing caller that
     *  passes it does not break. */
    use_full_file: z.boolean().optional(),
};
const tool = {
    name: 'sbom_diff',
    title: 'SBOM diff (added / removed / changed components)',
    description: 'Compare two generate_sbom scans, full component list, keyed by (ecosystem, name) so a ' +
        'version change is never confused with an unrelated same-named package. Default to/from: the ' +
        'two latest completed SBOM scans of project_path. Response arrays are capped; summary always ' +
        'carries the true, uncapped totals.',
    inputSchema,
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
    const needsDefaultPair = !inp.from_scan_id || !inp.to_scan_id;
    const sboms = needsDefaultPair
        ? ctx.storage.scans
            .listHistoryForProject(projectPath, 50)
            .filter((s) => s.scan_type === 'sbom' && s.status === 'completed')
        : [];
    if (needsDefaultPair && sboms.length < 2) {
        return failDomain('unknown_scan_id', `Need at least two completed SBOM scans of '${projectPath}' (found ${sboms.length}). ` +
            `Call generate_sbom twice or pass explicit ids.`);
    }
    const toId = inp.to_scan_id ?? sboms[0]?.scan_id;
    const fromId = inp.from_scan_id ?? sboms[1]?.scan_id;
    if (!toId || !fromId) {
        return failDomain('unknown_scan_id', 'Could not resolve both ends of the SBOM diff.');
    }
    if (toId === fromId) {
        return failDomain('unknown_scan_id', `Cannot diff a scan against itself (${toId}).`);
    }
    const fromComps = loadComponents(ctx, fromId);
    const toComps = loadComponents(ctx, toId);
    if (!fromComps || !toComps) {
        return failDomain('unknown_scan_id', 'One or both SBOM scans have no components recorded.');
    }
    const key = (c) => `${c.ecosystem}:${c.name}`;
    const fromMap = new Map(fromComps.map((c) => [key(c), c]));
    const toMap = new Map(toComps.map((c) => [key(c), c]));
    const added = [];
    const removed = [];
    const changed = [];
    let unchangedCount = 0;
    for (const [k, toComp] of toMap) {
        const fromComp = fromMap.get(k);
        if (!fromComp) {
            added.push(toComp);
        }
        else if ((fromComp.version ?? '') !== (toComp.version ?? '')) {
            changed.push({
                name: toComp.name,
                ecosystem: toComp.ecosystem,
                from_version: fromComp.version ?? '',
                to_version: toComp.version ?? '',
            });
        }
        else {
            unchangedCount += 1;
        }
    }
    for (const [k, fromComp] of fromMap) {
        if (!toMap.has(k))
            removed.push(fromComp);
    }
    const truncated = added.length > RESPONSE_CAP || removed.length > RESPONSE_CAP || changed.length > RESPONSE_CAP;
    return {
        ok: true,
        project_path: projectPath,
        from_scan_id: fromId,
        to_scan_id: toId,
        summary: {
            added: added.length,
            removed: removed.length,
            changed: changed.length,
            unchanged: unchangedCount,
        },
        added: added.slice(0, RESPONSE_CAP),
        removed: removed.slice(0, RESPONSE_CAP),
        changed: changed.slice(0, RESPONSE_CAP),
        truncated,
    };
}
/**
 * The full component list for a scan, always from the SBOM file still on
 * disk when it exists (`meta.file_path`) — the capped `top_packages`
 * summary is only a fallback for a scan row whose file has since been
 * removed.
 */
function loadComponents(ctx, scanId) {
    const rec = ctx.storage.scans.getById(scanId);
    if (!rec)
        return null;
    const filePath = rec.meta?.file_path;
    if (filePath && existsSync(filePath)) {
        try {
            const raw = readFileSync(filePath, 'utf8');
            return extractFromSbomJson(raw);
        }
        catch {
            /* fall through to the capped summary */
        }
    }
    const top = rec.meta
        ?.top_packages;
    if (!top || top.length === 0)
        return null;
    return top.map((c) => ({ name: c.name, ...(c.version !== undefined ? { version: c.version } : {}), ecosystem: 'unknown' }));
}
/** The ecosystem segment of a purl (`pkg:npm/lodash@4` → `npm`), or
 *  `'unknown'` when no purl is present. */
function ecosystemFromPurl(purl) {
    if (!purl)
        return 'unknown';
    const m = /^pkg:([^/]+)\//.exec(purl);
    return m?.[1] ?? 'unknown';
}
function extractFromSbomJson(raw) {
    let root;
    try {
        root = JSON.parse(raw);
    }
    catch {
        return [];
    }
    const cdx = root
        ?.components;
    if (Array.isArray(cdx)) {
        // flatMap rather than filter+map: the filter narrowed nothing for the
        // compiler, so the map needed an assertion to re-state what the filter
        // had already checked.
        return cdx.flatMap((c) => {
            if (typeof c?.name !== 'string')
                return [];
            const out = { name: c.name, ecosystem: ecosystemFromPurl(c.purl) };
            if (typeof c.version === 'string')
                out.version = c.version;
            return [out];
        });
    }
    const spdx = root?.packages;
    if (Array.isArray(spdx)) {
        return spdx.flatMap((p) => {
            if (typeof p?.name !== 'string')
                return [];
            const purlRef = (p.externalRefs ?? []).find((r) => r.referenceType === 'purl');
            const out = { name: p.name, ecosystem: ecosystemFromPurl(purlRef?.referenceLocator) };
            if (typeof p.versionInfo === 'string')
                out.version = p.versionInfo;
            return [out];
        });
    }
    return [];
}
function failDomain(code, message) {
    return { ok: false, error: { code, message } };
}
//# sourceMappingURL=sbomDiff.js.map