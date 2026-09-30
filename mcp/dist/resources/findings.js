/**
 * Findings resources — the server's project's open set (see
 * `history/openSet.ts`): the union of the newest usable scan of every
 * finding-producing type, deduplicated, active suppressions removed.
 *
 *   - guardian://findings/open{?page,page_size}
 *   - guardian://findings/critical{?page,page_size}
 *   - guardian://findings/by-severity/{level}{?page,page_size}
 *
 * They used to read the single newest completed scan in the whole database,
 * so `generate_sbom` after a SAST scan made every one of them read zero, and
 * another project's scan answered for this one.
 *
 * Paged (default {@link DEFAULT_PAGE_SIZE}, at most {@link MAX_PAGE_SIZE}),
 * each finding's message cut to {@link MESSAGE_MAX_CHARS} characters. Every
 * response carries the true `total`, the `sources` it read, and the newer
 * scans it `skipped` because they measured nothing.
 *
 * `{level}` must be one of {info, low, medium, high, critical}. Anything
 * else returns MCP -32602 (Invalid params).
 */
import { openSetForProject } from '../history/openSet.js';
import { SEVERITIES } from '../types.js';
import { registerResourceModule } from './index.js';
import { DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE, MESSAGE_MAX_CHARS, boundFinding, paginate, serverProjectPath, } from './paging.js';
const SCOPE_NOTE = "Scoped to the server's working-directory project: the newest usable scan of every " +
    'finding-producing type (never an SBOM, stack detection or diff review; a scan whose scanners ' +
    'did not run is skipped — `skipped` counts them and names the newest few), deduplicated, active ' +
    'suppressions removed. ' +
    `Paged with ?page=N&page_size=M (default ${DEFAULT_PAGE_SIZE}, max ${MAX_PAGE_SIZE}); messages ` +
    `are cut to ${MESSAGE_MAX_CHARS} characters.`;
registerResourceModule({
    name: 'guardian-findings-open',
    uri: 'guardian://findings/open{?page,page_size}',
    isTemplate: true,
    listAs: 'guardian://findings/open',
    description: `All open findings. ${SCOPE_NOTE}`,
    handler: async (uri, _params, ctx) => ({ json: respond(uri, ctx, () => true) }),
});
registerResourceModule({
    name: 'guardian-findings-critical',
    uri: 'guardian://findings/critical{?page,page_size}',
    isTemplate: true,
    listAs: 'guardian://findings/critical',
    description: `Open findings with severity=critical. ${SCOPE_NOTE}`,
    handler: async (uri, _params, ctx) => ({ json: respond(uri, ctx, (f) => f.severity === 'critical') }),
});
registerResourceModule({
    name: 'guardian-findings-by-severity',
    uri: 'guardian://findings/by-severity/{level}{?page,page_size}',
    isTemplate: true,
    description: `Open findings of one severity (info | low | medium | high | critical). ${SCOPE_NOTE}`,
    handler: async (uri, params, ctx) => {
        const raw = params['level'];
        const level = Array.isArray(raw) ? raw[0] : raw;
        if (!level || !SEVERITIES.includes(level)) {
            throw mcpInvalidParams(`level must be one of ${SEVERITIES.join('|')}, got '${level ?? '(missing)'}'`);
        }
        const severity = level;
        return { json: { level, ...respond(uri, ctx, (f) => f.severity === severity) } };
    },
});
function respond(uri, ctx, keep) {
    const set = openSetForProject(ctx.storage, serverProjectPath());
    const { items, total, page, page_size } = paginate(uri, set.findings.filter(keep));
    // `sources` is newest first. Not `newestSource`: that names an orchestrated
    // run by its parent, which is never itself a source.
    const newest = set.sources[0];
    return {
        project_path: set.project_path,
        findings: items.map(boundFinding),
        total,
        page,
        page_size,
        // The newest scan the set was read from — kept for callers of the old
        // single-scan shape. `sources` names every one.
        last_run: newest?.started_at ?? null,
        scan_id: newest?.scan_id ?? null,
        coverage: set.coverage,
        sources: set.sources,
        skipped: set.skipped,
        ...(set.future_dated_note !== undefined ? { future_dated_note: set.future_dated_note } : {}),
    };
}
function mcpInvalidParams(message) {
    const err = new Error(message);
    err.code = -32602;
    return err;
}
//# sourceMappingURL=findings.js.map