/**
 * Findings resources:
 *   - guardian://findings/open                  → latest completed scan,
 *                                                  minus suppressed fingerprints
 *   - guardian://findings/critical              → as above, severity=critical
 *   - guardian://findings/by-severity/{level}   → as above, severity={level}
 *
 * `{level}` must be one of {info, low, medium, high, critical}. Anything
 * else returns MCP -32602 (Invalid params).
 */
import { SEVERITIES } from '../types.js';
import { registerResourceModule } from './index.js';
registerResourceModule({
    name: 'guardian-findings-open',
    uri: 'guardian://findings/open',
    description: 'All findings from the latest completed scan, with active suppressions filtered out. ' +
        'Returns `{ findings: [], last_run: null, scan_id: null }` when no scan has run.',
    handler: async (uri, _params, ctx) => {
        const latest = ctx.storage.scans.getLatest();
        if (!latest) {
            return { json: { findings: [], last_run: null, scan_id: null, total: 0 } };
        }
        const findings = ctx.storage.findings.listOpen();
        const { items, total, page, page_size } = paginate(uri, findings);
        return {
            json: {
                findings: items,
                total,
                page,
                page_size,
                last_run: latest.started_at,
                scan_id: latest.scan_id,
            },
        };
    },
});
registerResourceModule({
    name: 'guardian-findings-critical',
    uri: 'guardian://findings/critical',
    description: 'Findings from the latest completed scan with severity=critical, suppressions filtered out.',
    handler: async (uri, _params, ctx) => {
        const latest = ctx.storage.scans.getLatest();
        if (!latest) {
            return { json: { findings: [], last_run: null, scan_id: null, total: 0 } };
        }
        const findings = ctx.storage.findings.listBySeverity('critical');
        const { items, total, page, page_size } = paginate(uri, findings);
        return {
            json: {
                findings: items,
                total,
                page,
                page_size,
                last_run: latest.started_at,
                scan_id: latest.scan_id,
            },
        };
    },
});
registerResourceModule({
    name: 'guardian-findings-by-severity',
    uri: 'guardian://findings/by-severity/{level}',
    isTemplate: true,
    description: 'Findings from the latest completed scan filtered by severity (info | low | medium | high | ' +
        'critical), with active suppressions removed.',
    handler: async (uri, params, ctx) => {
        const raw = params['level'];
        const level = Array.isArray(raw) ? raw[0] : raw;
        if (!level || !SEVERITIES.includes(level)) {
            throw mcpInvalidParams(`level must be one of ${SEVERITIES.join('|')}, got '${level ?? '(missing)'}'`);
        }
        const latest = ctx.storage.scans.getLatest();
        if (!latest) {
            return { json: { findings: [], last_run: null, scan_id: null, total: 0 } };
        }
        const findings = ctx.storage.findings.listBySeverity(level);
        const { items, total, page, page_size } = paginate(uri, findings);
        return {
            json: {
                level,
                findings: items,
                total,
                page,
                page_size,
                last_run: latest.started_at,
                scan_id: latest.scan_id,
            },
        };
    },
});
/**
 * Page findings via query-string params (`?page=N&page_size=M`). Defaults:
 * page=1, page_size=200, capped at 1000. Returning the totals as well lets
 * the model loop without ambiguity.
 */
function paginate(uri, all) {
    const total = all.length;
    const pageRaw = Number(uri.searchParams.get('page') ?? '1');
    const sizeRaw = Number(uri.searchParams.get('page_size') ?? '200');
    const page = Number.isFinite(pageRaw) && pageRaw > 0 ? Math.floor(pageRaw) : 1;
    const page_size = Number.isFinite(sizeRaw) && sizeRaw > 0
        ? Math.min(Math.floor(sizeRaw), 1000)
        : 200;
    const start = (page - 1) * page_size;
    const items = all.slice(start, start + page_size);
    return { items, total, page, page_size };
}
function mcpInvalidParams(message) {
    const err = new Error(message);
    err.code = -32602;
    return err;
}
//# sourceMappingURL=findings.js.map