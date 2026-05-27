/**
 * Scans resources:
 *   - guardian://scans/latest      → latest completed scan (any type)
 *   - guardian://scans/history     → 50 most recent scans
 *   - guardian://scans/{scan_id}   → full ScanResult by id
 *
 * The `{scan_id}` template returns enriched data (findings counts +
 * top_findings) so it lines up with the response shape the scan tools
 * produce. The other two return ScanRecord arrays.
 */
import { SEVERITY_ORDER } from '../types.js';
import { registerResourceModule } from './index.js';
registerResourceModule({
    name: 'guardian-scans-latest',
    uri: 'guardian://scans/latest',
    description: 'Latest completed scan of any type, with severity counts and the top-10 findings inlined. ' +
        'Returns `{ last_run: null }` when no scan has run yet.',
    handler: async (_uri, _params, ctx) => {
        const latest = ctx.storage.scans.getLatest();
        if (!latest)
            return { json: { last_run: null } };
        return { json: enrich(latest.scan_id, ctx) };
    },
});
registerResourceModule({
    name: 'guardian-scans-history',
    uri: 'guardian://scans/history',
    description: 'Up to 50 most-recent scans across every type, ordered by start time descending. Records are ' +
        'sparse — call `guardian://scans/{scan_id}` for the full ScanResult.',
    handler: async (_uri, _params, ctx) => {
        const scans = ctx.storage.scans.listHistory(50);
        return { json: { scans } };
    },
});
registerResourceModule({
    name: 'guardian-scans-by-id',
    uri: 'guardian://scans/{scan_id}',
    isTemplate: true,
    description: 'Full ScanResult for a given scan_id (record + findings counts + top_findings). Returns an ' +
        'MCP error (-32602) if the id is unknown.',
    handler: async (_uri, params, ctx) => {
        const raw = params['scan_id'];
        const scanId = Array.isArray(raw) ? raw[0] : raw;
        if (!scanId) {
            throw mcpInvalidParams('scan_id is required');
        }
        const record = ctx.storage.scans.getById(scanId);
        if (!record) {
            throw mcpInvalidParams(`unknown scan_id '${scanId}'`);
        }
        return { json: enrich(scanId, ctx) };
    },
});
function enrich(scanId, ctx) {
    const record = ctx.storage.scans.getById(scanId);
    if (!record)
        return { last_run: null };
    const findings = ctx.storage.findings.listByScan(scanId);
    const counts = countBySeverity(findings);
    const top = topFindings(findings, 10);
    return {
        ...record,
        findings_count_by_severity: counts,
        top_findings: top,
    };
}
function countBySeverity(findings) {
    const out = {
        info: 0,
        low: 0,
        medium: 0,
        high: 0,
        critical: 0,
    };
    for (const f of findings)
        out[f.severity] += 1;
    return out;
}
function topFindings(findings, limit) {
    return [...findings]
        .sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity] ||
        a.fingerprint.localeCompare(b.fingerprint))
        .slice(0, limit);
}
function mcpInvalidParams(message) {
    const err = new Error(message);
    err.code = -32602;
    return err;
}
//# sourceMappingURL=scans.js.map