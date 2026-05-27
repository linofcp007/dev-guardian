/**
 * `audit_executive` — sequences security + quality + deps + compliance scans
 * into a single roll-up report.
 *
 * Each sub-tool already persists its own scan record; this tool calls them
 * in sequence through the in-process `TOOLS` registry. After the sub-runs
 * we:
 *   - insert a parent `audit` scan row,
 *   - aggregate severity counts and top findings across all four,
 *   - compute deltas vs the previous `audit` scan if one exists.
 *
 * The audit scan row links to the children via `meta.sub_scan_ids` so
 * future tools (or a future report exporter) can fan back out.
 */
import { randomUUID } from 'node:crypto';
import { resolveProjectPath } from '../platform/projectPath.js';
import { ProjectPath, SeverityMin } from '../schemas.js';
import { filterFindings } from '../severity/filter.js';
import { computeTreeHash } from '../treeHash/computeTreeHash.js';
import { SEVERITY_ORDER, } from '../types.js';
import { registerToolModule, TOOLS } from './index.js';
const BASE_SUB_TOOLS = ['security_scan_full', 'quality_check', 'deps_audit', 'compliance_check'];
const WP_EXTRA_SUB_TOOLS = ['scan_wordpress'];
const DOTNET_EXTRA_SUB_TOOLS = ['scan_dotnet_secrets', 'dotnet_target_framework_check'];
const tool = {
    name: 'audit_executive',
    title: 'Executive audit (security + quality + deps + compliance)',
    description: 'Run security_scan_full, quality_check, deps_audit, and compliance_check in sequence, ' +
        'producing one aggregated report with severity counts, top-10 findings, and a delta vs the ' +
        'previous executive audit (when present).',
    inputSchema: {
        project_path: ProjectPath,
        severity_min: SeverityMin,
    },
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
    if (ctx.shell === null) {
        return failDomain('no_bash_shell', 'No usable bash shell found. Install Git Bash or WSL, then restart.');
    }
    // Pre-record the audit scan so the children can be linked by id even if a
    // later step fails. tree_hash is captured up front so it reflects the
    // pre-audit state.
    const auditScanId = randomUUID();
    const treeHash = await computeTreeHash(projectPath);
    ctx.storage.scans.insert({
        scan_id: auditScanId,
        scan_type: 'audit',
        project_path: projectPath,
        tree_hash: treeHash,
        meta: { sub_scan_ids: {} },
    });
    const subResults = {};
    const aggregateFindings = [];
    // Sub-tools are independent (write to separate report dirs, separate scan
    // rows). Running them concurrently turns a 4× sequential wait into a
    // 1× max-of-four. SQLite is single-writer but our writes are short and
    // WAL handles the contention.
    const subInput = { project_path: projectPath };
    if (inp.severity_min)
        subInput['severity_min'] = inp.severity_min;
    // Stack-aware: extend the base set with WP / .NET tools when the latest
    // stack snapshot indicates those languages.
    const subTools = buildSubToolsForStack(ctx);
    const subResultsArr = await Promise.all(subTools.map(async (toolName) => {
        const subTool = TOOLS.find((t) => t.name === toolName);
        if (!subTool) {
            return [
                toolName,
                {
                    tool: toolName,
                    ok: false,
                    error: { code: 'scanner_failed', message: `Tool '${toolName}' is not registered.` },
                },
            ];
        }
        const result = await subTool.handler(subInput, ctx);
        if (result.ok) {
            const r = result;
            const summary = { tool: toolName, ok: true };
            if (r.scan_id !== undefined)
                summary.scan_id = r.scan_id;
            if (r.findings_count_by_severity !== undefined)
                summary.findings_count_by_severity = r.findings_count_by_severity;
            if (r.top_findings !== undefined)
                summary.top_findings = r.top_findings;
            return [toolName, summary];
        }
        return [
            toolName,
            { tool: toolName, ok: false, error: result.error },
        ];
    }));
    for (const [name, summary] of subResultsArr) {
        subResults[name] = summary;
        if (summary.ok && summary.scan_id) {
            aggregateFindings.push(...ctx.storage.findings.listByScan(summary.scan_id));
        }
    }
    // Update audit row meta to link children.
    const subScanIds = {};
    for (const [name, summary] of Object.entries(subResults)) {
        subScanIds[name] = summary.scan_id ?? null;
    }
    // Severity floor: re-apply at the aggregate level so audit_executive's own
    // counts match what the model asked for.
    const filteredAggregate = filterFindings(aggregateFindings, inp.severity_min);
    const aggregate_counts = countBySeverity(filteredAggregate);
    const top_findings = topFindings(filteredAggregate, 10);
    // Delta vs previous audit scan, when one exists.
    const previousAudit = findPreviousAudit(ctx, auditScanId);
    let deltas;
    if (previousAudit) {
        const prevFindings = ctx.storage.findings.listByScan(previousAudit);
        const prevFingerprints = new Set(prevFindings.map((f) => f.fingerprint));
        const curFingerprints = new Set(filteredAggregate.map((f) => f.fingerprint));
        let newCount = 0;
        let resolvedCount = 0;
        for (const fp of curFingerprints)
            if (!prevFingerprints.has(fp))
                newCount += 1;
        for (const fp of prevFingerprints)
            if (!curFingerprints.has(fp))
                resolvedCount += 1;
        deltas = {
            since_audit_scan_id: previousAudit,
            new_findings: newCount,
            resolved_findings: resolvedCount,
        };
    }
    // Persist a snapshot of the aggregated findings on the audit row so
    // diff_scans can run against the audit scan_id directly.
    if (filteredAggregate.length > 0) {
        ctx.storage.findings.bulkInsert(
        // Re-key under the audit scan_id; INSERT OR IGNORE handles the cases
        // where a finding already exists on the audit row (unlikely but safe).
        filteredAggregate.map((f) => ({ ...f, scan_id: auditScanId })));
    }
    ctx.storage.scans.finalize({
        scan_id: auditScanId,
        status: 'completed',
        tools_run: subTools.map((name) => ({
            name,
            status: subResults[name]?.ok ? 'ok' : 'failed',
            ...(subResults[name]?.error ? { reason: subResults[name].error.code } : {}),
        })),
        missing_tools: [],
    });
    return {
        ok: true,
        scan_id: auditScanId,
        project_path: projectPath,
        sub_scans: subResults,
        aggregate_counts,
        top_findings,
        ...(deltas ? { deltas } : {}),
    };
}
function buildSubToolsForStack(ctx) {
    const snap = ctx.storage.stack.getLatest()?.snapshot;
    const languages = snap?.languages ?? [];
    const frameworks = snap?.frameworks ?? [];
    const out = [...BASE_SUB_TOOLS];
    if (languages.includes('php') && frameworks.includes('wordpress')) {
        out.push(...WP_EXTRA_SUB_TOOLS);
    }
    if (languages.includes('csharp') || languages.includes('fsharp')) {
        out.push(...DOTNET_EXTRA_SUB_TOOLS);
    }
    return out;
}
function findPreviousAudit(ctx, excludeScanId) {
    const history = ctx.storage.scans.listHistory(200);
    const prev = history.find((s) => s.scan_type === 'audit' &&
        s.status === 'completed' &&
        s.scan_id !== excludeScanId);
    return prev?.scan_id ?? null;
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
function failDomain(code, message) {
    return { ok: false, error: { code, message } };
}
//# sourceMappingURL=auditExecutive.js.map