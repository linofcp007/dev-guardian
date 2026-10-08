/**
 * `security_scan_full` — every security scan tool, run as one.
 *
 * It runs `scan_sast`, then `scan_secrets`, `scan_deps` and `scan_iac`,
 * through the same handlers an MCP client calls, so each scanner is invoked
 * and judged exactly one way everywhere. Each child is persisted as its own
 * scan, with `meta.parent_scan_id` naming this one; this scan's own row keeps
 * the merged, de-duplicated findings (and the dependency CVEs), so everything
 * that holds a `security_full` scan id — `audit_executive`, the CI gate,
 * `diff_scans`, a baseline — keeps working unchanged.
 *
 * It used to run `scripts/scan/full-security-scan.sh`, and a scanner was `ok`
 * whenever its report file existed. Reproduced against that script: Semgrep
 * exit 7 (registry unreachable) printed "Semgrep returned findings" and
 * counted as a clean run; `find … | head -1` under `pipefail` died of SIGPIPE
 * on a 3 000-file tree and Bandit was silently skipped; `auto_fix` was
 * accepted and ignored; the project's `.semgrep.yml`, registered custom rules
 * and `local_only` were never used; the Docker fallback broke on Git Bash.
 * Each of those is now the child tool's behaviour: `scan_sast` loads every
 * rule source, honours `local_only` and `auto_fix` (after the clean-tree
 * check, done once, here) and judges Semgrep's report rather than its exit
 * code.
 *
 * `scan_sast` runs first and alone — `auto_fix` may rewrite files the others
 * then read. The other three run concurrently; each takes its own scanner
 * slot, which is why this tool, an orchestrator, takes none.
 */
import { dedupeFindings } from '../runners/findingMerge.js';
import { historyState } from '../runners/git.js';
import { planSemgrepConfigs } from '../runners/semgrepConfigs.js';
import { z } from 'zod';
import { AllowDirty, AutoFix, Force, ProjectPath, SeverityMin } from '../schemas.js';
import { registerToolModule, TOOLS } from './index.js';
import { makeScanTool } from './scanToolFactory.js';
// The children must be registered wherever this tool is.
import './scanSast.js';
import './scanSecrets.js';
import './scanDeps.js';
import './scanIac.js';
/** Run in this order; the first alone, the rest together. */
const FIRST_CHILD = 'scan_sast';
const OTHER_CHILDREN = ['scan_secrets', 'scan_deps', 'scan_iac'];
registerToolModule(makeScanTool({
    name: 'security_scan_full',
    title: 'Full security scan',
    description: 'Run every security scan as one: scan_sast (Semgrep with the registry ruleset, the project .semgrep.yml ' +
        'and registered custom rules; Bandit for Python; .NET analyzers), scan_secrets (gitleaks over git ' +
        'history AND uncommitted files), scan_deps (Trivy vuln + license) and scan_iac (Trivy config). Each ' +
        'runs as its own scan (meta.parent_scan_id); this scan holds the merged, de-duplicated findings and ' +
        'lists them in child_scans. A scanner that did not run or failed is reported as such and coverage is ' +
        'partial/none, never full. Each tools_run entry names the project configuration that decided it ' +
        '(`honoured_config`: .trivyignore, .gitleaks.toml, .bandit, .semgrepignore, .guardianignore…), and ' +
        '`suppressed_by_repo_config` what .trivyignore suppressed — reported, never counted as findings. ' +
        'auto_fix applies Semgrep autofixes after a clean-tree check. PRIVACY: the ' +
        'Semgrep registry (--config=auto) sends usage metrics to Semgrep Inc.; local_only=true uses only rules ' +
        "on disk with --metrics=off. It does not stop Trivy's database download (scan_deps, scan_iac) nor, on " +
        "a .NET project, scan_sast's dotnet restore (the NuGet feeds).",
    scan_type: 'security_full',
    category: 'security',
    orchestrator: true,
    // scan_secrets reads git history: HEAD and every ref join the key.
    cacheState: (_input, { projectPath }) => historyState(projectPath),
    // The children's own rule packs: the cache key must move when a rule does.
    rulePacks: (input, { projectPath, plugin, rulesProjectPath }) => planSemgrepConfigs(rulesProjectPath, plugin, input.local_only === true, projectPath).rulePacks,
    inputSchema: {
        project_path: ProjectPath,
        severity_min: SeverityMin,
        auto_fix: AutoFix,
        allow_dirty: AllowDirty,
        local_only: z
            .boolean()
            .optional()
            .describe("Semgrep runs only rules already on disk (the project's .semgrep.yml, registered custom rules and the " +
            "plugin's LLM-application and web-JS sink packs) with --metrics=off; no registry, no telemetry. Trivy (scan_deps, " +
            "scan_iac) may still download its database, and a .NET project's restore still contacts its NuGet " +
            'feeds. Default: false.'),
        force: Force,
    },
    invoke: async (input, ctx) => {
        const outcomes = [];
        const first = await runChild(FIRST_CHILD, childInput(FIRST_CHILD, input, ctx.projectPath), ctx, ctx.childCallMeta);
        outcomes.push(first);
        if (!first.cancelled && !ctx.signal.aborted) {
            // An autofix may have rewritten the tree this scan hashed: the
            // children after it hash it again rather than inherit a stale hash.
            const { treeHash: _stale, ...rehash } = ctx.childCallMeta;
            const meta = input.auto_fix === true ? rehash : ctx.childCallMeta;
            outcomes.push(...(await Promise.all(OTHER_CHILDREN.map((name) => runChild(name, childInput(name, input, ctx.projectPath), ctx, meta)))));
        }
        const findings = dedupeFindings(outcomes.flatMap((o) => o.findings));
        const cves = outcomes.flatMap((o) => o.cves);
        const merged = {
            name: 'security_scan_full',
            parse: () => ({ findings, cves }),
        };
        const cancelled = ctx.signal.aborted || outcomes.some((o) => o.cancelled);
        return {
            outcome: cancelled ? 'cancelled' : 'completed',
            tools_run: uniqueRuns(outcomes.flatMap((o) => o.tools_run)),
            missing_tools: [...new Set(outcomes.flatMap((o) => o.missing_tools))],
            parser_inputs: [{ parser: merged, input: null }],
            report_paths: outcomes.flatMap((o) => o.report_paths),
            extras: { child_scans: outcomes.map((o) => o.child) },
        };
    },
}));
/**
 * What each child is asked for. `force`: a child is a fresh run under this
 * parent, never a cache hit on some earlier scan (whose row would then be
 * claimed by two parents). `scan_sast` also gets `local_only` and `auto_fix`;
 * the clean-tree check `auto_fix` needs has already passed (or been waived by
 * `allow_dirty`) for this call, and the children's own report directories must
 * not fail it a second time, so the child is told the tree is allowed dirty.
 */
function childInput(name, input, projectPath) {
    const base = { project_path: projectPath, force: true };
    if (name !== 'scan_sast')
        return base;
    return {
        ...base,
        ...(input.local_only === true ? { local_only: true } : {}),
        ...(input.auto_fix === true ? { auto_fix: true, allow_dirty: true } : {}),
    };
}
async function runChild(name, input, ctx, meta) {
    const empty = (child, runs, cancelled) => ({
        child,
        tools_run: runs,
        missing_tools: [],
        report_paths: [],
        findings: [],
        cves: [],
        cancelled,
    });
    const tool = TOOLS.find((t) => t.name === name);
    if (!tool) {
        return empty({ tool: name, scan_id: null, status: 'failed', error: 'not registered' }, [
            { name, status: 'failed', reason: `tool ${name} is not registered` },
        ], false);
    }
    if (ctx.signal.aborted)
        return empty({ tool: name, scan_id: null, status: 'cancelled' }, [], true);
    // A child that throws costs that child — a failed entry — never the
    // parent, and never its siblings' results (they run in Promise.all).
    let r;
    try {
        r = await tool.handler(input, ctx.plugin, meta);
    }
    catch (e) {
        if (ctx.signal.aborted)
            return empty({ tool: name, scan_id: null, status: 'cancelled' }, [], true);
        const reason = e instanceof Error ? e.message : String(e);
        return empty({ tool: name, scan_id: null, status: 'failed', error: 'threw' }, [
            { name, status: 'failed', reason: `threw: ${reason}` },
        ], false);
    }
    if (!r.ok) {
        if (r.error.code === 'cancelled') {
            return empty({ tool: name, scan_id: null, status: 'cancelled', error: r.error.code }, [], true);
        }
        return empty({ tool: name, scan_id: null, status: 'failed', error: r.error.code }, [{ name, status: 'failed', reason: `${r.error.code}: ${r.error.message}` }], false);
    }
    const scanId = typeof r['scan_id'] === 'string' ? r['scan_id'] : null;
    const status = typeof r['status'] === 'string' ? r['status'] : 'completed';
    const coverage = typeof r['coverage'] === 'string' ? r['coverage'] : undefined;
    return {
        child: { tool: name, scan_id: scanId, status, ...(coverage !== undefined ? { coverage } : {}) },
        tools_run: Array.isArray(r['tools_run']) ? r['tools_run'] : [],
        missing_tools: stringArray(r['missing_tools']),
        report_paths: stringArray(r['report_paths']),
        // From storage, not from the response: the response is filtered
        // (`severity_min` is never passed down, but `top_findings` is capped).
        findings: scanId !== null ? ctx.plugin.storage.findings.listByScan(scanId) : [],
        cves: scanId !== null ? ctx.plugin.storage.cves.listActive(scanId).map(toCveInput) : [],
        cancelled: status === 'cancelled',
    };
}
function toCveInput(c) {
    const out = { cve_id: c.cve_id, package_name: c.package_name, severity: c.severity };
    if (c.installed_version !== undefined)
        out.installed_version = c.installed_version;
    if (c.fixed_version !== undefined)
        out.fixed_version = c.fixed_version;
    return out;
}
function stringArray(value) {
    return Array.isArray(value) ? value.filter((v) => typeof v === 'string') : [];
}
/** Two children can report the same entry (Trivy missing for deps and IaC): keep one. */
function uniqueRuns(runs) {
    const seen = new Set();
    return runs.filter((r) => {
        const key = JSON.stringify([r.name, r.status, r.reason ?? '']);
        if (seen.has(key))
            return false;
        seen.add(key);
        return true;
    });
}
//# sourceMappingURL=securityScanFull.js.map