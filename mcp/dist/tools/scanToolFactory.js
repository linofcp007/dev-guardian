/**
 * Generic scan-tool factory.
 *
 * Most of our scan tools share the same lifecycle:
 *
 *   1. Validate input (zod)
 *   2. Resolve project_path
 *   3. (Optional) Check working-tree is clean for auto_fix
 *   4. Compute tree_hash
 *   5. Cache hit? → return existing scan_id flagged as cached
 *   6. Insert scans(running)
 *   7. Invoke the scanner (the tool-specific bit)
 *   8. Apply parsers, filter by severity_min, persist findings/CVEs
 *   9. Finalize scans → completed / failed / cancelled / output_too_large
 *  10. Build and return ScanResult
 *
 * Steps 1–6 and 8–10 are common — this factory implements them. Only step
 * 7 (and the bits inside `config.invoke`) is tool-specific.
 *
 * The factory is single-tenant per process: concurrent calls for the same
 * tree_hash are serialised by SQLite's transactions, but the runtime
 * doesn't attempt to coalesce two in-flight calls into a single run.
 */
import { randomUUID } from 'node:crypto';
import { makeProgressEmitter } from '../progress/progressEmitter.js';
import { getScanLimiter } from '../runners/concurrencyLimiter.js';
import { runShellScript } from '../runners/shellRunner.js';
import { filterFindings } from '../severity/filter.js';
import { SEVERITY_ORDER } from '../types.js';
import { computeTreeHash } from '../treeHash/computeTreeHash.js';
import { InvalidProjectPathError, resolveProjectPath, } from '../platform/projectPath.js';
import { isWorkingTreeClean } from './gitState.js';
const FIVE_MINUTES_MS = 5 * 60 * 1000;
export function makeScanTool(config) {
    return {
        name: config.name,
        description: config.description,
        ...(config.title ? { title: config.title } : {}),
        inputSchema: config.inputSchema,
        handler: (rawInput, plugin, callMeta) => runScanPipeline(config, rawInput, plugin, callMeta),
    };
}
async function runScanPipeline(config, input, plugin, callMeta) {
    if (config.supportsAutoFix !== false && input.auto_fix === true) {
        if (input.allow_dirty !== true) {
            try {
                const resolved = resolveProjectPath(input.project_path);
                if (!(await isWorkingTreeClean(resolved.path))) {
                    return failDomain('working_tree_dirty', `auto_fix=true requires a clean working tree.`, {
                        allow_dirty: true,
                    });
                }
            }
            catch (e) {
                if (e instanceof InvalidProjectPathError) {
                    return failDomain('not_a_git_repo', e.message);
                }
                throw e;
            }
        }
    }
    let resolvedProject;
    try {
        resolvedProject = resolveProjectPath(input.project_path);
    }
    catch (e) {
        if (e instanceof InvalidProjectPathError) {
            return failDomain('not_a_git_repo', e.message);
        }
        throw e;
    }
    const projectPath = resolvedProject.path;
    const warnings = [];
    if (resolvedProject.warning)
        warnings.push(resolvedProject.warning);
    if (plugin.storageWarning)
        warnings.push(plugin.storageWarning);
    if (plugin.shell === null) {
        return failDomain('no_bash_shell', 'No usable bash shell was found on this host. Run `install_toolchain` or install Git Bash / WSL.');
    }
    const treeHash = await computeTreeHash(projectPath);
    // Cache check.
    const ttl = config.cacheTtlMs ?? FIVE_MINUTES_MS;
    const fresh = new Date(Date.now() - ttl).toISOString();
    if (input.force !== true) {
        const cached = plugin.storage.scans.findCacheHit({
            tree_hash: treeHash,
            scan_type: config.scan_type,
            freshThreshold: fresh,
        });
        if (cached) {
            return cachedResult(plugin, cached.scan_id, warnings);
        }
    }
    // Insert running scan.
    const scanId = randomUUID();
    plugin.storage.scans.insert({
        scan_id: scanId,
        scan_type: config.scan_type,
        project_path: projectPath,
        tree_hash: treeHash,
    });
    plugin.storage.scans.attachTreeCache({
        tree_hash: treeHash,
        scan_id: scanId,
        scan_type: config.scan_type,
    });
    // Set up per-call context.
    // Use the host's AbortSignal if provided; otherwise build a fresh one so
    // child runners always have a signal to listen to. The host signal is
    // what propagates `notifications/cancelled` from the MCP client down to
    // SIGTERM on the child process tree.
    const controller = new AbortController();
    const externalSignal = callMeta?.signal;
    if (externalSignal) {
        if (externalSignal.aborted) {
            controller.abort();
        }
        else {
            externalSignal.addEventListener('abort', () => {
                controller.abort();
            }, { once: true });
        }
    }
    const progress = makeProgressEmitter({
        token: callMeta?.progressToken,
        notifier: plugin.progressNotifier,
    });
    const ctx = {
        plugin,
        scanId,
        projectPath,
        signal: controller.signal,
        progress,
        scriptEnv: {
            ...process.env,
            PROJECT_PATH: projectPath,
            GUARDIAN_SCAN_ID: scanId,
        },
    };
    // Acquire a slot from the global concurrency limiter so 50 parallel
    // calls from the host don't fork 50 scanner processes. Default cap is 2.
    const limiter = getScanLimiter();
    await limiter.acquire();
    let invocation;
    try {
        invocation = await config.invoke(input, ctx);
    }
    catch (e) {
        plugin.storage.scans.finalize({
            scan_id: scanId,
            status: 'failed',
            tools_run: [],
            missing_tools: [],
            error: e instanceof Error ? e.message : String(e),
        });
        progress.dispose();
        limiter.release();
        return failDomain('scanner_failed', e instanceof Error ? e.message : 'Scanner failed with an unknown error');
    }
    finally {
        progress.dispose();
    }
    limiter.release();
    // Apply parsers.
    let findings = [];
    const cves = [];
    const parserCtx = { project_path: projectPath };
    for (const task of invocation.parser_inputs) {
        const out = task.parser.parse(task.input, parserCtx);
        findings.push(...out.findings);
        cves.push(...out.cves);
    }
    // Severity floor.
    findings = filterFindings(findings, input.severity_min);
    // Persist findings + CVEs (best-effort; one transaction per repo).
    if (findings.length > 0) {
        plugin.storage.findings.bulkInsert(findings.map((f) => ({ ...f, scan_id: scanId })));
    }
    if (cves.length > 0) {
        plugin.storage.cves.bulkUpsert(cves.map((c) => ({ ...c, scan_id: scanId })));
    }
    const status = invocation.outcome === 'completed'
        ? 'completed'
        : invocation.outcome === 'cancelled'
            ? 'cancelled'
            : 'failed';
    const finalize = {
        scan_id: scanId,
        status,
        tools_run: invocation.tools_run,
        missing_tools: invocation.missing_tools,
    };
    if (invocation.report_paths[0] !== undefined)
        finalize.report_dir = invocation.report_paths[0];
    if (invocation.error !== undefined)
        finalize.error = invocation.error;
    // Persist extras into scans.meta so resources (compliance/status, etc.)
    // can read them without forcing a re-run.
    if (invocation.extras !== undefined)
        finalize.meta = invocation.extras;
    plugin.storage.scans.finalize(finalize);
    if (status === 'cancelled') {
        return failDomain('cancelled', 'Scan was cancelled by the host.');
    }
    if (invocation.outcome === 'output_too_large') {
        return failDomain('output_too_large', 'Scanner output exceeded 5 MB. Read full report from report_paths instead.', { report_paths: invocation.report_paths });
    }
    // Build the ScanResult response.
    const counts = countBySeverity(findings);
    const top = topFindings(findings, 10);
    const result = {
        scan_id: scanId,
        scan_type: config.scan_type,
        project_path: projectPath,
        tree_hash: treeHash,
        started_at: new Date().toISOString(), // best-effort; real value lives in DB
        finished_at: new Date().toISOString(),
        status,
        tools_run: invocation.tools_run,
        missing_tools: invocation.missing_tools,
        report_paths: invocation.report_paths,
        findings_count_by_severity: counts,
        top_findings: top,
        warnings,
    };
    const payload = {
        ...result,
        ...(invocation.extras ?? {}),
    };
    return { ok: true, ...payload };
}
function cachedResult(plugin, scanId, warnings) {
    const record = plugin.storage.scans.getById(scanId);
    if (!record) {
        return failDomain('unknown_scan_id', `Cached scan ${scanId} could not be loaded.`);
    }
    const findings = plugin.storage.findings.listByScan(scanId);
    const counts = countBySeverity(findings);
    const top = topFindings(findings, 10);
    const payload = {
        ...record,
        cached: true,
        cached_from: scanId,
        findings_count_by_severity: counts,
        top_findings: top,
        warnings,
    };
    return { ok: true, ...payload };
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
function failDomain(code, message, retry_with) {
    const error = { code, message };
    if (retry_with !== undefined)
        error.retry_with = retry_with;
    return { ok: false, error };
}
// Re-export for tools to build their `parser_inputs` ergonomically.
export { runShellScript };
//# sourceMappingURL=scanToolFactory.js.map