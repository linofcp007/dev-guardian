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
 *   8. Apply parsers, persist findings/CVEs
 *   9. Finalize scans → completed / failed / cancelled / output_too_large
 *  10. Filter by severity_min, then build and return ScanResult
 *
 * Steps 1–6 and 8–10 are common — this factory implements them. Only step
 * 7 (and the bits inside `config.invoke`) is tool-specific.
 *
 * **`severity_min` filters the response, never the history.** Step 8 stores
 * everything the scan found and step 10 shows the caller the slice they
 * asked for; the order used to be the other way round, which threw the rest
 * away. See the comment above `bulkInsert` for what that cost.
 *
 * The factory is single-tenant per process: concurrent calls for the same
 * tree_hash are serialised by SQLite's transactions, but the runtime
 * doesn't attempt to coalesce two in-flight calls into a single run.
 */
import { randomUUID } from 'node:crypto';
import { buildDriftAdvisory } from '../configdrift/advisory.js';
import { detectConfigDrift } from '../configdrift/detect.js';
import { configsDirFromScriptsDir } from '../platform/configsDir.js';
import { resolveVersion } from '../platform/version.js';
import { makeProgressEmitter } from '../progress/progressEmitter.js';
import { getScanLimiter } from '../runners/concurrencyLimiter.js';
import { runShellScript } from '../runners/shellRunner.js';
import { describeShortfallTiers, severityShortfall } from '../severity/breakdown.js';
import { filterFindings } from '../severity/filter.js';
import { SEVERITY_ORDER } from '../types.js';
import { computeTreeHash } from '../treeHash/computeTreeHash.js';
import { InvalidProjectPathError, resolveProjectPath, } from '../platform/projectPath.js';
import { isWorkingTreeClean } from './gitState.js';
import { assessCoverage } from './scanCoverage.js';
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
    const driftAdvisory = configDriftAdvisory(plugin, projectPath);
    if (driftAdvisory)
        warnings.push(driftAdvisory);
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
            return cachedResult(plugin, cached.scan_id, warnings, input.severity_min);
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
    // Cross-parser reconciliation (e.g. drop npm-audit dupes of Trivy CVEs)
    // before anything counts, persists, or filters the findings.
    if (invocation.dedupeFindings)
        findings = invocation.dedupeFindings(findings);
    // Persist findings + CVEs (best-effort; one transaction per repo).
    //
    // ---- Why the severity floor is NOT applied before this ---------------
    //
    // It used to be, and the filtered findings were therefore never written.
    // A caller passing `severity_min: 'high'` did not merely fail to SEE the
    // medium findings: they did not exist in the history. So a `set_baseline`
    // captured from that scan silently omitted them, `diff_scans` compared
    // against data that was never recorded, the next UNFILTERED scan reported
    // them as `new` — the opposite of true, they had been there all along —
    // and the trend showed an improvement that never happened.
    //
    // `cves` on the very next line was already upserted unfiltered, so the two
    // halves of a `deps` scan disagreed with each other about the same
    // vulnerability: a medium CVE below the floor kept its `cves` row (and its
    // place in `guardian://cves/active`) while its Finding was dropped.
    //
    // The floor is a property of the REQUEST. History records the TREE. The
    // filtering now happens once, below, on the response only.
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
    //
    // `severity_min` rides along in the same object. Now that the floor no
    // longer touches what is stored, a later reader of this scan row needs it
    // to answer a question the findings alone cannot: "this scan found nothing
    // above high" and "this scan was FILTERED at high" produce the same reply
    // count and are otherwise indistinguishable. It goes in `meta` — the
    // existing `TEXT NOT NULL DEFAULT '{}'` JSON column from schema v1 — and
    // not a new column: every reader of `meta` (riskScore, sbomDiff,
    // licenseCompatibility, the dotnet/wp resources, the dashboard snapshot)
    // picks named keys out of it, so an extra key is inert for all of them and
    // no migration is needed. No tool puts `severity_min` in `extras`, so
    // there is nothing to collide with.
    const meta = { ...(invocation.extras ?? {}) };
    if (input.severity_min !== undefined)
        meta['severity_min'] = input.severity_min;
    if (Object.keys(meta).length > 0)
        finalize.meta = meta;
    plugin.storage.scans.finalize(finalize);
    if (status === 'cancelled') {
        return failDomain('cancelled', 'Scan was cancelled by the host.');
    }
    if (invocation.outcome === 'output_too_large') {
        return failDomain('output_too_large', 'Scanner output exceeded 5 MB. Read full report from report_paths instead.', { report_paths: invocation.report_paths });
    }
    // Build the ScanResult response. THIS is where the severity floor lands:
    // it shapes the view, never the history persisted above.
    const visible = filterFindings(findings, input.severity_min);
    const counts = countBySeverity(visible);
    const top = topFindings(visible, 10);
    const floor = severityFloorNotice(findings, input.severity_min, scanId);
    if (floor?.warning)
        warnings.push(floor.warning);
    // Coverage: did the scanners that were supposed to run actually run? A
    // "0 findings" result is only trustworthy at coverage 'full'. When a primary
    // scanner was missing/failed we push a loud warning so the count is never
    // mistaken for a clean bill of health.
    const { coverage, warning: coverageWarning } = assessCoverage(config.scan_type, invocation.tools_run, invocation.missing_tools);
    if (coverageWarning)
        warnings.unshift(coverageWarning);
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
        coverage,
        ...(floor ? { severity_filter: floor.disclosure } : {}),
    };
    const payload = {
        ...result,
        ...(invocation.extras ?? {}),
    };
    return { ok: true, ...payload };
}
/**
 * The config-drift advisory, or `null` when there is nothing to say.
 *
 * ---- Why it hangs off the scan pipeline ------------------------------
 *
 * `init_project` copies four baseline configs into a project and then never
 * looks at them again, so a fix to a shipped config — `base.yml`'s
 * `wp-unescaped-output`, which could not match anything until b51a2dc — never
 * reaches a project that already ran init. A check only helps if it runs
 * somewhere people actually go, and every scan tool in this codebase comes
 * through here, including the cached path.
 *
 * ---- Why it checks all four, not "the one this scan reads" -----------
 *
 * The narrower design was tried first and does not survive contact: `scan_sast`
 * runs Semgrep with `--config=auto` plus registered custom rules and never
 * reads `.semgrep.yml` at all; `deps_audit` only existence-checks
 * `renovate.json`; `.pre-commit-config.yaml` is consumed by git hooks, not by
 * any scan. Mapping scan types to files would encode four claims about who
 * reads what, three of which are already false. What is true is simpler: these
 * are the baselines this project installed, and the scan is when the user is
 * looking. Reading four small files and hashing them costs nothing next to a
 * Semgrep run.
 *
 * Never throws, and cannot alter the scan: the return value's only
 * destination is the `warnings` string array.
 */
function configDriftAdvisory(plugin, projectPath) {
    try {
        return buildDriftAdvisory(detectConfigDrift({
            projectPath,
            configsDir: configsDirFromScriptsDir(plugin.scriptsDir),
            currentVersion: resolveVersion(),
        }));
    }
    catch {
        return null;
    }
}
/**
 * A cache hit, shaped exactly like a fresh run of the same call.
 *
 * `severityMin` is THIS call's floor, not the cached scan's: the stored
 * findings are the whole tree (see the persistence comment above), so the
 * view is re-derived per caller. Without that, a cache hit ignored the floor
 * the caller had just passed and answered with everything.
 *
 * One case it cannot repair: a scan row written by a version of this file
 * that filtered before persisting holds only the above-floor subset, and
 * nothing here can tell that apart from a tree with nothing else in it.
 * Those rows age out of the 5-minute cache window immediately; they persist
 * in history.
 */
function cachedResult(plugin, scanId, warnings, severityMin) {
    const record = plugin.storage.scans.getById(scanId);
    if (!record) {
        return failDomain('unknown_scan_id', `Cached scan ${scanId} could not be loaded.`);
    }
    const stored = plugin.storage.findings.listByScan(scanId);
    const visible = filterFindings(stored, severityMin);
    const counts = countBySeverity(visible);
    const top = topFindings(visible, 10);
    const floor = severityFloorNotice(stored, severityMin, scanId);
    // Re-derive coverage from the persisted tools_run/missing_tools so a cached
    // scan carries the same honest signal as a fresh one.
    const { coverage, warning: coverageWarning } = assessCoverage(record.scan_type, record.tools_run, record.missing_tools);
    const allWarnings = coverageWarning ? [coverageWarning, ...warnings] : [...warnings];
    if (floor?.warning)
        allWarnings.push(floor.warning);
    const payload = {
        ...record,
        cached: true,
        cached_from: scanId,
        findings_count_by_severity: counts,
        top_findings: top,
        warnings: allWarnings,
        coverage,
        ...(floor ? { severity_filter: floor.disclosure } : {}),
    };
    return { ok: true, ...payload };
}
/**
 * The `severity_filter` block for a response, plus the warning that goes
 * with it — or `null` when no floor was passed and there is nothing to say.
 *
 * `warning` is null when the floor withheld nothing: a caller who passes
 * `severity_min: 'high'` against a project with only criticals should not be
 * told anything happened, because nothing did.
 *
 * `all` must be the UNFILTERED findings of the scan; the whole point is to
 * describe the gap between those and what the response carries.
 */
function severityFloorNotice(all, min, scanId) {
    if (min === undefined)
        return null;
    const shortfall = severityShortfall(all, min);
    const disclosure = {
        severity_min: min,
        withheld: shortfall.total,
        withheld_by_severity: shortfall.by_severity,
        suggested_severity_min: shortfall.suggested_severity_min,
        recovered_by_suggestion: shortfall.recovered_by_suggestion,
    };
    if (shortfall.total === 0)
        return { disclosure, warning: null };
    const suggestion = shortfall.suggested_severity_min === null
        ? ''
        : ` Pass severity_min "${shortfall.suggested_severity_min}" to see ` +
            `${shortfall.recovered_by_suggestion} of them.`;
    return {
        disclosure,
        warning: `severity_min "${min}" filtered this response only: ${shortfall.total} finding(s) ` +
            `(${describeShortfallTiers(shortfall)}) are recorded in scan ${scanId} and are not ` +
            `shown here. Baselines and diffs against this scan include them.${suggestion}`,
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
function failDomain(code, message, retry_with) {
    const error = { code, message };
    if (retry_with !== undefined)
        error.retry_with = retry_with;
    return { ok: false, error };
}
// Re-export for tools to build their `parser_inputs` ergonomically.
export { runShellScript };
//# sourceMappingURL=scanToolFactory.js.map