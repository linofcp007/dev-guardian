/**
 * Writes a SARIF import (`./importSarif.ts`) to the project's history: one
 * `sarif_import` scan per run, its findings, and the identities of those the
 * log gave no fingerprints for (feature `sarif-import`).
 *
 * Not `makeScanTool`: the factory reassigns every identity (a fingerprint-
 * derived one must survive) and serves a five-minute cache (an import is a
 * fact about a file, never a result to reuse). The storage calls are the
 * factory's own — insert, bulkInsert, adoptIdentities, finalize.
 */
import { randomUUID } from 'node:crypto';
import { assignIdentities, makeSourceReader } from '../fingerprint/findingIdentity.js';
import { redactCredentialSnippets } from '../redaction/secretFindingRedaction.js';
/**
 * What the import left out, as the `missing_tools` entries that make the scan's
 * coverage partial (`tools/scanCoverage.ts#computeCoverage`) — the mechanism
 * every native scan uses for "a part of what was asked was not scanned".
 *
 * A result with no location inside the project is not one: it was imported
 * whole, only its place is unknown, and `counts.without_location` says how
 * many. Counting it as a gap made every later diff of that tool read absent
 * findings as unmeasured rather than resolved — always, for a log whose URIs
 * all point outside the root, as an image scan's do.
 */
export function importCoverageGaps(counts) {
    const gaps = [];
    if (counts.skipped.length > 0)
        gaps.push('sarif:skipped_results');
    if (counts.truncated > 0)
        gaps.push('sarif:results_over_limit');
    return gaps;
}
/** The scans written, one per run, in run order. */
export function persistSarifImport(storage, projectPath, result, opts) {
    return result.runs.map((run) => ({ scan_id: persistRun(storage, projectPath, run, opts) }));
}
function persistRun(storage, projectPath, run, opts) {
    const scanId = randomUUID();
    // No tree hash and no cache key: the scan is never served from the cache.
    storage.scans.insert({ scan_id: scanId, scan_type: 'sarif_import', project_path: projectPath, tree_hash: '' });
    try {
        const findings = withIdentities(run.findings, projectPath);
        if (findings.length > 0) {
            storage.findings.bulkInsert(findings.map((f) => ({ ...f, scan_id: scanId })));
            // A suppression that predates identities follows its finding from now on.
            storage.suppressions.adoptIdentities(scanId);
        }
        // The reader is the one "scanner" that ran.
        const toolsRun = [{ name: 'sarif', status: 'ok' }];
        storage.scans.finalize({
            scan_id: scanId,
            status: 'completed',
            tools_run: toolsRun,
            missing_tools: importCoverageGaps(run.counts),
            meta: {
                source_tool: run.source_tool,
                ...(run.source_version !== undefined ? { source_version: run.source_version } : {}),
                source_file: opts.sourceFile,
                counts: run.counts,
            },
        });
    }
    catch (e) {
        storage.scans.finalize({
            scan_id: scanId,
            status: 'failed',
            tools_run: [],
            missing_tools: [],
            error: e instanceof Error ? e.message : String(e),
        });
        throw e;
    }
    return scanId;
}
/**
 * Identities the log's fingerprints gave are kept as they are; the rest are
 * computed as the native scanners do, over the run's own findings without one
 * (the occurrence counter is per scan), reading the project's files. Credential
 * snippets are cleared last, as the factory does.
 */
function withIdentities(findings, projectPath) {
    const computed = assignIdentities(findings.filter((f) => f.identity === undefined), { projectPath, readSource: makeSourceReader(projectPath) });
    let next = 0;
    const merged = findings.map((f) => {
        if (f.identity !== undefined)
            return f;
        const keyed = computed[next];
        next += 1;
        return keyed ?? f;
    });
    return redactCredentialSnippets(merged);
}
//# sourceMappingURL=persistImport.js.map