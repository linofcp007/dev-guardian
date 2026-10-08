/**
 * `import_sarif` — record another tool's SARIF 2.1.0 log as `sarif_import`
 * scans, one per `run`, so its findings share the project's history:
 * baselines, diffs, suppressions, triage and reports (feature `sarif-import`).
 *
 * Not `makeScanTool`: the factory reassigns every identity and serves a
 * five-minute cache, both wrong for an import (see `sarif/persistImport.ts`).
 *
 * The log is untrusted input. It is read once, through the project's bounded
 * reader (`platform/projectFs.ts`, `hooks/configFile.ts`: the opened
 * descriptor is judged, a regular file only, at most the cap plus one byte);
 * a path outside the project needs `allow_outside_project`. Nothing the log
 * names is opened, fetched or run — its locations are resolved textually in
 * `sarif/importSarif.ts` — and no error quotes the log (US-1.AC-18): every
 * refusal below is a fixed text.
 */
import { basename, relative, resolve, sep } from 'node:path';
import { z } from 'zod';
import { readSmallText } from '../hooks/configFile.js';
import { isWithinDir, readProjectText } from '../platform/projectFs.js';
import { resolveProjectPath } from '../platform/projectPath.js';
import { importSarif, SarifImportError } from '../sarif/importSarif.js';
import { persistSarifImport } from '../sarif/persistImport.js';
import { ProjectPath } from '../schemas.js';
import { SEVERITY_ORDER, } from '../types.js';
import { computeCoverage } from './scanCoverage.js';
import { registerToolModule } from './index.js';
/** Largest log read: 50 MiB (US-1.AC-13). */
const LOG_MAX_BYTES = 50 * 1024 * 1024;
const TOP_FINDINGS = 10;
const inputSchema = {
    project_path: ProjectPath,
    sarif_path: z
        .string()
        .min(1)
        .describe('The SARIF 2.1.0 log to import: absolute, or relative to project_path.'),
    allow_outside_project: z
        .boolean()
        .optional()
        .describe('Read a log that is not under project_path. Default false: such a path is refused.'),
    max_results: z
        .number()
        .int()
        .min(1)
        .max(200_000)
        .optional()
        .describe('Results imported per run before stopping; the rest are counted and the scan is partial. Default 50000.'),
};
const tool = {
    name: 'import_sarif',
    title: 'Import a SARIF log',
    description: "Import another analysis tool's SARIF 2.1.0 log (CodeQL, Snyk, Trivy, Semgrep, gitleaks, a dev-guardian " +
        'export…) into the project history: one `sarif_import` scan per run, named by the tool that wrote it ' +
        '(tool.driver.name and version), one finding per result that is a finding. Imported findings behave like a ' +
        'native scanner\'s in set_baseline, diff_scans, regression_alert, suppress_finding, triage_findings, ' +
        "prioritize_findings and report_export — those take `source_tool` to say which tool's imports they read. " +
        "A new import of a tool becomes that tool's latest scan and never touches the open findings of another tool " +
        'or of the native scanners. Identities come from the log\'s fingerprints, else are computed as the native ' +
        'scanners do. Results that are not findings (pass, notApplicable…) and results accepted as suppressed at ' +
        'the source are counted, not imported; a result without a location inside the project is imported with no ' +
        'file. A result that cannot be read is skipped and the scan is partial, like one past max_results ' +
        '(default 50000, at most 200000). Secret-rule snippets are never stored. Read-only toward the log: nothing it ' +
        'names (URIs, helpUri, invocations) is opened, fetched or run. The log is read only if it is a regular file ' +
        'of at most 50 MiB under project_path (default: the working directory), or anywhere with ' +
        'allow_outside_project: true. Errors: invalid_sarif, outside_project, refused_file, not_found.',
    inputSchema,
    handler: async (input, ctx) => handler(input, ctx),
};
registerToolModule(tool);
function handler(input, ctx) {
    return Promise.resolve(run(input, ctx));
}
function run(input, ctx) {
    const inp = input;
    let projectPath;
    try {
        projectPath = resolveProjectPath(inp.project_path).path;
    }
    catch (e) {
        return fail('not_a_git_repo', e.message);
    }
    const logPath = resolve(projectPath, inp.sarif_path);
    const inside = isWithinDir(projectPath, logPath);
    if (!inside && inp.allow_outside_project !== true) {
        return fail('outside_project', 'The log is outside the project. Pass allow_outside_project: true to import it from there.');
    }
    const read = inside
        ? readProjectText(projectPath, logPath, LOG_MAX_BYTES)
        : readSmallText(logPath, LOG_MAX_BYTES);
    if (read.status === 'absent')
        return fail('not_found', 'No file exists at sarif_path.');
    // The path is lexically inside here, so an 'outside-project' refusal is a link that leads out of
    // the project (to a log, a device, a FIFO): the file is refused, whatever it is, not the location.
    if (read.status === 'refused')
        return fail('refused_file', refusalText(read.reason));
    let imported;
    try {
        imported = importSarif(read.text, {
            projectPath,
            ...(inp.max_results !== undefined ? { maxResults: inp.max_results } : {}),
        });
    }
    catch (e) {
        // The reader's message names a field or an index, never the log's content.
        if (e instanceof SarifImportError)
            return fail('invalid_sarif', e.message);
        throw e;
    }
    const sourceFile = inside ? relative(projectPath, logPath).split(sep).join('/') : basename(logPath);
    const scans = persistSarifImport(ctx.storage, projectPath, imported, { sourceFile });
    const runs = scans.map(({ scan_id }, i) => {
        const counts = imported.runs[i]?.counts;
        return counts === undefined ? null : describeRun(ctx, scan_id, counts);
    });
    const done = runs.filter((r) => r !== null);
    return {
        ok: true,
        project_path: projectPath,
        source_file: sourceFile,
        runs: done,
        counts_total: totalCounts(done.map((r) => r.counts)),
    };
}
/** The scan as its readers see it, plus how complete it was and what was left out. */
function describeRun(ctx, scanId, counts) {
    const scan = ctx.storage.scans.getById(scanId);
    if (scan === null)
        return null;
    const findings = ctx.storage.findings.listByScan(scanId);
    const coverage = computeCoverage(scan.tools_run, scan.missing_tools);
    const warnings = [];
    if (ctx.storageWarning)
        warnings.push(ctx.storageWarning);
    if (coverage !== 'full') {
        warnings.push(`Coverage ${coverage}: ${String(counts.skipped.length)} result(s) could not be read and ${String(counts.truncated)} ` +
            'were left out past the results limit, so absent findings are not proof they were fixed.');
    }
    if (counts.without_location > 0) {
        warnings.push(`${String(counts.without_location)} result(s) have no location inside the project and were imported without a file.`);
    }
    return {
        ...scan,
        findings_count_by_severity: countBySeverity(findings),
        top_findings: topFindings(findings),
        warnings,
        coverage,
        counts,
    };
}
function totalCounts(all) {
    const total = { results: 0, imported: 0, without_location: 0, skipped: 0, suppressed_at_source: 0, not_findings: 0, duplicates: 0, identity_computed: 0, truncated: 0 };
    for (const c of all) {
        total.results += c.results;
        total.imported += c.imported;
        total.without_location += c.without_location;
        total.skipped += c.skipped.length;
        total.suppressed_at_source += c.suppressed_at_source;
        total.not_findings += c.not_findings;
        total.duplicates += c.duplicates;
        total.identity_computed += c.identity_computed;
        total.truncated += c.truncated;
    }
    return total;
}
function countBySeverity(findings) {
    const out = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
    for (const f of findings)
        out[f.severity] += 1;
    return out;
}
function topFindings(findings) {
    return [...findings]
        .sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity] || a.fingerprint.localeCompare(b.fingerprint))
        .slice(0, TOP_FINDINGS);
}
/** Why a file that exists was not read — a fixed text per reason, never the file's content. */
function refusalText(reason) {
    switch (reason) {
        case 'too-large':
            return 'The log is larger than 50 MiB and was not read.';
        case 'not-a-regular-file':
            return 'sarif_path is not a regular file (a directory, FIFO or device) and was not read.';
        case 'outside-project':
            return 'sarif_path is a link that leads outside the project and was not read.';
        case 'remote-link':
            return 'sarif_path reaches a network or device path through a link and was not read.';
        default:
            return 'The log could not be read.';
    }
}
function fail(code, message) {
    return { ok: false, error: { code, message } };
}
//# sourceMappingURL=importSarif.js.map