/**
 * `report_export` — write a report for a scan (or a stakeholder narrative) to
 * `.guardian/reports/…`.
 *
 * Formats: markdown (default, handover doc), html (branded Pro Digital Key
 * shell, dark/light toggle, self-contained, browser-openable), sarif (SARIF
 * 2.1.0), json (raw findings). Local-only, no third-party services.
 *
 * Two HTML modes:
 *   - scan mode (default): renders scan metadata, a severity bar, findings and
 *     CVE tables for a scan_id.
 *   - narrative mode (`content_markdown`): wraps stakeholder Markdown in the same
 *     branded shell — used by `/guardian-report`. scan_id is ignored here.
 *
 * Scan mode also states each finding's CWE / OWASP Top 10:2025 category and
 * an "OWASP Top 10:2025 coverage" table (`frameworks/coverage.ts`): a
 * category is tested only when, for every source language of the scanned
 * project (`frameworks/projectLanguages.ts`), a scanner that ran fully ok in
 * THIS scan has enough rules for it. For an orchestrated security_full the
 * bookkeeping is its child scans', whose rows record what the parent's
 * merged bookkeeping does not (whether scan_sast ran `local_only`); for an
 * audit_executive row, its sub-scans' (and their children's), since the
 * row itself lists sub-tools, not scanners.
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { z } from 'zod';
import { owaspCoverage } from '../frameworks/coverage.js';
import { languagesOfRunsAsync, resolveProjectLanguagesAsync } from '../frameworks/projectLanguages.js';
import { latestStateScan } from '../history/openSet.js';
import { isOrchestratedFullScan, TARGET_SCAN_TYPES } from '../history/scanRoles.js';
import { resolveProjectPath } from '../platform/projectPath.js';
import { redactCredentialSnippets } from '../redaction/secretFindingRedaction.js';
import { escapeHtml, markdownToSafeHtml, renderHtmlDocument, severityBar, severityChip, } from '../report/htmlTheme.js';
import { owaspCoverageHtml, owaspCoverageMarkdown, taxonomyCell } from '../report/owaspCoverage.js';
import { toSarif } from '../report/sarif.js';
import { ProjectPath } from '../schemas.js';
import { CVE_SOURCE_SCAN_TYPES, } from '../types.js';
import { registerToolModule } from './index.js';
const inputSchema = {
    project_path: ProjectPath,
    scan_id: z
        .string()
        .uuid()
        .optional()
        .describe("Scan to export. Defaults to project_path's newest usable finding-producing scan."),
    format: z
        .enum(['html', 'sarif', 'markdown', 'json'])
        .optional()
        .default('markdown')
        .describe('Output format. markdown (default, handover doc), html (branded Pro Digital Key shell with a ' +
        'dark/light toggle, self-contained, opens offline), sarif (SARIF 2.1.0 for CI/IDE code ' +
        'scanning), or json (raw findings).'),
    content_markdown: z
        .string()
        .optional()
        .describe('Stakeholder-narrative Markdown. When set, it is wrapped in the branded HTML shell ' +
        '(dark/light) instead of rendering a scan — scan_id is ignored. Used by /guardian-report.'),
    title: z
        .string()
        .optional()
        .describe('Title for the content_markdown report. Default: "Pro Digital Key — Report".'),
    subtitle: z.string().optional().describe('Optional subtitle under the title (content_markdown mode).'),
    lang: z
        .enum(['en', 'pt', 'es'])
        .optional()
        .describe('Language for the HTML shell chrome (report title + footer). Default: en.'),
};
const tool = {
    name: 'report_export',
    title: 'Export a report (branded HTML / SARIF / Markdown / JSON)',
    description: 'Write a report in one of four formats: markdown (default — handover doc), html (branded Pro ' +
        'Digital Key shell with a dark/light toggle, self-contained, opens offline in any browser), ' +
        'sarif (SARIF 2.1.0 for GitHub/GitLab code scanning), or json (raw findings). Pass ' +
        'content_markdown to render a stakeholder narrative as Markdown (or branded HTML with ' +
        'format=html). A scan report gives each finding its CWE / OWASP Top 10:2025 category (SARIF: ' +
        'external/cwe and owasp-2025 tags) and states which OWASP categories the scan actually tested, per ' +
        'source language of the project. An explicit scan_id must be a scan of project_path (another ' +
        "project's is refused, with retry_with naming its project) and not still running. " +
        'Local file only — no external services, no web fonts.',
    inputSchema,
    handler: async (input, ctx) => handler(input, ctx),
};
registerToolModule(tool);
async function handler(input, ctx) {
    const inp = input;
    const format = inp.format ?? 'markdown';
    const lang = inp.lang ?? 'en';
    let projectPath;
    try {
        projectPath = resolveProjectPath(inp.project_path).path;
    }
    catch (e) {
        return failDomain('not_a_git_repo', e.message);
    }
    // Narrative mode — wrap stakeholder Markdown in the branded shell.
    if (inp.content_markdown != null) {
        const title = inp.title ?? 'Pro Digital Key — Report';
        const narrativeFormat = format === 'markdown' ? 'markdown' : 'html';
        const content = narrativeFormat === 'markdown'
            ? inp.content_markdown
            : renderHtmlDocument({
                title,
                ...(inp.subtitle ? { subtitle: inp.subtitle } : {}),
                sections: [markdownToSafeHtml(inp.content_markdown)],
                lang,
            });
        const outDir = join(projectPath, '.guardian', 'reports', `report-${slugify(title)}`);
        mkdirSync(outDir, { recursive: true });
        const fileName = narrativeFormat === 'markdown' ? 'report.md' : 'report.html';
        const outFile = join(outDir, fileName);
        writeFileSync(outFile, content, 'utf8');
        return {
            ok: true,
            kind: 'narrative',
            format: narrativeFormat,
            title,
            file_path: outFile,
            bytes: Buffer.byteLength(content, 'utf8'),
        };
    }
    // Scan mode. Default: THIS project's newest usable state scan — not the
    // newest completed scan in the whole database, which exported another
    // project's scan (or an SBOM) into this project's reports directory.
    const latest = inp.scan_id === undefined ? latestStateScan(ctx.storage, projectPath) : null;
    const scanId = inp.scan_id ?? latest?.scan?.scan_id;
    if (!scanId) {
        return failDomain('unknown_scan_id', `No usable completed scan of ${projectPath} to export.` +
            ((latest?.skipped.count ?? 0) > 0
                ? ` ${latest?.skipped.count ?? 0} scan(s) were skipped because their scanners did not run (coverage none).`
                : ''));
    }
    const scan = ctx.storage.scans.getById(scanId);
    if (!scan)
        return failDomain('unknown_scan_id', `Scan '${scanId}' not found.`);
    // An explicit scan_id must be a scan of THIS project: the report is written
    // into this project's `.guardian/reports`, and it used to take any scan in
    // the database — another project's findings filed under this one. A scan of
    // an audit target (a third-party skill, a site) belongs to no project, and
    // is exported wherever it is asked for.
    if (scan.project_path !== projectPath && !TARGET_SCAN_TYPES.has(scan.scan_type)) {
        return {
            ok: false,
            error: {
                code: 'unknown_scan_id',
                message: `Scan '${scanId}' is a scan of ${scan.project_path}, not of ${projectPath}; its report would be ` +
                    `written into ${projectPath}'s .guardian/reports. Pass project_path: '${scan.project_path}' to export it there.`,
                retry_with: { project_path: scan.project_path, scan_id: scanId },
            },
        };
    }
    // Its findings are inserted in chunks while the row is `running`: a report
    // now would hold whichever chunks happened to be in.
    if (scan.status === 'running') {
        return failDomain('unknown_scan_id', `Scan '${scanId}' is still running: its findings are not all stored yet.`);
    }
    // Redacted here too, not only at persistence time: this reads whatever is
    // stored, and `json` dumps a finding's every field — a row written before
    // `redaction/secretFindingRedaction.ts` existed, or by a path outside its
    // reach, must not resurface a credential's own line in an exported report.
    const findings = redactCredentialSnippets(ctx.storage.findings.listByScan(scanId));
    const cves = CVE_SOURCE_SCAN_TYPES.includes(scan.scan_type)
        ? ctx.storage.cves.listActive(scanId)
        : [];
    // Judged against the languages the scans recorded when they ran; a row
    // written before that record falls back to today's tree, and says so —
    // listed without blocking the server (`git ls-files` can take seconds).
    const runs = coverageRunsOfScan(ctx, scan);
    const owasp = owaspCoverage(runs, findings, await languagesOfRunsAsync(runs, () => resolveProjectLanguagesAsync(ctx.storage.stack, scan.project_path)));
    const { content, fileName } = renderReport(format, scan, findings, cves, lang, owasp);
    const outDir = join(projectPath, '.guardian', 'reports', `export-${scanId.slice(0, 8)}`);
    mkdirSync(outDir, { recursive: true });
    const outFile = join(outDir, fileName);
    writeFileSync(outFile, content, 'utf8');
    return {
        ok: true,
        kind: 'scan',
        scan_id: scanId,
        format,
        file_path: outFile,
        bytes: Buffer.byteLength(content, 'utf8'),
        findings_count: findings.length,
        cves_count: cves.length,
        ...((latest?.skipped.count ?? 0) > 0 ? { skipped_scans: latest?.skipped } : {}),
    };
}
/** The scan ids a row delegates to: an orchestrated security_full's children, an audit's sub-scans. */
function delegatedScanIds(scan) {
    if (isOrchestratedFullScan(scan)) {
        const children = scan.meta?.['child_scans'];
        return (Array.isArray(children) ? children : []).flatMap((child) => {
            const id = child !== null && typeof child === 'object' ? child.scan_id : undefined;
            return typeof id === 'string' ? [id] : [];
        });
    }
    if (scan.scan_type === 'audit') {
        const subs = scan.meta?.['sub_scan_ids'];
        if (subs === null || typeof subs !== 'object' || Array.isArray(subs))
            return [];
        return Object.values(subs).filter((id) => typeof id === 'string');
    }
    return null;
}
/**
 * The bookkeeping this report's coverage rests on: the scan itself, or —
 * for an orchestrated security_full or an audit_executive row — the scans
 * it delegated to, followed down (an audit's security_full sub-scan to its
 * own children). A delegated scan that is gone or did not complete
 * contributes nothing, so its categories read "not tested" rather than
 * borrowing the parent's merged bookkeeping.
 */
function coverageRunsOfScan(ctx, scan, seen = new Set()) {
    if (seen.has(scan.scan_id))
        return [];
    seen.add(scan.scan_id);
    const delegated = delegatedScanIds(scan);
    if (delegated === null) {
        return [
            {
                scan_id: scan.scan_id,
                scan_type: scan.scan_type,
                tools_run: scan.tools_run,
                missing_tools: scan.missing_tools,
                ...(scan.meta !== undefined ? { meta: scan.meta } : {}),
            },
        ];
    }
    const runs = [];
    for (const id of delegated) {
        const row = ctx.storage.scans.getById(id);
        if (row !== null && row.status === 'completed')
            runs.push(...coverageRunsOfScan(ctx, row, seen));
    }
    return runs;
}
function renderReport(format, scan, findings, cves, lang, owasp) {
    switch (format) {
        case 'sarif':
            return { content: toSarif(findings), fileName: 'report.sarif' };
        case 'json':
            return {
                content: JSON.stringify({ scan, findings, cves, owasp_2025: owasp }, null, 2),
                fileName: 'report.json',
            };
        case 'markdown':
            return { content: renderMarkdown(scan, findings, cves, owasp), fileName: 'report.md' };
        case 'html':
        default:
            return { content: renderHtml(scan, findings, cves, lang, owasp), fileName: 'report.html' };
    }
}
function renderMarkdown(scan, findings, cves, owasp) {
    const counts = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
    for (const f of findings)
        counts[f.severity] += 1;
    const lines = [];
    lines.push(`# dev-guardian scan report`);
    lines.push('');
    lines.push(`- **Scan ID:** ${scan.scan_id}`);
    lines.push(`- **Type:** ${scan.scan_type}`);
    lines.push(`- **Status:** ${scan.status}`);
    lines.push(`- **Started:** ${scan.started_at}`);
    lines.push(`- **Project:** \`${scan.project_path}\``);
    lines.push('');
    lines.push(`**Severity:** critical ${counts.critical} · high ${counts.high} · medium ${counts.medium} · low ${counts.low} · info ${counts.info}`);
    lines.push('');
    lines.push(`## Findings (${findings.length})`);
    lines.push('');
    if (findings.length === 0) {
        lines.push('_No findings._');
    }
    else {
        lines.push('| Sev | Tool | Rule | Title | Location | CWE / OWASP 2025 |');
        lines.push('| --- | --- | --- | --- | --- | --- |');
        for (const f of [...findings].sort((a, b) => severityOrder(b.severity) - severityOrder(a.severity))) {
            const loc = f.file_path ? `\`${f.file_path}${f.line_start ? `:${f.line_start}` : ''}\`` : '';
            lines.push(`| ${f.severity} | ${f.tool} | \`${f.rule_id ?? ''}\` | ${mdEscape(f.title)} | ${loc} | ${taxonomyCell(f)} |`);
        }
    }
    lines.push('');
    lines.push(...owaspCoverageMarkdown(owasp));
    if (cves.length > 0) {
        lines.push('');
        lines.push(`## Active CVEs (${cves.length})`);
        lines.push('');
        lines.push('| CVE | Sev | Package | Installed | Fixed |');
        lines.push('| --- | --- | --- | --- | --- |');
        for (const c of cves) {
            lines.push(`| ${c.cve_id} | ${c.severity} | ${c.package_name} | ${c.installed_version ?? ''} | ${c.fixed_version ?? ''} |`);
        }
    }
    lines.push('');
    lines.push("_Generated by dev-guardian — open-source. dev-guardian sends no telemetry of its own; " +
        "Semgrep's registry mode sends metrics — pass `local_only: true` to avoid it._");
    return lines.join('\n');
}
function mdEscape(s) {
    return s.replace(/\|/g, '\\|');
}
const SCAN_TITLE = {
    en: 'Security Report',
    pt: 'Relatório de Segurança',
    es: 'Informe de Seguridad',
};
function renderHtml(scan, findings, cves, lang, owasp) {
    const counts = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
    for (const f of findings)
        counts[f.severity] += 1;
    const meta = `<div class="pdk-meta">
  <strong>Scan ID:</strong> ${escapeHtml(scan.scan_id)}<br>
  <strong>Type:</strong> ${escapeHtml(scan.scan_type)}<br>
  <strong>Status:</strong> ${escapeHtml(scan.status)}<br>
  <strong>Started:</strong> ${escapeHtml(scan.started_at)}<br>
  <strong>Finished:</strong> ${escapeHtml(scan.finished_at ?? 'n/a')}<br>
  <strong>Project:</strong> <code>${escapeHtml(scan.project_path)}</code>
</div>`;
    const sevSection = `<h2>Severity distribution</h2>\n` +
        (findings.length === 0 ? '<p class="pdk-empty">No findings.</p>' : severityBar(counts));
    const findingRows = [...findings]
        .sort((a, b) => severityOrder(b.severity) - severityOrder(a.severity))
        .map((f) => `<tr>
  <td>${severityChip(f.severity)}</td>
  <td>${escapeHtml(f.tool)}</td>
  <td><code>${escapeHtml(f.rule_id ?? '')}</code></td>
  <td>${escapeHtml(f.title)}</td>
  <td><code>${escapeHtml(f.file_path ?? '')}${f.line_start ? `:${f.line_start}` : ''}</code></td>
  <td>${escapeHtml(taxonomyCell(f))}</td>
</tr>`)
        .join('');
    const findingsSection = `<h2>Findings (${findings.length})</h2>\n` +
        (findings.length === 0
            ? '<p class="pdk-empty">No findings.</p>'
            : `<table><thead><tr><th>Sev</th><th>Tool</th><th>Rule</th><th>Title</th><th>Location</th><th>CWE / OWASP 2025</th></tr></thead><tbody>${findingRows}</tbody></table>`);
    const cveRows = cves
        .map((c) => `<tr>
  <td><a href="https://nvd.nist.gov/vuln/detail/${escapeHtml(c.cve_id)}" target="_blank" rel="noopener">${escapeHtml(c.cve_id)}</a></td>
  <td>${severityChip(c.severity)}</td>
  <td>${escapeHtml(c.package_name)}</td>
  <td><code>${escapeHtml(c.installed_version ?? '')}</code></td>
  <td><code>${escapeHtml(c.fixed_version ?? '')}</code></td>
</tr>`)
        .join('');
    const cveSection = `<h2>Active CVEs (${cves.length})</h2>\n` +
        (cves.length === 0
            ? '<p class="pdk-empty">No CVEs indexed for this scan.</p>'
            : `<table><thead><tr><th>CVE</th><th>Sev</th><th>Package</th><th>Installed</th><th>Fixed</th></tr></thead><tbody>${cveRows}</tbody></table>`);
    return renderHtmlDocument({
        title: SCAN_TITLE[lang],
        subtitle: `${scan.scan_type} · ${scan.started_at} · ${scan.status}`,
        sections: [meta, sevSection, findingsSection, owaspCoverageHtml(owasp), cveSection],
        lang,
    });
}
function severityOrder(s) {
    return { info: 0, low: 1, medium: 2, high: 3, critical: 4 }[s] ?? 0;
}
function slugify(s) {
    return (s
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-+|-+$/g, '')
        .slice(0, 40) || 'report');
}
function failDomain(code, message) {
    return { ok: false, error: { code, message } };
}
//# sourceMappingURL=reportExport.js.map