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
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { z } from 'zod';
import { resolveProjectPath } from '../platform/projectPath.js';
import { escapeHtml, markdownToSafeHtml, renderHtmlDocument, severityBar, severityChip, } from '../report/htmlTheme.js';
import { toSarif } from '../report/sarif.js';
import { ProjectPath } from '../schemas.js';
import { registerToolModule } from './index.js';
const inputSchema = {
    project_path: ProjectPath,
    scan_id: z.string().uuid().optional().describe('Scan to export. Defaults to the latest completed.'),
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
        'format=html). Local file only — no external services, no web fonts.',
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
    // Scan mode.
    const scanId = inp.scan_id ?? ctx.storage.scans.getLatest()?.scan_id;
    if (!scanId) {
        return failDomain('unknown_scan_id', 'No completed scans to export.');
    }
    const scan = ctx.storage.scans.getById(scanId);
    if (!scan)
        return failDomain('unknown_scan_id', `Scan '${scanId}' not found.`);
    const findings = ctx.storage.findings.listByScan(scanId);
    const cves = scan.scan_type === 'deps' || scan.scan_type === 'security_full'
        ? ctx.storage.cves.listActive(scanId)
        : [];
    const { content, fileName } = renderReport(format, scan, findings, cves, lang);
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
    };
}
function renderReport(format, scan, findings, cves, lang) {
    switch (format) {
        case 'sarif':
            return { content: toSarif(findings), fileName: 'report.sarif' };
        case 'json':
            return {
                content: JSON.stringify({ scan, findings, cves }, null, 2),
                fileName: 'report.json',
            };
        case 'markdown':
            return { content: renderMarkdown(scan, findings, cves), fileName: 'report.md' };
        case 'html':
        default:
            return { content: renderHtml(scan, findings, cves, lang), fileName: 'report.html' };
    }
}
function renderMarkdown(scan, findings, cves) {
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
        lines.push('| Sev | Tool | Rule | Title | Location |');
        lines.push('| --- | --- | --- | --- | --- |');
        for (const f of [...findings].sort((a, b) => severityOrder(b.severity) - severityOrder(a.severity))) {
            const loc = f.file_path ? `\`${f.file_path}${f.line_start ? `:${f.line_start}` : ''}\`` : '';
            lines.push(`| ${f.severity} | ${f.tool} | \`${f.rule_id ?? ''}\` | ${mdEscape(f.title)} | ${loc} |`);
        }
    }
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
    lines.push('_Generated by dev-guardian — open-source, no telemetry._');
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
function renderHtml(scan, findings, cves, lang) {
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
</tr>`)
        .join('');
    const findingsSection = `<h2>Findings (${findings.length})</h2>\n` +
        (findings.length === 0
            ? '<p class="pdk-empty">No findings.</p>'
            : `<table><thead><tr><th>Sev</th><th>Tool</th><th>Rule</th><th>Title</th><th>Location</th></tr></thead><tbody>${findingRows}</tbody></table>`);
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
        sections: [meta, sevSection, findingsSection, cveSection],
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