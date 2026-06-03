/**
 * `report_export` — write a self-contained HTML report for a scan (or the
 * latest audit) to `.guardian/reports/export-<scan>/report.html`.
 *
 * Single static HTML file, no JS, no external assets. Renders:
 *   - scan metadata (type, started_at, status, tools_run)
 *   - severity counts as a horizontal bar
 *   - findings table sorted by severity
 *   - CVE table (when applicable)
 *
 * Local-only, no third-party services. Open in any browser.
 */

import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { z } from 'zod';
import type { PluginContext } from '../context.js';
import { resolveProjectPath } from '../platform/projectPath.js';
import { toSarif } from '../report/sarif.js';
import { ProjectPath } from '../schemas.js';
import type { Cve, DomainError, Finding, Severity, ToolResult } from '../types.js';
import { registerToolModule, type ToolModule } from './index.js';

const inputSchema = {
  project_path: ProjectPath,
  scan_id: z.string().uuid().optional().describe('Scan to export. Defaults to the latest completed.'),
  format: z
    .enum(['html', 'sarif', 'markdown', 'json'])
    .optional()
    .default('html')
    .describe(
      'Output format. html (default, self-contained, browser-openable), sarif (SARIF 2.1.0 for ' +
        'CI/IDE code scanning), markdown (handover doc), or json (raw findings).',
    ),
};

const tool: ToolModule = {
  name: 'report_export',
  title: 'Export scan as a report (HTML / SARIF / Markdown / JSON)',
  description:
    'Write a report for a scan in one of four formats: html (static, self-contained, opens in any ' +
    'browser), sarif (SARIF 2.1.0 for GitHub/GitLab code scanning and IDE viewers), markdown ' +
    '(handover doc), or json (raw findings). Local file only — no external services. Suitable for ' +
    'handover or audit evidence.',
  inputSchema,
  handler: async (input, ctx) => handler(input, ctx),
};

registerToolModule(tool);

async function handler(
  input: Record<string, unknown>,
  ctx: PluginContext,
): Promise<ToolResult<Record<string, unknown>>> {
  const inp = input as {
    project_path?: string;
    scan_id?: string;
    format?: 'html' | 'sarif' | 'markdown' | 'json';
  };
  const format = inp.format ?? 'html';
  let projectPath: string;
  try {
    projectPath = resolveProjectPath(inp.project_path).path;
  } catch (e) {
    return failDomain('not_a_git_repo', (e as Error).message);
  }

  const scanId =
    inp.scan_id ?? ctx.storage.scans.getLatest()?.scan_id;
  if (!scanId) {
    return failDomain('unknown_scan_id', 'No completed scans to export.');
  }
  const scan = ctx.storage.scans.getById(scanId);
  if (!scan) return failDomain('unknown_scan_id', `Scan '${scanId}' not found.`);

  const findings = ctx.storage.findings.listByScan(scanId);
  const cves =
    scan.scan_type === 'deps' || scan.scan_type === 'security_full'
      ? ctx.storage.cves.listActive(scanId)
      : [];

  const { content, fileName } = renderReport(format, scan, findings, cves);
  const outDir = join(projectPath, '.guardian', 'reports', `export-${scanId.slice(0, 8)}`);
  mkdirSync(outDir, { recursive: true });
  const outFile = join(outDir, fileName);
  writeFileSync(outFile, content, 'utf8');

  return {
    ok: true,
    scan_id: scanId,
    format,
    file_path: outFile,
    bytes: Buffer.byteLength(content, 'utf8'),
    findings_count: findings.length,
    cves_count: cves.length,
  };
}

type ScanRecordT = NonNullable<ReturnType<PluginContext['storage']['scans']['getById']>>;

function renderReport(
  format: 'html' | 'sarif' | 'markdown' | 'json',
  scan: ScanRecordT,
  findings: Finding[],
  cves: Cve[],
): { content: string; fileName: string } {
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
      return { content: renderHtml(scan, findings, cves), fileName: 'report.html' };
  }
}

function renderMarkdown(scan: ScanRecordT, findings: Finding[], cves: Cve[]): string {
  const counts: Record<Severity, number> = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
  for (const f of findings) counts[f.severity] += 1;
  const lines: string[] = [];
  lines.push(`# dev-guardian scan report`);
  lines.push('');
  lines.push(`- **Scan ID:** ${scan.scan_id}`);
  lines.push(`- **Type:** ${scan.scan_type}`);
  lines.push(`- **Status:** ${scan.status}`);
  lines.push(`- **Started:** ${scan.started_at}`);
  lines.push(`- **Project:** \`${scan.project_path}\``);
  lines.push('');
  lines.push(
    `**Severity:** critical ${counts.critical} · high ${counts.high} · medium ${counts.medium} · low ${counts.low} · info ${counts.info}`,
  );
  lines.push('');
  lines.push(`## Findings (${findings.length})`);
  lines.push('');
  if (findings.length === 0) {
    lines.push('_No findings._');
  } else {
    lines.push('| Sev | Tool | Rule | Title | Location |');
    lines.push('| --- | --- | --- | --- | --- |');
    for (const f of [...findings].sort((a, b) => severityOrder(b.severity) - severityOrder(a.severity))) {
      const loc = f.file_path ? `\`${f.file_path}${f.line_start ? `:${f.line_start}` : ''}\`` : '';
      lines.push(
        `| ${f.severity} | ${f.tool} | \`${f.rule_id ?? ''}\` | ${mdEscape(f.title)} | ${loc} |`,
      );
    }
  }
  if (cves.length > 0) {
    lines.push('');
    lines.push(`## Active CVEs (${cves.length})`);
    lines.push('');
    lines.push('| CVE | Sev | Package | Installed | Fixed |');
    lines.push('| --- | --- | --- | --- | --- |');
    for (const c of cves) {
      lines.push(
        `| ${c.cve_id} | ${c.severity} | ${c.package_name} | ${c.installed_version ?? ''} | ${c.fixed_version ?? ''} |`,
      );
    }
  }
  lines.push('');
  lines.push('_Generated by dev-guardian — open-source, no telemetry._');
  return lines.join('\n');
}

function mdEscape(s: string): string {
  return s.replace(/\|/g, '\\|');
}

function renderHtml(
  scan: ReturnType<NonNullable<PluginContext['storage']['scans']['getById']>>,
  findings: Finding[],
  cves: Cve[],
): string {
  if (!scan) return '';
  const counts: Record<Severity, number> = {
    info: 0,
    low: 0,
    medium: 0,
    high: 0,
    critical: 0,
  };
  for (const f of findings) counts[f.severity] += 1;

  const sevColor: Record<Severity, string> = {
    critical: '#7f1d1d',
    high: '#b91c1c',
    medium: '#b45309',
    low: '#1f6feb',
    info: '#6b7280',
  };
  const bar = (['critical', 'high', 'medium', 'low', 'info'] as Severity[])
    .map((s) => {
      const n = counts[s];
      if (n === 0) return '';
      return `<div style="flex:${n};background:${sevColor[s]};color:#fff;padding:6px 8px;text-align:center;font-size:13px;">${s}: ${n}</div>`;
    })
    .join('');

  const findingRows = [...findings]
    .sort((a, b) => severityOrder(b.severity) - severityOrder(a.severity))
    .map((f) => {
      const sev = f.severity;
      return `<tr>
        <td><span style="background:${sevColor[sev]};color:#fff;padding:2px 8px;border-radius:3px;font-size:11px;">${sev}</span></td>
        <td>${escapeHtml(f.tool)}</td>
        <td><code style="font-size:12px;">${escapeHtml(f.rule_id ?? '')}</code></td>
        <td>${escapeHtml(f.title)}</td>
        <td><code style="font-size:12px;">${escapeHtml(f.file_path ?? '')}${
          f.line_start ? `:${f.line_start}` : ''
        }</code></td>
      </tr>`;
    })
    .join('');

  const cveRows = cves
    .map(
      (c) => `<tr>
      <td><a href="https://nvd.nist.gov/vuln/detail/${escapeHtml(c.cve_id)}" target="_blank" rel="noopener">${escapeHtml(c.cve_id)}</a></td>
      <td><span style="background:${sevColor[c.severity]};color:#fff;padding:2px 8px;border-radius:3px;font-size:11px;">${c.severity}</span></td>
      <td>${escapeHtml(c.package_name)}</td>
      <td><code style="font-size:12px;">${escapeHtml(c.installed_version ?? '')}</code></td>
      <td><code style="font-size:12px;">${escapeHtml(c.fixed_version ?? '')}</code></td>
    </tr>`,
    )
    .join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>dev-guardian report — ${escapeHtml(scan.scan_id)}</title>
<style>
  body { font-family: -apple-system, Segoe UI, Roboto, sans-serif; max-width: 1100px; margin: 2rem auto; padding: 0 1rem; color: #1f2328; }
  h1 { margin-bottom: 0.25rem; }
  .meta { color: #57606a; font-size: 14px; margin-bottom: 1.5rem; }
  .bar { display: flex; border-radius: 4px; overflow: hidden; margin: 1rem 0 2rem; min-height: 28px; }
  table { width: 100%; border-collapse: collapse; margin-bottom: 2rem; }
  th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid #d0d7de; font-size: 14px; }
  th { background: #f6f8fa; font-weight: 600; }
  tr:hover { background: #f6f8fa; }
  code { background: #f6f8fa; padding: 2px 4px; border-radius: 3px; }
  .empty { color: #57606a; font-style: italic; }
  footer { color: #6b7280; font-size: 12px; margin-top: 3rem; border-top: 1px solid #d0d7de; padding-top: 1rem; }
</style>
</head>
<body>
<h1>dev-guardian scan report</h1>
<div class="meta">
  <strong>Scan ID:</strong> ${escapeHtml(scan.scan_id)}<br>
  <strong>Type:</strong> ${escapeHtml(scan.scan_type)}<br>
  <strong>Status:</strong> ${escapeHtml(scan.status)}<br>
  <strong>Started:</strong> ${escapeHtml(scan.started_at)}<br>
  <strong>Finished:</strong> ${escapeHtml(scan.finished_at ?? 'n/a')}<br>
  <strong>Project:</strong> <code>${escapeHtml(scan.project_path)}</code>
</div>

<h2>Severity distribution</h2>
${findings.length === 0 ? '<p class="empty">No findings.</p>' : `<div class="bar">${bar}</div>`}

<h2>Findings (${findings.length})</h2>
${
  findings.length === 0
    ? '<p class="empty">No findings.</p>'
    : `<table>
  <thead><tr><th>Sev</th><th>Tool</th><th>Rule</th><th>Title</th><th>Location</th></tr></thead>
  <tbody>${findingRows}</tbody>
</table>`
}

<h2>Active CVEs (${cves.length})</h2>
${
  cves.length === 0
    ? '<p class="empty">No CVEs indexed for this scan.</p>'
    : `<table>
  <thead><tr><th>CVE</th><th>Sev</th><th>Package</th><th>Installed</th><th>Fixed</th></tr></thead>
  <tbody>${cveRows}</tbody>
</table>`
}

<footer>Generated by dev-guardian MCP server · open-source · no telemetry</footer>
</body>
</html>`;
}

function severityOrder(s: Severity): number {
  return { info: 0, low: 1, medium: 2, high: 3, critical: 4 }[s] ?? 0;
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function failDomain(
  code: DomainError['code'],
  message: string,
): ToolResult<Record<string, unknown>> {
  return { ok: false, error: { code, message } };
}
