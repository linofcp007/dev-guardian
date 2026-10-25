/**
 * Review 3.6.1, finding 3: Markdown injection in `report_export`.
 *
 * The Markdown report put a finding's title, rule id, file path and tool and
 * a CVE's package fields into its tables with only `|` escaped (the title)
 * or nothing at all. Every one of them is the repository's text — a project's
 * own `.semgrep.yml` message, a file name, an imported SARIF log's tool name,
 * a lock file's package name — so a newline ended the table and a backtick
 * closed the code span: links, images and raw HTML landed in a stakeholder
 * report. Each untrusted field is now one line with no markup a viewer acts
 * on: `|`, `` ` ``, `<`, `>`, `[`, `]`, `!` and `\` escaped in a cell, and in a
 * code span no backtick and an escaped `|`. The HTML export escapes already;
 * its CVE link is now a percent-encoded path segment too.
 */

import { readFileSync } from 'node:fs';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { PluginContext } from '../../src/context.js';
import { resolveProjectPath } from '../../src/platform/projectPath.js';
import { makeFinding } from '../../src/runners/scannerParsers/index.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { Storage } from '../../src/storage/index.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { TOOLS } from '../../src/tools/index.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

beforeAll(async () => {
  await import('../../src/tools/reportExport.js');
});
afterAll(cleanupTempDirs);

const INJECT = 'x\n\n# Injected heading\n![p](https://evil.example/p.png) <img src=x onerror=alert(1)> [click](https://evil.example)';

function plugin(): PluginContext {
  const db = new Database(':memory:');
  runMigrations(db);
  return { storage: new Storage(db), shell: null, scriptsDir: '', progressNotifier: { send: () => {} } };
}

/** A completed deps scan whose finding and CVE carry the repository's hostile text in every field. */
function seed(ctx: PluginContext, project: string): void {
  ctx.storage.scans.insert({ scan_id: 'D1', scan_type: 'deps', project_path: project, tree_hash: 'h' });
  ctx.storage.findings.bulkInsert([
    {
      ...makeFinding({
        tool: `codeql${INJECT}`,
        rule_id: `rule\`${INJECT}`,
        severity: 'high',
        category: 'security',
        title: `Title | cell${INJECT}`,
        file_path: `src/a\`b${INJECT}.js`,
        line_start: 3,
        taxonomy: { cwe: [`CWE-79${INJECT}`] },
      }),
      scan_id: 'D1',
    },
  ]);
  ctx.storage.cves.bulkUpsert([
    {
      scan_id: 'D1',
      cve_id: `CVE-2026-0001${INJECT}`,
      package_name: `pkg${INJECT}`,
      installed_version: `1.0${INJECT}`,
      fixed_version: `1.1${INJECT}`,
      severity: 'high',
    },
  ]);
  ctx.storage.scans.finalize({ scan_id: 'D1', status: 'completed', tools_run: [{ name: 'trivy', status: 'ok' }], missing_tools: [] });
}

async function exportAs(format: 'markdown' | 'html'): Promise<string> {
  const ctx = plugin();
  const project = resolveProjectPath(makeTempDir('report-inject-')).path;
  seed(ctx, project);
  const tool = TOOLS.find((t) => t.name === 'report_export');
  if (!tool) throw new Error('report_export is not registered');
  const r = (await tool.handler({ project_path: project, scan_id: 'D1', format }, ctx)) as { ok: boolean; file_path: string };
  expect(r.ok, JSON.stringify(r)).toBe(true);
  return readFileSync(r.file_path, 'utf8');
}

/** The table rows (and the line after each table) of a Markdown report. */
const tableRows = (md: string, header: string): string[] => {
  const lines = md.split('\n');
  const start = lines.findIndex((l) => l.startsWith(header));
  expect(start, header).toBeGreaterThanOrEqual(0);
  const rows: string[] = [];
  for (const l of lines.slice(start + 2)) {
    if (!l.startsWith('|')) break;
    rows.push(l);
  }
  return rows;
};

describe('report_export (markdown) prints the repository’s text inert', () => {
  it('no field opens a heading, an image, a link or raw HTML', async () => {
    const md = await exportAs('markdown');
    expect(md).not.toMatch(/^# Injected heading/m);
    // A code span's content is literal text; outside one, every opener is escaped.
    const outsideCode = md.replace(/`[^`\n]*`/g, '');
    expect(outsideCode).not.toMatch(/(?<!\\)!(?<!\\)\[p/);
    expect(outsideCode).not.toMatch(/(?<!\\)<img/);
    expect(outsideCode).not.toMatch(/(?<!\\)\[click(?<!\\)\]/);
  });

  it('each finding and each CVE stays one table row of the right width', async () => {
    const md = await exportAs('markdown');
    // A cell boundary is an unescaped `|`.
    const cells = (row: string): number => row.split(/(?<!\\)\|/).length - 2;
    const findings = tableRows(md, '| Sev | Tool | Rule | Title | Location | CWE / OWASP 2025 |');
    expect(findings).toHaveLength(1);
    expect(cells(findings[0] ?? '')).toBe(6);
    const cves = tableRows(md, '| CVE | Sev | Package | Installed | Fixed |');
    expect(cves).toHaveLength(1);
    expect(cells(cves[0] ?? '')).toBe(5);
  });

  it('a code span is never closed early: rule ids and locations hold no backtick', async () => {
    const md = await exportAs('markdown');
    const row = tableRows(md, '| Sev | Tool | Rule | Title | Location | CWE / OWASP 2025 |')[0] ?? '';
    // Two code spans (rule, location): four backticks, no more.
    expect(row.match(/`/g)?.length).toBe(4);
  });
});

describe('report_export (html) escapes every field', () => {
  it('no raw tag, and the CVE link is one percent-encoded path segment', async () => {
    const html = await exportAs('html');
    expect(html).not.toMatch(/<img src=x/);
    const href = /href="https:\/\/nvd\.nist\.gov\/vuln\/detail\/([^"]*)"/.exec(html)?.[1] ?? '';
    expect(href).toMatch(/^CVE-2026-0001/);
    expect(href).not.toMatch(/[\s/<>]/);
  });
});
