/**
 * The OWASP Top 10:2025 / NIST CSF 2.0 renderings: report_export
 * (Markdown, HTML, SARIF, JSON), compliance_evidence's two new frameworks,
 * and the dashboard. One rule runs through all of them: a category is
 * covered only when a scanner able to detect it ran ok in the scans the
 * document covers — "0 findings" from a scanner that did not run is "not
 * tested" — and a finding with no taxonomy (stored before schema 13, or no
 * CWE from its scanner) is unmapped, never filed under a category.
 */

import { readFileSync } from 'node:fs';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { PluginContext } from '../../src/context.js';
import { buildSnapshot } from '../../src/dashboard/snapshot.js';
import { renderDashboard } from '../../src/dashboard/renderHtml.js';
import { renderStatus } from '../../src/dashboard/renderStatus.js';
import { resolveProjectPath } from '../../src/platform/projectPath.js';
import { makeFinding } from '../../src/runners/scannerParsers/index.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { Storage } from '../../src/storage/index.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { TOOLS } from '../../src/tools/index.js';
import type { ScanType, ToolRun } from '../../src/types.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

beforeAll(async () => {
  await import('../../src/tools/reportExport.js');
  await import('../../src/tools/complianceEvidence.js');
});
afterAll(cleanupTempDirs);

function getTool(name: string) {
  const t = TOOLS.find((x) => x.name === name);
  if (!t) throw new Error(`Tool '${name}' not registered`);
  return t;
}

const DBS = new WeakMap<PluginContext, Database>();

function makePlugin(): PluginContext {
  const db = new Database(':memory:');
  runMigrations(db);
  const plugin: PluginContext = {
    storage: new Storage(db),
    shell: { command: 'bash', args_prefix: [], needs_wsl_path_translate: false, label: 'fake' },
    scriptsDir: '',
    progressNotifier: { send: () => {} },
  };
  DBS.set(plugin, db);
  return plugin;
}

function tempProject(): string {
  return resolveProjectPath(makeTempDir('owasp-report-')).path;
}

let clock = Date.parse('2026-09-01T00:00:00.000Z');

function seedScan(
  plugin: PluginContext,
  opts: {
    id: string;
    type: ScanType;
    project: string;
    tools_run: ToolRun[];
    missing_tools?: string[];
    meta?: Record<string, unknown>;
    findings?: Array<Parameters<typeof makeFinding>[0]>;
  },
): void {
  plugin.storage.scans.insert({
    scan_id: opts.id,
    scan_type: opts.type,
    project_path: opts.project,
    tree_hash: 'h',
    ...(opts.meta !== undefined ? { meta: opts.meta } : {}),
  });
  if (opts.findings !== undefined && opts.findings.length > 0) {
    plugin.storage.findings.bulkInsert(opts.findings.map((f) => ({ ...makeFinding(f), scan_id: opts.id })));
  }
  plugin.storage.scans.finalize({
    scan_id: opts.id,
    status: 'completed',
    tools_run: opts.tools_run,
    missing_tools: opts.missing_tools ?? [],
  });
  // Distinct, ordered start times: the open set picks the newest per type.
  clock += 60_000;
  const at = new Date(clock).toISOString();
  DBS.get(plugin)?.prepare(`UPDATE scans SET started_at = ?, finished_at = ? WHERE id = ?`).run(at, at, opts.id);
}

const SQLI = {
  tool: 'semgrep',
  rule_id: 'javascript.lang.security.sqli',
  severity: 'high' as const,
  category: 'security' as const,
  title: 'SQL injection',
  file_path: 'src/db.js',
  line_start: 3,
  taxonomy: { cwe: ['CWE-89: SQL Injection'], owasp: ['A05:2025 - Injection'] },
};
const LEGACY = {
  tool: 'semgrep',
  rule_id: 'javascript.lang.security.other',
  severity: 'medium' as const,
  category: 'security' as const,
  title: 'stored before schema 13',
  file_path: 'src/app.js',
  line_start: 9,
};

async function exportScan(plugin: PluginContext, project: string, scanId: string, format: string): Promise<string> {
  const r = (await getTool('report_export').handler({ project_path: project, scan_id: scanId, format }, plugin)) as {
    ok: boolean;
    file_path: string;
  };
  expect(r.ok).toBe(true);
  return readFileSync(r.file_path, 'utf8');
}

describe('report_export', () => {
  it('Markdown: a CWE / OWASP column, and a coverage section that claims only what ran', async () => {
    const plugin = makePlugin();
    const project = tempProject();
    seedScan(plugin, { id: 'S1', type: 'sast', project, tools_run: [{ name: 'semgrep', status: 'ok' }], findings: [SQLI, LEGACY] });
    const md = await exportScan(plugin, project, 'S1', 'markdown');

    expect(md).toContain('| Sev | Tool | Rule | Title | Location | CWE / OWASP 2025 |');
    expect(md).toMatch(/SQL injection \| `src\/db\.js:3` \| CWE-89 · A05:2025 \|/);
    expect(md).toMatch(/stored before schema 13 \| `src\/app\.js:9` \| — \|/);

    expect(md).toContain('## OWASP Top 10:2025 coverage');
    expect(md).toMatch(/\| A05:2025 Injection \| tested \| semgrep \(sast\) \| 1 \|/);
    // Registry Semgrep cannot claim supply chain, logging or exception
    // handling — and says what would test them.
    expect(md).toMatch(/\| A03:2025 Software Supply Chain Failures \| NOT TESTED \| — \| 0 \|/);
    expect(md).toMatch(/\| A10:2025 Mishandling of Exceptional Conditions \| NOT TESTED \|/);
    expect(md).toMatch(/not tested.*is not a clean result/i);
    expect(md).toMatch(/1 of 2 findings carry no OWASP 2025 category/);
  });

  it('a Semgrep that failed tests nothing, and nothing reads clean', async () => {
    const plugin = makePlugin();
    const project = tempProject();
    seedScan(plugin, { id: 'F1', type: 'sast', project, tools_run: [{ name: 'semgrep', status: 'failed', reason: 'exit 2' }] });
    const md = await exportScan(plugin, project, 'F1', 'markdown');
    expect(md).not.toMatch(/\| tested \|/);
    expect(md).not.toMatch(/\| partial \|/);
    expect(md).toMatch(/\| A05:2025 Injection \| NOT TESTED \| — \| 0 \|/);
  });

  it('HTML: the same column and section, escaped, with each category linked to owasp.org', async () => {
    const plugin = makePlugin();
    const project = tempProject();
    seedScan(plugin, { id: 'H1', type: 'sast', project, tools_run: [{ name: 'semgrep', status: 'ok' }], findings: [SQLI, LEGACY] });
    const html = await exportScan(plugin, project, 'H1', 'html');
    expect(html).toContain('<th>CWE / OWASP 2025</th>');
    expect(html).toContain('CWE-89 · A05:2025');
    expect(html).toContain('<h2>OWASP Top 10:2025 coverage</h2>');
    expect(html).toContain('href="https://owasp.org/Top10/2025/A05_2025-Injection/"');
    expect(html).toMatch(/A03:2025[\s\S]*?NOT TESTED/);
  });

  it('SARIF: results and rules carry external/cwe and owasp-2025 tags', async () => {
    const plugin = makePlugin();
    const project = tempProject();
    seedScan(plugin, { id: 'R1', type: 'sast', project, tools_run: [{ name: 'semgrep', status: 'ok' }], findings: [SQLI] });
    const doc = JSON.parse(await exportScan(plugin, project, 'R1', 'sarif')) as {
      runs: Array<{ results: Array<{ properties: { tags?: string[] } }>; tool: { driver: { rules: Array<{ properties?: { tags?: string[] } }> } } }>;
    };
    expect(doc.runs[0]?.results[0]?.properties.tags).toEqual(['external/cwe/cwe-89', 'owasp-2025-a05']);
    expect(doc.runs[0]?.tool.driver.rules[0]?.properties?.tags).toEqual(['external/cwe/cwe-89', 'owasp-2025-a05']);
  });

  it('JSON: each finding keeps its fields, and the coverage table rides along', async () => {
    const plugin = makePlugin();
    const project = tempProject();
    seedScan(plugin, { id: 'J1', type: 'sast', project, tools_run: [{ name: 'semgrep', status: 'ok' }], findings: [SQLI, LEGACY] });
    const doc = JSON.parse(await exportScan(plugin, project, 'J1', 'json')) as {
      findings: Array<{ title: string; cwe?: string[]; owasp?: string[] }>;
      owasp_2025: { categories: Array<{ id: string; status: string }>; findings_unmapped: number };
    };
    expect(doc.findings.find((f) => f.title === 'SQL injection')?.owasp).toEqual(['A05:2025']);
    expect(doc.findings.find((f) => f.title === 'stored before schema 13')).not.toHaveProperty('owasp');
    expect(doc.owasp_2025.findings_unmapped).toBe(1);
    expect(doc.owasp_2025.categories.find((c) => c.id === 'A05:2025')?.status).toBe('tested');
  });

  // An orchestrated security_full row merges its children's bookkeeping and
  // does not record whether scan_sast ran local_only — the child does.
  it('an orchestrated security_full export reads coverage from its child scans', async () => {
    const plugin = makePlugin();
    const project = tempProject();
    seedScan(plugin, { id: 'C-SAST', type: 'sast', project, tools_run: [{ name: 'semgrep', status: 'ok' }], meta: { local_only: true } });
    seedScan(plugin, { id: 'C-DEPS', type: 'deps', project, tools_run: [{ name: 'trivy', status: 'ok' }] });
    seedScan(plugin, {
      id: 'P1',
      type: 'security_full',
      project,
      tools_run: [{ name: 'semgrep', status: 'ok' }, { name: 'trivy', status: 'ok' }],
      meta: {
        child_scans: [
          { tool: 'scan_sast', scan_id: 'C-SAST', status: 'completed' },
          { tool: 'scan_deps', scan_id: 'C-DEPS', status: 'completed' },
        ],
      },
    });
    const md = await exportScan(plugin, project, 'P1', 'markdown');
    expect(md).toMatch(/\| A03:2025 Software Supply Chain Failures \| tested \| trivy \(deps\) \|/);
    // local_only: the registry did not run, so injection was not tested.
    expect(md).toMatch(/\| A05:2025 Injection \| NOT TESTED \|/);
  });
});

async function evidence(plugin: PluginContext, project: string, framework: string): Promise<string> {
  const r = (await getTool('compliance_evidence').handler({ project_path: project, framework }, plugin)) as {
    ok: boolean;
    markdown: string;
  };
  expect(r.ok).toBe(true);
  return r.markdown;
}

function section(md: string, heading: string): string {
  const start = md.indexOf(heading);
  expect(start, heading).toBeGreaterThanOrEqual(0);
  const rest = md.slice(start + heading.length);
  const next = rest.search(/\n### |\n## |\n---/);
  return next >= 0 ? rest.slice(0, next) : rest;
}

describe('compliance_evidence', () => {
  it('owasp-top10-2025: per-category evidence — tested only where a capable scanner ran ok', async () => {
    const plugin = makePlugin();
    const project = tempProject();
    seedScan(plugin, { id: 'E-SAST', type: 'sast', project, tools_run: [{ name: 'semgrep', status: 'ok' }], findings: [SQLI, LEGACY] });
    seedScan(plugin, { id: 'E-SEC', type: 'secrets', project, tools_run: [{ name: 'gitleaks', status: 'skipped', reason: 'not_installed' }], missing_tools: ['gitleaks'] });
    const md = await evidence(plugin, project, 'owasp-top10-2025');

    const covered = section(md, '### OWASP Top 10:2025 controls evidenced by this document');
    const missing = section(md, '### OWASP Top 10:2025 controls NOT covered by this document');
    expect(covered).toMatch(/- A05:2025 \(Injection\): tested by semgrep \(sast[^)]*\); 1 open finding/);
    expect(covered).not.toContain('A03:2025');
    // gitleaks was not installed: A07 is still tested by the registry rules,
    // but supply chain, logging and exception handling were never looked at.
    expect(missing).toMatch(/- A03:2025 \(Software Supply Chain Failures\): NOT COVERED — no scanner able to detect it ran ok/);
    expect(missing).toMatch(/A03:2025[^\n]*Trivy vulnerability pass/);
    expect(missing).toContain('A09:2025');
    expect(missing).toContain('A10:2025');
    expect(md).toMatch(/1 of 2 open findings carry no OWASP 2025 category/);
    expect(md).toContain('https://owasp.org/Top10/2025/');
  });

  it('owasp-top10-2025 with no scans at all evidences nothing', async () => {
    const plugin = makePlugin();
    const project = tempProject();
    const md = await evidence(plugin, project, 'owasp-top10-2025');
    expect(section(md, '### OWASP Top 10:2025 controls evidenced by this document')).toContain('(none');
    for (const id of ['A01', 'A05', 'A10']) {
      expect(section(md, '### OWASP Top 10:2025 controls NOT covered by this document')).toContain(`${id}:2025`);
    }
  });

  it('nist-csf-2.0: every CSF 2.0 category listed, evidenced through the OWASP categories tested, mapping labelled as ours', async () => {
    const plugin = makePlugin();
    const project = tempProject();
    seedScan(plugin, { id: 'N-SAST', type: 'sast', project, tools_run: [{ name: 'semgrep', status: 'ok' }], findings: [SQLI] });
    const md = await evidence(plugin, project, 'nist-csf-2.0');

    expect(md).toMatch(/dev-guardian's own mapping/);
    const covered = section(md, '### NIST CSF 2.0 controls evidenced by this document');
    const missing = section(md, '### NIST CSF 2.0 controls NOT covered by this document');
    expect(covered).toMatch(/- ID\.RA \(Risk Assessment\): .*ID\.RA-01/);
    expect(covered).toMatch(/- PR\.PS \(Platform Security\): .*A05:2025/);
    // GOVERN, RESPOND and RECOVER are processes no code scan evidences.
    expect(missing).toMatch(/- GV\.OC \(Organizational Context\): NOT COVERED — .*no code scan/);
    expect(missing).toMatch(/- RS\.MA \(Incident Management\): NOT COVERED/);
    // GV.SC is reachable, but only through supply chain, which did not run.
    expect(missing).toMatch(/- GV\.SC \(Cybersecurity Supply Chain Risk Management\): NOT COVERED — .*A03:2025/);
    const listed = (md.match(/^- (GV|ID|PR|DE|RS|RC)\.[A-Z]{2} /gm) ?? []).length;
    expect(listed).toBe(22);
  });

  it('nist-csf-2.0 counts a finding once per CSF category, however many of its OWASP categories map there', async () => {
    const plugin = makePlugin();
    const project = tempProject();
    // CWE-321 + CWE-798: A04 and A07 — both filed under ID.RA.
    const KEY = { ...SQLI, rule_id: 'key', title: 'private key', taxonomy: { cwe: ['CWE-321', 'CWE-798'] } };
    seedScan(plugin, { id: 'N2', type: 'sast', project, tools_run: [{ name: 'semgrep', status: 'ok' }], findings: [KEY] });
    const md = await evidence(plugin, project, 'nist-csf-2.0');
    const covered = section(md, '### NIST CSF 2.0 controls evidenced by this document');
    expect(covered).toMatch(/- ID\.RA \(Risk Assessment\): [^\n]*; 1 open finding in those categories/);
    expect(covered).toMatch(/- PR\.AA [^\n]*subcategories PR\.AA-01, PR\.AA-03, PR\.AA-05;/);
  });
});

describe('dashboard', () => {
  it('the snapshot counts findings by OWASP category beside what was tested, and both views say so', () => {
    const plugin = makePlugin();
    const project = tempProject();
    seedScan(plugin, { id: 'D-SAST', type: 'sast', project, tools_run: [{ name: 'semgrep', status: 'ok' }], findings: [SQLI, LEGACY] });
    const snapshot = buildSnapshot(plugin.storage, project, clock + 1000);

    expect(snapshot.findings.by_owasp).toEqual({ 'A05:2025': 1 });
    expect(snapshot.findings.owasp_unmapped).toBe(1);
    const status = Object.fromEntries((snapshot.coverage.owasp ?? []).map((c) => [c.id, c.status]));
    expect(status['A05:2025']).toBe('tested');
    expect(status['A03:2025']).toBe('not_tested');

    const text = renderStatus(snapshot, { color: false });
    expect(text).toMatch(/OWASP 2025 +A05 1 · 1 unmapped/);
    expect(text).toMatch(/not tested: A03 A09 A10/);

    const html = renderDashboard(snapshot);
    expect(html).toContain('<h2>OWASP Top 10:2025</h2>');
    expect(html).toMatch(/A03:2025[\s\S]*?not tested/);
  });
});
