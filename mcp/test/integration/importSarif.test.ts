/**
 * `import_sarif` end to end on a real (in-memory) database — the
 * `sarif-import` feature's test plan T-01, T-05, T-06, T-20 and T-22.
 *
 *   - T-01: one `sarif_import` scan per run, with the source tool, and one
 *     finding per result that is a finding (US-1.AC-1);
 *   - T-05: results with no fingerprints get the identity the native scanners
 *     compute (`assignIdentities`), and the response says how many (US-1.AC-5);
 *   - T-06: imported findings behave like a native scanner's in every history
 *     tool — with `source_tool` choosing which tool's imports a tool reads
 *     (US-1.AC-6);
 *   - T-20: a dev-guardian SARIF export comes back with the same identity and
 *     severity for every finding (US-3.AC-1);
 *   - T-22: time is linear in the number of results (SC-003, NFR-3).
 *
 * Tools are called through their STRICT schemas (`helpers/sarif.ts#callTool`),
 * as the MCP host calls them, so a parameter a tool does not take yet —
 * `source_tool` — is a refusal, not silently ignored.
 */

import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { assignIdentities, makeSourceReader } from '../../src/fingerprint/findingIdentity.js';
import { openSetForProject } from '../../src/history/openSet.js';
import { toSarif } from '../../src/report/sarif.js';
import { makeFinding } from '../../src/runners/scannerParsers/index.js';
import { importSarif } from '../../src/sarif/importSarif.js';
import { persistSarifImport } from '../../src/sarif/persistImport.js';
import { strictInputSchema } from '../../src/tools/index.js';
import type { Finding, Severity } from '../../src/types.js';
import { freshPlugin, projectDir, type Seeded } from '../helpers/historySeed.js';
import {
  callTool,
  importOk,
  isImportScan,
  messageOf,
  metaCounts,
  okData,
  requireTool,
  sarifLog,
  sarifResult,
  sarifRule,
  sarifRun,
  scanRow,
  writeSarif,
  type JsonObject,
} from '../helpers/sarif.js';
import { cleanupTempDirs } from '../helpers/tempDir.js';
import { costOf, expectLinear, PERF_STRICT } from '../helpers/timing.js';

vi.setConfig({ testTimeout: 120_000 });

afterAll(cleanupTempDirs);
beforeAll(async () => {
  await import('../../src/registerAll.js');
});

/** A project with a few source files the logs below point into. */
function project(prefix: string): string {
  const dir = projectDir(prefix);
  mkdirSync(join(dir, 'src'), { recursive: true });
  mkdirSync(join(dir, 'test'), { recursive: true });
  writeFileSync(join(dir, 'src', 'db.js'), 'const a = 1;\nconst q = "SELECT * FROM t WHERE id = " + id;\nrun(q);\nmodule.exports = q;\n');
  writeFileSync(join(dir, 'src', 'view.js'), 'el.innerHTML = input;\nconsole.log(input);\n');
  writeFileSync(join(dir, 'test', 'fixture.js'), 'eval(payload);\n');
  return dir;
}

/** A failing result with a stable fingerprint (`fp`). */
function hit(ruleId: string, uri: string, line: number, fp: string, level = 'error', message = `${ruleId} at ${uri}:${String(line)}`): JsonObject {
  return sarifResult({ ruleId, level, message, uri, startLine: line, partialFingerprints: { primaryLocationLineHash: fp } });
}

// ---------------------------------------------------------------------------
describe('T-01 one scan per run, one finding per result (US-1.AC-1)', () => {
  it('T-01 a log of two runs registers two sarif_import scans with their source tool and version, and a finding per result that is a finding', async () => {
    const s = freshPlugin();
    const dir = project('sarif-t01-');
    const log = sarifLog([
      sarifRun({
        tool: 'CodeQL',
        semanticVersion: '2.19.0',
        rules: [sarifRule('js/sql-injection')],
        results: [
          hit('js/sql-injection', 'src/db.js', 2, 'h1:1', 'error', 'first'),
          // Same rule, file and line, another fingerprint: another result, another finding.
          hit('js/sql-injection', 'src/db.js', 2, 'h2:1', 'error', 'second'),
          sarifResult({ ruleId: 'js/sql-injection', kind: 'pass', message: 'checked, fine', uri: 'src/db.js', startLine: 3 }),
        ],
      }),
      sarifRun({
        tool: 'Snyk Code',
        version: '1.1290.0',
        results: [hit('javascript/XSS', 'src/view.js', 1, 's1:1', 'warning')],
      }),
    ]);
    const out = await importOk(s.plugin, dir, writeSarif(dir, 'reports/two-runs.sarif', log));
    expect(out.runs).toHaveLength(2);
    const [first, second] = out.runs;
    expect(first?.scan_type).toBe('sarif_import');
    expect(second?.scan_type).toBe('sarif_import');
    expect(first?.coverage).toBe('full');

    const codeql = scanRow(s.plugin, first?.scan_id ?? '');
    const snyk = scanRow(s.plugin, second?.scan_id ?? '');
    expect(isImportScan(codeql)).toBe(true);
    expect(codeql.status).toBe('completed');
    expect(codeql.project_path).toBe(dir);
    expect(codeql.meta).toMatchObject({ source_tool: 'CodeQL', source_version: '2.19.0', source_file: 'reports/two-runs.sarif' });
    expect(snyk.meta).toMatchObject({ source_tool: 'Snyk Code', source_version: '1.1290.0' });

    const codeqlRows = s.storage.findings.listByScan(codeql.scan_id);
    expect(codeqlRows.flatMap(messageOf).filter((m) => m === 'first' || m === 'second').sort()).toEqual(['first', 'second']);
    expect(codeqlRows).toHaveLength(2);
    expect(s.storage.findings.listByScan(snyk.scan_id)).toHaveLength(1);
    expect(metaCounts(codeql)).toMatchObject({ results: 3, not_findings: 1 });
  });

  it("T-01 the source tool's name is trimmed and at most 100 characters", async () => {
    const s = freshPlugin();
    const dir = project('sarif-t01-');
    const long = `  ${'T'.repeat(150)}  `;
    const out = await importOk(
      s.plugin,
      dir,
      writeSarif(dir, 'a.sarif', sarifLog([sarifRun({ tool: '  CodeQL  ', results: [hit('r', 'src/db.js', 2, 'a')] }), sarifRun({ tool: long, results: [] })])),
    );
    expect(scanRow(s.plugin, out.runs[0]?.scan_id ?? '').meta?.['source_tool']).toBe('CodeQL');
    const capped = scanRow(s.plugin, out.runs[1]?.scan_id ?? '').meta?.['source_tool'];
    expect(typeof capped === 'string' ? capped.length : -1).toBeLessThanOrEqual(100);
    expect(String(capped).startsWith('TTT')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
describe('T-05 identity computed when the log has no fingerprints (US-1.AC-5)', () => {
  /** The identity `assignIdentities` gives `row` alone, reading the project's files — the native recipe. */
  function nativeIdentity(dir: string, row: Finding): string {
    const subject = {
      tool: row.tool,
      fingerprint: row.fingerprint,
      ...(row.rule_id !== undefined ? { rule_id: row.rule_id } : {}),
      ...(row.subcategory !== undefined ? { subcategory: row.subcategory } : {}),
      ...(row.file_path !== undefined ? { file_path: row.file_path } : {}),
      ...(row.line_start !== undefined ? { line_start: row.line_start } : {}),
      ...(row.line_end !== undefined ? { line_end: row.line_end } : {}),
      ...(row.snippet !== undefined ? { snippet: row.snippet } : {}),
    };
    const [keyed] = assignIdentities([subject], { projectPath: dir, readSource: makeSourceReader(dir) });
    return keyed?.identity ?? '';
  }

  const noFp = (line: number): JsonObject =>
    sarifResult({ ruleId: 'js/sql-injection', level: 'error', message: 'no fingerprint', uri: 'src/db.js', startLine: line });
  const logOf = (line: number): JsonObject =>
    sarifLog([sarifRun({ tool: 'Snyk Code', results: [noFp(line), hit('javascript/XSS', 'src/view.js', 1, 'x1')] })]);

  it('T-05 a result without fingerprints gets the identity the native scanners compute, and identity_computed says so', async () => {
    const s = freshPlugin();
    const dir = project('sarif-t05-');
    const out = await importOk(s.plugin, dir, writeSarif(dir, 'a.sarif', logOf(2)));
    expect(out.counts_total['identity_computed']).toBe(1);
    const scan = scanRow(s.plugin, out.runs[0]?.scan_id ?? '');
    expect(metaCounts(scan)['identity_computed']).toBe(1);
    const row = s.storage.findings.listByScan(scan.scan_id).find((f) => messageOf(f).includes('no fingerprint'));
    expect(row, 'the result without fingerprints is stored').toBeDefined();
    if (row === undefined) return;
    expect(row.identity).toMatch(/^[0-9a-f]{64}$/);
    expect(row.identity).toBe(nativeIdentity(dir, row));
  });

  it('T-05 like a native finding, it survives a line inserted above it and changes with the flagged line', async () => {
    const s = freshPlugin();
    const dir = project('sarif-t05-');
    const identityAt = async (rel: string, line: number): Promise<string | undefined> => {
      const out = await importOk(s.plugin, dir, writeSarif(dir, rel, logOf(line)));
      return s.storage.findings.listByScan(out.runs[0]?.scan_id ?? '').find((f) => messageOf(f).includes('no fingerprint'))?.identity;
    };
    const before = await identityAt('1.sarif', 2);
    const file = join(dir, 'src', 'db.js');
    writeFileSync(file, `// a new first line\n${readFileSync(file, 'utf8')}`);
    const moved = await identityAt('2.sarif', 3);
    expect(moved).toBeDefined();
    expect(moved).toBe(before);
    writeFileSync(file, readFileSync(file, 'utf8').replace('SELECT * FROM t', 'SELECT * FROM other'));
    const edited = await identityAt('3.sarif', 3);
    expect(edited).not.toBe(before);
  });
});

// ---------------------------------------------------------------------------
describe('T-06 imported findings in every history tool (US-1.AC-6)', () => {
  // CodeQL #1: A (medium), B (medium), T (info, in a test file). Snyk #1: S (critical).
  // CodeQL #2: B and T unchanged, A fixed, C new (critical): +10 - 2 = 8 > 5.
  const A = (): JsonObject => hit('js/sql-injection', 'src/db.js', 2, 'A:1', 'warning', 'A');
  const B = (line = 1): JsonObject => hit('js/xss', 'src/view.js', line, 'B:1', 'warning', 'B');
  const T = (): JsonObject => hit('js/eval', 'test/fixture.js', 1, 'T:1', 'note', 'T');
  const C = (): JsonObject =>
    sarifResult({ ruleId: 'js/code-injection', message: 'C', uri: 'src/db.js', startLine: 3, partialFingerprints: { primaryLocationLineHash: 'C:1' }, properties: { 'security-severity': '9.8' } });
  const S = (): JsonObject =>
    sarifResult({ ruleId: 'javascript/HardcodedSecret', message: 'S', uri: 'src/db.js', startLine: 1, partialFingerprints: { snyk: 'S:1' }, properties: { 'security-severity': '9.5' } });
  const codeql = (results: JsonObject[]): JsonObject => sarifLog([sarifRun({ tool: 'CodeQL', version: '2.19.0', results })]);
  const snyk = (results: JsonObject[]): JsonObject => sarifLog([sarifRun({ tool: 'Snyk Code', version: '1.1290.0', results })]);

  interface Scenario {
    s: Seeded;
    dir: string;
    codeql1: string;
    snyk1: string;
    codeql2: string;
  }
  async function imported(s: Seeded, dir: string, rel: string, log: JsonObject): Promise<string> {
    const out = await importOk(s.plugin, dir, writeSarif(dir, rel, log));
    return out.runs[0]?.scan_id ?? '';
  }
  async function scenario(opts: { baselineAfterFirst?: boolean } = {}): Promise<Scenario> {
    const s = freshPlugin();
    const dir = project('sarif-t06-');
    const codeql1 = await imported(s, dir, 'ci/codeql-1.sarif', codeql([A(), B(), T()]));
    if (opts.baselineAfterFirst === true) {
      okData(await callTool('set_baseline', { project_path: dir, scan_type: 'sarif_import', source_tool: 'CodeQL' }, s.plugin));
    }
    const snyk1 = await imported(s, dir, 'ci/snyk-1.sarif', snyk([S()]));
    const codeql2 = await imported(s, dir, 'ci/codeql-2.sarif', codeql([B(), T(), C()]));
    return { s, dir, codeql1, snyk1, codeql2 };
  }
  const fingerprintOf = (sc: Scenario, scanId: string, message: string): string =>
    sc.s.storage.findings.listByScan(scanId).find((f) => messageOf(f).includes(message))?.fingerprint ?? '';

  // The input each tool gains, checked on its strict schema alone — the
  // refusal the MCP host would answer -32602 with. report_export has no
  // scan_type: source_tool alone names a tool's imports there.
  it.each([
    ['set_baseline', { scan_type: 'sarif_import', source_tool: 'CodeQL' }],
    ['diff_scans', { scan_type: 'sarif_import', source_tool: 'CodeQL' }],
    ['regression_alert', { scan_type: 'sarif_import', source_tool: 'CodeQL' }],
    ['report_export', { source_tool: 'CodeQL' }],
  ])('T-06 %s takes source_tool for SARIF imports: %o', async (name, input) => {
    const parsed = await strictInputSchema(requireTool(name)).safeParseAsync(input);
    expect(parsed.success, parsed.success ? '' : parsed.error.message).toBe(true);
  });

  it("T-06 set_baseline takes source_tool, and baselines that tool's newest import", async () => {
    const sc = await scenario();
    const codeqlBase = okData<{ scan_id: string }>(
      await callTool('set_baseline', { project_path: sc.dir, scan_type: 'sarif_import', source_tool: 'CodeQL' }, sc.s.plugin),
    );
    expect(codeqlBase.scan_id).toBe(sc.codeql2);
    const snykBase = okData<{ scan_id: string }>(
      await callTool('set_baseline', { project_path: sc.dir, scan_type: 'sarif_import', source_tool: 'Snyk Code' }, sc.s.plugin),
    );
    expect(snykBase.scan_id).toBe(sc.snyk1);
  });

  it('T-06 with imports from two tools, sarif_import without source_tool is refused, naming both tools', async () => {
    const sc = await scenario();
    for (const tool of ['set_baseline', 'diff_scans', 'regression_alert']) {
      const r = await callTool(tool, { project_path: sc.dir, scan_type: 'sarif_import' }, sc.s.plugin);
      expect(r.ok, tool).toBe(false);
      if (r.ok) continue;
      expect(r.rejectedBySchema, `${tool}: a domain refusal, not a schema one`).toBe(false);
      expect(r.message, tool).toMatch(/CodeQL/);
      expect(r.message, tool).toMatch(/Snyk Code/);
    }
  });

  it('T-06 source_tool with any scan_type but sarif_import is refused', async () => {
    const sc = await scenario();
    const r = await callTool('set_baseline', { project_path: sc.dir, scan_type: 'sast', source_tool: 'CodeQL' }, sc.s.plugin);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.rejectedBySchema).toBe(false);
      expect(r.message).toMatch(/source_tool/);
    }
  });

  it("T-06 diff_scans compares a tool's imports: against its baseline and its previous import, never another tool's", async () => {
    const sc = await scenario({ baselineAfterFirst: true });
    const vsBaseline = okData<{ from_scan_id: string; to_scan_id: string; summary: Record<string, number> }>(
      await callTool('diff_scans', { project_path: sc.dir, scan_type: 'sarif_import', source_tool: 'CodeQL', from: 'baseline' }, sc.s.plugin),
    );
    expect(vsBaseline.from_scan_id).toBe(sc.codeql1);
    expect(vsBaseline.to_scan_id).toBe(sc.codeql2);
    expect(vsBaseline.summary).toMatchObject({ new: 1, resolved: 1, unchanged: 2 });
    const vsPrevious = okData<{ from_scan_id: string; to_scan_id: string }>(
      await callTool('diff_scans', { project_path: sc.dir, scan_type: 'sarif_import', source_tool: 'CodeQL', from: 'previous' }, sc.s.plugin),
    );
    expect(vsPrevious.from_scan_id).toBe(sc.codeql1);
    const across = await callTool('diff_scans', { project_path: sc.dir, from_scan_id: sc.snyk1, to_scan_id: sc.codeql2 }, sc.s.plugin);
    expect(across.ok, 'two imports of different tools are not compared').toBe(false);
  });

  it('T-06 importing the same log twice diffs to nothing new and nothing resolved (SC-002)', async () => {
    const s = freshPlugin();
    const dir = project('sarif-t06-');
    const first = await imported(s, dir, 'one.sarif', codeql([A(), B(), T()]));
    const second = await imported(s, dir, 'two.sarif', codeql([A(), B(), T()]));
    const d = okData<{ summary: Record<string, number> }>(
      await callTool('diff_scans', { project_path: dir, from_scan_id: first, to_scan_id: second }, s.plugin),
    );
    expect(d.summary).toMatchObject({ new: 0, resolved: 0, unchanged: 3 });
  });

  it("T-06 regression_alert scores a tool's new import against that tool's baseline", async () => {
    const sc = await scenario({ baselineAfterFirst: true });
    const r = okData<{
      regressed: boolean;
      reference: string;
      baseline_scan_id: string;
      current_scan_id: string;
      new_findings_by_severity: Record<Severity, number>;
      resolved_findings_by_severity: Record<Severity, number>;
    }>(await callTool('regression_alert', { project_path: sc.dir, scan_type: 'sarif_import', source_tool: 'CodeQL' }, sc.s.plugin));
    expect(r.current_scan_id).toBe(sc.codeql2);
    expect(r.baseline_scan_id).toBe(sc.codeql1);
    expect(r.reference).toBe('baseline');
    expect(r.regressed).toBe(true);
    expect(r.new_findings_by_severity.critical).toBe(1);
    expect(r.resolved_findings_by_severity.medium).toBe(1);
  });

  it('T-06 suppress_finding takes an imported finding by its identity, and a later import of it stays suppressed', async () => {
    const sc = await scenario();
    const fp = fingerprintOf(sc, sc.codeql2, 'B');
    const identity = sc.s.storage.findings.listByScan(sc.codeql2).find((f) => f.fingerprint === fp)?.identity;
    const sup = okData<{ finding_identity: string | null }>(
      await callTool('suppress_finding', { project_path: sc.dir, finding_fingerprint: fp, reason: 'accepted risk' }, sc.s.plugin),
    );
    expect(sup.finding_identity).toBe(identity);
    // B moves down a line: a new fingerprint, the same SARIF fingerprint, the same identity.
    await imported(sc.s, sc.dir, 'ci/codeql-3.sarif', codeql([B(2), T(), C()]));
    const open = openSetForProject(sc.s.storage, sc.dir);
    expect(open.findings.flatMap(messageOf)).not.toContain('B');
    expect(open.suppressed).toBeGreaterThanOrEqual(1);
  });

  it('T-06 triage_findings and prioritize_findings read the imports of every tool, newest of each', async () => {
    const sc = await scenario();
    const triage = okData<{ summary: { total: number }; likely_false_positive: Array<{ fingerprint: string }> }>(
      await callTool('triage_findings', { project_path: sc.dir }, sc.s.plugin),
    );
    // CodeQL #2 holds B, T and C; Snyk #1 holds S — CodeQL #1's A is not open.
    expect(triage.summary.total).toBe(4);
    expect(triage.likely_false_positive.map((b) => b.fingerprint)).toContain(fingerprintOf(sc, sc.codeql2, 'T'));
    const ranked = okData<{ ranked: Array<{ finding: Finding }> }>(await callTool('prioritize_findings', { project_path: sc.dir }, sc.s.plugin));
    const messages = ranked.ranked.flatMap((r) => messageOf(r.finding));
    expect(messages).toEqual(expect.arrayContaining(['B', 'T', 'C', 'S']));
    expect(messages).not.toContain('A');
  });

  it("T-06 report_export takes source_tool, and exports that tool's newest import", async () => {
    const sc = await scenario();
    const r = okData<{ scan_id: string; file_path: string; findings_count: number }>(
      await callTool('report_export', { project_path: sc.dir, format: 'json', source_tool: 'Snyk Code' }, sc.s.plugin),
    );
    expect(r.scan_id).toBe(sc.snyk1);
    expect(r.findings_count).toBe(1);
    const sarif = okData<{ file_path: string }>(
      await callTool('report_export', { project_path: sc.dir, scan_id: sc.codeql2, format: 'sarif' }, sc.s.plugin),
    );
    const exported = readFileSync(sarif.file_path, 'utf8');
    expect(exported).toContain('js/code-injection');
    expect(exported).not.toContain('javascript/HardcodedSecret');
  });
});

// ---------------------------------------------------------------------------
describe('T-20 a dev-guardian SARIF export imports back with the same identities (US-3.AC-1)', () => {
  it('T-20 every finding of an export keeps its identity and its exact severity', async () => {
    const s = freshPlugin();
    const dir = project('sarif-t20-');
    const severities: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
    const built = severities.map((severity, i) =>
      makeFinding({
        tool: 'semgrep',
        rule_id: `dg.rule-${severity}`,
        severity,
        category: 'security',
        title: `finding ${severity}`,
        message: `message ${severity}`,
        file_path: i % 2 === 0 ? 'src/db.js' : 'src/view.js',
        line_start: 1 + (i % 2),
        taxonomy: { cwe: ['CWE-89'] },
      }),
    );
    const originals = assignIdentities(built, { projectPath: dir, readSource: makeSourceReader(dir) });
    const out = await importOk(s.plugin, dir, writeSarif(dir, 'exports/dev-guardian.sarif', toSarif(originals)));
    expect(out.counts_total['identity_computed']).toBe(0);
    const rows = out.runs.flatMap((run) => s.storage.findings.listByScan(run.scan_id));
    const bySeverity = new Map(rows.map((f) => [f.identity ?? '', f.severity]));
    expect(rows).toHaveLength(originals.length);
    for (const f of originals) {
      expect(bySeverity.get(f.identity), `${f.severity} finding ${f.identity}`).toBe(f.severity);
    }
  });
});

// ---------------------------------------------------------------------------
describe('T-22 import time is linear in the number of results (SC-003, NFR-3)', () => {
  /** A log of `n` results over 20 files; one in four carries no fingerprint, so identities are computed too. */
  function bulk(n: number): string {
    const results: string[] = [];
    for (let i = 0; i < n; i += 1) {
      const fp = i % 4 === 0 ? '' : `,"partialFingerprints":{"primaryLocationLineHash":"${i.toString(16)}:1"}`;
      results.push(
        `{"ruleId":"rule-${String(i % 13)}","level":"warning","message":{"text":"result ${String(i)}"},` +
          `"locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/f${String(i % 20)}.js"},"region":{"startLine":${String(i + 1)}}}}]${fp}}`,
      );
    }
    return `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Bulk","version":"1.0"}},"results":[${results.join(',')}]}]}`;
  }

  it('T-22 10 000 results cost about 8x what 1 250 cost — linear, not quadratic', () => {
    const s = freshPlugin();
    const dir = project('sarif-t22-');
    for (let f = 0; f < 20; f += 1) writeFileSync(join(dir, 'src', `f${String(f)}.js`), `line ${String(f)}\n`.repeat(40));
    const texts = new Map<number, string>();
    const textOf = (n: number): string => {
      let t = texts.get(n);
      if (t === undefined) {
        t = bulk(n);
        texts.set(n, t);
      }
      return t;
    };
    let runs = 0;
    const run = (n: number): void => {
      runs += 1;
      const result = importSarif(textOf(n), { projectPath: dir });
      persistSarifImport(s.storage, dir, result, { sourceFile: `bulk-${String(runs)}.sarif` });
    };
    expectLinear('import_sarif (parse + persist)', run, 1_250);
    if (PERF_STRICT) expect(costOf(() => run(10_000))).toBeLessThan(10_000);
  });

  it('T-22 control: the bulk log imports every one of its results (the timing above measures real work)', () => {
    const result = importSarif(bulk(8), { projectPath: projectDir('sarif-t22-') });
    expect(result.runs[0]?.findings).toHaveLength(8);
    expect(result.runs[0]?.counts.identity_computed).toBe(2);
  });
});
