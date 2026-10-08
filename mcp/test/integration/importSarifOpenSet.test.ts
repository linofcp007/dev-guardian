/**
 * The open set with SARIF imports in it — the `sarif-import` feature's test
 * plan T-07 (US-1.AC-7), a property over generated histories.
 *
 * The open set keeps one slot per scan type (`history/scanRoles.ts`). Every
 * import is one scan type, `sarif_import`, so a single slot would let an
 * import of CodeQL's log wipe out what Snyk's import had opened. The design
 * gives each source tool its own slot. What this pins, over random
 * interleavings of native scans and imports of three tools:
 *
 *   1. imports of different tools coexist: each tool's newest import is open;
 *   2. a new import of a tool replaces that tool's previous import — and only
 *      it (an import with no results empties that tool's part);
 *   3. the native findings in the open set are exactly what they are in the
 *      same history with no import at all.
 *
 * Each case runs the same native history in two projects — one with the
 * imports interleaved, one without — so (3) compares like with like.
 */

import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it, vi } from 'vitest';
import { openSetForProject, type OpenFinding } from '../../src/history/openSet.js';
import { resolveProjectPath } from '../../src/platform/projectPath.js';
import { importSarif } from '../../src/sarif/importSarif.js';
import { persistSarifImport } from '../../src/sarif/persistImport.js';
import type { ScanType, Severity, ToolRun } from '../../src/types.js';
import { freshPlugin, seedScan, type SeedFinding, type Seeded } from '../helpers/historySeed.js';
import { isImportScan, sarifLog, sarifResult, sarifRun, sarifText, type JsonObject } from '../helpers/sarif.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';
import { mulberry32 } from '../helpers/yamlFuzz.js';

vi.setConfig({ testTimeout: 120_000 });
afterAll(cleanupTempDirs);

const CASES = 200;
const SOURCE_TOOLS = ['CodeQL', 'Snyk Code', 'ESLint'] as const;
const NATIVE: ReadonlyArray<{ type: ScanType; tool: string; run: ToolRun }> = [
  { type: 'sast', tool: 'semgrep', run: { name: 'semgrep', status: 'ok' } },
  { type: 'secrets', tool: 'gitleaks', run: { name: 'gitleaks', status: 'ok' } },
  { type: 'deps', tool: 'trivy', run: { name: 'trivy', status: 'ok' } },
  { type: 'iac', tool: 'trivy-config', run: { name: 'trivy-config', status: 'ok' } },
];
const SEVERITIES: readonly Severity[] = ['info', 'low', 'medium', 'high', 'critical'];

function pick<T>(r: () => number, xs: readonly T[]): T {
  const x = xs[Math.floor(r() * xs.length)];
  if (x === undefined) throw new Error('empty pool');
  return x;
}

/** A native scan's findings: a few, drawn from a small pool so scans of one type overlap. */
function nativeFindings(r: () => number, tool: string): SeedFinding[] {
  return Array.from({ length: Math.floor(r() * 4) }, () => {
    const n = Math.floor(r() * 6);
    return { tool, rule_id: `${tool}.rule-${String(n)}`, severity: pick(r, SEVERITIES), file: `src/n${String(n)}.ts`, line: 1 + n };
  });
}

/** An import of `tool`: up to five failing results with fingerprints, drawn from a pool so imports overlap; sometimes none. */
function importLog(r: () => number, tool: string): JsonObject {
  const n = r() < 0.15 ? 0 : 1 + Math.floor(r() * 5);
  const ids = new Set<number>();
  while (ids.size < n) ids.add(Math.floor(r() * 8));
  const results = [...ids].map((id) =>
    sarifResult({
      ruleId: `${tool}/rule-${String(id % 3)}`,
      level: pick(r, ['error', 'warning', 'note']),
      message: `${tool} result ${String(id)}`,
      uri: `src/f${String(id)}.js`,
      startLine: 1 + id,
      partialFingerprints: { primaryLocationLineHash: `${tool}-${String(id)}` },
    }),
  );
  return sarifLog([sarifRun({ tool, results })]);
}

/** A native finding, as comparable across the two projects of a case. */
const nativeKey = (f: OpenFinding): string => `${f.fingerprint}|${f.severity}|${f.rule_id ?? ''}|${f.file_path ?? ''}`;

describe('T-07 the open set with imports of several tools (US-1.AC-7) — property', () => {
  it(`T-07 over ${String(CASES)} generated histories: imports of different tools coexist, a new import of a tool replaces only that tool's, and native findings are the same with and without imports`, () => {
    const s: Seeded = freshPlugin();
    const root = resolveProjectPath(makeTempDir('sarif-openset-')).path;
    const r = mulberry32(7_102_026);
    let seq = 0;

    for (let c = 0; c < CASES; c += 1) {
      const mixed = join(root, `case-${String(c)}-mixed`);
      const plain = join(root, `case-${String(c)}-native`);
      mkdirSync(mixed);
      mkdirSync(plain);
      const lastImport = new Map<string, string>();
      const steps = 1 + Math.floor(r() * 7);
      for (let k = 0; k < steps; k += 1) {
        if (r() < 0.4) {
          // The same native scan, in both projects.
          const native = pick(r, NATIVE);
          const findings = nativeFindings(r, native.tool);
          for (const project of [mixed, plain]) {
            seq += 1;
            seedScan(s, { id: `n-${String(seq)}`, type: native.type, project, findings, tools_run: [native.run] });
          }
        } else {
          const tool = pick(r, SOURCE_TOOLS);
          const result = importSarif(sarifText(importLog(r, tool)), { projectPath: mixed });
          const written = persistSarifImport(s.storage, mixed, result, { sourceFile: `c${String(c)}-${String(k)}.sarif` });
          expect(written).toHaveLength(1);
          const scanId = written[0]?.scan_id;
          if (scanId !== undefined) lastImport.set(tool, scanId);
        }
      }

      const label = `case ${String(c)}`;
      const set = openSetForProject(s.storage, mixed);
      const importOf = (f: OpenFinding): boolean => {
        const scan = s.storage.scans.getById(f.scan_id);
        return scan !== null && isImportScan(scan);
      };

      // (1) + (2): the imported part is exactly each tool's newest import.
      const imported = set.findings.filter(importOf);
      const newest = new Set(lastImport.values());
      expect(
        imported.filter((f) => !newest.has(f.scan_id)).map((f) => f.scan_id),
        `${label}: nothing open from an import a newer import of its tool replaced`,
      ).toEqual([]);
      for (const [tool, scanId] of lastImport) {
        const expected = s.storage.findings.listByScan(scanId).map((f) => f.fingerprint).sort();
        const actual = imported.filter((f) => f.scan_id === scanId).map((f) => f.fingerprint).sort();
        expect(actual, `${label}: ${tool}'s newest import is open, whole`).toEqual(expected);
      }

      // (3): native findings as if no import had happened.
      const natives = set.findings.filter((f) => !importOf(f)).map(nativeKey).sort();
      const control = openSetForProject(s.storage, plain).findings.map(nativeKey).sort();
      expect(natives, `${label}: native findings unchanged by imports`).toEqual(control);
    }
  });
});
