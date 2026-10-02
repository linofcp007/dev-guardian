/**
 * What makes an import's coverage partial — the `sarif-import` feature's
 * decision D-2, on top of US-1.AC-11, US-1.AC-12 and US-1.AC-17.
 *
 * A result with no physical location inside the project is imported whole:
 * its rule, severity and message are stored, only its place is unknown. No
 * finding was left out, so it is counted (`without_location`) but is not a
 * coverage gap. Marking it partial cost every later diff of that tool its
 * "resolved" verdicts (`history/runCompare.ts` reads an unknown tool's
 * findings as measured only by a full scan), and a log whose URIs all point
 * outside the root — Trivy's image scans — would never have been full.
 * A skipped result and the results limit do leave findings out.
 */

import { afterAll, describe, expect, it } from 'vitest';
import { importSarif } from '../../src/sarif/importSarif.js';
import { persistSarifImport } from '../../src/sarif/persistImport.js';
import { computeCoverage } from '../../src/tools/scanCoverage.js';
import { freshPlugin } from '../helpers/historySeed.js';
import { sarifLog, sarifResult, sarifRun, sarifText, type JsonObject } from '../helpers/sarif.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

afterAll(cleanupTempDirs);

function coverageOf(results: JsonObject[], maxResults?: number): { coverage: string; counts: unknown } {
  const project = makeTempDir('sarif-coverage-');
  const { storage } = freshPlugin();
  const parsed = importSarif(sarifText(sarifLog([sarifRun({ tool: 'CodeQL', results })])), {
    projectPath: project,
    ...(maxResults !== undefined ? { maxResults } : {}),
  });
  const [written] = persistSarifImport(storage, project, parsed, { sourceFile: 'codeql.sarif' });
  if (written === undefined) throw new Error('no scan written');
  const scan = storage.scans.getById(written.scan_id);
  if (scan === null) throw new Error('scan not stored');
  return { coverage: computeCoverage(scan.tools_run, scan.missing_tools), counts: scan.meta?.['counts'] };
}

const located = (n: number): JsonObject => sarifResult({ ruleId: `r${String(n)}`, message: `m${String(n)}`, uri: 'src/a.js', startLine: n });

describe('sarif-import D-2: what makes an import partial', () => {
  it('results outside the project are counted in without_location and leave coverage full', () => {
    const { coverage, counts } = coverageOf([
      located(1),
      sarifResult({ ruleId: 'image', message: 'in the image', uri: 'file:///usr/lib/libssl.so', startLine: 1 }),
      sarifResult({ ruleId: 'logical', message: 'no location', locations: [] }),
    ]);
    expect(counts).toMatchObject({ imported: 3, without_location: 2 });
    expect(coverage).toBe('full');
  });

  it('a skipped result still makes coverage partial', () => {
    const { coverage } = coverageOf([located(1), sarifResult({ message: null, uri: 'src/b.js', startLine: 1 })]);
    expect(coverage).toBe('partial');
  });

  it('the results limit still makes coverage partial', () => {
    const { coverage } = coverageOf([located(1), located(2), located(3)], 2);
    expect(coverage).toBe('partial');
  });
});
