/**
 * Scan retention against the readers that stand on the rows it keeps.
 *
 * Retention keeps the newest N scans per (project, scan type). Two seams let
 * it delete exactly the rows a reader needed, with nothing to say so:
 *
 *   - I1: a scoped scan (`meta.scope`, a `--staged` pre-commit run) is a
 *     `sast` row like any other, so fifty of them pushed out the last
 *     whole-project `scan_sast` — and the open set, which never reads a
 *     scoped row, lost every SAST finding.
 *   - I2: a baseline on an orchestrated `security_scan_full` parent is
 *     compared through the parent's CHILDREN (`history/runCompare.ts`), which
 *     are ordinary `sast`/`secrets`/`deps`/`iac` rows. Once the `sast` child
 *     was pruned, every new SAST finding read "not previously measured" and
 *     `regression_alert` went quiet.
 *
 * Both are driven here through the real readers, on the rows the real tools
 * write (the shapes in `test/helpers/historySeed.ts`).
 */

import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { openSetForProject } from '../../src/history/openSet.js';
import { pruneScans } from '../../src/storage/maintenance.js';
import { TOOLS } from '../../src/tools/index.js';
import { freshPlugin, projectDir, seedOrchestratedRun, seedScan } from '../helpers/historySeed.js';
import { cleanupTempDirs } from '../helpers/tempDir.js';
import { okResult } from '../helpers/toolResult.js';

afterAll(cleanupTempDirs);

beforeAll(async () => {
  await import('../../src/tools/regressionAlert.js');
});

function tool(name: string) {
  const t = TOOLS.find((x) => x.name === name);
  if (!t) throw new Error(`tool ${name} not registered`);
  return t;
}

const OLD = 'a'.repeat(64);
const NEW = 'b'.repeat(64);

describe('I1: scoped scans never prune the whole-project scan the open set reads', () => {
  it('three scoped sast scans + one whole-project scan, keep 3: the SAST finding is still open', () => {
    const s = freshPlugin();
    const p = projectDir('retention-scoped-');
    seedScan(s, { id: 'full-sast', type: 'sast', project: p, findings: [{ fp: OLD, severity: 'high' }] });
    for (const id of ['sc1', 'sc2', 'sc3']) {
      seedScan(s, { id, type: 'sast', project: p, meta: { scope: { mode: 'staged', files: 1 } } });
    }

    pruneScans(s.db, 3);

    const open = openSetForProject(s.storage, p);
    expect(open.sources.map((x) => x.scan_id)).toContain('full-sast');
    expect(open.findings.map((f) => f.fingerprint)).toEqual([OLD]);
  });
});

describe('I2: a baseline on an orchestrated parent keeps the children it is compared through', () => {
  interface AlertOut {
    regressed: boolean;
    reference: string;
    baseline_scan_id: string;
    current_scan_id: string;
    score_delta: number;
    new_findings_by_severity: Record<string, number>;
  }

  it('baseline on the parent, later sast scans push its sast child out, prune: regression_alert still reports the new high', async () => {
    const s = freshPlugin();
    const p = projectDir('retention-baseline-');
    seedOrchestratedRun(s, 'run1', p, { sast: { findings: [{ fp: OLD, identity: 'I-OLD', severity: 'high' }] } });
    s.storage.baselines.set({ scan_id: 'run1' });
    for (const id of ['sa', 'sb', 'sc']) {
      seedScan(s, { id, type: 'sast', project: p, findings: [{ fp: OLD, identity: 'I-OLD', severity: 'high' }] });
    }
    seedOrchestratedRun(s, 'run2', p, {
      sast: {
        findings: [
          { fp: OLD, identity: 'I-OLD', severity: 'high' },
          { fp: NEW, identity: 'I-NEW', severity: 'high' },
        ],
      },
    });

    pruneScans(s.db, 3);
    expect(s.storage.scans.getById('run1-sast')).not.toBeNull();

    const alert = okResult<AlertOut>(
      await tool('regression_alert').handler({ project_path: p, threshold: 0 }, s.plugin),
    );
    expect(alert.reference).toBe('baseline');
    expect([alert.baseline_scan_id, alert.current_scan_id]).toEqual(['run1', 'run2']);
    expect(alert.new_findings_by_severity['high']).toBe(1);
    expect(alert.score_delta).toBe(5);
    expect(alert.regressed).toBe(true);
  });
});
