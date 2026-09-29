/**
 * A response field a model is not told about is a field it does not read.
 *
 * The 3.0 review's first wave added fields that change how a result must be
 * read — a mass suppression counted apart, a database that is not being
 * used, scans dated in the future, the project files that decided part of a
 * scan — and no tool description named any of them: a model reading
 * `regression_alert` saw `regressed: false` and nothing of the 40 critical
 * findings a suppression had taken out of the score.
 *
 * Two halves, kept light:
 *   - each tool's description names the fields a model needs to use it
 *     correctly (the table below);
 *   - for the history tools, the fields a description promises exist in the
 *     tool's real result, on a seeded database — a description naming a key
 *     the tool never returns would be worse than none.
 *
 * The scan tools' per-run fields (`tools_run[].honoured_config`,
 * `suppressed_by_repo_config`, `plugin_packs`) and review_pr's
 * `preexisting_manifest_gaps` need real scanners to produce; the tests of
 * their producers hold those (`repoConfigNaming`, `trivyRepoConfig`,
 * `pluginPackGap`, `trivyManifestCoverage`).
 */

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import '../../../src/registerAll.js';
import { TOOLS } from '../../../src/tools/index.js';
import { freshPlugin, projectDir, seedScan, type Seeded } from '../../helpers/historySeed.js';
import { cleanupTempDirs } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

/** tool -> the response fields (or refusals) its description must name. */
const DOCUMENTED: Record<string, readonly string[]> = {
  regression_alert: ['suppressed_by_severity', 'not_remeasured_by_severity'],
  diff_scans: ['summary.suppressed', 'suppressed_findings', 'unknown_scan_id'],
  health_status: ['storage_warning', 'db adopt', 'suppressions', 'all_projects', 'future_dated_scans_ignored', 'future_dated_note'],
  risk_score: ['suppressed_count', 'future_dated_note'],
  report_export: ['retry_with', 'still running'],
  review_pr: ['preexisting_manifest_gaps'],
  scan_sast: ['honoured_config', 'plugin_packs'],
  scan_secrets: ['honoured_config'],
  scan_deps: ['honoured_config', 'suppressed_by_repo_config'],
  scan_iac: ['honoured_config', 'suppressed_by_repo_config'],
  security_scan_full: ['honoured_config', 'suppressed_by_repo_config'],
};

function tool(name: string): (typeof TOOLS)[number] {
  const t = TOOLS.find((x) => x.name === name);
  if (t === undefined) throw new Error(`${name} is not registered`);
  return t;
}

describe('tool descriptions name the response fields a model must read', () => {
  it.each(Object.entries(DOCUMENTED))('%s', (name, fields) => {
    const description = tool(name).description;
    const missing = fields.filter((f) => !description.includes(f));
    expect(missing, description).toEqual([]);
  });

  it('health_status tells the model to hand db adopt to the user, never to run it', () => {
    expect(tool('health_status').description).toMatch(/never run it yourself/i);
  });
});

describe('the history tools return what their descriptions promise (seeded database)', () => {
  let s: Seeded;
  let project = '';

  beforeAll(() => {
    s = freshPlugin();
    project = projectDir('field-docs-');
    seedScan(s, { id: 'a', type: 'sast', project, findings: [{ fp: 'kept', severity: 'high' }] });
    seedScan(s, {
      id: 'b',
      type: 'sast',
      project,
      findings: [
        { fp: 'kept', severity: 'high' },
        { fp: 'hidden', severity: 'critical' },
      ],
    });
    const hidden = s.storage.findings.listByScan('b').find((f) => f.fingerprint === 'hidden');
    if (hidden === undefined) throw new Error('seed');
    s.storage.suppressions.insert({
      finding_fingerprint: hidden.fingerprint,
      ...(hidden.identity !== undefined ? { finding_identity: hidden.identity } : {}),
      reason: 'accepted',
      project_path: project,
    });
  });

  async function call(name: string, input: Record<string, unknown>): Promise<Record<string, unknown>> {
    const r = (await tool(name).handler(input, s.plugin)) as unknown as Record<string, unknown>;
    expect(r['ok'], JSON.stringify(r)).toBe(true);
    return r;
  }

  it('regression_alert: suppressed_by_severity counts the suppressed critical apart', async () => {
    const r = await call('regression_alert', { project_path: project, scan_type: 'sast' });
    expect(r['suppressed_by_severity']).toMatchObject({ critical: 1 });
    expect(r['not_remeasured_by_severity']).toBeDefined();
    expect(r['regressed']).toBe(false);
  });

  it('diff_scans: summary.suppressed and suppressed_findings', async () => {
    const r = await call('diff_scans', { project_path: project, scan_type: 'sast' });
    expect((r['summary'] as Record<string, unknown>)['suppressed']).toBe(1);
    expect(r['suppressed_findings']).toHaveLength(1);
  });

  it('diff_scans: another project\'s scan id is refused with unknown_scan_id', async () => {
    const other = projectDir('field-docs-other-');
    seedScan(s, { id: 'other', type: 'sast', project: other });
    const r = (await tool('diff_scans').handler({ project_path: project, to_scan_id: 'other' }, s.plugin)) as unknown as {
      ok: boolean;
      error?: { code: string };
    };
    expect(r.ok).toBe(false);
    expect(r.error?.code).toBe('unknown_scan_id');
  });

  it('health_status: storage_warning, suppressions {active, this_project, all_projects}, storage.future_dated_scans_ignored', async () => {
    const r = await call('health_status', { project_path: project });
    expect(r).toHaveProperty('storage_warning', null);
    expect(r['suppressions']).toEqual({ active: 1, this_project: 1, all_projects: 0 });
    expect((r['storage'] as Record<string, unknown>)['future_dated_scans_ignored']).toBe(0);
  });

  it('risk_score: suppressed_count', async () => {
    const r = await call('risk_score', { project_path: project });
    expect(r['suppressed_count']).toBe(1);
  });

  it('report_export: another project\'s scan id is refused, with retry_with naming its project', async () => {
    const r = (await tool('report_export').handler({ project_path: project, scan_id: 'other' }, s.plugin)) as unknown as {
      ok: boolean;
      error?: { code: string; retry_with?: Record<string, unknown> };
    };
    expect(r.ok).toBe(false);
    expect(r.error?.code).toBe('unknown_scan_id');
    expect(r.error?.retry_with).toMatchObject({ scan_id: 'other' });
  });
});
