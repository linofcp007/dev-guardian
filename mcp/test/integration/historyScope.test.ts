/**
 * Project- and type-scoped history reads — the reproductions.
 *
 * One `.guardian/guardian.db` holds scans from many projects and of many
 * types. Every reader below used to answer from "the latest completed scan
 * of ANY type in ANY project" (or searched a window of the 50 newest rows),
 * and each test here is one of the ways that was measured to go wrong:
 *
 *   - `generate_sbom` after a SAST scan made `findings/open` and
 *     `risk_score` report zero — the SBOM row was the newest and has no
 *     findings;
 *   - `diff_scans from:'previous'` picked another project's scan;
 *   - `create_github_issues` filed project B's findings on project A's repo;
 *   - `guardian://baseline` showed another project's baseline;
 *   - lookups by type used a 50-scan window.
 */

import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';

vi.mock('../../src/tools/scanHelpers.js', async () => {
  const actual =
    await vi.importActual<typeof import('../../src/tools/scanHelpers.js')>(
      '../../src/tools/scanHelpers.js',
    );
  return { ...actual, scannerAvailable: vi.fn() };
});
vi.mock('../../src/runners/processRunner.js', () => ({ runProcess: vi.fn() }));

import { scannerAvailable } from '../../src/tools/scanHelpers.js';
import { RESOURCES } from '../../src/resources/index.js';
import { TOOLS } from '../../src/tools/index.js';
import { okResult } from '../helpers/toolResult.js';
import { cleanupTempDirs } from '../helpers/tempDir.js';
import { freshPlugin, projectDir, seedScan, type Seeded } from '../helpers/historySeed.js';

afterAll(cleanupTempDirs);
afterEach(() => {
  vi.restoreAllMocks();
  vi.mocked(scannerAvailable).mockReset();
});

beforeAll(async () => {
  await import('../../src/registerAll.js');
});

function tool(name: string) {
  const t = TOOLS.find((x) => x.name === name);
  if (!t) throw new Error(`tool ${name} not registered`);
  return t;
}

async function readResource(name: string, s: Seeded, cwd: string, uri: string, params: Record<string, string> = {}) {
  const r = RESOURCES.find((x) => x.name === name);
  if (!r) throw new Error(`resource ${name} not registered`);
  vi.spyOn(process, 'cwd').mockReturnValue(cwd);
  return (await r.handler(new URL(uri), params, s.plugin)).json;
}

describe('tool descriptions', () => {
  // Claude Code truncates at 2048; this repo keeps a 1500 margin. The history
  // readers' descriptions grew with their project_path/scan_type contract.
  it.each([
    'risk_score', 'diff_scans', 'regression_alert', 'set_baseline', 'triage_findings',
    'prioritize_findings', 'create_github_issues', 'suggest_fix', 'report_export', 'generate_sbom',
  ])('%s stays within 1500 characters', (name) => {
    expect(tool(name).description.length).toBeLessThanOrEqual(1500);
  });
});

describe('an SBOM (or any non-state scan) never shadows the findings', () => {
  it('guardian://findings/open and risk_score still report the SAST findings after generate_sbom', async () => {
    const s = freshPlugin();
    const p = projectDir();
    seedScan(s, { id: 'sast-1', type: 'sast', project: p, findings: [{ severity: 'high' }, { severity: 'critical' }] });
    // Exactly the row generate_sbom writes.
    seedScan(s, {
      id: 'sbom-1', type: 'sbom', project: p,
      tools_run: [{ name: 'syft', status: 'ok' }],
      meta: { format: 'cyclonedx-json', produced_by: 'syft' },
    });

    const open = (await readResource('guardian-findings-open', s, p, 'guardian://findings/open')) as {
      findings: unknown[]; total: number;
    };
    expect(open.total).toBe(2);
    expect(open.findings).toHaveLength(2);

    const risk = okResult<{ components: { findings: { open_findings: number } } }>(
      await tool('risk_score').handler({ project_path: p }, s.plugin),
    );
    expect(risk.components.findings.open_findings).toBe(2);
  });

  it('keeps every type\'s findings: a newer secrets scan does not hide the SAST ones', async () => {
    const s = freshPlugin();
    const p = projectDir();
    seedScan(s, { id: 'sast-1', type: 'sast', project: p, findings: [{ tool: 'semgrep' }] });
    seedScan(s, {
      id: 'sec-1', type: 'secrets', project: p,
      tools_run: [{ name: 'gitleaks', status: 'ok' }],
      findings: [{ tool: 'gitleaks', subcategory: 'secret' }],
    });
    const open = (await readResource('guardian-findings-open', s, p, 'guardian://findings/open')) as {
      findings: Array<{ tool: string }>;
    };
    expect(open.findings.map((f) => f.tool).sort()).toEqual(['gitleaks', 'semgrep']);
  });
});

describe('diff_scans stays inside one project', () => {
  it("from:'previous' picks this project's previous scan of the type, not another project's", async () => {
    const s = freshPlugin();
    const a = projectDir('hist-a-');
    const b = projectDir('hist-b-');
    const a1 = seedScan(s, { id: 'a1', type: 'sast', project: a, findings: [{ fp: 'x'.repeat(64) }] });
    seedScan(s, { id: 'b1', type: 'sast', project: b, findings: [{ fp: 'y'.repeat(64) }] });
    const a2 = seedScan(s, { id: 'a2', type: 'sast', project: a, findings: [{ fp: 'x'.repeat(64) }] });

    const r = okResult<{ from_scan_id: string; to_scan_id: string; summary: { new: number } }>(
      await tool('diff_scans').handler({ project_path: a, from: 'previous' }, s.plugin),
    );
    expect(r.to_scan_id).toBe(a2);
    expect(r.from_scan_id).toBe(a1);
    expect(r.summary.new).toBe(0);
  });

  it("to:'latest' is this project's latest state scan, not a later SBOM or another project's scan", async () => {
    const s = freshPlugin();
    const a = projectDir('hist-a-');
    const b = projectDir('hist-b-');
    seedScan(s, { id: 'a1', type: 'sast', project: a });
    const a2 = seedScan(s, { id: 'a2', type: 'sast', project: a });
    seedScan(s, { id: 'a-sbom', type: 'sbom', project: a });
    seedScan(s, { id: 'b1', type: 'sast', project: b });

    const r = okResult<{ to_scan_id: string }>(
      await tool('diff_scans').handler({ project_path: a }, s.plugin),
    );
    expect(r.to_scan_id).toBe(a2);
  });
});

describe('create_github_issues files only this project\'s open findings', () => {
  it("never plans project B's findings for project A's repository", async () => {
    vi.mocked(scannerAvailable).mockResolvedValue('gh');
    const s = freshPlugin();
    const a = projectDir('hist-a-');
    const b = projectDir('hist-b-');
    seedScan(s, { id: 'a1', type: 'sast', project: a, findings: [{ fp: 'a'.repeat(64), severity: 'high' }] });
    seedScan(s, { id: 'b1', type: 'sast', project: b, findings: [{ fp: 'b'.repeat(64), severity: 'critical' }] });

    const r = okResult<{ plans: Array<{ fingerprint: string }> }>(
      await tool('create_github_issues').handler({ project_path: a, dry_run: true }, s.plugin),
    );
    expect(r.plans.map((p) => p.fingerprint)).toEqual(['a'.repeat(64)]);
  });

  it('applies suppressions before planning', async () => {
    vi.mocked(scannerAvailable).mockResolvedValue('gh');
    const s = freshPlugin();
    const a = projectDir('hist-a-');
    seedScan(s, {
      id: 'a1', type: 'sast', project: a,
      findings: [{ fp: 'a'.repeat(64), severity: 'high' }, { fp: 'c'.repeat(64), severity: 'high' }],
    });
    s.storage.suppressions.insert({ finding_fingerprint: 'c'.repeat(64), reason: 'false positive' });

    const r = okResult<{ plans: Array<{ fingerprint: string }> }>(
      await tool('create_github_issues').handler({ project_path: a, dry_run: true }, s.plugin),
    );
    expect(r.plans.map((p) => p.fingerprint)).toEqual(['a'.repeat(64)]);
  });
});

describe('baselines are per project, and record the scan type', () => {
  it("guardian://baseline does not show another project's baseline", async () => {
    const s = freshPlugin();
    const a = projectDir('hist-a-');
    const b = projectDir('hist-b-');
    seedScan(s, { id: 'a1', type: 'sast', project: a });
    const b1 = seedScan(s, { id: 'b1', type: 'sast', project: b });
    s.storage.baselines.set({ scan_id: b1 });

    const mine = (await readResource('guardian-baseline', s, a, 'guardian://baseline')) as { active: boolean };
    expect(mine.active).toBe(false);
    const theirs = (await readResource('guardian-baseline', s, b, 'guardian://baseline')) as {
      active: boolean; scan_id: string; scan_type: string;
    };
    expect(theirs.active).toBe(true);
    expect(theirs.scan_id).toBe(b1);
    expect(theirs.scan_type).toBe('sast');
  });

  it("set_baseline without a scan_id takes this project's latest state scan", async () => {
    const s = freshPlugin();
    const a = projectDir('hist-a-');
    const b = projectDir('hist-b-');
    const a1 = seedScan(s, { id: 'a1', type: 'sast', project: a });
    seedScan(s, { id: 'a-sbom', type: 'sbom', project: a });
    seedScan(s, { id: 'b1', type: 'sast', project: b });

    const r = okResult<{ scan_id: string; scan_type: string; project_path: string }>(
      await tool('set_baseline').handler({ project_path: a }, s.plugin),
    );
    expect(r.scan_id).toBe(a1);
    expect(r.scan_type).toBe('sast');
    expect(r.project_path).toBe(a);
  });

  it('regression_alert compares same-type scans of this project only', async () => {
    const s = freshPlugin();
    const a = projectDir('hist-a-');
    const sast1 = seedScan(s, { id: 'sast1', type: 'sast', project: a, findings: [{ fp: 'k'.repeat(64) }] });
    const secrets = seedScan(s, {
      id: 'sec1', type: 'secrets', project: a,
      tools_run: [{ name: 'gitleaks', status: 'ok' }],
      findings: [
        { tool: 'gitleaks', severity: 'critical' },
        { tool: 'gitleaks', severity: 'critical' },
      ],
    });
    s.storage.baselines.set({ scan_id: secrets });
    const sast2 = seedScan(s, { id: 'sast2', type: 'sast', project: a, findings: [{ fp: 'k'.repeat(64) }] });

    const r = okResult<{ baseline_scan_id: string; current_scan_id: string; scan_type: string; score_delta: number }>(
      await tool('regression_alert').handler({ project_path: a }, s.plugin),
    );
    expect(r.current_scan_id).toBe(sast2);
    expect(r.scan_type).toBe('sast');
    // The secrets baseline is another type: never compared against a SAST run.
    expect(r.baseline_scan_id).toBe(sast1);
    expect(r.score_delta).toBe(0);
  });
});

describe('latest-by-type is a query, not a 50-scan window', () => {
  it('finds the compliance scan after 60 newer scans elsewhere', async () => {
    const s = freshPlugin();
    const a = projectDir('hist-a-');
    const b = projectDir('hist-b-');
    const compliance = seedScan(s, {
      id: 'comp-a', type: 'compliance', project: a,
      meta: { policy_documents_found: { privacy_policy: false, terms_of_service: false, security_policy: true } },
    });
    for (let i = 0; i < 60; i++) seedScan(s, { id: `b-${i}`, type: 'sast', project: b });

    const status = (await readResource('guardian-compliance-status', s, a, 'guardian://compliance/status')) as {
      scan_id?: string;
    };
    expect(status.scan_id).toBe(compliance);

    const risk = okResult<{ components: { compliance: { policies_missing: number } } }>(
      await tool('risk_score').handler({ project_path: a }, s.plugin),
    );
    expect(risk.components.compliance.policies_missing).toBe(2);
  });
});

describe('risk_score reports its real coverage', () => {
  it('flags partial coverage instead of a literal coverage_partial:false', async () => {
    const s = freshPlugin();
    const a = projectDir();
    seedScan(s, {
      id: 's1', type: 'sast', project: a,
      tools_run: [{ name: 'semgrep', status: 'ok' }, { name: 'bandit', status: 'failed' }],
      findings: [{ severity: 'high' }],
    });
    const r = okResult<{ coverage_caveat: boolean; coverage: { level: string } }>(
      await tool('risk_score').handler({ project_path: a }, s.plugin),
    );
    expect(r.coverage_caveat).toBe(true);
    expect(r.coverage.level).toBe('partial');
  });

  it('says so when it skipped a newer scan that measured nothing', async () => {
    const s = freshPlugin();
    const a = projectDir();
    const good = seedScan(s, { id: 'good', type: 'sast', project: a, findings: [{ severity: 'high' }] });
    const empty = seedScan(s, {
      id: 'empty', type: 'sast', project: a,
      tools_run: [{ name: 'semgrep', status: 'skipped', reason: 'not_installed' }],
      missing_tools: ['semgrep'],
    });
    const r = okResult<{
      components: { findings: { open_findings: number } };
      coverage: { skipped: Array<{ scan_id: string; reason: string }>; sources: Array<{ scan_id: string }> };
    }>(await tool('risk_score').handler({ project_path: a }, s.plugin));
    expect(r.components.findings.open_findings).toBe(1);
    expect(r.coverage.sources.map((x) => x.scan_id)).toEqual([good]);
    expect(r.coverage.skipped).toEqual([expect.objectContaining({ scan_id: empty, reason: 'coverage_none' })]);
  });
});

describe('report_export', () => {
  it("exports this project's latest state scan by default, not another project's or an SBOM", async () => {
    const s = freshPlugin();
    const a = projectDir('hist-a-');
    const b = projectDir('hist-b-');
    const a1 = seedScan(s, { id: 'a1', type: 'sast', project: a, findings: [{ severity: 'high' }] });
    seedScan(s, { id: 'a-sbom', type: 'sbom', project: a });
    seedScan(s, { id: 'b1', type: 'sast', project: b });

    const r = okResult<{ scan_id: string; findings_count: number }>(
      await tool('report_export').handler({ project_path: a, format: 'json' }, s.plugin),
    );
    expect(r.scan_id).toBe(a1);
    expect(r.findings_count).toBe(1);
  });
});

describe('suggest_fix', () => {
  it("finds the finding in this project's scans, not only the global latest", async () => {
    const s = freshPlugin();
    const a = projectDir('hist-a-');
    const fp = 'f'.repeat(64);
    seedScan(s, { id: 'a1', type: 'sast', project: a, findings: [{ fp, rule_id: 'r1' }] });
    seedScan(s, { id: 'a2', type: 'secrets', project: a, tools_run: [{ name: 'gitleaks', status: 'ok' }] });

    const r = okResult<{ finding: { fingerprint: string } }>(
      await tool('suggest_fix').handler({ project_path: a, finding_fingerprint: fp }, s.plugin),
    );
    expect(r.finding.fingerprint).toBe(fp);
  });

  it('lists only prior suppressions of the same tool and rule_id', async () => {
    const s = freshPlugin();
    const a = projectDir('hist-a-');
    const target = '1'.repeat(64);
    const sameRule = '2'.repeat(64);
    const otherRule = '3'.repeat(64);
    seedScan(s, {
      id: 'a1', type: 'sast', project: a,
      findings: [
        { fp: target, rule_id: 'r1' },
        { fp: sameRule, rule_id: 'r1' },
        { fp: otherRule, rule_id: 'r2' },
      ],
    });
    s.storage.suppressions.insert({ finding_fingerprint: sameRule, reason: 'same rule, accepted' });
    s.storage.suppressions.insert({ finding_fingerprint: otherRule, reason: 'unrelated rule' });

    const r = okResult<{ prior_related_suppressions: Array<{ reason: string }> }>(
      await tool('suggest_fix').handler({ project_path: a, finding_fingerprint: target }, s.plugin),
    );
    expect(r.prior_related_suppressions.map((x) => x.reason)).toEqual(['same rule, accepted']);
  });
});
