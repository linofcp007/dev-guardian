/**
 * Follow-up X, fix round 1 (Critical): the open set carries forward what the
 * newer scan did not re-measure.
 *
 * A slot's source is its newest usable scan, and its findings used to be the
 * slot's whole answer. When that scan only partly measured — a file Semgrep
 * only partly parsed (the shared judge's `partial` verdict), a Semgrep that
 * failed beside an ok Bandit, an image pass over image B — every older
 * finding it did not look at again vanished from `findings/open`,
 * `risk_score`, the dashboard, triage, prioritize, create_fix_pr,
 * validate_finding and create_github_issues, with only `coverage: partial`
 * left as a signal.
 *
 * The rule (controller ruling): carry forward every finding of the older
 * usable row(s) of the same slot that `runCompare` would call not
 * re-measured under the newer row (one shared predicate,
 * `runCompare.ts#openGapFor`), walking back while the older row also did not
 * measure it; newer copies win on identity; carried findings are marked
 * `not_remeasured: true`; the older row is a source, with what it was
 * carried for; suppressions still apply; a finding the newer row really
 * measured and did not find stays resolved.
 */

import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { openSetForProject } from '../../../src/history/openSet.js';
import { TOOLS } from '../../../src/tools/index.js';
import type { ToolRun } from '../../../src/types.js';
import { cleanupTempDirs } from '../../helpers/tempDir.js';
import { freshPlugin, projectDir, seedOrchestratedRun, seedScan, type SeedFinding } from '../../helpers/historySeed.js';

afterAll(cleanupTempDirs);
beforeAll(async () => {
  await import('../../../src/tools/riskScore.js');
});

const A_PHP: SeedFinding = { fp: 'a'.repeat(64), identity: 'id-a-php', tool: 'semgrep', rule_id: 'php-xss', file: 'wp/a.php', severity: 'high' };
const B_JS: SeedFinding = { fp: 'b'.repeat(64), identity: 'id-b-js', tool: 'semgrep', rule_id: 'js-eval', file: 'src/b.js', severity: 'high' };
const C_JS: SeedFinding = { fp: 'c'.repeat(64), identity: 'id-c-js', tool: 'semgrep', rule_id: 'js-eval', file: 'src/c.js', severity: 'high' };

const full: ToolRun[] = [{ name: 'semgrep', status: 'ok' }];
const partialOn = (...files: string[]): ToolRun[] => [
  {
    name: 'semgrep',
    status: 'ok',
    reason: 'partial',
    partially_parsed: files.map((file) => ({ file, type: 'PartialParsing', message: 'Syntax error' })),
  },
];

const byFile = (set: ReturnType<typeof openSetForProject>) =>
  Object.fromEntries(set.findings.map((f) => [f.file_path, { scan_id: f.scan_id, not_remeasured: f.not_remeasured }]));

describe('open set: a partly parsed file keeps its older findings (the reviewer\'s shape)', () => {
  function history(): { s: ReturnType<typeof freshPlugin>; p: string } {
    const s = freshPlugin();
    const p = projectDir('carry-sast-');
    seedScan(s, { id: 'a', type: 'sast', project: p, tools_run: full, findings: [A_PHP, B_JS, C_JS] });
    seedScan(s, { id: 'b', type: 'sast', project: p, tools_run: partialOn('wp/a.php'), missing_tools: ['semgrep'], findings: [B_JS] });
    return { s, p };
  }

  it('keeps a.php from the older row, flagged; b.js from the newer; c.js (measured, not found) stays resolved', () => {
    const { s, p } = history();
    const set = openSetForProject(s.storage, p);
    expect(byFile(set)).toEqual({
      'src/b.js': { scan_id: 'b', not_remeasured: undefined },
      'wp/a.php': { scan_id: 'a', not_remeasured: true },
    });
    expect(set.coverage).toBe('partial');
    expect(set.sources.map((x) => ({ scan_id: x.scan_id, findings: x.findings, carried_for: x.carried_for }))).toEqual([
      { scan_id: 'b', findings: 1, carried_for: undefined },
      { scan_id: 'a', findings: 1, carried_for: ['semgrep (partly parsed: wp/a.php)'] },
    ]);
  });

  it('a third partial row still carries a.php from the first', () => {
    const { s, p } = history();
    seedScan(s, { id: 'c', type: 'sast', project: p, tools_run: partialOn('wp/a.php'), missing_tools: ['semgrep'], findings: [B_JS] });
    const set = openSetForProject(s.storage, p);
    expect(byFile(set)).toEqual({
      'src/b.js': { scan_id: 'c', not_remeasured: undefined },
      'wp/a.php': { scan_id: 'a', not_remeasured: true },
    });
  });

  it('stops walking at a row that measured the file: a complete row between them resolves it for good', () => {
    const { s, p } = history();
    seedScan(s, { id: 'c', type: 'sast', project: p, tools_run: full, findings: [B_JS] }); // measured a.php, not found
    seedScan(s, { id: 'd', type: 'sast', project: p, tools_run: partialOn('wp/a.php'), missing_tools: ['semgrep'], findings: [B_JS] });
    expect(Object.keys(byFile(openSetForProject(s.storage, p)))).toEqual(['src/b.js']);
  });

  it('risk_score counts both open findings', async () => {
    const { s, p } = history();
    const tool = TOOLS.find((t) => t.name === 'risk_score');
    if (tool === undefined) throw new Error('risk_score not registered');
    const r = (await tool.handler({ project_path: p }, s.plugin)) as {
      ok: boolean;
      components: { findings: { open_findings: number; score: number } };
    };
    expect(r.ok).toBe(true);
    expect(r.components.findings.open_findings).toBe(2);
    expect(r.components.findings.score).toBe(10); // two highs
  });

  it('the newer copy wins on identity; a suppression still hides a carried finding', () => {
    const { s, p } = history();
    // b re-found a.php's identity on another line: its copy, not the carried one.
    seedScan(s, {
      id: 'c', type: 'sast', project: p, tools_run: partialOn('wp/a.php'), missing_tools: ['semgrep'],
      findings: [B_JS, { ...A_PHP, fp: 'e'.repeat(64), line: 40 }],
    });
    expect(byFile(openSetForProject(s.storage, p))['wp/a.php']).toEqual({ scan_id: 'c', not_remeasured: undefined });

    const { s: s2, p: p2 } = history();
    s2.storage.suppressions.insert({ finding_fingerprint: A_PHP.fp ?? '', finding_identity: 'id-a-php', reason: 'accepted', project_path: p2 });
    expect(Object.keys(byFile(openSetForProject(s2.storage, p2)))).toEqual(['src/b.js']);
  });
});

describe('open set: the same, through an orchestrated security_full run', () => {
  it("carries a.php from the older run's sast child, flagged, and lists that child", () => {
    const s = freshPlugin();
    const p = projectDir('carry-orch-');
    seedOrchestratedRun(s, 'run1', p, { sast: { findings: [A_PHP, B_JS, C_JS] } });
    seedOrchestratedRun(s, 'run2', p, { sast: { runs: partialOn('wp/a.php'), missing: ['semgrep'], findings: [B_JS] } });
    const set = openSetForProject(s.storage, p);
    expect(byFile(set)).toEqual({
      'src/b.js': { scan_id: 'run2-sast', not_remeasured: undefined },
      'wp/a.php': { scan_id: 'run1-sast', not_remeasured: true },
    });
    expect(set.sources.find((x) => x.scan_id === 'run1-sast')?.carried_for).toEqual(['semgrep (partly parsed: wp/a.php)']);
    expect(set.coverage).toBe('partial');
  });
});

describe('open set: two drops this closes', () => {
  it('a scan_sast whose Semgrep failed beside an ok Bandit keeps every older Semgrep finding, flagged', () => {
    const s = freshPlugin();
    const p = projectDir('carry-failed-');
    const bandit: SeedFinding = { fp: 'd'.repeat(64), identity: 'id-bandit', tool: 'bandit', rule_id: 'B101', file: 'app.py' };
    seedScan(s, { id: 'a', type: 'sast', project: p, tools_run: [{ name: 'semgrep', status: 'ok' }, { name: 'bandit', status: 'ok' }], findings: [B_JS, C_JS, bandit] });
    seedScan(s, {
      id: 'b', type: 'sast', project: p,
      tools_run: [{ name: 'semgrep', status: 'failed', reason: 'exit 7' }, { name: 'bandit', status: 'ok' }],
      findings: [],
    });
    const set = openSetForProject(s.storage, p);
    // Semgrep's findings: carried. Bandit's: measured by b and not found — resolved.
    expect(byFile(set)).toEqual({
      'src/b.js': { scan_id: 'a', not_remeasured: true },
      'src/c.js': { scan_id: 'a', not_remeasured: true },
    });
    expect(set.sources.find((x) => x.scan_id === 'a')?.carried_for).toEqual(['semgrep']);
  });

  it("scanning image B keeps image A's findings; scanning image A again resolves them", () => {
    const imageA: SeedFinding = { fp: 'f'.repeat(64), identity: 'id-img-a', tool: 'trivy', rule_id: 'CVE-2099-1', subcategory: 'cve', file: 'registry/app:1 (alpine 3.19)' };
    const imageB: SeedFinding = { fp: '1'.repeat(64), identity: 'id-img-b', tool: 'trivy', rule_id: 'CVE-2099-2', subcategory: 'cve', file: 'registry/other:2 (alpine 3.19)' };
    const image = (target: string): ToolRun[] => [{ name: 'trivy-image', status: 'ok', target }];

    const s = freshPlugin();
    const p = projectDir('carry-image-');
    seedScan(s, { id: 'a', type: 'containers', project: p, tools_run: image('registry/app:1'), findings: [imageA] });
    seedScan(s, { id: 'b', type: 'containers', project: p, tools_run: image('registry/other:2'), findings: [imageB] });
    const set = openSetForProject(s.storage, p);
    expect(byFile(set)).toEqual({
      'registry/other:2 (alpine 3.19)': { scan_id: 'b', not_remeasured: undefined },
      'registry/app:1 (alpine 3.19)': { scan_id: 'a', not_remeasured: true },
    });
    expect(set.sources.find((x) => x.scan_id === 'a')?.carried_for).toEqual(['trivy-image (registry/app:1)']);

    seedScan(s, { id: 'c', type: 'containers', project: p, tools_run: image('registry/app:1'), findings: [] });
    // c re-measured image A (resolved); image B's finding is carried from b.
    expect(byFile(openSetForProject(s.storage, p))).toEqual({
      'registry/other:2 (alpine 3.19)': { scan_id: 'b', not_remeasured: true },
    });
  });

  it('control: a complete newer row carries nothing, and a scanner the newer row did not run at all is not a gap', () => {
    const s = freshPlugin();
    const p = projectDir('carry-control-');
    const bandit: SeedFinding = { fp: 'd'.repeat(64), identity: 'id-bandit', tool: 'bandit', rule_id: 'B101', file: 'app.py' };
    seedScan(s, { id: 'a', type: 'sast', project: p, tools_run: [{ name: 'semgrep', status: 'ok' }, { name: 'bandit', status: 'ok' }], findings: [B_JS, bandit] });
    // Python gone: b runs Semgrep only — Bandit not named, no gap recorded.
    seedScan(s, { id: 'b', type: 'sast', project: p, tools_run: full, findings: [] });
    const set = openSetForProject(s.storage, p);
    expect(set.findings).toEqual([]);
    expect(set.sources.map((x) => x.scan_id)).toEqual(['b']);
    expect(set.coverage).toBe('full');
  });
});
