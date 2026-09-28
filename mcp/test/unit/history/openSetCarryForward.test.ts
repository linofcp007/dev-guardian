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
import { buildSnapshot } from '../../../src/dashboard/snapshot.js';
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

/**
 * Fix round 2.
 */
describe('open set, round 2: a pass that was not requested', () => {
  const image = (target: string): ToolRun => ({ name: 'trivy-image', status: 'ok', target });
  const imageCve: SeedFinding = { fp: '5'.repeat(64), identity: 'id-a-cve', tool: 'trivy', rule_id: 'CVE-2099-1', subcategory: 'cve', file: 'registry/app:1 (alpine 3.19)' };
  const imageMisconfig: SeedFinding = { fp: '6'.repeat(64), identity: 'id-a-mis', tool: 'trivy', rule_id: 'DS-0026', subcategory: 'dockerfile', file: 'app/Dockerfile' };

  it("the reviewer's probe: a Dockerfile-only run keeps image A's CVE as well as its misconfiguration", () => {
    const s = freshPlugin();
    const p = projectDir('carry-r2-image-');
    seedScan(s, {
      id: 'a', type: 'containers', project: p,
      tools_run: [{ name: 'trivy-dockerfile', status: 'ok' }, image('registry/app:1')],
      findings: [imageCve, imageMisconfig],
    });
    seedScan(s, { id: 'b', type: 'containers', project: p, tools_run: [{ name: 'trivy-dockerfile', status: 'ok' }], findings: [] });
    const set = openSetForProject(s.storage, p);
    expect(byFile(set)).toEqual({
      'registry/app:1 (alpine 3.19)': { scan_id: 'a', not_remeasured: true },
      'app/Dockerfile': { scan_id: 'a', not_remeasured: true },
    });
    expect(set.sources.find((x) => x.scan_id === 'a')?.carried_for).toEqual(['trivy-image (registry/app:1)']);
    expect(set.coverage).toBe('partial');
  });

  it('a DAST run that did not request nuclei keeps the older nuclei finding', () => {
    const s = freshPlugin();
    const p = projectDir('carry-r2-nuclei-');
    const nucleiHit: SeedFinding = { fp: '7'.repeat(64), identity: 'id-nuclei', tool: 'nuclei', rule_id: 'exposed-panel', file: '/admin' };
    seedScan(s, { id: 'a', type: 'dast', project: p, tools_run: [{ name: 'guardian-dast', status: 'ok' }, { name: 'nuclei', status: 'ok' }], findings: [nucleiHit] });
    seedScan(s, { id: 'b', type: 'dast', project: p, tools_run: [{ name: 'guardian-dast', status: 'ok' }], findings: [] });
    const set = openSetForProject(s.storage, p);
    expect(byFile(set)).toEqual({ '/admin': { scan_id: 'a', not_remeasured: true } });
    expect(set.sources.find((x) => x.scan_id === 'a')?.carried_for).toEqual(['nuclei']);
  });
});

describe('open set, round 2: what a carry reports', () => {
  it('coverage is partial whenever a finding is carried, even under a full newer scan', () => {
    const s = freshPlugin();
    const p = projectDir('carry-r2-cov-');
    const imageA: SeedFinding = { fp: 'f'.repeat(64), identity: 'id-img-a', tool: 'trivy', rule_id: 'CVE-2099-1', subcategory: 'cve', file: 'registry/app:1 (alpine 3.19)' };
    seedScan(s, { id: 'a', type: 'containers', project: p, tools_run: [{ name: 'trivy-image', status: 'ok', target: 'registry/app:1' }], findings: [imageA] });
    seedScan(s, { id: 'b', type: 'containers', project: p, tools_run: [{ name: 'trivy-image', status: 'ok', target: 'registry/other:2' }], findings: [] });
    const set = openSetForProject(s.storage, p);
    expect(set.sources.map((x) => x.coverage)).toEqual(['full', 'full']);
    expect(set.coverage).toBe('partial');
  });

  it("the dashboard reports what a carried scan was carried FOR, never that scan's own stale gaps", () => {
    const s = freshPlugin();
    const p = projectDir('carry-r2-dash-');
    const imageA: SeedFinding = { fp: 'f'.repeat(64), identity: 'id-img-a', tool: 'trivy', rule_id: 'CVE-2099-1', subcategory: 'cve', file: 'registry/app:1 (alpine 3.19)' };
    // a: hadolint was missing then; b: installed now, and scans another image.
    seedScan(s, {
      id: 'a', type: 'containers', project: p,
      tools_run: [{ name: 'trivy-image', status: 'ok', target: 'registry/app:1' }, { name: 'hadolint', status: 'skipped', reason: 'not_installed' }],
      missing_tools: ['hadolint'],
      findings: [imageA],
    });
    seedScan(s, {
      id: 'b', type: 'containers', project: p,
      tools_run: [{ name: 'trivy-image', status: 'ok', target: 'registry/other:2' }, { name: 'hadolint', status: 'ok' }],
      findings: [],
    });
    const snap = buildSnapshot(s.storage, p, Date.parse('2026-06-01T00:00:00.000Z'));
    expect(snap.coverage.missing_tools).not.toContain('hadolint');
    expect(snap.coverage.missing_tools).toContain('trivy-image');
    // trivy-image ran — over image B: reduced coverage, never "did not run".
    expect(snap.coverage.partial_tools).toContain('trivy-image');
    expect(snap.coverage.level).toBe('partial');
  });

  it('the dashboard says a pass that was not requested this time did not run', () => {
    const s = freshPlugin();
    const p = projectDir('carry-r2-dash-nuclei-');
    const nucleiHit: SeedFinding = { fp: '7'.repeat(64), identity: 'id-nuclei', tool: 'nuclei', rule_id: 'exposed-panel', file: '/admin' };
    seedScan(s, { id: 'a', type: 'dast', project: p, tools_run: [{ name: 'guardian-dast', status: 'ok' }, { name: 'nuclei', status: 'ok' }], findings: [nucleiHit] });
    seedScan(s, { id: 'b', type: 'dast', project: p, tools_run: [{ name: 'guardian-dast', status: 'ok' }], findings: [] });
    const snap = buildSnapshot(s.storage, p, Date.parse('2026-06-01T00:00:00.000Z'));
    expect(snap.coverage.missing_tools).toContain('nuclei');
    expect(snap.coverage.partial_tools).not.toContain('nuclei');
  });

  it('sources stay newest first, carried ones included', () => {
    const s = freshPlugin();
    const p = projectDir('carry-r2-order-');
    seedScan(s, { id: 'sec', type: 'secrets', project: p, tools_run: [{ name: 'gitleaks', status: 'ok' }], findings: [] });
    seedScan(s, { id: 'a', type: 'sast', project: p, tools_run: full, findings: [A_PHP, B_JS] });
    seedScan(s, { id: 'b', type: 'sast', project: p, tools_run: partialOn('wp/a.php'), missing_tools: ['semgrep'], findings: [B_JS] });
    const set = openSetForProject(s.storage, p);
    const started = set.sources.map((x) => x.started_at);
    expect(set.sources.map((x) => x.scan_id)).toEqual(['b', 'a', 'sec']);
    expect([...started].sort().reverse()).toEqual(started);
  });
});

describe('open set, round 2: a rule that did not load keeps its older findings', () => {
  it("bug_hunt's broken rule: the finding it made last time is carried; the rules that loaded still resolve", () => {
    const s = freshPlugin();
    const p = projectDir('carry-r2-rule-');
    const byRule = (rule: string, file: string, fp: string): SeedFinding => ({ fp: fp.repeat(64), identity: `id-${rule}-${file}`, tool: 'semgrep', rule_id: rule, file });
    const broken = byRule('bugfix-js-empty-catch', 'src/x.js', '8');
    const other = byRule('bugfix-js-off-by-one', 'src/y.js', '9');
    const gone = byRule('bugfix-js-off-by-one', 'src/z.js', '0');
    seedScan(s, { id: 'a', type: 'bugs', project: p, tools_run: full, findings: [broken, other, gone] });
    seedScan(s, {
      id: 'b', type: 'bugs', project: p,
      tools_run: [{ name: 'semgrep', status: 'ok', reason: 'semgrep failed: bugfix-js-empty-catch', failed_rules: [{ rule_id: 'bugfix-js-empty-catch', message: 'Invalid pattern' }] }],
      missing_tools: ['semgrep'],
      findings: [other],
    });
    const set = openSetForProject(s.storage, p);
    expect(byFile(set)).toEqual({
      'src/x.js': { scan_id: 'a', not_remeasured: true },
      'src/y.js': { scan_id: 'b', not_remeasured: undefined },
    });
    expect(set.sources.find((x) => x.scan_id === 'a')?.carried_for).toEqual(['semgrep (rule not loaded: bugfix-js-empty-catch)']);
  });
});

/**
 * The carry must stay linear in the history it walks. Each shape below is a
 * gap that persists in every newer scan, the adversarial case for a walk
 * back through history; the budget is far above what the linear walk needs
 * (tens of ms on these shapes, measured) and far below what the first,
 * quadratic version took (reviewer's measurement: 4.2 s for 200 x 300; 14 s,
 * 15.5 s and 10 s on the 250 x 1000 shapes, measured before this change).
 */
describe('open set, round 2: the carry stays cheap', () => {
  const BUDGET_MS = 2000;
  const scanId = (r: number): string => `row${String(r).padStart(4, '0')}`;

  function timed(s: ReturnType<typeof freshPlugin>, p: string): { set: ReturnType<typeof openSetForProject>; ms: number } {
    const t0 = performance.now();
    const set = openSetForProject(s.storage, p);
    return { set, ms: performance.now() - t0 };
  }

  /** Row 0 is the last full scan and holds a.php's 10 findings; every later row partly parses a.php. */
  function onePartlyParsedFile(rows: number, perRow: number) {
    const s = freshPlugin();
    const p = projectDir('carry-r2-perf-a-');
    for (let r = 0; r < rows; r++) {
      const findings: SeedFinding[] = [];
      for (let i = 0; i < perRow; i++) {
        const inA = i < 10;
        if (inA && r > 0) continue;
        const file = inA ? 'wp/a.php' : `src/f${i}.js`;
        findings.push({ fp: `${r}-${i}`.padEnd(64, 'x'), identity: `id-${i}`, tool: 'semgrep', rule_id: `r${i}`, file, line: i + 1 });
      }
      seedScan(s, {
        id: scanId(r), type: 'sast', project: p,
        tools_run: r === 0 ? full : partialOn('wp/a.php'),
        missing_tools: r === 0 ? [] : ['semgrep'],
        findings,
      });
    }
    return { s, p };
  }

  it.each([
    [200, 300],
    [250, 1000],
  ])('one file partly parsed in every newer scan (%i scans x %i findings)', (rows, perRow) => {
    const { s, p } = onePartlyParsedFile(rows, perRow);
    const { set, ms } = timed(s, p);
    expect(set.findings).toHaveLength(perRow);
    // Row 0 is 249 scans back: past the first version's 200-scan walk limit.
    expect(set.findings.filter((f) => f.not_remeasured === true).map((f) => f.scan_id)).toEqual(Array(10).fill(scanId(0)));
    expect(ms).toBeLessThan(BUDGET_MS);
  }, 180_000);

  it('Semgrep failing beside an ok Bandit in every newer scan (250 x 1000): only Semgrep rows are read', () => {
    const s = freshPlugin();
    const p = projectDir('carry-r2-perf-c-');
    for (let r = 0; r < 250; r++) {
      const findings: SeedFinding[] = [];
      for (let i = 0; i < 1000; i++) {
        const sem = r === 0 && i < 500;
        findings.push({ fp: `${r}-${i}`.padEnd(64, 'y'), identity: `id-${sem ? 's' : 'b'}${i}`, tool: sem ? 'semgrep' : 'bandit', rule_id: `r${i}`, file: `src/f${i}.py`, line: i + 1 });
      }
      seedScan(s, {
        id: scanId(r), type: 'sast', project: p,
        tools_run: r === 0
          ? [{ name: 'semgrep', status: 'ok' }, { name: 'bandit', status: 'ok' }]
          : [{ name: 'semgrep', status: 'failed', reason: 'exit 7' }, { name: 'bandit', status: 'ok' }],
        findings,
      });
    }
    const { set, ms } = timed(s, p);
    expect(set.findings).toHaveLength(1500);
    expect(set.findings.filter((f) => f.not_remeasured === true)).toHaveLength(500);
    expect(ms).toBeLessThan(BUDGET_MS);
  }, 180_000);

  it('Bandit failing in every newer scan while keeping its findings (250 x 1000): older copies are dropped on their keys', () => {
    const s = freshPlugin();
    const p = projectDir('carry-r2-perf-f-');
    for (let r = 0; r < 250; r++) {
      const findings: SeedFinding[] = [];
      for (let i = 0; i < 1000; i++) {
        findings.push({ fp: `${r}-${i}`.padEnd(64, 'w'), identity: `id-b${i}`, tool: 'bandit', rule_id: `B${i % 50}`, file: `src/f${i}.py`, line: i + 1 });
      }
      seedScan(s, {
        id: scanId(r), type: 'sast', project: p,
        tools_run: r === 0
          ? [{ name: 'semgrep', status: 'ok' }, { name: 'bandit', status: 'ok' }]
          : [{ name: 'semgrep', status: 'ok' }, { name: 'bandit', status: 'failed', reason: 'one file did not parse' }],
        findings,
      });
    }
    const { set, ms } = timed(s, p);
    // The newest scan holds every identity: nothing older adds one.
    expect(set.findings).toHaveLength(1000);
    expect(set.findings.every((f) => f.scan_id === scanId(249) && f.not_remeasured === undefined)).toBe(true);
    expect(ms).toBeLessThan(BUDGET_MS);
  }, 180_000);

  it('a finding the newest scan no longer reports, under a gap older than it, is still carried from the scan that had it', () => {
    // The keys-only drop must never drop a finding the open set lacks.
    const s = freshPlugin();
    const p = projectDir('carry-r2-known-');
    const bandit = (i: number): SeedFinding => ({ fp: `${i}`.padEnd(64, 'k'), identity: `id-k${i}`, tool: 'bandit', rule_id: 'B1', file: `src/k${i}.py` });
    const failing: ToolRun[] = [{ name: 'semgrep', status: 'ok' }, { name: 'bandit', status: 'failed', reason: 'x' }];
    seedScan(s, { id: 'a', type: 'sast', project: p, tools_run: [{ name: 'semgrep', status: 'ok' }, { name: 'bandit', status: 'ok' }], findings: [bandit(1), bandit(2), bandit(3)] });
    seedScan(s, { id: 'b', type: 'sast', project: p, tools_run: failing, findings: [bandit(1), bandit(2)] });
    seedScan(s, { id: 'c', type: 'sast', project: p, tools_run: failing, findings: [bandit(1)] });
    const set = openSetForProject(s.storage, p);
    expect(Object.fromEntries(set.findings.map((f) => [f.identity, [f.scan_id, f.not_remeasured ?? false]]))).toEqual({
      'id-k1': ['c', false],
      'id-k2': ['b', true],
      'id-k3': ['a', true],
    });
  });
});
