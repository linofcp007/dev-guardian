/**
 * The open set against both shapes a `security_full` row has had, and the
 * review findings of Task 8 fix round 1:
 *
 *   - script-era rows (`scripts/scan/full-security-scan.sh`): ONE row, its
 *     own findings, bookkeeping named after scanners (semgrep, gitleaks,
 *     trivy, trivy-dockerfile, bandit). It ran `semgrep --config=auto`,
 *     `gitleaks detect`, `trivy fs --scanners vuln,license` and
 *     `trivy config Dockerfile` — a subset of each dedicated tool's rule
 *     sources;
 *   - orchestrated rows (Task 9): the parent keeps the merged findings and
 *     `meta.child_scans`; every child is a real sast/secrets/deps/iac scan
 *     with `meta.parent_scan_id`.
 */

import { afterAll, describe, expect, it } from 'vitest';
import { buildSnapshot } from '../../../src/dashboard/snapshot.js';
import { describeOpenSet, latestStateScan, openSetForProject } from '../../../src/history/openSet.js';
import type { ToolRun } from '../../../src/types.js';
import { cleanupTempDirs } from '../../helpers/tempDir.js';
import { freshPlugin, seedOrchestratedRun, seedScan, type Seeded } from '../../helpers/historySeed.js';

afterAll(cleanupTempDirs);

const P = '/project';

const SCRIPT_OK: ToolRun[] = [
  { name: 'semgrep', status: 'ok' },
  { name: 'gitleaks', status: 'ok' },
  { name: 'trivy', status: 'ok' },
];
const SCRIPT_BLIND = {
  tools_run: [
    { name: 'semgrep', status: 'skipped', reason: 'not_installed' },
    { name: 'gitleaks', status: 'skipped', reason: 'not_installed' },
    { name: 'trivy', status: 'skipped', reason: 'not_installed' },
  ] satisfies ToolRun[],
  missing_tools: ['semgrep', 'gitleaks', 'trivy'],
};

const ids = (set: ReturnType<typeof openSetForProject>): string[] => set.findings.map((f) => f.fingerprint).sort();
const fp = (c: string): string => c.repeat(64);

/** Task 9's shape, in this file's project — see `seedOrchestratedRun`. */
function orchestrated(s: Seeded, id: string, children: Parameters<typeof seedOrchestratedRun>[3]): void {
  seedOrchestratedRun(s, id, P, children);
}

describe('a blind security_full is never a source (review item 1)', () => {
  it('script-era: a newer run where every scanner was missing leaves the older run as the source', () => {
    const s = freshPlugin();
    const good = seedScan(s, {
      id: 'good', type: 'security_full', project: P, tools_run: SCRIPT_OK,
      findings: [
        { fp: fp('1'), tool: 'semgrep' },
        { fp: fp('2'), tool: 'gitleaks', subcategory: 'secret' },
        { fp: fp('3'), tool: 'trivy', subcategory: 'cve' },
      ],
    });
    const blind = seedScan(s, { id: 'blind', type: 'security_full', project: P, ...SCRIPT_BLIND });

    const set = openSetForProject(s.storage, P);
    expect(ids(set)).toEqual([fp('1'), fp('2'), fp('3')]);
    expect(set.sources.map((x) => x.scan_id)).not.toContain(blind);
    expect(new Set(set.sources.map((x) => x.scan_id))).toEqual(new Set([good]));
    expect(set.newestSource?.scan_id).toBe(good);
    expect(set.skipped.count).toBe(1);
    expect(set.skipped.newest[0]).toMatchObject({ scan_id: blind, reason: 'coverage_none' });
    expect(set.skipped.newest[0]?.slots.slice().sort()).toEqual(['deps', 'sast', 'secrets']);

    // The dashboard must not read the blind run as "everything was fixed".
    const snap = buildSnapshot(s.storage, P, Date.parse('2026-06-01T00:00:00.000Z'));
    expect(snap.findings.total).toBe(3);
    expect(snap.deltas.since_previous?.resolved_count ?? 0).toBe(0);
  });

  it('script-era: a project whose only scan is blind reads coverage none, with no source', () => {
    const s = freshPlugin();
    seedScan(s, { id: 'blind', type: 'security_full', project: P, ...SCRIPT_BLIND });
    const set = openSetForProject(s.storage, P);
    expect(set.sources).toEqual([]);
    expect(set.coverage).toBe('none');
    expect(set.newestSource).toBeNull();
  });

  it('orchestrated: a blind parent and its blind children are no source either', () => {
    const s = freshPlugin();
    orchestrated(s, 'full', { sast: { blind: true }, secrets: { blind: true }, deps: { blind: true }, iac: { blind: true } });
    const set = openSetForProject(s.storage, P);
    expect(set.sources).toEqual([]);
    expect(set.coverage).toBe('none');
  });
});

describe('script-era security_full findings are routed to the scan type that re-evaluates them (review item 2a)', () => {
  function legacyWithDockerfile(s: Seeded): void {
    seedScan(s, {
      id: 'legacy', type: 'security_full', project: P,
      tools_run: [...SCRIPT_OK, { name: 'trivy-dockerfile', status: 'ok' }],
      findings: [
        { fp: fp('d'), tool: 'trivy', subcategory: 'dockerfile', rule_id: 'DS002', file: 'Dockerfile' },
        { fp: fp('c'), tool: 'trivy', subcategory: 'cve', rule_id: 'CVE-2026-1', file: 'package-lock.json' },
        { fp: fp('l'), tool: 'trivy', category: 'license', subcategory: 'gpl-3.0', file: 'package-lock.json' },
      ],
    });
  }

  it('a newer scan_deps (vuln + license) supersedes the CVEs and licenses, not the Dockerfile misconfigurations', () => {
    const s = freshPlugin();
    legacyWithDockerfile(s);
    seedScan(s, { id: 'deps', type: 'deps', project: P, tools_run: [{ name: 'trivy', status: 'ok' }] });
    expect(ids(openSetForProject(s.storage, P))).toEqual([fp('d')]);
  });

  it("a newer scan_containers, whose Dockerfile pass re-runs them, supersedes the misconfigurations", () => {
    const s = freshPlugin();
    legacyWithDockerfile(s);
    seedScan(s, { id: 'containers', type: 'containers', project: P, tools_run: [{ name: 'trivy-dockerfile', status: 'ok' }] });
    expect(ids(openSetForProject(s.storage, P))).toEqual([fp('c'), fp('l')]);
  });
});

describe('a script-era security_full never supersedes a dedicated scan (review item 2b)', () => {
  it("a newer script-era run does not drop scan_sast's findings from rule sources it never ran", () => {
    const s = freshPlugin();
    seedScan(s, { id: 'sast', type: 'sast', project: P, findings: [{ fp: fp('p'), tool: 'semgrep', rule_id: 'project.local-rule' }] });
    seedScan(s, { id: 'legacy', type: 'security_full', project: P, tools_run: SCRIPT_OK, findings: [{ fp: fp('a'), tool: 'semgrep', rule_id: 'registry.rule' }] });
    const set = openSetForProject(s.storage, P);
    expect(ids(set)).toEqual([fp('a'), fp('p')]);
    expect(set.sources.filter((x) => x.slot === 'sast').map((x) => x.scan_id).sort()).toEqual(['legacy', 'sast']);
  });

  it('a newer scan_sast supersedes an older script-era run', () => {
    const s = freshPlugin();
    seedScan(s, { id: 'legacy', type: 'security_full', project: P, tools_run: SCRIPT_OK, findings: [{ fp: fp('a'), tool: 'semgrep', rule_id: 'registry.rule' }] });
    seedScan(s, { id: 'sast', type: 'sast', project: P, findings: [{ fp: fp('p'), tool: 'semgrep', rule_id: 'project.local-rule' }] });
    expect(ids(openSetForProject(s.storage, P))).toEqual([fp('p')]);
  });

  it("an orchestrated security_full's sast child supersedes an older scan_sast, and the parent is never counted twice", () => {
    const s = freshPlugin();
    seedScan(s, { id: 'old-sast', type: 'sast', project: P, findings: [{ fp: fp('x'), tool: 'semgrep' }] });
    orchestrated(s, 'full', {
      sast: { findings: [{ fp: fp('z'), tool: 'semgrep', identity: 'I-z' }] },
      secrets: { findings: [{ fp: fp('s'), tool: 'gitleaks', identity: 'I-s' }] },
    });
    const set = openSetForProject(s.storage, P);
    expect(ids(set)).toEqual([fp('s'), fp('z')]);
    expect(set.sources.map((x) => x.scan_id)).not.toContain('full');
    expect(set.sources.find((x) => x.slot === 'sast')?.scan_id).toBe('full-sast');
  });
});

describe('an orchestrated run is "the latest scan" as a whole, never one arbitrary child', () => {
  it('latestStateScan and the open set name the parent, not whichever child started last', () => {
    const s = freshPlugin();
    orchestrated(s, 'run1', { sast: { findings: [{ fp: fp('a'), tool: 'semgrep', identity: 'I-a' }] } });
    orchestrated(s, 'run2', { sast: { findings: [{ fp: fp('b'), tool: 'semgrep', identity: 'I-b' }] } });

    expect(latestStateScan(s.storage, P).scan?.scan_id).toBe('run2');
    // An explicit type still means that type.
    expect(latestStateScan(s.storage, P, 'sast').scan?.scan_id).toBe('run2-sast');
    const set = openSetForProject(s.storage, P);
    expect(set.newest?.scan_id).toBe('run2');
    expect(set.newestSource?.scan_id).toBe('run2');
    expect(ids(set)).toEqual([fp('b')]);

    const snap = buildSnapshot(s.storage, P, Date.parse('2026-06-01T00:00:00.000Z'));
    expect(snap.scan?.scan_id).toBe('run2');
    expect(snap.deltas.since_previous).toMatchObject({ from_scan_id: 'run1', to_scan_id: 'run2', new_count: 1, resolved_count: 1 });
  });
});

describe('an orchestrated parent that measured nothing is never "the latest scan" (final review M1)', () => {
  // Semgrep and gitleaks absent, Trivy absent, no IaC: the iac child skipped
  // everything with nothing to scan — coverage `full` — so the search stops
  // on it, maps it to its parent, and the parent's own bookkeeping (every
  // scanner skipped, three missing) is coverage `none`. set_baseline and
  // report_export defaulted to that parent.
  const BLIND_RUN = {
    sast: { blind: true },
    secrets: { blind: true },
    deps: { blind: true },
    iac: { runs: [{ name: 'trivy-config', status: 'skipped', reason: 'nothing to scan' }] satisfies ToolRun[], missing: [] },
  };

  it('latestStateScan skips it, with every child, and returns the older usable scan', () => {
    const s = freshPlugin();
    seedScan(s, { id: 'good-sast', type: 'sast', project: P, findings: [{ fp: fp('g'), tool: 'semgrep' }] });
    orchestrated(s, 'blind-run', BLIND_RUN);

    const latest = latestStateScan(s.storage, P);
    expect(latest.scan?.scan_id).toBe('good-sast');
    expect(latest.coverage).toBe('full');
    expect(latest.hits.map((h) => h.scan.scan_id)).toContain('blind-run');
  });

  it('with nothing usable below it, the answer is no scan — never the blind parent', () => {
    const s = freshPlugin();
    orchestrated(s, 'blind-run', BLIND_RUN);
    expect(latestStateScan(s.storage, P).scan).toBeNull();
  });

  it('a parent that measured something is still the answer', () => {
    const s = freshPlugin();
    seedScan(s, { id: 'good-sast', type: 'sast', project: P });
    orchestrated(s, 'partial-run', { ...BLIND_RUN, sast: {} });
    const latest = latestStateScan(s.storage, P);
    expect(latest.scan?.scan_id).toBe('partial-run');
    expect(latest.coverage).toBe('partial');
  });
});

describe('skipped scans are summarised, never listed without bound (review item 3)', () => {
  it('counts every skipped scan and returns only the newest few', () => {
    const s = freshPlugin();
    seedScan(s, { id: 'good', type: 'secrets', project: P, tools_run: [{ name: 'gitleaks', status: 'ok' }], findings: [{ tool: 'gitleaks' }] });
    for (let i = 0; i < 40; i++) {
      seedScan(s, {
        id: `blind-${i}`, type: 'secrets', project: P,
        tools_run: [{ name: 'gitleaks', status: 'skipped', reason: 'not_installed' }], missing_tools: ['gitleaks'],
      });
    }
    const set = openSetForProject(s.storage, P);
    expect(set.findings).toHaveLength(1);
    expect(set.skipped.count).toBe(40);
    expect(set.skipped.by_reason).toEqual({ coverage_none: 40 });
    expect(set.skipped.newest.map((x) => x.scan_id)).toEqual(['blind-39', 'blind-38', 'blind-37', 'blind-36', 'blind-35']);
    expect(JSON.stringify(describeOpenSet(set)).length).toBeLessThan(4000);
  });
});
