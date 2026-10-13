/**
 * Review 8, findings 2, 3 and 18 — how the gate judges the gaps a scan names
 * per file, what each gap is as data, and where SARIF URIs point.
 *
 *   - a per-file Semgrep `Timeout` is accepted by the project's committed
 *     `.guardian/scan.yml` (`semgrep.accept_timeouts`), never by
 *     `--accept-partial-parse`;
 *   - a file at a path too long for Windows is never accepted;
 *   - a run whose gap is not only its files (`unscanned`, rules that did not
 *     load) is never cleared by naming files;
 *   - every gap carries a kind and a remedy (`coverage_gap_details`).
 */
import { describe, expect, it } from 'vitest';
import { evaluateGate, remedyFor, type GateInput } from '../../../src/ci/gate.js';
import { renderSarif } from '../../../src/ci/report.js';
import { CI_EXIT, GAP_KINDS, type ScanStepResult } from '../../../src/ci/types.js';
import type { Finding, ToolRun } from '../../../src/types.js';

const F = 'src/huge.js';

function input(over: Partial<GateInput> = {}): GateInput {
  return { findings: [], baseline: null, failOn: 'high', steps: [], droppedBaselineEntries: 0, ...over };
}

function semgrepStep(refs: Array<{ file: string; type: string }>, run: Partial<ToolRun> = {}): ScanStepResult {
  return {
    tool: 'security_scan_full',
    ran: true,
    tools_run: [{ name: 'semgrep', status: 'ok', reason: 'partial', ...run }],
    missing_tools: ['semgrep'],
    partial_parses: { semgrep: refs },
  };
}

describe('a per-file Timeout: accepted by the committed .guardian/scan.yml, nothing else', () => {
  it('not listed: exit 2, kind file_timeout, the remedy names scan.yml', () => {
    const v = evaluateGate(input({ steps: [semgrepStep([{ file: F, type: 'Timeout' }])] }));
    expect(v.exitCode).toBe(CI_EXIT.INCOMPLETE_SCAN);
    expect(v.coverageGaps[0]).toMatch(/not accepted: Timeout on src\/huge\.js .*\.guardian\/scan\.yml semgrep\.accept_timeouts/);
    expect(v.coverageGapDetails[0]).toMatchObject({ tool: 'semgrep', kind: 'file_timeout', gating: true });
    expect(v.coverageGapDetails[0]?.remedy).toMatch(/\.guardian\/scan\.yml/);
  });

  it('listed in accept_timeouts: exit 0, an accepted line naming its source, coverage still partial', () => {
    const v = evaluateGate(input({ steps: [semgrepStep([{ file: F, type: 'Timeout' }])], acceptedTimeouts: [`./${F}`] }));
    expect(v.exitCode).toBe(CI_EXIT.PASS);
    expect(v.coverage).toBe('partial');
    expect(v.coverageGaps).toEqual([]);
    expect(v.acceptedGaps).toEqual([`security_scan_full: semgrep timed out on ${F} — accepted (.guardian/scan.yml semgrep.accept_timeouts)`]);
    expect(v.coverageGapDetails).toEqual([expect.objectContaining({ kind: 'file_timeout', gating: false })]);
  });

  it('--accept-partial-parse never accepts a Timeout, and accept_timeouts never a parse error', () => {
    expect(evaluateGate(input({ steps: [semgrepStep([{ file: F, type: 'Timeout' }])], acceptedPartialParses: [F] })).exitCode)
      .toBe(CI_EXIT.INCOMPLETE_SCAN);
    expect(evaluateGate(input({ steps: [semgrepStep([{ file: F, type: 'PartialParsing' }])], acceptedTimeouts: [F] })).exitCode)
      .toBe(CI_EXIT.INCOMPLETE_SCAN);
  });

  it('a parse error and a timeout, each accepted by its own list: exit 0, two accepted lines', () => {
    const v = evaluateGate(input({
      steps: [semgrepStep([{ file: 'a.php', type: 'PartialParsing' }, { file: F, type: 'Timeout' }])],
      acceptedPartialParses: ['a.php'],
      acceptedTimeouts: [F],
    }));
    expect(v.exitCode).toBe(CI_EXIT.PASS);
    expect(v.acceptedGaps).toHaveLength(2);
  });
});

describe('a gap no acceptance clears', () => {
  it('a file at a path too long for Windows: exit 2, kind path_too_long, whatever is accepted', () => {
    const v = evaluateGate(input({
      steps: [semgrepStep([{ file: F, type: 'Path too long' }])],
      acceptedPartialParses: [F],
      acceptedTimeouts: [F],
    }));
    expect(v.exitCode).toBe(CI_EXIT.INCOMPLETE_SCAN);
    expect(v.coverageGapDetails[0]).toMatchObject({ kind: 'path_too_long', gating: true });
    expect(v.coverageGapDetails[0]?.remedy).toMatch(/LongPathsEnabled/);
  });

  it('a run that also missed files over the size limit (unscanned), or rules that did not load: never cleared by naming files', () => {
    for (const run of [{ unscanned: { oversized: 1 } }, { failed_rules: [{ rule_id: 'r', message: 'bad' }] }] as Array<Partial<ToolRun>>) {
      const v = evaluateGate(input({ steps: [semgrepStep([{ file: F, type: 'PartialParsing' }], run)], acceptedPartialParses: [F] }));
      expect(v.exitCode, JSON.stringify(run)).toBe(CI_EXIT.INCOMPLETE_SCAN);
      expect(v.acceptedGaps).toEqual([]);
    }
  });
});

describe('every gap as data', () => {
  it('a kind and a non-empty remedy for every kind; only missing_tool says install', () => {
    for (const kind of GAP_KINDS) {
      const remedy = remedyFor(kind, 'semgrep', 'x');
      expect(remedy.length, kind).toBeGreaterThan(10);
      if (kind === 'missing_tool') expect(remedy).toMatch(/^Install semgrep \(`pipx install semgrep`\)/);
      else expect(remedy, kind).not.toMatch(/^Install/);
    }
  });

  it('kinds from what a step says: not installed, no lockfile, a refused step, a failed run, a shallow clone', () => {
    const steps: ScanStepResult[] = [
      { tool: 'security_scan_full', ran: true, tools_run: [], missing_tools: ['bandit'] },
      { tool: 'scan_deps', ran: true, tools_run: [{ name: 'trivy', status: 'skipped', reason: 'no_supported_manifest' }], missing_tools: ['trivy'] },
      { tool: 'map_attack_surface', ran: false, reason: 'missing_scanner: semgrep is not installed', tools_run: [], missing_tools: [] },
      { tool: 'scan_iac', ran: true, tools_run: [{ name: 'zizmor', status: 'failed', reason: 'exit 2' }], missing_tools: [] },
      {
        tool: 'scan_secrets',
        ran: true,
        tools_run: [{ name: 'gitleaks', status: 'ok', reason: 'history truncated at abc — a shallow clone' }],
        missing_tools: ['gitleaks'],
      },
    ];
    const v = evaluateGate(input({ steps }));
    expect(v.coverageGapDetails.map((d) => [d.tool, d.kind])).toEqual([
      ['bandit', 'missing_tool'],
      ['trivy', 'no_lockfile'],
      ['map_attack_surface', 'missing_tool'],
      ['zizmor', 'scanner_failed'],
      ['gitleaks', 'other'],
    ]);
    expect(v.coverageGapDetails[4]?.remedy).toMatch(/git fetch --unshallow/);
    expect(v.coverageGapDetails.every((d) => d.gating)).toBe(true);
  });

  it('a dropped baseline entry is a gap line that never gates', () => {
    const v = evaluateGate(input({ droppedBaselineEntries: 2 }));
    expect(v.exitCode).toBe(CI_EXIT.PASS);
    expect(v.coverageGapDetails).toEqual([expect.objectContaining({ tool: 'baseline', kind: 'other', gating: false })]);
  });
});

describe('SARIF URIs resolve against the repository root (finding 18)', () => {
  const f: Finding = {
    fingerprint: 'fp',
    tool: 'semgrep',
    severity: 'high',
    category: 'security',
    title: 't',
    rule_id: 'r',
    file_path: 'src/app.js',
    line_start: 1,
    fix_available: false,
  } as Finding;
  const uriOf = (prefix: string | undefined): string => {
    const doc = JSON.parse(renderSarif(evaluateGate(input({ findings: [f] })), '/repo/packages/api', prefix === undefined ? {} : { repoPrefix: prefix })) as {
      runs: Array<{ results: Array<{ locations: Array<{ physicalLocation: { artifactLocation: { uri: string } } }> }> }>;
    };
    return doc.runs[0]?.results[0]?.locations[0]?.physicalLocation.artifactLocation.uri ?? '';
  };

  it('a project below the root has its place in the repository put in front', () => {
    expect(uriOf('packages/api/')).toBe('packages/api/src/app.js');
    expect(uriOf('packages\\api')).toBe('packages/api/src/app.js');
  });

  it('at the root, or with nothing usable, the URI is project-relative as before', () => {
    expect(uriOf(undefined)).toBe('src/app.js');
    expect(uriOf('')).toBe('src/app.js');
    expect(uriOf('../escape/')).toBe('src/app.js');
  });
});
