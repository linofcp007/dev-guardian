/**
 * The JSON verdict `scan --format json` prints is a CONTRACT with
 * dev-spec-driven: its finish gate (`finish --run`, `/spec-finish`) runs the
 * scan and parses the verdict. A key renamed here degraded there to
 * `parsed: false` and lost the list of blocking findings, with nothing
 * failing on either side — the two plugins' tests each used their own fake
 * of the other (review 8, C12).
 *
 * This file freezes what dev-spec-driven reads:
 *
 *   - since 1.29 — `exit_code` (0 pass · 1 blocked · 2 incomplete · 3
 *     config/usage), `coverage`, `coverage_gaps` (a STRING array),
 *     `new_findings`, `blocking_findings[].{file_path, line_start, severity,
 *     rule_id, title, tool}` (`tool` labels a finding with neither rule nor
 *     title), `baseline_absent`, `accepted_gaps`;
 *   - since 3.3.0 (dev-spec-driven 1.30 reads them when present) —
 *     `tool_version`, `coverage_gap_details[].{tool, kind, detail, remedy,
 *     gating}` (one per `coverage_gaps` line, same order, then the non-gating
 *     notes), `baseline_status`, and `--compact` (`new_findings` cut to the
 *     blocking ones, with `new_findings_count` and `new_findings_by_severity`).
 *
 * Checked against dev-spec-driven 1.30.0's reader, `guardianRecord` in its
 * `mcp/lib/engine/guardian.js`: it reads no key this file does not freeze.
 * Keys are only ever added. Change one of these and this test fails before
 * dev-spec-driven's gate quietly stops reading the verdict.
 */
import { describe, expect, it } from 'vitest';
import { evaluateGate } from '../../../src/ci/gate.js';
import { renderJson } from '../../../src/ci/report.js';
import { CI_EXIT, GAP_KINDS, type ScanStepResult } from '../../../src/ci/types.js';
import { SEVERITIES, type Finding } from '../../../src/types.js';

/** The GapKind set of the contract (scratch CONTRACT.md for dev-spec-driven 1.30 ↔ dev-guardian 3.3.0). */
const CONTRACT_GAP_KINDS = [
  'missing_tool',
  'no_lockfile',
  'partial_parse',
  'file_timeout',
  'taint_timeout',
  'path_too_long',
  'scanner_failed',
  'skipped',
  'other',
];

function finding(over: Partial<Finding> = {}): Finding {
  return {
    fingerprint: 'fp-1',
    tool: 'semgrep',
    category: 'security',
    severity: 'high',
    title: 'SQL built by interpolation',
    rule_id: 'web-js-sql-template',
    file_path: 'src/checkout.js',
    line_start: 4,
    ...over,
  } as Finding;
}

function verdictOf(): ReturnType<typeof evaluateGate> {
  const steps: ScanStepResult[] = [
    {
      tool: 'security_scan_full',
      ran: true,
      tools_run: [
        { name: 'semgrep', status: 'ok', partially_parsed: [{ file: 'a.js', type: 'Fixpoint timeout', message: 'x' }] },
        { name: 'trivy', status: 'skipped', reason: 'no_supported_manifest' },
      ],
      missing_tools: ['semgrep', 'trivy'],
      partial_parses: { semgrep: [{ file: 'a.js', type: 'Fixpoint timeout' }] },
    },
    { tool: 'map_attack_surface', ran: false, reason: 'missing_scanner: semgrep is not installed', tools_run: [], missing_tools: [] },
  ];
  return evaluateGate({
    findings: [finding(), finding({ fingerprint: 'fp-2', severity: 'medium', title: 'old debt', file_path: 'src/legacy.js' })],
    baseline: null,
    failOn: 'high',
    steps,
    droppedBaselineEntries: 0,
  });
}

describe('the JSON verdict dev-spec-driven parses (contract)', () => {
  const json = JSON.parse(renderJson(verdictOf(), { toolVersion: '3.3.0' })) as Record<string, unknown>;

  it('keeps every key dev-spec-driven 1.29 reads, with its type', () => {
    expect(json['exit_code']).toBe(CI_EXIT.GATE_FAILED);
    expect([0, 1, 2, 3]).toContain(json['exit_code']);
    expect(['full', 'partial', 'none']).toContain(json['coverage']);
    expect(Array.isArray(json['coverage_gaps'])).toBe(true);
    for (const gap of json['coverage_gaps'] as unknown[]) expect(typeof gap).toBe('string');
    expect(Array.isArray(json['new_findings'])).toBe(true);
    expect(typeof json['baseline_absent']).toBe('boolean');
    expect(Array.isArray(json['accepted_gaps'])).toBe(true);
    const blocking = json['blocking_findings'] as Array<Record<string, unknown>>;
    expect(blocking).toHaveLength(1);
    expect(blocking[0]).toMatchObject({
      file_path: 'src/checkout.js',
      line_start: 4,
      severity: 'high',
      rule_id: 'web-js-sql-template',
      title: 'SQL built by interpolation',
      tool: 'semgrep',
    });
  });

  it('carries tool_version and baseline_status (present | absent)', () => {
    expect(json['tool_version']).toBe('3.3.0');
    expect(json['baseline_status']).toBe('absent');
    const present = JSON.parse(
      renderJson(evaluateGate({ findings: [], baseline: { version: 1, generated_at: 'x', entries: [] }, failOn: 'high', steps: [], droppedBaselineEntries: 0 })),
    ) as Record<string, unknown>;
    expect(present['baseline_status']).toBe('present');
    // A caller that cannot tell its version still gets the key.
    expect(typeof present['tool_version']).toBe('string');
  });

  it('coverage_gap_details: one per coverage_gaps line in order, then the non-gating notes, each fully shaped', () => {
    const gaps = json['coverage_gaps'] as string[];
    const details = json['coverage_gap_details'] as Array<Record<string, unknown>>;
    expect(details.length).toBeGreaterThanOrEqual(gaps.length);
    gaps.forEach((gap, i) => expect(details[i]?.['detail']).toBe(gap));
    for (const d of details) {
      expect(Object.keys(d).sort()).toEqual(['detail', 'gating', 'kind', 'remedy', 'tool']);
      expect(typeof d['tool']).toBe('string');
      expect(CONTRACT_GAP_KINDS).toContain(d['kind']);
      expect(typeof d['remedy']).toBe('string');
      expect((d['remedy'] as string).length).toBeGreaterThan(0);
      expect(typeof d['gating']).toBe('boolean');
    }
    // The notes are not in coverage_gaps and never gate.
    for (const d of details.slice(gaps.length)) expect(d['gating']).toBe(false);
    const kinds = details.map((d) => d['kind']);
    expect(kinds).toContain('no_lockfile');
    expect(kinds).toContain('missing_tool');
    expect(kinds).toContain('taint_timeout');
    // Only a missing tool is "install something".
    for (const d of details) {
      if (d['kind'] !== 'missing_tool') expect(d['remedy']).not.toMatch(/^Install /);
    }
  });

  it('the GapKind set is exactly the contract’s', () => {
    expect([...GAP_KINDS].sort()).toEqual([...CONTRACT_GAP_KINDS].sort());
  });

  it('--compact: the same keys, new_findings cut to the blocking ones, with the full count and per-severity counts', () => {
    const compact = JSON.parse(renderJson(verdictOf(), { toolVersion: '3.3.0', compact: true })) as Record<string, unknown>;
    expect(Object.keys(compact).sort()).toEqual(Object.keys(json).sort());
    expect(compact['new_findings']).toEqual(compact['blocking_findings']);
    expect(compact['new_findings_count']).toBe(2);
    expect(json['new_findings_count']).toBe(2);
    const bySeverity = compact['new_findings_by_severity'] as Record<string, number>;
    expect(Object.keys(bySeverity).sort()).toEqual([...SEVERITIES].sort());
    expect(bySeverity['high']).toBe(1);
    expect(bySeverity['medium']).toBe(1);
    expect(compact['compact']).toBe(true);
    expect(json['compact']).toBe(false);
  });
});
