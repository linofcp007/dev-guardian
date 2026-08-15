import { describe, expect, it } from 'vitest';
import { renderStatus } from '../../../src/dashboard/renderStatus.js';
import { snap } from './snapshotFixture.js';

describe('renderStatus', () => {
  it('states what the numbers do NOT contain when coverage is partial', () => {
    // The governing rule. Asserting coverage.level would test the DATA; this
    // asserts the PROMISE — that the consequence reaches the screen. A render
    // that prints "partial coverage" and stops passes the wrong version of
    // this test and fails this one.
    const out = renderStatus(snap({
      coverage: { level: 'partial', tools_run: ['semgrep'],
        missing_tools: ['gitleaks', 'trivy'],
        omitted_categories: ['secrets', 'container and dependency'] },
    }), { color: false });
    expect(out).toMatch(/gitleaks/);
    expect(out).toMatch(/trivy/);
    expect(out).toMatch(/secrets/);
    expect(out).toMatch(/NOT in these numbers/i);
  });

  it('omits the missing-tools line entirely when coverage is full', () => {
    const out = renderStatus(snap(), { color: false });
    expect(out).not.toMatch(/MISSING/);
    expect(out).not.toMatch(/NOT in these numbers/i);
  });

  it('renders an absent delta as an explicit absence, never as zeros', () => {
    // "+0 new  -0 resolved" says nothing changed. The truth is that there is
    // nothing to compare against.
    const out = renderStatus(snap(), { color: false });
    expect(out).not.toMatch(/\+0 new/);
    expect(out).toMatch(/no baseline set/i);
  });

  it('shows both deltas when both references exist', () => {
    const out = renderStatus(snap({
      deltas: {
        since_previous: { from_scan_id: 'a', to_scan_id: 'b', new_count: 2,
          resolved_count: 7, unchanged_count: 95, new_findings: [] },
        since_baseline: { from_scan_id: 'z', to_scan_id: 'b', new_count: 19,
          resolved_count: 31, unchanged_count: 54, new_findings: [] },
      },
      baseline: { active: { baseline_id: 1, scan_id: 'z',
        set_at: '2026-07-12T00:00:00.000Z' }, age_days: 34 },
    }), { color: false });
    expect(out).toMatch(/\+2\b/);
    expect(out).toMatch(/-7\b/);
    expect(out).toMatch(/\+19\b/);
    expect(out).toMatch(/-31\b/);
    expect(out).toMatch(/34d/);
  });

  it('prints the open counts even when every one of them is zero', () => {
    const out = renderStatus(snap({
      findings: { total: 0,
        by_severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        by_category: {}, by_tool: {}, hotspots: [], items: [] },
    }), { color: false });
    expect(out).toMatch(/OPEN/);
    expect(out).toMatch(/\b0\b/);
  });

  it('omits sections that have nothing to say', () => {
    const out = renderStatus(snap(), { color: false });
    expect(out).not.toMatch(/SUPPRESSED/);
  });

  it('tells the reader when it has scanned nothing', () => {
    const out = renderStatus(snap({
      scan: null,
      coverage: { level: 'none', tools_run: [], missing_tools: [], omitted_categories: [] },
    }), { color: false });
    expect(out).toMatch(/dev-guardian scan/);
    expect(out).not.toMatch(/undefined|NaN/);
  });

  it('emits no ANSI escapes when color is off', () => {
    const withColor = renderStatus(snap(), { color: true });
    const without = renderStatus(snap(), { color: false });
    // \u001b is the ESC byte, written as an escape rather than a raw
    // control character so a copy-paste cannot silently lose it.
    expect(without).not.toMatch(/\u001b\[/);
    expect(withColor.replace(/\u001b\[[0-9;]*m/g, '')).toBe(without);
  });

  // Not in the task brief's literal test file — added because the brief's
  // suite never exercises design §6's HOTTEST overflow rule ("if more files
  // have findings, the count of the remainder is appended to the section,
  // never dropped silently"). A renderer that silently truncates to 3 files
  // and says nothing about the rest passes every other test in this file and
  // fails only this one.
  it('reports the remainder when more than 3 files have findings, never dropping it silently', () => {
    const out = renderStatus(snap({
      findings: { total: 15,
        by_severity: { critical: 0, high: 0, medium: 0, low: 15, info: 0 },
        by_category: {}, by_tool: {},
        hotspots: [
          { file_path: 'a.ts', count: 5 },
          { file_path: 'b.ts', count: 4 },
          { file_path: 'c.ts', count: 3 },
          { file_path: 'd.ts', count: 2 },
          { file_path: 'e.ts', count: 1 },
        ],
        items: [] },
    }), { color: false });
    expect(out).toMatch(/a\.ts/);
    expect(out).toMatch(/b\.ts/);
    expect(out).toMatch(/c\.ts/);
    expect(out).not.toMatch(/d\.ts/);
    expect(out).not.toMatch(/e\.ts/);
    expect(out).toMatch(/\+2\b/);
  });

  it('renders every truncation notice it is given', () => {
    const out = renderStatus(snap({
      truncation: [{ what: 'findings', shown: 2000, total: 5310,
        reason: 'cap of 2000' }],
    }), { color: false });
    expect(out).toMatch(/2000/);
    expect(out).toMatch(/5310/);
  });

  it('fits one screen — at most 24 lines for a fully populated snapshot', () => {
    const out = renderStatus(snap({
      coverage: { level: 'partial', tools_run: ['semgrep'],
        missing_tools: ['gitleaks'], omitted_categories: ['secrets'] },
      deltas: {
        since_previous: { from_scan_id: 'a', to_scan_id: 'b', new_count: 2,
          resolved_count: 7, unchanged_count: 95, new_findings: [] },
        since_baseline: { from_scan_id: 'z', to_scan_id: 'b', new_count: 19,
          resolved_count: 31, unchanged_count: 54, new_findings: [] },
      },
      baseline: { active: { baseline_id: 1, scan_id: 'z',
        set_at: '2026-07-12T00:00:00.000Z' }, age_days: 34 },
      suppressions: { active_count: 6,
        expiring_soon: [{ fingerprint: 'f', reason: 'r',
          expires_at: '2026-08-18T00:00:00.000Z' }] },
      truncation: [{ what: 'findings', shown: 2000, total: 5310, reason: 'cap' }],
    }), { color: false });
    expect(out.split('\n').length).toBeLessThanOrEqual(24);
  });
});
