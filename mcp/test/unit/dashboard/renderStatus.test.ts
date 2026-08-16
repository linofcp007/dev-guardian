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

  // Not in the task brief's literal test file — added because coverage data
  // showed design §2's corollary ("a score computed over a partial scan is
  // presented WITH its coverage caveat attached, never as a bare number") had
  // no test at all: nothing in the brief's suite sets coverage_caveat: true.
  // The regex spans one line on purpose (`.` does not match `\n`), so a
  // renderer that prints the caveat on a separate line — attached to the
  // screen, but not to the score — fails this test too.
  it('flags the risk score itself when it was computed over partial coverage', () => {
    const out = renderStatus(snap({
      coverage: { level: 'partial', tools_run: ['semgrep'],
        missing_tools: ['gitleaks', 'trivy'],
        omitted_categories: ['secrets', 'container and dependency'] },
      risk: { score: 62, band: 'high',
        components: { findings: { score: 40, open_findings: 104 },
          cves: { score: 14, active_cves: 5 },
          compliance: { score: 0, policies_missing: 0 },
          baseline: { score: 8, has_active_baseline: true } },
        next_action: 'Fix the 3 critical findings first.', coverage_caveat: true },
    }), { color: false });
    expect(out).toMatch(/RISK.*partial coverage — 2 scanners missing/);
  });

  // fix-round-3, Important 2 (coordinator review): Task 3 folded the
  // CVE-source gap into coverage.level/omitted_categories, so a project can
  // be 'partial' with missing_tools genuinely EMPTY (a secrets-only or
  // SAST-only project, or a new project whose first scan wasn't
  // deps-flavoured — no scanner failed, there is simply no deps/security_full
  // scan in this project's history to source CVE data from). Before this
  // fix, the RISK line's caveat unconditionally counted missing_tools,
  // producing the self-contradicting "⚠ partial coverage — 0 scanners
  // missing" — a warning that denies itself. No fixture anywhere paired
  // empty missing_tools with a non-empty omitted_categories, which is why
  // nothing caught it.
  it('names the omitted categories, not a self-contradicting "0 scanners missing", when the coverage gap has no missing tool', () => {
    const out = renderStatus(snap({
      coverage: { level: 'partial', tools_run: ['gitleaks'],
        missing_tools: [], omitted_categories: ['container and dependency'] },
      risk: { score: 13, band: 'low',
        components: { findings: { score: 5, open_findings: 2 },
          cves: { score: 0, active_cves: 0 },
          compliance: { score: 0, policies_missing: 0 },
          baseline: { score: 8, has_active_baseline: false } },
        next_action: 'Run a deps scan to measure CVE exposure.', coverage_caveat: true },
    }), { color: false });
    expect(out).not.toMatch(/0 scanners? missing/);
    expect(out).toMatch(/RISK.*partial coverage.*container and dependency/);
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

  // fix-round-3, Minor 4 (coordinator review): OPEN's four severity columns
  // used to omit `info` while `findings.total` counted it — a reader seeing
  // "2 crit 2 high 1 med 2 low" beside a total of 8 could not reconcile the
  // arithmetic (2+2+1+2 = 7, not 8). The HTML view never had this gap, since
  // severityBar always shows info. This is the OPEN line's own arithmetic
  // check: every column, plus info, must sum to the printed total.
  it("OPEN's severity columns sum to its own printed total, including info", () => {
    const out = renderStatus(snap({
      findings: { total: 8,
        by_severity: { critical: 2, high: 2, medium: 1, low: 2, info: 1 },
        by_category: {}, by_tool: {}, hotspots: [], items: [] },
    }), { color: false });
    const line = out.split('\n').find((l) => l.includes('OPEN'));
    expect(line).toBeTruthy();
    const text = line ?? '';
    // Each column read individually by its own label, not by position — this
    // is what proves the five displayed severities really do add up to the
    // trailing total, not just that all six numbers appear somewhere on the
    // line in some order.
    const crit = Number(/(\d+) crit/.exec(text)?.[1] ?? NaN);
    const high = Number(/(\d+) high/.exec(text)?.[1] ?? NaN);
    const med = Number(/(\d+) med/.exec(text)?.[1] ?? NaN);
    const low = Number(/(\d+) low/.exec(text)?.[1] ?? NaN);
    const info = Number(/(\d+) info/.exec(text)?.[1] ?? NaN);
    const trailingTotal = Number(/(\d+)\s*$/.exec(text.trimEnd())?.[1] ?? NaN);
    expect({ crit, high, med, low, info, trailingTotal }).toEqual(
      { crit: 2, high: 2, med: 1, low: 2, info: 1, trailingTotal: 8 },
    );
    expect(crit + high + med + low + info).toBe(trailingTotal);
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

  // Not in the task brief's literal test file — added because coverage data
  // showed the >=60s branch of the header's duration formatting was never
  // exercised (the fixture's default scan runs 47s). A renderer that always
  // prints raw seconds, or that divides but drops the remainder, both fail
  // this: the assertion requires "2m" AND "5s" together.
  it('formats a scan duration of a minute or more as minutes and seconds', () => {
    const out = renderStatus(snap({
      scan: { scan_id: 's1', scan_type: 'security_full', status: 'completed',
        started_at: '2026-08-15T10:00:00.000Z', finished_at: '2026-08-15T10:02:05.000Z',
        duration_seconds: 125, age_seconds: 7200 },
    }), { color: false });
    expect(out).toMatch(/2m 5s/);
  });

  // Not in the task brief's literal test file — added because coverage data
  // showed the header's "days ago" tier (a scan >= 24h old) was never
  // exercised; every other fixture uses the 2h-old default.
  it('formats a scan more than a day old in days, not hours', () => {
    const out = renderStatus(snap({
      scan: { scan_id: 's1', scan_type: 'security_full', status: 'completed',
        started_at: '2026-08-12T10:00:00.000Z', finished_at: '2026-08-12T10:00:47.000Z',
        duration_seconds: 47, age_seconds: 259_200 }, // 3 days
    }), { color: false });
    expect(out).toMatch(/3d ago/);
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
