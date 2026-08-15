/**
 * Shared `snap()` factory for dashboard-renderer tests: one fully populated,
 * valid `DashboardSnapshot`, overridden field-by-field per test via `over`.
 *
 * Lives in its own file (rather than being declared inline in
 * `renderStatus.test.ts`) because `renderHtml.test.ts` (Task 5) imports the
 * same factory — two copies would drift the moment one test file's idea of
 * "a fully populated snapshot" stopped matching the other's.
 *
 * The object literal was checked field-by-field against the committed
 * `DashboardSnapshot` (`../../../src/dashboard/types.ts`) rather than copied
 * blind from the task brief — see the Task 4 report for the diff. It
 * matched exactly; nothing here was changed from the brief's version.
 *
 * The trailing `as DashboardSnapshot` is not a shape workaround: every field
 * below already satisfies its interface. It is needed because
 * `{ ...full, ...over }` — spreading a `Partial<DashboardSnapshot>` after a
 * fully-populated literal — makes TypeScript widen every property of the
 * merged result to `T[K] | undefined` (the type `Partial` gives its
 * properties), even for keys `over` never touches and which keep their
 * original value at runtime. The cast asserts what is already true
 * structurally; it does not hide a mismatch.
 */
import type { DashboardSnapshot } from '../../../src/dashboard/types.js';

export function snap(over: Partial<DashboardSnapshot> = {}): DashboardSnapshot {
  return {
    project_path: '/p',
    generated_at: '2026-08-15T12:00:00.000Z',
    scan: {
      scan_id: 's1',
      scan_type: 'security_full',
      status: 'completed',
      started_at: '2026-08-15T10:00:00.000Z',
      finished_at: '2026-08-15T10:00:47.000Z',
      duration_seconds: 47,
      age_seconds: 7200,
    },
    coverage: {
      level: 'full',
      tools_run: ['semgrep'],
      missing_tools: [],
      omitted_categories: [],
    },
    risk: {
      score: 62,
      band: 'high',
      components: {
        findings: { score: 40, open_findings: 104 },
        cves: { score: 14, active_cves: 5 },
        compliance: { score: 0, policies_missing: 0 },
        baseline: { score: 8, has_active_baseline: true },
      },
      next_action: 'Fix the 3 critical findings first.',
      coverage_caveat: false,
    },
    findings: {
      total: 104,
      by_severity: { critical: 3, high: 12, medium: 31, low: 58, info: 0 },
      by_category: {},
      by_tool: {},
      hotspots: [{ file_path: 'src/auth/session.ts', count: 11 }],
      items: [],
    },
    cves: {
      total: 5,
      by_severity: { critical: 1, high: 4, medium: 0, low: 0, info: 0 },
      items: [],
    },
    deltas: { since_previous: null, since_baseline: null },
    baseline: { active: null, age_days: null },
    suppressions: { active_count: 0, expiring_soon: [] },
    truncation: [],
    ...over,
  } as DashboardSnapshot;
}
