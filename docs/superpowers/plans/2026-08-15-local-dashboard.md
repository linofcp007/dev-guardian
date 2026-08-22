# Local Dashboard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Two read-only views — `dev-guardian status` (one terminal screen) and `dev-guardian dashboard` (a self-contained HTML file) — over the SQLite state dev-guardian already persists for the project you are standing in.

> **Checkbox audit — 2026-08-22.** These boxes were ticked retrospectively, by
> reconciling every step against the shipped code, its tests and `git log`. They
> were **not** ticked during execution, so they are an audit of the result, not a
> live record of the run. Steps whose only product is an observation ("run the
> test, expected: FAIL", "RED first", "commit with this subject") cannot be
> verified after the fact; each was ticked on the artefact it was meant to leave
> behind — the named test file, or the named commit in `git log` — never on
> evidence that anyone watched it go red.
> Nothing in this plan was left unticked.

**Architecture:** One query pass, two thin renderers. `snapshot.ts` is the only module that touches storage; `risk.ts`, `delta.ts`, `hotspots.ts`, `renderStatus.ts` and `renderHtml.ts` are pure functions over data. The two views cannot disagree because there is one source, computed once. The CLI stays a shim that resolves a path, builds a snapshot, and renders.

**Tech Stack:** TypeScript (ESM, NodeNext), `node:sqlite` via the existing `Storage` facade, vitest. No new runtime dependencies. The HTML reuses `mcp/src/report/htmlTheme.ts`.

## Global Constraints

Copied verbatim from the design of record (`docs/superpowers/specs/2026-08-15-local-dashboard-design.md`) and `CLAUDE.md`:

- **Partial coverage disqualifies the verdict.** When any tool the scan intended to run did not run, neither view shows an all-clear state. Both show what was *not* looked at, and both say **what the numbers therefore do not contain** — naming the tools.
- **No silent truncation.** Findings cap at **2000**, new-findings-per-delta at **500**. When a cap bites, a `TruncationNotice` is produced and **both views render it**.
- **Every query is filtered by `project_path`.** Use the `ForProject` repository variants. `findings.listOpen()` and `scans.getLatest()` are forbidden to this feature — their documented contract (`mcp/src/storage/findingsRepo.ts:174-191`) is "any project", correct only for callers with no project in scope.
- **`risk_score`'s public behaviour must not change.** The extraction is a refactor; a characterisation test enforces it.
- **Read-only.** Nothing here runs a scan, mutates the database, opens a socket, or reaches the network.
- **Self-contained HTML.** No `<link>`, no `<script src>`, no CDN, no web font, no absolute `http(s)://` asset URL.
- TypeScript: ESM `.js` import specifiers, `noUncheckedIndexedAccess`, **no `!` non-null assertions, no `any`** (in tests too), **no new runtime dependencies**.
- **`mcp/dist/` is rebuilt and staged in the SAME commit as any `mcp/src/` change** — the repo is the distribution and `cli/dev-guardian.mjs` imports from `dist/`.
- Markdownlint stays clean for `skills/`, `commands/` and `README.md`.
- Purity means **no ambient time**: any function whose result depends on the clock takes `now: number` as a parameter. `Date.now()` inside a pure module is a defect.

---

## File Structure

| File | Kind | Responsibility |
| --- | --- | --- |
| `mcp/src/dashboard/types.ts` | types | `DashboardSnapshot` and every part of it; the tool→category table. |
| `mcp/src/dashboard/risk.ts` | **pure** | `scoreRisk(input)` — the 0–100 score, band, components, next action. |
| `mcp/src/dashboard/delta.ts` | **pure** | `compareFindings(from, to, cap)` — new / resolved / unchanged by fingerprint. |
| `mcp/src/dashboard/hotspots.ts` | **pure** | `rankFiles(findings, limit)` — files by finding count, descending. |
| `mcp/src/dashboard/snapshot.ts` | storage | `buildSnapshot(storage, projectPath, now)` — the one query pass. |
| `mcp/src/dashboard/renderStatus.ts` | **pure** | `renderStatus(snapshot, opts)` — the terminal screen. |
| `mcp/src/dashboard/renderHtml.ts` | **pure** | `renderDashboard(snapshot)` — the self-contained page. |
| `mcp/src/storage/scansRepo.ts` | modify | gains `listHistoryForProject(projectPath, limit)`. |
| `mcp/src/tools/riskScore.ts` | modify | becomes a thin wrapper over `scoreRisk`. |
| `cli/dev-guardian.mjs` | modify | gains `status` and `dashboard`. |
| `commands/guardian-status.md` | modify | invokes the CLI; loses the section with no data source. |

---

### Task 1: Types, the pure risk score, and the tool it comes from

**Files:**

- Create: `mcp/src/dashboard/types.ts`
- Create: `mcp/src/dashboard/risk.ts`
- Modify: `mcp/src/tools/riskScore.ts`
- Test: `mcp/test/unit/dashboard/risk.test.ts`
- Test: `mcp/test/unit/tools/riskScoreCharacterisation.test.ts`

**Interfaces:**

- Consumes: `Finding`, `Cve`, `Severity` from `mcp/src/types.ts`.
- Produces:

```ts
// types.ts
export interface RiskInput {
  /** Project-scoped, already suppression-filtered. */
  findings: readonly Finding[];
  /** Active CVEs for this project's latest deps-flavoured scan. */
  cves: readonly Cve[];
  /** 0–3: privacy_policy, terms_of_service, security_policy that are absent. */
  policies_missing: number;
  /** True when renovate OR dependabot is configured. */
  dependency_bot_configured: boolean;
  /** ISO timestamp of the active baseline, or null when none was ever set. */
  baseline_set_at: string | null;
  /** True when the scan behind these numbers did not run every intended tool. */
  coverage_partial: boolean;
  /** Injected clock. Never call Date.now() inside risk.ts. */
  now: number;
}

export interface RiskAssessment {
  score: number;
  band: 'low' | 'medium' | 'high' | 'critical';
  components: {
    findings: { score: number; open_findings: number };
    cves: { score: number; active_cves: number };
    compliance: { score: number; policies_missing: number };
    baseline: { score: number; has_active_baseline: boolean };
  };
  next_action: string;
  coverage_caveat: boolean;
}

/** Tools whose absence removes a whole class of finding from the numbers.
 *  A tool absent from this table contributes its own name, never nothing. */
export const TOOL_CATEGORIES: Readonly<Record<string, string>> = {
  semgrep: 'static-analysis',
  gitleaks: 'secrets',
  trivy: 'container and dependency',
  nuclei: 'dynamic',
};

// risk.ts
export function scoreRisk(input: RiskInput): RiskAssessment;
```

- [x] **Step 1: Write the failing tests**

Create `mcp/test/unit/dashboard/risk.test.ts`:

```ts
import { describe, expect, it } from 'vitest';
import { scoreRisk } from '../../../src/dashboard/risk.js';
import type { RiskInput } from '../../../src/dashboard/types.js';
import type { Finding, Cve } from '../../../src/types.js';

const NOW = Date.parse('2026-08-15T12:00:00.000Z');

function finding(severity: string): Finding {
  return {
    fingerprint: `fp-${severity}-${Math.random()}`,
    tool: 'semgrep', rule_id: 'r', severity,
    category: 'security', subcategory: null,
    title: 't', message: 'm', file_path: 'a.ts',
    line_start: 1, line_end: 1, snippet: null,
    fix_available: false, fix_applied: false, raw: {},
  } as unknown as Finding;
}

function cve(severity: string): Cve {
  return {
    cve_id: `CVE-${severity}`, package_name: 'p', installed_version: '1',
    fixed_version: '2', severity,
    first_seen_scan_id: 's', last_seen_scan_id: 's',
  } as unknown as Cve;
}

function base(over: Partial<RiskInput> = {}): RiskInput {
  return {
    findings: [], cves: [], policies_missing: 0,
    dependency_bot_configured: true, baseline_set_at: null,
    coverage_partial: false, now: NOW, ...over,
  };
}

describe('scoreRisk', () => {
  it('weights findings 10/5/2/1 by severity', () => {
    const r = scoreRisk(base({
      findings: [finding('critical'), finding('high'), finding('medium'), finding('low')],
      baseline_set_at: '2026-08-14T12:00:00.000Z',   // fresh: contributes 0
    }));
    expect(r.components.findings.score).toBe(18);      // 10+5+2+1
    expect(r.components.findings.open_findings).toBe(4);
  });

  it('caps the findings component at 40, not the whole score', () => {
    const many = Array.from({ length: 20 }, () => finding('critical'));  // raw 200
    const r = scoreRisk(base({ findings: many, baseline_set_at: '2026-08-14T12:00:00.000Z' }));
    expect(r.components.findings.score).toBe(40);
  });

  it('weights CVEs 8/4/1.5/0.5 and caps at 30', () => {
    const r = scoreRisk(base({
      cves: [cve('critical'), cve('high'), cve('medium'), cve('unknown')],
      baseline_set_at: '2026-08-14T12:00:00.000Z',
    }));
    expect(r.components.cves.score).toBe(14);          // 8+4+1.5+0.5 → rounded
    expect(r.components.cves.active_cves).toBe(4);
  });

  it('penalises a never-set baseline by 8, a >30d baseline by 8, a >90d baseline by 15', () => {
    const day = 24 * 60 * 60 * 1000;
    expect(scoreRisk(base({ baseline_set_at: null })).components.baseline.score).toBe(8);
    expect(scoreRisk(base({ baseline_set_at: new Date(NOW - 40 * day).toISOString() }))
      .components.baseline.score).toBe(8);
    expect(scoreRisk(base({ baseline_set_at: new Date(NOW - 100 * day).toISOString() }))
      .components.baseline.score).toBe(15);
    expect(scoreRisk(base({ baseline_set_at: new Date(NOW - 5 * day).toISOString() }))
      .components.baseline.score).toBe(0);
  });

  it('takes its clock from the input, never the ambient one', () => {
    // The wrong implementation calls Date.now() and this test passes today,
    // fails in 2027, and nobody knows why. Two different injected clocks over
    // the SAME baseline must produce two different staleness scores.
    const day = 24 * 60 * 60 * 1000;
    const setAt = new Date(NOW - 40 * day).toISOString();
    const fresh = scoreRisk(base({ baseline_set_at: setAt, now: NOW }));
    const later = scoreRisk(base({ baseline_set_at: setAt, now: NOW + 60 * day }));
    expect(fresh.components.baseline.score).toBe(8);
    expect(later.components.baseline.score).toBe(15);
  });

  it('bands at 70 / 40 / 15', () => {
    const crit = Array.from({ length: 7 }, () => finding('critical'));  // 40 cap
    expect(scoreRisk(base({ findings: crit, cves: [cve('critical'), cve('critical'),
      cve('critical'), cve('critical')], policies_missing: 3,
      dependency_bot_configured: false })).band).toBe('critical');
    expect(scoreRisk(base()).band).toBe('low');
  });

  it('sets coverage_caveat straight through from the input', () => {
    expect(scoreRisk(base({ coverage_partial: true })).coverage_caveat).toBe(true);
    expect(scoreRisk(base({ coverage_partial: false })).coverage_caveat).toBe(false);
  });

  it('never returns a score above 100 or below 0', () => {
    const many = Array.from({ length: 200 }, () => finding('critical'));
    const cves = Array.from({ length: 200 }, () => cve('critical'));
    const r = scoreRisk(base({ findings: many, cves, policies_missing: 3,
      dependency_bot_configured: false, baseline_set_at: null }));
    expect(r.score).toBeLessThanOrEqual(100);
    expect(r.score).toBeGreaterThanOrEqual(0);
  });
});
```

- [x] **Step 2: Run to verify it fails**

Run: `cd mcp && npx vitest run test/unit/dashboard/risk.test.ts`
Expected: FAIL — cannot resolve `../../../src/dashboard/risk.js`.

- [x] **Step 3: Write `types.ts`, then `risk.ts`**

`risk.ts` ports the arithmetic from `mcp/src/tools/riskScore.ts` **verbatim** — the same weights, caps, bands and recommendation strings — with two changes and no others: it reads its inputs from `RiskInput` instead of from `ctx.storage`, and it takes `now` from the input instead of calling `Date.now()`.

The recommendation strings, copied exactly:

```ts
function recommendation(score: number, open: number, cves: number, hasBaseline: boolean): string {
  if (score >= 70) return 'Run audit_executive and triage critical findings before any new deploy.';
  if (cves > 0) return 'Address active CVEs via deps_update_plan with prefer=security.';
  if (!hasBaseline) return 'Set a baseline with set_baseline so diff_scans can track regressions.';
  if (open > 50) return 'Run triage_findings to identify likely false positives, then suppress.';
  return 'Posture is stable. Consider a periodic audit_executive to confirm.';
}
```

Compliance score: `policies_missing * 3`, plus `6` when `dependency_bot_configured` is false, clamped to `[0, 15]`.

- [x] **Step 4: Run to verify it passes**

Run: `cd mcp && npx vitest run test/unit/dashboard/risk.test.ts`
Expected: PASS.

- [x] **Step 5: Write the characterisation test BEFORE touching the tool**

Create `mcp/test/unit/tools/riskScoreCharacterisation.test.ts`. It seeds an
in-memory database, calls the `risk_score` handler, and asserts the **whole
response object**. Run it against the *unmodified* tool first and confirm it
passes — that is what makes it a characterisation of current behaviour rather
than a description of the behaviour you are about to write.

```ts
import { describe, expect, it } from 'vitest';
import { openDatabase } from '../../../src/storage/db.js';
import { runMigrations } from '../../../src/storage/migrations/runner.js';
import { Storage } from '../../../src/storage/index.js';
import { TOOLS } from '../../../src/tools/index.js';
import '../../../src/tools/riskScore.js';

function seed() {
  const db = openDatabase({ inMemory: true });
  runMigrations(db);
  const storage = new Storage(db);
  const scanId = 'char-scan-1';
  storage.scans.insert({
    scan_id: scanId, scan_type: 'security_full', project_path: '/p', tree_hash: 'h',
  });
  storage.scans.finalize({
    scan_id: scanId, status: 'completed', tools_run: [], missing_tools: [],
  });
  storage.findings.bulkInsert([
    { scan_id: scanId, fingerprint: 'a', tool: 'semgrep', rule_id: 'r',
      severity: 'critical', category: 'security', subcategory: null,
      title: 't', message: 'm', file_path: 'a.ts', line_start: 1, line_end: 1,
      snippet: null, fix_available: false, raw: {} },
    { scan_id: scanId, fingerprint: 'b', tool: 'semgrep', rule_id: 'r',
      severity: 'high', category: 'security', subcategory: null,
      title: 't', message: 'm', file_path: 'b.ts', line_start: 1, line_end: 1,
      snippet: null, fix_available: false, raw: {} },
  ]);
  return { storage, db };
}

describe('risk_score — public behaviour is unchanged by the extraction', () => {
  it('returns the same object shape and values it always has', async () => {
    const { storage, db } = seed();
    const mod = TOOLS.find((t) => t.name === 'risk_score');
    expect(mod).toBeTruthy();
    const res = await mod?.handler({}, { storage } as never);
    expect(res).toEqual({
      ok: true,
      score: 23,                      // 15 findings + 0 cves + 0 compliance + 8 no-baseline
      band: 'medium',
      components: {
        findings: { score: 15, open_findings: 2 },
        cves: { score: 0, active_cves: 0 },
        compliance: { score: 0, policies_missing: 0 },
        baseline: { score: 8, has_active_baseline: false },
      },
      recommended_next_action:
        'Set a baseline with set_baseline so diff_scans can track regressions.',
    });
    db.close();
  });
});
```

If the asserted numbers do not match what the unmodified tool returns, **change
the test to match the tool, not the tool to match the test** — the point is to
pin existing behaviour. Record the real values you observed.

- [x] **Step 6: Rewire `tools/riskScore.ts` to call `scoreRisk`**

The handler keeps its own queries (`listOpen`, `findLatestOfType`, `cves.listActive`,
`baselines.getActive`) — its "any project" contract is correct and deliberate for
a tool with no `project_path` input. It assembles a `RiskInput`, passes
`Date.now()` as `now` and `false` as `coverage_partial`, calls `scoreRisk`, and maps
the result to its existing response: `next_action` → `recommended_next_action`,
`coverage_caveat` dropped.

- [x] **Step 7: Run both test files, then the suite**

Run: `cd mcp && npx vitest run test/unit/dashboard/risk.test.ts test/unit/tools/riskScoreCharacterisation.test.ts && npm test`
Expected: PASS. The characterisation test must produce **identical** values before and after Step 6.

- [x] **Step 8: Build and commit**

```bash
cd mcp && npm run build
cd .. && git add mcp/src mcp/test mcp/dist
git commit -m "feat(dashboard): extract the risk score as a pure, clock-injected function"
```

---

### Task 2: The two remaining pure calculators

**Files:**

- Create: `mcp/src/dashboard/delta.ts`
- Create: `mcp/src/dashboard/hotspots.ts`
- Test: `mcp/test/unit/dashboard/delta.test.ts`
- Test: `mcp/test/unit/dashboard/hotspots.test.ts`

**Interfaces:**

- Consumes: `Finding` from `mcp/src/types.ts`; `FindingDelta`, `Hotspot`, `TruncationNotice` from `dashboard/types.ts` (add them there in this task).
- Produces:

```ts
export interface FindingDelta {
  from_scan_id: string; to_scan_id: string;
  new_count: number; resolved_count: number; unchanged_count: number;
  new_findings: Finding[];
}
export interface Hotspot { file_path: string; count: number }
export interface TruncationNotice {
  what: string; shown: number; total: number; reason: string;
}

export function compareFindings(
  from: { scan_id: string; findings: readonly Finding[] },
  to: { scan_id: string; findings: readonly Finding[] },
  cap: number,
): { delta: FindingDelta; truncation: TruncationNotice | null };

export function rankFiles(findings: readonly Finding[], limit: number):
  { hotspots: Hotspot[]; remaining_files: number };
```

- [x] **Step 1: Write the failing tests**

`mcp/test/unit/dashboard/delta.test.ts`:

```ts
import { describe, expect, it } from 'vitest';
import { compareFindings } from '../../../src/dashboard/delta.js';
import type { Finding } from '../../../src/types.js';

function f(fingerprint: string): Finding {
  return {
    fingerprint, tool: 'semgrep', rule_id: 'r', severity: 'high',
    category: 'security', subcategory: null, title: 't', message: 'm',
    file_path: 'a.ts', line_start: 1, line_end: 1, snippet: null,
    fix_available: false, fix_applied: false, raw: {},
  } as unknown as Finding;
}

describe('compareFindings', () => {
  it('splits by fingerprint into new, resolved and unchanged', () => {
    const r = compareFindings(
      { scan_id: 'from', findings: [f('a'), f('b')] },
      { scan_id: 'to', findings: [f('b'), f('c')] },
      100,
    );
    expect(r.delta.new_count).toBe(1);        // c
    expect(r.delta.resolved_count).toBe(1);   // a
    expect(r.delta.unchanged_count).toBe(1);  // b
    expect(r.delta.new_findings.map((x) => x.fingerprint)).toEqual(['c']);
    expect(r.delta.from_scan_id).toBe('from');
    expect(r.delta.to_scan_id).toBe('to');
  });

  it('reports a truncation notice rather than silently capping new findings', () => {
    // The wrong implementation slices to the cap and returns null. A reader
    // then sees 2 rows and believes there were 2. Counts must stay TRUE even
    // when the list is cut.
    const to = Array.from({ length: 5 }, (_, i) => f(`n${i}`));
    const r = compareFindings({ scan_id: 'a', findings: [] }, { scan_id: 'b', findings: to }, 2);
    expect(r.delta.new_count).toBe(5);          // the COUNT is not capped
    expect(r.delta.new_findings).toHaveLength(2);
    expect(r.truncation).toEqual({
      what: 'new_findings', shown: 2, total: 5,
      reason: expect.stringContaining('cap'),
    });
  });

  it('returns no truncation notice when nothing was cut', () => {
    const r = compareFindings({ scan_id: 'a', findings: [] },
      { scan_id: 'b', findings: [f('x')] }, 100);
    expect(r.truncation).toBeNull();
  });

  it('is empty-safe on both sides', () => {
    const r = compareFindings({ scan_id: 'a', findings: [] },
      { scan_id: 'b', findings: [] }, 10);
    expect(r.delta.new_count).toBe(0);
    expect(r.delta.resolved_count).toBe(0);
    expect(r.delta.unchanged_count).toBe(0);
  });

  it('counts a fingerprint appearing twice on one side once', () => {
    // Findings are keyed (fingerprint, scan_id), so one scan cannot hold a
    // duplicate — but a caller merging two scans could. Set semantics, not
    // array arithmetic, is what keeps the three counts summing correctly.
    const r = compareFindings(
      { scan_id: 'a', findings: [f('x'), f('x')] },
      { scan_id: 'b', findings: [f('x')] },
      10,
    );
    expect(r.delta.unchanged_count).toBe(1);
    expect(r.delta.resolved_count).toBe(0);
  });
});
```

`mcp/test/unit/dashboard/hotspots.test.ts`:

```ts
import { describe, expect, it } from 'vitest';
import { rankFiles } from '../../../src/dashboard/hotspots.js';
import type { Finding } from '../../../src/types.js';

function f(file_path: string): Finding {
  return {
    fingerprint: `${file_path}-${Math.random()}`, tool: 'semgrep', rule_id: 'r',
    severity: 'low', category: 'security', subcategory: null, title: 't',
    message: 'm', file_path, line_start: 1, line_end: 1, snippet: null,
    fix_available: false, fix_applied: false, raw: {},
  } as unknown as Finding;
}

describe('rankFiles', () => {
  it('ranks files by finding count, descending', () => {
    const r = rankFiles([f('a.ts'), f('b.ts'), f('a.ts'), f('a.ts'), f('b.ts')], 10);
    expect(r.hotspots).toEqual([
      { file_path: 'a.ts', count: 3 },
      { file_path: 'b.ts', count: 2 },
    ]);
    expect(r.remaining_files).toBe(0);
  });

  it('reports how many files it did NOT show', () => {
    // Otherwise "3 hottest files" reads as "3 files have findings".
    const rows = ['a', 'b', 'c', 'd', 'e'].flatMap((n) => [f(`${n}.ts`)]);
    const r = rankFiles(rows, 3);
    expect(r.hotspots).toHaveLength(3);
    expect(r.remaining_files).toBe(2);
  });

  it('breaks ties by path so the output is stable across runs', () => {
    // An unstable sort makes the terminal screen change between two runs over
    // identical data, which reads as "something moved" when nothing did.
    const r = rankFiles([f('b.ts'), f('a.ts')], 10);
    expect(r.hotspots.map((h) => h.file_path)).toEqual(['a.ts', 'b.ts']);
  });

  it('groups findings with no file path under a single explicit bucket', () => {
    const orphan = { ...f('x'), file_path: null } as unknown as Finding;
    const r = rankFiles([orphan, orphan], 10);
    expect(r.hotspots).toEqual([{ file_path: '(no file)', count: 2 }]);
  });

  it('is empty-safe', () => {
    expect(rankFiles([], 5)).toEqual({ hotspots: [], remaining_files: 0 });
  });
});
```

- [x] **Step 2: Run to verify they fail**

Run: `cd mcp && npx vitest run test/unit/dashboard/delta.test.ts test/unit/dashboard/hotspots.test.ts`
Expected: FAIL — modules not found.

- [x] **Step 3: Implement both modules**

`compareFindings` builds a `Set` of fingerprints per side, derives the three
counts from set membership, slices `new_findings` to `cap`, and returns a
`TruncationNotice` when and only when the slice cut something. **`new_count` is
the true count, never the sliced length.**

`rankFiles` groups by `file_path ?? '(no file)'`, sorts by count descending then
`file_path` ascending, slices to `limit`, and returns `remaining_files` as the
number of distinct files beyond the slice.

- [x] **Step 4: Run to verify they pass**

Run: `cd mcp && npx vitest run test/unit/dashboard/delta.test.ts test/unit/dashboard/hotspots.test.ts`
Expected: PASS.

- [x] **Step 5: Build and commit**

```bash
cd mcp && npm run build
cd .. && git add mcp/src mcp/test mcp/dist
git commit -m "feat(dashboard): fingerprint delta and file hotspots, both disclosing what they cut"
```

---

### Task 3: The scoped scan history, and the one query pass

**Files:**

- Modify: `mcp/src/storage/scansRepo.ts`
- Create: `mcp/src/dashboard/snapshot.ts`
- Test: `mcp/test/unit/dashboard/snapshot.test.ts`

**Interfaces:**

- Consumes: `scoreRisk` (Task 1), `compareFindings` and `rankFiles` (Task 2).
- Produces:

```ts
// scansRepo.ts — beside the existing listHistory, never replacing it
listHistoryForProject(projectPath: string, limit?: number): ScanRecord[];

// snapshot.ts
export function buildSnapshot(
  storage: Storage,
  projectPath: string,
  now: number,
): DashboardSnapshot;
```

The full `DashboardSnapshot` shape is in the design of record §5. Add every
interface it names to `dashboard/types.ts` in this task: `DashboardSnapshot`,
`CoverageState`, `ScanSummary`, `FindingsSummary`, `CveSummary`,
`BaselineState`, `SuppressionState`.

- [x] **Step 1: Write the failing test**

`mcp/test/unit/dashboard/snapshot.test.ts`:

```ts
import { describe, expect, it } from 'vitest';
import { openDatabase } from '../../../src/storage/db.js';
import { runMigrations } from '../../../src/storage/migrations/runner.js';
import { Storage } from '../../../src/storage/index.js';
import { buildSnapshot } from '../../../src/dashboard/snapshot.js';
import type { ScanType, ToolRun } from '../../../src/types.js';

const NOW = Date.parse('2026-08-15T12:00:00.000Z');

function fresh() {
  const db = openDatabase({ inMemory: true });
  runMigrations(db);
  return { db, storage: new Storage(db) };
}

let scanSeq = 0;

function completedScan(
  storage: Storage,
  projectPath: string,
  opts: { tools_run?: ToolRun[]; missing_tools?: string[]; scan_type?: ScanType } = {},
) {
  // `scans.insert` does NOT generate an id — the caller supplies one, and the
  // record's field is `scan_id`, not `id`.
  const scanId = `scan-${++scanSeq}`;
  storage.scans.insert({
    scan_id: scanId,
    scan_type: opts.scan_type ?? 'security_full',
    project_path: projectPath, tree_hash: 'h',
  });
  storage.scans.finalize({
    scan_id: scanId, status: 'completed',
    // ToolRun is { name, status: 'ok' | 'skipped' | 'failed' } — there is no
    // `ok` boolean. `report_dir` and `error` are OPTIONAL: omit them; `null`
    // is not assignable to `string | undefined`.
    tools_run: opts.tools_run ?? [{ name: 'semgrep', status: 'ok' }],
    missing_tools: opts.missing_tools ?? [],
  });
  return scanId;
}

function insertFinding(storage: Storage, scanId: string, fingerprint: string,
  severity: string, file_path: string) {
  storage.findings.bulkInsert([{
    scan_id: scanId, fingerprint, tool: 'semgrep', rule_id: 'r', severity,
    category: 'security', subcategory: null, title: 't', message: 'm',
    file_path, line_start: 1, line_end: 1, snippet: null,
    fix_available: false, raw: {},
  }]);
}

describe('buildSnapshot', () => {
  it('returns ONLY the requested project, even when another scanned later', () => {
    // This is the listOpen() hazard, tested rather than trusted. The wrong
    // implementation reaches for findings.listOpen() / scans.getLatest(),
    // which return the newest scan in the WHOLE database. It never looks
    // wrong, because the result is never empty.
    const { storage, db } = fresh();
    const mine = completedScan(storage, '/mine');
    insertFinding(storage, mine, 'mine-1', 'high', 'mine.ts');
    const theirs = completedScan(storage, '/theirs');       // completes LATER
    insertFinding(storage, theirs, 'theirs-1', 'critical', 'theirs.ts');

    const snap = buildSnapshot(storage, '/mine', NOW);
    expect(snap.project_path).toBe('/mine');
    expect(snap.scan?.scan_id).toBe(mine);
    expect(snap.findings.total).toBe(1);
    expect(snap.findings.items[0]?.fingerprint).toBe('mine-1');
    expect(snap.findings.by_severity.critical).toBe(0);
    db.close();
  });

  it('marks coverage partial and names what the numbers therefore omit', () => {
    const { storage, db } = fresh();
    completedScan(storage, '/p', {
      tools_run: [{ name: 'semgrep', status: 'ok' }],
      missing_tools: ['gitleaks', 'trivy'],
    });
    const snap = buildSnapshot(storage, '/p', NOW);
    expect(snap.coverage.level).toBe('partial');
    expect(snap.coverage.missing_tools).toEqual(['gitleaks', 'trivy']);
    expect(snap.coverage.omitted_categories).toEqual(
      expect.arrayContaining(['secrets', 'container and dependency']),
    );
    expect(snap.risk.coverage_caveat).toBe(true);
    db.close();
  });

  it('names an unknown missing tool rather than dropping it', () => {
    const { storage, db } = fresh();
    completedScan(storage, '/p', { missing_tools: ['some-new-scanner'] });
    const snap = buildSnapshot(storage, '/p', NOW);
    expect(snap.coverage.omitted_categories).toContain('some-new-scanner');
    db.close();
  });

  it('compares against the previous scan OF THE SAME TYPE', () => {
    // Comparing security_full against a secrets-only run would report every
    // SAST finding as "new".
    const { storage, db } = fresh();
    const older = completedScan(storage, '/p', { scan_type: 'security_full' });
    insertFinding(storage, older, 'keep', 'high', 'a.ts');
    completedScan(storage, '/p', { scan_type: 'secrets' });   // different type
    const newest = completedScan(storage, '/p', { scan_type: 'security_full' });
    insertFinding(storage, newest, 'keep', 'high', 'a.ts');

    const snap = buildSnapshot(storage, '/p', NOW);
    expect(snap.deltas.since_previous?.from_scan_id).toBe(older);
    expect(snap.deltas.since_previous?.unchanged_count).toBe(1);
    expect(snap.deltas.since_previous?.new_count).toBe(0);
    db.close();
  });

  it('leaves a delta null — not zeroed — when its reference does not exist', () => {
    // Zeros read as "nothing changed". Null reads as "there is nothing to
    // compare against", which is the truth.
    const { storage, db } = fresh();
    completedScan(storage, '/p');
    const snap = buildSnapshot(storage, '/p', NOW);
    expect(snap.deltas.since_previous).toBeNull();
    expect(snap.deltas.since_baseline).toBeNull();
    expect(snap.baseline.active).toBeNull();
    db.close();
  });

  it('returns a usable snapshot when the project has never been scanned', () => {
    const { storage, db } = fresh();
    const snap = buildSnapshot(storage, '/never', NOW);
    expect(snap.scan).toBeNull();
    expect(snap.coverage.level).toBe('none');
    expect(snap.findings.total).toBe(0);
    expect(snap.risk.score).toBe(0);
    expect(snap.risk.coverage_caveat).toBe(true);   // unknown is not safe
    expect(Number.isNaN(snap.risk.score)).toBe(false);
    db.close();
  });

  it('excludes suppressed findings from the counts and from both deltas', () => {
    const { storage, db } = fresh();
    const scan = completedScan(storage, '/p');
    insertFinding(storage, scan, 'visible', 'high', 'a.ts');
    insertFinding(storage, scan, 'hidden', 'critical', 'b.ts');
    storage.suppressions.insert({
      finding_fingerprint: 'hidden', reason: 'false positive',
      created_by: 'test',   // expires_at is optional — omit, never pass null
    });
    const snap = buildSnapshot(storage, '/p', NOW);
    expect(snap.findings.total).toBe(1);
    expect(snap.findings.by_severity.critical).toBe(0);
    expect(snap.suppressions.active_count).toBe(1);
    db.close();
  });
});
```

- [x] **Step 2: Run to verify it fails**

Run: `cd mcp && npx vitest run test/unit/dashboard/snapshot.test.ts`
Expected: FAIL — `buildSnapshot` not found.

- [x] **Step 3: Add `listHistoryForProject` to `scansRepo.ts`**

Prepare it beside `listHistoryStmt`, with the identical predicate plus
`WHERE project_path = ?`, the same `ORDER BY started_at DESC, rowid DESC`, and
the same `LIMIT ?`. Do **not** change `listHistory` — other callers depend on
its "any project" contract.

- [x] **Step 4: Implement `snapshot.ts`**

It uses `scans.getLatestForProject`, `scans.listHistoryForProject`,
`findings.listOpenForProject`, `cves.listActive`, `baselines.getActive`,
`suppressions.listActive`. It never calls `findings.listOpen` or
`scans.getLatest`.

Coverage: `level` is `'none'` when there is no scan, `'partial'` when
`missing_tools` is non-empty, otherwise `'full'`. `omitted_categories` maps each
missing tool through `TOOL_CATEGORIES`, falling back to the tool's own name,
de-duplicated, order preserved.

Deltas: `since_previous` compares against the most recent completed scan of the
**same `scan_type`** for this project, excluding the current one;
`since_baseline` against the scan the active baseline points at. Each is `null`
when its reference is absent. Both sides are suppression-filtered before
comparison.

Grouping (`by_severity`, `by_category`, `by_tool`) is plain JavaScript over the
already-fetched findings. `by_severity` is initialised with every severity at
zero so a missing key never renders as `undefined`.

- [x] **Step 5: Run to verify it passes, then the suite**

Run: `cd mcp && npx vitest run test/unit/dashboard/snapshot.test.ts && npm test`
Expected: PASS.

- [x] **Step 6: Build and commit**

```bash
cd mcp && npm run build
cd .. && git add mcp/src mcp/test mcp/dist
git commit -m "feat(dashboard): the single project-scoped query pass"
```

---

### Task 4: The terminal screen

**Files:**

- Create: `mcp/src/dashboard/renderStatus.ts`
- Create: `mcp/test/unit/dashboard/snapshotFixture.ts` (the shared `snap()` factory, imported by Task 5 too)
- Test: `mcp/test/unit/dashboard/renderStatus.test.ts`

**Interfaces:**

- Consumes: `DashboardSnapshot` (Task 3).
- Produces:

```ts
export function renderStatus(
  snapshot: DashboardSnapshot,
  opts: { color: boolean },
): string;
```

The layout is in the design of record §6. Reproduce it; the exact column
positions are not load-bearing, the content rules are.

- [x] **Step 1: Write the failing test**

Put the `snap()` factory in `mcp/test/unit/dashboard/snapshotFixture.ts` and
export it — Task 5 imports the same factory, and two copies would drift.
Build snapshots from it rather than from a database; this module is pure.

`snapshotFixture.ts`:

```ts
import type { DashboardSnapshot } from '../../../src/dashboard/types.js';

export function snap(over: Partial<DashboardSnapshot> = {}): DashboardSnapshot {
  // …the object literal below, returned with `...over` spread last.
}
```

Then `renderStatus.test.ts` opens with:

```ts
import { describe, expect, it } from 'vitest';
import { renderStatus } from '../../../src/dashboard/renderStatus.js';
import { snap } from './snapshotFixture.js';
```

```ts
import { describe, expect, it } from 'vitest';
import { renderStatus } from '../../../src/dashboard/renderStatus.js';
import type { DashboardSnapshot } from '../../../src/dashboard/types.js';

function snap(over: Partial<DashboardSnapshot> = {}): DashboardSnapshot {
  return {
    project_path: '/p', generated_at: '2026-08-15T12:00:00.000Z',
    scan: { scan_id: 's1', scan_type: 'security_full', status: 'completed',
      started_at: '2026-08-15T10:00:00.000Z', finished_at: '2026-08-15T10:00:47.000Z',
      duration_seconds: 47, age_seconds: 7200 },
    coverage: { level: 'full', tools_run: ['semgrep'], missing_tools: [],
      omitted_categories: [] },
    risk: { score: 62, band: 'high',
      components: { findings: { score: 40, open_findings: 104 },
        cves: { score: 14, active_cves: 5 },
        compliance: { score: 0, policies_missing: 0 },
        baseline: { score: 8, has_active_baseline: true } },
      next_action: 'Fix the 3 critical findings first.', coverage_caveat: false },
    findings: { total: 104,
      by_severity: { critical: 3, high: 12, medium: 31, low: 58, info: 0 },
      by_category: {}, by_tool: {},
      hotspots: [{ file_path: 'src/auth/session.ts', count: 11 }], items: [] },
    cves: { total: 5, by_severity: { critical: 1, high: 4, medium: 0, low: 0, info: 0 },
      items: [] },
    deltas: { since_previous: null, since_baseline: null },
    baseline: { active: null, age_days: null },
    suppressions: { active_count: 0, expiring_soon: [] },
    truncation: [],
    ...over,
  } as DashboardSnapshot;
}

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
```

- [x] **Step 2: Run to verify it fails**

Run: `cd mcp && npx vitest run test/unit/dashboard/renderStatus.test.ts`
Expected: FAIL — module not found.

- [x] **Step 3: Implement `renderStatus.ts`**

Follow §6's layout. The colour implementation must satisfy the last-but-two
test literally: the coloured output with ANSI sequences stripped equals the
uncoloured output exactly, which means colour is only ever added around text
that is present either way.

- [x] **Step 4: Run to verify it passes**

Run: `cd mcp && npx vitest run test/unit/dashboard/renderStatus.test.ts`
Expected: PASS.

- [x] **Step 5: Build and commit**

```bash
cd mcp && npm run build
cd .. && git add mcp/src mcp/test mcp/dist
git commit -m "feat(dashboard): the one-screen terminal view"
```

---

### Task 5: The self-contained page

**Files:**

- Create: `mcp/src/dashboard/renderHtml.ts`
- Test: `mcp/test/unit/dashboard/renderHtml.test.ts`

**Interfaces:**

- Consumes: `DashboardSnapshot` (Task 3); `renderHtmlDocument`, `severityChip`, `severityBar`, `escapeHtml`, `SEVERITY_COLORS` from `mcp/src/report/htmlTheme.ts`.
- Produces:

```ts
export function renderDashboard(snapshot: DashboardSnapshot): string;
```

- [x] **Step 1: Write the failing test**

`mcp/test/unit/dashboard/renderHtml.test.ts`. Reuse the `snap()` factory from
Task 4 by exporting it from a shared test helper
`mcp/test/unit/dashboard/snapshotFixture.ts`, and import it in both files —
do not copy it.

```ts
import { describe, expect, it } from 'vitest';
import { renderDashboard } from '../../../src/dashboard/renderHtml.js';
import { snap } from './snapshotFixture.js';

/** Pull the inlined payload back out the way a browser would. */
function inlinedData(html: string): unknown {
  const m = html.match(
    /<script type="application\/json" id="guardian-data">([\s\S]*?)<\/script>/,
  );
  if (!m || m[1] === undefined) throw new Error('no inlined data block');
  return JSON.parse(m[1]);
}

describe('renderDashboard', () => {
  it('inlines data that is valid JSON and round-trips the findings', () => {
    const html = renderDashboard(snap({
      findings: { total: 1,
        by_severity: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
        by_category: { security: 1 }, by_tool: { semgrep: 1 }, hotspots: [],
        items: [{ fingerprint: 'a', severity: 'high', title: 'Injection',
          file_path: 'src/a.ts', tool: 'semgrep', rule_id: 'r',
          message: 'm', line_start: 3 } as never] },
    }));
    const data = inlinedData(html) as { findings: { items: { title: string }[] } };
    expect(data.findings.items[0]?.title).toBe('Injection');
  });

  it('reaches for nothing outside the file', () => {
    // The offline guarantee. A CDN <script src> added later would render
    // perfectly in a browser with network and break silently without one, and
    // no visual check would catch it.
    const html = renderDashboard(snap());
    expect(html).not.toMatch(/<script[^>]+\bsrc=/i);
    expect(html).not.toMatch(/<link[^>]+\bhref=/i);
    expect(html).not.toMatch(/https?:\/\/[^"'\s]+\.(?:js|css|woff2?|png|svg)/i);
    expect(html).not.toMatch(/@import\s+url/i);
  });

  it('carries a coverage banner, not a footnote, when coverage is partial', () => {
    const html = renderDashboard(snap({
      coverage: { level: 'partial', tools_run: ['semgrep'],
        missing_tools: ['gitleaks'], omitted_categories: ['secrets'] },
    }));
    expect(html).toMatch(/guardian-coverage-banner/);
    expect(html).toMatch(/gitleaks/);
    expect(html).toMatch(/secrets/);
  });

  it('has no coverage banner when coverage is full', () => {
    expect(renderDashboard(snap())).not.toMatch(/guardian-coverage-banner/);
  });

  it('states what it cut, in the visible document and not only in the data', () => {
    const html = renderDashboard(snap({
      truncation: [{ what: 'findings', shown: 2000, total: 5310, reason: 'cap of 2000' }],
    }));
    const visible = html.replace(
      /<script type="application\/json"[\s\S]*?<\/script>/g, '');
    expect(visible).toMatch(/2000/);
    expect(visible).toMatch(/5310/);
  });

  it('escapes finding text rather than letting it become markup', () => {
    // A finding's message comes from a scanner, which read it from the user's
    // source. It is untrusted text in this document.
    const html = renderDashboard(snap({
      findings: { total: 1,
        by_severity: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
        by_category: {}, by_tool: {}, hotspots: [],
        items: [{ fingerprint: 'a', severity: 'high',
          title: '<img src=x onerror=alert(1)>', file_path: 'a.ts',
          tool: 'semgrep', rule_id: 'r', message: 'm', line_start: 1 } as never] },
    }));
    const visible = html.replace(
      /<script type="application\/json"[\s\S]*?<\/script>/g, '');
    expect(visible).not.toMatch(/<img src=x/);
    expect(visible).toMatch(/&lt;img/);
  });

  it('closes the JSON block safely when a finding contains the closing tag', () => {
    // `</script>` inside the payload would end the block early and spill the
    // rest of the JSON into the document as markup.
    const html = renderDashboard(snap({
      findings: { total: 1,
        by_severity: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
        by_category: {}, by_tool: {}, hotspots: [],
        items: [{ fingerprint: 'a', severity: 'high', title: 'x</script><b>y',
          file_path: 'a.ts', tool: 'semgrep', rule_id: 'r', message: 'm',
          line_start: 1 } as never] },
    }));
    const data = inlinedData(html) as { findings: { items: { title: string }[] } };
    expect(data.findings.items[0]?.title).toBe('x</script><b>y');
  });

  it('renders a scanned-nothing project without undefined or NaN', () => {
    const html = renderDashboard(snap({
      scan: null,
      coverage: { level: 'none', tools_run: [], missing_tools: [], omitted_categories: [] },
    }));
    const visible = html.replace(
      /<script type="application\/json"[\s\S]*?<\/script>/g, '');
    expect(visible).not.toMatch(/undefined|NaN/);
    expect(visible).toMatch(/dev-guardian scan/);
  });
});
```

- [x] **Step 2: Run to verify it fails**

Run: `cd mcp && npx vitest run test/unit/dashboard/renderHtml.test.ts`
Expected: FAIL — module not found.

- [x] **Step 3: Implement `renderHtml.ts`**

Compose sections and hand them to `renderHtmlDocument({title, subtitle, sections, lang})`.
Sections: the risk header with its coverage caveat, the coverage banner when
partial, the severity bar, the two deltas, the filterable findings table, the
hotspots, the CVEs, the suppressions, the scan metadata.

Two details the tests pin:

- Serialise the payload with `JSON.stringify(snapshot).replace(/</g, '\\u003c')`.
  That keeps `</script>` from terminating the block while remaining valid JSON
  that `JSON.parse` restores exactly.
- Every value that came from a scanner goes through `escapeHtml` before
  reaching the visible document.

The interaction script is inline vanilla JS: read the JSON block, build the
table, wire severity/tool/category/file filters and column sorting. No
dependencies, no network.

- [x] **Step 4: Run to verify it passes**

Run: `cd mcp && npx vitest run test/unit/dashboard/renderHtml.test.ts`
Expected: PASS.

- [x] **Step 5: Build and commit**

```bash
cd mcp && npm run build
cd .. && git add mcp/src mcp/test mcp/dist
git commit -m "feat(dashboard): the self-contained HTML page"
```

---

### Task 6: The two CLI commands

**Files:**

- Modify: `cli/dev-guardian.mjs`
- Test: `mcp/test/e2e/dashboardCli.test.ts`

**Interfaces:**

- Consumes: `buildSnapshot`, `renderStatus`, `renderDashboard` from `mcp/dist/dashboard/*.js`; `openDatabase`, `Storage`, `runMigrations` from `mcp/dist/storage/*.js`.
- Produces: `dev-guardian status` and `dev-guardian dashboard`.

Flags:

```text
status     --project <path>   default: cwd
dashboard  --project <path>   default: cwd
           --out <path>       default: <project>/.guardian/dashboard.html
           --no-open          never launch a browser
```

Every value-taking flag goes through the existing `takeOperand()` helper, so a
missing operand is a usage error (exit 3) rather than a silent default. Both
commands accept the help spellings the CLI already routes.

- [x] **Step 1: Write the failing test**

`mcp/test/e2e/dashboardCli.test.ts`, invoking the CLI as a **real subprocess**,
following the `runCli` pattern already in `mcp/test/e2e/ciCliFixture.test.ts`.

```ts
import { describe, expect, it, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, existsSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = resolve(fileURLToPath(new URL('../../..', import.meta.url)));
const CLI = resolve(REPO_ROOT, 'cli', 'dev-guardian.mjs');

let project: string;
beforeAll(() => { project = mkdtempSync(join(tmpdir(), 'guardian-dash-')); });
afterAll(() => { rmSync(project, { recursive: true, force: true }); });

function runCli(args: string[]) {
  const r = spawnSync(process.execPath, [CLI, ...args],
    { encoding: 'utf8', env: { ...process.env, NO_COLOR: '1' } });
  return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

describe('dev-guardian status / dashboard', () => {
  it('status exits 0 and names the scan command on a project with no data', () => {
    const r = runCli(['status', '--project', project]);
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/dev-guardian scan/);
    expect(r.stdout).not.toMatch(/undefined|NaN/);
  });

  it('status exits 0 even with findings — it reports, it does not gate', () => {
    // `scan` gates and has exit codes for it. If `status` ever returns 1 on a
    // dirty project, every pipeline that runs it for a summary breaks.
    const r = runCli(['status', '--project', REPO_ROOT]);
    expect(r.status).toBe(0);
  });

  it('dashboard writes a file that parses, and prints its path', () => {
    const out = join(project, 'dash.html');
    const r = runCli(['dashboard', '--project', project, '--out', out, '--no-open']);
    expect(r.status).toBe(0);
    expect(existsSync(out)).toBe(true);
    const html = readFileSync(out, 'utf8');
    const m = html.match(
      /<script type="application\/json" id="guardian-data">([\s\S]*?)<\/script>/);
    expect(m).toBeTruthy();
    expect(() => JSON.parse(m?.[1] ?? '')).not.toThrow();
    expect(r.stdout).toContain(out);
  });

  it('never launches a browser when stdout is not a TTY', () => {
    // spawnSync gives the child a pipe, so this is the piped case by
    // construction. A render that shells out anyway would leave a browser
    // process behind on every CI run that calls it.
    const out = join(project, 'dash2.html');
    const r = runCli(['dashboard', '--project', project, '--out', out]);
    expect(r.status).toBe(0);
    expect(existsSync(out)).toBe(true);
  });

  it('exits 3 naming the flag when --out has no value', () => {
    const r = runCli(['dashboard', '--project', project, '--out']);
    expect(r.status).toBe(3);
    expect(r.stderr).toMatch(/--out/);
  });

  it('exits 3 when --project points nowhere', () => {
    const r = runCli(['status', '--project', join(project, 'nope')]);
    expect(r.status).toBe(3);
  });
});
```

- [x] **Step 2: Run to verify it fails**

Run: `cd mcp && npx vitest run test/e2e/dashboardCli.test.ts`
Expected: FAIL — `Unknown command: status`.

- [x] **Step 3: Implement both commands**

Add the imports at the top of `cli/dev-guardian.mjs` beside the existing
`../mcp/dist/...` imports. Each command: parse flags via `takeOperand`, resolve
and verify the project directory (exit 3 if absent), open the project's
database with `openDatabase({ projectPath })`, run migrations, wrap in
`Storage`, call `buildSnapshot(storage, projectPath, Date.now())`, render, and
close the database in a `finally`.

`status` writes to stdout with `color: process.stdout.isTTY === true && !process.env.NO_COLOR`.

`dashboard` writes the file, prints the path, and opens a browser **only** when
`process.stdout.isTTY` and `--no-open` was not passed. The opener is
`start` (win32), `open` (darwin), `xdg-open` (otherwise), spawned with
`shell: false` and detached, its result ignored — a missing `xdg-open` must not
fail the command that already succeeded.

Follow item 5's exit discipline: set `process.exitCode` and return; never call
`process.exit()` after writing to stdout, which truncates on POSIX.

- [x] **Step 4: Run to verify it passes, then the suite**

Run: `cd mcp && npx vitest run test/e2e/dashboardCli.test.ts && npm test`
Expected: PASS.

- [x] **Step 5: Commit**

```bash
git add cli mcp/test
git commit -m "feat(cli): status and dashboard commands"
```

---

### Task 7: The slash command, the docs, and the gate

**Files:**

- Modify: `commands/guardian-status.md`
- Modify: `README.md` (EN/PT/ES), `CHANGELOG.md`, `host-rules/AGENTS.md` and its paired host files, `cli/dev-guardian.mjs` help text

- [x] **Step 1: Rewrite `commands/guardian-status.md`**

It invokes `node cli/dev-guardian.mjs status --project .`, shows that output
verbatim, and then adds interpretation on top. Two of its current seven
sections need deciding, not carrying forward unchanged:

- **"Understanding gate"** stays. It reads `.guardian/last-grill.md`, a real
  file the `guardian-grill` skill writes — a file, not a table, and out of the
  CLI's scope.
- **"Last commands run"** is **removed**. No table in the schema records
  command invocations, so the line can only be fabricated. Say nothing rather
  than inviting an invention.

- [x] **Step 2: Measure the tool count and sweep every place it appears**

```bash
cd mcp && node -e "import('./dist/registerAll.js').then(()=>import('./dist/tools/index.js')).then(m=>console.log(m.TOOLS.length))"
cd .. && git grep -n "5[0-9] \(tools\|MCP\|herramientas\|ferramentas\)"
```

This task adds no MCP tool, so the count should be unchanged — **verify that
rather than assuming it.** Use no `--include` filter: a previous sweep on this
repo missed files on two axes, language (a Spanish "herramientas") and
extension (files with no `.md`/`.json`).

- [x] **Step 3: Document the two commands**

README in all three languages, `host-rules/AGENTS.md` and its paired host files,
and the CLI `--help` text. State plainly, in each:

- The page is a **snapshot, not live** — regenerate it after a new scan.
- The window is the latest scan plus two deltas. There is no multi-week trend.
- `status` and `dashboard` are **read-only** and always exit 0 when they
  render; they report, they do not gate.

- [x] **Step 4: CHANGELOG entry carrying the limits from design §12**

The snapshot-not-live property; the absent trend; the risk score being a
heuristic; that coverage is only as honest as `missing_tools`, so a scanner
that ran and silently produced nothing is indistinguishable from a clean
result; and that hotspots rank by count, not severity.

- [x] **Step 5: Full verification gate**

```bash
cd mcp && npm run build && GUARDIAN_REQUIRE_SEMGREP=1 npm test
GUARDIAN_REQUIRE_SEMGREP=1 npm run test:coverage
cd .. && npx markdownlint-cli2 "skills/**/*.md" "commands/**/*.md" "README.md"
```

Semgrep is installed but **not on PATH** — `%APPDATA%\Roaming\Python\Python314\Scripts`.
Note that the env var does **not** propagate past `&&` in a POSIX shell, so
each command carries it. Report the exact skip count (**target zero**) and all
four coverage numbers against 70/62/72/70.

- [x] **Step 6: Commit**

```bash
git add -A
git commit -m "docs(dashboard): document the two views and what they do not do"
```

---

## Self-Review Notes

Checked against the spec:

- §1 two views, read-only, no socket → Tasks 4, 5, 6; the read-only property is
  asserted by Task 6's "status exits 0 even with findings".
- §2 the coverage rule → Task 3 produces it, Tasks 4 and 5 assert it **as
  rendered output**, which is the form that can actually fail.
- §3 architecture, one query pass → Task 3 is the only storage-touching module;
  every other module's tests run without a database.
- §3.1 risk extraction with unchanged public behaviour → Task 1, with the
  characterisation test written and run *before* the tool is touched.
- §4 project scoping → Task 3's first test seeds two projects in one database.
- §5 the snapshot shape → Task 3, with every interface named.
- §5.1 no data → Tasks 3, 4, 5 and 6 each cover it; a project nobody scanned is
  `coverage_caveat: true`, unknown rather than safe.
- §6 the terminal screen → Task 4, including the one-screen line budget.
- §7 both deltas, same-type previous, null not zeroed → Task 3.
- §8 caps and disclosure → Task 2 produces the notice, Tasks 4 and 5 render it.
- §9 the page, self-contained, TTY-gated open → Tasks 5 and 6.
- §10 `/guardian-status` → Task 7.
- §11 testing → the test files named in each task.
- §12 limitations → Task 7's CHANGELOG entry.

Type consistency: `RiskAssessment` is defined in Task 1 and consumed by Tasks 3,
4 and 5 with the nested `components` shape that matches `risk_score`'s existing
wire output. `FindingDelta`, `Hotspot` and `TruncationNotice` are defined in
Task 2 and consumed by Tasks 3, 4 and 5. `DashboardSnapshot` is completed in
Task 3 and consumed by Tasks 4, 5 and 6. `buildSnapshot(storage, projectPath,
now)` has the same signature everywhere it appears.

One deliberate deviation from the spec, recorded rather than silent: the spec's
§5 listed `RiskAssessment.components` as four bare numbers. That shape cannot
satisfy §3.1's "public behaviour must not change", because `risk_score` returns
nested objects carrying the counts. The spec was amended to the nested shape
before this plan was written; the plan follows the amended spec.
