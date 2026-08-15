# Local dashboard over the SQLite state — design of record

**Date:** 2026-08-15
**Status:** approved
**Item 6 of 7** in the dev-guardian ↔ strix gap project.

## 1. What this is, and what it is not

Two read-only views of what dev-guardian already persisted for **the project you
are standing in**:

- `dev-guardian status` — one terminal screen.
- `dev-guardian dashboard` — a self-contained HTML file you open in a browser.

It is **for a developer on their own laptop, during development**. That was
chosen explicitly, and it excludes three neighbouring things:

- **Not a CI artifact.** Item 5 already emits SARIF for that, and SARIF uploads
  into the host's own UI.
- **Not a client deliverable.** `report_export` already writes a branded
  `report.html` for that.
- **Not a trend tool.** No multi-week history, no debt half-life, no per-scan
  time series. The window is the latest scan plus two deltas (§7).

Nothing here runs a scan, mutates the database, opens a socket, or reaches the
network. If there is no scan to show, both views say which command to run.

## 2. The rule that governs the design

A dashboard is the easiest place in this product to tell the lie the whole
project has spent five features fighting: **something that did not happen
acquiring the appearance of having happened.** A large green "0 critical
findings" with Semgrep, Trivy and gitleaks missing is that same lie with better
typography.

So, in both views:

> **Partial coverage disqualifies the verdict.** When any tool the scan
> intended to run did not run, neither view shows an all-clear state. Both show
> what was *not* looked at, and both say **what the numbers therefore do not
> contain** — naming the tools.

This is the same rule that made exit code `2` exist in item 5: a missing
scanner is a coverage gap, never a pass. The finding counts are not wrong; they
are *incomplete*, and the difference has to be on the screen, not in the
reader's head.

The corollary binds the risk score too: a score computed over a partial scan is
presented with its coverage caveat attached, never as a bare number.

## 3. Architecture

One query pass, two thin renderers — the shape item 5 validated, where
`gate.ts` was pure and testable and `report.ts` rendered three formats without
re-querying anything.

```text
mcp/src/dashboard/
  types.ts       — DashboardSnapshot and its parts
  snapshot.ts    — buildSnapshot(storage, projectPath): DashboardSnapshot
  risk.ts        — scoreRisk(input): RiskAssessment          (pure)
  delta.ts       — compareFindings(from, to): FindingDelta    (pure)
  hotspots.ts    — rankFiles(findings, limit): Hotspot[]      (pure)
  renderStatus.ts  — renderStatus(snapshot): string           (pure)
  renderHtml.ts    — renderDashboard(snapshot): string        (pure)
```

`snapshot.ts` is the only module that touches storage. Everything else is a
pure function over data, which is what makes the numbers testable without a
database and guarantees the two views cannot disagree: there is one source and
it is computed once.

`cli/dev-guardian.mjs` gains `status` and `dashboard`, both thin — they resolve
the project path, open storage read-only, call `buildSnapshot`, render, write
or print. The `.mjs` stays a shim, as item 5 established.

### 3.1 Reusing the existing scoring, correctly

`risk_score`'s current weights and bands are the product's answer to "should I
worry" and are kept verbatim: findings ≤40 (critical 10, high 5, medium 2, low
1), CVEs ≤30, compliance ≤15, baseline staleness ≤15; bands critical ≥70, high
≥40, medium ≥15.

What changes is *where they live*. Today they sit inside the tool handler and
read `findings.listOpen()`. That method's contract — documented at
`mcp/src/storage/findingsRepo.ts:174-191` — is deliberately "the latest
completed scan in the whole database, from any project", which is **correct**
for a tool that takes no `project_path`. It is equally deliberately forbidden
to a caller that *has* resolved a project path, because it would hand that
caller another project's findings whenever that project scanned more recently,
and the result never looks wrong. `validate_finding` made exactly that mistake.

The dashboard resolves a project path. So this work extracts the scoring into
`risk.ts` as a pure function over already-scoped inputs, and leaves
`tools/riskScore.ts` as a thin wrapper preserving its existing contract and
output shape. This is not a bug fix; it is respecting a boundary that is
already written down. **`risk_score`'s public behaviour must not change** —
that is a testable requirement, not an aspiration.

The same applies to `diff_scans` (`tools/diffScans.ts:115`, `:153`), which uses
the unscoped `scans.getLatest()` and `listHistory(200)`. The dashboard does not
call it; it uses `delta.ts` over project-scoped scans. `diff_scans` is left
alone.

## 4. Project scoping — non-negotiable

Every query the snapshot makes is filtered by `project_path`, using the
`ForProject` repository variants that already exist: `scans.getLatestForProject`,
`findings.listOpenForProject`, `surface.getLatestForProject`.

Where a scoped variant does **not** exist for something the snapshot needs
(scan history for the project, so the previous scan of the same type can be
found), it is added to the repository as SQL with a `project_path` filter,
beside the existing method — never worked around in JavaScript by fetching
everything and filtering, which silently truncates at the existing `LIMIT`.

Grouping work — by severity, category, tool and file — happens **in JavaScript**
over the already-fetched project findings, not in new SQL. The set is bounded
by one scan's findings, the grouping is pure and therefore testable without a
database, and it keeps the SQL surface small.

## 5. The snapshot

```ts
export interface DashboardSnapshot {
  project_path: string;
  generated_at: string;               // ISO
  scan: ScanSummary | null;           // null ⇒ nothing scanned yet
  coverage: CoverageState;
  risk: RiskAssessment;
  findings: FindingsSummary;
  cves: CveSummary;
  deltas: { since_previous: FindingDelta | null; since_baseline: FindingDelta | null };
  baseline: BaselineState;
  suppressions: SuppressionState;
  truncation: TruncationNotice[];     // empty when nothing was capped
}

export interface CoverageState {
  level: 'full' | 'partial' | 'none';
  tools_run: string[];
  missing_tools: string[];
  /** Rendered verbatim by both views. Empty iff level === 'full'. */
  omitted_categories: string[];       // e.g. ['container', 'secrets']
}

export interface ScanSummary {
  scan_id: string; scan_type: string; status: string;
  started_at: string; finished_at: string | null;
  duration_seconds: number | null;    // null while running or on a crash
  age_seconds: number;
}

export interface RiskAssessment {
  score: number; band: 'low' | 'medium' | 'high' | 'critical';
  /** Shaped to match `risk_score`'s existing wire output exactly, so the tool
   *  can map this to its response without inventing or dropping a field. */
  components: {
    findings: { score: number; open_findings: number };
    cves: { score: number; active_cves: number };
    compliance: { score: number; policies_missing: number };
    baseline: { score: number; has_active_baseline: boolean };
  };
  next_action: string;                // → the tool's `recommended_next_action`
  /** True when computed over a partial scan. Both views must show this.
   *  Not part of `risk_score`'s output; the tool drops it. */
  coverage_caveat: boolean;
}

export interface FindingsSummary {
  total: number;
  by_severity: Record<Severity, number>;
  by_category: Record<string, number>;
  by_tool: Record<string, number>;
  hotspots: Hotspot[];                // file + count, descending
  items: Finding[];                   // possibly capped — see §8
}

export interface FindingDelta {
  from_scan_id: string; to_scan_id: string;
  new_count: number; resolved_count: number; unchanged_count: number;
  new_findings: Finding[];            // possibly capped — see §8
}

export interface TruncationNotice {
  what: string;                       // 'findings' | 'new_findings' | …
  shown: number; total: number; reason: string;
}

export interface Hotspot { file_path: string; count: number }

export interface CveSummary {
  total: number;
  by_severity: Record<Severity, number>;
  items: Cve[];                       // as cvesRepo already returns them
}

export interface BaselineState {
  /** null ⇒ no baseline has ever been set for this project. */
  active: { baseline_id: number; scan_id: string; set_at: string; note?: string } | null;
  age_days: number | null;            // null iff active is null
}

export interface SuppressionState {
  active_count: number;
  /** Active suppressions expiring within 7 days, soonest first. */
  expiring_soon: { fingerprint: string; reason: string; expires_at: string }[];
}
```

`Severity`, `Finding` and `Cve` are the existing types from `mcp/src/types.ts`
and are imported, not redefined.

`coverage.omitted_categories` exists so the views can state consequences rather
than tool names alone: "gitleaks did not run" is inert to a reader who does not
know what gitleaks finds; "secret findings are not in these numbers" is not.
The mapping from tool to category is a small static table in `types.ts`, and a
tool absent from that table contributes its own name rather than being dropped.

## 5.1 What happens with no data

`scan === null` when the project has no completed scan. Both views then print a
single line naming the command to run (`dev-guardian scan`, or `/guardian-scan`
inside Claude Code) and exit **0** — an empty database is not an error. Every
other field carries its empty value; no view may render `undefined`, `NaN`, or
a risk score computed from nothing. `risk` in this state is
`{score: 0, band: 'low', …, coverage_caveat: true}` with `next_action` naming
the scan command, because a project nobody has scanned is *unknown*, not safe.

## 6. The terminal screen

`dev-guardian status`, ~18 lines, fitting one screen:

```text
dev-guardian · <project>                       scan 2h ago · security_full · 47s

  RISK  62/100  HIGH                     ⚠ partial coverage — 2 scanners missing
  →  Fix the 3 critical findings in src/auth/ first.

  OPEN         3 crit   12 high   31 med   58 low            104
  CVES         1 crit    4 high                                5

  SINCE LAST SCAN       +2 new     -7 resolved
  SINCE BASELINE       +19 new    -31 resolved            set 34d ago

  HOTTEST      src/auth/session.ts   11
               src/api/users.ts       8
               src/db/query.ts        6

  MISSING      trivy, gitleaks — container and secret findings are NOT in these numbers
  SUPPRESSED   6 active · 1 expires in 3 days

  full detail: dev-guardian dashboard
```

Rules the renderer must honour:

- **The `MISSING` line is not optional and not last-resort.** When coverage is
  partial it appears, and it states the consequence, not just the tool names.
  When coverage is full the line is absent entirely rather than saying "none".
- Sections with nothing to say are **omitted**, not printed empty — no
  `SUPPRESSED  0 active`. Exception: `OPEN` with a zero total prints, because
  "zero open findings" is the answer the user came for.
- `HOTTEST` shows at most 3 files; if more files have findings, the count of
  the remainder is appended to the section, never dropped silently.
- No colour codes when stdout is not a TTY, so the output pipes cleanly.
- Exit code is **0** whenever the view rendered, including with findings
  present. `status` reports; it does not gate. Gating is `scan`'s job and has
  its own exit codes. A usage error is `3`, matching item 5's `CI_EXIT`.

## 7. The two deltas

Shown side by side because they answer different questions:

- **Since last scan** — the previous *completed* scan **of the same
  `scan_type`, for this project**. Comparing a `security_full` against a
  `secrets`-only run would report every SAST finding as "new".
- **Since baseline** — the scan the active baseline points at. This measures
  accumulated drift, not the last change.

Both are computed by `compareFindings(from, to)` over fingerprint sets:
`new` = in `to` not in `from`; `resolved` = in `from` not in `to`;
`unchanged` = in both. Suppressed findings are excluded from **both** sides
before comparison, so suppressing something does not appear as "resolved".

Either delta is `null` when its reference does not exist — no previous scan of
that type, or no baseline set. `null` renders as an explicit absence
("no baseline set"), never as zeros, which would read as "nothing changed".

## 8. Caps, and saying so

The HTML inlines finding data as JSON. Findings are capped at **2000** items
and new-findings-per-delta at **500**. When a cap bites, a `TruncationNotice`
is added and **both views render it**: the table header states how many of how
many are shown and why.

There is no silent truncation anywhere. This is item 5's rule — a bounded
output that does not say it is bounded reads as "this is everything".

## 9. The HTML page

`dev-guardian dashboard` writes `<project>/.guardian/dashboard.html` and prints
the path.

- **Self-contained.** All data inlined in one
  `<script type="application/json" id="guardian-data">`; all CSS and JS inline.
  No `<link>`, no CDN, no font fetch, no network of any kind — the same
  property `report_export`'s HTML already has, and the reason its footer can
  say "generated locally · no telemetry".
- **Built on `mcp/src/report/htmlTheme.ts`**, which already provides the
  document shell, the dark/light theme with its no-flash inline script,
  `severityChip`, `severityBar`, `SEVERITY_COLORS` and the print stylesheet.
  This work adds a dashboard-specific section renderer and the interaction
  script; it does not fork the theme.
- **Interaction, in vanilla JS, no dependencies:** filter findings by severity,
  tool, category and file; sort the table by any column; expand a row for the
  message and snippet. Filtering is client-side over the inlined data — there
  is nothing to ask a server for, because there is no server.
- **Coverage banner.** When coverage is partial the page carries a banner, not
  a footnote, stating the missing tools and the omitted categories.
- **Opens the browser only when stdout is a TTY**, so it never tries inside a
  pipeline. `--no-open` suppresses it; `--out <path>` overrides the location.
  The platform open command is `start` / `open` / `xdg-open`, chosen by
  `process.platform`, spawned with `shell: false`.

## 10. `/guardian-status`

The slash command keeps its prompt, but stops improvising the numbers: it
invokes `dev-guardian status`, shows that output, and the model adds
interpretation on top. Deterministic underneath, useful above.

Two of its current seven sections have no data source and are handled honestly
rather than dropped in silence:

- **"Understanding gate"** reads `.guardian/last-grill.md`, a file the
  `guardian-grill` skill writes. That is a real file, not a table; the command
  keeps reading it directly. Out of scope for the CLI.
- **"Last commands run"** has no backing table anywhere in the schema. It is
  **removed** from the command. Building an invocation log to satisfy a
  display line is scope this feature does not carry, and leaving the line in
  invites the model to fabricate it — which is the §2 failure in miniature.

## 11. Testing

- **Pure modules** (`risk`, `delta`, `hotspots`, `renderStatus`, `renderHtml`)
  get unit tests over fixture snapshots, no database.
- **`snapshot.ts`** gets tests against an in-memory database
  (`openDatabase({inMemory: true})`), including: two projects in one database,
  asserting the snapshot returns only the requested one — the `listOpen`
  hazard, tested rather than trusted.
- **`risk_score`'s public output must be unchanged** by the extraction. A
  characterisation test asserts the tool's response for a fixed database state
  before and after; this is the test that makes §3.1 a requirement.
- **The coverage rule (§2) is tested as behaviour, not as a field:** a snapshot
  with a missing tool must produce a terminal screen containing the consequence
  sentence and an HTML page containing the banner. An assertion that
  `coverage.level === 'partial'` tests the data, not the promise.
- **The HTML is parsed, not string-matched**, for the assertions that matter:
  that the inlined JSON is valid JSON and round-trips, and that no `<script
  src>`, `<link href>` or absolute `http(s)://` asset URL appears anywhere in
  the document. A page that quietly gains a CDN dependency breaks the offline
  guarantee and no visual check would catch it.
- **A CLI end-to-end test** runs both subcommands as real subprocesses against
  a fixture project, asserting exit codes and that `dashboard` writes a file
  that parses.

## 12. Limitations, stated plainly

- **The page is a snapshot, not live.** It is accurate as of the moment it was
  generated and does not change when a new scan runs. Regenerate it. This is
  the cost of having no server, which is the trade that keeps the feature
  dependency-free and offline.
- **The window is the latest scan and two deltas.** There is no multi-week
  trend, no chronic-finding history, no "debt half-life". `/guardian-trend`
  continues to ask for things nothing computes; this work does not change that
  and does not pretend to.
- **The risk score is a heuristic**, unchanged from `risk_score` and carrying
  its existing weights. It is a prioritisation aid, not a measurement.
- **Coverage is only as honest as `missing_tools`.** The snapshot reports what
  the scan recorded as missing. A scanner that ran but silently produced
  nothing — a broken rule pack, an unreadable path — is indistinguishable from
  a clean result at this layer, and neither view can detect it.
- **Hotspots are counts, not severity-weighted.** A file with 11 low findings
  outranks one with 2 criticals. The severity columns are there to read
  alongside; the ranking itself is deliberately simple.
