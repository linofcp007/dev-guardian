/**
 * `renderStatus` — the one-screen terminal view behind `dev-guardian status`.
 *
 * Pure: a `DashboardSnapshot` in, a string out. No storage, no clock, no I/O
 * — every relative time shown (scan age, baseline age, suppression expiry)
 * is derived from fields the snapshot already carries (`age_seconds`,
 * `age_days`, `generated_at`), never from `Date.now()`.
 *
 * See docs/superpowers/specs/2026-08-15-local-dashboard-design.md §6 for the
 * layout and content rules this reproduces. Column positions there are not
 * load-bearing (this module does not try to right-align to a terminal
 * width); the content rules are, and two of them carry the feature's
 * governing promise (§2) into this specific view:
 *
 *  - Partial coverage never renders a bare verdict. `missingLine` states the
 *    CONSEQUENCE of what did not run ("<categories> findings are NOT in
 *    these numbers"), not just the tool names — and is omitted entirely,
 *    never printed empty, when coverage is full (§6: "the line is absent
 *    entirely rather than saying 'none'").
 *  - An absent delta (no previous scan of this type, no baseline set)
 *    renders as an explicit sentence, never as `+0 new  -0 resolved`, which
 *    would read as "nothing changed" when the truth is "nothing to compare
 *    against" (§7).
 */

import type {
  CoverageState,
  CveSummary,
  DashboardSnapshot,
  FindingDelta,
  FindingsSummary,
  Hotspot,
  SuppressionState,
  TruncationNotice,
} from './types.js';

const RESET = '\u001b[0m';

/**
 * Wraps `text` in an SGR colour code, or returns it unchanged when `color`
 * is off. Every call site paints a fragment inline, at the point it is
 * composed, rather than post-processing a finished line — so the plain and
 * coloured builds walk the exact same construction logic and differ ONLY by
 * the presence of these wrapper codes. That is what guarantees stripping
 * ANSI from the coloured output reproduces the uncoloured output exactly
 * (see the "emits no ANSI escapes" test): there is one code path, not two
 * that could quietly drift apart on spacing or content.
 */
function paint(text: string, code: string, color: boolean): string {
  return color ? `\u001b[${code}m${text}${RESET}` : text;
}

const BAND_CODE: Record<'low' | 'medium' | 'high' | 'critical', string> = {
  low: '32', // green
  medium: '33', // yellow
  high: '31', // red
  critical: '1;31', // bold red
};

const SEVERITY_CODE: Record<'critical' | 'high' | 'medium' | 'low' | 'info', string> = {
  critical: '1;31',
  high: '31',
  medium: '33',
  low: '34',
  info: '90',
};

export function renderStatus(snapshot: DashboardSnapshot, opts: { color: boolean }): string {
  const { color } = opts;

  // §5.1: a project with no completed scan gets a single-line pointer to the
  // command that produces one, never the full layout built over empty data.
  if (snapshot.scan === null) {
    return [
      `dev-guardian · ${snapshot.project_path}`,
      '',
      '  No scan yet — run `dev-guardian scan` (or `/guardian-scan` inside Claude Code) to get started.',
    ].join('\n');
  }
  const scan = snapshot.scan;

  const lines: string[] = [];

  lines.push(
    `dev-guardian · ${snapshot.project_path}   scan ${formatAge(scan.age_seconds)} · ` +
      `${scan.scan_type} · ${formatDuration(scan.duration_seconds, scan.status)}`,
  );
  lines.push('');

  lines.push(renderRiskLine(snapshot.risk, snapshot.coverage, color));
  lines.push(`  →  ${snapshot.risk.next_action}`);
  lines.push('');

  lines.push(renderOpenLine(snapshot.findings, color));
  const cvesLine = renderCvesLine(snapshot.cves, color);
  if (cvesLine !== null) lines.push(cvesLine);
  lines.push('');

  lines.push(renderSincePrevious(snapshot.deltas.since_previous, scan.scan_type, color));
  lines.push(renderSinceBaseline(snapshot.deltas.since_baseline, snapshot.baseline.age_days, color));
  lines.push('');

  const hottest = renderHottest(snapshot.findings.hotspots);
  if (hottest.length > 0) {
    lines.push(...hottest);
    lines.push('');
  }

  // MISSING / SUPPRESSED / truncation notices: each is independently
  // omitted when it has nothing to say (design §6: "sections with nothing
  // to say are omitted, not printed empty"), so this whole block — and its
  // trailing separator — disappears when there is nothing to report.
  const trailing: string[] = [];
  const missing = renderMissingLine(snapshot.coverage, color);
  if (missing !== null) trailing.push(missing);
  const suppressed = renderSuppressedLine(snapshot.suppressions, snapshot.generated_at);
  if (suppressed !== null) trailing.push(suppressed);
  trailing.push(...renderTruncationLines(snapshot.truncation));
  if (trailing.length > 0) {
    lines.push(...trailing);
    lines.push('');
  }

  lines.push('  full detail: dev-guardian dashboard');

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Header helpers
// ---------------------------------------------------------------------------

function formatAge(ageSeconds: number): string {
  const s = Math.max(0, Math.floor(ageSeconds));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86_400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86_400)}d ago`;
}

/** `status` carries the reason when there is no duration to show (a scan
 *  still `running`, or one that ended in `failed`/`cancelled`) — showing
 *  that instead of a blank or a fabricated number is what keeps this
 *  branch from ever rendering "NaNs". */
function formatDuration(durationSeconds: number | null, status: string): string {
  if (durationSeconds === null) return status;
  const s = Math.max(0, Math.floor(durationSeconds));
  if (s < 60) return `${s}s`;
  return `${Math.floor(s / 60)}m ${s % 60}s`;
}

// ---------------------------------------------------------------------------
// RISK
// ---------------------------------------------------------------------------

/**
 * Design §2's corollary: "a score computed over a partial scan is presented
 * with its coverage caveat attached, never as a bare number." Reads
 * `risk.coverage_caveat` specifically (not `coverage.level`) because that is
 * the field `RiskAssessment` documents as carrying this exact promise —
 * independent of `missingLine` below, which reads `coverage.omitted_categories`
 * for the same underlying fact. The two are always in sync in a real
 * snapshot (`snapshot.ts` derives both from the same `coverage.level`), but
 * each renderer here honours the contract of the field it was given, rather
 * than cross-deriving from a sibling.
 *
 * **The "N scanners missing" clause only when N > 0** (coordinator review,
 * Important). `snapshot.ts`'s `cveGap` can put coverage into `'partial'`
 * with `missing_tools` genuinely empty — no scanner failed to run, there is
 * simply no `deps`/`security_full` scan anywhere in this project's history to
 * source CVE data from. Counting tools unconditionally then printed the
 * self-contradicting "⚠ partial coverage — 0 scanners missing", which reads
 * as "this warning is noise" — the opposite of what a real coverage gap
 * should say. When there is nothing to count, this names the gap instead,
 * from `coverage.omitted_categories` — the same field `missingLine` already
 * uses for its own "what these numbers do not contain" clause — so the two
 * lines never disagree about what's missing, only about whether a tool is to
 * blame for it.
 */
function renderRiskLine(
  risk: DashboardSnapshot['risk'],
  coverage: CoverageState,
  color: boolean,
): string {
  const cluster = paint(`${risk.score}/100  ${risk.band.toUpperCase()}`, BAND_CODE[risk.band], color);
  let caveat = '';
  if (risk.coverage_caveat) {
    const n = coverage.missing_tools.length;
    const text = n > 0
      ? `⚠ partial coverage — ${n} ${n === 1 ? 'scanner' : 'scanners'} missing`
      : `⚠ partial coverage — ${coverage.omitted_categories.join(', ')} findings are NOT in these numbers`;
    caveat = `   ${paint(text, '33', color)}`;
  }
  return `  RISK  ${cluster}${caveat}`;
}

// ---------------------------------------------------------------------------
// OPEN / CVES
// ---------------------------------------------------------------------------

/**
 * Unlike CVES below, OPEN always prints every severity column, even at
 * zero — design §6's explicit exception: "OPEN with a zero total prints,
 * because 'zero open findings' is the answer the user came for."
 *
 * **`info` has its own column too** (coordinator review, Minor). It used to
 * be counted in `findings.total` but never shown, so a reader could see
 * "2 crit 2 high 1 med 2 low" beside a total of 8 with the arithmetic
 * visibly one short — the HTML view never had this gap, since `severityBar`
 * (`report/htmlTheme.ts`) always includes `info`. Showing it here, rather
 * than excluding it from the total, keeps `findings.total` meaning the same
 * count everywhere it is used (including `risk.components.findings.
 * open_findings`) instead of inventing a terminal-only subset total that
 * would then disagree with the very field it is computed from.
 */
function renderOpenLine(findings: FindingsSummary, color: boolean): string {
  const s = findings.by_severity;
  const parts = [
    paint(`${s.critical} crit`, SEVERITY_CODE.critical, color),
    paint(`${s.high} high`, SEVERITY_CODE.high, color),
    paint(`${s.medium} med`, SEVERITY_CODE.medium, color),
    paint(`${s.low} low`, SEVERITY_CODE.low, color),
    paint(`${s.info} info`, SEVERITY_CODE.info, color),
  ];
  return `  OPEN         ${parts.join('   ')}          ${findings.total}`;
}

/**
 * CVES, unlike OPEN, is omitted entirely when `total` is 0 (nothing carves
 * out an exception for it the way §6 does for OPEN), and within a non-empty
 * line only shows the severities that are actually non-zero — matching the
 * design §6 mock, which shows "1 crit  4 high" with no "0 med  0 low".
 */
function renderCvesLine(cves: CveSummary, color: boolean): string | null {
  if (cves.total === 0) return null;
  const s = cves.by_severity;
  const parts: string[] = [];
  if (s.critical > 0) parts.push(paint(`${s.critical} crit`, SEVERITY_CODE.critical, color));
  if (s.high > 0) parts.push(paint(`${s.high} high`, SEVERITY_CODE.high, color));
  if (s.medium > 0) parts.push(paint(`${s.medium} med`, SEVERITY_CODE.medium, color));
  if (s.low > 0) parts.push(paint(`${s.low} low`, SEVERITY_CODE.low, color));
  const breakdown = parts.length > 0 ? `${parts.join('   ')}   ` : '';
  return `  CVES         ${breakdown}${cves.total}`;
}

// ---------------------------------------------------------------------------
// Deltas — the "explicit absence, never zeros" rule (design §7)
// ---------------------------------------------------------------------------

/**
 * Takes `scanType` as its own parameter (the caller's already-narrowed
 * `scan.scan_type`, not `snapshot.scan` again) rather than the whole
 * snapshot — `snapshot.scan` is `ScanSummary | null` from this function's
 * own point of view, and the caller having already handled the null case
 * does not narrow it here too. Threading the narrowed value through avoids
 * re-deriving it with a fallback that could paper over a real gap.
 */
function renderSincePrevious(delta: FindingDelta | null, scanType: string, color: boolean): string {
  if (delta === null) {
    return `  SINCE LAST SCAN     no previous ${scanType} scan to compare`;
  }
  const added = paint(`+${delta.new_count} new`, '31', color);
  const resolved = paint(`-${delta.resolved_count} resolved`, '32', color);
  return `  SINCE LAST SCAN     ${added}   ${resolved}`;
}

function renderSinceBaseline(delta: FindingDelta | null, ageDays: number | null, color: boolean): string {
  if (delta === null) {
    return '  SINCE BASELINE      no baseline set';
  }
  const added = paint(`+${delta.new_count} new`, '31', color);
  const resolved = paint(`-${delta.resolved_count} resolved`, '32', color);
  const suffix = ageDays === null ? '' : `   set ${ageDays}d ago`;
  return `  SINCE BASELINE      ${added}   ${resolved}${suffix}`;
}

// ---------------------------------------------------------------------------
// HOTTEST — at most 3 files, remainder counted rather than dropped (§6)
// ---------------------------------------------------------------------------

function renderHottest(hotspots: readonly Hotspot[]): string[] {
  if (hotspots.length === 0) return [];
  const shown = hotspots.slice(0, 3);
  const lines: string[] = [];
  let isFirst = true;
  for (const h of shown) {
    const label = isFirst ? '  HOTTEST      ' : '               ';
    lines.push(`${label}${h.file_path}   ${h.count}`);
    isFirst = false;
  }
  const remaining = hotspots.length - shown.length;
  if (remaining > 0) {
    lines.push(`               +${remaining} more file${remaining === 1 ? '' : 's'} with findings`);
  }
  return lines;
}

// ---------------------------------------------------------------------------
// MISSING — the governing rule (§2), made visible
// ---------------------------------------------------------------------------

/**
 * `coverage.omitted_categories` is "rendered verbatim by both views" (see
 * its doc comment in `types.ts`) — this function joins it and
 * `missing_tools` for display, but does not paraphrase or grammatically
 * merge the category strings themselves. Absent (returns null) exactly when
 * `omitted_categories` is empty, which `types.ts` documents as happening iff
 * coverage is full — never printed as "MISSING: none".
 *
 * **"did not run this scan" only for tools that actually didn't run**
 * (coordinator review, Important). `coverage.missing_tools` can name a tool
 * that DID run — `coverage.partial_tools` (a subset of `missing_tools`)
 * flags exactly that: `bug_hunt` retrying with a surviving Semgrep pack
 * lands `semgrep` in both `missing_tools` (a real gap: one pack never ran)
 * and `partial_tools` (the tool itself is 'ok', with real findings already
 * on screen). Printing "semgrep did not run this scan" there would be false
 * — a scan with `by_tool: {semgrep: 1}` did run it. Split into two lines,
 * each naming only the tools its own claim is true for; either half is
 * omitted when it has nothing to name, matching design §6.
 */
function renderMissingLine(coverage: CoverageState, color: boolean): string | null {
  if (coverage.omitted_categories.length === 0) return null;
  const categories = coverage.omitted_categories.join(', ');
  const partial = coverage.partial_tools ?? [];
  const fullyMissing = coverage.missing_tools.filter((t) => !partial.includes(t));
  if (fullyMissing.length === 0 && partial.length === 0) {
    // No tool to name at all (e.g. the CVE-source gap alone: missing_tools
    // is genuinely empty, only omitted_categories carries the gap) —
    // unchanged from before this fix.
    const text = `MISSING      ${coverage.missing_tools.join(', ')} — ${categories} findings are NOT in these numbers`;
    return `  ${paint(text, '33', color)}`;
  }
  const lines: string[] = [];
  if (fullyMissing.length > 0) {
    const tools = fullyMissing.join(', ');
    lines.push(`MISSING      ${tools} did not run this scan — ${categories} findings are NOT in these numbers`);
  }
  if (partial.length > 0) {
    const tools = partial.join(', ');
    lines.push(`PARTIAL      ${tools} ran with reduced coverage — some ${categories} findings may be missing`);
  }
  return lines.map((text) => `  ${paint(text, '33', color)}`).join('\n');
}

// ---------------------------------------------------------------------------
// SUPPRESSED
// ---------------------------------------------------------------------------

function renderSuppressedLine(s: SuppressionState, generatedAt: string): string | null {
  if (s.active_count === 0) return null;
  const soonest = s.expiring_soon[0];
  let extra = '';
  if (soonest !== undefined) {
    const days = daysUntil(soonest.expires_at, generatedAt);
    if (days !== null) {
      const count = s.expiring_soon.length;
      extra = ` · ${count} expire${count === 1 ? 's' : ''} in ${days} day${days === 1 ? '' : 's'}`;
    }
  }
  return `  SUPPRESSED   ${s.active_count} active${extra}`;
}

/**
 * Both timestamps come from the snapshot (`expires_at`, and `generated_at`
 * as the snapshot's own "as of" instant) — never `Date.now()`, which is what
 * keeps this module clockless. Returns null rather than NaN when either
 * timestamp fails to parse, so a malformed date degrades to "omit the day
 * count" instead of printing garbage.
 */
function daysUntil(iso: string, referenceIso: string): number | null {
  const target = Date.parse(iso);
  const reference = Date.parse(referenceIso);
  if (Number.isNaN(target) || Number.isNaN(reference)) return null;
  return Math.max(0, Math.ceil((target - reference) / 86_400_000));
}

// ---------------------------------------------------------------------------
// Truncation notices (design §8: no cap is ever silent)
// ---------------------------------------------------------------------------

function renderTruncationLines(notices: readonly TruncationNotice[]): string[] {
  return notices.map(
    (n) => `  NOTE         ${n.what}: showing ${n.shown} of ${n.total} (${n.reason})`,
  );
}
