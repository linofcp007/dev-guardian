/**
 * Render a `GateVerdict` for a CI consumer: human-readable text (the
 * default), JSON (for scripting), and SARIF (for GitHub/GitLab/Azure
 * code-scanning upload — the reason this task exists at all; see the design
 * of record).
 *
 * Pure: every renderer takes everything it needs as an argument — no
 * filesystem access, no clock, no environment lookups. `renderSarif` alone
 * also takes `projectPath`, because a SARIF `artifactLocation.uri` is
 * resolved by the *consumer* (GitHub, GitLab, ...) against the repository
 * checkout root: an absolute path — POSIX or a Windows drive letter —
 * matches nothing there, so the finding lands in the results list with no
 * line annotation on the diff, which is the entire point of shipping SARIF
 * (the design of record, task resolution #2). See `toProjectRelativeUri`.
 *
 * SARIF generation is delegated to `../report/sarif.ts#toSarif`, the
 * project's existing SARIF producer (already used by the `report_export`
 * and `scan_skill` tools), rather than a second one. This module's own job
 * is limited to what CI specifically needs on top of that: relativised
 * URIs; `invocation.executionSuccessful` tied to `coverage`, so a consumer
 * reading only the SARIF upload can tell an incomplete scan from a clean one
 * without cross-referencing the exit code; and, for the one requirement
 * carried forward from Task 2 (see `renderSarif` below), a place for the
 * dropped-baseline-entries gap to surface via SARIF's own
 * `toolExecutionNotifications` mechanism. The design of record originally read as
 * keeping ALL of `coverage` out of SARIF; it is being amended (see the task
 * report) to describe this — the coarse boolean signal in SARIF natively,
 * general coverage-gap prose (tool names, "not installed" reasons) still
 * out of it entirely.
 */

import { SEVERITIES, type Finding, type Severity } from '../types.js';
import { untrustedText } from '../platform/untrustedText.js';
import { toSarif, type SarifSuppressed } from '../report/sarif.js';
import { suppressionNote } from '../runners/trivyRun.js';
import {
  CI_EXIT,
  type AcceptedGapDetail,
  type BaselineSource,
  type CiExitCode,
  type CoverageGapDetail,
  type ExclusionReset,
  type RulesSource,
} from './types.js';
import type { GateVerdict, RepoSuppressionEntry } from './gate.js';

/**
 * How the CLI is run, in the commands a report tells its reader to run. A
 * plugin install puts no `dev-guardian` on PATH, so `cli/dev-guardian.mjs`
 * passes the runnable `node "<plugin root>/cli/dev-guardian.mjs"` (review 8,
 * C7); the default is what works from a dev-guardian checkout's root.
 */
export const DEFAULT_CLI_COMMAND = 'node cli/dev-guardian.mjs';

export interface HumanOptions {
  /** See {@link DEFAULT_CLI_COMMAND}. */
  command?: string;
}

const EXIT_LABEL: Record<CiExitCode, string> = {
  [CI_EXIT.PASS]: 'PASS',
  [CI_EXIT.GATE_FAILED]: 'GATE FAILED',
  [CI_EXIT.INCOMPLETE_SCAN]: 'INCOMPLETE SCAN',
  [CI_EXIT.USAGE_ERROR]: 'USAGE ERROR',
};

// ---------------------------------------------------------------------------
// Human
// ---------------------------------------------------------------------------

/**
 * The headline always names the exit-code state, not just a finding count.
 * `evaluateGate` exits INCOMPLETE_SCAN whenever coverage isn't 'full', even
 * with zero new findings (a missing scanner reporting nothing is not a clean
 * scan) — a reader must be able to tell that apart from a genuine, clean
 * PASS at a glance, not by cross-referencing the coverage line themselves.
 *
 * `coverageGaps` is printed in full whenever non-empty, and `coverageNotes`
 * under `notes (not gating):`. That is also how the dropped-baseline-entries
 * line (carried forward from Task 2's review) reaches human output: a note
 * since 3.4 (it never gated, and `coverage_gaps` holds the gaps that do —
 * review 10), so it needs no special case here — contrast `renderSarif`,
 * which does need one, because SARIF has no general-purpose home for free text.
 *
 * `baselineAbsent` (added on review of this task) gets its own line, printed
 * plainly rather than folded into `coverageGaps`: the design of record requires the
 * CLI to say so on a first run and to name `baseline update` as the fix, and
 * that is a one-time onboarding fact about the whole run, not a per-scanner
 * gap. It cannot be inferred from `newFindings`/`coverageGaps` — an absent
 * baseline and a present-but-empty one make every finding "new" identically
 * — which is exactly why `GateVerdict` carries it as its own field (see
 * `gate.ts`) rather than this function trying to derive it.
 */
export function renderHuman(v: GateVerdict, opts: HumanOptions = {}): string {
  const command = opts.command ?? DEFAULT_CLI_COMMAND;
  const lines: string[] = [
    `dev-guardian CI: ${EXIT_LABEL[v.exitCode]} (exit code ${v.exitCode})`,
    // Right under the verdict: a pass with accepted gaps is not a pass over
    // every file (review 11, finding 1) — said where a reader looks first.
    ...acceptedSummary(v),
    `coverage: ${v.coverage}`,
    // Where the baseline and the rules came from, every run: on a pull
    // request, "the scanned tree's own" is the pull request's (docs/ci.md).
    describeBaselineSource(v.baselineSource),
    describeRulesSource(v.rulesSource),
    ...(v.exclusionsReset !== null ? [describeExclusionReset(v.exclusionsReset)] : []),
  ];

  if (v.baselineAbsent) {
    lines.push(
      v.baselineSource.from === 'ref'
        ? `no usable baseline at ${v.baselineSource.ref}, so every finding counts as new — run ` +
            `\`${command} baseline update --project .\` on that branch and commit .guardian/baseline.json there`
        : 'no baseline found, so every finding counts as new — record one on the base commit with ' +
            `\`${command} baseline update --project .\` and commit .guardian/baseline.json`,
    );
  }

  lines.push(
    `new findings: ${v.newFindings.length} (${v.blocking.length} at or above the fail-on threshold)`,
  );

  // Each gap with what clears it (its remedy: `coverage_gap_details` in the JSON).
  if (v.coverageGaps.length > 0) {
    lines.push('coverage gaps:');
    v.coverageGaps.forEach((gap, i) => {
      lines.push(`  - ${gap}`);
      const remedy = v.coverageGapDetails[i]?.remedy;
      if (remedy !== undefined) lines.push(`    fix: ${remedy}`);
    });
  }

  // Gaps accepted — by `--accept-partial-parse`, or by the project's committed
  // `.guardian/scan.yml` (each line says which) — printed as such: never as
  // coverage gaps, never silently. `coverage:` above still says `partial`.
  if (v.acceptedGaps.length > 0) {
    lines.push('accepted (not gating):');
    for (const gap of v.acceptedGaps) lines.push(`  - ${gap}`);
  }

  // Reported and never gating: the taint analysis's fixpoint timeouts.
  if (v.coverageNotes.length > 0) {
    lines.push('notes (not gating):');
    for (const note of v.coverageNotes) lines.push(`  - ${note}`);
  }
  for (const path of v.unusedPartialParseAcceptances) {
    lines.push(`note: --accept-partial-parse ${path}: no step reported it partly parsed (unused)`);
  }
  for (const path of v.unusedTimeoutAcceptances) {
    lines.push(`note: .guardian/scan.yml semgrep.accept_timeouts ${path}: no step reported a Timeout on it (unused — remove it)`);
  }

  if (v.blocking.length > 0) {
    lines.push('blocking findings:');
    for (const f of v.blocking) lines.push(`  - ${describeFinding(f)}`);
  }

  // Round 4, item 2: what the repository's own .trivyignore silenced left no
  // trace here. Named — never counted, never a gap.
  if (v.suppressedByRepoConfig.length > 0) {
    lines.push("suppressed by the repository's own configuration (not counted by the gate):");
    for (const s of v.suppressedByRepoConfig) lines.push(`  - ${s.step}: ${s.tool}: ${suppressionNote(s)}`);
  }

  // --rules-ref: configuration the tree changes against the ref. What the
  // gate read from the tree anyway comes first — a reviewer's to judge.
  if (v.rulesSource.from === 'ref') {
    const { ref, tree_differences: diffs } = v.rulesSource;
    const applied = diffs.filter((d) => d.applied === 'tree');
    const notApplied = diffs.filter((d) => d.applied === 'ref');
    if (applied.length > 0) {
      lines.push(`read from the scanned tree although it differs from ${ref} (no ref can supply it — review it):`);
      for (const d of applied) lines.push(`  - ${d.path} (${d.change}; read by ${d.read_by.join(', ')})`);
    }
    if (notApplied.length > 0) {
      lines.push(`changed in the scanned tree, not applied (${ref}'s copy was read):`);
      for (const d of notApplied) lines.push(`  - ${d.path} (${d.change})`);
    }
  }

  // Titles, paths and gap reasons come from the scanned repository and its
  // scanners: control, bidi and zero-width characters are written as visible
  // `\u{XXXX}` before they reach a terminal (`platform/untrustedText.ts`).
  return `${untrustedText(lines.join('\n'))}\n`;
}

/**
 * `N file(s) not analysed (accepted)` — and `M file(s) only partly parsed
 * (accepted)` — over the distinct files `acceptedGapDetails` names (one file
 * may be accepted in two steps); no line when nothing was accepted.
 */
function acceptedSummary(v: GateVerdict): string[] {
  const files = (kind: 'file_timeout' | 'partial_parse'): number =>
    new Set(v.acceptedGapDetails.filter((d) => d.kind === kind).map((d) => d.file)).size;
  const timedOut = files('file_timeout');
  const partly = files('partial_parse');
  const parts = [
    ...(timedOut > 0 ? [`${timedOut} file(s) not analysed (accepted)`] : []),
    ...(partly > 0 ? [`${partly} file(s) only partly parsed (accepted)`] : []),
  ];
  return parts.length > 0 ? [`${parts.join(', ')} — listed under "accepted (not gating)"`] : [];
}

function shortCommit(commit: string): string {
  return commit.slice(0, 12);
}

/** The one line naming where the baseline came from. */
function describeBaselineSource(b: BaselineSource): string {
  if (b.from === 'tree') return `baseline: ${b.path} in the scanned tree (no --baseline-ref)`;
  const at = `${b.ref} (${shortCommit(b.commit)})`;
  const differs = b.tree_differs ? " — the scanned tree's copy differs and was not read" : '';
  return b.present
    ? `baseline: ${b.path} at ${at}${differs}`
    : `baseline: none at ${at}, so every finding is new${differs}`;
}

/** The one line naming what `--reset-exclusions-from` put back before the scan. */
function describeExclusionReset(r: ExclusionReset): string {
  const at = `${r.ref} (${shortCommit(r.commit)})`;
  const parts = [
    ...(r.restored.length > 0 ? [`restored ${r.restored.join(', ')}`] : []),
    ...(r.removed.length > 0 ? [`removed ${r.removed.join(', ')} (none at the ref)`] : []),
  ];
  return parts.length > 0
    ? `exclusion files reset to ${at} before the scan: ${parts.join('; ')}`
    : `exclusion files reset to ${at} before the scan: none differed`;
}

/** The one line naming where the rules and scanner configuration came from. */
function describeRulesSource(r: RulesSource): string {
  if (r.from === 'tree') return "rules and configuration: the scanned tree's own (no --rules-ref)";
  const at = `${r.ref} (${shortCommit(r.commit)})`;
  const read = r.copied.length > 0 ? r.copied.join(', ') : 'none — the ref has none of them';
  const absent = r.absent.length > 0 ? `; not at the ref, so none read: ${r.absent.join(', ')}` : '';
  return `rules and configuration: from ${at}: ${read}${absent}`;
}

function describeFinding(f: Finding): string {
  const location =
    f.file_path !== undefined
      ? ` (${f.file_path}${f.line_start !== undefined ? `:${f.line_start}` : ''})`
      : '';
  return `[${f.severity}] ${f.title}${location}`;
}

// ---------------------------------------------------------------------------
// JSON
// ---------------------------------------------------------------------------

/**
 * The JSON verdict. Its keys are a contract: dev-spec-driven's finish gate
 * (1.29 and later) parses `exit_code`, `coverage_gaps` (a string array, kept
 * so), `new_findings` and `blocking_findings` (`file_path`, `line_start`,
 * `severity`, `rule_id`, `title`, `tool`), and since 1.30 reads
 * `tool_version`, `baseline_absent` / `baseline_status`,
 * `new_findings_count` and the gating `coverage_gap_details` (`tool`, `kind`,
 * `remedy`) when they are there. dev-spec-driven 1.30.x reads neither
 * `coverage` nor `accepted_gaps`; both are documented keys (docs/ci.md) and
 * `test/unit/ci/verdictContract.test.ts` freezes them with the rest. Keys are
 * only ever added.
 */
export interface JsonVerdict {
  /** The dev-guardian version that judged — dev-spec warns below the one it needs. */
  tool_version: string;
  exit_code: CiExitCode;
  coverage: GateVerdict['coverage'];
  coverage_gaps: string[];
  /** Every gap as data: kind, remedy, gating (`gate.ts`). */
  coverage_gap_details: CoverageGapDetail[];
  /** Reported, never gating (taint fixpoint timeouts); not in `coverage_gaps`. */
  coverage_notes: string[];
  /** Every new finding — with `compact`, only the blocking ones. */
  new_findings: Finding[];
  /** How many new findings there are, whatever `new_findings` holds. */
  new_findings_count: number;
  /** New findings per severity, every severity named. */
  new_findings_by_severity: Record<Severity, number>;
  /** `new_findings` holds only the blocking findings (`--compact`). */
  compact: boolean;
  blocking_findings: Finding[];
  baseline_absent: boolean;
  /**
   * `present` or `absent` — never "corrupt": an unreadable baseline is a
   * configuration error (exit 3, the parse error named), not "no baseline".
   */
  baseline_status: 'present' | 'absent';
  accepted_gaps: string[];
  /**
   * One per `accepted_gaps` line, same order: `tool`, `kind` (`file_timeout`
   * or `partial_parse`), `file`, `reason` (3.4.0 and later) — what a reader
   * counts accepted files by, never by parsing the lines.
   */
  accepted_gap_details: AcceptedGapDetail[];
  unused_partial_parse_acceptances: string[];
  /** `.guardian/scan.yml` `semgrep.accept_timeouts` entries no step reported a Timeout on (3.4.0 and later). */
  unused_timeout_acceptances: string[];
  suppressed_by_repo_config: RepoSuppressionEntry[];
  baseline_source: BaselineSource;
  rules_source: RulesSource;
  exclusions_reset: ExclusionReset | null;
}

export interface JsonOptions {
  /** The version that judged; `0.0.0` when the caller cannot tell. */
  toolVersion?: string;
  /**
   * `--compact`: the same keys, `new_findings` cut to the blocking ones.
   * 623 KB of JSON for 487 new findings did not fit an MCP call, nor a
   * terminal tool's output (review 8, C4); the blocking ones and the counts
   * are what a finish gate needs.
   */
  compact?: boolean;
}

/**
 * snake_case keys, matching every other JSON-facing shape in `../types.ts`
 * (`Finding.file_path`, `ScanResult.findings_count_by_severity`, ...) so a
 * script consuming this alongside the rest of dev-guardian's JSON output
 * sees one convention, not two. Every field of `GateVerdict` is carried —
 * this is a full serialisation, not a summary (`compact` aside).
 */
export function renderJson(v: GateVerdict, opts: JsonOptions = {}): string {
  const compact = opts.compact === true;
  const bySeverity = Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as Record<Severity, number>;
  for (const f of v.newFindings) bySeverity[f.severity] += 1;
  const payload: JsonVerdict = {
    tool_version: opts.toolVersion ?? '0.0.0',
    exit_code: v.exitCode,
    coverage: v.coverage,
    coverage_gaps: v.coverageGaps,
    coverage_gap_details: v.coverageGapDetails,
    coverage_notes: v.coverageNotes,
    new_findings: compact ? v.blocking : v.newFindings,
    new_findings_count: v.newFindings.length,
    new_findings_by_severity: bySeverity,
    compact,
    blocking_findings: v.blocking,
    baseline_absent: v.baselineAbsent,
    baseline_status: v.baselineAbsent ? 'absent' : 'present',
    accepted_gaps: v.acceptedGaps,
    accepted_gap_details: v.acceptedGapDetails,
    unused_partial_parse_acceptances: v.unusedPartialParseAcceptances,
    unused_timeout_acceptances: v.unusedTimeoutAcceptances,
    suppressed_by_repo_config: v.suppressedByRepoConfig,
    baseline_source: v.baselineSource,
    rules_source: v.rulesSource,
    exclusions_reset: v.exclusionsReset,
  };
  return JSON.stringify(payload, null, compact ? undefined : 2);
}

// ---------------------------------------------------------------------------
// SARIF
// ---------------------------------------------------------------------------

/**
 * `gate.ts#evaluateGate` always builds the dropped-baseline-entries note with
 * this exact prefix, and no other `coverageNotes` line starts with it — every
 * other line is `${step.tool}: ...`, and no scan step is named "baseline".
 * Matching the prefix (rather than owning a second copy of gate.ts's
 * wording) is what lets `renderSarif` single that one line out from the
 * general scanner-coverage gaps the design of record keeps out of SARIF entirely.
 */
const BASELINE_GAP_PREFIX = 'baseline: ';

interface SarifNotification {
  message: { text: string };
}

interface SarifInvocation {
  executionSuccessful: boolean;
  toolExecutionNotifications?: SarifNotification[];
}

interface SarifRun {
  invocations?: SarifInvocation[];
  [key: string]: unknown;
}

interface SarifDocument {
  runs: SarifRun[];
  [key: string]: unknown;
}

/**
 * SARIF carries findings, plus two narrow, deliberate exceptions for facts
 * about the *run* that change how those findings should be read — not the
 * general coverage-gap prose (tool names, "semgrep not installed" reasons),
 * which has no home in a findings-shaped format and stays
 * exit-code-and-human/JSON-only. The findings the repository's own
 * `.trivyignore` suppressed follow the new ones as results carrying an
 * `external` suppression that names the file (round 4, item 2): SARIF's
 * own way to say "found, and dismissed outside this tool".
 *
 * 1. `invocation.executionSuccessful` is set to `v.coverage === 'full'`.
 *    This is the SARIF-native way to say "this run was incomplete" — a
 *    consumer reading only the SARIF upload can now tell a clean scan from
 *    an incomplete one from this one boolean, without cross-referencing the
 *    exit code, closing the gap the design of record itself named as the reason
 *    exit code 2 has to exist as a separate channel. It is always present
 *    (every call attaches exactly one `invocations` entry), not only when
 *    there is a baseline gap to report alongside it — a fully clean run
 *    still gets an explicit `executionSuccessful: true`, so absence of
 *    `invocations` is never load-bearing for telling the two states apart.
 *
 * 2. A dropped baseline entry (carried forward from Task 2's review) is
 *    attached as a `toolExecutionNotifications` entry on that same
 *    invocation — SARIF's own mechanism for run-level messages that are not
 *    themselves findings. This one stays narrow (only the
 *    dropped-baseline-entries line, matched by prefix, never the general
 *    coverage gaps): it changes how a *result in this very document* should
 *    be read — a "new" finding that only resurfaced because its suppression
 *    entry could not be parsed, not because anyone reintroduced it — which
 *    is a fact about result trustworthiness, not scan completeness, so it
 *    does not piggyback on `executionSuccessful` (a dropped baseline entry
 *    alone must never flip that to `false` — `gate.ts` deliberately keeps
 *    `droppedBaselineEntries` out of `coverage` for the same reason; see the
 *    "surfaces a dropped-baseline-entries gap" test, which pins
 *    `executionSuccessful: true` in exactly this combination).
 *
 * (The design of record originally read as excluding all of `coverage` from SARIF;
 * it is being amended to describe the above, so the doc and this code agree.)
 */
export function renderSarif(v: GateVerdict, projectPath: string, opts: SarifOptions = {}): string {
  // A `file_path` that IS the project root relativises to `''`
  // (`toProjectRelativeUri`'s own "posixFile === posixRoot" branch). Passed
  // through, `toSarif`'s `if (f.file_path)` check (see `../report/sarif.ts`,
  // unmodified) treats that falsy `''` the same as an absent path and omits
  // `locations` entirely, rather than emitting an empty URI. That is the
  // right outcome, not a gap: a finding about the whole project has no
  // single line to annotate, so no location is more honest than one.
  //
  // A code-scanning service resolves a URI against the REPOSITORY root, so a
  // project below it (`scan --project packages/api` in a monorepo) has its
  // place in the repository put in front (review 8, finding 18): a URI
  // relative to the project annotated the wrong file, or none.
  const prefix = normalizeRepoPrefix(opts.repoPrefix);
  const relocate = (f: Finding): Finding => {
    if (f.file_path === undefined) return f;
    const rel = toProjectRelativeUri(f.file_path, projectPath);
    return { ...f, file_path: rel === '' ? '' : `${prefix}${rel}` };
  };
  const relocated: Finding[] = v.newFindings.map(relocate);
  // Round 4, item 2: what the repository's own configuration suppressed, as
  // results carrying an `external` suppression that names the file — how
  // SARIF says "found, and dismissed outside this tool".
  const suppressed: SarifSuppressed[] = v.suppressedByRepoConfig.flatMap((s) =>
    s.findings.map((f) => ({ finding: relocate(f), justification: `suppressed by the repository's ${s.file}` })),
  );

  const parsed: unknown = JSON.parse(toSarif(relocated, { suppressed }));
  // Safe: this is JSON we just produced from `toSarif` on the line above,
  // not untrusted input — a full runtime re-validation of our own output
  // belongs in the schema-validation test, not here.
  const doc = parsed as SarifDocument;

  const baselineGaps = v.coverageNotes.filter((note) => note.startsWith(BASELINE_GAP_PREFIX));
  const run = doc.runs[0];
  if (run !== undefined) {
    const invocation: SarifInvocation = { executionSuccessful: v.coverage === 'full' };
    if (baselineGaps.length > 0) {
      invocation.toolExecutionNotifications = baselineGaps.map((gap) => ({ message: { text: gap } }));
    }
    run.invocations = [invocation];
  }

  return JSON.stringify(doc, null, 2);
}

/**
 * Make `filePath` relative to `projectPath`, and — whatever relation the two
 * turn out to have — guarantee the result never starts with `/` or a drive
 * letter. GitHub (and every other SARIF consumer) resolves
 * `artifactLocation.uri` against the checkout root; an absolute path there
 * matches no file, so the finding renders in the results list with no line
 * annotation on the diff — silently, with nothing to say a path went wrong.
 *
 * This is deliberately a second line of defence, not the only one: most
 * scanner parsers already call `toRelativeIfPossible`
 * (`../runners/scannerParsers/index.ts`) before a `Finding` ever reaches
 * here. But that function's own fallback — reached when a path shares no
 * root with the project at all, e.g. a different Windows drive — returns
 * the path UNCHANGED, which can still be absolute; and a `Finding` can also
 * reach this module from anywhere else that builds one by hand. Rather than
 * trust every upstream caller to have relativised correctly, this function
 * makes "never absolute" hold unconditionally, for any input, including one
 * that is already relative (left untouched) or shares no root with
 * `projectPath` at all (stripped down to *something* non-absolute, on the
 * reasoning that an approximate relative path is still less wrong than an
 * absolute one GitHub will silently refuse to annotate).
 */
export interface SarifOptions {
  /**
   * The project's path inside its git repository (`git rev-parse
   * --show-prefix`: `packages/api/`, `''` at the root) — put in front of every
   * URI, so it resolves against the repository root. Omitted: the project is
   * the root.
   */
  repoPrefix?: string;
}

/** `packages/api/` — `/`-separated, with one trailing `/`, no leading one; `''` for none. */
function normalizeRepoPrefix(prefix: string | undefined): string {
  const p = (prefix ?? '').replace(/\\/g, '/').replace(/^\/+/, '').replace(/\/+$/, '');
  if (p === '' || p === '.' || p.split('/').includes('..')) return '';
  return `${p}/`;
}

function toProjectRelativeUri(filePath: string, projectPath: string): string {
  const posixFile = filePath.replace(/\\/g, '/');
  const posixRoot = projectPath.replace(/\\/g, '/').replace(/\/+$/, '');

  let rel = posixFile;
  if (posixRoot.length > 0) {
    if (posixFile === posixRoot) {
      rel = '';
    } else if (posixFile.startsWith(`${posixRoot}/`)) {
      rel = posixFile.slice(posixRoot.length + 1);
    }
  }

  // Whatever branch above ran, `rel` can still be absolute — e.g. a
  // `filePath` on a different Windows drive to `projectPath` shares no
  // prefix with it at all, so neither branch above touches it. Strip a
  // leading drive letter and a leading POSIX slash unconditionally so the
  // returned URI is never absolute, even in that case.
  return rel.replace(/^[A-Za-z]:\//, '').replace(/^\/+/, '');
}
