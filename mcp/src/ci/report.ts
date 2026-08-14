/**
 * Render a `GateVerdict` for a CI consumer: human-readable text (the
 * default), JSON (for scripting), and SARIF (for GitHub/GitLab/Azure
 * code-scanning upload — the reason this task exists at all; see the design
 * doc §6).
 *
 * Pure: every renderer takes everything it needs as an argument — no
 * filesystem access, no clock, no environment lookups. `renderSarif` alone
 * also takes `projectPath`, because a SARIF `artifactLocation.uri` is
 * resolved by the *consumer* (GitHub, GitLab, ...) against the repository
 * checkout root: an absolute path — POSIX or a Windows drive letter —
 * matches nothing there, so the finding lands in the results list with no
 * line annotation on the diff, which is the entire point of shipping SARIF
 * (design doc §6, task resolution #2). See `toProjectRelativeUri`.
 *
 * SARIF generation is delegated to `../report/sarif.ts#toSarif`, the
 * project's existing SARIF producer (already used by the `report_export`
 * and `scan_skill` tools), rather than a second one. This module's own job
 * is limited to what CI specifically needs on top of that: relativised
 * URIs, and — for the one requirement carried forward from Task 2 (see
 * `renderSarif` below) — a place for the dropped-baseline-entries gap to
 * surface without smuggling the general `coverage` signal into SARIF, which
 * design doc §9 deliberately keeps out of it.
 */

import type { Finding } from '../types.js';
import { toSarif } from '../report/sarif.js';
import { CI_EXIT, type CiExitCode } from './types.js';
import type { GateVerdict } from './gate.js';

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
 * `coverageGaps` is printed in full whenever non-empty. That is also how the
 * dropped-baseline-entries line (carried forward from Task 2's review)
 * reaches human output: it is just another entry in `coverageGaps`, so it
 * needs no special case here — contrast `renderSarif`, which does need one,
 * because SARIF has no general-purpose home for free text.
 */
export function renderHuman(v: GateVerdict): string {
  const lines: string[] = [
    `dev-guardian CI: ${EXIT_LABEL[v.exitCode]} (exit code ${v.exitCode})`,
    `coverage: ${v.coverage}`,
    `new findings: ${v.newFindings.length} (${v.blocking.length} at or above the fail-on threshold)`,
  ];

  if (v.coverageGaps.length > 0) {
    lines.push('coverage gaps:');
    for (const gap of v.coverageGaps) lines.push(`  - ${gap}`);
  }

  if (v.blocking.length > 0) {
    lines.push('blocking findings:');
    for (const f of v.blocking) lines.push(`  - ${describeFinding(f)}`);
  }

  return `${lines.join('\n')}\n`;
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

interface JsonVerdict {
  exit_code: CiExitCode;
  coverage: GateVerdict['coverage'];
  coverage_gaps: string[];
  new_findings: Finding[];
  blocking_findings: Finding[];
}

/**
 * snake_case keys, matching every other JSON-facing shape in `../types.ts`
 * (`Finding.file_path`, `ScanResult.findings_count_by_severity`, ...) so a
 * script consuming this alongside the rest of dev-guardian's JSON output
 * sees one convention, not two. Every field of `GateVerdict` is carried —
 * this is a full serialisation, not a summary.
 */
export function renderJson(v: GateVerdict): string {
  const payload: JsonVerdict = {
    exit_code: v.exitCode,
    coverage: v.coverage,
    coverage_gaps: v.coverageGaps,
    new_findings: v.newFindings,
    blocking_findings: v.blocking,
  };
  return JSON.stringify(payload, null, 2);
}

// ---------------------------------------------------------------------------
// SARIF
// ---------------------------------------------------------------------------

/**
 * `gate.ts#evaluateGate` always builds the dropped-baseline-entries gap with
 * this exact prefix, and no other `coverageGaps` line starts with it — every
 * other line is `${step.tool}: ...`, and no scan step is named "baseline".
 * Matching the prefix (rather than owning a second copy of gate.ts's
 * wording) is what lets `renderSarif` single that one line out from the
 * general scanner-coverage gaps design doc §9 keeps out of SARIF entirely.
 */
const BASELINE_GAP_PREFIX = 'baseline: ';

interface SarifNotification {
  message: { text: string };
}

interface SarifInvocation {
  executionSuccessful: boolean;
  toolExecutionNotifications: SarifNotification[];
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
 * SARIF carries findings, not the `coverage` signal (design doc §9): the
 * general "semgrep did not run" gaps stay exit-code-and-human/JSON-only, by
 * design, so a SARIF consumer never mistakes an incomplete scan for a clean
 * one just because the upload happens to look complete.
 *
 * The one exception, carried forward from Task 2's review, is narrower than
 * "coverage" in general: a dropped baseline entry changes how a *result in
 * this very document* should be read — a "new" finding that only resurfaced
 * because its suppression entry could not be parsed, not because anyone
 * reintroduced it. That is about the trustworthiness of `results`, not scan
 * completeness, so it is attached to the run as a
 * `toolExecutionNotifications` entry — SARIF's own mechanism for run-level
 * messages that are not themselves findings — rather than folded into
 * `results`, or omitted, or (the design-doc-violating option) used to carry
 * the general coverage gaps too. See the task report for why this reading of
 * §9 was chosen over leaving SARIF silent on it entirely: the brief (written
 * before Task 2 existed) does not mention this case, and the two sources
 * pull in different directions if §9 is read at the widest possible scope.
 *
 * SARIF's `invocation.executionSuccessful` is always `true` here rather than
 * derived from `coverage`, for the same reason: tying it to coverage would
 * be exactly the leak this function exists to avoid. It reports that
 * *rendering* completed, nothing about scan completeness.
 */
export function renderSarif(v: GateVerdict, projectPath: string): string {
  // A `file_path` that IS the project root relativises to `''`
  // (`toProjectRelativeUri`'s own "posixFile === posixRoot" branch). Passed
  // through, `toSarif`'s `if (f.file_path)` check (see `../report/sarif.ts`,
  // unmodified) treats that falsy `''` the same as an absent path and omits
  // `locations` entirely, rather than emitting an empty URI. That is the
  // right outcome, not a gap: a finding about the whole project has no
  // single line to annotate, so no location is more honest than one.
  const relocated: Finding[] = v.newFindings.map((f) =>
    f.file_path === undefined ? f : { ...f, file_path: toProjectRelativeUri(f.file_path, projectPath) },
  );

  const parsed: unknown = JSON.parse(toSarif(relocated));
  // Safe: this is JSON we just produced from `toSarif` on the line above,
  // not untrusted input — a full runtime re-validation of our own output
  // belongs in the schema-validation test, not here.
  const doc = parsed as SarifDocument;

  const baselineGaps = v.coverageGaps.filter((gap) => gap.startsWith(BASELINE_GAP_PREFIX));
  if (baselineGaps.length > 0) {
    const run = doc.runs[0];
    if (run !== undefined) {
      run.invocations = [
        {
          executionSuccessful: true,
          toolExecutionNotifications: baselineGaps.map((gap) => ({ message: { text: gap } })),
        },
      ];
    }
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
