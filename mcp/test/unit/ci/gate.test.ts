import { describe, expect, it } from 'vitest';
import { evaluateGate } from '../../../src/ci/gate.js';
import { buildBaseline } from '../../../src/ci/baseline.js';
import { CI_EXIT } from '../../../src/ci/types.js';
import type { Finding, Severity } from '../../../src/types.js';
import type { ScanStepResult } from '../../../src/ci/types.js';

function finding(over: Partial<Finding> = {}): Finding {
  return {
    fingerprint: 'fp1', tool: 'semgrep', severity: 'high', category: 'security',
    title: 'SQL injection', file_path: 'src/db.ts', fix_available: false, ...over,
  };
}

function step(over: Partial<ScanStepResult> = {}): ScanStepResult {
  return {
    tool: 'scan_sast', ran: true,
    tools_run: [{ name: 'semgrep', status: 'ok' }],
    missing_tools: [], ...over,
  };
}

// NOTE: adds `droppedBaselineEntries: 0` to the brief's default fixture.
// `GateInput` grew that required field after the brief was written (Task 1's
// review made `parseBaseline` report entries it had to drop) — see the
// "droppedBaselineEntries" describe block below for the tests that exercise
// it. The eight cases in the next block are otherwise verbatim from the brief.
function input(over: Partial<Parameters<typeof evaluateGate>[0]> = {}) {
  return {
    findings: [] as Finding[], baseline: null, failOn: 'high' as Severity,
    steps: [step()], droppedBaselineEntries: 0, ...over,
  };
}

describe('evaluateGate', () => {
  it('passes with no findings and full coverage', () => {
    expect(evaluateGate(input()).exitCode).toBe(CI_EXIT.PASS);
  });

  it('fails on a new finding at the threshold', () => {
    const v = evaluateGate(input({ findings: [finding({ severity: 'high' })] }));
    expect(v.exitCode).toBe(CI_EXIT.GATE_FAILED);
    expect(v.blocking.map((f) => f.fingerprint)).toEqual(['fp1']);
  });

  it('does NOT fail on a baselined finding, however severe', () => {
    // Historical debt must not fail the build — the reason the baseline exists.
    const f = finding({ severity: 'critical' });
    const v = evaluateGate(input({ findings: [f], baseline: buildBaseline([f], null, 'x') }));
    expect(v.exitCode).toBe(CI_EXIT.PASS);
    expect(v.blocking).toEqual([]);
  });

  it('does NOT fail on a new finding below the threshold, but still reports it', () => {
    const v = evaluateGate(input({ findings: [finding({ severity: 'low' })], failOn: 'high' }));
    expect(v.exitCode).toBe(CI_EXIT.PASS);
    expect(v.newFindings).toHaveLength(1);
    expect(v.blocking).toEqual([]);
  });

  it('fails on a new finding ABOVE the threshold', () => {
    const v = evaluateGate(input({ findings: [finding({ severity: 'critical' })], failOn: 'high' }));
    expect(v.exitCode).toBe(CI_EXIT.GATE_FAILED);
  });

  it('exits INCOMPLETE_SCAN when a scanner was missing, even with zero findings', () => {
    // The load-bearing one: without this, an uninstalled Semgrep produces
    // "zero new findings" and a green build.
    const v = evaluateGate(input({
      steps: [step({ tools_run: [], missing_tools: ['semgrep'] })],
    }));
    expect(v.exitCode).toBe(CI_EXIT.INCOMPLETE_SCAN);
    expect(v.coverageGaps.some((g) => g.includes('semgrep'))).toBe(true);
  });

  it('exits INCOMPLETE_SCAN when a step refused to run', () => {
    const v = evaluateGate(input({
      steps: [step({ ran: false, reason: 'no surface snapshot', tools_run: [] })],
    }));
    expect(v.exitCode).toBe(CI_EXIT.INCOMPLETE_SCAN);
  });

  it('prefers GATE_FAILED over INCOMPLETE_SCAN when both apply', () => {
    // A real regression outranks an incomplete scan: the pipeline must see the
    // actionable failure, and the gaps are still reported alongside it.
    const v = evaluateGate(input({
      findings: [finding({ severity: 'critical' })],
      steps: [step({ tools_run: [], missing_tools: ['semgrep'] })],
    }));
    expect(v.exitCode).toBe(CI_EXIT.GATE_FAILED);
    expect(v.coverageGaps).not.toEqual([]);
  });

  it('treats a step with nothing to do as complete, not as a gap', () => {
    // computeCoverage's own contract: no Dockerfile means no work, not a gap.
    const v = evaluateGate(input({
      steps: [step({ tools_run: [{ name: 'trivy', status: 'skipped' }], missing_tools: [] })],
    }));
    expect(v.exitCode).toBe(CI_EXIT.PASS);
  });
});

describe('evaluateGate — coverage gaps beyond "missing" (guards computeCoverage being read only partially)', () => {
  it('downgrades `coverage` itself, not just the exit code, when a step refuses to run', () => {
    // Guards an implementation that special-cases exitCode for a refused step
    // without updating `coverage` to match — a report that says "coverage:
    // full" next to exit code 2 would contradict itself. `ran: false` must
    // feed the same coverage signal a missing tool would, not a parallel one.
    const v = evaluateGate(input({
      steps: [step({ ran: false, reason: 'no surface snapshot', tools_run: [] })],
    }));
    expect(v.coverage).not.toBe('full');
  });

  it('reports a gap for a scanner that ran but failed, not only for one that is missing', () => {
    // Guards an implementation that reads `missing_tools` but ignores a
    // `status: 'failed'` entry in `tools_run` — computeCoverage itself
    // treats a failed run as a gap (see scanCoverage.ts), so a coverageGaps
    // list that only ever mentions `missing_tools` would go silent on this.
    const v = evaluateGate(input({
      steps: [step({ tools_run: [{ name: 'semgrep', status: 'failed', reason: 'crashed' }] })],
    }));
    expect(v.exitCode).toBe(CI_EXIT.INCOMPLETE_SCAN);
    expect(v.coverageGaps.some((g) => g.includes('semgrep'))).toBe(true);
  });

  it('does not report a gap for a tool that merely skipped (nothing to do)', () => {
    // Companion to the brief's "nothing to do" case: pins that `skipped` never
    // produces a coverageGaps line, not just that it doesn't flip the exit code.
    const v = evaluateGate(input({
      steps: [step({ tools_run: [{ name: 'trivy', status: 'skipped' }], missing_tools: [] })],
    }));
    expect(v.coverageGaps).toEqual([]);
  });

  it('falls back to a generic message for a refused step with no reason given', () => {
    // `ScanStepResult.reason` is optional even when `ran` is false. Guards
    // against a template literal that renders the bare word "undefined" into
    // the gap line instead of a readable fallback.
    const v = evaluateGate(input({
      steps: [step({ ran: false, reason: undefined, tools_run: [] })],
    }));
    expect(v.coverageGaps.some((g) => g.includes('undefined'))).toBe(false);
    expect(v.coverageGaps.some((g) => g.includes('scan_sast'))).toBe(true);
  });

  it('reports a failed tool without a parenthetical when no reason is given', () => {
    // Companion to the "reason given" failed-tool case above: pins the other
    // side of the `run.reason ? ... : ''` branch so both are exercised.
    const v = evaluateGate(input({
      steps: [step({ tools_run: [{ name: 'semgrep', status: 'failed' }] })],
    }));
    expect(v.coverageGaps.some((g) => g.includes('undefined'))).toBe(false);
    expect(v.coverageGaps.some((g) => g === 'scan_sast: semgrep failed')).toBe(true);
  });
});

describe('evaluateGate — droppedBaselineEntries (carried forward from Task 1 review)', () => {
  it('folds a non-zero droppedBaselineEntries into coverageGaps by name', () => {
    // Guards an implementation that silently ignores the field entirely.
    const v = evaluateGate(input({ droppedBaselineEntries: 2 }));
    expect(v.coverageGaps.some((g) => g.includes('baseline') && g.includes('2'))).toBe(true);
  });

  it('adds nothing to coverageGaps when droppedBaselineEntries is zero', () => {
    // Guards an implementation that unconditionally appends a "0 entries..."
    // line regardless of the count — the field defaults to 0 for every
    // baseline-less/clean-baseline run, which must stay silent.
    const v = evaluateGate(input({ droppedBaselineEntries: 0 }));
    expect(v.coverageGaps).toEqual([]);
  });

  it('does NOT fail the build or downgrade coverage on dropped baseline entries alone', () => {
    // Judgement call (see task report): a corrupt baseline LINE is not a
    // scanner that failed to run — it is baseline-integrity information, not
    // a scan-coverage signal. Any finding it actually un-suppresses is still
    // caught, on its own merits, by the ordinary blocking-findings path
    // (see the next test). This field must only ADD visibility, never invent
    // a second, independent reason to fail or flag the build as incomplete.
    const v = evaluateGate(input({ droppedBaselineEntries: 3 }));
    expect(v.exitCode).toBe(CI_EXIT.PASS);
    expect(v.coverage).toBe('full');
  });

  it('surfaces both facts when a dropped entry lets an old finding resurface as new', () => {
    // The scenario the requirement exists for: a fingerprint whose baseline
    // entry was dropped shows up in `blocking` on its own severity merits,
    // AND coverageGaps says a baseline entry was unreadable — two different
    // facts (a real regression vs. a parser that lost a line), both visible,
    // neither substituting for the other.
    const f = finding({ severity: 'critical' });
    const baselineMissingF = buildBaseline([], null, 'x'); // as if `f`'s entry was dropped
    const v = evaluateGate(input({
      findings: [f], baseline: baselineMissingF, droppedBaselineEntries: 1,
    }));
    expect(v.blocking.map((x) => x.fingerprint)).toEqual(['fp1']);
    expect(v.coverageGaps.some((g) => g.includes('baseline'))).toBe(true);
    expect(v.exitCode).toBe(CI_EXIT.GATE_FAILED);
  });
});

describe('evaluateGate — baselineAbsent (carried forward from Task 3 review)', () => {
  // Task 3's `renderHuman` needs to tell a reader "no baseline file was
  // found yet, run `baseline update`" — a fact design doc §4 says the CLI
  // must state on a first run. That fact lives one layer up from here:
  // `GateInput.baseline` is `null` precisely when Task 1's `parseBaseline`
  // could not read a file at all (see baseline.ts's module doc, the three
  // return states). It was reaching `evaluateGate` and being discarded
  // rather than carried into `GateVerdict` — this field carries it forward
  // instead of re-deriving it from something else.
  it('is true when the baseline was null (no file could be read)', () => {
    const v = evaluateGate(input({ findings: [finding()], baseline: null }));
    expect(v.baselineAbsent).toBe(true);
  });

  it('is false when the baseline was present but simply empty', () => {
    // The whole reason this field has to be its own thing rather than
    // derived: `newFindings(findings, null)` and
    // `newFindings(findings, { entries: [] })` produce the identical
    // result — nothing is known either way, so every existing GateVerdict
    // field (newFindings, blocking, coverage, coverageGaps) looks the same
    // in both cases. An implementation that infers "absent" from any of
    // those (e.g. "newFindings.length === findings.length") cannot tell
    // this case apart from the one above — same `findings` in both tests,
    // only `baseline` differs, and only `baselineAbsent` may differ with it.
    const emptyBaseline = buildBaseline([], null, 'x');
    const v = evaluateGate(input({ findings: [finding()], baseline: emptyBaseline }));
    expect(v.baselineAbsent).toBe(false);
  });

  it('does not affect exitCode, coverage, or blocking — visibility only', () => {
    // Guards an implementation that piggybacks extra logic onto this field
    // (e.g. treating an absent baseline as its own coverage gap). It must
    // only ever ADD a fact for the renderers to surface, exactly like
    // droppedBaselineEntries before it — never a second, independent reason
    // to fail or flag the build.
    const f = finding({ severity: 'critical' });
    const withNullBaseline = evaluateGate(input({ findings: [f], baseline: null }));
    const withEmptyBaseline = evaluateGate(
      input({ findings: [f], baseline: buildBaseline([], null, 'x') }),
    );
    expect(withNullBaseline.exitCode).toBe(withEmptyBaseline.exitCode);
    expect(withNullBaseline.coverage).toBe(withEmptyBaseline.coverage);
    expect(withNullBaseline.blocking.map((x) => x.fingerprint)).toEqual(
      withEmptyBaseline.blocking.map((x) => x.fingerprint),
    );
  });
});
