import { describe, expect, it } from 'vitest';
import { evaluateGate, exitCodeForCoverage } from '../../../src/ci/gate.js';
import { buildBaseline } from '../../../src/ci/baseline.js';
import { CI_EXIT } from '../../../src/ci/types.js';
import type { Finding, Severity, ToolRun } from '../../../src/types.js';
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

  it('says a scanner that ran with reduced coverage did so — not that it is "not installed"', () => {
    // The convention scanCoverage.ts documents: an `ok` entry whose name is
    // also in missing_tools ran, but did not cover everything (e.g. files
    // gitleaks could not read). The gap must be reported — and truthfully.
    const v = evaluateGate(input({
      steps: [
        step({
          tool: 'security_scan_full',
          tools_run: [{ name: 'gitleaks-working-tree', status: 'ok', reason: '1 file(s) could not be read' }],
          missing_tools: ['gitleaks-working-tree'],
        }),
      ],
    }));
    expect(v.exitCode).toBe(CI_EXIT.INCOMPLETE_SCAN);
    expect(v.coverageGaps).toEqual([
      'security_scan_full: gitleaks-working-tree ran with reduced coverage (1 file(s) could not be read)',
    ]);
  });

  it('says a Trivy ecosystem gap is reduced coverage of an installed Trivy, never "not installed"', () => {
    // The exact bookkeeping scan_deps writes when Trivy ran, covered npm, and
    // recognised nothing for a root .csproj (no packages.lock.json), as
    // security_scan_full merges it: `trivy` ok, `trivy:<ecosystem>` missing.
    // The gate used to look the pseudo-name up as if it were a scanner of its
    // own, find no `ok` run named `trivy:dotnet`, and print "not installed".
    const v = evaluateGate(input({
      steps: [
        step({
          tool: 'security_scan_full',
          tools_run: [
            { name: 'semgrep', status: 'ok' },
            { name: 'trivy', status: 'ok', reason: 'no_supported_manifest' },
            { name: 'trivy-config', status: 'ok' },
          ],
          missing_tools: ['trivy:dotnet'],
        }),
      ],
    }));
    expect(v.exitCode).toBe(CI_EXIT.INCOMPLETE_SCAN);
    expect(v.coverage).toBe('partial');
    expect(v.coverageGaps).toEqual([
      'security_scan_full: trivy ran with reduced coverage — dotnet not covered (no_supported_manifest)',
    ]);
  });

  it('says a Trivy that recognised no manifest at all was skipped, with its reason — not "not installed"', () => {
    // scan_deps' other shape: Trivy ran and its report had no Results at all
    // for a manifest that declares dependencies, so its entry is `skipped` and
    // the bare name is listed missing. Installed, so never "not installed".
    const v = evaluateGate(input({
      steps: [
        step({
          tool: 'security_scan_full',
          tools_run: [
            { name: 'semgrep', status: 'ok' },
            { name: 'trivy', status: 'skipped', reason: 'no_supported_manifest' },
            { name: 'trivy-config', status: 'ok' },
          ],
          missing_tools: ['trivy'],
        }),
      ],
    }));
    expect(v.exitCode).toBe(CI_EXIT.INCOMPLETE_SCAN);
    expect(v.coverageGaps).toEqual(['security_scan_full: trivy skipped (no_supported_manifest)']);
  });

  it('reports a tool that failed AND is listed missing once, as failed — not also as "not installed"', () => {
    // deps_audit lists a failed `npm audit` in missing_tools as well; the
    // failed line already names it, and it is installed.
    const v = evaluateGate(input({
      steps: [
        step({
          tool: 'deps_audit',
          tools_run: [
            { name: 'trivy', status: 'ok' },
            { name: 'npm', status: 'failed', reason: 'ran but produced no audit report (missing lockfile?)' },
          ],
          missing_tools: ['npm'],
        }),
      ],
    }));
    expect(v.coverageGaps).toEqual([
      'deps_audit: npm failed (ran but produced no audit report (missing lockfile?))',
    ]);
  });

  it('still says "not installed" for a scanner that is not installed', () => {
    const v = evaluateGate(input({
      steps: [
        step({
          tool: 'security_scan_full',
          tools_run: [
            { name: 'semgrep', status: 'ok' },
            { name: 'trivy', status: 'skipped', reason: 'not_installed' },
          ],
          missing_tools: ['trivy'],
        }),
      ],
    }));
    expect(v.coverageGaps).toEqual(['security_scan_full: trivy not installed']);
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
  // found yet, run `baseline update`" — a fact the design of record says the CLI
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

describe('exitCodeForCoverage (carried forward from Task 5 coordinator review)', () => {
  // `dev-guardian baseline update` has no `blocking`-findings concept of its
  // own (it writes unconditionally and never gates), so it cannot reuse
  // `evaluateGate` wholesale the way `scan` does — it needs exactly this
  // narrower coverage-only half of the rule. This was previously
  // re-implemented as a second ternary directly in cli/dev-guardian.mjs,
  // untested on its own and undiscriminated by any e2e assertion (every e2e
  // check accepted 0 OR 2) — an implementation that deleted the ternary and
  // always returned INCOMPLETE_SCAN would have passed every test in the
  // suite, on every machine, unconditionally. Extracted here so the mapping
  // gets the same fixture coverage every other rule in this module does, and
  // reused BY `evaluateGate` itself (see the "both branches" test below) so
  // there is exactly one definition, not two that could drift apart.

  it('maps full coverage to PASS', () => {
    expect(exitCodeForCoverage('full')).toBe(CI_EXIT.PASS);
  });

  it('maps partial coverage to INCOMPLETE_SCAN', () => {
    expect(exitCodeForCoverage('partial')).toBe(CI_EXIT.INCOMPLETE_SCAN);
  });

  it('maps no coverage to INCOMPLETE_SCAN', () => {
    // Guards a wrong implementation that only special-cases 'partial' (e.g.
    // `coverage === 'partial' ? INCOMPLETE_SCAN : PASS`), which would
    // silently mis-map 'none' — the worst coverage state — back to PASS.
    expect(exitCodeForCoverage('none')).toBe(CI_EXIT.INCOMPLETE_SCAN);
  });

  it("evaluateGate's own coverage-only branch agrees with exitCodeForCoverage, for every coverage value", () => {
    // Proves the "one definition, not two" claim directly rather than by
    // reading both call sites: with zero findings (so `blocking` is always
    // empty and can never override the comparison), evaluateGate's exitCode
    // must equal exitCodeForCoverage(coverage) for every coverage value a
    // step combination can produce.
    const full = evaluateGate(input({ steps: [step()] }));
    expect(full.exitCode).toBe(exitCodeForCoverage('full'));

    const partial = evaluateGate(
      input({ steps: [step({ tools_run: [{ name: 'semgrep', status: 'ok' }], missing_tools: ['gitleaks'] })] }),
    );
    expect(partial.coverage).toBe('partial');
    expect(partial.exitCode).toBe(exitCodeForCoverage('partial'));

    const none = evaluateGate(
      input({ steps: [step({ ran: false, reason: 'no surface snapshot', tools_run: [] })] }),
    );
    expect(none.coverage).toBe('none');
    expect(none.exitCode).toBe(exitCodeForCoverage('none'));
  });
});

/**
 * Follow-up X1 — `--accept-partial-parse <path>`. A Semgrep step the shared
 * judge found `partial` (some files only partly parsed: `ok` AND missing)
 * carries those files in `partial_parses` (runScans.ts). When EVERY one is
 * accepted, the gap prints as accepted and does not force exit 2; coverage
 * itself stays `partial` — in the verdict, and so in JSON and SARIF. Skipped,
 * failed, scanned-nothing and unlisted files still exit 2. Paths are
 * project-relative and matched exactly: no globs.
 */
describe('evaluateGate — --accept-partial-parse (follow-up X1)', () => {
  const WP = 'wp/rest-controller.php';
  const partialRun = (files: readonly string[]): ToolRun => ({
    name: 'semgrep',
    status: 'ok',
    reason: `partial: ${files.length} file(s) only partly parsed — findings in the unparsed spans may be missing`,
    partially_parsed: files.map((file) => ({ file, type: 'PartialParsing', message: 'Syntax error' })),
  });
  const partialStep = (files: readonly string[] = [WP], over: Partial<ScanStepResult> = {}): ScanStepResult =>
    step({
      tool: 'security_scan_full',
      tools_run: [partialRun(files)],
      missing_tools: ['semgrep'],
      partial_parses: { semgrep: files.map((file) => ({ file, type: 'PartialParsing' })) },
      ...over,
    });

  it('not accepted: exit 2, coverage partial, the gap names the file and the flag', () => {
    const v = evaluateGate(input({ steps: [partialStep()] }));
    expect(v.exitCode).toBe(CI_EXIT.INCOMPLETE_SCAN);
    expect(v.coverage).toBe('partial');
    expect(v.acceptedGaps).toEqual([]);
    expect(v.coverageGaps).toHaveLength(1);
    expect(v.coverageGaps[0]).toMatch(/^security_scan_full: semgrep ran with reduced coverage/);
    expect(v.coverageGaps[0]).toMatch(/not accepted: wp\/rest-controller\.php .*--accept-partial-parse/);
  });

  it('every file accepted: exit 0, printed as accepted, coverage stays partial', () => {
    const v = evaluateGate(input({ steps: [partialStep()], acceptedPartialParses: [WP] }));
    expect(v.exitCode).toBe(CI_EXIT.PASS);
    expect(v.coverage).toBe('partial');
    expect(v.coverageGaps).toEqual([]);
    expect(v.acceptedGaps).toEqual([
      'security_scan_full: semgrep only partly parsed wp/rest-controller.php — accepted (--accept-partial-parse)',
    ]);
    expect(v.unusedPartialParseAcceptances).toEqual([]);
  });

  it('an accepted path that is not the one partially parsed: exit 2, and the acceptance is reported unused', () => {
    const v = evaluateGate(input({ steps: [partialStep()], acceptedPartialParses: ['wp/other.php'] }));
    expect(v.exitCode).toBe(CI_EXIT.INCOMPLETE_SCAN);
    expect(v.acceptedGaps).toEqual([]);
    expect(v.coverageGaps[0]).toMatch(/not accepted: wp\/rest-controller\.php/);
    expect(v.unusedPartialParseAcceptances).toEqual(['wp/other.php']);
  });

  it('one of two files accepted: exit 2, naming only the unaccepted one', () => {
    const v = evaluateGate(input({ steps: [partialStep([WP, 'b.js'])], acceptedPartialParses: [WP] }));
    expect(v.exitCode).toBe(CI_EXIT.INCOMPLETE_SCAN);
    expect(v.coverageGaps[0]).toMatch(/not accepted: b\.js /);
    expect(v.coverageGaps[0]).not.toMatch(/not accepted: .*rest-controller/);
  });

  it('matched exactly: backslashes and a leading ./ normalise; case, globs, directories and prefixes do not', () => {
    for (const spelling of ['wp\\rest-controller.php', './wp/rest-controller.php']) {
      expect(evaluateGate(input({ steps: [partialStep()], acceptedPartialParses: [spelling] })).exitCode).toBe(CI_EXIT.PASS);
    }
    for (const spelling of ['WP/rest-controller.php', 'wp/*.php', 'wp/**', 'wp', 'wp/', 'rest-controller.php', '/wp/rest-controller.php']) {
      expect(evaluateGate(input({ steps: [partialStep()], acceptedPartialParses: [spelling] })).exitCode).toBe(
        CI_EXIT.INCOMPLETE_SCAN,
      );
    }
  });

  it('accepts per step: the SAST and the surface step each need their files accepted', () => {
    const steps = [partialStep(), partialStep(['app/routes.php'], { tool: 'map_attack_surface' })];
    expect(evaluateGate(input({ steps, acceptedPartialParses: [WP] })).exitCode).toBe(CI_EXIT.INCOMPLETE_SCAN);
    const both = evaluateGate(input({ steps, acceptedPartialParses: [WP, 'app/routes.php'] }));
    expect(both.exitCode).toBe(CI_EXIT.PASS);
    expect(both.acceptedGaps).toHaveLength(2);
  });

  it('never accepts a skipped, failed or scanned-nothing Semgrep, even with a file of the step accepted', () => {
    const skipped: ToolRun = { name: 'semgrep', status: 'skipped', reason: 'semgrep scanned 0 files' };
    const failed: ToolRun = { name: 'semgrep', status: 'failed', reason: 'exit 7' };
    for (const other of [skipped, failed]) {
      const v = evaluateGate(input({
        steps: [partialStep([WP], { tools_run: [partialRun([WP]), other] })],
        acceptedPartialParses: [WP],
      }));
      expect(v.exitCode).toBe(CI_EXIT.INCOMPLETE_SCAN);
      expect(v.acceptedGaps).toEqual([]);
    }
    // A step with no partial_parses at all (scanned nothing, not installed).
    const nothing = evaluateGate(input({
      steps: [step({ tools_run: [skipped], missing_tools: ['semgrep'] })],
      acceptedPartialParses: [WP],
    }));
    expect(nothing.exitCode).toBe(CI_EXIT.INCOMPLETE_SCAN);
    expect(nothing.unusedPartialParseAcceptances).toEqual([WP]);
  });

  it('another gap beside an accepted one still exits 2; a blocking finding still exits 1', () => {
    const gap = evaluateGate(input({
      steps: [partialStep(), step({ tool: 'scan_deps', tools_run: [], missing_tools: ['trivy'] })],
      acceptedPartialParses: [WP],
    }));
    expect(gap.exitCode).toBe(CI_EXIT.INCOMPLETE_SCAN);
    expect(gap.acceptedGaps).toHaveLength(1);
    const blocking = evaluateGate(input({ steps: [partialStep()], acceptedPartialParses: [WP], findings: [finding()] }));
    expect(blocking.exitCode).toBe(CI_EXIT.GATE_FAILED);
  });

  // Fix round 1: only a PARSE problem can be accepted. A per-file Timeout
  // (Semgrep gave up on the file) is per-file too, and the shared judge
  // calls it partial — but accepting a file's parse gap never means
  // accepting that it was not analysed at all.
  it('a per-file Timeout on an accepted file still exits 2, naming the type', () => {
    for (const types of [['Timeout'], ['PartialParsing', 'Timeout']]) {
      const v = evaluateGate(input({
        steps: [partialStep([WP], { partial_parses: { semgrep: types.map((type) => ({ file: WP, type })) } })],
        acceptedPartialParses: [WP],
      }));
      expect(v.exitCode).toBe(CI_EXIT.INCOMPLETE_SCAN);
      expect(v.acceptedGaps).toEqual([]);
      expect(v.coverageGaps[0]).toMatch(/not accepted: Timeout on wp\/rest-controller\.php/);
      expect(v.coverageGaps[0]).toMatch(/PartialParsing, Syntax error, Lexical error/);
      expect(v.unusedPartialParseAcceptances).toEqual([]);
    }
    for (const type of ['Syntax error', 'Lexical error']) {
      const v = evaluateGate(input({
        steps: [partialStep([WP], { partial_parses: { semgrep: [{ file: WP, type }] } })],
        acceptedPartialParses: [WP],
      }));
      expect(v.exitCode).toBe(CI_EXIT.PASS);
    }
  });

  it("the DAST step's partial-surface gap is accepted with the surface's files", () => {
    const dast = step({
      tool: 'scan_dast',
      tools_run: [{ name: 'guardian-dast', status: 'ok' }],
      missing_tools: ['guardian-dast:partial-surface'],
      partial_parses: { 'guardian-dast:partial-surface': [{ file: WP, type: 'PartialParsing' }] },
    });
    expect(evaluateGate(input({ steps: [dast] })).exitCode).toBe(CI_EXIT.INCOMPLETE_SCAN);
    const v = evaluateGate(input({ steps: [dast], acceptedPartialParses: [WP] }));
    expect(v.exitCode).toBe(CI_EXIT.PASS);
    expect(v.acceptedGaps).toEqual([
      'scan_dast: guardian-dast:partial-surface only partly parsed wp/rest-controller.php — accepted (--accept-partial-parse)',
    ]);
  });
});
