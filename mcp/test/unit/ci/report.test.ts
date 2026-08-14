/**
 * Schema validator: `ajv` 8.20.0 + `ajv-draft-04` 1.0.0 (both already
 * transitively present via `@modelcontextprotocol/sdk`'s own `ajv`
 * dependency, now promoted to explicit devDependencies).
 *
 * The vendored schema — `test/fixtures/sarif/sarif-schema-2.1.0.json` — is
 * the OASIS canonical SARIF 2.1.0 (errata01) schema, fetched from
 * https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json.
 * It declares `"$schema": "http://json-schema.org/draft-04/schema#"`.
 * Plain `ajv@8` ships only the draft-07+ meta-schemas and throws
 * `no schema with key or ref "http://json-schema.org/draft-04/schema#"` on
 * `ajv.compile(schema)` — confirmed by hand before reaching for a
 * dependency: this is not a strictness knob, `strict: false` does not
 * change it. `ajv-draft-04` is the ajv-validator org's own companion
 * package for exactly this (draft-04-dialect schemas under ajv8), so this
 * suite imports `Ajv` from `ajv-draft-04`, not from `ajv` directly, unlike
 * the brief's own illustrative snippet.
 */
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import Ajv from 'ajv-draft-04';
import { renderHuman, renderJson, renderSarif } from '../../../src/ci/report.js';
import { evaluateGate } from '../../../src/ci/gate.js';
import { buildBaseline } from '../../../src/ci/baseline.js';
import { CI_EXIT } from '../../../src/ci/types.js';
import { SEVERITIES, type Finding, type Severity } from '../../../src/types.js';
import type { ScanStepResult } from '../../../src/ci/types.js';

// Mirrors gate.test.ts's fixture helpers deliberately: every GateVerdict in
// this file is built by calling the real `evaluateGate`, never assembled by
// hand, per the task's resolution #1 — a hand-built verdict could hold a
// combination the gate would never actually produce, and a test built on one
// would prove nothing about real CLI output.

function finding(over: Partial<Finding> = {}): Finding {
  return {
    fingerprint: 'fp1',
    tool: 'semgrep',
    severity: 'high',
    category: 'security',
    title: 'SQL injection',
    file_path: 'src/db.ts',
    fix_available: false,
    ...over,
  };
}

function step(over: Partial<ScanStepResult> = {}): ScanStepResult {
  return {
    tool: 'scan_sast',
    ran: true,
    tools_run: [{ name: 'semgrep', status: 'ok' }],
    missing_tools: [],
    ...over,
  };
}

function input(over: Partial<Parameters<typeof evaluateGate>[0]> = {}) {
  return {
    findings: [] as Finding[],
    baseline: null,
    failOn: 'high' as Severity,
    steps: [step()],
    droppedBaselineEntries: 0,
    ...over,
  };
}

const PROJECT = '/proj';

describe('renderSarif', () => {
  const schema = JSON.parse(
    readFileSync('test/fixtures/sarif/sarif-schema-2.1.0.json', 'utf8'),
  ) as object;
  const ajv = new Ajv({ strict: false, allErrors: true, logger: false });
  const validate = ajv.compile(schema);

  function expectValidSarif(doc: unknown): void {
    const ok = validate(doc);
    // Print the errors — a bare `expect(ok).toBe(true)` on a schema failure
    // tells you nothing about which field is wrong.
    expect(validate.errors ?? [], JSON.stringify(validate.errors, null, 2)).toEqual([]);
    expect(ok).toBe(true);
  }

  it('produces a document that validates against the SARIF 2.1.0 schema', () => {
    const v = evaluateGate(input({ findings: [finding()] }));
    const doc = JSON.parse(renderSarif(v, PROJECT));
    expectValidSarif(doc);
  });

  it('emits one result per new finding, with a rule id and a location', () => {
    const v = evaluateGate(
      input({
        findings: [
          finding({ fingerprint: 'fp1', file_path: 'src/db.ts' }),
          finding({ fingerprint: 'fp2', file_path: 'src/api.ts', title: 'XSS' }),
        ],
      }),
    );
    const doc = JSON.parse(renderSarif(v, PROJECT));
    expect(doc.runs[0].results).toHaveLength(2);
    expect(doc.runs[0].results[0].ruleId).toBeTruthy();
    expect(doc.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri).toBe(
      'src/db.ts',
    );
  });

  it('includes a new finding below the fail-on threshold, not only blocking ones', () => {
    // Names the plausible-wrong implementation: rendering `v.blocking`
    // instead of `v.newFindings`. SARIF is meant to annotate everything new
    // on the PR diff (design doc §6), not just what fails the gate — a
    // `low` finding under a `critical` threshold is new but never blocking,
    // and a reviewer should still see it on the line it touched.
    const v = evaluateGate(input({ findings: [finding({ severity: 'low' })], failOn: 'critical' }));
    expect(v.blocking).toEqual([]); // sanity on the fixture
    expect(v.newFindings).toHaveLength(1);
    const doc = JSON.parse(renderSarif(v, PROJECT));
    expect(doc.runs[0].results).toHaveLength(1);
  });

  it('emits a project-relative URI for an already-relative file_path', () => {
    const v = evaluateGate(input({ findings: [finding({ file_path: 'src/db.ts' })] }));
    const doc = JSON.parse(renderSarif(v, PROJECT));
    const uri = doc.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri;
    expect(uri).toBe('src/db.ts');
  });

  it('rewrites a POSIX-absolute file_path under the project root to be relative', () => {
    const v = evaluateGate(input({ findings: [finding({ file_path: '/proj/src/db.ts' })] }));
    const doc = JSON.parse(renderSarif(v, PROJECT));
    const uri = doc.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri;
    expect(uri).toBe('src/db.ts');
    expect(uri.startsWith('/')).toBe(false);
  });

  it('rewrites a Windows-style absolute file_path under the project root to be relative', () => {
    const v = evaluateGate(input({ findings: [finding({ file_path: 'C:\\proj\\src\\db.ts' })] }));
    const doc = JSON.parse(renderSarif(v, 'C:\\proj'));
    const uri = doc.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri;
    expect(uri).toBe('src/db.ts');
    expect(uri).not.toMatch(/^[A-Za-z]:/);
  });

  it('omits the location, rather than emitting an empty URI, when file_path IS the project root', () => {
    // `file_path === projectPath` (e.g. a finding about the project as a
    // whole, not one file inside it — see `toRelativeIfPossible` in
    // `runners/scannerParsers/index.ts`, which recognises the same case)
    // relativises to `''`. `toSarif`'s own `if (f.file_path)` check (see
    // `report/sarif.ts`, unmodified by this task) treats `''` the same as
    // absent and omits `locations` — which, on reflection, is the more
    // honest rendering here anyway: a finding about the whole project has
    // no single line to annotate, so no location beats a misleading one.
    // This test pins that as understood behaviour, not an accident: an
    // implementation that instead emitted `uri: ''` would fail it.
    const v = evaluateGate(input({ findings: [finding({ file_path: PROJECT })] }));
    const doc = JSON.parse(renderSarif(v, PROJECT));
    expect(doc.runs[0].results).toHaveLength(1);
    expect(doc.runs[0].results[0].locations).toBeUndefined();
    expectValidSarif(doc);
  });

  it('never emits a leading slash, even for a POSIX path outside the project root', () => {
    // Guards the fallback branch specifically: a path sharing no common
    // root with `projectPath` at all (e.g. an absolute path the scanner
    // reported from outside the checkout) cannot be expressed as a true
    // relative path. An implementation that only handles the
    // shares-a-prefix case and returns everything else unchanged would
    // still leave this one absolute.
    const v = evaluateGate(input({ findings: [finding({ file_path: '/etc/passwd' })] }));
    const doc = JSON.parse(renderSarif(v, PROJECT));
    const uri = doc.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri;
    expect(uri.startsWith('/')).toBe(false);
  });

  it('never emits a drive letter, even for a Windows path on a different drive', () => {
    // Same fallback branch, Windows-flavoured: path.relative-style logic
    // cannot express a cross-drive path as relative at all, and a naive
    // port of that logic would leave `D:\...` absolute (and drive-lettered)
    // in the output.
    const v = evaluateGate(input({ findings: [finding({ file_path: 'D:\\other\\src\\db.ts' })] }));
    const doc = JSON.parse(renderSarif(v, 'C:\\proj'));
    const uri = doc.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri;
    expect(uri.startsWith('/')).toBe(false);
    expect(uri).not.toMatch(/^[A-Za-z]:/);
  });

  it('omits locations rather than crashing when file_path is absent', () => {
    const v = evaluateGate(input({ findings: [finding({ file_path: undefined })] }));
    const doc = JSON.parse(renderSarif(v, PROJECT));
    expect(doc.runs[0].results).toHaveLength(1);
    expect(doc.runs[0].results[0].locations).toBeUndefined();
    expectValidSarif(doc);
  });

  it('maps every guardian severity onto its own SARIF level explicitly', () => {
    // Exact map, not a spot check: an unmapped severity silently becoming
    // "warning" hides criticals. An implementation that only special-cases
    // 'critical' (or handles 4 of 5 and falls the last through a shared
    // default) would still pass a check that looked at only one severity.
    const findings = SEVERITIES.map((sev, i) => finding({ fingerprint: `fp${i}`, severity: sev }));
    const v = evaluateGate(input({ findings }));
    const doc = JSON.parse(renderSarif(v, PROJECT));
    const results = doc.runs[0].results as { properties: { severity: Severity }; level: string }[];
    const levelOf = (sev: Severity): string | undefined =>
      results.find((r) => r.properties.severity === sev)?.level;

    expect(levelOf('critical')).toBe('error');
    expect(levelOf('high')).toBe('error');
    expect(levelOf('medium')).toBe('warning');
    expect(levelOf('low')).toBe('note');
    expect(levelOf('info')).toBe('note');
  });

  it('still produces a valid, schema-conformant document with zero findings', () => {
    // Resolution #4: an upload step runs on every build, including the
    // green ones — `results: []` must still be a legal SARIF document, not
    // merely an empty array sitting inside an otherwise-broken shape.
    const v = evaluateGate(input());
    const doc = JSON.parse(renderSarif(v, PROJECT));
    expect(doc.runs[0].results).toEqual([]);
    expectValidSarif(doc);
  });

  it('surfaces a dropped-baseline-entries gap as a run-level notification (carried from Task 2)', () => {
    const v = evaluateGate(input({ droppedBaselineEntries: 2 }));
    expect(v.coverageGaps.some((g) => g.startsWith('baseline: '))).toBe(true); // sanity on the fixture
    expect(v.coverage).toBe('full'); // sanity: dropped entries alone never downgrade coverage
    const doc = JSON.parse(renderSarif(v, PROJECT));
    const notifications: { message: { text: string } }[] =
      doc.runs[0].invocations?.[0]?.toolExecutionNotifications ?? [];
    expect(
      notifications.some((n) => /baseline/.test(n.message.text) && /2/.test(n.message.text)),
    ).toBe(true);
    // Coverage is full here (see sanity above) even though there is a
    // notification to carry — executionSuccessful tracks `coverage`, not
    // "does this invocation have anything else attached to it".
    expect(doc.runs[0].invocations[0].executionSuccessful).toBe(true);
    expectValidSarif(doc);
  });

  it('reports executionSuccessful: true and no notifications on a fully clean run', () => {
    const v = evaluateGate(input());
    expect(v.coverage).toBe('full'); // sanity
    const doc = JSON.parse(renderSarif(v, PROJECT));
    expect(doc.runs[0].invocations).toHaveLength(1);
    expect(doc.runs[0].invocations[0].executionSuccessful).toBe(true);
    expect(doc.runs[0].invocations[0].toolExecutionNotifications ?? []).toEqual([]);
    expectValidSarif(doc);
  });

  it('sets executionSuccessful: false when coverage is not full, even with no baseline gap', () => {
    // The SARIF-native way to say "this run was incomplete" (design doc §9,
    // as amended): a consumer reading only the SARIF upload can now tell a
    // clean scan from an incomplete one from `executionSuccessful` alone,
    // without cross-referencing the exit code. Guards an implementation
    // that only sets this when there happens to be a baseline notification
    // to attach it to — an ordinary missing-scanner gap, with no baseline
    // involved at all, must still flip it to false.
    const v = evaluateGate(input({ steps: [step({ tools_run: [], missing_tools: ['semgrep'] })] }));
    expect(v.coverage).not.toBe('full'); // sanity on the fixture
    const doc = JSON.parse(renderSarif(v, PROJECT));
    expect(doc.runs[0].invocations).toHaveLength(1);
    expect(doc.runs[0].invocations[0].executionSuccessful).toBe(false);
    expectValidSarif(doc);
  });

  it('does not leak a generic scanner-coverage gap\'s text into SARIF (design doc §9, as amended)', () => {
    // design doc §9 (original): "SARIF carries findings, not the coverage
    // signal." As amended per review: the coarse *boolean* signal
    // (executionSuccessful — see the test above) is now deliberately part
    // of SARIF, closing the "a SARIF-only consumer can't tell" gap §9
    // itself named. What stays out is the general coverage gaps' free
    // TEXT — tool names, "not installed" reasons — which have no home in
    // SARIF's findings-shaped `results` and would be noise if dumped into
    // `properties` or a notification. Only the dropped-baseline-entries
    // line is the carried-forward exception for text specifically (see the
    // notification test above), because it is about the trustworthiness of
    // THIS document's results, not scan completeness in general.
    const v = evaluateGate(input({ steps: [step({ tools_run: [], missing_tools: ['semgrep'] })] }));
    expect(v.coverageGaps.some((g) => g.includes('semgrep'))).toBe(true); // sanity on the fixture
    const doc = JSON.parse(renderSarif(v, PROJECT));
    expect(JSON.stringify(doc)).not.toMatch(/semgrep/);
  });
});

describe('renderHuman', () => {
  it('names every coverage gap, not only the finding count', () => {
    const v = evaluateGate(input({ steps: [step({ tools_run: [], missing_tools: ['semgrep'] })] }));
    expect(renderHuman(v)).toMatch(/semgrep/);
  });

  it('surfaces the dropped-baseline-entries gap by name and count (carried from Task 2)', () => {
    const v = evaluateGate(input({ droppedBaselineEntries: 3 }));
    const text = renderHuman(v);
    expect(text).toMatch(/baseline/);
    expect(text).toMatch(/3/);
  });

  // Follow-up to the task-3 report's discrepancy #1: `GateVerdict` did not
  // preserve whether `baseline` was `null` (absent file) or present-but-empty,
  // so `renderHuman` had nothing to consult. Fixed by adding
  // `GateVerdict.baselineAbsent` (see gate.ts and its own new tests in
  // gate.test.ts) — carried forward from `baseline === null` rather than
  // inferred, since `newFindings` behaves identically for both cases.

  it('says plainly when the baseline file was absent, and how to fix it', () => {
    const v = evaluateGate(input({ baseline: null }));
    expect(v.baselineAbsent).toBe(true); // sanity on the fixture
    expect(renderHuman(v)).toMatch(/baseline update/);
  });

  it('says nothing about an absent baseline when one was present, even if empty', () => {
    // Guards an implementation that infers "absent" from something else
    // (e.g. "every finding is new") rather than reading `baselineAbsent`
    // directly — a present-but-empty baseline also makes every finding
    // "new", but must not trigger the absent-baseline message.
    const v = evaluateGate(input({ baseline: buildBaseline([], null, 'x') }));
    expect(v.baselineAbsent).toBe(false); // sanity on the fixture
    expect(renderHuman(v)).not.toMatch(/baseline update/);
  });

  it('distinguishes an incomplete scan with zero findings from a clean pass', () => {
    // Self-review question 2. A renderer that only prints "0 new findings"
    // when `newFindings` is empty would read identically whether coverage is
    // 'full' or not, so a reader could not tell an incomplete scan from a
    // clean one without cross-referencing a separate line themselves. The
    // headline must name the exit state, not just the count.
    const incomplete = evaluateGate(
      input({ steps: [step({ tools_run: [], missing_tools: ['semgrep'] })] }),
    );
    const clean = evaluateGate(input());
    expect(incomplete.newFindings).toEqual([]); // sanity: both fixtures have 0 findings
    expect(clean.newFindings).toEqual([]);
    expect(incomplete.exitCode).toBe(CI_EXIT.INCOMPLETE_SCAN);
    expect(clean.exitCode).toBe(CI_EXIT.PASS);

    const incompleteText = renderHuman(incomplete);
    const cleanText = renderHuman(clean);
    expect(incompleteText).not.toBe(cleanText);
    expect(incompleteText).toMatch(/INCOMPLETE/i);
    expect(cleanText).not.toMatch(/INCOMPLETE/i);
  });

  it('lists each blocking finding with its severity and file path', () => {
    const v = evaluateGate(
      input({ findings: [finding({ severity: 'critical', file_path: 'src/db.ts' })] }),
    );
    const text = renderHuman(v);
    expect(text).toMatch(/critical/);
    expect(text).toMatch(/src\/db\.ts/);
  });

  it('appends the line number when the finding has one', () => {
    const v = evaluateGate(
      input({ findings: [finding({ severity: 'critical', file_path: 'src/db.ts', line_start: 42 })] }),
    );
    const text = renderHuman(v);
    expect(text).toMatch(/^ {2}- \[critical] SQL injection \(src\/db\.ts:42\)$/m);
  });

  it('lists a blocking finding with no file_path without printing an empty location', () => {
    // `Finding.file_path` is optional (e.g. a dependency/license finding
    // with no single file to point at). Guards a template-literal
    // implementation that renders a bare " (undefined)" or " ()" instead of
    // omitting the location segment entirely.
    const v = evaluateGate(
      input({ findings: [finding({ severity: 'critical', file_path: undefined })] }),
    );
    const text = renderHuman(v);
    // Anchored with `$` (multiline mode): if a location were appended after
    // the title on this line, e.g. " (undefined)", the line would no longer
    // end right after "injection" and this match would fail. The headline
    // line legitimately has its own parens ("(exit code N)"), so the
    // assertion is scoped to this one line rather than the whole text.
    expect(text).toMatch(/^ {2}- \[critical] SQL injection$/m);
    expect(text).not.toMatch(/undefined/);
  });

  it('reads as a clean pass when there are no findings and coverage is full', () => {
    const v = evaluateGate(input());
    const text = renderHuman(v);
    expect(text).toMatch(/PASS/);
    expect(text).not.toMatch(/coverage gaps/i);
    expect(text).not.toMatch(/blocking findings/i);
  });
});

describe('renderJson', () => {
  it('round-trips and carries the exit code and the gaps', () => {
    const v = evaluateGate(input({ steps: [step({ tools_run: [], missing_tools: ['semgrep'] })] }));
    const o = JSON.parse(renderJson(v));
    expect(o.exit_code).toBe(CI_EXIT.INCOMPLETE_SCAN);
    expect(o.coverage_gaps).not.toEqual([]);
  });

  it('separates new findings from blocking findings rather than conflating them', () => {
    // Guards an implementation that serialises the same array under both
    // keys (or omits one entirely).
    const v = evaluateGate(input({ findings: [finding({ severity: 'low' })], failOn: 'critical' }));
    const o = JSON.parse(renderJson(v));
    expect(o.new_findings).toHaveLength(1);
    expect(o.blocking_findings).toHaveLength(0);
  });

  it('carries the coverage value alongside the gaps', () => {
    const v = evaluateGate(input());
    const o = JSON.parse(renderJson(v));
    expect(o.coverage).toBe('full');
    expect(o.exit_code).toBe(CI_EXIT.PASS);
    expect(o.coverage_gaps).toEqual([]);
  });

  it('carries baseline_absent, distinctly from an empty baseline', () => {
    const absent = JSON.parse(renderJson(evaluateGate(input({ baseline: null }))));
    const empty = JSON.parse(renderJson(evaluateGate(input({ baseline: buildBaseline([], null, 'x') }))));
    expect(absent.baseline_absent).toBe(true);
    expect(empty.baseline_absent).toBe(false);
  });
});
