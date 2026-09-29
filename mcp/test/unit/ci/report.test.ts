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
 *
 * `ajv-formats` (task 4 brief, item 5) is applied on top: measured by hand
 * before wiring it in, plain `ajv`/`ajv-draft-04` does NOT enforce the
 * `format` keyword at all — `{ type: 'string', format: 'uri-reference' }`
 * accepted a raw space, `%`, and `#` with no complaint, because format
 * validation moved into this separate, opt-in package starting at ajv@7.
 * That means every `expectValidSarif` call below this comment ran with
 * `uri-reference` silently unchecked until now — the SARIF-shaped assertions
 * were real, but the one property that would have caught `toSarif`'s
 * unescaped-URI bug was not. `ajv-formats` was already resolved
 * transitively (via `ajv-draft-04`'s own tree) before this task promoted it
 * to an explicit devDependency.
 *
 * Loaded with `createRequire`, not `import addFormats from 'ajv-formats'`:
 * confirmed by hand that the ordinary default import does not type-check
 * under this project's `moduleResolution: "NodeNext"` — `ajv-formats` ships
 * no `"type"`/`"exports"` field, and its `.d.ts` uses ESM `export default`
 * syntax for what Node16/NodeNext resolution treats as a CommonJS module;
 * `tsc` infers the MODULE NAMESPACE type for the import instead of the
 * default export and rejects calling it ("not callable"). `ajv-draft-04`,
 * imported the ordinary way two lines below, does not hit this — only
 * `ajv-formats` lacks the `export =` a CommonJS `.d.ts` needs for
 * `esModuleInterop` to unwrap it correctly here. `createRequire` sidesteps
 * the broken VALUE-level interop entirely (a plain runtime `require`, which
 * is what `ajv-formats` truly is); the TYPE still comes from the package's
 * own `.d.ts` via `FormatsPlugin`, so this is a loader workaround, not a
 * type escape hatch.
 */
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import Ajv from 'ajv-draft-04';
import type { FormatsPlugin } from 'ajv-formats';
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

/** A security_scan_full step whose Semgrep only partly parsed one file (follow-up X1). */
const WP = 'wp/rest-controller.php';
function partialStep(): ScanStepResult {
  return step({
    tool: 'security_scan_full',
    tools_run: [
      {
        name: 'semgrep',
        status: 'ok',
        reason: 'partial: 1 file(s) only partly parsed',
        partially_parsed: [{ file: WP, type: 'PartialParsing', message: 'Syntax error' }],
      },
    ],
    missing_tools: ['semgrep'],
    partial_parses: { semgrep: [{ file: WP, type: 'PartialParsing' }] },
  });
}

// See the module doc comment above for why this is `require`d rather than
// imported.
const addFormats = createRequire(import.meta.url)('ajv-formats') as FormatsPlugin;

describe('renderSarif', () => {
  const schema = JSON.parse(
    readFileSync('test/fixtures/sarif/sarif-schema-2.1.0.json', 'utf8'),
  ) as object;
  const ajv = new Ajv({ strict: false, allErrors: true, logger: false });
  addFormats(ajv);
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
    // on the PR diff (the design of record), not just what fails the gate — a
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
    // The SARIF-native way to say "this run was incomplete" (the design of record,
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

  it('keeps executionSuccessful: false for an accepted partial parse — coverage stays partial (follow-up X1)', () => {
    const v = evaluateGate(input({ steps: [partialStep()], acceptedPartialParses: [WP] }));
    expect(v.exitCode).toBe(CI_EXIT.PASS); // sanity: accepted
    const doc = JSON.parse(renderSarif(v, PROJECT));
    expect(doc.runs[0].invocations[0].executionSuccessful).toBe(false);
    expectValidSarif(doc);
  });

  it('keeps executionSuccessful: true on a GATE_FAILED verdict when coverage is still full', () => {
    // Mutation-proven gap (task report): rewiring the implementation to
    // `v.exitCode === 0` instead of `v.coverage === 'full'` left every other
    // test in this suite green, because none of them exercises the
    // combination that actually tells the two apart. GATE_FAILED with full
    // coverage is not an edge case — it is the COMMON shape of a red build:
    // every scanner ran, and the user's code has a real, new, blocking
    // finding. executionSuccessful describes whether the SCAN executed
    // successfully, not whether the gate passed; a mutant (or a future
    // change) that conflates the two would tell GitHub Code Scanning the
    // scan itself failed on most red builds, when what actually failed is
    // the code under scan.
    const v = evaluateGate(
      input({ findings: [finding({ severity: 'critical' })], failOn: 'high' }),
    );
    expect(v.exitCode).toBe(CI_EXIT.GATE_FAILED); // sanity: a blocking finding, not a coverage gap
    expect(v.coverage).toBe('full'); // sanity: every step in the default fixture ran
    const doc = JSON.parse(renderSarif(v, PROJECT));
    expect(doc.runs[0].invocations).toHaveLength(1);
    expect(doc.runs[0].invocations[0].executionSuccessful).toBe(true);
    expectValidSarif(doc);
  });

  it('does not leak a generic scanner-coverage gap\'s text into SARIF (the design of record, as amended)', () => {
    // the design of record (original): "SARIF carries findings, not the coverage
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

  // Task 4 brief, item 5: the three characters this schema test could not
  // actually catch before `ajv-formats` was wired in above. Each is a
  // project-relative path (`renderSarif`'s own relativisation — tested
  // elsewhere in this file — is orthogonal to the encoding fixed here), so
  // this is exercising exactly the shape `toSarif`/`toUri` receives from a
  // real scan.
  it('produces a schema-valid document for a file path containing a space', () => {
    const v = evaluateGate(input({ findings: [finding({ file_path: 'src/my file.ts' })] }));
    const doc = JSON.parse(renderSarif(v, PROJECT));
    expectValidSarif(doc);
    const uri = doc.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri;
    expect(uri).toBe('src/my%20file.ts');
  });

  it('produces a schema-valid document for a file path containing a percent sign', () => {
    const v = evaluateGate(input({ findings: [finding({ file_path: 'src/100%.ts' })] }));
    const doc = JSON.parse(renderSarif(v, PROJECT));
    expectValidSarif(doc);
    const uri = doc.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri;
    expect(uri).toBe('src/100%25.ts');
  });

  it('produces a schema-valid document for a file path containing #, without corrupting it into a fragment', () => {
    const v = evaluateGate(input({ findings: [finding({ file_path: 'src/notes#3.md' })] }));
    const doc = JSON.parse(renderSarif(v, PROJECT));
    expectValidSarif(doc);
    const uri = doc.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri;
    expect(uri).not.toContain('#');
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

  it('prints an accepted partial parse as accepted — never as a gap — with coverage partial (follow-up X1)', () => {
    const text = renderHuman(evaluateGate(input({ steps: [partialStep()], acceptedPartialParses: [WP, 'x.php'] })));
    expect(text).toMatch(/^dev-guardian CI: PASS \(exit code 0\)$/m);
    expect(text).toMatch(/^coverage: partial$/m);
    expect(text).not.toMatch(/coverage gaps/i);
    expect(text).toMatch(/^accepted \(--accept-partial-parse\):$/m);
    expect(text).toMatch(/^ {2}- security_scan_full: semgrep only partly parsed wp\/rest-controller\.php — accepted/m);
    expect(text).toMatch(/--accept-partial-parse x\.php: no step reported it partly parsed/);
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

  it('carries accepted partial parses apart from the gaps, and coverage stays partial (follow-up X1)', () => {
    const o = JSON.parse(renderJson(evaluateGate(input({ steps: [partialStep()], acceptedPartialParses: [WP, 'x.php'] }))));
    expect(o.exit_code).toBe(CI_EXIT.PASS);
    expect(o.coverage).toBe('partial');
    expect(o.coverage_gaps).toEqual([]);
    expect(o.accepted_gaps).toEqual([
      'security_scan_full: semgrep only partly parsed wp/rest-controller.php — accepted (--accept-partial-parse)',
    ]);
    expect(o.unused_partial_parse_acceptances).toEqual(['x.php']);
  });

  it('carries baseline_absent, distinctly from an empty baseline', () => {
    const absent = JSON.parse(renderJson(evaluateGate(input({ baseline: null }))));
    const empty = JSON.parse(renderJson(evaluateGate(input({ baseline: buildBaseline([], null, 'x') }))));
    expect(absent.baseline_absent).toBe(true);
    expect(empty.baseline_absent).toBe(false);
  });
});

/**
 * Round 4, item 2: a step whose Trivy run the repository's own .trivyignore
 * silenced — counted and named (`runners/trivyRun.ts`), never a gap.
 */
function suppressedStep(): ScanStepResult {
  const suppressedFinding = (id: string): Finding => ({
    fingerprint: `fp-${id}`,
    tool: 'trivy',
    rule_id: id,
    severity: 'high',
    category: 'security',
    subcategory: 'cve',
    title: `${id} in lodash`,
    file_path: 'package-lock.json',
    fix_available: true,
  });
  return step({
    tool: 'security_scan_full',
    tools_run: [
      {
        name: 'trivy',
        status: 'ok',
        honoured_config: ['.trivyignore'],
        suppressed_by_repo_config: {
          file: '.trivyignore',
          count: 2,
          ids: ['CVE-2020-8203', 'NSWG-ECO-516'],
          findings: [suppressedFinding('CVE-2020-8203'), suppressedFinding('NSWG-ECO-516')],
        },
      },
    ],
  });
}

describe("findings the repository's own configuration suppressed (round 4, item 2)", () => {
  const schema = JSON.parse(readFileSync('test/fixtures/sarif/sarif-schema-2.1.0.json', 'utf8')) as object;
  const ajv = new Ajv({ strict: false, allErrors: true, logger: false });
  addFormats(ajv);
  const validate = ajv.compile(schema);

  it('human: named, counted, and said not to be counted by the gate', () => {
    const text = renderHuman(evaluateGate(input({ steps: [suppressedStep()] })));
    expect(text).toMatch(/PASS/);
    expect(text).toMatch(/suppressed by the repository's own configuration \(not counted by the gate\):/);
    expect(text).toMatch(
      /  - security_scan_full: trivy: 2 findings suppressed by the repository's \.trivyignore: CVE-2020-8203, NSWG-ECO-516/,
    );
    expect(renderHuman(evaluateGate(input()))).not.toMatch(/suppressed by the repository/);
  });

  it('JSON: suppressed_by_repo_config', () => {
    const o = JSON.parse(renderJson(evaluateGate(input({ steps: [suppressedStep()] }))));
    expect(o.suppressed_by_repo_config).toHaveLength(1);
    expect(o.suppressed_by_repo_config[0]).toMatchObject({
      step: 'security_scan_full',
      tool: 'trivy',
      file: '.trivyignore',
      count: 2,
      ids: ['CVE-2020-8203', 'NSWG-ECO-516'],
    });
    expect(o.suppressed_by_repo_config[0].findings).toHaveLength(2);
    expect(JSON.parse(renderJson(evaluateGate(input()))).suppressed_by_repo_config).toEqual([]);
  });

  it('SARIF: each as a result with an external suppression naming the file; still a valid document', () => {
    const v = evaluateGate(input({ findings: [finding()], steps: [suppressedStep()] }));
    const doc = JSON.parse(renderSarif(v, PROJECT));
    const ok = validate(doc);
    expect(validate.errors ?? [], JSON.stringify(validate.errors, null, 2)).toEqual([]);
    expect(ok).toBe(true);
    const results = doc.runs[0].results as Array<Record<string, unknown>>;
    expect(results).toHaveLength(3);
    const suppressed = results.filter((r) => r['suppressions'] !== undefined);
    expect(suppressed.map((r) => r['ruleId'])).toEqual(['CVE-2020-8203', 'NSWG-ECO-516']);
    for (const r of suppressed) {
      expect(r['suppressions']).toEqual([
        { kind: 'external', justification: "suppressed by the repository's .trivyignore" },
      ]);
    }
    // The new finding is not suppressed, and a rule exists for every result.
    expect(results.filter((r) => r['suppressions'] === undefined)).toHaveLength(1);
    const rules = (doc.runs[0].tool.driver.rules as Array<{ id: string }>).map((r) => r.id);
    expect(rules).toEqual(expect.arrayContaining(['CVE-2020-8203', 'NSWG-ECO-516']));
  });
});

describe('where the baseline and the rules came from (--baseline-ref, --rules-ref)', () => {
  const COMMIT = '3a5adedb7f872de55c5a35820033be7f01d75f2a';

  it("without either flag, both lines name the scanned tree — the pull request's own, on a pull request", () => {
    const v = evaluateGate(input());
    expect(v.baselineSource).toEqual({ from: 'tree', path: '.guardian/baseline.json' });
    expect(v.rulesSource).toEqual({ from: 'tree' });
    const text = renderHuman(v);
    expect(text).toMatch(/^baseline: \.guardian\/baseline\.json in the scanned tree \(no --baseline-ref\)$/m);
    expect(text).toMatch(/^rules and configuration: the scanned tree's own \(no --rules-ref\)$/m);
    const o = JSON.parse(renderJson(v));
    expect(o.baseline_source).toEqual({ from: 'tree', path: '.guardian/baseline.json' });
    expect(o.rules_source).toEqual({ from: 'tree' });
  });

  it("a baseline read at a ref names the ref and its commit, and says the tree's differing copy was not read", () => {
    const baselineSource = {
      from: 'ref' as const,
      path: '.guardian/baseline.json',
      ref: 'origin/main',
      commit: COMMIT,
      present: true,
      tree_differs: true,
    };
    const v = evaluateGate(input({ baseline: buildBaseline([], null, 'now'), baselineSource }));
    expect(renderHuman(v)).toMatch(
      /^baseline: \.guardian\/baseline\.json at origin\/main \(3a5adedb7f87\) — the scanned tree's copy differs and was not read$/m,
    );
    expect(JSON.parse(renderJson(v)).baseline_source).toEqual(baselineSource);
  });

  it('none at the ref: every finding is new, and the fix is on that branch — not "run baseline update" here', () => {
    const baselineSource = {
      from: 'ref' as const,
      path: '.guardian/baseline.json',
      ref: 'origin/main',
      commit: COMMIT,
      present: false,
      tree_differs: false,
    };
    const text = renderHuman(evaluateGate(input({ findings: [finding()], baselineSource })));
    expect(text).toMatch(/^baseline: none at origin\/main \(3a5adedb7f87\), so every finding is new$/m);
    expect(text).toMatch(/no usable baseline at origin\/main — run `dev-guardian baseline update` on that branch/);
    expect(text).not.toMatch(/no baseline found/);
  });

  it('rules from a ref: what was read, what the ref lacks, and each configuration change named by which copy applied', () => {
    const rulesSource = {
      from: 'ref' as const,
      ref: 'origin/main',
      commit: COMMIT,
      copied: ['.semgrep.yml'],
      absent: ['.guardianignore', '.trivyignore'],
      tree_differences: [
        { path: '.gitleaksignore', change: 'added' as const, applied: 'tree' as const, read_by: ['gitleaks'] },
        { path: '.guardianignore', change: 'added' as const, applied: 'ref' as const, read_by: ['guardian'] },
        { path: '.semgrep.yml', change: 'modified' as const, applied: 'ref' as const, read_by: ['semgrep'] },
      ],
    };
    const v = evaluateGate(input({ rulesSource }));
    // Visibility only: a clean run still passes.
    expect(v.exitCode).toBe(CI_EXIT.PASS);
    const text = renderHuman(v);
    expect(text).toMatch(
      /^rules and configuration: from origin\/main \(3a5adedb7f87\): \.semgrep\.yml; not at the ref, so none read: \.guardianignore, \.trivyignore$/m,
    );
    expect(text).toMatch(
      /read from the scanned tree although it differs from origin\/main \(no ref can supply it — review it\):\n {2}- \.gitleaksignore \(added; read by gitleaks\)/,
    );
    expect(text).toMatch(
      /changed in the scanned tree, not applied \(origin\/main's copy was read\):\n {2}- \.guardianignore \(added\)\n {2}- \.semgrep\.yml \(modified\)/,
    );
    expect(JSON.parse(renderJson(v)).rules_source).toEqual(rulesSource);
  });

  it('nothing changed against the ref: no difference section at all', () => {
    const rulesSource = {
      from: 'ref' as const,
      ref: 'main',
      commit: COMMIT,
      copied: [],
      absent: ['.semgrep.yml'],
      tree_differences: [],
    };
    const text = renderHuman(evaluateGate(input({ rulesSource })));
    expect(text).toMatch(
      /^rules and configuration: from main \(3a5adedb7f87\): none — the ref has none of them; not at the ref, so none read: \.semgrep\.yml$/m,
    );
    expect(text).not.toMatch(/differs from main|not applied/);
  });
});
