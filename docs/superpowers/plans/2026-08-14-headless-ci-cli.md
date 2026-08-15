# Headless CI CLI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make dev-guardian's scans runnable from a CI pipeline — gated against
a committed baseline so historical debt does not fail the build, and reported
as SARIF so findings annotate the pull-request diff.

**Architecture:** The behaviour lives in TypeScript under `mcp/src/ci/`;
`cli/dev-guardian.mjs` stays a thin argument-parsing shim importing from
`../mcp/dist/`. Scans run through the existing MCP tool handlers — there is no
second implementation. The SQLite database is ephemeral; the portable state is
a committed baseline file.

**Tech Stack:** TypeScript (ESM, `"module": "NodeNext"` — `.js` import
specifiers), `node:sqlite` via the existing `Storage`, vitest. `cli/*.mjs` is
plain ESM JavaScript run directly by Node.

**Design of record:** [`docs/superpowers/specs/2026-08-14-headless-ci-cli-design.md`](../specs/2026-08-14-headless-ci-cli-design.md).
Read it before starting. Where this plan and the spec disagree, **the spec
wins** — report the discrepancy rather than silently resolving it. That has
happened seven times across the previous features and reporting it was correct
every time.

## Global Constraints

- **Build and test from `mcp/`.** `npm run build`, `npm test`, `npm run test:coverage`.
- **Commit `mcp/dist/`.** The repo *is* the distribution — Claude Code runs
  `mcp/dist/server.js` with no install-time build, and `cli/dev-guardian.mjs`
  imports from `mcp/dist/`. Run `npm run build` and stage `mcp/dist/` in the
  **same commit** as any `mcp/src/` change.
- TypeScript: `noUncheckedIndexedAccess`, `noUnusedLocals`,
  `noUnusedParameters`. **No `!` non-null assertions. No `any`.**
- **ESM import specifiers end in `.js`** even for `.ts` sources.
- **No new runtime dependencies.** One permitted exception, for Task 3 only: a
  **devDependency** for SARIF schema validation. The spec requires validation
  *against the schema*, and hand-rolled structural assertions are exactly the
  "my idea of the schema" it warns against.
- **Never add a top-level `bin/` directory.** The Claude Desktop plugin
  validator rejects any plugin shipping one, and the failure message points
  nowhere near the cause. Executable entry points belong in `cli/`.
- **A finding count without `coverage` beside it is not an answer.** Reuse
  `computeCoverage` from `mcp/src/tools/scanCoverage.ts`; do not re-derive
  "complete" anywhere.
- **`--start-command` may come only from argv, never from a repository file.**
- **Tests must distinguish the correct implementation from the plausible-wrong
  one.** The previous feature had thirteen findings of exactly that shape, most
  caught only by executing the shipped code or mutating it. Before writing an
  assertion, name the wrong implementation you are guarding against and confirm
  your assertion fails against it.
- **A skipped test must read as a skip** (`it.skipIf`), never `console.warn` +
  bare `return`. `GUARDIAN_REQUIRE_SEMGREP=1` turns absence into a hard failure.
- Markdownlint stays clean for `skills/`, `commands/`, `README.md`.

---

## File Structure

| File | Kind | Responsibility |
| --- | --- | --- |
| `mcp/src/ci/types.ts` | types | `BaselineFile`, `BaselineEntry`, `GateVerdict`, `CiExitCode`, `ScanStepResult`. |
| `mcp/src/ci/baseline.ts` | **pure** | Parse, serialise, and diff a baseline against a finding set. |
| `mcp/src/ci/gate.ts` | **pure** | Findings + baseline + threshold + coverage → verdict and exit code. |
| `mcp/src/ci/report.ts` | **pure** | Human, JSON and SARIF rendering. |
| `mcp/src/ci/runScans.ts` | I/O | Ephemeral context, ordered pipeline, per-step outcomes. |
| `mcp/src/ci/appRunner.ts` | I/O | Application lifecycle for the DAST pass. **Separable.** |
| `cli/dev-guardian.mjs` | modify | `scan` and `baseline` commands, exit codes. |

---

## Task 1: Types and the baseline file

**Files:**

- Create: `mcp/src/ci/types.ts`
- Create: `mcp/src/ci/baseline.ts`
- Test: `mcp/test/unit/ci/baseline.test.ts`

**Interfaces:**

- Consumes: `Finding`, `Severity` from `../types.js`.
- Produces:

```ts
export interface BaselineEntry {
  fingerprint: string;
  severity: Severity;
  title: string;
  file_path?: string;
  /** ISO date this entry entered the baseline. Stable across regenerations. */
  added: string;
}
export interface BaselineFile {
  version: 1;
  generated_at: string;
  entries: BaselineEntry[];
}
export const BASELINE_RELATIVE_PATH = '.guardian/baseline.json';

/** `null` means the file was absent — NOT an empty baseline. */
export function parseBaseline(text: string | null): BaselineFile | null;
export function serialiseBaseline(file: BaselineFile): string;
export function buildBaseline(
  findings: readonly Finding[],
  previous: BaselineFile | null,
  now: string,
): BaselineFile;
export function newFindings(
  findings: readonly Finding[],
  baseline: BaselineFile | null,
): Finding[];
```

- [ ] **Step 1: Write `mcp/src/ci/types.ts`**

Types only; no test. Later tasks import from it.

```ts
/**
 * Shapes shared by the CI entry point.
 *
 * `CiExitCode` is a union rather than bare numbers because the exit code IS
 * the contract with the pipeline: 2 in particular exists so that "a scanner
 * did not run" can never be mistaken for "nothing was found".
 */

import type { Severity } from '../types.js';

export const CI_EXIT = {
  PASS: 0,
  GATE_FAILED: 1,
  INCOMPLETE_SCAN: 2,
  USAGE_ERROR: 3,
} as const;
export type CiExitCode = (typeof CI_EXIT)[keyof typeof CI_EXIT];

export interface BaselineEntry {
  fingerprint: string;
  severity: Severity;
  title: string;
  file_path?: string;
  /** ISO date this entry entered the baseline. Preserved across regenerations
   *  so a reviewer can see how long a suppression has been carried. */
  added: string;
}

export interface BaselineFile {
  version: 1;
  generated_at: string;
  entries: BaselineEntry[];
}

export interface ScanStepResult {
  tool: string;
  ran: boolean;
  /** Present when `ran` is false: why the step did not produce results. */
  reason?: string;
  tools_run: ToolRun[];
  missing_tools: string[];
}
```

Import `ToolRun` from `../types.js`.

- [ ] **Step 2: Write the failing test**

Create `mcp/test/unit/ci/baseline.test.ts`:

```ts
import { describe, expect, it } from 'vitest';
import {
  parseBaseline, serialiseBaseline, buildBaseline, newFindings,
} from '../../../src/ci/baseline.js';
import type { Finding } from '../../../src/types.js';

function finding(over: Partial<Finding> = {}): Finding {
  return {
    fingerprint: 'fp1', tool: 'semgrep', severity: 'high', category: 'security',
    title: 'SQL injection', file_path: 'src/db.ts', fix_available: false, ...over,
  };
}

describe('parseBaseline', () => {
  it('returns null for an absent file, which is NOT an empty baseline', () => {
    // The distinction is the whole point: treating "no file" as "no known
    // findings" would fail the first build of every existing repository.
    expect(parseBaseline(null)).toBeNull();
  });

  it('returns an empty baseline for a file that genuinely holds none', () => {
    const parsed = parseBaseline('{"version":1,"generated_at":"x","entries":[]}');
    expect(parsed).not.toBeNull();
    expect(parsed?.entries).toEqual([]);
  });

  it('returns null for unparseable content rather than throwing', () => {
    expect(parseBaseline('{ not json')).toBeNull();
  });

  it('returns null for a JSON document of the wrong shape', () => {
    expect(parseBaseline('{"version":99}')).toBeNull();
    expect(parseBaseline('[]')).toBeNull();
  });
});

describe('newFindings', () => {
  it('returns everything when the baseline is absent', () => {
    expect(newFindings([finding()], null)).toHaveLength(1);
  });

  it('returns nothing when every fingerprint is baselined', () => {
    const b = buildBaseline([finding()], null, '2026-08-14');
    expect(newFindings([finding()], b)).toEqual([]);
  });

  it('returns only the fingerprints absent from the baseline', () => {
    const b = buildBaseline([finding({ fingerprint: 'old' })], null, '2026-08-14');
    const out = newFindings([finding({ fingerprint: 'old' }), finding({ fingerprint: 'new' })], b);
    expect(out.map((f) => f.fingerprint)).toEqual(['new']);
  });

  it('matches on fingerprint alone, not on severity or title', () => {
    // Guards the wrong implementation that compares whole objects: a scanner
    // re-wording a message would then resurface every baselined finding.
    const b = buildBaseline([finding({ title: 'old wording' })], null, '2026-08-14');
    expect(newFindings([finding({ title: 'new wording', severity: 'critical' })], b)).toEqual([]);
  });
});

describe('buildBaseline', () => {
  it('preserves the original `added` date for a fingerprint already present', () => {
    // A regeneration must not reset the clock on an old suppression — that
    // date is how a reviewer sees how long something has been carried.
    const first = buildBaseline([finding()], null, '2026-01-01');
    const second = buildBaseline([finding()], first, '2026-08-14');
    expect(second.entries[0]?.added).toBe('2026-01-01');
  });

  it('stamps a new fingerprint with the current date', () => {
    const first = buildBaseline([finding({ fingerprint: 'a' })], null, '2026-01-01');
    const second = buildBaseline(
      [finding({ fingerprint: 'a' }), finding({ fingerprint: 'b' })], first, '2026-08-14',
    );
    expect(second.entries.find((e) => e.fingerprint === 'b')?.added).toBe('2026-08-14');
  });

  it('drops entries whose finding no longer exists', () => {
    const first = buildBaseline([finding({ fingerprint: 'gone' })], null, '2026-01-01');
    const second = buildBaseline([finding({ fingerprint: 'kept' })], first, '2026-08-14');
    expect(second.entries.map((e) => e.fingerprint)).toEqual(['kept']);
  });

  it('sorts entries by fingerprint so the file does not churn between runs', () => {
    // A file whose line order moves on every regeneration produces noise
    // diffs and nobody reviews it any more.
    const b = buildBaseline(
      [finding({ fingerprint: 'c' }), finding({ fingerprint: 'a' }), finding({ fingerprint: 'b' })],
      null, '2026-08-14',
    );
    expect(b.entries.map((e) => e.fingerprint)).toEqual(['a', 'b', 'c']);
  });
});

describe('serialiseBaseline', () => {
  it('round-trips through parseBaseline', () => {
    const b = buildBaseline([finding()], null, '2026-08-14');
    expect(parseBaseline(serialiseBaseline(b))).toEqual(b);
  });

  it('ends with a newline so the file is POSIX-clean in a diff', () => {
    expect(serialiseBaseline(buildBaseline([], null, 'x')).endsWith('\n')).toBe(true);
  });
});
```

- [ ] **Step 3: Run to verify it fails**

Run: `cd mcp && npx vitest run test/unit/ci/baseline.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 4: Implement `baseline.ts`**

Pure. The doc comment must state why an absent file is not an empty one, in the
house style of `mcp/src/surface/specDiff.ts`.

- [ ] **Step 5: Run to verify it passes, then the suite, build, commit**

```bash
cd mcp && npm test && npm run build
git add mcp/src/ci mcp/test/unit/ci mcp/dist
git commit -m "feat(ci): baseline file, where an absent file is not an empty one"
```

---

## Task 2: The gate

**Files:**

- Create: `mcp/src/ci/gate.ts`
- Test: `mcp/test/unit/ci/gate.test.ts`

**Interfaces:**

- Consumes: `newFindings` and `BaselineFile` (Task 1); `CI_EXIT`, `CiExitCode`,
  `ScanStepResult` (Task 1); `computeCoverage` from `../tools/scanCoverage.js`;
  `SEVERITY_ORDER` from `../types.js`.
- Produces:

```ts
export interface GateInput {
  findings: readonly Finding[];
  baseline: BaselineFile | null;
  failOn: Severity;
  steps: readonly ScanStepResult[];
}
export interface GateVerdict {
  exitCode: CiExitCode;
  newFindings: Finding[];
  /** New findings at or above `failOn`. Subset of `newFindings`. */
  blocking: Finding[];
  coverage: ScanCoverage;
  /** One line per gap, naming the scanner and why. Empty only when none. */
  coverageGaps: string[];
}
export function evaluateGate(input: GateInput): GateVerdict;
```

- [ ] **Step 1: Write the failing test**

```ts
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

function input(over: Partial<Parameters<typeof evaluateGate>[0]> = {}) {
  return {
    findings: [] as Finding[], baseline: null, failOn: 'high' as Severity,
    steps: [step()], ...over,
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
```

- [ ] **Step 2: Run to verify it fails.** Expected: module not found.

- [ ] **Step 3: Implement `gate.ts`**

Severity comparison uses `SEVERITY_ORDER` from `../types.js` — do not re-derive
an ordering. Coverage comes from `computeCoverage(toolsRun, missingTools)` over
the union of every step's arrays; **do not write a second definition of
"complete"**. A step with `ran: false` contributes its `reason` as a gap.

- [ ] **Step 4: Run to verify it passes, then suite, build, commit**

```bash
cd mcp && npm test && npm run build
git add mcp/src/ci/gate.ts mcp/test/unit/ci/gate.test.ts mcp/dist
git commit -m "feat(ci): the gate, where a missing scanner is not a green build"
```

---

## Task 3: Report rendering, including schema-validated SARIF

**Files:**

- Create: `mcp/src/ci/report.ts`
- Modify: `mcp/package.json` (one devDependency — see Global Constraints)
- Test: `mcp/test/unit/ci/report.test.ts`

**Interfaces:**

- Consumes: `GateVerdict` (Task 2), `Finding` from `../types.js`.
- Produces:

```ts
export function renderHuman(v: GateVerdict): string;
export function renderJson(v: GateVerdict): string;
export function renderSarif(v: GateVerdict, projectPath: string): string;
```

- [ ] **Step 1: Choose and install the schema validator**

Add **one devDependency** for JSON-schema validation (`ajv` is the obvious
choice) and vendor the SARIF 2.1.0 schema JSON into
`mcp/test/fixtures/sarif/sarif-schema-2.1.0.json`. Record in your report which
validator and which schema revision you used.

Do **not** hand-write structural assertions and call them schema validation.
GitHub accepts a malformed SARIF file silently and displays nothing, which is
indistinguishable from a clean scan — the exact failure this validation exists
to catch.

- [ ] **Step 2: Write the failing test**

```ts
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import Ajv from 'ajv';
import { renderHuman, renderJson, renderSarif } from '../../../src/ci/report.js';
// build a GateVerdict via evaluateGate, as gate.test.ts does

describe('renderSarif', () => {
  it('produces a document that validates against the SARIF 2.1.0 schema', () => {
    const schema = JSON.parse(
      readFileSync('test/fixtures/sarif/sarif-schema-2.1.0.json', 'utf8'),
    ) as object;
    const ajv = new Ajv({ strict: false, allErrors: true });
    const validate = ajv.compile(schema);
    const doc = JSON.parse(renderSarif(verdictWithFindings, '/proj')) as unknown;
    const ok = validate(doc);
    // Print the errors — a bare `toBe(true)` on a schema failure tells you
    // nothing about which field is wrong.
    expect(validate.errors ?? [], JSON.stringify(validate.errors)).toEqual([]);
    expect(ok).toBe(true);
  });

  it('emits one result per finding, with a rule id and a location', () => {
    const doc = JSON.parse(renderSarif(verdictWithTwoFindings, '/proj'));
    expect(doc.runs[0].results).toHaveLength(2);
    expect(doc.runs[0].results[0].ruleId).toBeTruthy();
    expect(doc.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri)
      .toBe('src/db.ts');
  });

  it('emits project-relative URIs, never absolute paths', () => {
    // An absolute path in a SARIF artifactLocation does not match any file in
    // the checkout, so GitHub renders the finding with no line annotation.
    const doc = JSON.parse(renderSarif(verdictAbsolutePaths, '/proj'));
    const uri = doc.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri;
    expect(uri.startsWith('/')).toBe(false);
    expect(uri).not.toMatch(/^[A-Za-z]:/);
  });

  it('maps every guardian severity onto a SARIF level', () => {
    // Exact map, not a spot check: an unmapped severity silently becoming
    // "warning" hides criticals.
    // assert one result per severity with its expected `level`
  });

  it('still produces a valid document with zero findings', () => {
    const doc = JSON.parse(renderSarif(emptyVerdict, '/proj'));
    expect(doc.runs[0].results).toEqual([]);
  });
});

describe('renderHuman', () => {
  it('names every coverage gap, not only the finding count', () => {
    expect(renderHuman(verdictWithGap)).toMatch(/semgrep/);
  });

  it('says plainly when the baseline file was absent', () => {
    expect(renderHuman(verdictNoBaseline)).toMatch(/baseline update/);
  });
});

describe('renderJson', () => {
  it('round-trips and carries the exit code and the gaps', () => {
    const o = JSON.parse(renderJson(verdictWithGap));
    expect(o.exit_code).toBe(2);
    expect(o.coverage_gaps).not.toEqual([]);
  });
});
```

Build the `verdict…` fixtures with `evaluateGate`, not by hand — a hand-built
`GateVerdict` can hold a combination the gate would never produce.

- [ ] **Step 3: Run to verify it fails.** Expected: module not found.

- [ ] **Step 4: Implement `report.ts`.** Pure, no I/O.

- [ ] **Step 5: Run, then suite, build, commit**

```bash
cd mcp && npm test && npm run build
git add mcp/package.json mcp/package-lock.json mcp/src/ci/report.ts mcp/test mcp/dist
git commit -m "feat(ci): human, JSON and schema-validated SARIF output"
```

---

## Task 4: Running the scans

**Files:**

- Create: `mcp/src/ci/runScans.ts`
- Test: `mcp/test/integration/ciRunScans.test.ts`

**Interfaces:**

- Consumes: `TOOLS` from `../tools/index.js` (plus `import '../registerAll.js'`
  for the side-effect registration), `Storage`, `GuardianDatabase`,
  `runMigrations`, `probeShell`, `resolveScriptsDir`, `ScanStepResult` (Task 1).
- Produces:

```ts
export interface RunScansOptions {
  projectPath: string;
  /** Passed to scan_dast when present; absent means the DAST step is skipped. */
  baseUrl?: string;
  authorizedTarget?: boolean;
}
export interface RunScansResult {
  findings: Finding[];
  steps: ScanStepResult[];
}
export async function runScans(opts: RunScansOptions): Promise<RunScansResult>;
export const SCAN_SEQUENCE: readonly string[];
```

- [ ] **Step 1: Write the failing test**

The tool handlers are mocked at the `TOOLS` boundary so this test does not need
Semgrep — what it verifies is orchestration, not scanning.

```ts
describe('runScans', () => {
  it('runs the steps in the documented order', async () => {
    // Order is not cosmetic: map_attack_surface must precede scan_dast and
    // validate_finding, both of which refuse without a surface snapshot.
    const calls: string[] = [];
    // ... stub each handler to push its name
    await runScans({ projectPath: p });
    expect(calls).toEqual([
      'detect_stack', 'security_scan_full', 'license_compatibility',
      'map_attack_surface', 'validate_finding',
    ]);
  });

  it('includes scan_dast only when a base url is given', async () => {
    // and asserts it sits between map_attack_surface and validate_finding
  });

  it('does NOT abort when a step refuses — it records and continues', async () => {
    // The wrong implementation stops at the first refusal and reports less
    // than one that continues and says what it missed.
    // Stub map_attack_surface to return ok:false; assert validate_finding
    // still ran and the step is recorded with ran:false and its reason.
  });

  it('records a step that throws as ran:false rather than crashing the run', async () => {
    // A tool handler throwing must not take the whole pipeline down.
  });

  it('uses an ephemeral database that does not touch the project directory', async () => {
    // Assert no .guardian/ directory was created under projectPath by the run
    // itself — the baseline file is written by the CLI, not here.
  });

  it('collects findings from every step that produced them', async () => { /* exact set */ });
});
```

- [ ] **Step 2: Run to verify it fails.** Expected: module not found.

- [ ] **Step 3: Implement `runScans.ts`**

Build the `PluginContext` the way `mcp/src/server.ts` does — read it first:
`probeShell(storage.runtimeMeta)`, `resolveScriptsDir()`, and a
`progressNotifier` whose `notify` is a no-op (CI has no progress channel).

The database lives in a `mkdtemp` directory, removed on exit including on
failure.

`SCAN_SEQUENCE` is exported so the test asserts against the same constant the
implementation uses — but the order test must assert the **literal expected
array**, not `SCAN_SEQUENCE` itself, or it passes for any order.

- [ ] **Step 4: Run, then suite, build, commit**

```bash
cd mcp && npm test && npm run build
git add mcp/src/ci/runScans.ts mcp/test/integration/ciRunScans.test.ts mcp/dist
git commit -m "feat(ci): ordered scan pipeline over the existing tool handlers"
```

---

## Task 5: The CLI commands

**Files:**

- Modify: `cli/dev-guardian.mjs`
- Test: `mcp/test/e2e/ciCliFixture.test.ts`

**Interfaces:**

- Consumes: everything from Tasks 1–4, imported from `../mcp/dist/ci/*.js`.
- Produces: `dev-guardian scan` and `dev-guardian baseline update`.

- [ ] **Step 1: Write the failing e2e**

The CLI is invoked as a **subprocess**, because that is how a user runs it and
it is the only test that catches a defect in argument dispatch.

```ts
function runCli(args, cwd) {
  return spawnSync(process.execPath, ['cli/dev-guardian.mjs', ...args], {
    cwd: repoRoot, encoding: 'utf8',
  });
}

describe('dev-guardian scan', () => {
  it('exits 3 on an unknown flag, naming it', () => {
    const r = runCli(['scan', '--nope']);
    expect(r.status).toBe(3);
    expect(r.stderr).toMatch(/--nope/);
  });

  it('exits 3 and refuses when --start-command comes from a repo config file', () => {
    // The pwn-request guard. A fork's pull request can edit a repository file;
    // it must never gain code execution on the runner that way.
    // Write a .guardian/ci.json declaring start_command, then run without it
    // on argv; assert the refusal names the file and the reason.
    expect(r.status).toBe(3);
    expect(r.stderr).toMatch(/start.command/i);
  });

  it('writes the baseline only on `baseline update`, never on `scan`', () => {
    // Assert .guardian/baseline.json does not exist after a plain scan.
  });

  it('emits SARIF to the path given by --sarif', () => { /* file exists, parses */ });

  it('prints the human report on stdout and nothing to stderr on a pass', () => {
    // Pristine output: a CI log full of stray warnings trains people to
    // ignore it.
  });
});
```

- [ ] **Step 2: Run to verify it fails.** Expected: unknown command `scan`.

- [ ] **Step 3: Implement the commands in `cli/dev-guardian.mjs`**

Follow the file's existing shape: a `cmdScan(argv)` and `cmdBaseline(argv)`
beside `cmdMcpConfig` and `cmdCheck`, dispatched from `main`, plus help text.

Flags: `--project <path>`, `--fail-on <severity>` (default `high`),
`--format human|json` (default `human`), `--sarif <path>`, `--base-url <url>`,
`--authorized-target`, `--start-command <cmd> [args…]`.

**The `--start-command` refusal is here**, not in the TypeScript: if a
repository config file declares one, exit `3` with a message naming the file
and saying why the key is argv-only. Update the module's header comment to
document the new commands.

- [ ] **Step 4: Run, then suite, build, commit**

```bash
cd mcp && npm test
git add cli/dev-guardian.mjs mcp/test/e2e/ciCliFixture.test.ts
git commit -m "feat(cli): scan and baseline commands with four exit codes"
```

---

## Task 6: The application runner (separable)

**Files:**

- Create: `mcp/src/ci/appRunner.ts`
- Modify: `cli/dev-guardian.mjs` (wire `--start-command`)
- Test: `mcp/test/unit/ci/appRunner.test.ts`

**Interfaces:**

- Produces:

```ts
export interface StartAppOptions {
  /** argv array — never a shell string. */
  command: readonly string[];
  cwd: string;
  /** Polled until it answers or the timeout expires. */
  healthUrl: string;
  timeoutMs: number;
}
export interface RunningApp {
  /** Kills the process tree. Idempotent. */
  stop: () => Promise<void>;
}
export async function startApp(opts: StartAppOptions): Promise<RunningApp>;
```

- [ ] **Step 1: Write the failing test**

Against a real child process — a tiny `node -e` server, not a mock.

```ts
describe('startApp', () => {
  it('resolves once the health url answers', async () => { /* ... */ });

  it('rejects with a clear error when the health url never answers', async () => {
    // A hang is the worst failure mode in CI: the job burns its whole budget
    // and the log says nothing.
    await expect(startApp({ ...opts, timeoutMs: 300 })).rejects.toThrow(/timed out/i);
  });

  it('kills the process on timeout, leaving nothing running', async () => {
    // The assertion that matters: capture the pid, await the rejection, then
    // assert the process is gone.
  });

  it('stop() leaves nothing running, and is safe to call twice', async () => { /* ... */ });

  it('never uses a shell — a metacharacter in an argument is passed literally', async () => {
    // Guards the wrong implementation that joins argv into a string: the
    // child must receive `;` as data, not as a command separator.
  });
});
```

- [ ] **Step 2: Run to verify it fails.** Expected: module not found.

- [ ] **Step 3: Implement `appRunner.ts`**

`execa` (already a dependency) with `shell: false`. Poll the health URL with
`fetch`. Kill the process **tree**, not just the direct child — a `npm start`
spawns a grandchild, and killing only the parent orphans the server.

- [ ] **Step 4: Wire it into `cmdScan`**, with teardown in a `finally` so a
scan that throws still stops the app.

- [ ] **Step 5: Run, then suite, build, commit**

```bash
cd mcp && npm test && npm run build
git add mcp/src/ci/appRunner.ts cli/dev-guardian.mjs mcp/test/unit/ci/appRunner.test.ts mcp/dist
git commit -m "feat(ci): start the target app for the DAST pass, and always stop it"
```

---

## Task 7: Documentation and the distribution caveat

**Files:**

- Modify: `README.md` (EN/PT/ES), `host-rules/AGENTS.md` and its paired host
  files, `CHANGELOG.md`, `cli/dev-guardian.mjs` help text

- [ ] **Step 1: Measure the tool count and sweep every place it appears**

```bash
cd mcp && node -e "import('./dist/registerAll.js').then(()=>import('./dist/tools/index.js')).then(m=>console.log(m.TOOLS.length))"
grep -rn "5[0-9] \(tools\|MCP\|herramientas\|ferramentas\)" . | grep -v node_modules
```

The previous sweep missed files on **two** axes: language (a Spanish
"herramientas") and file extension (four files with no `.md`/`.json`, invisible
to an `--include` filter). Use no `--include` filter and check the result by
hand. This task adds no tool, so the count should be unchanged — **verify that
rather than assuming it.**

- [ ] **Step 2: Write the pipeline snippet**

A copy-pasteable GitHub Actions job in `README.md`, using
`git clone --depth 1` against a pinned tag, `node cli/dev-guardian.mjs scan
--sarif results.sarif`, and `github/codeql-action/upload-sarif`. State the
distribution caveat plainly: this is a clone of a plugin repository, not an
`npx` one-liner, and why.

- [ ] **Step 3: CHANGELOG entry with the limits in the same breath**

From design §9: the clone-based distribution; no trend history in CI; DAST
reaches only what the runner can reach; and **SARIF carries findings but not
the `coverage` signal**, so a consumer reading only the upload cannot tell a
clean scan from an incomplete one — which is why exit code `2` exists.

- [ ] **Step 4: Full verification gate**

```bash
cd mcp && npm run build && GUARDIAN_REQUIRE_SEMGREP=1 npm test && npm run test:coverage
npx markdownlint-cli2 "skills/**/*.md" "commands/**/*.md" "README.md"
```

Semgrep is installed but **not on PATH** — `%APPDATA%\Roaming\Python\Python314\Scripts`.
Report the exact skip count (**target zero**) and all four coverage numbers
against 70/62/72/70.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "docs(ci): document headless scanning and its distribution caveat"
```

---

## Self-Review Notes

Checked against the spec:

- §2 distribution → Task 7's snippet and caveat; the `npx` investigation is
  explicitly out of scope, as the spec says.
- §3 architecture, logic in TypeScript → Tasks 1–4 create `mcp/src/ci/*`;
  Task 5 keeps the `.mjs` a shim.
- §3 scan order → Task 4, with the literal-array assertion and the
  refusal-does-not-abort test.
- §4 baseline, absent ≠ empty → Task 1, first test.
- §5 gate and exit codes, `computeCoverage` reused → Task 2, including the
  nothing-to-do-is-not-a-gap case.
- §6 output, SARIF schema-validated → Task 3, with the devDependency decision
  made explicitly rather than left to interpretation.
- §7 `--start-command` argv-only, no shell, teardown on every path → Task 5's
  refusal test and Task 6's kill tests.
- §8 testing → the test files named in each task, plus Task 5's subprocess e2e.
- §9 limitations → Task 7's CHANGELOG entry carries them.
- §10 definition of done → Task 7 Step 4 is the gate.

Type consistency: `ScanStepResult` is defined in Task 1 and consumed by Tasks 2
and 4. `GateVerdict` is defined in Task 2 and consumed by Task 3. `CI_EXIT` is
defined in Task 1 and used by Tasks 2 and 5. `runScans` returns the exact shape
`evaluateGate` consumes.
