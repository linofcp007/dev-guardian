/**
 * The bookkeeping-name table (`history/runNames.ts`) is exhaustive — by
 * reading the source, not by trusting a list.
 *
 * Round 3 aliased names by a rule (`base-variant` speaks for `base`) and
 * fell back to the scan's coverage for whatever the rule missed; it missed
 * `npm` (findings say `npm-audit`) and `guardian-dast` (findings say
 * `dast`), and a partial scan resolved their findings. So this test reads
 * `src/` for every finding `tool` a scanner can produce and every name a
 * scan writes to `tools_run` / `missing_tools`, and fails on either one the
 * table does not place — or on a table name nothing writes any more.
 */

import { readdirSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  KNOWN_FINDING_KEYS,
  RUN_NAMES,
  SKILL_OSV,
  TRIVY_CONFIG,
  TRIVY_FS,
  findingKey,
  keysOfRun,
  runNameEntry,
} from '../../../src/history/runNames.js';

const SRC = fileURLToPath(new URL('../../../src/', import.meta.url));

function tsFiles(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const p = join(dir, e.name);
    if (e.isDirectory()) return tsFiles(p);
    return e.name.endsWith('.ts') ? [p] : [];
  });
}

const SOURCES = tsFiles(SRC).map((path) => ({
  file: relative(SRC, path).split('\\').join('/'),
  text: readFileSync(path, 'utf8'),
}));

/** Group 1 of every match; `absent` stands in for a match whose group 1 did not take part. */
function collect(
  pattern: RegExp,
  only?: (file: string) => boolean,
  absent?: string,
): Array<{ file: string; value: string }> {
  const out: Array<{ file: string; value: string }> = [];
  for (const { file, text } of SOURCES) {
    if (only !== undefined && !only(file)) continue;
    for (const m of text.matchAll(pattern)) {
      const value = m[1] ?? absent;
      if (value !== undefined) out.push({ file, value });
    }
  }
  return out;
}

/**
 * `tool: '<literal>'` keys that are not findings — response fields and
 * install records. A new one fails the test below until it is either mapped
 * (it is a finding tool) or listed here (it is not).
 */
const NOT_FINDING_TOOLS = new Set(['tools/perfCheck.ts:lighthouse', 'tools/perfCheck.ts:k6', 'tools/installToolchain.ts:all-default']);

/** Every finding `tool` value the source can produce. */
function findingTools(): string[] {
  const found = [
    // Parser constants: `export const BANDIT_TOOL_NAME = 'bandit'`.
    ...collect(/export const [A-Z_]+_TOOL_NAME\s*=\s*'([^']+)'/g),
    // Module constants used as `tool: TOOL` (skillaudit).
    ...collect(/\bconst TOOL\s*=\s*'([^']+)'/g),
    // Literal `tool: 'dast'` in findings built by hand (dast, dotnet).
    ...collect(/\btool:\s*'([^']+)'/g).filter((x) => !NOT_FINDING_TOOLS.has(`${x.file}:${x.value}`)),
  ];
  return [...new Set(found.map((x) => x.value))].sort();
}

/** Every name a scan in the source writes to `tools_run` or `missing_tools`. */
function bookkeepingNames(): string[] {
  const found = [
    // `{ name: 'semgrep', status: … }`, on one line or several.
    ...collect(/\{\s*name:\s*'([^']+)',\s*status:/g),
    // `missing_tools.push('semgrep')`.
    ...collect(/(?:missing_tools|missingTools)\??\.push\(\s*'([^']+)'\s*\)/g),
    // quality_check's helpers: `notInstalled(out, 'jscpd')`, `record(out, 'ruff', …)`.
    ...collect(/\b(?:notInstalled|record)\(\s*out,\s*'([^']+)'/g, (f) => f === 'tools/qualityCheck.ts'),
    // deps_audit's native auditors are recorded by command.
    ...collect(/tryNativeAudit\(\{\s*command:\s*'([^']+)'/g),
    // gitleaks' passes.
    ...collect(/export const GITLEAKS_[A-Z_]+\s*=\s*'([^']+)'/g),
    // audit_executive: one entry per sub-tool.
    ...collect(/const [A-Z_]*SUB_TOOLS\s*=\s*\[([^\]]+)\]/g).flatMap((x) =>
      [...x.value.matchAll(/'([^']+)'/g)].flatMap((m) => (m[1] === undefined ? [] : [{ file: x.file, value: m[1] }])),
    ),
  ];
  // scan_dast: `const DAST_ENGINE = 'guardian-dast'` and `${DAST_ENGINE}:unanswered`.
  const engine = collect(/const DAST_ENGINE\s*=\s*'([^']+)'/g)[0]?.value;
  if (engine !== undefined) {
    found.push({ file: 'tools/scanDast.ts', value: engine });
    for (const x of collect(/\$\{DAST_ENGINE\}(:[a-z-]+)/g)) found.push({ file: x.file, value: `${engine}${x.value}` });
  }
  // scan_skill's OSV entry: `name: 'osv.dev', status: report.osv.online ? …`.
  found.push(...collect(/name:\s*'(osv\.dev)'/g));
  // review_pr's per-file passes: `semgrepOnFiles` / `banditOnFiles` hand `name: '…'` to `scanFileBatches`.
  found.push(...collect(/\bname:\s*'([^']+)'/g, (f) => f === 'runners/fileBatchScan.ts'));
  // security_scan_full's own entry for a child that threw or answered an error: the child's name.
  found.push(...collect(/const FIRST_CHILD\s*=\s*'([^']+)'/g));
  found.push(...quoted(collect(/const OTHER_CHILDREN\s*=\s*\[([^\]]+)\]/g)));
  // generate_sbom: `let producedBy: 'syft' | 'trivy' | null`.
  found.push(...quoted(collect(/let producedBy:\s*([^=;]+)/g)));
  return [...new Set(found.map((x) => x.value))].sort();
}

/** Every `'…'` inside each collected value, as its own entry. */
function quoted(xs: Array<{ file: string; value: string }>): Array<{ file: string; value: string }> {
  return xs.flatMap((x) =>
    [...x.value.matchAll(/'([^']+)'/g)].flatMap((m) => (m[1] === undefined ? [] : [{ file: x.file, value: m[1] }])),
  );
}

/**
 * Bookkeeping names a scan writes through an expression rather than a
 * literal, and where {@link bookkeepingNames} reads each one's value. The
 * collectors above only see literals; a new expression fails the test below
 * until it is placed here — with the collector that reads it, or with why it
 * never reaches a `scans` row. (`history/` is left out: it reads rows.)
 */
const NAME_EXPRESSIONS: Readonly<Record<string, string>> = {
  'runners/gitleaksScan.ts:GITLEAKS_HISTORY': 'the GITLEAKS_* constants',
  'runners/gitleaksScan.ts:GITLEAKS_WORKING_TREE': 'the GITLEAKS_* constants',
  'runners/gitleaksScan.ts:name': 'a parameter only ever given a GITLEAKS_* constant',
  'runners/fileBatchScan.ts:opts.name': "semgrepOnFiles' and banditOnFiles' `name: '…'`",
  'tools/depsAudit.ts:opts.command': "tryNativeAudit's `command: '…'`",
  'tools/qualityCheck.ts:name': "notInstalled's and record's name argument",
  'tools/auditExecutive.ts:name': 'the *SUB_TOOLS arrays',
  'tools/securityScanFull.ts:name': 'FIRST_CHILD and OTHER_CHILDREN',
  'tools/scanDast.ts:DAST_ENGINE': 'DAST_ENGINE',
  'tools/scanDast.ts:`${DAST_ENGINE}:unanswered`': 'the `${DAST_ENGINE}:…` passes',
  'tools/scanDast.ts:`${DAST_ENGINE}:wall-clock`': 'the `${DAST_ENGINE}:…` passes',
  'tools/generateSbom.ts:producedBy': "producedBy's declared type",
  'tools/mapAttackSurface.ts:RECOVERY_STEP':
    'never reaches a scans row: map_attack_surface returns its tools_run and caches the surface, writing no scan',
  'tools/reviewPr.ts:...secrets.missing_tools': "a copy of gitleaksScan's names",
  'tools/scanWordpress.ts:...secrets.missing_tools': "a copy of gitleaksScan's names",
};

/** Every `tools_run` / `missing_tools` write whose name is an expression, as `file:expression`. */
function nameExpressions(): string[] {
  const writes = (file: string): boolean => !file.startsWith('history/');
  const found = [
    // `{ name: GITLEAKS_HISTORY, status: … }`, `{ name, status: … }`, `{ name: `${DAST_ENGINE}:…`, status: … }`.
    ...collect(/\{\s*name(?:\s*:\s*(`[^`]*`|[^,}]+?))?\s*,\s*status\s*:/g, writes, 'name'),
    // `missing_tools.push(name)`, `missing_tools.push(...other.missing_tools)`.
    ...collect(/(?:missing_tools|missingTools)\??\.push\(\s*([^)]+?)\s*\)/g, writes),
  ];
  return [...new Set(found.filter((x) => !/^'[^']*'$/.test(x.value)).map((x) => `${x.file}:${x.value}`))].sort();
}

/** The keys a finding of `tool` can have (Trivy and scan_skill split by pass). */
function keysOfTool(tool: string): string[] {
  const shapes = [
    { tool },
    { tool, subcategory: 'cve' },
    { tool, category: 'license' as const },
    { tool, subcategory: 'misconfiguration' },
    { tool, rule_id: 'osv-vulnerable-dependency' },
  ];
  return [...new Set(shapes.map((s) => findingKey(s)))];
}

describe('runNames: exhaustive over the source', () => {
  const tools = findingTools();
  const names = bookkeepingNames();

  it('the source scan finds what it must (positive control)', () => {
    expect(tools).toEqual(
      expect.arrayContaining([
        'npm-audit', 'dast', 'nuclei', 'trivy', 'semgrep', 'gitleaks', 'bandit', 'phpcs', 'security-code-scan',
        'guardian-scanskill', 'scan_dotnet_secrets', 'dotnet_efcore_audit', 'wpscan', 'eslint', 'ruff',
        'hadolint', 'docker-compose', 'budgets',
      ]),
    );
    expect(names).toEqual(
      expect.arrayContaining([
        'npm', 'pip-audit', 'guardian-dast', 'guardian-dast:unanswered', 'guardian-dast:wall-clock', 'nuclei',
        'gitleaks', 'gitleaks-working-tree', 'trivy', 'trivy-image', 'trivy-config', 'trivy-dockerfile',
        'semgrep-wp', 'phpcs-wpcs', 'phpcs', 'dotnet-sdk', 'security-code-scan', 'osv.dev', 'jscpd',
        'security_scan_full', 'deps_audit', 'quality_check', 'compliance_check', 'scan_wordpress',
        'hadolint', 'docker-compose', 'budgets', 'scan_sast', 'scan_iac', 'syft',
      ]),
    );
    expect(nameExpressions()).toEqual(
      expect.arrayContaining(['runners/gitleaksScan.ts:GITLEAKS_HISTORY', 'tools/securityScanFull.ts:name']),
    );
  });

  it('every finding tool a scanner produces is measured by some bookkeeping name', () => {
    const measured = new Set(Object.values(RUN_NAMES).flatMap((e) => [...e.measures]));
    const unplaced = tools.flatMap((t) => keysOfTool(t).filter((k) => !measured.has(k)).map((k) => `${t} (${k})`));
    expect(unplaced).toEqual([]);
  });

  it('every bookkeeping name a scan writes is in the table', () => {
    expect(names.filter((n) => !Object.hasOwn(RUN_NAMES, n))).toEqual([]);
  });

  it('every name written through an expression is one the collectors read (or never reaches a scan)', () => {
    expect(nameExpressions().filter((x) => !Object.hasOwn(NAME_EXPRESSIONS, x))).toEqual([]);
  });

  it('every name in the table is still written by some scan (no stale entries)', () => {
    expect(Object.keys(RUN_NAMES).filter((n) => !names.includes(n))).toEqual([]);
    expect(Object.keys(NAME_EXPRESSIONS).filter((x) => !nameExpressions().includes(x))).toEqual([]);
  });
});

describe('runNames: the pairs that do not share a name', () => {
  it.each([
    ['npm', ['npm-audit']],
    ['pip-audit', []],
    ['guardian-dast', ['dast']],
    ['guardian-dast:unanswered', ['dast']],
    ['guardian-dast:wall-clock', ['dast']],
    ['semgrep-wp', ['semgrep']],
    ['phpcs-wpcs', ['phpcs']],
    ['gitleaks-working-tree', ['gitleaks']],
    ['dotnet-sdk', ['security-code-scan']],
    ['trivy-image', [TRIVY_FS, TRIVY_CONFIG]],
    ['hadolint', ['hadolint']],
    ['docker-compose', ['docker-compose']],
    ['budgets', ['budgets']],
    ['scan_sast', ['semgrep', 'bandit', 'security-code-scan']],
    ['scan_iac', [TRIVY_CONFIG]],
    ['syft', []],
    ['trivy-config', [TRIVY_CONFIG]],
    ['trivy-dockerfile', [TRIVY_CONFIG]],
    ['osv.dev', [SKILL_OSV]],
    ['deps_audit', [TRIVY_FS, 'npm-audit']],
  ])('%s measures %j', (name, keys) => {
    expect(keysOfRun(name, true)).toEqual(keys);
  });

  it("jscpd or radon not ok leaves the quality budgets unmeasured: they are read from those scanners' reports", () => {
    expect(keysOfRun('jscpd', true)).toEqual(['jscpd']);
    expect(keysOfRun('jscpd', false)).toEqual(['jscpd', 'budgets']);
    expect(keysOfRun('radon', false)).toEqual(['radon', 'budgets']);
  });

  it('`trivy-image` looks at a target no other pass does; the Dockerfile and IaC passes do not', () => {
    expect(runNameEntry('trivy-image')?.ownTarget).toBe(true);
    expect(runNameEntry('trivy-dockerfile')?.ownTarget).toBeUndefined();
    expect(runNameEntry('trivy-config')?.ownTarget).toBeUndefined();
  });

  it('`trivy` that ran ok is the dependency pass; not ok, Trivy is absent and no pass ran', () => {
    expect(keysOfRun('trivy', true)).toEqual([TRIVY_FS]);
    expect(keysOfRun('trivy', false)).toEqual([TRIVY_FS, TRIVY_CONFIG]);
  });

  it('an unlisted `base:suffix` is a pass of a known base; anything else is unknown', () => {
    expect(runNameEntry('guardian-dast:some-new-pass')?.measures).toEqual(['dast']);
    expect(keysOfRun('some-future-scanner', true)).toBeNull();
    // Not the prototype's keys.
    expect(keysOfRun('constructor', true)).toBeNull();
    expect(KNOWN_FINDING_KEYS.has('npm-audit')).toBe(true);
  });

  it('Trivy findings are keyed by the pass that produces them', () => {
    expect(findingKey({ tool: 'trivy', subcategory: 'cve' })).toBe(TRIVY_FS);
    expect(findingKey({ tool: 'trivy', category: 'license' })).toBe(TRIVY_FS);
    expect(findingKey({ tool: 'trivy', subcategory: 'misconfiguration' })).toBe(TRIVY_CONFIG);
    expect(findingKey({ tool: 'npm-audit', subcategory: 'cve' })).toBe('npm-audit');
  });
});
