/**
 * Which VEX status each CVE of the deps scan gets, and why.
 *
 *   - `not_affected` ONLY from a VEX suppression (`suppress_finding` with
 *     `vex_status`) — never from a plain one, never inferred;
 *   - `affected` only when the dependency provider says the package is
 *     reachable (a file a route reaches imports it);
 *   - `under_investigation` for everything else, with the reason;
 *   - `fixed` never: a CVE in the latest scan is present by definition, and
 *     a fix nobody measured is not a fix.
 */
import { describe, expect, it } from 'vitest';
import { externalImports } from '../../../src/surface/moduleEdges.js';
import { buildVexStatements, type VexInputs } from '../../../src/vex/statements.js';
import { parseSbomInventory } from '../../../src/vex/sbom.js';
import { buildImportGraph } from '../../../src/validate/importGraph.js';
import { prepareDependencyIndex } from '../../../src/validate/dependencyProvider.js';
import type { AttackSurfaceSnapshot, Cve, Finding, Suppression } from '../../../src/types.js';

const PROJECT = '/proj';

function cve(over: Partial<Cve> = {}): Cve {
  return {
    cve_id: 'CVE-2021-23337',
    package_name: 'lodash',
    installed_version: '4.17.20',
    fixed_version: '4.17.21',
    severity: 'high',
    first_seen_scan_id: 's1',
    last_seen_scan_id: 's1',
    ...over,
  };
}

function finding(over: Partial<Finding> = {}): Finding {
  return {
    fingerprint: 'fp-lodash',
    identity: 'id-lodash',
    tool: 'trivy',
    rule_id: 'CVE-2021-23337',
    severity: 'high',
    category: 'security',
    subcategory: 'cve',
    title: 'lodash: command injection',
    file_path: 'package-lock.json',
    snippet: 'lodash@4.17.20->4.17.21',
    fix_available: true,
    ...over,
  };
}

function snapshot(externalFile: string | null): AttackSurfaceSnapshot {
  return {
    routes: [{
      method: 'GET', provenance: 'code', path_raw: '/users', path_resolved: '/users', path_partial: false,
      file: `${PROJECT}/src/routes.ts`, line: 1, framework: 'express', language: 'typescript',
      auth_hint: 'unknown', params: [], confidence: 'high',
    }],
    env_vars: [], ports: [], webhooks: [], coverage: [], tools_run: [], missing_tools: [],
    spec_files: [], spec_diff: null,
    imports: [{ file: 'src/routes.ts', module_file: 'src/db.ts' }],
    external_imports: externalImports(externalFile === null ? [] : [{ file: externalFile, specifier: 'lodash', language: 'typescript' }]),
  };
}

function inputs(over: Partial<VexInputs> = {}): VexInputs {
  const snap = snapshot(null);
  return {
    cves: [cve()],
    findings: [finding()],
    suppressions: [],
    projectPath: PROJECT,
    now: Date.parse('2026-09-28T00:00:00.000Z'),
    dependency: prepareDependencyIndex({ snapshot: snap, graph: buildImportGraph(snap.imports), projectPath: PROJECT }),
    sbom: null,
    ...over,
  };
}

function dependencyFor(externalFile: string) {
  const snap = snapshot(externalFile);
  return prepareDependencyIndex({
    snapshot: snap,
    graph: buildImportGraph(snap.imports),
    projectPath: PROJECT,
    // The code loads exactly the version the finding is about.
    npmResolver: () => ({ version: '4.17.20', source: 'package-lock.json' }),
  });
}

function vexSuppression(over: Partial<Suppression> = {}): Suppression {
  return {
    id: 1,
    finding_fingerprint: 'fp-lodash',
    finding_identity: 'id-lodash',
    reason: 'reviewed',
    created_at: '2026-09-01T00:00:00.000Z',
    project_path: PROJECT,
    vex_status: 'not_affected',
    vex_justification: 'vulnerable_code_not_in_execute_path',
    vex_impact_statement: 'template() is never called',
    ...over,
  };
}

describe('buildVexStatements — status', () => {
  it('is not_affected, with the justification, only from a VEX suppression of that CVE finding', () => {
    const [s] = buildVexStatements(inputs({ suppressions: [vexSuppression()] }));
    expect(s).toMatchObject({
      vulnerability: 'CVE-2021-23337',
      package_name: 'lodash',
      installed_version: '4.17.20',
      status: 'not_affected',
      justification: 'vulnerable_code_not_in_execute_path',
      impact_statement: 'template() is never called',
    });
  });

  it('matches the VEX suppression by identity when the fingerprint moved', () => {
    const [s] = buildVexStatements(
      inputs({ suppressions: [vexSuppression({ finding_fingerprint: 'an-older-fingerprint' })] }),
    );
    expect(s?.status).toBe('not_affected');
  });

  it('never reads a plain suppression as not_affected, and says it was suppressed', () => {
    const plain = vexSuppression({ vex_status: undefined, vex_justification: undefined, vex_impact_statement: undefined });
    const [s] = buildVexStatements(inputs({ suppressions: [plain] }));
    expect(s?.status).toBe('under_investigation');
    expect(s?.status_notes).toMatch(/suppressed .*without a VEX justification/);
  });

  it('ignores an expired VEX suppression and one scoped to another project', () => {
    for (const other of [
      vexSuppression({ expires_at: '2026-01-01T00:00:00.000Z' }),
      vexSuppression({ project_path: '/elsewhere' }),
    ]) {
      expect(buildVexStatements(inputs({ suppressions: [other] }))[0]?.status).toBe('under_investigation');
    }
  });

  it('is affected, with an action statement naming the fix, when a routed file imports the package', () => {
    const [s] = buildVexStatements(inputs({ dependency: dependencyFor('src/db.ts') }));
    expect(s?.status).toBe('affected');
    expect(s?.action_statement).toMatch(/4\.17\.21/);
    expect(s?.status_notes).toMatch(/src\/db\.ts/);
  });

  it('says so in the action statement when no fixed version is known', () => {
    const [s] = buildVexStatements(inputs({ cves: [cve({ fixed_version: undefined })], dependency: dependencyFor('src/db.ts') }));
    expect(s?.status).toBe('affected');
    expect(s?.action_statement).toMatch(/no fixed version/i);
  });

  it('is under_investigation, never not_affected, when the package is only imported by an unrouted file', () => {
    const [s] = buildVexStatements(inputs({ dependency: dependencyFor('tools/cli.ts') }));
    expect(s?.status).toBe('under_investigation');
    expect(s?.status_notes).toMatch(/tools\/cli\.ts/);
  });

  it('is under_investigation when there is no surface snapshot, and says why', () => {
    const [s] = buildVexStatements(inputs({ dependency: null }));
    expect(s?.status).toBe('under_investigation');
    expect(s?.status_notes).toMatch(/map_attack_surface/);
  });

  it('a VEX suppression wins over reachability: it is the author’s own statement', () => {
    const [s] = buildVexStatements(inputs({ suppressions: [vexSuppression()], dependency: dependencyFor('src/db.ts') }));
    expect(s?.status).toBe('not_affected');
  });

  it('never produces fixed', () => {
    const statuses = buildVexStatements(inputs({
      cves: [cve(), cve({ cve_id: 'CVE-2020-8203', fixed_version: '4.17.19' })],
      findings: [finding(), finding({ fingerprint: 'fp-2', identity: 'id-2', rule_id: 'CVE-2020-8203' })],
    })).map((s) => s.status);
    expect(statuses).not.toContain('fixed');
  });
});

describe('buildVexStatements — subcomponents from the SBOM', () => {
  const SBOM = JSON.stringify({
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    metadata: { component: { name: 'shop', purl: 'pkg:npm/shop@1.0.0' } },
    components: [
      { name: 'lodash', version: '4.17.20', purl: 'pkg:npm/lodash@4.17.20' },
      { name: 'lodash', version: '4.17.21', purl: 'pkg:npm/lodash@4.17.21' },
    ],
  });

  it('carries the purl of exactly the installed version', () => {
    const [s] = buildVexStatements(inputs({ sbom: parseSbomInventory(SBOM) }));
    expect(s?.subcomponent_purls).toEqual(['pkg:npm/lodash@4.17.20']);
  });

  it('carries none when the SBOM does not list that version', () => {
    const [s] = buildVexStatements(inputs({ cves: [cve({ installed_version: '3.10.1' })], sbom: parseSbomInventory(SBOM) }));
    expect(s?.subcomponent_purls).toEqual([]);
  });
});
