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

  it('carries none when neither a finding nor the SBOM says which ecosystem that version is from', () => {
    const [s] = buildVexStatements(inputs({ cves: [cve({ installed_version: '3.10.1' })], sbom: parseSbomInventory(SBOM) }));
    expect(s?.subcomponent_purls).toEqual([]);
  });
});

/* ------------------------------------------------------------------ */
/* Review of part C, C1/M3: tied by own ids, named with their aliases   */
/* ------------------------------------------------------------------ */

/** Real Trivy output for lodash 4.17.20: CVE-2026-4800's description MENTIONS CVE-2021-23337. */
function lodashScan(): Pick<VexInputs, 'cves' | 'findings'> {
  return {
    cves: [cve(), cve({ cve_id: 'CVE-2026-4800', fixed_version: '4.18.0' })],
    findings: [
      finding({ vuln_aliases: ['GHSA-35jh-r3h4-6jhm'] }),
      finding({
        fingerprint: 'fp-4800', identity: 'id-4800', rule_id: 'CVE-2026-4800', snippet: 'lodash@4.17.20->4.18.0',
        vuln_aliases: ['GHSA-r5fr-rjxr-66jc'], message: 'This is due to an incomplete fix for CVE-2021-23337.',
      }),
    ],
  };
}

describe('buildVexStatements — a statement is tied to a finding by its own ids only', () => {
  it('a VEX suppression of CVE-2021-23337 makes that statement not_affected and leaves CVE-2026-4800 alone', () => {
    const byId = new Map(buildVexStatements(inputs({ ...lodashScan(), suppressions: [vexSuppression()] }))
      .map((s) => [s.vulnerability, s]));
    expect(byId.get('CVE-2021-23337')?.status).toBe('not_affected');
    expect(byId.get('CVE-2026-4800')?.status).toBe('under_investigation');
    expect(byId.get('CVE-2026-4800')?.status_notes).not.toMatch(/suppressed/);
  });

  it('each statement carries its own finding’s justification, never the mentioning one’s', () => {
    const other = vexSuppression({
      id: 2, finding_fingerprint: 'fp-4800', finding_identity: 'id-4800',
      vex_justification: 'inline_mitigations_already_exist', vex_impact_statement: 'patched in place',
    });
    const byId = new Map(buildVexStatements(inputs({ ...lodashScan(), suppressions: [vexSuppression(), other] }))
      .map((s) => [s.vulnerability, s]));
    expect(byId.get('CVE-2021-23337')).toMatchObject({
      justification: 'vulnerable_code_not_in_execute_path', impact_statement: 'template() is never called',
    });
    expect(byId.get('CVE-2026-4800')).toMatchObject({
      justification: 'inline_mitigations_already_exist', impact_statement: 'patched in place',
    });
  });

  it('names each vulnerability with the aliases its scanner gave', () => {
    const byId = new Map(buildVexStatements(inputs(lodashScan())).map((s) => [s.vulnerability, s]));
    expect(byId.get('CVE-2021-23337')?.aliases).toEqual(['GHSA-35jh-r3h4-6jhm']);
    expect(byId.get('CVE-2026-4800')?.aliases).toEqual(['GHSA-r5fr-rjxr-66jc']);
  });

  it('ties a pip-audit PYSEC advisory to its CVE row through its aliases, not through its text', () => {
    // PYSEC-2021-142 is CVE-2020-14343 and mentions CVE-2020-1747;
    // PYSEC-2020-96 is CVE-2020-1747. pip-audit records each CVE alias as the
    // scan_cves row.
    const pysec = (fp: string, id: string, aliases: string[], message?: string): Finding => finding({
      fingerprint: fp, identity: `id-${fp}`, tool: 'pip-audit', subcategory: 'dependency', rule_id: id,
      file_path: 'requirements.txt', snippet: 'pyyaml@5.3', vuln_aliases: aliases,
      ...(message === undefined ? {} : { message }),
    });
    const statements = buildVexStatements(inputs({
      cves: [
        cve({ cve_id: 'CVE-2020-14343', package_name: 'pyyaml', installed_version: '5.3', fixed_version: '5.4' }),
        cve({ cve_id: 'CVE-2020-1747', package_name: 'pyyaml', installed_version: '5.3', fixed_version: '5.3.1' }),
      ],
      findings: [
        pysec('p142', 'PYSEC-2021-142', ['CVE-2020-14343', 'GHSA-8q59-q68h-6hv4'], 'an incomplete fix for CVE-2020-1747'),
        pysec('p96', 'PYSEC-2020-96', ['CVE-2020-1747']),
      ],
      suppressions: [vexSuppression({ finding_fingerprint: 'p142', finding_identity: 'id-p142' })],
    }));
    const byId = new Map(statements.map((s) => [s.vulnerability, s]));
    expect(byId.get('CVE-2020-14343')).toMatchObject({
      status: 'not_affected', aliases: ['PYSEC-2021-142', 'GHSA-8q59-q68h-6hv4'],
    });
    expect(byId.get('CVE-2020-1747')).toMatchObject({ status: 'under_investigation', aliases: ['PYSEC-2020-96'] });
  });

  it('states a vulnerability no CVE row names (PYSEC- or GHSA-only) under its own id', () => {
    const statements = buildVexStatements(inputs({
      cves: [],
      findings: [finding({
        fingerprint: 'ghsa', identity: 'id-ghsa', rule_id: 'GHSA-xvch-5gv4-984h', snippet: 'handlebars@4.7.6->4.7.7',
        message: 'Related to CVE-2021-23383.',
      })],
      suppressions: [vexSuppression({ finding_fingerprint: 'ghsa', finding_identity: 'id-ghsa', vex_justification: 'component_not_present' })],
    }));
    expect(statements).toHaveLength(1);
    expect(statements[0]).toMatchObject({
      vulnerability: 'GHSA-xvch-5gv4-984h', aliases: [], package_name: 'handlebars', installed_version: '4.7.6',
      status: 'not_affected', justification: 'component_not_present',
    });
  });

  it('a CVE row another finding merely mentions claims no suppression it never had', () => {
    // The GHSA-only handlebars finding mentions CVE-2021-23383, which a
    // separate row (another package) names.
    const statements = buildVexStatements(inputs({
      cves: [cve({ cve_id: 'CVE-2021-23383', package_name: 'handlebars', installed_version: '4.7.6', fixed_version: '4.7.7' })],
      findings: [
        finding({ fingerprint: 'ghsa', identity: 'id-ghsa', rule_id: 'GHSA-xvch-5gv4-984h', snippet: 'handlebars@4.7.6->4.7.7',
          message: 'Related to CVE-2021-23383.' }),
        finding({ fingerprint: 'cve', identity: 'id-cve', rule_id: 'CVE-2021-23383', snippet: 'handlebars@4.7.6->4.7.7' }),
      ],
      suppressions: [vexSuppression({ finding_fingerprint: 'ghsa', finding_identity: 'id-ghsa' })],
    }));
    const byId = new Map(statements.map((s) => [s.vulnerability, s]));
    expect(byId.get('CVE-2021-23383')?.status).toBe('under_investigation');
    expect(byId.get('CVE-2021-23383')?.status_notes).not.toMatch(/suppressed/);
    expect(byId.get('GHSA-xvch-5gv4-984h')?.status).toBe('not_affected');
  });
});

/* ------------------------------------------------------------------ */
/* Review of part C, I2: never two statuses for one subcomponent        */
/* ------------------------------------------------------------------ */

describe('buildVexStatements — subcomponents without an SBOM', () => {
  it('builds the purl from the ecosystem, name and version', () => {
    const statements = buildVexStatements(inputs({
      cves: [cve(), cve({ cve_id: 'CVE-2023-45133', package_name: '@babel/traverse', installed_version: '7.22.0' }),
        cve({ cve_id: 'CVE-2020-14343', package_name: 'PyYAML', installed_version: '5.3' })],
      findings: [
        finding(),
        finding({ fingerprint: 'b', identity: 'id-b', rule_id: 'CVE-2023-45133', snippet: '@babel/traverse@7.22.0->7.23.2' }),
        finding({ fingerprint: 'y', identity: 'id-y', rule_id: 'CVE-2020-14343', file_path: 'requirements.txt', snippet: 'PyYAML@5.3->5.4' }),
      ],
    }));
    expect(statements.map((s) => s.subcomponent_purls)).toEqual([
      ['pkg:npm/lodash@4.17.20'],
      ['pkg:npm/%40babel/traverse@7.22.0'],
      ['pkg:pypi/pyyaml@5.3'],
    ]);
  });

  it('keeps one CVE in two versions apart by their purls', () => {
    const statements = buildVexStatements(inputs({
      cves: [cve(), cve({ installed_version: '4.17.15' })],
      findings: [finding(), finding({ fingerprint: 'old', identity: 'id-old', snippet: 'lodash@4.17.15->4.17.21' })],
      suppressions: [vexSuppression({ finding_fingerprint: 'old', finding_identity: 'id-old' })],
    }));
    expect(statements.map((s) => [s.subcomponent_purls[0], s.status])).toEqual([
      ['pkg:npm/lodash@4.17.20', 'under_investigation'],
      ['pkg:npm/lodash@4.17.15', 'not_affected'],
    ]);
  });

  it('merges two versions it cannot tell apart into one statement, never two statuses', () => {
    // An image target names no ecosystem, so no purl can be built: the two
    // statements would be about the same (vulnerability, product).
    const image = 'alpine:3.18 (alpine 3.18.4)';
    const statements = buildVexStatements(inputs({
      cves: [
        cve({ cve_id: 'CVE-2023-5363', package_name: 'openssl', installed_version: '3.1.2' }),
        cve({ cve_id: 'CVE-2023-5363', package_name: 'openssl', installed_version: '3.1.3' }),
      ],
      findings: [
        finding({ fingerprint: 'a', identity: 'id-a', rule_id: 'CVE-2023-5363', file_path: image, snippet: 'openssl@3.1.2->3.1.4' }),
        finding({ fingerprint: 'b', identity: 'id-b', rule_id: 'CVE-2023-5363', file_path: image, snippet: 'openssl@3.1.3->3.1.4' }),
      ],
      suppressions: [vexSuppression({ finding_fingerprint: 'a', finding_identity: 'id-a' })],
    }));
    expect(statements).toHaveLength(1);
    expect(statements[0]).toMatchObject({ vulnerability: 'CVE-2023-5363', status: 'under_investigation', subcomponent_purls: [] });
    expect(statements[0]?.status_notes).toMatch(/3\.1\.2/);
    expect(statements[0]?.status_notes).toMatch(/3\.1\.3/);
  });
});
