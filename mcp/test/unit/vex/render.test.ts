/**
 * The two VEX documents `export_vex` writes, validated against the published
 * schemas themselves — vendored in `test/fixtures/vex/`:
 *
 *   - `openvex_json_schema_0.2.0.json` — github.com/openvex/spec at
 *     61b5f885d0f481f48683c93345e49ef1a6e9fdff (`openvex_json_schema.json`);
 *   - `cyclonedx-bom-1.6.schema.json`, `spdx.schema.json`,
 *     `jsf-0.82.schema.json` — github.com/CycloneDX/specification, tag 1.6
 *     (55343ba19dee1785acf1ce9191540d5fd7b590db), `schema/`.
 *
 * Retrieved 2026-09-28. `ajv-formats` implements neither `iri`,
 * `iri-reference` nor `idn-email`, which these schemas use; they are defined
 * below strictly enough to reject what matters here (no scheme, whitespace),
 * rather than switched off.
 */
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Ajv } from 'ajv';
import { Ajv2020 } from 'ajv/dist/2020.js';
import type { FormatsPlugin } from 'ajv-formats';
import { describe, expect, it } from 'vitest';
import { renderCycloneDxVex, renderOpenVex, type VexDocumentMeta } from '../../../src/vex/render.js';
import type { VexStatement } from '../../../src/vex/statements.js';

const require = createRequire(import.meta.url);
const addFormats = require('ajv-formats') as FormatsPlugin;
const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'fixtures', 'vex');

function schema(name: string): Record<string, unknown> {
  return JSON.parse(readFileSync(join(FIXTURES, name), 'utf8')) as Record<string, unknown>;
}

const IRI = /^[A-Za-z][A-Za-z0-9+.-]*:\S+$/;
function extraFormats(ajv: Ajv | Ajv2020): void {
  ajv.addFormat('iri', IRI);
  ajv.addFormat('iri-reference', /^\S+$/);
  ajv.addFormat('idn-email', /^[^\s@]+@[^\s@]+$/);
}

function openVexValidator() {
  const ajv = new Ajv2020({ allErrors: true, strict: false });
  addFormats(ajv);
  extraFormats(ajv);
  return ajv.compile(schema('openvex_json_schema_0.2.0.json'));
}

function cycloneDxValidator() {
  const ajv = new Ajv({ allErrors: true, strict: false });
  addFormats(ajv);
  extraFormats(ajv);
  ajv.addSchema(schema('spdx.schema.json'));
  ajv.addSchema(schema('jsf-0.82.schema.json'));
  return ajv.compile(schema('cyclonedx-bom-1.6.schema.json'));
}

function statement(over: Partial<VexStatement> = {}): VexStatement {
  return {
    vulnerability: 'CVE-2021-23337',
    aliases: [],
    package_name: 'lodash',
    installed_version: '4.17.20',
    fixed_version: '4.17.21',
    severity: 'high',
    status: 'under_investigation',
    status_notes: 'no import of lodash was found',
    subcomponent_purls: ['pkg:npm/lodash@4.17.20'],
    ...over,
  };
}

const STATEMENTS: VexStatement[] = [
  statement({
    aliases: ['GHSA-35jh-r3h4-6jhm', 'PYSEC-2099-1'],
    status: 'not_affected',
    justification: 'vulnerable_code_not_in_execute_path',
    impact_statement: 'template() is never called',
    status_notes: 'suppressed as not_affected in dev-guardian',
  }),
  statement({
    vulnerability: 'CVE-2020-8203',
    status: 'affected',
    action_statement: 'Upgrade lodash from 4.17.20 to 4.17.21 or later.',
    status_notes: 'src/db.ts imports lodash and is reachable in 1 hop via GET /users',
  }),
  statement({ vulnerability: 'CVE-2019-10744' }),
  // No SBOM entry for this one: no purl, and still a valid statement.
  statement({
    vulnerability: 'GHSA-p6mc-m468-83gw',
    package_name: 'minimist',
    installed_version: '1.2.5',
    fixed_version: null,
    subcomponent_purls: [],
    status: 'not_affected',
    justification: 'component_not_present',
  }),
];

const META: VexDocumentMeta = {
  documentId: '0f1e2d3c-4b5a-4968-8776-655443322110',
  timestamp: '2026-09-28T12:00:00.000Z',
  author: 'Unknown Author',
  toolVersion: '3.0.0',
  product: { id: 'pkg:npm/shop@1.0.0', name: 'shop', purl: 'pkg:npm/shop@1.0.0' },
};

describe('the schema validators are live (positive controls)', () => {
  // A validator that compiled nothing, or ignored the conditional rules,
  // would pass every document below — so each is shown rejecting one first.
  it('OpenVEX: rejects an affected statement with no action_statement, and a not_affected one with no justification', () => {
    const validate = openVexValidator();
    const doc = renderOpenVex([statement({ status: 'affected' })], META);
    expect(validate(doc)).toBe(false);
    const bare = renderOpenVex([statement({ status: 'not_affected' })], META);
    expect(validate(bare)).toBe(false);
  });

  it('CycloneDX: rejects an unknown analysis state', () => {
    const validate = cycloneDxValidator();
    const doc = renderCycloneDxVex([statement()], META) as { vulnerabilities: Array<{ analysis: { state: string } }> };
    const first = doc.vulnerabilities[0];
    if (first === undefined) throw new Error('no vulnerability rendered');
    first.analysis.state = 'probably_fine';
    expect(validate(doc)).toBe(false);
  });
});

describe('renderOpenVex', () => {
  it('produces a document valid against the OpenVEX 0.2.0 JSON schema', () => {
    const validate = openVexValidator();
    const doc = renderOpenVex(STATEMENTS, META);
    expect(validate(doc), JSON.stringify(validate.errors, null, 2)).toBe(true);
  });

  it('writes the status, justification, product and subcomponents OpenVEX expects', () => {
    const doc = renderOpenVex(STATEMENTS, META) as {
      '@context': string;
      '@id': string;
      statements: Array<Record<string, unknown>>;
    };
    expect(doc['@context']).toBe('https://openvex.dev/ns/v0.2.0');
    expect(doc['@id']).toBe(`urn:uuid:${META.documentId}`);
    expect(doc.statements[0]).toMatchObject({
      vulnerability: { name: 'CVE-2021-23337', '@id': 'https://nvd.nist.gov/vuln/detail/CVE-2021-23337' },
      status: 'not_affected',
      justification: 'vulnerable_code_not_in_execute_path',
      impact_statement: 'template() is never called',
      products: [{
        '@id': 'pkg:npm/shop@1.0.0',
        identifiers: { purl: 'pkg:npm/shop@1.0.0' },
        subcomponents: [{ '@id': 'pkg:npm/lodash@4.17.20', identifiers: { purl: 'pkg:npm/lodash@4.17.20' } }],
      }],
    });
    expect(doc.statements[1]).toMatchObject({ status: 'affected', action_statement: expect.stringMatching(/4\.17\.21/) });
    // Its aliases, the ids its scanner gave for the same vulnerability.
    expect(doc.statements[0]?.['vulnerability']).toMatchObject({ aliases: ['GHSA-35jh-r3h4-6jhm', 'PYSEC-2099-1'] });
    // A GHSA id links to its GitHub advisory, never to NVD; no aliases, no key.
    expect(doc.statements[3]?.['vulnerability']).toEqual({
      '@id': 'https://github.com/advisories/GHSA-p6mc-m468-83gw', name: 'GHSA-p6mc-m468-83gw',
    });
  });
});

describe('renderCycloneDxVex', () => {
  it('produces a BOM valid against the CycloneDX 1.6 JSON schema', () => {
    const validate = cycloneDxValidator();
    const doc = renderCycloneDxVex(STATEMENTS, META);
    expect(validate(doc), JSON.stringify(validate.errors, null, 2)).toBe(true);
  });

  it('maps each status and justification onto CycloneDX impact analysis', () => {
    const doc = renderCycloneDxVex(STATEMENTS, META) as {
      components: Array<{ 'bom-ref': string; name: string }>;
      vulnerabilities: Array<{
        id: string;
        analysis: { state: string; justification?: string; response?: string[]; detail: string };
        affects: Array<{ ref: string }>;
      }>;
    };
    const [notAffected, affected, triage, componentGone] = doc.vulnerabilities;
    expect(notAffected?.analysis).toMatchObject({ state: 'not_affected', justification: 'code_not_reachable' });
    expect(notAffected?.analysis.detail).toMatch(/vulnerable_code_not_in_execute_path/);
    expect(affected?.analysis).toMatchObject({ state: 'exploitable', response: ['update'] });
    expect(triage?.analysis.state).toBe('in_triage');
    // CycloneDX has no "component not present" justification: false_positive.
    expect(componentGone?.analysis.state).toBe('false_positive');
    expect(componentGone?.analysis.justification).toBeUndefined();
    // Every affects ref names a component in the same BOM.
    const refs = new Set(doc.components.map((c) => c['bom-ref']));
    for (const v of doc.vulnerabilities) for (const a of v.affects) expect(refs.has(a.ref)).toBe(true);
  });

  it('lists a vulnerability’s aliases as references, each with its source', () => {
    const doc = renderCycloneDxVex(STATEMENTS, META) as {
      vulnerabilities: Array<{ id: string; source?: { name: string; url: string }; references?: unknown[] }>;
    };
    expect(doc.vulnerabilities[0]?.references).toEqual([
      { id: 'GHSA-35jh-r3h4-6jhm', source: { name: 'GitHub Advisories', url: 'https://github.com/advisories/GHSA-35jh-r3h4-6jhm' } },
      { id: 'PYSEC-2099-1', source: { name: 'OSV', url: 'https://osv.dev/vulnerability/PYSEC-2099-1' } },
    ]);
    expect(doc.vulnerabilities[2]?.references).toBeUndefined();
    expect(doc.vulnerabilities[3]?.source).toEqual({
      name: 'GitHub Advisories', url: 'https://github.com/advisories/GHSA-p6mc-m468-83gw',
    });
  });

  it('maps a justification CycloneDX has no single value for to no justification, keeping the label in detail', () => {
    const doc = renderCycloneDxVex(
      [statement({ status: 'not_affected', justification: 'vulnerable_code_cannot_be_controlled_by_adversary' })],
      META,
    ) as { vulnerabilities: Array<{ analysis: { state: string; justification?: string; detail: string } }> };
    expect(doc.vulnerabilities[0]?.analysis).toMatchObject({ state: 'not_affected' });
    expect(doc.vulnerabilities[0]?.analysis.justification).toBeUndefined();
    expect(doc.vulnerabilities[0]?.analysis.detail).toMatch(/vulnerable_code_cannot_be_controlled_by_adversary/);
  });
});
