/**
 * Reading a `generate_sbom` document back as the purls `export_vex` names its
 * product and subcomponents by — CycloneDX (Syft and Trivy both write it) and
 * SPDX 2.3 JSON, whose purls live in `externalRefs`.
 */
import { describe, expect, it } from 'vitest';
import { parseSbomInventory, purlsFor } from '../../../src/vex/sbom.js';

const CDX = JSON.stringify({
  bomFormat: 'CycloneDX',
  specVersion: '1.6',
  metadata: { component: { type: 'application', name: 'shop', purl: 'pkg:npm/shop@1.0.0' } },
  components: [
    { type: 'library', name: 'lodash', version: '4.17.20', purl: 'pkg:npm/lodash@4.17.20' },
    { type: 'library', name: 'requests', version: '2.31.0', purl: 'pkg:pypi/requests@2.31.0' },
    { type: 'library', name: 'requests', version: '2.31.0', purl: 'pkg:npm/requests@2.31.0' },
    { type: 'library', name: '@babel/core', version: '7.22.0', purl: 'pkg:npm/%40babel/core@7.22.0' },
    { type: 'file', name: 'no-purl.txt' },
  ],
});

const SPDX = JSON.stringify({
  spdxVersion: 'SPDX-2.3',
  documentDescribes: ['SPDXRef-root'],
  packages: [
    { SPDXID: 'SPDXRef-root', name: 'shop', versionInfo: '1.0.0' },
    {
      SPDXID: 'SPDXRef-lodash',
      name: 'lodash',
      versionInfo: '4.17.20',
      externalRefs: [
        { referenceCategory: 'PACKAGE-MANAGER', referenceType: 'purl', referenceLocator: 'pkg:npm/lodash@4.17.20' },
      ],
    },
  ],
});

describe('parseSbomInventory', () => {
  it('reads a CycloneDX product and its components', () => {
    const inv = parseSbomInventory(CDX);
    expect(inv?.product_purl).toBe('pkg:npm/shop@1.0.0');
    expect(inv?.product_name).toBe('shop');
    expect(inv?.components).toContainEqual({ name: 'lodash', version: '4.17.20', purl: 'pkg:npm/lodash@4.17.20' });
  });

  it('reads SPDX packages and their purl external refs, naming the described package as the product', () => {
    const inv = parseSbomInventory(SPDX);
    expect(inv?.product_name).toBe('shop');
    expect(inv?.product_purl).toBeNull();
    expect(inv?.components).toContainEqual({ name: 'lodash', version: '4.17.20', purl: 'pkg:npm/lodash@4.17.20' });
  });

  it('is null for text that is neither', () => {
    expect(parseSbomInventory('not json')).toBeNull();
    expect(parseSbomInventory('{"hello": 1}')).toBeNull();
  });
});

describe('purlsFor', () => {
  it('finds the purl of one package version', () => {
    const inv = parseSbomInventory(CDX);
    if (inv === null) throw new Error('unparsed');
    expect(purlsFor(inv, 'lodash', '4.17.20', 'npm')).toEqual({ purls: ['pkg:npm/lodash@4.17.20'], ambiguous: false });
    expect(purlsFor(inv, '@babel/core', '7.22.0', null).purls).toEqual(['pkg:npm/%40babel/core@7.22.0']);
    expect(purlsFor(inv, 'lodash', '1.0.0', 'npm').purls).toEqual([]);
  });

  it('refuses to pick between ecosystems when it does not know which one the package is from', () => {
    const inv = parseSbomInventory(CDX);
    if (inv === null) throw new Error('unparsed');
    expect(purlsFor(inv, 'requests', '2.31.0', null)).toEqual({ purls: [], ambiguous: true });
    expect(purlsFor(inv, 'requests', '2.31.0', 'pypi').purls).toEqual(['pkg:pypi/requests@2.31.0']);
  });
});
