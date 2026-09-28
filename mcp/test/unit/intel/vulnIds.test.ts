/**
 * A finding's OWN vulnerability ids: its rule id when that is an advisory id,
 * plus the aliases its scanner recorded — never an id its title or
 * description merely mentions.
 *
 * The defect this replaces, reproduced through the real server: a PyYAML
 * advisory (PYSEC-2021-142, i.e. CVE-2020-14343) whose text MENTIONS
 * CVE-2020-1747 was tied to CVE-2020-1747. Suppressing it as VEX
 * not_affected published the user's statement against the other CVE, and a
 * KEV listing of a mentioned CVE boosted a finding that is not about it.
 */
import { describe, expect, it } from 'vitest';
import { advisoryIdFromUrl, findingVulnIds, sameVulnIds } from '../../../src/intel/vulnIds.js';
import type { Finding } from '../../../src/types.js';

function finding(over: Partial<Finding> = {}): Finding {
  return {
    fingerprint: 'fp',
    tool: 'trivy',
    severity: 'high',
    category: 'security',
    subcategory: 'cve',
    title: 'a vulnerability',
    snippet: 'lodash@4.17.20->4.17.21',
    fix_available: false,
    ...over,
  };
}

describe('findingVulnIds', () => {
  it('reads the rule id and the recorded aliases, rule id first, canonical case', () => {
    expect(findingVulnIds(finding({ rule_id: 'cve-2021-23337', vuln_aliases: ['ghsa-35JH-R3H4-6JHM'] })))
      .toEqual(['CVE-2021-23337', 'GHSA-35jh-r3h4-6jhm']);
  });

  it('never reads an id the title or message merely mentions', () => {
    const f = finding({
      tool: 'pip-audit',
      subcategory: 'dependency',
      rule_id: 'PYSEC-2021-142',
      title: 'PYSEC-2021-142 in pyyaml 5.3 (incomplete fix for CVE-2020-1747)',
      message: 'A vulnerability was discovered in the PyYAML library in versions before 5.4, where it is ' +
        'susceptible to arbitrary code execution … This flaw is due to an incomplete fix for CVE-2020-1747.',
      snippet: 'pyyaml@5.3',
      vuln_aliases: ['CVE-2020-14343', 'GHSA-8q59-q68h-6hv4'],
    });
    expect(findingVulnIds(f)).toEqual(['PYSEC-2021-142', 'CVE-2020-14343', 'GHSA-8q59-q68h-6hv4']);
  });

  it('takes the GHSA id out of an advisory URL rule id', () => {
    expect(findingVulnIds(finding({
      tool: 'npm-audit', subcategory: 'dependency', snippet: 'lodash@<4.17.21',
      rule_id: 'https://github.com/advisories/GHSA-35jh-r3h4-6jhm',
    }))).toEqual(['GHSA-35jh-r3h4-6jhm']);
  });

  it('accepts another advisory scheme only as a dependency finding’s own rule id', () => {
    expect(findingVulnIds(finding({ rule_id: 'SNYK-JS-LODASH-567746' }))).toEqual(['SNYK-JS-LODASH-567746']);
    // A Dockerfile misconfiguration's rule id is not a vulnerability.
    expect(findingVulnIds(finding({ subcategory: 'dockerfile', snippet: 'USER root', rule_id: 'AVD-DS-0002' })))
      .toEqual([]);
  });

  it('has nothing for a numeric npm advisory id, a WPScan title or a plain SAST rule', () => {
    expect(findingVulnIds(finding({ tool: 'npm-audit', subcategory: 'dependency', rule_id: '1096366', snippet: 'x@<1' })))
      .toEqual([]);
    expect(findingVulnIds(finding({
      tool: 'wpscan', subcategory: 'wordpress-plugin', snippet: 'component:akismet@4.1', rule_id: 'Akismet <= 4.1 - XSS',
    }))).toEqual([]);
    expect(findingVulnIds(finding({ tool: 'semgrep', subcategory: undefined, snippet: 'eval(x)', line_start: 3, rule_id: 'no-eval' })))
      .toEqual([]);
  });

  it('recognises a CVE rule id on any finding (a container OS package)', () => {
    expect(findingVulnIds(finding({ subcategory: undefined, snippet: undefined, rule_id: 'CVE-2024-3094' })))
      .toEqual(['CVE-2024-3094']);
  });
});

describe('sameVulnIds and advisoryIdFromUrl', () => {
  it('compares ids case-insensitively', () => {
    expect(sameVulnIds('GHSA-35jh-r3h4-6jhm', 'ghsa-35JH-r3h4-6jhm')).toBe(true);
    expect(sameVulnIds('CVE-2020-1747', 'CVE-2020-14343')).toBe(false);
  });

  it('reads the GHSA id of a GitHub advisory URL and nothing else', () => {
    expect(advisoryIdFromUrl('https://github.com/advisories/GHSA-xvch-5gv4-984h')).toBe('GHSA-xvch-5gv4-984h');
    expect(advisoryIdFromUrl('https://npmjs.com/advisories/1065')).toBeNull();
  });
});
