import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { npmAuditParser } from '../../../../src/runners/scannerParsers/npmAudit.js';

const here = dirname(fileURLToPath(import.meta.url));
const FIXTURE = resolve(here, '../../../fixtures/scanners/npm-audit.json');

describe('npmAuditParser (npm 7+ audit report v2)', () => {
  it('emits one Finding per advisory object, skipping transitive string `via`', () => {
    const { findings } = npmAuditParser.parse(readFileSync(FIXTURE, 'utf8'));
    // lodash + minimist advisories; the `consumer` package whose `via` is the
    // string "lodash" must NOT add a third finding.
    expect(findings).toHaveLength(2);
    expect(findings.every((f) => f.tool === 'npm-audit')).toBe(true);
    expect(findings.every((f) => f.category === 'security')).toBe(true);
  });

  it('maps npm severities (high/critical) onto the canonical scale', () => {
    const { findings } = npmAuditParser.parse(readFileSync(FIXTURE, 'utf8'));
    const lodash = findings.find((f) => f.title.includes('lodash'));
    const minimist = findings.find((f) => f.title.includes('minimist'));
    expect(lodash?.severity).toBe('high');
    expect(minimist?.severity).toBe('critical');
  });

  it('reflects fixAvailable as boolean or object', () => {
    const { findings } = npmAuditParser.parse(readFileSync(FIXTURE, 'utf8'));
    const lodash = findings.find((f) => f.title.includes('lodash'));
    const minimist = findings.find((f) => f.title.includes('minimist'));
    expect(lodash?.fix_available).toBe(true); // fixAvailable: true
    expect(minimist?.fix_available).toBe(true); // fixAvailable: { ... }
  });

  it('maps "moderate" to medium', () => {
    const json = JSON.stringify({
      vulnerabilities: {
        ms: {
          name: 'ms',
          severity: 'moderate',
          via: [{ source: 9001, name: 'ms', title: 'ReDoS in ms', url: 'https://x', severity: 'moderate', range: '<2.0.0' }],
          fixAvailable: false,
        },
      },
    });
    const { findings } = npmAuditParser.parse(json);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('medium');
  });
});

describe('npmAuditParser (npm 6 advisories map)', () => {
  const v1 = JSON.stringify({
    advisories: {
      '1065': {
        id: 1065,
        title: 'Prototype Pollution',
        module_name: 'lodash',
        severity: 'high',
        vulnerable_versions: '<4.17.12',
        recommendation: 'Upgrade to version 4.17.12 or later',
        url: 'https://npmjs.com/advisories/1065',
        cwe: 'CWE-471',
        cves: ['CVE-2019-10744'],
      },
    },
  });

  it('emits a Finding and a CVE from the v1 shape', () => {
    const { findings, cves } = npmAuditParser.parse(v1);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('high');
    expect(findings[0]?.fix_available).toBe(true); // recommendation mentions "Upgrade"
    expect(cves).toHaveLength(1);
    expect(cves[0]?.cve_id).toBe('CVE-2019-10744');
    expect(cves[0]?.package_name).toBe('lodash');
  });
});

describe('npmAuditParser edge cases', () => {
  it('returns nothing for a clean report', () => {
    const { findings, cves } = npmAuditParser.parse(
      JSON.stringify({ vulnerabilities: {}, metadata: { vulnerabilities: { total: 0 } } }),
    );
    expect(findings).toHaveLength(0);
    expect(cves).toHaveLength(0);
  });

  it('does not throw on empty or malformed input', () => {
    expect(npmAuditParser.parse('').findings).toHaveLength(0);
    expect(npmAuditParser.parse('not json').findings).toHaveLength(0);
    expect(npmAuditParser.parse(null).findings).toHaveLength(0);
  });
});
