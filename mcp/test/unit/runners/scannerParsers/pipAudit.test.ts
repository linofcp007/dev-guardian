import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { pipAuditParser } from '../../../../src/runners/scannerParsers/pipAudit.js';

const here = dirname(fileURLToPath(import.meta.url));
const FIXTURE = resolve(here, '../../../fixtures/scanners/pip-audit.json');

function read(): string {
  return readFileSync(FIXTURE, 'utf8');
}

describe('pipAuditParser', () => {
  it('emits one Finding per vuln entry', () => {
    const { findings } = pipAuditParser.parse(read());
    expect(findings).toHaveLength(2);
  });

  it('extracts the CVE alias into a scan_cves row, with the minimum fix version', () => {
    const { cves } = pipAuditParser.parse(read());
    expect(cves).toHaveLength(1);
    const cve = cves[0];
    expect(cve?.cve_id).toBe('CVE-2019-19844');
    expect(cve?.package_name).toBe('django');
    expect(cve?.installed_version).toBe('2.0.1');
    expect(cve?.fixed_version).toBe('1.11.27');
  });

  it('marks fix_available=true only when fix_versions is non-empty', () => {
    const { findings } = pipAuditParser.parse(read());
    const django = findings.find((f) => f.snippet?.startsWith('django@'));
    const requests = findings.find((f) => f.snippet?.startsWith('requests@'));
    expect(django?.fix_available).toBe(true);
    expect(requests?.fix_available).toBe(false);
  });

  it('does not emit a CVE row for a vuln with no CVE alias', () => {
    const { cves } = pipAuditParser.parse(read());
    expect(cves.some((c) => c.package_name === 'requests')).toBe(false);
  });

  it('defaults severity to medium — pip-audit JSON carries no severity field', () => {
    const { findings } = pipAuditParser.parse(read());
    expect(findings.every((f) => f.severity === 'medium')).toBe(true);
  });

  it('returns nothing for empty/unparseable input', () => {
    expect(pipAuditParser.parse('')).toEqual({ findings: [], cves: [] });
    expect(pipAuditParser.parse('not json')).toEqual({ findings: [], cves: [] });
  });
});
