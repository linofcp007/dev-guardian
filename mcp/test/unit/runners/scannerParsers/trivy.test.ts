import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { trivyParser } from '../../../../src/runners/scannerParsers/trivy.js';

const here = dirname(fileURLToPath(import.meta.url));
const FS_FIXTURE = resolve(here, '../../../fixtures/scanners/trivy-fs.json');
const DOCKERFILE_FIXTURE = resolve(here, '../../../fixtures/scanners/trivy-dockerfile.json');

function read(path: string): string {
  return readFileSync(path, 'utf8');
}

describe('trivyParser (fs scan)', () => {
  it('emits one Finding per Vulnerability and one Finding per License', () => {
    const { findings, cves } = trivyParser.parse(read(FS_FIXTURE));
    expect(findings).toHaveLength(3); // 2 vulns + 1 license
    expect(cves).toHaveLength(2);
  });

  it('maps Trivy severities to canonical Severity', () => {
    const { findings } = trivyParser.parse(read(FS_FIXTURE));
    const medium = findings.find((f) => f.rule_id === 'CVE-2023-26136');
    const high = findings.find((f) => f.rule_id === 'CVE-2022-25883');
    expect(medium?.severity).toBe('medium');
    expect(high?.severity).toBe('high');
  });

  it('emits a ParserCveInput per Vulnerability', () => {
    const { cves } = trivyParser.parse(read(FS_FIXTURE));
    const cve = cves.find((c) => c.cve_id === 'CVE-2022-25883');
    expect(cve?.package_name).toBe('semver');
    expect(cve?.installed_version).toBe('5.7.1');
    expect(cve?.fixed_version).toBe('7.5.2');
  });

  it('sets fix_available=true when FixedVersion is present', () => {
    const { findings } = trivyParser.parse(read(FS_FIXTURE));
    expect(findings.every((f) => (f.rule_id?.startsWith('CVE-') ? f.fix_available === true : true))).toBe(
      true,
    );
  });

  it('maps Licenses to category=license', () => {
    const { findings } = trivyParser.parse(read(FS_FIXTURE));
    const license = findings.find((f) => f.category === 'license');
    expect(license?.subcategory).toBe('agpl-3.0-or-later');
    expect(license?.severity).toBe('high');
  });
});

describe('trivyParser (Dockerfile config scan)', () => {
  it('emits one Finding per Misconfiguration with category=security', () => {
    const { findings, cves } = trivyParser.parse(read(DOCKERFILE_FIXTURE));
    expect(findings).toHaveLength(1);
    expect(cves).toEqual([]);
    const [f] = findings;
    expect(f?.category).toBe('security');
    expect(f?.rule_id).toBe('DS002');
    expect(f?.severity).toBe('high');
    expect(f?.line_start).toBe(1);
  });
});
